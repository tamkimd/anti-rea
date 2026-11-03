#!/usr/bin/env python3
"""Prepare, inventory, and probe the exact pinned REA npm runtime."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import subprocess
import sysconfig
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "locks/upstreams.json").is_file():
    ROOT = Path(sysconfig.get_path("data")) / "share/anti-rea"
PIN = json.loads((ROOT / "locks/upstreams.json").read_text())["integrations"]["rea"]
NODE_SANDBOX_IMAGE = "node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea"
NODE_SANDBOX_OUTPUT_LIMIT = 256 * 1024 * 1024


class IntegrationError(RuntimeError):
    pass


def _sandbox_mode():
    mode = os.environ.get("ANTI_REA_NODE_SANDBOX", "docker")
    if mode not in {"docker", "host"}:
        raise IntegrationError("ANTI_REA_NODE_SANDBOX must be 'docker' or the explicit unsafe override 'host'")
    return mode


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _tool_version(tool):
    command = [tool, "--version"]
    if _sandbox_mode() == "docker":
        try:
            subprocess.run(["docker", "image", "inspect", NODE_SANDBOX_IMAGE], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
            command = ["docker", "run", "--pull=never", "--rm", "--network=none",
                       NODE_SANDBOX_IMAGE, *command]
        except (OSError, subprocess.SubprocessError) as error:
            raise IntegrationError("Pinned Docker Node image is unavailable; sandbox version probe refused") from error
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise IntegrationError(f"{tool} version probe failed in the selected execution environment") from error


def npm_version():
    return _tool_version("npm")


def node_version():
    version = _tool_version("node")
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise IntegrationError("Unrecognized Node version")
    return version, tuple(map(int, match.groups()))


def _has_symlink_ancestor(path):
    current = Path(path)
    while current != current.parent:
        if current.is_symlink():
            return True
        current = current.parent
    return False


def _docker_output_path(path, cwd):
    destination = Path(path).expanduser()
    if not destination.is_absolute():
        destination = cwd / destination
    if destination.exists() or destination.is_symlink():
        raise IntegrationError("Docker sandbox output path must be new")
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir():
        raise IntegrationError("Docker sandbox output parent must be a real directory")
    return parent / destination.name, parent


def _copy_docker_output(destination, staged, expected_parent):
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as error:
        raise IntegrationError("Docker sandbox output parent changed during execution") from error
    if (parent != expected_parent or _has_symlink_ancestor(destination.parent)
            or destination.exists() or destination.is_symlink() or staged.is_symlink()):
        raise IntegrationError("Docker sandbox output path changed during execution")
    size = 0
    entries = [staged]
    while entries:
        item = entries.pop()
        metadata = item.lstat()
        if item.is_symlink() or not (item.is_file() or item.is_dir()):
            raise IntegrationError("Docker sandbox output contains an unsafe filesystem entry")
        if item.is_file():
            size += metadata.st_size
        else:
            entries.extend(item.iterdir())
        if size > NODE_SANDBOX_OUTPUT_LIMIT:
            raise IntegrationError("Docker sandbox output exceeded 256 MiB")
    if staged.is_dir():
        shutil.copytree(staged, destination)
    else:
        shutil.copy2(staged, destination)


def _docker_command(command, cwd, writable_cwd=False, network=False):
    """Map only cwd and explicit absolute path arguments into the pinned, offline container."""
    cwd = Path(cwd).resolve(strict=True)
    command = [str(arg) for arg in command]
    name = "anti-rea-" + uuid.uuid4().hex
    mounts = [(cwd, "/work", "rw" if writable_cwd else "ro")]
    mapped = []
    output_staging = tempfile.TemporaryDirectory(prefix="anti-rea-docker-output-")
    output_root = Path(output_staging.name)
    outputs = []
    next_output = False
    input_count = 0
    for arg in command:
        if next_output:
            destination, parent = _docker_output_path(arg, cwd)
            staged = output_root / f"{len(outputs)}{Path(arg).suffix}"
            outputs.append((destination, staged, parent))
            mapped.append(f"/output/{len(outputs)-1}{Path(arg).suffix}")
            mounts.append((output_root, "/output", "rw"))
            next_output = False
            continue
        if arg in {"--output", "--evidence_output"}:
            mapped.append(arg)
            next_output = True
            continue
        path = Path(arg)
        if path.is_absolute():
            resolved = path.resolve()
            if path.is_symlink() and resolved != cwd and cwd not in resolved.parents:
                output_staging.cleanup()
                raise IntegrationError("Docker sandbox refuses symlink path arguments outside its runtime")
            if resolved == cwd or cwd in resolved.parents:
                mapped.append("/work" + ("/" + resolved.relative_to(cwd).as_posix() if resolved != cwd else ""))
            elif resolved.exists():
                if not (resolved.is_dir() or resolved.is_file()):
                    output_staging.cleanup()
                    raise IntegrationError("Docker sandbox accepts only regular file and directory inputs")
                if "," in str(resolved):
                    output_staging.cleanup()
                    raise IntegrationError("Docker sandbox does not support comma in mounted paths")
                target = f"/input/{input_count}{resolved.suffix if resolved.is_file() else ''}"
                input_count += 1
                mounts.append((resolved, target, "ro"))
                mapped.append(target)
            else:
                mapped.append(arg)
        else:
            mapped.append(arg)
    if next_output:
        output_staging.cleanup()
        raise IntegrationError("Docker sandbox command has an output flag without a path")
    # Verify locally and prohibit implicit pulls so execution never changes the machine's image cache.
    try:
        checked = subprocess.run(["docker", "image", "inspect", NODE_SANDBOX_IMAGE],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        output_staging.cleanup()
        raise IntegrationError("Docker image availability check failed; sandbox execution refused") from error
    if checked.returncode:
        output_staging.cleanup()
        raise IntegrationError("Pinned Docker Node image is missing locally; sandbox execution refused")
    args = ["docker", "run", "--pull=never", "--rm", "--name", name,
            "--network=" + ("bridge" if network else "none"), "--read-only",
            "--workdir", "/work",
            "--pids-limit=64", "--memory=1g", "--cpus=2",
            "--security-opt=no-new-privileges", "--cap-drop=ALL",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
            "--env", "HOME=/tmp", "--env", "NPM_CONFIG_CACHE=/tmp/npm-cache"]
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]
    for source, target, mode in mounts:
        args += ["--mount", f"type=bind,src={source},dst={target}" +
                 (",readonly" if mode == "ro" else "")]
    args += [NODE_SANDBOX_IMAGE, *mapped]
    return args, name, outputs, output_staging


def run_bounded(command, cwd, timeout, stdout_limit, stderr_limit, *, writable_cwd=False, network=False):
    """Capture a child in temporary files, enforcing time and disk-output budgets while it runs."""
    from core import baseline as baseline_capture

    sandbox = _sandbox_mode() == "docker"
    if sandbox:
        command, container_name, output_paths, output_staging = _docker_command(
            command, cwd, writable_cwd=writable_cwd, network=network)
    else:
        container_name, output_paths, output_staging = None, [], None
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        options = {"cwd": cwd, "stdout": stdout_file, "stderr": stderr_file}
        if os.name == "posix":
            options["start_new_session"] = True
        elif os.name == "nt":
            options.update(baseline_capture._process_creation_options(subprocess.CREATE_NEW_PROCESS_GROUP))
        try:
            process = subprocess.Popen(command, **options)
        except BaseException:
            if output_staging:
                output_staging.cleanup()
            raise
        try:
            baseline_capture._contain_process_tree(process)
        except BaseException:
            if output_staging:
                output_staging.cleanup()
            raise
        deadline = time.monotonic() + timeout

        def group_exists():
            try:
                os.killpg(process.pid, 0)
                return True
            except (ProcessLookupError, PermissionError):
                return False

        def terminate_group():
            if container_name:
                try:
                    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if os.name == "posix":
                grace_deadline = time.monotonic() + 5
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    process.wait(timeout=max(0, grace_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
                # A child can close the capture files and outlive the group
                # leader, so check group disappearance within the same grace period.
                while group_exists() and time.monotonic() < grace_deadline:
                    time.sleep(min(0.05, grace_deadline - time.monotonic()))
                if group_exists():
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            else:
                baseline_capture._close_process_tree(process)
                try:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    if process.poll() is None:
                        try:
                            process.kill()
                        except OSError:
                            pass
                process.wait()

        previous_term = signal.getsignal(signal.SIGTERM)

        def terminate(signum, frame):
            terminate_group()
            raise IntegrationError("REA analysis cancelled")

        def output_budget_error():
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            exceeded = [name for name, size, limit in (
                ("stdout", stdout_size, stdout_limit), ("stderr", stderr_size, stderr_limit)) if size > limit]
            return IntegrationError(
                "REA process exceeded its output budget "
                f"(stdout={stdout_size}/{stdout_limit} bytes, stderr={stderr_size}/{stderr_limit} bytes, "
                f"exceeded={','.join(exceeded)})")

        signal.signal(signal.SIGTERM, terminate)
        try:
            while process.poll() is None:
                sizes = (os.fstat(stdout_file.fileno()).st_size, os.fstat(stderr_file.fileno()).st_size)
                if sizes[0] > stdout_limit or sizes[1] > stderr_limit:
                    terminate_group()
                    raise output_budget_error()
                if time.monotonic() >= deadline:
                    terminate_group()
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(0.05)
            sizes = (os.fstat(stdout_file.fileno()).st_size, os.fstat(stderr_file.fileno()).st_size)
            if sizes[0] > stdout_limit or sizes[1] > stderr_limit:
                raise output_budget_error()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read().decode("utf-8", errors="replace")
            stderr = stderr_file.read().decode("utf-8", errors="replace")
            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
            if container_name:
                try:
                    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if result.returncode == 0:
                    for destination, staged, parent in output_paths:
                        if staged.exists():
                            _copy_docker_output(destination, staged, parent)
            return result
        except BaseException:
            terminate_group()
            raise
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            baseline_capture._close_process_tree(process)
            if output_staging:
                output_staging.cleanup()


def supported_node(parts):
    return ((parts[0] == 22 and parts >= (22, 23, 4))
            or (parts[0] == 24 and parts >= (24, 22, 1))
            or parts[0] >= 26 and parts >= (26, 12, 1))


def package_tree_hash(path):
    entries = []
    for current, dirs, files in os.walk(path, followlinks=False):
        symlink_dirs = [name for name in dirs if (Path(current) / name).is_symlink()]
        dirs[:] = sorted(name for name in dirs if name not in symlink_dirs)
        for name in sorted(dirs + files + symlink_dirs):
            entry = Path(current) / name
            relative = entry.relative_to(path).as_posix()
            if entry.is_symlink():
                entries.append({"path": relative, "symlink": os.readlink(entry)})
            elif entry.is_file():
                entries.append({"path": relative, "sha256": sha(entry.read_bytes())})
    return sha(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode())


def verify_runtime(runtime):
    runtime = Path(runtime).expanduser()
    if runtime.is_symlink():
        raise IntegrationError("Runtime directory symlink refused")
    runtime = runtime.resolve(strict=True)
    lock = runtime / "package-lock.json"
    marker = runtime / "anti-rea-rea-runtime.json"
    if not lock.is_file() or sha(lock.read_bytes()) != PIN["package_lock_sha256"]:
        raise IntegrationError("Runtime lock does not match the pinned lock hash")
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    if any(manifest.get(key) != PIN[key] for key in
           ("source_commit", "npm_version", "npm_integrity", "package_lock_sha256")):
        raise IntegrationError("Runtime manifest does not match the pinned REA identity")
    package = runtime / "node_modules/rea-agents"
    metadata = json.loads((package / "package.json").read_text(encoding="utf-8"))
    if metadata.get("name") != PIN["npm_package"] or metadata.get("version") != PIN["npm_version"]:
        raise IntegrationError("Installed REA package identity mismatch")
    actual_hash = package_tree_hash(package)
    if actual_hash != manifest.get("package_tree_sha256"):
        raise IntegrationError("REA installed package tree changed after bootstrap")
    return runtime, manifest


def bootstrap(runtime):
    version, parts = node_version()
    if not supported_node(parts):
        raise IntegrationError(f"Pinned REA requires Node {PIN['node_requirement']}; found {version}; refusing install or execution")
    runtime = Path(runtime).expanduser().absolute()
    if runtime.exists() or runtime.is_symlink():
        raise IntegrationError("Choose a new, empty runtime directory")
    runtime.parent.mkdir(parents=True, exist_ok=True)
    owned = False
    try:
        runtime.mkdir(mode=0o700)
        owned = True
        shutil.copy2(ROOT / "integrations/rea/package.json", runtime / "package.json")
        shutil.copy2(ROOT / PIN["package_lock"], runtime / "package-lock.json")
        command = ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
        completed = run_bounded(command, runtime, 900, 8 * 1024 * 1024, 8 * 1024 * 1024,
                                writable_cwd=True, network=True)
        if completed.returncode:
            raise subprocess.CalledProcessError(completed.returncode, command, completed.stdout, completed.stderr)
        package = runtime / "node_modules/rea-agents"
        metadata = json.loads((package / "package.json").read_text(encoding="utf-8"))
        if metadata.get("version") != PIN["npm_version"]:
            raise IntegrationError("Installed REA version differs from the pin")
        manifest = {"schema_version": "1.0", "source_commit": PIN["source_commit"],
                    "npm_version": PIN["npm_version"], "npm_integrity": PIN["npm_integrity"],
                    "node_version": version, "npm_version_runtime": _tool_version("npm"),
                    "package_lock_sha256": PIN["package_lock_sha256"],
                    "package_tree_sha256": package_tree_hash(package), "install_command": command,
                    "install_scripts": "disabled"}
        with (runtime / "anti-rea-rea-runtime.json").open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
    except BaseException:
        if owned:
            shutil.rmtree(runtime, ignore_errors=True)
        raise
    return {"status": "ready", "runtime": str(runtime), "manifest": manifest}


def probe(runtime, timeout=30):
    version, parts = node_version()
    if not supported_node(parts):
        raise IntegrationError(f"Pinned REA requires Node {PIN['node_requirement']}; found {version}; runtime probe refused")
    runtime, manifest = verify_runtime(runtime)
    command = [str(runtime / "node_modules/.bin/rea"), "--version"]
    result = run_bounded(command, runtime, timeout, 1024 * 1024, 1024 * 1024)
    if result.returncode:
        raise IntegrationError("REA version probe failed: " + result.stderr[-2000:])
    return {"status": "ready", "package_version": PIN["npm_version"], "probe_output": result.stdout.strip(),
            "runtime_manifest_sha256": sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()),
            "providers": "not_probed"}


def _doctor_checks(report):
    checks = report.get("checks")
    if not isinstance(checks, list):
        raise IntegrationError("REA doctor JSON is missing readiness checks")
    ledger = []
    for check in checks:
        if (not isinstance(check, dict) or not isinstance(check.get("name"), str)
                or not isinstance(check.get("ok"), bool)
                or not isinstance(check.get("classification"), str)
                or (check.get("remediation") is not None and not isinstance(check.get("remediation"), str))):
            raise IntegrationError("REA doctor JSON contains an invalid readiness check")
        ledger.append({key: check[key] for key in ("name", "ok", "classification", "remediation")
                       if key in check})
    return ledger


def doctor(runtime, output, timeout=120):
    version, parts = node_version()
    if not supported_node(parts):
        raise IntegrationError(f"Pinned REA requires Node {PIN['node_requirement']}; found {version}; doctor refused")
    runtime, manifest = verify_runtime(runtime)
    command = [str(runtime / "node_modules/.bin/rea"), "doctor", "--json"]
    completed = run_bounded(command, runtime, timeout, 8 * 1024 * 1024, 1024 * 1024)
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise IntegrationError("REA doctor returned invalid JSON: " + completed.stderr[-2000:]) from error
    if not isinstance(report, dict) or not isinstance(report.get("healthy"), bool) or not isinstance(report.get("providerInspections"), list):
        raise IntegrationError("REA doctor JSON is missing expected readiness fields")
    checks = _doctor_checks(report)
    evidence = Path(output).expanduser()
    if evidence.exists() or evidence.is_symlink():
        raise IntegrationError("Doctor evidence output must be a new file")
    if evidence.parent.is_symlink() or not evidence.parent.is_dir():
        raise IntegrationError("Doctor evidence parent must already exist and be a real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(evidence, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            raw = completed.stdout.encode()
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        evidence.unlink(missing_ok=True)
        raise
    failed = [check for check in report.get("checks", []) if isinstance(check, dict) and check.get("ok") is False]
    providers = [{"id": item.get("id"), "configured": item.get("configured"), "available": item.get("available"),
                  "checks": item.get("checks", [])} for item in report["providerInspections"] if isinstance(item, dict)]
    return {"status": "healthy" if report["healthy"] else "incomplete", "exit_code": completed.returncode,
            "providers": providers, "checks": checks, "failed_check_count": len(failed),
            "failed_check_names": [item.get("name") for item in failed],
            "evidence": str(evidence.resolve()), "evidence_sha256": sha(raw),
            "runtime_manifest_sha256": sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())}


def analyze_javascript(runtime, target, output, bundle, timeout=360):
    version, parts = node_version()
    if not supported_node(parts):
        raise IntegrationError(f"Pinned REA requires Node {PIN['node_requirement']}; found {version}; analysis refused")
    runtime, manifest = verify_runtime(runtime)
    target = Path(target).expanduser().resolve(strict=True)
    if not target.is_dir() and not (target.is_file() and target.suffix.lower() == ".asar"):
        raise IntegrationError("JavaScript analysis target must be a directory or .asar file")
    output, bundle = Path(output).expanduser(), Path(bundle).expanduser()
    if output.exists() or output.is_symlink() or bundle.exists() or bundle.is_symlink():
        raise IntegrationError("Analysis report and evidence bundle paths must be new")
    if (output.parent.is_symlink() or not output.parent.is_dir() or bundle.parent.is_symlink() or not bundle.parent.is_dir()):
        raise IntegrationError("Analysis output parents must already exist and be real directories")
    command = [str(runtime / "node_modules/.bin/rea"), "analyze-javascript-application", str(target),
               "--detail", "summary", "--evidence_output", str(bundle), "--format", "json"]
    try:
        completed = run_bounded(command, runtime, timeout, 64 * 1024 * 1024, 8 * 1024 * 1024)
    except subprocess.TimeoutExpired as error:
        raise IntegrationError(f"REA analysis timed out after {timeout}s; process group was terminated") from error
    except IntegrationError as error:
        raise IntegrationError(str(error) + "; process group was terminated") from error
    raw = completed.stdout.encode()
    output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, output_flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if completed.returncode:
        raise IntegrationError(f"REA analysis failed with exit {completed.returncode}; raw output retained at {output}")
    try:
        summary, normalized, _, _ = _analysis_summary(output)
    except IntegrationError as error:
        raise IntegrationError(f"REA analysis summary is incomplete; raw output retained at {output}: {error}") from error
    if not bundle.is_file() or bundle.is_symlink():
        raise IntegrationError(f"REA analysis summary or evidence bundle is incomplete; raw output retained at {output}")
    return {"status": "passed", "operation": "analyze_javascript_application", "target": str(target),
            "evidence_id": normalized["parent_evidence_id"], "parent_digest": normalized["parent_digest"],
            "summary_sha256": sha(json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()),
            "report": str(output.resolve()), "report_sha256": sha(raw), "evidence_bundle": str(bundle.resolve()),
            "evidence_bundle_sha256": sha(bundle.read_bytes()), "runtime_manifest_sha256": sha(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())}


def _analysis_summary(report):
    try:
        raw = _read_report(Path(report))
        lines = [line for line in raw.decode("utf-8").splitlines() if line.strip()]
        summary = json.loads(lines[-1])["summary"]
        normalized = summary["normalized_result"]
        statistics = normalized["summary"]["statistics"]
        coverage = normalized["coverage"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IndexError, KeyError, TypeError) as error:
        raise IntegrationError("report is incomplete or malformed") from error
    if (summary.get("predicate_type") != "rea.analysis-view" or summary.get("operation") != "inspect_analysis_view"
            or not normalized.get("parent_evidence_id") or not isinstance(normalized.get("parent_digest"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", normalized["parent_digest"])
            or not isinstance(summary.get("parameters"), dict)
            or summary["parameters"].get("view") != {"kind": "summary"}
            or not isinstance(statistics, dict) or isinstance(statistics.get("findings"), bool)
            or not isinstance(statistics.get("findings"), int)
            or not isinstance(coverage, dict) or coverage.get("status") != "complete-within-view"
            or coverage.get("exhausted") is not True or isinstance(coverage.get("examined"), bool)
            or not isinstance(coverage.get("examined"), int) or isinstance(coverage.get("total"), bool)
            or not isinstance(coverage.get("total"), int) or coverage["examined"] != coverage["total"]
            or any(isinstance(statistics.get(key), bool) or not isinstance(statistics.get(key), int)
                   or statistics[key] < 0 for key in ("findings", "relevant_files", "parsed_javascript_files",
                                                      "skipped_javascript_files", "parse_failures"))):
        raise IntegrationError("summary or complete-within-view coverage is invalid")
    if (statistics["parsed_javascript_files"] == 0 or statistics["skipped_javascript_files"]
            or statistics["parse_failures"]):
        raise IntegrationError(
            "JavaScript source parsing is incomplete "
            f"(parsed={statistics['parsed_javascript_files']}, skipped={statistics['skipped_javascript_files']}, "
            f"parse_failures={statistics['parse_failures']})")
    return summary, normalized, statistics, coverage


def compare_javascript(runtime, before, after, evidence_dir, timeout=360):
    """Run the same pinned REA summary on two comparable JS targets and retain measured deltas."""
    before, after = Path(before).expanduser().resolve(strict=True), Path(after).expanduser().resolve(strict=True)
    if before == after or not before.is_dir() or not after.is_dir():
        raise IntegrationError("REA comparison requires distinct BEFORE and AFTER directories")
    output = Path(evidence_dir).expanduser()
    if output.is_symlink() or not output.is_dir():
        raise IntegrationError("REA comparison evidence directory must already exist and be real")
    output = output.resolve(strict=True)
    if any(root == output or root in output.parents or output in root.parents for root in (before, after)):
        raise IntegrationError("REA comparison evidence must be stored outside both analyzed targets")
    before_paths, before_tree_hash = _comparison_tree(before)
    after_paths, after_tree_hash = _comparison_tree(after)
    if before_paths != after_paths:
        raise IntegrationError("REA BEFORE/AFTER file scope is not identical")
    before_result = analyze_javascript(runtime, before, output / "before.jsonl", output / "before-bundle.json", timeout)
    after_result = analyze_javascript(runtime, after, output / "after.jsonl", output / "after-bundle.json", timeout)
    if (before_result["runtime_manifest_sha256"] != after_result["runtime_manifest_sha256"]
            or not re.fullmatch(r"[a-f0-9]{64}", before_result["runtime_manifest_sha256"])):
        raise IntegrationError("REA comparison runtime identity changed between analyses")

    def summary(result):
        return _analysis_summary(Path(result["report"]))

    before_summary, before_normalized, before_stats, before_coverage = summary(before_result)
    after_summary, after_normalized, after_stats, after_coverage = summary(after_result)
    for directory, result, normalized in ((before, before_result, before_normalized),
                                          (after, after_result, after_normalized)):
        artifact = normalized.get("artifact")
        if (Path(result["target"]).resolve(strict=True) != directory
                or not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str)
                or Path(artifact["path"]).resolve(strict=True) != directory
                or not isinstance(artifact.get("sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"])):
            raise IntegrationError("REA report target identity does not match the requested directory")
        raw_path = Path(result["report"])
        raw = _read_report(raw_path)
        if sha(raw) != result["report_sha256"]:
            raise IntegrationError("REA report changed after analysis")
        bundle = _read_report(Path(result["evidence_bundle"]))
        if sha(bundle) != result["evidence_bundle_sha256"]:
            raise IntegrationError("REA evidence bundle changed after analysis")
    scope_fields = ("relevant_files", "parsed_javascript_files", "skipped_javascript_files", "parse_failures")
    if (before_summary["parameters"]["view"] != after_summary["parameters"]["view"]
            or before_stats.get("relevant_files") != after_stats.get("relevant_files")):
        raise IntegrationError("REA BEFORE/AFTER analysis scope is not comparable")
    before_findings, after_findings = before_stats["findings"], after_stats["findings"]
    if any(isinstance(count, bool) or count < 0 for count in (before_findings, after_findings)):
        raise IntegrationError("REA finding counts are invalid")
    if (_comparison_tree(before)[1] != before_tree_hash or _comparison_tree(after)[1] != after_tree_hash):
        raise IntegrationError("REA comparison target changed while analysis was running")
    report = {"schema_version": "1.0", "record_type": "rea_comparison",
              "status": "measured", "runtime_manifest_sha256": before_result["runtime_manifest_sha256"],
              "analysis_view": before_summary["parameters"]["view"],
              "file_scope_sha256": sha("\n".join(before_paths).encode()),
              "before_tree_sha256": before_tree_hash, "after_tree_sha256": after_tree_hash,
              "scope": {key: before_stats.get(key) for key in scope_fields},
              "analysis_stats": {"before": before_stats, "after": after_stats},
              "coverage": {"before": before_coverage, "after": after_coverage},
              "before": {"target": str(before), "artifact_sha256": before_normalized["artifact"]["sha256"],
                         "evidence_id": before_summary["normalized_result"]["parent_evidence_id"],
                         "parent_digest": before_summary["normalized_result"]["parent_digest"],
                         "report": before_result["report"], "report_sha256": before_result["report_sha256"],
                         "evidence_bundle": before_result["evidence_bundle"],
                         "evidence_bundle_sha256": before_result["evidence_bundle_sha256"],
                         "findings": before_findings},
              "after": {"target": str(after), "artifact_sha256": after_normalized["artifact"]["sha256"],
                        "evidence_id": after_summary["normalized_result"]["parent_evidence_id"],
                        "parent_digest": after_summary["normalized_result"]["parent_digest"],
                        "report": after_result["report"], "report_sha256": after_result["report_sha256"],
                        "evidence_bundle": after_result["evidence_bundle"],
                        "evidence_bundle_sha256": after_result["evidence_bundle_sha256"],
                        "findings": after_findings},
              "finding_delta": after_findings - before_findings,
              "interpretation": "Static finding counts are measurements, not proof of protection or behavior preservation."}
    path = output / "comparison.json"
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
    if len(raw) > 64 * 1024 * 1024:
        raise IntegrationError("REA comparison report exceeded the 64 MiB limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "measured", "report": str(path), "report_sha256": sha(raw),
            "before_findings": before_findings, "after_findings": after_findings,
            "finding_delta": report["finding_delta"],
            "runtime_manifest_sha256": report["runtime_manifest_sha256"]}


def _comparison_tree(root):
    if not getattr(os, "O_NOFOLLOW", 0):
        raise IntegrationError("Safe no-follow comparison reads are unavailable on this platform")
    excluded = {".git", ".hg", ".svn", ".dart_tool", ".gradle", ".idea", ".cache",
                "node_modules", ".venv", "venv", "Pods", "vendor", "target"}
    files, pending, total_bytes, total_entries = {}, [Path(root)], 0, 0
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise IntegrationError(f"REA comparison cannot enumerate scope: {directory}") from error
        for entry in entries:
            total_entries += 1
            if total_entries > 100_000:
                raise IntegrationError("REA comparison exceeds the 100,000-entry scope limit")
            if entry.name in excluded and entry.is_dir(follow_symlinks=False):
                continue
            relative = Path(entry.path).relative_to(root).as_posix()
            if entry.is_symlink():
                raise IntegrationError(f"REA comparison scope contains a symlink: {relative}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False):
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
                fd = os.open(entry.path, flags)
                try:
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode):
                        raise IntegrationError(f"REA comparison scope changed file type: {relative}")
                    digest, size = hashlib.sha256(), 0
                    while chunk := os.read(fd, 1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                        total_bytes += len(chunk)
                        if total_bytes > 2 * 1024 * 1024 * 1024:
                            raise IntegrationError("REA comparison exceeds the 2 GiB scope limit")
                    after = os.fstat(fd)
                    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
                    if identity(before) != identity(after) or size != before.st_size:
                        raise IntegrationError(f"REA comparison file changed while hashing: {relative}")
                    files[relative] = digest.digest()
                finally:
                    os.close(fd)
            else:
                raise IntegrationError(f"REA comparison scope contains a special file: {relative}")
            if len(files) > 100_000:
                raise IntegrationError("REA comparison exceeds the 100,000-file scope limit")
    paths = sorted(files)
    tree = hashlib.sha256()
    for path in paths:
        tree.update(path.encode() + b"\0" + files[path])
    return paths, tree.hexdigest()


def _read_report(path):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise IntegrationError("Safe no-follow report reads are unavailable on this platform")
    fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 64 * 1024 * 1024:
            raise IntegrationError("REA comparison report must be a regular file within the 64 MiB limit")
        data = bytearray()
        while chunk := os.read(fd, 1024 * 1024):
            data.extend(chunk)
            if len(data) > 64 * 1024 * 1024:
                raise IntegrationError("REA comparison report exceeds the 64 MiB limit")
        after = os.fstat(fd)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after) or len(data) != before.st_size:
            raise IntegrationError("REA comparison report changed while being read")
        return bytes(data)
    finally:
        os.close(fd)


async def _mcp_analyze(runtime, target, output, timeout=360):
    version, parts = node_version()
    if not supported_node(parts):
        raise IntegrationError(f"Pinned REA requires Node {PIN['node_requirement']}; found {version}; MCP analysis refused")
    try:
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
    except ImportError as error:
        raise IntegrationError("MCP analysis requires Anti-REA installed on Python 3.11+") from error
    runtime, manifest = verify_runtime(runtime)
    target = Path(target).expanduser().resolve(strict=True)
    if not target.is_dir() and not (target.is_file() and target.suffix.lower() == ".asar"):
        raise IntegrationError("JavaScript analysis target must be a directory or .asar file")
    output = Path(output).expanduser()
    if output.exists() or output.is_symlink():
        raise IntegrationError("MCP evidence output must be a new file")
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise IntegrationError("MCP evidence parent must already exist and be a real directory")
    env = dict(os.environ)
    env["REA_MCP_INPUT_SCHEMA_PROFILE"] = "compact"
    params = StdioServerParameters(command=str(runtime / "node_modules/.bin/rea"), args=["mcp"], env=env)
    try:
        async with asyncio.timeout(timeout):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    server = await session.initialize()
                    tools = await session.list_tools()
                    names = sorted(tool.name for tool in tools.tools)
                    if "analyze_javascript_application" not in names:
                        raise IntegrationError("Pinned REA MCP server did not advertise JavaScript analysis")
                    input_record = {"input_path": str(target), "format": "directory" if target.is_dir() else "asar",
                                    "detail": "complete"}
                    result = await session.call_tool("analyze_javascript_application", input_record)
                    payload = result.structured_content
                    if result.is_error or not isinstance(payload, dict) or not payload.get("evidence_id"):
                        raise IntegrationError("REA MCP analysis returned an error or incomplete evidence")
                    raw = json.dumps({"server": {"name": server.server_info.name, "version": server.server_info.version},
                                      "tools": names, "tool_count": len(names), "tool": "analyze_javascript_application",
                                      "input": input_record, "result": payload}, sort_keys=True,
                                     ensure_ascii=False, separators=(",", ":")).encode()
    except TimeoutError as error:
        raise IntegrationError(f"REA MCP analysis timed out after {timeout}s") from error
    if len(raw) > 64 * 1024 * 1024:
        raise IntegrationError("REA MCP evidence exceeded the 64 MiB retention limit")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "passed", "server": server.server_info.name, "server_version": server.server_info.version,
            "tool_count": len(names), "evidence_id": payload["evidence_id"], "operation": payload.get("operation"),
            "target": str(target), "evidence": str(output.resolve()), "evidence_sha256": sha(raw),
            "runtime_manifest_sha256": sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())}


async def _mcp_inventory(runtime, output, timeout=180):
    version, parts = node_version()
    if not supported_node(parts):
        raise IntegrationError(f"Pinned REA requires Node {PIN['node_requirement']}; MCP inventory refused")
    try:
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
    except ImportError as error:
        raise IntegrationError("MCP inventory requires Anti-REA installed on Python 3.11+") from error
    output = Path(output).expanduser()
    if output.exists() or output.is_symlink() or output.parent.is_symlink() or not output.parent.is_dir():
        raise IntegrationError("Inventory output must be a new file in an existing real directory")
    runtime, manifest = verify_runtime(runtime)
    env = dict(os.environ)
    env["REA_MCP_INPUT_SCHEMA_PROFILE"] = "compact"
    params = StdioServerParameters(command=str(runtime / "node_modules/.bin/rea"), args=["mcp"], env=env)
    try:
        async with asyncio.timeout(timeout):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    server = await session.initialize()
                    listed = await session.list_tools()
                    tools = []
                    for tool in listed.tools:
                        contract = tool.model_dump(mode="json", by_alias=True)
                        tools.append({key: contract[key] for key in ("name", "inputSchema", "outputSchema")
                                      if contract.get(key) is not None})
                    listed_prompts = await session.list_prompts()
                    prompts = []
                    for prompt in listed_prompts.prompts:
                        contract = prompt.model_dump(mode="json", by_alias=True)
                        prompts.append({key: contract[key] for key in ("name", "title", "description", "arguments")
                                        if contract.get(key) is not None})
    except TimeoutError as error:
        raise IntegrationError(f"REA MCP inventory timed out after {timeout}s") from error
    names = [tool.get("name") for tool in tools]
    if (not tools or any(not isinstance(name, str) or not name for name in names)
            or len(names) != len(set(names))
            or any(not isinstance(tool.get("inputSchema"), dict) for tool in tools)):
        raise IntegrationError("REA MCP listed invalid or duplicate tool contracts")
    prompt_names = [prompt.get("name") for prompt in prompts]
    if (any(not isinstance(name, str) or not name for name in prompt_names)
            or len(prompt_names) != len(set(prompt_names))):
        raise IntegrationError("REA MCP listed invalid or duplicate prompt contracts")
    payload = {"schema_version": "1.0", "record_type": "upstream_runtime_tool_contracts",
               "id": f"rea-{PIN['npm_version']}-mcp-tools", "upstream": {
                   "repository": PIN["repository"], "source_commit": PIN["source_commit"],
                   "package": PIN["npm_package"], "version": PIN["npm_version"],
                   "npm_integrity": PIN["npm_integrity"],
                   "package_lock_sha256": PIN["package_lock_sha256"],
                   "runtime_manifest_sha256": sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()),
                   "node_version": version},
               "server": {"name": server.server_info.name, "version": server.server_info.version},
               "tool_count": len(tools), "tools": sorted(tools, key=lambda tool: tool["name"]),
               "prompt_count": len(prompts), "prompts": sorted(prompts, key=lambda prompt: prompt["name"]),
               "limitations": ["Runtime MCP inventory does not establish equivalence with source-only contracts or CLI commands.",
                               "Tool and prompt schemas do not establish provider installation, readiness, or successful execution."]}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
    if len(raw) > 64 * 1024 * 1024:
        raise IntegrationError("REA MCP inventory exceeded the 64 MiB retention limit")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "passed", "tool_count": len(tools), "prompt_count": len(prompts),
            "server_version": server.server_info.version,
            "output": str(output.resolve()), "sha256": sha(raw), "runtime_manifest_sha256": payload["upstream"]["runtime_manifest_sha256"]}


def mcp_inventory(runtime, output, timeout=180):
    return asyncio.run(_mcp_inventory(runtime, output, timeout))


def mcp_analyze(runtime, target, output, timeout=360):
    return asyncio.run(_mcp_analyze(runtime, target, output, timeout))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("bootstrap")
    install.add_argument("runtime")
    check = commands.add_parser("verify-runtime")
    check.add_argument("runtime")
    readiness = commands.add_parser("probe")
    readiness.add_argument("runtime")
    provider = commands.add_parser("doctor")
    provider.add_argument("runtime")
    provider.add_argument("output", help="new private JSON evidence path; includes detected configuration paths")
    analysis = commands.add_parser("analyze-javascript", help="run pinned REA analysis on a JS/Electron directory")
    analysis.add_argument("runtime")
    analysis.add_argument("target")
    analysis.add_argument("output", help="new private raw CLI output file")
    analysis.add_argument("bundle", help="new private REA evidence bundle file")
    comparison = commands.add_parser("compare-javascript", help="run comparable pinned REA analyses before and after")
    comparison.add_argument("runtime")
    comparison.add_argument("before")
    comparison.add_argument("after")
    comparison.add_argument("evidence_dir")
    mcp_analysis = commands.add_parser("mcp-analyze", help="call pinned REA over MCP and retain full evidence")
    mcp_analysis.add_argument("runtime")
    mcp_analysis.add_argument("target")
    mcp_analysis.add_argument("output")
    inventory = commands.add_parser("mcp-inventory", help="retain complete schemas from pinned REA runtime tools/list")
    inventory.add_argument("runtime")
    inventory.add_argument("output")
    args = parser.parse_args()
    try:
        if args.command == "bootstrap":
            result = bootstrap(args.runtime)
        elif args.command == "verify-runtime":
            runtime, manifest = verify_runtime(args.runtime)
            result = {"status": "verified", "runtime": str(runtime), "manifest": manifest}
        else:
            if args.command == "probe":
                result = probe(args.runtime)
            elif args.command == "doctor":
                result = doctor(args.runtime, args.output)
            elif args.command == "mcp-analyze":
                result = mcp_analyze(args.runtime, args.target, args.output)
            elif args.command == "mcp-inventory":
                result = mcp_inventory(args.runtime, args.output)
            elif args.command == "compare-javascript":
                result = compare_javascript(args.runtime, args.before, args.after, args.evidence_dir)
            else:
                result = analyze_javascript(args.runtime, args.target, args.output, args.bundle)
        print(json.dumps(result, sort_keys=True))
    except (IntegrationError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
