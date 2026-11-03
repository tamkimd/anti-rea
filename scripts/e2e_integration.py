#!/usr/bin/env python3
"""Prepare and run the pinned tester-army/e2e adapter in isolated directories."""

import argparse
import hashlib
import io
import json
import locale
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import sysconfig
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "locks/upstreams.json").is_file():
    ROOT = Path(sysconfig.get_path("data")) / "share/anti-rea"
try:
    from core import baseline as baseline_capture
except ModuleNotFoundError as error:
    if error.name != "core":
        raise
    sys.path.insert(0, str(ROOT))
    from core import baseline as baseline_capture
PIN = json.loads((ROOT / "locks/upstreams.json").read_text())["integrations"]["e2e"]
PACKAGE_LOCK = ROOT / PIN["package_lock"]
PACKAGES = {
    "e2e": PIN["packages"]["e2e"]["version"],
    "@e2e-dev/web": PIN["packages"]["@e2e-dev/web"]["version"],
    "@e2e-dev/mobile": PIN["packages"]["@e2e-dev/mobile"]["version"],
}
PERFORMANCE_MARKER = "ANTI_REA_PERFORMANCE "


class IntegrationError(RuntimeError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def save_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def node_version():
    value = subprocess.run(
        [node_executable(), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise IntegrationError("Unrecognized Node.js version: " + value)
    return value, tuple(map(int, match.groups()))


def node_executable():
    configured = os.environ.get("ANTI_REA_E2E_NODE")
    executable = (
        Path(configured).expanduser()
        if configured
        else Path(shutil.which("node") or "")
    )
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise IntegrationError(
            "Configured e2e Node executable is missing or not executable"
        )
    return str(executable.resolve(strict=True))


def node_environment(env=None):
    result = dict(os.environ if env is None else env)
    node_dir = str(Path(node_executable()).parent)
    result["PATH"] = node_dir + os.pathsep + result.get("PATH", "")
    return result


def npm_version():
    return subprocess.run(
        ["npm", "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env=node_environment(),
    ).stdout.strip()


def require_supported_node():
    version, parts = node_version()
    if not (
        (parts[0] == 22 and parts >= (22, 22, 3))
        or parts[0] >= 24
        and parts >= (24, 8, 0)
    ):
        raise IntegrationError(
            f"Pinned e2e runtime requires {PIN['node_requirement']}; found {version}"
        )
    return version


def run_bounded(command, cwd, timeout, env=None):
    processes = []
    previous_term = signal.getsignal(signal.SIGTERM)

    def group_exists():
        if os.name != "posix" or not processes:
            return False
        try:
            os.killpg(processes[0].pid, 0)
            return True
        except ProcessLookupError:
            return False

    def terminate(signum, frame):
        raise IntegrationError("Command cancelled")

    signal.signal(signal.SIGTERM, terminate)
    try:
        code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
            baseline_capture._run_command(
                command,
                Path(cwd),
                timeout,
                on_start=processes.append,
                env=env,
                total_output_limit=8 * 1024 * 1024,
                cleanup_grace=5,
            )
        )
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    if timed_out:
        raise IntegrationError(f"Command timed out after {timeout}s: {command[0]}")
    if stdout_truncated or stderr_truncated:
        raise IntegrationError("Command output exceeded 8 MiB")
    if group_exists():
        baseline_capture._stop_process(processes[0], grace_period=5)
        raise IntegrationError("Command left residual child processes")
    encoding = locale.getpreferredencoding(False)
    stdout_text = io.TextIOWrapper(io.BytesIO(stdout), encoding=encoding).read()
    stderr_text = io.TextIOWrapper(io.BytesIO(stderr), encoding=encoding).read()
    return subprocess.CompletedProcess(command, code, stdout_text, stderr_text)


def package_tree_hash(package_dir):
    package_dir = Path(package_dir)
    entries = []
    for current, dirs, files in os.walk(package_dir, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
        base = Path(current)
        for name in sorted(dirs + files):
            path = base / name
            rel = path.relative_to(package_dir).as_posix()
            if path.is_symlink():
                entries.append({"path": rel, "symlink": os.readlink(path)})
            elif path.is_file():
                entries.append({"path": rel, "sha256": sha(path.read_bytes())})
    return sha(canonical(entries))


def verify_runtime(runtime):
    runtime = Path(runtime).expanduser()
    if runtime.is_symlink():
        raise IntegrationError("Runtime directory symlink refused")
    runtime = runtime.resolve(strict=True)
    lock_path = runtime / "package-lock.json"
    manifest_path = runtime / "anti-rea-e2e-runtime.json"
    if (
        not lock_path.is_file()
        or sha(lock_path.read_bytes()) != PIN["package_lock_sha256"]
    ):
        raise IntegrationError(
            "Runtime lockfile is missing or does not match the pinned lock hash"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("package_lock_sha256") != PIN["package_lock_sha256"]:
        raise IntegrationError("Runtime manifest lock identity mismatch")
    actual = {}
    for name, version in PACKAGES.items():
        package_dir = runtime / "node_modules" / name
        pkg = json.loads((package_dir / "package.json").read_text(encoding="utf-8"))
        if pkg.get("version") != version:
            raise IntegrationError(
                f"Pinned package mismatch for {name}: {pkg.get('version')}"
            )
        actual[name] = {
            "version": version,
            "tree_sha256": package_tree_hash(package_dir),
        }
    if actual != manifest.get("packages"):
        raise IntegrationError(
            "Installed package tree identity differs from the runtime manifest"
        )
    return runtime, manifest


def bootstrap(runtime):
    require_supported_node()
    runtime = Path(runtime).expanduser().absolute()
    if runtime.exists() or runtime.is_symlink():
        raise IntegrationError("Choose a new, empty runtime directory")
    runtime.parent.mkdir(parents=True, exist_ok=True)
    owned = False
    try:
        runtime.mkdir(mode=0o700)
        owned = True
        shutil.copy2(ROOT / "integrations/e2e/package.json", runtime / "package.json")
        shutil.copy2(PACKAGE_LOCK, runtime / "package-lock.json")
        cmd = [
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--legacy-peer-deps",
        ]
        completed = run_bounded(cmd, cwd=runtime, timeout=600, env=node_environment())
        if completed.returncode:
            raise subprocess.CalledProcessError(
                completed.returncode, cmd, completed.stdout, completed.stderr
            )
        packages = {}
        for name, version in PACKAGES.items():
            pkg_dir = runtime / "node_modules" / name
            pkg = json.loads((pkg_dir / "package.json").read_text(encoding="utf-8"))
            if pkg.get("version") != version:
                raise IntegrationError(
                    f"Pinned package mismatch for {name}: {pkg.get('version')}"
                )
            packages[name] = {
                "version": version,
                "tree_sha256": package_tree_hash(pkg_dir),
            }
        manifest = {
            "schema_version": "1.0",
            "source_commit": PIN["source_commit"],
            "packages": packages,
            "node_version": node_version()[0],
            "npm_version": subprocess.run(
                ["npm", "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
                env=node_environment(),
            ).stdout.strip(),
            "package_lock_sha256": PIN["package_lock_sha256"],
            "install_command": cmd,
            "install_scripts": "disabled",
        }
        save_new(runtime / "anti-rea-e2e-runtime.json", manifest)
    except BaseException:
        # The destination was explicitly required to be new and is owned by this bootstrap.
        if owned:
            shutil.rmtree(runtime, ignore_errors=True)
        raise
    return {"status": "ready", "runtime": str(runtime), "manifest": manifest}


def install_browser(runtime, browser="chromium"):
    runtime, manifest = verify_runtime(runtime)
    if browser not in {"chromium", "firefox", "webkit"}:
        raise IntegrationError("Unsupported browser name")
    command = [str(runtime / "node_modules/.bin/e2e-web"), "install", browser]
    completed = run_bounded(command, cwd=runtime, timeout=900, env=node_environment())
    if completed.returncode:
        raise subprocess.CalledProcessError(
            completed.returncode, command, completed.stdout, completed.stderr
        )
    result = {
        "schema_version": "1.0",
        "browser": browser,
        "package_lock_sha256": manifest["package_lock_sha256"],
        "e2e_version": manifest["packages"]["e2e"]["version"],
        "web_engine_version": manifest["packages"]["@e2e-dev/web"]["version"],
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_new(runtime / f"browser-{browser}.json", result)
    return result


def create_fixture(runtime, project, fixture="web"):
    runtime, _ = verify_runtime(runtime)
    if fixture not in {"web", "static-spa", "pwa"}:
        raise IntegrationError("Unknown owned e2e fixture")
    project = Path(project).expanduser()
    if project.exists() or project.is_symlink():
        raise IntegrationError("Fixture destination must be new")
    project = project.parent.resolve() / project.name
    if runtime not in project.parents:
        raise IntegrationError(
            "Fixture project must be inside the isolated runtime directory"
        )
    shutil.copytree(ROOT / "fixtures/e2e" / fixture, project)
    return {
        "status": "created",
        "project": str(project),
        "fixture": f"owned-deterministic-{fixture}",
    }


def _assert_server_stopped(origin):
    parsed = urlparse(origin)
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"} or not parsed.port:
        raise IntegrationError("Fixture runner returned an unexpected app origin")
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=0.25):
            return False
    except OSError:
        return True


def validate_report(report, runtime):
    schema_path = Path(runtime) / "node_modules/e2e/schema/report-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:
        raise IntegrationError(
            "Install Anti-REA's Python package to validate the upstream report schema"
        ) from error
    errors = list(Draft202012Validator(schema).iter_errors(report))
    if errors:
        raise IntegrationError(
            "Upstream report failed report-v1 schema: "
            + "; ".join(e.message for e in errors[:5])
        )


def report_performance_metrics(report):
    values = []
    for result in report.get("run", {}).get("results", []):
        if result.get("kind") != "test" or not result.get("selected"):
            continue
        for attempt in result.get("attempts", []):
            for line in attempt.get("appLog", []):
                if line.get("text", "").startswith(PERFORMANCE_MARKER):
                    try:
                        metric = json.loads(line["text"][len(PERFORMANCE_MARKER) :])
                    except (json.JSONDecodeError, TypeError) as error:
                        raise IntegrationError(
                            "Browser performance marker is invalid JSON"
                        ) from error
                    if set(metric) != {
                        "dom_content_loaded_ms",
                        "load_event_ms",
                        "interaction_ms",
                    } or any(
                        isinstance(x, bool)
                        or not isinstance(x, (int, float))
                        or not 0 <= x < 600000
                        for x in metric.values()
                    ):
                        raise IntegrationError(
                            "Browser performance metrics are outside the accepted contract"
                        )
                    values.append(metric)
    if len(values) > 1:
        raise IntegrationError(
            "Each selected browser test must emit at most one performance sample"
        )
    return values[0] if values else None


def _project_file(project, relative):
    project = Path(project).resolve(strict=True)
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise IntegrationError("e2e config and test paths must stay inside the project")
    current = project
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise IntegrationError(
                "e2e config and test paths must not contain symlinks"
            )
    resolved = current.resolve(strict=True)
    if project not in resolved.parents or not resolved.is_file():
        raise IntegrationError("e2e config and test paths must be project files")
    return path


def run(
    project,
    runtime,
    output,
    stage,
    config="e2e.config.mjs",
    test_file="tests/behavior.e2e.ts",
):
    runtime, manifest = verify_runtime(runtime)
    if require_supported_node() != manifest["node_version"]:
        raise IntegrationError(
            "The active Node.js version differs from the pinned e2e runtime"
        )
    browser_marker = runtime / "browser-chromium.json"
    if browser_marker.is_symlink() or not browser_marker.is_file():
        raise IntegrationError(
            "Pinned Chromium is not prepared; run install-browser first"
        )
    browser = json.loads(browser_marker.read_text(encoding="utf-8"))
    if (
        browser.get("package_lock_sha256") != manifest["package_lock_sha256"]
        or browser.get("web_engine_version") != PACKAGES["@e2e-dev/web"]
    ):
        raise IntegrationError(
            "Chromium install record does not match the pinned e2e runtime"
        )
    project = Path(project).expanduser()
    if project.is_symlink():
        raise IntegrationError("Project directory symlink refused")
    project = project.resolve(strict=True)
    if not project.is_dir():
        raise IntegrationError("Project must be a real directory")
    config = _project_file(project, config)
    test_file = _project_file(project, test_file)
    output = Path(output)
    if output.is_absolute() or ".." in output.parts or not output.parts:
        raise IntegrationError("Output must be a new project-relative directory")
    report_dir = project
    for component in output.parts:
        report_dir = report_dir / component
        if report_dir.is_symlink():
            raise IntegrationError("E2E output path symlink refused")
    if report_dir.exists():
        raise IntegrationError("Each e2e attempt requires a fresh output directory")
    report_dir.parent.mkdir(parents=True, exist_ok=True)
    if stage not in {"before", "after", "fixture"}:
        raise IntegrationError("Stage must be before, after, or fixture")
    node = node_executable()
    command = [
        node,
        str(runtime / "node_modules/e2e/dist/cli/bin.js"),
        "run",
        test_file.as_posix(),
        "--config",
        config.as_posix(),
        "--output",
        output.as_posix(),
        "--workers",
        "1",
        "--retries",
        "0",
        "--reporter",
        "list",
    ]
    try:
        completed = run_bounded(
            command,
            cwd=project,
            timeout=300,
            env=node_environment({**os.environ, "E2E_TELEMETRY_DISABLED": "1"}),
        )
    except IntegrationError as error:
        raise IntegrationError(str(error) + "; process group was terminated") from error
    report_path = report_dir / "report.json"
    if not report_path.is_file():
        raise IntegrationError("e2e did not write a fresh report-1 document")
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    validate_report(report, runtime)
    run_record = report.get("run", {})
    if report.get("schemaVersion") != "report-1" or run_record.get("runner") != {
        "name": "e2e",
        "version": PACKAGES["e2e"],
    }:
        raise IntegrationError("e2e report is incomplete or not from the pinned runner")
    test_ids = sorted(
        item["testId"]
        for item in run_record.get("results", [])
        if item.get("kind") == "test" and item.get("selected")
    )
    if not test_ids:
        raise IntegrationError("e2e report contains no selected behavior tests")
    failed_tests = [
        item
        for item in run_record["results"]
        if item.get("kind") == "test"
        and item.get("selected")
        and item.get("status") != "passed"
    ]
    summary = run_record.get("summary", {})
    if run_record.get("status") == "passed":
        if (
            completed.returncode != 0
            or run_record.get("exitCode") != 0
            or failed_tests
            or summary.get("failed") != 0
            or summary.get("executed") != len(test_ids)
        ):
            raise IntegrationError(
                "e2e passed status is inconsistent with its exit code or selected tests"
            )
        status = "passed"
    elif (
        run_record.get("status") == "failed"
        and completed.returncode != 0
        and run_record.get("exitCode") != 0
        and failed_tests
        and summary.get("failed", 0) > 0
    ):
        status = "failed"
    else:
        raise IntegrationError(
            "e2e report is blocked, interrupted, or inconsistent\n"
            + completed.stdout[-2000:]
            + completed.stderr[-2000:]
        )
    origins = [
        target.get("baseOrigin")
        for target in run_record.get("targets", [])
        if target.get("platform") == "web"
    ]
    cleanup = bool(origins) and all(
        _assert_server_stopped(origin) for origin in origins
    )
    if not cleanup:
        raise IntegrationError(
            "e2e app server is still accepting connections after the run"
        )
    result = {
        "status": status,
        "stage": stage,
        "run_id": run_record.get("id"),
        "report_schema": report["schemaVersion"],
        "report_sha256": sha(report_bytes),
        "report": str(report_path),
        "runner": run_record["runner"],
        "target_engines": [
            target.get("engine") for target in run_record.get("targets", [])
        ],
        "test_ids": test_ids,
        "summary": summary,
        "cleanup": "loopback app port closed",
        "runtime_package_lock_sha256": manifest["package_lock_sha256"],
        "runtime_manifest_sha256": sha(canonical(manifest)),
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    metrics = report_performance_metrics(report)
    if metrics is not None:
        result["performance_metrics"] = metrics
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("bootstrap")
    prepare.add_argument("runtime")
    browser = commands.add_parser("install-browser")
    browser.add_argument("runtime")
    browser.add_argument("--browser", default="chromium")
    fixture = commands.add_parser("fixture")
    fixture.add_argument("runtime")
    fixture.add_argument("project")
    fixture.add_argument("--kind", choices=("web", "static-spa", "pwa"), default="web")
    execute = commands.add_parser("run")
    execute.add_argument("project")
    execute.add_argument("runtime")
    execute.add_argument("output")
    execute.add_argument(
        "--stage", choices=["before", "after", "fixture"], default="fixture"
    )
    execute.add_argument("--config", default="e2e.config.mjs")
    execute.add_argument("--test-file", default="tests/behavior.e2e.ts")
    args = parser.parse_args(argv)
    try:
        if args.command == "bootstrap":
            result = bootstrap(args.runtime)
        elif args.command == "install-browser":
            result = install_browser(args.runtime, args.browser)
        elif args.command == "fixture":
            result = create_fixture(args.runtime, args.project, args.kind)
        else:
            result = run(
                args.project,
                args.runtime,
                args.output,
                args.stage,
                args.config,
                args.test_file,
            )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, IntegrationError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
