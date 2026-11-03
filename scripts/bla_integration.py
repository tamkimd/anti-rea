#!/usr/bin/env python3
"""Bootstrap and inspect the pinned BLA runtime without harness or target setup."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "locks/upstreams.json").is_file():
    ROOT = Path(sysconfig.get_path("data")) / "share/anti-rea"
sys.path.insert(0, str(ROOT))
from scripts import rea_integration as runner  # noqa: E402

PIN = json.loads((ROOT / "locks/upstreams.json").read_text())["integrations"]["bla"]
MAX_SOURCE_BYTES = 1024 * 1024
MAX_CANDIDATE_BYTES = 64 * 1024 * 1024


class IntegrationError(RuntimeError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def supported_node(parts):
    return (parts[0] == 22 and parts >= (22, 23, 4)) or parts[0] >= 24


def npm_version():
    return runner._tool_version("npm")


def verify_runtime(runtime):
    runtime = Path(runtime).expanduser()
    if runtime.is_symlink():
        raise IntegrationError("BLA runtime directory symlink refused")
    runtime = runtime.resolve(strict=True)
    lock = runtime / "package-lock.json"
    marker = runtime / "anti-rea-bla-runtime.json"
    if not lock.is_file() or sha(lock.read_bytes()) != PIN["package_lock_sha256"]:
        raise IntegrationError("BLA runtime lock does not match the pinned lock hash")
    manifest = json.loads(marker.read_text())
    package = runtime / "node_modules/bla-agents"
    metadata = json.loads((package / "package.json").read_text())
    if (
        metadata.get("version") != PIN["npm_version"]
        or manifest.get("package_lock_sha256") != PIN["package_lock_sha256"]
        or runner.package_tree_hash(package) != manifest.get("package_tree_sha256")
    ):
        raise IntegrationError("BLA package or runtime manifest identity mismatch")
    return runtime, manifest


def bootstrap(runtime):
    version, parts = runner.node_version()
    if not supported_node(parts):
        raise IntegrationError(
            f"Pinned BLA requires Node {PIN['node_requirement']}; found {version}"
        )
    runtime = Path(runtime).expanduser().absolute()
    if runtime.exists() or runtime.is_symlink():
        raise IntegrationError("Choose a new, empty BLA runtime directory")
    runtime.parent.mkdir(parents=True, exist_ok=True)
    owned = False
    try:
        runtime.mkdir(mode=0o700)
        owned = True
        shutil.copy2(ROOT / "integrations/bla/package.json", runtime / "package.json")
        shutil.copy2(ROOT / PIN["package_lock"], runtime / "package-lock.json")
        result = runner.run_bounded(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            runtime,
            900,
            8 * 1024 * 1024,
            8 * 1024 * 1024,
            writable_cwd=True,
            network=True,
        )
        if result.returncode:
            raise IntegrationError(f"npm ci failed: {result.stderr[-2000:]}")
        package = runtime / "node_modules/bla-agents"
        manifest = {
            "schema_version": "1.0",
            "npm_version": PIN["npm_version"],
            "npm_integrity": PIN["npm_integrity"],
            "node_version": version,
            "npm_version_runtime": runner._tool_version("npm"),
            "package_lock_sha256": PIN["package_lock_sha256"],
            "package_tree_sha256": runner.package_tree_hash(package),
            "install_scripts": "disabled",
        }
        marker = runtime / "anti-rea-bla-runtime.json"
        marker.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        marker.chmod(0o600)
        return {"status": "installed", "runtime": str(runtime), "manifest": manifest}
    except BaseException:
        if owned:
            shutil.rmtree(runtime, ignore_errors=True)
        raise


def probe(runtime):
    runtime, manifest = verify_runtime(runtime)
    command = str(runtime / "node_modules/.bin/bla")
    result = runner.run_bounded(
        [command, "--version"], runtime, 30, 1024 * 1024, 1024 * 1024
    )
    if result.returncode:
        raise IntegrationError(f"BLA version probe failed: {result.stderr[-2000:]}")
    if PIN["npm_version"] not in result.stdout:
        raise IntegrationError("BLA CLI version probe did not match the pinned package")
    return {
        "status": "verified",
        "version": PIN["npm_version"],
        "node_version": manifest["node_version"],
        "package_tree_sha256": manifest["package_tree_sha256"],
    }


def cli_help(runtime):
    runtime, _ = verify_runtime(runtime)
    command = str(runtime / "node_modules/.bin/bla")
    result = runner.run_bounded(
        [command, "--help"], runtime, 30, 4 * 1024 * 1024, 1024 * 1024
    )
    if (
        result.returncode
        or "protect" not in result.stdout
        or "audit" not in result.stdout
    ):
        raise IntegrationError("Pinned BLA CLI help was incomplete")
    return {"status": "passed", "commands": result.stdout.splitlines()[:16]}


def _new_output(path):
    path = Path(path).expanduser()
    if (
        path.exists()
        or path.is_symlink()
        or path.parent.is_symlink()
        or not path.parent.is_dir()
    ):
        raise IntegrationError(
            "BLA output must be a new file in an existing real directory"
        )
    return path


def _remove_output(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _save_report(path, payload):
    path = _new_output(path)
    raw = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode()
        + b"\n"
    )
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path.resolve()), "sha256": sha(raw)}


def protect_javascript(
    runtime, source, candidate, report, intensity="balanced", seed="anti-rea"
):
    source = Path(source).expanduser()
    if (
        source.is_symlink()
        or not source.is_file()
        or source.suffix.lower() not in {".js", ".mjs", ".cjs"}
    ):
        raise IntegrationError(
            "BLA adapter accepts only a regular JavaScript source file"
        )
    if source.stat().st_size > MAX_SOURCE_BYTES:
        raise IntegrationError("BLA JavaScript source exceeds the 1 MiB adapter budget")
    original = source.read_bytes()
    source_hash = sha(original)
    candidate = _new_output(candidate)
    report = _new_output(report)
    if candidate.resolve() == source.resolve() or report.resolve() in {
        source.resolve(),
        candidate.resolve(),
    }:
        raise IntegrationError(
            "BLA source, candidate, and report paths must be distinct"
        )
    if intensity not in {"stealth", "balanced", "maximum", "bankrupt"}:
        raise IntegrationError("Unknown BLA intensity")
    if not isinstance(seed, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", seed):
        raise IntegrationError("BLA seed must be a short portable identifier")
    runtime, manifest = verify_runtime(runtime)
    command = [
        str(runtime / "node_modules/.bin/bla"),
        "protect",
        str(source.resolve()),
        "--output",
        str(candidate.resolve()),
        "--intensity",
        intensity,
        "--seed",
        seed,
        "--json",
    ]
    try:
        started = time.perf_counter_ns()
        result = runner.run_bounded(
            command, runtime, 900, 64 * 1024 * 1024, 8 * 1024 * 1024
        )
        elapsed_ms = max(1, (time.perf_counter_ns() - started) // 1_000_000)
        raw_report = {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "runtime_manifest": manifest,
        }
        saved = _save_report(report, raw_report)
        data = json.loads(result.stdout)
        if result.returncode or candidate.is_symlink() or not candidate.is_file():
            raise IntegrationError(
                "BLA protect did not create a regular candidate file"
            )
        if candidate.stat().st_size > MAX_CANDIDATE_BYTES:
            raise IntegrationError("BLA candidate exceeds the 64 MiB adapter budget")
        output_hash = sha(candidate.read_bytes())
        if (
            source.read_bytes() != original
            or data.get("originalSha256") != source_hash
            or data.get("protectedSha256") != output_hash
        ):
            raise IntegrationError(
                "BLA output did not preserve the input or match its reported candidate hash"
            )
    except (
        OSError,
        json.JSONDecodeError,
        AttributeError,
        TypeError,
        IntegrationError,
        subprocess.SubprocessError,
    ) as error:
        try:
            _remove_output(candidate)
        except OSError:
            pass
        if isinstance(error, IntegrationError):
            raise
        raise IntegrationError("BLA protect returned invalid output") from error
    return {
        "status": "passed",
        "source_sha256": source_hash,
        "candidate_sha256": output_hash,
        "candidate_bytes": candidate.stat().st_size,
        "elapsed_ms": elapsed_ms,
        "intensity": intensity,
        "seed": seed,
        "report": saved,
    }


def verify_javascript(runtime, original, candidate, report):
    runtime, manifest = verify_runtime(runtime)
    original = Path(original).expanduser()
    candidate = Path(candidate).expanduser()
    if any(path.is_symlink() or not path.is_file() for path in (original, candidate)):
        raise IntegrationError("BLA verification inputs must be regular files")
    report = _new_output(report)
    if report.resolve() in {original.resolve(), candidate.resolve()}:
        raise IntegrationError(
            "BLA report path must be separate from verification inputs"
        )
    command = [
        str(runtime / "node_modules/.bin/bla"),
        "verify",
        str(candidate.resolve()),
        str(original.resolve()),
        "--json",
    ]
    result = runner.run_bounded(
        command, runtime, 300, 32 * 1024 * 1024, 4 * 1024 * 1024
    )
    saved = _save_report(
        report,
        {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "runtime_manifest": manifest,
        },
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise IntegrationError(
            f"BLA verify returned invalid JSON; report retained at {saved['path']}"
        ) from error
    checks = data.get("checks")
    if (
        result.returncode
        or data.get("overallPassed") is not True
        or data.get("functionalIntegrityVerified") is not True
        or not isinstance(checks, list)
        or not checks
        or any(
            not isinstance(check, dict) or check.get("passed") is not True
            for check in checks
        )
    ):
        raise IntegrationError(
            f"BLA verification failed; report retained at {saved['path']}"
        )
    return {
        "status": "passed",
        "check_count": len(checks),
        "source_sha256": sha(original.read_bytes()),
        "candidate_sha256": sha(candidate.read_bytes()),
        "report": saved,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("bootstrap", "verify-runtime", "probe", "cli-help"):
        commands.add_parser(name).add_argument("runtime")
    protect = commands.add_parser(
        "protect-js", help="protect one JS file into a new candidate path"
    )
    protect.add_argument("runtime")
    protect.add_argument("source")
    protect.add_argument("candidate")
    protect.add_argument("report")
    protect.add_argument(
        "--intensity",
        choices=("stealth", "balanced", "maximum", "bankrupt"),
        default="balanced",
    )
    protect.add_argument("--seed", default="anti-rea")
    verify = commands.add_parser(
        "verify-js", help="run BLA's verifier against a protected JS candidate"
    )
    verify.add_argument("runtime")
    verify.add_argument("original")
    verify.add_argument("candidate")
    verify.add_argument("report")
    args = parser.parse_args(argv)
    try:
        if args.command == "bootstrap":
            result = bootstrap(args.runtime)
        elif args.command == "verify-runtime":
            runtime, manifest = verify_runtime(args.runtime)
            result = {
                "status": "verified",
                "runtime": str(runtime),
                "manifest": manifest,
            }
        elif args.command == "probe":
            result = probe(args.runtime)
        elif args.command == "cli-help":
            result = cli_help(args.runtime)
        elif args.command == "protect-js":
            result = protect_javascript(
                args.runtime,
                args.source,
                args.candidate,
                args.report,
                args.intensity,
                args.seed,
            )
        else:
            result = verify_javascript(
                args.runtime, args.original, args.candidate, args.report
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (IntegrationError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
