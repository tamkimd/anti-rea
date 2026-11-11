#!/usr/bin/env python3
"""Probe Craft Anything and run static JavaScript analysis without modifying targets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import sysconfig
import tempfile
from pathlib import Path

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

ENGINE = "craft-anything"
DEFAULT_TIMEOUT = 10
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
VERSION_RE = re.compile(
    r"(?:craft-anything-cli\s+)?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\Z"
)
SUPPORTED_SUFFIXES = {".asar", ".cjs", ".html", ".js", ".mjs", ".zip"}
MAX_INPUT_FILES = 20_000
MAX_INPUT_BYTES = 512 * 1024 * 1024


def _file_sha256(stream) -> bytes:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.digest()


def _run(command: list[str], timeout: float, env: dict[str, str] | None = None) -> dict:
    code, stdout, stderr, timed_out, out_truncated, err_truncated = (
        baseline_capture._run_command(
            command,
            Path.cwd(),
            timeout,
            env=env,
            total_output_limit=MAX_OUTPUT_BYTES,
            cleanup_grace=2,
        )
    )
    if timed_out:
        return {"status": "timeout", "reason": f"Command timed out after {timeout:g}s"}
    if out_truncated or err_truncated:
        return {"status": "failed", "reason": "CLI output exceeded 16 MiB"}
    try:
        out = stdout.decode("utf-8", errors="strict")
        err = stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return {"status": "failed", "reason": "CLI output was not valid UTF-8"}
    return {
        "status": "ok" if code == 0 else "failed",
        "returncode": code,
        "stdout": out,
        "stderr": err,
    }


def resolve_executable(executable: str | Path | None = None) -> Path | None:
    value = str(executable) if executable is not None else "craft-anything-cli"
    found = shutil.which(value) if not Path(value).is_absolute() else value
    if not found:
        return None
    path = Path(found).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        return None
    return resolved


def _validated_timeout(timeout: float) -> float:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout <= 300
    ):
        raise ValueError("timeout must be greater than 0 and at most 300 seconds")
    return float(timeout)


def _parse_version(stdout: str) -> str | None:
    for line in stdout.splitlines():
        match = VERSION_RE.fullmatch(line.strip())
        if match:
            return match.group(1)
    return None


def _javascript_capability(document: object) -> tuple[bool, str | None]:
    if not isinstance(document, dict):
        return False, "Capabilities output must be a JSON object"
    if document.get("analysis_mode") != "deep":
        return False, "Craft Anything did not confirm Deep analysis mode"
    toolsets = document.get("toolsets")
    if not isinstance(toolsets, list):
        return False, "Capabilities output has no toolset list"
    for toolset in toolsets:
        if not isinstance(toolset, dict) or toolset.get("id") != "javascript":
            continue
        tools = toolset.get("tools")
        if not isinstance(tools, list):
            return False, "JavaScript toolset has no tool list"
        for tool in tools:
            if isinstance(tool, dict) and tool.get("tool") == "js_app_map":
                if tool.get("available") is True:
                    return True, None
                return False, str(tool.get("reason") or "js_app_map is unavailable")
    return False, "Craft Anything does not expose the JavaScript app-map tool"


def probe(
    executable: str | Path | None = None,
    *,
    expected_version: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Check only the installed CLI version and its declared deep-JavaScript capability."""
    try:
        timeout = _validated_timeout(timeout)
    except ValueError as error:
        return {"engine": ENGINE, "status": "failed", "reason": str(error)}
    path = resolve_executable(executable)
    if path is None:
        return {
            "engine": ENGINE,
            "status": "unavailable",
            "reason": "craft-anything-cli was not found or is not executable",
        }

    version_result = _run([str(path), "--version"], timeout)
    if version_result["status"] != "ok":
        return {"engine": ENGINE, **version_result, "operation": "version"}
    version = _parse_version(version_result["stdout"])
    if version is None:
        return {
            "engine": ENGINE,
            "status": "failed",
            "operation": "version",
            "reason": "CLI returned an unrecognized version",
        }
    if expected_version is not None and version != expected_version:
        return {
            "engine": ENGINE,
            "status": "unavailable",
            "version": version,
            "reason": f"Expected Craft Anything {expected_version}, found {version}",
        }

    capabilities_result = _run(
        [str(path), "--deep", "--format", "json", "capabilities"], timeout
    )
    if capabilities_result["status"] != "ok":
        return {
            "engine": ENGINE,
            "version": version,
            **capabilities_result,
            "operation": "capabilities",
        }
    try:
        capabilities = json.loads(capabilities_result["stdout"])
    except json.JSONDecodeError:
        return {
            "engine": ENGINE,
            "version": version,
            "status": "failed",
            "operation": "capabilities",
            "reason": "Capabilities output was not valid JSON",
        }
    if isinstance(capabilities, dict) and capabilities.get("version") not in {
        None,
        version,
    }:
        return {
            "engine": ENGINE,
            "version": version,
            "status": "failed",
            "operation": "capabilities",
            "reason": "CLI version and capability version do not match",
        }
    supported, reason = _javascript_capability(capabilities)
    return {
        "engine": ENGINE,
        "version": version,
        "mode": "deep",
        "status": "ready" if supported else "unsupported",
        "supports_javascript_application": supported,
        **({} if reason is None else {"reason": reason}),
        "capabilities_sha256": hashlib.sha256(
            json.dumps(capabilities, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _input_kind(path: Path) -> tuple[str | None, str | None]:
    if path.is_symlink():
        return None, "Symlink targets are not supported"
    if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
        return "file", None
    if path.is_dir():
        found_javascript = False
        file_count = 0
        total_bytes = 0
        for current, dirs, files in os.walk(path, followlinks=False):
            base = Path(current)
            if any((base / name).is_symlink() for name in dirs + files):
                return None, "Input directories containing symlinks are not supported"
            dirs[:] = sorted(dirs)
            file_count += len(files)
            for name in files:
                try:
                    entry = base / name
                    if entry.is_symlink():
                        return (
                            None,
                            "Input directories containing symlinks are not supported",
                        )
                    total_bytes += entry.stat().st_size
                except OSError:
                    return None, "Input directory changed while it was being inspected"
            if file_count > MAX_INPUT_FILES or total_bytes > MAX_INPUT_BYTES:
                return (
                    None,
                    "Input exceeds Craft Anything's 20,000-file / 512 MiB analysis budget",
                )
            if any(
                Path(name).suffix.lower() in {".js", ".mjs", ".cjs"} for name in files
            ):
                found_javascript = True
        if found_javascript:
            return "directory", None
        return None, "Directory contains no JavaScript bundles"
    return (
        None,
        "Craft Anything JavaScript analysis supports JS/HTML files, ASAR/ZIP archives, or directories containing JS files",
    )


def _hash_input(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_file():
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as stream:
            digest.update(_file_sha256(stream))
        return digest.hexdigest()
    file_count = 0
    total_bytes = 0
    for current, dirs, files in os.walk(path, followlinks=False):
        base = Path(current)
        dirs[:] = sorted(dirs)
        for name in sorted(files):
            file_path = base / name
            if file_path.is_symlink() or not file_path.is_file():
                raise OSError("Input contains a non-regular file")
            metadata = file_path.stat()
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > MAX_INPUT_FILES or total_bytes > MAX_INPUT_BYTES:
                raise OSError("Input exceeds analysis budget")
            relative = file_path.relative_to(path).as_posix()
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            with file_path.open("rb") as stream:
                digest.update(_file_sha256(stream))
            digest.update(b"\0")
    return digest.hexdigest()


def _valid_analysis(document: object) -> tuple[bool, dict | None, str | None]:
    if not isinstance(document, dict):
        return False, None, "Analysis output must be a JSON object"
    if document.get("operation") != "js_app_map":
        return False, None, "Analysis output did not identify the js_app_map operation"
    coverage = document.get("coverage")
    result = document.get("result")
    if not isinstance(coverage, dict) or not isinstance(result, dict):
        return False, None, "Analysis output is missing structured result or coverage"
    if any(
        key in result and not isinstance(result[key], list)
        for key in ("endpoints", "routes", "ipc", "source_maps")
    ):
        return False, None, "Analysis candidate collections must be arrays"
    status = coverage.get("status")
    examined, total = coverage.get("examined"), coverage.get("total")
    if status not in {"complete", "partial", "page"}:
        return False, None, "Analysis output has an unrecognized coverage status"
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (examined, total)
    ):
        return False, None, "Analysis coverage counts are invalid"
    if total < 1 or examined > total or (status == "complete" and examined != total):
        return (
            False,
            None,
            "Analysis coverage counts do not support the declared status",
        )
    return True, document, None


def analyze(
    input_path: str | Path,
    *,
    executable: str | Path | None = None,
    expected_version: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    project_path: str | Path | None = None,
) -> dict:
    """Run Craft Anything's documented static JavaScript app-map analysis."""
    try:
        timeout = _validated_timeout(timeout)
    except ValueError as error:
        return {
            "engine": ENGINE,
            "status": "partial",
            "mode": "deep",
            "reason": str(error),
        }
    path = Path(input_path).expanduser()
    lexical = Path(os.path.abspath(path))
    if lexical.is_symlink():
        return {
            "engine": ENGINE,
            "status": "unsupported",
            "mode": "deep",
            "input_path": str(lexical),
            "reason": "Symlink inputs are not supported",
        }
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return {
            "engine": ENGINE,
            "status": "unsupported",
            "mode": "deep",
            "reason": "Input path does not exist",
        }
    kind, reason = _input_kind(resolved)
    if reason:
        return {
            "engine": ENGINE,
            "status": "unsupported",
            "mode": "deep",
            "input_path": str(resolved),
            "reason": reason,
        }

    try:
        input_hash = _hash_input(resolved)
    except OSError as error:
        return {
            "engine": ENGINE,
            "status": "partial",
            "mode": "deep",
            "input_path": str(resolved),
            "reason": str(error),
        }
    readiness = probe(executable, expected_version=expected_version, timeout=timeout)
    result = {
        "engine": ENGINE,
        "version": readiness.get("version"),
        "mode": "deep",
        "input_path": str(resolved),
        "input_sha256": input_hash,
        "input_kind": kind,
        "coverage": {
            "status": "unavailable",
            "basis": "no Craft Anything analysis was run",
        },
        "status": "partial",
        "readiness": readiness,
        "evidence": None,
    }
    if readiness.get("status") != "ready":
        result["reason"] = readiness.get(
            "reason", "Craft Anything analysis is unavailable"
        )
        result["engine_status"] = readiness.get("status", "unavailable")
        return result

    def run_analysis(project: Path) -> dict:
        cli_path = resolve_executable(executable)
        if cli_path is None:
            return {
                "status": "failed",
                "reason": "craft-anything-cli became unavailable after probing",
            }
        command = [
            str(cli_path),
            "--json",
            "--deep",
            "--project",
            str(project),
            "js-app-map",
            "--input-path",
            str(resolved),
            "--output-format",
            "json",
        ]
        return _run(command, timeout)

    try:
        if project_path is None:
            with tempfile.TemporaryDirectory(prefix="anti-rea-craft-") as temp_dir:
                project = Path(temp_dir) / "analysis.cany"
                analysis_result = run_analysis(project)
        else:
            project = Path(project_path).expanduser().resolve()
            analysis_result = run_analysis(project)
    except OSError as error:
        result["reason"] = f"Could not run Craft Anything analysis: {error}"
        result["engine_status"] = "failed"
        return result
    if analysis_result["status"] != "ok":
        result["reason"] = analysis_result.get(
            "reason", "Craft Anything analysis command failed"
        )
        result["engine_status"] = analysis_result["status"]
        if "returncode" in analysis_result:
            result["returncode"] = analysis_result["returncode"]
        return result
    try:
        document = json.loads(analysis_result["stdout"])
    except json.JSONDecodeError:
        result["reason"] = "Analysis output was not valid JSON"
        result["engine_status"] = "failed"
        return result
    valid, evidence, validation_error = _valid_analysis(document)
    if not valid:
        result["reason"] = validation_error
        result["engine_status"] = "failed"
        return result
    result["evidence"] = evidence
    result["coverage"] = evidence["coverage"]
    result["engine_status"] = (
        "complete" if evidence["coverage"]["status"] == "complete" else "partial"
    )
    result["status"] = result["engine_status"]
    try:
        result["input_sha256_after"] = _hash_input(resolved)
        result["input_unchanged"] = result["input_sha256_after"] == input_hash
    except OSError:
        result["input_unchanged"] = False
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_probe = sub.add_parser(
        "probe", help="probe the installed CLI and deep JavaScript capability"
    )
    p_probe.add_argument("--executable")
    p_probe.add_argument("--expected-version")
    p_probe.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p_analyze = sub.add_parser(
        "analyze", help="record Craft Anything availability for a JavaScript artifact"
    )
    p_analyze.add_argument("input_path")
    p_analyze.add_argument("--executable")
    p_analyze.add_argument("--expected-version")
    p_analyze.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p_analyze.add_argument("--project")
    args = parser.parse_args(argv)
    result = (
        probe(
            args.executable,
            expected_version=args.expected_version,
            timeout=args.timeout,
        )
        if args.command == "probe"
        else analyze(
            args.input_path,
            executable=args.executable,
            expected_version=args.expected_version,
            timeout=args.timeout,
            project_path=args.project,
        )
    )
    print(json.dumps(result, sort_keys=True))
    return (
        0
        if result.get("status") in {"ready", "unsupported", "complete", "partial"}
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
