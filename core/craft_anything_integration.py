"""Read-only adapter for the pinned Craft Anything CLI triage command."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path

from core import baseline, workflow

PINNED_VERSION = "0.6.0"
MAX_OUTPUT_BYTES = 8 * 1024 * 1024


def _tree_hash(path: Path) -> str:
    """Hash a regular file or an entire directory without following links."""
    if path.is_symlink():
        raise workflow.WorkflowError("Craft Anything target must not be a symlink")
    digest = hashlib.sha256()
    if path.is_file():
        paths = [(path, path.name)]
    elif path.is_dir():
        paths = []
        for item in sorted(path.rglob("*")):
            if item.is_symlink():
                raise workflow.WorkflowError("Craft Anything target contains a symlink")
            if item.is_dir():
                continue
            if not item.is_file():
                raise workflow.WorkflowError(
                    "Craft Anything target contains a special file"
                )
            paths.append((item, item.relative_to(path).as_posix()))
    else:
        raise workflow.WorkflowError(
            "Craft Anything target must be a regular file or directory"
        )
    for item, relative in paths:
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        file_hash = hashlib.sha256()
        with item.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                file_hash.update(chunk)
        digest.update(file_hash.digest())
    return digest.hexdigest()


def _version(
    cli: str, timeout: float, cancel_event=None, on_process=None
) -> tuple[str | None, str | None]:
    try:
        code, stdout, stderr, timed_out, truncated, _ = baseline._run_command(
            [cli, "--version"],
            Path.cwd(),
            timeout,
            on_process,
            cancel_event,
            total_output_limit=MAX_OUTPUT_BYTES,
        )
    except (OSError, workflow.WorkflowError) as error:
        return None, str(error)
    if timed_out or truncated or code != 0:
        return None, "Craft Anything version probe timed out or failed"
    output = stdout.decode("utf-8", errors="replace").strip()
    match = re.fullmatch(r"(?:craft-anything-cli\s+)?v?(\d+\.\d+\.\d+)", output)
    if not match:
        return None, "Craft Anything returned an invalid version string"
    return match.group(1), None


def probe(
    cli: str | None = None, timeout: float = 10, cancel_event=None, on_process=None
) -> dict:
    """Check whether the locally installed pinned CLI is available."""
    executable = shutil.which(cli) if cli else shutil.which("craft-anything-cli")
    if not executable:
        return {
            "status": "unavailable",
            "reason": "craft-anything-cli is not installed or executable",
        }
    version, error = _version(executable, timeout, cancel_event, on_process)
    if error:
        return {"status": "failed", "executable": executable, "reason": error}
    if version != PINNED_VERSION:
        return {
            "status": "unavailable",
            "executable": executable,
            "version": version,
            "reason": f"requires Craft Anything CLI {PINNED_VERSION}",
        }
    return {
        "status": "supported",
        "executable": str(Path(executable).resolve()),
        "version": version,
    }


def analyze(
    snapshot: str | Path,
    workspace: str | Path,
    *,
    timeout: float = 600,
    cli: str | None = None,
    report_path: str | Path | None = None,
    cancel_event=None,
    on_process=None,
) -> dict:
    """Run pinned read-only triage and retain its JSON evidence in an isolated project."""
    target_input = Path(snapshot).expanduser().absolute()
    if target_input.is_symlink():
        raise workflow.WorkflowError("Craft Anything target must not be a symlink")
    target = target_input.resolve(strict=True)
    report = (
        Path(report_path).expanduser().absolute() if report_path is not None else None
    )
    if report is not None and (
        report == target or report in target.parents or target in report.parents
    ):
        raise workflow.WorkflowError(
            "Craft Anything report must be outside the target tree"
        )
    external = Path(workspace).expanduser().absolute()
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or timeout <= 0
    ):
        raise workflow.WorkflowError("Craft Anything timeout must be positive")
    before_hash = _tree_hash(target)
    available = probe(cli, min(timeout, 10), cancel_event, on_process)
    result = {
        "schema_version": "1.0",
        "engine": "craft_anything",
        "mode": "deep",
        "status": available["status"],
        "input": {"path": str(target), "sha256": before_hash},
        "version": available.get("version"),
        "evidence": None,
    }
    if available["status"] != "supported":
        result["error"] = available.get("reason")
        result["cancelled"] = bool(cancel_event and cancel_event.is_set())
        return result
    if external == target or external in target.parents or target in external.parents:
        raise workflow.WorkflowError(
            "Craft Anything workspace must be outside the target tree"
        )
    external.mkdir(mode=0o700, parents=True, exist_ok=True)
    external = external.resolve(strict=True)
    if external == target or external in target.parents or target in external.parents:
        raise workflow.WorkflowError(
            "Craft Anything workspace must be outside the target tree"
        )
    run_dir = Path(tempfile.mkdtemp(prefix="anti-rea-craft-", dir=external))
    run_dir.chmod(stat.S_IRWXU)
    project = run_dir / "investigation.cany"
    project.mkdir(mode=0o700)
    result["project"] = str(project)
    argv = [
        available["executable"],
        "--deep",
        "--project",
        str(project),
        "--output-format",
        "json",
        "triage",
        str(target),
    ]
    try:
        code, stdout, stderr, timed_out, truncated, _ = baseline._run_command(
            argv,
            external,
            timeout,
            on_process,
            cancel_event,
            total_output_limit=MAX_OUTPUT_BYTES,
        )
    except (OSError, workflow.WorkflowError) as error:
        cancelled = (
            isinstance(error, workflow.WorkflowError)
            and "cancelled" in str(error).lower()
        )
        result.update(status="failed", error=str(error), cancelled=cancelled)
        code, stdout, stderr, timed_out, truncated = None, b"", b"", False, False
    result["command"] = argv
    result["stderr"] = stderr.decode("utf-8", errors="replace")[-4000:]
    if timed_out:
        result.update(status="failed", error="Craft Anything triage timed out")
    elif truncated:
        result.update(status="failed", error="Craft Anything output exceeded the limit")
    elif code is not None:
        try:
            evidence = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            result.update(status="failed", error="Craft Anything returned invalid JSON")
        else:
            result["evidence"] = evidence
            normalized = json.dumps(
                evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode()
            result["evidence_json"] = normalized.decode("utf-8")
            result["evidence_sha256"] = hashlib.sha256(normalized).hexdigest()
            if report is not None:
                report.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(
                        dir=report.parent, prefix=f".{report.name}.", delete=False
                    ) as stream:
                        temporary = Path(stream.name)
                        os.chmod(temporary, 0o600)
                        stream.write(normalized)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, report)
                    result["evidence_path"] = str(report)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
            if (
                code != 0
                or not isinstance(evidence, (dict, list))
                or (isinstance(evidence, dict) and "error" in evidence)
            ):
                result.update(
                    status="failed", error="Craft Anything triage returned an error"
                )
            else:
                result["status"] = _evidence_status(evidence)
    try:
        after_hash = _tree_hash(target)
        result["input"]["sha256_after"] = after_hash
        if after_hash != before_hash:
            result.update(
                status="failed", error="Craft Anything modified the input target"
            )
    except (OSError, workflow.WorkflowError) as error:
        result.update(
            status="failed", error=f"Could not verify target integrity: {error}"
        )
    return result


def _evidence_status(evidence) -> str:
    """Honor explicit partial/unsupported signals without interpreting engine scores."""
    if isinstance(evidence, list):
        states = [_evidence_status(item) for item in evidence if isinstance(item, dict)]
        return (
            "partial" if "partial" in states or "unavailable" in states else "supported"
        )
    state = str(evidence.get("status", "")).lower()
    if state in {"partial", "incomplete"}:
        return "partial"
    if state in {"unsupported", "unavailable", "not_supported"}:
        return "unavailable"
    coverage = evidence.get("coverage")
    if (
        isinstance(coverage, (int, float))
        and not isinstance(coverage, bool)
        and coverage < 1
    ):
        return "partial"
    return "supported"
