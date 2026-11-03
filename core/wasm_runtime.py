"""Read-only WebAssembly module compilation checks using Node's native parser."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from core import baseline, discovery, workflow

MAX_MODULE_BYTES = discovery.MAX_WASM_METADATA_BYTES
MAX_OUTPUT_BYTES = 4096
_NODE_VERSION = re.compile(r"^v\d+\.\d+\.\d+$")
_COMPILE_SCRIPT = (
    "const fs=require('node:fs');try{new WebAssembly.Module(fs.readFileSync(process.argv[1]));"
    "process.stdout.write(JSON.stringify({status:'compiled'}));}catch(e){"
    "process.stdout.write(JSON.stringify({status:'compile_rejected',error:e.name||'CompileError'}));}"
)


def _open_dir_nofollow(path: Path) -> int:
    if (not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0)
            or os.open not in os.supports_dir_fd or not path.is_absolute()):
        raise workflow.WorkflowError("Safe no-follow directory-relative WASM reads are unavailable")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _bounded(command: list[str], cwd: Path, timeout: float,
             env: dict[str, str]) -> tuple[int | None, bytes, bytes, bool, bool, bool]:
    return baseline._run_command(command, cwd, timeout, env=env, total_output_limit=MAX_OUTPUT_BYTES)


def probe_module(module_path: str | Path, node: str = "node", timeout_seconds: float = 10) -> dict:
    """Compile one bounded WASM file without instantiating it or invoking its code."""
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= 60):
        raise workflow.WorkflowError("WASM probe timeout must be greater than 0 and at most 60 seconds")
    raw = Path(module_path).expanduser()
    if not raw.name or raw.is_symlink() or raw.suffix.lower() != ".wasm":
        raise workflow.WorkflowError("WASM probe requires a regular .wasm file, not a symlink")
    parent_fd = None
    try:
        absolute = raw.absolute()
        parent = absolute.parent
        parent_fd = _open_dir_nofollow(parent)
        fd = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_NONBLOCK", 0),
                     dir_fd=parent_fd)
    except OSError as error:
        if parent_fd is not None:
            os.close(parent_fd)
        raise workflow.WorkflowError(f"WASM module cannot be opened safely: {error}") from error
    try:
        before = os.fstat(fd)
        metadata = before
        if not stat.S_ISREG(metadata.st_mode):
            raise workflow.WorkflowError("WASM probe requires a regular file")
        if metadata.st_size > MAX_MODULE_BYTES:
            raise workflow.WorkflowError(f"WASM module exceeds the {MAX_MODULE_BYTES}-byte probe limit")
        content = bytearray()
        while chunk := os.read(fd, min(1024 * 1024, MAX_MODULE_BYTES + 1 - len(content))):
            content.extend(chunk)
            if len(content) > MAX_MODULE_BYTES:
                raise workflow.WorkflowError(f"WASM module exceeds the {MAX_MODULE_BYTES}-byte probe limit")
        after = os.fstat(fd)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after) or len(content) != before.st_size:
            raise workflow.WorkflowError("WASM module changed while being read")
    finally:
        os.close(fd)
        os.close(parent_fd)

    executable = shutil.which(node)
    if executable is None:
        raise workflow.WorkflowError(f"Node runtime is unavailable: {node}")
    try:
        parsed_imports, parsed_exports = discovery._parse_wasm_metadata(bytes(content))
        parser_error = None
    except discovery.WasmMetadataError as error:
        parsed_imports, parsed_exports, parser_error = [], [], str(error)
    with tempfile.TemporaryDirectory(prefix="anti-rea-wasm-probe-") as scratch:
        root = Path(scratch)
        # Do not let ambient Node or dynamic-loader options inject code into this compile-only check.
        env = {"PATH": os.defpath, "HOME": str(root), "TMPDIR": str(root),
               "TMP": str(root), "TEMP": str(root), "LANG": "C"}
        version_code, version_out, _version_err, version_timeout, version_out_truncated, version_err_truncated = _bounded(
            [executable, "--version"], root, min(float(timeout_seconds), 10), env)
        version = version_out.decode("ascii", errors="replace").strip()
        if (version_code != 0 or version_timeout or version_out_truncated or version_err_truncated
                or not _NODE_VERSION.fullmatch(version)):
            raise workflow.WorkflowError("Node version probe failed or returned an invalid identity")
        candidate = root / "module.wasm"
        candidate.write_bytes(content)
        code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = _bounded(
            [executable, "-e", _COMPILE_SCRIPT, str(candidate)], root, float(timeout_seconds), env)
    if timed_out:
        return {"status": "timed_out", "module_path": str(raw),
                "module_sha256": hashlib.sha256(content).hexdigest(), "module_bytes": len(content),
                "node_version": version, "verification_scope": "compile_only_no_instantiation"}
    if code is None or code != 0 or stdout_truncated or stderr_truncated:
        return {"status": "probe_failed", "module_path": str(raw),
                "module_sha256": hashlib.sha256(content).hexdigest(), "module_bytes": len(content),
                "node_version": version, "verification_scope": "compile_only_no_instantiation",
                "error": "bounded Node probe failed"}
    try:
        result = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError("Node WASM probe returned invalid JSON") from error
    if not isinstance(result, dict) or result.get("status") not in {"compiled", "compile_rejected"}:
        raise workflow.WorkflowError("Node WASM probe returned an invalid result")
    identity = {"module_path": str(raw), "module_sha256": hashlib.sha256(content).hexdigest(),
                "module_bytes": len(content), "node_version": version,
                "verification_scope": "compile_only_no_instantiation"}
    if result["status"] == "compile_rejected":
        return {**identity, "status": "compile_rejected", "compile_error": result.get("error", "CompileError"),
                **({"parser_error": parser_error} if parser_error else {})}
    return {**identity, "status": "compiled", "imports": parsed_imports,
            "exports": parsed_exports, "metadata_source": "anti_rea_static_parser",
            **({"parser_error": parser_error} if parser_error else {})}
