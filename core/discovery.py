"""Bounded, read-only project discovery for target manifests."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
from pathlib import Path

from core import workflow

MAX_FILES = 100_000
MAX_ENTRIES = 200_000
MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_DEPTH = 128
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_SCRIPT_TEXT_BYTES = 512 * 1024
MAX_TOTAL_SCRIPT_TEXT_BYTES = 8 * 1024 * 1024
MAX_WORKER_REFERENCES = 4096
MAX_WORKER_REFERENCE_LENGTH = 4096
MAX_FRAMEWORK_HINTS = 256
MAX_WASM_METADATA_BYTES = 8 * 1024 * 1024
MAX_TOTAL_WASM_METADATA_BYTES = 64 * 1024 * 1024
MAX_WASM_MODULES = 128
MAX_WASM_ITEMS = 4096
MAX_WASM_NAME_BYTES = 4096
MAX_WASM_SECTIONS = 4096
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".dart_tool",
    ".gradle",
    ".idea",
    ".cache",
    "node_modules",
    ".venv",
    "venv",
    "Pods",
    "vendor",
    "target",
}
MANIFEST_KINDS = {
    "pubspec.yaml": "dart_or_flutter",
    "package.json": "javascript_or_typescript",
    "Cargo.toml": "rust",
    "go.mod": "go",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "pom.xml": "jvm",
    "build.gradle": "android_or_jvm",
    "build.gradle.kts": "android_or_jvm",
    "Package.swift": "swift",
}
ARTIFACT_SUFFIXES = {
    ".apk",
    ".aab",
    ".ipa",
    ".app",
    ".dylib",
    ".so",
    ".dll",
    ".exe",
    ".wasm",
    ".jar",
    ".class",
    ".dex",
    ".bundle",
    ".zip",
    ".framework",
    ".js",
    ".mjs",
    ".cjs",
    ".map",
}
DIRECTORY_ARTIFACT_SUFFIXES = {".app", ".framework"}
WORKER_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
SCRIPT_SUFFIXES = WORKER_SUFFIXES | {".jsx", ".tsx"}
SERVICE_WORKER_REGISTER = re.compile(
    r"\bserviceWorker\s*\.\s*register\s*\(\s*(['\"])([^'\"\r\n]+)\1\s*(?=,|\))"
)
WORKER_URL_CONSTRUCTOR = re.compile(
    r"\bnew\s+Worker\s*\(\s*new\s+URL\s*\(\s*(['\"])([^'\"\r\n]+)\1\s*,\s*import\.meta\.url\s*\)\s*(?=,|\))"
)
WORKER_LITERAL_CONSTRUCTOR = re.compile(
    r"\bnew\s+Worker\s*\(\s*(['\"])([^'\"\r\n]+)\1\s*(?=,|\))"
)
SSR_FRAMEWORK_PACKAGES = {"next", "nuxt", "@sveltejs/kit", "@remix-run/node"}
OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class DiscoveryError(ValueError):
    pass


def _worker_role(path: str) -> str | None:
    name = Path(path).name.lower()
    suffix = Path(name).suffix
    if suffix not in WORKER_SUFFIXES:
        return None
    stem = name[: -len(suffix)]
    if stem in {"sw", "service-worker", "serviceworker"}:
        return "service_worker_candidate"
    if stem.endswith(".worker"):
        return "web_worker_candidate"
    return None


def _worker_references(
    source_path: str,
    content: str,
    file_paths: set[str],
    component_id: str | None,
    limit: int,
) -> tuple[list[dict], bool]:
    results = []
    patterns = (
        (SERVICE_WORKER_REGISTER, "service_worker_registration"),
        (WORKER_URL_CONSTRUCTOR, "web_worker_constructor"),
        (WORKER_LITERAL_CONSTRUCTOR, "web_worker_constructor"),
    )
    for pattern, kind in patterns:
        for match in pattern.finditer(content):
            if len(results) >= limit:
                return results, True
            reference = match.group(2)
            if len(reference) > MAX_WORKER_REFERENCE_LENGTH:
                return results, True
            resolved_path = None
            status = "unresolved_base_url"
            if pattern is WORKER_URL_CONSTRUCTOR:
                if (
                    reference.startswith(("/", "\\"))
                    or "\\" in reference
                    or ":" in reference
                    or "?" in reference
                    or "#" in reference
                ):
                    status = "unresolved_base_url"
                else:
                    candidate = posixpath.normpath(
                        posixpath.join(posixpath.dirname(source_path), reference)
                    )
                    if candidate != ".." and not candidate.startswith("../"):
                        resolved_path = candidate
                        status = (
                            "resolved_in_inventory"
                            if candidate in file_paths
                            else "not_in_inventory"
                        )
            results.append(
                {
                    "source_path": source_path,
                    "reference": reference,
                    "kind": kind,
                    "resolved_path": resolved_path,
                    "status": status,
                    "basis": "literal regex match only; syntax context and runtime reachability not verified",
                    "component_id": component_id,
                }
            )
    return results, False


class WasmMetadataError(ValueError):
    """A bounded WASM metadata scan could not parse the module completely."""


def _wasm_u32(data: bytes, offset: int, end: int) -> tuple[int, int]:
    value = 0
    for index in range(5):
        if offset >= end:
            raise WasmMetadataError("truncated unsigned LEB128 integer")
        byte = data[offset]
        offset += 1
        if index == 4 and byte & 0xF0:
            raise WasmMetadataError("unsigned LEB128 integer exceeds 32 bits")
        value |= (byte & 0x7F) << (7 * index)
        if byte < 0x80:
            return value, offset
    raise WasmMetadataError("unsigned LEB128 integer exceeds five bytes")


def _wasm_name(data: bytes, offset: int, end: int) -> tuple[str, int]:
    length, offset = _wasm_u32(data, offset, end)
    if length > MAX_WASM_NAME_BYTES or offset + length > end:
        raise WasmMetadataError("name is oversized or truncated")
    try:
        return data[offset : offset + length].decode("utf-8"), offset + length
    except UnicodeDecodeError as error:
        raise WasmMetadataError("name is not valid UTF-8") from error


def _wasm_limits(data: bytes, offset: int, end: int) -> int:
    flags, offset = _wasm_u32(data, offset, end)
    if flags & ~1:
        raise WasmMetadataError("unsupported memory/table limits flags")
    _minimum, offset = _wasm_u32(data, offset, end)
    if flags & 1:
        _maximum, offset = _wasm_u32(data, offset, end)
    return offset


def _wasm_import_type(data: bytes, offset: int, end: int) -> tuple[str, int]:
    if offset >= end:
        raise WasmMetadataError("truncated import descriptor")
    kind = data[offset]
    offset += 1
    names = {0: "function", 1: "table", 2: "memory", 3: "global", 4: "tag"}
    if kind not in names:
        raise WasmMetadataError("unsupported import descriptor kind")
    if kind == 0:
        _type_index, offset = _wasm_u32(data, offset, end)
    elif kind == 1:
        if offset >= end or data[offset] not in {0x70, 0x6F}:
            raise WasmMetadataError("unsupported table reference type")
        offset = _wasm_limits(data, offset + 1, end)
    elif kind == 2:
        offset = _wasm_limits(data, offset, end)
    elif kind == 3:
        if (
            offset + 2 > end
            or data[offset] not in {0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F}
            or data[offset + 1] not in {0, 1}
        ):
            raise WasmMetadataError("unsupported global type")
        offset += 2
    else:
        if offset >= end or data[offset] != 0:
            raise WasmMetadataError("unsupported tag attribute")
        _type_index, offset = _wasm_u32(data, offset + 1, end)
    return names[kind], offset


def _wasm_imports(data: bytes, start: int, end: int) -> list[dict]:
    count, offset = _wasm_u32(data, start, end)
    if count > MAX_WASM_ITEMS:
        raise WasmMetadataError("import count exceeds scan limit")
    results = []
    for _ in range(count):
        module, offset = _wasm_name(data, offset, end)
        name, offset = _wasm_name(data, offset, end)
        kind, offset = _wasm_import_type(data, offset, end)
        results.append({"module": module, "name": name, "kind": kind})
    if offset != end:
        raise WasmMetadataError("import section has trailing bytes")
    return results


def _wasm_exports(data: bytes, start: int, end: int) -> list[dict]:
    count, offset = _wasm_u32(data, start, end)
    if count > MAX_WASM_ITEMS:
        raise WasmMetadataError("export count exceeds scan limit")
    names = {0: "function", 1: "table", 2: "memory", 3: "global", 4: "tag"}
    results = []
    for _ in range(count):
        name, offset = _wasm_name(data, offset, end)
        if offset >= end or data[offset] not in names:
            raise WasmMetadataError("unsupported export descriptor kind")
        kind = names[data[offset]]
        _index, offset = _wasm_u32(data, offset + 1, end)
        results.append({"name": name, "kind": kind})
    if offset != end:
        raise WasmMetadataError("export section has trailing bytes")
    return results


def _parse_wasm_metadata(data: bytes) -> tuple[list[dict], list[dict]]:
    if len(data) < 8 or data[:4] != b"\x00asm":
        raise WasmMetadataError("invalid WebAssembly magic header")
    if data[4:8] != b"\x01\x00\x00\x00":
        raise WasmMetadataError("unsupported WebAssembly binary version")
    imports, exports = [], []
    section_order = {
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
        13: 6,
        6: 7,
        7: 8,
        8: 9,
        9: 10,
        12: 11,
        10: 12,
        11: 13,
    }
    seen = set()
    previous_order = 0
    offset = 8
    sections = 0
    while offset < len(data):
        sections += 1
        if sections > MAX_WASM_SECTIONS:
            raise WasmMetadataError("section count exceeds scan limit")
        section_id = data[offset]
        offset += 1
        if section_id > 13:
            raise WasmMetadataError("unsupported WebAssembly section id")
        if section_id:
            order = section_order[section_id]
            if section_id in seen:
                raise WasmMetadataError("duplicate WebAssembly section")
            if order < previous_order:
                raise WasmMetadataError("WebAssembly sections are out of order")
            seen.add(section_id)
            previous_order = order
        section_size, offset = _wasm_u32(data, offset, len(data))
        end = offset + section_size
        if end > len(data):
            raise WasmMetadataError("section length exceeds module bytes")
        if section_id in {2, 7}:
            if section_id == 2:
                imports = _wasm_imports(data, offset, end)
            else:
                exports = _wasm_exports(data, offset, end)
        offset = end
    return imports, exports


def _git_identity(root: Path) -> dict:
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        return {
            "repository_root": top,
            "commit": commit,
            "dirty": bool(status),
            "dirty_status_sha256": hashlib.sha256(status.encode()).hexdigest(),
        }
    except (OSError, subprocess.SubprocessError):
        return {
            "repository": "not_detected",
            "limitations": ["Git identity unavailable; source revision is unknown."],
        }


def inspect_project(project: str | Path) -> dict:
    """Create a target manifest without executing project commands or following links."""
    if (
        not getattr(os, "O_NOFOLLOW", 0)
        or not getattr(os, "O_DIRECTORY", 0)
        or os.open not in os.supports_dir_fd
    ):
        raise DiscoveryError(
            "Safe no-follow directory-relative discovery is unavailable on this platform"
        )
    lexical = Path(project).expanduser()
    if lexical.is_symlink():
        raise DiscoveryError("Project root symlink refused")
    root = lexical.resolve(strict=True)
    if not root.is_dir():
        raise DiscoveryError("Project root must be a directory")
    files = []
    directory_artifacts = []
    excluded = []
    links = []
    manifest_text = {}
    manifest_scan_incomplete = False
    script_text = {}
    wasm_payloads = {}
    wasm_skip_reasons = {}
    wasm_metadata_scan_incomplete = False
    wasm_module_count = 0
    wasm_scan_bytes = 0
    script_text_bytes = 0
    script_scan_incomplete = False
    total_bytes = 0
    entries = 0

    def walk(directory_fd: int, relative: Path, depth: int) -> None:
        nonlocal total_bytes, entries, script_text_bytes, script_scan_incomplete
        nonlocal wasm_metadata_scan_incomplete, wasm_module_count, wasm_scan_bytes
        nonlocal manifest_scan_incomplete
        if depth > MAX_DEPTH:
            raise DiscoveryError("Project exceeds directory depth budget")
        names = []
        with os.scandir(directory_fd) as listing:
            for item in listing:
                entries += 1
                if entries > MAX_ENTRIES:
                    raise DiscoveryError("Project exceeds directory entry budget")
                names.append(item.name)
        for name in sorted(names):
            path = relative / name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                links.append(path.as_posix())
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if Path(name).suffix.lower() in DIRECTORY_ARTIFACT_SUFFIXES:
                    directory_artifacts.append(path.as_posix())
                if name in EXCLUDED_DIRS:
                    excluded.append(
                        {
                            "path": path.as_posix(),
                            "reason": "generated or installed dependency tree",
                        }
                    )
                    continue
                child_fd = os.open(
                    name, OPEN_FLAGS | os.O_DIRECTORY, dir_fd=directory_fd
                )
                try:
                    walk(child_fd, path, depth + 1)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                excluded.append(
                    {"path": path.as_posix(), "reason": "non-regular filesystem entry"}
                )
                continue
            if len(files) >= MAX_FILES or total_bytes + metadata.st_size > MAX_BYTES:
                raise DiscoveryError("Project exceeds file or byte inventory budget")
            fd = os.open(name, OPEN_FLAGS | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise DiscoveryError(
                        f"File changed type during discovery: {path.as_posix()}"
                    )
                hasher = hashlib.sha256()
                recognized_manifest = Path(name).name in MANIFEST_KINDS
                is_manifest = (
                    recognized_manifest and before.st_size <= MAX_MANIFEST_BYTES
                )
                if recognized_manifest and before.st_size > MAX_MANIFEST_BYTES:
                    manifest_scan_incomplete = True
                is_script = Path(name).suffix.lower() in SCRIPT_SUFFIXES
                is_wasm = Path(name).suffix.lower() == ".wasm"
                capture_wasm = False
                if is_wasm:
                    wasm_module_count += 1
                    if wasm_module_count > MAX_WASM_MODULES:
                        wasm_metadata_scan_incomplete = True
                    elif before.st_size > MAX_WASM_METADATA_BYTES:
                        wasm_skip_reasons[path.as_posix()] = (
                            "module exceeds the per-file metadata scan limit"
                        )
                        wasm_metadata_scan_incomplete = True
                    elif (
                        wasm_scan_bytes + before.st_size > MAX_TOTAL_WASM_METADATA_BYTES
                    ):
                        wasm_skip_reasons[path.as_posix()] = (
                            "aggregate WebAssembly metadata scan limit reached"
                        )
                        wasm_metadata_scan_incomplete = True
                    else:
                        capture_wasm = True
                        wasm_scan_bytes += before.st_size
                capture_script = (
                    is_script
                    and before.st_size <= MAX_SCRIPT_TEXT_BYTES
                    and script_text_bytes + before.st_size
                    <= MAX_TOTAL_SCRIPT_TEXT_BYTES
                )
                content_limit = (
                    MAX_MANIFEST_BYTES
                    if is_manifest
                    else MAX_SCRIPT_TEXT_BYTES
                    if capture_script
                    else MAX_WASM_METADATA_BYTES
                )
                content = (
                    bytearray()
                    if is_manifest or capture_script or capture_wasm
                    else None
                )
                if is_script and not capture_script:
                    script_scan_incomplete = True
                size = 0
                while True:
                    chunk = os.read(
                        fd, min(1024 * 1024, MAX_BYTES - total_bytes - size + 1)
                    )
                    if not chunk:
                        break
                    size += len(chunk)
                    if total_bytes + size > MAX_BYTES:
                        raise DiscoveryError("Project exceeds byte inventory budget")
                    hasher.update(chunk)
                    if content is not None:
                        if len(content) + len(chunk) > content_limit:
                            content = None
                        else:
                            content.extend(chunk)
                after = os.fstat(fd)

                def ident(st):
                    return (
                        st.st_dev,
                        st.st_ino,
                        st.st_size,
                        st.st_mtime_ns,
                        st.st_ctime_ns,
                    )

                if ident(before) != ident(after) or size != before.st_size:
                    raise DiscoveryError(
                        f"File changed during discovery: {path.as_posix()}"
                    )
            finally:
                os.close(fd)
            total_bytes += size
            entry = {
                "path": path.as_posix(),
                "size": size,
                "sha256": hasher.hexdigest(),
                "mode": stat.S_IMODE(before.st_mode) & 0o777,
            }
            files.append(entry)
            if content is not None:
                if is_wasm and capture_wasm:
                    wasm_payloads[path.as_posix()] = bytes(content)
                else:
                    decoded = bytes(content).decode("utf-8", errors="replace")
                    if is_manifest:
                        manifest_text[path.as_posix()] = decoded
                    if capture_script:
                        script_text[path.as_posix()] = decoded
                        script_text_bytes += size

    root_fd = os.open(root, OPEN_FLAGS | os.O_DIRECTORY)
    try:
        walk(root_fd, Path(), 0)
    finally:
        os.close(root_fd)

    manifests = []
    for item in files:
        name = Path(item["path"]).name
        kind = MANIFEST_KINDS.get(name)
        if not kind:
            if name.endswith((".csproj", ".fsproj", ".vbproj")):
                kind = "dotnet"
            elif name.startswith("settings.gradle"):
                kind = "android_or_jvm"
            elif name in {"Package.swift"}:
                kind = "swift"
        if kind:
            manifests.append(
                {"path": item["path"], "kind": kind, "sha256": item["sha256"]}
            )

    components = {}
    for manifest in manifests:
        parent = str(Path(manifest["path"]).parent)
        component_id = (
            "root"
            if parent == "."
            else re.sub(r"[^a-zA-Z0-9._-]+", "-", parent).strip("-")
        )
        runtime = manifest["kind"]
        content = manifest_text.get(manifest["path"], "")
        if manifest["kind"] == "dart_or_flutter":
            if manifest["path"] in manifest_text:
                runtime = (
                    "flutter" if re.search(r"(?m)^\s*flutter:\s*$", content) else "dart"
                )
            else:
                runtime = "dart_or_flutter"
        component = components.setdefault(
            parent,
            {
                "id": component_id or "component",
                "kind": manifest["kind"],
                "root": parent,
                "runtimes": [],
                "manifests": [],
                "artifacts": [],
            },
        )
        component["runtimes"].append(runtime)
        component["manifests"].append(manifest["path"])

    id_groups = {}
    for component in components.values():
        id_groups.setdefault(component["id"], []).append(component)
    for colliding in id_groups.values():
        if len(colliding) > 1:
            for component in colliding:
                component["id"] += (
                    "-" + hashlib.sha256(component["root"].encode()).hexdigest()[:8]
                )

    artifacts = sorted(
        directory_artifacts
        + [
            entry["path"]
            for entry in files
            if Path(entry["path"]).suffix.lower() in ARTIFACT_SUFFIXES
        ]
    )
    unassigned_artifacts = []
    for artifact in artifacts:
        artifact_path = Path(artifact)
        owners = [
            component
            for component in components.values()
            if component["root"] == "."
            or Path(component["root"]) in artifact_path.parents
        ]
        if owners:
            owner = max(
                owners, key=lambda component: len(Path(component["root"]).parts)
            )
            owner["artifacts"].append(artifact)
        else:
            unassigned_artifacts.append(artifact)
    if not components:
        components["project"] = {
            "id": "project",
            "kind": "unknown",
            "root": ".",
            "runtimes": [],
            "manifests": [],
            "artifacts": [],
        }
    components = list(components.values())
    wasm_modules = []
    wasm_paths = [
        item["path"] for item in files if Path(item["path"]).suffix.lower() == ".wasm"
    ]
    files_by_path = {item["path"]: item for item in files}
    if len(wasm_paths) > MAX_WASM_MODULES:
        wasm_metadata_scan_incomplete = True
    for path in wasm_paths[:MAX_WASM_MODULES]:
        entry = files_by_path[path]
        file_path = Path(path)
        owners = [
            component
            for component in components
            if component["root"] == "." or Path(component["root"]) in file_path.parents
        ]
        owner = (
            max(owners, key=lambda item: len(Path(item["root"]).parts))
            if owners
            else None
        )
        reason = wasm_skip_reasons.get(path)
        payload = wasm_payloads.get(path)
        if reason is None and payload is not None:
            try:
                imports, exports = _parse_wasm_metadata(payload)
                status = "parsed"
            except WasmMetadataError as error:
                imports, exports = [], []
                status = "incomplete"
                reason = str(error)
                wasm_metadata_scan_incomplete = True
        else:
            imports, exports = [], []
            status = "incomplete"
            reason = reason or "module was not included in the bounded metadata scan"
            wasm_metadata_scan_incomplete = True
        wasm_modules.append(
            {
                "path": path,
                "sha256": entry["sha256"],
                "status": status,
                "imports": imports,
                "exports": exports,
                "verified": False,
                "basis": "bounded WebAssembly binary section scan; module validity, runtime use, and host bindings are not verified",
                "component_id": owner["id"] if owner else None,
                **({"reason": reason} if reason else {}),
            }
        )
    framework_hints = []
    package_manifests = [
        item["path"] for item in manifests if Path(item["path"]).name == "package.json"
    ]
    framework_hint_scan_incomplete = any(
        path not in manifest_text for path in package_manifests
    )
    for manifest_path, content in sorted(manifest_text.items()):
        if Path(manifest_path).name != "package.json":
            continue
        try:
            package = json.loads(content)
        except json.JSONDecodeError:
            framework_hint_scan_incomplete = True
            continue
        if not isinstance(package, dict):
            framework_hint_scan_incomplete = True
            continue
        declarations = {}
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            values = package.get(section, {})
            if not isinstance(values, dict):
                framework_hint_scan_incomplete = True
                continue
            for name in SSR_FRAMEWORK_PACKAGES.intersection(values):
                declarations.setdefault(name, []).append(section)
        parent = str(Path(manifest_path).parent)
        component = next((item for item in components if item["root"] == parent), None)
        for name, sections in sorted(declarations.items()):
            if len(framework_hints) >= MAX_FRAMEWORK_HINTS:
                framework_hint_scan_incomplete = True
                break
            framework_hints.append(
                {
                    "manifest_path": manifest_path,
                    "package_name": name,
                    "role": "ssr_framework_candidate",
                    "verified": False,
                    "declared_in": sorted(sections),
                    "basis": "package.json declaration only; usage, configuration, server output, and reachability are unverified",
                    "component_id": component["id"] if component else None,
                }
            )
    entrypoint_hints = []
    for entry in files:
        role = _worker_role(entry["path"])
        if role is None:
            continue
        path = Path(entry["path"])
        owners = [
            item
            for item in components
            if item["root"] == "." or Path(item["root"]) in path.parents
        ]
        owner = (
            max(owners, key=lambda item: len(Path(item["root"]).parts))
            if owners
            else None
        )
        entrypoint_hints.append(
            {
                "path": entry["path"],
                "role": role,
                "basis": "filename convention; registration and reachability not verified",
                "component_id": owner["id"] if owner else None,
            }
        )
    inventory_digest = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    target_id = "target-" + hashlib.sha256(str(root).encode()).hexdigest()[:20]
    unknowns = []
    if excluded:
        unknowns.append(
            "Excluded generated/dependency directories were not inventoried; review their package lock and build identities."
        )
    if links:
        unknowns.append(
            "Symlinks were observed but not followed; their targets remain unknown."
        )
    if not manifests:
        unknowns.append(
            "No recognized build manifest was found; target family and build commands are unknown."
        )
    if manifest_scan_incomplete:
        unknowns.append(
            "One or more recognized manifests exceeded the bounded content scan; details inferred from their contents are incomplete."
        )
    if unassigned_artifacts:
        unknowns.append(
            "Artifacts outside recognized component roots remain unassigned: "
            + ", ".join(unassigned_artifacts[:20])
        )
    if entrypoint_hints:
        unknowns.append(
            "Worker entrypoint hints use filename conventions only; registration and reachability are unverified."
        )
    if framework_hints:
        unknowns.append(
            "JavaScript server-rendering framework hints come from package.json declarations only; usage, configuration, and server output are unverified."
        )
    if framework_hint_scan_incomplete:
        unknowns.append(
            "JavaScript server-rendering framework hint scanning was incomplete due to malformed, oversized, or unavailable package metadata or its result limit."
        )
    if wasm_modules:
        unknowns.append(
            "WebAssembly import/export entries are static module declarations only; module validity, runtime use, and host bindings are not verified."
        )
    if wasm_metadata_scan_incomplete:
        unknowns.append(
            "WebAssembly metadata scanning was incomplete due to malformed or unsupported binaries, oversized modules, or scan limits."
        )
    file_paths = {item["path"] for item in files}
    worker_references = []
    worker_reference_scan_incomplete = script_scan_incomplete
    for source_path, content in script_text.items():
        remaining = MAX_WORKER_REFERENCES - len(worker_references)
        if remaining <= 0:
            worker_reference_scan_incomplete = True
            break
        path = Path(source_path)
        owners = [
            item
            for item in components
            if item["root"] == "." or Path(item["root"]) in path.parents
        ]
        owner = (
            max(owners, key=lambda item: len(Path(item["root"]).parts))
            if owners
            else None
        )
        found, exceeded = _worker_references(
            source_path, content, file_paths, owner["id"] if owner else None, remaining
        )
        worker_references.extend(found)
        worker_reference_scan_incomplete |= exceeded
    if script_text:
        unknowns.append(
            "Worker reference scanning finds only bounded literal regex matches; comments, strings, computed references, and runtime reachability are not resolved."
        )
    if worker_reference_scan_incomplete:
        unknowns.append(
            "Static worker reference scan was incomplete due to its per-file, aggregate text, or 4096-reference budget."
        )
    return {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "target",
        "id": target_id,
        "source_root": str(root),
        "source_identity": _git_identity(root),
        "components": components,
        "manifests": manifests,
        "artifacts": artifacts,
        "unassigned_artifacts": unassigned_artifacts,
        "files": files,
        "entrypoint_hints": entrypoint_hints,
        "framework_hints": framework_hints,
        "framework_hint_scan_incomplete": framework_hint_scan_incomplete,
        "wasm_modules": wasm_modules,
        "wasm_metadata_scan_incomplete": wasm_metadata_scan_incomplete,
        "worker_references": worker_references,
        "worker_reference_scan_incomplete": worker_reference_scan_incomplete,
        "excluded": excluded,
        "unfollowed_symlinks": links,
        "inventory": {
            "file_count": len(files),
            "total_bytes": total_bytes,
            "sha256": inventory_digest,
            "budgets": {"files": MAX_FILES, "entries": MAX_ENTRIES, "bytes": MAX_BYTES},
        },
        "unknowns": unknowns,
    }
