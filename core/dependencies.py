"""Prepare only the pinned upstream runtimes selected for a workflow."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import sysconfig
import tomllib

from core import workflow
from core import upstream_review

ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_ENV = {"bla": "ANTI_REA_BLA_RUNTIME", "e2e": "ANTI_REA_E2E_RUNTIME",
                "rea": "ANTI_REA_REA_RUNTIME"}
_PROJECT_LOCK_LIMIT = 32 * 1024 * 1024


def _upstreams_path() -> Path:
    path = ROOT / "locks/upstreams.json"
    if path.is_file():
        return path
    path = Path(sysconfig.get_path("data")) / "share/anti-rea/locks/upstreams.json"
    if not path.is_file():
        raise workflow.WorkflowError("Packaged upstream lock file is unavailable")
    return path


def _node_identity(engine: str, adapter):
    checker = adapter.runner if engine == "bla" else adapter
    version, parts = checker.node_version()
    supported = (adapter.supported_node(parts) if engine in {"bla", "rea"}
                 else ((parts[0] == 22 and parts >= (22, 22, 3)) or
                       (parts[0] >= 24 and parts >= (24, 8, 0)))
                 if engine == "e2e" else False)
    if not supported:
        raise workflow.WorkflowError(f"Pinned {engine} runtime does not support Node {version}")
    return version


def _private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise workflow.WorkflowError("Dependency cache directories cannot be symlinks")
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    if not path.is_dir():
        raise workflow.WorkflowError("Dependency cache path must be a directory")
    if os.name != "nt":
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise workflow.WorkflowError("Dependency cache directories must be private and owned by the current user")
    return path


def _manifest_npm_version(engine: str, manifest: dict) -> str | None:
    if isinstance(manifest.get("npm_version_runtime"), str):
        return manifest["npm_version_runtime"]
    return manifest.get("npm_version") if engine == "e2e" else None


def _runtime_identity(engine: str, adapter, runtime: Path, node_version: str,
                      npm_version: str | None = None):
    try:
        runtime, manifest = adapter.verify_runtime(runtime)
    except Exception as error:
        raise workflow.WorkflowError(f"Pinned {engine} runtime verification failed: {error}") from error
    if manifest.get("node_version") != node_version:
        raise workflow.WorkflowError("Pinned runtime was prepared with a different Node version")
    actual_npm = _manifest_npm_version(engine, manifest)
    if npm_version is not None and actual_npm != npm_version:
        raise workflow.WorkflowError("Pinned runtime was prepared with a different npm version")
    return runtime, manifest


def _lock_selectors(header: str) -> list[str]:
    return [next(value for value in match if value).strip().strip("\"'")
            for match in re.findall(r'"([^\"]+)"|\'([^\']+)\'|([^,]+)', header)]


def _selector_package(selector: str) -> str:
    return selector.rpartition("@")[0].lstrip("/")


def _collapse_lock_entries(entries: dict[str, list[dict]]) -> dict[str, dict]:
    result = {}
    for name, identities in entries.items():
        distinct = {(item.get("version"), item.get("integrity")) for item in identities}
        if len(distinct) == 1:
            version, integrity = next(iter(distinct))
            result[name] = {"version": version, "integrity": integrity}
        else:
            result[name] = {"version": None, "integrity": None}
    return result


def _package_tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.is_dir() or root.is_symlink():
        raise workflow.WorkflowError("Python site-packages is missing or linked")
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise workflow.WorkflowError("Python site-packages contains a symlink")
        if path.is_file():
            relative = path.relative_to(root).as_posix().encode()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(path.stat().st_size.to_bytes(8, "big"))
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def _runtime_tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.is_dir() or root.is_symlink():
        raise workflow.WorkflowError("Python virtual environment is missing or linked")
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        relative = path.relative_to(root).as_posix().encode()
        info = path.lstat()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(info.st_mode.to_bytes(4, "big"))
        if path.is_symlink():
            target = os.readlink(path).encode()
            digest.update(len(target).to_bytes(4, "big"))
            digest.update(target)
        elif path.is_file():
            digest.update(info.st_size.to_bytes(8, "big"))
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif not path.is_dir():
            raise workflow.WorkflowError("Python virtual environment contains a special file")
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _yarn_classic_lock_entries(raw: bytes, packages: dict) -> dict[str, dict] | None:
    """Read direct identities from Yarn Classic lockfiles only."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "__metadata:" in text or not text.strip():
        return None
    entries: dict[str, list[dict]] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line or line[0].isspace() or line.startswith("#") or not line.endswith(":"):
            index += 1
            continue
        selectors = {_selector_package(item) for item in _lock_selectors(line[:-1])}
        block = []
        index += 1
        while index < len(lines) and (not lines[index] or lines[index][0].isspace()):
            block.append(lines[index])
            index += 1
        versions = re.findall(r'^\s+version\s+["\']?([^\s"\']+)', "\n".join(block), re.MULTILINE)
        integrities = re.findall(r'^\s+integrity\s*:?[ \t]+([^\s"\']+)', "\n".join(block), re.MULTILINE)
        if len(set(versions)) == 1 and len(set(integrities)) == 1:
            identity = {"version": versions[0], "integrity": integrities[0]}
            for name in packages.keys() & selectors:
                entries.setdefault(name, []).append(identity)
    return _collapse_lock_entries(entries) if entries else None


def _pnpm_v9_lock_entries(raw: bytes, packages: dict) -> dict[str, dict] | None:
    """Read direct package identities from pnpm's v9 packages map."""
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None
    if not any(re.fullmatch(r"lockfileVersion:\s*['\"]?9(?:\.0)?['\"]?", line) for line in lines):
        return None
    entries: dict[str, list[dict]] = {}
    in_packages = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == "packages:":
            in_packages = True
            index += 1
            continue
        if line and not line[0].isspace():
            in_packages = False
        if not in_packages or not re.match(r"^  [^ ].*:\s*$", line):
            index += 1
            continue
        key = line.strip()[:-1].strip().strip("\"'")
        name = _selector_package(key.split("(", 1)[0])
        block = []
        index += 1
        while index < len(lines) and (not lines[index] or lines[index].startswith("    ")):
            block.append(lines[index])
            index += 1
        versions = re.findall(r"(?:^|@)(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)", key)
        identities = re.findall(r"integrity:\s*['\"]?([^\s,'\"}]+)", "\n".join(block))
        if (name in packages and len(set(versions)) == 1 and len(set(identities)) == 1):
            entries.setdefault(name, []).append({"version": versions[0], "integrity": identities[0]})
    return _collapse_lock_entries(entries) if entries else None


def _project_dependency_report(engine: str, project: Path, pin: dict) -> dict:
    """Report project-local package matches without treating them as trusted runtimes."""
    packages = (pin.get("packages") if engine == "e2e" else
                {pin["npm_package"]: {"version": pin["npm_version"], "integrity": pin["npm_integrity"]}})
    result = {"status": "not_detected", "lockfile": None, "lockfile_manager": None,
              "packages": {}, "lockfile_matches_pin": None, "reusable": False,
              "reason": "project package metadata is unavailable"}
    try:
        try:
            manifest = json.loads(upstream_review._read_lock(project, Path("package.json"), "Project package manifest"))
        except workflow.WorkflowError:
            manifest = {}
        lockfiles = (("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm"),
                     ("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"))
        present = [(filename, manager) for filename, manager in lockfiles
                   if (project / filename).exists() or (project / filename).is_symlink()]
        declared = manifest.get("packageManager") if isinstance(manifest, dict) else None
        declared_manager = None
        if declared is not None:
            if not isinstance(declared, str) or "@" not in declared:
                return {**result, "status": "unavailable",
                        "reason": "project packageManager declaration is unsupported"}
            declared_manager, version = declared.split("@", 1)
            if (declared_manager not in {"npm", "pnpm", "yarn"}
                    or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version)):
                return {**result, "status": "unavailable",
                        "reason": "project packageManager declaration is unsupported"}
        managers = {manager for _, manager in present}
        if declared_manager is None and len(managers) > 1:
            return {**result, "status": "unavailable",
                    "reason": "multiple package-manager lockfiles are present without a packageManager declaration"}
        manager = declared_manager or next(iter(managers), None)
        selected = [item for item in present if item[1] == manager]
        if not selected and manager is not None:
            return {**result, "lockfile_manager": manager, "status": "unavailable",
                    "reason": "packageManager declaration has no matching project lockfile"}
        # npm gives npm-shrinkwrap.json precedence when both npm lockfiles exist.
        lockfile, result["lockfile_manager"] = next(
            (item for item in selected if item[0] == "npm-shrinkwrap.json"), selected[0]
        ) if selected else (None, None)
        lock = None
        raw_lock = None
        if lockfile:
            raw_lock = upstream_review._read_lock(project, Path(lockfile), "Project package lock")
            if len(raw_lock) > _PROJECT_LOCK_LIMIT:
                raise workflow.WorkflowError("Project package lock exceeds the size budget")
            if result["lockfile_manager"] == "npm":
                lock = json.loads(raw_lock)
        result["lockfile"] = lockfile
        entries = None
        lockfile_v1 = False
        if isinstance(lock, dict):
            version = lock.get("lockfileVersion")
            if version in {2, 3} and isinstance(lock.get("packages"), dict):
                entries = lock["packages"]
            elif version == 1 and isinstance(lock.get("dependencies"), dict):
                entries = lock["dependencies"]
                lockfile_v1 = True
        elif result["lockfile_manager"] == "yarn":
            entries = _yarn_classic_lock_entries(raw_lock, packages)
        elif result["lockfile_manager"] == "pnpm":
            entries = _pnpm_v9_lock_entries(raw_lock, packages)
        declarations = {}
        if isinstance(manifest, dict):
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                if isinstance(manifest.get(section), dict):
                    declarations.update({name: section for name in packages if name in manifest[section]})
        for name, expected in packages.items():
            locked = (entries.get(f"node_modules/{name}") if entries is not None and not lockfile_v1
                      and result["lockfile_manager"] == "npm" else
                      entries.get(name) if entries is not None else None)
            installed = None
            try:
                installed = json.loads(upstream_review._read_lock(
                    project, Path("node_modules") / name / "package.json", f"Installed {name} manifest"))
            except workflow.WorkflowError:
                pass
            locked_match = (isinstance(locked, dict) and locked.get("version") == expected.get("version")
                            and locked.get("integrity") == expected.get("integrity")) if entries is not None else None
            installed_match = (isinstance(installed, dict) and installed.get("name") == name
                               and installed.get("version") == expected.get("version"))
            result["packages"][name] = {"declared_in": declarations.get(name),
                                        "locked": bool(locked), "lock_matches_pin": locked_match,
                                        "installed": installed is not None,
                                        "installed_version_matches_pin": installed_match}
        result["lockfile_matches_pin"] = (all(item["lock_matches_pin"] for item in result["packages"].values())
                                           if entries is not None else None)
        all_installed = all(item["installed"] for item in result["packages"].values())
        all_versions = all(item["installed_version_matches_pin"] for item in result["packages"].values())
        result["status"] = (
            "pinned_metadata_match" if all_installed and all_versions and result["lockfile_matches_pin"] is True
            else "mismatch" if all_installed and entries is not None
            else "installed_unverified" if all_installed
            else "partial" if any(item["installed"] for item in result["packages"].values())
            else "not_installed" if lockfile else "not_detected")
        result["reason"] = (
            "installed bytes have no authenticated Anti-REA runtime identity"
            if result["status"] == "pinned_metadata_match"
            else "project lockfile format is detected but its package identity is not verified"
            if result["status"] == "installed_unverified"
            else "project dependencies do not fully match the pinned package set")
        return result
    except (workflow.WorkflowError, UnicodeDecodeError, json.JSONDecodeError):
        return {**result, "status": "unavailable",
                "reason": "project npm lock is missing, unsupported, or could not be safely read"}


def inspect_project_dependencies(engine: str, project: str | Path) -> dict:
    """Read project npm metadata without preparing or executing a runtime."""
    if engine not in _RUNTIME_ENV:
        raise workflow.WorkflowError("Unknown upstream engine")
    project_root = Path(project).expanduser().resolve(strict=True)
    if not project_root.is_dir():
        raise workflow.WorkflowError("Project root must be a directory")
    pin = json.loads(_upstreams_path().read_text())["integrations"][engine]
    return {"status": "inspected", "engine": engine,
            "project_dependencies": _project_dependency_report(engine, project_root, pin),
            "limitations": ["Project metadata matches do not authenticate installed package bytes; no dependency is reused by this inspection."]}


def inspect_python_dependencies(project: str | Path) -> dict:
    """Inspect one PEP 751 lockfile without resolving or installing packages."""
    project_root = Path(project).expanduser().resolve(strict=True)
    if not project_root.is_dir():
        raise workflow.WorkflowError("Project root must be a directory")
    lockfiles = sorted(path for path in project_root.iterdir()
                       if path.name == "pylock.toml" or
                       re.fullmatch(r"pylock\.[^.]+\.toml", path.name))
    if not lockfiles:
        return {"status": "not_detected", "lockfile": None, "packages": [],
                "reason": "No PEP 751 pylock.toml file was found"}
    if len(lockfiles) != 1:
        return {"status": "unavailable", "lockfile": None, "packages": [],
                "reason": "Multiple PEP 751 lockfiles require an explicit environment selection"}
    lockfile = lockfiles[0]
    relative = Path(lockfile.name)
    try:
        raw = upstream_review._read_lock(project_root, relative, "Python pylock.toml")
        if len(raw) > _PROJECT_LOCK_LIMIT:
            raise workflow.WorkflowError("Python lockfile exceeds the size budget")
        lock = tomllib.loads(raw.decode("utf-8"))
        if (lock.get("lock-version") != "1.0" or not isinstance(lock.get("created-by"), str)
                or not isinstance(lock.get("packages"), list)):
            raise workflow.WorkflowError("Python lockfile has an unsupported or invalid PEP 751 schema")
        packages = []
        complete = True
        for item in lock["packages"]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise workflow.WorkflowError("Python lockfile contains an invalid package entry")
            sources = []
            for kind in ("archive", "sdist"):
                source = item.get(kind)
                if isinstance(source, dict):
                    digest = source.get("hashes", {}).get("sha256") if isinstance(source.get("hashes"), dict) else None
                    sources.append({"kind": kind, "name": source.get("name"),
                                    "sha256": digest if isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest) else None})
            wheels = item.get("wheels", [])
            if not isinstance(wheels, list):
                raise workflow.WorkflowError("Python lockfile contains invalid wheel entries")
            for wheel in wheels:
                if not isinstance(wheel, dict):
                    raise workflow.WorkflowError("Python lockfile contains an invalid wheel entry")
                hashes = wheel.get("hashes") if isinstance(wheel.get("hashes"), dict) else {}
                digest = hashes.get("sha256")
                sources.append({"kind": "wheel", "name": wheel.get("name"),
                                "sha256": digest if isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest) else None})
            for kind in ("vcs", "directory"):
                if isinstance(item.get(kind), dict):
                    sources.append({"kind": kind, "sha256": None})
            if not sources or any(source["sha256"] is None for source in sources):
                complete = False
            packages.append({"name": item["name"], "version": item.get("version"),
                              "marker": item.get("marker"), "sources": sources})
        return {"status": "inspected" if complete else "partial", "lockfile": lockfile.name,
                "lockfile_sha256": hashlib.sha256(raw).hexdigest(), "lock_version": lock["lock-version"],
                "created_by": lock["created-by"], "requires_python": lock.get("requires-python"),
                "environments": lock.get("environments", []), "packages": packages,
                "limitations": ["Inspection only: does not evaluate environment markers, authenticate lock provenance, inspect installed package bytes, resolve dependencies, or install/reuse packages."]}
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, workflow.WorkflowError) as error:
        return {"status": "unavailable", "lockfile": lockfile.name, "packages": [],
                "reason": str(error)}


def prepare_python_dependencies(project: str | Path, cache: str | Path,
                                offline: bool = False) -> dict:
    """Install one fully hashed, wheel-only PEP 751 lock into a private cache."""
    if not isinstance(offline, bool):
        raise workflow.WorkflowError("Offline mode must be boolean")
    project_root = Path(project).expanduser().resolve(strict=True)
    if not project_root.is_dir():
        raise workflow.WorkflowError("Project root must be a directory")
    inspected = inspect_python_dependencies(project_root)
    if inspected["status"] != "inspected":
        raise workflow.WorkflowError(inspected.get("reason", "Python lock is incomplete"))
    lockfile = project_root / inspected["lockfile"]
    raw = upstream_review._read_lock(project_root, Path(lockfile.name), "Python pylock.toml")
    lock = tomllib.loads(raw.decode("utf-8"))
    if (set(lock) - {"lock-version", "created-by", "requires-python", "environments", "packages"}
            or lock.get("requires-python") not in (None, ">=3.11")
            or lock.get("environments") not in (None, [])):
        raise workflow.WorkflowError("Python lock environment selectors are unsupported")
    package_names = set()
    for package in lock["packages"]:
        name, version = package.get("name"), package.get("version")
        wheels = package.get("wheels")
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
                or not isinstance(version, str) or not wheels or not isinstance(wheels, list)
                or set(package) - {"name", "version", "wheels"}):
            raise workflow.WorkflowError("Python provisioning supports only unconditional wheel packages with exact versions")
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized in package_names:
            raise workflow.WorkflowError("Python lock contains duplicate normalized package names")
        package_names.add(normalized)
        for wheel in wheels:
            if (not isinstance(wheel, dict) or not isinstance(wheel.get("name"), str)
                    or not wheel["name"].endswith(".whl")
                    or set(wheel) - {"name", "url", "path", "hashes"}
                    or ("url" in wheel) == ("path" in wheel)
                    or not isinstance(wheel.get("hashes"), dict)
                    or set(wheel["hashes"]) != {"sha256"}
                    or not isinstance(wheel["hashes"].get("sha256"), str)
                    or not re.fullmatch(r"[a-f0-9]{64}", wheel["hashes"]["sha256"])):
                raise workflow.WorkflowError("Python lock contains an unsupported or unhashed wheel source")
            if "url" in wheel:
                from urllib.parse import urlsplit
                if not isinstance(wheel["url"], str):
                    raise workflow.WorkflowError("Python wheel URL must be text")
                try:
                    url = urlsplit(wheel["url"])
                    port = url.port
                except ValueError as error:
                    raise workflow.WorkflowError("Python wheel URL is malformed") from error
                if (not isinstance(wheel["url"], str) or url.scheme != "https" or not url.hostname
                        or url.username or url.password or port not in (None, 443)
                        or url.fragment or url.query):
                    raise workflow.WorkflowError("Python wheel URLs must use HTTPS without embedded credentials")
            else:
                if not isinstance(wheel["path"], str):
                    raise workflow.WorkflowError("Python wheel path must be relative text")
                relative = Path(wheel["path"])
                source = lockfile.parent / relative
                if (relative.is_absolute() or ".." in relative.parts or source.is_symlink()
                        or not source.is_file() or source.resolve().parent != lockfile.parent.resolve()):
                    raise workflow.WorkflowError("Python wheel paths must be regular files beside the lockfile")
    requested_cache = Path(cache).expanduser().absolute()
    if requested_cache.is_symlink():
        raise workflow.WorkflowError("Python dependency cache cannot be a symlink")
    cache_root = requested_cache.resolve()
    if cache_root == project_root or project_root in cache_root.parents or cache_root in project_root.parents:
        raise workflow.WorkflowError("Python dependency cache must be outside the project")
    _private_directory(cache_root)
    pip_version = subprocess.run([sys.executable, "-m", "pip", "--version"], check=True,
                                  capture_output=True, text=True, timeout=30).stdout.strip()
    identity = {"lock_sha256": inspected["lockfile_sha256"], "python": sys.version,
                "implementation": sys.implementation.name, "cache_tag": sys.implementation.cache_tag,
        "platform": sysconfig.get_platform(), "pip": pip_version,
        "interpreter_path": str(Path(sys.executable).resolve()),
        "interpreter_sha256": _file_sha256(Path(sys.executable).resolve())}
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    entry = cache_root / key
    if entry.exists() or entry.is_symlink():
        if entry.is_symlink() or not entry.is_dir():
            raise workflow.WorkflowError("Python dependency cache entry is not a safe directory")
        if not (entry / "anti-rea-manifest.json").is_file():
            if offline:
                raise ValueError("Offline Python dependency cache miss")
            import shutil
            shutil.rmtree(entry)
        else:
            try:
                manifest = json.loads((entry / "anti-rea-manifest.json").read_text())
                if manifest.get("identity") != identity or manifest.get("lock_sha256") != inspected["lockfile_sha256"]:
                    raise ValueError("identity mismatch")
                site = entry / "venv" / ("Lib/site-packages" if os.name == "nt" else
                                         f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
                tree = _package_tree_hash(site)
                runtime_tree = _runtime_tree_hash(entry / "venv")
                if (tree != manifest.get("site_packages_sha256")
                        or runtime_tree != manifest.get("venv_tree_sha256")):
                    raise ValueError("installed environment files changed")
                return {"status": "reused", "runtime": str(entry / "venv"),
                        "lock_sha256": inspected["lockfile_sha256"], "site_packages_sha256": tree,
                        "venv_tree_sha256": runtime_tree,
                        "cache_key": key, "python": sys.version.split()[0], "pip": pip_version}
            except (OSError, ValueError, workflow.WorkflowError, json.JSONDecodeError) as error:
                raise workflow.WorkflowError(f"Python dependency cache verification failed: {error}") from error
    if offline:
        raise ValueError("Offline Python dependency cache miss")
    try:
        entry.mkdir(mode=0o700)
    except FileExistsError as error:
        raise workflow.WorkflowError("Python dependency cache entry is being prepared concurrently") from error
    try:
        venv = entry / "venv"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True,
                       capture_output=True, text=True, timeout=60)
        target_python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        purelib = subprocess.run([str(target_python), "-I", "-c",
                                  "import sysconfig; print(sysconfig.get_path('purelib'))"],
                                 check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        report_path = entry / "pip-report.json"
        subprocess.run([sys.executable, "-m", "pip", "--python", str(target_python), "install",
                        "--isolated", "--disable-pip-version-check", "--no-input",
                        "--keyring-provider", "disabled", "--no-index", "--require-hashes",
                        "--no-deps", "--only-binary=:all:", "--report", str(report_path),
                        "-r", str(lockfile)], check=True, capture_output=True, text=True, timeout=600)
        report = json.loads(report_path.read_text())
        installs = report.get("install", [])
        expected = {re.sub(r"[-_.]+", "-", item["name"]).lower(): item["version"]
                    for item in lock["packages"]}
        actual = {re.sub(r"[-_.]+", "-", item["metadata"]["name"]).lower(): item["metadata"]["version"]
                  for item in installs}
        if actual != expected:
            raise workflow.WorkflowError("pip install report does not match the complete Python lock")
        site = Path(purelib)
        if not site.is_relative_to(venv.resolve()):
            raise workflow.WorkflowError("Python environment site-packages escaped the cache entry")
        tree = _package_tree_hash(site)
        runtime_tree = _runtime_tree_hash(venv)
        report_path.unlink()
        manifest_path = entry / "anti-rea-manifest.json"
        ready = entry / ".anti-rea-manifest-ready"
        ready.write_text(json.dumps(
            {"identity": identity, "lock_sha256": inspected["lockfile_sha256"],
             "site_packages_sha256": tree, "venv_tree_sha256": runtime_tree}, sort_keys=True) + "\n")
        ready.replace(manifest_path)
        return {"status": "prepared", "runtime": str(entry / "venv"),
                "lock_sha256": inspected["lockfile_sha256"], "site_packages_sha256": tree,
                "venv_tree_sha256": runtime_tree,
                "cache_key": key, "python": sys.version.split()[0], "pip": pip_version}
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, workflow.WorkflowError) as error:
        raise workflow.WorkflowError(f"Python dependency provisioning failed: {error}") from error
    finally:
        if entry.exists() and not (entry / "anti-rea-manifest.json").exists():
            import shutil
            shutil.rmtree(entry, ignore_errors=True)


def prepare(engine: str, project: str | Path, cache: str | Path | None, adapter,
            runtime: str | Path | None = None, offline: bool = False) -> dict:
    """Verify an explicit runtime or prepare/reuse an isolated pinned cache entry."""
    if engine not in _RUNTIME_ENV:
        raise workflow.WorkflowError("Unknown upstream engine")
    if not isinstance(offline, bool):
        raise workflow.WorkflowError("Offline mode must be boolean")
    project_root = Path(project).expanduser().resolve(strict=True)
    if not project_root.is_dir():
        raise workflow.WorkflowError("Project root must be a directory")
    pin = json.loads(_upstreams_path().read_text())["integrations"][engine]
    project_dependencies = _project_dependency_report(engine, project_root, pin)
    try:
        node_version = _node_identity(engine, adapter)
    except Exception as error:
        raise workflow.WorkflowError(f"Pinned {engine} Node runtime is unavailable: {error}") from error
    configured = runtime or os.environ.get(_RUNTIME_ENV[engine])
    if configured:
        selected = Path(configured).expanduser()
        if selected.is_symlink():
            raise workflow.WorkflowError("Configured runtime cannot be a symlink")
        selected, manifest = _runtime_identity(engine, adapter, selected, node_version)
        return _result(engine, pin, selected, manifest, node_version,
                       _manifest_npm_version(engine, manifest),
                       "verified", "explicit", project_dependencies)

    if cache is None:
        raise workflow.WorkflowError("Pass --cache-dir when no verified runtime was supplied")
    try:
        npm_version = adapter.npm_version()
    except Exception as error:
        raise workflow.WorkflowError(f"Pinned {engine} npm runtime is unavailable: {error}") from error

    cache_root = Path(cache).expanduser().absolute()
    if cache_root.is_symlink():
        raise workflow.WorkflowError("Dependency cache cannot be a symlink")
    canonical_cache = cache_root.resolve(strict=False)
    if canonical_cache == project_root or project_root in canonical_cache.parents:
        raise workflow.WorkflowError("Dependency cache must be outside the project")
    if offline and not canonical_cache.is_dir():
        raise workflow.WorkflowError("Offline dependency cache miss; prepare this pinned runtime while online")
    _private_directory(canonical_cache)
    node_key = re.sub(r"[^a-zA-Z0-9._-]", "_", node_version)
    npm_key = re.sub(r"[^a-zA-Z0-9._-]", "_", npm_version)
    platform_key = f"{sys.platform}-{platform.machine().lower()}"
    entry = canonical_cache / engine / f"{pin.get('npm_version', 'multi')}-{platform_key}-node-{node_key}-npm-{npm_key}"
    if entry.exists() or entry.is_symlink():
        if entry.is_symlink():
            raise workflow.WorkflowError("Cached runtime cannot be a symlink")
        selected, manifest = _runtime_identity(engine, adapter, entry, node_version, npm_version)
        return _result(engine, pin, selected, manifest, node_version, npm_version, "reused", "cache", project_dependencies)
    if offline:
        raise workflow.WorkflowError("Offline dependency cache miss; prepare this pinned runtime while online")
    _private_directory(entry.parent)
    try:
        adapter.bootstrap(entry)
    except Exception as error:
        raise workflow.WorkflowError(f"Pinned {engine} runtime preparation failed: {error}") from error
    selected, manifest = _runtime_identity(engine, adapter, entry, node_version, npm_version)
    return _result(engine, pin, selected, manifest, node_version, npm_version, "prepared", "cache", project_dependencies)


def _result(engine: str, pin: dict, runtime: Path, manifest: dict, node_version: str,
            npm_version: str | None, status: str, source: str, project_dependencies: dict | None = None) -> dict:
    packages = ({"e2e": pin["packages"]} if engine == "e2e" else
                {pin["npm_package"]: {"version": pin["npm_version"], "integrity": pin["npm_integrity"]}})
    tree_hash = manifest.get("package_tree_sha256")
    return {"status": status, "engine": engine, "runtime": str(runtime), "source": source,
            "packages": packages, "license": pin["license"], "node_requirement": pin["node_requirement"],
            "node_version": node_version, "npm_version": npm_version,
            "package_lock_sha256": pin["package_lock_sha256"],
            "package_tree_sha256": tree_hash,
            "project_dependencies": project_dependencies or {"status": "not_checked", "reusable": False},
            "install_scripts": manifest.get("install_scripts", "disabled"),
            "limitations": ["Only the exact pinned runtime is reused; engine applicability and successful operation require separate checks.",
                            "The cache is isolated from the project and does not install global or project dependencies."]}
