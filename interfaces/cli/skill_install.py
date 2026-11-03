"""Install the portable Anti-REA Skill into an explicit, empty directory."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sysconfig
import uuid

MANIFEST = ".anti-rea-install.json"
SCHEMA_VERSION = 1
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class SkillInstallError(ValueError):
    pass


def _require_safe_fs() -> None:
    if (not O_NOFOLLOW or not O_DIRECTORY or os.open not in os.supports_dir_fd
            or os.mkdir not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd
            or os.rmdir not in os.supports_dir_fd or os.rename not in os.supports_dir_fd):
        raise SkillInstallError("Safe Skill installation requires no-follow, directory-relative filesystem operations")


def _open_dir_at(parent_fd: int, name: str) -> int:
    return os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)


def _read_fd(fd: int) -> bytes:
    chunks = bytearray()
    while chunk := os.read(fd, 1024 * 1024):
        chunks.extend(chunk)
    return bytes(chunks)


def _read_at(root_fd: int, relative: str) -> bytes:
    rel = PurePosixPath(MANIFEST) if relative == MANIFEST else _relative(relative)
    parent_fd = os.dup(root_fd)
    try:
        for part in rel.parts[:-1]:
            child_fd = _open_dir_at(parent_fd, part)
            os.close(parent_fd)
            parent_fd = child_fd
        fd = os.open(rel.parts[-1], os.O_RDONLY | O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_NONBLOCK", 0),
                     dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SkillInstallError("Skill install contains a non-regular file")
            return _read_fd(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _open_parent_at(root_fd: int, parts: tuple[str, ...], create: bool = False) -> int:
    parent_fd = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=parent_fd)
                except FileExistsError:
                    pass
            child_fd = _open_dir_at(parent_fd, part)
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _inventory_at(root_fd: int) -> tuple[set[str], set[str]]:
    files, dirs = set(), set()

    def walk(directory_fd: int, prefix: PurePosixPath) -> None:
        with os.scandir(os.dup(directory_fd)) as entries:
            names = sorted(entry.name for entry in entries)
        for name in names:
            rel = prefix / name
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise SkillInstallError("Installed Skill contains a symlink")
            if stat.S_ISDIR(info.st_mode):
                dirs.add(rel.as_posix())
                child_fd = _open_dir_at(directory_fd, name)
                try:
                    walk(child_fd, rel)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                files.add(rel.as_posix())
            else:
                raise SkillInstallError("Installed Skill contains a non-regular entry")

    walk(root_fd, PurePosixPath())
    return files, dirs


def default_source() -> Path:
    source = Path(__file__).resolve().parents[2] / "skills" / "anti-rea"
    if source.is_dir():
        return source
    return Path(sysconfig.get_path("data")) / "share" / "anti-rea" / "skills" / "anti-rea"


def _relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts or "\\" in value
            or "\x00" in value or path.as_posix() != value or value == MANIFEST):
        raise SkillInstallError("Skill manifest contains an unsafe relative path")
    return path


def _tree(root: Path) -> dict[str, bytes]:
    _require_safe_fs()
    if root.is_symlink() or not root.is_dir():
        raise SkillInstallError("Skill source must be a real directory")
    root_fd = os.open(root, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    files: dict[str, bytes] = {}
    try:
        source_files, _ = _inventory_at(root_fd)
        for rel in source_files:
            if rel == MANIFEST:
                raise SkillInstallError(f"Skill source reserves {MANIFEST}")
            _relative(rel)
            files[rel] = _read_at(root_fd, rel)
    finally:
        os.close(root_fd)
    if not files:
        raise SkillInstallError("Skill source directory is empty")
    return files


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _destination(value: str | Path) -> Path:
    raw = Path(value).expanduser()
    if raw.name in {"", ".", ".."}:
        raise SkillInstallError("Destination must name a new directory")
    try:
        parent = raw.parent.resolve(strict=True)
    except OSError as error:
        raise SkillInstallError("Destination parent must already exist") from error
    if not parent.is_dir():
        raise SkillInstallError("Destination parent must be a directory")
    return parent / raw.name


def _owned_files(destination: Path) -> tuple[dict[str, bytes], dict]:
    _require_safe_fs()
    if destination.is_symlink() or not destination.is_dir():
        raise SkillInstallError("Destination is not a manifest-owned Skill installation")
    root_fd = os.open(destination, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        try:
            manifest = json.loads(_read_at(root_fd, MANIFEST))
        except (OSError, ValueError) as error:
            raise SkillInstallError("Skill install manifest is unreadable") from error
        return _owned_files_at(root_fd, manifest)
    finally:
        os.close(root_fd)


def _owned_files_at(root_fd: int, manifest: dict) -> tuple[dict[str, bytes], dict]:
    if (not isinstance(manifest, dict) or manifest.get("product") != "anti-rea"
            or manifest.get("schema_version") != SCHEMA_VERSION or not isinstance(manifest.get("files"), list)):
        raise SkillInstallError("Skill install manifest is invalid")
    expected = {}
    for item in manifest["files"]:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in item["sha256"])):
            raise SkillInstallError("Skill install manifest has an invalid file entry")
        rel = _relative(item["path"])
        if item["path"] in expected:
            raise SkillInstallError("Skill install manifest contains duplicate paths")
        try:
            contents = _read_at(root_fd, item["path"])
        except (OSError, SkillInstallError) as error:
            raise SkillInstallError(f"Installed Skill file is missing or unsafe: {item['path']}") from error
        if _digest(contents) != item["sha256"]:
            raise SkillInstallError(f"Installed Skill file was modified: {item['path']}")
        expected[item["path"]] = contents
    actual_files, actual_dirs = _inventory_at(root_fd)
    expected_dirs = {str(PurePosixPath(path).parent) for path in expected
                     if str(PurePosixPath(path).parent) != "."}
    for path in expected:
        expected_dirs.update(str(parent) for parent in PurePosixPath(path).parents if str(parent) != ".")
    if actual_files != set(expected) | {MANIFEST} or actual_dirs != expected_dirs:
        raise SkillInstallError("Installed Skill contains unowned or missing files")
    return expected, manifest


def _owned_files_fd(root_fd: int) -> tuple[dict[str, bytes], dict]:
    try:
        manifest = json.loads(_read_at(root_fd, MANIFEST))
    except (OSError, ValueError) as error:
        raise SkillInstallError("Skill install manifest is unreadable") from error
    return _owned_files_at(root_fd, manifest)


def _remove_owned_at(root_fd: int) -> None:
    files, _ = _owned_files_fd(root_fd)
    dirs = {str(parent) for path in files for parent in PurePosixPath(path).parents if str(parent) != "."}
    for path in sorted(files, reverse=True):
        parts = PurePosixPath(path).parts
        parent_fd = _open_parent_at(root_fd, parts[:-1])
        try:
            os.unlink(parts[-1], dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    os.unlink(MANIFEST, dir_fd=root_fd)
    for path in sorted(dirs, key=lambda item: (item.count("/"), item), reverse=True):
        parts = PurePosixPath(path).parts
        parent_fd = _open_parent_at(root_fd, parts[:-1])
        try:
            os.rmdir(parts[-1], dir_fd=parent_fd)
        finally:
            os.close(parent_fd)


def _backup_name(parent_fd: int, name: str) -> str:
    backup = f".{name}.anti-rea-backup-{uuid.uuid4().hex}"
    try:
        os.stat(backup, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return backup
    raise SkillInstallError("Update backup path already exists")


def plan(operation: str, destination: str | Path, source: str | Path | None = None) -> dict:
    if operation not in {"install", "update", "uninstall"}:
        raise SkillInstallError("Operation must be install, update, or uninstall")
    target = _destination(destination)
    installed_files = None
    if operation == "install":
        if target.exists() or target.is_symlink():
            raise SkillInstallError("Install refuses an existing destination")
        new = _tree(Path(source) if source is not None else default_source())
        changes = [{"action": "create", "path": path, "sha256": _digest(data)}
                   for path, data in sorted(new.items())]
        changes.append({"action": "create", "path": MANIFEST})
    elif operation == "update":
        old, manifest = _owned_files(target)
        installed_files = manifest["files"]
        new = _tree(Path(source) if source is not None else default_source())
        changes = []
        for path in sorted(old.keys() | new.keys()):
            if path not in new:
                changes.append({"action": "delete", "path": path})
            elif path not in old:
                changes.append({"action": "create", "path": path, "sha256": _digest(new[path])})
            elif old[path] != new[path]:
                changes.append({"action": "replace", "path": path, "sha256": _digest(new[path])})
        if old != new:
            changes.append({"action": "replace", "path": MANIFEST})
    else:
        old, manifest = _owned_files(target)
        installed_files = manifest["files"]
        changes = [{"action": "delete", "path": path} for path in sorted(old)]
        changes.append({"action": "delete", "path": MANIFEST})
    result = {"operation": operation, "destination": str(target), "changes": changes}
    if operation != "uninstall":
        result["source_files"] = [{"path": path, "sha256": _digest(content)}
                                  for path, content in sorted(new.items())]
    if installed_files is not None:
        result["installed_files"] = installed_files
    return result


def _write_tree(root_fd: int, files: dict[str, bytes]) -> None:
    if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
        raise SkillInstallError("Staging destination must be a real directory")
    for rel, data in files.items():
        parts = _relative(rel).parts
        parent_fd = _open_parent_at(root_fd, parts[:-1], create=True)
        try:
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), 0o644, dir_fd=parent_fd)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    manifest = {"product": "anti-rea", "schema_version": SCHEMA_VERSION,
                "files": [{"path": path, "sha256": _digest(data)} for path, data in sorted(files.items())]}
    fd = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=root_fd)
    try:
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


def execute(operation: str, destination: str | Path, source: str | Path | None = None,
            expected_plan: dict | None = None) -> dict:
    _require_safe_fs()
    preview = plan(operation, destination, source)
    if expected_plan is not None and expected_plan != preview:
        raise SkillInstallError("Skill files changed after the displayed change plan")
    target = Path(preview["destination"])
    if operation == "update" and not preview["changes"]:
        return preview
    files = _tree(Path(source) if source is not None else default_source()) if operation != "uninstall" else {}
    if operation != "uninstall" and preview["source_files"] != [
            {"path": path, "sha256": _digest(data)} for path, data in sorted(files.items())]:
        raise SkillInstallError("Skill files changed after the displayed change plan")
    parent_fd = os.open(target.parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        if operation == "install":
            os.mkdir(target.name, 0o700, dir_fd=parent_fd)
            root_fd = _open_dir_at(parent_fd, target.name)
            try:
                _write_tree(root_fd, files)
            except BaseException:
                _remove_partial_at(root_fd, files)
                try:
                    os.rmdir(target.name, dir_fd=parent_fd)
                except OSError:
                    pass
                raise
            finally:
                os.close(root_fd)
            return preview

        backup = _backup_name(parent_fd, target.name)
        os.rename(target.name, backup, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        backup_fd = None
        try:
            backup_fd = _open_dir_at(parent_fd, backup)
            _, manifest = _owned_files_fd(backup_fd)
            if manifest.get("files") != preview.get("installed_files"):
                raise SkillInstallError("Installed Skill changed after the displayed change plan")
            if operation == "uninstall":
                _remove_owned_at(backup_fd)
                os.close(backup_fd)
                backup_fd = None
                os.rmdir(backup, dir_fd=parent_fd)
                return preview

            os.mkdir(target.name, 0o700, dir_fd=parent_fd)
            new_fd = _open_dir_at(parent_fd, target.name)
            try:
                _write_tree(new_fd, files)
            except BaseException:
                _remove_partial_at(new_fd, files)
                try:
                    os.rmdir(target.name, dir_fd=parent_fd)
                except OSError:
                    pass
                raise
            finally:
                os.close(new_fd)
            _remove_owned_at(backup_fd)
            os.close(backup_fd)
            backup_fd = None
            os.rmdir(backup, dir_fd=parent_fd)
        except BaseException:
            if backup_fd is not None:
                os.close(backup_fd)
            try:
                os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                os.rename(backup, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            raise
    finally:
        os.close(parent_fd)
    return preview


def _remove_partial_at(root_fd: int, files: dict[str, bytes]) -> None:
    manifest = {"product": "anti-rea", "schema_version": SCHEMA_VERSION,
                "files": [{"path": path, "sha256": _digest(data)} for path, data in sorted(files.items())]}
    expected = dict(files)
    expected[MANIFEST] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    for rel, data in sorted(expected.items(), reverse=True):
        try:
            if _read_at(root_fd, rel) != data:
                continue
            parts = PurePosixPath(rel).parts
            parent_fd = _open_parent_at(root_fd, parts[:-1])
            try:
                os.unlink(parts[-1], dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        except (OSError, SkillInstallError):
            continue
    expected_dirs = {str(parent) for rel in files for parent in PurePosixPath(rel).parents if str(parent) != "."}
    for rel in sorted(expected_dirs, key=lambda item: (item.count("/"), item), reverse=True):
        parts = PurePosixPath(rel).parts
        parent_fd = _open_parent_at(root_fd, parts[:-1])
        try:
            os.rmdir(parts[-1], dir_fd=parent_fd)
        except OSError:
            pass
        finally:
            os.close(parent_fd)
    try:
        root.rmdir()
    except OSError:
        pass
