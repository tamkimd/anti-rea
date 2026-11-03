"""Build a fail-closed review checklist for candidate upstream pins."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sysconfig
from pathlib import Path

from core import workflow

ROOT = Path(__file__).resolve().parents[1]
VERIFICATION_LANES = {
    "rea": [
        "tests.test_upstream_locks",
        "tests.test_rea_integration",
        "tests.test_plan_execution",
    ],
    "e2e": [
        "tests.test_upstream_locks",
        "tests.test_e2e_integration",
        "tests.test_upstream_runner_cancellation",
    ],
    "bla": [
        "tests.test_upstream_locks",
        "tests.test_bla_integration",
        "tests.test_plan_execution",
    ],
    "mcp_python_sdk": [
        "tests.test_mcp_interface",
        "tests.test_packaging",
        "tests.test_cli_doctor",
    ],
}
IDENTITY_FIELDS = (
    "repository",
    "tag",
    "source_commit",
    "npm_package",
    "npm_version",
    "npm_integrity",
    "packages",
    "pypi_package",
    "pypi_version",
    "wheel_sha256",
    "source_archive_sha256",
    "package_lock_sha256",
    "license",
    "node_requirement",
    "python_requirement",
    "source_package_equivalence",
)
MAX_REVIEW_FILE_BYTES = 32 * 1024 * 1024
CAPABILITY_FIELDS = ("cli_commands", "mcp_prompts", "mcp_tools")


def _require_safe_relative_open() -> None:
    if (
        not getattr(os, "O_NOFOLLOW", 0)
        or not getattr(os, "O_DIRECTORY", 0)
        or os.open not in os.supports_dir_fd
    ):
        raise workflow.WorkflowError(
            "Safe no-follow directory-relative reads are unavailable on this platform"
        )


SHA256 = set("0123456789abcdef")


def _stable_manifest() -> Path:
    source = ROOT / "locks/upstreams.json"
    if source.is_file():
        return source
    packaged = Path(sysconfig.get_path("data")) / "share/anti-rea/locks/upstreams.json"
    if not packaged.is_file():
        raise workflow.WorkflowError("Stable upstream lock file is unavailable")
    return packaged


def _read_fd(fd: int, label: str) -> bytes:
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise workflow.WorkflowError(f"{label} must be a regular file")
        if before.st_size > MAX_REVIEW_FILE_BYTES:
            raise workflow.WorkflowError(f"{label} exceeds the size budget")
        chunks = []
        remaining = MAX_REVIEW_FILE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)

        def identity(item):
            return (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if (
            len(raw) > MAX_REVIEW_FILE_BYTES
            or identity(before) != identity(after)
            or len(raw) != before.st_size
        ):
            raise workflow.WorkflowError(
                f"{label} changed while being read or exceeds the size budget"
            )
        return raw
    except OSError as error:
        raise workflow.WorkflowError(f"Could not safely read {label}") from error


def _read_manifest(path: str | Path) -> tuple[Path, dict, bytes]:
    _require_safe_relative_open()
    requested = Path(path).expanduser().absolute()
    try:
        parent = requested.parent.resolve(strict=True)
        parent_fd = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened_parent = os.fstat(parent_fd)
            named_parent = os.stat(parent)
            if (opened_parent.st_dev, opened_parent.st_ino) != (
                named_parent.st_dev,
                named_parent.st_ino,
            ):
                raise workflow.WorkflowError(
                    "Upstream manifest directory changed while opening"
                )
            fd = os.open(
                requested.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
            try:
                raw = _read_fd(fd, "Upstream manifest")
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
        manifest = parent / requested.name
        value = json.loads(raw)
    except workflow.WorkflowError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise workflow.WorkflowError(
            "Upstream manifest is missing, linked, or invalid JSON"
        ) from error
    integrations = value.get("integrations") if isinstance(value, dict) else None
    if not isinstance(integrations, dict) or not integrations:
        raise workflow.WorkflowError("Upstream manifest must contain integrations")
    return manifest, value, raw


def _read_lock(root: Path, relative: Path, label: str) -> bytes:
    _require_safe_relative_open()
    directory_fd = -1
    try:
        resolved_root = root.resolve(strict=True)
        directory_fd = os.open(
            resolved_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        for part in relative.parts[:-1]:
            child_fd = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = child_fd
        fd = os.open(
            relative.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        try:
            return _read_fd(fd, label)
        finally:
            os.close(fd)
    except workflow.WorkflowError:
        raise
    except OSError as error:
        raise workflow.WorkflowError(
            f"{label} is missing, linked, or cannot be safely read"
        ) from error
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def _lock_identity(root: Path, name: str, pin: dict) -> dict:
    lock_name = pin.get("package_lock")
    expected_hash = pin.get("package_lock_sha256")
    packages = pin.get("packages")
    if not isinstance(lock_name, str) or not isinstance(expected_hash, str):
        if name == "mcp_python_sdk":
            return {
                "status": "not_applicable",
                "reason": "Python wheel and source archive hashes are pinned directly",
            }
        raise workflow.WorkflowError(
            f"Candidate {name} pin requires package_lock and package_lock_sha256"
        )
    relative = Path(lock_name)
    if relative.is_absolute() or ".." in relative.parts:
        raise workflow.WorkflowError(
            f"Candidate {name} package lock must stay inside its root"
        )
    raw = _read_lock(root, relative, f"Candidate {name} package lock")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != expected_hash:
        raise workflow.WorkflowError(
            f"Candidate {name} package lock SHA-256 does not match its pin"
        )
    try:
        lock = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise workflow.WorkflowError(
            f"Candidate {name} package lock is invalid JSON"
        ) from error
    if not isinstance(packages, dict):
        if name == "rea":
            packages = {
                pin.get("npm_package"): {
                    "version": pin.get("npm_version"),
                    "integrity": pin.get("npm_integrity"),
                }
            }
        elif name == "bla":
            packages = {
                pin.get("npm_package"): {
                    "version": pin.get("npm_version"),
                    "integrity": pin.get("npm_integrity"),
                }
            }
        else:
            raise workflow.WorkflowError(
                f"Candidate {name} pin requires direct package identities"
            )
    entries = lock.get("packages") if isinstance(lock, dict) else None
    if not isinstance(entries, dict):
        raise workflow.WorkflowError(f"Candidate {name} lock has no packages map")
    for package, identity in packages.items():
        entry = entries.get(f"node_modules/{package}")
        if not isinstance(entry, dict) or not isinstance(identity, dict):
            raise workflow.WorkflowError(
                f"Candidate {name} lock is missing direct package {package}"
            )
        if any(
            entry.get(field) != identity.get(field)
            for field in ("version", "integrity")
        ):
            raise workflow.WorkflowError(
                f"Candidate {name} lock identity differs for {package}"
            )
    return {"status": "verified", "sha256": actual_hash, "packages": packages}


def review(
    candidate_manifest: str | Path, stable_manifest: str | Path | None = None
) -> dict:
    candidate_path, candidate, candidate_raw = _read_manifest(candidate_manifest)
    stable_path, stable, stable_raw = _read_manifest(
        stable_manifest or _stable_manifest()
    )
    if candidate.get("lock_schema_version") != stable.get("lock_schema_version"):
        raise workflow.WorkflowError(
            "Candidate and stable upstream lock schemas differ"
        )
    candidate_integrations = candidate["integrations"]
    stable_integrations = stable["integrations"]
    if set(candidate_integrations) != set(stable_integrations):
        raise workflow.WorkflowError(
            "Candidate upstream names must exactly match stable integrations"
        )
    candidate_root = (
        candidate_path.parent.parent
        if candidate_path.parent.name == "locks"
        else candidate_path.parent
    )
    stable_root = (
        stable_path.parent.parent
        if stable_path.parent.name == "locks"
        else stable_path.parent
    )
    engines = {}
    for name in sorted(stable_integrations):
        before = stable_integrations[name]
        after = candidate_integrations[name]
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise workflow.WorkflowError(f"Upstream pin must be an object: {name}")
        stable_lock = _lock_identity(stable_root, name, before)
        candidate_lock = _lock_identity(candidate_root, name, after)
        changed = {
            field: {"stable": before.get(field), "candidate": after.get(field)}
            for field in IDENTITY_FIELDS
            if before.get(field) != after.get(field)
        }
        engines[name] = {
            "changed": changed,
            "stable_lock": stable_lock,
            "candidate_lock": candidate_lock,
            "verification_lanes": VERIFICATION_LANES.get(
                name, ["full regression suite"]
            ),
            "status": "review_required" if changed else "unchanged",
        }
    changed_engines = [name for name, item in engines.items() if item["changed"]]
    return {
        "schema_version": "1.0",
        "record_type": "upstream_candidate_review",
        "stable_manifest_sha256": hashlib.sha256(stable_raw).hexdigest(),
        "candidate_manifest_sha256": hashlib.sha256(candidate_raw).hexdigest(),
        "engines": engines,
        "changed_engines": changed_engines,
        "status": "review_required" if changed_engines else "unchanged",
        "promotion": "not_authorized",
        "required_before_promotion": [
            "install candidate separately",
            "compare contracts and capabilities",
            "run listed compatibility and regression lanes",
            "review evidence and reopen affected claims",
            "update stable pins only after acceptance",
        ]
        if changed_engines
        else [],
    }


def _validate_capability_ledger(value: object, label: str) -> dict:
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "1.0"
        or value.get("record_type") != "upstream_source_runtime_ledger"
        or not isinstance(value.get("upstream"), dict)
        or not all(
            isinstance(value["upstream"].get(key), str) and value["upstream"][key]
            for key in ("package", "version", "source_commit", "npm_integrity")
        )
    ):
        raise workflow.WorkflowError(
            f"{label} is not a supported upstream capability ledger"
        )
    for phase in ("source", "runtime"):
        surface = value.get(phase)
        if not isinstance(surface, dict):
            raise workflow.WorkflowError(
                f"{label} is missing its {phase} contract inventory"
            )
        for field in CAPABILITY_FIELDS:
            names = surface.get(field)
            if (
                not isinstance(names, list)
                or any(not isinstance(name, str) or not name for name in names)
                or len(set(names)) != len(names)
            ):
                raise workflow.WorkflowError(
                    f"{label} has an invalid {phase} {field} inventory"
                )
    if (
        not isinstance(value["source"].get("source_commit"), str)
        or not value["source"]["source_commit"]
    ):
        raise workflow.WorkflowError(f"{label} has no source commit identity")
    if not all(
        isinstance(value["runtime"].get(key), str) and value["runtime"][key]
        for key in ("package", "version", "npm_integrity", "node_version")
    ):
        raise workflow.WorkflowError(
            f"{label} has an incomplete runtime package identity"
        )
    for key in ("package_lock_sha256", "runtime_manifest_sha256"):
        digest = value["runtime"].get(key)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or not set(digest) <= SHA256
        ):
            raise workflow.WorkflowError(f"{label} has no valid runtime {key}")
    files = value["source"].get("files_sha256")
    if not isinstance(files, dict) or any(
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or ".." in Path(path).parts
        or not isinstance(digest, str)
        or len(digest) != 64
        or not set(digest) <= SHA256
        for path, digest in files.items()
    ):
        raise workflow.WorkflowError(
            f"{label} has an invalid source file identity inventory"
        )
    contract_hash = value["runtime"].get("mcp_tool_contracts_sha256")
    if (
        not isinstance(contract_hash, str)
        or len(contract_hash) != 64
        or not set(contract_hash) <= SHA256
    ):
        raise workflow.WorkflowError(
            f"{label} has no valid runtime MCP tool contract hash"
        )
    return value


def _ledger_identity_drift(value: dict) -> dict:
    declared, source, runtime = value["upstream"], value["source"], value["runtime"]
    pairs = {
        "source_commit": (declared["source_commit"], source["source_commit"]),
        "runtime_package": (declared["package"], runtime["package"]),
        "runtime_version": (declared["version"], runtime["version"]),
        "runtime_npm_integrity": (declared["npm_integrity"], runtime["npm_integrity"]),
    }
    return {
        key: {"declared": expected, "observed": actual}
        for key, (expected, actual) in pairs.items()
        if expected != actual
    }


def compare_capability_ledgers(stable: dict, candidate: dict) -> dict:
    """Compare source/runtime capability names without treating name parity as compatibility."""
    stable = _validate_capability_ledger(stable, "Stable capability ledger")
    candidate = _validate_capability_ledger(candidate, "Candidate capability ledger")
    changes = {}
    source_runtime_drift = {}
    for field in CAPABILITY_FIELDS:
        before_source, before_runtime = (
            set(stable["source"][field]),
            set(stable["runtime"][field]),
        )
        after_source, after_runtime = (
            set(candidate["source"][field]),
            set(candidate["runtime"][field]),
        )
        added, removed = (
            sorted(after_runtime - before_runtime),
            sorted(before_runtime - after_runtime),
        )
        source_added, source_removed = (
            sorted(after_source - before_source),
            sorted(before_source - after_source),
        )
        if added or removed or source_added or source_removed:
            changes[field] = {
                "runtime_added": added,
                "runtime_removed": removed,
                "source_added": source_added,
                "source_removed": source_removed,
            }
        drift = {
            "runtime_only": sorted(after_runtime - after_source),
            "source_only": sorted(after_source - after_runtime),
        }
        if drift["runtime_only"] or drift["source_only"]:
            source_runtime_drift[field] = drift
    identity_changed = stable["upstream"] != candidate["upstream"]
    source_file_changes = {
        path: {
            "stable": stable["source"]["files_sha256"].get(path),
            "candidate": candidate["source"]["files_sha256"].get(path),
        }
        for path in sorted(
            stable["source"]["files_sha256"].keys()
            | candidate["source"]["files_sha256"].keys()
        )
        if stable["source"]["files_sha256"].get(path)
        != candidate["source"]["files_sha256"].get(path)
    }
    source_identity_changes = {}
    if stable["source"]["source_commit"] != candidate["source"]["source_commit"]:
        source_identity_changes["source_commit"] = {
            "stable": stable["source"]["source_commit"],
            "candidate": candidate["source"]["source_commit"],
        }
    if source_file_changes:
        source_identity_changes["files_sha256"] = source_file_changes
    runtime_identity_changes = {
        field: {
            "stable": stable["runtime"][field],
            "candidate": candidate["runtime"][field],
        }
        for field in (
            "package",
            "version",
            "npm_integrity",
            "package_lock_sha256",
            "runtime_manifest_sha256",
            "node_version",
        )
        if stable["runtime"][field] != candidate["runtime"][field]
    }
    stable_identity_drift = _ledger_identity_drift(stable)
    candidate_identity_drift = _ledger_identity_drift(candidate)
    contract_hash_changed = (
        stable["runtime"]["mcp_tool_contracts_sha256"]
        != candidate["runtime"]["mcp_tool_contracts_sha256"]
    )
    return {
        "schema_version": "1.0",
        "record_type": "upstream_capability_review",
        "stable_upstream": stable["upstream"],
        "candidate_upstream": candidate["upstream"],
        "identity_changed": identity_changed,
        "changes": changes,
        "source_identity_changes": source_identity_changes,
        "runtime_identity_changes": runtime_identity_changes,
        "stable_identity_drift": stable_identity_drift,
        "candidate_identity_drift": candidate_identity_drift,
        "runtime_tool_contract_sha256": {
            "stable": stable["runtime"]["mcp_tool_contracts_sha256"],
            "candidate": candidate["runtime"]["mcp_tool_contracts_sha256"],
            "changed": contract_hash_changed,
        },
        "candidate_source_runtime_drift": source_runtime_drift,
        "status": "review_required"
        if identity_changed
        or changes
        or source_runtime_drift
        or stable_identity_drift
        or candidate_identity_drift
        or source_identity_changes
        or runtime_identity_changes
        or contract_hash_changed
        else "unchanged",
        "promotion": "not_authorized",
    }


def compare_capability_files(
    stable_path: str | Path, candidate_path: str | Path
) -> dict:
    ledgers, hashes = [], []
    for path, label in (
        (stable_path, "Stable capability ledger"),
        (candidate_path, "Candidate capability ledger"),
    ):
        requested = Path(path).expanduser().absolute()
        try:
            root = requested.parent.resolve(strict=True)
            raw = _read_lock(root, Path(requested.name), label)
            ledger = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise workflow.WorkflowError(f"{label} is invalid JSON") from error
        ledgers.append(_validate_capability_ledger(ledger, label))
        hashes.append(hashlib.sha256(raw).hexdigest())
    result = compare_capability_ledgers(*ledgers)
    result["stable_ledger_sha256"], result["candidate_ledger_sha256"] = hashes
    return result
