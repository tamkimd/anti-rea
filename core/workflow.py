"""Versioned workflow records and safe decision/state transitions.

This module validates orchestration records. It does not execute application code,
verify that a decision came from a human, or certify application protection.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics
import sysconfig
import tempfile
from typing import Any

SCHEMA_VERSION = "2.0"
PLAN_PROFILE_INTENSITIES = {"low-impact": "stealth", "balanced": "balanced",
                            "deep-protection": "maximum"}
PLAN_BLA_INTENSITIES = {"stealth", "balanced", "maximum", "bankrupt"}
RUN_STATES = {
    "discovered": {"baselining", "cancelled"},
    "baselining": {"awaiting_decision", "blocked", "failed", "cancelled"},
    "awaiting_decision": {"preparing", "cancelled", "needs_decision"},
    "needs_decision": {"awaiting_decision", "cancelled"},
    "preparing": {"executing", "blocked", "failed", "cancelled"},
    "executing": {"verifying", "blocked", "failed", "cancelled"},
    "verifying": {"completed", "blocked", "failed", "cancelled"},
    "completed": set(), "blocked": set(), "failed": set(), "cancelled": set(),
}
ACCEPTANCE = {"accepted", "rejected", "blocked", "needs_decision"}
ACCEPTANCE_CLAIM_CHECKS = {
    "bla_invariants_passed": "bla_invariants",
    "application_behavior_passed": "application_behavior",
    "e2e_behavior_passed": "e2e_behavior",
    "rea_comparison_passed": "rea_comparison",
    "performance_budget_met": "performance",
    "source_map_omitted_from_private_candidate": "public_source_map_absent",
    "flutter_aot_candidate_inspected": "flutter_aot_comparison",
    "flutter_android_same_target_behavior_passed": "flutter_android_behavior",
}
CHECK_ACCEPTANCE_CLAIMS = {check_id: claim_id for claim_id, check_id in ACCEPTANCE_CLAIM_CHECKS.items()}
ACCEPTANCE_CLAIM_IDS = set(ACCEPTANCE_CLAIM_CHECKS)


def acceptance_claim_ids(check_ids: list[str]) -> list[str]:
    """Return registered narrow claim IDs for known verification checks."""
    return sorted({CHECK_ACCEPTANCE_CLAIMS[check_id] for check_id in check_ids
                   if check_id in CHECK_ACCEPTANCE_CLAIMS})
_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SSR_FRAMEWORK_HINT_PACKAGES = {"next", "nuxt", "@sveltejs/kit", "@remix-run/node"}
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


class WorkflowError(ValueError):
    """Invalid workflow record, transition, or persisted state."""


def _reject_constant(value: str) -> None:
    raise WorkflowError(f"Invalid JSON number: {value}")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def read_json(path: str | Path, max_bytes: int = 32 * 1024 * 1024) -> Any:
    """Read one bounded regular JSON file without following a symlink."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise WorkflowError("Safe no-follow JSON reads are unavailable on this platform")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise WorkflowError("Workflow record must be a regular file")
        if info.st_size > max_bytes:
            raise WorkflowError("Workflow record exceeds JSON size budget")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise WorkflowError("Workflow record exceeds JSON size budget")
        return json.loads(payload, parse_constant=_reject_constant)
    finally:
        os.close(fd)


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


def _base(record: Any, kind: str) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
        raise WorkflowError(f"Expected schema_version {SCHEMA_VERSION} {kind} record")
    if record.get("record_type") != kind:
        raise WorkflowError(f"Expected {kind} record")
    identifier = record.get("id")
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise WorkflowError(f"Invalid {kind} id")
    return record


def _reference_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise WorkflowError(f"Invalid {field}")
    return value


def _private_directory(path: str | Path) -> Path:
    root = Path(path)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise WorkflowError("Workflow store must be a real directory")
    if os.name != "nt":
        if root.stat().st_uid != os.getuid():
            raise WorkflowError("Workflow store must be owned by the current user")
        root.chmod(0o700)
    return root


def validate_target(record: Any) -> dict[str, Any]:
    value = _base(record, "target")
    components = value.get("components")
    if not isinstance(components, list) or not components:
        raise WorkflowError("Target requires at least one discovered component")
    for component in components:
        if not isinstance(component, dict) or not all(isinstance(component.get(k), str) and component[k] for k in ("id", "kind")):
            raise WorkflowError("Each target component requires non-empty id and kind")
        if not _ID.fullmatch(component["id"]):
            raise WorkflowError("Invalid target component id")
    if len({x["id"] for x in components}) != len(components):
        raise WorkflowError("Target component ids must be unique")
    if "entrypoint_hints" in value:
        hints = value["entrypoint_hints"]
        files = value.get("files")
        file_paths = ({item.get("path") for item in files if isinstance(item, dict)}
                      if isinstance(files, list) else set())
        seen_hints = set()
        if not isinstance(hints, list):
            raise WorkflowError("Target entrypoint hints must be a list")
        for hint in hints:
            if (not isinstance(hint, dict) or not isinstance(hint.get("path"), str)
                    or not hint["path"] or Path(hint["path"]).is_absolute()
                    or ".." in Path(hint["path"]).parts or hint["path"] not in file_paths
                    or hint.get("role") not in {"service_worker_candidate", "web_worker_candidate"}
                    or not isinstance(hint.get("basis"), str) or not hint["basis"]
                    or hint.get("component_id") is not None
                    and hint.get("component_id") not in {item["id"] for item in components}
                    or (hint["path"], hint["role"]) in seen_hints):
                raise WorkflowError("Target entrypoint hints require a known path, candidate role, and valid component")
            seen_hints.add((hint["path"], hint["role"]))
    if "framework_hints" in value or "framework_hint_scan_incomplete" in value:
        hints = value.get("framework_hints")
        manifest_records = value.get("manifests", [])
        if not isinstance(manifest_records, list):
            raise WorkflowError("Target framework hints require a manifest list")
        manifests = {item["path"] for item in manifest_records
                     if isinstance(item, dict) and isinstance(item.get("path"), str)}
        files = value.get("files", [])
        if not isinstance(files, list):
            raise WorkflowError("Target framework hints require an inventory file list")
        file_paths = {item["path"] for item in files
                      if isinstance(item, dict) and isinstance(item.get("path"), str)}
        component_ids = {item["id"] for item in components}
        component_by_root = {item["root"]: item for item in components
                             if isinstance(item.get("root"), str)}
        if (not isinstance(hints, list) or len(hints) > 256
                or not isinstance(value.get("framework_hint_scan_incomplete"), bool)):
            raise WorkflowError("Target framework hints exceed their bounded record contract")
        seen = set()
        for hint in hints:
            if (not isinstance(hint, dict)
                    or not isinstance(hint.get("manifest_path"), str)
                    or hint["manifest_path"] not in manifests
                    or hint["manifest_path"] not in file_paths
                    or Path(hint["manifest_path"]).is_absolute()
                    or ".." in Path(hint["manifest_path"]).parts
                    or "\\" in hint["manifest_path"]
                    or Path(hint["manifest_path"]).as_posix() != hint["manifest_path"]
                    or Path(hint["manifest_path"]).name != "package.json"
                    or not isinstance(hint.get("package_name"), str)
                    or hint["package_name"] not in _SSR_FRAMEWORK_HINT_PACKAGES
                    or hint.get("role") != "ssr_framework_candidate" or hint.get("verified") is not False
                    or not isinstance(hint.get("declared_in"), list) or not hint["declared_in"]
                    or any(not isinstance(item, str) for item in hint["declared_in"])
                    or len(set(hint["declared_in"])) != len(hint["declared_in"])
                    or any(item not in {"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
                           for item in hint["declared_in"])
                    or not isinstance(hint.get("component_id"), str)
                    or hint["component_id"] not in component_ids
                    or component_by_root.get(Path(hint["manifest_path"]).parent.as_posix(), {}).get("id")
                    != hint["component_id"]
                    or not isinstance(hint.get("basis"), str) or not hint["basis"]
                    or (hint["manifest_path"], hint["package_name"]) in seen):
                raise WorkflowError("Target framework hints require declared package identity, inventory manifest, and valid component")
            seen.add((hint["manifest_path"], hint["package_name"]))
    if "worker_references" in value or "worker_reference_scan_incomplete" in value:
        references = value.get("worker_references")
        incomplete = value.get("worker_reference_scan_incomplete")
        files = value.get("files")
        file_paths = ({item.get("path") for item in files if isinstance(item, dict)}
                      if isinstance(files, list) else set())
        component_ids = {item["id"] for item in components}
        if (not isinstance(references, list) or not isinstance(incomplete, bool)
                or len(references) > 4096):
            raise WorkflowError("Target worker references exceed their bounded record contract")
        for reference in references:
            if (not isinstance(reference, dict)
                    or not isinstance(reference.get("source_path"), str)
                    or reference["source_path"] not in file_paths
                    or not isinstance(reference.get("reference"), str)
                    or not reference["reference"] or len(reference["reference"]) > 4096
                    or reference.get("kind") not in {"service_worker_registration", "web_worker_constructor"}
                    or reference.get("status") not in {"resolved_in_inventory", "not_in_inventory", "unresolved_base_url"}
                    or reference.get("component_id") is not None
                    and reference.get("component_id") not in component_ids
                    or not isinstance(reference.get("basis"), str) or not reference["basis"]):
                raise WorkflowError("Target worker references require inventoried source, bounded literal, kind, status, and component")
            resolved = reference.get("resolved_path")
            status = reference["status"]
            if status == "unresolved_base_url":
                if resolved is not None:
                    raise WorkflowError("Unresolved worker references cannot claim a target path")
            elif (not isinstance(resolved, str) or not resolved or Path(resolved).is_absolute()
                  or Path(resolved).as_posix() != resolved or "\\" in resolved
                  or ".." in Path(resolved).parts
                  or (status == "resolved_in_inventory") != (resolved in file_paths)):
                raise WorkflowError("Target worker references with resolved paths must match inventory status and remain inside the target")
    if "wasm_modules" in value or "wasm_metadata_scan_incomplete" in value:
        modules = value.get("wasm_modules")
        files = value.get("files")
        if not isinstance(files, list):
            raise WorkflowError("Target WebAssembly metadata requires the inventoried file list")
        file_records = {item.get("path"): item for item in files
                        if isinstance(item, dict) and isinstance(item.get("path"), str)}
        components_by_id = {item["id"]: item for item in components}
        if (not isinstance(modules, list) or len(modules) > 128
                or not isinstance(value.get("wasm_metadata_scan_incomplete"), bool)):
            raise WorkflowError("Target WebAssembly metadata exceeds its bounded record contract")
        seen_modules = set()
        for module in modules:
            path = module.get("path") if isinstance(module, dict) else None
            identity = file_records.get(path) if isinstance(path, str) else None
            imports = module.get("imports") if isinstance(module, dict) else None
            exports = module.get("exports") if isinstance(module, dict) else None
            if (not isinstance(module, dict) or not isinstance(path, str) or not path
                    or Path(path).is_absolute() or Path(path).as_posix() != path or "\\" in path
                    or ".." in Path(path).parts or Path(path).suffix.lower() != ".wasm"
                    or not isinstance(identity, dict) or module.get("sha256") != identity.get("sha256")
                    or module.get("status") not in {"parsed", "incomplete"}
                    or module.get("verified") is not False
                    or not isinstance(module.get("basis"), str) or not module["basis"]
                    or module["status"] == "incomplete" and
                    (not isinstance(module.get("reason"), str) or not module["reason"])
                    or module.get("component_id") is not None and module["component_id"] not in components_by_id
                    or not isinstance(imports, list) or len(imports) > 4096
                    or not isinstance(exports, list) or len(exports) > 4096
                    or path in seen_modules):
                raise WorkflowError("Target WebAssembly metadata requires a hash-bound inventoried module and bounded results")
            expected_component = module.get("component_id")
            module_path = Path(path)
            owners = [component for component in components
                      if isinstance(component.get("root"), str)
                      and (component["root"] == "." or Path(component["root"]) in module_path.parents)]
            owner = max(owners, key=lambda item: len(Path(item["root"]).parts)) if owners else None
            if (owner is not None and expected_component != owner["id"]
                    or owner is None and expected_component is not None):
                raise WorkflowError("Target WebAssembly metadata component does not own its module path")
            for imported in imports:
                if (not isinstance(imported, dict)
                        or not isinstance(imported.get("module"), str) or len(imported["module"]) > 4096
                        or not isinstance(imported.get("name"), str) or len(imported["name"]) > 4096
                        or imported.get("kind") not in {"function", "table", "memory", "global", "tag"}):
                    raise WorkflowError("Target WebAssembly imports require bounded module, name, and kind fields")
            for exported in exports:
                if (not isinstance(exported, dict)
                        or not isinstance(exported.get("name"), str) or len(exported["name"]) > 4096
                        or exported.get("kind") not in {"function", "table", "memory", "global", "tag"}):
                    raise WorkflowError("Target WebAssembly exports require bounded name and kind fields")
            seen_modules.add(path)
        wasm_paths = {path for path in file_records if Path(path).suffix.lower() == ".wasm"}
        if not value["wasm_metadata_scan_incomplete"] and seen_modules != wasm_paths:
            raise WorkflowError("Complete WebAssembly metadata must cover every inventoried module")
    if "unassigned_artifacts" in value:
        artifacts = value.get("artifacts")
        unassigned = value["unassigned_artifacts"]
        if (not isinstance(artifacts, list) or any(not isinstance(path, str) or not path
                                                    or Path(path).is_absolute() or ".." in Path(path).parts
                                                    for path in artifacts)
                or len(set(artifacts)) != len(artifacts)
                or not isinstance(unassigned, list)
                or any(not isinstance(path, str) or not path or Path(path).is_absolute()
                       or ".." in Path(path).parts for path in unassigned)
                or len(set(unassigned)) != len(unassigned)):
            raise WorkflowError("Target artifact lists must contain unique non-empty paths")
        owned = []
        for component in components:
            component_artifacts = component.get("artifacts")
            component_root = component.get("root")
            if (not isinstance(component_artifacts, list)
                    or any(not isinstance(path, str) or not path or Path(path).is_absolute()
                           or ".." in Path(path).parts for path in component_artifacts)
                    or len(set(component_artifacts)) != len(component_artifacts)
                    or not isinstance(component_root, str) or not component_root
                    or Path(component_root).is_absolute() or ".." in Path(component_root).parts):
                raise WorkflowError("Discovered components require a relative root and unique artifact paths")
            owned.extend(component_artifacts)
        if len(set(owned + unassigned)) != len(owned) + len(unassigned) or set(owned + unassigned) != set(artifacts):
            raise WorkflowError("Target component and unassigned artifacts must partition the target artifacts")
    return value


def validate_baseline(record: Any) -> dict[str, Any]:
    value = _base(record, "baseline")
    _reference_id(value.get("target_id"), "baseline target_id")
    if not isinstance(value.get("identity"), dict) or not value["identity"]:
        raise WorkflowError("Baseline requires source/build/artifact identity")
    artifacts = value["identity"].get("artifacts")
    build_duration = value["identity"].get("build_duration_ms")
    if build_duration is not None and (isinstance(build_duration, bool)
            or not isinstance(build_duration, int) or build_duration < 0):
        raise WorkflowError("Baseline build duration must be a nonnegative integer number of milliseconds")
    build_timing = value["identity"].get("build_timing")
    if build_timing is not None:
        trials = build_timing.get("trials") if isinstance(build_timing, dict) else None
        summary = build_timing.get("summary_ms") if isinstance(build_timing, dict) else None
        if (not isinstance(trials, list) or not 2 <= len(trials) <= 5
                or not isinstance(summary, dict)
                or set(summary) != {"min", "median", "max"}
                or not isinstance(build_timing.get("identical_artifacts"), bool)):
            raise WorkflowError("Baseline build timing evidence is malformed")
        durations = []
        trial_artifacts = []
        for trial in trials:
            measured = trial.get("elapsed_ms") if isinstance(trial, dict) else None
            hashes = trial.get("artifacts") if isinstance(trial, dict) else None
            evidence_path = trial.get("evidence_path") if isinstance(trial, dict) else None
            evidence_hash = trial.get("evidence_sha256") if isinstance(trial, dict) else None
            if (isinstance(measured, bool) or not isinstance(measured, int) or measured < 0
                    or not isinstance(hashes, dict) or not hashes or not isinstance(artifacts, dict)
                    or set(hashes) != set(artifacts)
                    or any(not isinstance(path, str) or not path or not isinstance(digest, str)
                           or not _SHA256.fullmatch(digest) for path, digest in hashes.items())
                    or not isinstance(evidence_path, str) or not Path(evidence_path).is_absolute()
                    or not isinstance(evidence_hash, str) or not _SHA256.fullmatch(evidence_hash)):
                raise WorkflowError("Baseline build timing trial is malformed")
            durations.append(measured)
            trial_artifacts.append(hashes)
        expected_summary = {"min": min(durations), "median": statistics.median(durations),
                            "max": max(durations)}
        if (build_duration != durations[0] or summary != expected_summary
                or build_timing["identical_artifacts"] != all(
                    hashes == trial_artifacts[0] for hashes in trial_artifacts[1:])
                or any(not isinstance(item, (int, float)) or isinstance(item, bool) or item < 0
                       for item in summary.values())):
            raise WorkflowError("Baseline build timing summary does not match its trials")
    if artifacts is not None and (not isinstance(artifacts, dict) or not artifacts
            or any(not isinstance(path, str) or not path or Path(path).is_absolute() or ".." in Path(path).parts
                   or not isinstance(item, dict) or isinstance(item.get("size"), bool)
                   or not isinstance(item.get("size"), int) or item["size"] < 0
                   or not isinstance(item.get("sha256"), str) or not _SHA256.fullmatch(item["sha256"])
                   or not isinstance(item.get("kind", "file"), str)
                   or item.get("kind", "file") not in {"file", "directory"}
                   for path, item in artifacts.items())):
        raise WorkflowError("Baseline artifact identities require safe paths, sizes, kinds, and SHA-256 values")
    flutter_toolchain = value["identity"].get("flutter_toolchain")
    if flutter_toolchain is not None:
        command = value["identity"].get("command")
        flutter = flutter_toolchain.get("flutter") if isinstance(flutter_toolchain, dict) else None
        android = flutter_toolchain.get("android") if isinstance(flutter_toolchain, dict) else None
        java = flutter_toolchain.get("java") if isinstance(flutter_toolchain, dict) else None
        build = flutter_toolchain.get("build") if isinstance(flutter_toolchain, dict) else None
        token = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+ -]{0,127}$")
        if (not isinstance(flutter, dict) or set(flutter) != {"framework_version", "channel", "framework_revision",
                                                              "engine_revision", "dart_sdk_version"}
                or any(not isinstance(item, str) or not token.fullmatch(item) for item in flutter.values())
                or not isinstance(android, dict)
                or set(android) not in ({"sdk_version", "platform_version", "build_tools_version"},
                                         {"sdk_version", "platform_version", "build_tools_version",
                                          "apksigner_sha256"})
                or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", item)
                       for key, item in android.items() if key != "apksigner_sha256")
                or ("apksigner_sha256" in android
                    and (not isinstance(android["apksigner_sha256"], str)
                         or not _SHA256.fullmatch(android["apksigner_sha256"])))
                or not isinstance(java, dict) or set(java) != {"binary", "version"}
                or not isinstance(java.get("binary"), str) or not Path(java["binary"]).is_absolute()
                or len(java["binary"]) > 1024 or not isinstance(java.get("version"), str)
                or not java["version"] or len(java["version"]) > 256
                or any(ord(char) < 32 for char in java["binary"] + java["version"])
                or not isinstance(build, dict) or set(build) != {"target", "command_sha256"}
                or not isinstance(command, list) or len(command) < 4
                or command[1:4] not in (["build", "apk", "--release"], ["build", "appbundle", "--release"])
                or build.get("target") != command[2]
                or not isinstance(build.get("command_sha256"), str)
                or not _SHA256.fullmatch(build["command_sha256"])
                or build["command_sha256"] != hashlib.sha256(canonical(command)).hexdigest()):
            raise WorkflowError("Baseline Flutter toolchain identity is malformed or does not bind its build command")
    if (not isinstance(value.get("evidence"), list) or not value["evidence"]
            or any(not isinstance(item, str) or not item for item in value["evidence"])):
        raise WorkflowError("Baseline requires retained evidence references")
    flutter_aot = value["identity"].get("flutter_aot_inspection")
    if flutter_aot is not None:
        from core import baseline as baseline_capture, dependencies, flutter_android
        expected = {"artifact_path", "artifact_sha256", "artifact_size", "abi", "operation", "status",
                    "report_path", "report_sha256", "runtime_manifest_path", "runtime_manifest_sha256",
                    "runtime_manifest_file_sha256"}
        artifacts = value["identity"].get("artifacts", {})
        artifact = artifacts.get(flutter_aot.get("artifact_path")) if isinstance(flutter_aot, dict) else None
        if (not isinstance(flutter_aot, dict) or set(flutter_aot) != expected
                or flutter_aot.get("operation") != "inspect_dart_aot"
                or flutter_aot.get("abi") not in {"arm64-v8a", "armeabi-v7a", "x86_64"}
                or flutter_aot.get("status") not in {"supported", "unsupported"}
                or not isinstance(artifact, dict)
                or flutter_aot.get("artifact_sha256") != artifact.get("sha256")
                or flutter_aot.get("artifact_size") != artifact.get("size")
                or any(not isinstance(flutter_aot.get(key), str) or not Path(flutter_aot[key]).is_absolute()
                       for key in ("report_path", "runtime_manifest_path"))
                or any(not isinstance(flutter_aot.get(key), str) or not _SHA256.fullmatch(flutter_aot[key])
                       for key in ("artifact_sha256", "report_sha256", "runtime_manifest_sha256",
                                   "runtime_manifest_file_sha256"))
                or not isinstance(flutter_toolchain, dict)
                or not isinstance(value["identity"].get("build_snapshot"), dict)
                or value["identity"].get("command", [None, None, None, None])[1:4]
                   != ["build", "apk", "--release"]
                or flutter_aot["report_path"] not in value["evidence"]
                or flutter_aot["runtime_manifest_path"] not in value["evidence"]):
            raise WorkflowError("Flutter AOT inspection must bind a captured APK, ABI, report, and pinned REA manifest")
        report_raw = verify_evidence_file({"path": flutter_aot["report_path"], "sha256": flutter_aot["report_sha256"]})
        manifest_raw = verify_evidence_file({"path": flutter_aot["runtime_manifest_path"],
                                             "sha256": flutter_aot["runtime_manifest_file_sha256"]})
        try:
            report = json.loads(report_raw)
            manifest = json.loads(manifest_raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise WorkflowError("Flutter AOT report or REA manifest is invalid JSON") from error
        rea_pin = json.loads(dependencies._upstreams_path().read_text())["integrations"]["rea"]
        if (not isinstance(manifest, dict)
                or manifest.get("schema_version") != "1.0"
                or manifest.get("npm_version") != rea_pin.get("npm_version")
                or manifest.get("npm_integrity") != rea_pin.get("npm_integrity")
                or manifest.get("package_lock_sha256") != rea_pin.get("package_lock_sha256")
                or hashlib.sha256(canonical(manifest)).hexdigest() != flutter_aot["runtime_manifest_sha256"]
                or flutter_android._classify_aot_report(report, flutter_aot,
                    str(Path(value["identity"]["build_snapshot"]["path"]) / flutter_aot["artifact_path"])
                    if isinstance(value["identity"].get("build_snapshot"), dict) else None) != flutter_aot["status"]
                or baseline_capture._hash_artifact(Path(value["identity"]["build_snapshot"]["path"]),
                    flutter_aot["artifact_path"]).get("sha256") != flutter_aot["artifact_sha256"]):
            raise WorkflowError("Flutter AOT inspection outcome or pinned REA manifest identity changed")
    if build_timing is not None:
        retained = set(value["evidence"])
        if any(trial["evidence_path"] not in retained for trial in build_timing["trials"]):
            raise WorkflowError("Baseline timing trial evidence is not retained")
    build_snapshot = value["identity"].get("build_snapshot")
    snapshot_baseline_id = value["identity"].get("snapshot_baseline_id", value["id"])
    if not isinstance(snapshot_baseline_id, str) or not _ID.fullmatch(snapshot_baseline_id):
        raise WorkflowError("Baseline snapshot source id is malformed")
    if build_snapshot is not None and (
            not isinstance(build_snapshot, dict)
            or not isinstance(build_snapshot.get("path"), str)
            or not Path(build_snapshot["path"]).is_absolute()
            or Path(build_snapshot["path"]).name != f"baseline-{snapshot_baseline_id}-build-snapshot"
            or not _SHA256.fullmatch(str(build_snapshot.get("source_tree_sha256", "")))
            or not _SHA256.fullmatch(str(build_snapshot.get("tree_sha256", "")))
            or not _SHA256.fullmatch(str(build_snapshot.get("file_scope_sha256", "")))):
        raise WorkflowError("Baseline build snapshot identity is malformed")
    if build_timing is not None:
        if not isinstance(build_snapshot, dict):
            raise WorkflowError("Repeated build timing requires a retained canonical build snapshot")
        snapshot_parent = Path(build_snapshot["path"]).parent
        for index, trial in enumerate(build_timing["trials"], start=1):
            evidence_path = Path(trial["evidence_path"])
            expected_name = (f"baseline-{value['id']}.json" if index == 1 else
                             f"baseline-{value['id']}-build-trial-{index}.json")
            if evidence_path.parent != snapshot_parent or evidence_path.name != expected_name:
                raise WorkflowError("Baseline build timing evidence path does not match its trial")
            raw = verify_evidence_file({"path": str(evidence_path), "sha256": trial["evidence_sha256"]})
            try:
                report = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise WorkflowError("Baseline build timing evidence is invalid JSON") from error
            if (not isinstance(report, dict) or not isinstance(report.get("argv"), list)
                    or not report["argv"] or any(not isinstance(arg, str) or not arg for arg in report["argv"])
                    or report.get("exit_code") != 0 or report.get("timed_out") is not False
                    or not isinstance(report.get("stdout_truncated"), bool)
                    or not isinstance(report.get("stderr_truncated"), bool)
                    or report.get("elapsed_ms") != trial["elapsed_ms"]
                    or report.get("artifacts_sha256") != trial["artifacts"]):
                raise WorkflowError("Baseline build timing report does not match its measured trial")
            if index == 1 and value["identity"].get("evidence_sha256") != trial["evidence_sha256"]:
                raise WorkflowError("Baseline primary build evidence hash differs from its timing record")
    behavior = value["identity"].get("behavior")
    if behavior is not None:
        artifacts = value["identity"].get("artifacts")
        if (not isinstance(behavior, dict) or not isinstance(behavior.get("command"), list)
                or not behavior["command"] or any(not isinstance(arg, str) or not arg for arg in behavior["command"])
                or behavior["command"].count("{artifact}") != 1
                or not isinstance(behavior.get("artifact"), str)
                or not isinstance(artifacts, dict) or behavior["artifact"] not in artifacts
                or not isinstance(artifacts.get(behavior["artifact"]), dict)
                or Path(behavior["artifact"]).suffix.lower() not in {".js", ".mjs", ".cjs"}
                or not isinstance(behavior.get("artifact_sha256"), str)
                or not _SHA256.fullmatch(behavior["artifact_sha256"])
                or behavior.get("artifact_sha256") != artifacts[behavior["artifact"]].get("sha256")
                or (any(key in behavior for key in ("snapshot_path", "snapshot_source_tree_sha256",
                                                    "snapshot_tree_sha256", "snapshot_file_scope_sha256"))
                    and (not isinstance(behavior.get("snapshot_path"), str)
                         or not Path(behavior["snapshot_path"]).is_absolute()
                         or Path(behavior["snapshot_path"]).name != f"baseline-{value['id']}-behavior-snapshot"
                         or any(not _SHA256.fullmatch(str(behavior.get(key, "")))
                                for key in ("snapshot_source_tree_sha256", "snapshot_tree_sha256",
                                            "snapshot_file_scope_sha256"))))
                or not isinstance(behavior.get("evidence_path"), str)
                or not Path(behavior["evidence_path"]).is_absolute()
                or behavior["evidence_path"] not in value["evidence"]
                or not isinstance(behavior.get("evidence_sha256"), str)
                or not _SHA256.fullmatch(behavior["evidence_sha256"])):
            raise WorkflowError("Baseline behavior identity must bind one captured JS artifact and hashed evidence")
    e2e = value["identity"].get("e2e_behavior")
    if e2e is not None:
        artifacts = value["identity"].get("artifacts")
        paths = (e2e.get("source_path"), e2e.get("snapshot_path"), e2e.get("report_path"),
                 e2e.get("runtime_path"), e2e.get("config"), e2e.get("test_file")) if isinstance(e2e, dict) else ()
        if (not isinstance(e2e, dict) or not isinstance(e2e.get("source_path"), str)
                or not isinstance(artifacts, dict) or e2e["source_path"] not in artifacts
                or not isinstance(artifacts[e2e["source_path"]], dict)
                or e2e.get("artifact_sha256") != artifacts[e2e["source_path"]].get("sha256")
                or any(not isinstance(path, str) or not path for path in paths)
                or any(not Path(e2e[key]).is_absolute() for key in ("snapshot_path", "report_path", "runtime_path"))
                or Path(e2e["snapshot_path"]).name != "snapshot"
                or Path(e2e["report_path"]).name != "report.json"
                or Path(e2e["snapshot_path"]).parent != Path(e2e["report_path"]).parent
                or Path(e2e["snapshot_path"]).parent.name != f"baseline-{value['id']}-e2e"
                or any(Path(e2e[key]).is_absolute() or ".." in Path(e2e[key]).parts for key in ("config", "test_file"))
                or e2e.get("report_path") not in value["evidence"]
                or not isinstance(e2e.get("report_sha256"), str) or not _SHA256.fullmatch(e2e["report_sha256"])
                or not isinstance(e2e.get("tree_sha256"), str) or not _SHA256.fullmatch(e2e["tree_sha256"])
                or not isinstance(e2e.get("file_scope_sha256"), str) or not _SHA256.fullmatch(e2e["file_scope_sha256"])
                or not isinstance(e2e.get("runtime_manifest_sha256"), str)
                or not _SHA256.fullmatch(e2e["runtime_manifest_sha256"])
                or not isinstance(e2e.get("runtime_package_lock_sha256"), str)
                or not _SHA256.fullmatch(e2e["runtime_package_lock_sha256"])
                or not isinstance(e2e.get("runner"), dict)
                or not isinstance(e2e["runner"].get("name"), str)
                or not isinstance(e2e["runner"].get("version"), str)
                or not isinstance(e2e.get("test_ids"), list) or not e2e["test_ids"]
                or any(not isinstance(item, str) or not item for item in e2e["test_ids"])
                or len(set(e2e["test_ids"])) != len(e2e["test_ids"])
                or e2e.get("cleanup") != "loopback app port closed"):
            raise WorkflowError("Baseline e2e identity must bind the artifact, private snapshot, report, runtime, and passing test scope")
    rea = value["identity"].get("rea_analysis")
    if rea is not None:
        artifacts = value["identity"].get("artifacts")
        if (not isinstance(rea, dict) or not isinstance(rea.get("source_path"), str)
                or not isinstance(artifacts, dict) or rea["source_path"] not in artifacts
                or not isinstance(artifacts[rea["source_path"]], dict)
                or Path(rea["source_path"]).suffix.lower() not in {".js", ".mjs", ".cjs"}
                or rea.get("artifact_sha256") != artifacts[rea["source_path"]].get("sha256")
                or any(not isinstance(rea.get(key), str) or not Path(rea[key]).is_absolute()
                       for key in ("snapshot_path", "report_path", "bundle_path", "runtime_path"))
                or Path(rea["snapshot_path"]).name != "snapshot"
                or Path(rea["snapshot_path"]).parent.name != f"baseline-{value['id']}-rea"
                or Path(rea["report_path"]).parent != Path(rea["snapshot_path"]).parent
                or Path(rea["bundle_path"]).parent != Path(rea["snapshot_path"]).parent
                or not _SHA256.fullmatch(str(rea.get("tree_sha256", "")))
                or not _SHA256.fullmatch(str(rea.get("file_scope_sha256", "")))
                or not _SHA256.fullmatch(str(rea.get("artifact_sha256", "")))
                or not _SHA256.fullmatch(str(rea.get("report_sha256", "")))
                or not _SHA256.fullmatch(str(rea.get("bundle_sha256", "")))
                or not _SHA256.fullmatch(str(rea.get("runtime_manifest_sha256", "")))
                or not isinstance(rea.get("evidence_id"), str) or not rea["evidence_id"]
                or not _SHA256.fullmatch(str(rea.get("parent_digest", "")))
                or rea.get("report_path") not in value["evidence"]
                or rea.get("bundle_path") not in value["evidence"]):
            raise WorkflowError("Baseline REA identity must bind a JS artifact, private snapshot, report, bundle, and runtime")
    return value


def validate_baseline_target(baseline: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    captured_baseline = validate_baseline(baseline)
    discovered_target = validate_target(target)
    if captured_baseline["target_id"] != discovered_target["id"]:
        raise WorkflowError("Baseline does not match its discovered target")
    e2e = captured_baseline["identity"].get("e2e_behavior")
    rea = captured_baseline["identity"].get("rea_analysis")
    flutter_aot = captured_baseline["identity"].get("flutter_aot_inspection")
    source_root = discovered_target.get("source_root")
    build_snapshot = captured_baseline["identity"].get("build_snapshot")
    if build_snapshot is not None and isinstance(source_root, str):
        target_root = Path(source_root).resolve(strict=False)
        path = Path(build_snapshot["path"]).resolve(strict=False)
        if path == target_root or path in target_root.parents or target_root in path.parents:
            raise WorkflowError("Baseline build snapshot must remain outside the target tree")
    if e2e is not None and isinstance(source_root, str):
        target_root = Path(source_root).resolve(strict=False)
        for key in ("snapshot_path", "report_path", "runtime_path"):
            path = Path(e2e[key]).resolve(strict=False)
            if path == target_root or path in target_root.parents or target_root in path.parents:
                raise WorkflowError("Baseline e2e snapshot, report, and runtime must remain outside the target tree")
    behavior = captured_baseline["identity"].get("behavior")
    if behavior is not None and "snapshot_path" in behavior and isinstance(source_root, str):
        target_root = Path(source_root).resolve(strict=False)
        path = Path(behavior["snapshot_path"]).resolve(strict=False)
        if path == target_root or path in target_root.parents or target_root in path.parents:
            raise WorkflowError("Baseline behavior snapshot must remain outside the target tree")
    if rea is not None and isinstance(source_root, str):
        target_root = Path(source_root).resolve(strict=False)
        for key in ("snapshot_path", "report_path", "bundle_path", "runtime_path"):
            path = Path(rea[key]).resolve(strict=False)
            if path == target_root or path in target_root.parents or target_root in path.parents:
                raise WorkflowError("Baseline REA snapshot, report, bundle, and runtime must remain outside the target tree")
    if flutter_aot is not None and isinstance(source_root, str):
        target_root = Path(source_root).resolve(strict=False)
        for key in ("report_path", "runtime_manifest_path"):
            path = Path(flutter_aot[key]).resolve(strict=False)
            if path == target_root or path in target_root.parents or target_root in path.parents:
                raise WorkflowError("Flutter AOT report and REA runtime manifest must remain outside the target tree")
    return captured_baseline


def validate_plan(record: Any) -> dict[str, Any]:
    value = _base(record, "plan")
    _reference_id(value.get("target_id"), "plan target_id")
    _reference_id(value.get("baseline_id"), "plan baseline_id")
    actions = value.get("actions")
    blockers = value.get("blockers", [])
    if (not isinstance(actions, list) or not isinstance(blockers, list)
            or (not actions and not blockers)
            or any(not isinstance(item, str) or not item.strip() for item in blockers)):
        raise WorkflowError("Plan requires a concrete action or an explicit readiness blocker")
    for action in actions:
        required_text = ("id", "finding_or_asset", "change", "mechanism", "engine", "expected_benefit", "cost", "rollback")
        required_lists = ("tradeoffs", "dependencies", "compatibility", "verification", "limitations")
        if (not isinstance(action, dict)
                or any(not isinstance(action.get(key), str) or not action[key] for key in required_text)
                or any(not isinstance(action.get(key), list) or not action[key]
                       or any(not isinstance(item, str) or not item for item in action[key]) for key in required_lists)):
            raise WorkflowError("Each plan action requires scope, mechanism, benefit, trade-offs, dependencies, compatibility, verification, limitations, and rollback")
        if not _ID.fullmatch(action["id"]):
            raise WorkflowError("Invalid plan action id")
    if len({x["id"] for x in actions}) != len(actions):
        raise WorkflowError("Plan action ids must be unique")
    profile = value.get("profile")
    if profile is not None:
        if (not isinstance(profile, dict) or set(profile) != {"name", "bla_intensity", "scope"}
                or not isinstance(profile.get("name"), str)
                or profile.get("name") not in {*PLAN_PROFILE_INTENSITIES, "custom"}
                or not isinstance(profile.get("bla_intensity"), str)
                or profile.get("bla_intensity") not in PLAN_BLA_INTENSITIES
                or profile.get("scope") != "BLA JavaScript actions only"):
            raise WorkflowError("Plan profile is invalid")
        if (profile["name"] != "custom"
                and profile["bla_intensity"] != PLAN_PROFILE_INTENSITIES[profile["name"]]):
            raise WorkflowError("Plan profile intensity does not match its named starting profile")
        for action in actions:
            config = action.get("execution")
            if isinstance(config, dict) and config.get("adapter") == "bla-js":
                if config.get("intensity") != profile["bla_intensity"]:
                    raise WorkflowError("BLA action intensity does not match the bound plan profile")
    for action in actions:
        if "performance" in action["verification"]:
            if (action.get("engine") != "bla" or not isinstance(action.get("execution"), dict)):
                raise WorkflowError("Performance check requires the BLA JavaScript execution adapter")
            validate_performance_budget(action["execution"].get("performance_budget"))
    budgets = value.get("budgets")
    if not isinstance(budgets, dict) or not budgets:
        raise WorkflowError("Plan requires explicit budgets")
    for key, limit in budgets.items():
        if (not isinstance(key, str) or not key or isinstance(limit, bool)
                or not isinstance(limit, (int, float)) or not math.isfinite(limit) or limit < 0):
            raise WorkflowError("Plan budgets must be named non-negative numbers")
    if not isinstance(value.get("rollback"), str) or not value["rollback"]:
        raise WorkflowError("Plan requires rollback instructions")
    return value


def validate_performance_budget(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or value.get("trials") != 3
            or isinstance(value.get("trials"), bool)
            or isinstance(value.get("max_elapsed_ms"), bool)
            or not isinstance(value.get("max_elapsed_ms"), int) or value["max_elapsed_ms"] <= 0
            or isinstance(value.get("max_candidate_bytes"), bool)
            or not isinstance(value.get("max_candidate_bytes"), int)
            or not 1 <= value["max_candidate_bytes"] <= 64 * 1024 * 1024
            or ("max_journey_regression_pct" in value
                and (isinstance(value["max_journey_regression_pct"], bool)
                     or not isinstance(value["max_journey_regression_pct"], (int, float))
                     or not math.isfinite(value["max_journey_regression_pct"])
                     or not 0 <= value["max_journey_regression_pct"] <= 1000))):
        raise WorkflowError("Performance budget requires exactly 3 trials and positive elapsed and candidate-size limits")
    return value


def validate_optimization_search(record: Any, plan: dict[str, Any] | None = None,
                                 baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate an immutable, explicitly bounded search scope for a plan."""
    value = _base(record, "optimization_search")
    for field in ("target_id", "baseline_id", "plan_id"):
        _reference_id(value.get(field), f"optimization search {field}")
    if (any(not isinstance(value.get(key), str) or not _SHA256.fullmatch(value[key])
            for key in ("baseline_sha256", "source_identity_sha256", "plan_sha256"))
            or not isinstance(value.get("decision_source"), str)
            or not value["decision_source"].strip()):
        raise WorkflowError("Optimization search requires source, baseline, and plan hashes plus an explicit decision source")
    runtime_identities = value.get("runtime_identities")
    if (not isinstance(runtime_identities, dict)
            or any(key not in {"bla-agents", "rea", "e2e"} or not isinstance(digest, str)
                   or not _SHA256.fullmatch(digest) for key, digest in runtime_identities.items())):
        raise WorkflowError("Optimization search requires valid pinned runtime identities")
    candidates = value.get("candidate_sets")
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 4:
        raise WorkflowError("Optimization search requires one to four approved candidate sets")
    candidate_ids = set()
    action_sets = set()
    estimated_cost = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise WorkflowError("Optimization candidate sets must be objects")
        candidate_id = _reference_id(candidate.get("id"), "optimization candidate id")
        candidate_cost = candidate.get("estimated_cost_micros")
        if isinstance(candidate_cost, bool) or not isinstance(candidate_cost, int) or candidate_cost < 0:
            raise WorkflowError("Optimization candidates require a non-negative estimated cost")
        estimated_cost += candidate_cost
        action_ids = candidate.get("action_ids")
        if (not isinstance(action_ids, list) or not action_ids
                or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in action_ids)
                or len(set(action_ids)) != len(action_ids)):
            raise WorkflowError("Optimization candidates require unique action ids")
        compatibility = candidate.get("compatibility_evidence")
        pairs = {tuple(sorted((action_ids[left], action_ids[right])))
                 for left in range(len(action_ids)) for right in range(left + 1, len(action_ids))}
        if not isinstance(compatibility, list) or len(compatibility) != len(pairs):
            raise WorkflowError("Every multi-action candidate requires bound compatibility evidence for each pair")
        seen_pairs = set()
        for item in compatibility:
            if (not isinstance(item, dict) or not isinstance(item.get("action_ids"), list)
                    or len(item["action_ids"]) != 2
                    or any(not isinstance(action_id, str) for action_id in item["action_ids"])
                    or not isinstance(item.get("evidence"), dict)):
                raise WorkflowError("Optimization compatibility evidence must identify one action pair")
            pair = tuple(sorted(item["action_ids"]))
            reference = item["evidence"]
            if (pair not in pairs or pair in seen_pairs
                    or not isinstance(reference.get("path"), str) or not Path(reference["path"]).is_absolute()
                    or not isinstance(reference.get("sha256"), str) or not _SHA256.fullmatch(reference["sha256"])):
                raise WorkflowError("Optimization compatibility evidence is invalid or outside its candidate set")
            try:
                proof = json.loads(verify_evidence_file(reference))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise WorkflowError("Optimization compatibility evidence is invalid JSON") from error
            if (not isinstance(proof, dict) or proof.get("schema_version") != "1.0"
                    or proof.get("record_type") != "optimizer_compatibility"
                    or proof.get("plan_sha256") != value["plan_sha256"]
                    or proof.get("baseline_sha256") != value["baseline_sha256"]
                    or proof.get("source_identity_sha256") != value["source_identity_sha256"]
                    or proof.get("action_ids") != list(pair)
                    or proof.get("compatible") is not True):
                raise WorkflowError("Optimization compatibility proof does not bind the source, baseline, plan, and action pair")
            seen_pairs.add(pair)
        action_set = frozenset(action_ids)
        if candidate_id in candidate_ids or action_set in action_sets:
            raise WorkflowError("Optimization candidate ids and action sets must be unique")
        candidate_ids.add(candidate_id)
        action_sets.add(action_set)
    budgets = value.get("budgets")
    budget_fields = ("max_elapsed_ms", "max_total_elapsed_ms", "max_candidate_bytes", "max_cost_micros")
    if (not isinstance(budgets, dict)
            or any(isinstance(budgets.get(key), bool) or not isinstance(budgets.get(key), int)
                   or budgets[key] < (0 if key == "max_cost_micros" else 1) for key in budget_fields)):
        raise WorkflowError("Optimization search requires positive time and size limits and a non-negative cost limit")
    if (not isinstance(budgets.get("cost_currency"), str)
            or not re.fullmatch(r"[A-Z]{3}", budgets["cost_currency"])):
        raise WorkflowError("Optimization search cost estimates require a three-letter currency code")
    if estimated_cost > budgets["max_cost_micros"]:
        raise WorkflowError("Approved candidate cost estimates exceed the total search cost limit")
    stop = value.get("stop_conditions")
    if (not isinstance(stop, dict) or not isinstance(stop.get("stop_on_first_acceptable"), bool)
            or stop.get("on_budget_exhaustion") != "stop"):
        raise WorkflowError("Optimization search requires reproducible stop conditions")
    if plan is not None:
        if baseline is None:
            raise WorkflowError("Optimization search validation requires the persisted baseline")
        approved_plan = validate_plan(plan)
        if (approved_plan["id"] != value["plan_id"]
                or approved_plan["target_id"] != value["target_id"]
                or approved_plan["baseline_id"] != value["baseline_id"]
                or record_hash(approved_plan) != value["plan_sha256"]):
            raise WorkflowError("Optimization search does not bind to the exact approved plan")
        allowed = {action["id"] for action in approved_plan["actions"]}
        if any(not set(candidate["action_ids"]) <= allowed for candidate in candidates):
            raise WorkflowError("Optimization candidate is outside the approved plan")
        actions_by_id = {action["id"]: action for action in approved_plan["actions"]}
        required_runtimes = set()
        for action_id in {item for candidate in candidates for item in candidate["action_ids"]}:
            action = actions_by_id[action_id]
            adapter = action.get("execution", {}).get("adapter") if isinstance(action.get("execution"), dict) else None
            if adapter == "bla-js":
                required_runtimes.add("bla-agents")
            if "rea_comparison" in action["verification"]:
                required_runtimes.add("rea")
            if "e2e_behavior" in action["verification"]:
                required_runtimes.add("e2e")
            if adapter not in {"bla-js", "source-map-candidate"}:
                raise WorkflowError("Optimization candidates require a supported executable action")
        if set(runtime_identities) != required_runtimes:
            raise WorkflowError("Optimization search must bind every required runtime identity exactly")
        plan_order = [action["id"] for action in approved_plan["actions"]]
        if any(candidate["action_ids"] != [action_id for action_id in plan_order
                                           if action_id in candidate["action_ids"]]
               for candidate in candidates):
            raise WorkflowError("Optimization candidate actions must preserve the saved plan order")
        if baseline is not None:
            captured = validate_baseline(baseline)
            if (captured["id"] != value["baseline_id"]
                    or captured["target_id"] != value["target_id"]
                    or record_hash(captured) != value["baseline_sha256"]
                    or record_hash(captured["identity"]) != value["source_identity_sha256"]):
                raise WorkflowError("Optimization search does not bind to the exact source and baseline identities")
    return value


def validate_optimization_selection(record: Any, search: dict[str, Any] | None = None) -> dict[str, Any]:
    value = _base(record, "optimization_selection")
    _reference_id(value.get("search_id"), "optimization selection search id")
    _reference_id(value.get("candidate_id"), "optimization selection candidate id")
    _reference_id(value.get("candidate_run_id"), "optimization selection candidate run id")
    if any(not isinstance(value.get(key), str) or not _SHA256.fullmatch(value[key])
           for key in ("search_sha256", "review_sha256", "runner_result_sha256")):
        raise WorkflowError("Optimization selection requires search and review hashes")
    _reference_id(value.get("runner_result_id"), "optimization runner result id")
    if (not isinstance(value.get("decision_source"), str) or not value["decision_source"].strip()):
        raise WorkflowError("Optimization selection requires an explicit decision source")
    mapping = value.get("candidate_runs")
    if (not isinstance(mapping, dict) or not 1 <= len(mapping) <= 4
            or any(not isinstance(candidate_id, str) or not _ID.fullmatch(candidate_id)
                   or not isinstance(run_id, str) or not _ID.fullmatch(run_id)
                   for candidate_id, run_id in mapping.items())
            or len(set(mapping.values())) != len(mapping)
            or mapping.get(value["candidate_id"]) != value["candidate_run_id"]):
        raise WorkflowError("Optimization selection requires its accepted candidate run mapping")
    if search is not None:
        validate_optimization_search(search)
        approved_ids = {item["id"] for item in search["candidate_sets"]}
        if (search["id"] != value["search_id"]
                or record_hash(search) != value["search_sha256"]
                or not set(mapping) <= approved_ids):
            raise WorkflowError("Optimization selection does not match its approved search")
    return value


def validate_optimization_search_result(record: Any, search: dict[str, Any] | None = None) -> dict[str, Any]:
    value = _base(record, "optimization_search_result")
    _reference_id(value.get("search_id"), "optimization search result search id")
    if not isinstance(value.get("search_sha256"), str) or not _SHA256.fullmatch(value["search_sha256"]):
        raise WorkflowError("Optimization runner result requires the approved search hash")
    outcomes = value.get("candidate_results")
    accepted = value.get("accepted_run_ids")
    if (not isinstance(outcomes, list) or not isinstance(accepted, dict)
            or any(not isinstance(item, dict) or not isinstance(item.get("candidate_id"), str)
                   or not isinstance(item.get("status"), str) for item in outcomes)
            or len({item["candidate_id"] for item in outcomes}) != len(outcomes)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in accepted.items())):
        raise WorkflowError("Optimization runner result outcomes are invalid")
    if search is not None:
        validate_optimization_search(search)
        if (value["search_id"] != search["id"] or value["search_sha256"] != record_hash(search)
                or [item["candidate_id"] for item in outcomes] != [x["id"] for x in search["candidate_sets"]]
                or any(accepted.get(item["candidate_id"]) != item.get("run_id")
                       for item in outcomes if item["status"] == "accepted")
                or set(accepted) != {item["candidate_id"] for item in outcomes
                                     if item["status"] == "accepted"}):
            raise WorkflowError("Optimization runner result does not match its approved search")
    return value


def validate_decision(record: Any, plan: dict[str, Any],
                      optimization_search: dict[str, Any] | None = None) -> dict[str, Any]:
    value = _base(record, "decision")
    validate_plan(plan)
    selected = value.get("selected_action_ids")
    decision = value.get("decision")
    if (not isinstance(selected, list) or any(not isinstance(x, str) for x in selected)
            or decision == "approved" and not selected):
        raise WorkflowError("Approved decisions require selected action ids")
    search_bound = any(key in value for key in ("optimization_search_id", "optimization_search_sha256",
                                                 "optimization_candidate_id"))
    if search_bound:
        if (optimization_search is None
                or value.get("optimization_search_id") != optimization_search.get("id")
                or value.get("optimization_search_sha256") != record_hash(optimization_search)
                or not isinstance(value.get("optimization_candidate_id"), str)):
            raise WorkflowError("Optimization decision requires its exact approved search record")
        candidate = next((item for item in optimization_search.get("candidate_sets", [])
                          if item.get("id") == value["optimization_candidate_id"]), None)
        if (candidate is None or optimization_search.get("plan_sha256") != record_hash(plan)
                or optimization_search.get("plan_id") != plan["id"]
                or candidate.get("action_ids") != selected):
            raise WorkflowError("Optimization decision does not match an approved candidate action set")
    elif decision == "approved" and len(selected) > 1:
        _validate_composite_actions(plan, selected)
    allowed = {action["id"] for action in plan["actions"]}
    if len(set(selected)) != len(selected) or not set(selected) <= allowed:
        raise WorkflowError("Decision selects duplicate or unapproved actions")
    if value.get("plan_sha256") != record_hash(plan):
        raise WorkflowError("Decision plan hash does not match the exact plan")
    if not isinstance(decision, str) or decision not in {"approved", "rejected"}:
        raise WorkflowError("Decision must explicitly approve or reject")
    if not isinstance(value.get("decision_source"), str) or not value["decision_source"]:
        raise WorkflowError("Decision source must be recorded")
    return value


def _validate_composite_actions(plan: dict[str, Any], action_ids: list[str]) -> list[dict[str, Any]]:
    approved_plan = validate_plan(plan)
    if not isinstance(action_ids, list) or len(action_ids) < 2:
        raise WorkflowError("Composite candidate requires at least two actions")
    by_id = {item["id"]: item for item in approved_plan["actions"]}
    order = [item["id"] for item in approved_plan["actions"] if item["id"] in action_ids]
    if order != action_ids or len(order) != len(set(action_ids)):
        raise WorkflowError("Composite actions must be unique and in saved plan order")
    actions = [by_id[action_id] for action_id in action_ids]
    paths = []
    for action in actions:
        config = action.get("execution")
        source_path = config.get("source_path") if isinstance(config, dict) else None
        if (action.get("engine") != "bla" or not isinstance(config, dict)
                or config.get("adapter") != "bla-js"
                or not isinstance(source_path, str) or Path(source_path).is_absolute()
                or not Path(source_path).parts or ".." in Path(source_path).parts
                or Path(source_path).suffix.lower() not in {".js", ".mjs", ".cjs"}):
            raise WorkflowError("Composite candidates support only safe BLA JavaScript actions")
        paths.append(Path(source_path).as_posix().casefold())
    if len(set(paths)) != len(paths) or any(
            first.startswith(second.rstrip("/") + "/") or second.startswith(first.rstrip("/") + "/")
            for index, first in enumerate(paths) for second in paths[index + 1:]):
        raise WorkflowError("Composite action source paths must be distinct and non-overlapping")
    verifications = [action["verification"] for action in actions]
    supported_checks = {"bla_invariants", "performance", "application_behavior", "rea_comparison", "e2e_behavior"}
    if (any(value != verifications[0] for value in verifications[1:])
            or "bla_invariants" not in verifications[0]
            or not set(verifications[0]) <= supported_checks):
        raise WorkflowError("Composite actions require compatible verification configurations")
    shared_fields = ("behavior_command", "e2e_config", "e2e_test_file", "e2e_runtime_manifest_sha256")
    for field in shared_fields:
        values = [action["execution"].get(field) for action in actions]
        if any(value != values[0] for value in values[1:]):
            raise WorkflowError("Composite actions require compatible behavior and e2e configurations")
    if "application_behavior" in verifications[0] and not actions[0]["execution"].get("behavior_command"):
        raise WorkflowError("Composite application behavior requires the same recorded behavior command")
    if any(isinstance(action["execution"].get("performance_budget"), dict)
           and action["execution"]["performance_budget"].get("max_journey_regression_pct") is not None
           for action in actions):
        raise WorkflowError("Composite BLA execution does not support per-action browser journey performance budgets")
    return actions


def validate_evidence_record(record: Any, kind: str) -> dict[str, Any]:
    """Validate evidence metadata shape; this does not authenticate referenced evidence."""
    value = _base(record, kind)
    _reference_id(value.get("run_id"), f"{kind} run_id")
    if kind == "execution":
        if not isinstance(value.get("plan_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", value["plan_sha256"]):
            raise WorkflowError("Execution requires a plan SHA-256")
        if (not isinstance(value.get("commands"), list) or not value["commands"]
                or any(not isinstance(c, list) or not c or any(not isinstance(a, str) for a in c) for c in value["commands"])):
            raise WorkflowError("Execution commands must be non-empty argument arrays")
        if (isinstance(value.get("exit_code"), bool) or value.get("exit_code") != 0
                or not isinstance(value.get("outputs"), list) or not value["outputs"]
                or any(not isinstance(x, dict) or not isinstance(x.get("path"), str) or not x["path"]
                       or not isinstance(x.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", x["sha256"])
                       for x in value["outputs"])):
            raise WorkflowError("Execution requires exit_code 0 and hashed output artifacts")
    elif kind == "verification":
        checks = value.get("checks")
        if (not isinstance(checks, list) or not checks
                or any(not isinstance(check, dict) or not isinstance(check.get("id"), str) or not check["id"] for check in checks)
                or len({check["id"] for check in checks}) != len(checks)):
            raise WorkflowError("Verification requires checks")
        for check in checks:
            if (not isinstance(check, dict) or not isinstance(check.get("id"), str) or not check["id"]
                    or not isinstance(check.get("status"), str)
                    or check["status"] not in {"passed", "failed", "blocked", "skipped"}
                    or not isinstance(check.get("evidence"), list) or not check["evidence"]
                    or any(not (isinstance(item, str) and item and check["status"] != "passed")
                           and not (isinstance(item, dict) and isinstance(item.get("path"), str)
                                    and Path(item["path"]).is_absolute()
                                    and isinstance(item.get("sha256"), str)
                                    and _SHA256.fullmatch(item["sha256"]))
                           for item in check["evidence"])):
                raise WorkflowError("Verification check requires an id, known status, and evidence references")
    elif kind == "acceptance":
        if (not isinstance(value.get("outcome"), str) or value["outcome"] not in ACCEPTANCE
                or not isinstance(value.get("claims"), list)
                or any(not isinstance(x, (str, dict)) or (isinstance(x, dict) and any(not isinstance(k, str) for k in x)) for x in value["claims"])
                or ("claim_ids" in value and (not isinstance(value["claim_ids"], list)
                    or any(not isinstance(x, str) or x not in ACCEPTANCE_CLAIM_IDS for x in value["claim_ids"])
                    or len(set(value["claim_ids"])) != len(value["claim_ids"])))
                or not isinstance(value.get("reasons"), list) or any(not isinstance(x, str) for x in value["reasons"])):
            raise WorkflowError("Acceptance requires a known outcome, valid claims and optional registered claim IDs, and reasons")
        if (not isinstance(value.get("verification_id"), str) or not _ID.fullmatch(value["verification_id"])
                or not isinstance(value.get("execution_id"), str) or not _ID.fullmatch(value["execution_id"])
                or not isinstance(value.get("plan_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", value["plan_sha256"])):
            raise WorkflowError("Acceptance must bind execution, verification, and plan identities")
    elif kind == "rollback":
        instructions = value.get("instructions")
        if not isinstance(instructions, list) or not instructions or any(not isinstance(x, str) or not x for x in instructions):
            raise WorkflowError("Rollback requires non-empty instructions")
        if not isinstance(value.get("artifacts"), list) or any(not isinstance(x, dict) for x in value["artifacts"]):
            raise WorkflowError("Rollback artifacts must be evidence objects")
    else:
        raise WorkflowError(f"Unknown evidence record type: {kind}")
    return value


def accept_run(run: dict[str, Any], target: dict[str, Any], baseline: dict[str, Any],
               plan: dict[str, Any], decision: dict[str, Any], execution: dict[str, Any],
               verification: dict[str, Any], acceptance: dict[str, Any],
               optimization_search: dict[str, Any] | None = None) -> dict[str, Any]:
    """Accept passing evidence or record a bound rejection without weakening the gate."""
    current = validate_run(run)
    discovered = validate_target(target)
    captured = validate_baseline_target(baseline, discovered)
    approved_plan = validate_plan_baseline(plan, captured)
    if optimization_search is not None:
        optimization_search = validate_optimization_search(optimization_search, approved_plan, captured)
    choice = validate_decision(decision, approved_plan, optimization_search)
    executed = validate_evidence_record(execution, "execution")
    checked = validate_evidence_record(verification, "verification")
    result = validate_evidence_record(acceptance, "acceptance")
    if current["state"] != "verifying":
        raise WorkflowError("Only a verifying run can be accepted")
    if (current["target_id"] != discovered["id"] or current.get("baseline_id") != captured["id"]
            or current.get("plan_id") != approved_plan["id"] or current.get("decision_id") != choice["id"]):
        raise WorkflowError("Run does not match its target, baseline, plan, and decision")
    if choice["decision"] != "approved":
        raise WorkflowError("Rejected decision cannot be accepted")
    if (executed["run_id"] != current["id"] or executed["plan_sha256"] != record_hash(approved_plan)
            or checked["run_id"] != current["id"] or result["run_id"] != current["id"]):
        raise WorkflowError("Evidence does not belong to this run and exact plan")
    if result.get("verification_id") != checked["id"] or result.get("execution_id") != executed["id"]:
        raise WorkflowError("Acceptance must reference the exact verification and execution evidence")
    if result.get("plan_sha256") != record_hash(approved_plan):
        raise WorkflowError("Acceptance does not match the exact approved plan")
    if ((current.get("execution_id") and current["execution_id"] != executed["id"])
            or (current.get("verification_id") and current["verification_id"] != checked["id"])):
        raise WorkflowError("Run execution or verification identities do not match acceptance evidence")
    if result["outcome"] == "rejected":
        if not result["reasons"] or any(not reason.strip() for reason in result["reasons"]):
            raise WorkflowError("Rejected result requires an explicit reason")
        return validate_run({**current, "state": "blocked", "acceptance_id": result["id"],
                             "acceptance": "rejected", "execution_id": executed["id"],
                             "verification_id": checked["id"]})
    if result["outcome"] != "accepted":
        raise WorkflowError("Only accepted or rejected outcomes can finalize verification")
    if result["claims"]:
        raise WorkflowError("Accepted results must use registered claim_ids instead of free-form claims")
    composite = len(choice["selected_action_ids"]) > 1
    if composite:
        _verify_composite_execution(current, captured, approved_plan, choice, executed, optimization_search)
    elif executed.get("action_id") != choice["selected_action_ids"][0]:
        raise WorkflowError("Execution must match the selected action for this run")
    if not checked["checks"] or any(check["status"] != "passed" for check in checked["checks"]):
        raise WorkflowError("Every verification check must pass before acceptance")
    required_checks = {item for action in approved_plan["actions"] if action["id"] in choice["selected_action_ids"]
                       for item in action["verification"]}
    passed_ids = {check["id"] for check in checked["checks"]}
    if not required_checks <= passed_ids:
        raise WorkflowError("Verification evidence omits checks required by the selected plan")
    unsupported = passed_ids - {"bla_invariants", "application_behavior", "rea_comparison", "e2e_behavior",
                               "performance", "public_source_map_absent", "flutter_aot_comparison",
                               "flutter_android_behavior"}
    if unsupported:
        raise WorkflowError(f"No semantic evidence validator is registered for: {', '.join(sorted(unsupported))}")
    passed_claims = {claim for claim, check_id in ACCEPTANCE_CLAIM_CHECKS.items() if check_id in passed_ids}
    claim_ids = result.get("claim_ids")
    if not claim_ids or not set(claim_ids) <= passed_claims:
        raise WorkflowError("Accepted claims must identify checks that passed semantic evidence validation")
    stage_executions = ({stage["action_id"]: _composite_stage_execution(executed, stage)
                         for stage in executed["action_stages"]} if composite else {})
    for check in checked["checks"]:
        raw_checks = []
        for evidence in check["evidence"]:
            raw_checks.append(verify_evidence_file(evidence, executed))
        if composite and check["id"] == "bla_invariants":
            references = check["evidence"]
            if len(references) != len(choice["selected_action_ids"]):
                raise WorkflowError("Composite BLA check must include one verifier report per selected action")
            by_action = {item.get("action_id"): (item, raw) for item, raw in zip(references, raw_checks)}
            if set(by_action) != set(choice["selected_action_ids"]):
                raise WorkflowError("Composite BLA check is missing or duplicates a selected action stage")
            for action_id in choice["selected_action_ids"]:
                reference, raw = by_action[action_id]
                _verify_bla_check(approved_plan, captured, discovered, stage_executions[action_id],
                                  [raw], [reference])
        elif composite and check["id"] == "performance":
            references = check["evidence"]
            by_action = {item.get("action_id"): (item, raw) for item, raw in zip(references, raw_checks)}
            if set(by_action) != set(choice["selected_action_ids"]) or len(by_action) != len(references):
                raise WorkflowError("Composite performance check must include one report per selected action")
            for action_id in choice["selected_action_ids"]:
                reference, raw = by_action[action_id]
                _verify_performance_check(approved_plan, captured, stage_executions[action_id],
                                          [raw], [reference])
        elif composite and check["id"] in {"application_behavior", "rea_comparison", "e2e_behavior"}:
            projection = _composite_final_execution(executed)
            if check["id"] == "application_behavior":
                _verify_behavior_check(approved_plan, captured, discovered, projection, raw_checks, check["evidence"])
            elif check["id"] == "rea_comparison":
                _verify_rea_check(current, approved_plan, captured, discovered, projection,
                                  raw_checks, check["evidence"])
            else:
                _verify_e2e_check(current, approved_plan, captured, discovered, projection,
                                  raw_checks, check["evidence"])
        elif check["id"] == "bla_invariants":
            _verify_bla_check(plan, captured, discovered, executed, raw_checks, check["evidence"])
        elif check["id"] == "application_behavior":
            _verify_behavior_check(plan, captured, discovered, executed, raw_checks, check["evidence"])
        elif check["id"] == "rea_comparison":
            _verify_rea_check(current, plan, captured, discovered, executed, raw_checks, check["evidence"])
        elif check["id"] == "e2e_behavior":
            _verify_e2e_check(current, plan, captured, discovered, executed, raw_checks, check["evidence"])
        elif check["id"] == "performance":
            _verify_performance_check(plan, captured, executed, raw_checks, check["evidence"])
        elif check["id"] == "public_source_map_absent":
            _verify_source_map_check(approved_plan, captured, executed, raw_checks, check["evidence"])
        elif check["id"] in {"flutter_aot_comparison", "flutter_android_behavior"}:
            _verify_flutter_check(approved_plan, captured, executed, check["id"], raw_checks, check["evidence"])
    if not result["reasons"]:
        raise WorkflowError("Accepted result requires reasons")
    return validate_run({**current, "state": "completed", "acceptance_id": result["id"], "acceptance": "accepted"})


def _composite_stage_execution(execution: dict[str, Any], stage: dict[str, Any]) -> dict[str, Any]:
    refs = [stage["protect_evidence"], stage["verify_evidence"]]
    if stage.get("performance_evidence"):
        refs.extend(sample["candidate_artifact"] for sample in stage["performance"]["trials"])
        refs.append(stage["performance_evidence"])
    value = {**execution, "action_id": stage["action_id"], "source_sha256": stage["input_sha256"],
             "outputs": [{"path": stage["candidate_path"], "sha256": stage["candidate_sha256"]}],
             "evidence": refs}
    if stage.get("performance") is not None:
        value["performance"] = stage["performance"]
    return value


def _composite_final_execution(execution: dict[str, Any]) -> dict[str, Any]:
    first = execution["action_stages"][0]
    return {**_composite_stage_execution(execution, first),
            "evidence": execution["evidence"],
            "rea_comparison": execution.get("rea_comparison"),
            "e2e_behavior": execution.get("e2e_behavior")}


def _tree_hash_for_files(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for path, file_hash in sorted(files.items()):
        digest.update(path.encode() + b"\0" + bytes.fromhex(file_hash))
    return digest.hexdigest()


def _verify_composite_stage_tree_chain(baseline_files: dict[str, str], stages: list[dict[str, Any]]) -> dict[str, str]:
    rolling = dict(baseline_files)
    for stage in stages:
        path = stage.get("source_path")
        output_hash = stage.get("candidate_sha256")
        if (not isinstance(path, str) or not isinstance(output_hash, str)
                or stage.get("input_tree_sha256") != _tree_hash_for_files(rolling)):
            raise WorkflowError("Composite action stages are disconnected or out of sequence")
        rolling[path] = output_hash
        if stage.get("output_tree_sha256") != _tree_hash_for_files(rolling):
            raise WorkflowError("Composite action stage output tree hash is invalid")
    return rolling


def _verify_composite_execution(run: dict[str, Any], baseline: dict[str, Any], plan: dict[str, Any],
                                decision: dict[str, Any], execution: dict[str, Any],
                                optimization_search: dict[str, Any] | None) -> None:
    if optimization_search is not None and not all(key in decision for key in
            ("optimization_search_id", "optimization_search_sha256", "optimization_candidate_id")):
        raise WorkflowError("Optimization search cannot be attached to a standard composite decision")
    actions = _validate_composite_actions(plan, decision["selected_action_ids"])
    stage_list = execution.get("action_stages")
    binding = execution.get("optimization_search")
    tree = execution.get("candidate_tree")
    measurements = execution.get("optimization_measurements")
    if (execution.get("action_id") != decision["selected_action_ids"][0]
            or execution.get("action_ids") != decision["selected_action_ids"]
            or (optimization_search is None and binding is not None)
            or (optimization_search is not None and binding != {
                "id": optimization_search["id"], "sha256": record_hash(optimization_search),
                "candidate_id": decision["optimization_candidate_id"]})
            or not isinstance(stage_list, list) or len(stage_list) != len(actions)
            or [item.get("action_id") for item in stage_list] != decision["selected_action_ids"]
            or not isinstance(tree, dict) or not isinstance(tree.get("path"), str)
            or not isinstance(tree.get("tree_sha256"), str) or not _SHA256.fullmatch(tree["tree_sha256"])
            or not isinstance(tree.get("file_scope_sha256"), str)
            or not _SHA256.fullmatch(tree["file_scope_sha256"])
            or not isinstance(measurements, dict)
            or isinstance(measurements.get("elapsed_ms"), bool)
            or not isinstance(measurements.get("elapsed_ms"), int) or measurements["elapsed_ms"] <= 0
            or isinstance(measurements.get("candidate_bytes"), bool)
            or not isinstance(measurements.get("candidate_bytes"), int) or measurements["candidate_bytes"] <= 0
            or not isinstance(tree.get("manifest_evidence"), dict)):
        raise WorkflowError("Composite execution is not bound to the exact approved action set")
    manifest_ref = tree["manifest_evidence"]
    if (len(execution["outputs"]) != 1
            or execution["outputs"][0] != {"path": manifest_ref.get("path"),
                                           "sha256": manifest_ref.get("sha256")}
            or manifest_ref.get("kind") != ("optimization-candidate-tree" if optimization_search is not None
                                              else "composite-candidate-tree")
            or not _execution_evidence_matches(execution, manifest_ref)):
        raise WorkflowError("Composite output must be the hash-bound candidate tree manifest")
    raw_manifest = verify_evidence_file(manifest_ref)
    try:
        manifest = json.loads(raw_manifest)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise WorkflowError("Composite candidate tree manifest is invalid JSON") from error
    candidate_root = Path(tree["path"])
    evidence_root = Path(manifest_ref["path"]).parent.resolve(strict=True)
    snapshot_path = Path(baseline["identity"]["build_snapshot"]["path"]).resolve(strict=True)
    state_root = snapshot_path.parent.parent
    candidates_root = state_root / "candidates"
    candidate_read_root = candidate_root if candidate_root.exists() else _retained_candidate(candidate_root, execution)
    if (candidate_read_root is None or candidate_root.is_symlink() or not candidate_read_root.is_dir()
            or evidence_root != state_root / "evidence"
            or candidate_root.parent.resolve(strict=True) != candidates_root.resolve(strict=True)
            or candidates_root.is_symlink()):
        raise WorkflowError("Composite candidate tree is outside the private candidates directory")
    expected_stages = []
    expected_by_path = {}
    stage_elapsed = 0
    artifacts = baseline["identity"]["artifacts"]
    for action, stage in zip(actions, stage_list):
        config = action["execution"]
        source_path = config["source_path"]
        identity = artifacts.get(source_path)
        if (not isinstance(identity, dict) or stage.get("source_path") != source_path
                or stage.get("input_sha256") != identity.get("sha256")
                or stage.get("candidate_path") != str((candidate_root / source_path).resolve(strict=False))
                or not isinstance(stage.get("candidate_sha256"), str)
                or not _SHA256.fullmatch(stage["candidate_sha256"])
                or not isinstance(stage.get("input_tree_sha256"), str)
                or not _SHA256.fullmatch(stage["input_tree_sha256"])
                or not isinstance(stage.get("output_tree_sha256"), str)
                or not _SHA256.fullmatch(stage["output_tree_sha256"])):
            raise WorkflowError("Composite action stage input or output identity is invalid")
        if (isinstance(stage.get("elapsed_ms"), bool) or not isinstance(stage.get("elapsed_ms"), int)
                or stage["elapsed_ms"] <= 0):
            raise WorkflowError("Composite action stage requires a positive measured duration")
        stage_elapsed += stage["elapsed_ms"]
        for field, kind in (("protect_evidence", "bla-protect"), ("verify_evidence", "bla-verify")):
            reference = stage.get(field)
            if (not isinstance(reference, dict) or reference.get("kind") != kind
                    or not _execution_evidence_matches(execution, {**reference, "action_id": action["id"]})):
                raise WorkflowError("Composite action stage evidence is missing or detached")
        perf = "performance" in action["verification"]
        if perf != isinstance(stage.get("performance"), dict) or perf != isinstance(stage.get("performance_evidence"), dict):
            raise WorkflowError("Composite performance evidence does not match the selected plan")
        if perf and (stage["performance_evidence"].get("kind") != "performance"
                     or not _execution_evidence_matches(
                         execution, {**stage["performance_evidence"], "action_id": action["id"]})):
            raise WorkflowError("Composite performance report is detached from its action stage")
        if perf:
            samples = stage["performance"].get("trials")
            if not isinstance(samples, list) or len(samples) != validate_performance_budget(
                    config.get("performance_budget"))["trials"]:
                raise WorkflowError("Composite performance stage has an invalid trial set")
            for sample in samples:
                artifact = sample.get("candidate_artifact") if isinstance(sample, dict) else None
                bound_reference = {**artifact, "action_id": action["id"]} if isinstance(artifact, dict) else None
                if (not isinstance(artifact, dict)
                        or artifact.get("kind") != "performance-candidate"
                        or not any(item == bound_reference for item in execution.get("evidence", []))):
                    raise WorkflowError("Composite performance candidate bytes are detached from their stage")
        expected_stages.append(stage)
        expected_by_path[source_path] = stage["candidate_sha256"]
    if (manifest.get("schema_version") != "1.0"
            or manifest.get("record_type") != ("optimization_candidate_tree" if optimization_search is not None
                                                 else "composite_candidate_tree")
            or manifest.get("run_id") != run["id"]
            or (optimization_search is not None and (
                manifest.get("search_id") != optimization_search["id"]
                or manifest.get("search_sha256") != record_hash(optimization_search)
                or manifest.get("candidate_id") != decision["optimization_candidate_id"]))
            or (optimization_search is None and any(key in manifest for key in
                ("search_id", "search_sha256", "candidate_id")))
            or manifest.get("plan_sha256") != record_hash(plan)
            or manifest.get("baseline_sha256") != record_hash(baseline)
            or manifest.get("action_ids") != decision["selected_action_ids"]
            or manifest.get("candidate_path") != str(candidate_root.resolve(strict=False))
            or manifest.get("candidate_tree_sha256") != tree["tree_sha256"]
            or manifest.get("candidate_file_scope_sha256") != tree["file_scope_sha256"]
            or manifest.get("optimization_measurements") != measurements
            or manifest.get("stages") != [{"action_id": stage["action_id"],
                "source_path": stage["source_path"], "input_sha256": stage["input_sha256"],
                "candidate_sha256": stage["candidate_sha256"],
                "input_tree_sha256": stage["input_tree_sha256"],
                "output_tree_sha256": stage["output_tree_sha256"],
                "elapsed_ms": stage["elapsed_ms"]} for stage in stage_list]
            or tree.get("candidate_bytes") != measurements["candidate_bytes"]
            or manifest.get("candidate_bytes") != measurements["candidate_bytes"]
            or measurements["elapsed_ms"] < stage_elapsed):
        raise WorkflowError("Composite candidate tree manifest identity does not match its run")
    from core import discovery
    from core.execution import _snapshot_tree_identity, _verify_build_snapshot
    baseline_root = _verify_build_snapshot(baseline)
    baseline_files = {item["path"]: item["sha256"]
                      for item in discovery.inspect_project(baseline_root)["files"]}
    candidate_files = {item["path"]: item["sha256"]
                      for item in discovery.inspect_project(candidate_read_root)["files"]}
    candidate_file_sizes = {item["path"]: item["size"]
                            for item in discovery.inspect_project(candidate_read_root)["files"]}
    actual_tree = _snapshot_tree_identity(candidate_read_root)
    rolling_files = _verify_composite_stage_tree_chain(baseline_files, stage_list)
    expected_files = {path: expected_by_path.get(path, digest) for path, digest in baseline_files.items()}
    if (candidate_files != expected_files or rolling_files != expected_files
            or manifest.get("candidate_files") != candidate_files
            or measurements["candidate_bytes"] != sum(candidate_file_sizes.values())
            or actual_tree["tree_sha256"] != tree["tree_sha256"]
            or actual_tree["file_scope_sha256"] != tree["file_scope_sha256"]):
        raise WorkflowError("Composite candidate tree differs from its baselined inputs and action stages")


def _verify_source_map_check(plan: dict, baseline: dict, execution: dict,
                             raw_checks: list[bytes], evidence: list[dict]) -> None:
    from core import baseline as baseline_capture, discovery

    action = next((item for item in plan["actions"] if item["id"] == execution.get("action_id")), None)
    config = action.get("execution") if action else None
    if (not action or not isinstance(config, dict) or config.get("adapter") != "source-map-candidate"
            or len(raw_checks) != 1 or len(evidence) != 1 or not isinstance(execution.get("source_map_candidate"), dict)):
        raise WorkflowError("Source-map acceptance requires its selected candidate manifest")
    try:
        manifest = json.loads(raw_checks[0])
        relative = config.get("source_path")
        snapshot = baseline.get("identity", {}).get("build_snapshot")
        artifacts = baseline.get("identity", {}).get("artifacts", {})
        map_identity = artifacts.get(relative)
        if (not isinstance(manifest, dict) or manifest.get("run_id") != execution["run_id"]
                or manifest.get("action_id") != action["id"]
                or manifest.get("plan_sha256") != record_hash(plan)
                or manifest.get("baseline_id") != baseline["id"]
                or not isinstance(snapshot, dict) or not isinstance(map_identity, dict)
                or manifest.get("source_path") != relative or not relative.lower().endswith(".map")
                or manifest.get("source_sha256") != map_identity.get("sha256")
                or manifest.get("baseline_tree_sha256") != snapshot.get("tree_sha256")
                or manifest.get("baseline_file_scope_sha256") != snapshot.get("file_scope_sha256")
                or execution["source_map_candidate"] != {key: value for key, value in manifest.items()
                                                          if key != "candidate_files"}):
            raise WorkflowError("Source-map manifest does not match the approved plan and baseline")
        source_root = Path(snapshot["path"])
        baseline_manifest = discovery.inspect_project(source_root)
        if baseline_manifest["unfollowed_symlinks"]:
            raise WorkflowError("Source-map baseline contains symlinks")
        base_files = {item["path"]: item["sha256"] for item in baseline_manifest["files"]}
        if (base_files.get(relative) != map_identity["sha256"]
                or baseline_capture._hash_artifact(source_root, relative) != map_identity):
            raise WorkflowError("Baseline source map changed after capture")
        candidate = Path(manifest["candidate_path"])
        evidence_parent = Path(evidence[0]["path"]).parent
        expected_parent = evidence_parent.parent / "candidates"
        candidate_read_root = candidate if candidate.exists() else _retained_candidate(candidate, execution)
        if (candidate.is_symlink() or candidate_read_root is None or not candidate_read_root.is_dir() or evidence_parent.is_symlink()
                or expected_parent.is_symlink()):
            raise WorkflowError("Source-map candidate tree is missing or linked")
        if candidate.parent.resolve(strict=True) != expected_parent.resolve(strict=True):
            raise WorkflowError("Source-map candidate is outside its private store")
        candidate_manifest = discovery.inspect_project(candidate_read_root)
        if candidate_manifest["unfollowed_symlinks"]:
            raise WorkflowError("Source-map candidate contains symlinks")
        candidate_files = {item["path"]: item["sha256"] for item in candidate_manifest["files"]}
        expected_files = {path: digest for path, digest in base_files.items() if path != relative}
        tree = hashlib.sha256()
        for path, digest in sorted(candidate_files.items()):
            tree.update(path.encode() + b"\0" + bytes.fromhex(digest))
        scope = hashlib.sha256("\n".join(sorted(candidate_files)).encode()).hexdigest()
        if (relative in candidate_files or candidate_files != expected_files
                or manifest.get("candidate_files") != candidate_files
                or manifest.get("candidate_tree_sha256") != tree.hexdigest()
                or manifest.get("candidate_file_scope_sha256") != scope):
            raise WorkflowError("Source-map candidate removed more than the selected map or changed other files")
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, AttributeError, ValueError) as error:
        if isinstance(error, WorkflowError):
            raise
        raise WorkflowError("Source-map candidate evidence is malformed") from error


def finalize_run(run: dict[str, Any], target: dict[str, Any], baseline: dict[str, Any],
                 plan: dict[str, Any], decision: dict[str, Any], execution: dict[str, Any],
                 verification: dict[str, Any], acceptance: dict[str, Any],
                 optimization_search: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Turn any failed accepted-result gate into a bound rejection, never a bypass."""
    current = validate_run(run)
    try:
        return accept_run(run, target, baseline, plan, decision, execution, verification, acceptance,
                          optimization_search), acceptance
    except WorkflowError as error:
        executed = validate_evidence_record(execution, "execution")
        checked = validate_evidence_record(verification, "verification")
        rejected = {"schema_version": SCHEMA_VERSION, "record_type": "acceptance",
                    "id": "reject-" + hashlib.sha256(
                        f"{current['id']}:{executed['id']}:{checked['id']}:{error}".encode()).hexdigest()[:24],
                    "run_id": current["id"], "outcome": "rejected", "claims": [],
                    "reasons": [f"Acceptance gate rejected candidate: {error}"],
                    "verification_id": checked["id"], "execution_id": executed["id"],
                    "plan_sha256": record_hash(plan)}
        return (accept_run(run, target, baseline, plan, decision, executed, checked, rejected,
                           optimization_search), rejected)


def refresh_blocked_flutter_verification(store: str | Path, run_id: str,
                                        verification: dict[str, Any]) -> dict[str, Any]:
    """Attach external Flutter evidence as a new immutable verification after a blocked build."""
    root = _private_directory(store)
    runs, records = root / "runs", root / "records"
    run_id = _reference_id(run_id, "run id")
    run_path = runs / f"run-{run_id}.json"
    current = validate_run(read_json(run_path))
    if current["state"] != "verifying" or not all(current.get(key) for key in
                                                  ("execution_id", "verification_id", "plan_id", "baseline_id")):
        raise WorkflowError("External Flutter verification requires a verifying run")
    target = validate_target(read_record(records / f"target-{current['target_id']}.json", "target"))
    baseline = validate_baseline_target(read_record(records / f"baseline-{current['baseline_id']}.json", "baseline"), target)
    plan = validate_plan_baseline(read_record(records / f"plan-{current['plan_id']}.json", "plan"), baseline)
    execution = read_record(records / f"execution-{current['execution_id']}.json", "execution")
    action = next((item for item in plan["actions"] if item["id"] == execution.get("action_id")), None)
    if (not action or action.get("engine") != "flutter-dart-obfuscation"
            or execution.get("run_id") != run_id or execution.get("plan_sha256") != record_hash(plan)):
        raise WorkflowError("External verification is available only for the bound Flutter candidate")
    previous = read_record(records / f"verification-{current['verification_id']}.json", "verification")
    checked = validate_evidence_record(verification, "verification")
    required = set(action["verification"])
    if (any(check["status"] != "blocked" for check in previous["checks"])
            or {check["id"] for check in previous["checks"]} != required
            or checked["id"] == previous["id"] or checked["run_id"] != run_id
            or {check["id"] for check in checked["checks"]} != required):
        raise WorkflowError("Flutter evidence must replace an all-blocked verification with a new complete record")
    write_record(records, checked)
    updated = validate_run({**current, "verification_id": checked["id"]})
    write_run_state(runs, updated, current)
    return updated


def _verify_flutter_check(plan: dict, baseline: dict, execution: dict, check_id: str,
                          raw_checks: list[bytes], evidence: list[dict]) -> None:
    """Validate package observations and behavior reports against the private candidate."""
    from core import baseline as baseline_capture
    from core.execution import _snapshot_tree_identity

    action = next((item for item in plan["actions"] if item["id"] == execution.get("action_id")), None)
    config = action.get("execution") if action else None
    output = execution.get("flutter_candidate")
    if (not action or action.get("engine") != "flutter-dart-obfuscation"
            or not isinstance(config, dict) or config.get("adapter") != "flutter-dart-obfuscation"
            or not isinstance(output, dict) or check_id not in action["verification"]):
        raise WorkflowError("Flutter semantic acceptance requires the selected candidate and required plan check")
    baseline_toolchain = baseline.get("identity", {}).get("flutter_toolchain")
    lock_hash = baseline.get("identity", {}).get("dependency_lock_sha256")
    try:
        candidate_path = Path(output["candidate_artifact"])
        candidate_sha = output["candidate_artifact_sha256"]
        baseline_artifact = baseline["identity"]["artifacts"][config["artifact_path"]]["sha256"]
        snapshot = baseline["identity"]["build_snapshot"]
        store_root = Path(snapshot["path"]).parent.parent.resolve(strict=True)
        if baseline_capture._hash_artifact(Path(snapshot["path"]), config["artifact_path"]).get("sha256") != baseline_artifact:
            raise WorkflowError("Flutter baseline APK changed after capture")
        candidates_root = store_root / "candidates"
        symbols_root = store_root / "symbols"
        symbols_path = Path(output["symbols_path"])
        candidate_read_path = candidate_path if candidate_path.exists() else _retained_candidate(candidate_path, execution)
        if (candidate_path.is_symlink() or candidate_path.parent.resolve(strict=True) != candidates_root.resolve(strict=True)
                or candidate_read_path is None
                or symbols_path.is_symlink() or symbols_path.parent.resolve(strict=True) != symbols_root.resolve(strict=True)
                or not isinstance(candidate_sha, str) or not _SHA256.fullmatch(candidate_sha)):
            raise WorkflowError("Flutter candidate APK or private symbol tree is missing, changed, or outside private state")
        candidate_identity = baseline_capture._hash_artifact(candidate_read_path.parent, candidate_read_path.name)
        if (candidate_identity.get("sha256") != candidate_sha
                or not isinstance(output.get("symbols_tree_sha256"), str)
                or _snapshot_tree_identity(symbols_path).get("tree_sha256") != output["symbols_tree_sha256"]
                or len(execution.get("outputs", [])) != 1
                or execution["outputs"][0].get("path") != str(candidate_path)
                or execution["outputs"][0].get("sha256") != candidate_sha):
            raise WorkflowError("Flutter candidate APK or private symbol tree is missing, changed, or outside private state")
        symbol_refs = [item for item in execution.get("evidence", [])
                       if isinstance(item, dict) and item.get("kind") == "flutter-split-debug-info"]
        if (len(symbol_refs) != 1 or symbol_refs[0].get("path") != str(symbols_path)
                or symbol_refs[0].get("sha256") != output.get("symbols_tree_sha256")):
            raise WorkflowError("Flutter symbol tree is not bound to the execution evidence")
        commands = execution.get("commands")
        argv = commands[0] if isinstance(commands, list) and len(commands) == 1 else None
        engine = execution.get("engine")
        expected_split = f"--split-debug-info={symbols_path}"
        if (not isinstance(baseline_toolchain, dict) or not isinstance(argv, list)
                or not isinstance(engine, dict)
                or argv.count("--obfuscate") != 1 or argv.count(expected_split) != 1
                or argv[:len(baseline["identity"]["command"])] != baseline["identity"]["command"]
                or argv[len(baseline["identity"]["command"]):] != ["--obfuscate", expected_split]
                or engine.get("version")
                != baseline_toolchain.get("flutter", {}).get("framework_version")):
            raise WorkflowError("Flutter execution record does not bind the obfuscation command and private symbols")
        if (not isinstance(baseline_toolchain, dict)
                or not isinstance(lock_hash, str) or not _SHA256.fullmatch(lock_hash)
                or output.get("dependency_lock_sha256") != lock_hash):
            raise WorkflowError("Flutter baseline toolchain or dependency lock identity is missing")
        if check_id == "flutter_aot_comparison":
            if len(evidence) != 2 or len(raw_checks) != 2:
                raise WorkflowError("Flutter AOT comparison requires two raw hash-bound REA reports")
            observations = []
            runtime_identities = set()
            selected_abi = config.get("selected_abi")
            required_sections = {"_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions",
                                "_kDartVmSnapshotData", "_kDartIsolateSnapshotData"}
            for reference, raw in zip(evidence, raw_checks):
                if verify_evidence_file(reference, execution) != raw:
                    raise WorkflowError("Flutter AOT evidence changed after it was authenticated")
                if reference.get("kind") != "rea-inspect-dart-aot":
                    raise WorkflowError("Flutter AOT evidence must reference raw REA inspect_dart_aot output")
                report = json.loads(raw)
                runtime_ref = reference.get("rea_runtime_manifest")
                if not isinstance(runtime_ref, dict):
                    raise WorkflowError("REA inspection reference lacks its pinned runtime manifest")
                runtime_raw = verify_evidence_file(runtime_ref, execution)
                runtime_manifest = json.loads(runtime_raw)
                runtime_hash = hashlib.sha256(canonical(runtime_manifest)).hexdigest()
                if (not isinstance(runtime_manifest, dict)
                        or runtime_ref.get("sha256") != hashlib.sha256(runtime_raw).hexdigest()
                        or reference.get("rea_runtime_manifest_sha256") != runtime_hash
                        or runtime_hash != config.get("rea_runtime_manifest_sha256")):
                    raise WorkflowError("REA runtime manifest hash mismatch")
                if not all(isinstance(runtime_manifest.get(key), str) and runtime_manifest[key]
                           for key in ("npm_version", "npm_integrity", "package_lock_sha256",
                                       "package_tree_sha256", "node_version")):
                    raise WorkflowError("REA runtime identity is incomplete")
                runtime_identities.add(runtime_hash)
                side = reference.get("side")
                expected_package_hash = baseline_artifact if side == "baseline" else candidate_sha if side == "candidate" else None
                expected_size = (baseline["identity"]["artifacts"][config["artifact_path"]]["size"]
                                 if side == "baseline" else candidate_identity["size"] if side == "candidate" else None)
                normalized = report.get("normalized_result") if isinstance(report, dict) else None
                subject_root = report.get("subject") if isinstance(report, dict) else None
                subject = subject_root.get("digest") if isinstance(subject_root, dict) else None
                libapp = normalized.get("libapp") if isinstance(normalized, dict) else None
                sections = libapp.get("sections") if isinstance(libapp, dict) else None
                section_names = {item.get("name") for item in sections if isinstance(item, dict)} if isinstance(sections, list) else set()
                section_records = [item for item in sections if isinstance(item, dict)] if isinstance(sections, list) else []
                provider = report.get("provider") if isinstance(report, dict) else None
                target_record = normalized.get("target") if isinstance(normalized, dict) else None
                if (not isinstance(report, dict) or not isinstance(provider, dict) or provider.get("id") != "flutter"
                        or reference.get("sha256") != hashlib.sha256(raw).hexdigest()
                        or report.get("predicate_type") != "rea.analysis" or report.get("operation") != "inspect_dart_aot"
                        or not report.get("evidence_id") or not isinstance(subject_root, dict)
                        or subject_root.get("format") != "apk" or not isinstance(subject, dict)
                        or subject.get("sha256") != expected_package_hash
                        or not isinstance(normalized, dict) or not isinstance(target_record, dict)
                        or target_record.get("sha256") != expected_package_hash
                        or target_record.get("bytes") != expected_size
                        or normalized.get("abi") != selected_abi
                        or reference.get("abi") != selected_abi
                        or not isinstance(libapp, dict) or libapp.get("coverage") != "complete"
                        or section_names != required_sections
                        or len(sections) != len(required_sections)
                        or any(isinstance(item.get("offset"), bool) or not isinstance(item.get("offset"), int)
                               or item["offset"] < 0 or isinstance(item.get("size"), bool)
                               or not isinstance(item.get("size"), int) or item["size"] <= 0
                               for item in section_records)
                        or not isinstance(libapp.get("sha256"), str) or not _SHA256.fullmatch(libapp["sha256"])
                        or not isinstance(libapp.get("snapshot_hash"), str) or not libapp["snapshot_hash"]):
                    raise WorkflowError("REA AOT report is incomplete or not bound to the exact selected APK and ABI")
                observations.append({"side": side, "package_sha256": expected_package_hash,
                                    "libapp_sha256": libapp["sha256"],
                                    "snapshot_hash": libapp["snapshot_hash"], "sections": section_names})
            if ({item["side"] for item in observations} != {"baseline", "candidate"}
                    or len(runtime_identities) != 1
                    or observations[0]["snapshot_hash"] != observations[1]["snapshot_hash"]
                    or observations[0]["libapp_sha256"] == observations[1]["libapp_sha256"]):
                raise WorkflowError("REA AOT observations do not provide a comparable baseline/candidate pair")
        else:
            if len(raw_checks) != 1 or len(evidence) != 1:
                raise WorkflowError("Flutter behavior verification requires one paired before/after report")
            if (evidence[0].get("kind") != "flutter-android-behavior"
                    or verify_evidence_file(evidence[0], execution) != raw_checks[0]):
                raise WorkflowError("Flutter behavior report is not a safe hash-bound evidence file")
            report = json.loads(raw_checks[0])
            if not isinstance(report, dict):
                raise WorkflowError("Flutter behavior report must be a JSON object")
            before, after = report.get("baseline"), report.get("candidate")
            if (not isinstance(report, dict) or report.get("schema_version") != "1.0"
                    or report.get("record_type") != "flutter-android-behavior"
                    or report.get("run_id") != execution["run_id"] or report.get("action_id") != action["id"]
                    or report.get("plan_sha256") != record_hash(plan)
                    or report.get("baseline_sha256") != record_hash(baseline)
                    or report.get("source_identity_sha256") != record_hash(baseline["identity"])
                    or report.get("toolchain_identity_sha256") != record_hash(baseline_toolchain)
                    or report.get("dependency_lock_sha256") != lock_hash
                    or not isinstance(before, dict) or not isinstance(after, dict)
                    or before.get("apk_sha256") != baseline_artifact or after.get("apk_sha256") != candidate_sha
                    or not isinstance(before.get("device_identity_sha256"), str)
                    or not _SHA256.fullmatch(before["device_identity_sha256"])
                    or before.get("device_identity_sha256") != after.get("device_identity_sha256")):
                raise WorkflowError("Flutter behavior report must bind the exact baseline/candidate APKs on one device")
            before_cases, after_cases = before.get("cases"), after.get("cases")
            before_ids = [item.get("case_id") for item in before_cases if isinstance(item, dict)] if isinstance(before_cases, list) else []
            after_ids = [item.get("case_id") for item in after_cases if isinstance(item, dict)] if isinstance(after_cases, list) else []
            if (not isinstance(before_cases, list) or not before_cases or not isinstance(after_cases, list)
                    or before_ids != after_ids or len(set(before_ids)) != len(before_ids)
                    or [item.get("case_id") for item in before_cases if isinstance(item, dict)]
                    != [item.get("case_id") for item in after_cases if isinstance(item, dict)]
                    or any(not isinstance(item, dict) or not isinstance(item.get("case_id"), str)
                           or not item["case_id"] or item.get("result") != "passed"
                           for item in [*before_cases, *after_cases])):
                raise WorkflowError("Flutter behavior cases must be identical, non-empty, and passing on both APKs")
            signing = report.get("signing_comparison")
            if not isinstance(signing, dict):
                raise WorkflowError("Flutter candidate signing comparison is missing; release signing remains unverified")
            signing_observations = []
            for side, expected_hash in (("baseline", baseline_artifact), ("candidate", candidate_sha)):
                reference = signing.get(side)
                if not isinstance(reference, dict) or reference.get("kind") != "apk-signature-verification":
                    raise WorkflowError("Flutter candidate signing comparison requires both hash-bound APK signature reports")
                signing_raw = verify_evidence_file(reference, execution)
                signed = json.loads(signing_raw)
                if (reference.get("sha256") != hashlib.sha256(signing_raw).hexdigest()
                        or not isinstance(signed, dict) or signed.get("record_type") != "apk-signature-verification"
                        or signed.get("apk_sha256") != expected_hash or signed.get("result") != "Verifies"
                        or isinstance(signed.get("signer_count"), bool) or signed.get("signer_count") != 1
                        or not isinstance(signed.get("certificate_sha256"), str)
                        or not _SHA256.fullmatch(signed["certificate_sha256"])):
                    raise WorkflowError("Flutter release signing report is incomplete or does not match its APK")
                from core import flutter_android
                apk_path = (Path(snapshot["path"]) / config["artifact_path"]
                            if side == "baseline" else candidate_read_path)
                verified = flutter_android.verify_apk_signature(
                    apk_path, baseline["identity"]["command"], baseline_toolchain, snapshot["path"])
                if (verified.get("apk_sha256") != expected_hash or verified.get("result") != "Verifies"
                        or verified.get("signer_count") != signed["signer_count"]
                        or verified.get("certificate_sha256") != [signed["certificate_sha256"]]):
                    raise WorkflowError("Flutter signature report does not match direct apksigner verification")
                signing_observations.append(signed["certificate_sha256"])
            if signing_observations[0] != signing_observations[1]:
                raise WorkflowError("Flutter candidate signing certificate differs from the captured baseline APK")
    except WorkflowError:
        raise
    except (KeyError, OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError, ValueError) as error:
        raise WorkflowError(f"Flutter semantic evidence is missing or invalid: {error}") from error


def verify_evidence_file(reference: dict[str, str], execution: dict[str, Any] | None = None) -> bytes:
    """Read and authenticate one bounded regular evidence file without following its final symlink."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise WorkflowError("Safe raw evidence authentication is unavailable on this platform")
    path = Path(reference["path"])
    if not path.exists() and not path.is_symlink():
        retained = _retained_candidate(path, execution)
        if retained is not None:
            reference = {**reference, "path": str(retained)}
    try:
        fd = os.open(reference["path"], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise WorkflowError(f"Verification evidence is missing, linked, or unreadable: {reference['path']}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_EVIDENCE_BYTES:
            raise WorkflowError("Verification evidence must be a regular file within the 64 MiB limit")
        digest = hashlib.sha256()
        size = 0
        contents = bytearray()
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > MAX_EVIDENCE_BYTES:
                raise WorkflowError("Verification evidence exceeds the 64 MiB limit")
            digest.update(chunk)
            contents.extend(chunk)
        after = os.fstat(fd)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or size != before.st_size:
            raise WorkflowError("Verification evidence changed while being authenticated")
        if digest.hexdigest() != reference["sha256"]:
            raise WorkflowError(f"Verification evidence hash mismatch: {reference['path']}")
        return bytes(contents)
    finally:
        os.close(fd)


def _retained_candidate(path: Path, execution: dict[str, Any] | None) -> Path | None:
    """Resolve an absent candidate only through its authenticated quarantine record."""
    if ".." in path.parts:
        return None
    original = Path(os.path.abspath(path))
    candidate_root = original
    while candidate_root.parent != candidate_root and candidate_root.parent.name != "candidates":
        candidate_root = candidate_root.parent
    if candidate_root.parent.name != "candidates":
        return None
    relative = original.relative_to(candidate_root)
    candidates = candidate_root.parent
    if (candidates.name != "candidates" or candidates.is_symlink() or not candidates.is_dir()
            or candidate_root.is_symlink()):
        return None
    store = candidates.parent
    records = store / "records"
    discarded = store / "discarded"
    if records.is_symlink() or discarded.is_symlink() or not discarded.is_dir():
        return None
    if execution is None:
        return None
    execution = validate_evidence_record(execution, "execution")
    matches = []
    for record_path in records.glob("rollback-*.json"):
        rollback = validate_evidence_record(read_record(record_path, "rollback"), "rollback")
        if record_path.stem != f"rollback-{rollback['id']}":
            raise WorkflowError("Rollback filename does not match its record id")
        artifacts = rollback.get("artifacts")
        artifact = (artifacts[0] if isinstance(artifacts, list) and len(artifacts) == 1 else None)
        if not isinstance(artifact, dict) or artifact.get("path") != str(candidate_root):
            continue
        retained = Path(artifact.get("retained_path", ""))
        execution_id = execution["id"]
        expected_id = "rollback-" + hashlib.sha256(
            f"{rollback['run_id']}:{execution_id}".encode()
        ).hexdigest()[:24]
        if rollback.get("run_id") != execution.get("run_id"):
            raise WorkflowError("Rollback candidate belongs to another execution run")
        tree = execution.get("candidate_tree")
        source_map = execution.get("source_map_candidate")
        identities = {}
        if isinstance(tree, dict):
            identities[tree.get("path")] = {"kind": "tree", "sha256": tree.get("tree_sha256"),
                                               "file_scope_sha256": tree.get("file_scope_sha256")}
        if isinstance(source_map, dict):
            identities[source_map.get("candidate_path")] = {
                "kind": "tree", "sha256": source_map.get("candidate_tree_sha256"),
                "file_scope_sha256": source_map.get("candidate_file_scope_sha256")}
        for output in execution["outputs"]:
            identities[output["path"]] = {"sha256": output["sha256"]}
        if (rollback["id"] != expected_id or artifact.get("action") != "quarantined"
                or retained.parent.resolve(strict=True) != discarded.resolve(strict=True)
                or retained.name != f"{rollback['id']}{candidate_root.suffix}"
                or retained.is_symlink() or artifact.get("path") not in identities
                or any(artifact.get(key) != value for key, value in identities[artifact["path"]].items())):
            raise WorkflowError("Rollback candidate retention record is invalid")
        from core.execution import _verify_rollback_artifact
        _verify_rollback_artifact(retained, artifact)
        matches.append(retained)
    if len(matches) > 1:
        raise WorkflowError("Multiple rollback records claim the same candidate")
    if not matches:
        return None
    return matches[0] / relative


def _verify_bla_check(plan: dict[str, Any], baseline: dict[str, Any], target: dict[str, Any],
                      execution: dict[str, Any], evidence: list[bytes], references: list[dict[str, Any]]) -> None:
    reports = [item for item in execution.get("evidence", []) if isinstance(item, dict)
               and item.get("kind") == "bla-verify"]
    if (len(reports) != 1 or len(evidence) != 1 or len(references) != 1
            or not _execution_evidence_matches(execution, reports[0])
            or references[0].get("path") != reports[0].get("path")
            or references[0].get("sha256") != reports[0].get("sha256")):
        raise WorkflowError("BLA invariant evidence requires exactly one pinned verifier report")
    try:
        report = json.loads(evidence[0])
        output = json.loads(report["stdout"])
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise WorkflowError("BLA verifier evidence is not valid JSON") from error
    selected = next((item for item in plan["actions"] if item.get("id") == execution.get("action_id")), None)
    if selected is None:
        selected = next((item for item in plan["actions"] if item.get("engine") == "bla"
                         and item.get("execution", {}).get("adapter") == "bla-js"), None)
    source_path = selected.get("execution", {}).get("source_path") if selected else None
    artifact = baseline.get("identity", {}).get("artifacts", {}).get(source_path)
    source_root = target.get("source_root")
    build_snapshot = baseline.get("identity", {}).get("build_snapshot")
    outputs = execution.get("outputs", [])
    command = report.get("command")
    engine = execution.get("engine", {})
    manifest = report.get("runtime_manifest", {})
    if (not isinstance(command, list) or any(not isinstance(arg, str) for arg in command)
            or not isinstance(output.get("targetPath"), str) or not isinstance(output.get("originalPath"), str)
            or not isinstance(engine, dict) or not isinstance(manifest, dict)):
        raise WorkflowError("BLA report identity fields are malformed")
    if (report.get("returncode") != 0 or output.get("overallPassed") is not True
            or output.get("functionalIntegrityVerified") is not True
            or not isinstance(output.get("checks"), list) or not output["checks"]
            or any(not isinstance(item, dict) or item.get("passed") is not True for item in output["checks"])
            or len(command) < 5 or command[1] != "verify" or command[-1] != "--json"
            or not isinstance(source_path, str) or not isinstance(source_root, str)
            or not isinstance(build_snapshot, dict)
            or not isinstance(artifact, dict) or len(outputs) != 1
            or manifest.get("npm_version") != engine.get("version")
            or manifest.get("package_tree_sha256") != engine.get("package_tree_sha256")):
        raise WorkflowError("BLA verifier report does not prove all invariant checks passed")
    source = Path(build_snapshot["path"]) / source_path
    candidate = Path(outputs[0]["path"])
    try:
        from core.execution import _verify_build_snapshot
        _verify_build_snapshot(baseline)
        source_hash = _hash_project_file(Path(build_snapshot["path"]), source_path)
        verify_evidence_file({"path": str(candidate), "sha256": outputs[0]["sha256"]}, execution)
    except (OSError, KeyError, TypeError) as error:
        raise WorkflowError("BLA source or candidate identity could not be verified") from error
    if (source_hash != artifact.get("sha256") or source_hash != execution.get("source_sha256")
            or Path(command[2]).resolve() != candidate.resolve()
            or Path(command[3]).resolve() != source.resolve()
            or Path(output.get("targetPath", "")).resolve() != candidate.resolve()
            or Path(output.get("originalPath", "")).resolve() != source.resolve()):
        raise WorkflowError("BLA verifier report paths or artifact identities do not match this run")


def _verify_behavior_check(plan: dict[str, Any], baseline: dict[str, Any], target: dict[str, Any],
                           execution: dict[str, Any], evidence: list[bytes],
                           check_references: list[dict[str, Any]]) -> None:
    selected = next((item for item in plan["actions"] if item.get("id") == execution.get("action_id")), None)
    if selected is None:
        selected = next((item for item in plan["actions"] if item.get("engine") == "bla"
                         and item.get("execution", {}).get("adapter") == "bla-js"), None)
    config = selected.get("execution", {}) if selected else {}
    command = config.get("behavior_command")
    source_path = config.get("source_path")
    source_root = target.get("source_root")
    outputs = execution.get("outputs", [])
    captured_behavior = baseline.get("identity", {}).get("behavior")
    if (not isinstance(command, list) or command.count("{artifact}") != 1
            or not isinstance(source_path, str) or not isinstance(source_root, str)
            or len(outputs) != 1 or len(evidence) != 3
            or not isinstance(captured_behavior, dict)
            or captured_behavior.get("command") != command
            or captured_behavior.get("artifact") != source_path):
        raise WorkflowError("Application behavior evidence is not bound to a comparable source and candidate")
    behavior_refs = [item for item in execution.get("evidence", []) if isinstance(item, dict)
                     and item.get("kind") in {"behavior-baseline", "behavior-source", "behavior-candidate"}]
    if (len(behavior_refs) != 3
            or [item.get("kind") for item in behavior_refs] !=
               ["behavior-baseline", "behavior-source", "behavior-candidate"]
            or any(not _execution_evidence_matches(execution, item) for item in behavior_refs)
            or len(check_references) != 3
            or [item.get("kind") for item in check_references] !=
               ["behavior-baseline", "behavior-source", "behavior-candidate"]
            or {item.get("path") for item in behavior_refs} != {item.get("path") for item in check_references}
            or {item.get("sha256") for item in behavior_refs} != {item.get("sha256") for item in check_references}):
        raise WorkflowError("Application behavior reports are not bound to execution evidence")
    if (behavior_refs[0].get("path") != captured_behavior.get("evidence_path")
            or behavior_refs[0].get("sha256") != captured_behavior.get("evidence_sha256")):
        raise WorkflowError("Application behavior check does not include the captured baseline report")
    build_snapshot = baseline.get("identity", {}).get("build_snapshot")
    if not isinstance(build_snapshot, dict):
        raise WorkflowError("BLA report is not bound to a private baseline build snapshot")
    source = Path(build_snapshot["path"]) / source_path
    candidate = Path(outputs[0]["path"])
    snapshots = execution.get("rea_comparison", {})
    before_snapshot, after_snapshot = snapshots.get("before_snapshot"), snapshots.get("after_snapshot")
    if not isinstance(before_snapshot, str) or not isinstance(after_snapshot, str):
        raise WorkflowError("Application behavior reports require paired private snapshots")
    baseline_snapshot_identity = _rea_snapshot_identity(Path(captured_behavior["snapshot_path"]))
    if (baseline_snapshot_identity["tree_sha256"] != captured_behavior["snapshot_tree_sha256"]
            or baseline_snapshot_identity["file_scope_sha256"] != captured_behavior["snapshot_file_scope_sha256"]):
        raise WorkflowError("Baseline behavior snapshot changed after capture")
    expected_argv = ([str(Path(captured_behavior["snapshot_path"]) / source_path)
                      if arg == "{artifact}" else arg for arg in command],
                     [str(Path(before_snapshot) / source_path) if arg == "{artifact}" else arg for arg in command],
                     [str(Path(after_snapshot) / source_path) if arg == "{artifact}" else arg for arg in command])
    try:
        reports = [json.loads(item) for item in evidence]
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise WorkflowError("Application behavior evidence is not valid JSON") from error
    if any(report.get("argv") != argv or report.get("exit_code") != 0 or report.get("timed_out")
           or report.get("stdout_truncated") or report.get("stderr_truncated")
           or not isinstance(report.get("stdout"), str)
           for report, argv in zip(reports, expected_argv)) \
            or len({report["stdout"] for report in reports}) != 1:
        raise WorkflowError("Application behavior reports do not prove equal successful baseline/source/candidate output")
    artifact = baseline.get("identity", {}).get("artifacts", {}).get(source_path)
    try:
        from core.execution import _verify_build_snapshot
        _verify_build_snapshot(baseline)
        source_hash = _hash_project_file(Path(build_snapshot["path"]), source_path)
        verify_evidence_file({"path": str(candidate), "sha256": outputs[0]["sha256"]}, execution)
    except (OSError, KeyError, TypeError) as error:
        raise WorkflowError("Application behavior source or candidate identity could not be verified") from error
    if (not isinstance(artifact, dict) or artifact.get("sha256") != source_hash
            or captured_behavior.get("artifact_sha256") != source_hash
            or execution.get("source_sha256") != source_hash):
        raise WorkflowError("Application behavior source no longer matches the saved baseline")


def _verify_rea_check(run: dict[str, Any], plan: dict[str, Any], baseline: dict[str, Any],
                      target: dict[str, Any], execution: dict[str, Any], evidence: list[bytes],
                      references: list[dict[str, Any]]) -> None:
    selected = next((item for item in plan["actions"] if item.get("id") == execution.get("action_id")), None)
    config = selected.get("execution", {}) if selected else {}
    source_path = config.get("source_path")
    metadata = execution.get("rea_comparison")
    reports = [item for item in execution.get("evidence", []) if isinstance(item, dict)
               and item.get("kind") == "rea-comparison"]
    if (not isinstance(metadata, dict) or len(evidence) != 1 or len(references) != 1 or len(reports) != 1
            or not _execution_evidence_matches(execution, reports[0])
            or references[0].get("path") != reports[0].get("path")
            or references[0].get("sha256") != reports[0].get("sha256")
            or not isinstance(source_path, str)):
        raise WorkflowError("REA comparison evidence is not bound to this execution")
    try:
        report = json.loads(evidence[0])
        snapshot_root = Path(metadata["snapshot_root"]).resolve(strict=True)
        before = Path(metadata["before_snapshot"]).resolve(strict=True)
        after = Path(metadata["after_snapshot"]).resolve(strict=True)
        if (before != (snapshot_root / "before").resolve(strict=True)
                or after != (snapshot_root / "after").resolve(strict=True) or before == after
                or snapshot_root.name != hashlib.sha256(f"{run['id']}:{selected['id']}".encode()).hexdigest()[:32]
                or snapshot_root.parent.name != "behavior-snapshots"):
            raise WorkflowError("REA snapshots do not belong to this run and selected action")
        before_identity = _rea_snapshot_identity(before)
        after_identity = _rea_snapshot_identity(after)
        artifact = baseline.get("identity", {}).get("artifacts", {}).get(source_path)
        output = execution.get("outputs", [])
        if (not isinstance(artifact, dict) or len(output) != 1
                or before_identity["tree_sha256"] != metadata.get("before_tree_sha256")
                or after_identity["tree_sha256"] != metadata.get("after_tree_sha256")
                or before_identity["file_scope_sha256"] != after_identity["file_scope_sha256"]
                or before_identity["file_scope_sha256"] != metadata.get("file_scope_sha256")
                or _hash_project_file(before, source_path) != artifact.get("sha256")
                or _hash_project_file(after, source_path) != output[0].get("sha256")
                or metadata.get("source_sha256") != artifact.get("sha256")
                or metadata.get("candidate_sha256") != output[0].get("sha256")):
            raise WorkflowError("REA source/candidate snapshots do not match baseline and execution outputs")
        if (report.get("schema_version") != "1.0" or report.get("record_type") != "rea_comparison"
                or report.get("status") != "measured" or report.get("finding_delta") !=
                report.get("after", {}).get("findings") - report.get("before", {}).get("findings")
                or report.get("before_tree_sha256") != metadata.get("before_tree_sha256")
                or report.get("after_tree_sha256") != metadata.get("after_tree_sha256")
                or report.get("file_scope_sha256") != metadata.get("file_scope_sha256")
                or report.get("runtime_manifest_sha256") != metadata.get("runtime_manifest_sha256")
                or not _SHA256.fullmatch(str(report.get("runtime_manifest_sha256", "")))
                or report.get("interpretation") !=
                "Static finding counts are measurements, not proof of protection or behavior preservation."):
            raise WorkflowError("REA comparison summary is inconsistent or incomplete")
        for side, snapshot in (("before", before), ("after", after)):
            result = report[side]
            if Path(result["target"]).resolve(strict=True) != snapshot:
                raise WorkflowError("REA report target does not match the saved snapshot")
            refs = {item.get("kind"): item for item in execution.get("evidence", [])
                    if isinstance(item, dict) and item.get("kind") in {f"rea-{side}-report", f"rea-{side}-bundle"}}
            report_ref, bundle_ref = refs.get(f"rea-{side}-report"), refs.get(f"rea-{side}-bundle")
            if (not report_ref or not bundle_ref or len(refs) != 2
                    or report_ref.get("path") != result["report"]
                    or report_ref.get("sha256") != result["report_sha256"]
                    or bundle_ref.get("path") != result["evidence_bundle"]
                    or bundle_ref.get("sha256") != result["evidence_bundle_sha256"]):
                raise WorkflowError("REA raw report or evidence bundle is not bound to execution")
            raw_report = verify_evidence_file(report_ref)
            verify_evidence_file(bundle_ref)
            lines = [line for line in raw_report.decode("utf-8").splitlines() if line.strip()]
            summary = json.loads(lines[-1])["summary"]
            normalized = summary["normalized_result"]
            stats = normalized["summary"]["statistics"]
            coverage = normalized["coverage"]
            if (summary.get("predicate_type") != "rea.analysis-view"
                    or summary.get("operation") != "inspect_analysis_view"
                    or normalized.get("artifact", {}).get("path") != str(snapshot)
                    or normalized.get("artifact", {}).get("sha256") != result["artifact_sha256"]
                    or normalized.get("parent_evidence_id") != result["evidence_id"]
                    or normalized.get("parent_digest") != result["parent_digest"]
                    or stats.get("findings") != result["findings"]
                    or coverage.get("status") != "complete-within-view"
                    or coverage.get("exhausted") is not True
                    or coverage.get("examined") != coverage.get("total")):
                raise WorkflowError("REA raw report does not support the saved comparison")
    except WorkflowError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise WorkflowError("REA comparison evidence is malformed or unreadable") from error


def _verify_e2e_check(run: dict[str, Any], plan: dict[str, Any], baseline: dict[str, Any],
                      target: dict[str, Any], execution: dict[str, Any], evidence: list[bytes],
                      references: list[dict[str, Any]]) -> None:
    selected = next((item for item in plan["actions"] if item.get("id") == execution.get("action_id")), None)
    config = selected.get("execution", {}) if selected else {}
    metadata = execution.get("e2e_behavior")
    if (not isinstance(metadata, dict) or metadata.get("passed") is not True
            or len(evidence) != 2 or len(references) != 2):
        raise WorkflowError("e2e evidence must contain paired reports for the selected action")
    refs = {item.get("kind"): item for item in execution.get("evidence", [])
            if isinstance(item, dict) and item.get("kind") in {"e2e-before", "e2e-after"}}
    if (set(refs) != {"e2e-before", "e2e-after"}
            or [references[0].get("kind"), references[1].get("kind")] != ["e2e-before", "e2e-after"]
            or any(not _execution_evidence_matches(execution, reference) for reference in references)
            or any(references[index].get("path") != metadata[side].get("path")
                   or references[index].get("sha256") != metadata[side].get("sha256")
                   for index, side in enumerate(("before", "after")) if isinstance(metadata.get(side), dict))):
            raise WorkflowError("e2e reports are not bound to the execution record")
    if selected is None or "e2e_behavior" not in selected.get("verification", []):
        raise WorkflowError("e2e evidence is not required by the selected action")
    source_path = config.get("source_path")
    source_root = target.get("source_root")
    outputs = execution.get("outputs", [])
    snapshot_identity = metadata.get("snapshot_identity")
    baseline_e2e = baseline.get("identity", {}).get("e2e_behavior")
    before = Path(metadata.get("before_snapshot", ""))
    after = Path(metadata.get("after_snapshot", ""))
    if (not isinstance(source_path, str) or not isinstance(source_root, str) or len(outputs) != 1
            or not isinstance(snapshot_identity, dict) or not isinstance(baseline_e2e, dict)
            or str(before) != baseline_e2e.get("snapshot_path")
            or after.name != "after"
            or after.parent.name != hashlib.sha256(f"{run['id']}:{selected['id']}".encode()).hexdigest()[:32]
            or after.parent.parent.name != "behavior-snapshots"):
        raise WorkflowError("e2e snapshots do not belong to the selected run and action")
    try:
        before_identity, after_identity = _rea_snapshot_identity(before), _rea_snapshot_identity(after)
        artifact = baseline.get("identity", {}).get("artifacts", {}).get(source_path)
        if (not isinstance(artifact, dict) or baseline_e2e.get("source_path") != source_path
                or baseline_e2e.get("artifact_sha256") != artifact.get("sha256")
                or before_identity["tree_sha256"] != baseline_e2e.get("tree_sha256")
                or before_identity["file_scope_sha256"] != baseline_e2e.get("file_scope_sha256")
                or before_identity["tree_sha256"] != snapshot_identity.get("before_tree_sha256")
                or after_identity["tree_sha256"] != snapshot_identity.get("after_tree_sha256")
                or before_identity["file_scope_sha256"] != after_identity["file_scope_sha256"]
                or before_identity["file_scope_sha256"] != snapshot_identity.get("file_scope_sha256")
                or _hash_project_file(before, source_path) != artifact.get("sha256")
                or _hash_project_file(after, source_path) != outputs[0].get("sha256")):
            raise WorkflowError("e2e snapshots do not match the baseline and candidate")
        runtime_path = Path(metadata["runtime_path"])
        if runtime_path.is_symlink():
            raise WorkflowError("e2e runtime path is linked")
        adapter_path = Path(__file__).resolve().parents[1] / "scripts/e2e_integration.py"
        if not adapter_path.is_file():
            adapter_path = Path(sysconfig.get_path("data")) / "share/anti-rea/scripts/e2e_integration.py"
        spec = importlib.util.spec_from_file_location("anti_rea_e2e_integration", adapter_path)
        if spec is None or spec.loader is None:
            raise WorkflowError("Pinned e2e report validator is unavailable")
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        runtime, manifest = adapter.verify_runtime(runtime_path)
        browser_path = runtime / "browser-chromium.json"
        if browser_path.is_symlink():
            raise WorkflowError("e2e browser install record is linked")
        browser_marker = json.loads(browser_path.read_text(encoding="utf-8"))
        manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False).encode()).hexdigest()
        if (manifest_hash != metadata.get("runtime_manifest_sha256")
                or manifest_hash != baseline_e2e.get("runtime_manifest_sha256")
                or browser_marker.get("package_lock_sha256") != adapter.PIN["package_lock_sha256"]
                or browser_marker.get("e2e_version") != adapter.PACKAGES["e2e"]
                or browser_marker.get("web_engine_version") != adapter.PACKAGES["@e2e-dev/web"]
                or metadata.get("runner") != {"name": "e2e", "version": adapter.PACKAGES["e2e"]}
                or metadata.get("cleanup") != {"before": "loopback app port closed", "after": "loopback app port closed"}
                or config.get("e2e_config", "e2e.config.mjs") != metadata.get("config")
                or config.get("e2e_test_file", "tests/behavior.e2e.ts") != metadata.get("test_file")
                or metadata.get("config") != baseline_e2e.get("config")
                or metadata.get("test_file") != baseline_e2e.get("test_file")
                or metadata.get("runner") != baseline_e2e.get("runner")):
            raise WorkflowError("e2e runtime, cleanup, or selected test configuration identity differs")
        reports = []
        for raw in evidence:
            report = json.loads(raw)
            adapter.validate_report(report, runtime)
            run_record = report["run"]
            results = [item for item in run_record["results"] if item.get("kind") == "test" and item.get("selected")]
            test_ids = sorted(item["testId"] for item in results)
            summary = run_record["summary"]
            targets = run_record["targets"]
            browser_versions = {attempt.get("environment", {}).get("browser")
                                for item in results for attempt in item.get("attempts", [])}
            invalid = [report.get("schemaVersion") != "report-1",
                       run_record.get("runner") != metadata["runner"],
                       run_record.get("environment", {}).get("runtime") != f"node v{manifest['node_version'].replace('v', '')}",
                       run_record.get("status") != "passed", run_record.get("exitCode") != 0,
                       not test_ids, any(item.get("status") != "passed" for item in results),
                       summary.get("executed") != len(results), summary.get("passed") != len(results),
                       any(summary.get(key) != 0 for key in ("failed", "interrupted", "flaky", "skipped")),
                       len(browser_versions) != 1, not next(iter(browser_versions), "").startswith("chromium "),
                       len(targets) != 1, bool(targets) and targets[0].get("platform") != "web",
                       bool(targets) and targets[0].get("engine") != {"name": "web", "version": adapter.PACKAGES["@e2e-dev/web"],
                                                                        "spiVersion": 1}]
            if any(invalid):
                raise WorkflowError("e2e report does not prove all selected browser tests passed")
            origin = targets[0].get("baseOrigin")
            if not adapter._assert_server_stopped(origin):
                raise WorkflowError("e2e app server is still running during acceptance")
            reports.append((test_ids, browser_versions))
        if (reports[0] != reports[1] or reports[0][0] != metadata.get("test_ids")
                or reports[0][0] != baseline_e2e.get("test_ids")
                or references[0].get("path") != baseline_e2e.get("report_path")
                or references[0].get("sha256") != baseline_e2e.get("report_sha256")
                or references[0]["sha256"] != metadata["before"]["sha256"]
                or references[1]["sha256"] != metadata["after"]["sha256"]):
            raise WorkflowError("e2e BEFORE/AFTER reports have different test scope or configuration")
    except WorkflowError:
        raise
    except Exception as error:
        raise WorkflowError("e2e behavior evidence is malformed or unreadable") from error


def _rea_snapshot_identity(root: Path) -> dict[str, str]:
    from core.discovery import inspect_project
    manifest = inspect_project(root)
    if manifest["unfollowed_symlinks"]:
        raise WorkflowError("REA snapshot contains symlinks")
    files = sorted(manifest["files"], key=lambda item: item["path"])
    tree = hashlib.sha256()
    for item in files:
        tree.update(item["path"].encode() + b"\0" + bytes.fromhex(item["sha256"]))
    scope = hashlib.sha256("\n".join(item["path"] for item in files).encode()).hexdigest()
    return {"tree_sha256": tree.hexdigest(), "file_scope_sha256": scope}


def _hash_project_file(root: Path, relative: str) -> str:
    from core.baseline import _hash_artifact
    return _hash_artifact(root, relative)["sha256"]


def _execution_evidence_matches(execution: dict[str, Any], reference: dict[str, Any]) -> bool:
    return any(isinstance(item, dict) and item.get("path") == reference.get("path")
               and item.get("sha256") == reference.get("sha256")
               and item.get("kind") == reference.get("kind") for item in execution.get("evidence", []))


def _verify_performance_check(plan: dict[str, Any], baseline: dict[str, Any], execution: dict[str, Any],
                              evidence: list[bytes], references: list[dict[str, Any]]) -> None:
    action = next((item for item in plan["actions"] if item.get("id") == execution.get("action_id")), None)
    config = action.get("execution", {}) if action else {}
    budget = validate_performance_budget(config.get("performance_budget"))
    report_ref = next((item for item in references if item.get("kind") == "performance"), None)
    metadata = execution.get("performance")
    if (report_ref is None or not isinstance(metadata, dict) or len(evidence) != len(references)
            or not all(_execution_evidence_matches(execution, ref) for ref in references)):
        raise WorkflowError("Performance evidence is not bound to this execution")
    try:
        parsed = [json.loads(raw) for raw in evidence]
        report_index = references.index(report_ref)
        report = parsed[report_index]
        samples = report.get("trials")
        if (report.get("schema_version") != "1.0" or report.get("run_id") != execution.get("run_id")
                or report.get("action_id") != execution.get("action_id")
                or report.get("plan_sha256") != record_hash(plan)
                or report.get("source_sha256") != execution.get("source_sha256")
                or report.get("runtime_manifest_sha256") != execution.get("engine", {}).get("package_tree_sha256")
                or report.get("budget") != budget or not isinstance(samples, list)
                or len(samples) != budget["trials"]
                or isinstance(report.get("source_bytes"), bool)
                or not isinstance(report.get("source_bytes"), int) or report["source_bytes"] <= 0):
            raise WorkflowError("Performance report identity or trial count does not match the approved plan")
        source_artifact = baseline.get("identity", {}).get("artifacts", {}).get(config.get("source_path"))
        if (not isinstance(source_artifact, dict)
                or source_artifact.get("sha256") != report["source_sha256"]
                or source_artifact.get("size") != report["source_bytes"]):
            raise WorkflowError("Performance source size or identity does not match the captured artifact")
        output = execution.get("outputs", [])
        if not isinstance(output, list) or len(output) != 1:
            raise WorkflowError("Performance evidence must identify one retained candidate")
        source_suffix = Path(config["source_path"]).suffix.lower()
        for index, sample in enumerate(samples):
            if (not isinstance(sample, dict) or sample.get("source_sha256") != report["source_sha256"]
                    or not isinstance(sample.get("candidate_sha256"), str)
                    or not _SHA256.fullmatch(sample["candidate_sha256"])
                    or isinstance(sample.get("elapsed_ms"), bool) or not isinstance(sample.get("elapsed_ms"), int)
                    or sample["elapsed_ms"] <= 0 or isinstance(sample.get("candidate_bytes"), bool)
                    or not isinstance(sample.get("candidate_bytes"), int) or sample["candidate_bytes"] <= 0):
                raise WorkflowError("Performance report contains an invalid sample")
            artifact = sample.get("candidate_artifact")
            if (not isinstance(artifact, dict) or artifact.get("kind") != "performance-candidate"
                    or not isinstance(artifact.get("path"), str) or not Path(artifact["path"]).is_absolute()
                    or artifact.get("sha256") != sample["candidate_sha256"]
                    or not _execution_evidence_matches(execution, artifact)):
                raise WorkflowError("Performance trial candidate is missing bound byte evidence")
            if index == 0:
                if artifact.get("path") != output[0].get("path") or artifact["sha256"] != output[0].get("sha256"):
                    raise WorkflowError("First performance trial does not match the retained execution output")
            else:
                expected_artifact = (Path(report_ref["path"]).parent /
                                     f"{Path(report_ref['path']).stem}-candidate-{index}{source_suffix}")
                if artifact["path"] != str(expected_artifact):
                    raise WorkflowError("Performance trial candidate is outside its private evidence path")
            candidate = verify_evidence_file(artifact, execution)
            if (len(candidate) != sample["candidate_bytes"]
                    or hashlib.sha256(candidate).hexdigest() != sample["candidate_sha256"]):
                raise WorkflowError(f"Performance trial {index + 1} size or hash does not match retained bytes")
        passed = all(sample["elapsed_ms"] <= budget["max_elapsed_ms"]
                      and sample["candidate_bytes"] <= budget["max_candidate_bytes"] for sample in samples)
        summary = {"elapsed_ms_min": min(x["elapsed_ms"] for x in samples),
                   "elapsed_ms_max": max(x["elapsed_ms"] for x in samples),
                   "elapsed_ms_mean": sum(x["elapsed_ms"] for x in samples) / len(samples),
                   "candidate_bytes_min": min(x["candidate_bytes"] for x in samples),
                   "candidate_bytes_max": max(x["candidate_bytes"] for x in samples),
                   "candidate_bytes_mean": sum(x["candidate_bytes"] for x in samples) / len(samples),
                   "candidate_growth_bytes_min": min(x["candidate_bytes"] for x in samples) - report["source_bytes"],
                   "candidate_growth_bytes_max": max(x["candidate_bytes"] for x in samples) - report["source_bytes"]}
        if report.get("summary") != summary:
            raise WorkflowError("Performance variability summary does not match the individual trials")
        browser = report.get("browser_journey")
        if browser is not None:
            expected_refs = []
            trials = browser.get("trials", {})
            if set(trials) != {"source", "candidate"}:
                raise WorkflowError("Browser journey evidence must include source and candidate trials")
            for side in ("source", "candidate"):
                if not isinstance(trials[side], list) or len(trials[side]) != 3:
                    raise WorkflowError("Browser journey evidence requires three trials per side")
                for sample in trials[side]:
                    ref = sample.get("evidence")
                    if not isinstance(ref, dict) or ref.get("kind") != f"performance-{side}":
                        raise WorkflowError("Browser journey trial lacks bound report evidence")
                    expected_refs.append(ref)
            if references != [report_ref, *expected_refs] or len(parsed) != 7:
                raise WorkflowError("Browser journey reports are missing or out of order")
            adapter_path = Path(__file__).resolve().parents[1] / "scripts/e2e_integration.py"
            if not adapter_path.is_file():
                adapter_path = Path(sysconfig.get_path("data"), "share/anti-rea/scripts/e2e_integration.py")
            spec = importlib.util.spec_from_file_location("anti_rea_e2e_performance_validate", adapter_path)
            if spec is None or spec.loader is None:
                raise WorkflowError("Pinned e2e report validator is unavailable")
            adapter = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(adapter)
            e2e_before = baseline.get("identity", {}).get("e2e_behavior", {})
            runtime, manifest = adapter.verify_runtime(config["e2e_runtime_path"])
            manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False).encode()).hexdigest()
            if manifest_hash != e2e_before.get("runtime_manifest_sha256"):
                raise WorkflowError("Browser performance runtime differs from the baseline runtime")
            baseline_raw = verify_evidence_file({"path": e2e_before["report_path"],
                                                 "sha256": e2e_before["report_sha256"]})
            baseline_report = json.loads(baseline_raw)
            baseline_run = baseline_report.get("run", {})
            baseline_browser = {sample.get("environment", {}).get("browser")
                                for result in baseline_run.get("results", []) if result.get("selected")
                                for sample in result.get("attempts", [])}
            index = 1
            for side in ("source", "candidate"):
                for sample in trials[side]:
                    raw_report = parsed[index]
                    adapter.validate_report(raw_report, config["e2e_runtime_path"])
                    run_record = raw_report.get("run", {})
                    selected = [item for item in run_record.get("results", [])
                                if item.get("kind") == "test" and item.get("selected")]
                    ids = sorted(item.get("testId") for item in selected)
                    browser_versions = {attempt.get("environment", {}).get("browser")
                                        for item in selected for attempt in item.get("attempts", [])}
                    targets = run_record.get("targets", [])
                    metrics = adapter.report_performance_metrics(raw_report)
                    if (raw_report.get("run", {}).get("status") != "passed"
                            or metrics != sample.get("metrics") or ids != e2e_before.get("test_ids")
                            or run_record.get("runner") != e2e_before.get("runner")
                            or run_record.get("environment", {}).get("runtime") != f"node {manifest['node_version']}"
                            or len(browser_versions) != 1 or browser_versions != baseline_browser
                            or len(targets) != 1 or targets[0].get("platform") != "web"
                            or targets[0].get("engine") != {"name": "web", "version": adapter.PACKAGES["@e2e-dev/web"],
                                                               "spiVersion": 1}):
                        raise WorkflowError("Browser journey metric does not match its passing pinned report")
                    index += 1
            calculated = {}
            for key in ("dom_content_loaded_ms", "load_event_ms", "interaction_ms"):
                source_values = sorted(x["metrics"][key] for x in trials["source"])
                candidate_values = sorted(x["metrics"][key] for x in trials["candidate"])
                source_median, candidate_median = source_values[1], candidate_values[1]
                regression = ((candidate_median - source_median) / source_median * 100
                              if source_median > 0 else (0 if candidate_median <= 1 else 1000))
                calculated[key] = {"source_min": source_values[0], "source_median": source_median,
                    "source_max": source_values[-1], "candidate_min": candidate_values[0],
                    "candidate_median": candidate_median, "candidate_max": candidate_values[-1],
                    "regression_percent": regression}
            if (browser.get("summary") != calculated
                    or browser.get("max_regression_percent") != budget.get("max_journey_regression_pct")):
                raise WorkflowError("Browser journey summary does not match repeated source/candidate reports")
            passed = passed and all(item["regression_percent"] <= budget["max_journey_regression_pct"]
                                    for item in calculated.values())
        elif len(references) != 1:
            raise WorkflowError("Unexpected performance evidence references")
        if (report.get("passed") is not passed or metadata != report or not passed
                or samples[0]["candidate_sha256"] != output[0].get("sha256")):
            raise WorkflowError("Performance budget was exceeded or report summary is inconsistent")
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError, KeyError, IndexError) as error:
        raise WorkflowError("Performance report is malformed") from error
    except Exception as error:
        if isinstance(error, WorkflowError):
            raise
        raise WorkflowError("Browser performance evidence could not be validated") from error

def validate_plan_baseline(plan: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    approved_plan = validate_plan(plan)
    captured_baseline = validate_baseline(baseline)
    if (approved_plan["target_id"] != captured_baseline["target_id"]
            or approved_plan["baseline_id"] != captured_baseline["id"]):
        raise WorkflowError("Plan does not match its saved target baseline")
    if approved_plan.get("blockers") and not approved_plan["actions"]:
        raise WorkflowError("Blocked plan cannot be submitted for a user decision")
    for action in approved_plan["actions"]:
        config = action.get("execution")
        if not isinstance(config, dict) or config.get("adapter") != "flutter-dart-obfuscation":
            continue
        path = config.get("artifact_path")
        target = config.get("target")
        command = captured_baseline["identity"].get("command", [])
        artifact = captured_baseline["identity"].get("artifacts", {}).get(path)
        evidence_hashes = {item.get("sha256") for item in action.get("evidence", [])
                           if isinstance(item, dict) and item.get("path") == path}
        expected_target = "apk"
        aot = captured_baseline["identity"].get("flutter_aot_inspection")
        if (action.get("engine") != "flutter-dart-obfuscation"
                or not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts
                or Path(path).suffix.lower() != ".apk"
                or target != expected_target or len(command) < 4
                or config.get("selected_abi") not in {"arm64-v8a", "armeabi-v7a", "x86_64"}
                or Path(command[0]).name != "flutter" or command[1:4] != ["build", target, "--release"]
                or config.get("flutter_executable") != command[0]
                or not isinstance(captured_baseline["identity"].get("dependency_lock_sha256"), str)
                or not _SHA256.fullmatch(captured_baseline["identity"]["dependency_lock_sha256"])
                or not isinstance(aot, dict) or aot.get("status") != "supported"
                or aot.get("artifact_path") != path
                or aot.get("abi") != config.get("selected_abi")
                or aot.get("runtime_manifest_sha256") != config.get("rea_runtime_manifest_sha256")
                or not isinstance(artifact, dict) or artifact.get("sha256") not in evidence_hashes
                or action.get("verification") != ["flutter_aot_comparison", "flutter_android_behavior"]):
            raise WorkflowError("Flutter obfuscation action must bind one captured Flutter release artifact and exact required checks")
    return approved_plan


def submit_plan(run: dict[str, Any], target: dict[str, Any], baseline: dict[str, Any],
                plan: dict[str, Any]) -> dict[str, Any]:
    """Bind a concrete plan to a baselining run and advance to user review."""
    current = validate_run(run)
    discovered = validate_target(target)
    captured = validate_baseline_target(baseline, discovered)
    candidate = validate_plan_baseline(plan, captured)
    if current["state"] != "baselining":
        raise WorkflowError("A plan can only be submitted to a baselining run")
    if current["target_id"] != discovered["id"]:
        raise WorkflowError("Run does not match the discovered target")
    return transition_run(current, "awaiting_decision", baseline_id=captured["id"], plan_id=candidate["id"])


def bind_decision(run: dict[str, Any], plan: dict[str, Any], decision: dict[str, Any],
                  optimization_search: dict[str, Any] | None = None) -> dict[str, Any]:
    current = validate_run(run)
    approved_plan = validate_plan(plan)
    choice = validate_decision(decision, approved_plan, optimization_search)
    if (current["state"] != "awaiting_decision" or current.get("plan_id") != approved_plan["id"]
            or current.get("baseline_id") != approved_plan["baseline_id"]
            or current.get("target_id") != approved_plan["target_id"]):
        raise WorkflowError("Run is not awaiting this target and baseline plan's decision")
    return validate_run(dict(current, decision_id=choice["id"]))


def validate_run(record: Any) -> dict[str, Any]:
    value = _base(record, "run")
    if not isinstance(value.get("state"), str) or value["state"] not in RUN_STATES:
        raise WorkflowError("Unknown run state")
    if value["state"] == "cancelled" and (not isinstance(value.get("cancellation_reason"), str)
                                            or not value["cancellation_reason"]):
        raise WorkflowError("Cancelled runs require a cancellation reason")
    _reference_id(value.get("target_id"), "run target_id")
    if "resume_of" in value:
        _reference_id(value["resume_of"], "run resume_of")
        if value["resume_of"] == value["id"]:
            raise WorkflowError("A resumed run must use a new run id")
    if "resume_identity_sha256" in value and (not isinstance(value["resume_identity_sha256"], str)
                                               or not _SHA256.fullmatch(value["resume_identity_sha256"])):
        raise WorkflowError("Resume identity must be a SHA-256")
    if ("resume_of" in value) != ("resume_identity_sha256" in value):
        raise WorkflowError("Resumed runs require both source run and verified identity")
    for field in ("baseline_id", "plan_id", "decision_id", "execution_id", "verification_id", "acceptance_id"):
        if field in value and value[field] is not None:
            _reference_id(value[field], f"run {field}")
    if value["state"] in {"awaiting_decision", "needs_decision", "preparing", "executing", "verifying", "completed"}:
        if not all(value.get(k) for k in ("baseline_id", "plan_id")):
            raise WorkflowError("Decision and later states require baseline and plan records")
    if value["state"] in {"preparing", "executing", "verifying", "completed"} and not value.get("decision_id"):
        raise WorkflowError("Execution states require an explicit decision record")
    if value["state"] == "blocked" and value.get("acceptance") == "rejected" and not all(
            value.get(key) for key in ("baseline_id", "plan_id", "decision_id", "execution_id", "verification_id")):
        raise WorkflowError("Rejected runs require baseline, plan, decision, execution, and verification identities")
    if value["state"] in {"verifying", "completed", "blocked"} and ("execution_id" in value) != ("verification_id" in value):
        raise WorkflowError("Execution and verification identities must be recorded together")
    if "acceptance" in value:
        if not isinstance(value["acceptance"], str) or value["acceptance"] not in ACCEPTANCE:
            raise WorkflowError("Run has an invalid acceptance outcome")
        if ((value["state"] == "completed" and value["acceptance"] != "accepted")
                or (value["state"] == "blocked" and value["acceptance"] != "rejected")
                or value["state"] not in {"completed", "blocked"}):
            raise WorkflowError("Acceptance outcome is only valid on an evidence-accepted completed run or rejected blocked run")
    if value["state"] == "completed":
        if not value.get("acceptance_id") or value.get("acceptance") != "accepted":
            raise WorkflowError("Completed runs require an accepted immutable acceptance record")
    elif value["state"] == "blocked" and value.get("acceptance") == "rejected":
        if not value.get("acceptance_id"):
            raise WorkflowError("Rejected runs require an immutable acceptance record")
    elif value.get("acceptance_id") is not None and not (value["state"] == "blocked" and value.get("acceptance") == "rejected"):
        raise WorkflowError("Acceptance record identity is only valid on a completed or rejected blocked run")
    return value


def transition_run(record: dict[str, Any], next_state: str, **updates: Any) -> dict[str, Any]:
    current = validate_run(record)
    if not isinstance(next_state, str) or next_state not in RUN_STATES.get(current["state"], set()):
        raise WorkflowError(f"Invalid run transition: {current['state']} -> {next_state}")
    allowed_updates = {"baseline_id", "plan_id", "decision_id", "execution_id", "verification_id",
                       "blocker", "error_code", "cancellation_reason"}
    if next_state == "completed":
        raise WorkflowError("Only accept_run may complete a run")
    if set(updates) - allowed_updates:
        raise WorkflowError("Run transition contains protected or unknown fields")
    changed = dict(current)
    changed.update(updates)
    changed["state"] = next_state
    if next_state == "cancelled" and not changed.get("cancellation_reason"):
        changed["cancellation_reason"] = "user_requested"
    if next_state == "awaiting_decision" and any(current.get(k) != changed.get(k) for k in ("baseline_id", "plan_id")):
        changed["decision_id"] = None
    return validate_run(changed)


def start_execution(run: dict[str, Any], plan: dict[str, Any], decision: dict[str, Any],
                    optimization_search: dict[str, Any] | None = None) -> dict[str, Any]:
    current = validate_run(run)
    choice = validate_decision(decision, plan, optimization_search)
    if decision["decision"] != "approved":
        raise WorkflowError("Rejected decision cannot start execution")
    if len(choice["selected_action_ids"]) > 1:
        _validate_composite_actions(plan, choice["selected_action_ids"])
    if (current["state"] not in {"awaiting_decision", "needs_decision"}
            or current.get("plan_id") != plan["id"]
            or current.get("baseline_id") != plan["baseline_id"]
            or current.get("target_id") != plan["target_id"]
            or current.get("decision_id") != decision["id"]):
        raise WorkflowError("Run, baseline, and approved plan do not match")
    return transition_run(current, "preparing", decision_id=decision["id"])


def _validate_decision_shape(record: Any) -> dict[str, Any]:
    value = _base(record, "decision")
    selected = value.get("selected_action_ids")
    if (not isinstance(selected, list) or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in selected)
            or len(set(selected)) != len(selected)):
        raise WorkflowError("Decision requires unique valid selected action ids")
    if value.get("decision") == "approved" and not selected:
        raise WorkflowError("Approved decisions require selected action ids")
    search_fields = ("optimization_search_id", "optimization_search_sha256", "optimization_candidate_id")
    if any(field in value for field in search_fields):
        if (any(not isinstance(value.get(field), str) or not value[field] for field in search_fields)
                or not _SHA256.fullmatch(value["optimization_search_sha256"])):
            raise WorkflowError("Search-bound decisions require search id, hash, and candidate id")
    if not isinstance(value.get("plan_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", value["plan_sha256"]):
        raise WorkflowError("Decision requires a plan SHA-256")
    if not isinstance(value.get("decision"), str) or value["decision"] not in {"approved", "rejected"}:
        raise WorkflowError("Decision must explicitly approve or reject")
    if not isinstance(value.get("decision_source"), str) or not value["decision_source"]:
        raise WorkflowError("Decision source must be recorded")
    return value


def write_record(directory: str | Path, record: dict[str, Any]) -> Path:
    """Atomically create one immutable JSON record without replacing an existing id."""
    kind = record.get("record_type") if isinstance(record, dict) else None
    validators = {"target": validate_target, "baseline": validate_baseline, "plan": validate_plan,
                  "optimization_search": validate_optimization_search,
                  "optimization_search_result": validate_optimization_search_result,
                  "optimization_selection": validate_optimization_selection,
                  "decision": _validate_decision_shape, **{name: lambda value, name=name: validate_evidence_record(value, name)
                                                             for name in ("execution", "verification", "acceptance", "rollback")}}
    if not isinstance(kind, str) or kind not in validators:
        raise WorkflowError("Unknown immutable workflow record type")
    validators[kind](record)
    root = _private_directory(directory)
    if kind == "optimization_search":
        try:
            plan = read_record(root / f"plan-{record['plan_id']}.json", "plan")
            baseline = read_record(root / f"baseline-{record['baseline_id']}.json", "baseline")
        except FileNotFoundError as error:
            raise WorkflowError("Optimization search requires its persisted plan and baseline") from error
        validate_optimization_search(record, plan, baseline)
    if kind == "optimization_selection":
        search = read_record(root / f"optimization_search-{record['search_id']}.json", "optimization_search")
        validate_optimization_selection(record, search)
        result = read_record(root / f"optimization_search_result-{record['runner_result_id']}.json",
                             "optimization_search_result")
        if record_hash(result) != record["runner_result_sha256"]:
            raise WorkflowError("Optimization selection runner result hash does not match")
        from core import optimizer
        runner_result = read_record(root / f"optimization_search_result-{record['runner_result_id']}.json",
                                    "optimization_search_result")
        optimizer._validated_search_result(root.parent, search, record["candidate_runs"])
        review = optimizer._review_approved_search(root.parent, search["id"],
                                                   record["candidate_runs"], enforce_stop=False)
        if (record_hash(runner_result) != record["runner_result_sha256"]
                or record_hash(review) != record["review_sha256"]
                or not any(item["candidate_id"] == record["candidate_id"]
                           and item["run_id"] == record["candidate_run_id"]
                           for item in review["pareto_frontier"])):
            raise WorkflowError("Optimization selection must match a candidate on the current approved Pareto frontier")
    path = root / f"{kind}-{record['id']}.json"
    payload = json.dumps(record, indent=2, ensure_ascii=False).encode() + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=".anti-rea-", dir=root)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            existing = read_record(path, kind)
            if canonical(existing) != canonical(record):
                raise WorkflowError(f"Immutable record id collision: {path.name}") from error
        directory_fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return path


def write_run_state(directory: str | Path, record: dict[str, Any], expected_current: dict[str, Any] | None) -> Path:
    """Compare-and-swap mutable run state; immutable records use write_record()."""
    value = validate_run(record)
    root = _private_directory(directory)
    path = root / f"run-{value['id']}.json"
    lock = root / f".run-{value['id']}.lock"
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise WorkflowError("Run is locked by another transition; inspect the lock before retrying") from error
    try:
        os.write(lock_fd, str(os.getpid()).encode())
        os.fsync(lock_fd)
        os.close(lock_fd)
        if path.exists():
            current = validate_run(read_json(path))
            if expected_current is None or record_hash(current) != record_hash(validate_run(expected_current)):
                raise WorkflowError("Run record changed since it was read")
            if value["state"] != current["state"]:
                if value["state"] not in RUN_STATES[current["state"]]:
                    raise WorkflowError(f"Invalid run transition: {current['state']} -> {value['state']}")
            elif value.get("verification_id") != current.get("verification_id"):
                if ({k: v for k, v in value.items() if k != "verification_id"}
                        != {k: v for k, v in current.items() if k != "verification_id"}):
                    raise WorkflowError("Verification refresh cannot change any other run binding")
                records = root.parent / "records"
                if current.get("state") != "verifying" or not current.get("verification_id") or not value.get("verification_id"):
                    raise WorkflowError("Only a verifying run may refresh a blocked verification")
                previous = read_record(records / f"verification-{current['verification_id']}.json", "verification")
                replacement = read_record(records / f"verification-{value['verification_id']}.json", "verification")
                if (previous.get("run_id") != current["id"]
                        or any(check["status"] != "blocked" for check in previous["checks"])
                        or replacement.get("run_id") != current["id"]
                        or {check["id"] for check in replacement["checks"]} != {check["id"] for check in previous["checks"]}
                        or replacement["id"] == previous["id"]):
                    raise WorkflowError("Verification refresh requires a new record replacing an all-blocked check set")
            elif value.get("decision_id") != current.get("decision_id"):
                if (current.get("state") not in {"awaiting_decision", "needs_decision"}
                        or {k: v for k, v in value.items() if k != "decision_id"}
                        != {k: v for k, v in current.items() if k != "decision_id"}):
                    raise WorkflowError("Same-state decision updates are only allowed while awaiting a decision")
            elif value != current:
                raise WorkflowError("Same-state updates may only bind a decision or refreshed blocked verification")
        elif expected_current is not None:
            raise WorkflowError("Run state file is missing")
        elif value["state"] != "discovered":
            raise WorkflowError("New runs must begin in discovered state")
        if (value["state"] == "completed"
                or value["state"] == "blocked" and value.get("acceptance") == "rejected"):
            if expected_current is None or expected_current["state"] != "verifying":
                raise WorkflowError("Only a verifying run may be finalized")
            records = root.parent / "records"
            try:
                target = read_record(records / f"target-{value['target_id']}.json", "target")
                baseline = read_record(records / f"baseline-{value['baseline_id']}.json", "baseline")
                plan = read_record(records / f"plan-{value['plan_id']}.json", "plan")
                decision = read_record(records / f"decision-{value['decision_id']}.json", "decision")
                optimization_search = (read_record(
                    records / f"optimization_search-{decision['optimization_search_id']}.json", "optimization_search")
                    if decision.get("optimization_search_id") else None)
                acceptance = read_record(records / f"acceptance-{value['acceptance_id']}.json", "acceptance")
                verification = read_record(records / f"verification-{acceptance['verification_id']}.json", "verification")
                execution = read_record(records / f"execution-{acceptance['execution_id']}.json", "execution")
            except (FileNotFoundError, KeyError) as error:
                raise WorkflowError("Completion requires all referenced immutable records") from error
            finalized = accept_run(expected_current, target, baseline, plan, decision, execution, verification,
                                   acceptance, optimization_search)
            if record_hash(finalized) != record_hash(value):
                raise WorkflowError("Finalized run does not match its validated acceptance evidence")
        payload = json.dumps(value, indent=2, ensure_ascii=False).encode() + b"\n"
        fd, temporary = tempfile.mkstemp(prefix=f".run-{value['id']}-", dir=root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return path
    finally:
        try:
            os.close(lock_fd)
        except OSError:
            pass
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def read_record(path: str | Path, expected_type: str | None = None) -> dict[str, Any]:
    value = read_json(path)
    kind = expected_type or (value.get("record_type") if isinstance(value, dict) else None)
    if kind == "decision":
        return _validate_decision_shape(value)
    if kind == "optimization_search":
        search = validate_optimization_search(_base(value, kind))
        records = Path(path).parent
        plan = read_record(records / f"plan-{search['plan_id']}.json", "plan")
        baseline = read_record(records / f"baseline-{search['baseline_id']}.json", "baseline")
        return validate_optimization_search(search, plan, baseline)
    if kind == "optimization_search_result":
        result = validate_optimization_search_result(_base(value, kind))
        records = Path(path).parent
        search = read_record(records / f"optimization_search-{result['search_id']}.json", "optimization_search")
        return validate_optimization_search_result(result, search)
    if kind == "optimization_selection":
        selection = validate_optimization_selection(_base(value, kind))
        records = Path(path).parent
        search = read_record(records / f"optimization_search-{selection['search_id']}.json", "optimization_search")
        return validate_optimization_selection(selection, search)
    return _base(value, kind)


def assemble_run_report(records_dir: str | Path, run_record: Any) -> dict[str, Any]:
    """Load and cross-check records linked to a run without requiring unfinished stages."""
    # shortcut: reports replay the acceptance gate but do not authenticate who wrote the local store.
    run = validate_run(run_record)
    records = Path(records_dir)

    def linked(field: str, kind: str, *, optional: bool = False) -> dict[str, Any] | None:
        record_id = run.get(field)
        if not record_id:
            return None
        try:
            value = read_record(records / f"{kind}-{record_id}.json", kind)
        except FileNotFoundError as error:
            if optional:
                return None
            raise WorkflowError(f"Run references missing {kind} record {record_id}") from error
        if value["id"] != record_id:
            raise WorkflowError(f"Run {field} does not match the linked {kind} record id")
        return value

    target = read_record(records / f"target-{run['target_id']}.json", "target")
    target = validate_target(target)
    if target["id"] != run["target_id"]:
        raise WorkflowError("Run target_id does not match the linked target record")

    baseline_may_be_pending = (run["state"] == "baselining"
                               or run["state"] in {"failed", "cancelled"} and not run.get("plan_id"))
    baseline = linked("baseline_id", "baseline", optional=baseline_may_be_pending)
    if baseline is not None:
        baseline = validate_baseline_target(baseline, target)

    plan = linked("plan_id", "plan")
    if plan is not None:
        if baseline is None:
            raise WorkflowError("Run plan cannot be validated without its baseline")
        plan = validate_plan_baseline(plan, baseline)
        if plan["target_id"] != target["id"]:
            raise WorkflowError("Run plan does not match its target")

    decision = linked("decision_id", "decision")
    optimization_search = None
    if decision is not None:
        if plan is None:
            raise WorkflowError("Run decision cannot be validated without its plan")
        if decision.get("optimization_search_id"):
            optimization_search = read_record(
                records / f"optimization_search-{decision['optimization_search_id']}.json", "optimization_search")
            optimization_search = validate_optimization_search(optimization_search, plan, baseline)
        decision = validate_decision(decision, plan, optimization_search)

    execution_record = linked("execution_id", "execution")
    if execution_record is not None:
        execution_record = validate_evidence_record(execution_record, "execution")
        if (plan is None or decision is None
                or execution_record["run_id"] != run["id"]
                or execution_record["plan_sha256"] != record_hash(plan)):
            raise WorkflowError("Run execution does not match its run and plan")
        if decision["decision"] == "approved":
            if len(decision["selected_action_ids"]) > 1:
                if execution_record.get("action_ids") != decision["selected_action_ids"]:
                    raise WorkflowError("Run execution does not match its selected composite actions")
            elif execution_record.get("action_id") != decision["selected_action_ids"][0]:
                raise WorkflowError("Run execution does not match its selected action")

    verification = linked("verification_id", "verification")
    if verification is not None:
        verification = validate_evidence_record(verification, "verification")
        if verification["run_id"] != run["id"]:
            raise WorkflowError("Run verification does not belong to this run")

    acceptance = linked("acceptance_id", "acceptance")
    if acceptance is not None:
        acceptance = validate_evidence_record(acceptance, "acceptance")
        expected_outcome = "accepted" if run["state"] == "completed" else "rejected"
        if (run["state"] not in {"completed", "blocked"}
                or acceptance["run_id"] != run["id"]
                or acceptance["outcome"] != expected_outcome
                or plan is None or execution_record is None or verification is None
                or acceptance["plan_sha256"] != record_hash(plan)
                or acceptance["execution_id"] != execution_record["id"]
                or acceptance["verification_id"] != verification["id"]):
            raise WorkflowError("Run acceptance does not match its linked evidence")
        verifying_run = {key: value for key, value in run.items()
                         if key not in {"acceptance_id", "acceptance"}}
        verifying_run["state"] = "verifying"
        derived = accept_run(verifying_run, target, baseline, plan, decision,
                             execution_record, verification, acceptance, optimization_search)
        if canonical(derived) != canonical(run):
            raise WorkflowError("Persisted terminal run does not match replayed acceptance evidence")

    report = {"status": "ok", "run": run, "target": target}
    for kind, value in (("baseline", baseline), ("plan", plan), ("decision", decision),
                        ("optimization_search", optimization_search),
                        ("execution", execution_record), ("verification", verification),
                        ("acceptance", acceptance)):
        if value is not None:
            report[kind] = value
    report["rollbacks"] = []
    for path in records.glob("rollback-*.json"):
        rollback = validate_evidence_record(read_record(path, "rollback"), "rollback")
        if path.stem != f"rollback-{rollback['id']}":
            raise WorkflowError("Rollback filename does not match its record id")
        if rollback["run_id"] == run["id"]:
            report["rollbacks"].append(rollback)
    return report
