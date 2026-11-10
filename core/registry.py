"""Truthful catalog of the adapters currently implemented by Anti-REA."""

from __future__ import annotations

import hashlib
import json
import sysconfig
from pathlib import Path

from core import workflow

_OPERATIONS = ("probe", "supports", "plan", "execute", "verify", "collect", "cleanup")
_STATUS = {"implemented", "partial", "unavailable"}
_CRAFT_ANYTHING = {
    "repository": "https://github.com/storytold/craft-anything",
    "version": "0.6.0",
    "source_commit": "899b4ebd24ca17d4a84af1e1b9ef9c0304de08ab",
}


def _lock_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    if (root / "locks/upstreams.json").is_file():
        return root
    root = Path(sysconfig.get_path("data")) / "share/anti-rea"
    if not (root / "locks/upstreams.json").is_file():
        raise workflow.WorkflowError("Packaged upstream lock file is unavailable")
    return root


def _operation(status: str, scope: str) -> dict:
    return {"status": status, "scope": scope}


def get_registry() -> dict:
    """Return implemented lanes with identities derived from checked-in pins."""
    root = _lock_root()
    lock_manifest = root / "locks/upstreams.json"
    path_has_symlink = False
    component = root
    for part in Path("locks/upstreams.json").parts:
        component /= part
        path_has_symlink = path_has_symlink or component.is_symlink()
    if path_has_symlink or not lock_manifest.is_file():
        raise workflow.WorkflowError("Pinned upstream manifest must be a regular file")
    lock = json.loads(lock_manifest.read_text(encoding="utf-8"))
    items = []
    for engine in ("bla", "rea", "e2e"):
        pin = lock.get("integrations", {}).get(engine)
        if not isinstance(pin, dict) or not isinstance(pin.get("package_lock"), str):
            raise workflow.WorkflowError(f"Missing pinned package lock for {engine}")
        relative_lock = Path(pin["package_lock"])
        lock_candidate = root / relative_lock
        parent = root
        has_symlink = relative_lock.is_absolute() or ".." in relative_lock.parts
        for part in relative_lock.parts:
            parent /= part
            has_symlink = has_symlink or parent.is_symlink()
        lock_path = lock_candidate.resolve()
        if (
            has_symlink
            or root.resolve() not in lock_path.parents
            or not lock_path.is_file()
            or hashlib.sha256(lock_path.read_bytes()).hexdigest()
            != pin.get("package_lock_sha256")
        ):
            raise workflow.WorkflowError(
                f"Pinned package lock identity is invalid for {engine}"
            )

        if engine == "bla":
            artifact_types = ["one regular JavaScript file no larger than 1 MiB"]
            operations = {
                "probe": _operation(
                    "implemented", "Pinned Node package readiness only."
                ),
                "supports": _operation(
                    "partial",
                    "JavaScript candidates with a hash-bound baseline and supported plan.",
                ),
                "plan": _operation(
                    "partial", "One balanced BLA JavaScript action; no combinations."
                ),
                "execute": _operation(
                    "partial",
                    "One approved BLA JavaScript action into a private candidate.",
                ),
                "verify": _operation(
                    "implemented",
                    "BLA invariant verification for the selected JavaScript candidate.",
                ),
                "collect": _operation(
                    "partial",
                    "Run-bound execution, verification, behavior, and REA evidence.",
                ),
                "cleanup": _operation(
                    "partial",
                    "Private candidate quarantine and rollback; not deployment rollback.",
                ),
            }
            limitations = [
                "Source/package equivalence is not verified.",
                "Fixture evidence does not establish protection for a user's application.",
            ]
        elif engine == "rea":
            artifact_types = [
                "JavaScript application directory or .asar for static analysis"
            ]
            operations = {
                "probe": _operation(
                    "implemented", "Pinned Node package version probe."
                ),
                "supports": _operation(
                    "partial",
                    "JavaScript static-analysis lane; provider readiness remains separate.",
                ),
                "plan": _operation(
                    "unavailable", "REA measures exposure; it is not a defense planner."
                ),
                "execute": _operation(
                    "partial", "Pinned CLI/MCP inventory and JavaScript analysis."
                ),
                "verify": _operation(
                    "partial",
                    "Report schema, scope, runtime identity, and comparable analysis checks.",
                ),
                "collect": _operation(
                    "implemented", "Raw reports and evidence bundles are retained."
                ),
                "cleanup": _operation(
                    "implemented",
                    "Bounded process-group termination on POSIX; Windows descendant cleanup is not verified.",
                ),
            }
            limitations = [
                "Provider availability and non-JavaScript applicability remain unknown or unavailable.",
                "Source/package equivalence is not verified.",
            ]
        else:
            artifact_types = ["Owned fixture-compatible local web projects"]
            operations = {
                "probe": _operation(
                    "partial",
                    "Pinned package and browser-runtime readiness; not application compatibility.",
                ),
                "supports": _operation(
                    "partial", "Pinned fixture-compatible web contract only."
                ),
                "plan": _operation(
                    "unavailable", "e2e verifies behavior; it is not a defense planner."
                ),
                "execute": _operation(
                    "partial",
                    "Pinned browser behavior runs for supported web fixtures.",
                ),
                "verify": _operation(
                    "implemented",
                    "Pinned report schema, requested scope, and server cleanup.",
                ),
                "collect": _operation(
                    "implemented", "Raw run reports are retained, including failures."
                ),
                "cleanup": _operation(
                    "partial",
                    "Loopback server cleanup verified on supported POSIX runs; Windows descendants are not verified.",
                ),
            }
            limitations = [
                "The project test/config code is not OS-sandboxed.",
                "Mobile and general application workflows are not verified.",
                "Source/package equivalence is not verified.",
            ]

        if set(operations) != set(_OPERATIONS) or any(
            value.get("status") not in _STATUS for value in operations.values()
        ):
            raise workflow.WorkflowError(
                f"Invalid adapter operation coverage for {engine}"
            )
        packages = pin.get("packages") or {
            pin["npm_package"]: {
                "version": pin["npm_version"],
                "integrity": pin["npm_integrity"],
            }
        }
        items.append(
            {
                "id": engine,
                "kind": "analysis_engine"
                if engine == "rea"
                else "behavior_runner"
                if engine == "e2e"
                else "defense_engine",
                "repository": pin.get("repository"),
                "source_commit": pin.get("source_commit"),
                "source_package_equivalence": pin.get(
                    "source_package_equivalence", "unknown"
                ),
                "installation": {
                    "method": "isolated npm runtime",
                    "package_lock": pin["package_lock"],
                    "package_lock_sha256": pin["package_lock_sha256"],
                    "install_scripts": "disabled",
                },
                "packages": packages,
                "license": {
                    "declared": pin.get("license"),
                    "independent_review": "unverified",
                },
                "supported_artifacts": artifact_types,
                "supported_runtimes": [pin.get("node_requirement", "unknown")],
                "operations": operations,
                "limitations": limitations,
            }
        )

    items.append(
        {
            "id": "craft-anything",
            "kind": "analysis_engine",
            "repository": _CRAFT_ANYTHING["repository"],
            "source_commit": _CRAFT_ANYTHING["source_commit"],
            "source_package_equivalence": "not_verified",
            "installation": {
                "method": "use a preinstalled craft-anything-cli; Anti-REA does not download it"
            },
            "packages": {"craft-anything-cli": {"version": _CRAFT_ANYTHING["version"]}},
            "license": {
                "declared": "MIT OR Apache-2.0",
                "independent_review": "unverified",
            },
            "supported_artifacts": [
                "Regular files or directories accepted by Craft Anything triage; per-target coverage is reported by the upstream engine"
            ],
            "supported_runtimes": ["craft-anything-cli 0.6.0"],
            "operations": {
                "probe": _operation(
                    "partial", "Installed CLI identity and exact version only."
                ),
                "supports": _operation(
                    "partial", "Delegated to upstream triage and its coverage evidence."
                ),
                "plan": _operation(
                    "unavailable",
                    "Craft Anything provides findings, not Anti-REA hardening actions.",
                ),
                "execute": _operation(
                    "unavailable",
                    "Analysis only; rebuild and target-changing tools are never invoked.",
                ),
                "verify": _operation(
                    "partial",
                    "CLI result, input identity, and read-only input stability.",
                ),
                "collect": _operation(
                    "partial",
                    "Structured triage output is retained in private Anti-REA state.",
                ),
                "cleanup": _operation(
                    "partial",
                    "Project data is isolated from the target; automatic cleanup and retention are not verified.",
                ),
            },
            "limitations": [
                "Craft Anything findings do not establish protection or replace REA measurement.",
                "Input is static triage only; behavior, runtime protection, and rebuild are not tested.",
                "Source/package equivalence and independent license review are unverified.",
            ],
        }
    )

    items.append(
        {
            "id": "source-map-candidate",
            "kind": "built_in_release_adapter",
            "repository": None,
            "source_commit": None,
            "source_package_equivalence": "not_applicable",
            "installation": {"method": "Anti-REA package; no external engine"},
            "packages": {},
            "license": {"declared": None, "independent_review": "not_applicable"},
            "supported_artifacts": [
                "One inventoried source-map file in a private captured build snapshot"
            ],
            "supported_runtimes": ["Python filesystem operations"],
            "operations": {
                "probe": _operation(
                    "implemented", "Built into Anti-REA; no external runtime probe."
                ),
                "supports": _operation(
                    "partial",
                    "Only a selected hash-bound source map in a private build snapshot.",
                ),
                "plan": _operation(
                    "partial",
                    "Plan-bound exclusion of exactly one selected source map.",
                ),
                "execute": _operation(
                    "partial",
                    "Private candidate-tree copy that omits the selected map.",
                ),
                "verify": _operation(
                    "partial",
                    "Tree identity and selected-map omission; deployed exposure is not checked.",
                ),
                "collect": _operation(
                    "implemented", "Plan-bound manifest and run evidence are persisted."
                ),
                "cleanup": _operation(
                    "partial",
                    "Authenticated private candidate quarantine and rollback.",
                ),
            },
            "limitations": [
                "Does not change deployment configuration or verify the served release.",
                "Candidate-tree exclusion does not establish protection.",
            ],
        }
    )

    items.append(
        {
            "id": "flutter-android-build",
            "kind": "built_in_platform_build_adapter",
            "repository": None,
            "source_commit": None,
            "source_package_equivalence": "not_applicable",
            "installation": {
                "method": "uses an existing Flutter SDK; no installation or global changes"
            },
            "packages": {},
            "license": {"declared": None, "independent_review": "not_applicable"},
            "supported_artifacts": ["Flutter Android release APK or app bundle"],
            "supported_runtimes": [
                "Flutter SDK selected by executable name or path",
                "Android SDK readiness unverified",
            ],
            "operations": {
                "probe": _operation(
                    "partial",
                    "Read-only Flutter, Android SDK/license, and connected-device readiness; does not test an app.",
                ),
                "supports": _operation(
                    "partial",
                    "Flutter Android projects with pubspec.yaml and android/; no app compatibility claim.",
                ),
                "plan": _operation(
                    "partial",
                    "Release APK or app bundle with Dart obfuscation and split debug information.",
                ),
                "execute": _operation(
                    "partial",
                    "Bounded Flutter release build through the shared private baseline snapshot.",
                ),
                "verify": _operation(
                    "partial",
                    "Expected artifact path and bytes are captured and hashed; no runtime or signing verification.",
                ),
                "collect": _operation(
                    "implemented",
                    "Baseline command output and artifact identities are retained.",
                ),
                "cleanup": _operation(
                    "partial",
                    "Private build snapshot cleanup; split debug information is retained in private state.",
                ),
            },
            "limitations": [
                "The readiness probe reports Android SDK/license/device state but does not accept licenses or test app compatibility.",
                "Signing and runtime behavior are not verified.",
                "Flutter Dart obfuscation is not resource encryption or reverse-engineering prevention.",
                "Fixture tests verify command/capture wiring only; no real application build evidence is available.",
            ],
        }
    )

    items.append(
        {
            "id": "wasm-compile-probe",
            "kind": "built_in_diagnostic",
            "repository": None,
            "source_commit": None,
            "source_package_equivalence": "not_applicable",
            "installation": {
                "method": "uses an existing Node runtime; no installation or global changes"
            },
            "packages": {},
            "license": {"declared": None, "independent_review": "not_applicable"},
            "supported_artifacts": ["One regular .wasm file up to 8 MiB"],
            "supported_runtimes": [
                "Existing Node runtime; exact version is recorded per probe"
            ],
            "operations": {
                "probe": _operation(
                    "implemented",
                    "Bounded Node WebAssembly.Module compile check on a private copy.",
                ),
                "supports": _operation(
                    "partial",
                    "Compile validity only; no host binding or application compatibility.",
                ),
                "plan": _operation(
                    "unavailable", "Diagnostic only; no WASM transformation plan."
                ),
                "execute": _operation(
                    "unavailable", "Module is never instantiated or executed."
                ),
                "verify": _operation(
                    "partial",
                    "Compile status and selected static metadata; no runtime binding verification.",
                ),
                "collect": _operation(
                    "implemented",
                    "Module hash, byte count, Node version, and compile result are returned.",
                ),
                "cleanup": _operation(
                    "implemented",
                    "Private temporary module copy is removed after the probe.",
                ),
            },
            "limitations": [
                "Does not instantiate the module or verify imports against host bindings.",
                "Does not establish application behavior, platform compatibility, or protection.",
            ],
        }
    )

    result = {
        "schema_version": "1.0",
        "record_type": "engine_registry",
        "engines": items,
    }
    validate_registry(result)
    return result


def validate_registry(value: dict) -> dict:
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "1.0"
        or value.get("record_type") != "engine_registry"
        or not isinstance(value.get("engines"), list)
    ):
        raise workflow.WorkflowError("Engine registry record is invalid")
    ids = set()
    for engine in value["engines"]:
        if (
            not isinstance(engine, dict)
            or not isinstance(engine.get("id"), str)
            or not engine["id"]
            or engine["id"] in ids
            or not isinstance(engine.get("kind"), str)
            or not isinstance(engine.get("operations"), dict)
            or set(engine["operations"]) != set(_OPERATIONS)
            or any(
                not isinstance(operation, dict)
                or operation.get("status") not in _STATUS
                or not isinstance(operation.get("scope"), str)
                for operation in engine["operations"].values()
            )
            or not isinstance(engine.get("supported_artifacts"), list)
            or not isinstance(engine.get("supported_runtimes"), list)
            or not isinstance(engine.get("limitations"), list)
        ):
            raise workflow.WorkflowError(
                "Engine registry entry is incomplete or invalid"
            )
        ids.add(engine["id"])
    if ids != {
        "bla",
        "rea",
        "e2e",
        "craft-anything",
        "source-map-candidate",
        "flutter-android-build",
        "wasm-compile-probe",
    }:
        raise workflow.WorkflowError(
            "Engine registry entries differ from implemented adapters"
        )
    return value
