"""Evidence-grounded, deliberately narrow plan recommendations."""

from __future__ import annotations

import hashlib
import re

from core import workflow


def create_plan(
    target: dict,
    baseline: dict,
    plan_id: str,
    budgets: dict | None = None,
    behavior_command: list[str] | None = None,
    e2e_behavior: bool = False,
    performance_budget: dict | None = None,
    profile: str = "balanced",
    bla_intensity: str | None = None,
) -> dict:
    """Create limited evidence-derived recommendations and a BLA starting profile."""
    workflow._reference_id(plan_id, "plan id")
    if not isinstance(profile, str) or profile not in {
        *workflow.PLAN_PROFILE_INTENSITIES,
        "custom",
    }:
        raise workflow.WorkflowError(
            "Profile must be low-impact, balanced, deep-protection, or custom"
        )
    if profile == "custom":
        if (
            not isinstance(bla_intensity, str)
            or bla_intensity not in workflow.PLAN_BLA_INTENSITIES
        ):
            raise workflow.WorkflowError(
                "Custom profile requires a supported BLA intensity"
            )
        selected_intensity = bla_intensity
    else:
        selected_intensity = workflow.PLAN_PROFILE_INTENSITIES[profile]
        if bla_intensity is not None and bla_intensity != selected_intensity:
            raise workflow.WorkflowError(
                "BLA intensity can only be customized with the custom profile"
            )
    discovered = workflow.validate_target(target)
    captured = workflow.validate_baseline_target(baseline, discovered)
    artifact_records = captured["identity"].get("artifacts")
    if not isinstance(artifact_records, dict):
        raise workflow.WorkflowError(
            "Baseline has no artifact identities for recommendation"
        )
    actions = []
    blockers = []
    already_obfuscated_flutter = False
    if behavior_command is not None and (
        not isinstance(behavior_command, list)
        or not behavior_command
        or any(not isinstance(arg, str) or not arg for arg in behavior_command)
        or behavior_command.count("{artifact}") != 1
    ):
        raise workflow.WorkflowError(
            "Behavior command must be argv containing exactly one {artifact} argument"
        )
    baseline_behavior = captured["identity"].get("behavior")
    if behavior_command is not None and (
        not isinstance(baseline_behavior, dict)
        or baseline_behavior.get("command") != behavior_command
    ):
        raise workflow.WorkflowError(
            "Behavior command must exactly match the command captured in the baseline"
        )
    if not isinstance(e2e_behavior, bool):
        raise workflow.WorkflowError("e2e_behavior must be a boolean")
    baseline_e2e = captured["identity"].get("e2e_behavior")
    if e2e_behavior and not isinstance(baseline_e2e, dict):
        raise workflow.WorkflowError(
            "Baseline e2e behavior must be captured before recommending browser verification"
        )
    performance_budget = performance_budget or {
        "trials": 3,
        "max_elapsed_ms": 30000,
        "max_candidate_bytes": 64 * 1024 * 1024,
    }
    if (
        e2e_behavior
        and isinstance(baseline_e2e, dict)
        and isinstance(baseline_e2e.get("performance_metrics"), dict)
    ):
        performance_budget.setdefault("max_journey_regression_pct", 25)
    workflow.validate_performance_budget(performance_budget)
    baseline_rea = captured["identity"].get("rea_analysis")
    if isinstance(baseline_rea, dict):
        rea_report = workflow.verify_evidence_file(
            {
                "path": baseline_rea["report_path"],
                "sha256": baseline_rea["report_sha256"],
            }
        )
        if hashlib.sha256(rea_report).hexdigest() != baseline_rea["report_sha256"]:
            raise workflow.WorkflowError(
                "Baseline REA report changed before recommendation generation"
            )
    for path, identity in sorted(artifact_records.items()):
        if not isinstance(path, str):
            continue
        if not path.lower().endswith((".map", ".js", ".mjs", ".cjs", ".apk")):
            continue
        if (
            not isinstance(identity, dict)
            or isinstance(identity.get("size"), bool)
            or not isinstance(identity.get("size"), int)
            or identity["size"] < 0
            or not isinstance(identity.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", identity["sha256"])
        ):
            raise workflow.WorkflowError(
                f"Baseline artifact identity is invalid: {path}"
            )
        command = captured["identity"].get("command", [])
        if (
            path.lower().endswith(".apk")
            and len(command) >= 4
            and command[1:4] == ["build", "apk", "--release"]
        ):
            obfuscation_args = {"--obfuscate", "--split-debug-info"}
            if (
                any(
                    arg in obfuscation_args or arg.startswith("--split-debug-info=")
                    for arg in command[4:]
                )
                or "--obfuscate" in command[4:]
            ):
                already_obfuscated_flutter = True
                continue
            if not isinstance(captured["identity"].get("dependency_lock_sha256"), str):
                raise workflow.WorkflowError(
                    "Flutter obfuscation requires a captured pubspec.lock identity"
                )
            if not isinstance(captured["identity"].get("flutter_toolchain"), dict):
                continue
            target_name = command[2]
            aot_inspection = captured["identity"].get("flutter_aot_inspection")
            if (
                not isinstance(aot_inspection, dict)
                or aot_inspection.get("status") != "supported"
                or aot_inspection.get("artifact_path") != path
                or aot_inspection.get("abi") != "arm64-v8a"
            ):
                blockers.append(
                    f"Flutter obfuscation for {path} is blocked until REA confirms a supported arm64-v8a AOT profile for this exact baseline APK."
                )
                continue
            if not any(
                item.get("engine") == "flutter-dart-obfuscation" for item in actions
            ):
                actions.append(
                    {
                        "id": "flutter-dart-obfuscation-"
                        + hashlib.sha256(path.encode()).hexdigest()[:12],
                        "finding_or_asset": f"Captured Flutter Android artifact: {path}",
                        "change": "Build an isolated Dart-obfuscated candidate and retain its symbol map privately.",
                        "mechanism": "Run the same captured Flutter Android release target with --obfuscate and --split-debug-info.",
                        "engine": "flutter-dart-obfuscation",
                        "execution": {
                            "adapter": "flutter-dart-obfuscation",
                            "artifact_path": path,
                            "target": target_name,
                            "flutter_executable": command[0],
                            "selected_abi": "arm64-v8a",
                            "rea_runtime_manifest_sha256": aot_inspection[
                                "runtime_manifest_sha256"
                            ],
                        },
                        "evidence": [
                            {
                                "baseline_id": captured["id"],
                                "path": path,
                                "sha256": identity["sha256"],
                            }
                        ],
                        "expected_benefit": "Rename Dart symbols in the release artifact; measure the packaged result.",
                        "cost": "Private candidate build, package inspection, behavior validation, and symbol-map retention.",
                        "tradeoffs": [
                            "Dart obfuscation does not encrypt resources or prevent reverse engineering.",
                            "Obfuscated stack traces require the matching private symbol map.",
                        ],
                        "dependencies": [
                            "Same pinned Flutter, Android SDK, dependency lock, and signing configuration as baseline."
                        ],
                        "compatibility": [
                            "Only the selected APK or AAB target is built."
                        ],
                        "verification": [
                            "flutter_aot_comparison",
                            "flutter_android_behavior",
                        ],
                        "limitations": [
                            "A successful build is unverified until package/AOT inspection and same-target behavior evidence pass.",
                            "This does not establish protection or confidentiality.",
                        ],
                        "rollback": f"Discard the private candidate and retain the baseline artifact: {path}",
                    }
                )
            continue
        if path.lower().endswith(".apk"):
            continue
        common = {
            "evidence": [
                {
                    "baseline_id": captured["id"],
                    "path": path,
                    "sha256": identity["sha256"],
                }
            ]
            + (
                [
                    {
                        "baseline_id": captured["id"],
                        "path": baseline_rea["report_path"],
                        "sha256": baseline_rea["report_sha256"],
                        "kind": "rea-before",
                    }
                ]
                if baseline_rea and baseline_rea["source_path"] == path
                else []
            ),
            "cost": "Review and verification time; BLA requires an isolated pinned runtime.",
            "tradeoffs": [
                "Protected output may be larger or slower.",
                "Debugging and stack traces may be less readable.",
                "Transformation does not prevent runtime inspection or reconstruction.",
            ],
            "dependencies": [
                "Optional pinned bla-agents runtime; no global installation."
            ],
            "compatibility": [
                "Adapter accepts one JavaScript file up to 1 MiB.",
                "Retain the original and verify application behavior before acceptance.",
            ],
            "verification": ["bla_invariants", "rea_comparison", "performance"]
            + (
                ["application_behavior"]
                if behavior_command is not None
                and baseline_behavior.get("snapshot_path")
                and baseline_behavior.get("artifact") == path
                else []
            )
            + (["e2e_behavior"] if e2e_behavior else []),
            "limitations": [
                "Does not provide confidentiality or prevent determined reverse engineering.",
                "Behavior equivalence and comparable REA checks do not establish protection.",
            ]
            + (
                [
                    "Captured REA analysis measures one summary view and does not establish protection."
                ]
                if baseline_rea and baseline_rea["source_path"] == path
                else []
            ),
            "rollback": f"Discard the isolated candidate and restore the original artifact: {path}",
        }
        if path.lower().endswith(".map"):
            executable = isinstance(captured["identity"].get("build_snapshot"), dict)
            actions.append(
                {
                    **common,
                    "id": "source-map-"
                    + hashlib.sha256(path.encode()).hexdigest()[:12],
                    "finding_or_asset": f"Captured source-map artifact: {path}",
                    "change": (
                        "Create a private release-tree candidate omitting this map; use it as packaging input only after review."
                        if executable
                        else "Review whether this map is included in the public release and exclude it if needed."
                    ),
                    "mechanism": (
                        "Copy the captured build tree and omit only this map while preserving the private baseline."
                        if executable
                        else "Review the project's release packaging or deployment configuration."
                    ),
                    "engine": "release packaging candidate"
                    if executable
                    else "release packaging configuration (manual review)",
                    **(
                        {
                            "execution": {
                                "adapter": "source-map-candidate",
                                "source_path": path,
                            }
                        }
                        if executable
                        else {}
                    ),
                    "expected_benefit": "Reduce direct disclosure of authored source when this map would otherwise be public.",
                    "cost": "Build and review time; a downstream packaging or deployment step must consume the candidate tree.",
                    "tradeoffs": [
                        "Private source maps remain available for debugging.",
                        "The candidate does not change deployment settings or verify the served release.",
                    ],
                    "dependencies": (
                        [
                            "No additional engine; uses the private captured build snapshot."
                        ]
                        if executable
                        else ["Review the project build or deployment configuration."]
                    ),
                    "compatibility": (
                        [
                            "Candidate-tree omission does not change deployment configuration."
                        ]
                        if executable
                        else [
                            "Confirm target deployment and error-reporting workflow before changing publication."
                        ]
                    ),
                    "verification": ["public_source_map_absent"]
                    if executable
                    else ["manual_release_review"],
                    "limitations": [
                        "Candidate-tree exclusion does not prove that a deployed release omits the map.",
                        "This does not prevent inspection or reconstruction of shipped runtime code.",
                    ],
                    "rollback": (
                        f"Discard the private candidate and retain the original build tree: {path}"
                        if executable
                        else f"Restore the prior map publication rule and redeploy the matching release: {path}"
                    ),
                }
            )
        else:
            if not isinstance(captured["identity"].get("build_snapshot"), dict):
                continue
            execution = {
                "adapter": "bla-js",
                "source_path": path,
                "intensity": selected_intensity,
                "performance_budget": performance_budget,
            }
            if baseline_rea and baseline_rea["source_path"] == path:
                execution["rea_baseline_report"] = baseline_rea["report_path"]
                execution["rea_baseline_report_sha256"] = baseline_rea["report_sha256"]
                execution["rea_baseline_evidence_id"] = baseline_rea["evidence_id"]
            if (
                behavior_command is not None
                and baseline_behavior.get("artifact") == path
                and baseline_behavior.get("snapshot_path")
            ):
                execution["behavior_command"] = behavior_command
            if e2e_behavior:
                execution.update(
                    {
                        "e2e_config": baseline_e2e["config"],
                        "e2e_test_file": baseline_e2e["test_file"],
                        "e2e_runtime_path": baseline_e2e["runtime_path"],
                        "e2e_runtime_manifest_sha256": baseline_e2e[
                            "runtime_manifest_sha256"
                        ],
                    }
                )
            actions.append(
                {
                    "id": "bla-js-" + hashlib.sha256(path.encode()).hexdigest()[:12],
                    "finding_or_asset": f"Captured JavaScript artifact: {path}",
                    "change": "Create a BLA-protected candidate while preserving the original artifact.",
                    "mechanism": "Apply the pinned BLA JavaScript transformation to an isolated copy and run BLA's invariant verifier.",
                    "engine": "bla",
                    "execution": execution,
                    "expected_benefit": "Increase the effort required to read the transformed JavaScript; measure rather than assume protection.",
                    **common,
                }
            )
    if not actions:
        if blockers:
            return workflow.validate_plan(
                {
                    "schema_version": workflow.SCHEMA_VERSION,
                    "record_type": "plan",
                    "id": plan_id,
                    "target_id": discovered["id"],
                    "baseline_id": captured["id"],
                    "actions": [],
                    "blockers": blockers,
                    "budgets": budgets or {"runtime_ms": 60000},
                    "profile": {
                        "name": profile,
                        "bla_intensity": selected_intensity,
                        "scope": "BLA JavaScript actions only",
                    },
                    "rollback": "No candidate has been created; retain the captured baseline.",
                }
            )
        if already_obfuscated_flutter:
            raise workflow.WorkflowError(
                "Flutter baseline is already obfuscated; no same-obfuscation candidate is available"
            )
        if not any(path.lower().endswith(".map") for path in artifact_records):
            raise workflow.WorkflowError(
                "No source-map recommendation is supported by the captured artifacts"
            )
        if not isinstance(captured["identity"].get("build_snapshot"), dict):
            raise workflow.WorkflowError(
                "Executable recommendations require a fresh baseline build snapshot"
            )
        raise workflow.WorkflowError(
            "No source-map recommendation is supported by the captured artifacts"
        )
    plan = {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "plan",
        "id": plan_id,
        "target_id": discovered["id"],
        "baseline_id": captured["id"],
        "actions": actions,
        "profile": {
            "name": profile,
            "bla_intensity": selected_intensity,
            "scope": "BLA JavaScript actions only",
        },
        **({"blockers": blockers} if blockers else {}),
        "budgets": budgets or {"runtime_ms": 60000},
        "rollback": "For each selected action, follow its rollback instructions and discard the isolated candidate; retain the captured baseline.",
    }
    return workflow.validate_plan(plan)
