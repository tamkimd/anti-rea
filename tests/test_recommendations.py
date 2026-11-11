import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jsonschema

from core import flutter_android, recommendations, workflow


class RecommendationTests(unittest.TestCase):
    def setUp(self):
        self.target = {
            "schema_version": "2.0",
            "record_type": "target",
            "id": "target-r",
            "components": [{"id": "web", "kind": "javascript"}],
        }
        self.baseline = {
            "schema_version": "2.0",
            "record_type": "baseline",
            "id": "base-r",
            "target_id": "target-r",
            "identity": {
                "build_snapshot": {
                    "path": "/tmp/baseline-base-r-build-snapshot",
                    "source_tree_sha256": "1" * 64,
                    "tree_sha256": "2" * 64,
                    "file_scope_sha256": "3" * 64,
                },
                "artifacts": {
                    "dist/app.js.map": {"size": 40, "sha256": "a" * 64},
                    "dist/app.js": {"size": 20, "sha256": "b" * 64},
                },
                "behavior": {
                    "command": ["node", "check.mjs", "{artifact}"],
                    "artifact": "dist/app.js",
                    "artifact_sha256": "b" * 64,
                    "snapshot_path": "/tmp/baseline-base-r-behavior-snapshot",
                    "snapshot_source_tree_sha256": "d" * 64,
                    "snapshot_tree_sha256": "e" * 64,
                    "snapshot_file_scope_sha256": "f" * 64,
                    "evidence_path": "/tmp/baseline-behavior.json",
                    "evidence_sha256": "c" * 64,
                },
            },
            "evidence": ["before.json", "/tmp/baseline-behavior.json"],
        }

    def _baseline_with_craft_report(self, findings, *, status="partial"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        report_path = root / "baseline-base-r-craft-anything.json"
        snapshot_path = self.baseline["identity"]["build_snapshot"]["path"]
        coverage = {
            "status": "complete" if status == "complete" else "partial",
            "examined": 1,
            "total": 1 if status == "complete" else 2,
        }
        report = {
            "engine": "craft-anything",
            "version": "0.6.0",
            "mode": "deep",
            "status": status,
            "engine_status": status,
            "input_path": str(Path(snapshot_path) / "dist/app.js"),
            "input_sha256": "b" * 64,
            "input_unchanged": True,
            "coverage": coverage,
            "evidence": {"result": findings},
        }
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        report_path.write_bytes(raw)
        craft = {
            "engine": "craft-anything",
            "source_path": "dist/app.js",
            "artifact_sha256": "b" * 64,
            "snapshot_path": snapshot_path,
            "snapshot_tree_sha256": "2" * 64,
            "report_path": str(report_path),
            "report_sha256": hashlib.sha256(raw).hexdigest(),
            "project_path": str(root / "baseline-base-r-craft-anything.cany"),
            "version": "0.6.0",
            "mode": "deep",
            "status": status,
            "engine_status": status,
            "input_sha256": "b" * 64,
            "input_unchanged": True,
            "coverage": coverage,
        }
        return {
            **self.baseline,
            "identity": {
                **self.baseline["identity"],
                "craft_anything_analysis": craft,
            },
            "evidence": [*self.baseline["evidence"], str(report_path)],
        }, craft

    def test_plan_contains_hash_supported_conditional_source_map_and_bla_actions(self):
        plan = recommendations.create_plan(self.target, self.baseline, "plan-r")
        self.assertEqual(
            [a["engine"] for a in plan["actions"]],
            ["bla", "release packaging candidate"],
        )
        source_map, js_action = plan["actions"][1], plan["actions"][0]
        self.assertEqual(source_map["evidence"][0]["sha256"], "a" * 64)
        self.assertIn("private release-tree candidate", source_map["change"])
        self.assertIn("does not prove", source_map["limitations"][0])
        self.assertEqual(source_map["verification"], ["public_source_map_absent"])
        self.assertEqual(
            source_map["execution"],
            {"adapter": "source-map-candidate", "source_path": "dist/app.js.map"},
        )
        self.assertIn("downstream packaging", source_map["cost"])
        self.assertIn("does not change deployment settings", source_map["tradeoffs"][1])
        self.assertEqual(
            js_action["execution"],
            {
                "adapter": "bla-js",
                "source_path": "dist/app.js",
                "intensity": "balanced",
                "performance_budget": {
                    "trials": 3,
                    "max_elapsed_ms": 30000,
                    "max_candidate_bytes": 64 * 1024 * 1024,
                },
            },
        )
        self.assertEqual(
            plan["profile"],
            {
                "name": "balanced",
                "bla_intensity": "balanced",
                "scope": "BLA JavaScript actions only",
            },
        )
        self.assertEqual(js_action["evidence"][0]["sha256"], "b" * 64)
        self.assertEqual(
            plan["rollback"],
            "For each selected action, follow its rollback instructions and discard the isolated candidate; retain the captured baseline.",
        )

    def test_profiles_bind_supported_bla_intensity_into_reviewable_plan(self):
        for profile, intensity in (
            ("low-impact", "stealth"),
            ("balanced", "balanced"),
            ("deep-protection", "maximum"),
            ("custom", "bankrupt"),
        ):
            kwargs = {"profile": profile}
            if profile == "custom":
                kwargs["bla_intensity"] = intensity
            plan = recommendations.create_plan(
                self.target, self.baseline, "profile-" + profile, **kwargs
            )
            action = next(item for item in plan["actions"] if item["engine"] == "bla")
            self.assertEqual(action["execution"]["intensity"], intensity)
            self.assertEqual(plan["profile"]["name"], profile)
            self.assertEqual(plan["profile"]["bla_intensity"], intensity)

    def test_profiles_reject_unknown_or_ambiguous_custom_intensity(self):
        for kwargs in (
            {"profile": "unexpected"},
            {"profile": "custom"},
            {"profile": "balanced", "bla_intensity": "maximum"},
            {"profile": "custom", "bla_intensity": []},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(workflow.WorkflowError):
                recommendations.create_plan(
                    self.target, self.baseline, "profile-invalid", **kwargs
                )

    def test_saved_profile_and_bla_action_intensity_cannot_drift(self):
        plan = recommendations.create_plan(
            self.target, self.baseline, "profile-tamper", profile="low-impact"
        )
        plan["profile"]["bla_intensity"] = "maximum"
        with self.assertRaisesRegex(workflow.WorkflowError, "does not match"):
            workflow.validate_plan(plan)
        plan = recommendations.create_plan(
            self.target, self.baseline, "profile-tamper-action", profile="low-impact"
        )
        action = next(action for action in plan["actions"] if action["engine"] == "bla")
        action["execution"]["intensity"] = "maximum"
        with self.assertRaisesRegex(workflow.WorkflowError, "does not match"):
            workflow.validate_plan(plan)

    def test_flutter_apk_recommends_explicit_obfuscation_with_fail_closed_checks(self):
        command = ["/sdk/flutter", "build", "apk", "--release"]
        toolchain = {
            "flutter": {
                "framework_version": "3.47.8",
                "channel": "stable",
                "framework_revision": "a1",
                "engine_revision": "b2",
                "dart_sdk_version": "3.13.7",
            },
            "android": {
                "sdk_version": "36.0.0",
                "platform_version": "android-37",
                "build_tools_version": "36.0.0",
                "apksigner_sha256": "f" * 64,
            },
            "java": {"binary": "/opt/jdk/bin/java", "version": "OpenJDK 17"},
            "build": {
                "target": "apk",
                "command_sha256": hashlib.sha256(
                    workflow.canonical(command)
                ).hexdigest(),
            },
        }
        baseline = {
            **self.baseline,
            "identity": {
                "command": command,
                "build_snapshot": self.baseline["identity"]["build_snapshot"],
                "dependency_lock_sha256": "d" * 64,
                "flutter_toolchain": toolchain,
                "artifacts": {
                    "build/app/outputs/flutter-apk/app-release.apk": {
                        "size": 12,
                        "sha256": "c" * 64,
                    }
                },
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "baseline-base-r-build-snapshot"
            apk_path = snapshot_path / "build/app/outputs/flutter-apk/app-release.apk"
            apk_path.parent.mkdir(parents=True)
            apk_path.write_bytes(b"baseline-apk")
            apk_hash = hashlib.sha256(b"baseline-apk").hexdigest()
            baseline["identity"]["build_snapshot"]["path"] = str(snapshot_path)
            baseline["identity"]["artifacts"][
                "build/app/outputs/flutter-apk/app-release.apk"
            ] = {"size": len(b"baseline-apk"), "sha256": apk_hash}
            report_path = Path(directory) / "report.json"
            manifest_path = Path(directory) / "rea-manifest.json"
            names = (
                "_kDartVmSnapshotInstructions",
                "_kDartIsolateSnapshotInstructions",
                "_kDartVmSnapshotData",
                "_kDartIsolateSnapshotData",
            )
            report_path.write_text(
                json.dumps(
                    {
                        "predicate_type": "rea.analysis",
                        "operation": "inspect_dart_aot",
                        "provider": {"id": "flutter"},
                        "evidence_id": "aot-before",
                        "subject": {"format": "apk", "digest": {"sha256": apk_hash}},
                        "normalized_result": {
                            "abi": "arm64-v8a",
                            "target": {
                                "sha256": apk_hash,
                                "bytes": len(b"baseline-apk"),
                            },
                            "libapp": {
                                "coverage": "complete",
                                "sections": [
                                    {"name": name, "offset": index, "size": 8}
                                    for index, name in enumerate(names)
                                ],
                                "sha256": "d" * 64,
                                "snapshot_hash": "before-snapshot",
                            },
                        },
                    }
                )
            )
            manifest = {
                "schema_version": "1.0",
                "npm_version": "6.8.0",
                "npm_integrity": "sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==",
                "package_lock_sha256": "b6cb714948a7ec224fa6f676f0e9b6f570bbabf3518a1a187be571ac8ddfe232",
                "package_tree_sha256": "2" * 64,
                "node_version": "v24.22.1",
            }
            manifest_path.write_text(json.dumps(manifest))
            with patch.object(
                flutter_android,
                "_verify_rea_runtime",
                return_value=(manifest_path, manifest_path.read_bytes(), manifest),
            ):
                baseline = flutter_android.attach_aot_inspection(
                    baseline, report_path, directory, "arm64-v8a", "base-r-aot"
                )
            plan = recommendations.create_plan(self.target, baseline, "plan-flutter")
            action = plan["actions"][0]
            self.assertEqual(action["engine"], "flutter-dart-obfuscation")
            self.assertEqual(
                action["execution"],
                {
                    "adapter": "flutter-dart-obfuscation",
                    "artifact_path": "build/app/outputs/flutter-apk/app-release.apk",
                    "target": "apk",
                    "flutter_executable": "/sdk/flutter",
                    "selected_abi": "arm64-v8a",
                    "rea_runtime_manifest_sha256": baseline["identity"][
                        "flutter_aot_inspection"
                    ]["runtime_manifest_sha256"],
                },
            )
            self.assertEqual(
                action["verification"],
                ["flutter_aot_comparison", "flutter_android_behavior"],
            )
            self.assertIn("unverified", action["limitations"][0])

    def test_flutter_without_supported_aot_evidence_is_a_blocked_plan(self):
        command = ["/sdk/flutter", "build", "apk", "--release"]
        toolchain = {
            "flutter": {
                "framework_version": "3.47.8",
                "channel": "stable",
                "framework_revision": "a1",
                "engine_revision": "b2",
                "dart_sdk_version": "3.13.7",
            },
            "android": {
                "sdk_version": "36.0.0",
                "platform_version": "android-37",
                "build_tools_version": "36.0.0",
                "apksigner_sha256": "f" * 64,
            },
            "java": {"binary": "/opt/jdk/bin/java", "version": "OpenJDK 17"},
            "build": {
                "target": "apk",
                "command_sha256": hashlib.sha256(
                    workflow.canonical(command)
                ).hexdigest(),
            },
        }
        baseline = {
            **self.baseline,
            "identity": {
                "command": command,
                "build_snapshot": self.baseline["identity"]["build_snapshot"],
                "dependency_lock_sha256": "d" * 64,
                "flutter_toolchain": toolchain,
                "artifacts": {
                    "build/app/outputs/flutter-apk/app-release.apk": {
                        "size": 12,
                        "sha256": "c" * 64,
                    }
                },
            },
        }
        plan = recommendations.create_plan(
            self.target, baseline, "plan-flutter-blocked"
        )
        self.assertEqual(plan["actions"], [])
        self.assertEqual(
            plan["profile"],
            {
                "name": "balanced",
                "bla_intensity": "balanced",
                "scope": "BLA JavaScript actions only",
            },
        )
        self.assertIn("supported arm64-v8a AOT profile", plan["blockers"][0])
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        jsonschema.validate(plan, schema)
        with self.assertRaisesRegex(workflow.WorkflowError, "Blocked plan"):
            workflow.validate_plan_baseline(plan, baseline)

    def test_already_obfuscated_flutter_baseline_is_not_recommended_again(self):
        command = [
            "/sdk/flutter",
            "build",
            "apk",
            "--release",
            "--obfuscate",
            "--split-debug-info=/private/symbols",
        ]
        baseline = {
            **self.baseline,
            "identity": {
                "command": command,
                "build_snapshot": self.baseline["identity"]["build_snapshot"],
                "dependency_lock_sha256": "d" * 64,
                "artifacts": {
                    "build/app/outputs/flutter-apk/app-release.apk": {
                        "size": 12,
                        "sha256": "c" * 64,
                    }
                },
            },
        }
        with self.assertRaisesRegex(workflow.WorkflowError, "already obfuscated"):
            recommendations.create_plan(self.target, baseline, "plan-flutter-already")

    def test_plan_surfaces_captured_rea_before_evidence_for_decision(self):
        rea_temp = tempfile.TemporaryDirectory()
        self.addCleanup(rea_temp.cleanup)
        rea_root = Path(rea_temp.name) / "baseline-base-r-rea"
        rea_root.mkdir()
        report_path = rea_root / "report.jsonl"
        report_path.write_text("fixture report")
        rea = {
            "source_path": "dist/app.js",
            "artifact_sha256": "b" * 64,
            "snapshot_path": str(rea_root / "snapshot"),
            "tree_sha256": "e" * 64,
            "file_scope_sha256": "f" * 64,
            "report_path": str(report_path),
            "report_sha256": "d" * 64,
            "bundle_path": "/tmp/baseline-base-r-rea/bundle.json",
            "bundle_sha256": "1" * 64,
            "runtime_path": "/tmp/rea-runtime",
            "runtime_manifest_sha256": "2" * 64,
            "evidence_id": "ev_fixture",
            "parent_digest": "3" * 64,
        }
        rea["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
        rea["bundle_path"] = str(rea_root / "bundle.json")
        baseline = {
            **self.baseline,
            "identity": {**self.baseline["identity"], "rea_analysis": rea},
            "evidence": [
                *self.baseline["evidence"],
                rea["report_path"],
                rea["bundle_path"],
            ],
        }
        plan = recommendations.create_plan(self.target, baseline, "plan-rea")
        self.assertFalse(
            any(
                item.get("execution", {}).get("adapter") == "source-map-candidate"
                for item in plan["actions"]
            )
        )
        self.assertTrue(
            any(
                "cannot satisfy the selected REA acceptance gate" in item
                for item in plan["blockers"]
            )
        )
        self.assertEqual(
            next(
                item
                for item in plan["finding_mappings"]
                if item.get("candidate") == "dist/app.js.map"
            )["status"],
            "blocked",
        )
        action = next(
            item
            for item in plan["actions"]
            if item.get("execution", {}).get("source_path") == "dist/app.js"
        )
        self.assertIn(
            {
                "baseline_id": "base-r",
                "path": rea["report_path"],
                "sha256": rea["report_sha256"],
                "kind": "rea-before",
            },
            action["evidence"],
        )
        self.assertEqual(action["execution"]["rea_baseline_evidence_id"], "ev_fixture")
        report_path.unlink()

    def test_craft_findings_feed_supported_actions_without_claiming_verification(self):
        baseline, craft = self._baseline_with_craft_report(
            {
                "summary": "Web app: endpoint and external source-map candidates.",
                "endpoints": [{"url": "/api/v1/users"}],
                "routes": [],
                "ipc": [],
                "source_maps": [
                    {"present": True, "inline": False, "resolved": "app.js.map"}
                ],
            }
        )

        plan = recommendations.create_plan(self.target, baseline, "plan-craft")

        js_action = next(item for item in plan["actions"] if item["engine"] == "bla")
        map_action = next(
            item
            for item in plan["actions"]
            if item["engine"] == "release packaging candidate"
        )
        evidence = {
            "baseline_id": "base-r",
            "path": craft["report_path"],
            "sha256": craft["report_sha256"],
            "kind": "craft-anything-before",
        }
        self.assertIn(evidence, js_action["evidence"])
        self.assertEqual(js_action["analysis_findings"]["engine_status"], "partial")
        self.assertEqual(
            js_action["analysis_findings"]["candidate_counts"]["endpoints"], 1
        )
        self.assertIn(
            "not independently confirmed",
            js_action["analysis_findings"]["interpretation"],
        )
        self.assertIn(evidence, map_action["evidence"])
        self.assertEqual(
            map_action["analysis_findings"]["matched_source_map"], "dist/app.js.map"
        )
        mappings = plan["finding_mappings"]
        self.assertIn(
            {
                "engine": "craft-anything",
                "finding_type": "source_map",
                "candidate": "dist/app.js.map",
                "status": "mapped",
                "action_id": map_action["id"],
            },
            mappings,
        )
        endpoint_mapping = next(
            item for item in mappings if item["finding_type"] == "endpoint"
        )
        self.assertEqual(endpoint_mapping["status"], "blocked")
        self.assertTrue(
            any(
                "no validated action for this finding type" in item
                for item in plan["blockers"]
            )
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "finding mappings"):
            workflow.validate_plan(
                {**plan, "finding_mappings": [{**mappings[0], "action_id": "missing"}]}
            )

    def test_craft_analysis_gate_can_select_partial_before_and_default_is_ready_only(
        self,
    ):
        partial, _ = self._baseline_with_craft_report(
            {
                "summary": "Partial scan",
                "endpoints": [],
                "routes": [],
                "ipc": [],
                "source_maps": [],
            }
        )
        partial_plan = recommendations.create_plan(
            self.target, partial, "plan-craft-partial"
        )
        self.assertNotIn("craft-anything", partial_plan.get("analysis_gates", []))
        partial_gate_plan = recommendations.create_plan(
            self.target,
            partial,
            "plan-craft-partial-gate",
            analysis_gates=["craft-anything"],
        )
        self.assertEqual(partial_gate_plan["analysis_gates"], ["craft-anything"])

        complete, _ = self._baseline_with_craft_report(
            {
                "summary": "Full scan",
                "endpoints": [],
                "routes": [],
                "ipc": [],
                "source_maps": [],
            },
            status="complete",
        )
        complete_plan = recommendations.create_plan(
            self.target, complete, "plan-craft-complete"
        )
        self.assertIn("craft-anything", complete_plan["analysis_gates"])

    def test_craft_inline_source_map_without_supported_action_becomes_blocker(self):
        baseline, _ = self._baseline_with_craft_report(
            {
                "summary": "Web app: inline source-map candidate.",
                "endpoints": [],
                "routes": [],
                "ipc": [],
                "source_maps": [{"present": True, "inline": True}],
            },
            status="complete",
        )

        plan = recommendations.create_plan(self.target, baseline, "plan-craft-inline")

        self.assertTrue(
            any(
                "without a matching captured .map artifact" in item
                for item in plan["blockers"]
            )
        )

    def test_no_supported_artifact_or_bad_ids_fail_without_creating_plan(self):
        baseline = {
            **self.baseline,
            "identity": {
                "artifacts": {"dist/app.bin": {"size": 20, "sha256": "b" * 64}}
            },
        }
        with self.assertRaisesRegex(
            workflow.WorkflowError, "No source-map recommendation"
        ):
            recommendations.create_plan(self.target, baseline, "plan-none")
        with self.assertRaisesRegex(workflow.WorkflowError, "plan id"):
            recommendations.create_plan(self.target, self.baseline, "../escape")
        malformed = {
            **self.baseline,
            "identity": {"artifacts": {"app.map": {"size": -1, "sha256": "z" * 64}}},
        }
        with self.assertRaisesRegex(workflow.WorkflowError, "artifact identities"):
            recommendations.create_plan(self.target, malformed, "plan-bad")
        with self.assertRaisesRegex(workflow.WorkflowError, "argv containing"):
            recommendations.create_plan(
                self.target,
                self.baseline,
                "plan-command",
                behavior_command=["node", "app.js"],
            )

    def test_behavior_command_is_bound_into_the_bla_action(self):
        command = ["node", "check.mjs", "{artifact}"]
        plan = recommendations.create_plan(
            self.target, self.baseline, "plan-command", behavior_command=command
        )
        self.assertEqual(plan["actions"][0]["execution"]["behavior_command"], command)

    def test_legacy_baseline_does_not_recommend_executable_bla(self):
        baseline = {
            **self.baseline,
            "identity": {
                k: v
                for k, v in self.baseline["identity"].items()
                if k != "build_snapshot"
            },
        }
        plan = recommendations.create_plan(self.target, baseline, "plan-legacy-build")
        self.assertEqual(plan["actions"][0]["verification"], ["manual_release_review"])
        self.assertNotIn("execution", plan["actions"][0])

    def test_legacy_behavior_baseline_does_not_schedule_unisolated_command(self):
        behavior = {
            key: value
            for key, value in self.baseline["identity"]["behavior"].items()
            if not key.startswith("snapshot_") and key != "snapshot_path"
        }
        baseline = {
            **self.baseline,
            "identity": {**self.baseline["identity"], "behavior": behavior},
        }
        plan = recommendations.create_plan(
            self.target,
            baseline,
            "plan-legacy-behavior",
            behavior_command=behavior["command"],
        )
        self.assertNotIn("behavior_command", plan["actions"][0]["execution"])
        self.assertNotIn("application_behavior", plan["actions"][0]["verification"])

    def test_performance_budget_is_plan_bound_and_validated(self):
        plan = recommendations.create_plan(
            self.target,
            self.baseline,
            "plan-perf",
            performance_budget={
                "trials": 3,
                "max_elapsed_ms": 900,
                "max_candidate_bytes": 100000,
            },
        )
        action = plan["actions"][0]
        self.assertIn("performance", action["verification"])
        self.assertEqual(
            action["execution"]["performance_budget"]["max_elapsed_ms"], 900
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "exactly 3 trials"):
            recommendations.create_plan(
                self.target,
                self.baseline,
                "plan-perf-invalid",
                performance_budget={
                    "trials": 2,
                    "max_elapsed_ms": 900,
                    "max_candidate_bytes": 100000,
                },
            )

    def test_behavior_command_must_match_the_baseline_capture(self):
        with self.assertRaisesRegex(
            workflow.WorkflowError, "match the command captured"
        ):
            recommendations.create_plan(
                self.target,
                self.baseline,
                "plan-command-mismatch",
                behavior_command=["node", "other-check.mjs", "{artifact}"],
            )

    def test_behavior_lane_only_attaches_to_the_captured_js_artifact(self):
        baseline = {
            **self.baseline,
            "identity": {
                **self.baseline["identity"],
                "artifacts": {
                    "dist/app.js": {"size": 20, "sha256": "b" * 64},
                    "dist/other.js": {"size": 22, "sha256": "d" * 64},
                },
            },
        }
        plan = recommendations.create_plan(
            self.target,
            baseline,
            "plan-multi-js",
            behavior_command=baseline["identity"]["behavior"]["command"],
        )
        actions = {
            item["execution"]["source_path"]: item
            for item in plan["actions"]
            if item["engine"] == "bla"
        }
        self.assertIn("behavior_command", actions["dist/app.js"]["execution"])
        self.assertIn("application_behavior", actions["dist/app.js"]["verification"])
        self.assertNotIn("behavior_command", actions["dist/other.js"]["execution"])
        self.assertNotIn(
            "application_behavior", actions["dist/other.js"]["verification"]
        )

    def test_optional_browser_check_is_bound_to_default_fixture_paths(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "captured before"):
            recommendations.create_plan(
                self.target, self.baseline, "plan-e2e-no-baseline", e2e_behavior=True
            )
        e2e = {
            "source_path": "dist/app.js",
            "artifact_sha256": "b" * 64,
            "snapshot_path": "/tmp/baseline-base-r-e2e/snapshot",
            "tree_sha256": "d" * 64,
            "file_scope_sha256": "e" * 64,
            "report_path": "/tmp/baseline-base-r-e2e/report.json",
            "report_sha256": "f" * 64,
            "runtime_path": "/tmp/e2e-runtime",
            "runtime_manifest_sha256": "1" * 64,
            "runtime_package_lock_sha256": "2" * 64,
            "runner": {"name": "e2e", "version": "1.2.3"},
            "test_ids": ["suite/test"],
            "config": "e2e.config.mjs",
            "test_file": "tests/behavior.e2e.ts",
            "cleanup": "loopback app port closed",
        }
        baseline = {
            **self.baseline,
            "identity": {**self.baseline["identity"], "e2e_behavior": e2e},
            "evidence": [*self.baseline["evidence"], e2e["report_path"]],
        }
        plan = recommendations.create_plan(
            self.target, baseline, "plan-e2e", e2e_behavior=True
        )
        action = next(item for item in plan["actions"] if item["engine"] == "bla")
        self.assertIn("e2e_behavior", action["verification"])
        self.assertNotIn("application_behavior", action["verification"])
        self.assertEqual(
            (action["execution"]["e2e_config"], action["execution"]["e2e_test_file"]),
            (e2e["config"], e2e["test_file"]),
        )
        self.assertEqual(
            action["execution"]["e2e_runtime_manifest_sha256"],
            e2e["runtime_manifest_sha256"],
        )

    def test_cli_recommendation_saves_generated_plan(self):
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            records = store / "records"
            workflow.write_record(records, self.target)
            workflow.write_record(records, self.baseline)
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "recommend",
                    "target-r",
                    "base-r",
                    "plan-cli",
                    str(store),
                    "--profile",
                    "low-impact",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["status"], "recommendations_ready"
            )
            saved = workflow.read_record(records / "plan-plan-cli.json", "plan")
            self.assertEqual(saved["baseline_id"], "base-r")
            self.assertEqual(saved["profile"]["name"], "low-impact")
            self.assertEqual(
                next(a for a in saved["actions"] if a["engine"] == "bla")["execution"][
                    "intensity"
                ],
                "stealth",
            )

    def test_cli_reports_blocked_flutter_plan_without_crashing(self):
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        target = {
            "schema_version": "2.0",
            "record_type": "target",
            "id": "target-cli-flutter",
            "components": [{"id": "app", "kind": "flutter"}],
        }
        command = ["/sdk/flutter", "build", "apk", "--release"]
        toolchain = {
            "flutter": {
                "framework_version": "3.47.8",
                "channel": "stable",
                "framework_revision": "a1",
                "engine_revision": "b2",
                "dart_sdk_version": "3.13.7",
            },
            "android": {
                "sdk_version": "36.0.0",
                "platform_version": "android-37",
                "build_tools_version": "36.0.0",
                "apksigner_sha256": "f" * 64,
            },
            "java": {"binary": "/opt/jdk/bin/java", "version": "OpenJDK 17"},
            "build": {
                "target": "apk",
                "command_sha256": hashlib.sha256(
                    workflow.canonical(command)
                ).hexdigest(),
            },
        }
        baseline = {
            "schema_version": "2.0",
            "record_type": "baseline",
            "id": "base-cli-flutter",
            "target_id": "target-cli-flutter",
            "identity": {
                "command": command,
                "dependency_lock_sha256": "a" * 64,
                "flutter_toolchain": toolchain,
                "artifacts": {
                    "build/app/outputs/flutter-apk/app-release.apk": {
                        "size": 12,
                        "sha256": "b" * 64,
                    }
                },
            },
            "evidence": ["before.json"],
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            records = store / "records"
            workflow.write_record(records, target)
            workflow.write_record(records, baseline)
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "recommend",
                    "target-cli-flutter",
                    "base-cli-flutter",
                    "plan-cli-flutter",
                    str(store),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            response = json.loads(result.stdout)
            self.assertEqual(response["status"], "blocked")
            self.assertEqual(response["actions"], [])
            self.assertEqual(response["profile"]["name"], "balanced")
            self.assertIn("supported arm64-v8a AOT profile", response["blockers"][0])

    def test_cli_status_and_report_read_persisted_run(self):
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            workflow.write_record(store / "records", self.target)
            run = {
                "schema_version": "2.0",
                "record_type": "run",
                "id": "run-status",
                "target_id": "target-r",
                "state": "discovered",
            }
            workflow.write_run_state(store / "runs", run, None)
            for command in ("status", "report"):
                result = subprocess.run(
                    [sys.executable, str(cli), command, "run-status", str(store)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["run"], run)


if __name__ == "__main__":
    unittest.main()
