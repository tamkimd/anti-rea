import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WheelPayloadTests(unittest.TestCase):
    def test_codex_cli_smoke_summary_records_partial_real_result(self):
        example = ROOT / "examples/codex-cli"
        summary = json.loads((example / "evidence-summary.json").read_text())
        evidence_bytes = (example / summary["evidence"]["file"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(evidence_bytes).hexdigest(), summary["evidence"]["sha256"]
        )
        evidence = json.loads(evidence_bytes)
        self.assertEqual(summary["result"], "partial")
        self.assertTrue(summary["skill"]["project_copy_read_by_harness"])
        self.assertEqual(evidence["product"]["version"], "0.1.32")
        self.assertEqual(evidence["product"]["doctor_exit_code"], 0)
        self.assertEqual(evidence["product"]["probe_exit_code"], 0)
        self.assertTrue(evidence["execution"]["recommendation_skipped"])
        self.assertFalse(evidence["execution"]["source_project_modified"])

    def test_current_codex_readiness_evidence_is_hash_bound_and_stops_on_blocker(self):
        example = ROOT / "examples/codex-cli"
        summary = json.loads((example / "evidence-summary.json").read_text())
        current = (example / summary["evidence"]["file"]).read_bytes()
        probe = (example / summary["readiness_evidence"]["file"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(current).hexdigest(), summary["evidence"]["sha256"]
        )
        self.assertEqual(
            hashlib.sha256(probe).hexdigest(), summary["readiness_evidence"]["sha256"]
        )
        run = json.loads(current)
        readiness = json.loads(probe)
        self.assertEqual(run["product"]["version"], "0.1.32")
        self.assertTrue(run["execution"]["recommendation_skipped"])
        self.assertEqual(readiness["probe"]["status"], "blocked")
        self.assertEqual(readiness["probe"]["android_build"], "blocked")
        self.assertTrue(readiness["harness_stop"]["recommendation_skipped"])

    def test_codex_plan_review_is_hash_bound_and_stops_before_decision(self):
        example = ROOT / "examples/codex-cli"
        summary = json.loads((example / "evidence-summary.json").read_text())
        review_bytes = (example / summary["plan_review_evidence"]["file"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(review_bytes).hexdigest(),
            summary["plan_review_evidence"]["sha256"],
        )
        review = json.loads(review_bytes)
        self.assertEqual(review["doctor_status"], "ready")
        self.assertEqual(review["run"]["state"], "awaiting_decision")
        self.assertFalse(review["run"]["decision_recorded"])
        self.assertFalse(review["run"]["candidate_executed"])
        self.assertEqual(
            review["plan_profile"]["saved_field"], "absent; this is a legacy plan"
        )
        self.assertEqual(len(review["actions"]), 4)
        self.assertEqual(review["user_follow_up"]["selection"], "review_only")
        self.assertFalse(review["user_follow_up"]["anti_rea_decision_recorded"])
        self.assertEqual(
            review["user_follow_up"]["run_state_after_choice"], "awaiting_decision"
        )

    def test_flutter_example_evidence_hashes_match_real_reports(self):
        example = ROOT / "examples/flutter-todo"
        summary = json.loads((example / "evidence-summary.json").read_text())
        baseline = summary["anti_rea_baseline"]
        build_report = (example / baseline["build_output_report"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(build_report).hexdigest(),
            baseline["build_output_report_sha256"],
        )
        build = json.loads(build_report)
        self.assertEqual(build["exit_code"], 0)
        self.assertTrue(
            all(
                build["artifacts_sha256"][path] == identity
                for path, identity in baseline["artifacts"].items()
            )
        )

        manifest = json.loads((example / baseline["manifest_report"]).read_text())
        self.assertEqual(manifest["raw_record_sha256"], baseline["manifest_sha256"])
        self.assertEqual(manifest["record"]["id"], baseline["id"])
        baseline_record = manifest["record"]
        self.assertEqual(
            len(baseline_record["identity"]["artifacts"]), baseline["artifact_count"]
        )

        browser = baseline["e2e"]
        report_bytes = (example / browser["report"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(report_bytes).hexdigest(), browser["report_sha256"]
        )
        report = json.loads(report_bytes)
        self.assertEqual(report["schemaVersion"], "report-1")
        self.assertEqual(report["run"]["id"], browser["run_id"])
        self.assertEqual(report["run"]["status"], "passed")
        self.assertEqual(report["run"]["summary"]["passed"], 1)
        self.assertEqual(report["run"]["summary"]["failed"], 0)
        e2e_identity = baseline_record["identity"]["e2e_behavior"]
        self.assertEqual(e2e_identity["source_path"], browser["primary_artifact"])
        self.assertEqual(e2e_identity["report_sha256"], browser["report_sha256"])
        self.assertEqual(e2e_identity["tree_sha256"], browser["snapshot_tree_sha256"])

        rea = summary["rea_analysis"]
        rea_bytes = (example / rea["record"]).read_bytes()
        self.assertEqual(hashlib.sha256(rea_bytes).hexdigest(), rea["record_sha256"])
        attempt = json.loads(rea_bytes)
        self.assertEqual(attempt["status"], "blocked")
        self.assertEqual(
            attempt["target"]["artifact_sha256"],
            baseline["artifacts"]["build-out/web/main.dart.js"],
        )
        self.assertEqual(
            attempt["attempts"][2]["statistics"]["parsed_javascript_files"], 0
        )
        self.assertEqual(
            attempt["attempts"][2]["statistics"]["skipped_javascript_files"], 1
        )
        self.assertEqual(attempt["attempts"][2]["statistics"]["findings"], 0)
        self.assertFalse(rea["raw_rea_report"])
        for entry in attempt["attempts"]:
            for field in ("raw_output", "evidence_bundle"):
                if field not in entry:
                    continue
                artifact = entry[field]
                payload = (example / artifact["path"]).read_bytes()
                self.assertEqual(len(payload), artifact["sanitized_bytes"])
                self.assertEqual(
                    hashlib.sha256(payload).hexdigest(), artifact["sanitized_sha256"]
                )
                json.loads(payload)
        full_timeout = json.loads(
            (example / attempt["attempts"][1]["raw_output"]["path"]).read_text()
        )
        self.assertEqual(full_timeout["code"], "provider_timeout")
        primary = json.loads(
            (example / attempt["attempts"][2]["raw_output"]["path"]).read_text()
        )
        stats = primary["summary"]["normalized_result"]["summary"]["statistics"]
        self.assertEqual(stats["parsed_javascript_files"], 0)
        self.assertEqual(stats["skipped_javascript_files"], 1)
        high_memory_timeout = json.loads(
            (example / attempt["attempts"][3]["raw_output"]["path"]).read_text()
        )
        self.assertEqual(high_memory_timeout["code"], "provider_timeout")
        low_semantic = json.loads(
            (example / attempt["attempts"][4]["raw_output"]["path"]).read_text()
        )
        self.assertEqual(low_semantic["status"], "blocked_provider_timeout")
        self.assertEqual(low_semantic["attempt"]["max_heap_mb"], 4096)
        self.assertEqual(low_semantic["attempt"]["max_semantic_nodes_per_file"], 64)
        self.assertEqual(low_semantic["result"]["error_code"], "provider_timeout")
        self.assertFalse(low_semantic["result"]["analysis_report_created"])

        bootstrap_ref = rea["bootstrap_report"]
        bootstrap_bytes = (example / bootstrap_ref["record"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(bootstrap_bytes).hexdigest(), bootstrap_ref["record_sha256"]
        )
        bootstrap = json.loads(bootstrap_bytes)
        self.assertEqual(bootstrap["status"], "passed_with_limited_scope")
        self.assertEqual(
            bootstrap["artifact"]["sha256"],
            "d1efa9256397f63a22c573a118092250f6e797b0d2a1ec9d403463d590df8578",
        )
        self.assertNotEqual(
            bootstrap["artifact"]["sha256"],
            baseline["artifacts"]["build-out/web/main.dart.js"],
        )
        self.assertEqual(
            bootstrap["artifact"]["path"], "build-out/web/flutter_bootstrap.js"
        )
        self.assertEqual(bootstrap["statistics"]["parsed_javascript_files"], 1)
        self.assertEqual(bootstrap["statistics"]["skipped_javascript_files"], 0)
        self.assertEqual(bootstrap["statistics"]["parse_failures"], 0)
        self.assertEqual(bootstrap["statistics"]["findings"], 9)
        self.assertEqual(
            bootstrap["coverage"],
            {
                "status": "complete-within-view",
                "examined": 18,
                "total": 18,
                "next_offset": None,
                "exhausted": True,
            },
        )
        self.assertIn(
            "main.dart.js app bundle was excluded", bootstrap["scope"]["classification"]
        )
        result_sheet = (example / "REA-RESULT.md").read_text()
        self.assertIn(bootstrap["artifact"]["sha256"], result_sheet)
        self.assertIn(f"{bootstrap['artifact']['size']:,} bytes", result_sheet)
        self.assertIn(f"{bootstrap['statistics']['findings']} |", result_sheet)
        self.assertIn("does **not** analyze the Todo application logic", result_sheet)

        retry_ref = rea["latest_diagnostic"]
        retry_bytes = (example / retry_ref["record"]).read_bytes()
        self.assertEqual(
            hashlib.sha256(retry_bytes).hexdigest(), retry_ref["record_sha256"]
        )
        retry = json.loads(retry_bytes)
        self.assertEqual(retry["status"], "blocked_provider_timeout")
        self.assertEqual(retry["rea"]["analysis_timeout_ms"], 600000)
        self.assertEqual(retry["rea"]["max_heap_mb"], 4096)
        self.assertEqual(retry["rea"]["statistics"]["parsed_javascript_files"], 0)
        self.assertEqual(retry["rea"]["statistics"]["skipped_javascript_files"], 1)
        self.assertEqual(retry["rea"]["statistics"]["findings"], 0)
        self.assertFalse(retry["analysis_report_created"])
        self.assertIn(f"({retry_ref['record']})", result_sheet)
        self.assertIn("0 parsed, 1 skipped, 0 findings", result_sheet)
        self.assertEqual(
            hashlib.sha256((example / rea["record"]).read_bytes()).hexdigest(),
            rea["record_sha256"],
        )

    def test_loopweek_flutter_reports_are_hash_bound_and_scoped(self):
        example = ROOT / "examples/loopweek-flutter"
        summary = json.loads((example / "evidence-summary.json").read_text())
        self.assertEqual(summary["source"]["license"], "MIT")
        self.assertEqual(summary["release_artifact"]["stored_in_repository"], False)
        for key in ("flutter_build_identification", "dart_aot_inspection"):
            ref = summary["operations"][key]["report"]
            payload = (example / ref["file"]).read_bytes()
            self.assertEqual(len(payload), ref["sanitized_bytes"])
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(), ref["sanitized_sha256"]
            )
            report = json.loads(payload)
            self.assertEqual(report["evidence_id"], ref["evidence_id"])
            self.assertEqual(report["operation"], ref["operation"])
            self.assertEqual(
                report["subject"]["digest"]["sha256"],
                summary["release_artifact"]["sha256"],
            )
        identify = json.loads(
            (
                example
                / summary["operations"]["flutter_build_identification"]["report"][
                    "file"
                ]
            ).read_text()
        )
        self.assertTrue(identify["normalized_result"]["flutter_detected"])
        self.assertEqual(identify["normalized_result"]["coverage"], "complete")
        self.assertEqual(len(identify["normalized_result"]["abis"]), 3)
        aot = json.loads(
            (
                example / summary["operations"]["dart_aot_inspection"]["report"]["file"]
            ).read_text()
        )
        result = aot["normalized_result"]
        self.assertEqual(result["abi"], "arm64-v8a")
        self.assertEqual(result["libapp"]["coverage"], "complete")
        self.assertEqual(len(result["libapp"]["sections"]), 4)
        self.assertEqual(result["string_pool"]["coverage"], "partial")
        self.assertGreaterEqual(len(result["string_pool"]["package_uris"]), 500)
        self.assertGreaterEqual(len(result["string_pool"]["class_like_tokens"]), 2000)
        self.assertIn("No candidate", " ".join(summary["limitations"]))
        summary_text = (example / "README.md").read_text().lower()
        self.assertIn("no protection claim", summary_text)
        self.assertIn("partial", summary_text)

    def test_loopweek_unmerged_rea_candidate_aot_result_is_hash_bound_and_not_promoted(
        self,
    ):
        example = ROOT / "examples/loopweek-flutter"
        summary = json.loads((example / "evidence-summary.json").read_text())
        reference = summary["upstream_candidate_aot_inspection"]
        raw = (example / reference["report"]).read_bytes()
        self.assertEqual(len(raw), reference["report_bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), reference["report_sha256"])
        record = json.loads(raw)
        self.assertEqual(
            record["operation"]["full_report_sha256"], reference["raw_report_sha256"]
        )
        self.assertEqual(record["artifact"]["sha256"], reference["apk_sha256"])
        self.assertEqual(
            record["upstream"]["commit"], reference["rea_candidate_commit"]
        )
        self.assertEqual(
            record["upstream"]["release_status"], "unmerged_upstream_candidate"
        )
        self.assertEqual(record["aot"]["abi"], "arm64-v8a")
        self.assertEqual(record["aot"]["libapp"]["coverage"], "complete")
        self.assertEqual(
            record["aot"]["libapp"]["sections"][1]["name"], "_kDartSnapshotData"
        )
        self.assertEqual(record["aot"]["libapp"]["sections"][1]["kind"], 2)
        self.assertEqual(record["aot"]["string_pool"]["coverage"], "partial")
        verification = record["source_verification"]
        self.assertEqual(verification["checkout_commit"], record["upstream"]["commit"])
        self.assertEqual(verification["npm_build_exit_code"], 0)
        self.assertEqual(verification["build_tasks"], {"successful": 3, "total": 3})
        self.assertEqual(verification["flutter_provider_tests_passed"], 103)
        self.assertEqual(
            verification["git_install_with_scripts_disabled"]["cli_startup"],
            "missing_compiled_runtime",
        )
        packed = verification["packed_source_install"]
        self.assertEqual(
            packed["tarball_sha256"],
            "8ceb743bd90226b5c28353316841f6a420fbaefc347a86a1b45eb831155f0377",
        )
        self.assertTrue(packed["install_scripts_disabled"])
        self.assertTrue(packed["worker_module_imported"])
        self.assertFalse(verification["source_build_is_pinned_release"])
        self.assertFalse(verification["pinned_anti_rea_runtime_changed"])
        replay = verification["exact_baseline_reinspection"]
        self.assertEqual(
            replay["raw_report_sha256"], record["operation"]["full_report_sha256"]
        )
        self.assertEqual(replay["artifact_sha256"], record["artifact"]["sha256"])
        self.assertEqual(replay["libapp_coverage"], "complete")
        self.assertEqual(replay["string_pool_coverage"], "partial")
        self.assertFalse(reference["candidate_artifact_built"])
        self.assertFalse(reference["protection_claim"])
        self.assertFalse(
            record["interpretation"]["anti_rea_pinned_runtime_gate"].startswith(
                "passed"
            )
        )
        for host_path in ("/private/tmp/", "/Users/", "/Volumes/"):
            self.assertNotIn(host_path, raw.decode())

    def test_loopweek_android_package_and_emulator_evidence_are_bounded(self):
        example = ROOT / "examples/loopweek-flutter"
        summary = json.loads((example / "evidence-summary.json").read_text())
        package_ref = summary["operations"]["android_package_inspection"]["report"]
        package_bytes = (example / package_ref["file"]).read_bytes()
        self.assertEqual(len(package_bytes), package_ref["sanitized_bytes"])
        self.assertEqual(
            hashlib.sha256(package_bytes).hexdigest(), package_ref["sanitized_sha256"]
        )
        package = json.loads(package_bytes)
        self.assertEqual(package["evidence_id"], package_ref["evidence_id"])
        self.assertEqual(package["operation"], "inspect_android_package")
        self.assertEqual(
            package["subject"]["digest"]["sha256"],
            summary["release_artifact"]["sha256"],
        )
        self.assertEqual(package["provider"]["version"], "0.7.1")
        self.assertEqual(package["raw_result"]["loaded"]["class_count"], 1688)
        self.assertEqual(package["raw_result"]["loaded"]["resource_count"], 561)
        self.assertEqual(
            package["normalized_result"]["signature_verification"], "not_performed"
        )

        behavior_ref = summary["runtime_behavior"]["evidence_file"]
        behavior_bytes = (example / behavior_ref).read_bytes()
        self.assertEqual(
            len(behavior_bytes), summary["runtime_behavior"]["report_bytes"]
        )
        self.assertEqual(
            hashlib.sha256(behavior_bytes).hexdigest(),
            summary["runtime_behavior"]["report_sha256"],
        )
        behavior = json.loads(behavior_bytes)
        self.assertEqual(
            behavior["record_type"], "anti_rea_loopweek_flutter_emulator_behavior_check"
        )
        self.assertEqual(behavior["status"], "passed_single_emulator_journey")
        self.assertEqual(
            behavior["device"],
            {"android_version": "16", "api_level": 36, "abi": "arm64-v8a"},
        )
        self.assertEqual(
            behavior["artifact_sha256"], summary["release_artifact"]["sha256"]
        )
        self.assertEqual(len(behavior["steps"]), 4)
        self.assertEqual(
            behavior["screenshot"]["sha256"],
            "7ce8d7180977ca88cdce03f78341c6cd212f17a5f634eab4700a8e3696ccdd40",
        )
        self.assertFalse(behavior["screenshot"]["stored_in_repository"])
        self.assertIn("One emulator journey only", behavior["limitations"][0])
        self.assertIn(
            "No BEFORE/AFTER transformation comparison", behavior["limitations"][1]
        )

        def assert_no_host_paths(value):
            if isinstance(value, dict):
                for item in value.values():
                    assert_no_host_paths(item)
            elif isinstance(value, list):
                for item in value:
                    assert_no_host_paths(item)
            elif isinstance(value, str):
                for prefix in ("/tmp/", "/var/folders/", "/Users/", "/Volumes/"):
                    self.assertNotIn(prefix, value)

        for report in (package, behavior):
            assert_no_host_paths(report)

    def test_loopweek_apk_signature_evidence_is_hash_bound_and_trust_scoped(self):
        example = ROOT / "examples/loopweek-flutter"
        summary = json.loads((example / "evidence-summary.json").read_text())
        ref = summary["operations"]["apk_signature_verification"]["report"]
        payload = (example / ref["file"]).read_bytes()
        self.assertEqual(len(payload), ref["bytes"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), ref["sha256"])
        report = json.loads(payload)
        self.assertEqual(
            report["artifact"]["sha256"], summary["release_artifact"]["sha256"]
        )
        self.assertEqual(report["result"], "Verifies")
        self.assertTrue(report["signature_schemes"]["v2"])
        self.assertEqual(sum(report["signature_schemes"].values()), 1)
        self.assertEqual(len(report["signers"]), 1)
        self.assertEqual(report["signers"][0]["algorithm"], "RSA-2048")
        self.assertFalse(
            summary["operations"]["apk_signature_verification"][
                "publisher_identity_externally_trusted"
            ]
        )
        self.assertIn("not externally trusted", " ".join(report["limitations"]))

    def test_loopweek_local_flutter_baseline_records_real_blockers_without_host_paths(
        self,
    ):
        example = ROOT / "examples/loopweek-flutter"
        published = json.loads((example / "evidence-summary.json").read_text())
        local_ref = published["local_anti_rea_baseline"]
        self.assertEqual(
            local_ref["report"], "evidence/local-anti-rea-baseline-001.json"
        )
        self.assertFalse(local_ref["artifact_stored_in_repository"])
        self.assertFalse(local_ref["protection_claim"])
        summary_path = example / "evidence/local-anti-rea-baseline-001.json"
        summary_bytes = summary_path.read_bytes()
        self.assertEqual(len(summary_bytes), local_ref["report_bytes"])
        self.assertEqual(
            hashlib.sha256(summary_bytes).hexdigest(), local_ref["report_sha256"]
        )
        summary = json.loads(summary_bytes)
        self.assertEqual(
            hashlib.sha256(summary_bytes).hexdigest(), local_ref["report_sha256"]
        )
        self.assertEqual(
            summary["record_type"], "anti_rea_loopweek_local_flutter_baseline"
        )
        baseline = summary["baseline"]
        artifact = baseline["artifact"]
        self.assertEqual(
            artifact["sha256"],
            "9389f711fd6566c0906a38d137d1221801dbcb7e90db26b727aee04b3987b18b",
        )
        self.assertEqual(artifact["size"], 62349581)
        self.assertFalse(artifact["stored_in_repository"])
        self.assertFalse(baseline["lock_matches_source"])
        self.assertEqual(len(baseline["transitive_lock_version_changes"]), 4)

        behavior_ref = published["local_baseline_behavior"]
        behavior_bytes = (example / behavior_ref["evidence_file"]).read_bytes()
        self.assertEqual(len(behavior_bytes), behavior_ref["report_bytes"])
        self.assertEqual(
            hashlib.sha256(behavior_bytes).hexdigest(), behavior_ref["report_sha256"]
        )
        behavior = json.loads(behavior_bytes)
        self.assertEqual(behavior["artifact"]["sha256"], artifact["sha256"])
        self.assertEqual(behavior["status"], "passed_single_emulator_journey")
        self.assertFalse(behavior["protection_claim"])
        self.assertEqual(len(behavior["steps"]), 5)
        self.assertIn(
            "remained visible and checked", behavior["observed_after_relaunch"]
        )
        self.assertEqual(behavior["app_process_log_check"]["matched_errors"], [])
        self.assertFalse(behavior["screenshot"]["stored_in_repository"])
        self.assertEqual(summary["behavior"]["status"], behavior["status"])
        self.assertEqual(
            summary["behavior"]["report_sha256"], behavior_ref["report_sha256"]
        )
        self.assertEqual(summary["behavior"]["report_bytes"], len(behavior_bytes))

        readiness_ref = published["local_aot_planning_readiness"]
        readiness_bytes = (example / readiness_ref["record"]).read_bytes()
        self.assertEqual(len(readiness_bytes), readiness_ref["record_bytes"])
        self.assertEqual(
            hashlib.sha256(readiness_bytes).hexdigest(), readiness_ref["record_sha256"]
        )
        readiness = json.loads(readiness_bytes)
        self.assertEqual(
            readiness["record_type"], "anti_rea_loopweek_flutter_aot_readiness"
        )
        self.assertEqual(readiness["baseline"]["artifact_sha256"], artifact["sha256"])
        self.assertEqual(readiness["inspection"]["status"], "unsupported")
        self.assertEqual(readiness["inspection"]["abi"], "arm64-v8a")
        self.assertEqual(readiness["inspection"]["rea_version"], "6.8.0")
        self.assertEqual(readiness["plan"]["status"], "blocked")
        self.assertEqual(readiness["plan"]["actions"], 0)
        self.assertFalse(readiness["candidate_built"])
        self.assertFalse(readiness["protection_claim"])
        for host_path in ("/private/tmp/", "/Users/", "/Volumes/"):
            self.assertNotIn(host_path, readiness_bytes.decode())
        launch_bytes = (
            example / behavior_ref["launch_smoke_evidence_file"]
        ).read_bytes()
        self.assertEqual(len(launch_bytes), behavior_ref["launch_smoke_report_bytes"])
        self.assertEqual(
            hashlib.sha256(launch_bytes).hexdigest(),
            behavior_ref["launch_smoke_report_sha256"],
        )
        launch = json.loads(launch_bytes)
        self.assertEqual(launch["artifact"]["sha256"], artifact["sha256"])
        self.assertEqual(launch["status"], "passed_install_and_launch")

        for host_path in ("/private/tmp/", "/Users/", "/Volumes/"):
            self.assertNotIn(host_path, behavior_bytes.decode())

        rea = summary["rea"]
        identify = json.loads(
            (
                example / rea["flutter_build_identification"]["report"]["file"]
            ).read_text()
        )
        self.assertEqual(identify["operation"], "identify_flutter_build")
        self.assertEqual(identify["subject"]["digest"]["sha256"], artifact["sha256"])
        self.assertEqual(len(identify["normalized_result"]["abis"]), 3)
        self.assertEqual(identify["normalized_result"]["coverage"], "partial")

        aot = json.loads(
            (example / rea["dart_aot_inspection"]["report"]["file"]).read_text()
        )
        self.assertEqual(aot["status"], "blocked")
        self.assertEqual(aot["error"]["code"], "unsupported_target")
        self.assertEqual(
            aot["error"]["details"]["diagnostics"]["observed_exports"],
            [
                {"name": "_kDartSnapshotText", "offset": 2949120, "size": 3965760},
                {"name": "_kDartSnapshotData", "offset": 704, "size": 2899168},
            ],
        )

        package = json.loads(
            (example / rea["android_package_inspection"]["report"]["file"]).read_text()
        )
        self.assertEqual(package["status"], "blocked")
        self.assertEqual(package["error"]["code"], "capability_unavailable")

        signing = json.loads(
            (
                example
                / summary["independent_apk_signature_verification"]["report"]["file"]
            ).read_text()
        )
        self.assertEqual(signing["artifact"]["sha256"], artifact["sha256"])
        self.assertEqual(signing["result"], "Verifies")
        self.assertEqual(signing["signers"][0]["identity"], "Android Debug")
        self.assertFalse(signing["publisher_identity_externally_trusted"])
        self.assertEqual(summary["candidate"]["status"], "not_built")

        def assert_no_host_paths(value):
            if isinstance(value, dict):
                for item in value.values():
                    assert_no_host_paths(item)
            elif isinstance(value, list):
                for item in value:
                    assert_no_host_paths(item)
            elif isinstance(value, str):
                for prefix in ("/tmp/", "/private/tmp/", "/Users/", "/Volumes/"):
                    self.assertNotIn(prefix, value)

        for path in example.joinpath("evidence").glob("*local-baseline-001*.json"):
            payload = path.read_bytes()
            assert_no_host_paths(json.loads(payload))
        for reference in (
            rea["flutter_build_identification"]["report"],
            rea["dart_aot_inspection"]["report"],
            rea["android_package_inspection"]["report"],
            rea["apk_signature_static_inspection"]["report"],
            summary["independent_apk_signature_verification"]["report"],
        ):
            payload = (example / reference["file"]).read_bytes()
            self.assertEqual(len(payload), reference["bytes"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), reference["sha256"])

    def test_loopweek_clean_source_baseline_refresh_is_hash_bound_and_keeps_artifacts_external(
        self,
    ):
        example = ROOT / "examples/loopweek-flutter"
        published = json.loads((example / "evidence-summary.json").read_text())
        reference = published["local_anti_rea_baseline_refresh"]
        report_bytes = (example / reference["report"]).read_bytes()
        self.assertEqual(len(report_bytes), reference["report_bytes"])
        self.assertEqual(
            hashlib.sha256(report_bytes).hexdigest(), reference["report_sha256"]
        )
        report = json.loads(report_bytes)
        self.assertEqual(
            report["record_type"], "anti_rea_loopweek_clean_source_flutter_baseline"
        )
        self.assertEqual(
            report["source"]["commit"], "f07a75f0875c2b51a953c258c358fbfca957be89"
        )
        self.assertEqual(
            report["source"]["license_sha256"],
            "f447360da327a54e53044a3d956e0ed663c5c816f7781812158f9635913bb6b8",
        )
        self.assertFalse(report["source"]["dirty"])
        self.assertEqual(report["baseline"]["status"], "captured")
        self.assertFalse(report["baseline"]["lock_matches_source"])
        self.assertEqual(len(report["baseline"]["transitive_lock_version_changes"]), 4)
        artifact = report["baseline"]["artifact"]
        self.assertEqual(artifact["sha256"], reference["artifact_sha256"])
        self.assertFalse(artifact["stored_in_repository"])
        aot = report["aot_inspection"]
        self.assertEqual(aot["status"], "unsupported")
        self.assertEqual(aot["artifact_sha256"], artifact["sha256"])
        aot_bytes = (example / aot["report"]).read_bytes()
        self.assertEqual(len(aot_bytes), aot["report_bytes"])
        self.assertEqual(hashlib.sha256(aot_bytes).hexdigest(), aot["report_sha256"])
        aot_report = json.loads(aot_bytes)
        self.assertEqual(aot_report["artifact_sha256"], artifact["sha256"])
        self.assertEqual(aot_report["error"]["category"], "unsupported_target")
        self.assertEqual(
            aot_report["error"]["details"]["diagnostics"]["abi"], "arm64-v8a"
        )
        plan = report["plan"]
        self.assertEqual(plan["status"], "blocked")
        self.assertEqual(plan["action_count"], 0)
        self.assertFalse(plan["candidate_built"])
        candidate_ref = published["upstream_candidate_aot_inspection_refresh"]
        candidate_bytes = (example / candidate_ref["report"]).read_bytes()
        self.assertEqual(len(candidate_bytes), candidate_ref["report_bytes"])
        self.assertEqual(
            hashlib.sha256(candidate_bytes).hexdigest(), candidate_ref["report_sha256"]
        )
        candidate = json.loads(candidate_bytes)
        self.assertEqual(candidate["artifact"]["sha256"], artifact["sha256"])
        self.assertEqual(
            candidate["operation"]["full_report_sha256"],
            candidate_ref["raw_report_sha256"],
        )
        self.assertEqual(candidate["aot"]["libapp"]["coverage"], "complete")
        self.assertEqual(candidate["aot"]["string_pool"]["coverage"], "partial")
        self.assertFalse(candidate["protection_claim"])
        self.assertFalse(candidate["candidate_artifact_built"])
        self.assertEqual(
            candidate["upstream"]["release_status"], "unmerged_upstream_candidate"
        )
        for host_path in ("/private/tmp/", "/Users/", "/Volumes/"):
            self.assertNotIn(host_path.encode(), candidate_bytes)
        package_ref = reference["android_package_inspection"]
        self.assertEqual(package_ref["artifact_sha256"], artifact["sha256"])
        self.assertFalse(package_ref["artifact_stored_in_repository"])
        package_bytes = (example / package_ref["report"]).read_bytes()
        self.assertEqual(len(package_bytes), package_ref["report_bytes"])
        self.assertEqual(
            hashlib.sha256(package_bytes).hexdigest(), package_ref["report_sha256"]
        )
        package = json.loads(package_bytes)
        self.assertEqual(package["evidence_id"], package_ref["evidence_id"])
        self.assertEqual(package["subject"]["digest"]["sha256"], artifact["sha256"])
        self.assertEqual(package["provider"]["version"], "0.7.1")
        self.assertEqual(package["raw_result"]["loaded"]["class_count"], 1695)
        self.assertEqual(package["normalized_result"]["resource_count"], 561)
        self.assertEqual(
            package["normalized_result"]["signature_verification"], "not_performed"
        )
        for host_path in ("/private/tmp/", "/var/folders/", "/Users/", "/Volumes/"):
            self.assertNotIn(host_path.encode(), package_bytes)
        behavior_ref = published["local_baseline_refresh_behavior"]
        behavior_bytes = (example / behavior_ref["evidence_file"]).read_bytes()
        self.assertEqual(len(behavior_bytes), behavior_ref["report_bytes"])
        self.assertEqual(
            hashlib.sha256(behavior_bytes).hexdigest(), behavior_ref["report_sha256"]
        )
        behavior = json.loads(behavior_bytes)
        self.assertEqual(behavior["artifact"]["sha256"], artifact["sha256"])
        self.assertEqual(behavior["status"], "passed_single_emulator_journey")
        self.assertEqual(behavior["app_process_log_check"]["matched_errors"], [])
        self.assertFalse(behavior["protection_claim"])
        for host_path in ("/private/tmp/", "/Users/", "/Volumes/"):
            self.assertNotIn(host_path.encode(), behavior_bytes)
        second_journey_ref = published["local_baseline_refresh_behavior_second_journey"]
        second_journey_bytes = (
            example / second_journey_ref["evidence_file"]
        ).read_bytes()
        self.assertEqual(len(second_journey_bytes), second_journey_ref["report_bytes"])
        self.assertEqual(
            hashlib.sha256(second_journey_bytes).hexdigest(),
            second_journey_ref["report_sha256"],
        )
        second_journey = json.loads(second_journey_bytes)
        self.assertEqual(second_journey["artifact"]["sha256"], artifact["sha256"])
        self.assertEqual(second_journey["status"], "passed_single_emulator_journey")
        self.assertEqual(second_journey["app_process_log_check"]["matched_errors"], [])
        self.assertEqual(
            second_journey["screenshot"]["sha256"],
            "57791919e3b02c626e961af82751891f444bbf6042666570a57c050e644e32e7",
        )
        self.assertFalse(second_journey["protection_claim"])
        for host_path in ("/private/tmp/", "/Users/", "/Volumes/"):
            self.assertNotIn(host_path.encode(), second_journey_bytes)
        signature = report["signature"]
        signature_bytes = (example / signature["report"]).read_bytes()
        self.assertEqual(len(signature_bytes), signature["report_bytes"])
        self.assertEqual(
            hashlib.sha256(signature_bytes).hexdigest(), signature["report_sha256"]
        )
        signature_report = json.loads(signature_bytes)
        self.assertEqual(signature_report["result"], "Verifies")
        self.assertEqual(signature_report["artifact_sha256"], artifact["sha256"])
        self.assertFalse(signature_report["publisher_identity_externally_trusted"])
        for content in (report_bytes, aot_bytes, signature_bytes):
            for host_path in ("/private/tmp/", "/Users/", "/Volumes/"):
                self.assertNotIn(host_path.encode(), content)

    def test_todomvc_targeted_rea_timeout_is_retained_as_incomplete(self):
        example = ROOT / "examples/todomvc-react"
        summary = json.loads((example / "evidence-summary.json").read_text())
        attempt_ref = summary["rea"]["latest_attempt"]
        raw = (example / attempt_ref["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), attempt_ref["sha256"])
        attempt = json.loads(raw)
        self.assertEqual(
            attempt["target"]["artifact_sha256"],
            summary["baseline"]["artifacts"]["dist/app.bundle.js"]["sha256"],
        )
        self.assertEqual(attempt["analysis"]["error_code"], "provider_timeout")
        self.assertFalse(attempt["analysis"]["complete_analysis_report"])
        self.assertEqual(
            attempt["analysis"]["statistics"]["parsed_javascript_files"], 0
        )
        self.assertEqual(
            attempt["analysis"]["statistics"]["skipped_javascript_files"], 1
        )
        self.assertEqual(attempt["analysis"]["statistics"]["findings"], 0)
        self.assertEqual(summary["recommendation"]["candidate_executed"], False)

    def test_todomvc_real_rea_source_report_is_hash_bound_and_scoped(self):
        example = ROOT / "examples/todomvc-react"
        summary = json.loads((example / "evidence-summary.json").read_text())
        report_ref = summary["rea"]["source_analysis"]
        raw = (example / report_ref["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report_ref["sha256"])
        report = json.loads(raw)
        self.assertEqual(report["status"], "passed_with_limited_scope")
        self.assertEqual(report["capture"]["exit_code"], 0)
        self.assertEqual(report["rea_report"]["operation"], "inspect_analysis_view")
        result = report["rea_report"]["normalized_result"]
        stats = result["summary"]["statistics"]
        self.assertEqual(stats["parsed_javascript_files"], 9)
        self.assertEqual(stats["skipped_javascript_files"], 0)
        self.assertEqual(stats["parse_failures"], 0)
        self.assertEqual(stats["findings"], 86)
        self.assertEqual(result["coverage"]["status"], "complete-within-view")
        self.assertEqual(len(report["scope"]["selected_paths"]), 9)
        self.assertEqual(len(report["scope"]["selected_source_sha256"]), 9)
        self.assertIn(
            "generated production bundle dist/app.bundle.js",
            report["scope"]["excluded"].lower(),
        )
        self.assertEqual(summary["recommendation"]["candidate_executed"], False)

    def test_todomvc_terminal_fallback_evidence_binds_cli_baseline_e2e_and_plan(self):
        example = ROOT / "examples/todomvc-react"
        summary = json.loads((example / "evidence-summary.json").read_text())
        evidence_ref = summary["terminal_fallback"]
        raw = (example / evidence_ref["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), evidence_ref["sha256"])
        evidence = json.loads(raw)
        self.assertEqual(evidence["status"], "recommendations_ready_before_choice")
        self.assertFalse(evidence["harness_scope"]["verified_ai_harness"])
        self.assertEqual(evidence["source"]["commit"], summary["source"]["commit"])
        self.assertEqual(
            evidence["environment"]["build_runtime"],
            {"node": "v22.23.3", "npm": "11.17.0"},
        )
        self.assertEqual(evidence["environment"]["browser_runtime"]["node"], "v24.22.1")
        self.assertEqual(
            evidence["inspect"]["target_id"], evidence["baseline"]["target_id"]
        )
        self.assertEqual(
            evidence["baseline"]["id"],
            evidence["recommendation"]["plan"]["baseline_id"],
        )
        self.assertEqual(evidence["browser_behavior"]["status"], "passed")
        report_bytes = (
            example / evidence["browser_behavior"]["report_file"]
        ).read_bytes()
        self.assertEqual(
            hashlib.sha256(report_bytes).hexdigest(),
            evidence["browser_behavior"]["report_sha256"],
        )
        self.assertEqual(json.loads(report_bytes)["run"]["status"], "passed")
        self.assertFalse(evidence["decision"]["recorded"])
        self.assertFalse(evidence["decision"]["candidate_executed"])

    def test_skill_requires_a_requirements_checklist_and_supported_readiness_probe(
        self,
    ):
        skill = (ROOT / "skills/anti-rea/SKILL.md").read_text()
        example = (
            ROOT / "skills/anti-rea/examples/inspect-before-planning.md"
        ).read_text()
        workflow = (ROOT / "skills/anti-rea/references/workflow.md").read_text()
        for content in (skill, example, workflow):
            for required in (
                "requirements checklist",
                "confirmed, missing, or unverified",
                "flutter-android-probe",
                "without accepting licenses or installing tools",
                "unknown",
            ):
                self.assertIn(required, content)
            self.assertNotIn("flutter-android-probe PROJECT", content)
        self.assertIn("does not verify", skill)
        self.assertIn("explicitly reject the plan or choose no actions", skill)
        self.assertIn("Never treat silence or an ambiguous reply as approval", skill)
        self.assertIn("not compatibility", example)
        self.assertIn("does not verify", workflow)

    def test_manual_handoff_covers_commands_evidence_and_boundaries(self):
        guidance = (ROOT / "docs/harness-fallback.md").read_text()
        for required in (
            "anti-rea inspect",
            "anti-rea baseline",
            "anti-rea recommend",
            "anti-rea transition",
            "anti-rea choose",
            "anti-rea start",
            "anti-rea execute-plan",
            "anti-rea accept",
            "anti-rea report",
            "plan SHA-256",
            "does not restore a deployment",
            '"${BUILD[@]}"',
            "verification_id",
            "acceptance outcome",
            "data, not instructions",
            "blocked or unsupported",
        ):
            self.assertIn(required, guidance)

    def test_copy_ready_handoff_preserves_plan_decision_and_acceptance_boundaries(self):
        guidance = (ROOT / "docs/harness-fallback.md").read_text()
        skill = (ROOT / "skills/anti-rea/SKILL.md").read_text()
        start = guidance.index("### Copy-ready handoff")
        end = guidance.index("The handoff is a portable instruction template", start)
        handoff = guidance[start:end]
        for required in (
            "exact baseline BASELINE_ID",
            "plan SHA-256",
            "evidence identities",
            "Wait for me to select action IDs",
            "exact plan hash",
            "required gate is blocked",
            "private candidate",
            "acceptance outcome",
            "not proof of",
            "rollback instructions",
        ):
            self.assertIn(required, handoff)
        self.assertIn("portable handoff template", skill)
        ordered = (
            "anti-rea init-run",
            "anti-rea transition",
            "anti-rea submit-plan",
            "anti-rea choose",
            "anti-rea start",
            "anti-rea execute-plan",
            "anti-rea accept",
        )
        positions = [guidance.index(command) for command in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_portable_skill_links_and_handoff_are_self_contained(self):
        skill_root = ROOT / "skills/anti-rea"
        for source in skill_root.rglob("*.md"):
            for destination in re.findall(r"\[[^\]]+\]\(([^)]+)\)", source.read_text()):
                if destination.startswith(("https://", "http://", "mailto:")):
                    continue
                target = (source.parent / destination.split("#", 1)[0]).resolve()
                self.assertTrue(
                    target.is_relative_to(skill_root.resolve()),
                    f"{source}: {destination}",
                )
                self.assertTrue(target.exists(), f"{source}: {destination}")
        handoff = " ".join(
            (skill_root / "references/harness-fallback.md").read_text().split()
        )
        for required in (
            "plan SHA-256",
            "select action IDs",
            "exact plan hash",
            "blocked",
            "private candidate",
            "acceptance outcome",
            "not acceptance",
            "rollback instructions",
        ):
            self.assertIn(required, handoff)

    def test_private_linux_aarch64_wheel_install_record_is_bound_to_verified_artifacts(
        self,
    ):
        record = json.loads(
            (
                ROOT / "verification/anti-rea-0.1.32-source-linux-aarch64.json"
            ).read_text()
        )
        self.assertEqual(record["artifact_kind"], "private_source_verification_build")
        self.assertFalse(record["official_release_artifact"])
        self.assertEqual(record["platform"], "linux/arm64")
        self.assertEqual(record["python"], "3.11.18")
        self.assertEqual(
            record["wheel_sha256"],
            "72dcef2dc638b271037f70746392f1f4cc8679cd2cf86a0580c06e1e0c051d44",
        )
        self.assertEqual(record["pip_check"], "No broken requirements found.")
        self.assertEqual(record["cli_help_exit_code"], 0)
        self.assertEqual(
            record["example_report_sha256"],
            "c194d6455d509ba722835c0e64a45bab0461d476124474cc4affbb55f22ac644",
        )
        self.assertFalse(record["apk_bundled"])
        self.assertFalse(record["build_output_bundled"])

    def test_current_private_wheel_baseline_smoke_is_hash_bound(self):
        record = json.loads(
            (
                ROOT / "verification/anti-rea-0.1.32-baseline-sandbox-wheel.json"
            ).read_text()
        )
        self.assertFalse(record["official_release_artifact"])
        self.assertEqual(record["python"], "3.11.18")
        self.assertEqual(
            record["install"]["pip_check"], "No broken requirements found."
        )
        self.assertEqual(record["install"]["doctor_status"], "ready")
        self.assertTrue(record["install"]["baseline_adapter_module_imported"])
        self.assertTrue(
            record["installed_baseline_smoke"]["store_and_outputs_outside_repository"]
        )
        self.assertEqual(
            record["installed_baseline_smoke"]["artifact"]["sha256"],
            "4181fdec4b408261f5537dfa30759473e0dbd0773c7e877855b8e6b75b0b0b31",
        )
        self.assertEqual(
            record["installed_baseline_smoke"]["sandbox_image"],
            "node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea",
        )
        self.assertFalse(
            any(
                prefix in json.dumps(record)
                for prefix in ("/Users/", "/Volumes/", "/private/tmp/")
            )
        )

    def test_built_wheel_imports_adapters_and_runs_doctor_after_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel_dir = root / "wheel"
            wheel_dir.mkdir()
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    str(ROOT),
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(wheel_dir),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            wheel = next(wheel_dir.glob("anti_rea-0.1.32-*.whl"))
            environment = root / "venv"
            venv.EnvBuilder(with_pip=True, system_site_packages=True).create(
                environment
            )
            python = environment / (
                "Scripts/python.exe" if os.name == "nt" else "bin/python"
            )
            dependency_paths = [
                str(Path(path).resolve())
                for path in sys.path
                if path and "site-packages" in path and Path(path).resolve() != ROOT
            ]
            runtime_env = os.environ.copy()
            site_packages = environment / (
                "Lib/site-packages"
                if os.name == "nt"
                else f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
            )
            runtime_env["PYTHONPATH"] = os.pathsep.join(
                [str(site_packages), *dependency_paths]
            )
            subprocess.run(
                [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            imported = subprocess.run(
                [
                    str(python),
                    "-c",
                    "from pathlib import Path; import sys; from scripts import rea_integration; "
                    "assert Path(rea_integration.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()); "
                    "assert (rea_integration.ROOT / 'locks/upstreams.json').is_file()",
                ],
                cwd=root,
                env=runtime_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(imported.returncode, 0, imported.stdout + imported.stderr)
            executable = environment / (
                "Scripts/anti-rea.exe" if os.name == "nt" else "bin/anti-rea"
            )
            doctor = subprocess.run(
                [str(executable), "doctor"],
                cwd=root,
                env=runtime_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(doctor.returncode, 0, doctor.stdout + doctor.stderr)
            self.assertEqual(json.loads(doctor.stdout)["status"], "ready")

            image = "node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea"
            docker = shutil.which("docker")
            available = (
                docker
                and subprocess.run(
                    [docker, "image", "inspect", image],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                ).returncode
                == 0
            )
            if available:
                project = root / "project"
                project.mkdir()
                (project / "package.json").write_text(
                    '{"name":"wheel-smoke","version":"1.0.0"}\n'
                )
                result = subprocess.run(
                    [
                        str(executable),
                        "baseline",
                        str(project),
                        "--store",
                        str(root / "state"),
                        "--id",
                        "installed-wheel",
                        "--artifact",
                        "dist.js",
                        "--",
                        "node",
                        "-e",
                        "require('fs').writeFileSync('dist.js','wheel smoke')",
                    ],
                    cwd=root,
                    env=runtime_env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(
                    json.loads(result.stdout)["artifacts"]["dist.js"]["size"], 11
                )
                self.assertFalse((project / "dist.js").exists())

    def test_built_wheel_contains_required_product_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    str(ROOT),
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    directory,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            wheel = next(Path(directory).glob("anti_rea-0.1.32-*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                names = set(archive.namelist())

        expected = {
            "README.md",
            "docs/cli.md",
            "docs/harness-setup.md",
            "docs/harness-fallback.md",
            "docs/harness-compatibility.md",
            "docs/schema-versioning.md",
            "docs/upstream-integrations.md",
            "schemas/workflow-v2.schema.json",
            "schemas/release-manifest-v1.schema.json",
            "skills/anti-rea/SKILL.md",
            "skills/anti-rea/examples/inspect-before-planning.md",
            "skills/anti-rea/references/acceptance.md",
            "skills/anti-rea/references/harness-fallback.md",
            "locks/upstreams.json",
            "locks/rea-capability-readiness.json",
            "locks/pylock.toml",
            "locks/rea-runtime-tool-contracts.json.gz",
            "scripts/bla_integration.py",
            "scripts/e2e_integration.py",
            "scripts/rea_integration.py",
            "docs/release.md",
            "docs/optimization.md",
            "integrations/bla/package-lock.json",
            "integrations/e2e/package-lock.json",
            "integrations/rea/package-lock.json",
            "fixtures/e2e/web/server.cjs",
            "fixtures/e2e/web/app.js",
            "fixtures/e2e/web/e2e.config.mjs",
            "fixtures/e2e/web/tests/behavior.e2e.ts",
            "fixtures/e2e/pwa/server.cjs",
            "fixtures/e2e/pwa/e2e.config.mjs",
            "fixtures/e2e/pwa/tests/behavior.e2e.ts",
            "examples/todomvc-react/README.md",
            "examples/todomvc-react/evidence-summary.json",
            "examples/todomvc-react/evidence/rea-attempt-600s-targeted.json",
            "examples/todomvc-react/evidence/rea-source-report-001.json",
            "examples/todomvc-react/evidence/cli-fallback-workflow.json",
            "examples/todomvc-react/evidence/cli-fallback-e2e-report.json",
            "examples/todomvc-react/e2e.config.mjs",
            "examples/todomvc-react/server.cjs",
            "examples/todomvc-react/tests/behavior.e2e.ts",
            "examples/flutter-todo/README.md",
            "examples/flutter-todo/REA-RESULT.md",
            "examples/flutter-todo/evidence-summary.json",
            "examples/flutter-todo/e2e.config.mjs",
            "examples/flutter-todo/server.cjs",
            "examples/flutter-todo/tests/behavior.e2e.ts",
            "examples/flutter-todo/evidence-summary.json",
            "examples/flutter-todo/evidence/baseline-build-output.json",
            "examples/flutter-todo/evidence/baseline-manifest.sanitized.json",
            "examples/flutter-todo/evidence/browser-e2e.report1.json",
            "examples/flutter-todo/evidence/rea-attempt-result.json",
            "examples/flutter-todo/evidence/rea-attempt-001-full-snapshot.output.json",
            "examples/flutter-todo/evidence/rea-attempt-002-main-dart-js.output.json",
            "examples/flutter-todo/evidence/rea-attempt-002-evidence-bundle.json",
            "examples/flutter-todo/evidence/rea-attempt-003-main-dart-js-timeout.output.json",
            "examples/flutter-todo/evidence/rea-attempt-004-low-semantic-timeout.json",
            "examples/flutter-todo/evidence/rea-attempt-005-unminified-timeout.json",
            "examples/flutter-todo/evidence/rea-bootstrap-report-001.json",
            "examples/codex-cli/evidence-summary.json",
            "examples/codex-cli/evidence/codex-cli-inspect.json",
            "examples/codex-cli/evidence/codex-cli-current.json",
            "examples/codex-cli/evidence/codex-cli-flutter-probe.json",
            "examples/codex-cli/evidence/codex-cli-todomvc-plan-review.json",
            "examples/loopweek-flutter/README.md",
            "examples/loopweek-flutter/evidence-summary.json",
            "examples/loopweek-flutter/evidence/identify-flutter-build-001.json",
            "examples/loopweek-flutter/evidence/inspect-dart-aot-arm64-001.json",
            "examples/loopweek-flutter/evidence/inspect-android-package-001.json",
            "examples/loopweek-flutter/evidence/behavior-check-001.json",
            "examples/loopweek-flutter/evidence/apk-signature-verification-001.json",
            "examples/loopweek-flutter/evidence/local-anti-rea-baseline-001.json",
            "examples/loopweek-flutter/evidence/local-anti-rea-baseline-002.json",
            "examples/loopweek-flutter/evidence/inspect-android-package-local-baseline-002.json",
            "examples/loopweek-flutter/evidence/rea-inspect-dart-aot-local-baseline-002.json",
            "examples/loopweek-flutter/evidence/apksigner-verification-local-baseline-002.json",
            "examples/loopweek-flutter/evidence/local-baseline-emulator-launch-001.json",
            "examples/loopweek-flutter/evidence/local-baseline-emulator-behavior-001.json",
            "examples/loopweek-flutter/evidence/local-baseline-emulator-behavior-002.json",
            "examples/loopweek-flutter/evidence/local-baseline-emulator-behavior-003.json",
            "examples/loopweek-flutter/evidence/local-aot-readiness-blocked-001.json",
            "examples/loopweek-flutter/evidence/rea-pr3662-aot-candidate.json",
            "examples/loopweek-flutter/evidence/rea-pr3662-aot-clean-source-baseline-002.json",
            "examples/loopweek-flutter/evidence/rea-identify-flutter-local-baseline-001.json",
            "examples/loopweek-flutter/evidence/rea-inspect-dart-aot-local-baseline-001.json",
            "examples/loopweek-flutter/evidence/rea-inspect-android-package-local-baseline-001.json",
            "examples/loopweek-flutter/evidence/rea-inspect-apk-signature-local-baseline-001.json",
            "examples/loopweek-flutter/evidence/apksigner-verification-local-baseline-001.json",
        }
        payload_suffix = ".data/data/share/anti-rea/"
        missing = {
            path
            for path in expected
            if not any(name.endswith(payload_suffix + path) for name in names)
        }
        self.assertFalse(
            missing, f"wheel is missing required payload files: {sorted(missing)}"
        )
        self.assertIn("core/release.py", names)
        self.assertIn("core/upstream_review.py", names)
        self.assertIn("core/optimizer.py", names)
        self.assertIn("interfaces/cli/skill_install.py", names)
        self.assertIn("scripts/rea_integration.py", names)


if __name__ == "__main__":
    unittest.main()
