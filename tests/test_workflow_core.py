import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from core import execution
from core import workflow as w


class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.evidence_temp = tempfile.TemporaryDirectory()
        self.target = {
            "schema_version": "2.0",
            "record_type": "target",
            "id": "target-1",
            "components": [{"id": "web", "kind": "static-web"}],
        }
        self.baseline = {
            "schema_version": "2.0",
            "record_type": "baseline",
            "id": "base-1",
            "target_id": "target-1",
            "identity": {"source": "a"},
            "evidence": ["before.json"],
        }
        self.action = {
            "id": "maps",
            "finding_or_asset": "Public source maps",
            "change": "Remove public source maps",
            "mechanism": "Exclude map files from release packaging",
            "engine": "project build",
            "expected_benefit": "Reduce direct source disclosure",
            "tradeoffs": ["Debugging is less convenient"],
            "dependencies": ["No additional dependency"],
            "cost": "No direct cost identified",
            "compatibility": ["Verify production source-map policy"],
            "verification": ["behavior"],
            "limitations": ["Does not prevent runtime inspection"],
            "rollback": "Restore original packaging configuration",
        }
        self.plan = {
            "schema_version": "2.0",
            "record_type": "plan",
            "id": "plan-1",
            "target_id": "target-1",
            "baseline_id": "base-1",
            "actions": [self.action],
            "budgets": {"runtime_ms": 100},
            "rollback": "Restore original artifact",
        }
        self.decision = {
            "schema_version": "2.0",
            "record_type": "decision",
            "id": "decision-1",
            "plan_sha256": w.record_hash(self.plan),
            "selected_action_ids": ["maps"],
            "decision": "approved",
            "decision_source": "user conversation",
        }
        self.run = {
            "schema_version": "2.0",
            "record_type": "run",
            "id": "run-1",
            "target_id": "target-1",
            "baseline_id": "base-1",
            "plan_id": "plan-1",
            "decision_id": "decision-1",
            "state": "awaiting_decision",
        }

    def evidence_ref(self, name="report.json", content=b"owned test evidence"):
        path = Path(self.evidence_temp.name) / name
        path.write_bytes(content)
        return {
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def tearDown(self):
        self.evidence_temp.cleanup()

    def test_baseline_behavior_shape_matches_the_json_schema(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["$defs"]["baseline"])
        behavior = {
            "command": ["node", "{artifact}"],
            "artifact": "app.js",
            "artifact_sha256": "a" * 64,
            "snapshot_path": "/tmp/baseline-base-1-behavior-snapshot",
            "snapshot_source_tree_sha256": "c" * 64,
            "snapshot_tree_sha256": "d" * 64,
            "snapshot_file_scope_sha256": "e" * 64,
            "evidence_path": "/tmp/behavior.json",
            "evidence_sha256": "b" * 64,
        }
        record = {
            **self.baseline,
            "identity": {
                "artifacts": {"app.js": {"size": 1, "sha256": "a" * 64}},
                "behavior": behavior,
            },
            "evidence": ["/tmp/build.json", "/tmp/behavior.json"],
        }
        w.validate_baseline(record)
        self.assertEqual(list(validator.iter_errors(record)), [])
        legacy_behavior = {
            key: value
            for key, value in behavior.items()
            if not key.startswith("snapshot_") and key != "snapshot_path"
        }
        legacy = {
            **record,
            "identity": {
                "artifacts": record["identity"]["artifacts"],
                "behavior": legacy_behavior,
            },
        }
        w.validate_baseline(legacy)
        self.assertEqual(list(validator.iter_errors(legacy)), [])
        malformed = {
            **record,
            "identity": {
                "artifacts": record["identity"]["artifacts"],
                "behavior": {**behavior, "command": ["node", "app.js"]},
            },
        }
        with self.assertRaisesRegex(w.WorkflowError, "Baseline behavior identity"):
            w.validate_baseline(malformed)
        self.assertTrue(list(validator.iter_errors(malformed)))

    def test_build_snapshot_shape_is_additive_for_legacy_baselines(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["$defs"]["baseline"])
        w.validate_baseline(self.baseline)
        record = {
            **self.baseline,
            "identity": {
                **self.baseline["identity"],
                "build_snapshot": {
                    "path": "/tmp/baseline-base-1-build-snapshot",
                    "source_tree_sha256": "a" * 64,
                    "tree_sha256": "b" * 64,
                    "file_scope_sha256": "c" * 64,
                },
            },
        }
        w.validate_baseline(record)
        self.assertEqual(list(validator.iter_errors(record)), [])
        malformed = {
            **record,
            "identity": {**record["identity"], "build_snapshot": {"path": "relative"}},
        }
        with self.assertRaisesRegex(w.WorkflowError, "build snapshot"):
            w.validate_baseline(malformed)

    def test_build_duration_is_optional_nonnegative_milliseconds(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["$defs"]["baseline"])
        record = {**self.baseline, "identity": {"source": "a", "build_duration_ms": 0}}
        w.validate_baseline(record)
        self.assertEqual(list(validator.iter_errors(record)), [])
        malformed = {**record, "identity": {"source": "a", "build_duration_ms": True}}
        with self.assertRaisesRegex(w.WorkflowError, "build duration"):
            w.validate_baseline(malformed)

    def test_directory_artifact_identity_is_validated_in_runtime_and_schema(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["$defs"]["baseline"])
        record = {
            **self.baseline,
            "identity": {
                "artifacts": {
                    "Demo.app": {"kind": "directory", "size": 10, "sha256": "a" * 64}
                }
            },
        }
        w.validate_baseline(record)
        self.assertEqual(list(validator.iter_errors(record)), [])
        malformed = {
            **record,
            "identity": {
                "artifacts": {
                    "Demo.app": {"kind": "directory", "size": -1, "sha256": "a" * 64}
                }
            },
        }
        with self.assertRaisesRegex(w.WorkflowError, "artifact identities"):
            w.validate_baseline(malformed)
        self.assertTrue(list(validator.iter_errors(malformed)))
        malformed_kind = {
            **record,
            "identity": {
                "artifacts": {"Demo.app": {"kind": [], "size": 10, "sha256": "a" * 64}}
            },
        }
        with self.assertRaisesRegex(w.WorkflowError, "artifact identities"):
            w.validate_baseline(malformed_kind)
        self.assertTrue(list(validator.iter_errors(malformed_kind)))

    def test_baseline_e2e_shape_matches_the_json_schema(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["$defs"]["baseline"])
        e2e = {
            "source_path": "app.js",
            "artifact_sha256": "a" * 64,
            "snapshot_path": "/tmp/baseline-base-1-e2e/snapshot",
            "tree_sha256": "b" * 64,
            "file_scope_sha256": "c" * 64,
            "report_path": "/tmp/baseline-base-1-e2e/report.json",
            "report_sha256": "d" * 64,
            "runtime_path": "/tmp/runtime",
            "runtime_manifest_sha256": "e" * 64,
            "runtime_package_lock_sha256": "f" * 64,
            "runner": {"name": "e2e", "version": "0.22.0"},
            "test_ids": ["greeting"],
            "config": "e2e.config.mjs",
            "test_file": "tests/behavior.e2e.ts",
            "cleanup": "loopback app port closed",
        }
        record = {
            **self.baseline,
            "identity": {
                "artifacts": {"app.js": {"size": 1, "sha256": "a" * 64}},
                "e2e_behavior": e2e,
            },
            "evidence": ["/tmp/build.json", "/tmp/baseline-base-1-e2e/report.json"],
        }
        w.validate_baseline(record)
        self.assertEqual(list(validator.iter_errors(record)), [])
        malformed = {
            **record,
            "identity": {
                **record["identity"],
                "e2e_behavior": {**e2e, "report_sha256": "not-a-sha256"},
            },
        }
        with self.assertRaisesRegex(w.WorkflowError, "Baseline e2e identity"):
            w.validate_baseline(malformed)
        self.assertTrue(list(validator.iter_errors(malformed)))

    def test_plan_hash_binds_decision_and_execution(self):
        w.validate_target(self.target)
        w.validate_baseline(self.baseline)
        w.validate_decision(self.decision, self.plan)
        self.assertEqual(
            w.start_execution(self.run, self.plan, self.decision)["state"], "preparing"
        )
        changed = {**self.plan, "budgets": {"runtime_ms": 101}}
        with self.assertRaisesRegex(w.WorkflowError, "hash"):
            w.start_execution(self.run, changed, self.decision)
        second = {**self.action, "id": "maps-two"}
        multi_plan = {**self.plan, "actions": [self.action, second]}
        multi_decision = {
            **self.decision,
            "plan_sha256": w.record_hash(multi_plan),
            "selected_action_ids": ["maps", "maps-two"],
        }
        with self.assertRaisesRegex(w.WorkflowError, "safe BLA JavaScript"):
            w.start_execution(self.run, multi_plan, multi_decision)

    def test_submit_plan_binds_matching_baseline_and_advances_for_review(self):
        run = {
            "schema_version": "2.0",
            "record_type": "run",
            "id": "new-run",
            "target_id": "target-1",
            "state": "baselining",
        }
        next_run = w.submit_plan(run, self.target, self.baseline, self.plan)
        self.assertEqual(
            (next_run["state"], next_run["baseline_id"], next_run["plan_id"]),
            ("awaiting_decision", "base-1", "plan-1"),
        )
        with self.assertRaisesRegex(
            w.WorkflowError, "does not match the discovered target"
        ):
            w.submit_plan(
                {**run, "target_id": "different"}, self.target, self.baseline, self.plan
            )
        with self.assertRaisesRegex(w.WorkflowError, "only be submitted"):
            w.submit_plan(next_run, self.target, self.baseline, self.plan)

    def test_rejected_or_unselected_actions_cannot_execute(self):
        rejected = {**self.decision, "decision": "rejected"}
        with self.assertRaisesRegex(w.WorkflowError, "Rejected"):
            w.start_execution(self.run, self.plan, rejected)
        unknown = {**self.decision, "selected_action_ids": ["other"]}
        with self.assertRaisesRegex(w.WorkflowError, "unapproved"):
            w.start_execution(self.run, self.plan, unknown)

    def test_approved_decision_requires_compatible_composite_actions(self):
        second = {**self.action, "id": "maps-two"}
        plan = {**self.plan, "actions": [self.action, second]}
        decision = {
            **self.decision,
            "plan_sha256": w.record_hash(plan),
            "selected_action_ids": ["maps", "maps-two"],
        }
        with self.assertRaisesRegex(w.WorkflowError, "safe BLA JavaScript"):
            w.validate_decision(decision, plan)
        rejected = {**decision, "decision": "rejected"}
        self.assertEqual(w.validate_decision(rejected, plan)["decision"], "rejected")
        with tempfile.TemporaryDirectory() as directory:
            w.write_record(directory, decision)
            stored = Path(directory) / "decision-invalid.json"
            stored.write_text(json.dumps(decision))
            self.assertEqual(
                w.read_record(stored, "decision")["selected_action_ids"],
                ["maps", "maps-two"],
            )

    def test_plan_rejects_incomplete_recommendation_tradeoffs(self):
        with self.assertRaisesRegex(w.WorkflowError, "scope, mechanism, benefit"):
            w.validate_plan(
                {**self.plan, "actions": [{"id": "maps", "change": "remove maps"}]}
            )

    def test_decision_schema_allows_multi_action_approval(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["$defs"]["decision"])
        second = {**self.action, "id": "maps-two"}
        plan = {**self.plan, "actions": [self.action, second]}
        decision = {
            **self.decision,
            "plan_sha256": w.record_hash(plan),
            "selected_action_ids": ["maps", "maps-two"],
        }
        self.assertEqual(list(validator.iter_errors(decision)), [])

    def test_invalid_transitions_and_incomplete_execution_are_rejected(self):
        with self.assertRaisesRegex(w.WorkflowError, "Invalid run transition"):
            w.transition_run(self.run, "completed", acceptance="accepted")
        with self.assertRaisesRegex(w.WorkflowError, "Invalid run transition"):
            w.transition_run(self.run, [])
        with self.assertRaisesRegex(w.WorkflowError, "baseline and plan"):
            w.validate_run(
                {
                    "schema_version": "2.0",
                    "record_type": "run",
                    "id": "r2",
                    "target_id": "target-1",
                    "state": "executing",
                }
            )
        with self.assertRaisesRegex(w.WorkflowError, "baseline and plan"):
            w.validate_run(
                {
                    "schema_version": "2.0",
                    "record_type": "run",
                    "id": "r3",
                    "target_id": "target-1",
                    "state": "awaiting_decision",
                }
            )
        with self.assertRaisesRegex(w.WorkflowError, "accept_run"):
            w.transition_run(
                {
                    "schema_version": "2.0",
                    "record_type": "run",
                    "id": "r4",
                    "target_id": "target-1",
                    "state": "verifying",
                    "baseline_id": "b1",
                    "plan_id": "p1",
                    "decision_id": "d1",
                },
                "completed",
                acceptance="accepted",
            )
        with self.assertRaisesRegex(w.WorkflowError, "protected or unknown"):
            w.transition_run(self.run, "needs_decision", target_id="other-target")
        with self.assertRaisesRegex(
            w.WorkflowError, "only valid on an evidence-accepted completed run"
        ):
            w.validate_run(
                {
                    "schema_version": "2.0",
                    "record_type": "run",
                    "id": "r5",
                    "target_id": "target-1",
                    "state": "failed",
                    "acceptance": "accepted",
                }
            )
        with self.assertRaisesRegex(w.WorkflowError, "protected or unknown"):
            w.transition_run(self.run, "needs_decision", acceptance="accepted")
        with self.assertRaisesRegex(w.WorkflowError, "accept_run"):
            w.transition_run({**self.run, "state": "verifying"}, "completed")

    def test_completed_run_schema_requires_a_non_null_acceptance_record(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["$defs"]["run"])
        completed = {
            "schema_version": "2.0",
            "record_type": "run",
            "id": "run-completed",
            "target_id": "target-1",
            "state": "completed",
            "baseline_id": "base-1",
            "plan_id": "plan-1",
            "decision_id": "decision-1",
            "execution_id": "execution-1",
            "verification_id": "verification-1",
            "acceptance": "accepted",
            "acceptance_id": None,
        }
        self.assertTrue(list(validator.iter_errors(completed)))
        with self.assertRaisesRegex(w.WorkflowError, "Completed runs require"):
            w.validate_run(completed)
        completed["acceptance_id"] = "acceptance-1"
        self.assertEqual(list(validator.iter_errors(completed)), [])
        self.assertEqual(w.validate_run(completed), completed)

    def test_cancelled_runs_require_a_recorded_reason(self):
        run = {
            "schema_version": "2.0",
            "record_type": "run",
            "id": "run-cancel-check",
            "target_id": "target-cancel-check",
            "state": "discovered",
        }
        cancelled = w.transition_run(run, "cancelled")
        self.assertEqual(cancelled["cancellation_reason"], "user_requested")
        with self.assertRaisesRegex(w.WorkflowError, "cancellation reason"):
            w.validate_run({**cancelled, "cancellation_reason": ""})

    def test_evidence_authentication_rejects_symlinks(self):
        reference = self.evidence_ref("real-report.json")
        link = Path(self.evidence_temp.name) / "linked-report.json"
        link.symlink_to(reference["path"])
        with self.assertRaisesRegex(w.WorkflowError, "missing, linked, or unreadable"):
            w.verify_evidence_file({**reference, "path": str(link)})

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_evidence_authentication_rejects_fifo_without_blocking(self):
        fifo = Path(self.evidence_temp.name) / "evidence.json"
        os.mkfifo(fifo)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from core.workflow import verify_evidence_file; "
                "verify_evidence_file({'path': sys.argv[1], 'sha256': '0' * 64})",
                str(fifo),
            ],
            capture_output=True,
            text=True,
            timeout=2,
            cwd=Path(__file__).parents[1],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Verification evidence must be a regular file", result.stderr)

    def test_candidate_rollback_discards_only_authenticated_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "records").mkdir()
            (root / "runs").mkdir()
            (root / "candidates").mkdir()
            candidate = root / "candidates" / "candidate.js"
            candidate.write_bytes(b"candidate")
            digest = hashlib.sha256(b"candidate").hexdigest()
            run = {
                "schema_version": "2.0",
                "record_type": "run",
                "id": "rollback-run",
                "target_id": "target-1",
                "baseline_id": "base-1",
                "plan_id": "plan-1",
                "decision_id": "decision-1",
                "execution_id": "exec-rollback",
                "verification_id": "verify-rollback",
                "state": "verifying",
            }
            (root / "runs" / "run-rollback-run.json").write_text(json.dumps(run))
            record = {
                "schema_version": "2.0",
                "record_type": "execution",
                "id": "exec-rollback",
                "run_id": "rollback-run",
                "plan_sha256": "a" * 64,
                "commands": [["fixture"]],
                "exit_code": 0,
                "outputs": [{"path": str(candidate), "sha256": digest}],
            }
            w.write_record(root / "records", record)
            result = execution.discard_candidate(root, "rollback-run")
            self.assertEqual(result["status"], "discarded")
            self.assertFalse(candidate.exists())
            self.assertEqual(Path(result["retained_at"]).read_bytes(), b"candidate")
            saved = w.read_record(
                root / "records" / f"rollback-{result['rollback_id']}.json", "rollback"
            )
            self.assertEqual(saved["artifacts"][0]["action"], "quarantined")
            self.assertTrue(
                execution.discard_candidate(root, "rollback-run")["already_discarded"]
            )
            Path(result["retained_at"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(w.WorkflowError, "hash mismatch"):
                execution.discard_candidate(root, "rollback-run")

    def test_candidate_rollback_refuses_changed_or_outside_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "records").mkdir()
            (root / "runs").mkdir()
            (root / "candidates").mkdir()
            candidate = root / "candidates" / "candidate.js"
            candidate.write_bytes(b"changed")
            run = {
                "schema_version": "2.0",
                "record_type": "run",
                "id": "rollback-run",
                "target_id": "target-1",
                "baseline_id": "base-1",
                "plan_id": "plan-1",
                "decision_id": "decision-1",
                "execution_id": "exec-rollback",
                "verification_id": "verify-rollback",
                "state": "verifying",
            }
            (root / "runs" / "run-rollback-run.json").write_text(json.dumps(run))
            record = {
                "schema_version": "2.0",
                "record_type": "execution",
                "id": "exec-rollback",
                "run_id": "rollback-run",
                "plan_sha256": "a" * 64,
                "commands": [["fixture"]],
                "exit_code": 0,
                "outputs": [
                    {
                        "path": str(candidate),
                        "sha256": hashlib.sha256(b"original").hexdigest(),
                    }
                ],
            }
            w.write_record(root / "records", record)
            with self.assertRaisesRegex(w.WorkflowError, "hash mismatch"):
                execution.discard_candidate(root, "rollback-run")
            self.assertTrue(candidate.exists())
            record["outputs"][0]["path"] = str(root / "protected.js")
            w.write_record(
                root / "records",
                {**record, "id": "exec-outside", "run_id": "rollback-other"},
            )
            run.update(id="rollback-other", execution_id="exec-outside")
            (root / "runs" / "run-rollback-other.json").write_text(json.dumps(run))
            with self.assertRaisesRegex(
                w.WorkflowError, "outside the private candidate directory"
            ):
                execution.discard_candidate(root, "rollback-other")

    def test_candidate_rollback_restores_candidate_when_record_persistence_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "records").mkdir()
            (root / "runs").mkdir()
            (root / "candidates").mkdir()
            candidate = root / "candidates" / "candidate.js"
            candidate.write_bytes(b"candidate")
            run = {
                "schema_version": "2.0",
                "record_type": "run",
                "id": "rollback-run",
                "target_id": "target-1",
                "baseline_id": "base-1",
                "plan_id": "plan-1",
                "decision_id": "decision-1",
                "execution_id": "exec-rollback",
                "verification_id": "verify-rollback",
                "state": "verifying",
            }
            (root / "runs" / "run-rollback-run.json").write_text(json.dumps(run))
            record = {
                "schema_version": "2.0",
                "record_type": "execution",
                "id": "exec-rollback",
                "run_id": "rollback-run",
                "plan_sha256": "a" * 64,
                "commands": [["fixture"]],
                "exit_code": 0,
                "outputs": [
                    {
                        "path": str(candidate),
                        "sha256": hashlib.sha256(b"candidate").hexdigest(),
                    }
                ],
            }
            w.write_record(root / "records", record)
            with patch.object(
                w, "write_record", side_effect=OSError("record storage unavailable")
            ):
                with self.assertRaisesRegex(OSError, "record storage unavailable"):
                    execution.discard_candidate(root, "rollback-run")
            self.assertEqual(candidate.read_bytes(), b"candidate")
            self.assertEqual(list((root / "discarded").iterdir()), [])
            self.assertEqual(list((root / "records").glob("rollback-*.json")), [])

    def test_acceptance_requires_bound_records_and_all_checks_pass(self):
        run = {**self.run, "state": "verifying"}
        execution = {
            "schema_version": "2.0",
            "record_type": "execution",
            "id": "exec-1",
            "run_id": "run-1",
            "plan_sha256": w.record_hash(self.plan),
            "action_id": "maps",
            "commands": [["build"]],
            "exit_code": 0,
            "outputs": [{"path": "release.bin", "sha256": "a" * 64}],
        }
        verification = {
            "schema_version": "2.0",
            "record_type": "verification",
            "id": "verify-1",
            "run_id": "run-1",
            "checks": [
                {
                    "id": "behavior",
                    "status": "passed",
                    "evidence": [self.evidence_ref()],
                }
            ],
        }
        acceptance = {
            "schema_version": "2.0",
            "record_type": "acceptance",
            "id": "accept-1",
            "run_id": "run-1",
            "outcome": "accepted",
            "claims": [],
            "claim_ids": ["application_behavior_passed"],
            "reasons": ["All checks passed"],
            "verification_id": "verify-1",
            "execution_id": "exec-1",
            "plan_sha256": w.record_hash(self.plan),
        }
        with self.assertRaisesRegex(w.WorkflowError, "No semantic evidence validator"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                self.plan,
                self.decision,
                execution,
                verification,
                acceptance,
            )
        evidence_path = Path(verification["checks"][0]["evidence"][0]["path"])
        evidence_path.write_bytes(b"tampered evidence")
        with self.assertRaisesRegex(w.WorkflowError, "No semantic evidence validator"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                self.plan,
                self.decision,
                execution,
                verification,
                acceptance,
            )
        with self.assertRaisesRegex(w.WorkflowError, "Every verification check"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                self.plan,
                self.decision,
                execution,
                {
                    **verification,
                    "checks": [
                        {"id": "behavior", "status": "skipped", "evidence": ["not-run"]}
                    ],
                },
                acceptance,
            )
        with self.assertRaisesRegex(w.WorkflowError, "omits checks"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                self.plan,
                self.decision,
                execution,
                {
                    **verification,
                    "checks": [
                        {
                            "id": "other",
                            "status": "passed",
                            "evidence": [self.evidence_ref("other.json")],
                        }
                    ],
                },
                acceptance,
            )
        with self.assertRaisesRegex(w.WorkflowError, "this run"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                self.plan,
                self.decision,
                {**execution, "run_id": "other"},
                verification,
                acceptance,
            )
        with self.assertRaisesRegex(w.WorkflowError, "hash"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                {**self.plan, "budgets": {"runtime_ms": 101}},
                self.decision,
                execution,
                verification,
                acceptance,
            )
        second = {**self.action, "id": "maps-two"}
        multi_plan = {**self.plan, "actions": [self.action, second]}
        multi_decision = {
            **self.decision,
            "plan_sha256": w.record_hash(multi_plan),
            "selected_action_ids": ["maps", "maps-two"],
        }
        multi_execution = {**execution, "plan_sha256": w.record_hash(multi_plan)}
        multi_acceptance = {**acceptance, "plan_sha256": w.record_hash(multi_plan)}
        with self.assertRaisesRegex(w.WorkflowError, "safe BLA JavaScript"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                multi_plan,
                multi_decision,
                multi_execution,
                verification,
                multi_acceptance,
            )

    def test_accepted_record_cannot_add_unbound_free_form_claims(self):
        plan = {
            **self.plan,
            "actions": [{**self.action, "verification": ["application_behavior"]}],
        }
        decision = {**self.decision, "plan_sha256": w.record_hash(plan)}
        run = {**self.run, "state": "verifying"}
        execution = {
            "schema_version": "2.0",
            "record_type": "execution",
            "id": "exec-claims",
            "run_id": "run-1",
            "plan_sha256": w.record_hash(plan),
            "action_id": "maps",
            "commands": [["build"]],
            "exit_code": 0,
            "outputs": [{"path": "release.bin", "sha256": "a" * 64}],
        }
        verification = {
            "schema_version": "2.0",
            "record_type": "verification",
            "id": "verify-claims",
            "run_id": "run-1",
            "checks": [
                {
                    "id": "application_behavior",
                    "status": "passed",
                    "evidence": [self.evidence_ref("claim-report.json")],
                }
            ],
        }
        acceptance = {
            "schema_version": "2.0",
            "record_type": "acceptance",
            "id": "accept-claims",
            "run_id": "run-1",
            "outcome": "accepted",
            "claims": [],
            "claim_ids": ["application_behavior_passed"],
            "reasons": ["behavior check passed"],
            "verification_id": "verify-claims",
            "execution_id": "exec-claims",
            "plan_sha256": w.record_hash(plan),
        }
        with patch.object(w, "_verify_behavior_check"):
            accepted = w.accept_run(
                run,
                self.target,
                self.baseline,
                plan,
                decision,
                execution,
                verification,
                acceptance,
            )
            self.assertEqual(accepted["acceptance"], "accepted")
            with self.assertRaisesRegex(w.WorkflowError, "registered claim_ids"):
                w.accept_run(
                    run,
                    self.target,
                    self.baseline,
                    plan,
                    decision,
                    execution,
                    verification,
                    {**acceptance, "claims": ["the app is fully protected"]},
                )

    def test_rejected_acceptance_finalizes_run_as_blocked_with_bound_evidence(self):
        run = {
            **self.run,
            "state": "verifying",
            "execution_id": "exec-rejected",
            "verification_id": "verify-rejected",
        }
        execution = {
            "schema_version": "2.0",
            "record_type": "execution",
            "id": "exec-rejected",
            "run_id": "run-1",
            "plan_sha256": w.record_hash(self.plan),
            "commands": [["build"]],
            "exit_code": 0,
            "outputs": [{"path": "release.bin", "sha256": "a" * 64}],
        }
        verification = {
            "schema_version": "2.0",
            "record_type": "verification",
            "id": "verify-rejected",
            "run_id": "run-1",
            "checks": [
                {
                    "id": "behavior",
                    "status": "failed",
                    "evidence": ["source and candidate output differ"],
                }
            ],
        }
        rejection = {
            "schema_version": "2.0",
            "record_type": "acceptance",
            "id": "reject-1",
            "run_id": "run-1",
            "outcome": "rejected",
            "claims": [],
            "reasons": ["Behavior check failed"],
            "verification_id": "verify-rejected",
            "execution_id": "exec-rejected",
            "plan_sha256": w.record_hash(self.plan),
        }
        blocked = w.accept_run(
            run,
            self.target,
            self.baseline,
            self.plan,
            self.decision,
            execution,
            verification,
            rejection,
        )
        self.assertEqual(
            (blocked["state"], blocked["acceptance"], blocked["acceptance_id"]),
            ("blocked", "rejected", "reject-1"),
        )
        self.assertEqual(
            (blocked["execution_id"], blocked["verification_id"]),
            ("exec-rejected", "verify-rejected"),
        )
        with self.assertRaisesRegex(w.WorkflowError, "immutable acceptance record"):
            w.validate_run({**blocked, "acceptance_id": None})

    def test_semantic_acceptance_failure_becomes_a_bound_rejection(self):
        run = {
            **self.run,
            "state": "verifying",
            "execution_id": "exec-semantic",
            "verification_id": "verify-semantic",
        }
        execution = {
            "schema_version": "2.0",
            "record_type": "execution",
            "id": "exec-semantic",
            "run_id": "run-1",
            "plan_sha256": w.record_hash(self.plan),
            "action_id": "maps",
            "commands": [["build"]],
            "exit_code": 0,
            "outputs": [{"path": "release.bin", "sha256": "a" * 64}],
        }
        verification = {
            "schema_version": "2.0",
            "record_type": "verification",
            "id": "verify-semantic",
            "run_id": "run-1",
            "checks": [
                {
                    "id": "behavior",
                    "status": "passed",
                    "evidence": [self.evidence_ref("semantic-report.json")],
                },
                {
                    "id": "unsupported_check",
                    "status": "passed",
                    "evidence": [self.evidence_ref("unsupported-report.json")],
                },
            ],
        }
        claimed_acceptance = {
            "schema_version": "2.0",
            "record_type": "acceptance",
            "id": "accept-semantic",
            "run_id": "run-1",
            "outcome": "accepted",
            "claims": [],
            "claim_ids": ["application_behavior_passed"],
            "reasons": ["checks passed"],
            "verification_id": "verify-semantic",
            "execution_id": "exec-semantic",
            "plan_sha256": w.record_hash(self.plan),
        }
        self.assertEqual(
            w.validate_evidence_record(
                {**claimed_acceptance, "claims": ["the app is fully protected"]},
                "acceptance",
            )["claims"],
            ["the app is fully protected"],
        )
        with self.assertRaisesRegex(w.WorkflowError, "registered claim_ids"):
            w.accept_run(
                run,
                self.target,
                self.baseline,
                self.plan,
                self.decision,
                execution,
                {
                    **verification,
                    "checks": [
                        {
                            "id": "behavior",
                            "status": "passed",
                            "evidence": [self.evidence_ref("semantic-report.json")],
                        },
                        {
                            "id": "unsupported_check",
                            "status": "passed",
                            "evidence": [self.evidence_ref("unsupported-report.json")],
                        },
                    ],
                },
                {
                    **claimed_acceptance,
                    "claims": ["the app is fully protected"],
                    "claim_ids": ["application_behavior_passed"],
                },
            )
        blocked, rejection = w.finalize_run(
            run,
            self.target,
            self.baseline,
            self.plan,
            self.decision,
            execution,
            verification,
            claimed_acceptance,
        )
        self.assertEqual(
            (blocked["state"], blocked["acceptance"]), ("blocked", "rejected")
        )
        self.assertIn("unsupported_check", rejection["reasons"][0])

    def test_terminal_state_writer_revalidates_persisted_acceptance_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = root / "records"
            runs = root / "runs"
            for item in (self.target, self.baseline, self.plan):
                w.write_record(records, item)
            run = {
                "schema_version": "2.0",
                "record_type": "run",
                "id": "run-1",
                "target_id": "target-1",
                "state": "discovered",
            }
            w.write_run_state(runs, run, None)
            next_run = w.transition_run(run, "baselining")
            w.write_run_state(runs, next_run, run)
            run = next_run
            next_run = w.transition_run(
                run, "awaiting_decision", baseline_id="base-1", plan_id="plan-1"
            )
            w.write_run_state(runs, next_run, run)
            run = next_run
            w.write_record(records, self.decision)
            bound = w.bind_decision(run, self.plan, self.decision)
            w.write_run_state(runs, bound, run)
            run = bound
            next_run = w.start_execution(run, self.plan, self.decision)
            w.write_run_state(runs, next_run, run)
            run = next_run
            next_run = w.transition_run(run, "executing")
            w.write_run_state(runs, next_run, run)
            run = next_run
            run = w.transition_run(run, "verifying")
            w.write_run_state(runs, run, w.read_record(runs / "run-run-1.json", "run"))
            execution = {
                "schema_version": "2.0",
                "record_type": "execution",
                "id": "exec-1",
                "run_id": "run-1",
                "plan_sha256": w.record_hash(self.plan),
                "action_id": "maps",
                "commands": [["build"]],
                "exit_code": 0,
                "outputs": [{"path": "release.bin", "sha256": "a" * 64}],
            }
            verification = {
                "schema_version": "2.0",
                "record_type": "verification",
                "id": "verify-1",
                "run_id": "run-1",
                "checks": [
                    {
                        "id": "behavior",
                        "status": "passed",
                        "evidence": [self.evidence_ref("terminal-report.json")],
                    }
                ],
            }
            acceptance = {
                "schema_version": "2.0",
                "record_type": "acceptance",
                "id": "accept-1",
                "run_id": "run-1",
                "outcome": "accepted",
                "claims": [],
                "claim_ids": ["application_behavior_passed"],
                "reasons": ["passed"],
                "verification_id": "verify-1",
                "execution_id": "exec-1",
                "plan_sha256": w.record_hash(self.plan),
            }
            for record in (execution, verification, acceptance):
                w.write_record(records, record)
            with self.assertRaisesRegex(
                w.WorkflowError, "No semantic evidence validator"
            ):
                w.accept_run(
                    run,
                    self.target,
                    self.baseline,
                    self.plan,
                    self.decision,
                    execution,
                    verification,
                    acceptance,
                )
            completed = {
                **run,
                "state": "completed",
                "acceptance_id": "accept-1",
                "acceptance": "accepted",
            }
            with self.assertRaisesRegex(w.WorkflowError, "Completion requires"):
                w.write_run_state(
                    runs, {**completed, "acceptance_id": "not-recorded"}, run
                )
            with self.assertRaisesRegex(
                w.WorkflowError, "No semantic evidence validator"
            ):
                w.write_run_state(runs, completed, run)

    def test_records_are_immutable_and_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = w.write_record(directory, self.target)
            self.assertEqual(w.read_record(path, "target"), self.target)
            self.assertEqual(w.write_record(directory, self.target), path)
            with self.assertRaisesRegex(w.WorkflowError, "id collision"):
                w.write_record(
                    directory,
                    {**self.target, "components": [{"id": "web", "kind": "other"}]},
                )

    def test_record_type_cannot_escape_immutable_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "store"
            store.mkdir()
            malicious = {**self.target, "record_type": "../escaped"}
            with self.assertRaisesRegex(w.WorkflowError, "record type"):
                w.write_record(store, malicious)
            self.assertEqual(list(root.glob("escaped-*.json")), [])

    def test_malformed_contract_values_raise_workflow_errors(self):
        with self.assertRaisesRegex(w.WorkflowError, "schema_version 2.0"):
            w.validate_target({**self.target, "schema_version": "1.0"})
        with self.assertRaisesRegex(w.WorkflowError, "evidence references"):
            w.validate_baseline({**self.baseline, "evidence": [1]})
        with self.assertRaisesRegex(w.WorkflowError, "Decision must explicitly"):
            w.validate_decision({**self.decision, "decision": []}, self.plan)
        with self.assertRaisesRegex(w.WorkflowError, "Unknown run state"):
            w.validate_run({**self.run, "state": []})
        with self.assertRaisesRegex(w.WorkflowError, "known status"):
            w.validate_evidence_record(
                {
                    "schema_version": "2.0",
                    "record_type": "verification",
                    "id": "v2",
                    "run_id": "r1",
                    "checks": [{"id": "x", "status": [], "evidence": ["report.json"]}],
                },
                "verification",
            )
        with self.assertRaisesRegex(w.WorkflowError, "known outcome"):
            w.validate_evidence_record(
                {
                    "schema_version": "2.0",
                    "record_type": "acceptance",
                    "id": "a2",
                    "run_id": "r1",
                    "outcome": [],
                    "claims": [],
                    "reasons": [],
                },
                "acceptance",
            )
        with self.assertRaisesRegex(w.WorkflowError, "budgets"):
            w.validate_plan({**self.plan, "budgets": {}})

    def test_run_state_updates_use_compare_and_swap(self):
        run = {
            "schema_version": "2.0",
            "record_type": "run",
            "id": "r1",
            "target_id": "target-1",
            "state": "discovered",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = w.write_run_state(directory, run, None)
            if os.name != "nt":
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            next_run = w.transition_run(run, "baselining")
            w.write_run_state(directory, next_run, run)
            with self.assertRaisesRegex(w.WorkflowError, "record changed"):
                w.write_run_state(directory, next_run, run)
            self.assertEqual(w.read_record(path, "run")["state"], "baselining")

    def test_schema_publishes_all_workflow_record_types(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        self.assertEqual(
            set(schema["$defs"]),
            {
                "target",
                "baseline",
                "plan",
                "decision",
                "run",
                "execution",
                "verification",
                "acceptance",
                "rollback",
                "optimization_search",
                "optimization_search_result",
                "optimization_selection",
            },
        )

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "JSON Schema runtime is installed with MCP dependencies",
    )
    def test_plan_schema_matches_rich_recommendation_validator(self):
        import jsonschema

        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        validator = jsonschema.Draft202012Validator(schema["$defs"]["plan"])
        validator.validate(self.plan)
        incomplete = {**self.plan, "actions": [{"id": "maps", "change": "Remove maps"}]}
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate(incomplete)
        profiled = {
            **self.plan,
            "profile": {
                "name": "low-impact",
                "bla_intensity": "stealth",
                "scope": "BLA JavaScript actions only",
            },
            "actions": [
                {
                    **self.action,
                    "engine": "bla",
                    "execution": {"adapter": "bla-js", "intensity": "stealth"},
                }
            ],
        }
        validator.validate(profiled)
        self.assertEqual(w.validate_plan(profiled), profiled)
        for invalid in (
            {
                **profiled,
                "profile": {**profiled["profile"], "bla_intensity": "maximum"},
            },
            {
                **profiled,
                "actions": [
                    {
                        **profiled["actions"][0],
                        "execution": {"adapter": "bla-js", "intensity": "maximum"},
                    }
                ],
            },
        ):
            with self.subTest(
                profile=invalid["profile"], action=invalid["actions"][0]["execution"]
            ):
                with self.assertRaises(jsonschema.ValidationError):
                    validator.validate(invalid)
                with self.assertRaises(w.WorkflowError):
                    w.validate_plan(invalid)
        custom = {
            **profiled,
            "profile": {
                "name": "custom",
                "bla_intensity": "bankrupt",
                "scope": "BLA JavaScript actions only",
            },
            "actions": [
                {
                    **profiled["actions"][0],
                    "execution": {"adapter": "bla-js", "intensity": "bankrupt"},
                }
            ],
        }
        validator.validate(custom)
        self.assertEqual(w.validate_plan(custom), custom)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "JSON Schema runtime is installed with MCP dependencies",
    )
    def test_all_workflow_record_contract_examples_pass_json_schema(self):
        import jsonschema

        defs = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )["$defs"]
        records = {
            "target": self.target,
            "baseline": self.baseline,
            "plan": self.plan,
            "decision": self.decision,
            "run": self.run,
            "execution": {
                "schema_version": "2.0",
                "record_type": "execution",
                "id": "e1",
                "run_id": "run-1",
                "plan_sha256": w.record_hash(self.plan),
                "commands": [["build", "release"]],
                "exit_code": 0,
                "outputs": [{"path": "release.bin", "sha256": "a" * 64}],
            },
            "verification": {
                "schema_version": "2.0",
                "record_type": "verification",
                "id": "v1",
                "run_id": "run-1",
                "checks": [
                    {
                        "id": "behavior",
                        "status": "passed",
                        "evidence": [{"path": "/tmp/e2e.json", "sha256": "c" * 64}],
                    }
                ],
            },
            "acceptance": {
                "schema_version": "2.0",
                "record_type": "acceptance",
                "id": "a1",
                "run_id": "run-1",
                "outcome": "blocked",
                "claims": [],
                "reasons": ["Fixture only"],
                "verification_id": "v1",
                "execution_id": "e1",
                "plan_sha256": w.record_hash(self.plan),
            },
            "rollback": {
                "schema_version": "2.0",
                "record_type": "rollback",
                "id": "rb1",
                "run_id": "run-1",
                "instructions": ["Restore original artifact"],
                "artifacts": [],
            },
            "optimization_search": {
                "schema_version": "2.0",
                "record_type": "optimization_search",
                "id": "search-1",
                "target_id": "target-1",
                "baseline_id": "base-1",
                "plan_id": "plan-1",
                "baseline_sha256": w.record_hash(self.baseline),
                "source_identity_sha256": w.record_hash(self.baseline["identity"]),
                "plan_sha256": w.record_hash(self.plan),
                "runtime_identities": {},
                "candidate_sets": [
                    {
                        "id": "candidate-1",
                        "action_ids": ["maps"],
                        "estimated_cost_micros": 0,
                        "compatibility_evidence": [],
                    }
                ],
                "budgets": {
                    "max_elapsed_ms": 100,
                    "max_total_elapsed_ms": 200,
                    "max_candidate_bytes": 1000,
                    "max_cost_micros": 0,
                    "cost_currency": "USD",
                },
                "stop_conditions": {
                    "stop_on_first_acceptable": False,
                    "on_budget_exhaustion": "stop",
                },
                "decision_source": "CLI confirmation",
            },
            "optimization_search_result": {
                "schema_version": "2.0",
                "record_type": "optimization_search_result",
                "id": "optresult-1",
                "status": "candidates_available",
                "search_id": "search-1",
                "search_sha256": "a" * 64,
                "budgets": {},
                "candidate_results": [
                    {
                        "candidate_id": "candidate-1",
                        "status": "accepted",
                        "run_id": "run-1",
                    }
                ],
                "accepted_run_ids": {"candidate-1": "run-1"},
                "review": None,
                "total_elapsed_ms": 1,
                "actual_cost_status": "unavailable",
            },
            "optimization_selection": {
                "schema_version": "2.0",
                "record_type": "optimization_selection",
                "id": "selection-1",
                "search_id": "search-1",
                "search_sha256": "a" * 64,
                "runner_result_id": "optresult-1",
                "runner_result_sha256": "c" * 64,
                "candidate_id": "candidate-1",
                "candidate_run_id": "run-1",
                "candidate_runs": {"candidate-1": "run-1"},
                "review_sha256": "b" * 64,
                "decision_source": "CLI selection",
            },
        }
        self.assertEqual(set(records), set(defs))
        for kind, record in records.items():
            with self.subTest(record_type=kind):
                jsonschema.Draft202012Validator(defs[kind]).validate(record)
        accepted_v2 = {
            **records["acceptance"],
            "outcome": "accepted",
            "claims": [{"text": "legacy accepted claim"}],
        }
        jsonschema.Draft202012Validator(defs["acceptance"]).validate(accepted_v2)
        jsonschema.Draft202012Validator(defs["acceptance"]).validate(
            {**accepted_v2, "claims": [], "claim_ids": ["application_behavior_passed"]}
        )
        rejected_decision = {
            **self.decision,
            "decision": "rejected",
            "selected_action_ids": [],
        }
        jsonschema.Draft202012Validator(defs["decision"]).validate(rejected_decision)
        self.assertEqual(
            w.validate_decision(rejected_decision, self.plan), rejected_decision
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(defs["decision"]).validate(
                {**rejected_decision, "decision": "approved"}
            )
        completed = {
            **self.run,
            "state": "completed",
            "acceptance": "accepted",
            "acceptance_id": "accept-1",
        }
        jsonschema.Draft202012Validator(defs["run"]).validate(completed)
        rejected = {
            **self.run,
            "state": "blocked",
            "acceptance": "rejected",
            "acceptance_id": "reject-1",
            "execution_id": "e1",
            "verification_id": "v1",
        }
        jsonschema.Draft202012Validator(defs["run"]).validate(rejected)
        self.assertEqual(w.validate_run(rejected), rejected)
        resumed = {
            **self.run,
            "state": "preparing",
            "decision_id": "decision-1",
            "resume_of": "run-old",
            "resume_identity_sha256": "d" * 64,
        }
        jsonschema.Draft202012Validator(defs["run"]).validate(resumed)
        self.assertEqual(w.validate_run(resumed), resumed)
        cancelled = {
            "schema_version": "2.0",
            "record_type": "run",
            "id": "cancelled-1",
            "target_id": "target-1",
            "state": "cancelled",
            "cancellation_reason": "user_requested",
        }
        jsonschema.Draft202012Validator(defs["run"]).validate(cancelled)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(defs["run"]).validate(
                {**cancelled, "cancellation_reason": ""}
            )
        self.assertEqual(w.validate_run(completed), completed)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "JSON Schema runtime is installed with MCP dependencies",
    )
    def test_malformed_records_rejected_by_schema_and_core(self):
        import jsonschema

        defs = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )["$defs"]
        invalid = {
            "baseline": {**self.baseline, "evidence": [1]},
            "plan": {**self.plan, "budgets": {}},
            "decision": {**self.decision, "decision": []},
            "run": {**self.run, "state": []},
            "run_missing_verification_id": {
                **self.run,
                "state": "verifying",
                "execution_id": "exec-1",
                "baseline_id": "base-1",
                "plan_id": "plan-1",
                "decision_id": "decision-1",
            },
            "run_missing_execution_id": {
                **self.run,
                "state": "verifying",
                "verification_id": "verify-1",
                "baseline_id": "base-1",
                "plan_id": "plan-1",
                "decision_id": "decision-1",
            },
            "completed_run": {
                "schema_version": "2.0",
                "record_type": "run",
                "id": "done-1",
                "target_id": "target-1",
                "baseline_id": "base-1",
                "plan_id": "plan-1",
                "decision_id": "decision-1",
                "acceptance_id": "accept-1",
                "acceptance": "rejected",
                "state": "completed",
            },
            "execution": {
                "schema_version": "2.0",
                "record_type": "execution",
                "id": "e2",
                "run_id": "r1",
                "plan_sha256": "a" * 64,
                "commands": [["build"]],
                "outputs": [{"path": "app.bin", "sha256": "b" * 64}],
            },
            "verification": {
                "schema_version": "2.0",
                "record_type": "verification",
                "id": "v3",
                "run_id": "r1",
                "checks": [{"id": "x", "status": "passed"}],
            },
            "acceptance": {
                "schema_version": "2.0",
                "record_type": "acceptance",
                "id": "a3",
                "run_id": "r1",
                "outcome": "accepted",
                "claims": [1],
                "reasons": [1],
                "verification_id": "v1",
                "execution_id": "e1",
                "plan_sha256": "a" * 64,
            },
        }
        validators = {
            "baseline": w.validate_baseline,
            "plan": w.validate_plan,
            "decision": lambda x: w.validate_decision(x, self.plan),
            "run": w.validate_run,
            "run_missing_verification_id": w.validate_run,
            "run_missing_execution_id": w.validate_run,
            "execution": lambda x: w.validate_evidence_record(x, "execution"),
            "verification": lambda x: w.validate_evidence_record(x, "verification"),
            "acceptance": lambda x: w.validate_evidence_record(x, "acceptance"),
        }
        for kind, record in invalid.items():
            schema_kind = (
                "run" if kind.startswith("run") or kind == "completed_run" else kind
            )
            with self.subTest(record_type=kind):
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.Draft202012Validator(defs[schema_kind]).validate(record)
                with self.assertRaises(w.WorkflowError):
                    validators[schema_kind](record)

    def test_execution_verification_acceptance_and_rollback_record_shapes(self):
        execution = {
            "schema_version": "2.0",
            "record_type": "execution",
            "id": "e1",
            "run_id": "r1",
            "plan_sha256": "a" * 64,
            "commands": [["tool", "--version"]],
            "exit_code": 0,
            "outputs": [{"path": "tool.out", "sha256": "b" * 64}],
        }
        verification = {
            "schema_version": "2.0",
            "record_type": "verification",
            "id": "v1",
            "run_id": "r1",
            "checks": [
                {
                    "id": "behavior",
                    "status": "passed",
                    "evidence": [{"path": "/tmp/report.json", "sha256": "a" * 64}],
                }
            ],
        }
        acceptance = {
            "schema_version": "2.0",
            "record_type": "acceptance",
            "id": "a1",
            "run_id": "r1",
            "outcome": "blocked",
            "claims": [],
            "reasons": ["No app evidence"],
            "verification_id": "v1",
            "execution_id": "e1",
            "plan_sha256": "a" * 64,
        }
        rollback = {
            "schema_version": "2.0",
            "record_type": "rollback",
            "id": "b1",
            "run_id": "r1",
            "instructions": ["Restore baseline artifact"],
            "artifacts": [],
        }
        for record in (execution, verification, acceptance, rollback):
            kind = record["record_type"]
            self.assertEqual(w.validate_evidence_record(record, kind), record)
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(
                    w.read_record(w.write_record(directory, record), kind), record
                )
        with self.assertRaisesRegex(w.WorkflowError, "known status"):
            w.validate_evidence_record(
                {
                    **verification,
                    "checks": [
                        {"id": "x", "status": "maybe", "evidence": ["report.json"]}
                    ],
                },
                "verification",
            )
        failed = {
            **verification,
            "checks": [
                {
                    "id": "performance",
                    "status": "failed",
                    "evidence": [{"path": "/tmp/measurement.json", "sha256": "b" * 64}],
                }
            ],
        }
        self.assertEqual(w.validate_evidence_record(failed, "verification"), failed)
        with self.assertRaisesRegex(w.WorkflowError, "evidence references"):
            w.validate_evidence_record(
                {
                    **verification,
                    "checks": [
                        {
                            "id": "passed",
                            "status": "passed",
                            "evidence": ["unhashed report"],
                        }
                    ],
                },
                "verification",
            )

    def test_schema_rejects_invalid_reference_ids_like_runtime_validators(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        cases = [
            ("baseline", {**self.baseline, "target_id": "bad id"}),
            ("plan", {**self.plan, "target_id": "bad id"}),
            ("plan", {**self.plan, "baseline_id": "bad id"}),
            ("run", {**self.run, "target_id": "bad id"}),
            ("run", {**self.run, "baseline_id": "bad id"}),
            ("run", {**self.run, "plan_id": "bad id"}),
            ("run", {**self.run, "decision_id": "bad id"}),
        ]
        for kind, record in cases:
            with self.subTest(kind=kind, record=record):
                self.assertFalse(
                    Draft202012Validator(schema["$defs"][kind]).is_valid(record)
                )

    def test_record_reader_rejects_symlink_and_nonstandard_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual.json"
            actual.write_text('{"x": 1}')
            link = root / "link.json"
            link.symlink_to(actual)
            with self.assertRaises(OSError):
                w.read_json(link)
            with patch.object(w.os, "O_NOFOLLOW", 0):
                with self.assertRaisesRegex(
                    w.WorkflowError, "no-follow JSON reads are unavailable"
                ):
                    w.read_json(actual)
            actual.write_text('{"x": NaN}')
            with self.assertRaisesRegex(w.WorkflowError, "Invalid JSON number"):
                w.read_json(actual)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_record_reader_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "record.json"
            os.mkfifo(fifo)
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from core.workflow import read_json; read_json(sys.argv[1])",
                    str(fifo),
                ],
                capture_output=True,
                text=True,
                timeout=2,
                cwd=Path(__file__).parents[1],
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Workflow record must be a regular file", result.stderr)

    def test_cli_auto_rejects_unverified_passed_check_labels_and_quarantines_candidate(
        self,
    ):
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "state"
            store.mkdir()
            run_path = store / "runs" / "run-r1.json"

            def invoke(*args):
                return subprocess.run(
                    [sys.executable, str(cli), *map(str, args)],
                    capture_output=True,
                    text=True,
                )

            target = {
                "schema_version": "2.0",
                "record_type": "target",
                "id": "target-1",
                "components": [{"id": "app", "kind": "fixture"}],
            }
            target_path = Path(directory) / "target.json"
            target_path.write_text(json.dumps(target))
            result = invoke("record-target", target_path, store)
            self.assertEqual(result.returncode, 0, result.stdout)
            result = invoke("init-run", "target-1", "r1", store)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = invoke("transition", run_path, "baselining", store)
            self.assertEqual(result.returncode, 0, result.stdout)
            baseline = {
                "schema_version": "2.0",
                "record_type": "baseline",
                "id": "b1",
                "target_id": "target-1",
                "identity": {"source": "a"},
                "evidence": ["before.json"],
            }
            baseline_path = Path(directory) / "baseline.json"
            baseline_path.write_text(json.dumps(baseline))
            result = invoke("record-baseline", baseline_path, store)
            self.assertEqual(result.returncode, 0, result.stdout)
            action = {
                **self.action,
                "id": "a1",
                "finding_or_asset": "Private maps",
                "change": "Remove private maps",
            }
            plan = {
                "schema_version": "2.0",
                "record_type": "plan",
                "id": "p1",
                "target_id": "target-1",
                "baseline_id": "b1",
                "actions": [action],
                "budgets": {"runtime_ms": 10},
                "rollback": "Restore source",
            }
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(json.dumps(plan))
            result = invoke("record-plan", plan_path, store)
            self.assertEqual(result.returncode, 0, result.stdout)
            updates = Path(directory) / "updates.json"
            updates.write_text(json.dumps({"baseline_id": "b1", "plan_id": "p1"}))
            result = invoke(
                "transition", run_path, "awaiting_decision", store, "--updates", updates
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            decision = {
                "schema_version": "2.0",
                "record_type": "decision",
                "id": "d1",
                "plan_sha256": w.record_hash(plan),
                "selected_action_ids": ["a1"],
                "decision": "approved",
                "decision_source": "test client",
            }
            decision_path = Path(directory) / "decision.json"
            decision_path.write_text(json.dumps(decision))
            result = invoke("record-decision", run_path, decision_path, store)
            self.assertEqual(result.returncode, 0, result.stdout)
            result = invoke("start", run_path, store)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(w.read_record(run_path, "run")["state"], "preparing")
            result = invoke("transition", run_path, "executing", store)
            self.assertEqual(result.returncode, 0, result.stdout)
            result = invoke("transition", run_path, "verifying", store)
            self.assertEqual(result.returncode, 0, result.stdout)
            candidates = store / "candidates"
            candidates.mkdir()
            candidate = candidates / "candidate.js"
            candidate.write_bytes(b"candidate")
            execution = {
                "schema_version": "2.0",
                "record_type": "execution",
                "id": "e1",
                "run_id": "r1",
                "plan_sha256": w.record_hash(plan),
                "action_id": "a1",
                "commands": [["fixture"]],
                "exit_code": 0,
                "outputs": [
                    {
                        "path": str(candidate),
                        "sha256": hashlib.sha256(b"candidate").hexdigest(),
                    }
                ],
            }
            execution_path = Path(directory) / "execution.json"
            execution_path.write_text(json.dumps(execution))
            result = invoke("record-evidence", "execution", execution_path, store)
            self.assertEqual(result.returncode, 0, result.stdout)
            verification = {
                "schema_version": "2.0",
                "record_type": "verification",
                "id": "v1",
                "run_id": "r1",
                "checks": [
                    {
                        "id": "behavior",
                        "status": "passed",
                        "evidence": [self.evidence_ref("cli-report.json")],
                    }
                ],
            }
            acceptance = {
                "schema_version": "2.0",
                "record_type": "acceptance",
                "id": "a1",
                "run_id": "r1",
                "outcome": "accepted",
                "claims": [],
                "claim_ids": ["application_behavior_passed"],
                "reasons": ["passed"],
                "verification_id": "v1",
                "execution_id": "e1",
                "plan_sha256": w.record_hash(plan),
            }
            verification_path = Path(directory) / "verification.json"
            verification_path.write_text(json.dumps(verification))
            acceptance_path = Path(directory) / "acceptance.json"
            acceptance_path.write_text(json.dumps(acceptance))
            result = invoke(
                "accept",
                run_path,
                store,
                "--execution",
                execution_path,
                "--verification",
                verification_path,
                "--acceptance",
                acceptance_path,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(json.loads(result.stdout)["status"], "rejected")
            rejected = w.read_record(run_path, "run")
            self.assertEqual(
                (rejected["state"], rejected["acceptance"]), ("blocked", "rejected")
            )
            self.assertFalse(candidate.exists())
            rollback = w.read_record(
                next((store / "records").glob("rollback-*.json")), "rollback"
            )
            self.assertEqual(
                Path(rollback["artifacts"][0]["retained_path"]).read_bytes(),
                b"candidate",
            )

    def test_cli_submit_plan_moves_matching_run_to_decision_checkpoint(self):
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "state"
            store.mkdir()
            target = {
                "schema_version": "2.0",
                "record_type": "target",
                "id": "target-cli",
                "components": [{"id": "web", "kind": "fixture"}],
            }
            baseline = {
                "schema_version": "2.0",
                "record_type": "baseline",
                "id": "base-cli",
                "target_id": "target-cli",
                "identity": {"source": "fixture"},
                "evidence": ["before.json"],
            }
            review_action = {
                **self.action,
                "expected_benefit": "review\x1b[2J carefully",
                "execution": {
                    "adapter": "bla-js",
                    "source_path": "dist/app.js",
                    "intensity": "stealth",
                    "performance_budget": {
                        "trials": 3,
                        "max_elapsed_ms": 30000,
                        "max_candidate_bytes": 67108864,
                    },
                },
            }
            plan = {
                "schema_version": "2.0",
                "record_type": "plan",
                "id": "plan-cli",
                "target_id": "target-cli",
                "baseline_id": "base-cli",
                "actions": [review_action],
                "profile": {
                    "name": "low-impact",
                    "bla_intensity": "stealth",
                    "scope": "BLA JavaScript actions only",
                },
                "budgets": {"runtime_ms": 100},
                "rollback": "discard",
            }
            for record in (target, baseline):
                w.write_record(store / "records", record)
            run = {
                "schema_version": "2.0",
                "record_type": "run",
                "id": "run-cli",
                "target_id": "target-cli",
                "state": "discovered",
            }
            run_path = w.write_run_state(store / "runs", run, None)
            baselining = w.transition_run(run, "baselining")
            w.write_run_state(store / "runs", baselining, run)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan))
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "submit-plan",
                    str(run_path),
                    str(plan_path),
                    str(store),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "awaiting_decision")
            persisted = w.read_record(run_path, "run")
            self.assertEqual(persisted["plan_id"], "plan-cli")
            decision = {
                "schema_version": "2.0",
                "record_type": "decision",
                "id": "decision-cli",
                "plan_sha256": w.record_hash(plan),
                "selected_action_ids": [self.action["id"]],
                "decision": "approved",
                "decision_source": "explicit CLI test choice",
            }
            decision_path = root / "decision.json"
            decision_path.write_text(json.dumps(decision))
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "record-decision",
                    str(run_path),
                    str(decision_path),
                    str(store),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                w.read_record(run_path, "run")["decision_id"], "decision-cli"
            )

            interactive = {**run, "id": "run-interactive"}
            interactive_path = w.write_run_state(store / "runs", interactive, None)
            interactive_baseline = w.transition_run(interactive, "baselining")
            w.write_run_state(store / "runs", interactive_baseline, interactive)
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "submit-plan",
                    str(interactive_path),
                    str(plan_path),
                    str(store),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "choose",
                    "run-interactive",
                    str(store),
                    "--decision-id",
                    "decision-interactive",
                ],
                input=f"{self.action['id']}\ny\n",
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(r"review\u001b[2J carefully", result.stdout)
            self.assertIn(
                "Starting profile: low-impact; BLA intensity: stealth", result.stdout
            )
            self.assertIn('"source_path":"dist/app.js"', result.stdout)
            self.assertIn('"max_elapsed_ms":30000', result.stdout)
            self.assertNotIn("\x1b", result.stdout)
            saved = w.read_record(
                store / "records" / "decision-decision-interactive.json", "decision"
            )
            self.assertEqual(
                (saved["decision"], saved["plan_sha256"], saved["selected_action_ids"]),
                ("approved", w.record_hash(plan), [self.action["id"]]),
            )
            abandoned = {**run, "id": "run-abandoned"}
            abandoned_path = w.write_run_state(store / "runs", abandoned, None)
            abandoned_baselining = w.transition_run(abandoned, "baselining")
            w.write_run_state(store / "runs", abandoned_baselining, abandoned)
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "submit-plan",
                    str(abandoned_path),
                    str(plan_path),
                    str(store),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(
                [sys.executable, str(cli), "choose", "run-abandoned", str(store)],
                input="",
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 130)
            self.assertEqual(
                w.read_record(abandoned_path, "run")["state"], "awaiting_decision"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "choose",
                    "run-abandoned",
                    str(store),
                    "--decision-id",
                    "decision-reject",
                ],
                input="\n",
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rejected = w.read_record(
                store / "records" / "decision-decision-reject.json", "decision"
            )
            self.assertEqual(
                (rejected["decision"], rejected["selected_action_ids"]),
                ("rejected", []),
            )


if __name__ == "__main__":
    unittest.main()
