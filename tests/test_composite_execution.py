import copy
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import baseline, execution, optimizer, recommendations, workflow
from interfaces.cli import anti_rea


@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class CompositeExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._sandbox_env = patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
        cls._sandbox_env.start()

    @classmethod
    def tearDownClass(cls):
        cls._sandbox_env.stop()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        project = self.root / "project"
        project.mkdir()
        (project / "build.py").write_text(
            "from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\n"
            "Path('dist/app.js').write_text('source-app')\n")
        self.store = self.root / "store"
        self.baseline, _ = baseline.capture(project, self.store, [sys.executable, "build.py"],
                                            ["dist/app.js"], "composite-baseline")
        records = self.store / "records"
        self.target = workflow.read_record(records / f"target-{self.baseline['target_id']}.json", "target")
        self.plan = recommendations.create_plan(self.target, self.baseline, "composite-plan")
        self.action = next(item for item in self.plan["actions"]
                           if item.get("execution", {}).get("adapter") == "bla-js")
        self.action["verification"] = ["bla_invariants"]
        self.action["execution"].pop("performance_budget", None)
        workflow.write_record(records, self.plan)
        self.saved_plan = copy.deepcopy(self.plan)
        self.second = copy.deepcopy(self.action)
        self.second["id"] = "js-second"
        self.second["execution"]["source_path"] = "dist/second.js"
        self.plan["actions"].append(self.second)

    def test_composite_action_order_must_match_saved_plan(self):
        ordered = workflow._validate_composite_actions(
            self.plan, [self.action["id"], self.second["id"]])
        self.assertEqual([item["id"] for item in ordered], [self.action["id"], self.second["id"]])
        with self.assertRaisesRegex(workflow.WorkflowError, "saved plan order"):
            workflow._validate_composite_actions(self.plan, [self.second["id"], self.action["id"]])

    def test_composite_rejects_duplicate_overlapping_mixed_and_incompatible_actions(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "unique and in saved plan order"):
            workflow._validate_composite_actions(self.plan, [self.action["id"], self.action["id"]])

        overlapping = copy.deepcopy(self.second)
        overlapping["execution"]["source_path"] = "dist/app.js/child.js"
        self.plan["actions"][1] = overlapping
        with self.assertRaisesRegex(workflow.WorkflowError, "non-overlapping"):
            workflow._validate_composite_actions(self.plan, [self.action["id"], overlapping["id"]])

        mixed = copy.deepcopy(self.second)
        mixed["execution"]["adapter"] = "source-map-candidate"
        self.plan["actions"][1] = mixed
        with self.assertRaisesRegex(workflow.WorkflowError, "only safe BLA JavaScript"):
            workflow._validate_composite_actions(self.plan, [self.action["id"], mixed["id"]])

        incompatible = copy.deepcopy(self.second)
        incompatible["execution"]["e2e_config"] = "different.config.mjs"
        self.plan["actions"][1] = incompatible
        with self.assertRaisesRegex(workflow.WorkflowError, "compatible behavior and e2e"):
            workflow._validate_composite_actions(self.plan, [self.action["id"], incompatible["id"]])

    def test_single_candidate_preflight_remains_available_to_existing_executor(self):
        search = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "optimization_search",
                  "id": "single-search", "target_id": self.target["id"], "baseline_id": self.baseline["id"],
                  "baseline_sha256": workflow.record_hash(self.baseline),
                  "source_identity_sha256": workflow.record_hash(self.baseline["identity"]),
                  "plan_id": self.saved_plan["id"], "plan_sha256": workflow.record_hash(self.saved_plan),
                  "runtime_identities": {"bla-agents": "b" * 64},
                  "candidate_sets": [{"id": "single-candidate", "action_ids": [self.action["id"]],
                                      "estimated_cost_micros": 0, "compatibility_evidence": []}],
                  "budgets": {"max_elapsed_ms": 1000, "max_total_elapsed_ms": 3000,
                              "max_candidate_bytes": 1000, "max_cost_micros": 0, "cost_currency": "USD"},
                  "stop_conditions": {"stop_on_first_acceptable": False, "on_budget_exhaustion": "stop"}}
        search["decision_source"] = "test approval"
        workflow.write_record(self.store / "records", search)
        result = execution.validate_approved_candidate_set(self.store, search["id"], "single-candidate")
        self.assertEqual(result["candidate"]["action_ids"], [self.action["id"]])
        self.assertEqual(result["actions"], [self.action])

    def test_composite_snapshot_captures_final_composed_tree(self):
        baseline_root = Path(self.baseline["identity"]["build_snapshot"]["path"])
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            candidate = temporary / "candidate"
            shutil.copytree(baseline_root, candidate)
            (candidate / "dist/app.js").write_bytes(b"final composed output")
            before, after = temporary / "nested" / "before", temporary / "nested" / "after"
            identity = execution._create_composite_snapshots(
                baseline_root, self.baseline, candidate, before, after)
            self.assertEqual((after / "dist/app.js").read_bytes(), b"final composed output")
            self.assertNotEqual(identity["before_tree_sha256"], identity["after_tree_sha256"])
            self.assertEqual(identity["file_scope_sha256"],
                             execution._snapshot_tree_identity(after)["file_scope_sha256"])

    def test_composite_nested_evidence_replays_from_authenticated_quarantine(self):
        root = self.root / "rollback-store"
        for name in ("candidates", "discarded", "evidence", "records"):
            (root / name).mkdir(parents=True, exist_ok=True)
        candidate = root / "candidates" / "composite-run"
        nested = candidate / "dist" / "app.js"
        nested.parent.mkdir(parents=True)
        nested.write_bytes(b"composite output")
        file_hash = hashlib.sha256(nested.read_bytes()).hexdigest()
        tree = execution._snapshot_tree_identity(candidate)
        manifest = root / "evidence" / "manifest.json"
        manifest.write_text("{}")
        execution_record = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "execution",
            "id": "composite-execution", "run_id": "composite-run",
            "plan_sha256": "a" * 64, "commands": [["fixture"]], "exit_code": 0,
            "outputs": [{"path": str(manifest), "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}],
            "candidate_tree": {"path": str(candidate), "tree_sha256": tree["tree_sha256"],
                "file_scope_sha256": tree["file_scope_sha256"]}}
        workflow.write_record(root / "records", execution_record)
        rollback_id = "rollback-" + hashlib.sha256(
            f"composite-run:{execution_record['id']}".encode()).hexdigest()[:24]
        retained = root / "discarded" / rollback_id
        candidate.rename(retained)
        workflow.write_record(root / "records", {"schema_version": workflow.SCHEMA_VERSION,
            "record_type": "rollback", "id": rollback_id, "run_id": "composite-run",
            "instructions": ["Candidate retained for replay test."], "artifacts": [{
                "path": str(candidate), "retained_path": str(retained), "kind": "tree",
                "sha256": tree["tree_sha256"], "file_scope_sha256": tree["file_scope_sha256"],
                "action": "quarantined"}]})
        reference = {"path": str(nested), "sha256": file_hash}
        self.assertEqual(workflow.verify_evidence_file(reference, execution_record), b"composite output")
        with self.assertRaisesRegex(workflow.WorkflowError, "missing, linked, or unreadable"):
            workflow.verify_evidence_file(reference)

    def test_composite_accepted_report_replays_after_candidate_rollback(self):
        project = self.root / "composite-project"
        project.mkdir()
        (project / "build.py").write_text(
            "from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\n"
            "Path('dist/a.js').write_text('source-a')\nPath('dist/b.js').write_text('source-b')\n")
        store = self.root / "composite-state"
        captured, _ = baseline.capture(project, store, [sys.executable, "build.py"],
                                       ["dist/a.js", "dist/b.js"], "composite-replay-baseline")
        records = store / "records"
        target = workflow.read_record(records / f"target-{captured['target_id']}.json", "target")
        plan = recommendations.create_plan(target, captured, "composite-replay-plan")
        actions = [item for item in plan["actions"] if item.get("execution", {}).get("adapter") == "bla-js"]
        self.assertEqual(len(actions), 2)
        for action in actions:
            action["verification"] = ["bla_invariants"]
            action["execution"].pop("performance_budget", None)
        workflow.write_record(records, plan)
        action_ids = [item["id"] for item in actions]
        runtime_hash = "b" * 64
        run_id = "composite-replay-run"
        run = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "run", "id": run_id,
               "target_id": target["id"], "state": "discovered"}
        run_path = workflow.write_run_state(store / "runs", run, None)
        baselining = workflow.transition_run(run, "baselining")
        workflow.write_run_state(run_path.parent, baselining, run)
        awaiting = workflow.submit_plan(baselining, target, captured, plan)
        workflow.write_run_state(run_path.parent, awaiting, baselining)
        with patch("builtins.input", side_effect=[",".join(action_ids), "yes"]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(anti_rea.main(["choose", run_id, str(store),
                "--decision-id", "composite-replay-decision"]), 0)
        decision = workflow.read_record(records / "decision-composite-replay-decision.json", "decision")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(anti_rea.main(["start", str(run_path), str(store)]), 0)
        fake_runtime = self.root / "fixture-runtime"
        fake_runtime.mkdir()

        def invoke(_adapter, argv, *_args, **_kwargs):
            if argv[0] == "probe":
                return {"package_tree_sha256": runtime_hash, "version": "1.2.3"}
            source, output_path, report_path = map(Path, argv[2:5])
            source_bytes = source.read_bytes()
            source_hash = hashlib.sha256(source_bytes).hexdigest()
            if argv[0] == "protect-js":
                output_path.write_bytes(b"protected:" + source_bytes)
                candidate_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()
                report = {"command": ["/fixture/bla", "protect", str(source), "--output",
                                       str(output_path), "--json"],
                    "source_sha256": source_hash, "candidate_sha256": candidate_hash}
                elapsed = 1
            else:
                candidate_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()
                report = {"command": ["/fixture/bla", "verify", str(output_path), str(source), "--json"],
                    "candidate_sha256": candidate_hash,
                    "returncode": 0, "stdout": json.dumps({"targetPath": str(output_path),
                    "originalPath": str(source), "overallPassed": True,
                    "functionalIntegrityVerified": True, "checks": [{"passed": True}]}),
                    "runtime_manifest": {"npm_version": "1.2.3", "package_tree_sha256": runtime_hash}}
                elapsed = 1
            report_path.write_text(json.dumps(report))
            return {"source_sha256": source_hash, "candidate_sha256": candidate_hash,
                "candidate_bytes": output_path.stat().st_size, "elapsed_ms": elapsed,
                "report": {"path": str(report_path),
                    "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest()}}

        with patch.object(execution, "_invoke", side_effect=invoke):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(anti_rea.main(["execute-plan", run_id, action_ids[0], str(store),
                    "--bla-runtime", str(fake_runtime)]), 0)
            run_state = workflow.read_record(run_path, "run")
            result = {"status": run_state["state"], "execution_id": run_state.get("execution_id"),
                      "verification_id": run_state.get("verification_id")}
        self.assertEqual(result["status"], "verifying")
        executed = workflow.read_record(records / f"execution-{result['execution_id']}.json", "execution")
        self.assertTrue(any(command[1] == "protect" for command in executed["commands"]))
        self.assertTrue(any(command[1] == "verify" for command in executed["commands"]))
        verification = workflow.read_record(records / f"verification-{result['verification_id']}.json", "verification")
        acceptance = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "acceptance",
            "id": "composite-replay-acceptance", "run_id": run_id, "outcome": "accepted",
            "claims": [], "claim_ids": ["bla_invariants_passed"], "reasons": ["Fixture accepted"],
            "verification_id": verification["id"], "execution_id": executed["id"],
            "plan_sha256": workflow.record_hash(plan)}
        workflow.write_record(records, acceptance)
        verifying = workflow.read_record(run_path, "run")
        terminal = workflow.accept_run(verifying, target, captured, plan, decision, executed,
                                       verification, acceptance)
        workflow.write_run_state(run_path.parent, terminal, verifying)
        rollback = execution.discard_candidate(store, run_id)
        self.assertEqual(workflow.assemble_run_report(records, terminal)["status"], "ok")
        retained = Path(rollback["retained_at"])
        (retained / "dist" / "a.js").write_text("tampered")
        with self.assertRaisesRegex(workflow.WorkflowError, "Retained rollback tree hash mismatch"):
            workflow.assemble_run_report(records, terminal)

        retry_id = "composite-cancelled-run"
        retry = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "run", "id": retry_id,
                 "target_id": target["id"], "state": "discovered"}
        retry_path = workflow.write_run_state(store / "runs", retry, None)
        baselining = workflow.transition_run(retry, "baselining")
        workflow.write_run_state(retry_path.parent, baselining, retry)
        awaiting = workflow.submit_plan(baselining, target, captured, plan)
        workflow.write_run_state(retry_path.parent, awaiting, baselining)
        bound = workflow.bind_decision(awaiting, plan, decision)
        workflow.write_run_state(retry_path.parent, bound, awaiting)
        preparing = workflow.start_execution(bound, plan, decision)
        workflow.write_run_state(retry_path.parent, preparing, bound)
        with patch.object(execution, "_invoke", side_effect=invoke):
            result = execution.execute_bla_action(store, retry_id, action_ids[0], fake_runtime)
        self.assertEqual(result["status"], "verifying")
        rollback = execution.discard_candidate(store, retry_id)
        self.assertEqual(rollback["status"], "discarded")
        verifying = workflow.read_record(retry_path, "run")
        cancelled = workflow.transition_run(verifying, "cancelled", cancellation_reason="user_requested")
        workflow.write_run_state(retry_path.parent, cancelled, verifying)
        retained_retry = Path(rollback["retained_at"])
        retry_artifact = retained_retry / "dist/a.js"
        retry_bytes = retry_artifact.read_bytes()
        retry_artifact.write_bytes(b"tampered composite resume evidence")
        with self.assertRaisesRegex(workflow.WorkflowError, "Retained rollback tree hash mismatch"):
            execution.prepare_resume(store, retry_id, "composite-resume-tampered")
        retry_artifact.write_bytes(retry_bytes)
        resumed = execution.prepare_resume(store, retry_id, "composite-resume-retry")
        self.assertEqual((resumed["state"], resumed["action_ids"]), ("preparing", action_ids))

    def test_composite_stage_tree_chain_rejects_detached_or_tampered_stages(self):
        base = {"dist/app.js": hashlib.sha256(b"source").hexdigest(),
                "dist/second.js": hashlib.sha256(b"second-source").hexdigest()}
        first_hash = hashlib.sha256(b"first-output").hexdigest()
        second_hash = hashlib.sha256(b"second-output").hexdigest()
        first_files = {**base, "dist/app.js": first_hash}
        final_files = {**first_files, "dist/second.js": second_hash}
        stages = [{"source_path": "dist/app.js", "candidate_sha256": first_hash,
                   "input_tree_sha256": workflow._tree_hash_for_files(base),
                   "output_tree_sha256": workflow._tree_hash_for_files(first_files)},
                  {"source_path": "dist/second.js", "candidate_sha256": second_hash,
                   "input_tree_sha256": workflow._tree_hash_for_files(first_files),
                   "output_tree_sha256": workflow._tree_hash_for_files(final_files)}]
        self.assertEqual(workflow._verify_composite_stage_tree_chain(base, stages), final_files)

        detached = copy.deepcopy(stages)
        detached[1]["input_tree_sha256"] = workflow._tree_hash_for_files(base)
        with self.assertRaisesRegex(workflow.WorkflowError, "disconnected"):
            workflow._verify_composite_stage_tree_chain(base, detached)
        tampered = copy.deepcopy(stages)
        tampered[0]["candidate_sha256"] = hashlib.sha256(b"tampered-output").hexdigest()
        with self.assertRaisesRegex(workflow.WorkflowError, "output tree hash"):
            workflow._verify_composite_stage_tree_chain(base, tampered)
