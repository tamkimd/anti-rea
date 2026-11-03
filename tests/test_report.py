import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import workflow
from interfaces.cli import anti_rea


@unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK requires Python 3.11+ clean environment")
class RunReportTests(unittest.TestCase):
    def _base_store(self, store: Path, state: str = "awaiting_decision") -> tuple[str, dict, dict, dict]:
        target = {"schema_version": "2.0", "record_type": "target", "id": "target-report-shared",
                  "components": [{"id": "app", "kind": "fixture"}]}
        baseline = {"schema_version": "2.0", "record_type": "baseline", "id": "baseline-report-shared",
                    "target_id": target["id"], "identity": {"source": "fixture"}, "evidence": ["before.json"]}
        action = {"id": "protect", "finding_or_asset": "fixture asset", "change": "fixture change",
                  "mechanism": "report validation", "engine": "fixture", "expected_benefit": "exercise validation",
                  "cost": "none", "tradeoffs": ["fixture"], "dependencies": ["none"],
                  "compatibility": ["fixture"], "verification": ["behavior"],
                  "limitations": ["does not establish protection"], "rollback": "discard fixture"}
        plan = {"schema_version": "2.0", "record_type": "plan", "id": "plan-report-shared",
                "target_id": target["id"], "baseline_id": baseline["id"], "actions": [action],
                "budgets": {"runtime_ms": 100}, "rollback": "discard fixture"}
        records = store / "records"
        workflow.write_record(records, target)
        run = {"schema_version": "2.0", "record_type": "run", "id": "run-report-shared",
               "target_id": target["id"], "state": "discovered"}
        current = workflow.write_run_state(store / "runs", run, None)
        run = workflow.transition_run(run, "baselining", baseline_id=baseline["id"])
        workflow.write_run_state(store / "runs", run, {**workflow.read_json(current)})
        if state == "baselining":
            return run["id"], target, baseline, plan
        workflow.write_record(records, baseline)
        workflow.write_record(records, plan)
        run = workflow.transition_run(run, "awaiting_decision", plan_id=plan["id"])
        current = workflow.read_json(store / "runs" / f"run-{run['id']}.json")
        workflow.write_run_state(store / "runs", run, current)
        return run["id"], target, baseline, plan

    def _assert_both_report_interfaces_fail(self, store: Path, run_id: str):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = anti_rea.main(["report", run_id, str(store)])
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")
        from interfaces.mcp import server
        with patch.dict("os.environ", {"ANTI_REA_STATE_DIR": str(store)}):
            with self.assertRaises(workflow.WorkflowError):
                server.get_report(run_id)

    def test_baselining_report_allows_baseline_record_not_written_yet(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            run_id, _, _, _ = self._base_store(store, "baselining")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(anti_rea.main(["report", run_id, str(store)]), 0)
            self.assertNotIn("baseline", json.loads(output.getvalue()))
            with patch.dict("os.environ", {"ANTI_REA_STATE_DIR": str(store)}):
                report = server.get_report(run_id)
            self.assertEqual(report["run"]["state"], "baselining")
            self.assertNotIn("baseline", report)

    def test_report_rejects_record_id_and_plan_baseline_mismatches_through_both_interfaces(self):
        for corrupt in ("record_id", "plan_baseline"):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as directory:
                store = Path(directory)
                run_id, _, _, plan = self._base_store(store)
                if corrupt == "record_id":
                    plan["id"] = "unexpected-plan-id"
                else:
                    plan["baseline_id"] = "different-baseline"
                (store / "records" / "plan-plan-report-shared.json").write_text(json.dumps(plan))
                self._assert_both_report_interfaces_fail(store, run_id)

    def test_report_rejects_execution_from_a_different_run_through_both_interfaces(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            run_id, _, _, plan = self._base_store(store)
            records = store / "records"
            decision = {"schema_version": "2.0", "record_type": "decision", "id": "decision-report-shared",
                        "plan_sha256": workflow.record_hash(plan), "selected_action_ids": ["protect"],
                        "decision": "approved", "decision_source": "fixture"}
            workflow.write_record(records, decision)
            source = workflow.read_json(store / "runs" / f"run-{run_id}.json")
            source = workflow.bind_decision(source, plan, decision)
            workflow.write_run_state(store / "runs", source,
                                     workflow.read_json(store / "runs" / f"run-{run_id}.json"))
            for next_state in ("preparing", "executing"):
                current = workflow.read_json(store / "runs" / f"run-{run_id}.json")
                changed = workflow.transition_run(current, next_state)
                workflow.write_run_state(store / "runs", changed, current)
            evidence_file = store / "evidence.json"
            evidence_file.write_text("fixture")
            execution = {"schema_version": "2.0", "record_type": "execution", "id": "exec-report-shared",
                         "run_id": "other-run", "plan_sha256": workflow.record_hash(plan),
                         "action_id": "protect", "commands": [["fixture"]], "exit_code": 0,
                         "outputs": [{"path": "candidate.js", "sha256": "a" * 64}]}
            verification = {"schema_version": "2.0", "record_type": "verification", "id": "verify-report-shared",
                            "run_id": run_id, "checks": [{"id": "behavior", "status": "passed",
                            "evidence": [{"path": str(evidence_file),
                                          "sha256": hashlib.sha256(evidence_file.read_bytes()).hexdigest()}]}]}
            workflow.write_record(records, execution)
            workflow.write_record(records, verification)
            current = workflow.read_json(store / "runs" / f"run-{run_id}.json")
            verifying = workflow.transition_run(current, "verifying", execution_id=execution["id"],
                                                  verification_id=verification["id"])
            workflow.write_run_state(store / "runs", verifying, current)
            self._assert_both_report_interfaces_fail(store, run_id)

    def test_rejected_terminal_report_replays_through_shared_mcp_and_cli_paths(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            run_id, target, baseline, plan = self._base_store(store)
            records = store / "records"
            decision = {"schema_version": "2.0", "record_type": "decision", "id": "decision-report-shared",
                        "plan_sha256": workflow.record_hash(plan), "selected_action_ids": ["protect"],
                        "decision": "approved", "decision_source": "fixture"}
            workflow.write_record(records, decision)
            current = workflow.read_json(store / "runs" / f"run-{run_id}.json")
            bound = workflow.bind_decision(current, plan, decision)
            workflow.write_run_state(store / "runs", bound, current)
            preparing = workflow.start_execution(bound, plan, decision)
            workflow.write_run_state(store / "runs", preparing, bound)
            executing = workflow.transition_run(preparing, "executing")
            workflow.write_run_state(store / "runs", executing, preparing)
            execution = {"schema_version": "2.0", "record_type": "execution", "id": "exec-report-shared",
                         "run_id": run_id, "plan_sha256": workflow.record_hash(plan),
                         "action_id": "protect", "commands": [["fixture"]], "exit_code": 0,
                         "outputs": [{"path": "candidate.js", "sha256": "a" * 64}]}
            verification = {"schema_version": "2.0", "record_type": "verification", "id": "verify-report-shared",
                            "run_id": run_id, "checks": [{"id": "behavior", "status": "failed",
                            "evidence": ["behavior check failed"]}]}
            workflow.write_record(records, execution)
            workflow.write_record(records, verification)
            verifying = workflow.transition_run(executing, "verifying", execution_id=execution["id"],
                                                 verification_id=verification["id"])
            workflow.write_run_state(store / "runs", verifying, executing)
            acceptance = {"schema_version": "2.0", "record_type": "acceptance", "id": "reject-report-shared",
                          "run_id": run_id, "outcome": "rejected", "claims": [],
                          "reasons": ["The behavior check failed."], "verification_id": verification["id"],
                          "execution_id": execution["id"], "plan_sha256": workflow.record_hash(plan)}
            blocked = workflow.accept_run(verifying, target, baseline, plan, decision,
                                          execution, verification, acceptance)
            workflow.write_record(records, acceptance)
            workflow.write_run_state(store / "runs", blocked, verifying)

            report = workflow.assemble_run_report(records, blocked)
            self.assertEqual((report["run"]["state"], report["acceptance"]["outcome"]), ("blocked", "rejected"))
            with patch.dict("os.environ", {"ANTI_REA_STATE_DIR": str(store)}):
                self.assertEqual(server.get_report(run_id)["acceptance"]["id"], acceptance["id"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(anti_rea.main(["report", run_id, str(store)]), 0)
            self.assertEqual(json.loads(output.getvalue())["acceptance"]["outcome"], "rejected")


if __name__ == "__main__":
    unittest.main()
