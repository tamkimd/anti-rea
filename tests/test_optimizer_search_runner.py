import copy
import os
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core import execution, optimizer, workflow
from tests import test_optimizer_accepted_runs as accepted_run_fixtures


class OptimizerSearchRunnerTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
        self.sandbox.start()
        self.addCleanup(self.sandbox.stop)
        self.fixtures = accepted_run_fixtures.AcceptedOptimizerRunTests()
        self.fixtures.setUp()
        self.addCleanup(self.fixtures.doCleanups)
        self.store, _, self.context = self.fixtures.accepted_bla_run(
            "runner-fixture", b"runner fixture candidate")
        _, self.baseline, self.target, self.plan, self.action, _ = self.context
        self.search = {"schema_version": workflow.SCHEMA_VERSION,
                       "record_type": "optimization_search", "id": "runner-search",
                       "target_id": self.target["id"], "baseline_id": self.baseline["id"],
                       "baseline_sha256": workflow.record_hash(self.baseline),
                       "source_identity_sha256": workflow.record_hash(self.baseline["identity"]),
                       "plan_id": self.plan["id"], "plan_sha256": workflow.record_hash(self.plan),
                       "runtime_identities": {"bla-agents": "b" * 64, "rea": "c" * 64},
                       "candidate_sets": [{"id": "candidate-a", "action_ids": [self.action["id"]],
                                           "estimated_cost_micros": 0, "compatibility_evidence": []}],
                       "budgets": {"max_elapsed_ms": 1000, "max_total_elapsed_ms": 3000,
                                   "max_candidate_bytes": 1000, "max_cost_micros": 0,
                                   "cost_currency": "USD"},
                       "stop_conditions": {"stop_on_first_acceptable": False,
                                           "on_budget_exhaustion": "stop"}}
        optimizer.approve_search_space(self.store, self.search, "runner fixture approval")

    def _patch_runtime_identities(self):
        return patch.object(optimizer, "_search_runtime_identity",
                            side_effect=lambda path, engine: self.search["runtime_identities"][engine])

    def _preflight(self, _store, search_id, candidate_id):
        records = self.store / "records"
        search = workflow.read_record(records / f"optimization_search-{search_id}.json",
                                      "optimization_search")
        plan = workflow.read_record(records / f"plan-{self.plan['id']}.json", "plan")
        baseline = workflow.read_record(records / f"baseline-{self.baseline['id']}.json", "baseline")
        return {"search": search, "plan": plan, "baseline": baseline,
                "candidate": next(item for item in search["candidate_sets"] if item["id"] == candidate_id),
                "actions": [self.action]}

    def test_preflight_failure_is_retained_without_claiming_no_acceptable_candidate(self):
        with self._patch_runtime_identities(), patch.object(
                execution, "validate_approved_candidate_set",
                side_effect=workflow.WorkflowError("preflight rejected")):
            result = optimizer.execute_approved_search(self.store, self.search["id"], "bla", "rea")
        self.assertEqual(result["status"], "not_evaluated")
        self.assertEqual(result["candidate_results"][0]["status"], "failed")

    def test_reinvoking_search_returns_its_single_immutable_result(self):
        with self._patch_runtime_identities(), patch.object(
                execution, "validate_approved_candidate_set",
                side_effect=workflow.WorkflowError("preflight rejected")) as preflight:
            first = optimizer.execute_approved_search(self.store, self.search["id"], "bla", "rea")
            second = optimizer.execute_approved_search(self.store, self.search["id"], "changed-runtime")
        self.assertEqual(first["result_id"], second["result_id"])
        self.assertEqual(first["result_sha256"], second["result_sha256"])
        self.assertEqual(preflight.call_count, 1)
        self.assertEqual(len(list((self.store / "records").glob("optimization_search_result-*.json"))), 1)

    def test_cancellation_is_not_reported_as_budget_exhaustion(self):
        class Cancel:
            value = False

            def is_set(self):
                return self.value

        cancel = Cancel()

        def stop_during_execution(*_args):
            cancel.value = True
            raise workflow.WorkflowError("cancelled by caller")

        with self._patch_runtime_identities(), \
                patch.object(execution, "validate_approved_candidate_set", side_effect=self._preflight), \
                patch.object(execution, "execute_bla_action", side_effect=stop_during_execution):
            result = optimizer.execute_approved_search(self.store, self.search["id"], "bla", "rea",
                                                       cancel_event=cancel)
        self.assertEqual(result["candidate_results"][0]["status"], "cancelled")
        self.assertEqual(result["status"], "not_evaluated")
        run_path = next((self.store / "runs").glob("run-searchrun-*.json"))
        self.assertEqual(workflow.read_json(run_path)["state"], "cancelled")

    def test_acceptance_work_counts_against_candidate_budget_before_persisting_success(self):
        self.search["budgets"]["max_elapsed_ms"] = 150
        optimizer.approve_search_space(self.store, {**self.search, "id": "slow-accept-search"},
                                       "slow acceptance test")
        search_id = "slow-accept-search"
        records = self.store / "records"
        original_read_record = workflow.read_record

        def fake_executor(store, run_id, action_id, *_args):
            run_path = store / "runs" / f"run-{run_id}.json"
            run = workflow.validate_run(workflow.read_json(run_path))
            executing = workflow.transition_run(run, "executing")
            workflow.write_run_state(run_path.parent, executing, run)
            verifying = workflow.transition_run(executing, "verifying", execution_id="execution-slow",
                                                 verification_id="verification-slow")
            workflow.write_run_state(run_path.parent, verifying, executing)
            return {"status": "verifying", "run_id": run_id, "action_id": action_id}

        def read_record(path, kind):
            if kind == "execution" and Path(path).name == "execution-execution-slow.json":
                return {"schema_version": workflow.SCHEMA_VERSION, "record_type": "execution",
                        "id": "execution-slow", "run_id": "unused", "plan_sha256": "a" * 64,
                        "outputs": [], "evidence": []}
            if kind == "verification" and Path(path).name == "verification-verification-slow.json":
                return {"schema_version": workflow.SCHEMA_VERSION, "record_type": "verification",
                        "id": "verification-slow", "run_id": "unused", "checks": []}
            return original_read_record(path, kind)

        def slow_accept(run, *_args, **_kwargs):
            time.sleep(0.25)
            return {**run, "state": "completed", "acceptance": "accepted",
                    "acceptance_id": "searchaccept-slow"}

        with self._patch_runtime_identities(), \
                patch.object(execution, "validate_approved_candidate_set", side_effect=self._preflight), \
                patch.object(execution, "execute_bla_action", side_effect=fake_executor), \
                patch.object(workflow, "read_record", side_effect=read_record), \
                patch.object(workflow, "accept_run", side_effect=slow_accept):
            result = optimizer.execute_approved_search(self.store, search_id, "bla", "rea")
        self.assertEqual(result["candidate_results"][0]["status"], "over_budget")
        run_path = next((self.store / "runs").glob("run-searchrun-*.json"))
        self.assertEqual(workflow.read_json(run_path)["state"], "failed")
        self.assertFalse((records / "acceptance-searchaccept-slow.json").exists())

    def test_failed_candidate_time_counts_toward_global_budget(self):
        search = {**self.search, "id": "global-deadline-search",
                  "budgets": {**self.search["budgets"], "max_total_elapsed_ms": 150}}
        optimizer.approve_search_space(self.store, search, "global deadline test")

        def overrun(*_args):
            time.sleep(0.2)
            raise workflow.WorkflowError("candidate timed out")

        with self._patch_runtime_identities(), \
                patch.object(execution, "validate_approved_candidate_set", side_effect=self._preflight), \
                patch.object(execution, "execute_bla_action", side_effect=overrun):
            result = optimizer.execute_approved_search(self.store, search["id"], "bla", "rea")
        self.assertEqual(result["candidate_results"][0]["status"], "over_budget")
        self.assertEqual(result["status"], "budget_exhausted")
        self.assertGreater(result["total_elapsed_ms"], search["budgets"]["max_total_elapsed_ms"])

    def test_live_runner_can_review_accepted_runs_without_retrospective_stop_failure(self):
        search = copy.deepcopy(self.search)
        search["id"] = "stop-search"
        self.plan["id"] = "runner-stop-plan"
        second_action = copy.deepcopy(self.action)
        second_action["id"] = "second-js-action"
        second_action["evidence"] = copy.deepcopy(self.action["evidence"])
        self.plan["actions"].append(second_action)
        workflow.write_record(self.store / "records", self.plan)
        search["plan_id"] = self.plan["id"]
        search["plan_sha256"] = workflow.record_hash(self.plan)
        search["candidate_sets"] = [
            {"id": "first", "action_ids": [self.action["id"]],
             "estimated_cost_micros": 0, "compatibility_evidence": []},
            {"id": "second", "action_ids": [second_action["id"]],
             "estimated_cost_micros": 0, "compatibility_evidence": []}]
        search["stop_conditions"]["stop_on_first_acceptable"] = True
        optimizer.approve_search_space(self.store, search, "runner fixture approval")
        accepted_id = "accepted-second"
        measurement = {"candidate_id": "second", "run_id": accepted_id,
                       "target_id": self.target["id"],
                       "baseline_sha256": workflow.record_hash(self.baseline),
                       "plan_sha256": search["plan_sha256"], "runtime_sha256": "b" * 64,
                       "source_sha256": search["source_identity_sha256"],
                       "action_id": second_action["id"], "action_ids": [second_action["id"]],
                       "elapsed_ms": 100, "candidate_bytes": 20, "artifact_sha256": "d" * 64,
                       "correctness_passed": True, "integrity_passed": True,
                       "elapsed_trials_ms": {"min": 90, "median": 100, "max": 110},
                       "candidate_size_trials": {"min": 19, "median": 20, "max": 21},
                       "acceptance_id": "accept-second", "accepted_record_sha256": "e" * 64}
        with patch.object(optimizer, "_accepted_run_measurement", return_value=measurement):
            reviewed = optimizer._review_approved_search(
                self.store, search["id"], {"second": accepted_id}, enforce_stop=False)
            self.assertEqual(reviewed["status"], "candidates_available")
            with self.assertRaisesRegex(workflow.WorkflowError, "stop-on-first order"):
                optimizer.review_approved_search(self.store, search["id"], {"second": accepted_id})


if __name__ == "__main__":
    unittest.main()
