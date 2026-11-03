import copy
import contextlib
import hashlib
import io
import json
import os
import unittest
from unittest.mock import patch

from core import optimizer, workflow
from interfaces.cli import anti_rea
from tests.test_optimizer_accepted_runs import AcceptedOptimizerRunTests


class ApprovedOptimizerSearchTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
        self.sandbox.start()
        self.addCleanup(self.sandbox.stop)
        self.fixtures = AcceptedOptimizerRunTests()
        self.fixtures.setUp()
        self.addCleanup(self.fixtures.doCleanups)
        self.store, self.accepted, self.context = self.fixtures.accepted_bla_run(
            "approved-search-run", b"approved candidate")
        self.search = self._approve_search()
        self._write_runner_result({"candidate-a": self.accepted["id"]}, [
            {"candidate_id": "candidate-a", "run_id": self.accepted["id"], "status": "accepted",
             "elapsed_ms": 10, "candidate_bytes": 100}])
        self.selection = optimizer.select_approved_search_candidate(
            self.store, self.search["id"], "candidate-a", {"candidate-a": self.accepted["id"]},
            "test user selection")

    def _write_runner_result(self, accepted_run_ids, candidate_results):
        report = {"status": "candidates_available", "search_id": self.search["id"],
                  "search_sha256": workflow.record_hash(self.search), "budgets": self.search["budgets"],
                  "candidate_results": candidate_results, "accepted_run_ids": accepted_run_ids,
                  "review": None, "total_elapsed_ms": 20,
                  "actual_cost_status": "unavailable; approved estimates only"}
        result = {"schema_version": workflow.SCHEMA_VERSION,
                  "record_type": "optimization_search_result",
                  "id": "optresult-" + hashlib.sha256(workflow.canonical(report)).hexdigest()[:24], **report}
        workflow.write_record(self.store / "records", result)
        return result

    def _approve_search(self, candidate_sets=None):
        _, baseline, target, plan, action, _ = self.context
        if candidate_sets is None:
            candidate_sets = [{"id": "candidate-a", "action_ids": [action["id"]],
                               "estimated_cost_micros": 0, "compatibility_evidence": []}]
        search = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "optimization_search",
                  "id": "approved-search", "target_id": target["id"], "baseline_id": baseline["id"],
                  "baseline_sha256": workflow.record_hash(baseline),
                  "source_identity_sha256": workflow.record_hash(baseline["identity"]),
                  "plan_id": plan["id"], "plan_sha256": workflow.record_hash(plan),
                  "runtime_identities": {"bla-agents": "b" * 64, "rea": "c" * 64},
                  "candidate_sets": candidate_sets,
                  "budgets": {"max_elapsed_ms": 1000, "max_total_elapsed_ms": 3000,
                              "max_candidate_bytes": 1000, "max_cost_micros": 0,
                              "cost_currency": "USD"},
                  "stop_conditions": {"stop_on_first_acceptable": False,
                                      "on_budget_exhaustion": "stop"}}
        optimizer.approve_search_space(self.store, search, "test approval")
        return workflow.read_record(self.store / "records" / f"optimization_search-{search['id']}.json",
                                    "optimization_search")

    def test_candidate_generation_proposes_only_verified_singletons_without_approval(self):
        _, baseline, target, plan, action, _ = self.context
        template = {**self.search, "id": "generated-proposal"}
        template.pop("candidate_sets")
        template["candidate_generation"] = {
            "action_ids": [action["id"]],
            "estimated_cost_micros_by_action": {action["id"]: 0},
            "compatibility_evidence": []}
        before = set((self.store / "records").glob("optimization_search-*.json"))
        proposal = optimizer.generate_search_proposal(self.store, template)
        after = set((self.store / "records").glob("optimization_search-*.json"))
        self.assertEqual(proposal["candidate_sets"], [{
            "id": "candidate-" + hashlib.sha256(workflow.canonical([action["id"]])).hexdigest()[:16],
            "action_ids": [action["id"]], "estimated_cost_micros": 0,
            "compatibility_evidence": []}])
        self.assertEqual(after, before)
        template_path = self.fixtures.root / "generated-search-template.json"
        template_path.write_text(json.dumps(template))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["optimize-generate-candidates", str(template_path), str(self.store)])
        self.assertEqual(status, 0)
        cli_result = json.loads(output.getvalue())
        self.assertEqual((cli_result["status"], cli_result["approval_required"]), ("proposal", True))
        self.assertEqual(cli_result["search"]["candidate_sets"], proposal["candidate_sets"])

    def test_candidate_generation_adds_only_hash_bound_nonoverlapping_pairs(self):
        _, baseline, target, plan, action, _ = self.context
        plan = copy.deepcopy(plan)
        plan["id"] = "generated-pair-plan"
        second = copy.deepcopy(action)
        second["id"] = "generated-pair-js"
        second["execution"]["source_path"] = "dist/second.js"
        plan["actions"].append(second)
        workflow.write_record(self.store / "records", plan)
        pair = sorted([action["id"], second["id"]])
        proof = {"schema_version": "1.0", "record_type": "optimizer_compatibility",
                 "plan_sha256": workflow.record_hash(plan), "baseline_sha256": workflow.record_hash(baseline),
                 "source_identity_sha256": workflow.record_hash(baseline["identity"]),
                 "action_ids": pair, "compatible": True}
        proof_path = self.fixtures.root / "generated-compatibility.json"
        proof_path.write_text(json.dumps(proof))
        ids = [action["id"], second["id"]]
        template = {**self.search, "id": "generated-pair-proposal", "plan_id": plan["id"],
                    "plan_sha256": workflow.record_hash(plan),
                    "budgets": {**self.search["budgets"], "max_cost_micros": 10}}
        template.pop("candidate_sets")
        template["candidate_generation"] = {
            "action_ids": ids,
            "estimated_cost_micros_by_action": {action_id: 2 for action_id in ids},
            "compatibility_evidence": [{"action_ids": ids,
                                         "evidence": {"path": str(proof_path),
                                                      "sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest()}}]}
        proposal = optimizer.generate_search_proposal(self.store, template)
        self.assertEqual([candidate["action_ids"] for candidate in proposal["candidate_sets"]],
                         [[action["id"]], [second["id"]], ids])
        self.assertEqual(proposal["candidate_sets"][-1]["estimated_cost_micros"], 4)
        self.assertEqual(proposal["candidate_sets"][-1]["compatibility_evidence"][0]["evidence"]["sha256"],
                         hashlib.sha256(proof_path.read_bytes()).hexdigest())

    def test_candidate_generation_rejects_unverified_actions_and_unbound_pair_proofs(self):
        _, baseline, target, plan, action, _ = self.context
        unverified = copy.deepcopy(plan)
        unverified["id"] = "generated-unverified-plan"
        unverified["actions"][0]["verification"].remove("application_behavior")
        workflow.write_record(self.store / "records", unverified)
        template = {**self.search, "id": "generated-unverified-proposal", "plan_id": unverified["id"],
                    "plan_sha256": workflow.record_hash(unverified)}
        template.pop("candidate_sets")
        template["candidate_generation"] = {
            "action_ids": [action["id"]], "estimated_cost_micros_by_action": {action["id"]: 0}}
        with self.assertRaisesRegex(workflow.WorkflowError, "not an eligible"):
            optimizer.generate_search_proposal(self.store, template)

        paired = copy.deepcopy(plan)
        paired["id"] = "generated-unbound-pair-plan"
        second = copy.deepcopy(action)
        second["id"] = "generated-unbound-js"
        second["execution"]["source_path"] = "dist/second.js"
        paired["actions"].append(second)
        workflow.write_record(self.store / "records", paired)
        ids = [action["id"], second["id"]]
        proof = {"schema_version": "1.0", "record_type": "optimizer_compatibility",
                 "plan_sha256": "f" * 64, "baseline_sha256": workflow.record_hash(baseline),
                 "source_identity_sha256": workflow.record_hash(baseline["identity"]),
                 "action_ids": sorted(ids), "compatible": True}
        proof_path = self.fixtures.root / "generated-unbound-compatibility.json"
        proof_path.write_text(json.dumps(proof))
        template = {**self.search, "id": "generated-unbound-pair-proposal", "plan_id": paired["id"],
                    "plan_sha256": workflow.record_hash(paired)}
        template.pop("candidate_sets")
        template["candidate_generation"] = {
            "action_ids": ids, "estimated_cost_micros_by_action": {action_id: 0 for action_id in ids},
            "compatibility_evidence": [{"action_ids": ids,
                                         "evidence": {"path": str(proof_path),
                                                      "sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest()}}]}
        with self.assertRaisesRegex(workflow.WorkflowError, "does not bind"):
            optimizer.generate_search_proposal(self.store, template)
        template["candidate_generation"]["compatibility_evidence"][0]["action_ids"] = [action["id"], None]
        with self.assertRaisesRegex(workflow.WorkflowError, "identify one action pair"):
            optimizer.generate_search_proposal(self.store, template)

    def test_candidate_generation_refuses_more_than_four_proposals(self):
        _, baseline, target, plan, action, _ = self.context
        plan = copy.deepcopy(plan)
        plan["id"] = "generated-over-cap-plan"
        action_ids = [action["id"]]
        for index in range(2):
            extra = copy.deepcopy(action)
            extra["id"] = f"generated-extra-{index}"
            extra["execution"]["source_path"] = f"dist/extra-{index}.js"
            plan["actions"].append(extra)
            action_ids.append(extra["id"])
        workflow.write_record(self.store / "records", plan)
        proofs = []
        for index, pair_ids in enumerate(([action_ids[0], action_ids[1]], [action_ids[0], action_ids[2]])):
            pair = sorted(pair_ids)
            path = self.fixtures.root / f"generated-over-cap-{index}.json"
            path.write_text(json.dumps({"schema_version": "1.0", "record_type": "optimizer_compatibility",
                                        "plan_sha256": workflow.record_hash(plan),
                                        "baseline_sha256": workflow.record_hash(baseline),
                                        "source_identity_sha256": workflow.record_hash(baseline["identity"]),
                                        "action_ids": pair, "compatible": True}))
            proofs.append({"action_ids": pair_ids,
                           "evidence": {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}})
        template = {**self.search, "id": "generated-over-cap-proposal", "plan_id": plan["id"],
                    "plan_sha256": workflow.record_hash(plan)}
        template.pop("candidate_sets")
        template["candidate_generation"] = {
            "action_ids": action_ids,
            "estimated_cost_micros_by_action": {action_id: 0 for action_id in action_ids},
            "compatibility_evidence": proofs}
        with self.assertRaisesRegex(workflow.WorkflowError, "four-candidate search limit"):
            optimizer.generate_search_proposal(self.store, template)

    def test_review_uses_approved_candidate_mapping_and_persisted_budgets(self):
        result = optimizer.review_approved_search(
            self.store, self.search["id"], {"candidate-a": self.accepted["id"]})
        self.assertEqual(result["status"], "candidates_available")
        self.assertEqual(result["pareto_frontier"][0]["candidate_id"], "candidate-a")
        self.assertEqual(result["pareto_frontier"][0]["run_id"], self.accepted["id"])
        self.assertEqual(result["budgets"], {key: self.search["budgets"][key] for key in
                                               ("max_elapsed_ms", "max_total_elapsed_ms",
                                                "max_candidate_bytes")})

    def test_missing_approved_candidates_return_not_evaluated(self):
        result = optimizer.review_approved_search(self.store, self.search["id"], {})
        self.assertEqual(result["status"], "not_evaluated")
        self.assertEqual(result["rejected"], [{"candidate_id": "candidate-a", "reason": "not_evaluated"}])

    def test_over_budget_accepted_run_is_reported_as_rejected_candidate(self):
        search = copy.deepcopy(self.search)
        search["id"] = "over-budget-search"
        search["budgets"]["max_elapsed_ms"] = 1
        optimizer.approve_search_space(self.store, search, "test approval")
        result = optimizer.review_approved_search(
            self.store, search["id"], {"candidate-a": self.accepted["id"]})
        self.assertEqual(result["status"], "no_acceptable_candidate")
        self.assertEqual(result["rejected"], [{"candidate_id": "candidate-a", "reason": "candidate_over_budget"}])

    def test_review_rejects_run_outside_approved_candidate_mapping(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "unapproved candidate"):
            optimizer.review_approved_search(
                self.store, self.search["id"], {"unapproved": self.accepted["id"]})

    def test_review_rejects_wrong_plan_and_action(self):
        store, baseline, target, plan, action, decision = self.context
        other_plan = copy.deepcopy(plan)
        other_plan["id"] = "different-plan"
        other_plan["budgets"]["runtime_ms"] += 1
        workflow.write_record(store / "records", other_plan)
        other_decision = {**decision, "id": "different-plan-decision",
                          "plan_sha256": workflow.record_hash(other_plan)}
        workflow.write_record(store / "records", other_decision)
        other_action = next(item for item in other_plan["actions"] if item["id"] == action["id"])
        _, other_run, _ = self.fixtures.accepted_bla_run(
            "different-plan-run", b"different plan output",
            context=(store, baseline, target, other_plan, other_action, other_decision))
        with self.assertRaisesRegex(workflow.WorkflowError, "(?i)optimization search|approved search candidate identity"):
            optimizer.review_approved_search(
                self.store, self.search["id"], {"candidate-a": other_run["id"]})

        other_action_plan = copy.deepcopy(plan)
        other_action_plan["id"] = "different-action-plan"
        selected = next(item for item in other_action_plan["actions"] if item["id"] == action["id"])
        selected["id"] = "different-action"
        workflow.write_record(store / "records", other_action_plan)
        changed_decision = {**decision, "id": "different-action-decision",
                            "plan_sha256": workflow.record_hash(other_action_plan),
                            "selected_action_ids": ["different-action"]}
        workflow.write_record(store / "records", changed_decision)
        changed_action = next(item for item in other_action_plan["actions"]
                              if item["id"] == "different-action")
        _, changed_run, _ = self.fixtures.accepted_bla_run(
            "different-action-run", b"different action output",
            context=(store, baseline, target, other_action_plan, changed_action, changed_decision))
        with self.assertRaisesRegex(workflow.WorkflowError, "(?i)optimization search|approved search candidate identity"):
            optimizer.review_approved_search(
                self.store, self.search["id"], {"candidate-a": changed_run["id"]})

    def test_review_rejects_wrong_target_and_runtime_identity(self):
        other_project = self.fixtures.root / "other-project"
        other_project.mkdir()
        (other_project / "build.py").write_text((self.fixtures.project / "build.py").read_text())
        _, other_target_run, _ = self.fixtures.accepted_bla_run(
            "different-target-run", b"other target", project=other_project)
        with self.assertRaisesRegex(workflow.WorkflowError, "(?i)optimization search|approved search candidate identity"):
            optimizer.review_approved_search(
                self.store, self.search["id"], {"candidate-a": other_target_run["id"]})

        _, other_runtime_run, _ = self.fixtures.accepted_bla_run(
            "different-runtime-run", b"other runtime", self.context, runtime_hash="d" * 64)
        with self.assertRaisesRegex(workflow.WorkflowError, "(?i)optimization search|approved search candidate identity"):
            optimizer.review_approved_search(
                self.store, self.search["id"], {"candidate-a": other_runtime_run["id"]})

    def test_review_revalidates_composite_candidate_mapping(self):
        _, baseline, target, plan, action, _ = self.context
        combined_plan = copy.deepcopy(plan)
        combined_plan["id"] = "combined-plan"
        other = copy.deepcopy(action)
        other["id"] = "js-two"
        other["execution"]["source_path"] = "dist/second.js"
        combined_plan["actions"].append(other)
        workflow.write_record(self.store / "records", combined_plan)
        actions = [action["id"], other["id"]]
        proof = {"schema_version": "1.0", "record_type": "optimizer_compatibility",
                 "plan_sha256": workflow.record_hash(combined_plan),
                 "baseline_sha256": workflow.record_hash(baseline),
                 "source_identity_sha256": workflow.record_hash(baseline["identity"]),
                 "action_ids": sorted(actions), "compatible": True}
        proof_path = self.fixtures.root / "compatibility.json"
        proof_path.write_text(json.dumps(proof))
        candidate = {"id": "combined", "action_ids": actions,
                     "estimated_cost_micros": 0,
                     "compatibility_evidence": [{"action_ids": actions,
                                                 "evidence": {"path": str(proof_path),
                                                              "sha256": hashlib.sha256(
                                                                  proof_path.read_bytes()).hexdigest()}}]}
        # Replace the fixture search with a valid multi-action approved scope.
        search = {**self.search, "id": "combined-search", "plan_id": combined_plan["id"],
                  "plan_sha256": workflow.record_hash(combined_plan), "candidate_sets": [candidate]}
        optimizer.approve_search_space(self.store, search, "test approval")
        unmeasured = optimizer.review_approved_search(self.store, search["id"], {})
        self.assertEqual(unmeasured["status"], "not_evaluated")
        self.assertEqual(unmeasured["rejected"], [{"candidate_id": "combined", "reason": "not_evaluated"}])
        with self.assertRaisesRegex(workflow.WorkflowError, "(?i)candidate identity|approved candidate|exact approved plan"):
            optimizer.review_approved_search(self.store, search["id"], {"combined": self.accepted["id"]})

    def test_cli_review_search_uses_candidate_run_mapping(self):
        mapping_path = self.fixtures.root / "candidate-runs.json"
        mapping_path.write_text(json.dumps({"candidate-a": self.accepted["id"]}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["optimize-review-search", self.search["id"], str(self.store),
                                    str(mapping_path)])
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["search_id"], self.search["id"])
        self.assertEqual(result["pareto_frontier"][0]["run_id"], self.accepted["id"])

    def test_cli_select_search_persists_explicit_frontier_choice(self):
        mapping_path = self.fixtures.root / "candidate-runs-for-selection.json"
        mapping_path.write_text(json.dumps({"candidate-a": self.accepted["id"]}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["optimize-select-search", self.search["id"], str(self.store),
                                    "candidate-a", str(mapping_path), "user selected candidate-a"])
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "selected")
        record = workflow.read_record(self.store / "records" / result["record"],
                                      "optimization_selection")
        self.assertEqual(record["decision_source"], "user selected candidate-a")
        self.assertEqual(record["candidate_run_id"], self.accepted["id"])

    def test_selection_persists_review_and_candidate_mapping(self):
        record = workflow.read_record(self.store / "records" / self.selection["record"],
                                      "optimization_selection")
        self.assertEqual(record["search_sha256"], workflow.record_hash(self.search))
        self.assertEqual(record["review_sha256"], self.selection["review_sha256"])
        self.assertEqual(record["candidate_run_id"], self.accepted["id"])
        self.assertEqual(record["candidate_runs"], {"candidate-a": self.accepted["id"]})
        with self.assertRaisesRegex(workflow.WorkflowError, "decision source"):
            optimizer.select_approved_search_candidate(
                self.store, self.search["id"], "candidate-a", {"candidate-a": self.accepted["id"]}, " ")

    def test_selection_rejects_candidate_outside_the_current_frontier(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "Pareto frontier"):
            optimizer.select_approved_search_candidate(
                self.store, self.search["id"], "missing-candidate", {"candidate-a": self.accepted["id"]},
                "test user selection")

    def test_stop_on_first_selection_accepts_second_after_persisted_first_failure(self):
        _, baseline, target, plan, action, _ = self.context
        second_action = copy.deepcopy(action)
        second_action["id"] = "second-js"
        plan = copy.deepcopy(plan)
        plan["id"] = "two-candidate-plan"
        plan["actions"].append(second_action)
        workflow.write_record(self.store / "records", plan)
        search = copy.deepcopy(self.search)
        search.update({"id": "ordered-search", "plan_id": plan["id"],
                       "plan_sha256": workflow.record_hash(plan),
                       "candidate_sets": [
                           {"id": "first", "action_ids": [action["id"]], "estimated_cost_micros": 0,
                            "compatibility_evidence": []},
                           {"id": "second", "action_ids": [second_action["id"]], "estimated_cost_micros": 0,
                            "compatibility_evidence": []}],
                       "stop_conditions": {"stop_on_first_acceptable": True,
                                           "on_budget_exhaustion": "stop"}})
        optimizer.approve_search_space(self.store, search, "test chronology approval")
        search = workflow.read_record(self.store / "records" / "optimization_search-ordered-search.json",
                                      "optimization_search")
        decision = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "decision",
                    "id": "second-candidate-decision", "plan_sha256": workflow.record_hash(plan),
                    "selected_action_ids": [second_action["id"]], "decision": "approved",
                    "decision_source": "test"}
        workflow.write_record(self.store / "records", decision)
        _, second_run, _ = self.fixtures.accepted_bla_run(
            "accepted-second-search-candidate", b"approved candidate",
            context=(self.store, baseline, target, plan, second_action, decision))
        first_run_id = "failed-first-candidate"
        first = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "run", "id": first_run_id,
                 "target_id": target["id"], "state": "discovered"}
        workflow.write_run_state(self.store / "runs", first, None)
        first = workflow.transition_run(first, "baselining")
        workflow.write_run_state(self.store / "runs", first, {"schema_version": workflow.SCHEMA_VERSION,
                               "record_type": "run", "id": first_run_id,
                               "target_id": target["id"], "state": "discovered"})
        baselining = first
        first = workflow.transition_run(first, "failed", error_code="optimization_candidate_failed")
        workflow.write_run_state(self.store / "runs", first, baselining)
        outcomes = [{"candidate_id": "first", "run_id": first_run_id, "status": "failed"},
                    {"candidate_id": "second", "run_id": second_run["id"], "status": "accepted",
                     "elapsed_ms": 10, "candidate_bytes": 100}]
        result = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "optimization_search_result",
                  "id": "optresult-ordered", "status": "candidates_available", "search_id": search["id"],
                  "search_sha256": workflow.record_hash(search), "budgets": search["budgets"],
                  "candidate_results": outcomes, "accepted_run_ids": {"second": second_run["id"]},
                  "review": None, "total_elapsed_ms": 20,
                  "actual_cost_status": "unavailable; approved estimates only"}
        workflow.write_record(self.store / "records", result)
        selected = optimizer.select_approved_search_candidate(
            self.store, search["id"], "second", {"second": second_run["id"]}, "user chose second")
        self.assertEqual(selected["candidate_id"], "second")

    def test_confirm_approved_search_reevaluation_accepts_matching_distinct_run(self):
        _, reevaluated, _ = self.fixtures.accepted_bla_run(
            "approved-search-rerun", b"approved candidate", self.context)
        result = optimizer.confirm_approved_search_reevaluation(
            self.store, self.search["id"], self.selection["id"], self.accepted["id"], reevaluated["id"])
        self.assertEqual(result["status"], "independently_reevaluated")
        self.assertEqual(result["initial_run_id"], self.accepted["id"])
        self.assertEqual(result["reevaluation_run_id"], reevaluated["id"])
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(b"approved candidate").hexdigest())
        self.assertEqual(result["selection_id"], self.selection["id"])

    def test_confirm_rejects_candidate_outside_approved_search(self):
        _, reevaluated, _ = self.fixtures.accepted_bla_run(
            "unapproved-search-rerun", b"approved candidate", self.context)
        with self.assertRaisesRegex(workflow.WorkflowError, "(?i)selection"):
            optimizer.confirm_approved_search_reevaluation(
                self.store, self.search["id"], "unknown-selection", self.accepted["id"], reevaluated["id"])

    def test_confirm_requires_persisted_selection_even_for_an_approved_candidate(self):
        _, reevaluated, _ = self.fixtures.accepted_bla_run(
            "unselected-search-rerun", b"approved candidate", self.context)
        with self.assertRaisesRegex(workflow.WorkflowError, "selection"):
            optimizer.confirm_approved_search_reevaluation(
                self.store, self.search["id"], "candidate-a", self.accepted["id"], reevaluated["id"])

    def test_confirm_rejects_selection_with_a_changed_review_hash(self):
        _, reevaluated, _ = self.fixtures.accepted_bla_run(
            "changed-review-rerun", b"approved candidate", self.context)
        path = self.store / "records" / self.selection["record"]
        selection = workflow.read_record(path, "optimization_selection")
        selection["review_sha256"] = "f" * 64
        path.write_text(json.dumps(selection))
        with self.assertRaisesRegex(workflow.WorkflowError, "review has changed"):
            optimizer.confirm_approved_search_reevaluation(
                self.store, self.search["id"], self.selection["id"], self.accepted["id"], reevaluated["id"])

    def test_confirm_rejects_mismatched_output(self):
        _, reevaluated, _ = self.fixtures.accepted_bla_run(
            "different-output-rerun", b"different output", self.context)
        with self.assertRaisesRegex(workflow.WorkflowError, "output|identical|reproduce"):
            optimizer.confirm_approved_search_reevaluation(
                self.store, self.search["id"], self.selection["id"], self.accepted["id"], reevaluated["id"])

    def test_confirm_rejects_mismatched_runtime(self):
        _, reevaluated, _ = self.fixtures.accepted_bla_run(
            "different-runtime-rerun", b"approved candidate", self.context, runtime_hash="d" * 64)
        with self.assertRaisesRegex(workflow.WorkflowError, "runtime|identity|approved"):
            optimizer.confirm_approved_search_reevaluation(
                self.store, self.search["id"], self.selection["id"], self.accepted["id"], reevaluated["id"])

    def test_confirm_rejects_mismatched_plan_and_action(self):
        store, baseline, target, plan, action, decision = self.context
        alternate_plan = copy.deepcopy(plan)
        alternate_plan["id"] = "reevaluation-plan"
        alternate_plan["budgets"]["runtime_ms"] += 1
        workflow.write_record(store / "records", alternate_plan)
        alternate_decision = {**decision, "id": "reevaluation-plan-decision",
                              "plan_sha256": workflow.record_hash(alternate_plan)}
        workflow.write_record(store / "records", alternate_decision)
        alternate_action = next(item for item in alternate_plan["actions"] if item["id"] == action["id"])
        _, other_plan_run, _ = self.fixtures.accepted_bla_run(
            "reevaluation-wrong-plan", b"approved candidate",
            context=(store, baseline, target, alternate_plan, alternate_action, alternate_decision))
        with self.assertRaisesRegex(workflow.WorkflowError, "plan|identity|approved"):
            optimizer.confirm_approved_search_reevaluation(
                self.store, self.search["id"], self.selection["id"], self.accepted["id"], other_plan_run["id"])

        alternate_action_plan = copy.deepcopy(plan)
        alternate_action_plan["id"] = "reevaluation-action-plan"
        selected = next(item for item in alternate_action_plan["actions"] if item["id"] == action["id"])
        selected["id"] = "reevaluation-action"
        workflow.write_record(store / "records", alternate_action_plan)
        changed_decision = {**decision, "id": "reevaluation-action-decision",
                            "plan_sha256": workflow.record_hash(alternate_action_plan),
                            "selected_action_ids": ["reevaluation-action"]}
        workflow.write_record(store / "records", changed_decision)
        changed_action = next(item for item in alternate_action_plan["actions"]
                              if item["id"] == "reevaluation-action")
        _, other_action_run, _ = self.fixtures.accepted_bla_run(
            "reevaluation-wrong-action", b"approved candidate",
            context=(store, baseline, target, alternate_action_plan, changed_action, changed_decision))
        with self.assertRaisesRegex(workflow.WorkflowError, "action|identity|approved"):
            optimizer.confirm_approved_search_reevaluation(
                self.store, self.search["id"], self.selection["id"], self.accepted["id"], other_action_run["id"])

    def test_cli_confirm_search_uses_persisted_candidate_limits(self):
        _, rerun, _ = self.fixtures.accepted_bla_run(
            "approved-search-cli-rerun", b"approved candidate", self.context)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["optimize-confirm-search", str(self.store), self.search["id"],
                                    self.selection["id"], self.accepted["id"], rerun["id"]])
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["candidate_id"], "candidate-a")
        self.assertEqual(result["selection_id"], self.selection["id"])
        self.assertEqual(result["status"], "independently_reevaluated")


if __name__ == "__main__":
    unittest.main()
