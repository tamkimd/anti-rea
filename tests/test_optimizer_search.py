import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core import optimizer, workflow
from interfaces.cli import anti_rea


class OptimizerSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "state"
        self.records = self.store / "records"
        self.records.mkdir(parents=True)
        self.baseline = {"schema_version": "2.0", "record_type": "baseline",
                         "id": "baseline-search", "target_id": "target-search",
                         "identity": {"source": "fixture"}, "evidence": ["before.json"]}
        workflow.write_record(self.records, self.baseline)
        action = {"id": "js", "finding_or_asset": "app.js", "change": "Protect JavaScript",
                  "mechanism": "Run the selected pinned transform", "engine": "bla",
                  "execution": {"adapter": "bla-js", "source_path": "app.js", "intensity": "balanced"},
                  "expected_benefit": "Reduce direct inspection", "cost": "Transform and verification time",
                  "tradeoffs": ["Output may grow"], "dependencies": ["Pinned BLA runtime"],
                  "compatibility": ["Check application behavior"], "verification": ["bla_invariants"],
                  "limitations": ["Does not prevent reconstruction"], "rollback": "Discard candidate"}
        second = {**action, "id": "maps", "finding_or_asset": "app.js.map",
                  "change": "Omit source map", "engine": "release packaging",
                  "execution": {"adapter": "source-map-candidate", "source_path": "app.js.map"}}
        self.plan = {"schema_version": "2.0", "record_type": "plan", "id": "plan-search",
                     "target_id": "target-search", "baseline_id": "baseline-search",
                     "actions": [action, second], "budgets": {"runtime_ms": 500},
                     "rollback": "Discard private candidate"}
        workflow.write_record(self.records, self.plan)
        self.plan_hash = workflow.record_hash(self.plan)
        proof = {"schema_version": "1.0", "record_type": "optimizer_compatibility",
                 "plan_sha256": self.plan_hash,
                 "baseline_sha256": workflow.record_hash(self.baseline),
                 "source_identity_sha256": workflow.record_hash(self.baseline["identity"]),
                 "action_ids": ["js", "maps"], "compatible": True}
        self.proof_path = self.root / "compatibility.json"
        self.proof_path.write_text(json.dumps(proof))
        self.search = {"schema_version": "2.0", "record_type": "optimization_search",
                       "id": "search-1", "target_id": "target-search", "baseline_id": "baseline-search",
                       "baseline_sha256": workflow.record_hash(self.baseline),
                       "source_identity_sha256": workflow.record_hash(self.baseline["identity"]),
                       "plan_id": "plan-search", "plan_sha256": self.plan_hash,
                       "runtime_identities": {"bla-agents": "f" * 64},
                       "candidate_sets": [
                           {"id": "individual", "action_ids": ["js"], "estimated_cost_micros": 0,
                            "compatibility_evidence": []},
                           {"id": "combined", "action_ids": ["js", "maps"],
                            "estimated_cost_micros": 0,
                            "compatibility_evidence": [{"action_ids": ["js", "maps"],
                                                        "evidence": {"path": str(self.proof_path),
                                                                     "sha256": hashlib.sha256(
                                                                         self.proof_path.read_bytes()).hexdigest()}}]}],
                       "budgets": {"max_elapsed_ms": 1000, "max_total_elapsed_ms": 2000,
                                   "max_candidate_bytes": 64000, "max_cost_micros": 0,
                                   "cost_currency": "USD"},
                       "stop_conditions": {"stop_on_first_acceptable": False,
                                           "on_budget_exhaustion": "stop"}}

    def test_search_scope_binds_plan_and_pairwise_compatibility_proof(self):
        value = workflow.validate_optimization_search(
            {**self.search, "decision_source": "test approval"}, self.plan, self.baseline)
        self.assertEqual(value["candidate_sets"][1]["action_ids"], ["js", "maps"])
        result = optimizer.approve_search_space(self.store, self.search, "CLI interactive confirmation")
        self.assertEqual(result["status"], "approved")
        stored = workflow.read_record(self.records / "optimization_search-search-1.json", "optimization_search")
        self.assertEqual(stored["decision_source"], "CLI interactive confirmation")
        self.assertEqual(stored["plan_sha256"], self.plan_hash)

    def test_search_scope_requires_all_runtime_identities(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "bind every required runtime"):
            workflow.validate_optimization_search(
                {**self.search, "runtime_identities": {}, "decision_source": "test"},
                self.plan, self.baseline)

    def test_search_scope_rejects_compatibility_proof_from_different_source(self):
        proof = {"schema_version": "1.0", "record_type": "optimizer_compatibility",
                 "plan_sha256": self.plan_hash, "baseline_sha256": workflow.record_hash(self.baseline),
                 "source_identity_sha256": "a" * 64, "action_ids": ["js", "maps"], "compatible": True}
        self.proof_path.write_text(json.dumps(proof))
        reference = {"path": str(self.proof_path),
                     "sha256": hashlib.sha256(self.proof_path.read_bytes()).hexdigest()}
        candidate = {**self.search["candidate_sets"][1],
                     "compatibility_evidence": [{"action_ids": ["js", "maps"], "evidence": reference}]}
        with self.assertRaisesRegex(workflow.WorkflowError, "bind the source, baseline"):
            workflow.validate_optimization_search(
                {**self.search, "candidate_sets": [candidate], "decision_source": "test"},
                self.plan, self.baseline)

    def test_read_record_rechecks_saved_search_compatibility_evidence(self):
        optimizer.approve_search_space(self.store, self.search, "CLI --yes")
        path = self.records / "optimization_search-search-1.json"
        self.assertEqual(workflow.read_record(path, "optimization_search")["id"], "search-1")
        self.proof_path.write_text(json.dumps({"schema_version": "1.0", "record_type": "optimizer_compatibility",
                                               "plan_sha256": self.plan_hash, "action_ids": ["js", "maps"],
                                               "compatible": False}))
        with self.assertRaisesRegex(workflow.WorkflowError, "evidence hash mismatch"):
            workflow.read_record(path, "optimization_search")

    def test_read_record_rechecks_saved_search_plan_and_baseline_bindings(self):
        optimizer.approve_search_space(self.store, self.search, "CLI --yes")
        path = self.records / "optimization_search-search-1.json"
        baseline_path = self.records / "baseline-baseline-search.json"
        baseline_path.write_text(json.dumps({**self.baseline, "identity": {"source": "changed"}}))
        with self.assertRaisesRegex(workflow.WorkflowError, "exact source and baseline identities"):
            workflow.read_record(path, "optimization_search")

    def test_search_scope_rejects_unbound_or_missing_combination_evidence(self):
        missing = {**self.search, "candidate_sets": [self.search["candidate_sets"][1] | {
            "compatibility_evidence": []}]}
        with self.assertRaisesRegex(workflow.WorkflowError, "compatibility evidence"):
            workflow.validate_optimization_search({**missing, "decision_source": "test"}, self.plan, self.baseline)
        tampered = {**self.search, "plan_sha256": "a" * 64,
                    "candidate_sets": [self.search["candidate_sets"][0]]}
        with self.assertRaisesRegex(workflow.WorkflowError, "exact approved plan"):
            workflow.validate_optimization_search({**tampered, "decision_source": "test"}, self.plan, self.baseline)

    def test_search_scope_rejects_estimated_candidate_cost_over_budget(self):
        candidate = {**self.search["candidate_sets"][0], "estimated_cost_micros": 2}
        budget = {**self.search["budgets"], "max_cost_micros": 1}
        with self.assertRaisesRegex(workflow.WorkflowError, "cost estimates exceed"):
            workflow.validate_optimization_search(
                {**self.search, "candidate_sets": [candidate], "budgets": budget,
                 "decision_source": "test"}, self.plan, self.baseline)

    def test_search_scope_requires_plan_order_for_combination(self):
        candidate = {**self.search["candidate_sets"][1], "action_ids": ["maps", "js"],
                     "compatibility_evidence": [{"action_ids": ["js", "maps"],
                                                 "evidence": {"path": str(self.proof_path),
                                                              "sha256": hashlib.sha256(
                                                                  self.proof_path.read_bytes()).hexdigest()}}]}
        with self.assertRaisesRegex(workflow.WorkflowError, "preserve the saved plan order"):
            workflow.validate_optimization_search(
                {**self.search, "candidate_sets": [candidate], "decision_source": "test"},
                self.plan, self.baseline)

    def test_cli_requires_explicit_approval_and_preview_does_not_persist(self):
        path = self.root / "search.json"
        path.write_text(json.dumps(self.search))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["optimize-approve-search", str(path), str(self.store), "--preview"])
        self.assertEqual(status, 0)
        self.assertFalse((self.records / "optimization_search-search-1.json").exists())
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("sys.stdin", io.StringIO("")):
            status = anti_rea.main(["optimize-approve-search", str(path), str(self.store)])
        self.assertEqual(status, 2)
        self.assertFalse((self.records / "optimization_search-search-1.json").exists())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["optimize-approve-search", str(path), str(self.store), "--yes"])
        self.assertEqual(status, 0)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([item["status"] for item in records], ["approval_required", "approved"])
        self.assertTrue((self.records / "optimization_search-search-1.json").is_file())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK requires Python 3.11+ environment")
    def test_mcp_preview_is_read_only_and_approval_uses_shared_record_validation(self):
        from interfaces.mcp import server

        path = self.records / "optimization_search-search-1.json"
        with patch.dict("os.environ", {"ANTI_REA_STATE_DIR": str(self.store)}):
            preview = server.preview_optimization_search(self.search)
            self.assertEqual(preview["status"], "approval_required")
            self.assertEqual(preview["runtime_identities"], self.search["runtime_identities"])
            self.assertFalse(path.exists())
            approved = server.approve_optimization_search(self.search)
            self.assertEqual(approved["status"], "approved")
            saved = workflow.read_record(path, "optimization_search")
            self.assertEqual(saved["decision_source"], "MCP tool invocation")

            self.proof_path.write_text(json.dumps({"record_type": "optimizer_compatibility"}))
            with self.assertRaisesRegex(workflow.WorkflowError, "evidence hash mismatch"):
                workflow.read_record(path, "optimization_search")


if __name__ == "__main__":
    unittest.main()
