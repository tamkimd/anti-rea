import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core import optimizer, workflow


class OptimizerReviewTests(unittest.TestCase):
    budgets = {
        "max_elapsed_ms": 1000,
        "max_total_elapsed_ms": 3000,
        "max_candidate_bytes": 1000,
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def candidate(self, candidate_id, elapsed, size, **changes):
        item = {
            "candidate_id": candidate_id,
            "run_id": "run-" + candidate_id,
            "source_sha256": "a" * 64,
            "runtime_sha256": "b" * 64,
            "artifact_sha256": "c" * 64,
            "correctness_passed": True,
            "integrity_passed": True,
            "elapsed_ms": elapsed,
            "candidate_bytes": size,
            **changes,
        }
        proof = {
            "schema_version": "1.0",
            "record_type": "optimizer_candidate_measurement",
            **item,
        }
        path = Path(self.temp.name) / f"{candidate_id}.json"
        raw = json.dumps(proof, sort_keys=True).encode()
        path.write_bytes(raw)
        item["evidence"] = {
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        return item

    def test_pareto_frontier_excludes_dominated_and_failed_candidates(self):
        result = optimizer.review_candidates(
            ["c1", "c2", "c3", "c4"],
            [
                self.candidate("c1", 100, 500),
                self.candidate("c2", 200, 400),
                self.candidate("c3", 300, 600),
                self.candidate("c4", 50, 100, correctness_passed=False),
            ],
            self.budgets,
        )
        self.assertEqual(result["status"], "candidates_available")
        self.assertEqual(
            [item["candidate_id"] for item in result["pareto_frontier"]], ["c1", "c2"]
        )
        self.assertEqual(
            result["rejected"],
            [{"candidate_id": "c4", "reason": "correctness_or_integrity_failed"}],
        )
        self.assertIsNone(result["selection"])
        self.assertTrue(result["independent_reevaluation_required"])

    def test_optimization_hash_checked_report_must_match_each_measurement(self):
        item = self.candidate("c1", 100, 100)
        item["elapsed_ms"] = 99
        with self.assertRaisesRegex(workflow.WorkflowError, "hash-checked report"):
            optimizer.review_candidates(["c1"], [item], self.budgets)

    def test_cli_returns_advisory_frontier_from_hash_checked_measurement_file(self):
        item = self.candidate("c1", 100, 100)
        payload = {
            "approved_candidate_ids": ["c1"],
            "measurements": [item],
            "budgets": self.budgets,
        }
        path = Path(self.temp.name) / "measurements.json"
        path.write_text(json.dumps(payload))
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        result = subprocess.run(
            [sys.executable, str(cli), "optimize-review", str(path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["record_type"], "optimization_review")
        self.assertEqual(report["pareto_frontier"][0]["candidate_id"], "c1")

    def test_independent_reevaluation_requires_matching_output_and_distinct_run(self):
        candidate = self.candidate("c1", 100, 100)
        reevaluation = {
            "schema_version": "1.0",
            "record_type": "optimizer_independent_reevaluation",
            **{
                key: candidate[key]
                for key in (
                    "candidate_id",
                    "source_sha256",
                    "runtime_sha256",
                    "artifact_sha256",
                    "candidate_bytes",
                )
            },
            "run_id": "independent-c1",
            "correctness_passed": True,
            "integrity_passed": True,
            "elapsed_ms": 120,
        }
        proof = dict(reevaluation)
        path = Path(self.temp.name) / "independent.json"
        raw = json.dumps(proof, sort_keys=True).encode()
        path.write_bytes(raw)
        reevaluation["evidence"] = {
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        result = optimizer.confirm_independent_reevaluation(
            candidate,
            reevaluation,
            {"max_elapsed_ms": 1000, "max_candidate_bytes": 1000},
        )
        self.assertEqual(result["status"], "independently_reevaluated")
        self.assertEqual(result["artifact_sha256"], candidate["artifact_sha256"])
        changed = dict(reevaluation, artifact_sha256="d" * 64)
        with self.assertRaisesRegex(
            workflow.WorkflowError, "identical inputs and output"
        ):
            optimizer.confirm_independent_reevaluation(
                candidate,
                changed,
                {"max_elapsed_ms": 1000, "max_candidate_bytes": 1000},
            )
        for invalid in (
            dict(reevaluation, run_id=""),
            dict(reevaluation, candidate_bytes=99),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(workflow.WorkflowError):
                    optimizer.confirm_independent_reevaluation(
                        candidate,
                        invalid,
                        {"max_elapsed_ms": 1000, "max_candidate_bytes": 1000},
                    )
        for key in ("elapsed_ms", "candidate_bytes"):
            original = dict(candidate, **{key: 1001})
            proof = {k: v for k, v in original.items() if k != "evidence"}
            proof.update(
                schema_version="1.0", record_type="optimizer_candidate_measurement"
            )
            evidence_path = Path(self.temp.name) / f"over-budget-{key}.json"
            raw = json.dumps(proof, sort_keys=True).encode()
            evidence_path.write_bytes(raw)
            original["evidence"] = {
                "path": str(evidence_path),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            rerun = dict(reevaluation, candidate_bytes=original["candidate_bytes"])
            if key == "candidate_bytes":
                rerun_proof = {k: v for k, v in rerun.items() if k != "evidence"}
                rerun_path = Path(self.temp.name) / "over-budget-rerun.json"
                rerun_raw = json.dumps(rerun_proof, sort_keys=True).encode()
                rerun_path.write_bytes(rerun_raw)
                rerun["evidence"] = {
                    "path": str(rerun_path),
                    "sha256": hashlib.sha256(rerun_raw).hexdigest(),
                }
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(
                    workflow.WorkflowError, "Original candidate exceeds"
                ),
            ):
                optimizer.confirm_independent_reevaluation(
                    original,
                    rerun,
                    {"max_elapsed_ms": 1000, "max_candidate_bytes": 1000},
                )

    def test_cli_confirms_independent_reevaluation(self):
        candidate = self.candidate("c1", 100, 100)
        reevaluation = {
            "schema_version": "1.0",
            "record_type": "optimizer_independent_reevaluation",
            **{
                key: candidate[key]
                for key in (
                    "candidate_id",
                    "source_sha256",
                    "runtime_sha256",
                    "artifact_sha256",
                    "candidate_bytes",
                )
            },
            "run_id": "independent-c1",
            "correctness_passed": True,
            "integrity_passed": True,
            "elapsed_ms": 120,
        }
        path = Path(self.temp.name) / "independent-cli.json"
        raw = json.dumps(reevaluation, sort_keys=True).encode()
        path.write_bytes(raw)
        reevaluation["evidence"] = {
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        paths = [
            Path(self.temp.name) / name
            for name in ("candidate.json", "reevaluation.json", "budgets.json")
        ]
        paths[0].write_text(json.dumps(candidate))
        paths[1].write_text(json.dumps(reevaluation))
        paths[2].write_text(
            json.dumps({"max_elapsed_ms": 1000, "max_candidate_bytes": 1000})
        )
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "optimize-confirm",
                *(str(path) for path in paths),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["status"], "independently_reevaluated"
        )

    def test_independent_reevaluation_rejects_same_run_or_failed_gates(self):
        candidate = self.candidate("c1", 100, 100)
        reevaluation = {
            "schema_version": "1.0",
            "record_type": "optimizer_independent_reevaluation",
            **{
                key: candidate[key]
                for key in (
                    "candidate_id",
                    "source_sha256",
                    "runtime_sha256",
                    "artifact_sha256",
                    "candidate_bytes",
                )
            },
            "run_id": candidate["run_id"],
            "correctness_passed": True,
            "integrity_passed": True,
            "elapsed_ms": 120,
            "evidence": {"path": "/missing", "sha256": "e" * 64},
        }
        with self.assertRaisesRegex(workflow.WorkflowError, "distinct run"):
            optimizer.confirm_independent_reevaluation(
                candidate,
                reevaluation,
                {"max_elapsed_ms": 1000, "max_candidate_bytes": 1000},
            )
        reevaluation["run_id"] = "independent"
        reevaluation["integrity_passed"] = False
        with self.assertRaisesRegex(
            workflow.WorkflowError, "correctness, integrity, or budget"
        ):
            optimizer.confirm_independent_reevaluation(
                candidate,
                reevaluation,
                {"max_elapsed_ms": 1000, "max_candidate_bytes": 1000},
            )

    def test_no_passing_candidates_and_total_budget_exhaustion_are_explicit(self):
        failed = self.candidate("c1", 100, 100, integrity_passed=False)
        result = optimizer.review_candidates(["c1"], [failed], self.budgets)
        self.assertEqual(result["status"], "no_acceptable_candidate")
        self.assertEqual(result["pareto_frontier"], [])
        slow = self.candidate("c1", 1001, 100)
        too_slow = optimizer.review_candidates(["c1"], [slow], self.budgets)
        self.assertEqual(too_slow["rejected"][0]["reason"], "candidate_over_budget")
        exhausted = optimizer.review_candidates(
            ["c1", "c2"],
            [self.candidate("c1", 800, 100), self.candidate("c2", 800, 100)],
            {**self.budgets, "max_total_elapsed_ms": 1000},
        )
        self.assertEqual(exhausted["status"], "budget_exhausted")
        self.assertEqual(exhausted["pareto_frontier"], [])

    def test_optimization_rejects_unapproved_or_incomparable_candidates(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "approved search space"):
            optimizer.review_candidates(
                ["approved"], [self.candidate("other", 1, 1)], self.budgets
            )
        other = self.candidate("c2", 2, 2, source_sha256="c" * 64)
        with self.assertRaisesRegex(workflow.WorkflowError, "share source and runtime"):
            optimizer.review_candidates(
                ["c1", "c2"], [self.candidate("c1", 1, 1), other], self.budgets
            )
        with self.assertRaisesRegex(workflow.WorkflowError, "one to four"):
            optimizer.review_candidates(["a", "b", "c", "d", "e"], [], self.budgets)

    def test_optimization_requires_a_distinct_execution_run_per_candidate(self):
        measurements = [
            self.candidate("c1", 100, 100, run_id="reused-run"),
            self.candidate("c2", 120, 110, run_id="reused-run"),
        ]
        with self.assertRaisesRegex(workflow.WorkflowError, "distinct execution run"):
            optimizer.review_candidates(["c1", "c2"], measurements, self.budgets)


if __name__ == "__main__":
    unittest.main()
