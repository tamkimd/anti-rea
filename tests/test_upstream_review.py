import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import upstream_review
from core.workflow import WorkflowError

ROOT = Path(__file__).parents[1]


class UpstreamReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "locks").mkdir()
        (self.root / "integrations/rea").mkdir(parents=True)
        (self.root / "integrations/e2e").mkdir(parents=True)
        (self.root / "integrations/bla").mkdir(parents=True)
        stable = json.loads((ROOT / "locks/upstreams.json").read_text())
        self.manifest = self.root / "locks/upstreams.json"
        self._copy_pinned_files(stable)
        self.manifest.write_text(json.dumps(stable))

    def _copy_pinned_files(self, manifest):
        for pin in manifest["integrations"].values():
            lock = pin.get("package_lock")
            if lock:
                source = ROOT / lock
                destination = self.root / lock
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)

    def test_unchanged_candidate_has_verified_locks_and_no_promotion_request(self):
        result = upstream_review.review(self.manifest)
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["changed_engines"], [])
        self.assertEqual(result["promotion"], "not_authorized")
        self.assertTrue(
            all(
                result["engines"][name]["candidate_lock"]["status"] == "verified"
                for name in ("rea", "e2e", "bla")
            )
        )

    def test_cli_emits_candidate_review(self):
        cli = ROOT / "interfaces/cli/anti_rea.py"
        result = subprocess.run(
            [sys.executable, str(cli), "upstream-review", str(self.manifest)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "unchanged")

    def test_changed_pin_lists_affected_checks_and_requires_human_promotion_review(
        self,
    ):
        value = json.loads(self.manifest.read_text())
        pin = value["integrations"]["bla"]
        lock_path = self.root / pin["package_lock"]
        lock = json.loads(lock_path.read_text())
        lock["packages"]["node_modules/bla-agents"]["version"] = "1.6.4"
        lock["packages"]["node_modules/bla-agents"]["integrity"] = "sha512-candidate"
        raw = json.dumps(lock, separators=(",", ":")).encode()
        lock_path.write_bytes(raw)
        pin["npm_version"] = "1.6.4"
        pin["npm_integrity"] = "sha512-candidate"
        pin["package_lock_sha256"] = hashlib.sha256(raw).hexdigest()
        self.manifest.write_text(json.dumps(value))
        result = upstream_review.review(self.manifest)
        self.assertEqual(result["changed_engines"], ["bla"])
        self.assertEqual(result["engines"]["bla"]["status"], "review_required")
        self.assertIn(
            "tests.test_bla_integration", result["engines"]["bla"]["verification_lanes"]
        )
        self.assertEqual(result["promotion"], "not_authorized")
        self.assertIn(
            "compare contracts and capabilities", result["required_before_promotion"]
        )

    def test_candidate_lock_hash_mismatch_fails_closed(self):
        value = json.loads(self.manifest.read_text())
        lock_path = self.root / value["integrations"]["bla"]["package_lock"]
        lock_path.write_bytes(lock_path.read_bytes() + b" ")
        with self.assertRaisesRegex(WorkflowError, "SHA-256"):
            upstream_review.review(self.manifest)

    def test_candidate_lock_path_traversal_is_rejected(self):
        value = json.loads(self.manifest.read_text())
        value["integrations"]["bla"]["package_lock"] = "../../outside.json"
        self.manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(WorkflowError, "stay inside"):
            upstream_review.review(self.manifest)

    def test_candidate_manifest_hash_binds_the_bytes_that_were_parsed(self):
        original_bytes = self.manifest.read_bytes()
        read_lock = upstream_review._lock_identity
        mutated = False

        def read_then_mutate(root, name, pin):
            nonlocal mutated
            result = read_lock(root, name, pin)
            if root == self.root.resolve() and not mutated:
                mutated = True
                self.manifest.write_text("{}")
            return result

        with patch.object(
            upstream_review, "_lock_identity", side_effect=read_then_mutate
        ):
            result = upstream_review.review(self.manifest)
        self.assertTrue(mutated)
        self.assertEqual(
            result["candidate_manifest_sha256"],
            hashlib.sha256(original_bytes).hexdigest(),
        )
        self.assertNotEqual(self.manifest.read_bytes(), original_bytes)

    def test_symlinked_candidate_lock_is_rejected(self):
        pin = json.loads(self.manifest.read_text())["integrations"]["bla"]
        lock_path = self.root / pin["package_lock"]
        lock_path.unlink()
        lock_path.symlink_to(ROOT / pin["package_lock"])
        with self.assertRaisesRegex(WorkflowError, "safely read"):
            upstream_review.review(self.manifest)

    def test_upstream_reads_fail_closed_without_nofollow(self):
        with patch.object(upstream_review.os, "O_NOFOLLOW", 0):
            with self.assertRaisesRegex(
                WorkflowError, "no-follow directory-relative reads"
            ):
                upstream_review._read_manifest(self.manifest)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_upstream_manifest_and_lock_fifos_are_rejected_without_blocking(self):
        lock = self.root / "integrations/rea/package-lock.json"
        for path, code, args in (
            (
                self.manifest,
                "import sys; from core.upstream_review import _read_manifest; _read_manifest(sys.argv[1])",
                (str(self.manifest),),
            ),
            (
                lock,
                "import sys; from pathlib import Path; from core.upstream_review import _read_lock; "
                "_read_lock(Path(sys.argv[1]), Path(sys.argv[2]), 'REA package lock')",
                (str(self.root), "integrations/rea/package-lock.json"),
            ),
        ):
            path.unlink()
            os.mkfifo(path)
            result = subprocess.run(
                [sys.executable, "-c", code, *args],
                capture_output=True,
                text=True,
                timeout=2,
                cwd=ROOT,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be a regular file", result.stderr)

    def test_capability_diff_reports_surface_changes_and_internal_drift(self):
        stable_path = ROOT / "locks/rea-source-runtime-ledger.json"
        candidate_path = self.root / "candidate-ledger.json"
        candidate = json.loads(stable_path.read_text())
        candidate["upstream"]["version"] = "6.9.0"
        candidate["source"]["mcp_tools"].append("new_source_tool")
        candidate["runtime"]["mcp_tools"].remove(candidate["runtime"]["mcp_tools"][0])
        candidate_path.write_text(json.dumps(candidate))

        result = upstream_review.compare_capability_files(stable_path, candidate_path)
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["promotion"], "not_authorized")
        self.assertIn("new_source_tool", result["changes"]["mcp_tools"]["source_added"])
        self.assertTrue(result["changes"]["mcp_tools"]["runtime_removed"])
        self.assertIn("mcp_tools", result["candidate_source_runtime_drift"])
        self.assertEqual(len(result["candidate_ledger_sha256"]), 64)

    def test_capability_diff_rejects_duplicate_or_missing_surfaces(self):
        ledger = json.loads((ROOT / "locks/rea-source-runtime-ledger.json").read_text())
        duplicate = json.loads(json.dumps(ledger))
        duplicate["source"]["cli_commands"].append(
            duplicate["source"]["cli_commands"][0]
        )
        with self.assertRaisesRegex(WorkflowError, "invalid source cli_commands"):
            upstream_review.compare_capability_ledgers(ledger, duplicate)
        missing = json.loads(json.dumps(ledger))
        del missing["runtime"]["mcp_tools"]
        with self.assertRaisesRegex(WorkflowError, "invalid runtime mcp_tools"):
            upstream_review.compare_capability_ledgers(ledger, missing)

    def test_capability_diff_flags_schema_change_without_name_change(self):
        ledger = json.loads((ROOT / "locks/rea-source-runtime-ledger.json").read_text())
        candidate = json.loads(json.dumps(ledger))
        candidate["upstream"]["version"] = "6.9.0"
        candidate["runtime"]["mcp_tool_contracts_sha256"] = "f" * 64
        result = upstream_review.compare_capability_ledgers(ledger, candidate)
        self.assertTrue(result["runtime_tool_contract_sha256"]["changed"])
        self.assertEqual(result["changes"], {})
        self.assertEqual(result["status"], "review_required")

    def test_capability_diff_reports_source_and_runtime_identity_mismatch(self):
        stable = json.loads((ROOT / "locks/rea-source-runtime-ledger.json").read_text())
        candidate = json.loads(json.dumps(stable))
        candidate["upstream"]["source_commit"] = "f" * 40
        candidate["runtime"]["version"] = "6.7.9"
        candidate["runtime"]["npm_integrity"] = "sha512-mismatch"
        result = upstream_review.compare_capability_ledgers(stable, candidate)
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(
            result["candidate_identity_drift"]["source_commit"],
            {"declared": "f" * 40, "observed": stable["source"]["source_commit"]},
        )
        self.assertEqual(
            result["candidate_identity_drift"]["runtime_version"],
            {"declared": stable["upstream"]["version"], "observed": "6.7.9"},
        )
        self.assertIn("runtime_npm_integrity", result["candidate_identity_drift"])

    def test_capability_ledger_requires_source_runtime_identity_fields(self):
        stable = json.loads((ROOT / "locks/rea-source-runtime-ledger.json").read_text())
        candidate = json.loads(json.dumps(stable))
        del candidate["runtime"]["npm_integrity"]
        with self.assertRaisesRegex(
            WorkflowError, "incomplete runtime package identity"
        ):
            upstream_review.compare_capability_ledgers(stable, candidate)

    def test_capability_diff_flags_source_only_identity_changes(self):
        stable = json.loads((ROOT / "locks/rea-source-runtime-ledger.json").read_text())
        candidate = json.loads(json.dumps(stable))
        candidate["source"]["source_commit"] = "d" * 40
        candidate["upstream"]["source_commit"] = "d" * 40
        candidate["source"]["files_sha256"]["src/TOOL_CONTRACTS.ts"] = "a" * 64

        result = upstream_review.compare_capability_ledgers(stable, candidate)
        self.assertEqual(result["status"], "review_required")
        self.assertIn("source_commit", result["source_identity_changes"])
        self.assertIn(
            "src/TOOL_CONTRACTS.ts", result["source_identity_changes"]["files_sha256"]
        )
        self.assertEqual(result["runtime_identity_changes"], {})
        self.assertTrue(result["identity_changed"])

    def test_capability_diff_flags_consistent_source_and_runtime_identity_changes(self):
        stable = json.loads((ROOT / "locks/rea-source-runtime-ledger.json").read_text())
        candidate = json.loads(json.dumps(stable))
        candidate["source"]["source_commit"] = "d" * 40
        candidate["upstream"]["source_commit"] = "d" * 40
        candidate["source"]["files_sha256"]["src/TOOL_CONTRACTS.ts"] = "a" * 64
        runtime = candidate["runtime"]
        candidate["upstream"]["package"] = runtime["package"] = "rea-agents-next"
        candidate["upstream"]["version"] = runtime["version"] = "6.9.0"
        candidate["upstream"]["npm_integrity"] = runtime["npm_integrity"] = (
            "sha512-next"
        )
        runtime["package_lock_sha256"] = "b" * 64
        runtime["runtime_manifest_sha256"] = "c" * 64
        runtime["node_version"] = "v24.23.0"

        result = upstream_review.compare_capability_ledgers(stable, candidate)
        self.assertEqual(result["status"], "review_required")
        self.assertIn("source_commit", result["source_identity_changes"])
        self.assertIn(
            "src/TOOL_CONTRACTS.ts", result["source_identity_changes"]["files_sha256"]
        )
        self.assertEqual(
            set(result["runtime_identity_changes"]),
            {
                "package",
                "version",
                "npm_integrity",
                "package_lock_sha256",
                "runtime_manifest_sha256",
                "node_version",
            },
        )
        self.assertTrue(result["identity_changed"])

    def test_capability_diff_cli_emits_hash_bound_review(self):
        stable = ROOT / "locks/rea-source-runtime-ledger.json"
        candidate = json.loads(stable.read_text())
        candidate["upstream"]["version"] = "6.9.0"
        candidate_path = self.root / "candidate-ledger.json"
        candidate_path.write_text(json.dumps(candidate))
        cli = ROOT / "interfaces/cli/anti_rea.py"
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "upstream-capabilities",
                str(stable),
                str(candidate_path),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "review_required")
        self.assertEqual(report["promotion"], "not_authorized")
        self.assertEqual(
            report["candidate_ledger_sha256"],
            hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
