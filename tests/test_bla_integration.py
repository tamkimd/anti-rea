import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import bla_integration as bla


class BLAIntegrationTests(unittest.TestCase):
    def test_node_policy_matches_pinned_requirement(self):
        self.assertFalse(bla.supported_node((22, 23, 3)))
        self.assertTrue(bla.supported_node((22, 23, 4)))
        self.assertFalse(bla.supported_node((23, 0, 0)))
        self.assertTrue(bla.supported_node((24, 0, 0)))
        self.assertTrue(bla.supported_node((26, 0, 0)))

    def test_bootstrap_cleans_its_partial_runtime_after_install_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "bla-runtime"
            with (
                mock.patch.object(
                    bla.runner, "node_version", return_value=("v24.22.1", (24, 22, 1))
                ),
                mock.patch.object(
                    bla.runner,
                    "run_bounded",
                    return_value=subprocess.CompletedProcess(
                        ["npm"], 1, "", "install failed"
                    ),
                ),
            ):
                with self.assertRaisesRegex(bla.IntegrationError, "npm ci failed"):
                    bla.bootstrap(runtime)
            self.assertFalse(runtime.exists())

    def test_runtime_verification_rejects_unpinned_lock(self):
        with self.assertRaisesRegex(bla.IntegrationError, "lock"):
            bla.verify_runtime(Path(__file__).parent)

    def test_protection_refuses_source_overwrite_and_existing_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.js"
            source.write_text("export const x = 1;\n")
            with self.assertRaisesRegex(bla.IntegrationError, "new file"):
                bla.protect_javascript("unused", source, source, root / "report.json")

    def test_protection_rejects_candidate_symlink_output_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            source = root / "app.js"
            source.write_text("export const x = 1;\n")
            outside = root / "outside.js"
            outside.write_text("keep me")
            candidates = root / "candidates"
            candidates.mkdir()
            candidate = candidates / "candidate.js"
            report = root / "report.json"

            def symlink_runner(command, *args, **kwargs):
                Path(command[command.index("--output") + 1]).symlink_to(outside)
                return subprocess.CompletedProcess(command, 0, "{}", "")

            with (
                mock.patch.object(
                    bla,
                    "verify_runtime",
                    return_value=(runtime, {"package_tree_sha256": "x"}),
                ),
                mock.patch.object(
                    bla.runner, "run_bounded", side_effect=symlink_runner
                ),
            ):
                with self.assertRaisesRegex(
                    bla.IntegrationError, "regular candidate file"
                ):
                    bla.protect_javascript(runtime, source, candidate, report)
            self.assertEqual(outside.read_text(), "keep me")
            self.assertFalse(candidate.exists())
            self.assertFalse(candidate.is_symlink())
            self.assertTrue(report.is_file())

    def test_protection_removes_malformed_directory_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            source = root / "app.js"
            source.write_text("export const x = 1;\n")
            candidate = root / "candidate.js"
            report = root / "report.json"

            def malformed_runner(command, *args, **kwargs):
                Path(command[command.index("--output") + 1]).mkdir()
                return subprocess.CompletedProcess(command, 0, "{}", "")

            with (
                mock.patch.object(
                    bla,
                    "verify_runtime",
                    return_value=(runtime, {"package_tree_sha256": "x"}),
                ),
                mock.patch.object(
                    bla.runner, "run_bounded", side_effect=malformed_runner
                ),
            ):
                with self.assertRaisesRegex(bla.IntegrationError, "regular candidate"):
                    bla.protect_javascript(runtime, source, candidate, report)
            self.assertFalse(candidate.exists())

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_BLA_RUNTIME"),
        "set ANTI_REA_BLA_RUNTIME for live BLA package checks",
    )
    def test_live_pinned_runtime_version_and_cli_contract(self):
        runtime = Path(os.environ["ANTI_REA_BLA_RUNTIME"])
        self.assertEqual(bla.probe(runtime)["version"], "1.6.3")
        self.assertEqual(bla.cli_help(runtime)["status"], "passed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "before.js"
            candidate = root / "after.js"
            protect_report = root / "protect-report.json"
            verify_report = root / "verify-report.json"
            source.write_text(
                "export function greet(name) { return `Hello, ${name}!`; }\n"
            )
            original = source.read_bytes()
            protected = bla.protect_javascript(
                runtime, source, candidate, protect_report, seed="fixture-v2"
            )
            verified = bla.verify_javascript(runtime, source, candidate, verify_report)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(protected["status"], verified["status"])
            code = (
                f"const a=await import({json.dumps(source.as_uri())});"
                f"const b=await import({json.dumps(candidate.as_uri())});"
                "if(a.greet('Ada')!==b.greet('Ada')||b.greet('Ada')!=='Hello, Ada!')process.exit(1);"
            )
            result = subprocess.run(
                [shutil.which("node"), "--input-type=module", "-e", code],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
