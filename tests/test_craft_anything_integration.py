import hashlib
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from core import craft_anything_integration as craft
from core import workflow


class CraftAnythingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target.bin"
        self.target.write_bytes(b"original artifact")
        self.workspace = self.root / "external"

    def tearDown(self):
        self.temp.cleanup()

    def fake_cli(self, body, version="0.6.0"):
        executable = self.root / "craft-anything-cli"
        executable.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys, time\n"
            "if '--version' in sys.argv: print('craft-anything-cli "
            + version
            + "'); raise SystemExit(0)\n"
            + body
        )
        executable.chmod(0o700)
        return str(executable)

    def test_probe_requires_exact_pinned_version(self):
        cli = self.fake_cli("print('{}')\n", version="0.6.1")
        result = craft.probe(cli)
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("requires Craft Anything CLI 0.6.0", result["reason"])

    def test_missing_cli_is_unavailable_without_downloading(self):
        result = craft.probe(str(self.root / "missing"))
        self.assertEqual(result["status"], "unavailable")

    def test_triage_uses_only_read_only_deep_command_and_records_json(self):
        cli = self.fake_cli(
            "assert sys.argv[1:] == ['--deep', '--project', sys.argv[3], '--output-format', 'json', 'triage', "
            "sys.argv[-1]]\n"
            "print(json.dumps({'result': {'kind': 'file'}, 'coverage': 1.0}))\n"
        )
        result = craft.analyze(self.target, self.workspace, cli=cli)
        self.assertEqual(result["status"], "supported")
        self.assertEqual(result["version"], "0.6.0")
        self.assertEqual(result["input"]["sha256"], result["input"]["sha256_after"])
        self.assertEqual(result["evidence"]["result"]["kind"], "file")
        self.assertNotIn("--allow-run", result["command"])
        self.assertNotIn("rebuild", result["command"])
        self.assertNotIn("chat", result["command"])
        self.assertTrue(Path(result["project"]).is_dir())
        self.assertTrue(
            Path(result["project"]).is_relative_to(self.workspace.resolve())
        )
        self.assertEqual(
            stat.S_IMODE(Path(result["project"]).parent.stat().st_mode), 0o700
        )

    def test_normalized_evidence_can_be_persisted_privately(self):
        report = self.workspace / "craft-evidence.json"
        cli = self.fake_cli("print(json.dumps({'z': 1, 'a': 2}))\n")
        result = craft.analyze(self.target, self.workspace, cli=cli, report_path=report)
        self.assertEqual(report.read_text(), result["evidence_json"])
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(result["evidence_path"], str(report))
        self.assertEqual(
            result["evidence_sha256"], hashlib.sha256(report.read_bytes()).hexdigest()
        )

    def test_directory_input_and_explicit_partial_evidence(self):
        target = self.root / "bundle"
        target.mkdir()
        (target / "app.bin").write_bytes(b"payload")
        cli = self.fake_cli(
            "print(json.dumps({'status': 'partial', 'coverage': 0.5}))\n"
        )
        result = craft.analyze(target, self.workspace, cli=cli)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["input"]["sha256"], result["input"]["sha256_after"])

    def test_unavailable_cli_does_not_create_external_workspace_or_project(self):
        result = craft.analyze(
            self.target, self.workspace, cli=str(self.root / "missing")
        )
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(self.workspace.exists())
        self.assertIsNone(result["evidence"])

    def test_invalid_json_is_failed(self):
        cli = self.fake_cli("print('not json')\n")
        result = craft.analyze(self.target, self.workspace, cli=cli)
        self.assertEqual(result["status"], "failed")
        self.assertIn("invalid JSON", result["error"])

    def test_timeout_is_failed(self):
        cli = self.fake_cli("time.sleep(5)\n")
        result = craft.analyze(self.target, self.workspace, cli=cli, timeout=0.2)
        self.assertEqual(result["status"], "failed")
        self.assertIn("timed out", result["error"])

    def test_cancellation_stops_triage_process(self):
        cli = self.fake_cli("time.sleep(5)\n")
        cancel = threading.Event()
        timer = threading.Timer(0.2, cancel.set)
        timer.start()
        try:
            result = craft.analyze(
                self.target, self.workspace, cli=cli, timeout=5, cancel_event=cancel
            )
        finally:
            timer.cancel()
        self.assertEqual(result["status"], "failed")
        self.assertIn("cancelled", result["error"])

    def test_target_mutation_is_detected_after_analysis(self):
        cli = self.fake_cli(
            "pathlib.Path(sys.argv[-1]).write_bytes(b'mutated')\n"
            "print(json.dumps({'result': 'done'}))\n"
        )
        result = craft.analyze(self.target, self.workspace, cli=cli)
        self.assertEqual(result["status"], "failed")
        self.assertIn("modified the input", result["error"])

    def test_workspace_must_be_external_and_symlinks_are_refused(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "outside the target"):
            craft.analyze(
                self.target, self.target.parent, cli=self.fake_cli("print('{}')\n")
            )
        link = self.root / "link"
        link.symlink_to(self.target)
        with self.assertRaisesRegex(workflow.WorkflowError, "must not be a symlink"):
            craft.analyze(link, self.workspace, cli=self.fake_cli("print('{}')\n"))


if __name__ == "__main__":
    unittest.main()
