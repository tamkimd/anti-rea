from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import craft_anything_integration as craft


class CraftAnythingIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "argv.log"
        self.cli = self.root / "craft-anything-cli"
        self._write_cli()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_cli(self, behavior: str = "ok") -> None:
        capabilities = {
            "version": "0.6.0",
            "analysis_mode": "deep",
            "toolsets": [
                {
                    "id": "javascript",
                    "tools": [{"tool": "js_app_map", "available": True}],
                }
            ],
        }
        evidence = {
            "operation": "js_app_map",
            "coverage": {"status": "complete", "examined": 1, "total": 1},
            "result": {"modules_total": 1, "summary": "fixture analyzed"},
        }
        script = f'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
with open(os.environ["CRAFT_TEST_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\\n")
if "--version" in args:
    print("craft-anything-cli 0.6.0")
elif "capabilities" in args:
    behavior = os.environ.get("CRAFT_TEST_BEHAVIOR", "{behavior}")
    if behavior == "timeout":
        time.sleep(5)
    elif behavior == "malformed":
        print("not json")
    else:
        print(json.dumps({capabilities!r}))
elif "js-app-map" in args:
    behavior = os.environ.get("CRAFT_TEST_BEHAVIOR", "{behavior}")
    if behavior == "analysis-malformed":
        print("not json")
    else:
        evidence = {evidence!r}
        if behavior == "analysis-invalid-coverage":
            evidence["coverage"] = {{"status": "complete", "examined": 2, "total": 1}}
        print(json.dumps(evidence))
else:
    sys.exit(2)
'''
        self.cli.write_text(script, encoding="utf-8")
        self.cli.chmod(0o755)

    def _env(self, behavior: str = "ok") -> dict[str, str]:
        return {
            **os.environ,
            "CRAFT_TEST_LOG": str(self.log),
            "CRAFT_TEST_BEHAVIOR": behavior,
        }

    def _invoke(self, behavior: str = "ok", timeout: float = 1.0) -> dict:
        original = craft._run
        craft._run = lambda command, command_timeout, env=None: original(
            command,
            command_timeout,
            env=self._env(behavior),
        )
        try:
            return craft.analyze(
                self.root / "app.js", executable=self.cli, timeout=timeout
            )
        finally:
            craft._run = original

    def test_probe_reports_ready_for_supported_capability(self) -> None:
        original = craft._run
        craft._run = lambda command, timeout, env=None: original(
            command, timeout, env=self._env()
        )
        try:
            result = craft.probe(self.cli)
        finally:
            craft._run = original
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["supports_javascript_application"])
        self.assertEqual(result["version"], "0.6.0")

    def test_unavailable_cli_is_explicit(self) -> None:
        result = craft.probe(self.root / "missing")
        self.assertEqual(result["status"], "unavailable")

    def test_malformed_capability_output_fails_closed(self) -> None:
        original = craft._run
        craft._run = lambda command, timeout, env=None: original(
            command, timeout, env=self._env("malformed")
        )
        try:
            result = craft.probe(self.cli)
        finally:
            craft._run = original
        self.assertEqual(result["status"], "failed")
        self.assertIn("JSON", result["reason"])

    def test_version_mismatch_is_unavailable(self) -> None:
        original = craft._run
        craft._run = lambda command, timeout, env=None: original(
            command, timeout, env=self._env()
        )
        try:
            result = craft.probe(self.cli, expected_version="0.5.0")
        finally:
            craft._run = original
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("Expected", result["reason"])

    def test_probe_timeout_is_explicit(self) -> None:
        original = craft._run
        craft._run = lambda command, timeout, env=None: original(
            command, timeout, env=self._env("timeout")
        )
        try:
            result = craft.probe(self.cli, timeout=0.05)
        finally:
            craft._run = original
        self.assertEqual(result["status"], "timeout")

    def test_analysis_records_evidence_and_leaves_target_unchanged(self) -> None:
        target = self.root / "app.js"
        target.write_text("const app = true;\n", encoding="utf-8")
        before = craft._hash_input(target)
        result = self._invoke()
        after = craft._hash_input(target)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["engine"], "craft-anything")
        self.assertEqual(result["version"], "0.6.0")
        self.assertEqual(result["mode"], "deep")
        self.assertEqual(result["input_sha256"], before)
        self.assertEqual(result["input_sha256_after"], after)
        self.assertTrue(result["input_unchanged"])
        self.assertEqual(result["coverage"]["examined"], 1)
        calls = [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(calls), 3)
        self.assertIn("js-app-map", calls[2])
        self.assertIn("--input-path", calls[2])

    def test_analysis_timeout_is_partial_and_preserves_target(self) -> None:
        target = self.root / "app.js"
        target.write_text("const app = true;\n", encoding="utf-8")
        before = craft._hash_input(target)
        result = self._invoke("timeout", timeout=0.05)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["engine_status"], "timeout")
        self.assertEqual(craft._hash_input(target), before)

    def test_malformed_analysis_is_partial(self) -> None:
        target = self.root / "app.js"
        target.write_text("const app = true;\n", encoding="utf-8")
        result = self._invoke("analysis-malformed")
        self.assertEqual(result["status"], "partial")
        self.assertIn("valid JSON", result["reason"])

    def test_inconsistent_complete_coverage_is_not_a_successful_analysis(self) -> None:
        target = self.root / "app.js"
        target.write_text("const app = true;\n", encoding="utf-8")
        result = self._invoke("analysis-invalid-coverage")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["engine_status"], "failed")
        self.assertIn("coverage counts", result["reason"])

    def test_unsupported_artifact_does_not_run_cli(self) -> None:
        target = self.root / "app.py"
        target.write_text("print('unchanged')\n", encoding="utf-8")
        result = craft.analyze(target, executable=self.cli)
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
