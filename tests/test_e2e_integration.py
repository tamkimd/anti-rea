import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import e2e_integration as e2e


class E2EIntegrationTests(unittest.TestCase):
    def test_bootstrap_removes_owned_partial_runtime_on_copy_or_interrupt(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            with (
                patch.object(e2e, "require_supported_node"),
                patch.object(e2e.shutil, "copy2", side_effect=OSError("copy failed")),
            ):
                with self.assertRaisesRegex(OSError, "copy failed"):
                    e2e.bootstrap(runtime)
            self.assertFalse(runtime.exists())
            with (
                patch.object(e2e, "require_supported_node"),
                patch.object(e2e, "run_bounded", side_effect=KeyboardInterrupt),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    e2e.bootstrap(runtime)
            self.assertFalse(runtime.exists())

    def test_run_bounded_preserves_small_text_output_and_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            result = e2e.run_bounded(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)",
                ],
                directory,
                5,
            )
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "out\n")
        self.assertEqual(result.stderr, "err\n")

    def test_explicit_e2e_node_is_used_and_added_to_child_path(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "node"
            executable.write_text("#!/bin/sh\nprintf 'v22.23.3\\n'\n")
            executable.chmod(0o700)
            with patch.dict(
                os.environ, {"ANTI_REA_E2E_NODE": str(executable), "PATH": "/usr/bin"}
            ):
                self.assertEqual(e2e.node_version()[0], "v22.23.3")
                self.assertEqual(
                    Path(e2e.node_environment()["PATH"].split(os.pathsep)[0]),
                    Path(directory).resolve(),
                )

    @unittest.skipUnless(os.name == "posix", "process-group cleanup is POSIX-specific")
    def test_run_bounded_rejects_live_process_that_exceeds_combined_output_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            command = [
                sys.executable,
                "-c",
                (
                    "import sys, time; "
                    "sys.stdout.buffer.write(b'o' * (5 * 1024 * 1024)); sys.stdout.flush(); "
                    "sys.stderr.buffer.write(b'e' * (5 * 1024 * 1024)); sys.stderr.flush(); "
                    "time.sleep(30)"
                ),
            ]
            real_popen = subprocess.Popen
            processes = []

            def record_process(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            started = time.monotonic()
            with patch.object(e2e.subprocess, "Popen", side_effect=record_process):
                with self.assertRaisesRegex(
                    e2e.IntegrationError, "output exceeded 8 MiB"
                ):
                    e2e.run_bounded(command, directory, 20)
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].poll())

    def test_browser_performance_marker_requires_three_finite_nonnegative_metrics(self):
        report = {
            "run": {
                "results": [
                    {
                        "kind": "test",
                        "selected": True,
                        "attempts": [
                            {
                                "appLog": [
                                    {
                                        "text": e2e.PERFORMANCE_MARKER
                                        + json.dumps(
                                            {
                                                "dom_content_loaded_ms": 10.5,
                                                "load_event_ms": 12,
                                                "interaction_ms": 8,
                                            }
                                        )
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        }
        self.assertEqual(
            e2e.report_performance_metrics(report),
            {"dom_content_loaded_ms": 10.5, "load_event_ms": 12, "interaction_ms": 8},
        )
        malformed = json.loads(json.dumps(report))
        malformed["run"]["results"][0]["attempts"][0]["appLog"][0]["text"] = (
            e2e.PERFORMANCE_MARKER
            + json.dumps(
                {
                    "dom_content_loaded_ms": True,
                    "load_event_ms": 12,
                    "interaction_ms": 8,
                }
            )
        )
        with self.assertRaisesRegex(
            e2e.IntegrationError, "outside the accepted contract"
        ):
            e2e.report_performance_metrics(malformed)

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for upstream schema validation",
    )
    def test_saved_fixture_report_matches_upstream_schema(self):
        runtime = Path(os.environ["ANTI_REA_E2E_RUNTIME"])
        report = json.loads(
            (
                Path(__file__).parents[1] / "evidence/fixtures/e2e/report.json"
            ).read_text()
        )
        e2e.validate_report(report, runtime)

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for upstream schema validation",
    )
    def test_malformed_report_is_rejected_by_upstream_schema(self):
        runtime = Path(os.environ["ANTI_REA_E2E_RUNTIME"])
        report = {"schemaVersion": "unknown", "run": {}}
        with self.assertRaisesRegex(e2e.IntegrationError, "report-v1 schema"):
            e2e.validate_report(report, runtime)

    def test_owned_fixture_source_is_complete(self):
        fixture = Path(__file__).parents[1] / "fixtures/e2e/web"
        self.assertTrue((fixture / "server.cjs").is_file())
        self.assertTrue((fixture / "e2e.config.mjs").is_file())
        self.assertTrue((fixture / "tests/behavior.e2e.ts").is_file())

    def test_owned_pwa_fixture_source_is_complete_and_scoped(self):
        root = Path(__file__).parents[1]
        fixture = root / "fixtures/e2e/pwa"
        for relative in ("server.cjs", "e2e.config.mjs", "tests/behavior.e2e.ts"):
            self.assertTrue((fixture / relative).is_file())
        test_source = (fixture / "tests/behavior.e2e.ts").read_text()
        self.assertIn("pwa-fixture-v1", test_source)
        self.assertIn("registration.update()", test_source)
        self.assertIn(
            "cached fallback failed while network was unavailable", test_source
        )
        self.assertIn("registration.unregister()", test_source)

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for pinned browser execution",
    )
    def test_upstream_pwa_fixture_update_and_cleanup(self):
        runtime = Path(os.environ["ANTI_REA_E2E_RUNTIME"]).resolve(strict=True)
        project = runtime / "pwa-fixture-test"
        e2e.create_fixture(runtime, project, "pwa")
        try:
            result = e2e.run(project, runtime, ".e2e/pwa-test-run", "fixture")
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["summary"]["passed"], 1)
            self.assertEqual(result["cleanup"], "loopback app port closed")
        finally:
            shutil.rmtree(project, ignore_errors=True)

    def test_config_and_test_paths_refuse_escape_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "e2e.config.mjs").write_text("export default {}")
            (project / "test.ts").write_text("export {}")
            self.assertEqual(e2e._project_file(project, "test.ts"), Path("test.ts"))
            with self.assertRaisesRegex(e2e.IntegrationError, "stay inside"):
                e2e._project_file(project, "../test.ts")
            outside = root / "outside.ts"
            outside.write_text("export {}")
            (project / "linked.ts").symlink_to(outside)
            with self.assertRaisesRegex(e2e.IntegrationError, "symlinks"):
                e2e._project_file(project, "linked.ts")

    def test_run_requires_the_node_version_recorded_by_the_runtime(self):
        manifest = {"node_version": "v24.22.1"}
        with (
            patch.object(
                e2e, "verify_runtime", return_value=(Path("/runtime"), manifest)
            ),
            patch.object(e2e, "require_supported_node", return_value="v22.23.4"),
        ):
            with self.assertRaisesRegex(
                e2e.IntegrationError, "differs from the pinned e2e runtime"
            ):
                e2e.run("/missing-project", "/runtime", ".e2e/run", "fixture")

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for the pinned upstream smoke test",
    )
    def test_upstream_web_engine_report_and_cleanup(self):
        runtime = Path(os.environ["ANTI_REA_E2E_RUNTIME"]).resolve(strict=True)
        project = runtime / "fixture-test"
        e2e.create_fixture(runtime, project)
        try:
            result = e2e.run(project, runtime, ".e2e/test-run", "fixture")
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["summary"]["passed"], 1)
            self.assertEqual(result["cleanup"], "loopback app port closed")
        finally:
            shutil.rmtree(project, ignore_errors=True)

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for the pinned upstream smoke test",
    )
    def test_failed_browser_assertion_returns_report_after_cleanup(self):
        runtime = Path(os.environ["ANTI_REA_E2E_RUNTIME"]).resolve(strict=True)
        project = runtime / "fixture-failure-test"
        e2e.create_fixture(runtime, project)
        try:
            test_file = project / "tests/behavior.e2e.ts"
            test_file.write_text(
                test_file.read_text().replace("Hello, Ada!", "wrong greeting")
            )
            result = e2e.run(project, runtime, ".e2e/test-failure", "fixture")
            self.assertEqual(result["status"], "failed")
            self.assertGreater(result["summary"]["failed"], 0)
            self.assertEqual(result["cleanup"], "loopback app port closed")
            self.assertTrue(Path(result["report"]).is_file())
        finally:
            shutil.rmtree(project, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
