import ctypes
import hashlib
import io
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from functools import partial
from pathlib import Path
from unittest.mock import MagicMock, patch

import jsonschema

from core import baseline, workflow
from interfaces.cli import anti_rea as cli


@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class BaselineCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.project = base / "project"
        self.project.mkdir()
        (self.project / "pyproject.toml").write_text("[project]\nname='fixture'\n")
        (self.project / "build.py").write_text(
            "from pathlib import Path\nPath('dist.bin').write_bytes(b'baseline')\nprint('built')\n"
        )
        self.store = base / "state"

    def tearDown(self):
        self.temp.cleanup()

    def test_capture_records_build_output_and_artifact_hash(self):
        record, evidence = baseline.capture(
            self.project,
            self.store,
            [sys.executable, "build.py"],
            ["dist.bin"],
            "before-1",
        )
        self.assertEqual(record["identity"]["artifacts"]["dist.bin"]["size"], 8)
        self.assertEqual(json.loads(evidence.read_text())["stdout"], "built\n")
        self.assertIsInstance(record["identity"]["build_duration_ms"], int)
        self.assertGreaterEqual(record["identity"]["build_duration_ms"], 0)
        snapshot = Path(record["identity"]["build_snapshot"]["path"])
        self.assertTrue((snapshot / "dist.bin").is_file())
        self.assertFalse((self.project / "dist.bin").exists())
        self.assertEqual(
            json.loads(evidence.read_text())["argv"], [sys.executable, "build.py"]
        )
        self.assertEqual(
            workflow.read_record(
                self.store / "records" / "baseline-before-1.json", "baseline"
            ),
            record,
        )
        self.assertFalse(self.store.is_relative_to(self.project))

    def test_baseline_runs_rea_and_craft_concurrently_and_keeps_partial_results(self):
        rea_started = threading.Event()
        craft_started = threading.Event()
        report_path = self.store / "evidence" / "craft-before.json"

        def fake_rea(*args, **kwargs):
            rea_started.set()
            self.assertTrue(craft_started.wait(2))
            raise workflow.WorkflowError("fake REA provider failed")

        def fake_craft(
            snapshot,
            state,
            baseline_id,
            cli,
            timeout,
            cancel_event=None,
            on_process=None,
        ):
            craft_started.set()
            self.assertTrue(rea_started.wait(2))
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text('{"summary":"triaged"}')
            return (
                {
                    "engine": "craft-anything",
                    "status": "passed",
                    "mode": "deep",
                    "version": "0.6.0",
                    "input_sha256": "c" * 64,
                    "coverage": {"files": 1},
                    "evidence": {
                        "path": str(report_path),
                        "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                    },
                },
                report_path,
            )

        with (
            patch.object(baseline, "_capture_rea", side_effect=fake_rea),
            patch.object(baseline, "_capture_craft_anything", side_effect=fake_craft),
        ):
            (self.project / "build.py").write_text(
                "from pathlib import Path\nPath('dist.js').write_text('built')\n"
            )
            record, _ = baseline.capture(
                self.project,
                self.store,
                [sys.executable, "build.py"],
                ["dist.js"],
                "parallel-engines",
                rea_runtime="pinned-rea-runtime",
            )
        engines = record["identity"]["analysis_engines"]
        self.assertEqual(engines["rea"]["status"], "failed")
        self.assertEqual(engines["craft-anything"]["status"], "passed", engines)
        self.assertEqual(engines["craft-anything"]["input_sha256"], "c" * 64)
        self.assertIn(str(report_path), record["evidence"])

    def test_build_command_writes_only_to_private_snapshot(self):
        (self.project / "settings.json").write_text('{"mode":"original"}')
        (self.project / "build.py").write_text(
            "from pathlib import Path\nPath('dist.bin').write_text('built')\n"
            "Path('settings.json').write_text('changed')\nPath('../sibling.txt').write_text('side effect')\n"
        )
        record, _ = baseline.capture(
            self.project,
            self.store,
            [sys.executable, "build.py"],
            ["dist.bin"],
            "private-build",
        )
        snapshot = Path(record["identity"]["build_snapshot"]["path"])
        self.assertEqual(
            (self.project / "settings.json").read_text(), '{"mode":"original"}'
        )
        self.assertFalse((self.project.parent / "sibling.txt").exists())
        self.assertEqual((snapshot / "settings.json").read_text(), "changed")
        self.assertEqual((snapshot.parent / "sibling.txt").read_text(), "side effect")

    def test_opt_in_build_timing_trials_use_fresh_private_copies_and_bind_outputs(self):
        counter = self.project.parent / "trial-count.txt"
        (self.project / "build.py").write_text(
            "from pathlib import Path\nimport sys\n"
            "counter=Path(sys.argv[1]); n=int(counter.read_text())+1 if counter.exists() else 1\n"
            "counter.write_text(str(n)); Path('dist.bin').write_text(str(n))\n"
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "from 1 to 5"):
            baseline.capture(
                self.project,
                self.project.parent / "invalid-state",
                [sys.executable, "build.py", str(counter)],
                ["dist.bin"],
                "invalid-trials",
                build_time_trials=6,
            )
        self.assertFalse(counter.exists())
        record, _ = baseline.capture(
            self.project,
            self.store,
            [sys.executable, "build.py", str(counter)],
            ["dist.bin"],
            "timed-before",
            build_time_trials=3,
        )
        timing = record["identity"]["build_timing"]
        self.assertEqual(len(timing["trials"]), 3)
        self.assertEqual(
            [Path(item["evidence_path"]).name for item in timing["trials"]],
            [
                "baseline-timed-before.json",
                "baseline-timed-before-build-trial-2.json",
                "baseline-timed-before-build-trial-3.json",
            ],
        )
        self.assertEqual(
            [Path(item["evidence_path"]).exists() for item in timing["trials"]],
            [True] * 3,
        )
        self.assertEqual(
            [item["artifacts"]["dist.bin"] for item in timing["trials"]],
            [hashlib.sha256(value.encode()).hexdigest() for value in ("1", "2", "3")],
        )
        self.assertFalse(timing["identical_artifacts"])
        durations = [item["elapsed_ms"] for item in timing["trials"]]
        self.assertEqual(
            timing["summary_ms"],
            {
                "min": min(durations),
                "median": statistics.median(durations),
                "max": max(durations),
            },
        )
        self.assertEqual(record["identity"]["build_duration_ms"], durations[0])
        snapshot = Path(record["identity"]["build_snapshot"]["path"])
        self.assertEqual((snapshot / "dist.bin").read_text(), "1")
        self.assertFalse(
            (snapshot.parent / "baseline-timed-before-build-trial-2-snapshot").exists()
        )
        self.assertFalse(
            (snapshot.parent / "baseline-timed-before-build-trial-3-snapshot").exists()
        )
        self.assertEqual(counter.read_text(), "3")
        workflow.validate_baseline(record)
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/workflow-v2.schema.json").read_text()
        )
        jsonschema.validate(record, schema)
        changed = json.loads(json.dumps(record))
        changed_trials = changed["identity"]["build_timing"]["trials"]
        changed_trials[1]["elapsed_ms"] += 1
        durations = [item["elapsed_ms"] for item in changed_trials]
        changed["identity"]["build_timing"]["summary_ms"] = {
            "min": min(durations),
            "median": statistics.median(durations),
            "max": max(durations),
        }
        with self.assertRaisesRegex(
            workflow.WorkflowError, "does not match its measured trial"
        ):
            workflow.validate_baseline(changed)
        report_path = Path(timing["trials"][1]["evidence_path"])
        report = json.loads(report_path.read_text())
        report["elapsed_ms"] += 1
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(workflow.WorkflowError, "hash mismatch"):
            workflow.validate_baseline(record)

    def test_cli_surfaces_opt_in_build_timing_summary(self):
        output = io.StringIO()
        command = [
            sys.executable,
            "-c",
            "from pathlib import Path; Path('dist.bin').write_bytes(b'ok')",
        ]
        with patch.dict(os.environ):
            os.environ.pop("ANTI_REA_REA_RUNTIME", None)
            with redirect_stdout(output):
                status = cli.main(
                    [
                        "baseline",
                        str(self.project),
                        "--store",
                        str(self.store),
                        "--id",
                        "cli-timing",
                        "--artifact",
                        "dist.bin",
                        "--build-time-trials",
                        "2",
                        "--",
                        *command,
                    ]
                )
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(len(result["build_timing"]["trials"]), 2)

    def test_absolute_project_script_argument_runs_from_private_snapshot(self):
        record, evidence = baseline.capture(
            self.project,
            self.store,
            [sys.executable, str(self.project / "build.py")],
            ["dist.bin"],
            "absolute-build-script",
        )
        snapshot = Path(record["identity"]["build_snapshot"]["path"])
        command = json.loads(evidence.read_text())["argv"]
        self.assertEqual(command, [sys.executable, str(snapshot / "build.py")])
        self.assertTrue((snapshot / "dist.bin").is_file())
        self.assertFalse((self.project / "dist.bin").exists())

    def test_embedded_absolute_project_path_is_redirected_into_private_snapshot(self):
        (self.project / "settings.json").write_text("private config")
        (self.project / "build.py").write_text(
            "import pathlib,sys\npathlib.Path('dist.bin').write_text(pathlib.Path(sys.argv[1].split('=',1)[1]).read_text())\n"
        )
        record, evidence = baseline.capture(
            self.project,
            self.store,
            [sys.executable, "build.py", f"--config={self.project}/settings.json"],
            ["dist.bin"],
            "embedded-path",
        )
        snapshot = Path(record["identity"]["build_snapshot"]["path"])
        self.assertEqual(
            json.loads(evidence.read_text())["argv"],
            [sys.executable, "build.py", f"--config={snapshot}/settings.json"],
        )
        self.assertEqual((snapshot / "dist.bin").read_text(), "private config")

    def test_apple_bundle_baseline_hashes_tree_without_following_external_symlinks(
        self,
    ):
        app = self.project / "Example.app"
        app.mkdir()
        binary = app / "Example"
        binary.write_bytes(b"release-v1")
        outside = self.project.parent / "outside-secret"
        outside.write_text("secret-v1")
        (app / "external-link").symlink_to(outside)

        identity = baseline._hash_artifact(self.project, "Example.app")
        self.assertEqual((identity["kind"], identity["size"]), ("directory", 10))
        with self.assertRaisesRegex(
            workflow.WorkflowError, "Apple bundle builds with symlinks"
        ):
            baseline.capture(
                self.project,
                self.store,
                [sys.executable, "-c", "pass"],
                ["Example.app"],
                "apple-bundle-one",
            )
        outside.write_text("secret-v2")
        same = baseline._hash_artifact(self.project, "Example.app")
        self.assertEqual(same, identity)
        (self.project / "Alias.app").symlink_to(app, target_is_directory=True)
        with self.assertRaisesRegex(workflow.WorkflowError, "linked, or escapes"):
            baseline._hash_artifact(self.project, "Alias.app")
        binary.write_bytes(b"release-v2")
        changed = baseline._hash_artifact(self.project, "Example.app")
        self.assertNotEqual(changed["sha256"], identity["sha256"])

    def test_capture_rejects_state_directory_that_contains_project(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            project = state / "project"
            project.mkdir()
            (project / "app.js").write_text("fixture")
            with self.assertRaisesRegex(
                workflow.WorkflowError, "State must be outside"
            ):
                baseline.capture(
                    project,
                    state,
                    [sys.executable, "-c", "pass"],
                    ["app.js"],
                    "nested-state",
                )
            self.assertEqual(sorted(path.name for path in state.iterdir()), ["project"])

    def test_capture_records_hash_bound_behavior_on_the_built_javascript(self):
        (self.project / "build.py").write_text(
            "from pathlib import Path\nPath('app.js').write_text('fixture')\n"
        )
        (self.project / "check.py").write_text(
            "import pathlib,sys\nprint(pathlib.Path(sys.argv[1]).read_text())\n"
        )
        command = [sys.executable, "check.py", "{artifact}"]
        record, _ = baseline.capture(
            self.project,
            self.store,
            [sys.executable, "build.py"],
            ["app.js"],
            "before-behavior",
            behavior_command=command,
        )
        behavior = record["identity"]["behavior"]
        self.assertEqual(behavior["command"], command)
        self.assertEqual(behavior["artifact"], "app.js")
        self.assertEqual(
            behavior["artifact_sha256"],
            record["identity"]["artifacts"]["app.js"]["sha256"],
        )
        self.assertIn(behavior["evidence_path"], record["evidence"])
        report = json.loads(Path(behavior["evidence_path"]).read_text())
        self.assertEqual(
            report["argv"],
            [
                sys.executable,
                "check.py",
                str(Path(behavior["snapshot_path"]) / "app.js"),
            ],
        )
        self.assertNotEqual(Path(behavior["snapshot_path"]), self.project.resolve())
        self.assertEqual(
            (report["exit_code"], report["stdout"], report["timed_out"]),
            (0, "fixture\n", False),
        )
        self.assertEqual(
            workflow.read_record(
                self.store / "records" / "baseline-before-behavior.json", "baseline"
            ),
            record,
        )

    def test_failed_or_mutating_behavior_keeps_output_but_never_creates_baseline(self):
        (self.project / "build.py").write_text(
            "from pathlib import Path\nPath('app.js').write_text('fixture')\n"
        )
        failed = [sys.executable, "-c", "raise SystemExit(7)", "{artifact}"]
        with self.assertRaisesRegex(
            workflow.WorkflowError, "behavior command exited 7"
        ):
            baseline.capture(
                self.project,
                self.store,
                [sys.executable, "build.py"],
                ["app.js"],
                "failed-behavior",
                behavior_command=failed,
            )
        failure_path = (
            self.store / "evidence" / "baseline-failed-behavior-behavior.json"
        )
        self.assertTrue(failure_path.is_file())
        self.assertEqual(json.loads(failure_path.read_text())["exit_code"], 7)
        self.assertFalse(
            (self.store / "records" / "baseline-failed-behavior.json").exists()
        )

        mutation_store = self.store.parent / "mutation-state"
        mutating = [
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('changed')",
            "{artifact}",
        ]
        with self.assertRaisesRegex(
            workflow.WorkflowError, "changed during behavior verification"
        ):
            baseline.capture(
                self.project,
                mutation_store,
                [sys.executable, "build.py"],
                ["app.js"],
                "mutating-behavior",
                behavior_command=mutating,
            )
        self.assertTrue(
            (
                mutation_store / "evidence" / "baseline-mutating-behavior-behavior.json"
            ).is_file()
        )
        self.assertFalse(
            (mutation_store / "records" / "baseline-mutating-behavior.json").exists()
        )

    def test_baseline_behavior_mutates_only_its_private_snapshot(self):
        (self.project / "app.js").write_text("export const fixture = true;\n")
        (self.project / "settings.json").write_text('{"mode":"original"}\n')
        command = [
            sys.executable,
            "-c",
            "from pathlib import Path; import json,sys; "
            "Path('settings.json').write_text('{\\\"mode\\\":\\\"changed\\\"}'); "
            "print(Path(sys.argv[1]).read_text())",
            "{artifact}",
        ]
        record, _ = baseline.capture(
            self.project,
            self.store,
            [sys.executable, "-c", "pass"],
            ["app.js"],
            "private-behavior",
            behavior_command=command,
        )
        snapshot = Path(record["identity"]["behavior"]["snapshot_path"])
        self.assertEqual(
            json.loads((self.project / "settings.json").read_text()),
            {"mode": "original"},
        )
        self.assertEqual(
            json.loads((snapshot / "settings.json").read_text()), {"mode": "changed"}
        )
        self.assertEqual(
            json.loads(
                Path(record["identity"]["behavior"]["evidence_path"]).read_text()
            )["exit_code"],
            0,
        )

    def test_cli_can_capture_baseline_behavior(self):
        (self.project / "build.py").write_text(
            "from pathlib import Path\nPath('app.js').write_text('fixture')\n"
        )
        command = [
            sys.executable,
            "-c",
            "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
            "{artifact}",
        ]
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "baseline",
                str(self.project),
                "--store",
                str(self.store),
                "--id",
                "cli-behavior",
                "--artifact",
                "app.js",
                "--behavior-command-json",
                json.dumps(command),
                "--",
                sys.executable,
                "build.py",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["behavior_evidence"])

    @unittest.skipIf(os.name == "nt", "POSIX signal and process-group integration")
    def test_cli_baseline_sigint_stops_child_and_reports_cancelled(self):
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        process = subprocess.Popen(
            [
                sys.executable,
                str(cli),
                "baseline",
                str(self.project),
                "--store",
                str(self.store),
                "--id",
                "cli-cancelled",
                "--artifact",
                "app.js",
                "--",
                sys.executable,
                "-c",
                "from pathlib import Path; import time; Path('app.js').write_text('x'); time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while (
            time.monotonic() < deadline
            and process.poll() is None
            and not (self.project / "app.js").exists()
        ):
            time.sleep(0.02)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            self.fail(
                f"CLI exited before the baseline child started ({process.returncode}): {stdout}{stderr}"
            )
        os.kill(process.pid, signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(process.returncode, 130, stdout + stderr)
        self.assertEqual(
            json.loads(stdout),
            {"status": "cancelled", "id": "cli-cancelled", "reason": "user_requested"},
        )
        self.assertFalse(
            (self.store / "records" / "baseline-cli-cancelled.json").exists()
        )

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for pinned browser capture",
    )
    def test_capture_runs_browser_check_on_private_baseline_snapshot(self):
        project = self.project.parent / "web"
        shutil.copytree(Path(__file__).parents[1] / "fixtures/e2e/web", project)
        node = os.environ.get("ANTI_REA_NODE", "node")
        with patch.dict(
            os.environ,
            {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
        ):
            record, _ = baseline.capture(
                project,
                self.store,
                [sys.executable, "-c", "pass"],
                ["app.js"],
                "before-e2e",
                e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
            )
        captured = record["identity"]["e2e_behavior"]
        self.assertEqual(captured["source_path"], "app.js")
        self.assertEqual(captured["cleanup"], "loopback app port closed")
        self.assertIn(captured["report_path"], record["evidence"])
        self.assertTrue(Path(captured["snapshot_path"]).is_dir())
        self.assertEqual(
            json.loads(Path(captured["report_path"]).read_text())["run"]["status"],
            "passed",
        )
        self.assertFalse((project / ".anti-rea-e2e").exists())
        self.assertFalse(
            (
                self.store
                / "evidence"
                / "baseline-before-e2e-e2e"
                / "snapshot"
                / ".anti-rea-e2e"
            ).exists()
        )

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"), "pinned browser runtime is required"
    )
    def test_capture_runs_browser_check_on_built_static_spa_artifact_tree(self):
        project = self.project.parent / "static-spa"
        shutil.copytree(Path(__file__).parents[1] / "fixtures/e2e/static-spa", project)
        node = os.environ.get("ANTI_REA_NODE", "node")
        artifacts = ["dist/index.html", "dist/assets/app.js", "dist/assets/site.css"]
        with patch.dict(
            os.environ,
            {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
        ):
            record, _ = baseline.capture(
                project,
                self.store,
                [node, "build.mjs"],
                artifacts,
                "before-static-spa",
                e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
                e2e_config="e2e.config.mjs",
                e2e_test_file="tests/behavior.e2e.ts",
            )
        captured = record["identity"]["e2e_behavior"]
        snapshot = Path(captured["snapshot_path"])
        self.assertEqual(captured["source_path"], "dist/assets/app.js")
        self.assertTrue(all((snapshot / path).is_file() for path in artifacts))
        report = json.loads(Path(captured["report_path"]).read_text())
        self.assertEqual(report["run"]["status"], "passed")

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"), "pinned browser runtime is required"
    )
    def test_capture_runs_browser_check_with_multiple_javascript_artifacts(self):
        project = self.project.parent / "multi-js"
        (project / "dist").mkdir(parents=True)
        harness = Path(__file__).parents[1] / "examples/todomvc-react"
        (project / "anti-rea-example").mkdir()
        (project / "tests").mkdir()
        shutil.copy(harness / "server.cjs", project / "anti-rea-example/server.cjs")
        (project / "e2e.config.mjs").write_text(
            (harness / "e2e.config.mjs").read_text()
        )
        (project / "tests/behavior.e2e.ts").write_text(
            "import { test } from '@e2e-dev/web';\n"
            "import { expect } from 'e2e';\n"
            "test('multi bundle target renders', async ({ app, screen }) => {\n"
            "  await app.open('/');\n"
            "  await expect(screen.getByText('example ready')).toBeVisible();\n"
            "});\n"
        )
        (project / "dist/index.html").write_text(
            "<!doctype html><html><body><main>example ready</main>"
            '<script src="app.js"></script><script src="chunk.js"></script></body></html>'
        )
        (project / "dist/app.js").write_text("window.exampleReady = true;\n")
        (project / "dist/chunk.js").write_text("window.exampleChunk = true;\n")
        node = os.environ.get("ANTI_REA_NODE", "node")
        with patch.dict(
            os.environ,
            {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
        ):
            record, _ = baseline.capture(
                project,
                self.store,
                [sys.executable, "-c", "pass"],
                ["dist/index.html", "dist/app.js", "dist/chunk.js"],
                "before-multi-js",
                e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
                e2e_config="e2e.config.mjs",
                e2e_test_file="tests/behavior.e2e.ts",
            )
        captured = record["identity"]["e2e_behavior"]
        self.assertEqual(captured["source_path"], "dist/app.js")
        self.assertEqual(
            json.loads(Path(captured["report_path"]).read_text())["run"]["status"],
            "passed",
        )

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for pinned browser capture",
    )
    def test_cli_can_capture_baseline_e2e(self):
        project = self.project.parent / "web-cli"
        shutil.copytree(Path(__file__).parents[1] / "fixtures/e2e/web", project)
        node = os.environ.get("ANTI_REA_NODE", "node")
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        with patch.dict(
            os.environ,
            {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "baseline",
                    str(project),
                    "--store",
                    str(self.store),
                    "--id",
                    "cli-e2e",
                    "--artifact",
                    "app.js",
                    "--e2e-runtime",
                    os.environ["ANTI_REA_E2E_RUNTIME"],
                    "--",
                    sys.executable,
                    "-c",
                    "pass",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["e2e_evidence"])

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_REA_RUNTIME"),
        "set ANTI_REA_REA_RUNTIME for pinned REA capture",
    )
    def test_capture_runs_rea_on_private_baseline_snapshot(self):
        project = self.project.parent / "web-rea"
        shutil.copytree(Path(__file__).parents[1] / "fixtures/e2e/web", project)
        (project / "build.py").write_text(
            "from pathlib import Path\nPath('app.js').write_text(Path('app.js').read_text())\n"
        )
        record, _ = baseline.capture(
            project,
            self.store,
            [sys.executable, "-c", "pass"],
            ["app.js"],
            "before-rea",
            rea_runtime=os.environ["ANTI_REA_REA_RUNTIME"],
        )
        captured = record["identity"]["rea_analysis"]
        self.assertEqual(captured["source_path"], "app.js")
        self.assertIn(captured["report_path"], record["evidence"])
        self.assertIn(captured["bundle_path"], record["evidence"])
        self.assertEqual(workflow.validate_baseline(record), record)
        self.assertTrue(Path(captured["snapshot_path"]).is_dir())
        from core import recommendations

        target = workflow.read_record(
            self.store / "records" / f"target-{record['target_id']}.json", "target"
        )
        plan = recommendations.create_plan(target, record, "rea-plan")
        action = next(
            item
            for item in plan["actions"]
            if item.get("execution", {}).get("source_path") == "app.js"
        )
        self.assertEqual(
            action["execution"]["rea_baseline_evidence_id"], captured["evidence_id"]
        )

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_REA_RUNTIME"),
        "set ANTI_REA_REA_RUNTIME for pinned REA capture",
    )
    def test_cli_can_capture_baseline_rea(self):
        project = self.project.parent / "web-rea-cli"
        shutil.copytree(Path(__file__).parents[1] / "fixtures/e2e/web", project)
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        node = os.environ.get("ANTI_REA_NODE", "node")
        with patch.dict(
            os.environ,
            {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "baseline",
                    str(project),
                    "--store",
                    str(self.store),
                    "--id",
                    "cli-rea",
                    "--artifact",
                    "app.js",
                    "--rea-runtime",
                    os.environ["ANTI_REA_REA_RUNTIME"],
                    "--",
                    sys.executable,
                    "-c",
                    "pass",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["rea_evidence"])

    def test_failure_timeout_and_unsafe_artifact_never_create_baseline(self):
        with self.assertRaisesRegex(workflow.WorkflowError, "exited 3"):
            baseline.capture(
                self.project,
                self.store,
                [sys.executable, "-c", "raise SystemExit(3)"],
                ["dist.bin"],
                "failed",
            )
        self.assertFalse((self.store / "records" / "baseline-failed.json").exists())
        with self.assertRaisesRegex(workflow.WorkflowError, "timed out"):
            baseline.capture(
                self.project,
                self.store,
                [sys.executable, "-c", "import time; time.sleep(2)"],
                ["dist.bin"],
                "timeout",
                0.1,
            )
        with self.assertRaisesRegex(workflow.WorkflowError, "stay inside"):
            baseline.capture(
                self.project,
                self.store,
                [sys.executable, "build.py"],
                ["../outside"],
                "escape",
            )
        self.assertFalse((self.store / "records" / "baseline-escape.json").exists())

    def test_symlink_artifact_is_rejected(self):
        (self.project / "linked.bin").symlink_to(self.project / "build.py")
        with self.assertRaisesRegex(workflow.WorkflowError, "linked"):
            baseline.capture(
                self.project,
                self.store,
                [sys.executable, "build.py"],
                ["linked.bin"],
                "link",
            )

    def test_artifact_hashing_fails_closed_without_nofollow(self):
        with patch.object(baseline.os, "O_NOFOLLOW", 0):
            with self.assertRaisesRegex(
                workflow.WorkflowError, "Safe artifact hashing"
            ):
                baseline._hash_artifact(self.project, "build.py")
            directory_fd = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    workflow.WorkflowError, "Safe artifact hashing"
                ):
                    baseline._hash_directory_artifact(directory_fd, "fixture.app")
            finally:
                os.close(directory_fd)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_artifact_hashing_rejects_fifo_without_blocking(self):
        fifo = self.project / "pipe.bin"
        os.mkfifo(fifo)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from pathlib import Path; from core.baseline import _hash_artifact; "
                "_hash_artifact(Path(sys.argv[1]), 'pipe.bin')",
                str(self.project),
            ],
            capture_output=True,
            text=True,
            timeout=2,
            cwd=Path(__file__).parents[1],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Artifact is not a regular file", result.stderr)

    def test_artifact_failure_retains_raw_output_without_creating_a_baseline(self):
        with self.assertRaisesRegex(
            workflow.WorkflowError,
            "Baseline artifact capture failed; evidence retained",
        ):
            baseline.capture(
                self.project,
                self.store,
                [sys.executable, "build.py"],
                ["missing.bin"],
                "missing",
            )
        self.assertFalse((self.store / "records" / "baseline-missing.json").exists())
        report = json.loads(
            (self.store / "evidence" / "baseline-missing.json").read_text()
        )
        self.assertEqual(report["stdout"], "built\n")
        self.assertEqual(report["exit_code"], 0)

    def test_cancellation_after_trial_one_prevents_trial_two_launch(self):
        event = threading.Event()
        command_calls = []
        original = baseline._run_command

        def run(*args, **kwargs):
            result = original(*args, **kwargs)
            command_calls.append(args[0])
            if len(command_calls) == 1:
                event.set()
            return result

        with patch.object(baseline, "_run_command", side_effect=run):
            with self.assertRaisesRegex(workflow.WorkflowError, "Command cancelled"):
                baseline.capture(
                    self.project,
                    self.store,
                    [sys.executable, "build.py"],
                    ["dist.bin"],
                    "cancel-between-trials",
                    cancel_event=event,
                    build_time_trials=3,
                )
        self.assertEqual(len(command_calls), 1)
        evidence = self.store / "evidence"
        self.assertTrue((evidence / "baseline-cancel-between-trials.json").is_file())
        self.assertFalse(
            (evidence / "baseline-cancel-between-trials-build-trial-2.json").exists()
        )
        self.assertFalse(
            (
                evidence / "baseline-cancel-between-trials-build-trial-2-snapshot"
            ).exists()
        )

    def test_cancellation_during_secondary_copy_cleans_partial_snapshot(self):
        event = threading.Event()
        command_calls = []
        original_run = baseline._run_command
        from core import execution

        original_copy = execution._copy_project_file
        copied_secondary_files = []

        def run(*args, **kwargs):
            result = original_run(*args, **kwargs)
            command_calls.append(args[0])
            return result

        def copy(
            source_root,
            relative,
            destination,
            expected_sha256,
            expected_size,
            snapshot_root,
            cancel_event=None,
        ):
            result = original_copy(
                source_root,
                relative,
                destination,
                expected_sha256,
                expected_size,
                snapshot_root,
                cancel_event,
            )
            if (
                snapshot_root.name
                == "baseline-cancel-during-copy-build-trial-2-snapshot"
            ):
                copied_secondary_files.append(relative)
                event.set()
            return result

        with (
            patch.object(baseline, "_run_command", side_effect=run),
            patch.object(execution, "_copy_project_file", side_effect=copy),
        ):
            with self.assertRaisesRegex(workflow.WorkflowError, "Command cancelled"):
                baseline.capture(
                    self.project,
                    self.store,
                    [sys.executable, "build.py"],
                    ["dist.bin"],
                    "cancel-during-copy",
                    cancel_event=event,
                    build_time_trials=2,
                )
        self.assertEqual(len(command_calls), 1)
        self.assertEqual(len(copied_secondary_files), 1)
        self.assertFalse(
            (
                self.store
                / "evidence"
                / "baseline-cancel-during-copy-build-trial-2-snapshot"
            ).exists()
        )

    def test_cancellation_during_initial_copy_cleans_partial_build_snapshot(self):
        event = threading.Event()
        from core import execution

        original_copy = execution._copy_project_file
        copied = []

        def copy(*args, **kwargs):
            result = original_copy(*args, **kwargs)
            copied.append(args[1])
            event.set()
            return result

        with patch.object(execution, "_copy_project_file", side_effect=copy):
            with self.assertRaisesRegex(workflow.WorkflowError, "Command cancelled"):
                baseline.capture(
                    self.project,
                    self.store,
                    [sys.executable, "build.py"],
                    ["dist.bin"],
                    "cancel-initial-copy",
                    cancel_event=event,
                )
        self.assertEqual(len(copied), 1)
        self.assertFalse(
            (
                self.store / "evidence" / "baseline-cancel-initial-copy-build-snapshot"
            ).exists()
        )

    def test_cancellation_during_behavior_snapshot_copy_removes_partial_snapshot(self):
        (self.project / "build.py").write_text(
            "from pathlib import Path\nPath('dist').mkdir()\nPath('dist/app.js').write_text('export const ready = true;')\n"
        )
        cancel = threading.Event()
        from core import execution

        original_copy = execution._copy_project_file

        def cancel_during_behavior_copy(*args, **kwargs):
            result = original_copy(*args, **kwargs)
            if Path(args[5]).name == "baseline-behavior-copy-behavior-snapshot":
                cancel.set()
            return result

        behavior = [
            sys.executable,
            "-c",
            "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
            "{artifact}",
        ]
        with patch.object(
            execution, "_copy_project_file", side_effect=cancel_during_behavior_copy
        ):
            with self.assertRaisesRegex(workflow.WorkflowError, "Command cancelled"):
                baseline.capture(
                    self.project,
                    self.store,
                    [sys.executable, "build.py"],
                    ["dist/app.js"],
                    "behavior-copy",
                    behavior_command=behavior,
                    cancel_event=cancel,
                )
        self.assertFalse(
            (
                self.store / "evidence" / "baseline-behavior-copy-behavior-snapshot"
            ).exists()
        )

    def test_cancellation_during_e2e_and_rea_snapshot_copy_removes_partial_roots(self):
        from core import discovery, execution

        for lane in ("e2e", "rea"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "project"
                root.mkdir()
                (root / "app.js").write_text("export const ready = true;\n")
                (root / "source.txt").write_text("unchanged input\n")
                runtime = Path(directory) / "runtime"
                runtime.mkdir()
                state = Path(directory) / "state"
                (state / "evidence").mkdir(parents=True)
                target = discovery.inspect_project(root)
                artifact = baseline._hash_artifact(root, "app.js")
                cancel = threading.Event()
                original_copy = execution._copy_project_file

                def cancel_after_first_copy(*args, **kwargs):
                    result = original_copy(*args, **kwargs)
                    cancel.set()
                    return result

                if lane == "e2e":
                    operation = partial(
                        baseline._capture_e2e,
                        root,
                        state,
                        target,
                        {"app.js": artifact},
                        f"cancel-{lane}",
                        runtime,
                        "e2e.config.mjs",
                        "tests/behavior.e2e.ts",
                        cancel,
                    )
                else:
                    operation = partial(
                        baseline._capture_rea,
                        root,
                        state,
                        target,
                        {"app.js": artifact},
                        f"cancel-{lane}",
                        runtime,
                        cancel,
                    )
                with patch.object(
                    execution, "_copy_project_file", side_effect=cancel_after_first_copy
                ):
                    with self.assertRaisesRegex(
                        workflow.WorkflowError, "Command cancelled"
                    ):
                        operation()
                self.assertFalse(
                    (state / "evidence" / f"baseline-cancel-{lane}-{lane}").exists()
                )
                self.assertEqual(
                    (root / "app.js").read_text(), "export const ready = true;\n"
                )

    def test_dangling_trial_snapshot_symlink_is_removed_on_failure(self):
        original = baseline._run_command
        calls = []
        replaced = [False]

        def replace_with_dangling_link(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(args[1])
            if len(calls) == 2:
                shutil.rmtree(calls[1])
                calls[1].symlink_to(
                    calls[1].parent / "missing-target", target_is_directory=True
                )
                replaced[0] = calls[1].is_symlink() and not calls[1].exists()
            return result

        with patch.object(
            baseline, "_run_command", side_effect=replace_with_dangling_link
        ):
            with self.assertRaisesRegex(
                workflow.WorkflowError, "Baseline artifact capture failed"
            ):
                baseline.capture(
                    self.project,
                    self.store,
                    [sys.executable, "build.py"],
                    ["dist.bin"],
                    "dangling-trial",
                    build_time_trials=2,
                )
        self.assertTrue(replaced[0])
        self.assertFalse(calls[1].exists())
        self.assertFalse(calls[1].is_symlink())

    def test_command_output_is_streamed_with_a_hard_capture_limit(self):
        record, evidence = baseline.capture(
            self.project,
            self.store,
            [
                sys.executable,
                "-c",
                "print('x' * 1500000); from pathlib import Path; Path('dist.bin').write_bytes(b'x')",
            ],
            ["dist.bin"],
            "large-output",
        )
        output = json.loads(evidence.read_text())
        self.assertEqual(len(output["stdout"].encode()), baseline.MAX_OUTPUT_BYTES)
        self.assertTrue(output["stdout_truncated"])

    def test_cancelled_command_kills_its_process_group(self):
        event = threading.Event()
        started = threading.Event()
        result = []

        def run():
            def on_start(_):
                started.set()

            try:
                result.append(
                    baseline._run_command(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        self.project,
                        60,
                        on_start,
                        event,
                    )
                )
            except workflow.WorkflowError as error:
                result.append(str(error))

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(started.wait(3))
        event.set()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, ["Command cancelled"])

    def test_on_start_failure_stops_spawned_process(self):
        process = None
        real_popen = subprocess.Popen

        def capture_process(*args, **kwargs):
            nonlocal process
            process = real_popen(*args, **kwargs)
            return process

        with patch.object(baseline.subprocess, "Popen", side_effect=capture_process):
            with self.assertRaisesRegex(RuntimeError, "callback failed"):
                baseline._run_command(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    self.project,
                    10,
                    on_start=lambda _: (_ for _ in ()).throw(
                        RuntimeError("callback failed")
                    ),
                )
        self.assertIsNotNone(process)
        self.assertIsNotNone(process.poll())

    def test_partial_reader_start_failure_reaps_child_and_preserves_error(self):
        process = None
        real_popen = subprocess.Popen
        real_start = threading.Thread.start
        starts = 0

        def capture_process(*args, **kwargs):
            nonlocal process
            process = real_popen(*args, **kwargs)
            return process

        def fail_second_start(thread):
            nonlocal starts
            starts += 1
            if starts == 2:
                raise RuntimeError("reader start failed")
            return real_start(thread)

        with (
            patch.object(baseline.subprocess, "Popen", side_effect=capture_process),
            patch.object(threading.Thread, "start", new=fail_second_start),
        ):
            with self.assertRaisesRegex(RuntimeError, "reader start failed"):
                baseline._run_command(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    self.project,
                    10,
                )
        self.assertEqual(starts, 2)
        self.assertIsNotNone(process)
        self.assertIsNotNone(process.poll())

    @unittest.skipIf(
        os.name == "nt", "descendant process-group cleanup is POSIX-specific"
    )
    def test_exited_command_cannot_leave_pipe_holding_descendant(self):
        pid_file = self.project / "descendant.pid"
        code = (
            "import pathlib,signal,subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-c',\"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)\"]); "
            f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid))"
        )
        started = time.monotonic()
        result = baseline._run_command([sys.executable, "-c", code], self.project, 2)
        self.assertEqual(result[0], 0)
        self.assertLess(time.monotonic() - started, 5)
        pid = int(pid_file.read_text())
        state = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True
        ).stdout.strip()
        self.assertTrue(
            not state or state.startswith("Z"),
            f"descendant process remains active: {state}",
        )

    @unittest.skipUnless(
        os.name == "nt", "Windows Job Object cleanup is Windows-specific"
    )
    def test_exited_command_kills_descendants_in_its_windows_job(self):
        ready = self.project / "descendant.ready"
        survived = self.project / "descendant.survived"
        child = (
            "import pathlib,time; "
            f"pathlib.Path({str(ready)!r}).write_text('ready'); time.sleep(1); "
            f"pathlib.Path({str(survived)!r}).write_text('survived')"
        )
        parent = (
            "import pathlib,subprocess,sys,time\n"
            f"subprocess.Popen([sys.executable,'-c',{child!r}], "
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            f"ready=pathlib.Path({str(ready)!r}); deadline=time.monotonic()+5\n"
            "while not ready.exists() and time.monotonic()<deadline:\n"
            "    time.sleep(.01)\n"
            "assert ready.exists()"
        )
        result = baseline._run_command([sys.executable, "-c", parent], self.project, 10)
        self.assertEqual(result[0], 0)
        time.sleep(1.5)
        self.assertFalse(
            survived.exists(), "descendant outlived the command's Windows job"
        )

    def test_windows_process_creation_is_suspended_until_job_assignment(self):
        with (
            patch.object(baseline.os, "name", "nt"),
            patch.object(subprocess, "CREATE_SUSPENDED", 0x00000004, create=True),
            patch.object(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True
            ),
        ):
            self.assertEqual(
                baseline._process_creation_options(), {"creationflags": 0x00000004}
            )
            self.assertEqual(
                baseline._process_creation_options(subprocess.CREATE_NEW_PROCESS_GROUP),
                {"creationflags": 0x00000204},
            )

    def test_windows_job_assignment_precedes_primary_thread_resume(self):
        kernel = MagicMock()
        kernel.CreateJobObjectW.return_value = 11
        kernel.SetInformationJobObject.return_value = True
        kernel.AssignProcessToJobObject.return_value = True
        kernel.CreateToolhelp32Snapshot.return_value = 22

        def populate_thread_entry(_snapshot, ref):
            ref._obj.th32OwnerProcessID = 55
            ref._obj.th32ThreadID = 66
            return True

        kernel.Thread32First.side_effect = populate_thread_entry
        kernel.Thread32Next.return_value = False
        kernel.OpenThread.return_value = 33
        kernel.ResumeThread.return_value = 1
        kernel.CloseHandle.return_value = True
        process = type("FakeProcess", (), {"pid": 55, "_handle": 44})()
        with (
            patch.object(baseline.os, "name", "nt"),
            patch.object(ctypes, "WinDLL", return_value=kernel, create=True),
        ):
            baseline._contain_process_tree(process)
            self.assertEqual(process._anti_rea_job_handle, 11)
            baseline._close_process_tree(process)
        names = [call[0] for call in kernel.method_calls]
        self.assertLess(
            names.index("SetInformationJobObject"),
            names.index("AssignProcessToJobObject"),
        )
        self.assertLess(
            names.index("AssignProcessToJobObject"), names.index("ResumeThread")
        )
        job_info = kernel.SetInformationJobObject.call_args.args[2]._obj
        self.assertEqual(job_info.BasicLimitInformation.LimitFlags, 0x00002000)
        closed = [call.args[0] for call in kernel.CloseHandle.call_args_list]
        self.assertEqual(closed, [22, 33, 11])


class DockerBaselineSandboxTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("ANTI_REA_DOCKER_TEST"),
        "set ANTI_REA_DOCKER_TEST=1 when the pinned Node image is available",
    )
    @patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "docker"})
    def test_node_build_writes_to_private_snapshot_with_offline_only_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "package.json").write_text(
                '{"name":"sandbox-fixture","version":"1.0.0"}'
            )
            (root / "build.mjs").write_text(
                "import { mkdir, writeFile } from 'node:fs/promises';\n"
                "await mkdir('dist', {recursive:true});\n"
                "await writeFile('dist/app.js', 'built in sandbox');\n"
            )
            state = Path(directory) / "state"
            node = shutil.which("node") or "/usr/local/bin/node"
            from scripts import rea_integration

            original = rea_integration._docker_command
            observed = {}

            def capture(command, cwd, **kwargs):
                observed["cwd"] = Path(cwd).resolve()
                observed["kwargs"] = kwargs
                result = original(command, cwd, **kwargs)
                observed["command"] = result[0]
                observed["container"] = result[1]
                return result

            with patch.object(rea_integration, "_docker_command", side_effect=capture):
                record, _ = baseline.capture(
                    root, state, [node, "build.mjs"], ["dist/app.js"], "docker-build"
                )
            snapshot = Path(record["identity"]["build_snapshot"]["path"])
            self.assertEqual((snapshot / "dist/app.js").read_text(), "built in sandbox")
            self.assertFalse((root / "dist").exists())
            self.assertEqual(
                observed["kwargs"], {"writable_cwd": True, "network": False}
            )
            docker_args = observed["command"]
            self.assertIn("--network=none", docker_args)
            mounts = [
                docker_args[index + 1]
                for index, arg in enumerate(docker_args[:-1])
                if arg == "--mount"
            ]
            self.assertEqual(len(mounts), 1)
            self.assertEqual(mounts[0], f"type=bind,src={snapshot},dst=/work")

    @patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "docker"})
    def test_unsupported_executables_and_external_absolute_arguments_fail_closed(self):
        from scripts import rea_integration

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "snapshot"
            root.mkdir()
            outside = Path(directory) / "outside-secret"
            outside.write_text("secret")
            (root / "linked-secret").symlink_to(outside)
            with patch.object(rea_integration, "_docker_command") as docker_command:
                for executable in ("flutter", sys.executable, "ruby"):
                    with (
                        self.subTest(executable=executable),
                        self.assertRaisesRegex(
                            workflow.WorkflowError, "No Docker project-command profile"
                        ),
                    ):
                        baseline._run_project_command([executable, "build"], root, 1)
                node = shutil.which("node") or "/usr/local/bin/node"
                for external in (
                    str(Path.home() / ".npmrc"),
                    str(root / "linked-secret"),
                ):
                    with self.assertRaisesRegex(
                        workflow.WorkflowError, "outside the private snapshot"
                    ):
                        baseline._run_project_command(
                            [node, "build.mjs", external], root, 1
                        )
                docker_command.assert_not_called()

    @patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
    def test_explicit_host_override_allows_python_fixture_command(self):
        result = baseline._run_project_command(
            [sys.executable, "-c", "pass"], Path.cwd(), 5
        )
        self.assertEqual(result[:4], (0, b"", b"", False))

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_DOCKER_TEST"),
        "set ANTI_REA_DOCKER_TEST=1 when the pinned Node image is available",
    )
    @patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "docker"})
    def test_cancellation_removes_named_container(self):
        from scripts import rea_integration

        node = shutil.which("node") or "/usr/local/bin/node"
        original = rea_integration._docker_command
        container = {}

        def capture(*args, **kwargs):
            result = original(*args, **kwargs)
            container["name"] = result[1]
            return result

        cancelled = threading.Event()
        timer = threading.Timer(0.5, cancelled.set)
        timer.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.object(
                    rea_integration, "_docker_command", side_effect=capture
                ):
                    with self.assertRaisesRegex(
                        workflow.WorkflowError, "Command cancelled"
                    ):
                        baseline._run_project_command(
                            [node, "-e", "setInterval(()=>{},1000)"],
                            root,
                            30,
                            cancel_event=cancelled,
                        )
        finally:
            timer.cancel()
        self.assertIn("name", container)
        inspected = subprocess.run(
            ["docker", "container", "inspect", container["name"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertNotEqual(inspected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
