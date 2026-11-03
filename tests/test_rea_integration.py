import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import rea_integration as rea


class REAIntegrationTests(unittest.TestCase):
    def test_sandbox_mode_defaults_to_docker_and_rejects_unknown_modes(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(rea._sandbox_mode(), "docker")
            with (
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(
                    rea.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(["docker"], 1, "", ""),
                ),
            ):
                with self.assertRaisesRegex(
                    rea.IntegrationError, "image is missing locally"
                ):
                    rea.run_bounded(["node", "--version"], directory, 5, 1024, 1024)
        with mock.patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "something-else"}):
            with self.assertRaisesRegex(rea.IntegrationError, "must be 'docker'"):
                rea._sandbox_mode()

    def test_sandbox_version_probe_uses_the_pinned_image_not_host_tools(self):
        with (
            mock.patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "docker"}),
            mock.patch.object(
                rea.subprocess,
                "run",
                side_effect=[
                    subprocess.CompletedProcess(["docker"], 0, "", ""),
                    subprocess.CompletedProcess(["docker"], 0, "v24.22.1\n", ""),
                ],
            ) as run,
        ):
            self.assertEqual(rea.node_version(), ("v24.22.1", (24, 22, 1)))
        self.assertIn(rea.NODE_SANDBOX_IMAGE, run.call_args.args[0])

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_DOCKER_TEST"),
        "set ANTI_REA_DOCKER_TEST=1 for Docker isolation probes",
    )
    def test_live_docker_profile_blocks_network_and_writes_outside_output_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "candidate.js"
            with mock.patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "docker"}):
                readonly = rea.run_bounded(
                    [
                        "node",
                        "-e",
                        "require('node:fs').writeFileSync('/work/escaped.js','bad')",
                    ],
                    root,
                    20,
                    1024,
                    1024,
                )
                self.assertNotEqual(readonly.returncode, 0)
                self.assertFalse((root / "escaped.js").exists())
                network = rea.run_bounded(
                    [
                        "node",
                        "-e",
                        "fetch('https://example.com',{signal:AbortSignal.timeout(2000)}).then(()=>process.exit(1),()=>process.exit(0))",
                    ],
                    root,
                    10,
                    1024,
                    1024,
                )
                self.assertEqual(network.returncode, 0, network.stderr)
                copied = rea.run_bounded(
                    [
                        "node",
                        "-e",
                        "require('node:fs').writeFileSync(process.argv.at(-1),'ok')",
                        "--",
                        "--output",
                        str(output),
                    ],
                    root,
                    20,
                    1024,
                    1024,
                )
                self.assertEqual(copied.returncode, 0, copied.stderr)
            self.assertEqual(output.read_text(), "ok")

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_DOCKER_TEST"),
        "set ANTI_REA_DOCKER_TEST=1 for Docker isolation probes",
    )
    def test_live_docker_profile_removes_timed_out_container(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "docker"}),
        ):
            original = rea._docker_command
            names = []

            def capture_name(*args, **kwargs):
                result = original(*args, **kwargs)
                names.append(result[1])
                return result

            with mock.patch.object(rea, "_docker_command", side_effect=capture_name):
                with self.assertRaises(subprocess.TimeoutExpired):
                    rea.run_bounded(
                        ["node", "-e", "setInterval(()=>{},1000)"],
                        directory,
                        0.2,
                        1024,
                        1024,
                    )
            check = subprocess.run(
                ["docker", "container", "inspect", names[0]],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertNotEqual(check.returncode, 0)

    def test_docker_command_is_pinned_offline_and_maps_only_declared_paths(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                rea.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(["docker"], 0, "", ""),
            ),
        ):
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            target = root / "source"
            target.mkdir()
            source_file = target / "app.js"
            source_file.write_text("export const safe = true;")
            command, name, outputs, staging = rea._docker_command(
                [
                    str(runtime / "node_modules/.bin/rea"),
                    "analyze",
                    str(target),
                    str(source_file),
                    "--evidence_output",
                    str(root / "bundle.zip"),
                ],
                runtime,
            )
            try:
                self.assertEqual(command[:3], ["docker", "run", "--pull=never"])
                self.assertIn("--network=none", command)
                self.assertIn("--read-only", command)
                self.assertEqual(command[command.index("--workdir") + 1], "/work")
                self.assertIn(rea.NODE_SANDBOX_IMAGE, command)
                self.assertIn("/work/node_modules/.bin/rea", command)
                self.assertIn("/output/0.zip", command)
                self.assertIn("/input/1.js", command)
                self.assertEqual(outputs[0][0], root.resolve() / "bundle.zip")
                self.assertTrue(name.startswith("anti-rea-"))
                mounts = [
                    command[index + 1]
                    for index, item in enumerate(command[:-1])
                    if item == "--mount"
                ]
                self.assertTrue(
                    any(
                        f"src={staging.name},dst=/output" in item
                        and "readonly" not in item
                        for item in mounts
                    )
                )
                self.assertTrue(
                    any(
                        Path(item.split("src=", 1)[1].split(",", 1)[0]).resolve()
                        == target.resolve()
                        and "readonly" in item
                        for item in mounts
                    )
                )
                self.assertFalse(any(f"src={root}," in item for item in mounts))
            finally:
                staging.cleanup()

    def test_docker_command_refuses_missing_image_without_host_fallback(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                rea.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(["docker"], 1, "", ""),
            ),
        ):
            with self.assertRaisesRegex(
                rea.IntegrationError, "image is missing locally"
            ):
                rea._docker_command(["node", "--version"], directory)

    def test_docker_output_copy_rejects_a_grandparent_symlink_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = root / "trusted"
            parent = trusted / "grandparent" / "parent"
            parent.mkdir(parents=True)
            destination, expected_parent = rea._docker_output_path(
                parent / "candidate.js", root
            )
            staged = root / "staged.js"
            staged.write_text("candidate")
            (trusted / "grandparent").rename(trusted / "original-grandparent")
            outside = root / "outside"
            outside.mkdir()
            (trusted / "grandparent").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(rea.IntegrationError, "parent changed"):
                rea._copy_docker_output(destination, staged, expected_parent)
            self.assertFalse((outside / "parent" / "candidate.js").exists())

    def test_docker_command_allows_only_runtime_internal_symlinks(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                rea.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(["docker"], 0, "", ""),
            ),
        ):
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            target = runtime / "tool.js"
            target.write_text("process.exit(0)")
            shim = runtime / "shim"
            shim.symlink_to(target)
            command, _, _, staging = rea._docker_command([str(shim)], runtime)
            try:
                self.assertIn("/work/tool.js", command)
            finally:
                staging.cleanup()
            outside = root / "outside.js"
            outside.write_text("process.exit(1)")
            escape = runtime / "escape"
            escape.symlink_to(outside)
            with self.assertRaisesRegex(rea.IntegrationError, "outside its runtime"):
                rea._docker_command([str(escape)], runtime)

    def test_comparison_and_report_reads_fail_closed_without_nofollow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_text("{}")
            with mock.patch.object(rea.os, "O_NOFOLLOW", 0):
                with self.assertRaisesRegex(
                    rea.IntegrationError, "no-follow report reads"
                ):
                    rea._read_report(report)
                with self.assertRaisesRegex(
                    rea.IntegrationError, "no-follow comparison reads"
                ):
                    rea._comparison_tree(root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_report_reader_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "report.json"
            os.mkfifo(fifo)
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from scripts.rea_integration import _read_report; _read_report(sys.argv[1])",
                    str(fifo),
                ],
                capture_output=True,
                text=True,
                timeout=2,
                cwd=Path(__file__).parents[1],
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("REA comparison report must be a regular file", result.stderr)

    def test_doctor_summary_preserves_classified_readiness_checks(self):
        report = {
            "checks": [
                {
                    "name": "node",
                    "ok": True,
                    "classification": "healthy",
                    "detail": "24.22.1",
                },
                {
                    "name": "hopper",
                    "ok": False,
                    "classification": "missing_analysis_engine",
                    "remediation": "Configure Hopper",
                    "detail": "private path",
                },
            ]
        }
        self.assertEqual(
            rea._doctor_checks(report),
            [
                {"name": "node", "ok": True, "classification": "healthy"},
                {
                    "name": "hopper",
                    "ok": False,
                    "classification": "missing_analysis_engine",
                    "remediation": "Configure Hopper",
                },
            ],
        )
        with self.assertRaisesRegex(rea.IntegrationError, "invalid readiness check"):
            rea._doctor_checks(
                {
                    "checks": [
                        {
                            "name": "hopper",
                            "ok": "false",
                            "classification": "missing_analysis_engine",
                        }
                    ]
                }
            )

    def test_node_policy_blocks_known_incompatible_runtime(self):
        self.assertFalse(rea.supported_node((22, 23, 3)))
        self.assertTrue(rea.supported_node((22, 23, 4)))
        self.assertTrue(rea.supported_node((24, 22, 1)))
        self.assertTrue(rea.supported_node((26, 12, 1)))
        self.assertFalse(rea.supported_node((25, 0, 0)))

    def test_runtime_verification_rejects_unpinned_lock(self):
        with self.assertRaisesRegex(rea.IntegrationError, "lock"):
            rea.verify_runtime(Path(__file__).parent)

    def test_runtime_verification_binds_manifest_and_package_to_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            lock = rea.ROOT / rea.PIN["package_lock"]
            (runtime / "package-lock.json").write_bytes(lock.read_bytes())
            package = runtime / "node_modules/rea-agents"
            package.mkdir(parents=True)
            metadata = {
                "name": rea.PIN["npm_package"],
                "version": rea.PIN["npm_version"],
            }
            (package / "package.json").write_text(json.dumps(metadata))
            manifest = {
                "source_commit": rea.PIN["source_commit"],
                "npm_version": rea.PIN["npm_version"],
                "npm_integrity": rea.PIN["npm_integrity"],
                "package_lock_sha256": rea.PIN["package_lock_sha256"],
                "package_tree_sha256": rea.package_tree_hash(package),
            }
            marker = runtime / "anti-rea-rea-runtime.json"
            marker.write_text(json.dumps(manifest))
            self.assertEqual(rea.verify_runtime(runtime)[1], manifest)
            for key in (
                "source_commit",
                "npm_version",
                "npm_integrity",
                "package_lock_sha256",
            ):
                altered = dict(manifest, **{key: "untrusted"})
                marker.write_text(json.dumps(altered))
                with (
                    self.subTest(key=key),
                    self.assertRaisesRegex(rea.IntegrationError, "pinned REA identity"),
                ):
                    rea.verify_runtime(runtime)
            marker.write_text(json.dumps(manifest))
            (package / "package.json").write_text(
                json.dumps({"name": "other", "version": rea.PIN["npm_version"]})
            )
            with self.assertRaisesRegex(rea.IntegrationError, "package identity"):
                rea.verify_runtime(runtime)

    def test_mcp_analysis_refuses_unsupported_node_before_launch(self):
        with mock.patch.object(
            rea, "node_version", return_value=("v22.23.3", (22, 23, 3))
        ):
            with self.assertRaisesRegex(rea.IntegrationError, "MCP analysis refused"):
                rea.mcp_analyze("missing-runtime", "missing-target", "unused-output")

    def test_mcp_inventory_refuses_symlink_output_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with mock.patch.object(
                rea, "node_version", return_value=("v24.22.1", (24, 22, 1))
            ):
                with self.assertRaisesRegex(
                    rea.IntegrationError, "existing real directory"
                ):
                    rea.mcp_inventory("missing-runtime", alias / "inventory.json")

    def test_package_hash_tracks_symlinked_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            package.mkdir()
            target = root / "target"
            target.mkdir()
            before = rea.package_tree_hash(package)
            (package / "linked").symlink_to(target, target_is_directory=True)
            self.assertNotEqual(before, rea.package_tree_hash(package))

    def test_rea_comparison_binds_requested_report_target_and_rejects_changed_inputs(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before"
            after = root / "after"
            evidence = root / "evidence"
            before.mkdir()
            after.mkdir()
            evidence.mkdir()
            for target in (before, after):
                (target / "app.js").write_text("export const app = true;\n")
            wrong_target = [True]

            def mock_analyze(runtime, target, report, bundle, timeout):
                target = Path(target)
                report = Path(report)
                bundle = Path(bundle)
                bundle.write_bytes(b"bundle")
                summary = {
                    "predicate_type": "rea.analysis-view",
                    "operation": "inspect_analysis_view",
                    "parameters": {"view": {"kind": "summary"}},
                    "normalized_result": {
                        "artifact": {"path": str(target), "sha256": "a" * 64},
                        "parent_evidence_id": "ev_fixture",
                        "parent_digest": "b" * 64,
                        "summary": {
                            "statistics": {
                                "findings": 1,
                                "relevant_files": 1,
                                "parsed_javascript_files": 1,
                                "skipped_javascript_files": 0,
                                "parse_failures": 0,
                            }
                        },
                        "coverage": {
                            "status": "complete-within-view",
                            "examined": 1,
                            "total": 1,
                            "exhausted": True,
                        },
                    },
                }
                if wrong_target[0]:
                    summary["normalized_result"]["artifact"]["path"] = str(
                        after if target == before else before
                    )
                raw = (json.dumps({"summary": summary}) + "\n").encode()
                report.write_bytes(raw)
                return {
                    "target": str(target),
                    "report": str(report),
                    "report_sha256": rea.sha(raw),
                    "evidence_bundle": str(bundle),
                    "evidence_bundle_sha256": rea.sha(b"bundle"),
                    "runtime_manifest_sha256": "b" * 64,
                }

            with mock.patch.object(rea, "analyze_javascript", side_effect=mock_analyze):
                with self.assertRaisesRegex(rea.IntegrationError, "target identity"):
                    rea.compare_javascript("runtime", before, after, evidence)

            wrong_target[0] = False
            evidence2 = root / "evidence-changed"
            evidence2.mkdir()

            def mutate_during_analysis(runtime, target, report, bundle, timeout):
                result = mock_analyze(runtime, target, report, bundle, timeout)
                if Path(target).resolve() == before.resolve():
                    (before / "app.js").write_text("changed during analysis")
                return result

            with mock.patch.object(
                rea, "analyze_javascript", side_effect=mutate_during_analysis
            ):
                with self.assertRaisesRegex(
                    rea.IntegrationError, "changed while analysis was running"
                ):
                    rea.compare_javascript("runtime", before, after, evidence2)

    def test_bootstrap_removes_only_its_partial_runtime_on_failure(self):
        for error in (subprocess.CalledProcessError(1, ["npm"]), KeyboardInterrupt()):
            with (
                self.subTest(error=type(error).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                runtime = Path(directory) / "new-runtime"
                with (
                    mock.patch.object(
                        rea, "node_version", return_value=("v24.22.1", (24, 22, 1))
                    ),
                    mock.patch.object(rea, "run_bounded", side_effect=error),
                ):
                    with self.assertRaises(type(error)):
                        rea.bootstrap(runtime)
                self.assertFalse(runtime.exists())

    @mock.patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
    def test_bounded_runner_enforces_output_and_timeout_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(rea.IntegrationError, "output budget"):
                rea.run_bounded(
                    [sys.executable, "-c", "print('x' * 10000)"], directory, 5, 32, 32
                )
            with self.assertRaises(subprocess.TimeoutExpired):
                rea.run_bounded(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    directory,
                    0.1,
                    1024,
                    1024,
                )

    @mock.patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
    def test_bounded_runner_identifies_output_stream_and_counts_without_retaining_text(
        self,
    ):
        commands = {
            "stdout": "import sys; sys.stdout.write('x' * 100)",
            "stderr": "import sys; sys.stderr.write('x' * 100)",
            "stdout,stderr": "import sys; sys.stdout.write('x' * 100); sys.stderr.write('y' * 100)",
        }
        with tempfile.TemporaryDirectory() as directory:
            for expected, script in commands.items():
                with (
                    self.subTest(exceeded=expected),
                    self.assertRaises(rea.IntegrationError) as raised,
                ):
                    rea.run_bounded(
                        [sys.executable, "-u", "-c", script], directory, 5, 32, 32
                    )
                message = str(raised.exception)
                self.assertIn(f"exceeded={expected}", message)
                self.assertRegex(message, r"stdout=\d+/32 bytes, stderr=\d+/32 bytes")
                self.assertNotIn("xxxxxxxx", message)

    def test_probe_and_doctor_use_bounded_output_runner(self):
        runtime = Path("/runtime")
        manifest = {"runtime": "pinned"}
        with (
            mock.patch.object(
                rea, "node_version", return_value=("v24.22.1", (24, 22, 1))
            ),
            mock.patch.object(rea, "verify_runtime", return_value=(runtime, manifest)),
            mock.patch.object(
                rea, "run_bounded", side_effect=rea.IntegrationError("output budget")
            ) as run,
        ):
            with self.assertRaisesRegex(rea.IntegrationError, "output budget"):
                rea.probe(runtime, timeout=17)
            self.assertEqual(run.call_args.args[2:], (17, 1024 * 1024, 1024 * 1024))
            with self.assertRaisesRegex(rea.IntegrationError, "output budget"):
                rea.doctor(runtime, Path("/unused"), timeout=19)
            self.assertEqual(run.call_args.args[2:], (19, 8 * 1024 * 1024, 1024 * 1024))

    def test_catalog_inventory_is_package_only_and_version_bound(self):
        inventory = json.loads(
            (
                Path(__file__).parents[1] / "locks/rea-capability-inventory.json"
            ).read_text()
        )
        self.assertEqual(inventory["status"], "package_catalog_only")
        self.assertGreater(inventory["catalog_entry_count"], 100)
        self.assertIn("provider readiness", " ".join(inventory["limitations"]))

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_REA_RUNTIME"),
        "set ANTI_REA_REA_RUNTIME for live REA analysis",
    )
    def test_upstream_analysis_runs_and_retains_both_evidence_outputs(self):
        runtime = Path(os.environ["ANTI_REA_REA_RUNTIME"])
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "raw-output.jsonl"
            bundle = Path(directory) / "evidence.json"
            result = rea.analyze_javascript(
                runtime, root / "fixtures/e2e/web", output, bundle
            )
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["evidence_id"].startswith("ev_"))
            self.assertTrue(output.is_file() and bundle.is_file())

    def test_analysis_summary_requires_complete_scope_and_valid_parent_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.jsonl"
            summary = {
                "predicate_type": "rea.analysis-view",
                "operation": "inspect_analysis_view",
                "parameters": {"view": {"kind": "summary"}},
                "normalized_result": {
                    "parent_evidence_id": "ev_fixture",
                    "parent_digest": "a" * 64,
                    "summary": {
                        "statistics": {
                            "findings": 0,
                            "relevant_files": 1,
                            "parsed_javascript_files": 1,
                            "skipped_javascript_files": 0,
                            "parse_failures": 0,
                        }
                    },
                    "coverage": {
                        "status": "complete-within-view",
                        "exhausted": True,
                        "examined": 1,
                        "total": 1,
                    },
                },
            }
            report.write_text(json.dumps({"summary": summary}) + "\n")
            self.assertEqual(rea._analysis_summary(report)[2]["findings"], 0)
            summary["normalized_result"]["coverage"]["exhausted"] = False
            report.write_text(json.dumps({"summary": summary}) + "\n")
            with self.assertRaisesRegex(rea.IntegrationError, "coverage"):
                rea._analysis_summary(report)
            summary["normalized_result"]["coverage"]["exhausted"] = True
            summary["normalized_result"]["summary"]["statistics"].update(
                parsed_javascript_files=0, skipped_javascript_files=0
            )
            report.write_text(json.dumps({"summary": summary}) + "\n")
            with self.assertRaisesRegex(
                rea.IntegrationError, "source parsing is incomplete"
            ):
                rea._analysis_summary(report)
            summary["normalized_result"]["summary"]["statistics"][
                "skipped_javascript_files"
            ] = 1
            report.write_text(json.dumps({"summary": summary}) + "\n")
            with self.assertRaisesRegex(
                rea.IntegrationError, "source parsing is incomplete"
            ):
                rea._analysis_summary(report)
            summary["normalized_result"]["summary"]["statistics"].update(
                parsed_javascript_files=1, skipped_javascript_files=0, parse_failures=1
            )
            report.write_text(json.dumps({"summary": summary}) + "\n")
            with self.assertRaisesRegex(
                rea.IntegrationError, "source parsing is incomplete"
            ):
                rea._analysis_summary(report)

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_REA_RUNTIME"),
        "set ANTI_REA_REA_RUNTIME for live REA comparison",
    )
    def test_comparable_before_after_reports_findings_without_claiming_protection(self):
        runtime = Path(os.environ["ANTI_REA_REA_RUNTIME"])
        fixture = Path(__file__).parents[1] / "fixtures/e2e/web"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before"
            after = root / "after"
            evidence = root / "evidence"
            evidence.mkdir()
            shutil.copytree(fixture, before)
            shutil.copytree(fixture, after)
            changed = next(after.rglob("*.cjs"))
            changed.write_text(changed.read_text() + "\n// changed candidate\n")
            result = rea.compare_javascript(runtime, before, after, evidence)
            report = json.loads((evidence / "comparison.json").read_text())
            self.assertEqual(result["status"], "measured")
            self.assertEqual(
                result["finding_delta"],
                report["after"]["findings"] - report["before"]["findings"],
            )
            self.assertIn("not proof of protection", report["interpretation"])
            extra = after / "new.js"
            extra.write_text("export const added = true;\n")
            evidence2 = root / "evidence-mismatch"
            evidence2.mkdir()
            with self.assertRaisesRegex(
                rea.IntegrationError, "file scope is not identical"
            ):
                rea.compare_javascript(runtime, before, after, evidence2)
            (after / "scope-link.js").symlink_to(after / "new.js")
            with self.assertRaisesRegex(rea.IntegrationError, "contains a symlink"):
                rea.compare_javascript(runtime, before, after, evidence2)

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_REA_RUNTIME"),
        "set ANTI_REA_REA_RUNTIME for live REA MCP integration",
    )
    def test_upstream_mcp_handshake_lists_and_calls_analysis_tool(self):
        runtime = Path(os.environ["ANTI_REA_REA_RUNTIME"])
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "mcp-evidence.json"
            result = rea.mcp_analyze(runtime, root / "fixtures/e2e/web", evidence)
            self.assertEqual(result["server_version"], "6.8.0")
            self.assertGreater(result["tool_count"], 100)
            self.assertTrue(result["evidence_id"].startswith("ev_"))
            self.assertTrue(evidence.is_file())

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_REA_RUNTIME"),
        "set ANTI_REA_REA_RUNTIME for live REA MCP contract inventory",
    )
    def test_upstream_mcp_inventory_retains_version_bound_schemas(self):
        runtime = Path(os.environ["ANTI_REA_REA_RUNTIME"])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "contracts.json"
            result = rea.mcp_inventory(runtime, output)
            inventory = json.loads(output.read_text())
            self.assertEqual(result["tool_count"], inventory["tool_count"])
            self.assertEqual(result["prompt_count"], inventory["prompt_count"])
            self.assertGreater(result["tool_count"], 100)
            self.assertTrue(
                all(
                    isinstance(tool.get("inputSchema"), dict)
                    for tool in inventory["tools"]
                )
            )
            self.assertTrue(
                all(
                    isinstance(prompt.get("name"), str)
                    for prompt in inventory["prompts"]
                )
            )
            self.assertIn("equivalence", " ".join(inventory["limitations"]))


if __name__ == "__main__":
    unittest.main()
