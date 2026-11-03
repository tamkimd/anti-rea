import importlib.util
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK requires Python 3.11+ clean environment")
@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class MCPInterfaceTests(unittest.TestCase):
    def test_flutter_aot_attachment_mcp_uses_shared_blocker_record(self):
        from core import flutter_android, workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / "state"
            snapshot = state / "evidence" / "baseline-before-build-snapshot"
            apk = snapshot / "build/app/outputs/flutter-apk/app-release.apk"
            apk.parent.mkdir(parents=True); apk.write_bytes(b"mcp-apk")
            command = ["/sdk/flutter", "build", "apk", "--release"]
            toolchain = {"flutter": {"framework_version": "3.47.8", "channel": "stable",
                "framework_revision": "a1", "engine_revision": "b2", "dart_sdk_version": "3.13.7"},
                "android": {"sdk_version": "36.0.0", "platform_version": "android-37", "build_tools_version": "36.0.0", "apksigner_sha256": "f" * 64},
                "java": {"binary": "/opt/jdk/bin/java", "version": "OpenJDK 17"},
                "build": {"target": "apk", "command_sha256": hashlib.sha256(workflow.canonical(command)).hexdigest()}}
            artifact_hash = hashlib.sha256(b"mcp-apk").hexdigest()
            baseline = {"schema_version": "2.0", "record_type": "baseline", "id": "before",
                "target_id": "target-before", "identity": {"command": command, "flutter_toolchain": toolchain,
                    "dependency_lock_sha256": "d" * 64,
                    "artifacts": {"build/app/outputs/flutter-apk/app-release.apk": {
                        "size": len(b"mcp-apk"), "sha256": artifact_hash}},
                    "build_snapshot": {"path": str(snapshot), "source_tree_sha256": "a" * 64,
                        "tree_sha256": "b" * 64, "file_scope_sha256": "c" * 64}}, "evidence": ["before.json"]}
            workflow.write_record(state / "records", baseline)
            report = root / "rea-aot.json"
            report.write_text(json.dumps({"record_type": "anti_rea_upstream_operation_result",
                "operation": "inspect_dart_aot", "status": "blocked", "artifact_sha256": artifact_hash,
                "error": {"category": "unsupported_target", "details": {"diagnostics": {"abi": "arm64-v8a"}}}}))
            manifest = root / "anti-rea-rea-runtime.json"
            runtime_manifest = {"schema_version": "1.0", "npm_version": "6.8.0",
                "npm_integrity": "sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==",
                "package_lock_sha256": "b6cb714948a7ec224fa6f676f0e9b6f570bbabf3518a1a187be571ac8ddfe232",
                "package_tree_sha256": "e" * 64, "node_version": "v24.22.1"}
            manifest.write_text(json.dumps(runtime_manifest))
            with patch.dict(os.environ, {"ANTI_REA_STATE_DIR": str(state)}), \
                    patch.object(flutter_android, "_verify_rea_runtime",
                                  return_value=(manifest, manifest.read_bytes(), runtime_manifest)):
                result = server.attach_flutter_aot_inspection("before", "before-aot", str(report),
                                                              str(root), "arm64-v8a")
            self.assertEqual((result["status"], result["aot_status"]), ("attached", "unsupported"))
            saved = workflow.read_record(state / "records" / "baseline-before-aot.json", "baseline")
            self.assertEqual(saved["identity"]["flutter_aot_inspection"]["artifact_sha256"], artifact_hash)

    def test_flutter_android_probe_delegates_to_shared_readiness_core(self):
        from interfaces.mcp import server
        expected={"status":"blocked","checks":{"android_licenses":"not_accepted"}}
        with patch("interfaces.mcp.server.flutter_android.probe_android_environment",
                   return_value=expected) as probe:
            self.assertEqual(server.probe_flutter_android_environment("/sdk/flutter",90),expected)
        probe.assert_called_once_with("/sdk/flutter",90)

    def test_server_shutdown_stops_and_joins_active_execution(self):
        from interfaces.mcp import server
        cancel_event=threading.Event()
        process=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],
                                 start_new_session=(os.name != "nt"))
        worker_finished=threading.Event()
        def wait_for_shutdown():
            cancel_event.wait(5)
            process.wait()
            worker_finished.set()
        worker=threading.Thread(target=wait_for_shutdown,daemon=True)
        with server._execution_jobs_lock:
            server._execution_jobs.add("shutdown-fixture")
            server._execution_controls["shutdown-fixture"]=(cancel_event,{"process":process,"thread":worker})
        worker.start()
        try:
            server._shutdown_active_executions()
            self.assertTrue(cancel_event.is_set())
            self.assertIsNotNone(process.poll())
            self.assertTrue(worker_finished.is_set())
            self.assertFalse(worker.is_alive())
        finally:
            with server._execution_jobs_lock:
                server._execution_jobs.discard("shutdown-fixture")
                server._execution_controls.pop("shutdown-fixture",None)
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_cancel_run_persists_terminal_state(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            server.save_target({"schema_version":"2.0","record_type":"target","id":"target-cancel",
                                "components":[{"id":"web","kind":"fixture"}]})
            server.create_run("target-cancel","run-cancel")
            result=server.cancel_run("run-cancel")
            self.assertEqual(result["state"],"cancelled")
            self.assertEqual(server.get_run("run-cancel")["cancellation_reason"],"user_requested")

    def test_get_report_replays_accepted_evidence_and_allows_incomplete_runs(self):
        from core import baseline, execution, recommendations, workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            root=Path(directory)
            incomplete_target={"schema_version":"2.0","record_type":"target","id":"target-report-incomplete",
                              "components":[{"id":"web","kind":"fixture"}]}
            server.save_target(incomplete_target)
            server.create_run(incomplete_target["id"],"run-report-incomplete")
            incomplete=server.get_report("run-report-incomplete")
            self.assertEqual(incomplete["run"]["state"],"discovered")
            self.assertEqual(incomplete["target"]["id"],incomplete_target["id"])
            self.assertNotIn("acceptance",incomplete)
            self.assertEqual(incomplete["rollbacks"],[])

            project=root/"project"; project.mkdir()
            (project/"build.py").write_text(
                "from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\n"
                "Path('dist/app.js').write_text('bundle')\n"
                "Path('dist/app.js.map').write_text('private map')\n"
                "Path('dist/keep.txt').write_text('keep')\n")
            store=root/"state"
            captured,_=baseline.capture(project,store,[sys.executable,"build.py"],
                ["dist/app.js","dist/app.js.map","dist/keep.txt"],"base-report-mcp")
            target=workflow.read_record(store/"records"/f"target-{captured['target_id']}.json","target")
            plan=recommendations.create_plan(target,captured,"plan-report-mcp")
            action=next(item for item in plan["actions"]
                        if item.get("verification")==["public_source_map_absent"])
            workflow.write_record(store/"records",plan)
            server.create_run(target["id"],"run-report-complete")
            server.transition_run("run-report-complete","baselining",{"baseline_id":captured["id"]})
            server.submit_plan("run-report-complete",plan)
            decision={"schema_version":"2.0","record_type":"decision","id":"decision-report-mcp",
                      "plan_sha256":workflow.record_hash(plan),"selected_action_ids":[action["id"]],
                      "decision":"approved","decision_source":"owned source-map fixture"}
            server.record_decision("run-report-complete",decision)
            server.authorize_run("run-report-complete")
            result=execution.execute_bla_action(store,"run-report-complete",action["id"],None)
            verification=workflow.read_record(store/"records"/f"verification-{result['verification_id']}.json","verification")
            execution_record=workflow.read_record(store/"records"/f"execution-{result['execution_id']}.json","execution")
            acceptance={"schema_version":"2.0","record_type":"acceptance","id":"accept-report-mcp",
                        "run_id":"run-report-complete","outcome":"accepted",
                        "claims":[],"claim_ids":["source_map_omitted_from_private_candidate"],
                        "reasons":["Source-map candidate manifest and preserved files passed validation"],
                        "verification_id":verification["id"],"execution_id":execution_record["id"],
                        "plan_sha256":workflow.record_hash(plan)}
            accepted=server.accept_run("run-report-complete",execution_record["id"],verification,acceptance)
            self.assertEqual(accepted["acceptance"],"accepted")
            report=server.get_report("run-report-complete")
            self.assertEqual(report["status"],"ok")
            self.assertEqual(report["run"]["acceptance"],"accepted")
            self.assertEqual(report["target"]["id"],target["id"])
            self.assertEqual(report["baseline"]["id"],captured["id"])
            self.assertEqual(report["plan"]["id"],plan["id"])
            self.assertEqual(report["decision"]["id"],decision["id"])
            self.assertEqual(report["execution"]["id"],execution_record["id"])
            self.assertEqual(report["verification"]["id"],verification["id"])
            self.assertEqual(report["acceptance"]["id"],acceptance["id"])

            manifest_ref=execution_record["evidence"][0]
            manifest_path=Path(manifest_ref["path"])
            manifest=json.loads(manifest_path.read_text())
            manifest["candidate_files"]["dist/app.js.map"] = captured["identity"]["artifacts"]["dist/app.js.map"]["sha256"]
            tampered=workflow.canonical(manifest)
            manifest_path.write_bytes(tampered)
            tampered_sha=hashlib.sha256(tampered).hexdigest()
            execution_record["outputs"][0]["sha256"]=tampered_sha
            execution_record["evidence"][0]["sha256"]=tampered_sha
            verification["checks"][0]["evidence"][0]["sha256"]=tampered_sha
            (store/"records"/f"execution-{execution_record['id']}.json").write_text(json.dumps(execution_record))
            (store/"records"/f"verification-{verification['id']}.json").write_text(json.dumps(verification))
            with self.assertRaisesRegex(workflow.WorkflowError,"candidate removed more than the selected map"):
                server.get_report("run-report-complete")
            from interfaces.cli import anti_rea
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                result=anti_rea.main(["report","run-report-complete",str(store)])
            self.assertEqual(result,2)
            self.assertEqual(json.loads(output.getvalue())["status"],"failed")

    def test_async_baseline_returns_run_id_and_persists_capture(self):
        from core import workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/"state";project=Path(directory)/"project";project.mkdir()
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state)}):
                (project/"app.js").write_text("before")
                scheduled=server.start_baseline_async(str(project),[sys.executable,"-c","import time; time.sleep(.1)"],
                    ["app.js"],"baseline-async","run-baseline-async")
                self.assertEqual((scheduled["status"],scheduled["state"],scheduled["poll_tool"]),
                                 ("scheduled","baselining","get_run"))
                with server._execution_jobs_lock:
                    worker=server._execution_controls["run-baseline-async"][1]["thread"]
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                run=server.get_run("run-baseline-async")
                baseline=workflow.read_record(state/"records"/"baseline-baseline-async.json","baseline")
                self.assertEqual((run["state"],run["baseline_id"],run["operation_active"]),
                                 ("baselining","baseline-async",False))
                self.assertEqual(baseline["target_id"],run["target_id"])

    def test_async_baseline_worker_start_failure_marks_run_failed_and_clears_worker(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/"state";project=Path(directory)/"project";project.mkdir()
            (project/"app.js").write_text("before")
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state)}), \
                    patch.object(server.threading.Thread,"start",side_effect=RuntimeError("thread unavailable")):
                with self.assertRaisesRegex(RuntimeError,"thread unavailable"):
                    server.start_baseline_async(str(project),[sys.executable,"-c","pass"],
                        ["app.js"],"baseline-start-failure","run-start-failure")
                self.assertEqual(server.get_run("run-start-failure")["state"],"failed")
                with server._execution_jobs_lock:
                    self.assertNotIn("run-start-failure",server._execution_jobs)
                    self.assertNotIn("run-start-failure",server._execution_controls)

    def test_completed_async_baseline_can_be_cancelled_before_plan_submission(self):
        from core import workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/"state";project=Path(directory)/"project";project.mkdir()
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state)}):
                (project/"app.js").write_text("before")
                server.start_baseline_async(str(project),[sys.executable,"-c","pass"],
                    ["app.js"],"baseline-cancel-complete","run-cancel-complete")
                with server._execution_jobs_lock:
                    worker=server._execution_controls["run-cancel-complete"][1]["thread"]
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                baseline=workflow.read_record(
                    state/"records"/"baseline-baseline-cancel-complete.json","baseline")
                result=server.cancel_run("run-cancel-complete")
                self.assertEqual((result["status"],server.get_run("run-cancel-complete")["state"]),
                                 ("cancelled","cancelled"))
                self.assertEqual(workflow.read_record(
                    state/"records"/"baseline-baseline-cancel-complete.json","baseline"),baseline)

    def test_completed_baseline_cancellation_rejects_record_id_mismatch(self):
        from interfaces.mcp import server
        from core import workflow
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/"state";project=Path(directory)/"project";project.mkdir()
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state)}):
                (project/"app.js").write_text("before")
                server.start_baseline_async(str(project),[sys.executable,"-c","pass"],
                    ["app.js"],"baseline-cancel-mismatch","run-cancel-mismatch")
                with server._execution_jobs_lock:
                    worker=server._execution_controls["run-cancel-mismatch"][1]["thread"]
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                baseline_path=state/"records"/"baseline-baseline-cancel-mismatch.json"
                baseline=workflow.read_record(baseline_path,"baseline")
                baseline["id"]="baseline-other-id"
                baseline_path.write_text(json.dumps(baseline))
                with self.assertRaisesRegex(workflow.WorkflowError,"does not match the run"):
                    server.cancel_run("run-cancel-mismatch")
                self.assertEqual(server.get_run("run-cancel-mismatch")["state"],"baselining")

    def test_flutter_android_baseline_async_uses_shared_capture_and_private_symbols(self):
        from core import workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);state=base/"state";project=base/"project"
            (project/"android").mkdir(parents=True)
            (project/"pubspec.yaml").write_text("name: flutter_fixture\n")
            flutter=base/"flutter"
            flutter.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\nimport sys\n"
                "import time\ntime.sleep(.1)\n"
                "artifact=Path('build/app/outputs/flutter-apk/app-release.apk')\n"
                "artifact.parent.mkdir(parents=True,exist_ok=True)\nartifact.write_bytes(b'fixture-apk')\n"
                "symbols=Path(next(arg.split('=',1)[1] for arg in sys.argv if arg.startswith('--split-debug-info=')))\n"
                "symbols.mkdir(parents=True)\n(symbols/'app.symbols').write_bytes(b'fixture-symbols')\n")
            flutter.chmod(0o700)
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state)}), \
                    patch("core.flutter_android.shutil.which",return_value=str(flutter)), \
                    patch("core.flutter_android.capture_toolchain_identity", side_effect=lambda command, cwd: {
                        "flutter":{"framework_version":"3.47.8","channel":"stable","framework_revision":"a1",
                                   "engine_revision":"b2","dart_sdk_version":"3.13.7"},
                        "android":{"sdk_version":"36.0.0","platform_version":"android-37","build_tools_version":"36.0.0","apksigner_sha256":"f"*64},
                        "java":{"binary":"/opt/jdk/bin/java","version":"OpenJDK 17"},
                        "build":{"target":command[2],"command_sha256":hashlib.sha256(workflow.canonical(command)).hexdigest()}}):
                scheduled=server.start_flutter_android_baseline_async(
                    str(project),"flutter-before","flutter-run","apk",str(state/"symbols"),str(flutter),
                    obfuscate=True)
                with server._execution_jobs_lock:
                    worker=server._execution_controls["flutter-run"][1]["thread"]
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                baseline=workflow.read_record(state/"records"/"baseline-flutter-before.json","baseline")
                self.assertEqual((scheduled["status"],scheduled["poll_tool"]),("scheduled","get_run"))
                self.assertEqual(set(baseline["identity"]["artifacts"]),
                                 {"build/app/outputs/flutter-apk/app-release.apk"})
                self.assertEqual((state/"symbols"/"app.symbols").read_bytes(),b"fixture-symbols")

    def test_flutter_android_baseline_async_defaults_to_unobfuscated_release(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);state=base/"state";project=base/"project"
            (project/"android").mkdir(parents=True)
            (project/"pubspec.yaml").write_text("name: flutter_fixture\n")
            args_file=base/"flutter-argv.json"
            flutter=base/"flutter"
            flutter.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\nimport json, os, sys\n"
                "Path(os.environ['ANTI_REA_ARGS_OUTPUT']).write_text(json.dumps(sys.argv))\n"
                "artifact=Path('build/app/outputs/flutter-apk/app-release.apk')\n"
                "artifact.parent.mkdir(parents=True,exist_ok=True)\nartifact.write_bytes(b'fixture-before-apk')\n")
            flutter.chmod(0o700)
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state),"ANTI_REA_ARGS_OUTPUT":str(args_file)}), \
                    patch("core.flutter_android.shutil.which",return_value=str(flutter)), \
                    patch("core.flutter_android.capture_toolchain_identity", side_effect=lambda command, cwd: {
                        "flutter":{"framework_version":"3.47.8","channel":"stable","framework_revision":"a1",
                                   "engine_revision":"b2","dart_sdk_version":"3.13.7"},
                        "android":{"sdk_version":"36.0.0","platform_version":"android-37","build_tools_version":"36.0.0","apksigner_sha256":"f"*64},
                        "java":{"binary":"/opt/jdk/bin/java","version":"OpenJDK 17"},
                        "build":{"target":command[2],"command_sha256":hashlib.sha256(workflow.canonical(command)).hexdigest()}}):
                scheduled=server.start_flutter_android_baseline_async(
                    str(project),"flutter-unobfuscated-before","flutter-unobfuscated-run","apk",flutter=str(flutter))
                with server._execution_jobs_lock:
                    worker=server._execution_controls["flutter-unobfuscated-run"][1]["thread"]
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(scheduled["status"],"scheduled")
            argv=json.loads(args_file.read_text())
            self.assertEqual(argv[1:4],["build","apk","--release"])
            self.assertNotIn("--obfuscate",argv)
            self.assertFalse(any(argument.startswith("--split-debug-info=") for argument in argv))

    def test_flutter_android_baseline_refuses_symbol_output_outside_state(self):
        from core import workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            with self.assertRaisesRegex(workflow.WorkflowError,"direct child of Anti-REA state"):
                server.start_flutter_android_baseline_async(
                    directory,"outside-before","outside-run","apk",str(Path(directory)/"symbols"),
                    obfuscate=True)

    def test_flutter_android_mcp_rejects_split_debug_info_without_obfuscation(self):
        from core import workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            project=Path(directory)/"project"
            project.mkdir()
            (project/"android").mkdir()
            (project/"pubspec.yaml").write_text("name: fixture\n")
            with self.assertRaisesRegex(workflow.WorkflowError, "requires --obfuscate"):
                server.start_flutter_android_baseline_async(
                    str(project),"bad-symbols","bad-symbols-run","apk",str(Path(directory)/"state"/"symbols"))

    def test_approved_optimization_search_runs_async_and_persists_result(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            root=server.store_root()
            (root/"records").mkdir(exist_ok=True)
            (root/"runs").mkdir(exist_ok=True)
            search={"schema_version":"2.0","record_type":"optimization_search","id":"mcp-search",
                    "candidate_sets":[{"id":"candidate-a"}]}
            started=threading.Event();finish=threading.Event()
            original_read=server.workflow.read_record
            def read_record(path,kind=None):
                if kind=="optimization_search":
                    return search
                return original_read(path,kind)
            def run_search(_store,search_id,_bla,_rea,_e2e,cancel_event,_on_process):
                started.set();finish.wait(timeout=5)
                return {"status":"not_evaluated","search_id":search_id,
                        "cancelled":cancel_event.is_set()}
            with patch.object(server.workflow,"read_record",side_effect=read_record), \
                    patch.object(server.optimizer,"execute_approved_search",side_effect=run_search):
                scheduled=server.start_approved_optimization_search("mcp-search")
                self.assertEqual((scheduled["status"],scheduled["run_id"],scheduled["poll_tool"]),
                                 ("scheduled","mcp-search","get_approved_optimization_search"))
                key=server._optimization_operation_key("mcp-search")
                with server._execution_jobs_lock:
                    worker=server._execution_controls[key][1]["thread"]
                self.assertTrue(started.wait(timeout=5))
                self.assertEqual(server.get_approved_optimization_search("mcp-search")["status"],"running")
                finish.set();worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                result=server.get_approved_optimization_search("mcp-search")
                self.assertEqual(result["status"],"completed")
                self.assertEqual(result["result"]["search_id"],"mcp-search")
                persisted=server.workflow.read_json(
                    root/"runs"/"optimization-search-mcp-search.json")
                self.assertEqual(persisted["status"],"completed")
                self.assertNotIn(key,server._execution_controls)

    def test_cancel_approved_optimization_search_stops_active_process(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            root=server.store_root()
            (root/"records").mkdir(exist_ok=True)
            (root/"runs").mkdir(exist_ok=True)
            search={"schema_version":"2.0","record_type":"optimization_search","id":"mcp-cancel-search",
                    "candidate_sets":[{"id":"candidate-a"}]}
            original_read=server.workflow.read_record
            def read_record(path,kind=None):
                if kind=="optimization_search":
                    return search
                return original_read(path,kind)
            process_started=threading.Event()
            def run_search(_store,search_id,_bla,_rea,_e2e,cancel_event,on_process):
                process=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],
                                         start_new_session=(os.name!="nt"))
                on_process(process);process_started.set();cancel_event.wait(timeout=10)
                process.wait(timeout=5)
                return {"status":"not_evaluated","search_id":search_id,
                        "cancelled":cancel_event.is_set()}
            with patch.object(server.workflow,"read_record",side_effect=read_record), \
                    patch.object(server.optimizer,"execute_approved_search",side_effect=run_search):
                server.start_approved_optimization_search("mcp-cancel-search")
                key=server._optimization_operation_key("mcp-cancel-search")
                with server._execution_jobs_lock:
                    control=server._execution_controls[key][1]
                    worker=control["thread"]
                self.assertTrue(process_started.wait(timeout=5))
                process=control["process"]
                cancelled=server.cancel_approved_optimization_search("mcp-cancel-search")
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertIsNotNone(process.poll())
                self.assertEqual(cancelled["status"],"cancellation_requested")
                self.assertTrue(server.get_approved_optimization_search(
                    "mcp-cancel-search")["result"]["cancelled"])

    def test_optimization_search_poll_reports_interrupted_state_after_restart(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            root=server.store_root()
            (root/"records").mkdir(exist_ok=True)
            (root/"runs").mkdir(exist_ok=True)
            search={"schema_version":"2.0","record_type":"optimization_search","id":"mcp-restart-search",
                    "candidate_sets":[{"id":"candidate-a"}]}
            original_read=server.workflow.read_record
            def read_record(path,kind=None):
                if kind=="optimization_search":
                    return search
                return original_read(path,kind)
            with patch.object(server.workflow,"read_record",side_effect=read_record):
                server._write_optimization_operation(search,"running")
                result=server.get_approved_optimization_search("mcp-restart-search")
            self.assertEqual(result["status"],"interrupted")
            self.assertFalse(result["operation_active"])
            self.assertEqual(result["candidate_results"],
                             [{"candidate_id":"candidate-a","status":"not_evaluated"}])

    def test_optimization_search_reservation_is_exclusive_across_concurrent_callers(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            search={"schema_version":"2.0","record_type":"optimization_search","id":"mcp-exclusive-search",
                    "candidate_sets":[{"id":"candidate-a"}]}
            barrier=threading.Barrier(2)
            outcomes=[]
            def reserve():
                barrier.wait()
                try:
                    server._write_optimization_operation(search,"running",exclusive=True)
                    outcomes.append("reserved")
                except FileExistsError:
                    outcomes.append("already_reserved")
            callers=[threading.Thread(target=reserve) for _ in range(2)]
            for caller in callers: caller.start()
            for caller in callers: caller.join(timeout=5)
            self.assertTrue(all(not caller.is_alive() for caller in callers))
            self.assertCountEqual(outcomes,["reserved","already_reserved"])
            self.assertEqual(server._read_optimization_operation(search)["status"],"running")

    def test_optimization_search_reservation_is_exclusive_across_server_processes(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            root=Path(directory)/"state"
            search={"schema_version":"2.0","record_type":"optimization_search",
                    "id":"mcp-process-exclusive-search","candidate_sets":[{"id":"candidate-a"}]}
            env={**os.environ,"ANTI_REA_STATE_DIR":str(root),
                 "ANTI_REA_TEST_SEARCH":json.dumps(search)}
            script=(
                "import json, os\n"
                "from interfaces.mcp import server\n"
                "search=json.loads(os.environ['ANTI_REA_TEST_SEARCH'])\n"
                "try:\n"
                "    server._write_optimization_operation(search, 'running', exclusive=True)\n"
                "    print('reserved')\n"
                "except FileExistsError:\n"
                "    print('already_reserved')\n"
            )
            children=[subprocess.Popen([sys.executable,"-c",script],cwd=Path(__file__).parents[1],
                                       env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                      for _ in range(2)]
            outcomes=[]
            try:
                for child in children:
                    stdout,stderr=child.communicate(timeout=15)
                    self.assertEqual(child.returncode,0,stderr)
                    outcomes.append(stdout.strip())
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
            self.assertCountEqual(outcomes,["reserved","already_reserved"])
            self.assertEqual(server._read_optimization_operation(search)["status"],"running")

    def test_optimization_search_start_failure_persists_failed_state_and_clears_worker(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,{"ANTI_REA_STATE_DIR":str(Path(directory)/"state")}):
            root=server.store_root()
            (root/"records").mkdir(exist_ok=True)
            search={"schema_version":"2.0","record_type":"optimization_search","id":"mcp-start-failure",
                    "candidate_sets":[{"id":"candidate-a"}]}
            original_read=server.workflow.read_record
            def read_record(path,kind=None):
                if kind=="optimization_search":
                    return search
                return original_read(path,kind)
            with patch.object(server.workflow,"read_record",side_effect=read_record), \
                    patch.object(server.threading.Thread,"start",side_effect=RuntimeError("thread unavailable")):
                with self.assertRaisesRegex(RuntimeError,"thread unavailable"):
                    server.start_approved_optimization_search("mcp-start-failure")
            key=server._optimization_operation_key("mcp-start-failure")
            with server._execution_jobs_lock:
                self.assertNotIn(key,server._execution_jobs)
                self.assertNotIn(key,server._execution_controls)
            with patch.object(server.workflow,"read_record",side_effect=read_record):
                result=server.get_approved_optimization_search("mcp-start-failure")
            self.assertEqual(result["status"],"failed")
            self.assertEqual(result["error"],"thread unavailable")

    def test_cancel_async_baseline_terminates_build_and_marks_cancelled(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/"state";project=Path(directory)/"project";project.mkdir()
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state)}):
                (project/"app.js").write_text("before")
                server.start_baseline_async(str(project),[sys.executable,"-c","import time; time.sleep(30)"],
                    ["app.js"],"baseline-cancel-async","run-cancel-async")
                deadline=time.monotonic()+5
                process=None
                while time.monotonic()<deadline:
                    with server._execution_jobs_lock:
                        active=server._execution_controls.get("run-cancel-async")
                        process=active[1].get("process") if active else None
                    if process is not None:
                        break
                    time.sleep(.01)
                self.assertIsNotNone(process,"baseline child process did not start")
                result=server.cancel_run("run-cancel-async")
                with server._execution_jobs_lock:
                    worker=server._execution_controls["run-cancel-async"][1]["thread"]
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertIsNotNone(process.poll())
                self.assertEqual(result["status"],"cancellation_requested")
                self.assertEqual(server.get_run("run-cancel-async")["state"],"cancelled")

    def test_cancel_async_baseline_at_capture_completion_marks_cancelled(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/"state";project=Path(directory)/"project";project.mkdir()
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state)}):
                (project/"app.js").write_text("before")
                capture_started=threading.Event();allow_finish=threading.Event()
                def capture(*args,**kwargs):
                    capture_started.set()
                    allow_finish.wait(timeout=5)
                with patch.object(server.baseline_capture,"capture",capture):
                    server.start_baseline_async(str(project),[sys.executable,"-c","pass"],["app.js"],
                        "baseline-cancel-race","run-cancel-race")
                    self.assertTrue(capture_started.wait(timeout=5))
                    result=server.cancel_run("run-cancel-race")
                    allow_finish.set()
                    with server._execution_jobs_lock:
                        worker=server._execution_controls["run-cancel-race"][1]["thread"]
                    worker.join(timeout=5)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(result["status"],"cancellation_requested")
                    self.assertEqual(server.get_run("run-cancel-race")["state"],"cancelled")

    def test_cancel_verifying_run_quarantines_unchanged_candidate(self):
        from core import workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            root=Path(directory)
            for name in ("records","runs","candidates"):
                (root/name).mkdir()
            candidate=root/"candidates"/"candidate.js";candidate.write_bytes(b"candidate")
            digest=hashlib.sha256(b"candidate").hexdigest()
            run={"schema_version":"2.0","record_type":"run","id":"run-cancel-verifying",
                 "target_id":"target-cancel-verifying","state":"discovered"}
            run_path=workflow.write_run_state(root/"runs",run,None)
            for next_state,updates in (("baselining",{}),("awaiting_decision",{"baseline_id":"base-cancel-verifying",
                    "plan_id":"plan-cancel-verifying"}),("preparing",{"decision_id":"decision-cancel-verifying"}),
                    ("executing",{}),("verifying",{"execution_id":"exec-cancel-verifying",
                    "verification_id":"verify-cancel-verifying"})):
                changed=workflow.transition_run(run,next_state,**updates)
                workflow.write_run_state(run_path.parent,changed,run)
                run=changed
            execution_record={"schema_version":"2.0","record_type":"execution","id":"exec-cancel-verifying",
                              "run_id":run["id"],"plan_sha256":"a"*64,"commands":[["fixture"]],
                              "exit_code":0,"outputs":[{"path":str(candidate),"sha256":digest}]}
            workflow.write_record(root/"records",execution_record)
            result=server.cancel_run(run["id"])
            self.assertEqual(result["state"],"cancelled")
            self.assertFalse(candidate.exists())
            rollback=workflow.read_record(next((root/"records").glob("rollback-*.json")),"rollback")
            retained=Path(rollback["artifacts"][0]["retained_path"])
            self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(),digest)

    def test_create_run_rejects_path_like_ids_before_file_access(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            with self.assertRaisesRegex(ValueError,"target id"):
                server.create_run("../outside","run-safe")
            with self.assertRaisesRegex(ValueError,"run id"):
                server.create_run("target-safe","../outside")
            self.assertFalse((Path(directory).parent/"target-outside.json").exists())

    def test_cancel_run_stops_active_execution_process(self):
        from core import baseline, workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            target={"schema_version":"2.0","record_type":"target","id":"target-live-cancel",
                    "components":[{"id":"web","kind":"fixture"}]}
            baseline_record={"schema_version":"2.0","record_type":"baseline","id":"base-live-cancel",
                             "target_id":target["id"],"identity":{"source":"fixture"},"evidence":["before.json"]}
            action={"id":"protect","finding_or_asset":"fixture","change":"fixture","mechanism":"fixture",
                    "engine":"fixture","expected_benefit":"test cancellation","cost":"none","tradeoffs":["fixture"],
                    "dependencies":["none"],"compatibility":["fixture"],"verification":["behavior"],
                    "limitations":["no protection claim"],"rollback":"discard"}
            plan={"schema_version":"2.0","record_type":"plan","id":"plan-live-cancel",
                  "target_id":target["id"],"baseline_id":baseline_record["id"],"actions":[action],
                  "budgets":{"runtime_ms":1000},"rollback":"discard"}
            server.save_target(target);server.save_baseline(baseline_record);server.save_plan(plan)
            server.create_run(target["id"],"run-live-cancel")
            server.transition_run("run-live-cancel","baselining")
            server.submit_plan("run-live-cancel",plan)
            decision={"schema_version":"2.0","record_type":"decision","id":"decision-live-cancel",
                      "plan_sha256":workflow.record_hash(plan),"selected_action_ids":["protect"],
                      "decision":"approved","decision_source":"test"}
            server.record_decision("run-live-cancel",decision);server.authorize_run("run-live-cancel")
            process_finished=threading.Event()
            def blocking_execution(store,run_id,action_id,runtime,cancel_event,on_process,rea_runtime=None,e2e_runtime=None):
                path=Path(store)/"runs"/f"run-{run_id}.json"
                current=workflow.read_record(path,"run");active=workflow.transition_run(current,"executing")
                workflow.write_run_state(path.parent,active,current)
                try:
                    baseline._run_command([sys.executable,"-c","import time; time.sleep(30)"],Path(directory),60,on_process,cancel_event)
                except workflow.WorkflowError:
                    current=workflow.read_record(path,"run")
                    cancelled=workflow.transition_run(current,"cancelled",cancellation_reason="user_requested")
                    workflow.write_run_state(path.parent,cancelled,current)
                    raise
                finally:
                    process_finished.set()
            with patch.object(server.execution,"execute_bla_action",blocking_execution):
                server.execute_plan("run-live-cancel","protect","unused-runtime", "unused-rea-runtime")
                for _ in range(50):
                    with server._execution_jobs_lock:
                        active=server._execution_controls.get("run-live-cancel")
                        process=active[1].get("process") if active else None
                    if process is not None: break
                    time.sleep(.02)
                self.assertIsNotNone(process)
                self.assertEqual(server.cancel_run("run-live-cancel")["status"],"cancellation_requested")
                self.assertTrue(process_finished.wait(3))
                for _ in range(50):
                    state=server.get_run("run-live-cancel")
                    if not state["execution_active"]: break
                    time.sleep(.02)
                self.assertEqual(state["state"],"cancelled")
                self.assertIsNotNone(process.poll())

    def test_execution_worker_start_failure_marks_run_failed_and_clears_worker(self):
        from core import workflow
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            target={"schema_version":"2.0","record_type":"target","id":"target-start-failure",
                    "components":[{"id":"web","kind":"fixture"}]}
            baseline_record={"schema_version":"2.0","record_type":"baseline","id":"base-start-failure",
                             "target_id":target["id"],"identity":{"source":"fixture"},"evidence":["before.json"]}
            action={"id":"protect","finding_or_asset":"fixture","change":"fixture","mechanism":"fixture",
                    "engine":"fixture","expected_benefit":"test worker startup","cost":"none","tradeoffs":["fixture"],
                    "dependencies":["none"],"compatibility":["fixture"],"verification":["behavior"],
                    "limitations":["no protection claim"],"rollback":"discard"}
            plan={"schema_version":"2.0","record_type":"plan","id":"plan-start-failure",
                  "target_id":target["id"],"baseline_id":baseline_record["id"],"actions":[action],
                  "budgets":{"runtime_ms":1000},"rollback":"discard"}
            server.save_target(target);server.save_baseline(baseline_record);server.save_plan(plan)
            server.create_run(target["id"],"run-execution-start-failure")
            server.transition_run("run-execution-start-failure","baselining")
            server.submit_plan("run-execution-start-failure",plan)
            decision={"schema_version":"2.0","record_type":"decision","id":"decision-start-failure",
                      "plan_sha256":workflow.record_hash(plan),"selected_action_ids":["protect"],
                      "decision":"approved","decision_source":"test"}
            server.record_decision("run-execution-start-failure",decision)
            server.authorize_run("run-execution-start-failure")
            with patch.object(server.threading.Thread,"start",side_effect=RuntimeError("thread unavailable")):
                with self.assertRaisesRegex(RuntimeError,"thread unavailable"):
                    server.execute_plan("run-execution-start-failure","protect","unused-runtime")
            self.assertEqual(server.get_run("run-execution-start-failure")["state"],"failed")
            with server._execution_jobs_lock:
                self.assertNotIn("run-execution-start-failure",server._execution_jobs)
                self.assertNotIn("run-execution-start-failure",server._execution_controls)

    def test_start_baseline_uses_shared_capture_and_persists_record(self):
        from interfaces.mcp import server
        from core import workflow
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); project=base/"project"; project.mkdir()
            (project/"pyproject.toml").write_text("[project]\nname='fixture'\n")
            (project/"build.py").write_text("from pathlib import Path\nPath('out.bin').write_bytes(b'ok')\n")
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(base/"state")}):
                result=server.start_baseline(str(project),[sys.executable,"build.py"],["out.bin"],"before-mcp",
                                             build_time_trials=2)
                self.assertEqual(result["status"],"captured")
                self.assertEqual(len(result["build_timing"]["trials"]),2)
                saved=server.get_target(result["target_id"])
                self.assertEqual(saved["record_type"],"target")
                baseline=workflow.read_record(base/"state"/"records"/"baseline-before-mcp.json","baseline")
                self.assertEqual(baseline["identity"]["artifacts"]["out.bin"]["size"],2)
                self.assertGreaterEqual(baseline["identity"]["build_duration_ms"],0)

    def test_start_baseline_accepts_optional_behavior_command(self):
        from interfaces.mcp import server
        from core import workflow
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);project=base/"project";project.mkdir()
            (project/"pyproject.toml").write_text("[project]\nname='fixture'\n")
            (project/"build.py").write_text("from pathlib import Path\nPath('app.js').write_text('fixture')\n")
            behavior=[sys.executable,"-c","import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())","{artifact}"]
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(base/"state")}):
                result=server.start_baseline(str(project),[sys.executable,"build.py"],["app.js"],
                                             "before-mcp-behavior",behavior_command=behavior)
                baseline=workflow.read_record(base/"state"/"records"/"baseline-before-mcp-behavior.json","baseline")
                self.assertEqual(baseline["identity"]["behavior"]["command"],behavior)
                self.assertEqual(result["behavior_evidence"],baseline["identity"]["behavior"]["evidence_path"])

    @unittest.skipUnless(os.environ.get("ANTI_REA_E2E_RUNTIME"), "pinned e2e runtime is required")
    def test_start_baseline_captures_pinned_e2e_before_report(self):
        from interfaces.mcp import server
        from core import workflow
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); project=base/"project"; state=base/"state"
            shutil.copytree(Path(__file__).parents[1]/"fixtures/e2e/web",project)
            node=os.environ.get("ANTI_REA_NODE","node")
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state),
                                        "PATH":f"{Path(node).resolve().parent}:{os.environ.get('PATH','')}"}):
                result=server.start_baseline(str(project),[sys.executable,"-c","pass"],["app.js"],
                    "before-mcp-e2e",e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"])
            saved=workflow.read_record(state/"records"/"baseline-before-mcp-e2e.json","baseline")
            self.assertEqual(result["e2e_evidence"],saved["identity"]["e2e_behavior"]["report_path"])
            self.assertTrue(Path(result["e2e_evidence"]).is_file())

    @unittest.skipUnless(os.environ.get("ANTI_REA_REA_RUNTIME"), "pinned REA runtime is required")
    def test_start_baseline_captures_pinned_rea_before_report(self):
        from interfaces.mcp import server
        from core import workflow
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); project=base/"project"; state=base/"state"
            shutil.copytree(Path(__file__).parents[1]/"fixtures/e2e/web",project)
            node=os.environ.get("ANTI_REA_NODE","node")
            with patch.dict(os.environ,{"ANTI_REA_STATE_DIR":str(state),
                                        "PATH":f"{Path(node).resolve().parent}:{os.environ.get('PATH','')}"}):
                result=server.start_baseline(str(project),[sys.executable,"-c","pass"],["app.js"],
                    "before-mcp-rea",rea_runtime=os.environ["ANTI_REA_REA_RUNTIME"])
            saved=workflow.read_record(state/"records"/"baseline-before-mcp-rea.json","baseline")
            self.assertEqual(result["rea_evidence"],saved["identity"]["rea_analysis"]["report_path"])
            self.assertTrue(Path(result["rea_evidence"]).is_file())

    def test_submit_plan_binds_run_to_exact_plan_for_decision(self):
        from interfaces.mcp import server
        from core import workflow
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            target={"schema_version":"2.0","record_type":"target","id":"target-p","components":[{"id":"web","kind":"fixture"}]}
            baseline={"schema_version":"2.0","record_type":"baseline","id":"base-p","target_id":"target-p",
                      "identity":{"source":"fixture"},"evidence":["before.json"]}
            action={"id":"protect","finding_or_asset":"fixture asset","change":"fixture change","mechanism":"exercise binding",
                    "engine":"bla","execution":{"adapter":"bla-js","source_path":"dist/a.js"},
                    "expected_benefit":"test plan binding","cost":"none","tradeoffs":["fixture"],
                    "dependencies":["none"],"compatibility":["fixture only"],"verification":["bla_invariants"],
                    "limitations":["no protection claim"],"rollback":"discard"}
            second={**action,"id":"protect-second","execution":{"adapter":"bla-js","source_path":"dist/b.js"}}
            plan={"schema_version":"2.0","record_type":"plan","id":"plan-p","target_id":"target-p",
                  "baseline_id":"base-p","actions":[action,second],"budgets":{"runtime_ms":100},"rollback":"discard"}
            server.save_target(target);server.save_baseline(baseline);server.create_run("target-p","run-p")
            server.transition_run("run-p","baselining")
            result=server.submit_plan("run-p",plan)
            self.assertEqual(result["status"],"awaiting_decision")
            run=server.get_run("run-p")
            self.assertEqual((run["plan_id"],run["baseline_id"]),(plan["id"],baseline["id"]))
            self.assertEqual(result["plan_sha256"],workflow.record_hash(plan))
            decision={"schema_version":"2.0","record_type":"decision","id":"decision-p",
                      "plan_sha256":result["plan_sha256"],"selected_action_ids":["protect","protect-second"],
                      "decision":"approved","decision_source":"explicit client choice"}
            server.record_decision("run-p",decision)
            self.assertEqual(server.get_run("run-p")["decision_id"],"decision-p")
            self.assertEqual(server.authorize_run("run-p")["state"],"preparing")

    def test_create_plan_uses_saved_source_map_baseline(self):
        from interfaces.mcp import server
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            target={"schema_version":"2.0","record_type":"target","id":"target-map","components":[{"id":"web","kind":"fixture"}]}
            baseline={"schema_version":"2.0","record_type":"baseline","id":"base-map","target_id":"target-map",
                      "identity":{"artifacts":{"dist/app.js.map":{"size":5,"sha256":"c"*64}},"source":"fixture"},
                      "evidence":["before.json"]}
            server.save_target(target);server.save_baseline(baseline)
            result=server.create_plan("target-map","base-map","plan-map",profile="deep-protection")
            self.assertEqual(result["status"],"recommendations_ready")
            self.assertEqual(result["profile"]["name"],"deep-protection")
            self.assertEqual(result["actions"][0]["evidence"][0]["baseline_id"],"base-map")
            plan=result["plan"]
            self.assertEqual(plan["id"],result["id"])
            server.create_run("target-map","run-map-plan-handoff")
            server.transition_run("run-map-plan-handoff","baselining")
            submitted=server.submit_plan("run-map-plan-handoff",plan)
            self.assertEqual(submitted["plan_sha256"],result["plan_sha256"])
            self.assertEqual(server.get_run("run-map-plan-handoff")["state"],"awaiting_decision")

    def test_create_plan_returns_profile_with_blocked_flutter_aot_plan(self):
        from interfaces.mcp import server
        from core import workflow
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"ANTI_REA_STATE_DIR":directory}):
            target={"schema_version":"2.0","record_type":"target","id":"target-flutter-blocked",
                    "components":[{"id":"app","kind":"flutter"}]}
            command=["/sdk/flutter","build","apk","--release"]
            toolchain={"flutter":{"framework_version":"3.47.8","channel":"stable","framework_revision":"a1",
                                   "engine_revision":"b2","dart_sdk_version":"3.13.7"},
                       "android":{"sdk_version":"36.0.0","platform_version":"android-37",
                                  "build_tools_version":"36.0.0","apksigner_sha256":"f"*64},
                       "java":{"binary":"/opt/jdk/bin/java","version":"OpenJDK 17"},
                       "build":{"target":"apk","command_sha256":hashlib.sha256(
                           workflow.canonical(command)).hexdigest()}}
            baseline={"schema_version":"2.0","record_type":"baseline","id":"base-flutter-blocked",
                      "target_id":"target-flutter-blocked","identity":{"command":command,
                          "dependency_lock_sha256":"a"*64,
                          "flutter_toolchain":toolchain,
                          "artifacts":{"build/app/outputs/flutter-apk/app-release.apk":
                                       {"size":12,"sha256":"b"*64}}},"evidence":["before.json"]}
            server.save_target(target);server.save_baseline(baseline)
            result=server.create_plan("target-flutter-blocked","base-flutter-blocked","plan-flutter-blocked")
            self.assertEqual(result["status"],"blocked")
            self.assertEqual(result["actions"],[])
            self.assertEqual(result["profile"]["name"],"balanced")
            self.assertIn("supported arm64-v8a AOT profile",result["blockers"][0])

    def test_mcp_acceptance_completes_only_with_bound_passing_evidence(self):
        from interfaces.mcp import server
        from core import workflow

        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"ANTI_REA_STATE_DIR": directory}):
            target={"schema_version":"2.0","record_type":"target","id":"target-1",
                    "components":[{"id":"web","kind":"fixture"}]}
            baseline={"schema_version":"2.0","record_type":"baseline","id":"base-1","target_id":"target-1",
                      "identity":{"source":"fixture"},"evidence":["before.json"]}
            action={"id":"a1","finding_or_asset":"fixture bundle","change":"test selected plan","mechanism":"test only",
                    "engine":"owned fixture","expected_benefit":"exercise the evidence gate","cost":"none",
                    "tradeoffs":["fixture only"],"dependencies":["none"],"compatibility":["not a protection claim"],
                    "verification":["behavior"],"limitations":["does not establish protection"],"rollback":"discard fixture"}
            plan={"schema_version":"2.0","record_type":"plan","id":"plan-1","target_id":"target-1",
                  "baseline_id":"base-1","actions":[action],"budgets":{"runtime_ms":100},"rollback":"discard"}
            server.save_target(target)
            server.save_baseline(baseline)
            server.save_plan(plan)
            server.create_run("target-1","run-1")
            server.transition_run("run-1","baselining")
            server.transition_run("run-1","awaiting_decision",{"baseline_id":"base-1","plan_id":"plan-1"})
            decision={"schema_version":"2.0","record_type":"decision","id":"decision-1",
                      "plan_sha256":workflow.record_hash(plan),"selected_action_ids":["a1"],
                      "decision":"approved","decision_source":"test client"}
            server.record_decision("run-1",decision)
            server.authorize_run("run-1")
            server.transition_run("run-1","executing")
            server.transition_run("run-1","verifying")
            execution={"schema_version":"2.0","record_type":"execution","id":"exec-1","run_id":"run-1",
                       "plan_sha256":workflow.record_hash(plan),"commands":[["fixture"]],"exit_code":0,
                       "outputs":[{"path":"fixture.out","sha256":"a"*64}]}
            server.save_evidence("execution",execution)
            verification={"schema_version":"2.0","record_type":"verification","id":"verify-1","run_id":"run-1",
                          "checks":[{"id":"behavior","status":"passed","evidence":[
                              {"path":str((Path(directory)/"report.json").resolve()),
                               "sha256":hashlib.sha256(b"test evidence").hexdigest()}]}]}
            (Path(directory)/"report.json").write_bytes(b"test evidence")
            acceptance={"schema_version":"2.0","record_type":"acceptance","id":"accept-1","run_id":"run-1",
                        "outcome":"accepted","claims":[],"claim_ids":["application_behavior_passed"],"reasons":["owned test"],
                        "verification_id":"verify-1","execution_id":"exec-1","plan_sha256":workflow.record_hash(plan)}
            bad={**verification,"id":"verify-2","checks":[{"id":"behavior","status":"skipped","evidence":["report.json"]}]}
            rejected=server.accept_run("run-1","exec-1",bad,
                                       {**acceptance,"id":"accept-2","verification_id":"verify-2"})
            self.assertEqual((rejected["status"],rejected["state"]),("rejected","blocked"))
            with self.assertRaisesRegex(workflow.WorkflowError,"Only a verifying run"):
                server.accept_run("run-1","exec-1",verification,acceptance)
            self.assertEqual(server.get_run("run-1")["state"],"blocked")

    def test_inspect_project_saves_and_retrieves_same_manifest(self):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from core import workflow
        from interfaces.mcp import server

        root=Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            project=base/"project"; project.mkdir()
            (project/"pyproject.toml").write_text("[project]\nname='sample'\n")
            (project/"pylock.toml").write_text('lock-version = "1.0"\ncreated-by = "fixture"\npackages = []\n')
            (project/"module.py").write_text("print('data only')\n")
            state=base/"state"
            env={**os.environ,"ANTI_REA_STATE_DIR":str(state)}
            params=StdioServerParameters(command=sys.executable,
                                         args=["-m","interfaces.cli.anti_rea","mcp","serve"],
                                         env=env,cwd=str(root))

            async def exercise():
                async with stdio_client(params) as (read,write):
                    async with ClientSession(read,write) as session:
                        await session.initialize()
                        tool_names={tool.name for tool in (await session.list_tools()).tools}
                        self.assertIn("inspect_project",tool_names)
                        self.assertIn("inspect_python_dependencies",tool_names)
                        self.assertIn("prepare_python_dependencies",tool_names)
                        self.assertIn("probe_wasm_module",tool_names)
                        self.assertIn("start_baseline_async",tool_names)
                        self.assertIn("start_flutter_android_baseline_async",tool_names)
                        self.assertIn("attach_flutter_aot_inspection",tool_names)
                        self.assertIn("probe_flutter_android_environment",tool_names)
                        self.assertIn("get_report",tool_names)
                        self.assertIn("rollback_candidate",tool_names)
                        self.assertIn("preview_optimization_search",tool_names)
                        self.assertIn("generate_optimization_candidates",tool_names)
                        self.assertIn("approve_optimization_search",tool_names)
                        self.assertIn("review_approved_optimization_search",tool_names)
                        self.assertIn("select_approved_optimization_candidate",tool_names)
                        self.assertIn("confirm_approved_search_reevaluation",tool_names)
                        self.assertIn("start_approved_optimization_search",tool_names)
                        self.assertIn("get_approved_optimization_search",tool_names)
                        self.assertIn("cancel_approved_optimization_search",tool_names)
                        self.assertIn("generate_optimization_candidates",tool_names)
                        self.assertIn("execute project code",server.workflow_contract()["execution"])
                        contract=await session.call_tool("workflow_contract",{})
                        self.assertFalse(contract.is_error)
                        self.assertEqual(contract.structured_content["schema_version"],"2.0")
                        found=await session.call_tool("inspect_project",{"project":str(project)})
                        self.assertFalse(found.is_error)
                        python_lock=await session.call_tool("inspect_python_dependencies",{"project":str(project)})
                        self.assertFalse(python_lock.is_error)
                        self.assertEqual(python_lock.structured_content["status"],"inspected")
                        wasm=base.resolve()/"module.wasm"
                        wasm.write_bytes(b"\x00asm\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00")
                        probed=await session.call_tool("probe_wasm_module",{"module":str(wasm)})
                        self.assertFalse(probed.is_error)
                        self.assertEqual(probed.structured_content["status"],"compiled")
                        self.assertEqual(probed.structured_content["verification_scope"],
                                         "compile_only_no_instantiation")
                        summary=found.structured_content
                        self.assertEqual(summary["file_count"],3)
                        full=await session.call_tool("get_target",{"target_id":summary["id"]})
                        self.assertFalse(full.is_error)
                        self.assertEqual(full.structured_content["inventory"]["sha256"],summary["inventory_sha256"])
                        scheduled=await session.call_tool("start_baseline_async",{
                            "project":str(project),"command":[sys.executable,"-c","import time; time.sleep(.05)"],
                            "artifacts":["module.py"],"baseline_id":"stdio-before","run_id":"stdio-run"})
                        self.assertFalse(scheduled.is_error)
                        self.assertEqual(scheduled.structured_content["poll_tool"],"get_run")
                        deadline=time.monotonic()+10
                        while time.monotonic()<deadline:
                            polled=await session.call_tool("get_run",{"run_id":"stdio-run"})
                            self.assertFalse(polled.is_error)
                            if not polled.structured_content["operation_active"]:
                                break
                            await asyncio.sleep(.02)
                        else:
                            self.fail("stdio baseline operation did not finish")
                        self.assertEqual(polled.structured_content["state"],"baselining")
                        incomplete=await session.call_tool("get_report",{"run_id":"stdio-run"})
                        self.assertFalse(incomplete.is_error)
                        self.assertEqual(incomplete.structured_content["run"]["state"],"baselining")
                        self.assertEqual(incomplete.structured_content["baseline"]["id"],"stdio-before")
                        self.assertNotIn("acceptance",incomplete.structured_content)
                        saved=workflow.read_record(state/"records"/"baseline-stdio-before.json","baseline")
                        self.assertEqual(saved["target_id"],summary["id"])

            import asyncio
            asyncio.run(exercise())
            self.assertEqual(len(list((state/"records").glob("target-*.json"))),1)

    def test_inspect_rejects_nested_state_without_creating_it(self):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        root=Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as directory:
            project=Path(directory)/"project"; project.mkdir()
            (project/"pyproject.toml").write_text("[project]\nname='sample'\n")
            state=project/".anti-rea"
            params=StdioServerParameters(command=sys.executable,args=["-m","interfaces.mcp.server"],
                env={**os.environ,"ANTI_REA_STATE_DIR":str(state)},cwd=str(root))

            async def exercise():
                async with stdio_client(params) as (read,write):
                    async with ClientSession(read,write) as session:
                        await session.initialize()
                        result=await session.call_tool("inspect_project",{"project":str(project)})
                        self.assertFalse(result.is_error)
                        self.assertEqual(result.structured_content["status"],"blocked")

            import asyncio
            asyncio.run(exercise())
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
