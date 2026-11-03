import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

from core import baseline, execution, workflow, flutter_android, discovery
from core import recommendations
from interfaces.cli import anti_rea


@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class SnapshotCopyTests(unittest.TestCase):
    def test_candidate_execution_resolves_store_symlink_ancestors_before_separation_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);project=root/"project";project.mkdir()
            (project/"pyproject.toml").write_text("[project]\nname='target'\n")
            alias=root/"target-alias";alias.symlink_to(project,target_is_directory=True)
            store=alias/"state"
            target=discovery.inspect_project(project)
            records=store/"records"
            workflow.write_record(records,target)
            run={"schema_version":"2.0","record_type":"run","id":"alias-run",
                 "target_id":target["id"],"state":"discovered"}
            run_path=workflow.write_run_state(store/"runs",run,None)
            baselining=workflow.transition_run(run,"baselining")
            workflow.write_run_state(run_path.parent,baselining,run)
            awaiting=workflow.transition_run(baselining,"awaiting_decision",baseline_id="base-alias",
                                              plan_id="plan-alias")
            workflow.write_run_state(run_path.parent,awaiting,baselining)
            preparing=workflow.transition_run(awaiting,"preparing",decision_id="decision-alias")
            workflow.write_run_state(run_path.parent,preparing,awaiting)
            with self.assertRaisesRegex(workflow.WorkflowError,"state and target must be separate"):
                execution.execute_bla_action(store,"alias-run","action",None)
            self.assertFalse((project/"state/candidates").exists())

    def test_snapshot_copy_refuses_traversal_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"project";root.mkdir()
            outside=Path(directory)/"outside.js";outside.write_text("outside")
            destination=Path(directory)/"snapshot"/"outside.js"
            destination_root=destination.parent
            destination_root.mkdir()
            with self.assertRaisesRegex(workflow.WorkflowError,"escapes project root"):
                execution._copy_project_file(root,"../outside.js",destination,
                                             hashlib.sha256(b"outside").hexdigest(),len(b"outside"),destination_root)
            linked=root/"linked.js";linked.symlink_to(outside)
            with self.assertRaises(OSError):
                execution._copy_project_file(root,"linked.js",destination,
                                             hashlib.sha256(b"outside").hexdigest(),len(b"outside"),destination_root)
            self.assertFalse(destination.exists())
            self.assertEqual(outside.read_text(),"outside")

    def test_snapshot_copy_refuses_destination_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"project";root.mkdir()
            source=root/"app.js";source.write_text("inside")
            snapshot=Path(directory)/"snapshot";snapshot.mkdir()
            outside=Path(directory)/"outside";outside.mkdir()
            (snapshot/"linked").symlink_to(outside,target_is_directory=True)
            destination=snapshot/"linked"/"escaped.js"
            content=source.read_bytes()
            with self.assertRaises(OSError):
                execution._copy_project_file(root,"app.js",destination,
                    hashlib.sha256(content).hexdigest(),len(content),snapshot)
            self.assertFalse((outside/"escaped.js").exists())

    def test_snapshot_copy_preserves_owner_executable_bit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"project";root.mkdir()
            source=root/"check.sh";source.write_text("#!/bin/sh\nexit 0\n");source.chmod(0o700)
            snapshot=Path(directory)/"snapshot";snapshot.mkdir()
            execution._copy_project_file(root,"check.sh",snapshot/"check.sh",
                hashlib.sha256(source.read_bytes()).hexdigest(),source.stat().st_size,snapshot)
            self.assertTrue((snapshot/"check.sh").stat().st_mode & stat.S_IXUSR)

    def test_snapshot_copy_cancellation_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"project";root.mkdir()
            source=root/"large.bin";source.write_bytes(b"x"*(1024*1024))
            snapshot=Path(directory)/"snapshot";snapshot.mkdir()
            event=threading.Event()
            original_write=os.write
            def cancel_after_first_chunk(fd, data):
                written=original_write(fd,data)
                event.set()
                return written
            with patch.object(execution.os,"write",side_effect=cancel_after_first_chunk):
                with self.assertRaisesRegex(workflow.WorkflowError,"Command cancelled"):
                    execution._copy_project_file(root,"large.bin",snapshot/"large.bin",
                        hashlib.sha256(source.read_bytes()).hexdigest(),source.stat().st_size,snapshot,event)
            self.assertTrue(event.is_set())
            self.assertFalse((snapshot/"large.bin").exists())

    def test_snapshot_copy_cancellation_during_fsync_does_not_report_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"project";root.mkdir()
            source=root/"file.js";source.write_text("export const ready = true;\n")
            snapshot=Path(directory)/"snapshot";snapshot.mkdir()
            event=threading.Event()
            original_fsync=os.fsync
            def cancel_after_fsync(fd):
                original_fsync(fd)
                event.set()
            with patch.object(execution.os,"fsync",side_effect=cancel_after_fsync):
                with self.assertRaisesRegex(workflow.WorkflowError,"Command cancelled"):
                    execution._copy_project_file(root,"file.js",snapshot/"file.js",
                        hashlib.sha256(source.read_bytes()).hexdigest(),source.stat().st_size,snapshot,event)
            self.assertFalse((snapshot/"file.js").exists())

    def test_performance_trial_retention_binds_and_checks_candidate_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);candidate=root/"trial.js";candidate.write_bytes(b"protected trial")
            evidence=root/"evidence";evidence.mkdir()
            digest=hashlib.sha256(candidate.read_bytes()).hexdigest()
            reference=execution._retain_performance_trial(candidate,evidence,"run-performance",1,
                                                           digest,candidate.stat().st_size)
            retained=Path(reference["path"])
            self.assertEqual((reference["kind"],retained.parent,retained.read_bytes()),
                             ("performance-candidate",evidence.resolve(),candidate.read_bytes()))
            with self.assertRaisesRegex(workflow.WorkflowError,"hash mismatch"):
                execution._retain_performance_trial(candidate,evidence,"other-performance",1,
                                                     "0"*64,candidate.stat().st_size)
            self.assertFalse((evidence/"other-performance-candidate-1.js").exists())

    def test_cancelled_composite_snapshot_copy_removes_both_partial_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            before_source=root/"baseline";before_source.mkdir();(before_source/"app.js").write_text("before")
            after_source=root/"candidate";after_source.mkdir();(after_source/"app.js").write_text("after")
            (root/"snapshots").mkdir()
            before=root/"snapshots"/"before";after=root/"snapshots"/"after"
            event=threading.Event()
            original_copy=execution._copy_project_file
            def cancel_after_copy(*args, **kwargs):
                result=original_copy(*args, **kwargs)
                event.set()
                return result
            with patch.object(execution,"_verify_build_snapshot",return_value=before_source), \
                    patch.object(execution,"_copy_project_file",side_effect=cancel_after_copy):
                with self.assertRaisesRegex(workflow.WorkflowError,"Command cancelled"):
                    execution._create_composite_snapshots(before_source,{},after_source,before,after,event)
            self.assertFalse(before.exists())
            self.assertFalse(after.exists())


    def test_resume_requires_exact_baseline_inputs_and_creates_new_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);project=root/"project";project.mkdir();store=root/"state"
            (project/"pyproject.toml").write_text("[project]\nname='resume-fixture'\n")
            (project/"build.py").write_text("from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\nPath('dist/app.mjs').write_text('export const ok = true;\\n')\nPath('Apple.framework').mkdir(exist_ok=True)\nPath('Apple.framework/Info.plist').write_text('identity-v1')\n")
            (project/"source.js").write_text("export const original = true;\n")
            (project/"Apple.framework").mkdir()
            framework_info=project/"Apple.framework"/"Info.plist";framework_info.write_text("identity-v1")
            behavior=[sys.executable,"-c","import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
                      "{artifact}"]
            captured,_=baseline.capture(project,store,[sys.executable,"build.py"],["dist/app.mjs","Apple.framework"],
                                        "resume-baseline",behavior_command=behavior)
            records=store/"records"
            target=workflow.read_record(records/f"target-{captured['target_id']}.json","target")
            artifact=captured["identity"]["artifacts"]["dist/app.mjs"]
            action={"id":"protect","finding_or_asset":"fixture JS","change":"Create a separate candidate",
                    "mechanism":"Pinned BLA transformation","engine":"bla","expected_benefit":"fixture exercise",
                    "cost":"none","tradeoffs":["synthetic only"],"dependencies":["pinned runtime"],
                    "compatibility":["JavaScript"],"verification":["bla_invariants"],
                    "limitations":["no protection claim"],"rollback":"quarantine candidate",
                    "execution":{"adapter":"bla-js","source_path":"dist/app.mjs"},
                    "evidence":[{"path":"dist/app.mjs","sha256":artifact["sha256"]}]}
            plan={"schema_version":"2.0","record_type":"plan","id":"resume-plan",
                  "target_id":target["id"],"baseline_id":captured["id"],"actions":[action],
                  "budgets":{"runtime_ms":1000},"rollback":"quarantine candidate"}
            workflow.write_record(records,plan)
            decision={"schema_version":"2.0","record_type":"decision","id":"resume-decision",
                      "plan_sha256":workflow.record_hash(plan),"selected_action_ids":["protect"],
                      "decision":"approved","decision_source":"owned test"}
            workflow.write_record(records,decision)
            old={"schema_version":"2.0","record_type":"run","id":"failed-run",
                 "target_id":target["id"],"state":"discovered"}
            old_path=workflow.write_run_state(store/"runs",old,None)
            for next_state,updates in (("baselining",{}),("awaiting_decision",{"baseline_id":captured["id"],"plan_id":plan["id"]})):
                changed=workflow.transition_run(old,next_state,**updates)
                workflow.write_run_state(old_path.parent,changed,old);old=changed
            bound=workflow.bind_decision(old,plan,decision)
            workflow.write_run_state(old_path.parent,bound,old);old=bound
            preparing=workflow.start_execution(old,plan,decision)
            workflow.write_run_state(old_path.parent,preparing,old);old=preparing
            executing=workflow.transition_run(old,"executing")
            workflow.write_run_state(old_path.parent,executing,old);old=executing
            failed=workflow.transition_run(old,"failed",error_code="fixture_failure")
            workflow.write_run_state(old_path.parent,failed,old)

            artifact_path=Path(captured["identity"]["build_snapshot"]["path"])/"dist/app.mjs";original=artifact_path.read_bytes()
            artifact_path.write_bytes(original+b"// drift\n")
            with self.assertRaisesRegex(workflow.WorkflowError,"build snapshot changed"):
                execution.prepare_resume(store,"failed-run","retry-drift")
            artifact_path.write_bytes(original)
            (project/"source.js").write_text("export const changed = true;\n")
            with self.assertRaisesRegex(workflow.WorkflowError,"source input changed after baseline"):
                execution.prepare_resume(store,"failed-run","retry-source-drift")
            (project/"source.js").write_text("export const original = true;\n")
            (project/"unbaselined.txt").write_text("new input\n")
            with self.assertRaisesRegex(workflow.WorkflowError,"project files added"):
                execution.prepare_resume(store,"failed-run","retry-added-file")
            (project/"unbaselined.txt").unlink()

            baseline_evidence=Path(captured["evidence"][0])
            saved_evidence=baseline_evidence.read_bytes()
            baseline_evidence.unlink()
            with self.assertRaisesRegex(workflow.WorkflowError,"baseline evidence"):
                execution.prepare_resume(store,"failed-run","retry-missing-baseline-evidence")
            baseline_evidence.write_bytes(saved_evidence)
            baseline_evidence.write_bytes(saved_evidence+b"tampered")
            with self.assertRaisesRegex(workflow.WorkflowError,"baseline evidence is invalid"):
                execution.prepare_resume(store,"failed-run","retry-tampered-baseline-evidence")
            baseline_evidence.write_bytes(saved_evidence)

            framework_info.write_text("identity-v2")
            with self.assertRaisesRegex(workflow.WorkflowError,"input changed"):
                execution.prepare_resume(store,"failed-run","retry-framework-drift")
            framework_info.write_text("identity-v1")

            behavior_evidence=Path(captured["identity"]["behavior"]["evidence_path"])
            saved_behavior=behavior_evidence.read_bytes()
            behavior_evidence.write_bytes(saved_behavior+b"tampered")
            with self.assertRaisesRegex(workflow.WorkflowError,"baseline evidence is invalid"):
                execution.prepare_resume(store,"failed-run","retry-tampered-behavior-evidence")
            behavior_evidence.write_bytes(saved_behavior)
            behavior_snapshot=Path(captured["identity"]["behavior"]["snapshot_path"])
            snapshot_file=behavior_snapshot/"source.js"
            saved_snapshot=snapshot_file.read_bytes()
            snapshot_file.write_bytes(saved_snapshot+b"tampered")
            with self.assertRaisesRegex(workflow.WorkflowError,"behavior snapshot changed"):
                execution.prepare_resume(store,"failed-run","retry-tampered-behavior-snapshot")
            snapshot_file.write_bytes(saved_snapshot)

            resumed=execution.prepare_resume(store,"failed-run","retry-valid")
            record=workflow.read_record(store/"runs"/"run-retry-valid.json","run")
            self.assertEqual((resumed["state"],record["state"],record["resume_of"]),
                             ("preparing","preparing","failed-run"))
            self.assertEqual(len(record["resume_identity_sha256"]),64)
            self.assertEqual(workflow.read_record(old_path,"run")["state"],"failed")

    def test_resume_rejects_tampered_prior_execution_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);project=root/"project";project.mkdir();store=root/"state"
            (project/"package.json").write_text('{"name":"resume-evidence-fixture"}\n')
            (project/"build.py").write_text("from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\nPath('dist/app.js').write_text('const ok = true;\\n')\n")
            captured,_=baseline.capture(project,store,[sys.executable,"build.py"],["dist/app.js"],"resume-evidence-baseline")
            records=store/"records"
            target=workflow.read_record(records/f"target-{captured['target_id']}.json","target")
            artifact=captured["identity"]["artifacts"]["dist/app.js"]
            action={"id":"protect","finding_or_asset":"fixture JS","change":"Create a separate candidate",
                    "mechanism":"Pinned BLA transformation","engine":"bla","expected_benefit":"fixture exercise",
                    "cost":"none","tradeoffs":["synthetic only"],"dependencies":["pinned runtime"],
                    "compatibility":["JavaScript"],"verification":["bla_invariants"],
                    "limitations":["no protection claim"],"rollback":"quarantine candidate",
                    "execution":{"adapter":"bla-js","source_path":"dist/app.js"},
                    "evidence":[{"path":"dist/app.js","sha256":artifact["sha256"]}]}
            plan={"schema_version":"2.0","record_type":"plan","id":"resume-evidence-plan",
                  "target_id":target["id"],"baseline_id":captured["id"],"actions":[action],
                  "budgets":{"runtime_ms":1000},"rollback":"quarantine candidate"}
            workflow.write_record(records,plan)
            decision={"schema_version":"2.0","record_type":"decision","id":"resume-evidence-decision",
                      "plan_sha256":workflow.record_hash(plan),"selected_action_ids":["protect"],
                      "decision":"approved","decision_source":"owned test"}
            workflow.write_record(records,decision)
            run={"schema_version":"2.0","record_type":"run","id":"failed-evidence-run",
                 "target_id":target["id"],"state":"discovered"}
            run_path=workflow.write_run_state(store/"runs",run,None)
            baselining=workflow.transition_run(run,"baselining")
            workflow.write_run_state(run_path.parent,baselining,run)
            awaiting=workflow.submit_plan(baselining,target,captured,plan)
            workflow.write_run_state(run_path.parent,awaiting,baselining)
            bound=workflow.bind_decision(awaiting,plan,decision)
            workflow.write_run_state(run_path.parent,bound,awaiting)
            preparing=workflow.start_execution(bound,plan,decision)
            workflow.write_run_state(run_path.parent,preparing,bound)
            executing=workflow.transition_run(preparing,"executing")
            workflow.write_run_state(run_path.parent,executing,preparing)
            report=store/"evidence"/"prior-execution.json"
            report.parent.mkdir(parents=True,exist_ok=True)
            report.write_text('{"result":"failed attempt evidence"}\n')
            report_ref={"path":str(report),"sha256":hashlib.sha256(report.read_bytes()).hexdigest()}
            output=store/"candidates"/"prior.js"
            output.parent.mkdir(exist_ok=True)
            output.write_text("candidate")
            prior_execution={"schema_version":"2.0","record_type":"execution","id":"prior-execution",
                             "run_id":"failed-evidence-run","plan_sha256":workflow.record_hash(plan),
                             "action_id":"protect","commands":[[sys.executable,"build.py"]],"exit_code":0,
                             "outputs":[{"path":str(output),"sha256":hashlib.sha256(output.read_bytes()).hexdigest()}],
                             "evidence":[report_ref]}
            prior_verification={"schema_version":"2.0","record_type":"verification","id":"prior-verification",
                                "run_id":"failed-evidence-run","execution_id":"prior-execution",
                                "checks":[{"id":"failed_check","status":"failed","evidence":["fixture failure"]}]}
            workflow.write_record(records,prior_execution)
            workflow.write_record(records,prior_verification)
            failed=workflow.transition_run(executing,"failed",error_code="fixture_failure",
                                           execution_id="prior-execution",verification_id="prior-verification")
            workflow.write_run_state(run_path.parent,failed,executing)

            report.write_text('{"result":"tampered"}\n')
            with self.assertRaisesRegex(workflow.WorkflowError,"evidence hash mismatch"):
                execution.prepare_resume(store,"failed-evidence-run","retry-tampered-execution-evidence")
            self.assertFalse((store/"runs"/"run-retry-tampered-execution-evidence.json").exists())

    @unittest.skipUnless(os.environ.get("ANTI_REA_E2E_RUNTIME"), "pinned e2e runtime is required")
    def test_resume_revalidates_baseline_e2e_report_snapshot_and_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); project=root/"project"; store=root/"state"
            shutil.copytree(Path(__file__).parents[1]/"fixtures/e2e/web",project)
            node=Path(os.environ.get("ANTI_REA_NODE","node")).resolve()
            path_env=str(node.parent)+":"+os.environ.get("PATH","")
            with patch.dict(os.environ,{"PATH":path_env}):
                captured,_=baseline.capture(project,store,[sys.executable,"-c","pass"],["app.js"],
                    "resume-e2e-baseline",e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"])
            records=store/"records"
            target=workflow.read_record(records/f"target-{captured['target_id']}.json","target")
            plan=recommendations.create_plan(target,captured,"resume-e2e-plan",e2e_behavior=True)
            action=next(item for item in plan["actions"] if item["execution"]["source_path"]=="app.js")
            workflow.write_record(records,plan)
            decision={"schema_version":"2.0","record_type":"decision","id":"resume-e2e-decision",
                      "plan_sha256":workflow.record_hash(plan),"selected_action_ids":[action["id"]],
                      "decision":"approved","decision_source":"owned integration test"}
            workflow.write_record(records,decision)
            run={"schema_version":"2.0","record_type":"run","id":"resume-e2e-failed",
                 "target_id":target["id"],"state":"discovered"}
            path=workflow.write_run_state(store/"runs",run,None)
            for state,updates in (("baselining",{}),
                ("awaiting_decision",{"baseline_id":captured["id"],"plan_id":plan["id"]})):
                changed=workflow.transition_run(run,state,**updates)
                workflow.write_run_state(path.parent,changed,run);run=changed
            changed=workflow.bind_decision(run,plan,decision);workflow.write_run_state(path.parent,changed,run);run=changed
            changed=workflow.start_execution(run,plan,decision);workflow.write_run_state(path.parent,changed,run);run=changed
            changed=workflow.transition_run(run,"executing");workflow.write_run_state(path.parent,changed,run);run=changed
            changed=workflow.transition_run(run,"failed",error_code="fixture_failure");workflow.write_run_state(path.parent,changed,run)

            e2e=captured["identity"]["e2e_behavior"]
            report=Path(e2e["report_path"]); saved_report=report.read_bytes()
            report.write_bytes(saved_report+b"tampered")
            path_env=str(node.parent)+":"+os.environ.get("PATH","")
            with patch.dict(os.environ,{"PATH":path_env}):
                with self.assertRaisesRegex(workflow.WorkflowError,"baseline evidence is invalid"):
                    execution.prepare_resume(store,"resume-e2e-failed","resume-e2e-bad-report")
                report.write_bytes(saved_report)
                snapshot=Path(e2e["snapshot_path"]); app=snapshot/"app.js"; saved_app=app.read_bytes()
                app.write_bytes(saved_app+b"// drift\n")
                with self.assertRaisesRegex(workflow.WorkflowError,"baseline e2e snapshot changed"):
                    execution.prepare_resume(store,"resume-e2e-failed","resume-e2e-drift")
                app.write_bytes(saved_app)
                resumed=execution.prepare_resume(store,"resume-e2e-failed","resume-e2e-valid")
            self.assertEqual(resumed["state"],"preparing")


if __name__ == "__main__":
    unittest.main()

@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class FlutterCandidateTests(unittest.TestCase):
    @staticmethod
    def toolchain_identity(command):
        return {"flutter": {"framework_version": "3.47.8", "channel": "stable",
                            "framework_revision": "a1", "engine_revision": "b2", "dart_sdk_version": "3.13.7"},
                "android": {"sdk_version": "36.0.0", "platform_version": "android-37",
                            "build_tools_version": "36.0.0", "apksigner_sha256": "f" * 64},
                "java": {"binary": "/opt/jdk/bin/java", "version": "OpenJDK 17"},
                "build": {"target": command[2], "command_sha256": hashlib.sha256(
                    workflow.canonical(command)).hexdigest()}}

    def prepare_run(self, root, run_id):
        project = root / "flutter-app"
        project.mkdir()
        store = root / "state"
        (project / "pubspec.yaml").write_text("name: fixture_app\ndependencies:\n  flutter:\n    sdk: flutter\n")
        (project / "pubspec.lock").write_text("packages: {}\n")
        (project / "main.dart").write_text("void main() {}\n")
        (project / "android").mkdir()
        fake = root / "flutter"
        fake.write_text("#!/usr/bin/env python3\nimport pathlib,sys\n"
                        "args=sys.argv[1:]\n"
                        "out=pathlib.Path('build/app/outputs/flutter-apk/app-release.apk')\n"
                        "out.parent.mkdir(parents=True,exist_ok=True)\n"
                        "out.write_bytes(b'obfuscated' if '--obfuscate' in args else b'baseline')\n"
                        "if '--split-debug-info=' in ' '.join(args):\n"
                        " p=pathlib.Path(next(a.split('=',1)[1] for a in args if a.startswith('--split-debug-info=')))\n"
                        " p.mkdir(parents=True,exist_ok=True); (p/'symbols.json').write_text('{}')\n")
        fake.chmod(0o700)
        artifact = "build/app/outputs/flutter-apk/app-release.apk"
        command = [str(fake), "build", "apk", "--release"]
        with patch("core.flutter_android.capture_toolchain_identity",
                   side_effect=lambda actual, cwd: self.toolchain_identity(actual)):
            captured, _ = baseline.capture(project, store, command, [artifact], f"{run_id}-base")
        apk = captured["identity"]["artifacts"][artifact]
        runtime_manifest = {"schema_version": "1.0", "npm_version": "6.8.0",
            "npm_integrity": "sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==",
            "package_lock_sha256": "b6cb714948a7ec224fa6f676f0e9b6f570bbabf3518a1a187be571ac8ddfe232",
            "package_tree_sha256": "b" * 64, "node_version": "v24.22.1"}
        runtime_path = store / "evidence" / "rea-runtime-baseline.json"
        runtime_path.write_text(json.dumps(runtime_manifest))
        sections = ["_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions",
                    "_kDartVmSnapshotData", "_kDartIsolateSnapshotData"]
        report = {"evidence_id": "ev-baseline", "subject": {"format": "apk", "digest": {"sha256": apk["sha256"]}},
            "provider": {"id": "flutter"}, "predicate_type": "rea.analysis", "operation": "inspect_dart_aot",
            "normalized_result": {"target": {"sha256": apk["sha256"], "bytes": apk["size"]},
                "abi": "arm64-v8a", "libapp": {"coverage": "complete", "sha256": "c" * 64,
                    "snapshot_hash": "baseline-snapshot", "sections": [
                        {"name": name, "offset": index * 10, "size": 5} for index, name in enumerate(sections)]}}}
        report_path = store / "evidence" / "rea-aot-baseline.json"
        report_path.write_text(json.dumps(report))
        with patch.object(flutter_android, "_verify_rea_runtime",
                          return_value=(runtime_path, runtime_path.read_bytes(), runtime_manifest)):
            captured = flutter_android.attach_aot_inspection(captured, report_path, runtime_path,
                                                             "arm64-v8a", f"{run_id}-base-aot")
        workflow.write_record(store / "records", captured)
        target = workflow.read_record(store / "records" / f"target-{captured['target_id']}.json", "target")
        plan = recommendations.create_plan(target, captured, f"{run_id}-plan")
        action = plan["actions"][0]
        workflow.write_record(store / "records", plan)
        run = {"schema_version": "2.0", "record_type": "run", "id": run_id,
               "target_id": target["id"], "state": "discovered"}
        run_path = workflow.write_run_state(store / "runs", run, None)
        baselining = workflow.transition_run(run, "baselining")
        workflow.write_run_state(run_path.parent, baselining, run)
        awaiting = workflow.submit_plan(baselining, target, captured, plan)
        workflow.write_run_state(run_path.parent, awaiting, baselining)
        decision = {"schema_version": "2.0", "record_type": "decision", "id": f"{run_id}-decision",
                    "plan_sha256": workflow.record_hash(plan), "selected_action_ids": [action["id"]],
                    "decision": "approved", "decision_source": "owned test"}
        workflow.write_record(store / "records", decision)
        bound = workflow.bind_decision(awaiting, plan, decision)
        workflow.write_run_state(run_path.parent, bound, awaiting)
        preparing = workflow.start_execution(bound, plan, decision)
        workflow.write_run_state(run_path.parent, preparing, bound)
        return store, captured, target, plan, action, decision, run_path, fake

    def test_fake_flutter_candidate_is_private_and_remains_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, baseline_record, target, plan, action, decision, run_path, _ = self.prepare_run(root, "flutter-run")
            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)):
                result = execution.execute_bla_action(store, "flutter-run", action["id"], None)
            self.assertEqual(result["status"], "built_unverified")
            self.assertFalse(result["accepted"])
            self.assertTrue(Path(result["candidate"]).resolve().is_relative_to((store / "candidates").resolve()))
            self.assertTrue(Path(result["symbols"]).resolve().is_relative_to((store / "symbols").resolve()))
            self.assertEqual([check["status"] for check in result["checks"]], ["blocked", "blocked"])
            run = workflow.validate_run(workflow.read_json(run_path))
            execution_record = workflow.read_record(store / "records" / f"execution-{result['execution_id']}.json", "execution")
            verification = workflow.read_record(store / "records" / f"verification-{result['verification_id']}.json", "verification")
            self.assertEqual(execution_record["flutter_candidate"]["status"], "built_unverified")
            # Even fabricated passed statuses cannot pass without semantic reports and bound toolchain/lock IDs.
            passed_checks = []
            for check in verification["checks"]:
                forged = store / "evidence" / f"forged-{check['id']}.json"
                forged.write_text("{}")
                passed_checks.append({"id": check["id"], "status": "passed", "evidence": [
                    {"path": str(forged), "sha256": hashlib.sha256(forged.read_bytes()).hexdigest()}]})
            verification = {**verification, "id": "verify-flutter-external", "checks": passed_checks}
            updated_run = workflow.refresh_blocked_flutter_verification(store, run["id"], verification)
            self.assertEqual(updated_run["verification_id"], verification["id"])
            self.assertEqual(workflow.read_record(store / "records" / f"verification-{result['verification_id']}.json",
                                                  "verification")["checks"][0]["status"], "blocked")
            acceptance = {"schema_version": "2.0", "record_type": "acceptance", "id": "flutter-acceptance",
                          "run_id": run["id"], "outcome": "accepted", "claim_ids": [
                              "flutter_aot_candidate_inspected", "flutter_android_same_target_behavior_passed"],
                          "claims": [], "reasons": ["test"], "verification_id": verification["id"],
                          "execution_id": execution_record["id"], "plan_sha256": workflow.record_hash(plan)}
            with self.assertRaisesRegex(workflow.WorkflowError, "semantic report|Flutter semantic|execution record|AOT comparison"):
                workflow.accept_run(updated_run, target, baseline_record, plan, decision,
                                    execution_record, verification, acceptance)

    def test_candidate_hash_drift_fails_semantic_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, captured, target, plan, action, _, _, _ = self.prepare_run(root, "flutter-drift")
            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)):
                result = execution.execute_bla_action(store, "flutter-drift", action["id"], None)
            execution_record = workflow.read_record(store / "records" / f"execution-{result['execution_id']}.json", "execution")
            candidate = Path(result["candidate"])
            candidate.write_bytes(b"tampered")
            report_path = store / "evidence" / "aot.json"
            candidate_sha = execution_record["flutter_candidate"]["candidate_artifact_sha256"]
            report_path.write_text(json.dumps({"schema_version": "1.0", "record_type": "flutter-aot-inspection",
                "status": "passed", "run_id": "flutter-drift", "action_id": action["id"],
                "plan_sha256": workflow.record_hash(plan), "baseline_id": captured["id"],
                "baseline_sha256": workflow.record_hash(captured),
                "source_identity_sha256": workflow.record_hash(captured["identity"]),
                "baseline_artifact_sha256": captured["identity"]["artifacts"][action["execution"]["artifact_path"]]["sha256"],
                "candidate_artifact_sha256": candidate_sha}))
            ref = {"path": str(report_path), "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest()}
            with self.assertRaisesRegex(workflow.WorkflowError, "Flutter candidate APK"):
                workflow._verify_flutter_check(plan, captured, execution_record, "flutter_aot_comparison",
                                               [], [])

    def test_flutter_aot_verifier_replays_candidate_from_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, captured, _target, plan, action, _decision, _run_path, _ = self.prepare_run(
                root, "flutter-rollback-replay")
            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)):
                result = execution.execute_bla_action(store, "flutter-rollback-replay", action["id"], None)
            executed = workflow.read_record(
                store / "records" / f"execution-{result['execution_id']}.json", "execution")
            output = executed["flutter_candidate"]
            artifact_path = action["execution"]["artifact_path"]
            baseline_artifact = captured["identity"]["artifacts"][artifact_path]
            runtime_path = store / "evidence" / "rea-runtime-baseline.json"
            runtime_raw = runtime_path.read_bytes()
            runtime_manifest = json.loads(runtime_raw)
            runtime_ref = {"path": str(runtime_path), "sha256": hashlib.sha256(runtime_raw).hexdigest()}
            runtime_identity = workflow.record_hash(runtime_manifest)
            refs, raws = [], []
            sections = ["_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions",
                        "_kDartVmSnapshotData", "_kDartIsolateSnapshotData"]
            for side, digest, size in (
                    ("baseline", baseline_artifact["sha256"], baseline_artifact["size"]),
                    ("candidate", output["candidate_artifact_sha256"], Path(result["candidate"]).stat().st_size)):
                report = {"evidence_id": f"ev-{side}", "subject": {"format": "apk", "digest": {"sha256": digest}},
                    "provider": {"id": "flutter"}, "predicate_type": "rea.analysis", "operation": "inspect_dart_aot",
                    "normalized_result": {"target": {"sha256": digest, "bytes": size},
                        "abi": action["execution"]["selected_abi"], "libapp": {
                            "coverage": "complete", "sha256": "c" * 64 if side == "baseline" else "d" * 64,
                            "snapshot_hash": "same-dart-build",
                            "sections": [{"name": name, "offset": index * 10, "size": 5}
                                         for index, name in enumerate(sections)]}}}
                raw = json.dumps(report).encode()
                report_path = store / "evidence" / f"{side}-aot.json"
                report_path.write_bytes(raw)
                refs.append({"path": str(report_path), "sha256": hashlib.sha256(raw).hexdigest(),
                    "kind": "rea-inspect-dart-aot", "side": side,
                    "abi": action["execution"]["selected_abi"], "rea_runtime_manifest": runtime_ref,
                    "rea_runtime_manifest_sha256": runtime_identity})
                raws.append(raw)
            execution.discard_candidate(store, "flutter-rollback-replay")
            self.assertFalse(Path(result["candidate"]).exists())
            workflow._verify_flutter_check(plan, captured, executed, "flutter_aot_comparison", raws, refs)

    def test_structurally_plausible_forged_rea_reports_fail_abi_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, captured, _target, plan, action, _, _, _ = self.prepare_run(root, "flutter-forged")
            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)):
                result = execution.execute_bla_action(store, "flutter-forged", action["id"], None)
            execution_record = workflow.read_record(store / "records" / f"execution-{result['execution_id']}.json", "execution")
            candidate_hash = execution_record["flutter_candidate"]["candidate_artifact_sha256"]
            runtime_path = store / "evidence" / "rea-runtime.json"
            runtime_manifest = {"schema_version": "1.0", "npm_version": "6.8.0",
                "npm_integrity": "sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==",
                "package_lock_sha256": "b6cb714948a7ec224fa6f676f0e9b6f570bbabf3518a1a187be571ac8ddfe232",
                "package_tree_sha256": "b" * 64, "node_version": "v24.22.1"}
            runtime_path.write_text(json.dumps(runtime_manifest))
            runtime_ref = {"path": str(runtime_path), "sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest()}
            runtime_identity = workflow.record_hash(runtime_manifest)
            expected_sections = ["_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions",
                                 "_kDartVmSnapshotData", "_kDartIsolateSnapshotData"]
            refs, raws = [], []
            baseline_identity = captured["identity"]["artifacts"][action["execution"]["artifact_path"]]
            candidate_identity = baseline._hash_artifact(Path(result["candidate"]).parent,
                                                          Path(result["candidate"]).name)
            for side, package_hash, package_size in (("baseline", baseline_identity["sha256"], baseline_identity["size"]),
                                                      ("candidate", candidate_hash, candidate_identity["size"])):
                sections = [{"name": name, "offset": index * 100, "size": 50}
                            for index, name in enumerate(expected_sections)]
                if side == "candidate":
                    sections.pop()  # Plausible report, but incomplete selected-ABI section coverage.
                normalized = {"target": {"sha256": package_hash, "bytes": package_size},
                    "abi": action["execution"]["selected_abi"],
                    "libapp": {"coverage": "complete", "sha256": "c" * 64 if side == "baseline" else "d" * 64,
                               "snapshot_hash": "same-sdk-build", "sections": sections}}
                report = {"evidence_id": f"ev-{side}", "subject": {"format": "apk", "digest": {"sha256": package_hash}},
                    "provider": {"id": "flutter"}, "predicate_type": "rea.analysis", "operation": "inspect_dart_aot",
                    "normalized_result": normalized}
                raw = json.dumps(report).encode()
                report_path = store / "evidence" / f"{side}-inspect.json"
                report_path.write_bytes(raw)
                refs.append({"path": str(report_path), "sha256": hashlib.sha256(raw).hexdigest(),
                    "kind": "rea-inspect-dart-aot", "side": side, "abi": action["execution"]["selected_abi"],
                    "rea_runtime_manifest": runtime_ref, "rea_runtime_manifest_sha256": runtime_identity})
                raws.append(raw)
            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)):
                with self.assertRaisesRegex(workflow.WorkflowError, "AOT report is incomplete"):
                    workflow._verify_flutter_check(plan, captured, execution_record,
                        "flutter_aot_comparison", raws, refs)

    def test_behavior_report_without_bound_signing_evidence_remains_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, captured, _target, plan, action, _, _, _ = self.prepare_run(root, "flutter-signing")
            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)):
                result = execution.execute_bla_action(store, "flutter-signing", action["id"], None)
            execution_record = workflow.read_record(store / "records" / f"execution-{result['execution_id']}.json", "execution")
            candidate_hash = execution_record["flutter_candidate"]["candidate_artifact_sha256"]
            baseline_hash = captured["identity"]["artifacts"][action["execution"]["artifact_path"]]["sha256"]
            device_hash = "e" * 64
            cases = [{"case_id": "launch", "result": "passed"}]
            report = {"schema_version": "1.0", "record_type": "flutter-android-behavior",
                "run_id": "flutter-signing", "action_id": action["id"],
                "plan_sha256": workflow.record_hash(plan), "baseline_sha256": workflow.record_hash(captured),
                "source_identity_sha256": workflow.record_hash(captured["identity"]),
                "toolchain_identity_sha256": workflow.record_hash(captured["identity"]["flutter_toolchain"]),
                "dependency_lock_sha256": captured["identity"]["dependency_lock_sha256"],
                "baseline": {"apk_sha256": baseline_hash, "device_identity_sha256": device_hash, "cases": cases},
                "candidate": {"apk_sha256": candidate_hash, "device_identity_sha256": device_hash, "cases": cases}}
            raw = json.dumps(report).encode()
            report_path = store / "evidence" / "behavior.json"
            report_path.write_bytes(raw)
            ref = {"path": str(report_path), "sha256": hashlib.sha256(raw).hexdigest(),
                   "kind": "flutter-android-behavior"}
            with self.assertRaisesRegex(workflow.WorkflowError, "signing comparison is missing"):
                workflow._verify_flutter_check(plan, captured, execution_record,
                    "flutter_android_behavior", [raw], [ref])

    def test_flutter_behavior_signature_json_must_match_local_apksigner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, captured, _target, plan, action, _, _, _ = self.prepare_run(root, "flutter-signature-proof")
            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)):
                result = execution.execute_bla_action(store, "flutter-signature-proof", action["id"], None)
            executed = workflow.read_record(store / "records" / f"execution-{result['execution_id']}.json", "execution")
            baseline_hash = captured["identity"]["artifacts"][action["execution"]["artifact_path"]]["sha256"]
            candidate_hash = executed["flutter_candidate"]["candidate_artifact_sha256"]
            device_hash = "e" * 64
            report = {"schema_version": "1.0", "record_type": "flutter-android-behavior",
                "run_id": "flutter-signature-proof", "action_id": action["id"],
                "plan_sha256": workflow.record_hash(plan), "baseline_sha256": workflow.record_hash(captured),
                "source_identity_sha256": workflow.record_hash(captured["identity"]),
                "toolchain_identity_sha256": workflow.record_hash(captured["identity"]["flutter_toolchain"]),
                "dependency_lock_sha256": captured["identity"]["dependency_lock_sha256"],
                "baseline": {"apk_sha256": baseline_hash, "device_identity_sha256": device_hash,
                             "cases": [{"case_id": "launch", "result": "passed"}]},
                "candidate": {"apk_sha256": candidate_hash, "device_identity_sha256": device_hash,
                              "cases": [{"case_id": "launch", "result": "passed"}]}}
            signatures = {}
            for side, apk_hash in (("baseline", baseline_hash), ("candidate", candidate_hash)):
                signed = {"record_type": "apk-signature-verification", "apk_sha256": apk_hash,
                          "result": "Verifies", "signer_count": 1, "certificate_sha256": "a" * 64}
                raw_signed = json.dumps(signed).encode()
                signature_path = store / "evidence" / f"{side}-signature.json"
                signature_path.write_bytes(raw_signed)
                signatures[side] = {"path": str(signature_path),
                    "sha256": hashlib.sha256(raw_signed).hexdigest(), "kind": "apk-signature-verification"}
            report["signing_comparison"] = signatures
            raw = json.dumps(report).encode()
            report_path = store / "evidence" / "behavior-with-signatures.json"
            report_path.write_bytes(raw)
            ref = {"path": str(report_path), "sha256": hashlib.sha256(raw).hexdigest(),
                   "kind": "flutter-android-behavior"}

            def observed(apk_hash, certificate):
                return {"apk_sha256": apk_hash, "result": "Verifies", "signer_count": 1,
                        "certificate_sha256": [certificate]}

            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)), \
                    patch("core.flutter_android.verify_apk_signature", side_effect=[
                        observed(baseline_hash, "b" * 64)] ) as verify:
                with self.assertRaisesRegex(workflow.WorkflowError, "direct apksigner verification"):
                    workflow._verify_flutter_check(plan, captured, executed,
                        "flutter_android_behavior", [raw], [ref])
            self.assertEqual(verify.call_count, 1)

            with patch("core.flutter_android.capture_toolchain_identity",
                       side_effect=lambda command, cwd: self.toolchain_identity(command)), \
                    patch("core.flutter_android.verify_apk_signature", side_effect=[
                        observed(baseline_hash, "a" * 64), observed(candidate_hash, "a" * 64)]) as verify:
                workflow._verify_flutter_check(plan, captured, executed,
                    "flutter_android_behavior", [raw], [ref])
            self.assertEqual(verify.call_count, 2)


@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class SourceMapCandidateTests(unittest.TestCase):
    def prepare_run(self, root, run_id):
        project=root/"project"; project.mkdir(); store=root/"state"
        (project/"build.py").write_text(
            "from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\n"
            "Path('dist/app.js').write_text('bundle')\nPath('dist/app.js.map').write_text('private map')\n"
            "Path('dist/keep.txt').write_text('keep')\n")
        captured,_=baseline.capture(project,store,[sys.executable,"build.py"],
                                   ["dist/app.js","dist/app.js.map","dist/keep.txt"],f"{run_id}-before")
        target=workflow.read_record(store/"records"/f"target-{captured['target_id']}.json","target")
        plan=recommendations.create_plan(target,captured,f"{run_id}-plan")
        action=next(item for item in plan["actions"] if item["verification"]==["public_source_map_absent"])
        workflow.write_record(store/"records",plan)
        run={"schema_version":"2.0","record_type":"run","id":run_id,
             "target_id":target["id"],"state":"discovered"}
        run_path=workflow.write_run_state(store/"runs",run,None)
        baselining=workflow.transition_run(run,"baselining")
        workflow.write_run_state(run_path.parent,baselining,run)
        awaiting=workflow.submit_plan(baselining,target,captured,plan)
        workflow.write_run_state(run_path.parent,awaiting,baselining)
        decision={"schema_version":"2.0","record_type":"decision","id":f"{run_id}-decision",
                  "plan_sha256":workflow.record_hash(plan),"selected_action_ids":[action["id"]],
                  "decision":"approved","decision_source":"owned test"}
        workflow.write_record(store/"records",decision)
        bound=workflow.bind_decision(awaiting,plan,decision)
        workflow.write_run_state(run_path.parent,bound,awaiting)
        preparing=workflow.start_execution(bound,plan,decision)
        workflow.write_run_state(run_path.parent,preparing,bound)
        return store, captured, target, plan, action, decision, run_path

    def test_cancel_helper_routes_composite_tree_not_its_evidence_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ("records","runs","candidates","evidence"):
                (root/name).mkdir()
            candidate=root/"candidates"/"composite-run"
            candidate.mkdir()
            (candidate/"app.js").write_text("candidate")
            tree=execution._snapshot_tree_identity(candidate)
            manifest=root/"evidence"/"composite-manifest.json"
            manifest.write_text("manifest")
            digest=hashlib.sha256(manifest.read_bytes()).hexdigest()
            run={"schema_version":"2.0","record_type":"run","id":"composite-cancel",
                 "target_id":"target-composite-cancel","state":"discovered"}
            run_path=workflow.write_run_state(root/"runs",run,None)
            for next_state,updates in (("baselining",{}),
                    ("awaiting_decision",{"baseline_id":"base-composite-cancel","plan_id":"plan-composite-cancel"}),
                    ("preparing",{"decision_id":"decision-composite-cancel"}),("executing",{}),
                    ("verifying",{"execution_id":"exec-composite-cancel",
                                   "verification_id":"verify-composite-cancel"})):
                changed=workflow.transition_run(run,next_state,**updates)
                workflow.write_run_state(run_path.parent,changed,run)
                run=changed
            record={"schema_version":"2.0","record_type":"execution","id":"exec-composite-cancel",
                    "run_id":run["id"],"plan_sha256":"a"*64,"commands":[["fixture"]],"exit_code":0,
                    "outputs":[{"path":str(manifest),"sha256":digest}],"candidate_tree":{
                        "path":str(candidate),"tree_sha256":tree["tree_sha256"],
                        "file_scope_sha256":tree["file_scope_sha256"]}}
            workflow.write_record(root/"records",record)

            expected={"kind":"tree","sha256":tree["tree_sha256"],
                      "file_scope_sha256":tree["file_scope_sha256"]}
            with patch.object(execution,"_verify_candidate_for_rollback",return_value=expected) as verify:
                result=execution.discard_candidate_if_active(root,run["id"])
            self.assertEqual(result["status"],"discarded")
            self.assertFalse(candidate.exists())
            self.assertTrue(Path(result["retained_at"]).is_dir())
            verify.assert_called_once()
            self.assertTrue(verify.call_args.args[-1])
            rollback=workflow.read_record(root/"records"/f"rollback-{result['rollback_id']}.json","rollback")
            retained=Path(rollback["artifacts"][0]["retained_path"])
            self.assertEqual(execution._snapshot_tree_identity(retained),tree)

    def test_candidate_omits_only_selected_map_and_acceptance_authenticates_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            store,captured,target,plan,action,decision,run_path=self.prepare_run(root,"map-run")
            output=io.StringIO()
            with patch.dict(os.environ,{"ANTI_REA_BLA_RUNTIME":""}), redirect_stdout(output):
                self.assertEqual(anti_rea.main(["execute-plan","map-run",action["id"],str(store)]),0)
            result=json.loads(output.getvalue())
            self.assertEqual(result["status"],"verifying")
            candidate=Path(result["candidate"])
            self.assertFalse((candidate/"dist/app.js.map").exists())
            self.assertEqual((candidate/"dist/app.js").read_text(),"bundle")
            self.assertEqual((candidate/"dist/keep.txt").read_text(),"keep")
            baseline_tree=Path(captured["identity"]["build_snapshot"]["path"])
            self.assertEqual((baseline_tree/"dist/app.js.map").read_text(),"private map")
            executed=workflow.read_record(store/"records"/f"execution-{result['execution_id']}.json","execution")
            verification=workflow.read_record(store/"records"/f"verification-{result['verification_id']}.json","verification")
            acceptance={"schema_version":"2.0","record_type":"acceptance","id":"map-accept",
                        "run_id":"map-run","outcome":"accepted","claims":[],"claim_ids":["source_map_omitted_from_private_candidate"],
                        "reasons":["Exact candidate-tree exclusion verified"],"verification_id":verification["id"],
                        "execution_id":executed["id"],"plan_sha256":workflow.record_hash(plan)}
            self.assertEqual(workflow.accept_run(workflow.read_record(run_path,"run"),target,captured,plan,
                decision,executed,verification,acceptance)["state"],"completed")
            (candidate/"dist/keep.txt").write_text("changed")
            with self.assertRaisesRegex(workflow.WorkflowError,"candidate removed more than the selected map"):
                workflow.accept_run(workflow.read_record(run_path,"run"),target,captured,plan,
                    decision,executed,verification,acceptance)
            with self.assertRaisesRegex(workflow.WorkflowError,"candidate removed more than the selected map"):
                execution.discard_candidate(store,"map-run")
            (candidate/"dist/keep.txt").write_text("keep")
            terminal=workflow.accept_run(workflow.read_record(run_path,"run"),target,captured,plan,
                decision,executed,verification,acceptance)
            self.assertEqual(terminal["state"],"completed")
            workflow.write_record(store/"records",acceptance)
            workflow.write_run_state(run_path.parent,terminal,workflow.read_record(run_path,"run"))
            rollback=execution.discard_candidate(store,"map-run")
            self.assertEqual(rollback["status"],"discarded")
            self.assertFalse(candidate.exists())
            self.assertEqual(workflow.assemble_run_report(store/"records",terminal)["status"],"ok")
            retained=Path(rollback["retained_at"])
            self.assertTrue((retained/"dist/app.js").is_file())
            self.assertFalse((retained/"dist/app.js.map").exists())
            source_map_ref=next(item for item in executed["evidence"]
                                if item.get("kind")=="source-map-candidate")
            workflow._verify_source_map_check(plan,captured,executed,
                [workflow.verify_evidence_file(source_map_ref)],[source_map_ref])
            self.assertTrue(execution.discard_candidate(store,"map-run")["already_discarded"])
            (retained/"dist/keep.txt").write_text("tampered")
            with self.assertRaisesRegex(workflow.WorkflowError,"Retained rollback tree hash mismatch"):
                execution.discard_candidate(store,"map-run")

    def test_cancel_verifying_run_quarantines_source_map_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            store,_captured,_target,_plan,action,_decision,_run_path=self.prepare_run(root,"map-resume-run")
            output=io.StringIO()
            with patch.dict(os.environ,{"ANTI_REA_BLA_RUNTIME":""}), redirect_stdout(output):
                self.assertEqual(anti_rea.main(["execute-plan","map-resume-run",action["id"],str(store)]),0)
            result=json.loads(output.getvalue())
            candidate=Path(result["candidate"])
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(anti_rea.main(["cancel","map-resume-run",str(store)]),0)
            self.assertEqual(json.loads(output.getvalue())["state"],"cancelled")
            self.assertFalse(candidate.exists())
            rollback=workflow.read_record(next((store/"records").glob("rollback-*.json")),"rollback")
            retained=Path(rollback["artifacts"][0]["retained_path"])
            self.assertTrue((retained/"dist/app.js").is_file())
            self.assertFalse((retained/"dist/app.js.map").exists())
            (retained/"dist/keep.txt").write_text("tampered")
            with self.assertRaisesRegex(workflow.WorkflowError,"Retained rollback tree hash mismatch"):
                execution.prepare_resume(store,"map-resume-run","map-resume-tampered")
            (retained/"dist/keep.txt").write_text("keep")
            resumed=execution.prepare_resume(store,"map-resume-run","map-resume-new")
            self.assertEqual((resumed["state"],resumed["resume_of"]),("preparing","map-resume-run"))

    def test_resume_refuses_source_map_candidate_without_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            store,_captured,_target,_plan,action,_decision,run_path=self.prepare_run(root,"map-active-run")
            output=io.StringIO()
            with patch.dict(os.environ,{"ANTI_REA_BLA_RUNTIME":""}), redirect_stdout(output):
                self.assertEqual(anti_rea.main(["execute-plan","map-active-run",action["id"],str(store)]),0)
            run=workflow.validate_run(workflow.read_json(run_path))
            cancelled=workflow.transition_run(run,"cancelled",cancellation_reason="user_requested")
            workflow.write_run_state(run_path.parent,cancelled,run)
            with self.assertRaisesRegex(workflow.WorkflowError,"active candidate"):
                execution.prepare_resume(store,"map-active-run","map-active-retry")
            self.assertFalse((store/"runs"/"run-map-active-retry.json").exists())

    def test_copy_cancellation_stops_before_verification_and_removes_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            store,captured,_target,_plan,action,_decision,run_path=self.prepare_run(root,"map-cancel")
            cancel=threading.Event()
            original=execution._copy_project_file
            def cancel_after_copy(*args):
                original(*args)
                cancel.set()
            with patch.object(execution,"_copy_project_file",side_effect=cancel_after_copy):
                with self.assertRaisesRegex(workflow.WorkflowError,"Command cancelled"):
                    execution.execute_bla_action(store,"map-cancel",action["id"],None,cancel)
            saved=workflow.validate_run(workflow.read_json(run_path))
            self.assertEqual(saved["state"],"cancelled")
            self.assertEqual(list((store/"candidates").iterdir()),[])
            baseline_tree=Path(captured["identity"]["build_snapshot"]["path"])
            self.assertEqual((baseline_tree/"dist/app.js.map").read_text(),"private map")
