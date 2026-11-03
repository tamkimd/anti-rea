import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core import baseline, execution, recommendations, workflow


@unittest.skipUnless(
    os.environ.get("ANTI_REA_BLA_RUNTIME"),
    "set ANTI_REA_BLA_RUNTIME for pinned engine execution",
)
@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class PlanExecutionTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME")
        and os.environ.get("ANTI_REA_REA_RUNTIME"),
        "pinned REA and browser runtimes are required",
    )
    @patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "docker"})
    def test_built_static_spa_runs_plan_bound_browser_and_rea_candidate_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            store = root / "state"
            shutil.copytree(
                Path(__file__).parents[1] / "fixtures/e2e/static-spa", project
            )
            node = os.environ.get("ANTI_REA_NODE", "node")
            artifacts = [
                "dist/index.html",
                "dist/assets/app.js",
                "dist/assets/site.css",
            ]
            with patch.dict(
                os.environ,
                {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
            ):
                captured, _ = baseline.capture(
                    project,
                    store,
                    [node, "build.mjs"],
                    artifacts,
                    "static-spa-before",
                    e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
                )
            target = workflow.read_record(
                store / "records" / f"target-{captured['target_id']}.json", "target"
            )
            plan = recommendations.create_plan(
                target, captured, "static-spa-plan", e2e_behavior=True
            )
            action = next(
                item
                for item in plan["actions"]
                if item.get("execution", {}).get("source_path") == "dist/assets/app.js"
            )
            workflow.write_record(store / "records", plan)
            run = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "run",
                "id": "static-spa-run",
                "target_id": target["id"],
                "state": "discovered",
            }
            run_path = workflow.write_run_state(store / "runs", run, None)
            baselining = workflow.transition_run(run, "baselining")
            workflow.write_run_state(run_path.parent, baselining, run)
            awaiting = workflow.submit_plan(baselining, target, captured, plan)
            workflow.write_run_state(run_path.parent, awaiting, baselining)
            decision = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "decision",
                "id": "static-spa-decision",
                "plan_sha256": workflow.record_hash(plan),
                "selected_action_ids": [action["id"]],
                "decision": "approved",
                "decision_source": "owned static SPA integration test",
            }
            workflow.write_record(store / "records", decision)
            bound = workflow.bind_decision(awaiting, plan, decision)
            workflow.write_run_state(run_path.parent, bound, awaiting)
            preparing = workflow.start_execution(bound, plan, decision)
            workflow.write_run_state(run_path.parent, preparing, bound)
            with patch.dict(
                os.environ,
                {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
            ):
                result = execution.execute_bla_action(
                    store,
                    "static-spa-run",
                    action["id"],
                    os.environ["ANTI_REA_BLA_RUNTIME"],
                    rea_runtime=os.environ["ANTI_REA_REA_RUNTIME"],
                    e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
                )
            verification = workflow.read_record(
                store / "records" / f"verification-{result['verification_id']}.json",
                "verification",
            )
            self.assertEqual(
                {item["id"]: item["status"] for item in verification["checks"]},
                {
                    "bla_invariants": "passed",
                    "rea_comparison": "passed",
                    "performance": "passed",
                    "e2e_behavior": "passed",
                },
            )
            executed = workflow.read_record(
                store / "records" / f"execution-{result['execution_id']}.json",
                "execution",
            )
            perf_check = next(
                item for item in verification["checks"] if item["id"] == "performance"
            )
            self.assertEqual(
                len(executed["performance"]["browser_journey"]["trials"]["source"]), 3
            )
            self.assertEqual(
                len(executed["performance"]["browser_journey"]["trials"]["candidate"]),
                3,
            )
            browser_order = [
                command[command.index("--output") + 1].split("performance-", 1)[1]
                for command in executed["commands"]
                if "--output" in command
                and command[command.index("--output") + 1].startswith(
                    ".anti-rea-e2e/performance-"
                )
            ]
            self.assertEqual(
                browser_order,
                [
                    "source-0",
                    "candidate-0",
                    "candidate-1",
                    "source-1",
                    "source-2",
                    "candidate-2",
                ],
            )
            perf_bytes = [
                Path(item["path"]).read_bytes() for item in perf_check["evidence"]
            ]
            workflow._verify_performance_check(
                plan, captured, executed, perf_bytes, perf_check["evidence"]
            )
            changed = json.loads(perf_bytes[0])
            changed["browser_journey"]["summary"]["interaction_ms"][
                "candidate_median"
            ] += 1
            with self.assertRaisesRegex(
                workflow.WorkflowError, "Browser journey summary"
            ):
                workflow._verify_performance_check(
                    plan,
                    captured,
                    executed,
                    [json.dumps(changed).encode(), *perf_bytes[1:]],
                    perf_check["evidence"],
                )
            acceptance = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "acceptance",
                "id": "static-spa-accept",
                "run_id": "static-spa-run",
                "outcome": "accepted",
                "claims": [],
                "claim_ids": workflow.acceptance_claim_ids(
                    [item["id"] for item in verification["checks"]]
                ),
                "reasons": ["Pinned browser and comparable REA checks passed"],
                "verification_id": verification["id"],
                "execution_id": executed["id"],
                "plan_sha256": workflow.record_hash(plan),
            }
            accepted = workflow.accept_run(
                workflow.read_record(run_path, "run"),
                target,
                captured,
                plan,
                decision,
                executed,
                verification,
                acceptance,
            )
            self.assertEqual(
                (accepted["state"], accepted["acceptance"]), ("completed", "accepted")
            )

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for pinned browser execution",
    )
    def test_plan_bound_e2e_acceptance_compares_baseline_and_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            store = root / "state"
            shutil.copytree(Path(__file__).parents[1] / "fixtures/e2e/web", project)
            node = os.environ.get("ANTI_REA_NODE", "node")
            with patch.dict(
                os.environ,
                {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
            ):
                baseline_record, _ = baseline.capture(
                    project,
                    store,
                    [sys.executable, "-c", "pass"],
                    ["app.js"],
                    "e2e-before",
                    e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
                )
            target = workflow.read_record(
                store / "records" / f"target-{baseline_record['target_id']}.json",
                "target",
            )
            plan = recommendations.create_plan(
                target, baseline_record, "plan-e2e", e2e_behavior=True
            )
            action = next(
                item
                for item in plan["actions"]
                if item["execution"]["source_path"] == "app.js"
            )
            action["verification"] = ["bla_invariants", "e2e_behavior"]
            workflow.write_record(store / "records", plan)
            run = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "run",
                "id": "run-e2e",
                "target_id": target["id"],
                "state": "discovered",
            }
            run_path = workflow.write_run_state(store / "runs", run, None)
            baselining = workflow.transition_run(run, "baselining")
            workflow.write_run_state(run_path.parent, baselining, run)
            awaiting = workflow.submit_plan(baselining, target, baseline_record, plan)
            workflow.write_run_state(run_path.parent, awaiting, baselining)
            decision = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "decision",
                "id": "decision-e2e",
                "plan_sha256": workflow.record_hash(plan),
                "selected_action_ids": [action["id"]],
                "decision": "approved",
                "decision_source": "owned fixture integration test",
            }
            workflow.write_record(store / "records", decision)
            bound = workflow.bind_decision(awaiting, plan, decision)
            workflow.write_run_state(run_path.parent, bound, awaiting)
            preparing = workflow.start_execution(bound, plan, decision)
            workflow.write_run_state(run_path.parent, preparing, bound)
            env_path = f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"
            with patch.dict(os.environ, {"PATH": env_path}):
                result = execution.execute_bla_action(
                    store,
                    "run-e2e",
                    action["id"],
                    os.environ["ANTI_REA_BLA_RUNTIME"],
                    e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
                )
            self.assertEqual(result["status"], "verifying")
            records = store / "records"
            executed = workflow.read_record(
                records / f"execution-{result['execution_id']}.json", "execution"
            )
            verification = workflow.read_record(
                records / f"verification-{result['verification_id']}.json",
                "verification",
            )
            self.assertEqual(
                {item["id"]: item["status"] for item in verification["checks"]},
                {"bla_invariants": "passed", "e2e_behavior": "passed"},
            )
            acceptance = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "acceptance",
                "id": "accept-e2e",
                "run_id": "run-e2e",
                "outcome": "accepted",
                "claims": [],
                "claim_ids": ["bla_invariants_passed", "e2e_behavior_passed"],
                "reasons": ["Pinned paired browser reports passed"],
                "verification_id": verification["id"],
                "execution_id": executed["id"],
                "plan_sha256": workflow.record_hash(plan),
            }
            accepted = workflow.accept_run(
                workflow.read_record(run_path, "run"),
                target,
                baseline_record,
                plan,
                decision,
                executed,
                verification,
                acceptance,
            )
            self.assertEqual(
                (accepted["state"], accepted["acceptance"]), ("completed", "accepted")
            )
            before_report = Path(
                baseline_record["identity"]["e2e_behavior"]["report_path"]
            )
            saved_report = before_report.read_bytes()
            before_report.write_bytes(saved_report + b"tampered")
            with self.assertRaisesRegex(workflow.WorkflowError, "hash mismatch"):
                workflow.accept_run(
                    workflow.read_record(run_path, "run"),
                    target,
                    baseline_record,
                    plan,
                    decision,
                    executed,
                    verification,
                    acceptance,
                )
            before_report.write_bytes(saved_report)
            baseline_snapshot = Path(
                baseline_record["identity"]["e2e_behavior"]["snapshot_path"]
            )
            original_app = (baseline_snapshot / "app.js").read_bytes()
            (baseline_snapshot / "app.js").write_bytes(original_app + b"// drift\n")
            with self.assertRaisesRegex(
                workflow.WorkflowError, "snapshots do not match"
            ):
                workflow.accept_run(
                    workflow.read_record(run_path, "run"),
                    target,
                    baseline_record,
                    plan,
                    decision,
                    executed,
                    verification,
                    acceptance,
                )
            (baseline_snapshot / "app.js").write_bytes(original_app)
            tampered = {
                **executed,
                "e2e_behavior": {
                    **executed["e2e_behavior"],
                    "test_ids": ["unrelated-test"],
                },
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "different test scope"):
                workflow.accept_run(
                    workflow.read_record(run_path, "run"),
                    target,
                    baseline_record,
                    plan,
                    decision,
                    tampered,
                    verification,
                    acceptance,
                )

    @unittest.skipUnless(
        os.environ.get("ANTI_REA_E2E_RUNTIME"),
        "set ANTI_REA_E2E_RUNTIME for pinned browser execution",
    )
    def test_failed_baseline_browser_behavior_blocks_capture_with_report_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            store = root / "state"
            shutil.copytree(Path(__file__).parents[1] / "fixtures/e2e/web", project)
            test_file = project / "tests/behavior.e2e.ts"
            test_file.write_text(
                test_file.read_text().replace("Hello, Ada!", "wrong greeting")
            )
            node = os.environ.get("ANTI_REA_NODE", "node")
            with patch.dict(
                os.environ,
                {"PATH": f"{Path(node).resolve().parent}:{os.environ.get('PATH', '')}"},
            ):
                with self.assertRaisesRegex(
                    workflow.WorkflowError, "Baseline e2e did not pass"
                ):
                    baseline.capture(
                        project,
                        store,
                        [sys.executable, "-c", "pass"],
                        ["app.js"],
                        "e2e-failure-before",
                        e2e_runtime=os.environ["ANTI_REA_E2E_RUNTIME"],
                    )
            report = (
                store / "evidence" / "baseline-e2e-failure-before-e2e" / "report.json"
            )
            self.assertTrue(report.is_file())
            self.assertEqual(json.loads(report.read_text())["run"]["status"], "failed")
            self.assertFalse(
                (store / "records" / "baseline-e2e-failure-before.json").exists()
            )

    @unittest.skipUnless(
        importlib.util.find_spec("mcp"), "MCP SDK is required for background execution"
    )
    def test_selected_bla_action_checks_behavior_and_comparable_rea(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            store = root / "state"
            (project / "package.json").write_text(
                '{"name":"owned-fixture","type":"module"}\n'
            )
            source = "export function greet(name) { return `Hello, ${name}!`; }\n"
            (project / "make.py").write_text(
                "from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\nPath('dist/app.mjs').write_text("
                + repr(source)
                + ")\n"
            )
            (project / "check.mjs").write_text(
                "import { pathToFileURL } from 'node:url';\nconst mod = await import(pathToFileURL(process.argv[2]));\nprocess.stdout.write(mod.greet('Ada'));\n"
            )
            behavior_command = [
                os.environ.get("ANTI_REA_NODE", "node"),
                "check.mjs",
                "{artifact}",
            ]
            baseline_record, _ = baseline.capture(
                project,
                store,
                [sys.executable, "make.py"],
                ["dist/app.mjs"],
                "before-run",
                behavior_command=behavior_command,
            )
            target = workflow.read_record(
                store / "records" / f"target-{baseline_record['target_id']}.json",
                "target",
            )
            plan = recommendations.create_plan(
                target, baseline_record, "plan-run", behavior_command=behavior_command
            )
            workflow.write_record(store / "records", plan)
            run = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "run",
                "id": "run-bla",
                "target_id": target["id"],
                "state": "discovered",
            }
            run_path = workflow.write_run_state(store / "runs", run, None)
            baselining = workflow.transition_run(run, "baselining")
            workflow.write_run_state(run_path.parent, baselining, run)
            awaiting = workflow.submit_plan(baselining, target, baseline_record, plan)
            workflow.write_run_state(run_path.parent, awaiting, baselining)
            selected = plan["actions"][0]["id"]
            decision = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "decision",
                "id": "decision-bla",
                "plan_sha256": workflow.record_hash(plan),
                "selected_action_ids": [selected],
                "decision": "approved",
                "decision_source": "owned integration test",
            }
            decision = workflow.validate_decision(decision, plan)
            workflow.write_record(store / "records", decision)
            bound = workflow.bind_decision(awaiting, plan, decision)
            workflow.write_run_state(run_path.parent, bound, awaiting)
            preparing = workflow.start_execution(bound, plan, decision)
            workflow.write_run_state(run_path.parent, preparing, bound)

            from core import execution

            with self.assertRaisesRegex(workflow.WorkflowError, "not selected"):
                execution.execute_bla_action(
                    store,
                    "run-bla",
                    "another-action",
                    os.environ["ANTI_REA_BLA_RUNTIME"],
                )
            build_artifact = (
                Path(baseline_record["identity"]["build_snapshot"]["path"])
                / "dist/app.mjs"
            )
            built_bytes = build_artifact.read_bytes()
            build_artifact.write_bytes(built_bytes + b"// tampered snapshot\n")
            with self.assertRaisesRegex(
                workflow.WorkflowError, "Baseline build snapshot changed"
            ):
                execution.execute_bla_action(
                    store, "run-bla", selected, os.environ["ANTI_REA_BLA_RUNTIME"]
                )
            build_artifact.write_bytes(built_bytes)
            source_artifact = project / "make.py"
            original_build = source_artifact.read_text()
            source_artifact.write_text(original_build + "# changed after baseline\n")
            with self.assertRaisesRegex(
                workflow.WorkflowError,
                "Non-artifact source input changed after baseline",
            ):
                execution.execute_bla_action(
                    store, "run-bla", selected, os.environ["ANTI_REA_BLA_RUNTIME"]
                )
            source_artifact.write_text(original_build)
            with patch.dict(os.environ, {"ANTI_REA_STATE_DIR": str(store)}):
                from interfaces.mcp import server

                scheduled = server.execute_plan(
                    "run-bla", selected, os.environ["ANTI_REA_BLA_RUNTIME"]
                )
                self.assertEqual(scheduled["status"], "scheduled")
                for _ in range(300):
                    current = server.get_run("run-bla")
                    if (
                        not current["execution_active"]
                        and current["state"] != "preparing"
                    ):
                        break
                    time.sleep(0.1)
                self.assertEqual(current["state"], "verifying", current)
            execution_file = next((store / "records").glob("execution-*.json"))
            saved_execution = workflow.read_record(execution_file, "execution")
            self.assertEqual(current["execution_id"], saved_execution["id"])
            self.assertEqual(
                current["verification_id"],
                workflow.read_record(
                    next((store / "records").glob("verification-*.json")),
                    "verification",
                )["id"],
            )
            self.assertTrue(Path(saved_execution["outputs"][0]["path"]).is_file())
            self.assertEqual(
                workflow.read_record(run_path, "run")["state"], "verifying"
            )
            verification_file = next((store / "records").glob("verification-*.json"))
            verification = workflow.read_record(verification_file, "verification")
            bla_check = next(
                item
                for item in verification["checks"]
                if item["id"] == "bla_invariants"
            )
            bla_bytes = Path(bla_check["evidence"][0]["path"]).read_bytes()
            workflow._verify_bla_check(
                plan,
                baseline_record,
                target,
                saved_execution,
                [bla_bytes],
                bla_check["evidence"],
            )
            invalid_report = json.loads(bla_bytes)
            invalid_output = json.loads(invalid_report["stdout"])
            invalid_output["overallPassed"] = False
            invalid_report["stdout"] = json.dumps(invalid_output)
            with self.assertRaisesRegex(
                workflow.WorkflowError, "does not prove all invariant checks passed"
            ):
                workflow._verify_bla_check(
                    plan,
                    baseline_record,
                    target,
                    saved_execution,
                    [json.dumps(invalid_report).encode()],
                    bla_check["evidence"],
                )
            behavior_check = next(
                item
                for item in verification["checks"]
                if item["id"] == "application_behavior"
            )
            behavior_bytes = [
                Path(item["path"]).read_bytes() for item in behavior_check["evidence"]
            ]
            self.assertEqual(len(behavior_bytes), 3)
            workflow._verify_behavior_check(
                plan,
                baseline_record,
                target,
                saved_execution,
                behavior_bytes,
                behavior_check["evidence"],
            )
            rea_check = next(
                item
                for item in verification["checks"]
                if item["id"] == "rea_comparison"
            )
            rea_bytes = [
                Path(item["path"]).read_bytes() for item in rea_check["evidence"]
            ]
            workflow._verify_rea_check(
                workflow.read_record(run_path, "run"),
                plan,
                baseline_record,
                target,
                saved_execution,
                rea_bytes,
                rea_check["evidence"],
            )
            tampered = json.loads(rea_bytes[0])
            tampered["finding_delta"] += 1
            with self.assertRaisesRegex(
                workflow.WorkflowError, "summary is inconsistent"
            ):
                workflow._verify_rea_check(
                    workflow.read_record(run_path, "run"),
                    plan,
                    baseline_record,
                    target,
                    saved_execution,
                    [json.dumps(tampered).encode()],
                    rea_check["evidence"],
                )
            with patch.dict(os.environ, {"ANTI_REA_STATE_DIR": str(store)}):
                self.assertEqual(
                    server.get_evidence("execution", saved_execution["id"]),
                    saved_execution,
                )
            perf_check = next(
                item for item in verification["checks"] if item["id"] == "performance"
            )
            perf_bytes = [
                Path(item["path"]).read_bytes() for item in perf_check["evidence"]
            ]
            workflow._verify_performance_check(
                plan,
                baseline_record,
                saved_execution,
                perf_bytes,
                perf_check["evidence"],
            )
            tampered_summary = json.loads(perf_bytes[0])
            tampered_summary["summary"]["elapsed_ms_mean"] += 1
            with self.assertRaisesRegex(workflow.WorkflowError, "variability summary"):
                workflow._verify_performance_check(
                    plan,
                    baseline_record,
                    saved_execution,
                    [json.dumps(tampered_summary).encode()],
                    perf_check["evidence"],
                )
            tampered_perf = json.loads(perf_bytes[0])
            tampered_perf["trials"].pop()
            with self.assertRaisesRegex(workflow.WorkflowError, "trial count"):
                workflow._verify_performance_check(
                    plan,
                    baseline_record,
                    saved_execution,
                    [json.dumps(tampered_perf).encode()],
                    perf_check["evidence"],
                )
            over_budget = json.loads(perf_bytes[0])
            over_budget["trials"][0]["candidate_bytes"] += 1
            over_budget["summary"]["candidate_bytes_max"] += 1
            over_budget["summary"]["candidate_bytes_mean"] += 1 / 3
            over_budget["summary"]["candidate_growth_bytes_max"] += 1
            with self.assertRaisesRegex(workflow.WorkflowError, "budget was exceeded"):
                workflow._verify_performance_check(
                    plan,
                    baseline_record,
                    saved_execution,
                    [json.dumps(over_budget).encode()],
                    perf_check["evidence"],
                )
            check_status = {
                check["id"]: check["status"] for check in verification["checks"]
            }
            self.assertEqual(
                check_status,
                {
                    "bla_invariants": "passed",
                    "application_behavior": "passed",
                    "rea_comparison": "passed",
                    "performance": "passed",
                },
            )
            acceptance = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "acceptance",
                "id": "accept-bla",
                "run_id": "run-bla",
                "outcome": "accepted",
                "claims": [],
                "claim_ids": workflow.acceptance_claim_ids(
                    [item["id"] for item in verification["checks"]]
                ),
                "reasons": ["test"],
                "verification_id": verification["id"],
                "execution_id": saved_execution["id"],
                "plan_sha256": workflow.record_hash(plan),
            }
            baseline_behavior = Path(
                baseline_record["identity"]["behavior"]["evidence_path"]
            )
            baseline_behavior_bytes = baseline_behavior.read_bytes()
            baseline_behavior.write_bytes(b"tampered baseline behavior")
            with self.assertRaisesRegex(workflow.WorkflowError, "hash mismatch"):
                workflow.accept_run(
                    workflow.read_record(run_path, "run"),
                    target,
                    baseline_record,
                    plan,
                    decision,
                    saved_execution,
                    verification,
                    acceptance,
                )
            baseline_behavior.write_bytes(baseline_behavior_bytes)
            accepted = workflow.accept_run(
                workflow.read_record(run_path, "run"),
                target,
                baseline_record,
                plan,
                decision,
                saved_execution,
                verification,
                acceptance,
            )
            self.assertEqual(
                (accepted["state"], accepted["acceptance"]), ("completed", "accepted")
            )

            blocked_plan = recommendations.create_plan(
                target,
                baseline_record,
                "plan-bla-blocked",
                behavior_command=[
                    os.environ.get("ANTI_REA_NODE", "node"),
                    "check.mjs",
                    "{artifact}",
                ],
            )
            blocked_plan["actions"][0]["verification"].append("independent_perf")
            workflow.write_record(store / "records", blocked_plan)
            blocked_run = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "run",
                "id": "run-bla-blocked",
                "target_id": target["id"],
                "state": "discovered",
            }
            blocked_path = workflow.write_run_state(store / "runs", blocked_run, None)
            baselining = workflow.transition_run(blocked_run, "baselining")
            workflow.write_run_state(blocked_path.parent, baselining, blocked_run)
            awaiting = workflow.submit_plan(
                baselining, target, baseline_record, blocked_plan
            )
            workflow.write_run_state(blocked_path.parent, awaiting, baselining)
            blocked_action = blocked_plan["actions"][0]["id"]
            blocked_decision = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "decision",
                "id": "decision-bla-blocked",
                "plan_sha256": workflow.record_hash(blocked_plan),
                "selected_action_ids": [blocked_action],
                "decision": "approved",
                "decision_source": "owned integration test",
            }
            workflow.write_record(store / "records", blocked_decision)
            bound = workflow.bind_decision(awaiting, blocked_plan, blocked_decision)
            workflow.write_run_state(blocked_path.parent, bound, awaiting)
            preparing = workflow.start_execution(bound, blocked_plan, blocked_decision)
            workflow.write_run_state(blocked_path.parent, preparing, bound)
            result = execution.execute_bla_action(
                store,
                "run-bla-blocked",
                blocked_action,
                os.environ["ANTI_REA_BLA_RUNTIME"],
                rea_runtime=os.environ["ANTI_REA_REA_RUNTIME"],
            )
            self.assertEqual(result["status"], "rejected")
            rejected = workflow.read_record(blocked_path, "run")
            self.assertEqual(
                (rejected["state"], rejected["acceptance"]), ("blocked", "rejected")
            )
            blocked_execution = workflow.read_record(
                store / "records" / f"execution-{result['execution_id']}.json",
                "execution",
            )
            active_candidate = Path(blocked_execution["outputs"][0]["path"])
            self.assertFalse(active_candidate.exists())
            self.assertTrue(Path(result["candidate_retained_at"]).is_file())
            self.assertEqual(
                workflow.read_record(
                    store / "records" / f"acceptance-{result['acceptance_id']}.json",
                    "acceptance",
                )["outcome"],
                "rejected",
            )


if __name__ == "__main__":
    unittest.main()
