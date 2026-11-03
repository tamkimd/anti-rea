import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from core import baseline, execution, optimizer, recommendations, workflow
from interfaces.cli import anti_rea


@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class AcceptedOptimizerRunTests(unittest.TestCase):
    budgets = {
        "max_elapsed_ms": 1000,
        "max_total_elapsed_ms": 3000,
        "max_candidate_bytes": 1000,
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "build.py").write_text(
            "from pathlib import Path\nPath('dist').mkdir(exist_ok=True)\nPath('dist/app.js').write_text('source-app')\n"
        )

    def accepted_bla_run(
        self,
        run_id,
        candidate_content,
        context=None,
        project=None,
        action_id=None,
        runtime_hash="b" * 64,
        include_behavior=True,
        include_rea=True,
    ):
        store = self.root / "store"
        project = project or self.project
        records = store / "records"
        if context is None:
            behavior_command = (
                [sys.executable, "-c", "print('stable-behavior')", "{artifact}"]
                if include_behavior
                else None
            )
            captured, _ = baseline.capture(
                project,
                store,
                [sys.executable, "build.py"],
                ["dist/app.js"],
                f"{run_id}-baseline",
                behavior_command=behavior_command,
            )
            target = workflow.read_record(
                records / f"target-{captured['target_id']}.json", "target"
            )
            plan = recommendations.create_plan(
                target,
                captured,
                f"{run_id}-plan",
                behavior_command=behavior_command,
                performance_budget={
                    "trials": 3,
                    "max_elapsed_ms": self.budgets["max_elapsed_ms"],
                    "max_candidate_bytes": self.budgets["max_candidate_bytes"],
                },
            )
            action = next(
                item
                for item in plan["actions"]
                if item["execution"].get("adapter") == "bla-js"
            )
            if action_id:
                action["id"] = action_id
            action["verification"] = (
                ["bla_invariants", "performance"]
                + (["rea_comparison"] if include_rea else [])
                + (["application_behavior"] if include_behavior else [])
            )
            workflow.write_record(records, plan)
            decision = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "decision",
                "id": f"{run_id}-decision",
                "plan_sha256": workflow.record_hash(plan),
                "selected_action_ids": [action["id"]],
                "decision": "approved",
                "decision_source": "accepted optimizer fixture",
            }
            workflow.write_record(records, decision)
            context = (store, captured, target, plan, action, decision)
        else:
            store, captured, target, plan, action, decision = context
        run = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "run",
            "id": run_id,
            "target_id": target["id"],
            "state": "discovered",
        }
        run_path = workflow.write_run_state(store / "runs", run, None)
        changed = workflow.transition_run(run, "baselining")
        workflow.write_run_state(run_path.parent, changed, run)
        run = workflow.submit_plan(changed, target, captured, plan)
        workflow.write_run_state(run_path.parent, run, changed)
        changed = workflow.bind_decision(run, plan, decision)
        workflow.write_run_state(run_path.parent, changed, run)
        run = workflow.start_execution(changed, plan, decision)
        workflow.write_run_state(run_path.parent, run, changed)
        changed = workflow.transition_run(run, "executing")
        workflow.write_run_state(run_path.parent, changed, run)

        source = Path(captured["identity"]["build_snapshot"]["path"]) / "dist/app.js"
        candidate_dir = store / "candidates"
        evidence_dir = store / "evidence"
        candidate_dir.mkdir(mode=0o700, exist_ok=True)
        evidence_dir.mkdir(mode=0o700, exist_ok=True)
        candidate = candidate_dir / f"{run_id}.js"
        candidate.write_bytes(candidate_content)
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        artifact_hash = hashlib.sha256(candidate_content).hexdigest()
        engine_version = "1.2.3"

        def save(name, value):
            path = evidence_dir / f"{run_id}-{name}"
            path.write_bytes(workflow.canonical(value) + b"\n")
            return {
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        protect_ref = save(
            "protect.json",
            {"source_sha256": source_hash, "candidate_sha256": artifact_hash},
        )
        verification_report = {
            "command": [
                "/fixture/bla",
                "verify",
                str(candidate),
                str(source),
                "--json",
            ],
            "returncode": 0,
            "stdout": json.dumps(
                {
                    "targetPath": str(candidate),
                    "originalPath": str(source),
                    "overallPassed": True,
                    "functionalIntegrityVerified": True,
                    "checks": [{"passed": True}],
                }
            ),
            "runtime_manifest": {
                "npm_version": engine_version,
                "package_tree_sha256": runtime_hash,
            },
        }
        verify_ref = save("verify.json", verification_report)
        perf_budget = action["execution"]["performance_budget"]
        samples = []
        performance_candidate_refs = []
        for index, (elapsed, size_delta) in enumerate(((100, 0), (125, 1), (115, 0))):
            trial_content = candidate_content + b"x" * size_delta
            trial_path = (
                candidate
                if index == 0
                else evidence_dir / f"{run_id}-performance-candidate-{index}.js"
            )
            if index:
                trial_path.write_bytes(trial_content)
            trial_hash = hashlib.sha256(trial_content).hexdigest()
            artifact_ref = {
                "path": str(trial_path),
                "sha256": trial_hash,
                "kind": "performance-candidate",
            }
            performance_candidate_refs.append(artifact_ref)
            samples.append(
                {
                    "elapsed_ms": elapsed,
                    "candidate_bytes": len(trial_content),
                    "source_sha256": source_hash,
                    "candidate_sha256": trial_hash,
                    "candidate_artifact": artifact_ref,
                }
            )
        performance = {
            "schema_version": "1.0",
            "run_id": run_id,
            "action_id": action["id"],
            "plan_sha256": workflow.record_hash(plan),
            "source_sha256": source_hash,
            "runtime_manifest_sha256": runtime_hash,
            "source_bytes": source.stat().st_size,
            "budget": perf_budget,
            "trials": samples,
            "summary": {
                "elapsed_ms_min": min(s["elapsed_ms"] for s in samples),
                "elapsed_ms_max": max(s["elapsed_ms"] for s in samples),
                "elapsed_ms_mean": sum(s["elapsed_ms"] for s in samples) / 3,
                "candidate_bytes_min": min(s["candidate_bytes"] for s in samples),
                "candidate_bytes_max": max(s["candidate_bytes"] for s in samples),
                "candidate_bytes_mean": sum(s["candidate_bytes"] for s in samples) / 3,
                "candidate_growth_bytes_min": min(s["candidate_bytes"] for s in samples)
                - source.stat().st_size,
                "candidate_growth_bytes_max": max(s["candidate_bytes"] for s in samples)
                - source.stat().st_size,
            },
            "passed": True,
        }
        perf_ref = save("performance.json", performance)
        behavior_refs = []
        rea_refs = []
        rea_comparison = None
        if include_behavior:
            from core.execution import _create_rea_snapshots

            snapshot_key = hashlib.sha256(
                f"{run_id}:{action['id']}".encode()
            ).hexdigest()[:32]
            snapshot_root = store / "behavior-snapshots" / snapshot_key
            snapshot_root.mkdir(mode=0o700, parents=True)
            before_snapshot, after_snapshot = (
                snapshot_root / "before",
                snapshot_root / "after",
            )
            snapshot_identity = _create_rea_snapshots(
                Path(target["source_root"]),
                target,
                captured,
                "dist/app.js",
                candidate,
                artifact_hash,
                source_hash,
                before_snapshot,
                after_snapshot,
            )
            behavior_command = action["execution"]["behavior_command"]
            baseline_behavior = captured["identity"]["behavior"]
            behavior_refs.append(
                {
                    "path": baseline_behavior["evidence_path"],
                    "sha256": baseline_behavior["evidence_sha256"],
                    "kind": "behavior-baseline",
                }
            )
            from core import baseline as baseline_capture

            for label, snapshot in (
                ("source", before_snapshot),
                ("candidate", after_snapshot),
            ):
                argv = [
                    str(snapshot / "dist/app.js") if arg == "{artifact}" else arg
                    for arg in behavior_command
                ]
                code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
                    baseline_capture._run_command(argv, snapshot, 120)
                )
                report_path = evidence_dir / f"{run_id}-behavior-{label}.json"
                baseline_capture._write_output(
                    report_path,
                    argv,
                    code,
                    stdout,
                    stderr,
                    time.time(),
                    timed_out,
                    stdout_truncated,
                    stderr_truncated,
                )
                behavior_refs.append(
                    {
                        "path": str(report_path),
                        "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                        "kind": f"behavior-{label}",
                    }
                )
        if include_rea:
            from core.execution import _snapshot_tree_identity

            snapshot_key = hashlib.sha256(
                f"{run_id}:{action['id']}".encode()
            ).hexdigest()[:32]
            snapshot_root = store / "behavior-snapshots" / snapshot_key
            if not snapshot_root.exists():
                snapshot_root.mkdir(mode=0o700, parents=True)
            before_snapshot, after_snapshot = (
                snapshot_root / "before",
                snapshot_root / "after",
            )
            if not before_snapshot.exists():
                from core.execution import _create_rea_snapshots

                snapshot_identity = _create_rea_snapshots(
                    Path(target["source_root"]),
                    target,
                    captured,
                    "dist/app.js",
                    candidate,
                    artifact_hash,
                    source_hash,
                    before_snapshot,
                    after_snapshot,
                )
            else:
                snapshot_identity = {
                    **_snapshot_tree_identity(before_snapshot),
                    "before_tree_sha256": _snapshot_tree_identity(before_snapshot)[
                        "tree_sha256"
                    ],
                    "after_tree_sha256": _snapshot_tree_identity(after_snapshot)[
                        "tree_sha256"
                    ],
                    "file_scope_sha256": _snapshot_tree_identity(before_snapshot)[
                        "file_scope_sha256"
                    ],
                    "source_path": "dist/app.js",
                    "source_sha256": source_hash,
                    "candidate_sha256": artifact_hash,
                }
            side_results = {}
            for side, snapshot in (
                ("before", before_snapshot),
                ("after", after_snapshot),
            ):
                tree = _snapshot_tree_identity(snapshot)
                raw_path = evidence_dir / f"{run_id}-rea-{side}.jsonl"
                bundle_path = evidence_dir / f"{run_id}-rea-{side}.bundle"
                bundle_path.write_bytes(b"fixture evidence bundle\n")
                resolved_snapshot = snapshot.resolve(strict=True)
                result = {
                    "target": str(resolved_snapshot),
                    "report": str(raw_path),
                    "report_sha256": "0" * 64,
                    "evidence_bundle": str(bundle_path),
                    "evidence_bundle_sha256": hashlib.sha256(
                        bundle_path.read_bytes()
                    ).hexdigest(),
                    "artifact_sha256": tree["tree_sha256"],
                    "evidence_id": f"{run_id}-{side}",
                    "parent_digest": tree["tree_sha256"],
                    "findings": 0,
                }
                raw_summary = {
                    "predicate_type": "rea.analysis-view",
                    "operation": "inspect_analysis_view",
                    "normalized_result": {
                        "artifact": {
                            "path": str(resolved_snapshot),
                            "sha256": result["artifact_sha256"],
                        },
                        "parent_evidence_id": result["evidence_id"],
                        "parent_digest": result["parent_digest"],
                        "summary": {"statistics": {"findings": 0}},
                        "coverage": {
                            "status": "complete-within-view",
                            "exhausted": True,
                            "examined": 1,
                            "total": 1,
                        },
                    },
                }
                raw_path.write_text(json.dumps({"summary": raw_summary}) + "\n")
                result["report_sha256"] = hashlib.sha256(
                    raw_path.read_bytes()
                ).hexdigest()
                side_results[side] = result
                rea_refs.extend(
                    [
                        {
                            "path": str(raw_path),
                            "sha256": result["report_sha256"],
                            "kind": f"rea-{side}-report",
                        },
                        {
                            "path": str(bundle_path),
                            "sha256": result["evidence_bundle_sha256"],
                            "kind": f"rea-{side}-bundle",
                        },
                    ]
                )
            rea_comparison = {
                "schema_version": "1.0",
                "record_type": "rea_comparison",
                "status": "measured",
                "finding_delta": 0,
                "before_tree_sha256": snapshot_identity["before_tree_sha256"],
                "after_tree_sha256": snapshot_identity["after_tree_sha256"],
                "file_scope_sha256": snapshot_identity["file_scope_sha256"],
                "runtime_manifest_sha256": runtime_hash,
                "interpretation": "Static finding counts are measurements, not proof of protection or behavior preservation.",
                **side_results,
            }
            rea_ref = save("rea-comparison.json", rea_comparison)
            rea_refs.append({**rea_ref, "kind": "rea-comparison"})
        verify_ref = {**verify_ref, "kind": "bla-verify"}
        perf_ref = {**perf_ref, "kind": "performance"}
        execution_record = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "execution",
            "id": f"{run_id}-execution",
            "run_id": run_id,
            "plan_sha256": workflow.record_hash(plan),
            "action_id": action["id"],
            "commands": [["/fixture/bla", "protect"], ["/fixture/bla", "verify"]],
            "exit_code": 0,
            "outputs": [{"path": str(candidate), "sha256": artifact_hash}],
            "engine": {
                "name": "bla-agents",
                "version": engine_version,
                "package_tree_sha256": runtime_hash,
            },
            "source_sha256": source_hash,
            "evidence": [{**protect_ref, "kind": "bla-protect"}, verify_ref, perf_ref]
            + performance_candidate_refs
            + behavior_refs
            + rea_refs,
            "performance": performance,
        }
        if rea_comparison is not None:
            execution_record["rea_comparison"] = {
                **execution_record.get("rea_comparison", {}),
                "snapshot_root": str(snapshot_root),
                "before_snapshot": str(before_snapshot),
                "after_snapshot": str(after_snapshot),
                **snapshot_identity,
                "runtime_manifest_sha256": runtime_hash,
            }
        elif include_behavior:
            execution_record["rea_comparison"] = {
                "before_snapshot": str(before_snapshot),
                "after_snapshot": str(after_snapshot),
            }
        verification = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "verification",
            "id": f"{run_id}-verification",
            "run_id": run_id,
            "checks": [
                {"id": "bla_invariants", "status": "passed", "evidence": [verify_ref]},
                {"id": "performance", "status": "passed", "evidence": [perf_ref]},
            ]
            + (
                [
                    {
                        "id": "rea_comparison",
                        "status": "passed",
                        "evidence": [rea_refs[-1]],
                    }
                ]
                if include_rea
                else []
            )
            + (
                [
                    {
                        "id": "application_behavior",
                        "status": "passed",
                        "evidence": behavior_refs,
                    }
                ]
                if include_behavior
                else []
            ),
        }
        workflow.write_record(records, execution_record)
        workflow.write_record(records, verification)
        run = workflow.transition_run(
            changed,
            "verifying",
            execution_id=execution_record["id"],
            verification_id=verification["id"],
        )
        workflow.write_run_state(run_path.parent, run, changed)
        acceptance = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "acceptance",
            "id": f"{run_id}-acceptance",
            "run_id": run_id,
            "outcome": "accepted",
            "claims": [],
            "claim_ids": workflow.acceptance_claim_ids(
                [
                    item["id"]
                    for item in verification["checks"]
                    if item["status"] == "passed"
                ]
            ),
            "reasons": ["accepted fixture evidence"],
            "verification_id": verification["id"],
            "execution_id": execution_record["id"],
            "plan_sha256": workflow.record_hash(plan),
        }
        workflow.write_record(records, acceptance)
        try:
            workflow.accept_run(
                run,
                target,
                captured,
                plan,
                decision,
                execution_record,
                verification,
                acceptance,
            )
        except workflow.WorkflowError as error:
            raise AssertionError(str(error)) from error
        accepted, _ = workflow.finalize_run(
            run,
            target,
            captured,
            plan,
            decision,
            execution_record,
            verification,
            acceptance,
        )
        if accepted.get("state") != "completed":
            raise AssertionError(accepted)
        workflow.write_run_state(run_path.parent, accepted, run)
        return store, accepted, context

    def test_accepted_runs_are_revalidated_and_measurements_are_derived(self):
        store, accepted, _ = self.accepted_bla_run("candidate-one", b"protected-one")
        result = optimizer.review_accepted_runs(store, [accepted["id"]], self.budgets)
        candidate = result["pareto_frontier"][0]
        self.assertEqual(
            result["provenance_status"], "accepted_workflow_evidence_revalidated"
        )
        self.assertEqual(candidate["candidate_id"], accepted["id"])
        self.assertEqual(candidate["elapsed_ms"], 115)
        self.assertEqual(candidate["candidate_bytes"], len(b"protected-one"))
        self.assertEqual(
            candidate["elapsed_trials_ms"], {"min": 100, "median": 115, "max": 125}
        )

    def test_accepted_report_replays_after_candidate_rollback(self):
        store, accepted, _ = self.accepted_bla_run(
            "rollback-report", b"protected-report"
        )
        execution.discard_candidate(store, accepted["id"])
        report = workflow.assemble_run_report(store / "records", accepted)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(len(report["rollbacks"]), 1)
        retained = Path(report["rollbacks"][0]["artifacts"][0]["retained_path"])
        retained.write_bytes(b"tampered")
        with self.assertRaisesRegex(workflow.WorkflowError, "hash mismatch"):
            workflow.assemble_run_report(store / "records", accepted)

    def test_performance_gate_rejects_forged_source_and_retained_candidate_sizes(self):
        store, accepted, context = self.accepted_bla_run(
            "size-proof", b"protected-size-proof"
        )
        _store, captured, _target, plan, _action, _decision = context
        execution_path = (
            store / "records" / f"execution-{accepted['execution_id']}.json"
        )
        executed = workflow.read_record(execution_path, "execution")
        report_ref = next(
            item for item in executed["evidence"] if item.get("kind") == "performance"
        )
        original = json.loads(Path(report_ref["path"]).read_bytes())

        def reject_forged_report(report, message):
            raw = workflow.canonical(report) + b"\n"
            reference = {**report_ref, "sha256": hashlib.sha256(raw).hexdigest()}
            forged_execution = {
                **executed,
                "performance": report,
                "evidence": [
                    {**item, "sha256": reference["sha256"]}
                    if item.get("kind") == "performance"
                    else item
                    for item in executed["evidence"]
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, message):
                workflow._verify_performance_check(
                    plan, captured, forged_execution, [raw], [reference]
                )

        forged_source = json.loads(json.dumps(original))
        forged_source["source_bytes"] += 1
        forged_source["summary"]["candidate_growth_bytes_min"] -= 1
        forged_source["summary"]["candidate_growth_bytes_max"] -= 1
        reject_forged_report(forged_source, "source size or identity")

        for index in (0, 2):
            with self.subTest(trial=index):
                forged_candidate = json.loads(json.dumps(original))
                forged_candidate["trials"][index]["candidate_bytes"] += 1
                sizes = [item["candidate_bytes"] for item in forged_candidate["trials"]]
                source_size = forged_candidate["source_bytes"]
                forged_candidate["summary"].update(
                    candidate_bytes_min=min(sizes),
                    candidate_bytes_max=max(sizes),
                    candidate_bytes_mean=sum(sizes) / len(sizes),
                    candidate_growth_bytes_min=min(sizes) - source_size,
                    candidate_growth_bytes_max=max(sizes) - source_size,
                )
                reject_forged_report(
                    forged_candidate, "size or hash does not match retained bytes"
                )

    def test_optimizer_rejects_accepted_run_without_comparable_behavior_check(self):
        store, accepted, _ = self.accepted_bla_run(
            "missing-behavior", b"protected", include_behavior=False
        )
        with self.assertRaisesRegex(
            workflow.WorkflowError, "comparable application_behavior or e2e_behavior"
        ):
            optimizer.review_accepted_runs(store, [accepted["id"]], self.budgets)

    def test_optimizer_rejects_accepted_run_without_rea_comparison(self):
        store, accepted, _ = self.accepted_bla_run(
            "missing-rea", b"protected", include_rea=False
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "passing rea_comparison"):
            optimizer.review_accepted_runs(store, [accepted["id"]], self.budgets)

    def test_review_rejects_forged_terminal_run_and_tampered_performance_report(self):
        store, accepted, _ = self.accepted_bla_run("candidate-two", b"protected-two")
        run_path = store / "runs" / f"run-{accepted['id']}.json"
        run_path.write_text(
            json.dumps({**accepted, "acceptance_id": "forged-acceptance"})
        )
        with self.assertRaises(workflow.WorkflowError):
            optimizer.review_accepted_runs(store, [accepted["id"]], self.budgets)

        store, accepted, _ = self.accepted_bla_run(
            "candidate-three", b"protected-three"
        )
        performance_path = next(
            (store / "evidence").glob("candidate-three-performance.json")
        )
        performance_path.write_text(performance_path.read_text() + " ")
        with self.assertRaises(workflow.WorkflowError):
            optimizer.review_accepted_runs(store, [accepted["id"]], self.budgets)

    def test_accepted_confirmation_requires_distinct_run_and_identical_output(self):
        store, first, context = self.accepted_bla_run("confirm-first", b"same-output")
        _, second, _ = self.accepted_bla_run("confirm-second", b"same-output", context)
        result = optimizer.confirm_accepted_reevaluation(
            store, first["id"], second["id"], self.budgets
        )
        self.assertEqual(result["status"], "independently_reevaluated")
        _, different, _ = self.accepted_bla_run(
            "confirm-different", b"different-output", context
        )
        with self.assertRaisesRegex(
            workflow.WorkflowError, "reproduce identical bytes"
        ):
            optimizer.confirm_accepted_reevaluation(
                store, first["id"], different["id"], self.budgets
            )

    def test_cli_accepted_run_review_emits_bound_candidates(self):
        store, accepted, _ = self.accepted_bla_run("cli-candidate", b"cli-output")
        budget_path = self.root / "budgets.json"
        budget_path.write_text(json.dumps(self.budgets))
        output = StringIO()
        with redirect_stdout(output):
            status = anti_rea.main(
                [
                    "optimize-review-accepted",
                    str(store),
                    str(budget_path),
                    "--run-id",
                    accepted["id"],
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(output.getvalue())["pareto_frontier"][0]["run_id"],
            accepted["id"],
        )

    def test_accepted_run_list_preserves_approval_order_and_rejects_bad_search_sets(
        self,
    ):
        store, first, context = self.accepted_bla_run("ordered-first", b"first")
        _, second, _ = self.accepted_bla_run("ordered-second", b"second", context)
        result = optimizer.review_accepted_runs(
            store, [second["id"], first["id"]], self.budgets
        )
        self.assertEqual(result["approved_candidate_ids"], [second["id"], first["id"]])
        for run_ids, pattern in (
            ([first["id"], first["id"]], "unique approved candidate run ids"),
            ([first["id"]] * 5, "unique approved candidate run ids"),
        ):
            with (
                self.subTest(run_ids=run_ids),
                self.assertRaisesRegex(workflow.WorkflowError, pattern),
            ):
                optimizer.review_accepted_runs(store, run_ids, self.budgets)

    def test_optimizer_rejects_mixed_target_action_or_runtime_identity(self):
        store, _, context = self.accepted_bla_run("identity-first", b"first")
        _, other_action, _ = self.accepted_bla_run(
            "identity-action", b"same", action_id="bla-js-other"
        )
        with self.assertRaisesRegex(
            workflow.WorkflowError, "same selected action identity"
        ):
            optimizer.review_accepted_runs(
                store, ["identity-first", other_action["id"]], self.budgets
            )

        other_project = self.root / "other-project"
        other_project.mkdir()
        (other_project / "build.py").write_text((self.project / "build.py").read_text())
        _, other_target, _ = self.accepted_bla_run(
            "identity-target", b"same", project=other_project
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "same target identity"):
            optimizer.review_accepted_runs(
                store, ["identity-first", other_target["id"]], self.budgets
            )

        _, other_runtime, _ = self.accepted_bla_run(
            "identity-runtime", b"same", context, runtime_hash="c" * 64
        )
        with self.assertRaisesRegex(
            workflow.WorkflowError, "source and runtime identities"
        ):
            optimizer.review_accepted_runs(
                store, ["identity-first", other_runtime["id"]], self.budgets
            )

    def test_incomplete_run_is_not_an_optimizer_candidate(self):
        store, accepted, _ = self.accepted_bla_run("incomplete-run", b"candidate")
        run_path = store / "runs" / f"run-{accepted['id']}.json"
        for incomplete in (
            {
                key: value
                for key, value in accepted.items()
                if key not in {"acceptance", "acceptance_id"}
            }
            | {"state": "failed"},
            {**accepted, "state": "blocked", "acceptance": "rejected"},
        ):
            with self.subTest(state=incomplete["state"]):
                run_path.write_text(json.dumps(incomplete))
                with self.assertRaisesRegex(workflow.WorkflowError, "not accepted"):
                    optimizer.review_accepted_runs(
                        store, [accepted["id"]], self.budgets
                    )


if __name__ == "__main__":
    unittest.main()
