"""Plan-bound execution for supported private candidate adapters."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core import baseline as baseline_capture
from core import discovery, workflow


def validate_approved_candidate_set(
    store: str | Path, search_id: str, candidate_id: str
) -> dict:
    """Load and preflight one approved BLA candidate set before creating its run."""
    root = workflow._private_directory(store).resolve(strict=True)
    records = root / "records"
    search = workflow.read_record(
        records
        / f"optimization_search-{workflow._reference_id(search_id, 'optimization search id')}.json",
        "optimization_search",
    )
    plan = workflow.read_record(records / f"plan-{search['plan_id']}.json", "plan")
    baseline = workflow.read_record(
        records / f"baseline-{search['baseline_id']}.json", "baseline"
    )
    target = workflow.read_record(
        records / f"target-{search['target_id']}.json", "target"
    )
    baseline = workflow.validate_baseline_target(baseline, target)
    search = workflow.validate_optimization_search(search, plan, baseline)
    candidate = next(
        (item for item in search["candidate_sets"] if item["id"] == candidate_id), None
    )
    if candidate is None:
        raise workflow.WorkflowError(
            "Optimization candidate is not in the approved search"
        )
    if len(candidate["action_ids"]) == 1:
        action = next(
            (
                item
                for item in plan["actions"]
                if item["id"] == candidate["action_ids"][0]
            ),
            None,
        )
        config = action.get("execution") if isinstance(action, dict) else None
        source_path = config.get("source_path") if isinstance(config, dict) else None
        if (
            not action
            or action.get("engine") != "bla"
            or config.get("adapter") != "bla-js"
            or not isinstance(source_path, str)
            or Path(source_path).is_absolute()
            or not Path(source_path).parts
            or ".." in Path(source_path).parts
            or Path(source_path).suffix.lower() not in {".js", ".mjs", ".cjs"}
        ):
            raise workflow.WorkflowError(
                "Approved candidate set is not a safe BLA JavaScript action"
            )
        actions = [action]
    else:
        actions = workflow._validate_composite_actions(plan, candidate["action_ids"])
    artifacts = baseline.get("identity", {}).get("artifacts", {})
    for action in actions:
        config = action["execution"]
        path = config["source_path"]
        identity = artifacts.get(path)
        expected = {
            item.get("path"): item.get("sha256")
            for item in action.get("evidence", [])
            if isinstance(item, dict)
        }
        if not isinstance(identity, dict) or expected.get(path) != identity.get(
            "sha256"
        ):
            raise workflow.WorkflowError(
                "Composite BLA action source must match its saved baseline artifact"
            )
    if "bla-agents" not in search["runtime_identities"]:
        raise workflow.WorkflowError(
            "Approved composite search has no pinned BLA runtime identity"
        )
    if "application_behavior" in actions[0]["verification"]:
        behavior = baseline.get("identity", {}).get("behavior")
        if (
            not isinstance(behavior, dict)
            or behavior.get("artifact") != actions[0]["execution"]["source_path"]
        ):
            raise workflow.WorkflowError(
                "Composite behavior check must use the first selected baseline artifact"
            )
    if "rea_comparison" in actions[0]["verification"] and not baseline.get(
        "identity", {}
    ).get("rea_analysis"):
        raise workflow.WorkflowError(
            "Composite REA comparison requires a captured compatible baseline analysis"
        )
    if "e2e_behavior" in actions[0]["verification"]:
        baseline_e2e = baseline.get("identity", {}).get("e2e_behavior")
        if (
            not isinstance(baseline_e2e, dict)
            or baseline_e2e.get("source_path") != actions[0]["execution"]["source_path"]
        ):
            raise workflow.WorkflowError(
                "Composite e2e verification must match the captured baseline artifact"
            )
    _verify_build_snapshot(baseline)
    return {
        "search": search,
        "plan": plan,
        "baseline": baseline,
        "candidate": candidate,
        "actions": actions,
    }


def execute_bla_action(
    store: str | Path,
    run_id: str,
    action_id: str,
    runtime: str | Path | None,
    cancel_event=None,
    on_process=None,
    rea_runtime: str | Path | None = None,
    e2e_runtime: str | Path | None = None,
    optimization_search: dict | None = None,
    craft_anything_cli: str | Path | None = None,
) -> dict:
    root = workflow._private_directory(store).resolve(strict=True)
    records = root / "records"
    run_path = root / "runs" / f"run-{workflow._reference_id(run_id, 'run id')}.json"
    run = workflow.validate_run(workflow.read_json(run_path))
    if run["state"] != "preparing":
        raise workflow.WorkflowError("BLA execution requires a preparing run")
    target = workflow.read_record(records / f"target-{run['target_id']}.json", "target")
    source_root = target.get("source_root")
    if not isinstance(source_root, str) or not source_root:
        raise workflow.WorkflowError("BLA target must include a discovered source root")
    target_root = Path(source_root).resolve(strict=True)
    if (
        root == target_root
        or root in target_root.parents
        or target_root in root.parents
    ):
        raise workflow.WorkflowError(
            "Anti-REA state and target must be separate directory trees"
        )
    baseline = workflow.read_record(
        records / f"baseline-{run['baseline_id']}.json", "baseline"
    )
    plan = workflow.validate_plan(
        workflow.read_record(records / f"plan-{run['plan_id']}.json", "plan")
    )
    decision = workflow.read_record(
        records / f"decision-{run['decision_id']}.json", "decision"
    )
    if decision.get("optimization_search_id"):
        if optimization_search is None:
            optimization_search = workflow.read_record(
                records
                / f"optimization_search-{decision['optimization_search_id']}.json",
                "optimization_search",
            )
        optimization_search = workflow.validate_optimization_search(
            optimization_search, plan, baseline
        )
    decision = workflow.validate_decision(decision, plan, optimization_search)
    if decision["decision"] != "approved" or decision[
        "plan_sha256"
    ] != workflow.record_hash(plan):
        raise workflow.WorkflowError(
            "BLA execution requires approval of the exact persisted plan"
        )
    if len(decision["selected_action_ids"]) > 1:
        if action_id not in decision["selected_action_ids"]:
            raise workflow.WorkflowError(
                "BLA action was not selected by the recorded decision"
            )
        return execute_selected_composite(
            store,
            run_id,
            runtime,
            rea_runtime,
            e2e_runtime,
            cancel_event,
            on_process,
            craft_anything_cli,
        )
    if action_id not in decision["selected_action_ids"]:
        raise workflow.WorkflowError(
            "BLA action was not selected by the recorded decision"
        )
    action = next((item for item in plan["actions"] if item["id"] == action_id), None)
    config = action.get("execution") if action else None
    if (
        action
        and isinstance(config, dict)
        and config.get("adapter") == "source-map-candidate"
    ):
        return _execute_source_map_candidate(
            root,
            records,
            run_path,
            run,
            target,
            target_root,
            baseline,
            plan,
            action,
            config,
            cancel_event,
        )
    if (
        action
        and isinstance(config, dict)
        and config.get("adapter") == "flutter-dart-obfuscation"
    ):
        return _execute_flutter_obfuscation(
            root,
            records,
            run_path,
            run,
            target,
            target_root,
            baseline,
            plan,
            action,
            config,
            cancel_event,
            on_process,
        )
    if (
        not action
        or action.get("engine") != "bla"
        or not isinstance(config, dict)
        or config.get("adapter") != "bla-js"
    ):
        raise workflow.WorkflowError(
            "Selected action is not a supported BLA JavaScript operation"
        )
    if not runtime:
        raise workflow.WorkflowError("BLA execution requires a pinned runtime")
    baseline = workflow.validate_baseline_target(baseline, target)
    if "rea_comparison" in action["verification"]:
        rea_runtime = rea_runtime or os.environ.get("ANTI_REA_REA_RUNTIME")
        if not rea_runtime:
            raise workflow.WorkflowError(
                "REA comparison is required; pass rea_runtime or set ANTI_REA_REA_RUNTIME"
            )
    if "e2e_behavior" in action["verification"]:
        baseline_e2e = baseline.get("identity", {}).get("e2e_behavior")
        e2e_runtime = (
            e2e_runtime
            or os.environ.get("ANTI_REA_E2E_RUNTIME")
            or (
                baseline_e2e.get("runtime_path")
                if isinstance(baseline_e2e, dict)
                else None
            )
        )
        if not e2e_runtime:
            raise workflow.WorkflowError(
                "e2e behavior requires a runtime captured by the baseline"
            )

    source_relative = config.get("source_path")
    expected = {
        item.get("path"): item.get("sha256")
        for item in action.get("evidence", [])
        if isinstance(item, dict)
    }
    expected_hash = expected.get(source_relative)
    artifact_identity = (
        baseline.get("identity", {}).get("artifacts", {}).get(source_relative)
    )
    if (
        not isinstance(source_relative, str)
        or not isinstance(expected_hash, str)
        or not isinstance(artifact_identity, dict)
        or artifact_identity.get("sha256") != expected_hash
    ):
        raise workflow.WorkflowError(
            "BLA source must be an evidence-linked artifact in the selected baseline"
        )
    build_snapshot = baseline["identity"].get("build_snapshot")
    if not isinstance(build_snapshot, dict):
        raise workflow.WorkflowError(
            "BLA execution requires a fresh baseline with a private build snapshot"
        )
    source_root = Path(build_snapshot["path"])
    _verify_build_snapshot(baseline)
    _verify_live_project_inputs(target, target_root)
    source_hash = baseline_capture._hash_artifact(source_root, source_relative)[
        "sha256"
    ]
    if source_hash != expected_hash:
        raise workflow.WorkflowError("BLA source changed after baseline capture")
    source = source_root / source_relative
    if source.suffix.lower() not in {".js", ".mjs", ".cjs"}:
        raise workflow.WorkflowError(
            "BLA adapter supports only JavaScript source artifacts"
        )
    intensity = config.get("intensity", "balanced")
    if intensity not in {"stealth", "balanced", "maximum", "bankrupt"}:
        raise workflow.WorkflowError("Invalid BLA intensity in selected plan")
    performance_budget = (
        workflow.validate_performance_budget(config.get("performance_budget"))
        if "performance" in action["verification"]
        else None
    )

    runtime_path = Path(runtime).expanduser()
    if runtime_path.is_symlink():
        raise workflow.WorkflowError("BLA runtime symlink refused")
    runtime = runtime_path.resolve(strict=True)
    if optimization_search is not None:
        from core.optimizer import _search_runtime_identity

        approved_runtime = optimization_search.get("runtime_identities", {}).get(
            "bla-agents"
        )
        if (
            approved_runtime is not None
            and _search_runtime_identity(runtime, "bla-agents") != approved_runtime
        ):
            raise workflow.WorkflowError(
                "BLA runtime differs from the approved optimization search"
            )
    if (
        runtime == target_root
        or runtime in target_root.parents
        or target_root in runtime.parents
        or runtime == root
        or runtime in root.parents
        or root in runtime.parents
        or runtime == source_root
        or runtime in source_root.parents
        or source_root in runtime.parents
    ):
        raise workflow.WorkflowError(
            "BLA runtime, Anti-REA state, and target must be separate directory trees"
        )
    rea_runtime_path = None
    if rea_runtime:
        lexical_rea_runtime = Path(rea_runtime).expanduser()
        if lexical_rea_runtime.is_symlink():
            raise workflow.WorkflowError("REA runtime symlink refused")
        rea_runtime_path = lexical_rea_runtime.resolve(strict=True)
        if optimization_search is not None:
            from core.optimizer import _search_runtime_identity

            approved_runtime = optimization_search.get("runtime_identities", {}).get(
                "rea"
            )
            if (
                approved_runtime is not None
                and _search_runtime_identity(rea_runtime_path, "rea")
                != approved_runtime
            ):
                raise workflow.WorkflowError(
                    "REA runtime differs from the approved optimization search"
                )
        if any(
            path == rea_runtime_path
            or path in rea_runtime_path.parents
            or rea_runtime_path in path.parents
            for path in (target_root, root, runtime, source_root)
        ):
            raise workflow.WorkflowError(
                "REA runtime must be separate from BLA runtime, state, and target"
            )
    e2e_runtime_path = None
    if e2e_runtime:
        lexical_e2e_runtime = Path(e2e_runtime).expanduser()
        if lexical_e2e_runtime.is_symlink():
            raise workflow.WorkflowError("e2e runtime symlink refused")
        e2e_runtime_path = lexical_e2e_runtime.resolve(strict=True)
        if optimization_search is not None:
            from core.optimizer import _search_runtime_identity

            approved_runtime = optimization_search.get("runtime_identities", {}).get(
                "e2e"
            )
            if (
                approved_runtime is not None
                and _search_runtime_identity(e2e_runtime_path, "e2e")
                != approved_runtime
            ):
                raise workflow.WorkflowError(
                    "e2e runtime differs from the approved optimization search"
                )
        if any(
            path == e2e_runtime_path
            or path in e2e_runtime_path.parents
            or e2e_runtime_path in path.parents
            for path in (target_root, root, runtime, rea_runtime_path, source_root)
            if path is not None
        ):
            raise workflow.WorkflowError(
                "e2e runtime must be separate from BLA/REA runtimes, state, and target"
            )
        baseline_e2e = baseline.get("identity", {}).get("e2e_behavior")
        if "e2e_behavior" in action["verification"] and (
            not isinstance(baseline_e2e, dict)
            or e2e_runtime_path
            != Path(baseline_e2e["runtime_path"]).resolve(strict=True)
            or config.get("e2e_runtime_manifest_sha256")
            != baseline_e2e["runtime_manifest_sha256"]
        ):
            raise workflow.WorkflowError(
                "e2e runtime identity differs from the baseline capture"
            )
    adapter = _bla_script()
    candidates = workflow._private_directory(root / "candidates")
    evidence_dir = workflow._private_directory(root / "evidence")
    stem = hashlib.sha256(f"{run_id}:{action_id}".encode()).hexdigest()[:32]
    candidate = candidates / f"{stem}{source.suffix.lower()}"
    protect_report = evidence_dir / f"{stem}-protect.json"
    verify_report = evidence_dir / f"{stem}-verify.json"
    performance_path = evidence_dir / f"{stem}-performance.json"
    if any(
        path.exists() or path.is_symlink()
        for path in (candidate, protect_report, verify_report)
    ):
        raise workflow.WorkflowError("BLA candidate or evidence path already exists")

    executing = workflow.transition_run(run, "executing")
    workflow.write_run_state(run_path.parent, executing, run)
    performance_candidate_paths = []
    try:
        probe = _invoke(adapter, ["probe", str(runtime)], 60, cancel_event, on_process)
        manifest = probe
        protected = _invoke(
            adapter,
            [
                "protect-js",
                str(runtime),
                str(source),
                str(candidate),
                str(protect_report),
                "--intensity",
                intensity,
                "--seed",
                run_id,
            ],
            960,
            cancel_event,
            on_process,
        )
        verified = _invoke(
            adapter,
            [
                "verify-js",
                str(runtime),
                str(source),
                str(candidate),
                str(verify_report),
            ],
            360,
            cancel_event,
            on_process,
        )
        if (
            protected["source_sha256"] != expected_hash
            or verified["source_sha256"] != expected_hash
        ):
            raise workflow.WorkflowError("BLA source identity changed during execution")
        if protected["candidate_sha256"] != verified["candidate_sha256"]:
            raise workflow.WorkflowError("BLA verification candidate identity mismatch")
        performance_ref = None
        performance = None
        performance_candidate_refs = []
        if performance_budget:
            source_bytes = source.stat().st_size
            first_ref = {
                "path": str(candidate.resolve(strict=True)),
                "sha256": protected["candidate_sha256"],
                "kind": "performance-candidate",
            }
            performance_candidate_refs.append(first_ref)
            trials = [
                {
                    "elapsed_ms": protected["elapsed_ms"],
                    "candidate_bytes": protected["candidate_bytes"],
                    "source_sha256": protected["source_sha256"],
                    "candidate_sha256": protected["candidate_sha256"],
                    "candidate_artifact": first_ref,
                }
            ]
            for index in range(1, performance_budget["trials"]):
                trial_candidate = (
                    candidates / f"{stem}-trial-{index}{source.suffix.lower()}"
                )
                trial_report = evidence_dir / f"{stem}-trial-{index}.json"
                try:
                    trial = _invoke(
                        adapter,
                        [
                            "protect-js",
                            str(runtime),
                            str(source),
                            str(trial_candidate),
                            str(trial_report),
                            "--intensity",
                            intensity,
                            "--seed",
                            f"{run_id}-{index}",
                        ],
                        960,
                        cancel_event,
                        on_process,
                    )
                    artifact_ref = _retain_performance_trial(
                        trial_candidate,
                        evidence_dir,
                        performance_path.stem,
                        index,
                        trial["candidate_sha256"],
                        trial["candidate_bytes"],
                    )
                    performance_candidate_paths.append(Path(artifact_ref["path"]))
                    performance_candidate_refs.append(artifact_ref)
                    trials.append(
                        {
                            "elapsed_ms": trial["elapsed_ms"],
                            "candidate_bytes": trial["candidate_bytes"],
                            "source_sha256": trial["source_sha256"],
                            "candidate_sha256": trial["candidate_sha256"],
                            "candidate_artifact": artifact_ref,
                        }
                    )
                finally:
                    _remove_output(trial_candidate)
            performance = {
                "schema_version": "1.0",
                "run_id": run_id,
                "action_id": action_id,
                "plan_sha256": workflow.record_hash(plan),
                "source_sha256": expected_hash,
                "runtime_manifest_sha256": manifest["package_tree_sha256"],
                "source_bytes": source_bytes,
                "budget": performance_budget,
                "trials": trials,
                "summary": {
                    "elapsed_ms_min": min(t["elapsed_ms"] for t in trials),
                    "elapsed_ms_max": max(t["elapsed_ms"] for t in trials),
                    "elapsed_ms_mean": sum(t["elapsed_ms"] for t in trials)
                    / len(trials),
                    "candidate_bytes_min": min(t["candidate_bytes"] for t in trials),
                    "candidate_bytes_max": max(t["candidate_bytes"] for t in trials),
                    "candidate_bytes_mean": sum(t["candidate_bytes"] for t in trials)
                    / len(trials),
                    "candidate_growth_bytes_min": min(
                        t["candidate_bytes"] for t in trials
                    )
                    - source_bytes,
                    "candidate_growth_bytes_max": max(
                        t["candidate_bytes"] for t in trials
                    )
                    - source_bytes,
                },
                "passed": all(
                    t["elapsed_ms"] <= performance_budget["max_elapsed_ms"]
                    and t["candidate_bytes"]
                    <= performance_budget["max_candidate_bytes"]
                    for t in trials
                ),
            }
        package_hash = manifest["package_tree_sha256"]
        protect_raw = workflow.read_json(protect_report)
        verify_raw = workflow.read_json(verify_report)
        commands = [protect_raw["command"], verify_raw["command"]]
        if performance_budget:
            commands.extend(
                [
                    [
                        "performance-trial",
                        str(runtime),
                        str(source),
                        intensity,
                        f"{run_id}-{index}",
                    ]
                    for index in range(1, performance_budget["trials"])
                ]
            )
        behavior_command = config.get("behavior_command")
        analysis_policy = plan.get(
            "analysis_policy",
            {"engines": ["rea"], "acceptance_gates": ["rea"]},
        )
        selected_analysis_engines = analysis_policy.get("engines", [])
        craft_selected = "craft-anything" in selected_analysis_engines
        craft_cli = craft_anything_cli or os.environ.get("ANTI_REA_CRAFT_ANYTHING_CLI")
        behavior_evidence = None
        behavior_result = None
        snapshot_identity = None
        before_snapshot = after_snapshot = None
        if (
            {"rea_comparison", "e2e_behavior", "application_behavior"}
            & set(action["verification"])
            or behavior_command is not None
            or "rea" in selected_analysis_engines
            or craft_selected
        ):
            snapshots = workflow._private_directory(root / "behavior-snapshots")
            snapshot_root = snapshots / stem
            if snapshot_root.exists() or snapshot_root.is_symlink():
                raise workflow.WorkflowError(
                    "Verification snapshot path already exists"
                )
            snapshot_root.mkdir(mode=0o700)
            before_snapshot, after_snapshot = (
                snapshot_root / "before",
                snapshot_root / "after",
            )
            snapshot_identity = _create_rea_snapshots(
                target_root,
                target,
                baseline,
                source_relative,
                candidate,
                verified["candidate_sha256"],
                expected_hash,
                before_snapshot,
                after_snapshot,
                cancel_event,
            )
        if behavior_command is not None:
            if (
                not isinstance(behavior_command, list)
                or not behavior_command
                or any(not isinstance(arg, str) or not arg for arg in behavior_command)
                or behavior_command.count("{artifact}") != 1
            ):
                raise workflow.WorkflowError(
                    "Invalid behavior command in selected plan"
                )
            captured_behavior = baseline["identity"].get("behavior")
            if (
                not isinstance(captured_behavior, dict)
                or captured_behavior.get("command") != behavior_command
                or captured_behavior.get("artifact") != source_relative
                or captured_behavior.get("artifact_sha256") != expected_hash
                or not isinstance(captured_behavior.get("snapshot_path"), str)
            ):
                raise workflow.WorkflowError(
                    "Selected behavior command or artifact differs from baseline evidence"
                )
            baseline_ref = {
                "path": captured_behavior["evidence_path"],
                "sha256": captured_behavior["evidence_sha256"],
                "kind": "behavior-baseline",
            }
            baseline_raw = workflow.verify_evidence_file(baseline_ref)
            try:
                baseline_report = json.loads(baseline_raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise workflow.WorkflowError(
                    "Baseline behavior evidence is invalid JSON"
                ) from error
            baseline_argv = [
                str(Path(captured_behavior["snapshot_path"]) / source_relative)
                if arg == "{artifact}"
                else arg
                for arg in behavior_command
            ]
            if (
                baseline_report.get("argv") != baseline_argv
                or baseline_report.get("exit_code") != 0
                or baseline_report.get("timed_out")
                or baseline_report.get("stdout_truncated")
                or baseline_report.get("stderr_truncated")
                or not isinstance(baseline_report.get("stdout"), str)
            ):
                raise workflow.WorkflowError(
                    "Baseline behavior evidence does not prove a successful source run"
                )
            behavior_runs = [
                {
                    "stdout": baseline_report["stdout"],
                    "timed_out": False,
                    "truncated": False,
                    "path": baseline_ref["path"],
                    "sha256": baseline_ref["sha256"],
                    "kind": baseline_ref["kind"],
                }
            ]
            for label, snapshot, artifact in (
                ("source", before_snapshot, before_snapshot / source_relative),
                ("candidate", after_snapshot, after_snapshot / source_relative),
            ):
                argv = [
                    str(artifact) if arg == "{artifact}" else arg
                    for arg in behavior_command
                ]
                code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
                    baseline_capture._run_command(
                        argv, snapshot, 120, on_process, cancel_event
                    )
                )
                result_path = evidence_dir / f"{stem}-behavior-{label}.json"
                baseline_capture._write_output(
                    result_path,
                    argv,
                    code,
                    stdout,
                    stderr,
                    time.time(),
                    timed_out,
                    stdout_truncated,
                    stderr_truncated,
                )
                behavior_runs.append(
                    {
                        "exit_code": code,
                        "stdout": stdout.decode("utf-8", errors="replace"),
                        "timed_out": timed_out,
                        "truncated": stdout_truncated or stderr_truncated,
                        "path": str(result_path),
                        "sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
                        "kind": f"behavior-{label}",
                    }
                )
                if timed_out or code != 0 or stdout_truncated or stderr_truncated:
                    break
            behavior_result = (
                len(behavior_runs) == 3
                and len({item["stdout"] for item in behavior_runs}) == 1
                and all(
                    not run["timed_out"] and not run["truncated"]
                    for run in behavior_runs
                )
            )
            behavior_evidence = [
                {"path": run["path"], "sha256": run["sha256"], "kind": run["kind"]}
                for run in behavior_runs
            ]
            # behavior_runs includes the immutable BEFORE report, which was
            # captured during baseline creation and is not a subprocess here.
            started_behavior_runs = len(behavior_runs) - 1
            behavior_commands = [
                [
                    "behavior-check",
                    *[
                        str(before_snapshot / source_relative)
                        if arg == "{artifact}"
                        else arg
                        for arg in behavior_command
                    ],
                ],
                [
                    "behavior-check",
                    *[
                        str(after_snapshot / source_relative)
                        if arg == "{artifact}"
                        else arg
                        for arg in behavior_command
                    ],
                ],
            ]
            commands.extend(behavior_commands[:started_behavior_runs])
        e2e_behavior = None
        if "e2e_behavior" in action["verification"]:
            if (
                e2e_runtime_path is None
                or before_snapshot is None
                or after_snapshot is None
            ):
                raise workflow.WorkflowError(
                    "e2e behavior requires a verified runtime and paired snapshots"
                )
            baseline_e2e = baseline["identity"].get("e2e_behavior")
            if not isinstance(baseline_e2e, dict):
                raise workflow.WorkflowError(
                    "e2e behavior was not captured during baseline"
                )
            e2e_dir = workflow._private_directory(evidence_dir / f"{stem}-e2e")
            config_path = config.get("e2e_config", "e2e.config.mjs")
            test_path = config.get("e2e_test_file", "tests/behavior.e2e.ts")
            before_ref = {
                "path": baseline_e2e["report_path"],
                "sha256": baseline_e2e["report_sha256"],
                "kind": "e2e-before",
            }
            with tempfile.TemporaryDirectory(
                prefix="anti-rea-e2e-", dir=e2e_runtime_path
            ) as temporary:
                workspace = Path(temporary)
                project_copy = workspace / "after"
                shutil.copytree(after_snapshot, project_copy)
                after_result = _invoke_e2e(
                    _e2e_script(),
                    [
                        "run",
                        str(project_copy),
                        str(e2e_runtime_path),
                        ".anti-rea-e2e/after",
                        "--stage",
                        "after",
                        "--config",
                        config_path,
                        "--test-file",
                        test_path,
                    ],
                    360,
                    cancel_event,
                    on_process,
                )
                raw = workflow.verify_evidence_file(
                    {
                        "path": after_result["report"],
                        "sha256": after_result["report_sha256"],
                    }
                )
                report_path = e2e_dir / "after-report.json"
                _write_snapshot_file(report_path, raw)
                after_ref = {
                    "path": str(report_path),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "kind": "e2e-after",
                }
            e2e_behavior = {
                "before": before_ref,
                "after": after_ref,
                "before_snapshot": baseline_e2e["snapshot_path"],
                "after_snapshot": str(after_snapshot),
                "snapshot_identity": snapshot_identity,
                "runtime_path": str(e2e_runtime_path),
                "runtime_manifest_sha256": baseline_e2e["runtime_manifest_sha256"],
                "runner": baseline_e2e["runner"],
                "test_ids": baseline_e2e["test_ids"],
                "cleanup": {
                    "before": baseline_e2e["cleanup"],
                    "after": after_result["cleanup"],
                },
                "config": config_path,
                "test_file": test_path,
                "passed": (
                    after_result["status"] == "passed"
                    and baseline_e2e["runtime_manifest_sha256"]
                    == after_result["runtime_manifest_sha256"]
                    and baseline_e2e["test_ids"] == after_result["test_ids"]
                ),
            }
            commands.append(after_result["command"])
        if (
            performance
            and performance_budget.get("max_journey_regression_pct") is not None
            and "e2e_behavior" in action["verification"]
            and isinstance(
                baseline.get("identity", {})
                .get("e2e_behavior", {})
                .get("performance_metrics"),
                dict,
            )
        ):
            if (
                e2e_runtime_path is None
                or before_snapshot is None
                or after_snapshot is None
            ):
                raise workflow.WorkflowError(
                    "Browser performance measurement requires paired browser snapshots"
                )
            browser_trials = {"source": [], "candidate": []}
            adapter_module = _load_e2e_adapter(_e2e_script())
            for index in range(performance_budget["trials"]):
                paired_sides = (
                    ("source", before_snapshot),
                    ("candidate", after_snapshot),
                )
                if index % 2:
                    paired_sides = paired_sides[::-1]
                for side, snapshot in paired_sides:
                    with tempfile.TemporaryDirectory(
                        prefix="anti-rea-e2e-perf-", dir=e2e_runtime_path
                    ) as temporary:
                        project_copy = Path(temporary) / "project"
                        shutil.copytree(snapshot, project_copy)
                        result = _invoke_e2e(
                            _e2e_script(),
                            [
                                "run",
                                str(project_copy),
                                str(e2e_runtime_path),
                                f".anti-rea-e2e/performance-{side}-{index}",
                                "--stage",
                                "fixture",
                                "--config",
                                config.get(
                                    "e2e_config",
                                    baseline["identity"]["e2e_behavior"]["config"],
                                ),
                                "--test-file",
                                config.get(
                                    "e2e_test_file",
                                    baseline["identity"]["e2e_behavior"]["test_file"],
                                ),
                            ],
                            360,
                            cancel_event,
                            on_process,
                        )
                        raw = workflow.verify_evidence_file(
                            {
                                "path": result["report"],
                                "sha256": result["report_sha256"],
                            }
                        )
                        report = json.loads(raw)
                        metrics = adapter_module.report_performance_metrics(report)
                        if result["status"] != "passed" or not isinstance(
                            metrics, dict
                        ):
                            raise workflow.WorkflowError(
                                f"{side} browser performance trial {index + 1} lacks a passing metric"
                            )
                        report_path = (
                            evidence_dir / f"{stem}-browser-{side}-{index}.json"
                        )
                        _write_snapshot_file(report_path, raw)
                        browser_trials[side].append(
                            {
                                "metrics": metrics,
                                "evidence": {
                                    "path": str(report_path.resolve()),
                                    "sha256": hashlib.sha256(raw).hexdigest(),
                                    "kind": f"performance-{side}",
                                },
                            }
                        )
                        commands.append(result["command"])
            browser_summary = {}
            for key in ("dom_content_loaded_ms", "load_event_ms", "interaction_ms"):
                source_values = sorted(
                    item["metrics"][key] for item in browser_trials["source"]
                )
                candidate_values = sorted(
                    item["metrics"][key] for item in browser_trials["candidate"]
                )
                source_median, candidate_median = source_values[1], candidate_values[1]
                browser_summary[key] = {
                    "source_min": source_values[0],
                    "source_median": source_median,
                    "source_max": source_values[-1],
                    "candidate_min": candidate_values[0],
                    "candidate_median": candidate_median,
                    "candidate_max": candidate_values[-1],
                    "regression_percent": (
                        (candidate_median - source_median) / source_median * 100
                        if source_median > 0
                        else (0 if candidate_median <= 1 else 1000)
                    ),
                }
            performance["browser_journey"] = {
                "trials": browser_trials,
                "summary": browser_summary,
                "max_regression_percent": performance_budget[
                    "max_journey_regression_pct"
                ],
            }
            performance["passed"] = performance["passed"] and all(
                item["regression_percent"]
                <= performance_budget["max_journey_regression_pct"]
                for item in browser_summary.values()
            )
        if performance:
            performance_path.write_bytes(workflow.canonical(performance) + b"\n")
            performance_ref = {
                "path": str(performance_path.resolve()),
                "sha256": hashlib.sha256(performance_path.read_bytes()).hexdigest(),
                "kind": "performance",
            }
        performance_evidence = (
            [performance_ref]
            + [
                sample["evidence"]
                for side in ("source", "candidate")
                for sample in performance.get("browser_journey", {})
                .get("trials", {})
                .get(side, [])
            ]
            if performance_ref
            else []
        )
        rea_comparison = None
        craft_analysis = None
        craft_pool = ThreadPoolExecutor(max_workers=1) if craft_selected else None
        craft_future = (
            craft_pool.submit(
                _capture_craft_analysis_pair,
                before_snapshot,
                after_snapshot,
                state=root,
                evidence_dir=evidence_dir,
                stem=stem,
                cli=craft_cli,
                baseline=baseline,
                cancel_event=cancel_event,
                on_process=on_process,
            )
            if craft_pool is not None and before_snapshot and after_snapshot
            else None
        )
        rea_selected = "rea" in selected_analysis_engines
        rea_gate = "rea_comparison" in action["verification"]
        rea_analysis = None
        if rea_selected or rea_gate:
            rea_analysis, rea_comparison = _capture_rea_analysis_pair(
                rea_runtime_path,
                before_snapshot,
                after_snapshot,
                snapshot_identity,
                baseline,
                evidence_dir,
                stem,
                1200,
                cancel_event,
                on_process,
            )
            if rea_gate and rea_analysis["status"] != "passed":
                if craft_future:
                    craft_future.result()
                if craft_pool:
                    craft_pool.shutdown(wait=True, cancel_futures=True)
                raise workflow.WorkflowError(
                    rea_analysis.get("reason") or "REA comparison gate failed"
                )
            if rea_comparison:
                commands.append(
                    [
                        "rea-compare",
                        str(rea_runtime_path),
                        str(before_snapshot),
                        str(after_snapshot),
                    ]
                )
        if craft_future:
            craft_analysis = craft_future.result()
        if craft_pool:
            craft_pool.shutdown(wait=True, cancel_futures=True)
        execution_id = (
            "exec-" + hashlib.sha256(f"{run_id}:{action_id}".encode()).hexdigest()[:24]
        )
        verification_id = (
            "verify-"
            + hashlib.sha256(f"{run_id}:{action_id}".encode()).hexdigest()[:24]
        )
        outputs = [{"path": str(candidate), "sha256": verified["candidate_sha256"]}]
        execution = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "execution",
            "id": execution_id,
            "run_id": run_id,
            "plan_sha256": workflow.record_hash(plan),
            "action_id": action_id,
            "commands": commands,
            "exit_code": 0,
            "outputs": outputs,
            "engine": {
                "name": "bla-agents",
                "version": manifest["version"],
                "package_tree_sha256": package_hash,
            },
            "source_sha256": expected_hash,
            "evidence": [protected["report"]["path"], verified["report"]["path"]],
        }
        if rea_comparison:
            execution["rea_comparison"] = rea_comparison
        if rea_analysis:
            execution.setdefault("analysis_engines", {})["rea"] = rea_analysis
        if craft_analysis:
            execution.setdefault("analysis_engines", {})["craft-anything"] = (
                craft_analysis
            )
        if e2e_behavior:
            execution["e2e_behavior"] = e2e_behavior
        if performance_budget:
            execution["performance"] = performance
        checks = []
        for check_id in action["verification"]:
            if check_id == "bla_invariants":
                checks.append(
                    {
                        "id": check_id,
                        "status": "passed",
                        "evidence": [{**verified["report"], "kind": "bla-verify"}],
                    }
                )
            elif check_id == "application_behavior" and behavior_command is not None:
                checks.append(
                    {
                        "id": check_id,
                        "status": "passed" if behavior_result else "failed",
                        "evidence": [
                            {
                                "path": item["path"],
                                "sha256": item["sha256"],
                                "kind": item["kind"],
                            }
                            for item in behavior_evidence
                        ]
                        if behavior_result
                        else [item["path"] for item in behavior_evidence]
                        or ["not-run: behavior command failed to start"],
                    }
                )
            elif check_id == "rea_comparison" and rea_comparison:
                checks.append(
                    {
                        "id": check_id,
                        "status": "passed",
                        "evidence": [
                            {
                                "path": rea_comparison["path"],
                                "sha256": rea_comparison["sha256"],
                                "kind": "rea-comparison",
                            }
                        ],
                    }
                )
            elif check_id == "craft_analysis" and craft_analysis:
                evidence = [
                    side["evidence"]
                    for side in (craft_analysis["before"], craft_analysis["after"])
                    if isinstance(side.get("evidence"), dict)
                ]
                checks.append(
                    {
                        "id": check_id,
                        "status": (
                            "passed"
                            if craft_analysis["status"] == "passed"
                            else "failed"
                        ),
                        "evidence": evidence
                        or [
                            side.get("reason")
                            or f"{side['side']} Craft Anything unavailable"
                            for side in (
                                craft_analysis["before"],
                                craft_analysis["after"],
                            )
                        ],
                    }
                )
            elif check_id == "e2e_behavior" and e2e_behavior:
                checks.append(
                    {
                        "id": check_id,
                        "status": "passed" if e2e_behavior["passed"] else "failed",
                        "evidence": (
                            [e2e_behavior["before"], e2e_behavior["after"]]
                            if e2e_behavior["passed"]
                            else [
                                e2e_behavior["before"]["path"],
                                e2e_behavior["after"]["path"],
                            ]
                        ),
                    }
                )
            elif check_id == "performance":
                checks.append(
                    {
                        "id": check_id,
                        "status": "passed"
                        if performance_budget and performance["passed"]
                        else "failed",
                        "evidence": performance_evidence
                        or ["not-run: performance budget missing"],
                    }
                )
            else:
                checks.append(
                    {
                        "id": check_id,
                        "status": "blocked",
                        "evidence": [
                            f"not-run: independent check required: {check_id}"
                        ],
                    }
                )
        verification_record = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "verification",
            "id": verification_id,
            "run_id": run_id,
            "checks": checks,
        }
        execution["evidence"] = [
            {**protected["report"], "kind": "bla-protect"},
            {**verified["report"], "kind": "bla-verify"},
            *performance_evidence,
            *performance_candidate_refs,
            *(behavior_evidence or []),
        ]
        if craft_analysis:
            execution["evidence"].extend(
                side["evidence"]
                for side in (
                    craft_analysis["before"],
                    craft_analysis["after"],
                )
                if isinstance(side.get("evidence"), dict)
            )
            execution["evidence"].extend(
                side["upstream_evidence"]
                for side in (craft_analysis["before"], craft_analysis["after"])
                if isinstance(side.get("upstream_evidence"), dict)
            )
        if rea_comparison:
            comparison = workflow.read_json(rea_comparison["path"])
            execution["evidence"].append(
                {
                    "path": rea_comparison["path"],
                    "sha256": rea_comparison["sha256"],
                    "kind": "rea-comparison",
                }
            )
            for side in ("before", "after"):
                execution["evidence"].extend(
                    [
                        {
                            "path": comparison[side]["report"],
                            "sha256": comparison[side]["report_sha256"],
                            "kind": f"rea-{side}-report",
                        },
                        {
                            "path": comparison[side]["evidence_bundle"],
                            "sha256": comparison[side]["evidence_bundle_sha256"],
                            "kind": f"rea-{side}-bundle",
                        },
                    ]
                )
        if e2e_behavior:
            execution["evidence"].extend(
                [e2e_behavior["before"], e2e_behavior["after"]]
            )
        workflow.write_record(records, execution)
        workflow.write_record(records, verification_record)
        verifying = workflow.transition_run(
            executing,
            "verifying",
            execution_id=execution_id,
            verification_id=verification_id,
        )
        workflow.write_run_state(run_path.parent, verifying, executing)
        failed_checks = [check for check in checks if check["status"] != "passed"]
        if failed_checks:
            rejection = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "acceptance",
                "id": "reject-"
                + hashlib.sha256(f"{run_id}:{execution_id}".encode()).hexdigest()[:24],
                "run_id": run_id,
                "outcome": "rejected",
                "claims": [],
                "reasons": [
                    f"Required verification failed or was unavailable: {check['id']} ({check['status']})"
                    for check in failed_checks
                ],
                "verification_id": verification_id,
                "execution_id": execution_id,
                "plan_sha256": workflow.record_hash(plan),
            }
            workflow.write_record(records, rejection)
            rejected = workflow.accept_run(
                verifying,
                target,
                baseline,
                plan,
                decision,
                execution,
                verification_record,
                rejection,
                optimization_search,
            )
            workflow.write_run_state(run_path.parent, rejected, verifying)
            quarantine = discard_candidate(root, run_id)
            return {
                "status": "rejected",
                "run_id": run_id,
                "action_id": action_id,
                "execution_id": execution_id,
                "verification_id": verification_id,
                "acceptance_id": rejection["id"],
                "candidate_retained_at": quarantine["retained_at"],
                "checks": checks,
                "accepted": False,
            }
    except BaseException as error:
        for path in performance_candidate_paths:
            _remove_output(path)
        _remove_output(candidate)
        current = workflow.validate_run(workflow.read_json(run_path))
        if (
            current["state"] == "executing"
            and cancel_event is not None
            and cancel_event.is_set()
        ):
            cancelled = workflow.transition_run(
                current, "cancelled", cancellation_reason="user_requested"
            )
            workflow.write_run_state(run_path.parent, cancelled, current)
        elif current["state"] == "executing":
            failed = workflow.transition_run(
                current, "failed", error_code="bla_execution_failed"
            )
            workflow.write_run_state(run_path.parent, failed, current)
        if isinstance(error, workflow.WorkflowError):
            raise
        raise workflow.WorkflowError(f"BLA execution failed: {error}") from error
    return {
        "status": "verifying",
        "run_id": run_id,
        "action_id": action_id,
        "candidate": str(candidate),
        "candidate_sha256": verified["candidate_sha256"],
        "execution_id": execution_id,
        "verification_id": verification_id,
        "checks": checks,
        "accepted": False,
    }


def execute_approved_candidate_set(
    store: str | Path,
    run_id: str,
    search_id: str,
    candidate_id: str,
    runtime: str | Path | None,
    rea_runtime: str | Path | None = None,
    e2e_runtime: str | Path | None = None,
    cancel_event=None,
    on_process=None,
    direct: bool = False,
    craft_anything_cli: str | Path | None = None,
) -> dict:
    """Compose one preflighted approved set of distinct BLA JavaScript actions privately."""
    root = workflow._private_directory(store).resolve(strict=True)
    if direct:
        records = root / "records"
        run_context = workflow.validate_run(
            workflow.read_json(
                root / "runs" / f"run-{workflow._reference_id(run_id, 'run id')}.json"
            )
        )
        plan = workflow.validate_plan(
            workflow.read_record(
                records / f"plan-{run_context['plan_id']}.json", "plan"
            )
        )
        decision_context = workflow.read_record(
            records / f"decision-{run_context['decision_id']}.json", "decision"
        )
        actions = workflow._validate_composite_actions(
            plan, decision_context["selected_action_ids"]
        )
        baseline = workflow.read_record(
            records / f"baseline-{run_context['baseline_id']}.json", "baseline"
        )
        artifacts = baseline.get("identity", {}).get("artifacts", {})
        for action in actions:
            path = action["execution"]["source_path"]
            expected = {
                item.get("path"): item.get("sha256")
                for item in action.get("evidence", [])
                if isinstance(item, dict)
            }
            identity = artifacts.get(path)
            if not isinstance(identity, dict) or expected.get(path) != identity.get(
                "sha256"
            ):
                raise workflow.WorkflowError(
                    "Composite BLA source must match its saved baseline artifact"
                )
        candidate = {
            "id": candidate_id,
            "action_ids": [action["id"] for action in actions],
        }
        search = None
    else:
        state = validate_approved_candidate_set(root, search_id, candidate_id)
        search, plan, baseline, candidate, actions = (
            state[key] for key in ("search", "plan", "baseline", "candidate", "actions")
        )
    analysis_policy = plan.get("analysis_policy", {})
    rea_selected = "rea" in analysis_policy.get("engines", [])
    craft_selected = "craft-anything" in analysis_policy.get("engines", [])
    craft_cli = craft_anything_cli or os.environ.get("ANTI_REA_CRAFT_ANYTHING_CLI")
    if len(actions) < 2:
        raise workflow.WorkflowError(
            "Composite execution requires at least two actions; use the single-action executor"
        )
    records = root / "records"
    run_id = workflow._reference_id(run_id, "run id")
    run_path = root / "runs" / f"run-{run_id}.json"
    run = workflow.validate_run(workflow.read_json(run_path))
    if run["state"] != "preparing":
        raise workflow.WorkflowError(
            "Approved candidate execution requires a preparing run"
        )
    target = workflow.read_record(records / f"target-{run['target_id']}.json", "target")
    if (
        run.get("target_id") != target["id"]
        or run.get("plan_id") != plan["id"]
        or run.get("baseline_id") != baseline["id"]
    ):
        raise workflow.WorkflowError(
            "Approved candidate run does not match its saved plan and baseline"
        )
    decision = workflow.read_record(
        records / f"decision-{run['decision_id']}.json", "decision"
    )
    decision = workflow.validate_decision(decision, plan, search)
    if (
        decision["decision"] != "approved"
        or (
            not direct
            and (
                decision.get("optimization_search_id") != search["id"]
                or decision.get("optimization_search_sha256")
                != workflow.record_hash(search)
                or decision.get("optimization_candidate_id") != candidate_id
            )
        )
        or decision["selected_action_ids"] != candidate["action_ids"]
    ):
        raise workflow.WorkflowError(
            "Run decision is not bound to this exact approved candidate"
        )
    target_root = Path(target["source_root"]).resolve(strict=True)
    if (
        root == target_root
        or root in target_root.parents
        or target_root in root.parents
    ):
        raise workflow.WorkflowError(
            "Anti-REA state and target must be separate directory trees"
        )
    baseline = workflow.validate_baseline_target(baseline, target)
    baseline_root = _verify_build_snapshot(baseline)
    _verify_live_project_inputs(target, target_root)
    if not runtime:
        raise workflow.WorkflowError(
            "Approved BLA candidate requires its pinned runtime"
        )
    runtime_path = Path(runtime).expanduser()
    rea_runtime_path = Path(rea_runtime).expanduser() if rea_runtime else None
    baseline_e2e = baseline.get("identity", {}).get("e2e_behavior")
    e2e_runtime_path = (
        Path(e2e_runtime).expanduser()
        if e2e_runtime
        else Path(baseline_e2e["runtime_path"]).expanduser()
        if isinstance(baseline_e2e, dict)
        else None
    )
    if (
        search is not None
        and "rea" in search["runtime_identities"]
        and rea_runtime_path is None
    ):
        raise workflow.WorkflowError("Approved search requires its pinned REA runtime")
    if (
        search is not None
        and "e2e" in search["runtime_identities"]
        and e2e_runtime_path is None
    ):
        raise workflow.WorkflowError("Approved search requires its pinned e2e runtime")
    runtime_paths = {
        "bla-agents": runtime_path,
        "rea": rea_runtime_path,
        "e2e": e2e_runtime_path,
    }
    from core.optimizer import _search_runtime_identity

    for name, digest in (
        search["runtime_identities"].items() if search is not None else []
    ):
        path = runtime_paths[name]
        if path is None or _search_runtime_identity(path, name) != digest:
            raise workflow.WorkflowError(
                f"Approved search {name} runtime identity is missing or changed"
            )
    runtime_path = runtime_path.resolve(strict=True)
    if rea_runtime_path:
        rea_runtime_path = rea_runtime_path.resolve(strict=True)
    if e2e_runtime_path:
        e2e_runtime_path = e2e_runtime_path.resolve(strict=True)
    for path in (runtime_path, rea_runtime_path, e2e_runtime_path):
        if path is not None and any(
            path == other or path in other.parents or other in path.parents
            for other in (root, target_root, baseline_root)
            if path != other
        ):
            raise workflow.WorkflowError(
                "Pinned runtimes, state, baseline, and target must be separate trees"
            )

    max_elapsed_ms = (
        search["budgets"]["max_elapsed_ms"] if search is not None else 3600000
    )
    started = time.monotonic()

    def remaining_timeout(cap: float) -> float:
        remaining = max_elapsed_ms / 1000 - (time.monotonic() - started)
        if remaining <= 0:
            raise workflow.WorkflowError(
                "Approved candidate exceeded its elapsed-time budget"
            )
        return min(cap, remaining)

    execution_id = (
        "exec-"
        + hashlib.sha256(f"{run_id}:{search_id}:{candidate_id}".encode()).hexdigest()[
            :24
        ]
    )
    verification_id = (
        "verify-"
        + hashlib.sha256(f"{run_id}:{search_id}:{candidate_id}".encode()).hexdigest()[
            :24
        ]
    )
    stem = hashlib.sha256(f"{run_id}:{search_id}:{candidate_id}".encode()).hexdigest()[
        :32
    ]
    candidates = workflow._private_directory(root / "candidates")
    evidence_dir = workflow._private_directory(root / "evidence")
    candidate_root = candidates / f"{stem}-composite"
    manifest_path = evidence_dir / f"{stem}-candidate-tree.json"
    if (
        candidate_root.exists()
        or candidate_root.is_symlink()
        or manifest_path.exists()
        or manifest_path.is_symlink()
    ):
        raise workflow.WorkflowError("Composite candidate or manifest already exists")
    base_files = discovery.inspect_project(baseline_root)["files"]
    executing = workflow.transition_run(run, "executing")
    workflow.write_run_state(run_path.parent, executing, run)
    performance_candidate_paths = []
    temporary_trial_paths = []
    try:
        if cancel_event is not None and cancel_event.is_set():
            raise workflow.WorkflowError("Command cancelled")
        probe = _invoke(
            _bla_script(),
            ["probe", str(runtime_path)],
            remaining_timeout(60),
            cancel_event,
            on_process,
        )
        if search is not None and probe.get("package_tree_sha256") != search[
            "runtime_identities"
        ].get("bla-agents"):
            raise workflow.WorkflowError(
                "BLA runtime differs from the approved search identity"
            )
        candidate_root.mkdir(mode=0o700)
        for item in base_files:
            _copy_project_file(
                baseline_root,
                item["path"],
                candidate_root / item["path"],
                item["sha256"],
                item["size"],
                candidate_root,
                cancel_event,
            )

        stages, stage_evidence, commands = [], [], []
        checks = actions[0]["verification"]
        for action in actions:
            if cancel_event is not None and cancel_event.is_set():
                raise workflow.WorkflowError("Command cancelled")
            stage_started = time.monotonic()
            action_id = action["id"]
            config = action["execution"]
            source_path = config["source_path"]
            source = baseline_root / source_path
            source_identity = baseline["identity"]["artifacts"][source_path]
            input_tree_identity = _snapshot_tree_identity(candidate_root)
            intensity = config.get("intensity", "balanced")
            if intensity not in {"stealth", "balanced", "maximum", "bankrupt"}:
                raise workflow.WorkflowError(
                    "Invalid BLA intensity in composite action"
                )
            destination = candidate_root / source_path
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if destination.is_symlink() or not destination.is_file():
                raise workflow.WorkflowError(
                    "Composite BLA stage input is not a regular private file"
                )
            destination.unlink()
            performance_budget = (
                workflow.validate_performance_budget(config.get("performance_budget"))
                if "performance" in checks
                else None
            )
            trial_count = performance_budget["trials"] if performance_budget else 1
            trials, stage_refs, stage_commands = [], [], []
            performance_path = evidence_dir / f"{stem}-{action_id}-performance.json"
            main_protect = main_verify = main_candidate_sha256 = None
            for trial_index in range(trial_count):
                if cancel_event is not None and cancel_event.is_set():
                    raise workflow.WorkflowError("Command cancelled")
                output_path = (
                    destination
                    if trial_index == 0
                    else candidates
                    / f"{stem}-{action_id}-trial-{trial_index}{source.suffix.lower()}"
                )
                if trial_index:
                    temporary_trial_paths.append(output_path)
                protect_path = (
                    evidence_dir
                    / f"{stem}-{action_id}-trial-{trial_index}-protect.json"
                )
                verify_path = (
                    evidence_dir / f"{stem}-{action_id}-trial-{trial_index}-verify.json"
                )
                protected = _invoke(
                    _bla_script(),
                    [
                        "protect-js",
                        str(runtime_path),
                        str(source),
                        str(output_path),
                        str(protect_path),
                        "--intensity",
                        intensity,
                        "--seed",
                        f"{run_id}-{action_id}-{trial_index}",
                    ],
                    remaining_timeout(960),
                    cancel_event,
                    on_process,
                )
                verified = _invoke(
                    _bla_script(),
                    [
                        "verify-js",
                        str(runtime_path),
                        str(source),
                        str(output_path),
                        str(verify_path),
                    ],
                    remaining_timeout(360),
                    cancel_event,
                    on_process,
                )
                if (
                    protected.get("source_sha256") != source_identity["sha256"]
                    or verified.get("source_sha256") != source_identity["sha256"]
                    or protected.get("candidate_sha256")
                    != verified.get("candidate_sha256")
                    or not output_path.is_file()
                    or output_path.is_symlink()
                ):
                    raise workflow.WorkflowError(
                        "Composite BLA stage identity or verifier output does not match"
                    )
                if performance_budget and (
                    protected.get("elapsed_ms", 0)
                    > performance_budget["max_elapsed_ms"]
                    or protected.get("candidate_bytes", 0)
                    > performance_budget["max_candidate_bytes"]
                ):
                    raise workflow.WorkflowError(
                        f"Composite BLA stage exceeded its performance budget: {action_id}"
                    )
                protect_ref = {
                    **protected["report"],
                    "kind": "bla-protect",
                    "action_id": action_id,
                }
                verify_ref = {
                    **verified["report"],
                    "kind": "bla-verify",
                    "action_id": action_id,
                }
                stage_refs.extend([protect_ref, verify_ref])
                protect_report = json.loads(
                    workflow.verify_evidence_file(protected["report"])
                )
                verify_report = json.loads(
                    workflow.verify_evidence_file(verified["report"])
                )
                protect_command, verify_command = (
                    protect_report.get("command"),
                    verify_report.get("command"),
                )
                if (
                    not isinstance(protect_command, list)
                    or not all(isinstance(arg, str) for arg in protect_command)
                    or not isinstance(verify_command, list)
                    or not all(isinstance(arg, str) for arg in verify_command)
                ):
                    raise workflow.WorkflowError(
                        "BLA report is missing its executed command"
                    )
                stage_commands.extend([protect_command, verify_command])
                artifact_ref = None
                if performance_budget:
                    artifact_ref = (
                        {
                            "path": str(output_path.resolve(strict=True)),
                            "sha256": protected["candidate_sha256"],
                            "kind": "performance-candidate",
                        }
                        if trial_index == 0
                        else _retain_performance_trial(
                            output_path,
                            evidence_dir,
                            performance_path.stem,
                            trial_index,
                            protected["candidate_sha256"],
                            protected["candidate_bytes"],
                        )
                    )
                    if trial_index:
                        performance_candidate_paths.append(Path(artifact_ref["path"]))
                        _remove_output(output_path)
                    stage_refs.append({**artifact_ref, "action_id": action_id})
                trials.append(
                    {
                        "elapsed_ms": protected["elapsed_ms"],
                        "candidate_bytes": protected["candidate_bytes"],
                        "source_sha256": protected["source_sha256"],
                        "candidate_sha256": protected["candidate_sha256"],
                        **(
                            {"candidate_artifact": artifact_ref} if artifact_ref else {}
                        ),
                    }
                )
                if trial_index == 0:
                    main_protect, main_verify = protect_ref, verify_ref
                    main_candidate_sha256 = verified["candidate_sha256"]
                elif not performance_budget:
                    _remove_output(output_path)
            performance = None
            performance_ref = None
            if performance_budget:
                source_bytes = source.stat().st_size
                performance = {
                    "schema_version": "1.0",
                    "run_id": run_id,
                    "action_id": action_id,
                    "plan_sha256": workflow.record_hash(plan),
                    "source_sha256": source_identity["sha256"],
                    "runtime_manifest_sha256": probe["package_tree_sha256"],
                    "source_bytes": source_bytes,
                    "budget": performance_budget,
                    "trials": trials,
                    "summary": {
                        "elapsed_ms_min": min(item["elapsed_ms"] for item in trials),
                        "elapsed_ms_max": max(item["elapsed_ms"] for item in trials),
                        "elapsed_ms_mean": sum(item["elapsed_ms"] for item in trials)
                        / len(trials),
                        "candidate_bytes_min": min(
                            item["candidate_bytes"] for item in trials
                        ),
                        "candidate_bytes_max": max(
                            item["candidate_bytes"] for item in trials
                        ),
                        "candidate_bytes_mean": sum(
                            item["candidate_bytes"] for item in trials
                        )
                        / len(trials),
                        "candidate_growth_bytes_min": min(
                            item["candidate_bytes"] for item in trials
                        )
                        - source_bytes,
                        "candidate_growth_bytes_max": max(
                            item["candidate_bytes"] for item in trials
                        )
                        - source_bytes,
                    },
                    "passed": all(
                        item["elapsed_ms"] <= performance_budget["max_elapsed_ms"]
                        and item["candidate_bytes"]
                        <= performance_budget["max_candidate_bytes"]
                        for item in trials
                    ),
                }
                _write_snapshot_file(
                    performance_path, workflow.canonical(performance) + b"\n"
                )
                performance_ref = {
                    "path": str(performance_path.resolve()),
                    "sha256": hashlib.sha256(performance_path.read_bytes()).hexdigest(),
                    "kind": "performance",
                    "action_id": action_id,
                }
                stage_refs.append(performance_ref)
                stage_commands.extend(
                    [
                        [
                            "performance-trial",
                            action_id,
                            str(runtime_path),
                            str(source),
                            str(trial_index),
                        ]
                        for trial_index in range(1, trial_count)
                    ]
                )
            stages.append(
                {
                    "action_id": action_id,
                    "source_path": source_path,
                    "input_sha256": source_identity["sha256"],
                    "candidate_path": str(destination.resolve(strict=True)),
                    "candidate_sha256": main_candidate_sha256,
                    "input_tree_sha256": input_tree_identity["tree_sha256"],
                    "output_tree_sha256": _snapshot_tree_identity(candidate_root)[
                        "tree_sha256"
                    ],
                    "protect_evidence": {
                        key: value
                        for key, value in main_protect.items()
                        if key != "action_id"
                    },
                    "verify_evidence": {
                        key: value
                        for key, value in main_verify.items()
                        if key != "action_id"
                    },
                    "performance": performance,
                    "performance_evidence": (
                        {
                            key: value
                            for key, value in performance_ref.items()
                            if key != "action_id"
                        }
                        if performance_ref
                        else None
                    ),
                    "elapsed_ms": max(
                        1, int((time.monotonic() - stage_started) * 1000)
                    ),
                }
            )
            stage_evidence.extend(stage_refs)
            commands.extend(stage_commands)

        candidate_file_records = discovery.inspect_project(candidate_root)["files"]
        candidate_files = {
            item["path"]: item["sha256"] for item in candidate_file_records
        }
        expected_files = {item["path"]: item["sha256"] for item in base_files}
        expected_files.update(
            {stage["source_path"]: stage["candidate_sha256"] for stage in stages}
        )
        if candidate_files != expected_files:
            raise workflow.WorkflowError(
                "Composite candidate tree differs outside the selected BLA outputs"
            )
        tree_identity = _snapshot_tree_identity(candidate_root)
        candidate_bytes = sum(item["size"] for item in candidate_file_records)
        if candidate_bytes > (
            search["budgets"]["max_candidate_bytes"]
            if search is not None
            else 64 * 1024 * 1024
        ):
            raise workflow.WorkflowError(
                "Composite candidate tree exceeds its approved size budget"
            )
        snapshot_stem = hashlib.sha256(
            f"{run_id}:{actions[0]['id']}".encode()
        ).hexdigest()[:32]
        snapshot_root = (
            workflow._private_directory(root / "behavior-snapshots") / snapshot_stem
        )
        if snapshot_root.exists() or snapshot_root.is_symlink():
            raise workflow.WorkflowError(
                "Composite verification snapshot path already exists"
            )
        before_snapshot, after_snapshot = (
            snapshot_root / "before",
            snapshot_root / "after",
        )
        if (
            {"application_behavior", "rea_comparison", "e2e_behavior"} & set(checks)
            or rea_selected
            or craft_selected
        ):
            snapshot_identity = _create_composite_snapshots(
                baseline_root,
                baseline,
                candidate_root,
                before_snapshot,
                after_snapshot,
                cancel_event,
            )
        else:
            snapshot_identity = None
        behavior_refs, rea_comparison, e2e_behavior = [], None, None
        craft_analysis = None
        craft_pool = ThreadPoolExecutor(max_workers=1) if craft_selected else None
        craft_future = (
            craft_pool.submit(
                _capture_craft_analysis_pair,
                before_snapshot,
                after_snapshot,
                state=root,
                evidence_dir=evidence_dir,
                stem=stem,
                cli=craft_cli,
                baseline=baseline,
                cancel_event=cancel_event,
                on_process=on_process,
            )
            if craft_pool is not None and snapshot_identity is not None
            else None
        )
        first_stage = stages[0]
        if "application_behavior" in checks:
            behavior = baseline["identity"]["behavior"]
            command = actions[0]["execution"]["behavior_command"]
            baseline_ref = {
                "path": behavior["evidence_path"],
                "sha256": behavior["evidence_sha256"],
                "kind": "behavior-baseline",
            }
            baseline_raw = workflow.verify_evidence_file(baseline_ref)
            baseline_report = json.loads(baseline_raw)
            source_report = _run_behavior_check(
                command,
                before_snapshot,
                first_stage["source_path"],
                f"{stem}-behavior-source",
                on_process,
                cancel_event,
                remaining_timeout(120),
                evidence_dir,
                "behavior-source",
            )
            candidate_report = _run_behavior_check(
                command,
                after_snapshot,
                first_stage["source_path"],
                f"{stem}-behavior-candidate",
                on_process,
                cancel_event,
                remaining_timeout(120),
                evidence_dir,
                "behavior-candidate",
            )
            behavior_refs = [baseline_ref, source_report, candidate_report]
            stage_evidence.extend(behavior_refs)
            stable_behavior = (
                not baseline_report.get("timed_out")
                and baseline_report.get("exit_code") == 0
                and source_report["status"] == "passed"
                and candidate_report["status"] == "passed"
                and baseline_report.get("stdout")
                == source_report["stdout"]
                == candidate_report["stdout"]
            )
            commands.extend(
                [
                    [
                        "behavior-check",
                        str(before_snapshot / first_stage["source_path"]),
                    ],
                    [
                        "behavior-check",
                        str(after_snapshot / first_stage["source_path"]),
                    ],
                ]
                if stable_behavior
                else []
            )
        else:
            stable_behavior = True
        rea_analysis = None
        if rea_selected or "rea_comparison" in checks:
            rea_analysis, rea_comparison = _capture_rea_analysis_pair(
                rea_runtime_path,
                before_snapshot,
                after_snapshot,
                snapshot_identity,
                baseline,
                evidence_dir,
                stem,
                remaining_timeout(1200),
                cancel_event,
                on_process,
                source_path=first_stage["source_path"],
                source_sha256=first_stage["input_sha256"],
                candidate_sha256=first_stage["candidate_sha256"],
            )
            if "rea_comparison" in checks and rea_analysis["status"] != "passed":
                if craft_future:
                    craft_future.result()
                if craft_pool:
                    craft_pool.shutdown(wait=True, cancel_futures=True)
                raise workflow.WorkflowError(
                    rea_analysis.get("reason") or "Composite REA comparison gate failed"
                )
            if rea_comparison:
                report = workflow.read_json(rea_comparison["path"])
                stage_evidence.append(
                    {
                        "path": rea_comparison["path"],
                        "sha256": rea_comparison["sha256"],
                        "kind": "rea-comparison",
                    }
                )
                for side in ("before", "after"):
                    stage_evidence.extend(
                        [
                            {
                                "path": report[side]["report"],
                                "sha256": report[side]["report_sha256"],
                                "kind": f"rea-{side}-report",
                            },
                            {
                                "path": report[side]["evidence_bundle"],
                                "sha256": report[side]["evidence_bundle_sha256"],
                                "kind": f"rea-{side}-bundle",
                            },
                        ]
                    )
                commands.append(
                    [
                        "rea-compare",
                        str(rea_runtime_path),
                        str(before_snapshot),
                        str(after_snapshot),
                    ]
                )
        elif snapshot_identity:
            rea_comparison = {
                **snapshot_identity,
                "before_snapshot": str(before_snapshot),
                "after_snapshot": str(after_snapshot),
                "snapshot_root": str(snapshot_root),
                "source_path": first_stage["source_path"],
                "source_sha256": first_stage["input_sha256"],
                "candidate_sha256": first_stage["candidate_sha256"],
            }
        if craft_future:
            craft_analysis = craft_future.result()
            stage_evidence.extend(
                side["evidence"]
                for side in (craft_analysis["before"], craft_analysis["after"])
                if isinstance(side.get("evidence"), dict)
            )
            stage_evidence.extend(
                side["upstream_evidence"]
                for side in (craft_analysis["before"], craft_analysis["after"])
                if isinstance(side.get("upstream_evidence"), dict)
            )
        if craft_pool:
            craft_pool.shutdown(wait=True, cancel_futures=True)
        if "e2e_behavior" in checks:
            baseline_e2e = baseline["identity"]["e2e_behavior"]
            e2e_before = {
                "path": baseline_e2e["report_path"],
                "sha256": baseline_e2e["report_sha256"],
                "kind": "e2e-before",
            }
            with tempfile.TemporaryDirectory(
                prefix="anti-rea-e2e-composite-", dir=e2e_runtime_path
            ) as temporary:
                project_copy = Path(temporary) / "after"
                shutil.copytree(after_snapshot, project_copy)
                result = _invoke_e2e(
                    _e2e_script(),
                    [
                        "run",
                        str(project_copy),
                        str(e2e_runtime_path),
                        ".anti-rea-e2e/after",
                        "--stage",
                        "after",
                        "--config",
                        actions[0]["execution"].get(
                            "e2e_config", baseline_e2e["config"]
                        ),
                        "--test-file",
                        actions[0]["execution"].get(
                            "e2e_test_file", baseline_e2e["test_file"]
                        ),
                    ],
                    remaining_timeout(360),
                    cancel_event,
                    on_process,
                )
                raw = workflow.verify_evidence_file(
                    {"path": result["report"], "sha256": result["report_sha256"]}
                )
                e2e_after_path = evidence_dir / f"{stem}-e2e-after.json"
                _write_snapshot_file(e2e_after_path, raw)
                e2e_after = {
                    "path": str(e2e_after_path.resolve()),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "kind": "e2e-after",
                }
            before_e2e_root = Path(baseline_e2e["snapshot_path"])
            before_identity = _snapshot_tree_identity(before_e2e_root)
            after_identity = _snapshot_tree_identity(after_snapshot)
            if (
                before_identity["file_scope_sha256"]
                != after_identity["file_scope_sha256"]
                or workflow._hash_project_file(
                    after_snapshot, first_stage["source_path"]
                )
                != first_stage["candidate_sha256"]
            ):
                raise workflow.WorkflowError(
                    "Composite e2e snapshot is not the final composed candidate"
                )
            e2e_behavior = {
                "before": e2e_before,
                "after": e2e_after,
                "before_snapshot": str(before_e2e_root),
                "after_snapshot": str(after_snapshot),
                "snapshot_identity": {
                    "before_tree_sha256": before_identity["tree_sha256"],
                    "after_tree_sha256": after_identity["tree_sha256"],
                    "file_scope_sha256": before_identity["file_scope_sha256"],
                },
                "runtime_path": str(e2e_runtime_path),
                "runtime_manifest_sha256": baseline_e2e["runtime_manifest_sha256"],
                "runner": baseline_e2e["runner"],
                "test_ids": baseline_e2e["test_ids"],
                "cleanup": {
                    "before": baseline_e2e["cleanup"],
                    "after": result["cleanup"],
                },
                "config": actions[0]["execution"].get(
                    "e2e_config", baseline_e2e["config"]
                ),
                "test_file": actions[0]["execution"].get(
                    "e2e_test_file", baseline_e2e["test_file"]
                ),
                "passed": result["status"] == "passed"
                and baseline_e2e["runtime_manifest_sha256"]
                == result["runtime_manifest_sha256"]
                and baseline_e2e["test_ids"] == result["test_ids"],
            }
            stage_evidence.extend([e2e_before, e2e_after])
            commands.append(result["command"])

        elapsed_ms = max(1, int((time.monotonic() - started) * 1000))
        if elapsed_ms > max_elapsed_ms:
            raise workflow.WorkflowError(
                "Approved candidate exceeded its elapsed-time budget"
            )
        measurements = {"elapsed_ms": elapsed_ms, "candidate_bytes": candidate_bytes}
        candidate_manifest = {
            "schema_version": "1.0",
            "record_type": "composite_candidate_tree"
            if direct
            else "optimization_candidate_tree",
            "run_id": run_id,
            **(
                {
                    "search_id": search["id"],
                    "search_sha256": workflow.record_hash(search),
                    "candidate_id": candidate_id,
                }
                if search is not None
                else {}
            ),
            "plan_sha256": workflow.record_hash(plan),
            "baseline_sha256": workflow.record_hash(baseline),
            "action_ids": candidate["action_ids"],
            "candidate_path": str(candidate_root.resolve(strict=True)),
            "candidate_tree_sha256": tree_identity["tree_sha256"],
            "candidate_file_scope_sha256": tree_identity["file_scope_sha256"],
            "candidate_files": candidate_files,
            "candidate_bytes": candidate_bytes,
            "optimization_measurements": measurements,
            "stages": [
                {
                    "action_id": stage["action_id"],
                    "source_path": stage["source_path"],
                    "input_sha256": stage["input_sha256"],
                    "candidate_sha256": stage["candidate_sha256"],
                    "input_tree_sha256": stage["input_tree_sha256"],
                    "output_tree_sha256": stage["output_tree_sha256"],
                    "elapsed_ms": stage["elapsed_ms"],
                }
                for stage in stages
            ],
        }
        _write_snapshot_file(
            manifest_path, workflow.canonical(candidate_manifest) + b"\n"
        )
        manifest_ref = {
            "path": str(manifest_path.resolve()),
            "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "kind": "optimization-candidate-tree"
            if search is not None
            else "composite-candidate-tree",
        }
        stages_evidence = [*stage_evidence, manifest_ref]
        execution_record = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "execution",
            "id": execution_id,
            "run_id": run_id,
            "plan_sha256": workflow.record_hash(plan),
            "action_id": candidate["action_ids"][0],
            "action_ids": candidate["action_ids"],
            **(
                {
                    "optimization_search": {
                        "id": search["id"],
                        "sha256": workflow.record_hash(search),
                        "candidate_id": candidate_id,
                    }
                }
                if search is not None
                else {}
            ),
            "commands": commands or [["bla-composite", *candidate["action_ids"]]],
            "exit_code": 0,
            "outputs": [
                {"path": manifest_ref["path"], "sha256": manifest_ref["sha256"]}
            ],
            "engine": {
                "name": "bla-agents",
                "version": probe["version"],
                "package_tree_sha256": probe["package_tree_sha256"],
            },
            "source_sha256": first_stage["input_sha256"],
            "evidence": stages_evidence,
            "action_stages": stages,
            "candidate_tree": {
                "path": str(candidate_root.resolve(strict=True)),
                "tree_sha256": tree_identity["tree_sha256"],
                "file_scope_sha256": tree_identity["file_scope_sha256"],
                "candidate_bytes": candidate_bytes,
                "manifest_evidence": manifest_ref,
            },
            "optimization_measurements": measurements,
        }
        if rea_comparison:
            execution_record["rea_comparison"] = rea_comparison
        if rea_analysis:
            execution_record.setdefault("analysis_engines", {})["rea"] = rea_analysis
        if craft_analysis:
            execution_record.setdefault("analysis_engines", {})["craft-anything"] = (
                craft_analysis
            )
        if e2e_behavior:
            execution_record["e2e_behavior"] = e2e_behavior
        verification_checks = [
            {
                "id": "bla_invariants",
                "status": "passed",
                "evidence": [
                    {
                        **stage["verify_evidence"],
                        "kind": "bla-verify",
                        "action_id": stage["action_id"],
                    }
                    for stage in stages
                ],
            }
        ]
        if "performance" in checks:
            verification_checks.append(
                {
                    "id": "performance",
                    "status": "passed"
                    if all(stage["performance"]["passed"] for stage in stages)
                    else "failed",
                    "evidence": [
                        {
                            **stage["performance_evidence"],
                            "action_id": stage["action_id"],
                        }
                        for stage in stages
                    ],
                }
            )
        if "application_behavior" in checks:
            verification_checks.append(
                {
                    "id": "application_behavior",
                    "status": "passed" if stable_behavior else "failed",
                    "evidence": (
                        [
                            {
                                key: value
                                for key, value in ref.items()
                                if key != "action_id"
                            }
                            for ref in behavior_refs
                        ]
                        if stable_behavior
                        else [ref["path"] for ref in behavior_refs]
                        or ["not-run: behavior check unavailable"]
                    ),
                }
            )
        if "rea_comparison" in checks:
            verification_checks.append(
                {
                    "id": "rea_comparison",
                    "status": "passed",
                    "evidence": [
                        {
                            "path": rea_comparison["path"],
                            "sha256": rea_comparison["sha256"],
                            "kind": "rea-comparison",
                        }
                    ],
                }
            )
        if "craft_analysis" in checks:
            evidence = [
                side["evidence"]
                for side in (
                    (craft_analysis or {}).get("before", {}),
                    (craft_analysis or {}).get("after", {}),
                )
                if isinstance(side.get("evidence"), dict)
            ]
            verification_checks.append(
                {
                    "id": "craft_analysis",
                    "status": (
                        "passed"
                        if craft_analysis and craft_analysis["status"] == "passed"
                        else "failed"
                    ),
                    "evidence": evidence
                    or [
                        side.get("reason")
                        or f"{side.get('side', 'unknown')} Craft Anything unavailable"
                        for side in (
                            (craft_analysis or {}).get("before", {}),
                            (craft_analysis or {}).get("after", {}),
                        )
                    ],
                }
            )
        if "e2e_behavior" in checks:
            verification_checks.append(
                {
                    "id": "e2e_behavior",
                    "status": "passed" if e2e_behavior["passed"] else "failed",
                    "evidence": [e2e_behavior["before"], e2e_behavior["after"]],
                }
            )
        verification = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "verification",
            "id": verification_id,
            "run_id": run_id,
            "checks": verification_checks,
        }
        workflow.write_record(records, execution_record)
        workflow.write_record(records, verification)
        verifying = workflow.transition_run(
            executing,
            "verifying",
            execution_id=execution_id,
            verification_id=verification_id,
        )
        workflow.write_run_state(run_path.parent, verifying, executing)
        failed = [check for check in verification_checks if check["status"] != "passed"]
        if failed:
            rejection = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "acceptance",
                "id": "reject-"
                + hashlib.sha256(f"{run_id}:{execution_id}".encode()).hexdigest()[:24],
                "run_id": run_id,
                "outcome": "rejected",
                "claims": [],
                "reasons": [
                    f"Required composite verification failed: {check['id']}"
                    for check in failed
                ],
                "verification_id": verification_id,
                "execution_id": execution_id,
                "plan_sha256": workflow.record_hash(plan),
            }
            workflow.write_record(records, rejection)
            rejected = workflow.accept_run(
                verifying,
                target,
                baseline,
                plan,
                decision,
                execution_record,
                verification,
                rejection,
                search,
            )
            workflow.write_run_state(run_path.parent, rejected, verifying)
            discarded = discard_candidate(root, run_id)
            return {
                "status": "rejected",
                "run_id": run_id,
                "action_ids": candidate["action_ids"],
                "execution_id": execution_id,
                "verification_id": verification_id,
                "acceptance_id": rejection["id"],
                "checks": verification_checks,
                "candidate_retained_at": discarded["retained_at"],
                "accepted": False,
                "elapsed_ms": elapsed_ms,
                "candidate_bytes": candidate_bytes,
                "candidate_tree_sha256": tree_identity["tree_sha256"],
            }
        return {
            "status": "verifying",
            "run_id": run_id,
            "action_ids": candidate["action_ids"],
            "candidate": str(candidate_root),
            "execution_id": execution_id,
            "verification_id": verification_id,
            "checks": verification_checks,
            "accepted": False,
            "elapsed_ms": elapsed_ms,
            "candidate_bytes": candidate_bytes,
            "candidate_tree_sha256": tree_identity["tree_sha256"],
        }
    except BaseException as error:
        for path in performance_candidate_paths:
            _remove_output(path)
        for path in temporary_trial_paths:
            _remove_output(path)
        _remove_output(candidate_root)
        current = workflow.validate_run(workflow.read_json(run_path))
        if current["state"] == "executing":
            if cancel_event is not None and cancel_event.is_set():
                changed = workflow.transition_run(
                    current, "cancelled", cancellation_reason="user_requested"
                )
            else:
                changed = workflow.transition_run(
                    current, "failed", error_code="composite_bla_execution_failed"
                )
            workflow.write_run_state(run_path.parent, changed, current)
        if isinstance(error, workflow.WorkflowError):
            raise
        raise workflow.WorkflowError(
            f"Approved composite execution failed: {error}"
        ) from error


def execute_selected_composite(
    store: str | Path,
    run_id: str,
    runtime: str | Path | None,
    rea_runtime: str | Path | None = None,
    e2e_runtime: str | Path | None = None,
    cancel_event=None,
    on_process=None,
    craft_anything_cli: str | Path | None = None,
) -> dict:
    root = workflow._private_directory(store).resolve(strict=True)
    run = workflow.validate_run(
        workflow.read_json(
            root / "runs" / f"run-{workflow._reference_id(run_id, 'run id')}.json"
        )
    )
    decision = workflow.read_record(
        root / "records" / f"decision-{run['decision_id']}.json", "decision"
    )
    selected = decision.get("selected_action_ids", [])
    if decision.get("decision") != "approved" or len(selected) < 2:
        raise workflow.WorkflowError(
            "Composite execution requires explicit approval of multiple actions"
        )
    plan = workflow.read_record(
        root / "records" / f"plan-{run['plan_id']}.json", "plan"
    )
    workflow._validate_composite_actions(plan, selected)
    key = hashlib.sha256(f"{run_id}:{decision['id']}".encode()).hexdigest()[:24]
    return execute_approved_candidate_set(
        store,
        run_id,
        f"direct-{key}",
        "direct-composite",
        runtime,
        rea_runtime,
        e2e_runtime,
        cancel_event,
        on_process,
        direct=True,
        craft_anything_cli=craft_anything_cli,
    )


def _execute_source_map_candidate(
    root: Path,
    records: Path,
    run_path: Path,
    run: dict,
    target: dict,
    target_root: Path,
    baseline: dict,
    plan: dict,
    action: dict,
    config: dict,
    cancel_event=None,
) -> dict:
    """Create a private release-tree candidate with one evidenced map omitted."""
    baseline = workflow.validate_baseline_target(baseline, target)
    relative = config.get("source_path")
    expected = {
        item.get("path"): item.get("sha256")
        for item in action.get("evidence", [])
        if isinstance(item, dict)
    }
    identity = baseline.get("identity", {}).get("artifacts", {}).get(relative)
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or not Path(relative).parts
        or ".." in Path(relative).parts
        or not relative.lower().endswith(".map")
        or not isinstance(identity, dict)
        or expected.get(relative) != identity.get("sha256")
    ):
        raise workflow.WorkflowError(
            "Source-map path must be a safe, evidence-linked baseline artifact"
        )
    snapshot = baseline["identity"].get("build_snapshot")
    if not isinstance(snapshot, dict):
        raise workflow.WorkflowError(
            "Source-map candidate requires a private build snapshot"
        )
    source_root = _verify_build_snapshot(baseline)
    _verify_live_project_inputs(target, target_root)
    if baseline_capture._hash_artifact(source_root, relative) != identity:
        raise workflow.WorkflowError("Source map changed after baseline capture")
    files = discovery.inspect_project(source_root)["files"]
    if relative not in {item["path"] for item in files}:
        raise workflow.WorkflowError(
            "Source map is missing from the captured build tree"
        )
    stem = hashlib.sha256(f"{run['id']}:{action['id']}".encode()).hexdigest()[:32]
    candidates = workflow._private_directory(root / "candidates")
    candidate_root = candidates / f"{stem}-release"
    evidence_dir = workflow._private_directory(root / "evidence")
    manifest_path = evidence_dir / f"{stem}-source-map.json"
    if (
        candidate_root.exists()
        or candidate_root.is_symlink()
        or manifest_path.exists()
        or manifest_path.is_symlink()
    ):
        raise workflow.WorkflowError(
            "Source-map candidate or evidence path already exists"
        )
    candidate_root.mkdir(mode=0o700)
    executing = workflow.transition_run(run, "executing")
    workflow.write_run_state(run_path.parent, executing, run)
    try:
        if cancel_event is not None and cancel_event.is_set():
            raise workflow.WorkflowError("Command cancelled")
        for item in files:
            if cancel_event is not None and cancel_event.is_set():
                raise workflow.WorkflowError("Command cancelled")
            if item["path"] != relative:
                _copy_project_file(
                    source_root,
                    item["path"],
                    candidate_root / item["path"],
                    item["sha256"],
                    item["size"],
                    candidate_root,
                    cancel_event,
                )
        candidate_identity = _snapshot_tree_identity(candidate_root)
        candidate_files = {
            item["path"]: item["sha256"]
            for item in discovery.inspect_project(candidate_root)["files"]
        }
        expected_files = {
            item["path"]: item["sha256"] for item in files if item["path"] != relative
        }
        if candidate_files != expected_files:
            raise workflow.WorkflowError(
                "Source-map candidate differs outside the selected map"
            )
        manifest = {
            "schema_version": "1.0",
            "run_id": run["id"],
            "action_id": action["id"],
            "plan_sha256": workflow.record_hash(plan),
            "baseline_id": baseline["id"],
            "baseline_tree_sha256": snapshot["tree_sha256"],
            "baseline_file_scope_sha256": snapshot["file_scope_sha256"],
            "source_path": relative,
            "source_sha256": identity["sha256"],
            "candidate_path": str(candidate_root),
            "candidate_tree_sha256": candidate_identity["tree_sha256"],
            "candidate_file_scope_sha256": candidate_identity["file_scope_sha256"],
            "candidate_files": candidate_files,
        }
        _write_snapshot_file(manifest_path, workflow.canonical(manifest))
        manifest_ref = {
            "path": str(manifest_path.resolve()),
            "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "kind": "source-map-candidate",
        }
        execution_id = (
            "exec-"
            + hashlib.sha256(f"{run['id']}:{action['id']}".encode()).hexdigest()[:24]
        )
        verification_id = (
            "verify-"
            + hashlib.sha256(f"{run['id']}:{action['id']}".encode()).hexdigest()[:24]
        )
        executed = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "execution",
            "id": execution_id,
            "run_id": run["id"],
            "plan_sha256": workflow.record_hash(plan),
            "action_id": action["id"],
            "commands": [["source-map-candidate", relative]],
            "exit_code": 0,
            "outputs": [
                {"path": str(manifest_path.resolve()), "sha256": manifest_ref["sha256"]}
            ],
            "engine": {"name": "anti-rea-release-tree", "version": "1"},
            "source_sha256": identity["sha256"],
            "evidence": [manifest_ref],
            "source_map_candidate": {
                key: value
                for key, value in manifest.items()
                if key != "candidate_files"
            },
        }
        checked = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "verification",
            "id": verification_id,
            "run_id": run["id"],
            "checks": [
                {
                    "id": "public_source_map_absent",
                    "status": "passed",
                    "evidence": [manifest_ref],
                }
            ],
        }
        if cancel_event is not None and cancel_event.is_set():
            raise workflow.WorkflowError("Command cancelled")
        workflow.write_record(records, executed)
        workflow.write_record(records, checked)
        verifying = workflow.transition_run(
            executing,
            "verifying",
            execution_id=execution_id,
            verification_id=verification_id,
        )
        workflow.write_run_state(run_path.parent, verifying, executing)
        return {
            "status": "verifying",
            "run_id": run["id"],
            "action_id": action["id"],
            "candidate": str(candidate_root),
            "candidate_tree_sha256": candidate_identity["tree_sha256"],
            "execution_id": execution_id,
            "verification_id": verification_id,
            "checks": checked["checks"],
            "accepted": False,
        }
    except BaseException as error:
        _remove_output(candidate_root)
        current = workflow.validate_run(workflow.read_json(run_path))
        if current["state"] == "executing":
            if cancel_event is not None and cancel_event.is_set():
                changed = workflow.transition_run(
                    current, "cancelled", cancellation_reason="user_requested"
                )
            else:
                changed = workflow.transition_run(
                    current, "failed", error_code="source_map_candidate_failed"
                )
            workflow.write_run_state(run_path.parent, changed, current)
        if isinstance(error, workflow.WorkflowError):
            raise
        raise workflow.WorkflowError(
            f"Source-map candidate execution failed: {error}"
        ) from error


def _execute_flutter_obfuscation(
    root: Path,
    records: Path,
    run_path: Path,
    run: dict,
    target: dict,
    target_root: Path,
    baseline: dict,
    plan: dict,
    action: dict,
    config: dict,
    cancel_event=None,
    on_process=None,
) -> dict:
    """Build one private Flutter obfuscated package; build success never implies acceptance."""
    baseline = workflow.validate_baseline_target(baseline, target)
    plan = workflow.validate_plan_baseline(plan, baseline)
    relative = config["artifact_path"]
    identity = baseline["identity"]["artifacts"][relative]
    expected = {
        item.get("path"): item.get("sha256")
        for item in action.get("evidence", [])
        if isinstance(item, dict)
    }
    if expected.get(relative) != identity.get("sha256"):
        raise workflow.WorkflowError(
            "Flutter artifact must match the selected plan's captured baseline"
        )
    snapshot = baseline["identity"].get("build_snapshot")
    if not isinstance(snapshot, dict):
        raise workflow.WorkflowError(
            "Flutter obfuscation requires a private baseline build snapshot"
        )
    source_root = _verify_build_snapshot(baseline)
    _verify_live_project_inputs(target, target_root)
    if baseline_capture._hash_artifact(source_root, relative) != identity:
        raise workflow.WorkflowError("Flutter baseline artifact changed after capture")
    baseline_lock_hash = baseline.get("identity", {}).get("dependency_lock_sha256")
    if (
        not isinstance(baseline_lock_hash, str)
        or baseline_capture._hash_artifact(source_root, "pubspec.lock").get("sha256")
        != baseline_lock_hash
    ):
        raise workflow.WorkflowError(
            "Flutter pubspec.lock is missing or changed after baseline capture"
        )
    command = baseline["identity"].get("command")
    if (
        not isinstance(command, list)
        or len(command) < 4
        or Path(command[0]).name != "flutter"
        or command[1:4] != ["build", config["target"], "--release"]
        or "--obfuscate" in command
        or any(arg.startswith("--split-debug-info") for arg in command)
    ):
        raise workflow.WorkflowError(
            "Flutter baseline command must be an un-obfuscated release build"
        )
    from core import flutter_android

    baseline_toolchain = baseline["identity"].get("flutter_toolchain")
    current_toolchain = flutter_android.capture_toolchain_identity(command, target_root)
    if (
        not isinstance(baseline_toolchain, dict)
        or current_toolchain != baseline_toolchain
    ):
        raise workflow.WorkflowError(
            "Flutter toolchain identity changed or was not captured at baseline"
        )
    stem = hashlib.sha256(f"{run['id']}:{action['id']}".encode()).hexdigest()[:32]
    candidates = workflow._private_directory(root / "candidates")
    candidate = candidates / f"{stem}{Path(relative).suffix.lower()}"
    symbols_root = workflow._private_directory(root / "symbols")
    symbols = (symbols_root / stem).resolve()
    workspace_root = workflow._private_directory(root / "workspaces")
    workspace = workspace_root / stem
    evidence_dir = workflow._private_directory(root / "evidence")
    manifest_path = evidence_dir / f"{stem}-flutter-candidate.json"
    if any(
        path.exists() or path.is_symlink()
        for path in (candidate, symbols, workspace, manifest_path)
    ):
        raise workflow.WorkflowError("Flutter candidate output path already exists")
    workspace.mkdir(mode=0o700)
    execution_started = False
    try:
        for item in discovery.inspect_project(source_root)["files"]:
            if cancel_event is not None and cancel_event.is_set():
                raise workflow.WorkflowError("Command cancelled")
            _copy_project_file(
                source_root,
                item["path"],
                workspace / item["path"],
                item["sha256"],
                item["size"],
                workspace,
                cancel_event,
            )
        executing = workflow.transition_run(run, "executing")
        workflow.write_run_state(run_path.parent, executing, run)
        execution_started = True
        argv = [*command, "--obfuscate", f"--split-debug-info={symbols}"]
        code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
            baseline_capture._run_command(
                argv,
                workspace,
                3600,
                on_process,
                cancel_event,
                total_output_limit=baseline_capture.MAX_OUTPUT_BYTES,
            )
        )
        if timed_out or code != 0 or stdout_truncated or stderr_truncated:
            raise workflow.WorkflowError(
                "Flutter obfuscated build failed, timed out, or exceeded output limits"
            )
        if (
            baseline_capture._hash_artifact(workspace, "pubspec.lock").get("sha256")
            != baseline_lock_hash
        ):
            raise workflow.WorkflowError(
                "Flutter candidate build changed pubspec.lock; dependency identity drifted"
            )
        artifact_identity = baseline_capture._hash_artifact(workspace, relative)
        _copy_project_file(
            workspace,
            relative,
            candidate,
            artifact_identity["sha256"],
            artifact_identity["size"],
            candidates,
            cancel_event,
        )
        if not symbols.is_dir() or symbols.is_symlink():
            raise workflow.WorkflowError(
                "Flutter did not produce the private split-debug-info directory"
            )
        symbol_identity = _snapshot_tree_identity(symbols)
        candidate_ref = {
            "path": str(candidate.resolve()),
            "sha256": artifact_identity["sha256"],
            "kind": "flutter-package",
        }
        symbol_ref = {
            "path": str(symbols.resolve()),
            "sha256": symbol_identity["tree_sha256"],
            "kind": "flutter-split-debug-info",
        }
        manifest = {
            "schema_version": "1.0",
            "record_type": "flutter_candidate",
            "run_id": run["id"],
            "action_id": action["id"],
            "plan_sha256": workflow.record_hash(plan),
            "baseline_id": baseline["id"],
            "baseline_sha256": workflow.record_hash(baseline),
            "source_identity_sha256": workflow.record_hash(baseline["identity"]),
            "baseline_artifact_sha256": identity["sha256"],
            "dependency_lock_sha256": baseline_lock_hash,
            "flutter_toolchain": baseline_toolchain,
            "candidate_artifact_sha256": artifact_identity["sha256"],
            "candidate_artifact": str(candidate.resolve()),
            "symbols_tree_sha256": symbol_identity["tree_sha256"],
            "symbols_path": str(symbols.resolve()),
            "command": argv,
            "status": "built_unverified",
            "limitations": [
                "No Flutter AOT/package inspection evidence was supplied.",
                "No same-target Android behavior evidence was supplied.",
                "Build success does not establish protection.",
            ],
        }
        _write_snapshot_file(manifest_path, workflow.canonical(manifest))
        manifest_ref = {
            "path": str(manifest_path.resolve()),
            "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "kind": "flutter-candidate-manifest",
        }
        execution_id = "exec-" + stem[:24]
        verification_id = "verify-" + stem[:24]
        executed = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "execution",
            "id": execution_id,
            "run_id": run["id"],
            "plan_sha256": workflow.record_hash(plan),
            "action_id": action["id"],
            "commands": [argv],
            "exit_code": 0,
            "outputs": [candidate_ref],
            "engine": {
                "name": "flutter",
                "version": baseline_toolchain["flutter"]["framework_version"],
            },
            "source_sha256": identity["sha256"],
            "evidence": [manifest_ref, symbol_ref],
            "flutter_candidate": {
                key: value
                for key, value in manifest.items()
                if key not in {"limitations", "command"}
            },
        }
        checks = [
            {"id": check_id, "status": "blocked", "evidence": [manifest_ref]}
            for check_id in action["verification"]
        ]
        checked = {
            "schema_version": workflow.SCHEMA_VERSION,
            "record_type": "verification",
            "id": verification_id,
            "run_id": run["id"],
            "checks": checks,
        }
        workflow.write_record(records, executed)
        workflow.write_record(records, checked)
        current = workflow.validate_run(workflow.read_json(run_path))
        verifying = workflow.transition_run(
            current,
            "verifying",
            execution_id=execution_id,
            verification_id=verification_id,
        )
        workflow.write_run_state(run_path.parent, verifying, current)
        return {
            "status": "built_unverified",
            "run_id": run["id"],
            "action_id": action["id"],
            "candidate": str(candidate),
            "symbols": str(symbols),
            "candidate_sha256": artifact_identity["sha256"],
            "execution_id": execution_id,
            "verification_id": verification_id,
            "checks": checks,
            "accepted": False,
        }
    except BaseException as error:
        _remove_output(candidate)
        _remove_output(symbols)
        current = workflow.validate_run(workflow.read_json(run_path))
        if execution_started and current["state"] == "executing":
            if cancel_event is not None and cancel_event.is_set():
                changed = workflow.transition_run(
                    current, "cancelled", cancellation_reason="user_requested"
                )
            else:
                changed = workflow.transition_run(
                    current, "failed", error_code="flutter_candidate_build_failed"
                )
            workflow.write_run_state(run_path.parent, changed, current)
        if isinstance(error, workflow.WorkflowError):
            raise
        raise workflow.WorkflowError(
            f"Flutter obfuscated candidate build failed: {error}"
        ) from error
    finally:
        _remove_output(workspace)


def prepare_resume(store: str | Path, run_id: str, new_run_id: str) -> dict:
    """Start a fresh attempt only after revalidating saved inputs and refusing stale stage outputs."""
    root = workflow._private_directory(store)
    records, runs = root / "records", root / "runs"
    old_id = workflow._reference_id(run_id, "run id")
    new_id = workflow._reference_id(new_run_id, "new run id")
    if old_id == new_id:
        raise workflow.WorkflowError("Resume requires a new run id")
    previous = workflow.validate_run(workflow.read_json(runs / f"run-{old_id}.json"))
    if previous["state"] not in {"failed", "cancelled"} or not all(
        previous.get(key) for key in ("baseline_id", "plan_id", "decision_id")
    ):
        raise workflow.WorkflowError(
            "Only failed or cancelled runs with a bound plan can be resumed"
        )
    target = workflow.validate_target(
        workflow.read_record(records / f"target-{previous['target_id']}.json", "target")
    )
    baseline = workflow.validate_baseline_target(
        workflow.read_record(
            records / f"baseline-{previous['baseline_id']}.json", "baseline"
        ),
        target,
    )
    evidence_hash = baseline["identity"].get("evidence_sha256")
    captured_behavior = baseline["identity"].get("behavior")
    captured_e2e = baseline["identity"].get("e2e_behavior")
    captured_rea = baseline["identity"].get("rea_analysis")
    if not isinstance(baseline["identity"].get("build_snapshot"), dict):
        raise workflow.WorkflowError(
            "Resume requires a fresh baseline with a private build snapshot"
        )
    build_root = _verify_build_snapshot(baseline)
    evidence_specs = [
        (
            baseline["evidence"][0] if baseline["evidence"] else None,
            evidence_hash,
            baseline_capture._snapshot_argv(
                baseline["identity"].get("command", []),
                Path(target["source_root"]),
                build_root,
            ),
            "build",
        )
    ]
    if isinstance(captured_behavior, dict):
        if not isinstance(captured_behavior.get("snapshot_path"), str):
            raise workflow.WorkflowError(
                "Resume requires recapturing behavior with a private baseline snapshot"
            )
        behavior_argv = [
            str(
                Path(captured_behavior["snapshot_path"]) / captured_behavior["artifact"]
            )
            if arg == "{artifact}"
            else arg
            for arg in captured_behavior["command"]
        ]
        evidence_specs.append(
            (
                captured_behavior["evidence_path"],
                captured_behavior["evidence_sha256"],
                behavior_argv,
                "behavior",
            )
        )
    if isinstance(captured_e2e, dict):
        evidence_specs.append(
            (captured_e2e["report_path"], captured_e2e["report_sha256"], None, "e2e")
        )
    if isinstance(captured_rea, dict):
        evidence_specs.extend(
            (
                (
                    captured_rea["report_path"],
                    captured_rea["report_sha256"],
                    None,
                    "rea-report",
                ),
                (
                    captured_rea["bundle_path"],
                    captured_rea["bundle_sha256"],
                    None,
                    "rea-bundle",
                ),
            )
        )
    captured_engines = baseline["identity"].get("analysis_engines", {})
    captured_craft = (
        captured_engines.get("craft-anything")
        if isinstance(captured_engines, dict)
        else None
    )
    if isinstance(captured_craft, dict):
        for reference in (
            captured_craft.get("upstream_evidence"),
            captured_craft.get("evidence"),
        ):
            if isinstance(reference, dict):
                evidence_specs.append(
                    (reference.get("path"), reference.get("sha256"), None, "engine")
                )
    if (
        not isinstance(evidence_hash, str)
        or len(baseline["evidence"]) != len(evidence_specs)
        or [item[0] for item in evidence_specs] != baseline["evidence"]
        or any(
            not isinstance(item[1], str) or len(item[1]) != 64
            for item in evidence_specs
        )
    ):
        raise workflow.WorkflowError("Resume baseline evidence identity is missing")
    for evidence_path, expected_hash, expected_argv, kind in evidence_specs:
        try:
            evidence_bytes = workflow.verify_evidence_file(
                {"path": evidence_path, "sha256": expected_hash}
            )
            baseline_output = json.loads(evidence_bytes)
        except (workflow.WorkflowError, json.JSONDecodeError) as error:
            raise workflow.WorkflowError(
                f"Resume baseline evidence is invalid: {error}"
            ) from error
        if kind == "e2e":
            _verify_baseline_e2e(baseline, target, baseline_output)
        elif kind == "behavior":
            snapshot_identity = _snapshot_tree_identity(
                Path(captured_behavior["snapshot_path"])
            )
            if (
                snapshot_identity["tree_sha256"]
                != captured_behavior["snapshot_tree_sha256"]
                or snapshot_identity["file_scope_sha256"]
                != captured_behavior["snapshot_file_scope_sha256"]
            ):
                raise workflow.WorkflowError(
                    "Resume baseline behavior snapshot changed"
                )
        elif kind in {"rea-report", "rea-bundle", "engine"}:
            pass
        elif (
            not isinstance(baseline_output, dict)
            or baseline_output.get("exit_code") != 0
            or not isinstance(baseline_output.get("stdout"), str)
            or baseline_output.get("timed_out")
            or baseline_output.get("stdout_truncated")
            or baseline_output.get("stderr_truncated")
            or baseline_output.get("argv") != expected_argv
        ):
            raise workflow.WorkflowError(
                "Resume baseline evidence does not prove the saved build or behavior succeeded"
            )
    plan = workflow.validate_plan_baseline(
        workflow.read_record(records / f"plan-{previous['plan_id']}.json", "plan"),
        baseline,
    )
    decision = workflow.validate_decision(
        workflow.read_record(
            records / f"decision-{previous['decision_id']}.json", "decision"
        ),
        plan,
    )
    if (
        decision["decision"] != "approved"
        or decision["plan_sha256"] != workflow.record_hash(plan)
        or not decision["selected_action_ids"]
    ):
        raise workflow.WorkflowError(
            "Resume requires actions selected by the exact approved plan"
        )
    if isinstance(captured_rea, dict):
        _verify_baseline_rea(baseline, target)
    composite_actions = (
        workflow._validate_composite_actions(plan, decision["selected_action_ids"])
        if len(decision["selected_action_ids"]) > 1
        else None
    )
    selected_actions = composite_actions or [
        next(
            item
            for item in plan["actions"]
            if item["id"] == decision["selected_action_ids"][0]
        )
    ]
    for action_evidence in selected_actions:
        rea_reference = action_evidence.get("execution", {})
        if rea_reference.get("rea_baseline_report") and (
            not isinstance(captured_rea, dict)
            or rea_reference.get("rea_baseline_report") != captured_rea["report_path"]
            or rea_reference.get("rea_baseline_report_sha256")
            != captured_rea["report_sha256"]
            or rea_reference.get("rea_baseline_evidence_id")
            != captured_rea["evidence_id"]
        ):
            raise workflow.WorkflowError(
                "Resume plan REA baseline reference no longer matches its baseline"
            )
    action_id = decision["selected_action_ids"][0]
    action_ids = decision["selected_action_ids"]
    action = selected_actions[0]
    config = action.get("execution", {})
    source_map_action = (
        action.get("engine") == "release packaging candidate"
        and config.get("adapter") == "source-map-candidate"
    )
    bla_action = (
        action.get("engine") == "bla"
        and config.get("adapter") == "bla-js"
        and all(
            item.get("engine") == "bla"
            and item.get("execution", {}).get("adapter") == "bla-js"
            for item in selected_actions
        )
    )
    if not (source_map_action or bla_action):
        raise workflow.WorkflowError(
            "Resume supports only selected BLA JavaScript or source-map candidate actions"
        )
    composite_action = len(action_ids) > 1

    if not isinstance(target.get("source_root"), str) or not target["source_root"]:
        raise workflow.WorkflowError("Resume requires the saved project source root")
    source_root = Path(target["source_root"])
    try:
        _verify_live_project_inputs(target, source_root)
    except (OSError, discovery.DiscoveryError) as error:
        raise workflow.WorkflowError(
            f"Resume could not revalidate the current project: {error}"
        ) from error
    _verify_build_snapshot(baseline)

    if previous.get("execution_id") or previous.get("verification_id"):
        if not previous.get("execution_id") or not previous.get("verification_id"):
            raise workflow.WorkflowError(
                "Previous execution and verification identities are incomplete"
            )
        prior_execution = workflow.validate_evidence_record(
            workflow.read_record(
                records / f"execution-{previous['execution_id']}.json", "execution"
            ),
            "execution",
        )
        prior_verification = workflow.validate_evidence_record(
            workflow.read_record(
                records / f"verification-{previous['verification_id']}.json",
                "verification",
            ),
            "verification",
        )
        if (
            prior_execution["run_id"] != old_id
            or prior_execution["plan_sha256"] != workflow.record_hash(plan)
            or prior_verification["run_id"] != old_id
        ):
            raise workflow.WorkflowError(
                "Previous stage outputs are not bound to the resumed run and plan"
            )
        for reference in prior_execution.get("evidence", []):
            if (
                not isinstance(reference, dict)
                or not reference.get("path")
                or not reference.get("sha256")
            ):
                raise workflow.WorkflowError(
                    "Previous execution contains an invalid evidence reference"
                )
            workflow.verify_evidence_file(reference)
        for check in prior_verification["checks"]:
            if check["status"] == "passed":
                for reference in check["evidence"]:
                    workflow.verify_evidence_file(reference)
        for output in prior_execution["outputs"]:
            candidate = (
                Path(prior_execution["candidate_tree"]["path"])
                if composite_action
                and isinstance(prior_execution.get("candidate_tree"), dict)
                else Path(prior_execution["source_map_candidate"]["candidate_path"])
                if source_map_action
                and isinstance(prior_execution.get("source_map_candidate"), dict)
                else Path(output["path"])
            )
            candidates = root / "candidates"
            if candidate.parent.resolve(strict=False) == candidates.resolve(
                strict=False
            ) and (candidate.exists() or candidate.is_symlink()):
                raise workflow.WorkflowError(
                    "Resume refuses an active candidate from the previous attempt"
                )
        if previous["state"] == "cancelled" and prior_execution["outputs"]:
            expected_rollback = (
                "rollback-"
                + hashlib.sha256(
                    f"{old_id}:{prior_execution['id']}".encode()
                ).hexdigest()[:24]
            )
            rollback = workflow.validate_evidence_record(
                workflow.read_record(
                    records / f"rollback-{expected_rollback}.json", "rollback"
                ),
                "rollback",
            )
            if rollback["run_id"] != old_id or len(rollback["artifacts"]) != 1:
                raise workflow.WorkflowError(
                    "Cancelled attempt lacks a matching candidate quarantine record"
                )
            rollback_artifact = rollback["artifacts"][0]
            if composite_action:
                tree = prior_execution.get("candidate_tree")
                retained_path = Path(rollback_artifact.get("retained_path", ""))
                if (
                    not isinstance(tree, dict)
                    or rollback_artifact.get("path") != tree.get("path")
                    or rollback_artifact.get("kind") != "tree"
                    or rollback_artifact.get("sha256") != tree.get("tree_sha256")
                    or rollback_artifact.get("file_scope_sha256")
                    != tree.get("file_scope_sha256")
                    or retained_path.parent.resolve(strict=False)
                    != (root / "discarded").resolve(strict=True)
                ):
                    raise workflow.WorkflowError(
                        "Cancelled composite attempt lacks its matching tree quarantine record"
                    )
                _verify_rollback_artifact(retained_path, rollback_artifact)
            elif source_map_action:
                map_identity = prior_execution.get("source_map_candidate")
                retained_path = Path(rollback_artifact.get("retained_path", ""))
                if (
                    not isinstance(map_identity, dict)
                    or rollback_artifact.get("path")
                    != map_identity.get("candidate_path")
                    or rollback_artifact.get("kind") != "tree"
                    or rollback_artifact.get("sha256")
                    != map_identity.get("candidate_tree_sha256")
                    or rollback_artifact.get("file_scope_sha256")
                    != map_identity.get("candidate_file_scope_sha256")
                    or retained_path.parent.resolve(strict=False)
                    != (root / "discarded").resolve(strict=True)
                ):
                    raise workflow.WorkflowError(
                        "Cancelled source-map attempt lacks a matching tree quarantine record"
                    )
                _verify_rollback_artifact(retained_path, rollback_artifact)
            else:
                if (
                    rollback_artifact.get("sha256")
                    != prior_execution["outputs"][0]["sha256"]
                ):
                    raise workflow.WorkflowError(
                        "Cancelled attempt lacks a matching candidate quarantine record"
                    )
                workflow.verify_evidence_file(
                    {
                        "path": rollback_artifact["retained_path"],
                        "sha256": rollback_artifact["sha256"],
                    }
                )

    identity = workflow.record_hash(
        {
            "target_inventory": target["inventory"]["sha256"],
            "current_inventory": target["inventory"]["sha256"],
            "baseline_identity": baseline["identity"],
            "plan_sha256": workflow.record_hash(plan),
            "decision_sha256": workflow.record_hash(decision),
        }
    )
    resumed = {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "run",
        "id": new_id,
        "target_id": target["id"],
        "state": "discovered",
        "resume_of": old_id,
        "resume_identity_sha256": identity,
    }
    run_path = workflow.write_run_state(runs, resumed, None)
    baselining = workflow.transition_run(resumed, "baselining")
    workflow.write_run_state(run_path.parent, baselining, resumed)
    awaiting = workflow.submit_plan(baselining, target, baseline, plan)
    workflow.write_run_state(run_path.parent, awaiting, baselining)
    bound = workflow.bind_decision(awaiting, plan, decision)
    workflow.write_run_state(run_path.parent, bound, awaiting)
    preparing = workflow.start_execution(bound, plan, decision)
    workflow.write_run_state(run_path.parent, preparing, bound)
    return {
        "status": "resumed",
        "run_id": new_id,
        "resume_of": old_id,
        "action_id": action_id,
        "action_ids": action_ids,
        "resume_identity_sha256": identity,
        "state": preparing["state"],
    }


def _verify_baseline_e2e(baseline: dict, target: dict, report: dict) -> None:
    captured = baseline["identity"]["e2e_behavior"]
    try:
        adapter_path = _e2e_script()
        spec = importlib.util.spec_from_file_location(
            "anti_rea_resume_e2e", adapter_path
        )
        if spec is None or spec.loader is None:
            raise workflow.WorkflowError(
                "Pinned e2e validator is unavailable during resume"
            )
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        runtime, manifest = adapter.verify_runtime(captured["runtime_path"])
        if (
            adapter.require_supported_node() != manifest["node_version"]
            or hashlib.sha256(
                json.dumps(
                    manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest()
            != captured["runtime_manifest_sha256"]
        ):
            raise workflow.WorkflowError("Resume baseline e2e runtime identity changed")
        marker_path = runtime / "browser-chromium.json"
        if marker_path.is_symlink():
            raise workflow.WorkflowError("Resume baseline e2e browser marker is linked")
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if (
            marker.get("package_lock_sha256") != adapter.PIN["package_lock_sha256"]
            or marker.get("e2e_version") != adapter.PACKAGES["e2e"]
            or marker.get("web_engine_version") != adapter.PACKAGES["@e2e-dev/web"]
        ):
            raise workflow.WorkflowError(
                "Resume baseline e2e browser runtime identity changed"
            )
        adapter.validate_report(report, runtime)
        run = report["run"]
        results = [
            item
            for item in run["results"]
            if item.get("kind") == "test" and item.get("selected")
        ]
        test_ids = sorted(item["testId"] for item in results)
        targets = run.get("targets", [])
        browser_versions = {
            attempt.get("environment", {}).get("browser")
            for item in results
            for attempt in item.get("attempts", [])
        }
        summary = run.get("summary", {})
        if (
            report.get("schemaVersion") != "report-1"
            or run.get("status") != "passed"
            or run.get("exitCode") != 0
            or run.get("runner") != captured["runner"]
            or run.get("environment", {}).get("runtime")
            != f"node {manifest['node_version']}"
            or not test_ids
            or test_ids != captured["test_ids"]
            or any(item.get("status") != "passed" for item in results)
            or summary.get("executed") != len(results)
            or summary.get("passed") != len(results)
            or any(
                summary.get(key) != 0
                for key in ("failed", "interrupted", "flaky", "skipped")
            )
            or len(targets) != 1
            or targets[0].get("platform") != "web"
            or targets[0].get("engine")
            != {
                "name": "web",
                "version": adapter.PACKAGES["@e2e-dev/web"],
                "spiVersion": 1,
            }
            or len(browser_versions) != 1
            or not next(iter(browser_versions), "").startswith("chromium ")
        ):
            raise workflow.WorkflowError(
                "Resume baseline e2e report no longer proves the captured tests passed"
            )
        snapshot = Path(captured["snapshot_path"])
        identity = _snapshot_tree_identity(snapshot)
        if (
            identity["tree_sha256"] != captured["tree_sha256"]
            or identity["file_scope_sha256"] != captured["file_scope_sha256"]
            or baseline_capture._hash_artifact(snapshot, captured["source_path"])[
                "sha256"
            ]
            != captured["artifact_sha256"]
        ):
            raise workflow.WorkflowError("Resume baseline e2e snapshot changed")
        if captured[
            "cleanup"
        ] != "loopback app port closed" or not adapter._assert_server_stopped(
            targets[0].get("baseOrigin")
        ):
            raise workflow.WorkflowError(
                "Resume baseline e2e app server cleanup could not be verified"
            )
    except workflow.WorkflowError:
        raise
    except Exception as error:
        raise workflow.WorkflowError(
            "Resume baseline e2e evidence is malformed or unreadable"
        ) from error


def _verify_baseline_rea(baseline: dict, target: dict) -> None:
    captured = baseline["identity"]["rea_analysis"]
    try:
        adapter_path = _rea_script()
        spec = importlib.util.spec_from_file_location(
            "anti_rea_resume_rea", adapter_path
        )
        if spec is None or spec.loader is None:
            raise workflow.WorkflowError(
                "Pinned REA validator is unavailable during resume"
            )
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        runtime, manifest = adapter.verify_runtime(captured["runtime_path"])
        manifest_sha = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        report = workflow.verify_evidence_file(
            {"path": captured["report_path"], "sha256": captured["report_sha256"]}
        )
        bundle = workflow.verify_evidence_file(
            {"path": captured["bundle_path"], "sha256": captured["bundle_sha256"]}
        )
        summary, normalized, stats, coverage = adapter._analysis_summary(
            captured["report_path"]
        )
        snapshot = Path(captured["snapshot_path"])
        identity = _snapshot_tree_identity(snapshot)
        artifact = baseline_capture._hash_artifact(snapshot, captured["source_path"])
        if (
            hashlib.sha256(report).hexdigest() != captured["report_sha256"]
            or hashlib.sha256(bundle).hexdigest() != captured["bundle_sha256"]
            or manifest_sha != captured["runtime_manifest_sha256"]
            or identity["tree_sha256"] != captured["tree_sha256"]
            or identity["file_scope_sha256"] != captured["file_scope_sha256"]
            or artifact["sha256"] != captured["artifact_sha256"]
            or normalized["parent_evidence_id"] != captured["evidence_id"]
            or normalized["parent_digest"] != captured["parent_digest"]
            or normalized.get("artifact", {}).get("sha256")
            != captured["artifact_sha256"]
            or Path(normalized.get("artifact", {}).get("path", "")).resolve(strict=True)
            != snapshot.resolve(strict=True)
            or stats != captured["statistics"]
            or coverage != captured["coverage"]
        ):
            raise workflow.WorkflowError(
                "Resume baseline REA report, bundle, runtime, or snapshot identity changed"
            )
    except workflow.WorkflowError:
        raise
    except Exception as error:
        raise workflow.WorkflowError(
            "Resume baseline REA evidence is malformed or unreadable"
        ) from error


def discard_candidate(store: str | Path, run_id: str) -> dict:
    """Quarantine this run's unchanged isolated file or release-tree candidate."""
    root = workflow._private_directory(store).resolve(strict=True)
    records = root / "records"
    run_path = root / "runs" / f"run-{workflow._reference_id(run_id, 'run id')}.json"
    run = workflow.validate_run(workflow.read_json(run_path))
    if (
        run["state"] not in {"verifying", "completed"}
        and not (run["state"] == "blocked" and run.get("acceptance") == "rejected")
        or not run.get("execution_id")
    ):
        raise workflow.WorkflowError(
            "Candidate rollback requires a verifying, completed, or rejected run"
        )
    execution_record = workflow.read_record(
        records / f"execution-{run['execution_id']}.json", "execution"
    )
    if execution_record["run_id"] != run_id or len(execution_record["outputs"]) != 1:
        raise workflow.WorkflowError(
            "Rollback requires exactly one execution output bound to this run"
        )
    output = execution_record["outputs"][0]
    candidates = root / "candidates"
    source_map = execution_record.get("source_map_candidate")
    composite_tree = execution_record.get("candidate_tree")
    if isinstance(composite_tree, dict):
        candidate = Path(composite_tree.get("path", ""))
        if candidate.name in {"", ".", ".."}:
            raise workflow.WorkflowError("Composite rollback candidate path is invalid")
        expected_artifact = {
            "kind": "tree",
            "sha256": composite_tree.get("tree_sha256"),
            "file_scope_sha256": composite_tree.get("file_scope_sha256"),
        }
    elif isinstance(source_map, dict):
        candidate = Path(source_map.get("candidate_path", ""))
        if candidate.name in {"", ".", ".."}:
            raise workflow.WorkflowError(
                "Source-map rollback candidate path is invalid"
            )
        expected_artifact = {
            "kind": "tree",
            "sha256": source_map.get("candidate_tree_sha256"),
            "file_scope_sha256": source_map.get("candidate_file_scope_sha256"),
        }
    else:
        candidate = Path(output["path"])
        expected_artifact = {"sha256": output["sha256"]}
    if (
        candidates.is_symlink()
        or not candidates.is_dir()
        or candidate.parent.resolve(strict=False) != candidates.resolve(strict=True)
    ):
        raise workflow.WorkflowError(
            "Rollback output is outside the private candidate directory"
        )
    rollback_id = (
        "rollback-"
        + hashlib.sha256(f"{run_id}:{execution_record['id']}".encode()).hexdigest()[:24]
    )
    rollback_path = records / f"rollback-{rollback_id}.json"
    if rollback_path.exists():
        saved = workflow.read_record(rollback_path, "rollback")
        if not candidate.exists() and saved["run_id"] == run_id:
            retained_ref = saved["artifacts"][0]
            retained_path = Path(retained_ref["retained_path"])
            if (
                retained_path.parent.resolve(strict=True)
                != (root / "discarded").resolve(strict=True)
                or retained_ref.get("path") != str(candidate)
                or any(
                    retained_ref.get(key) != value
                    for key, value in expected_artifact.items()
                )
            ):
                raise workflow.WorkflowError(
                    "Retained rollback artifact identity is inconsistent"
                )
            _verify_rollback_artifact(retained_path, retained_ref)
            return {
                "status": "discarded",
                "run_id": run_id,
                "rollback_id": rollback_id,
                "candidate": str(candidate),
                "already_discarded": True,
                "retained_at": str(retained_path),
            }
        raise workflow.WorkflowError(
            "Rollback record exists but candidate state is inconsistent"
        )
    artifact = _verify_candidate_for_rollback(
        root,
        records,
        run,
        execution_record,
        candidate,
        output,
        expected_artifact,
        source_map is not None,
        composite_tree is not None,
    )
    discarded = workflow._private_directory(root / "discarded")
    retained = discarded / f"{rollback_id}{candidate.suffix}"
    if retained.exists() or retained.is_symlink():
        raise workflow.WorkflowError("Rollback retention path already exists")
    candidate.rename(retained)
    record = {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "rollback",
        "id": rollback_id,
        "run_id": run_id,
        "instructions": [
            "The isolated candidate was removed from the active candidate directory and retained privately for audit; the original project and baseline were not modified."
        ],
        "artifacts": [
            {
                "path": str(candidate),
                "retained_path": str(retained),
                **artifact,
                "action": "quarantined",
            }
        ],
    }
    try:
        _verify_rollback_artifact(retained, record["artifacts"][0])
        workflow.write_record(records, record)
    except BaseException:
        if retained.exists() and not candidate.exists():
            retained.rename(candidate)
        raise
    return {
        "status": "discarded",
        "run_id": run_id,
        "rollback_id": rollback_id,
        "candidate": str(candidate),
        "already_discarded": False,
        "retained_at": str(retained),
    }


def discard_candidate_if_active(store: str | Path, run_id: str) -> dict:
    """Quarantine this run's output only when it is inside Anti-REA's active candidate directory."""
    root = workflow._private_directory(store).resolve(strict=True)
    run_path = root / "runs" / f"run-{workflow._reference_id(run_id, 'run id')}.json"
    run = workflow.validate_run(workflow.read_json(run_path))
    if not run.get("execution_id"):
        return {"status": "no_active_candidate"}
    record = workflow.read_record(
        root / "records" / f"execution-{run['execution_id']}.json", "execution"
    )
    outputs = record.get("outputs", [])
    if record.get("run_id") != run_id or len(outputs) != 1:
        return {"status": "no_active_candidate"}
    candidates = root / "candidates"
    if candidates.is_symlink():
        raise workflow.WorkflowError(
            "Private candidate directory must not be a symlink"
        )
    composite_tree = record.get("candidate_tree")
    source_map = record.get("source_map_candidate")
    candidate = (
        Path(composite_tree.get("path", ""))
        if isinstance(composite_tree, dict)
        else Path(source_map.get("candidate_path", ""))
        if isinstance(source_map, dict)
        else Path(outputs[0]["path"])
    )
    try:
        if candidate.parent.resolve(strict=True) != candidates.resolve(strict=True):
            return {"status": "no_active_candidate"}
    except OSError:
        return {"status": "no_active_candidate"}
    if not candidate.exists() and not candidate.is_symlink():
        return {"status": "no_active_candidate"}
    return discard_candidate(root, run_id)


def _verify_candidate_for_rollback(
    root: Path,
    records: Path,
    run: dict,
    execution_record: dict,
    candidate: Path,
    output: dict,
    expected: dict,
    source_map: bool,
    composite_tree: bool = False,
) -> dict:
    candidates = root / "candidates"
    if (
        candidate.name in {"", ".", ".."}
        or candidates.is_symlink()
        or not candidates.is_dir()
        or candidate.parent.resolve(strict=True) != candidates.resolve(strict=True)
    ):
        raise workflow.WorkflowError(
            "Rollback output is outside the private candidate directory"
        )
    if composite_tree:
        target = workflow.read_record(
            records / f"target-{run['target_id']}.json", "target"
        )
        baseline = workflow.validate_baseline_target(
            workflow.read_record(
                records / f"baseline-{run['baseline_id']}.json", "baseline"
            ),
            target,
        )
        plan = workflow.validate_plan_baseline(
            workflow.read_record(records / f"plan-{run['plan_id']}.json", "plan"),
            baseline,
        )
        decision = workflow.read_record(
            records / f"decision-{run['decision_id']}.json", "decision"
        )
        search = None
        if decision.get("optimization_search_id"):
            search = workflow.read_record(
                records
                / f"optimization_search-{decision['optimization_search_id']}.json",
                "optimization_search",
            )
            search = workflow.validate_optimization_search(search, plan, baseline)
        decision = workflow.validate_decision(decision, plan, search)
        workflow._verify_composite_execution(
            run, baseline, plan, decision, execution_record, search
        )
        actual = _snapshot_tree_identity(candidate)
        if actual["tree_sha256"] != expected.get("sha256") or actual[
            "file_scope_sha256"
        ] != expected.get("file_scope_sha256"):
            raise workflow.WorkflowError(
                "Composite candidate tree changed before rollback"
            )
        return expected
    if not source_map:
        workflow.verify_evidence_file(
            {"path": str(candidate), "sha256": output["sha256"]}
        )
        return expected
    target = workflow.read_record(records / f"target-{run['target_id']}.json", "target")
    baseline = workflow.validate_baseline_target(
        workflow.read_record(
            records / f"baseline-{run['baseline_id']}.json", "baseline"
        ),
        target,
    )
    plan = workflow.validate_plan_baseline(
        workflow.read_record(records / f"plan-{run['plan_id']}.json", "plan"), baseline
    )
    references = [
        item
        for item in execution_record.get("evidence", [])
        if isinstance(item, dict) and item.get("kind") == "source-map-candidate"
    ]
    if (
        len(references) != 1
        or references[0].get("path") != output.get("path")
        or references[0].get("sha256") != output.get("sha256")
    ):
        raise workflow.WorkflowError(
            "Source-map rollback manifest is not bound to its execution output"
        )
    raw = workflow.verify_evidence_file(references[0])
    workflow._verify_source_map_check(
        plan, baseline, execution_record, [raw], references
    )
    actual = _snapshot_tree_identity(candidate)
    if actual["tree_sha256"] != expected.get("sha256") or actual[
        "file_scope_sha256"
    ] != expected.get("file_scope_sha256"):
        raise workflow.WorkflowError(
            "Source-map candidate tree changed before rollback"
        )
    return expected


def _verify_rollback_artifact(path: Path, artifact: dict) -> None:
    if artifact.get("kind") == "tree":
        if path.is_symlink() or not path.is_dir():
            raise workflow.WorkflowError("Retained rollback tree is missing or linked")
        actual = _snapshot_tree_identity(path)
        if actual["tree_sha256"] != artifact.get("sha256") or actual[
            "file_scope_sha256"
        ] != artifact.get("file_scope_sha256"):
            raise workflow.WorkflowError("Retained rollback tree hash mismatch")
    else:
        workflow.verify_evidence_file({"path": str(path), "sha256": artifact["sha256"]})


def _bla_script() -> Path:
    local = Path(__file__).resolve().parents[1] / "scripts/bla_integration.py"
    if local.is_file():
        return local
    installed = (
        Path(sysconfig.get_path("data")) / "share/anti-rea/scripts/bla_integration.py"
    )
    if not installed.is_file():
        raise workflow.WorkflowError("Packaged BLA adapter is missing")
    return installed


def _rea_script() -> Path:
    local = Path(__file__).resolve().parents[1] / "scripts/rea_integration.py"
    if local.is_file():
        return local
    installed = (
        Path(sysconfig.get_path("data")) / "share/anti-rea/scripts/rea_integration.py"
    )
    if not installed.is_file():
        raise workflow.WorkflowError("Packaged REA adapter is missing")
    return installed


def _e2e_script() -> Path:
    local = Path(__file__).resolve().parents[1] / "scripts/e2e_integration.py"
    if local.is_file():
        return local
    installed = (
        Path(sysconfig.get_path("data")) / "share/anti-rea/scripts/e2e_integration.py"
    )
    if not installed.is_file():
        raise workflow.WorkflowError("Packaged e2e adapter is missing")
    return installed


def _load_e2e_adapter(path: Path):
    spec = importlib.util.spec_from_file_location("anti_rea_e2e_performance", path)
    if spec is None or spec.loader is None:
        raise workflow.WorkflowError("Pinned e2e performance parser is unavailable")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


def _invoke(
    adapter: Path,
    arguments: list[str],
    timeout: float,
    cancel_event=None,
    on_process=None,
) -> dict:
    try:
        code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
            baseline_capture._run_command(
                [sys.executable, str(adapter), *arguments],
                adapter.parent,
                timeout,
                on_process,
                cancel_event,
            )
        )
    except subprocess.TimeoutExpired as error:
        raise workflow.WorkflowError("BLA adapter command timed out") from error
    if timed_out:
        raise workflow.WorkflowError("BLA adapter command timed out")
    if stdout_truncated or stderr_truncated:
        raise workflow.WorkflowError("BLA adapter output exceeded its capture budget")
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError("BLA adapter returned invalid JSON") from error
    if (
        code
        or not isinstance(payload, dict)
        or payload.get("status") != "passed"
        and payload.get("status") != "verified"
    ):
        raise workflow.WorkflowError(f"BLA adapter failed: {payload}")
    return payload


def _invoke_rea(
    adapter: Path,
    arguments: list[str],
    timeout: float,
    cancel_event=None,
    on_process=None,
) -> dict:
    try:
        code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
            baseline_capture._run_command(
                [sys.executable, str(adapter), *arguments],
                adapter.parent,
                timeout,
                on_process,
                cancel_event,
            )
        )
    except subprocess.TimeoutExpired as error:
        raise workflow.WorkflowError("REA comparison timed out") from error
    if timed_out or stdout_truncated or stderr_truncated:
        raise workflow.WorkflowError(
            "REA comparison timed out or exceeded its output budget"
        )
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError("REA comparison returned invalid JSON") from error
    if code or not isinstance(payload, dict) or payload.get("status") != "measured":
        raise workflow.WorkflowError(f"REA comparison failed: {payload}")
    return payload


def _invoke_e2e(
    adapter: Path,
    arguments: list[str],
    timeout: float,
    cancel_event=None,
    on_process=None,
) -> dict:
    try:
        code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
            baseline_capture._run_command(
                [sys.executable, str(adapter), *arguments],
                adapter.parent,
                timeout,
                on_process,
                cancel_event,
            )
        )
    except subprocess.TimeoutExpired as error:
        raise workflow.WorkflowError("e2e behavior run timed out") from error
    if timed_out or stdout_truncated or stderr_truncated:
        raise workflow.WorkflowError(
            "e2e behavior run timed out or exceeded its output budget"
        )
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        detail = stderr.decode("utf-8", errors="replace")[-2000:]
        raise workflow.WorkflowError(
            f"e2e adapter returned invalid JSON: {detail}"
        ) from error
    if (
        code
        or not isinstance(payload, dict)
        or payload.get("status") not in {"passed", "failed"}
        or not isinstance(payload.get("report"), str)
        or not isinstance(payload.get("report_sha256"), str)
        or payload.get("cleanup") != "loopback app port closed"
    ):
        raise workflow.WorkflowError(f"e2e behavior failed: {payload}")
    return payload


def _remove_output(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _retain_performance_trial(
    candidate: Path,
    evidence_dir: Path,
    report_stem: str,
    trial_index: int,
    expected_sha256: str,
    expected_size: int,
) -> dict:
    if candidate.is_symlink() or not candidate.is_file():
        raise workflow.WorkflowError(
            "BLA performance trial candidate must be a regular file"
        )
    contents = workflow.verify_evidence_file(
        {"path": str(candidate.resolve(strict=True)), "sha256": expected_sha256}
    )
    if len(contents) != expected_size:
        raise workflow.WorkflowError(
            "BLA performance trial size changed before evidence retention"
        )
    retained = (
        evidence_dir
        / f"{report_stem}-candidate-{trial_index}{candidate.suffix.lower()}"
    )
    try:
        _write_snapshot_file(retained, contents)
    except BaseException:
        _remove_output(retained)
        raise
    return {
        "path": str(retained.resolve(strict=True)),
        "sha256": expected_sha256,
        "kind": "performance-candidate",
    }


def _create_rea_snapshots(
    root: Path,
    target: dict,
    baseline: dict,
    source_relative: str,
    candidate: Path,
    candidate_sha256: str,
    source_sha256: str,
    before: Path,
    after: Path,
    cancel_event=None,
) -> dict:
    build_snapshot = baseline.get("identity", {}).get("build_snapshot")
    if not isinstance(build_snapshot, dict):
        raise workflow.WorkflowError(
            "REA comparison requires a private baseline build snapshot"
        )
    build_root = Path(build_snapshot["path"])
    _verify_build_snapshot(baseline)
    current = discovery.inspect_project(root)
    if current["unfollowed_symlinks"]:
        raise workflow.WorkflowError(
            "REA comparison requires a source tree without symlinks"
        )
    original_files = {item["path"]: item["sha256"] for item in target["files"]}
    current_files = {item["path"]: item for item in current["files"]}
    artifacts = baseline["identity"].get("artifacts", {})
    for path, digest in original_files.items():
        if (
            path not in artifacts
            and current_files.get(path, {}).get("sha256") != digest
        ):
            raise workflow.WorkflowError(
                f"Non-artifact source input changed after baseline: {path}"
            )
    if any(
        path not in original_files and path not in artifacts for path in current_files
    ):
        raise workflow.WorkflowError(
            "Project contains unbaselined files added since baseline capture"
        )
    for path, identity in artifacts.items():
        actual = baseline_capture._hash_artifact(build_root, path)
        if actual["sha256"] != identity["sha256"]:
            raise workflow.WorkflowError(
                f"Baselined artifact changed before REA comparison: {path}"
            )
    selected_identity = artifacts.get(source_relative)
    if (
        not isinstance(selected_identity, dict)
        or selected_identity.get("sha256") != source_sha256
    ):
        raise workflow.WorkflowError(
            "Selected REA artifact is not bound to the saved baseline"
        )

    before.mkdir(mode=0o700)
    after.mkdir(mode=0o700)
    try:
        for item in discovery.inspect_project(build_root)["files"]:
            path = item["path"]
            if path in artifacts:
                continue
            _copy_project_file(
                build_root,
                path,
                before / path,
                item["sha256"],
                item["size"],
                before,
                cancel_event,
            )
            _copy_project_file(
                build_root,
                path,
                after / path,
                item["sha256"],
                item["size"],
                after,
                cancel_event,
            )
        for path, identity in artifacts.items():
            if path != source_relative:
                _copy_project_file(
                    build_root,
                    path,
                    before / path,
                    identity["sha256"],
                    identity["size"],
                    before,
                    cancel_event,
                )
                _copy_project_file(
                    build_root,
                    path,
                    after / path,
                    identity["sha256"],
                    identity["size"],
                    after,
                    cancel_event,
                )
        _copy_project_file(
            build_root,
            source_relative,
            before / source_relative,
            selected_identity["sha256"],
            selected_identity["size"],
            before,
            cancel_event,
        )
    except BaseException:
        _remove_output(before)
        _remove_output(after)
        raise
    candidate_bytes = workflow.verify_evidence_file(
        {"path": str(candidate), "sha256": candidate_sha256}
    )
    if hashlib.sha256(candidate_bytes).hexdigest() == source_sha256:
        raise workflow.WorkflowError(
            "BLA candidate unexpectedly matches the original source bytes"
        )
    _write_snapshot_file(after / source_relative, candidate_bytes)
    before_identity = _snapshot_tree_identity(before)
    after_identity = _snapshot_tree_identity(after)
    if before_identity["file_scope_sha256"] != after_identity["file_scope_sha256"]:
        raise workflow.WorkflowError(
            "REA BEFORE/AFTER snapshots do not have identical file scope"
        )
    return {
        "before_tree_sha256": before_identity["tree_sha256"],
        "after_tree_sha256": after_identity["tree_sha256"],
        "file_scope_sha256": before_identity["file_scope_sha256"],
        "source_path": source_relative,
        "source_sha256": source_sha256,
        "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
    }


def _capture_craft_analysis_pair(
    before: Path,
    after: Path,
    *,
    state: Path,
    evidence_dir: Path,
    stem: str,
    cli: str | Path | None,
    baseline: dict,
    cancel_event=None,
    on_process=None,
) -> dict:
    """Run read-only Craft triage concurrently on the exact paired snapshots."""
    from core import craft_anything_integration

    def capture(side: str, snapshot: Path) -> dict:
        report_path = evidence_dir / f"{stem}-craft-{side}.json"
        try:
            result = craft_anything_integration.analyze(
                snapshot,
                state / "craft-anything" / stem / side,
                timeout=600,
                cli=str(cli) if cli is not None else None,
                report_path=report_path,
                cancel_event=cancel_event,
                on_process=on_process,
            )
        except Exception as error:
            return {
                "side": side,
                "status": "failed",
                "reason": str(error),
                "input_sha256": None,
                "evidence": None,
            }
        status = result.get("status")
        if status == "supported":
            status = "passed"
        raw_report = result.get("evidence_path")
        upstream_evidence = (
            {
                "path": raw_report,
                "sha256": hashlib.sha256(Path(raw_report).read_bytes()).hexdigest(),
                "kind": f"craft-anything-{side}-upstream",
            }
            if isinstance(raw_report, str) and Path(raw_report).is_file()
            else None
        )
        evidence_path = evidence_dir / f"{stem}-craft-{side}-record.json"
        envelope = {
            "schema_version": "1.0",
            "engine": "craft-anything",
            "side": side,
            "status": status,
            "version": result.get("version"),
            "mode": result.get("mode"),
            "input": result.get("input"),
            "coverage": (
                result.get("evidence", {}).get("coverage")
                if isinstance(result.get("evidence"), dict)
                else None
            ),
            "evidence": result.get("evidence"),
            "upstream_evidence": upstream_evidence,
            "reason": result.get("error"),
        }
        _write_snapshot_file(evidence_path, workflow.canonical(envelope) + b"\n")
        evidence = {
            "path": str(evidence_path.resolve()),
            "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            "kind": f"craft-anything-{side}",
        }
        return {
            "side": side,
            "status": status,
            "version": result.get("version"),
            "mode": result.get("mode"),
            "input_sha256": result.get("input", {}).get("sha256"),
            "coverage": (
                result.get("evidence", {}).get("coverage")
                if isinstance(result.get("evidence"), dict)
                else None
            ),
            "evidence": evidence,
            "upstream_evidence": upstream_evidence,
            "reason": result.get("error"),
        }

    with ThreadPoolExecutor(max_workers=2) as pool:
        before_future = pool.submit(capture, "before", before)
        after_future = pool.submit(capture, "after", after)
        before_result = before_future.result()
        after_result = after_future.result()
    captured_before = (
        baseline.get("identity", {})
        .get("analysis_engines", {})
        .get("craft-anything", {})
    )
    if captured_before.get("status") == "passed" and before_result.get(
        "input_sha256"
    ) != captured_before.get("input_sha256"):
        before_result.update(
            status="failed",
            reason="Paired BEFORE triage does not match the saved baseline input hash",
        )
    status = (
        "passed"
        if before_result["status"] == after_result["status"] == "passed"
        else "partial"
    )
    return {
        "engine": "craft-anything",
        "status": status,
        "before": before_result,
        "after": after_result,
    }


def _capture_rea_analysis_pair(
    runtime: Path | None,
    before: Path | None,
    after: Path | None,
    snapshot_identity: dict | None,
    baseline: dict,
    evidence_dir: Path,
    stem: str,
    timeout: float,
    cancel_event=None,
    on_process=None,
    *,
    source_path: str | None = None,
    source_sha256: str | None = None,
    candidate_sha256: str | None = None,
) -> tuple[dict, dict | None]:
    """Capture a paired REA analysis; non-gating failures stay reportable and partial."""
    baseline_engine = (
        baseline.get("identity", {}).get("analysis_engines", {}).get("rea", {})
    )
    if not baseline_engine:
        legacy = baseline.get("identity", {}).get("rea_analysis", {})
        baseline_engine = {
            "status": "passed" if legacy else "unavailable",
            "version": "6.8.0" if legacy else None,
            "input_sha256": legacy.get("input_sha256") if legacy else None,
            "coverage": legacy.get("coverage") if legacy else None,
            "evidence": (
                {
                    "path": legacy.get("report_path"),
                    "sha256": legacy.get("report_sha256"),
                }
                if legacy.get("report_path") and legacy.get("report_sha256")
                else None
            ),
        }
    before_result = {
        "side": "before",
        "status": baseline_engine.get("status", "unavailable"),
        "version": baseline_engine.get("version"),
        "input_sha256": baseline_engine.get("input_sha256"),
        "coverage": baseline_engine.get("coverage"),
        "evidence": baseline_engine.get("evidence"),
    }
    try:
        if (
            runtime is None
            or before is None
            or after is None
            or snapshot_identity is None
        ):
            raise workflow.WorkflowError(
                "REA comparison requires a verified runtime and paired snapshots"
            )
        output_dir = workflow._private_directory(evidence_dir / f"{stem}-rea")
        result = _invoke_rea(
            _rea_script(),
            [
                "compare-javascript",
                str(runtime),
                str(before),
                str(after),
                str(output_dir),
            ],
            timeout,
            cancel_event,
            on_process,
        )
        comparison_path = Path(result["report"])
        comparison_hash = result["report_sha256"]
        report = json.loads(
            workflow.verify_evidence_file(
                {"path": str(comparison_path), "sha256": comparison_hash}
            )
        )
        if (
            report.get("status") != "measured"
            or report.get("before_tree_sha256")
            != snapshot_identity["before_tree_sha256"]
            or report.get("after_tree_sha256") != snapshot_identity["after_tree_sha256"]
        ):
            raise workflow.WorkflowError(
                "REA comparison does not match this run's project snapshots"
            )
        comparison = {
            "path": str(comparison_path),
            "sha256": comparison_hash,
            "before_snapshot": str(before),
            "after_snapshot": str(after),
            **snapshot_identity,
            "runtime_manifest_sha256": report["runtime_manifest_sha256"],
        }
        if source_path is not None:
            comparison.update(
                source_path=source_path,
                source_sha256=source_sha256,
                candidate_sha256=candidate_sha256,
            )
        pair = {
            "engine": "rea",
            "status": "passed",
            "before": before_result,
            "after": {
                "side": "after",
                "status": "passed",
                "version": baseline_engine.get("version", "6.8.0"),
                "input_sha256": report.get("after_tree_sha256"),
                "coverage": report.get("coverage"),
                "evidence": {
                    "path": str(comparison_path),
                    "sha256": comparison_hash,
                    "kind": "rea-comparison",
                },
            },
        }
        return pair, comparison
    except Exception as error:
        if cancel_event is not None and cancel_event.is_set():
            raise
        if (
            isinstance(error, workflow.WorkflowError)
            and "cancelled" in str(error).lower()
        ):
            raise
        return (
            {
                "engine": "rea",
                "status": "partial",
                "before": before_result,
                "after": {
                    "side": "after",
                    "status": "failed",
                    "version": baseline_engine.get("version"),
                    "input_sha256": None,
                    "reason": str(error),
                },
                "reason": str(error),
            },
            None,
        )


def _create_composite_snapshots(
    baseline_root: Path,
    baseline: dict,
    candidate_root: Path,
    before: Path,
    after: Path,
    cancel_event=None,
) -> dict:
    """Create full-project paired snapshots so final checks observe every composed action."""
    _verify_build_snapshot(baseline)
    before.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    before.mkdir(mode=0o700)
    after.mkdir(mode=0o700)
    try:
        for item in discovery.inspect_project(baseline_root)["files"]:
            _copy_project_file(
                baseline_root,
                item["path"],
                before / item["path"],
                item["sha256"],
                item["size"],
                before,
                cancel_event,
            )
        for item in discovery.inspect_project(candidate_root)["files"]:
            _copy_project_file(
                candidate_root,
                item["path"],
                after / item["path"],
                item["sha256"],
                item["size"],
                after,
                cancel_event,
            )
    except BaseException:
        _remove_output(before)
        _remove_output(after)
        raise
    before_identity = _snapshot_tree_identity(before)
    after_identity = _snapshot_tree_identity(after)
    if before_identity["file_scope_sha256"] != after_identity["file_scope_sha256"]:
        raise workflow.WorkflowError(
            "Composite BEFORE/AFTER snapshots do not have identical file scope"
        )
    return {
        "before_tree_sha256": before_identity["tree_sha256"],
        "after_tree_sha256": after_identity["tree_sha256"],
        "file_scope_sha256": before_identity["file_scope_sha256"],
    }


def _run_behavior_check(
    command: list[str],
    snapshot: Path,
    source_path: str,
    stem: str,
    on_process,
    cancel_event,
    timeout: float,
    evidence_dir: Path,
    kind: str,
) -> dict:
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(arg, str) or not arg for arg in command)
        or command.count("{artifact}") != 1
        or kind not in {"behavior-source", "behavior-candidate"}
    ):
        raise workflow.WorkflowError(
            "Invalid composite application behavior configuration"
        )
    argv = [
        str(snapshot / source_path) if arg == "{artifact}" else arg for arg in command
    ]
    code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
        baseline_capture._run_command(argv, snapshot, timeout, on_process, cancel_event)
    )
    path = evidence_dir / f"{stem}.json"
    baseline_capture._write_output(
        path,
        argv,
        code,
        stdout,
        stderr,
        time.time(),
        timed_out,
        stdout_truncated,
        stderr_truncated,
    )
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "kind": kind,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "status": "passed"
        if code == 0 and not timed_out and not stdout_truncated and not stderr_truncated
        else "failed",
    }


def _verify_build_snapshot(baseline: dict) -> Path:
    identity = baseline.get("identity", {}).get("build_snapshot")
    if not isinstance(identity, dict):
        raise workflow.WorkflowError("Baseline has no private build snapshot")
    root = Path(identity["path"])
    actual = _snapshot_tree_identity(root)
    if (
        actual["tree_sha256"] != identity["tree_sha256"]
        or actual["file_scope_sha256"] != identity["file_scope_sha256"]
    ):
        raise workflow.WorkflowError("Baseline build snapshot changed")
    for path, expected in baseline["identity"]["artifacts"].items():
        if baseline_capture._hash_artifact(root, path) != expected:
            raise workflow.WorkflowError(
                f"Baseline build snapshot artifact changed: {path}"
            )
    return root


def _verify_live_project_inputs(target: dict, root: Path) -> None:
    current = discovery.inspect_project(root)
    if current["unfollowed_symlinks"]:
        raise workflow.WorkflowError("Project source contains symlinks")
    if current["source_identity"] != target["source_identity"]:
        raise workflow.WorkflowError("Project source revision changed since discovery")
    expected = {item["path"]: item["sha256"] for item in target.get("files", [])}
    actual = {item["path"]: item["sha256"] for item in current["files"]}
    if any(path not in expected for path in actual):
        raise workflow.WorkflowError("project files added since discovery")
    if any(path not in actual for path in expected):
        raise workflow.WorkflowError("project files removed since discovery")
    if actual != expected:
        changed = next(
            (
                path
                for path in sorted(expected.keys() | actual.keys())
                if expected.get(path) != actual.get(path)
            ),
            "inventory",
        )
        raise workflow.WorkflowError(
            f"Non-artifact source input changed after baseline: {changed}"
        )


def _copy_project_file(
    root: Path,
    relative: str,
    destination: Path,
    expected_hash: str,
    expected_size: int,
    destination_root: Path,
    cancel_event=None,
) -> None:
    parts = Path(relative).parts
    if Path(relative).is_absolute() or not parts or ".." in parts:
        raise workflow.WorkflowError("Snapshot file path escapes project root")
    if not hasattr(os, "O_NOFOLLOW"):
        raise workflow.WorkflowError(
            "Safe REA snapshots are unavailable on this platform"
        )
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    destination_root = Path(os.path.abspath(destination_root))
    destination = Path(os.path.abspath(destination))
    try:
        destination_parts = destination.relative_to(destination_root).parts
    except ValueError as error:
        raise workflow.WorkflowError(
            "Snapshot destination escapes its private root"
        ) from error
    if (
        not destination_parts
        or ".." in destination_parts
        or destination_root.is_symlink()
        or not destination_root.is_dir()
    ):
        raise workflow.WorkflowError("Snapshot destination escapes its private root")
    directory = os.open(root, flags | getattr(os, "O_DIRECTORY", 0))
    opened = [directory]
    output = None
    complete = False
    try:
        if cancel_event is not None and cancel_event.is_set():
            raise workflow.WorkflowError("Command cancelled")
        destination_directory = os.open(
            destination_root, flags | getattr(os, "O_DIRECTORY", 0)
        )
        opened.append(destination_directory)
        for part in parts[:-1]:
            directory = os.open(
                part, flags | getattr(os, "O_DIRECTORY", 0), dir_fd=directory
            )
            opened.append(directory)
        source = os.open(
            parts[-1], flags | getattr(os, "O_NONBLOCK", 0), dir_fd=directory
        )
        opened.append(source)
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise workflow.WorkflowError(
                f"Snapshot input is not a regular file: {relative}"
            )
        for part in destination_parts[:-1]:
            try:
                child = os.open(
                    part,
                    flags | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=destination_directory,
                )
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=destination_directory)
                child = os.open(
                    part,
                    flags | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=destination_directory,
                )
            destination_directory = child
            opened.append(child)
        output = os.open(
            destination_parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destination_directory,
        )
        opened.append(output)
        os.fchmod(output, 0o600 | (stat.S_IMODE(before.st_mode) & stat.S_IXUSR))
        digest, size = hashlib.sha256(), 0
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise workflow.WorkflowError("Command cancelled")
            chunk = os.read(source, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            view = memoryview(chunk)
            while view:
                if cancel_event is not None and cancel_event.is_set():
                    raise workflow.WorkflowError("Command cancelled")
                written = os.write(output, view)
                if not written:
                    raise OSError("Snapshot write made no progress")
                view = view[written:]
        if cancel_event is not None and cancel_event.is_set():
            raise workflow.WorkflowError("Command cancelled")
        after = os.fstat(source)

        def identity(item):
            return (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if (
            identity(before) != identity(after)
            or size != expected_size
            or digest.hexdigest() != expected_hash
        ):
            os.unlink(destination_parts[-1], dir_fd=destination_directory)
            raise workflow.WorkflowError(
                f"Snapshot input changed since discovery: {relative}"
            )
        os.fsync(output)
        if cancel_event is not None and cancel_event.is_set():
            raise workflow.WorkflowError("Command cancelled")
        complete = True
    except BaseException:
        if output is not None and not complete:
            try:
                os.unlink(destination_parts[-1], dir_fd=destination_directory)
            except FileNotFoundError:
                pass
        raise
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _write_snapshot_file(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        view = memoryview(contents)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def _snapshot_tree_identity(root: Path) -> dict[str, str]:
    manifest = discovery.inspect_project(root)
    if manifest["unfollowed_symlinks"]:
        raise workflow.WorkflowError("REA snapshot unexpectedly contains symlinks")
    files = sorted(manifest["files"], key=lambda item: item["path"])
    tree = hashlib.sha256()
    for item in files:
        tree.update(item["path"].encode() + b"\0" + bytes.fromhex(item["sha256"]))
    scope = hashlib.sha256(
        "\n".join(item["path"] for item in files).encode()
    ).hexdigest()
    return {"tree_sha256": tree.hexdigest(), "file_scope_sha256": scope}
