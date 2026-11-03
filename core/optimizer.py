"""Bounded Pareto review for an explicitly approved set of completed candidates."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import statistics
import time
from pathlib import Path

from core import workflow

_HASH = re.compile(r"^[a-f0-9]{64}$")
MAX_CANDIDATES = 4


def validate_search_space(
    store: str | Path, search: dict, decision_source: str
) -> dict:
    """Bind proposed candidate combinations and budgets to the exact saved plan."""
    if not isinstance(search, dict):
        raise workflow.WorkflowError("Optimization search proposal must be an object")
    if not isinstance(decision_source, str) or not decision_source.strip():
        raise workflow.WorkflowError(
            "Optimization search approval requires an explicit decision source"
        )
    root = workflow._private_directory(store)
    plan_id = workflow._reference_id(
        search.get("plan_id"), "optimization search plan id"
    )
    baseline_id = workflow._reference_id(
        search.get("baseline_id"), "optimization search baseline id"
    )
    plan = workflow.read_record(root / "records" / f"plan-{plan_id}.json", "plan")
    baseline = workflow.read_record(
        root / "records" / f"baseline-{baseline_id}.json", "baseline"
    )
    return workflow.validate_optimization_search(
        {**search, "decision_source": decision_source}, plan, baseline
    )


def generate_search_proposal(store: str | Path, template: dict) -> dict:
    """Expand selected plan actions and supplied compatible pairs into a bounded proposal only."""
    if not isinstance(template, dict) or "candidate_sets" in template:
        raise workflow.WorkflowError(
            "Candidate generation requires a search template without candidate_sets"
        )
    generation = template.get("candidate_generation")
    if not isinstance(generation, dict):
        raise workflow.WorkflowError("Search template requires candidate_generation")
    root = workflow._private_directory(store)
    plan_id = workflow._reference_id(
        template.get("plan_id"), "optimization search plan id"
    )
    plan = workflow.read_record(root / "records" / f"plan-{plan_id}.json", "plan")
    scoped_ids = generation.get("action_ids")
    costs = generation.get("estimated_cost_micros_by_action")
    proofs = generation.get("compatibility_evidence", [])
    if (
        not isinstance(scoped_ids, list)
        or not 1 <= len(scoped_ids) <= 4
        or any(not isinstance(item, str) for item in scoped_ids)
        or len(set(scoped_ids)) != len(scoped_ids)
        or not isinstance(costs, dict)
        or set(costs) != set(scoped_ids)
        or any(
            isinstance(cost, bool) or not isinstance(cost, int) or cost < 0
            for cost in costs.values()
        )
        or not isinstance(proofs, list)
    ):
        raise workflow.WorkflowError(
            "Candidate generation requires one to four unique actions, per-action cost estimates, and pair evidence"
        )
    actions = {
        action["id"]: action for action in workflow.validate_plan(plan)["actions"]
    }
    for action_id in scoped_ids:
        action = actions.get(action_id)
        required = {"bla_invariants", "performance", "rea_comparison"}
        if (
            not action
            or action.get("engine") != "bla"
            or not isinstance(action.get("execution"), dict)
            or action["execution"].get("adapter") != "bla-js"
            or not required <= set(action.get("verification", []))
            or not set(action.get("verification", [])).intersection(
                {"application_behavior", "e2e_behavior"}
            )
        ):
            raise workflow.WorkflowError(
                f"Candidate generation action is not an eligible verified BLA JavaScript action: {action_id}"
            )
    ordered_ids = [
        action["id"] for action in plan["actions"] if action["id"] in scoped_ids
    ]
    candidates = []

    def add(action_ids: list[str], evidence: list[dict]) -> None:
        identifier = hashlib.sha256(workflow.canonical(action_ids)).hexdigest()[:16]
        candidates.append(
            {
                "id": f"candidate-{identifier}",
                "action_ids": action_ids,
                "estimated_cost_micros": sum(
                    costs[action_id] for action_id in action_ids
                ),
                "compatibility_evidence": evidence,
            }
        )

    for action_id in ordered_ids:
        add([action_id], [])
    pairs_seen = set()
    normalized_proofs = []
    for item in proofs:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("action_ids"), list)
            or len(item["action_ids"]) != 2
            or any(
                not isinstance(action_id, str) or not workflow._ID.fullmatch(action_id)
                for action_id in item.get("action_ids", [])
            )
            or not isinstance(item.get("evidence"), dict)
        ):
            raise workflow.WorkflowError(
                "Compatibility evidence must identify one action pair"
            )
        pair = tuple(sorted(item["action_ids"]))
        if (
            len(set(pair)) != 2
            or not set(pair) <= set(ordered_ids)
            or pair in pairs_seen
        ):
            raise workflow.WorkflowError(
                "Compatibility evidence must identify a unique pair within the selected action scope"
            )
        pairs_seen.add(pair)
        action_ids = [action_id for action_id in ordered_ids if action_id in pair]
        workflow._validate_composite_actions(plan, action_ids)
        normalized_proofs.append(
            (action_ids, {"action_ids": list(pair), "evidence": item["evidence"]})
        )
    normalized_proofs.sort(
        key=lambda entry: [ordered_ids.index(action_id) for action_id in entry[0]]
    )
    # shortcut: only propose singles and evidenced pairs, generate higher-order sets when searches require them.
    for action_ids, proof in normalized_proofs:
        add(action_ids, [proof])
    if not 1 <= len(candidates) <= 4:
        raise workflow.WorkflowError(
            "Generated candidate count exceeds the four-candidate search limit; narrow the selected scope or pair evidence"
        )
    proposal = {
        key: value for key, value in template.items() if key != "candidate_generation"
    }
    proposal["candidate_sets"] = candidates
    return validate_search_space(store, proposal, proposal.get("decision_source", ""))


def approve_search_space(store: str | Path, search: dict, decision_source: str) -> dict:
    """Persist a user-approved, bounded search scope for the future executor."""
    approved = validate_search_space(store, search, decision_source)
    path = workflow.write_record(
        workflow._private_directory(store) / "records", approved
    )
    return {
        "status": "approved",
        "id": approved["id"],
        "plan_sha256": approved["plan_sha256"],
        "baseline_sha256": approved["baseline_sha256"],
        "source_identity_sha256": approved["source_identity_sha256"],
        "runtime_identities": approved["runtime_identities"],
        "candidate_sets": approved["candidate_sets"],
        "record": path.name,
        "search_sha256": workflow.record_hash(approved),
    }


class _SearchDeadline:
    def __init__(self, deadline: float, external=None):
        self.deadline, self.external = deadline, external

    def is_set(self) -> bool:
        return self.deadline_expired() or self.cancelled()

    def deadline_expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def cancelled(self) -> bool:
        return bool(self.external and self.external.is_set())


def _search_runtime_identity(path: str | Path, engine: str) -> str:
    from core import execution

    adapter_path = {
        "bla-agents": execution._bla_script(),
        "rea": execution._rea_script(),
        "e2e": execution._e2e_script(),
    }[engine]
    spec = importlib.util.spec_from_file_location(
        f"anti_rea_search_{engine}", adapter_path
    )
    if spec is None or spec.loader is None:
        raise workflow.WorkflowError(f"Pinned {engine} adapter could not be loaded")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    _, manifest = adapter.verify_runtime(path)
    if engine == "bla-agents":
        return manifest["package_tree_sha256"]
    return hashlib.sha256(workflow.canonical(manifest)).hexdigest()


def execute_approved_search(
    store: str | Path,
    search_id: str,
    runtime: str | Path | None = None,
    rea_runtime: str | Path | None = None,
    e2e_runtime: str | Path | None = None,
    cancel_event=None,
    on_process=None,
) -> dict:
    """Run approved BLA candidate sets in order under the saved wall-clock limits."""
    from core import execution

    root = workflow._private_directory(store)
    records = workflow._private_directory(root / "records")
    runs = workflow._private_directory(root / "runs")
    search = workflow.read_record(
        records
        / f"optimization_search-{workflow._reference_id(search_id, 'optimization search id')}.json",
        "optimization_search",
    )
    existing_results = []
    for path in records.glob("optimization_search_result-*.json"):
        saved = workflow.read_record(path, "optimization_search_result")
        if saved["search_id"] == search["id"]:
            report = {
                key: value
                for key, value in saved.items()
                if key not in {"id", "schema_version", "record_type"}
            }
            expected_id = (
                "optresult-"
                + hashlib.sha256(workflow.canonical(report)).hexdigest()[:24]
            )
            if saved["id"] != expected_id:
                raise workflow.WorkflowError(
                    "Persisted approved-search result identity is invalid"
                )
            existing_results.append(saved)
    if len(existing_results) > 1:
        raise workflow.WorkflowError(
            "Approved search has conflicting persisted runner results"
        )
    if existing_results:
        saved = existing_results[0]
        path = records / f"optimization_search_result-{saved['id']}.json"
        return {
            **{
                key: value
                for key, value in saved.items()
                if key not in {"schema_version", "record_type"}
            },
            "result_id": saved["id"],
            "result_record": path.name,
            "result_sha256": workflow.record_hash(saved),
        }
    plan = workflow.read_record(records / f"plan-{search['plan_id']}.json", "plan")
    baseline = workflow.read_record(
        records / f"baseline-{search['baseline_id']}.json", "baseline"
    )
    target = workflow.read_record(
        records / f"target-{search['target_id']}.json", "target"
    )
    runtime = runtime or os.environ.get("ANTI_REA_BLA_RUNTIME")
    rea_runtime = rea_runtime or os.environ.get("ANTI_REA_REA_RUNTIME")
    e2e_runtime = e2e_runtime or os.environ.get("ANTI_REA_E2E_RUNTIME")
    if not runtime:
        raise workflow.WorkflowError(
            "Approved search execution requires its pinned BLA runtime"
        )
    started = time.monotonic()
    global_deadline = started + search["budgets"]["max_total_elapsed_ms"] / 1000
    expected_runtimes = search["runtime_identities"]
    supplied = {"bla-agents": runtime, "rea": rea_runtime, "e2e": e2e_runtime}
    for engine, expected in expected_runtimes.items():
        path = supplied[engine]
        if not path and engine == "e2e":
            e2e = baseline.get("identity", {}).get("e2e_behavior")
            path = e2e.get("runtime_path") if isinstance(e2e, dict) else None
        if not path or _search_runtime_identity(path, engine) != expected:
            raise workflow.WorkflowError(
                f"Approved search {engine} runtime identity is missing or changed"
            )
        supplied[engine] = path

    outcome_by_id = {}
    accepted_runs: dict[str, str] = {}
    measured_count = 0

    def mark_remaining(reason: str, candidates: list[dict]) -> None:
        for item in candidates:
            outcome_by_id.setdefault(
                item["id"], {"candidate_id": item["id"], "status": reason}
            )

    for candidate_index, candidate in enumerate(search["candidate_sets"]):
        candidate_id = candidate["id"]
        if cancel_event is not None and cancel_event.is_set():
            outcome_by_id[candidate_id] = {
                "candidate_id": candidate_id,
                "status": "cancelled",
            }
            mark_remaining(
                "not_evaluated_cancelled",
                search["candidate_sets"][candidate_index + 1 :],
            )
            break
        if time.monotonic() >= global_deadline:
            outcome_by_id[candidate_id] = {
                "candidate_id": candidate_id,
                "status": "not_evaluated_budget",
            }
            mark_remaining(
                "not_evaluated_budget", search["candidate_sets"][candidate_index + 1 :]
            )
            break
        candidate_started = time.monotonic()
        candidate_deadline = min(
            global_deadline,
            candidate_started + search["budgets"]["max_elapsed_ms"] / 1000,
        )
        deadline_event = _SearchDeadline(candidate_deadline, cancel_event)
        identity = hashlib.sha256(
            f"{workflow.record_hash(search)}:{candidate_id}".encode()
        ).hexdigest()[:24]
        run_id, decision_id = f"searchrun-{identity}", f"searchdecision-{identity}"
        run_path = runs / f"run-{run_id}.json"
        created_run = False
        try:
            preflight = execution.validate_approved_candidate_set(
                root, search["id"], candidate_id
            )
            if (
                workflow.record_hash(preflight["search"])
                != workflow.record_hash(search)
                or workflow.record_hash(preflight["plan"]) != workflow.record_hash(plan)
                or workflow.record_hash(preflight["baseline"])
                != workflow.record_hash(baseline)
            ):
                raise workflow.WorkflowError(
                    "Approved search inputs changed during candidate preflight"
                )
            checks = set(preflight["actions"][0]["verification"])
            if not {
                "bla_invariants",
                "performance",
                "rea_comparison",
            } <= checks or not checks.intersection(
                {"application_behavior", "e2e_behavior"}
            ):
                raise workflow.WorkflowError(
                    "Optimization candidates require BLA, performance, REA, and behavior verification"
                )
            if run_path.exists() or run_path.is_symlink():
                raise workflow.WorkflowError(
                    f"Approved search candidate already has a run: {candidate_id}"
                )
            run = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "run",
                "id": run_id,
                "target_id": target["id"],
                "state": "discovered",
            }
            workflow.write_run_state(runs, run, None)
            created_run = True
            state = workflow.transition_run(run, "baselining")
            workflow.write_run_state(runs, state, run)
            awaiting = workflow.transition_run(
                state,
                "awaiting_decision",
                baseline_id=baseline["id"],
                plan_id=plan["id"],
            )
            workflow.write_run_state(runs, awaiting, state)
            decision = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "decision",
                "id": decision_id,
                "plan_sha256": search["plan_sha256"],
                "selected_action_ids": candidate["action_ids"],
                "decision": "approved",
                "decision_source": f"approved optimization search {search['id']} candidate {candidate_id}",
                "optimization_search_id": search["id"],
                "optimization_search_sha256": workflow.record_hash(search),
                "optimization_candidate_id": candidate_id,
            }
            workflow.write_record(records, decision)
            bound = workflow.bind_decision(
                awaiting, plan, decision, optimization_search=search
            )
            workflow.write_run_state(runs, bound, awaiting)
            preparing = workflow.start_execution(
                bound, plan, decision, optimization_search=search
            )
            workflow.write_run_state(runs, preparing, bound)
            if len(candidate["action_ids"]) == 1:
                result = execution.execute_bla_action(
                    root,
                    run_id,
                    candidate["action_ids"][0],
                    supplied["bla-agents"],
                    deadline_event,
                    on_process,
                    supplied.get("rea"),
                    supplied.get("e2e"),
                    search,
                )
            else:
                result = execution.execute_approved_candidate_set(
                    root,
                    run_id,
                    search["id"],
                    candidate_id,
                    supplied["bla-agents"],
                    supplied.get("rea"),
                    supplied.get("e2e"),
                    deadline_event,
                    on_process,
                )
            if deadline_event.cancelled():
                current = workflow.validate_run(workflow.read_json(run_path))
                if current["state"] in {"preparing", "executing", "verifying"}:
                    cancelled = workflow.transition_run(
                        current, "cancelled", cancellation_reason="user_requested"
                    )
                    workflow.write_run_state(runs, cancelled, current)
                outcome_by_id[candidate_id] = {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "status": "cancelled",
                    "elapsed_ms": max(
                        1, int((time.monotonic() - candidate_started) * 1000)
                    ),
                }
                mark_remaining(
                    "not_evaluated_cancelled",
                    search["candidate_sets"][candidate_index + 1 :],
                )
                break
            if deadline_event.deadline_expired():
                current = workflow.validate_run(workflow.read_json(run_path))
                if current["state"] in {"preparing", "executing", "verifying"}:
                    failed = workflow.transition_run(
                        current,
                        "failed",
                        error_code="optimization_time_budget_exceeded",
                    )
                    workflow.write_run_state(runs, failed, current)
                outcome_by_id[candidate_id] = {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "status": "over_budget",
                    "elapsed_ms": max(
                        1, int((time.monotonic() - candidate_started) * 1000)
                    ),
                }
                if time.monotonic() >= global_deadline:
                    mark_remaining(
                        "not_evaluated_budget",
                        search["candidate_sets"][candidate_index + 1 :],
                    )
                    break
                continue
            if result.get("status") == "rejected":
                measured_count += 1
                elapsed_ms = max(1, int((time.monotonic() - candidate_started) * 1000))
                outcome_by_id[candidate_id] = {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "status": "rejected",
                    "elapsed_ms": elapsed_ms,
                    "reason": result.get("reason", "verification_rejected"),
                }
                continue
            current = workflow.validate_run(workflow.read_json(run_path))
            if current["state"] != "verifying" or result.get("status") != "verifying":
                raise workflow.WorkflowError(
                    "Approved search candidate did not reach semantic verification"
                )
            if deadline_event.cancelled():
                cancelled = workflow.transition_run(
                    current, "cancelled", cancellation_reason="user_requested"
                )
                workflow.write_run_state(runs, cancelled, current)
                outcome_by_id[candidate_id] = {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "status": "cancelled",
                    "elapsed_ms": max(
                        1, int((time.monotonic() - candidate_started) * 1000)
                    ),
                }
                mark_remaining(
                    "not_evaluated_cancelled",
                    search["candidate_sets"][candidate_index + 1 :],
                )
                break
            if deadline_event.deadline_expired():
                failed = workflow.transition_run(
                    current, "failed", error_code="optimization_time_budget_exceeded"
                )
                workflow.write_run_state(runs, failed, current)
                outcome_by_id[candidate_id] = {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "status": "over_budget",
                    "elapsed_ms": max(
                        1, int((time.monotonic() - candidate_started) * 1000)
                    ),
                }
                if time.monotonic() >= global_deadline:
                    mark_remaining(
                        "not_evaluated_budget",
                        search["candidate_sets"][candidate_index + 1 :],
                    )
                    break
                continue
            execution_record = workflow.read_record(
                records / f"execution-{current['execution_id']}.json", "execution"
            )
            verification = workflow.read_record(
                records / f"verification-{current['verification_id']}.json",
                "verification",
            )
            acceptance = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "acceptance",
                "id": f"searchaccept-{identity}",
                "run_id": run_id,
                "outcome": "accepted",
                "claims": [],
                "claim_ids": workflow.acceptance_claim_ids(
                    [
                        check["id"]
                        for check in verification["checks"]
                        if check["status"] == "passed"
                    ]
                ),
                "reasons": [
                    "The approved candidate passed its recorded verification gates."
                ],
                "verification_id": verification["id"],
                "execution_id": execution_record["id"],
                "plan_sha256": search["plan_sha256"],
            }
            accepted = workflow.accept_run(
                current,
                target,
                baseline,
                plan,
                decision,
                execution_record,
                verification,
                acceptance,
                optimization_search=search,
            )
            elapsed_ms = max(1, int((time.monotonic() - candidate_started) * 1000))
            measured_count += 1
            if deadline_event.cancelled():
                stopped = workflow.transition_run(
                    current, "cancelled", cancellation_reason="user_requested"
                )
                workflow.write_run_state(runs, stopped, current)
                outcome_by_id[candidate_id] = {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "status": "cancelled",
                    "elapsed_ms": elapsed_ms,
                }
                mark_remaining(
                    "not_evaluated_cancelled",
                    search["candidate_sets"][candidate_index + 1 :],
                )
                break
            if (
                elapsed_ms > search["budgets"]["max_elapsed_ms"]
                or deadline_event.deadline_expired()
            ):
                failed = workflow.transition_run(
                    current, "failed", error_code="optimization_time_budget_exceeded"
                )
                workflow.write_run_state(runs, failed, current)
                outcome_by_id[candidate_id] = {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "status": "over_budget",
                    "elapsed_ms": elapsed_ms,
                }
                if time.monotonic() >= global_deadline:
                    mark_remaining(
                        "not_evaluated_budget",
                        search["candidate_sets"][candidate_index + 1 :],
                    )
                    break
                continue
            candidate_bytes = result.get("candidate_bytes")
            if candidate_bytes is None and result.get("candidate"):
                candidate_bytes = Path(result["candidate"]).stat().st_size
            workflow.write_record(records, acceptance)
            workflow.write_run_state(runs, accepted, current)
            accepted_runs[candidate_id] = run_id
            outcome_by_id[candidate_id] = {
                "candidate_id": candidate_id,
                "run_id": run_id,
                "status": "accepted",
                "elapsed_ms": elapsed_ms,
                "candidate_bytes": candidate_bytes,
                "candidate_tree_sha256": (
                    result.get("candidate_tree_sha256")
                    or result.get("candidate_sha256")
                ),
            }
            if search["stop_conditions"]["stop_on_first_acceptable"]:
                mark_remaining(
                    "not_evaluated_stop_condition",
                    search["candidate_sets"][
                        search["candidate_sets"].index(candidate) + 1 :
                    ],
                )
                break
        except Exception as error:
            was_cancelled = bool(cancel_event and cancel_event.is_set())
            timed_out = deadline_event.deadline_expired()
            if created_run and run_path.is_file() and not run_path.is_symlink():
                current = workflow.validate_run(workflow.read_json(run_path))
                if current["state"] in {"preparing", "executing", "verifying"}:
                    if was_cancelled:
                        stopped = workflow.transition_run(
                            current, "cancelled", cancellation_reason="user_requested"
                        )
                    else:
                        code = (
                            "optimization_time_budget_exceeded"
                            if timed_out
                            else "optimization_candidate_failed"
                        )
                        stopped = workflow.transition_run(
                            current, "failed", error_code=code
                        )
                    workflow.write_run_state(runs, stopped, current)
            outcome_by_id[candidate_id] = {
                "candidate_id": candidate_id,
                "run_id": run_id,
                "status": "cancelled"
                if was_cancelled
                else "over_budget"
                if timed_out
                else "failed",
                "elapsed_ms": max(
                    1, int((time.monotonic() - candidate_started) * 1000)
                ),
                "reason": str(error)[:500],
            }
            if not created_run:
                outcome_by_id[candidate_id]["failure_phase"] = "preflight"
            if was_cancelled or timed_out:
                if was_cancelled or time.monotonic() >= global_deadline:
                    mark_remaining(
                        "not_evaluated_cancelled"
                        if was_cancelled
                        else "not_evaluated_budget",
                        search["candidate_sets"][candidate_index + 1 :],
                    )
                    break
                continue

    outcomes = [
        outcome_by_id[candidate["id"]] for candidate in search["candidate_sets"]
    ]
    measured = (
        _review_approved_search(root, search["id"], accepted_runs, enforce_stop=False)
        if accepted_runs
        else None
    )
    total_elapsed_ms = max(1, int((time.monotonic() - started) * 1000))
    if total_elapsed_ms > search["budgets"]["max_total_elapsed_ms"]:
        status = "budget_exhausted"
    elif any(
        item["status"] == "accepted" and item.get("candidate_id") in accepted_runs
        for item in outcomes
    ):
        status = "candidates_available"
    elif measured_count:
        status = "no_acceptable_candidate"
    else:
        status = "not_evaluated"
    report = {
        "status": status,
        "search_id": search["id"],
        "search_sha256": workflow.record_hash(search),
        "budgets": search["budgets"],
        "candidate_results": outcomes,
        "accepted_run_ids": accepted_runs,
        "review": measured,
        "total_elapsed_ms": total_elapsed_ms,
        "actual_cost_status": "unavailable; approved estimates only",
    }
    result_record = {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "optimization_search_result",
        "id": "optresult-"
        + hashlib.sha256(workflow.canonical(report)).hexdigest()[:24],
        **report,
    }
    result_path = workflow.write_record(records, result_record)
    return {
        **report,
        "result_id": result_record["id"],
        "result_record": result_path.name,
        "result_sha256": workflow.record_hash(result_record),
    }


def _validated_search_result(
    store: str | Path, search: dict, candidate_runs: dict[str, str]
) -> dict:
    """Require a persisted runner report and replay every evaluated outcome against run state."""
    root = workflow._private_directory(store)
    matches = []
    for path in (root / "records").glob("optimization_search_result-*.json"):
        result = workflow.read_record(path, "optimization_search_result")
        if result["search_id"] == search["id"]:
            matches.append(result)
    if len(matches) != 1:
        raise workflow.WorkflowError(
            "Selection requires exactly one persisted approved-search runner result"
        )
    result = matches[0]
    if (
        result["search_sha256"] != workflow.record_hash(search)
        or result["accepted_run_ids"] != candidate_runs
    ):
        raise workflow.WorkflowError(
            "Runner result does not match the approved search and accepted run mapping"
        )
    if [item.get("candidate_id") for item in result["candidate_results"]] != [
        item["id"] for item in search["candidate_sets"]
    ]:
        raise workflow.WorkflowError(
            "Runner result does not preserve approved candidate order"
        )
    stop_seen = False
    for item in result["candidate_results"]:
        status, candidate_id, run_id = (
            item.get("status"),
            item["candidate_id"],
            item.get("run_id"),
        )
        if stop_seen and status not in {"not_evaluated_stop_condition"}:
            raise workflow.WorkflowError(
                "Runner chronology violates stop-on-first-acceptable"
            )
        if status == "accepted":
            if run_id != candidate_runs.get(candidate_id):
                raise workflow.WorkflowError(
                    "Accepted runner outcome is not bound to its run"
                )
            _accepted_run_measurement(store, run_id, search)
            if search["stop_conditions"]["stop_on_first_acceptable"]:
                stop_seen = True
        elif status == "rejected":
            if not run_id:
                raise workflow.WorkflowError("Rejected chronology has no persisted run")
            run = workflow.validate_run(
                workflow.read_json(root / "runs" / f"run-{run_id}.json")
            )
            if run["state"] != "blocked" or run.get("acceptance") != "rejected":
                raise workflow.WorkflowError(
                    "Rejected runner outcome disagrees with current run state"
                )
            workflow.assemble_run_report(root / "records", run)
        elif status in {"failed", "over_budget"}:
            if not run_id:
                raise workflow.WorkflowError(
                    "Failed chronology has no deterministic run identity"
                )
            run_path = root / "runs" / f"run-{run_id}.json"
            if run_path.exists():
                run = workflow.validate_run(workflow.read_json(run_path))
                if (
                    run["state"] != "failed"
                    or status == "over_budget"
                    and run.get("error_code") != "optimization_time_budget_exceeded"
                ):
                    raise workflow.WorkflowError(
                        "Failed runner outcome disagrees with current run state"
                    )
                if run.get("plan_id"):
                    workflow.assemble_run_report(root / "records", run)
            elif item.get("failure_phase") != "preflight":
                raise workflow.WorkflowError(
                    "Failed chronology has no persisted failed run state"
                )
            else:
                from core import execution

                execution.validate_approved_candidate_set(
                    root, search["id"], candidate_id
                )
        elif status.startswith("not_evaluated"):
            if run_id:
                raise workflow.WorkflowError(
                    "Unevaluated candidate unexpectedly references a run"
                )
            if (
                search["stop_conditions"]["stop_on_first_acceptable"]
                and not stop_seen
                and candidate_runs
            ):
                raise workflow.WorkflowError(
                    "Runner result does not prove earlier candidate failure chronology"
                )
        elif status == "cancelled":
            if run_id:
                run = workflow.validate_run(
                    workflow.read_json(root / "runs" / f"run-{run_id}.json")
                )
                if run["state"] != "cancelled":
                    raise workflow.WorkflowError(
                        "Cancelled runner outcome disagrees with current run state"
                    )
            if candidate_runs and search["stop_conditions"]["stop_on_first_acceptable"]:
                raise workflow.WorkflowError(
                    "A cancelled candidate cannot precede an accepted selection"
                )
        else:
            raise workflow.WorkflowError(
                "Runner result contains an unsupported outcome"
            )
    if (
        search["stop_conditions"]["stop_on_first_acceptable"]
        and candidate_runs
        and not stop_seen
    ):
        raise workflow.WorkflowError(
            "Runner result does not prove stop-on-first-acceptable chronology"
        )
    return result


def review_candidates(
    approved_ids: list[str], measurements: list[dict], budgets: dict
) -> dict:
    """Filter correctness/integrity failures and return the size/time Pareto frontier.

    Candidate production and independent winner reevaluation remain the caller's
    responsibility; this function only reviews completed, comparable measurements.
    """
    if (
        not isinstance(approved_ids, list)
        or not 1 <= len(approved_ids) <= MAX_CANDIDATES
        or any(not isinstance(item, str) or not item for item in approved_ids)
        or len(set(approved_ids)) != len(approved_ids)
    ):
        raise workflow.WorkflowError(
            "Optimization requires one to four unique approved candidate ids"
        )
    if not isinstance(budgets, dict):
        raise workflow.WorkflowError("Optimization budgets must be an object")
    max_elapsed = budgets.get("max_elapsed_ms")
    max_total = budgets.get("max_total_elapsed_ms")
    max_bytes = budgets.get("max_candidate_bytes")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (max_elapsed, max_total, max_bytes)
    ):
        raise workflow.WorkflowError(
            "Optimization requires positive per-candidate, total-time, and size budgets"
        )
    if not isinstance(measurements, list) or len(measurements) > len(approved_ids):
        raise workflow.WorkflowError(
            "Candidate results exceed the approved search space"
        )
    by_id = {}
    run_ids = set()
    for item in measurements:
        if not isinstance(item, dict):
            raise workflow.WorkflowError("Candidate measurements must be objects")
        candidate_id = item.get("candidate_id")
        if (
            candidate_id not in approved_ids
            or candidate_id in by_id
            or not isinstance(item.get("run_id"), str)
            or not item["run_id"]
            or not isinstance(item.get("source_sha256"), str)
            or not _HASH.fullmatch(item["source_sha256"])
            or not isinstance(item.get("runtime_sha256"), str)
            or not _HASH.fullmatch(item["runtime_sha256"])
            or not isinstance(item.get("artifact_sha256"), str)
            or not _HASH.fullmatch(item["artifact_sha256"])
            or not isinstance(item.get("evidence"), dict)
            or not isinstance(item["evidence"].get("path"), str)
            or not isinstance(item["evidence"].get("sha256"), str)
            or not _HASH.fullmatch(item["evidence"]["sha256"])
        ):
            raise workflow.WorkflowError(
                "Candidate identity or evidence is invalid or outside the approved search space"
            )
        if item["run_id"] in run_ids:
            raise workflow.WorkflowError(
                "Each optimization candidate must have a distinct execution run"
            )
        for key in ("elapsed_ms", "candidate_bytes"):
            if (
                isinstance(item.get(key), bool)
                or not isinstance(item.get(key), int)
                or item[key] <= 0
            ):
                raise workflow.WorkflowError(
                    f"Candidate {key} must be a positive integer"
                )
        if any(
            not isinstance(item.get(key), bool)
            for key in ("correctness_passed", "integrity_passed")
        ):
            raise workflow.WorkflowError(
                "Candidate correctness and integrity results must be explicit booleans"
            )
        try:
            proof = json.loads(workflow.verify_evidence_file(item["evidence"]))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise workflow.WorkflowError(
                "Candidate optimization evidence is invalid JSON"
            ) from error
        fields = (
            "candidate_id",
            "run_id",
            "source_sha256",
            "runtime_sha256",
            "artifact_sha256",
            "correctness_passed",
            "integrity_passed",
            "elapsed_ms",
            "candidate_bytes",
        )
        if (
            not isinstance(proof, dict)
            or proof.get("schema_version") != "1.0"
            or proof.get("record_type") != "optimizer_candidate_measurement"
            or any(proof.get(key) != item.get(key) for key in fields)
        ):
            raise workflow.WorkflowError(
                "Candidate measurements do not match their hash-checked report"
            )
        by_id[candidate_id] = item
        run_ids.add(item["run_id"])
    identities = {
        (item["source_sha256"], item["runtime_sha256"]) for item in by_id.values()
    }
    if len(identities) > 1:
        raise workflow.WorkflowError(
            "Optimization candidates must share source and runtime identities"
        )

    return _review_validated(
        approved_ids, by_id, budgets, "caller_supplied_measurements_untrusted"
    )


def _review_validated(
    approved_ids: list[str],
    by_id: dict[str, dict],
    budgets: dict,
    provenance_status: str,
) -> dict:
    """Apply the bounded search to measurements that were validated by a caller."""
    max_elapsed, max_total, max_bytes = (
        budgets["max_elapsed_ms"],
        budgets["max_total_elapsed_ms"],
        budgets["max_candidate_bytes"],
    )
    total_elapsed = sum(item["elapsed_ms"] for item in by_id.values())
    rejected = []
    acceptable = []
    for candidate_id in approved_ids:
        item = by_id.get(candidate_id)
        if item is None:
            rejected.append({"candidate_id": candidate_id, "reason": "not_evaluated"})
        elif not item["correctness_passed"] or not item["integrity_passed"]:
            rejected.append(
                {
                    "candidate_id": candidate_id,
                    "reason": "correctness_or_integrity_failed",
                }
            )
        elif item["elapsed_ms"] > max_elapsed or item["candidate_bytes"] > max_bytes:
            rejected.append(
                {"candidate_id": candidate_id, "reason": "candidate_over_budget"}
            )
        else:
            acceptable.append(item)
    if total_elapsed > max_total:
        return {
            "schema_version": "1.0",
            "record_type": "optimization_review",
            "status": "budget_exhausted",
            "approved_candidate_ids": approved_ids,
            "provenance_status": provenance_status,
            "candidate_count": len(by_id),
            "total_elapsed_ms": total_elapsed,
            "budgets": budgets,
            "rejected": rejected
            + [
                {
                    "candidate_id": item["candidate_id"],
                    "reason": "total_search_time_exceeded",
                }
                for item in acceptable
            ],
            "pareto_frontier": [],
            "selection": None,
            "independent_reevaluation_required": True,
        }

    frontier = [
        item
        for item in acceptable
        if not any(
            other is not item
            and other["elapsed_ms"] <= item["elapsed_ms"]
            and other["candidate_bytes"] <= item["candidate_bytes"]
            and (
                other["elapsed_ms"] < item["elapsed_ms"]
                or other["candidate_bytes"] < item["candidate_bytes"]
            )
            for other in acceptable
        )
    ]
    frontier.sort(
        key=lambda item: (
            item["elapsed_ms"],
            item["candidate_bytes"],
            item["candidate_id"],
        )
    )
    return {
        "schema_version": "1.0",
        "record_type": "optimization_review",
        "status": "candidates_available"
        if frontier
        else "no_acceptable_candidate"
        if by_id
        else "not_evaluated",
        "provenance_status": provenance_status,
        "approved_candidate_ids": approved_ids,
        "candidate_count": len(by_id),
        "total_elapsed_ms": total_elapsed,
        "budgets": budgets,
        "rejected": rejected,
        "pareto_frontier": [
            {
                "candidate_id": item["candidate_id"],
                "run_id": item["run_id"],
                "elapsed_ms": item["elapsed_ms"],
                "candidate_bytes": item["candidate_bytes"],
                "artifact_sha256": item["artifact_sha256"],
                "source_sha256": item["source_sha256"],
                "runtime_sha256": item["runtime_sha256"],
                "evidence_sha256": item.get(
                    "evidence_sha256", item.get("evidence", {}).get("sha256")
                ),
                **(
                    {
                        "acceptance_id": item["acceptance_id"],
                        "accepted_record_sha256": item["accepted_record_sha256"],
                        "target_id": item["target_id"],
                        "plan_sha256": item["plan_sha256"],
                        "action_id": item["action_id"],
                        "elapsed_trials_ms": item["elapsed_trials_ms"],
                        "candidate_size_trials": item["candidate_size_trials"],
                    }
                    if "accepted_record_sha256" in item
                    else {}
                ),
            }
            for item in frontier
        ],
        "selection": None,
        "independent_reevaluation_required": True,
    }


def _accepted_run_measurement(
    store: str | Path, run_id: str, optimization_search: dict | None = None
) -> dict:
    """Revalidate a completed run and derive optimizer metrics from its accepted evidence."""
    from core import workflow

    workflow._reference_id(run_id, "optimizer run id")
    supplied_root = Path(store).expanduser()
    if supplied_root.is_symlink() or not supplied_root.is_dir():
        raise workflow.WorkflowError(
            "Optimizer store must be an existing real directory"
        )
    root = supplied_root.resolve(strict=True)
    runs, records = root / "runs", root / "records"
    private_dirs = (root, runs, records, root / "evidence", root / "candidates")
    if any(path.is_symlink() or not path.is_dir() for path in private_dirs):
        raise workflow.WorkflowError(
            "Optimizer store, run, evidence, candidate, and record directories must be real directories"
        )
    if os.name != "nt" and any(
        path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077
        for path in private_dirs
    ):
        raise workflow.WorkflowError(
            "Optimizer workflow state must be private to the current user"
        )
    run = workflow.validate_run(workflow.read_json(runs / f"run-{run_id}.json"))
    if run.get("state") != "completed" or run.get("acceptance") != "accepted":
        raise workflow.WorkflowError(
            f"Optimizer candidate run is not accepted: {run_id}"
        )

    def load(kind: str, identifier: str) -> dict:
        return workflow.read_record(
            records / f"{kind}-{workflow._reference_id(identifier, kind + ' id')}.json",
            kind,
        )

    try:
        target = load("target", run["target_id"])
        baseline = load("baseline", run["baseline_id"])
        plan = load("plan", run["plan_id"])
        decision = load("decision", run["decision_id"])
        execution = load("execution", run["execution_id"])
        verification = load("verification", run["verification_id"])
        acceptance = load("acceptance", run["acceptance_id"])
    except OSError as error:
        raise workflow.WorkflowError(
            "Accepted optimizer run is missing a persisted workflow record"
        ) from error
    pending = {
        key: value
        for key, value in run.items()
        if key not in {"acceptance", "acceptance_id"}
    }
    pending["state"] = "verifying"
    accepted = workflow.accept_run(
        pending,
        target,
        baseline,
        plan,
        decision,
        execution,
        verification,
        acceptance,
        optimization_search=optimization_search,
    )
    if workflow.record_hash(accepted) != workflow.record_hash(run):
        raise workflow.WorkflowError(
            "Persisted optimizer run differs from its revalidated acceptance bundle"
        )
    engine = execution.get("engine")
    composite = len(decision.get("selected_action_ids", [])) > 1
    if (
        decision.get("decision") != "approved"
        or not isinstance(engine, dict)
        or engine.get("name") != "bla-agents"
        or not isinstance(engine.get("version"), str)
        or not engine["version"]
        or not isinstance(engine.get("package_tree_sha256"), str)
        or not _HASH.fullmatch(engine["package_tree_sha256"])
        or len(execution.get("outputs", [])) != 1
        or composite
        and not isinstance(execution.get("optimization_measurements"), dict)
        or not composite
        and not isinstance(execution.get("performance"), dict)
    ):
        raise workflow.WorkflowError(
            "Optimizer requires an accepted, measured BLA candidate run"
        )
    selected_action_ids = decision["selected_action_ids"]
    if composite and execution.get("action_ids") != selected_action_ids:
        raise workflow.WorkflowError(
            "Composite optimizer run differs from its approved action set"
        )
    action = next(
        (item for item in plan["actions"] if item.get("id") == selected_action_ids[0]),
        None,
    )
    config = action.get("execution") if action else None
    if (
        not isinstance(config, dict)
        or config.get("adapter") != "bla-js"
        or not composite
        and execution.get("action_id") != selected_action_ids[0]
    ):
        raise workflow.WorkflowError(
            "Optimizer run is not a selected BLA JavaScript action"
        )
    checks = {item["id"]: item for item in verification["checks"]}
    if (
        checks.get("bla_invariants", {}).get("status") != "passed"
        or checks.get("performance", {}).get("status") != "passed"
    ):
        raise workflow.WorkflowError(
            "Optimizer run must pass BLA invariant and performance gates"
        )
    if not any(
        checks.get(check_id, {}).get("status") == "passed"
        for check_id in ("application_behavior", "e2e_behavior")
    ):
        raise workflow.WorkflowError(
            "Optimizer candidates require a passing comparable application_behavior or e2e_behavior check"
        )
    if checks.get("rea_comparison", {}).get("status") != "passed":
        raise workflow.WorkflowError(
            "Optimizer candidates require a passing rea_comparison check"
        )
    if composite:
        measures = execution["optimization_measurements"]
        tree = execution.get("candidate_tree")
        if (
            not isinstance(tree, dict)
            or not isinstance(tree.get("tree_sha256"), str)
            or not _HASH.fullmatch(tree["tree_sha256"])
            or any(
                isinstance(measures.get(key), bool)
                or not isinstance(measures.get(key), int)
                or measures[key] <= 0
                for key in ("elapsed_ms", "candidate_bytes")
            )
        ):
            raise workflow.WorkflowError(
                "Composite optimizer measurements or candidate tree identity are invalid"
            )
        return {
            "candidate_id": run_id,
            "run_id": run_id,
            "target_id": target["id"],
            "baseline_sha256": workflow.record_hash(baseline),
            "source_sha256": workflow.record_hash(baseline["identity"]),
            "runtime_sha256": engine["package_tree_sha256"],
            "artifact_sha256": tree["tree_sha256"],
            "correctness_passed": True,
            "integrity_passed": True,
            "plan_sha256": execution["plan_sha256"],
            "action_id": selected_action_ids[0],
            "action_ids": selected_action_ids,
            "elapsed_ms": measures["elapsed_ms"],
            "candidate_bytes": measures["candidate_bytes"],
            "acceptance_id": acceptance["id"],
            "accepted_record_sha256": hashlib.sha256(
                workflow.canonical(acceptance)
            ).hexdigest(),
            "evidence_sha256": workflow.record_hash(execution),
        }
    reports = [
        item
        for item in execution.get("evidence", [])
        if isinstance(item, dict) and item.get("kind") == "performance"
    ]
    perf_refs = [
        item
        for item in checks["performance"]["evidence"]
        if isinstance(item, dict) and item.get("kind") == "performance"
    ]
    if len(reports) != 1 or perf_refs != reports:
        raise workflow.WorkflowError(
            "Optimizer performance report is not bound to the accepted execution"
        )
    evidence_dir = root / "evidence"
    try:
        performance_path = Path(reports[0]["path"]).resolve(strict=True)
    except OSError as error:
        raise workflow.WorkflowError(
            "Accepted optimizer performance report is missing"
        ) from error
    if performance_path.parent != evidence_dir.resolve(strict=True):
        raise workflow.WorkflowError(
            "Accepted optimizer performance report is outside private workflow evidence"
        )
    raw = workflow.verify_evidence_file(reports[0])
    try:
        performance = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError(
            "Accepted performance report is invalid JSON"
        ) from error
    if performance != execution["performance"]:
        raise workflow.WorkflowError(
            "Accepted execution performance metadata differs from its report"
        )
    output = execution["outputs"][0]
    candidate = Path(output["path"])
    candidates = root / "candidates"
    if (
        candidates.is_symlink()
        or not candidates.is_dir()
        or candidate.is_symlink()
        or not candidate.is_file()
        or candidate.resolve(strict=True).parent != candidates.resolve(strict=True)
    ):
        raise workflow.WorkflowError(
            "Accepted optimizer artifact is outside the private candidate directory"
        )
    candidate_bytes_raw = workflow.verify_evidence_file(output)
    samples = performance.get("trials")
    if (
        not isinstance(samples, list)
        or len(samples) != 3
        or samples[0].get("candidate_sha256") != output["sha256"]
        or samples[0].get("candidate_bytes") != len(candidate_bytes_raw)
    ):
        raise workflow.WorkflowError(
            "Accepted optimizer trials do not identify the retained candidate artifact"
        )
    timings = [sample["elapsed_ms"] for sample in samples]
    sizes = [sample["candidate_bytes"] for sample in samples]
    return {
        "candidate_id": run_id,
        "run_id": run_id,
        "target_id": target["id"],
        "baseline_sha256": workflow.record_hash(baseline),
        "source_sha256": execution["source_sha256"],
        "runtime_sha256": execution["engine"]["package_tree_sha256"],
        "artifact_sha256": output["sha256"],
        "correctness_passed": True,
        "integrity_passed": True,
        "plan_sha256": execution["plan_sha256"],
        "action_id": execution["action_id"],
        "elapsed_ms": int(statistics.median(timings)),
        "candidate_bytes": len(candidate_bytes_raw),
        "acceptance_id": acceptance["id"],
        "accepted_record_sha256": hashlib.sha256(
            workflow.canonical(acceptance)
        ).hexdigest(),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "elapsed_trials_ms": {
            "min": min(timings),
            "median": statistics.median(timings),
            "max": max(timings),
        },
        "candidate_size_trials": {
            "min": min(sizes),
            "median": statistics.median(sizes),
            "max": max(sizes),
        },
    }


def review_accepted_runs(store: str | Path, run_ids: list[str], budgets: dict) -> dict:
    """Review only persisted, accepted BLA candidate runs; IDs are the approved search set."""
    from core import workflow

    if (
        not isinstance(run_ids, list)
        or not 1 <= len(run_ids) <= MAX_CANDIDATES
        or any(not isinstance(item, str) for item in run_ids)
        or len(set(run_ids)) != len(run_ids)
    ):
        raise workflow.WorkflowError(
            "Optimization requires one to four unique approved candidate run ids"
        )
    if not isinstance(budgets, dict):
        raise workflow.WorkflowError("Optimization budgets must be an object")
    measurements = [_accepted_run_measurement(store, run_id) for run_id in run_ids]
    identities = {
        (item["source_sha256"], item["runtime_sha256"]) for item in measurements
    }
    if len(identities) > 1:
        raise workflow.WorkflowError(
            "Accepted optimizer runs must share source and runtime identities"
        )
    if len({item["target_id"] for item in measurements}) != 1:
        raise workflow.WorkflowError(
            "Accepted optimizer runs must share the same target identity"
        )
    if len({item["action_id"] for item in measurements}) != 1:
        raise workflow.WorkflowError(
            "Accepted optimizer runs must share the same selected action identity"
        )
    for value in (
        budgets.get("max_elapsed_ms"),
        budgets.get("max_total_elapsed_ms"),
        budgets.get("max_candidate_bytes"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise workflow.WorkflowError(
                "Optimization requires positive time and size budgets"
            )
    by_id = {item["candidate_id"]: item for item in measurements}
    return _review_validated(
        run_ids, by_id, budgets, "accepted_workflow_evidence_revalidated"
    )


def review_approved_search(
    store: str | Path, search_id: str, candidate_runs: dict[str, str]
) -> dict:
    """Review caller-supplied accepted runs and enforce the approved stop order."""
    return _review_approved_search(store, search_id, candidate_runs, enforce_stop=True)


def _review_approved_search(
    store: str | Path,
    search_id: str,
    candidate_runs: dict[str, str],
    *,
    enforce_stop: bool,
) -> dict:
    """Review accepted runs only when they match an explicitly approved search scope."""
    root = workflow._private_directory(store)
    search = workflow.read_record(
        root
        / "records"
        / f"optimization_search-{workflow._reference_id(search_id, 'optimization search id')}.json",
        "optimization_search",
    )
    if not isinstance(candidate_runs, dict):
        raise workflow.WorkflowError(
            "Approved search results must map candidate IDs to accepted run IDs"
        )
    approved = {candidate["id"]: candidate for candidate in search["candidate_sets"]}
    if any(
        not isinstance(candidate_id, str)
        or candidate_id not in approved
        or not isinstance(run_id, str)
        or not run_id
        for candidate_id, run_id in candidate_runs.items()
    ) or len(set(candidate_runs.values())) != len(candidate_runs):
        raise workflow.WorkflowError(
            "Optimization results contain a duplicate or unapproved candidate"
        )
    records = root / "records"
    plan = workflow.read_record(records / f"plan-{search['plan_id']}.json", "plan")
    actions = {item["id"]: item for item in plan["actions"]}
    for candidate in approved.values():
        if len(candidate["action_ids"]) > 1:
            workflow._validate_composite_actions(plan, candidate["action_ids"])
        else:
            action = actions[candidate["action_ids"][0]]
            config = action.get("execution")
            if not isinstance(config, dict) or config.get("adapter") != "bla-js":
                raise workflow.WorkflowError(
                    "Approved search contains an adapter without accepted-run optimization measurement"
                )

    measurements = {}
    ordered_ids = [
        candidate["id"]
        for candidate in search["candidate_sets"]
        if candidate["id"] in candidate_runs
    ]
    for candidate_id in ordered_ids:
        candidate = approved[candidate_id]
        measurement = _accepted_run_measurement(
            store, candidate_runs[candidate_id], search
        )
        expected_runtime = search["runtime_identities"].get("bla-agents")
        if (
            measurement["target_id"] != search["target_id"]
            or measurement["baseline_sha256"] != search["baseline_sha256"]
            or measurement["plan_sha256"] != search["plan_sha256"]
            or measurement["runtime_sha256"] != expected_runtime
            or measurement.get("action_ids", [measurement["action_id"]])
            != candidate["action_ids"]
        ):
            raise workflow.WorkflowError(
                "Accepted run is outside its approved search candidate identity or budget"
            )
        measurement["candidate_id"] = candidate_id
        measurement["source_sha256"] = search["source_identity_sha256"]
        measurements[candidate_id] = measurement

    budgets = {
        key: search["budgets"][key]
        for key in ("max_elapsed_ms", "max_total_elapsed_ms", "max_candidate_bytes")
    }
    reviewed = _review_validated(
        list(approved),
        measurements,
        budgets,
        "approved_search_and_accepted_workflow_evidence_revalidated",
    )
    reviewed["search_id"] = search["id"]
    reviewed["search_sha256"] = workflow.record_hash(search)
    if enforce_stop and search["stop_conditions"]["stop_on_first_acceptable"]:
        acceptable_ids = [
            candidate_id
            for candidate_id in ordered_ids
            if measurements[candidate_id]["elapsed_ms"]
            <= search["budgets"]["max_elapsed_ms"]
            and measurements[candidate_id]["candidate_bytes"]
            <= search["budgets"]["max_candidate_bytes"]
        ]
        if acceptable_ids:
            candidate_order = [item["id"] for item in search["candidate_sets"]]
            first_index = candidate_order.index(acceptable_ids[0])
            if any(
                item not in measurements for item in candidate_order[:first_index]
            ) or any(candidate_order.index(item) > first_index for item in ordered_ids):
                raise workflow.WorkflowError(
                    "Accepted runs do not prove the approved stop-on-first order"
                )
    return reviewed


def confirm_accepted_reevaluation(
    store: str | Path,
    candidate_run_id: str,
    reevaluation_run_id: str,
    budgets: dict,
    optimization_search: dict | None = None,
) -> dict:
    """Confirm a separately accepted run only when it reproduces the selected candidate bytes."""
    from core import workflow

    if candidate_run_id == reevaluation_run_id:
        raise workflow.WorkflowError(
            "Independent reevaluation requires a distinct accepted run"
        )
    if not isinstance(budgets, dict):
        raise workflow.WorkflowError(
            "Independent reevaluation budgets must be an object"
        )
    candidate = _accepted_run_measurement(store, candidate_run_id, optimization_search)
    reevaluation = _accepted_run_measurement(
        store, reevaluation_run_id, optimization_search
    )
    limit_ms, limit_bytes = (
        budgets.get("max_elapsed_ms"),
        budgets.get("max_candidate_bytes"),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (limit_ms, limit_bytes)
    ):
        raise workflow.WorkflowError(
            "Independent reevaluation requires positive time and size budgets"
        )
    compare_fields = (
        "target_id",
        "source_sha256",
        "runtime_sha256",
        "artifact_sha256",
        "candidate_bytes",
        "plan_sha256",
        "action_id",
    ) + (("action_ids",) if "action_ids" in candidate else ())
    if (
        any(candidate[key] != reevaluation[key] for key in compare_fields)
        or candidate["elapsed_ms"] > limit_ms
        or candidate["candidate_bytes"] > limit_bytes
        or reevaluation["elapsed_ms"] > limit_ms
        or reevaluation["candidate_bytes"] > limit_bytes
    ):
        raise workflow.WorkflowError(
            "Accepted reevaluation must pass budgets and reproduce identical bytes"
        )
    return {
        "status": "independently_reevaluated",
        "initial_run_id": candidate_run_id,
        "reevaluation_run_id": reevaluation_run_id,
        "artifact_sha256": candidate["artifact_sha256"],
        "initial_acceptance_id": candidate["acceptance_id"],
        "reevaluation_acceptance_id": reevaluation["acceptance_id"],
        "initial_acceptance_sha256": candidate["accepted_record_sha256"],
        "reevaluation_acceptance_sha256": reevaluation["accepted_record_sha256"],
    }


def confirm_approved_search_reevaluation(
    store: str | Path,
    search_id: str,
    selection_id: str,
    candidate_run_id: str,
    reevaluation_run_id: str,
) -> dict:
    """Confirm a distinct accepted rerun of a persisted Pareto-frontier selection."""
    root = workflow._private_directory(store)
    search = workflow.read_record(
        root
        / "records"
        / f"optimization_search-{workflow._reference_id(search_id, 'optimization search id')}.json",
        "optimization_search",
    )
    selection_id = workflow._reference_id(selection_id, "optimization selection id")
    try:
        selection = workflow.read_record(
            root / "records" / f"optimization_selection-{selection_id}.json",
            "optimization_selection",
        )
    except FileNotFoundError as error:
        raise workflow.WorkflowError(
            "Persisted optimization selection does not exist"
        ) from error
    if (
        selection["search_id"] != search["id"]
        or selection["search_sha256"] != workflow.record_hash(search)
        or selection["candidate_run_id"] != candidate_run_id
    ):
        raise workflow.WorkflowError(
            "Optimization selection does not match the search or candidate run"
        )
    runner_result = _validated_search_result(store, search, selection["candidate_runs"])
    if (
        runner_result["id"] != selection["runner_result_id"]
        or workflow.record_hash(runner_result) != selection["runner_result_sha256"]
    ):
        raise workflow.WorkflowError(
            "Persisted runner result changed since candidate selection"
        )
    reviewed = _review_approved_search(
        store, search_id, selection["candidate_runs"], enforce_stop=False
    )
    if workflow.record_hash(reviewed) != selection["review_sha256"]:
        raise workflow.WorkflowError(
            "Selected search review has changed since candidate selection"
        )
    frontier_item = next(
        (
            item
            for item in reviewed["pareto_frontier"]
            if item["candidate_id"] == selection["candidate_id"]
            and item["run_id"] == candidate_run_id
        ),
        None,
    )
    if frontier_item is None:
        raise workflow.WorkflowError(
            "Selected candidate is no longer on the approved search Pareto frontier"
        )
    candidate_id = selection["candidate_id"]
    candidate = next(
        (item for item in search["candidate_sets"] if item["id"] == candidate_id), None
    )
    if candidate is None:
        raise workflow.WorkflowError(
            "Selected candidate is not in the approved optimization search"
        )
    plan = workflow.read_record(
        root / "records" / f"plan-{search['plan_id']}.json", "plan"
    )
    if len(candidate["action_ids"]) > 1:
        workflow._validate_composite_actions(plan, candidate["action_ids"])
    else:
        action_id = candidate["action_ids"][0]
        action = next(
            (item for item in plan["actions"] if item["id"] == action_id), None
        )
        if action is None or action.get("execution", {}).get("adapter") != "bla-js":
            raise workflow.WorkflowError(
                "Approved candidate does not use a supported BLA JavaScript action"
            )
    expected_runtime = search["runtime_identities"].get("bla-agents")
    for run_id in (candidate_run_id, reevaluation_run_id):
        measurement = _accepted_run_measurement(store, run_id, search)
        if (
            measurement["target_id"] != search["target_id"]
            or measurement["baseline_sha256"] != search["baseline_sha256"]
            or measurement["plan_sha256"] != search["plan_sha256"]
            or measurement["runtime_sha256"] != expected_runtime
            or measurement.get("action_ids", [measurement["action_id"]])
            != candidate["action_ids"]
        ):
            raise workflow.WorkflowError(
                "Reevaluation run is outside the approved search candidate identity"
            )
    budgets = {
        key: search["budgets"][key] for key in ("max_elapsed_ms", "max_candidate_bytes")
    }
    result = confirm_accepted_reevaluation(
        store,
        candidate_run_id,
        reevaluation_run_id,
        budgets,
        optimization_search=search,
    )
    return {
        **result,
        "search_id": search["id"],
        "search_sha256": workflow.record_hash(search),
        "candidate_id": candidate_id,
        "selection_id": selection["id"],
        "selection_sha256": workflow.record_hash(selection),
        "review_sha256": selection["review_sha256"],
    }


def select_approved_search_candidate(
    store: str | Path,
    search_id: str,
    candidate_id: str,
    candidate_runs: dict[str, str],
    decision_source: str,
) -> dict:
    """Persist an explicit choice from the current accepted-candidate Pareto frontier."""
    if not isinstance(decision_source, str) or not decision_source.strip():
        raise workflow.WorkflowError(
            "Optimization selection requires an explicit decision source"
        )
    root = workflow._private_directory(store)
    search = workflow.read_record(
        root
        / "records"
        / f"optimization_search-{workflow._reference_id(search_id, 'optimization search id')}.json",
        "optimization_search",
    )
    candidate_id = workflow._reference_id(candidate_id, "optimization candidate id")
    result = _validated_search_result(store, search, candidate_runs)
    reviewed = _review_approved_search(
        store, search_id, candidate_runs, enforce_stop=False
    )
    selected = next(
        (
            item
            for item in reviewed["pareto_frontier"]
            if item["candidate_id"] == candidate_id
        ),
        None,
    )
    if selected is None:
        raise workflow.WorkflowError(
            "Selection must identify a candidate on the approved search Pareto frontier"
        )
    selection_payload = {
        "search_sha256": workflow.record_hash(search),
        "runner_result_id": result["id"],
        "runner_result_sha256": workflow.record_hash(result),
        "review_sha256": workflow.record_hash(reviewed),
        "candidate_id": candidate_id,
        "candidate_run_id": selected["run_id"],
        "candidate_runs": candidate_runs,
        "decision_source": decision_source.strip(),
    }
    selection_id = (
        "select-"
        + hashlib.sha256(workflow.canonical(selection_payload)).hexdigest()[:24]
    )
    selection = {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "optimization_selection",
        "id": selection_id,
        "search_id": search["id"],
        **selection_payload,
    }
    path = workflow.write_record(root / "records", selection)
    return {
        "status": "selected",
        "id": selection["id"],
        "search_id": search["id"],
        "search_sha256": selection["search_sha256"],
        "candidate_id": candidate_id,
        "runner_result_id": selection["runner_result_id"],
        "candidate_run_id": selected["run_id"],
        "review_sha256": selection["review_sha256"],
        "decision_source": selection["decision_source"],
        "record": path.name,
    }


def confirm_independent_reevaluation(
    candidate: dict, reevaluation: dict, budgets: dict
) -> dict:
    """Confirm identical candidate bytes passed a separately recorded bounded rerun."""
    if (
        not isinstance(candidate, dict)
        or not isinstance(reevaluation, dict)
        or not isinstance(budgets, dict)
    ):
        raise workflow.WorkflowError(
            "Candidate, reevaluation, and budgets must be objects"
        )
    limit_ms, limit_bytes = (
        budgets.get("max_elapsed_ms"),
        budgets.get("max_candidate_bytes"),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (limit_ms, limit_bytes)
    ):
        raise workflow.WorkflowError(
            "Independent reevaluation requires positive time and size budgets"
        )
    fields = (
        "candidate_id",
        "run_id",
        "source_sha256",
        "runtime_sha256",
        "artifact_sha256",
        "correctness_passed",
        "integrity_passed",
        "elapsed_ms",
        "candidate_bytes",
    )
    if any(key not in candidate for key in fields) or any(
        key not in reevaluation for key in fields
    ):
        raise workflow.WorkflowError(
            "Candidate and reevaluation identities are incomplete"
        )
    if (
        any(
            not isinstance(candidate.get(key), str) or not candidate[key]
            for key in ("candidate_id", "run_id")
        )
        or any(
            not isinstance(candidate.get(key), str)
            or not _HASH.fullmatch(candidate[key])
            for key in ("source_sha256", "runtime_sha256", "artifact_sha256")
        )
        or any(
            isinstance(candidate.get(key), bool)
            or not isinstance(candidate.get(key), int)
            or candidate[key] <= 0
            for key in ("elapsed_ms", "candidate_bytes")
        )
    ):
        raise workflow.WorkflowError("Candidate identity or measurements are invalid")
    if (
        candidate.get("correctness_passed") is not True
        or candidate.get("integrity_passed") is not True
    ):
        raise workflow.WorkflowError(
            "Only a passing candidate can be independently reevaluated"
        )
    initial_evidence = candidate.get("evidence")
    try:
        initial_proof = json.loads(workflow.verify_evidence_file(initial_evidence))
    except (TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError("Initial candidate evidence is invalid") from error
    if (
        not isinstance(initial_proof, dict)
        or initial_proof.get("record_type") != "optimizer_candidate_measurement"
        or initial_proof.get("schema_version") != "1.0"
        or any(initial_proof.get(key) != candidate.get(key) for key in fields)
    ):
        raise workflow.WorkflowError(
            "Initial candidate does not match its hash-checked caller report"
        )
    if (
        candidate["run_id"] == reevaluation["run_id"]
        or not isinstance(reevaluation.get("run_id"), str)
        or not reevaluation["run_id"]
        or any(
            candidate[key] != reevaluation[key]
            for key in (
                "candidate_id",
                "source_sha256",
                "runtime_sha256",
                "artifact_sha256",
                "candidate_bytes",
            )
        )
    ):
        raise workflow.WorkflowError(
            "Independent reevaluation must use a distinct run with identical inputs and output"
        )
    if candidate["elapsed_ms"] > limit_ms or candidate["candidate_bytes"] > limit_bytes:
        raise workflow.WorkflowError(
            "Original candidate exceeds the independent reevaluation budget"
        )
    if (
        reevaluation.get("record_type") != "optimizer_independent_reevaluation"
        or reevaluation.get("schema_version") != "1.0"
        or any(
            not isinstance(reevaluation.get(key), str)
            or not _HASH.fullmatch(reevaluation[key])
            for key in ("source_sha256", "runtime_sha256", "artifact_sha256")
        )
        or reevaluation.get("correctness_passed") is not True
        or reevaluation.get("integrity_passed") is not True
        or isinstance(reevaluation.get("elapsed_ms"), bool)
        or not isinstance(reevaluation.get("elapsed_ms"), int)
        or isinstance(reevaluation.get("candidate_bytes"), bool)
        or not isinstance(reevaluation.get("candidate_bytes"), int)
        or reevaluation["elapsed_ms"] <= 0
        or reevaluation["candidate_bytes"] <= 0
        or reevaluation["elapsed_ms"] > limit_ms
        or reevaluation["candidate_bytes"] > limit_bytes
    ):
        raise workflow.WorkflowError(
            "Independent reevaluation failed correctness, integrity, or budget gates"
        )
    evidence = reevaluation.get("evidence")
    if (
        not isinstance(evidence, dict)
        or not isinstance(evidence.get("path"), str)
        or not isinstance(evidence.get("sha256"), str)
        or not _HASH.fullmatch(evidence["sha256"])
    ):
        raise workflow.WorkflowError(
            "Independent reevaluation evidence reference is invalid"
        )
    try:
        proof = json.loads(workflow.verify_evidence_file(evidence))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError(
            "Independent reevaluation evidence is invalid JSON"
        ) from error
    if (
        not isinstance(proof, dict)
        or proof.get("record_type") != "optimizer_independent_reevaluation"
        or proof.get("schema_version") != "1.0"
        or any(proof.get(key) != reevaluation.get(key) for key in fields)
    ):
        raise workflow.WorkflowError(
            "Independent reevaluation does not match its hash-checked caller report"
        )
    return {
        "status": "independently_reevaluated",
        "candidate_id": candidate["candidate_id"],
        "initial_run_id": candidate["run_id"],
        "reevaluation_run_id": reevaluation["run_id"],
        "artifact_sha256": candidate["artifact_sha256"],
        "evidence_sha256": evidence["sha256"],
    }
