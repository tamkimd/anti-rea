"""Anti-REA workflow MCP tools; business rules stay in core.workflow."""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from core import (
    baseline as baseline_capture,
)
from core import (
    dependencies,
    discovery,
    execution,
    flutter_android,
    optimizer,
    recommendations,
    wasm_runtime,
    workflow,
)

server = MCPServer("Anti-REA")
_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
_execution_jobs: set[str] = set()
_execution_jobs_lock = threading.Lock()
_execution_controls: dict[str, tuple[threading.Event, dict[str, Any]]] = {}


def _shutdown_active_executions() -> None:
    with _execution_jobs_lock:
        active = list(_execution_controls.values())
    for event, _ in active:
        event.set()
    for _, control in active:
        process = control.get("process")
        if process is not None and process.poll() is None:
            baseline_capture._stop_process(process)
    for _, control in active:
        worker = control.get("thread")
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=10)


atexit.register(_shutdown_active_executions)


def _optimization_operation_key(search_id: str) -> str:
    return f"optimization-search:{workflow._reference_id(search_id, 'optimization search id')}"


def _optimization_result_path(search_id: str) -> Path:
    return (
        workflow._private_directory(store_root() / "runs")
        / f"optimization-search-{search_id}.json"
    )


def _write_optimization_operation(
    search: dict[str, Any],
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    *,
    exclusive: bool = False,
) -> None:
    path = _optimization_result_path(search["id"])
    value = {
        "schema_version": "1.0",
        "record_type": "optimization_search_operation",
        "search_id": search["id"],
        "search_sha256": workflow.record_hash(search),
        "status": status,
        "result": result,
        "error": error,
    }
    payload = (
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False).encode()
        + b"\n"
    )
    fd, temporary = tempfile.mkstemp(prefix=".optimization-search-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_optimization_operation(search: dict[str, Any]) -> dict[str, Any] | None:
    path = _optimization_result_path(search["id"])
    if not path.exists():
        return None
    value = workflow.read_json(path)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "1.0"
        or value.get("record_type") != "optimization_search_operation"
        or value.get("search_id") != search["id"]
        or value.get("search_sha256") != workflow.record_hash(search)
        or value.get("status") not in {"running", "completed", "failed"}
        or value.get("status") == "completed"
        and not isinstance(value.get("result"), dict)
        or value.get("status") == "failed"
        and not isinstance(value.get("error"), str)
    ):
        raise workflow.WorkflowError(
            "Optimization operation state does not match its approved search"
        )
    return value


def state_path() -> Path:
    configured = os.environ.get("ANTI_REA_STATE_DIR")
    if configured:
        root = Path(configured).expanduser()
    elif os.name == "nt":
        root = (
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
            / "Anti-REA"
            / "state"
        )
    elif sys_platform() == "darwin":
        root = Path.home() / "Library/Application Support/Anti-REA/state"
    else:
        root = (
            Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
            / "anti-rea"
        )
    return root


def store_root() -> Path:
    root = state_path()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise workflow.WorkflowError(
            "Anti-REA state directory must be a real directory"
        )
    if os.name != "nt" and root.stat().st_uid != os.getuid():
        raise workflow.WorkflowError(
            "Anti-REA state directory must be owned by the current user"
        )
    root.chmod(0o700)
    return root


def sys_platform() -> str:
    import sys

    return sys.platform


def run_path(run_id: str) -> Path:
    if not isinstance(run_id, str) or not _ID.fullmatch(run_id):
        raise workflow.WorkflowError("Invalid run id")
    return store_root() / "runs" / f"run-{run_id}.json"


@server.tool()
def workflow_contract() -> dict[str, Any]:
    """Return the schema version, run states, and current execution boundary."""
    return {
        "schema_version": workflow.SCHEMA_VERSION,
        "run_states": sorted(workflow.RUN_STATES),
        "execution": "explicitly requested baseline and selected BLA commands execute project code; timeouts do not provide OS isolation",
    }


@server.tool()
def validate_target(record: dict[str, Any]) -> dict[str, Any]:
    """Validate a versioned discovered-target manifest."""
    value = workflow.validate_target(record)
    return {
        "status": "valid",
        "id": value["id"],
        "components": len(value["components"]),
    }


@server.tool()
def inspect_project(project: str) -> dict[str, Any]:
    """Perform bounded read-only local discovery and save its manifest in Anti-REA state."""
    target = discovery.inspect_project(project)
    root = Path(target["source_root"])
    configured_store = state_path().expanduser().resolve()
    if configured_store == root or root in configured_store.parents:
        return {
            "status": "blocked",
            "error": "Anti-REA state must be outside the inspected project",
        }
    records = store_root() / "records"
    path = workflow.write_record(records, workflow.validate_target(target))
    return {
        "status": "discovered",
        "id": target["id"],
        "components": target["components"],
        "manifest_count": len(target["manifests"]),
        "file_count": target["inventory"]["file_count"],
        "inventory_sha256": target["inventory"]["sha256"],
        "unknowns": target["unknowns"],
        "record": path.name,
    }


@server.tool()
def inspect_python_dependencies(project: str) -> dict[str, Any]:
    """Inspect a PEP 751 Python lockfile without resolving or installing packages."""
    return dependencies.inspect_python_dependencies(project)


@server.tool()
def prepare_python_dependencies(
    project: str, cache: str, offline: bool = False
) -> dict[str, Any]:
    """Prepare one hashed PEP 751 wheel lock in an isolated private cache."""
    return dependencies.prepare_python_dependencies(project, cache, offline)


@server.tool()
def probe_wasm_module(
    module: str, node: str = "node", timeout_seconds: float = 10
) -> dict[str, Any]:
    """Compile-check a bounded WASM file without instantiating it or checking host bindings."""
    return wasm_runtime.probe_module(module, node, timeout_seconds)


@server.tool()
def probe_flutter_android_environment(
    flutter: str = "flutter", timeout_seconds: float = 120
) -> dict[str, Any]:
    """Check Flutter, Android SDK/license/JDK, and connected device readiness without changing the host."""
    return flutter_android.probe_android_environment(flutter, timeout_seconds)


@server.tool()
def get_target(target_id: str) -> dict[str, Any]:
    """Retrieve a previously discovered full target manifest by stable ID."""
    if not isinstance(target_id, str) or not _ID.fullmatch(target_id):
        raise workflow.WorkflowError("Invalid target id")
    return workflow.validate_target(
        workflow.read_record(
            store_root() / "records" / f"target-{target_id}.json", "target"
        )
    )


@server.tool()
def save_target(record: dict[str, Any]) -> dict[str, Any]:
    """Save a validated target manifest for subsequent baseline/run binding."""
    value = workflow.validate_target(record)
    path = workflow.write_record(store_root() / "records", value)
    return {"status": "saved", "id": value["id"], "record": path.name}


@server.tool()
def save_baseline(record: dict[str, Any]) -> dict[str, Any]:
    """Save an immutable baseline record; evidence references must already exist."""
    value = workflow.validate_baseline(record)
    records = store_root() / "records"
    target = workflow.validate_target(
        workflow.read_record(records / f"target-{value['target_id']}.json", "target")
    )
    value = workflow.validate_baseline_target(value, target)
    path = workflow.write_record(records, value)
    return {"status": "saved", "id": value["id"], "record": path.name}


@server.tool()
def start_baseline(
    project: str,
    command: list[str],
    artifacts: list[str],
    baseline_id: str,
    timeout_seconds: float = 600,
    behavior_command: list[str] | None = None,
    e2e_runtime: str | None = None,
    e2e_config: str = "e2e.config.mjs",
    e2e_test_file: str = "tests/behavior.e2e.ts",
    rea_runtime: str | None = None,
    build_time_trials: int = 1,
) -> dict[str, Any]:
    """Run an explicit BEFORE command and hash selected project artifacts.

    This executes project code. Optional build_time_trials (1-5) repeats builds on fresh copies;
    repeating commands may add cost or external side effects. Timeout and output limits do not provide OS isolation.
    """
    baseline, evidence = baseline_capture.capture(
        project,
        store_root(),
        command,
        artifacts,
        baseline_id,
        timeout_seconds,
        behavior_command,
        e2e_runtime,
        e2e_config,
        e2e_test_file,
        rea_runtime,
        build_time_trials=build_time_trials,
    )
    return {
        "status": "captured",
        "id": baseline["id"],
        "target_id": baseline["target_id"],
        "artifacts": baseline["identity"]["artifacts"],
        "evidence": str(evidence),
        "build_duration_ms": baseline["identity"]["build_duration_ms"],
        "build_timing": baseline["identity"].get("build_timing"),
        "behavior_evidence": baseline["identity"]
        .get("behavior", {})
        .get("evidence_path"),
        "e2e_evidence": baseline["identity"].get("e2e_behavior", {}).get("report_path"),
        "rea_evidence": baseline["identity"].get("rea_analysis", {}).get("report_path"),
    }


@server.tool()
def start_baseline_async(
    project: str,
    command: list[str],
    artifacts: list[str],
    baseline_id: str,
    run_id: str,
    timeout_seconds: float = 600,
    behavior_command: list[str] | None = None,
    e2e_runtime: str | None = None,
    e2e_config: str = "e2e.config.mjs",
    e2e_test_file: str = "tests/behavior.e2e.ts",
    rea_runtime: str | None = None,
    build_time_trials: int = 1,
) -> dict[str, Any]:
    """Schedule a BEFORE capture; poll get_run and pass its run id to submit_plan."""
    workflow._reference_id(baseline_id, "baseline id")
    workflow._reference_id(run_id, "run id")
    root = Path(project).expanduser().resolve(strict=True)
    state = store_root().resolve()
    if (
        not root.is_dir()
        or state == root
        or state in root.parents
        or root in state.parents
    ):
        raise workflow.WorkflowError(
            "Anti-REA state and target must be separate directory trees"
        )
    target = discovery.inspect_project(root)
    workflow.write_record(state / "records", target)
    create_run(target["id"], run_id)
    run_file = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(run_file))
    baselining = workflow.transition_run(current, "baselining", baseline_id=baseline_id)
    workflow.write_run_state(run_file.parent, baselining, current)

    with _execution_jobs_lock:
        if run_id in _execution_jobs:
            raise workflow.WorkflowError("An operation is already active for this run")
        _execution_jobs.add(run_id)
        cancel_event = threading.Event()
        control: dict[str, Any] = {"process": None, "kind": "baseline"}
        _execution_controls[run_id] = (cancel_event, control)

    def work() -> None:
        try:
            baseline_capture.capture(
                project,
                state,
                command,
                artifacts,
                baseline_id,
                timeout_seconds,
                behavior_command,
                e2e_runtime,
                e2e_config,
                e2e_test_file,
                rea_runtime,
                cancel_event,
                lambda process: control.update(process=process),
                build_time_trials=build_time_trials,
            )
        except BaseException as error:
            if not (
                cancel_event.is_set()
                and isinstance(error, workflow.WorkflowError)
                and str(error) == "Command cancelled"
            ):
                print(f"Anti-REA baseline capture failed: {error}", file=sys.stderr)
            try:
                run = workflow.validate_run(workflow.read_json(run_file))
                if run["state"] == "baselining":
                    if cancel_event.is_set():
                        changed = workflow.transition_run(
                            run, "cancelled", cancellation_reason="user_requested"
                        )
                    else:
                        changed = workflow.transition_run(
                            run, "failed", error_code="baseline_capture_failed"
                        )
                    workflow.write_run_state(run_file.parent, changed, run)
            except Exception:
                pass
        finally:
            with _execution_jobs_lock:
                if cancel_event.is_set():
                    try:
                        run = workflow.validate_run(workflow.read_json(run_file))
                        if run["state"] == "baselining":
                            changed = workflow.transition_run(
                                run, "cancelled", cancellation_reason="user_requested"
                            )
                            workflow.write_run_state(run_file.parent, changed, run)
                    except Exception:
                        pass
                _execution_jobs.discard(run_id)
                _execution_controls.pop(run_id, None)

    worker = threading.Thread(
        target=work, name=f"anti-rea-baseline-{run_id}", daemon=True
    )
    control["thread"] = worker
    try:
        worker.start()
    except BaseException:
        try:
            run = workflow.validate_run(workflow.read_json(run_file))
            if run["state"] == "baselining":
                failed = workflow.transition_run(
                    run, "failed", error_code="baseline_capture_failed"
                )
                workflow.write_run_state(run_file.parent, failed, run)
        finally:
            with _execution_jobs_lock:
                _execution_jobs.discard(run_id)
                _execution_controls.pop(run_id, None)
        raise
    return {
        "status": "scheduled",
        "run_id": run_id,
        "baseline_id": baseline_id,
        "state": "baselining",
        "poll_tool": "get_run",
    }


@server.tool()
def start_flutter_android_baseline_async(
    project: str,
    baseline_id: str,
    run_id: str,
    target: str,
    split_debug_info: str | None = None,
    flutter: str = "flutter",
    timeout_seconds: float = 3600,
    obfuscate: bool = False,
) -> dict[str, Any]:
    """Schedule an explicit Flutter Android release baseline; poll get_run for completion."""
    state = store_root().resolve()
    symbols = (
        Path(split_debug_info).expanduser().resolve()
        if split_debug_info is not None
        else None
    )
    if obfuscate:
        if symbols is None or symbols.parent != state:
            raise workflow.WorkflowError(
                "Flutter split debug information must be a direct child of Anti-REA state"
            )
        if symbols.exists() or symbols.is_symlink():
            raise workflow.WorkflowError(
                "Flutter split debug information path already exists"
            )
    command = flutter_android.build_command(
        project, target, symbols, flutter, obfuscate=obfuscate
    )
    artifact = (
        "build/app/outputs/flutter-apk/app-release.apk"
        if target == "apk"
        else "build/app/outputs/bundle/release/app-release.aab"
    )
    return start_baseline_async(
        project, command, [artifact], baseline_id, run_id, timeout_seconds
    )


@server.tool()
def attach_flutter_aot_inspection(
    baseline_id: str,
    new_baseline_id: str,
    report_path: str,
    rea_runtime_path: str,
    abi: str,
) -> dict[str, Any]:
    """Create an immutable Flutter baseline version bound to a raw REA AOT inspection."""
    workflow._reference_id(baseline_id, "baseline id")
    records = store_root() / "records"
    baseline = workflow.read_record(
        records / f"baseline-{baseline_id}.json", "baseline"
    )
    updated = flutter_android.attach_aot_inspection(
        baseline, report_path, rea_runtime_path, abi, new_baseline_id
    )
    path = workflow.write_record(records, updated)
    return {
        "status": "attached",
        "id": updated["id"],
        "aot_status": updated["identity"]["flutter_aot_inspection"]["status"],
        "baseline_sha256": workflow.record_hash(updated),
        "record": path.name,
    }


@server.tool()
def save_plan(record: dict[str, Any]) -> dict[str, Any]:
    """Save a concrete plan bound to a target and baseline."""
    value = workflow.validate_plan(record)
    records = store_root() / "records"
    baseline = workflow.validate_baseline(
        workflow.read_record(
            records / f"baseline-{value['baseline_id']}.json", "baseline"
        )
    )
    value = workflow.validate_plan_baseline(value, baseline)
    path = workflow.write_record(records, value)
    return {
        "status": "saved",
        "id": value["id"],
        "sha256": workflow.record_hash(value),
        "record": path.name,
    }


@server.tool()
def generate_optimization_candidates(search_template: dict[str, Any]) -> dict[str, Any]:
    """Generate a bounded proposal; this tool neither approves nor executes candidates."""
    proposal = optimizer.generate_search_proposal(store_root(), search_template)
    return {"status": "proposal", "approval_required": True, "search": proposal}


@server.tool()
def preview_optimization_search(search: dict[str, Any]) -> dict[str, Any]:
    """Validate and preview a bounded candidate search without persisting approval."""
    value = optimizer.validate_search_space(
        store_root(), search, "pending MCP approval"
    )
    return {
        "status": "approval_required",
        "id": value["id"],
        "target_id": value["target_id"],
        "baseline_id": value["baseline_id"],
        "plan_id": value["plan_id"],
        "baseline_sha256": value["baseline_sha256"],
        "source_identity_sha256": value["source_identity_sha256"],
        "plan_sha256": value["plan_sha256"],
        "runtime_identities": value["runtime_identities"],
        "candidate_sets": value["candidate_sets"],
        "budgets": value["budgets"],
        "stop_conditions": value["stop_conditions"],
    }


@server.tool()
def approve_optimization_search(search: dict[str, Any]) -> dict[str, Any]:
    """Persist the bounded search scope after this explicit MCP approval call."""
    return optimizer.approve_search_space(store_root(), search, "MCP tool invocation")


@server.tool()
def start_approved_optimization_search(
    search_id: str,
    bla_runtime: str | None = None,
    rea_runtime: str | None = None,
    e2e_runtime: str | None = None,
) -> dict[str, Any]:
    """Schedule an explicitly approved bounded search; poll by its search ID."""
    search_id = workflow._reference_id(search_id, "optimization search id")
    root = store_root()
    search = workflow.read_record(
        root / "records" / f"optimization_search-{search_id}.json",
        "optimization_search",
    )
    key = _optimization_operation_key(search_id)
    with _execution_jobs_lock:
        if key in _execution_jobs:
            raise workflow.WorkflowError("This optimization search is already running")
        if _optimization_result_path(search_id).exists():
            raise workflow.WorkflowError(
                "This optimization search has already been started"
            )
        for candidate in search["candidate_sets"]:
            identity = hashlib.sha256(
                f"{workflow.record_hash(search)}:{candidate['id']}".encode()
            ).hexdigest()[:24]
            run_file = root / "runs" / f"run-searchrun-{identity}.json"
            if run_file.exists() or run_file.is_symlink():
                raise workflow.WorkflowError(
                    "An approved search candidate already has a run"
                )
        cancel_event = threading.Event()
        control: dict[str, Any] = {
            "process": None,
            "kind": "optimization_search",
            "search_id": search_id,
        }
        try:
            _write_optimization_operation(search, "running", exclusive=True)
        except FileExistsError as error:
            raise workflow.WorkflowError(
                "This optimization search has already been started"
            ) from error
        _execution_jobs.add(key)
        _execution_controls[key] = (cancel_event, control)

    def on_process(process) -> None:
        control["process"] = process

    def work() -> None:
        try:
            result = optimizer.execute_approved_search(
                root,
                search_id,
                bla_runtime,
                rea_runtime,
                e2e_runtime,
                cancel_event,
                on_process,
            )
            _write_optimization_operation(search, "completed", result=result)
        except BaseException as error:
            try:
                _write_optimization_operation(search, "failed", error=str(error)[:500])
            except BaseException as persist_error:
                print(
                    f"Anti-REA optimization operation state failed to persist: {persist_error}",
                    file=sys.stderr,
                )
            print(
                f"Anti-REA approved optimization search failed: {error}",
                file=sys.stderr,
            )
        finally:
            with _execution_jobs_lock:
                _execution_jobs.discard(key)
                _execution_controls.pop(key, None)

    worker = threading.Thread(
        target=work, name=f"anti-rea-optimization-{search_id}", daemon=True
    )
    control["thread"] = worker
    try:
        worker.start()
    except BaseException as error:
        try:
            _write_optimization_operation(search, "failed", error=str(error)[:500])
        finally:
            with _execution_jobs_lock:
                _execution_jobs.discard(key)
                _execution_controls.pop(key, None)
        raise
    return {
        "status": "scheduled",
        "run_id": search_id,
        "search_id": search_id,
        "operation": "optimization_search",
        "poll_tool": "get_approved_optimization_search",
        "cancel_tool": "cancel_approved_optimization_search",
    }


@server.tool()
def get_approved_optimization_search(search_id: str) -> dict[str, Any]:
    """Poll a search operation and report persisted candidate run states after restart."""
    search_id = workflow._reference_id(search_id, "optimization search id")
    root = store_root()
    search = workflow.read_record(
        root / "records" / f"optimization_search-{search_id}.json",
        "optimization_search",
    )
    operation = _read_optimization_operation(search)
    key = _optimization_operation_key(search_id)
    with _execution_jobs_lock:
        active = key in _execution_jobs
    candidate_results = []
    for candidate in search["candidate_sets"]:
        identity = hashlib.sha256(
            f"{workflow.record_hash(search)}:{candidate['id']}".encode()
        ).hexdigest()[:24]
        run_id = f"searchrun-{identity}"
        run_path = root / "runs" / f"run-{run_id}.json"
        if not run_path.exists():
            candidate_results.append(
                {"candidate_id": candidate["id"], "status": "not_evaluated"}
            )
            continue
        run = workflow.validate_run(workflow.read_json(run_path))
        status = {
            "completed": "accepted",
            "blocked": "rejected",
            "cancelled": "cancelled",
            "failed": "failed",
        }.get(run["state"], run["state"])
        if (
            run["state"] == "failed"
            and run.get("error_code") == "optimization_time_budget_exceeded"
        ):
            status = "over_budget"
        candidate_results.append(
            {
                "candidate_id": candidate["id"],
                "run_id": run_id,
                "status": status,
                "state": run["state"],
            }
        )
    effectiveness_table = []
    evaluated = next(
        (
            item
            for item in candidate_results
            if item.get("run_id")
            and workflow.read_json(root / "runs" / f"run-{item['run_id']}.json").get(
                "plan_id"
            )
        ),
        None,
    )
    if evaluated:
        candidate_run = workflow.validate_run(
            workflow.read_json(root / "runs" / f"run-{evaluated['run_id']}.json")
        )
        effectiveness_table = workflow.assemble_run_report(
            root / "records", candidate_run
        ).get("effectiveness_table", [])
    elif {"plan_id", "baseline_id"} <= search.keys():
        try:
            plan = workflow.read_record(
                root / "records" / f"plan-{search['plan_id']}.json", "plan"
            )
            baseline = workflow.read_record(
                root / "records" / f"baseline-{search['baseline_id']}.json", "baseline"
            )
        except FileNotFoundError:
            plan = baseline = None
        if plan and baseline:
            actions = {item["id"]: item for item in plan["actions"]}
            artifacts = baseline.get("identity", {}).get("artifacts", {})
            statuses = {
                item["candidate_id"]: item["status"] for item in candidate_results
            }
            for index, candidate in enumerate(search["candidate_sets"], 1):
                selected = [actions[action_id] for action_id in candidate["action_ids"]]
                artifact_path = next(
                    (
                        path
                        for action in selected
                        for path in (
                            action.get("execution", {}).get("source_path"),
                            action.get("execution", {}).get("artifact_path"),
                        )
                        if path in artifacts
                    ),
                    None,
                )
                if artifact_path is None and len(artifacts) == 1:
                    artifact_path = next(iter(artifacts))
                artifact = (
                    {"path": artifact_path, **artifacts[artifact_path]}
                    if artifact_path
                    else None
                )
                effectiveness_table.append(
                    {
                        "iteration": index,
                        "candidate_id": candidate["id"],
                        "engine": ", ".join(
                            dict.fromkeys(a["engine"] for a in selected)
                        ),
                        "before": artifact,
                        "baseline_record_sha256": workflow.record_hash(baseline),
                        "after": None,
                        "checks": {},
                        "status": statuses.get(candidate["id"], "not_evaluated"),
                    }
                )
    if operation and operation["status"] == "completed":
        return {
            "status": "completed",
            "run_id": search_id,
            "search_id": search_id,
            "operation_active": False,
            "result": operation["result"],
            "effectiveness_table": effectiveness_table,
        }
    if operation and operation["status"] == "failed":
        return {
            "status": "failed",
            "run_id": search_id,
            "search_id": search_id,
            "operation_active": False,
            "error": operation.get("error"),
            "candidate_results": candidate_results,
            "effectiveness_table": effectiveness_table,
        }
    status = "running" if active else "interrupted" if operation else "not_started"
    return {
        "status": status,
        "run_id": search_id,
        "search_id": search_id,
        "operation_active": active,
        "candidate_results": candidate_results,
        "effectiveness_table": effectiveness_table,
    }


@server.tool()
def cancel_approved_optimization_search(search_id: str) -> dict[str, Any]:
    """Cancel a scheduled search and terminate its currently active subprocess."""
    search_id = workflow._reference_id(search_id, "optimization search id")
    key = _optimization_operation_key(search_id)
    with _execution_jobs_lock:
        active = _execution_controls.get(key)
        if active is None:
            return {"status": "not_active", "search_id": search_id}
        event, control = active
        event.set()
        process = control.get("process")
        if process is not None and process.poll() is None:
            baseline_capture._stop_process(process)
    return {"status": "cancellation_requested", "search_id": search_id}


@server.tool()
def review_approved_optimization_search(
    search_id: str, candidate_runs: dict[str, str]
) -> dict[str, Any]:
    """Review accepted candidate runs against the exact persisted search approval."""
    return optimizer.review_approved_search(store_root(), search_id, candidate_runs)


@server.tool()
def select_approved_optimization_candidate(
    search_id: str,
    candidate_id: str,
    candidate_runs: dict[str, str],
    decision_source: str,
) -> dict[str, Any]:
    """Persist an explicit choice from the approved search Pareto frontier."""
    return optimizer.select_approved_search_candidate(
        store_root(), search_id, candidate_id, candidate_runs, decision_source
    )


@server.tool()
def confirm_approved_search_reevaluation(
    search_id: str, selection_id: str, candidate_run_id: str, reevaluation_run_id: str
) -> dict[str, Any]:
    """Confirm a distinct accepted rerun of a persisted Pareto-frontier selection."""
    return optimizer.confirm_approved_search_reevaluation(
        store_root(), search_id, selection_id, candidate_run_id, reevaluation_run_id
    )


@server.tool()
def submit_plan(run_id: str, plan: dict[str, Any]) -> dict[str, Any]:
    """Bind a concrete plan to a baselining run and present it for a client decision."""
    path = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(path))
    records = store_root() / "records"
    target = workflow.read_record(
        records / f"target-{current['target_id']}.json", "target"
    )
    baseline_id = plan.get("baseline_id") if isinstance(plan, dict) else None
    if not isinstance(baseline_id, str) or not _ID.fullmatch(baseline_id):
        raise workflow.WorkflowError("Plan requires a valid baseline id")
    baseline = workflow.read_record(
        records / f"baseline-{baseline_id}.json", "baseline"
    )
    changed = workflow.submit_plan(current, target, baseline, plan)
    saved_plan = workflow.validate_plan(plan)
    plan_path = workflow.write_record(records, saved_plan)
    workflow.write_run_state(path.parent, changed, current)
    return {
        "status": "awaiting_decision",
        "run_id": run_id,
        "plan_id": saved_plan["id"],
        "plan_sha256": workflow.record_hash(saved_plan),
        "record": plan_path.name,
    }


@server.tool()
def create_plan(
    target_id: str,
    baseline_id: str,
    plan_id: str,
    behavior_command: list[str] | None = None,
    e2e_behavior: bool = False,
    profile: str = "balanced",
    bla_intensity: str | None = None,
    performance_max_ms: int = 30000,
    performance_max_bytes: int = 64 * 1024 * 1024,
    performance_max_journey_regression_percent: float = 25,
) -> dict[str, Any]:
    """Create limited recommendations supported by saved baseline artifact hashes."""
    workflow._reference_id(target_id, "target id")
    workflow._reference_id(baseline_id, "baseline id")
    records = store_root() / "records"
    target = workflow.read_record(records / f"target-{target_id}.json", "target")
    baseline = workflow.read_record(
        records / f"baseline-{baseline_id}.json", "baseline"
    )
    plan = recommendations.create_plan(
        target,
        baseline,
        plan_id,
        behavior_command=behavior_command,
        e2e_behavior=e2e_behavior,
        profile=profile,
        bla_intensity=bla_intensity,
        performance_budget={
            "trials": 3,
            "max_elapsed_ms": performance_max_ms,
            "max_candidate_bytes": performance_max_bytes,
            "max_journey_regression_pct": performance_max_journey_regression_percent,
        },
    )
    path = workflow.write_record(records, plan)
    return {
        "status": "recommendations_ready" if plan["actions"] else "blocked",
        "id": plan["id"],
        "plan_sha256": workflow.record_hash(plan),
        "profile": plan["profile"],
        "plan": plan,
        "actions": plan["actions"],
        "blockers": plan.get("blockers", []),
        "record": path.name,
    }


@server.tool()
def execute_plan(
    run_id: str,
    action_id: str,
    bla_runtime: str | None = None,
    rea_runtime: str | None = None,
    e2e_runtime: str | None = None,
) -> dict[str, Any]:
    """Schedule the approved selection; action_id must be one selected action; poll get_run."""
    runtime = bla_runtime or os.environ.get("ANTI_REA_BLA_RUNTIME")
    rea_runtime = rea_runtime or os.environ.get("ANTI_REA_REA_RUNTIME")
    e2e_runtime = e2e_runtime or os.environ.get("ANTI_REA_E2E_RUNTIME")
    run_file = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(run_file))
    if current["state"] != "preparing":
        raise workflow.WorkflowError("Execution requires a preparing run")
    with _execution_jobs_lock:
        if run_id in _execution_jobs:
            raise workflow.WorkflowError(
                "An execution task is already active for this run"
            )
        _execution_jobs.add(run_id)
        cancel_event = threading.Event()
        control: dict[str, Any] = {"process": None, "kind": "execution"}
        _execution_controls[run_id] = (cancel_event, control)

    def work() -> None:
        try:
            execution.execute_bla_action(
                store_root(),
                run_id,
                action_id,
                runtime,
                cancel_event,
                lambda process: control.update(process=process),
                rea_runtime=rea_runtime,
                e2e_runtime=e2e_runtime,
            )
        except BaseException as error:
            if not (
                cancel_event.is_set()
                and isinstance(error, workflow.WorkflowError)
                and str(error) == "Command cancelled"
            ):
                print(f"Anti-REA BLA execution failed: {error}", file=sys.stderr)
            try:
                run = workflow.validate_run(workflow.read_json(run_file))
                if run["state"] == "preparing":
                    failed = workflow.transition_run(
                        run, "failed", error_code="bla_execution_failed"
                    )
                    workflow.write_run_state(run_file.parent, failed, run)
            except Exception:
                pass
        finally:
            with _execution_jobs_lock:
                _execution_jobs.discard(run_id)
                _execution_controls.pop(run_id, None)

    worker = threading.Thread(target=work, name=f"anti-rea-{run_id}", daemon=True)
    control["thread"] = worker
    try:
        worker.start()
    except BaseException:
        try:
            run = workflow.validate_run(workflow.read_json(run_file))
            if run["state"] == "preparing":
                failed = workflow.transition_run(
                    run, "failed", error_code="bla_execution_failed"
                )
                workflow.write_run_state(run_file.parent, failed, run)
        finally:
            with _execution_jobs_lock:
                _execution_jobs.discard(run_id)
                _execution_controls.pop(run_id, None)
        raise
    return {
        "status": "scheduled",
        "run_id": run_id,
        "state": "preparing",
        "execution_started": True,
        "poll_tool": "get_run",
    }


@server.tool()
def cancel_run(run_id: str) -> dict[str, Any]:
    """Cancel a run, terminate active work, and discard incomplete outputs."""
    path = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(path))
    with _execution_jobs_lock:
        active = _execution_controls.get(run_id)
        if active:
            event, control = active
            event.set()
            process = control.get("process")
            if process is not None and process.poll() is None:
                baseline_capture._stop_process(process)
        elif run_id not in _execution_jobs:
            if current["state"] == "baselining":
                baseline_id = current.get("baseline_id")
                if baseline_id is None:
                    raise workflow.WorkflowError(
                        "Only a completed asynchronous baseline can be cancelled through this tool"
                    )
                records = store_root() / "records"
                target = workflow.validate_target(
                    workflow.read_record(
                        records / f"target-{current['target_id']}.json", "target"
                    )
                )
                baseline = workflow.read_record(
                    records / f"baseline-{baseline_id}.json", "baseline"
                )
                if baseline.get("id") != baseline_id:
                    raise workflow.WorkflowError(
                        "Saved baseline id does not match the run"
                    )
                workflow.validate_baseline_target(baseline, target)
            if current["state"] in {
                "discovered",
                "baselining",
                "awaiting_decision",
                "needs_decision",
                "preparing",
                "verifying",
            }:
                if current["state"] == "verifying" and current.get("execution_id"):
                    execution.discard_candidate_if_active(store_root(), run_id)
                changed = workflow.transition_run(
                    current, "cancelled", cancellation_reason="user_requested"
                )
                workflow.write_run_state(path.parent, changed, current)
                return {"status": "cancelled", "run_id": run_id, "state": "cancelled"}
            raise workflow.WorkflowError(
                f"Run cannot be cancelled from {current['state']}"
            )
    return {
        "status": "cancellation_requested",
        "run_id": run_id,
        "state": current["state"],
    }


@server.tool()
def rollback_candidate(run_id: str) -> dict[str, Any]:
    """Discard the unchanged isolated BLA candidate for a verifying or completed run."""
    return execution.discard_candidate(store_root(), run_id)


@server.tool()
def save_evidence(record_type: str, record: dict[str, Any]) -> dict[str, Any]:
    """Persist immutable execution, verification, acceptance, or rollback evidence metadata."""
    value = workflow.validate_evidence_record(record, record_type)
    path = workflow.write_record(store_root() / "records", value)
    return {
        "status": "saved",
        "record_type": record_type,
        "id": value["id"],
        "record": path.name,
    }


@server.tool()
def get_evidence(record_type: str, record_id: str) -> dict[str, Any]:
    """Retrieve a persisted immutable execution, verification, acceptance, or rollback record."""
    if record_type not in {"execution", "verification", "acceptance", "rollback"}:
        raise workflow.WorkflowError("Unsupported evidence record type")
    workflow._reference_id(record_id, "evidence record id")
    value = workflow.read_record(
        store_root() / "records" / f"{record_type}-{record_id}.json", record_type
    )
    return workflow.validate_evidence_record(value, record_type)


@server.tool()
def create_run(target_id: str, run_id: str) -> dict[str, Any]:
    """Create a persistent run in discovered state."""
    workflow._reference_id(target_id, "target id")
    workflow._reference_id(run_id, "run id")
    record = {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "run",
        "id": run_id,
        "target_id": target_id,
        "state": "discovered",
    }
    workflow.validate_run(record)
    workflow.validate_target(
        workflow.read_record(
            store_root() / "records" / f"target-{target_id}.json", "target"
        )
    )
    path = workflow.write_run_state(store_root() / "runs", record, None)
    return {
        "status": "created",
        "id": run_id,
        "state": "discovered",
        "record": path.name,
    }


@server.tool()
def transition_run(
    run_id: str, next_state: str, updates: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Advance a run with compare-and-swap; completion awaits an independent acceptance gate."""
    if next_state == "completed":
        raise workflow.WorkflowError(
            "Only the evidence acceptance gate may complete a run"
        )
    path = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(path))
    changed = workflow.transition_run(current, next_state, **(updates or {}))
    saved = workflow.write_run_state(path.parent, changed, current)
    return {
        "status": "transitioned",
        "id": run_id,
        "state": changed["state"],
        "record": saved.name,
    }


@server.tool()
def record_decision(run_id: str, decision: dict[str, Any]) -> dict[str, Any]:
    """Record a client-transmitted user choice bound to the exact plan hash."""
    path_to_run = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(path_to_run))
    if current["state"] != "awaiting_decision":
        raise workflow.WorkflowError("Run is not awaiting a decision")
    records = store_root() / "records"
    approved_plan = workflow.validate_plan(
        workflow.read_record(records / f"plan-{current['plan_id']}.json", "plan")
    )
    changed = workflow.bind_decision(current, approved_plan, decision)
    choice = workflow.validate_decision(decision, approved_plan)
    path = workflow.write_record(records, choice)
    workflow.write_run_state(path_to_run.parent, changed, current)
    return {
        "status": "recorded",
        "id": choice["id"],
        "plan_sha256": choice["plan_sha256"],
        "decision": choice["decision"],
        "record": path.name,
        "human_choice_assertion": "The MCP client supplied this choice; the server cannot independently prove human approval.",
    }


@server.tool()
def authorize_run(run_id: str) -> dict[str, Any]:
    """Authorize the next run stage after matching an approved decision; performs no hardening."""
    path_to_run = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(path_to_run))
    if current["state"] not in {
        "awaiting_decision",
        "needs_decision",
    } or not current.get("decision_id"):
        raise workflow.WorkflowError(
            "Run is not ready for decision-bound authorization"
        )
    records = store_root() / "records"
    plan = workflow.validate_plan(
        workflow.read_record(records / f"plan-{current['plan_id']}.json", "plan")
    )
    decision = workflow.validate_decision(
        workflow.read_record(
            records / f"decision-{current['decision_id']}.json", "decision"
        ),
        plan,
    )
    started = workflow.start_execution(current, plan, decision)
    saved = workflow.write_run_state(path_to_run.parent, started, current)
    return {
        "status": "authorized",
        "id": run_id,
        "state": started["state"],
        "record": saved.name,
        "execution_started": False,
    }


@server.tool()
def resume_run(run_id: str, new_run_id: str) -> dict[str, Any]:
    """Prepare a fresh BLA attempt only after saved source, plan, decision, and prior evidence validate."""
    return execution.prepare_resume(store_root(), run_id, new_run_id)


@server.tool()
def get_run(run_id: str) -> dict[str, Any]:
    """Read the current persistent run record."""
    record = workflow.validate_run(workflow.read_json(run_path(run_id)))
    with _execution_jobs_lock:
        active = _execution_controls.get(run_id)
        kind = active[1].get("kind") if active else None
        return {
            **record,
            "operation_active": active is not None,
            "operation": kind,
            "execution_active": kind == "execution",
        }


@server.tool()
def get_report(run_id: str) -> dict[str, Any]:
    """Return a run and its linked validated records, including rollback evidence."""
    run = workflow.validate_run(workflow.read_json(run_path(run_id)))
    return workflow.assemble_run_report(store_root() / "records", run)


@server.tool()
def accept_run(
    run_id: str,
    execution_id: str,
    verification: dict[str, Any],
    acceptance: dict[str, Any],
) -> dict[str, Any]:
    """Accept passing evidence or record a bound rejection and quarantine its candidate."""
    path = run_path(run_id)
    current = workflow.validate_run(workflow.read_json(path))
    records = store_root() / "records"
    if not isinstance(execution_id, str) or not _ID.fullmatch(execution_id):
        raise workflow.WorkflowError("Invalid execution evidence id")
    target = workflow.read_record(
        records / f"target-{current['target_id']}.json", "target"
    )
    baseline = workflow.read_record(
        records / f"baseline-{current['baseline_id']}.json", "baseline"
    )
    plan = workflow.read_record(records / f"plan-{current['plan_id']}.json", "plan")
    decision = workflow.read_record(
        records / f"decision-{current['decision_id']}.json", "decision"
    )
    execution_record = workflow.read_record(
        records / f"execution-{execution_id}.json", "execution"
    )
    flutter_check_ids = {"flutter_aot_comparison", "flutter_android_behavior"}
    if (
        isinstance(verification, dict)
        and verification.get("id") != current.get("verification_id")
        and {
            check.get("id")
            for check in verification.get("checks", [])
            if isinstance(check, dict)
        }
        == flutter_check_ids
    ):
        current = workflow.refresh_blocked_flutter_verification(
            store_root(), run_id, verification
        )
    changed, acceptance = workflow.finalize_run(
        current,
        target,
        baseline,
        plan,
        decision,
        execution_record,
        verification,
        acceptance,
    )
    workflow.write_record(records, verification)
    workflow.write_record(records, acceptance)
    saved = workflow.write_run_state(path.parent, changed, current)
    quarantine = (
        execution.discard_candidate_if_active(store_root(), run_id)
        if changed["acceptance"] == "rejected"
        else None
    )
    return {
        "status": changed["acceptance"],
        "id": run_id,
        "state": changed["state"],
        "acceptance": changed["acceptance"],
        "record": saved.name,
        **(
            {"candidate_retained_at": quarantine["retained_at"]}
            if quarantine and "retained_at" in quarantine
            else {}
        ),
    }


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
