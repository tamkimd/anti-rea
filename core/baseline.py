"""Capture a bounded BEFORE build and its artifact identities."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core import discovery, workflow

MAX_OUTPUT_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARTIFACT_TREE_METADATA_BYTES = 64 * 1024 * 1024
_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def capture(
    project: str | Path,
    store: str | Path,
    argv: list[str],
    artifacts: list[str],
    baseline_id: str,
    timeout: float = 600,
    behavior_command: list[str] | None = None,
    e2e_runtime: str | Path | None = None,
    e2e_config: str = "e2e.config.mjs",
    e2e_test_file: str = "tests/behavior.e2e.ts",
    rea_runtime: str | Path | None = None,
    cancel_event=None,
    on_process=None,
    build_time_trials: int = 1,
    craft_anything_cli: str | Path | None = None,
) -> tuple[dict, Path]:
    """Run an explicit baseline command, retaining bounded output and artifact hashes.

    Supported Node build/behavior commands use the pinned offline Docker profile by
    default. `ANTI_REA_NODE_SANDBOX=host` explicitly opts into the bounded host runner;
    unsupported executables fail closed when Docker mode is selected.
    """
    project_alias = Path(project).expanduser().absolute()
    root = project_alias.resolve(strict=True)
    state = Path(store).expanduser().resolve()
    if (
        not root.is_dir()
        or state == root
        or root in state.parents
        or state in root.parents
    ):
        raise workflow.WorkflowError("State must be outside the project directory")
    if not isinstance(baseline_id, str) or not _ID.fullmatch(baseline_id):
        raise workflow.WorkflowError("Invalid baseline id")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(arg, str) or not arg for arg in argv)
        or not isinstance(artifacts, list)
        or not artifacts
        or any(not isinstance(path, str) or not path for path in artifacts)
        or len(set(artifacts)) != len(artifacts)
    ):
        raise workflow.WorkflowError("Provide a command and unique artifact paths")
    javascript_artifacts = [
        path
        for path in artifacts
        if Path(path).suffix.lower() in {".js", ".mjs", ".cjs"}
    ]
    if behavior_command is not None and (
        not isinstance(behavior_command, list)
        or not behavior_command
        or any(not isinstance(arg, str) or not arg for arg in behavior_command)
        or behavior_command.count("{artifact}") != 1
        or len(javascript_artifacts) != 1
    ):
        raise workflow.WorkflowError(
            "Behavior capture requires one JavaScript artifact and exactly one {artifact} argument"
        )
    if e2e_runtime is not None and (
        not javascript_artifacts
        or not isinstance(e2e_config, str)
        or not e2e_config
        or not isinstance(e2e_test_file, str)
        or not e2e_test_file
    ):
        raise workflow.WorkflowError(
            "Baseline e2e requires JavaScript artifacts and project-relative config/test files"
        )
    if rea_runtime is not None and not javascript_artifacts:
        raise workflow.WorkflowError(
            "Baseline REA requires at least one JavaScript artifact"
        )
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout <= 3600
    ):
        raise workflow.WorkflowError(
            "Timeout must be greater than 0 and at most 3600 seconds"
        )
    if (
        isinstance(build_time_trials, bool)
        or not isinstance(build_time_trials, int)
        or not 1 <= build_time_trials <= 5
    ):
        raise workflow.WorkflowError(
            "Build timing trials must be an integer from 1 to 5"
        )

    workflow._private_directory(state)
    target = discovery.inspect_project(root)
    records = state / "records"
    workflow.write_record(records, target)
    output_path = state / "evidence" / f"baseline-{baseline_id}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_path.parent.is_symlink() or not output_path.parent.is_dir():
        raise workflow.WorkflowError("Evidence path must be a real directory")
    if os.name != "nt":
        output_path.parent.chmod(0o700)
    if output_path.exists() or output_path.is_symlink():
        raise workflow.WorkflowError("Baseline evidence id already exists")
    trial_output_paths = [
        output_path.with_name(f"baseline-{baseline_id}-build-trial-{trial}.json")
        for trial in range(2, build_time_trials + 1)
    ]
    if any(path.exists() or path.is_symlink() for path in trial_output_paths):
        raise workflow.WorkflowError(
            "Baseline timing trial evidence path already exists"
        )
    trial_snapshot_paths = [
        output_path.parent / f"baseline-{baseline_id}-build-trial-{trial}-snapshot"
        for trial in range(2, build_time_trials + 1)
    ]
    if any(path.exists() or path.is_symlink() for path in trial_snapshot_paths):
        raise workflow.WorkflowError(
            "Baseline timing trial snapshot path already exists"
        )
    from core import execution

    build_snapshot = output_path.parent / f"baseline-{baseline_id}-build-snapshot"
    if build_snapshot.exists() or build_snapshot.is_symlink():
        raise workflow.WorkflowError("Baseline build snapshot path already exists")
    if any(path in artifacts for path in target.get("unfollowed_symlinks", [])):
        raise workflow.WorkflowError(
            "Artifact path is missing, linked, or escapes project"
        )
    if any(
        Path(path).is_relative_to(Path(artifact))
        for path in target.get("unfollowed_symlinks", [])
        for artifact in artifacts
        if Path(artifact).suffix.lower() in discovery.DIRECTORY_ARTIFACT_SUFFIXES
    ):
        raise workflow.WorkflowError(
            "Apple bundle builds with symlinks cannot be snapshotted safely"
        )
    build_snapshot.mkdir(mode=0o700)
    try:
        for item in target["files"]:
            if cancel_event is not None and cancel_event.is_set():
                raise workflow.WorkflowError("Command cancelled")
            execution._copy_project_file(
                root,
                item["path"],
                build_snapshot / item["path"],
                item["sha256"],
                item["size"],
                build_snapshot,
                cancel_event,
            )
    except BaseException:
        execution._remove_output(build_snapshot)
        raise
    source_tree = execution._snapshot_tree_identity(build_snapshot)
    build_runs = []
    build_duration_ms = None
    evidence = None
    for trial in range(1, build_time_trials + 1):
        trial_created = False
        try:
            if cancel_event is not None and cancel_event.is_set():
                raise workflow.WorkflowError("Command cancelled")
            trial_snapshot = build_snapshot
            if trial > 1:
                trial_snapshot = trial_snapshot_paths[trial - 2]
                trial_snapshot.mkdir(mode=0o700)
                trial_created = True
                for item in target["files"]:
                    if cancel_event is not None and cancel_event.is_set():
                        raise workflow.WorkflowError("Command cancelled")
                    execution._copy_project_file(
                        root,
                        item["path"],
                        trial_snapshot / item["path"],
                        item["sha256"],
                        item["size"],
                        trial_snapshot,
                        cancel_event,
                    )
            build_argv = _snapshot_argv(argv, root, trial_snapshot, project_alias)
            if cancel_event is not None and cancel_event.is_set():
                raise workflow.WorkflowError("Command cancelled")
            trial_started = time.time()
            build_started = time.monotonic()
            try:
                code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
                    _run_project_command(
                        build_argv, trial_snapshot, timeout, on_process, cancel_event
                    )
                )
            except OSError as error:
                raise workflow.WorkflowError(
                    f"Could not start baseline command: {error}"
                ) from error
            duration = round((time.monotonic() - build_started) * 1000)
            trial_output = output_path if trial == 1 else trial_output_paths[trial - 2]
            if timed_out or code != 0:
                trial_evidence = _write_output(
                    trial_output,
                    build_argv,
                    code,
                    stdout,
                    stderr,
                    trial_started,
                    elapsed_ms=duration,
                    timed_out=timed_out,
                    stdout_truncated=stdout_truncated,
                    stderr_truncated=stderr_truncated,
                )
                if trial == 1:
                    build_duration_ms, evidence = duration, trial_evidence
                reason = "timed out" if timed_out else f"exited {code}"
                raise workflow.WorkflowError(
                    f"Baseline command {reason}; evidence retained at {trial_output}"
                )
            try:
                trial_artifacts = {
                    path: _hash_artifact(trial_snapshot, path)["sha256"]
                    for path in artifacts
                }
            except (OSError, workflow.WorkflowError) as error:
                _write_output(
                    trial_output,
                    build_argv,
                    code,
                    stdout,
                    stderr,
                    trial_started,
                    stdout_truncated=stdout_truncated,
                    stderr_truncated=stderr_truncated,
                    elapsed_ms=duration,
                )
                raise workflow.WorkflowError(
                    f"Baseline artifact capture failed; evidence retained at "
                    f"{trial_output}: {error}"
                ) from error
            trial_evidence = _write_output(
                trial_output,
                build_argv,
                code,
                stdout,
                stderr,
                trial_started,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                elapsed_ms=duration,
                artifacts_sha256=trial_artifacts,
            )
            if trial == 1:
                build_duration_ms, evidence = duration, trial_evidence
            build_runs.append(
                {
                    "elapsed_ms": duration,
                    "artifacts": trial_artifacts,
                    "evidence_path": str(trial_evidence),
                    "evidence_sha256": hashlib.sha256(
                        trial_evidence.read_bytes()
                    ).hexdigest(),
                }
            )
        finally:
            if trial_created and (
                trial_snapshot.exists() or trial_snapshot.is_symlink()
            ):
                execution._remove_output(trial_snapshot)
    build_timing = None
    if build_time_trials > 1:
        durations = [item["elapsed_ms"] for item in build_runs]
        build_timing = {
            "trials": build_runs,
            "summary_ms": {
                "min": min(durations),
                "median": statistics.median(durations),
                "max": max(durations),
            },
            "identical_artifacts": all(
                item["artifacts"] == build_runs[0]["artifacts"]
                for item in build_runs[1:]
            ),
        }
    if any(
        Path(link).is_relative_to(Path(artifact))
        for link in discovery.inspect_project(build_snapshot)["unfollowed_symlinks"]
        for artifact in artifacts
        if Path(artifact).suffix.lower() in discovery.DIRECTORY_ARTIFACT_SUFFIXES
    ):
        raise workflow.WorkflowError(
            "Apple bundle builds with symlinks cannot be snapshotted safely"
        )

    identities = {}
    try:
        for relative in artifacts:
            identities[relative] = _hash_artifact(build_snapshot, relative)
            if (
                identities[relative].get("kind") == "directory"
                and discovery.inspect_project(build_snapshot)["unfollowed_symlinks"]
            ):
                raise workflow.WorkflowError(
                    "Apple bundle builds with symlinks or unlisted files cannot be snapshotted safely"
                )
    except (OSError, workflow.WorkflowError) as error:
        output_path.unlink(missing_ok=True)
        raise workflow.WorkflowError(
            f"Baseline artifact capture failed: {error}"
        ) from error
    behavior_identity = None
    e2e_identity = None
    rea_identity = None
    analysis_engines = {}
    evidence_paths = [str(output_path), *(str(path) for path in trial_output_paths)]
    if behavior_command is not None:
        relative = javascript_artifacts[0]
        snapshot_path = output_path.parent / f"baseline-{baseline_id}-behavior-snapshot"
        if snapshot_path.exists() or snapshot_path.is_symlink():
            raise workflow.WorkflowError(
                "Baseline behavior snapshot path already exists"
            )
        snapshot_path.mkdir(mode=0o700)
        try:
            for item in discovery.inspect_project(build_snapshot)["files"]:
                execution._copy_project_file(
                    build_snapshot,
                    item["path"],
                    snapshot_path / item["path"],
                    item["sha256"],
                    item["size"],
                    snapshot_path,
                    cancel_event,
                )
        except BaseException:
            execution._remove_output(snapshot_path)
            raise
        before_snapshot = execution._snapshot_tree_identity(snapshot_path)
        behavior_argv = [
            str(snapshot_path / relative) if arg == "{artifact}" else arg
            for arg in behavior_command
        ]
        behavior_path = output_path.with_name(f"baseline-{baseline_id}-behavior.json")
        try:
            code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
                _run_project_command(
                    behavior_argv, snapshot_path, timeout, on_process, cancel_event
                )
            )
        except OSError as error:
            raise workflow.WorkflowError(
                f"Could not start baseline behavior command: {error}"
            ) from error
        behavior_evidence = _write_output(
            behavior_path,
            behavior_argv,
            code,
            stdout,
            stderr,
            time.time(),
            timed_out=timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )
        after_behavior = _hash_artifact(snapshot_path, relative)
        if after_behavior != identities[relative]:
            raise workflow.WorkflowError(
                "Baseline artifact changed during behavior verification; evidence retained at "
                f"{behavior_path}"
            )
        if timed_out or code != 0 or stdout_truncated or stderr_truncated:
            reason = (
                "timed out"
                if timed_out
                else f"exited {code}"
                if code
                else "exceeded its output limit"
            )
            raise workflow.WorkflowError(
                f"Baseline behavior command {reason}; evidence retained at {behavior_path}"
            )
        behavior_sha256 = hashlib.sha256(behavior_evidence.read_bytes()).hexdigest()
        after_snapshot = execution._snapshot_tree_identity(snapshot_path)
        behavior_identity = {
            "command": behavior_command,
            "artifact": relative,
            "artifact_sha256": identities[relative]["sha256"],
            "snapshot_path": str(snapshot_path),
            "snapshot_source_tree_sha256": before_snapshot["tree_sha256"],
            "snapshot_tree_sha256": after_snapshot["tree_sha256"],
            "snapshot_file_scope_sha256": after_snapshot["file_scope_sha256"],
            "evidence_path": str(behavior_evidence),
            "evidence_sha256": behavior_sha256,
        }
        evidence_paths.append(str(behavior_evidence))
    if e2e_runtime is not None:
        e2e_identity, report_path = _capture_e2e(
            build_snapshot,
            state,
            target,
            identities,
            baseline_id,
            e2e_runtime,
            e2e_config,
            e2e_test_file,
            cancel_event,
            on_process,
        )
        evidence_paths.append(str(report_path))
    analysis_jobs = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        analysis_jobs["craft-anything"] = pool.submit(
            _capture_craft_anything,
            build_snapshot,
            state,
            baseline_id,
            craft_anything_cli,
            timeout,
            cancel_event,
            on_process,
        )
        if rea_runtime is not None:
            analysis_jobs["rea"] = pool.submit(
                _capture_rea,
                build_snapshot,
                state,
                target,
                identities,
                baseline_id,
                rea_runtime,
                cancel_event,
                on_process,
            )
        for engine, future in analysis_jobs.items():
            try:
                captured = future.result()
            except Exception as error:
                analysis_engines[engine] = {
                    "engine": engine,
                    "status": "failed",
                    "reason": str(error),
                }
            else:
                if engine == "rea":
                    rea_identity, rea_report, rea_bundle = captured
                    analysis_engines[engine] = {
                        "engine": engine,
                        "status": "passed",
                        "mode": "javascript-static-analysis",
                        "version": "6.8.0",
                        "input_sha256": rea_identity["tree_sha256"],
                        "coverage": rea_identity["coverage"],
                        "report_path": str(rea_report),
                        "report_sha256": rea_identity["report_sha256"],
                        "evidence_path": str(rea_bundle),
                        "evidence_sha256": rea_identity["bundle_sha256"],
                    }
                    evidence_paths.extend((str(rea_report), str(rea_bundle)))
                else:
                    engine_record, report_paths = captured
                    analysis_engines[engine] = engine_record
                    if isinstance(report_paths, (str, Path)):
                        report_paths = [report_paths]
                    evidence_paths.extend(str(path) for path in report_paths)
    if "rea" not in analysis_engines:
        analysis_engines["rea"] = {
            "engine": "rea",
            "status": "unavailable",
            "reason": "No REA runtime was selected for this baseline.",
        }
    flutter_lock = None
    flutter_toolchain = None
    if any(
        "flutter" in component.get("runtimes", [])
        for component in target.get("components", [])
    ):
        try:
            flutter_lock = _hash_artifact(build_snapshot, "pubspec.lock")["sha256"]
        except (OSError, workflow.WorkflowError):
            flutter_lock = None
        if len(argv) >= 4 and argv[1:4] in (
            ["build", "apk", "--release"],
            ["build", "appbundle", "--release"],
        ):
            from core import flutter_android

            flutter_toolchain = flutter_android.capture_toolchain_identity(argv, root)
    baseline = {
        "schema_version": workflow.SCHEMA_VERSION,
        "record_type": "baseline",
        "id": baseline_id,
        "target_id": target["id"],
        "identity": {
            "source": target["source_identity"],
            "inventory_sha256": target["inventory"]["sha256"],
            "command": argv,
            "artifacts": identities,
            "build_duration_ms": build_duration_ms,
            **({"build_timing": build_timing} if build_timing else {}),
            "build_snapshot": {
                "path": str(build_snapshot),
                "source_tree_sha256": source_tree["tree_sha256"],
                "tree_sha256": execution._snapshot_tree_identity(build_snapshot)[
                    "tree_sha256"
                ],
                "file_scope_sha256": execution._snapshot_tree_identity(build_snapshot)[
                    "file_scope_sha256"
                ],
            },
            **({"dependency_lock_sha256": flutter_lock} if flutter_lock else {}),
            **({"flutter_toolchain": flutter_toolchain} if flutter_toolchain else {}),
            "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            **({"behavior": behavior_identity} if behavior_identity else {}),
            **({"e2e_behavior": e2e_identity} if e2e_identity else {}),
            **({"rea_analysis": rea_identity} if rea_identity else {}),
            "analysis_engines": analysis_engines,
        },
        "evidence": evidence_paths,
    }
    workflow.validate_baseline_target(baseline, target)
    if cancel_event is not None and cancel_event.is_set():
        raise workflow.WorkflowError("Command cancelled")
    try:
        workflow.write_record(records, baseline)
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise
    return baseline, evidence


def _capture_craft_anything(
    root: Path,
    state: Path,
    baseline_id: str,
    cli: str | Path | None,
    timeout: float,
    cancel_event=None,
    on_process=None,
) -> tuple[dict, list[Path]]:
    """Capture Craft Anything triage in an external per-baseline project."""
    from core import craft_anything_integration

    report_path = state / "evidence" / f"baseline-{baseline_id}-craft-anything.json"
    result = craft_anything_integration.analyze(
        root,
        state / "evidence" / f"baseline-{baseline_id}-craft-anything",
        timeout=min(timeout, 600),
        cli=str(cli) if cli is not None else None,
        report_path=report_path,
        cancel_event=cancel_event,
        on_process=on_process,
    )
    status = result["status"]
    if status == "supported":
        status = "passed"
    raw_evidence_ref = None
    evidence_path = result.get("evidence_path")
    if isinstance(evidence_path, str) and Path(evidence_path).is_file():
        raw_evidence_ref = {
            "path": evidence_path,
            "sha256": hashlib.sha256(Path(evidence_path).read_bytes()).hexdigest(),
        }
    record_path = report_path.with_name(report_path.stem + "-record.json")
    report = {
        "schema_version": "1.0",
        "engine": "craft-anything",
        "status": status,
        "mode": result.get("mode", "deep"),
        "version": result.get("version"),
        "input": result.get("input"),
        "coverage": (
            result.get("evidence", {}).get("coverage")
            if isinstance(result.get("evidence"), dict)
            else None
        ),
        "evidence": result.get("evidence"),
        "upstream_evidence": raw_evidence_ref,
        "reason": result.get("error"),
    }
    record_path.write_bytes(workflow.canonical(report) + b"\n")
    if os.name != "nt":
        record_path.chmod(0o600)
    report_ref = {
        "path": str(record_path),
        "sha256": hashlib.sha256(record_path.read_bytes()).hexdigest(),
    }
    engine = {
        "engine": "craft-anything",
        "status": status,
        "mode": result.get("mode", "deep"),
        "version": result.get("version"),
        "input_sha256": result.get("input", {}).get("sha256"),
        "coverage": (
            result.get("evidence", {}).get("coverage")
            if isinstance(result.get("evidence"), dict)
            else None
        ),
        "evidence": report_ref,
        "upstream_evidence": raw_evidence_ref,
        "project": result.get("project"),
        "reason": result.get("error"),
    }
    return engine, [
        path
        for path in (Path(evidence_path) if raw_evidence_ref else None, record_path)
        if path is not None
    ]


def _capture_e2e(
    root: Path,
    state: Path,
    target: dict,
    artifacts: dict,
    baseline_id: str,
    runtime: str | Path,
    config: str,
    test_file: str,
    cancel_event=None,
    on_process=None,
) -> tuple[dict, Path]:
    """Run the pinned browser lane against a private, baseline-hash-bound project snapshot."""
    from core import execution

    source_path = next(
        path
        for path in artifacts
        if Path(path).suffix.lower() in {".js", ".mjs", ".cjs"}
    )
    artifact = artifacts[source_path]
    runtime_path = Path(runtime).expanduser()
    if runtime_path.is_symlink():
        raise workflow.WorkflowError("e2e runtime symlink refused")
    runtime_path = runtime_path.resolve(strict=True)
    if any(
        path == runtime_path
        or path in runtime_path.parents
        or runtime_path in path.parents
        for path in (root, state)
    ):
        raise workflow.WorkflowError(
            "e2e runtime, target, and Anti-REA state must be separate directory trees"
        )
    if target.get("unfollowed_symlinks"):
        raise workflow.WorkflowError("Baseline e2e snapshot refuses project symlinks")

    snapshot_root = state / "evidence" / f"baseline-{baseline_id}-e2e"
    if snapshot_root.exists() or snapshot_root.is_symlink():
        raise workflow.WorkflowError("Baseline e2e evidence path already exists")
    snapshot_root.mkdir(mode=0o700)
    snapshot = snapshot_root / "snapshot"
    snapshot.mkdir(mode=0o700)

    current = discovery.inspect_project(root)
    if current["unfollowed_symlinks"]:
        raise workflow.WorkflowError("Baseline e2e snapshot refuses project symlinks")
    original = {item["path"]: item["sha256"] for item in target.get("files", [])}
    current_files = {item["path"]: item for item in current["files"]}
    artifact_paths = set(artifacts)
    for path, digest in original.items():
        if (
            path not in artifact_paths
            and current_files.get(path, {}).get("sha256") != digest
        ):
            raise workflow.WorkflowError(
                f"Baseline e2e source input changed during build: {path}"
            )
    if any(
        path not in original and path not in artifact_paths for path in current_files
    ):
        raise workflow.WorkflowError(
            "Baseline e2e refuses unbaselined project files added during build"
        )

    try:
        for path, item in current_files.items():
            if path not in artifact_paths:
                execution._copy_project_file(
                    root,
                    path,
                    snapshot / path,
                    item["sha256"],
                    item["size"],
                    snapshot,
                    cancel_event,
                )
        for path, identity in artifacts.items():
            actual = _hash_artifact(root, path)
            if actual != identity:
                raise workflow.WorkflowError(
                    f"Baseline e2e artifact changed after hashing: {path}"
                )
            execution._copy_project_file(
                root,
                path,
                snapshot / path,
                identity["sha256"],
                identity["size"],
                snapshot,
                cancel_event,
            )
    except BaseException:
        execution._remove_output(snapshot_root)
        raise

    snapshot_identity = execution._snapshot_tree_identity(snapshot)
    with tempfile.TemporaryDirectory(
        prefix="anti-rea-e2e-baseline-", dir=runtime_path
    ) as temporary:
        project_copy = Path(temporary) / "before"
        shutil.copytree(snapshot, project_copy)
        result = execution._invoke_e2e(
            execution._e2e_script(),
            [
                "run",
                str(project_copy),
                str(runtime_path),
                ".anti-rea-e2e/baseline",
                "--stage",
                "before",
                "--config",
                config,
                "--test-file",
                test_file,
            ],
            360,
            cancel_event,
            on_process,
        )
        report_bytes = workflow.verify_evidence_file(
            {"path": result["report"], "sha256": result["report_sha256"]}
        )
    report_path = snapshot_root / "report.json"
    execution._write_snapshot_file(report_path, report_bytes)
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    if (
        result["status"] != "passed"
        or result["cleanup"] != "loopback app port closed"
        or execution._snapshot_tree_identity(snapshot) != snapshot_identity
        or _hash_artifact(snapshot, source_path) != artifact
    ):
        raise workflow.WorkflowError(
            f"Baseline e2e did not pass against an unchanged snapshot; report retained at {report_path}"
        )
    return (
        {
            "source_path": source_path,
            "artifact_sha256": artifact["sha256"],
            "snapshot_path": str(snapshot),
            **snapshot_identity,
            "report_path": str(report_path),
            "report_sha256": report_hash,
            "runtime_path": str(runtime_path),
            "runtime_manifest_sha256": result["runtime_manifest_sha256"],
            "runtime_package_lock_sha256": result["runtime_package_lock_sha256"],
            "runner": result["runner"],
            "test_ids": result["test_ids"],
            **(
                {"performance_metrics": result["performance_metrics"]}
                if result.get("performance_metrics")
                else {}
            ),
            "config": config,
            "test_file": test_file,
            "cleanup": result["cleanup"],
        },
        report_path,
    )


def _capture_rea(
    root: Path,
    state: Path,
    target: dict,
    artifacts: dict,
    baseline_id: str,
    runtime: str | Path,
    cancel_event=None,
    on_process=None,
) -> tuple[dict, Path, Path]:
    from core import execution

    adapter_path = execution._rea_script()
    import importlib.util

    spec = importlib.util.spec_from_file_location("anti_rea_baseline_rea", adapter_path)
    if spec is None or spec.loader is None:
        raise workflow.WorkflowError("Pinned REA adapter is unavailable")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    runtime_path = Path(runtime).expanduser()
    if runtime_path.is_symlink():
        raise workflow.WorkflowError("REA runtime symlink refused")
    runtime_path = runtime_path.resolve(strict=True)
    if any(
        path == runtime_path
        or path in runtime_path.parents
        or runtime_path in path.parents
        for path in (root, state)
    ):
        raise workflow.WorkflowError(
            "REA runtime, target, and Anti-REA state must be separate directory trees"
        )
    if target.get("unfollowed_symlinks"):
        raise workflow.WorkflowError("Baseline REA snapshot refuses project symlinks")
    source_path = next(
        path
        for path in artifacts
        if Path(path).suffix.lower() in {".js", ".mjs", ".cjs"}
    )
    artifact = artifacts[source_path]
    snapshot_root = state / "evidence" / f"baseline-{baseline_id}-rea"
    snapshot_root.mkdir(mode=0o700)
    snapshot = snapshot_root / "snapshot"
    snapshot.mkdir(mode=0o700)
    current = discovery.inspect_project(root)
    if current["unfollowed_symlinks"]:
        raise workflow.WorkflowError("Baseline REA snapshot refuses project symlinks")
    original = {item["path"]: item["sha256"] for item in target.get("files", [])}
    current_files = {item["path"]: item for item in current["files"]}
    artifact_paths = set(artifacts)
    for path, digest in original.items():
        if (
            path not in artifact_paths
            and current_files.get(path, {}).get("sha256") != digest
        ):
            raise workflow.WorkflowError(
                f"Baseline REA source input changed during build: {path}"
            )
    if any(
        path not in original and path not in artifact_paths for path in current_files
    ):
        raise workflow.WorkflowError(
            "Baseline REA refuses unbaselined project files added during build"
        )
    try:
        for path, item in current_files.items():
            if path not in artifact_paths:
                execution._copy_project_file(
                    root,
                    path,
                    snapshot / path,
                    item["sha256"],
                    item["size"],
                    snapshot,
                    cancel_event,
                )
        for path, identity in artifacts.items():
            if _hash_artifact(root, path) != identity:
                raise workflow.WorkflowError(
                    f"Baseline REA artifact changed after hashing: {path}"
                )
            execution._copy_project_file(
                root,
                path,
                snapshot / path,
                identity["sha256"],
                identity["size"],
                snapshot,
                cancel_event,
            )
    except BaseException:
        execution._remove_output(snapshot_root)
        raise
    tree = execution._snapshot_tree_identity(snapshot)
    report_path, bundle_path = (
        snapshot_root / "report.jsonl",
        snapshot_root / "bundle.json",
    )
    try:
        code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
            _run_command(
                [
                    sys.executable,
                    str(adapter_path),
                    "analyze-javascript",
                    str(runtime_path),
                    str(snapshot),
                    str(report_path),
                    str(bundle_path),
                ],
                adapter_path.parent,
                360,
                on_process,
                cancel_event,
            )
        )
        if timed_out or stdout_truncated or stderr_truncated:
            raise workflow.WorkflowError(
                "REA baseline analysis timed out or exceeded its output budget"
            )
        try:
            result = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise workflow.WorkflowError(
                "REA baseline adapter returned invalid JSON"
            ) from error
        if code or not isinstance(result, dict) or result.get("status") != "passed":
            raise workflow.WorkflowError(f"REA baseline analysis failed: {result}")
        summary, normalized, stats, coverage = adapter._analysis_summary(report_path)
        if os.name != "nt":
            report_path.chmod(0o600)
            bundle_path.chmod(0o600)
    except Exception as error:
        raise workflow.WorkflowError(
            f"Baseline REA analysis failed: {error}"
        ) from error
    if (
        _hash_artifact(snapshot, source_path)["sha256"] != artifact["sha256"]
        or execution._snapshot_tree_identity(snapshot) != tree
    ):
        raise workflow.WorkflowError("Baseline REA snapshot changed during analysis")
    runtime_manifest = adapter.verify_runtime(runtime_path)[1]
    manifest_sha = hashlib.sha256(
        json.dumps(runtime_manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return (
        {
            "source_path": source_path,
            "artifact_sha256": artifact["sha256"],
            "snapshot_path": str(snapshot),
            **tree,
            "report_path": str(report_path),
            "report_sha256": result["report_sha256"],
            "bundle_path": str(bundle_path),
            "bundle_sha256": result["evidence_bundle_sha256"],
            "runtime_path": str(runtime_path),
            "runtime_manifest_sha256": manifest_sha,
            "evidence_id": normalized["parent_evidence_id"],
            "parent_digest": normalized["parent_digest"],
            "statistics": stats,
            "coverage": coverage,
        },
        report_path,
        bundle_path,
    )


def _hash_artifact(root: Path, relative: str) -> dict[str, int | str]:
    if (
        os.open not in os.supports_dir_fd
        or not getattr(os, "O_NOFOLLOW", 0)
        or not getattr(os, "O_DIRECTORY", 0)
    ):
        raise workflow.WorkflowError(
            "Safe artifact hashing is unavailable on this platform"
        )
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise workflow.WorkflowError("Artifact paths must stay inside the project")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow)
    opened = [directory]
    try:
        for part in candidate.parts[:-1]:
            directory = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow,
                dir_fd=directory,
            )
            opened.append(directory)
        fd = os.open(
            candidate.parts[-1],
            os.O_RDONLY
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory,
        )
        opened.append(fd)
        before = os.fstat(fd)
        if stat.S_ISDIR(before.st_mode):
            if candidate.suffix.lower() not in discovery.DIRECTORY_ARTIFACT_SUFFIXES:
                raise workflow.WorkflowError(
                    f"Only Apple app and framework directories are supported artifacts: {relative}"
                )
            return _hash_directory_artifact(fd, relative)
        if not stat.S_ISREG(before.st_mode):
            raise workflow.WorkflowError(f"Artifact is not a regular file: {relative}")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                raise workflow.WorkflowError(
                    f"Artifact exceeds size budget: {relative}"
                )
            digest.update(chunk)
        after = os.fstat(fd)

        def identity(info):
            return (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        if identity(before) != identity(after) or size != before.st_size:
            raise workflow.WorkflowError(
                f"Artifact changed during baseline capture: {relative}"
            )
        return {"size": size, "sha256": digest.hexdigest()}
    except OSError as error:
        raise workflow.WorkflowError(
            f"Artifact path is missing, linked, or escapes project: {relative}"
        ) from error
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _hash_directory_artifact(root_fd: int, label: str) -> dict[str, int | str]:
    if (
        not getattr(os, "O_NOFOLLOW", 0)
        or not getattr(os, "O_DIRECTORY", 0)
        or os.open not in os.supports_dir_fd
    ):
        raise workflow.WorkflowError(
            "Safe artifact hashing is unavailable on this platform"
        )
    entries = []
    total_bytes = 0
    metadata_bytes = 0
    root_mode = stat.S_IMODE(os.fstat(root_fd).st_mode) & 0o777

    def add(entry: dict) -> None:
        nonlocal metadata_bytes
        metadata_bytes += (
            len(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()) + 1
        )
        if (
            len(entries) >= discovery.MAX_ENTRIES
            or metadata_bytes > MAX_ARTIFACT_TREE_METADATA_BYTES
        ):
            raise workflow.WorkflowError(
                f"Artifact exceeds tree metadata budget: {label}"
            )
        entries.append(entry)

    def visit(directory_fd: int, prefix: str) -> None:
        nonlocal total_bytes
        before = os.fstat(directory_fd)
        with os.scandir(directory_fd) as listing:
            names = sorted(item.name for item in listing)
        for name in names:
            relative = f"{prefix}/{name}" if prefix else name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode) & 0o777
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(name, dir_fd=directory_fd)
                add({"path": relative, "type": "symlink", "target": target})
            elif stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino, stat.S_IMODE(opened.st_mode)) != (
                        metadata.st_dev,
                        metadata.st_ino,
                        stat.S_IMODE(metadata.st_mode),
                    ):
                        raise workflow.WorkflowError(
                            f"Artifact directory changed during capture: {label}/{relative}"
                        )
                    add({"path": relative, "type": "directory", "mode": mode})
                    visit(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(metadata.st_mode):
                fd = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NONBLOCK,
                    dir_fd=directory_fd,
                )
                try:
                    before_file = os.fstat(fd)
                    if not stat.S_ISREG(before_file.st_mode) or (
                        before_file.st_dev,
                        before_file.st_ino,
                        before_file.st_size,
                        before_file.st_mtime_ns,
                        before_file.st_ctime_ns,
                        stat.S_IMODE(before_file.st_mode),
                    ) != (
                        metadata.st_dev,
                        metadata.st_ino,
                        metadata.st_size,
                        metadata.st_mtime_ns,
                        metadata.st_ctime_ns,
                        stat.S_IMODE(metadata.st_mode),
                    ):
                        raise workflow.WorkflowError(
                            f"Artifact file changed during capture: {label}/{relative}"
                        )
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := os.read(fd, 1024 * 1024):
                        size += len(chunk)
                        total_bytes += len(chunk)
                        if total_bytes > MAX_ARTIFACT_BYTES:
                            raise workflow.WorkflowError(
                                f"Artifact exceeds size budget: {label}"
                            )
                        digest.update(chunk)
                    after_file = os.fstat(fd)
                    if (
                        before_file.st_dev,
                        before_file.st_ino,
                        before_file.st_size,
                        before_file.st_mtime_ns,
                        before_file.st_ctime_ns,
                    ) != (
                        after_file.st_dev,
                        after_file.st_ino,
                        after_file.st_size,
                        after_file.st_mtime_ns,
                        after_file.st_ctime_ns,
                    ) or size != before_file.st_size:
                        raise workflow.WorkflowError(
                            f"Artifact file changed during capture: {label}/{relative}"
                        )
                    add(
                        {
                            "path": relative,
                            "type": "file",
                            "mode": mode,
                            "size": size,
                            "sha256": digest.hexdigest(),
                        }
                    )
                finally:
                    os.close(fd)
            else:
                raise workflow.WorkflowError(
                    f"Artifact contains a non-regular entry: {label}/{relative}"
                )
        after = os.fstat(directory_fd)
        if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise workflow.WorkflowError(
                f"Artifact directory changed during capture: {label}/{prefix}"
            )

    visit(root_fd, "")
    payload = json.dumps(
        {"format": "anti-rea-tree-v1", "root_mode": root_mode, "entries": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "kind": "directory",
        "size": total_bytes,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _write_output(
    path: Path,
    argv: list[str],
    exit_code: int | None,
    stdout: bytes,
    stderr: bytes,
    started: float,
    timed_out: bool = False,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
    elapsed_ms: int | None = None,
    artifacts_sha256: dict[str, str] | None = None,
) -> Path:
    payload = {
        "argv": argv,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stdout_truncated": stdout_truncated,
        "stderr": stderr.decode("utf-8", errors="replace"),
        "stderr_truncated": stderr_truncated,
        "started_at": started,
        "finished_at": time.time(),
    }
    if elapsed_ms is not None:
        payload["elapsed_ms"] = elapsed_ms
    if artifacts_sha256 is not None:
        payload["artifacts_sha256"] = artifacts_sha256
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return path


def _snapshot_argv(
    argv: list[str], root: Path, snapshot: Path, project_alias: Path | None = None
) -> list[str]:
    output = []
    private = str(snapshot)
    sources = {str(root)}
    if project_alias is not None and project_alias.is_absolute():
        sources.add(str(project_alias))
    for arg in argv:
        path = Path(arg).expanduser()
        try:
            relative = (
                path.resolve(strict=False).relative_to(root)
                if path.is_absolute()
                else None
            )
        except (OSError, ValueError):
            relative = None
        if relative is not None:
            output.append(str(snapshot / relative))
        else:
            for source in sources:
                arg = arg.replace(source + os.sep, private + os.sep)
            output.append(arg)
    return output


def _run_command(
    argv: list[str],
    root: Path,
    timeout: float,
    on_start=None,
    cancel_event=None,
    env=None,
    total_output_limit: int | None = None,
    cleanup_grace: float = 1,
) -> tuple[int | None, bytes, bytes, bool, bool, bool]:
    if total_output_limit is not None and (
        isinstance(total_output_limit, bool)
        or not isinstance(total_output_limit, int)
        or total_output_limit < 1
    ):
        raise workflow.WorkflowError("Output limit must be a positive integer")
    process = subprocess.Popen(
        argv,
        cwd=root,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.copy() if env is None else env,
        start_new_session=(os.name != "nt"),
        **_process_creation_options(),
    )
    _contain_process_tree(process)
    captured = [bytearray(), bytearray()]
    truncated = [False, False]
    output_exceeded = threading.Event()
    capture_lock = threading.Lock()
    total_captured = 0

    def drain(stream, output, index):
        nonlocal total_captured
        while chunk := stream.read(64 * 1024):
            with capture_lock:
                remaining = (
                    MAX_OUTPUT_BYTES - len(output)
                    if total_output_limit is None
                    else total_output_limit - total_captured
                )
                accepted = chunk[: max(remaining, 0)]
                output.extend(accepted)
                if total_output_limit is not None:
                    total_captured += len(accepted)
                if len(chunk) > max(remaining, 0):
                    truncated[index] = True
                    if total_output_limit is not None:
                        output_exceeded.set()

    readers = []
    try:
        if on_start:
            on_start(process)
        pending_readers = [
            threading.Thread(
                target=drain, args=(process.stdout, captured[0], 0), daemon=True
            ),
            threading.Thread(
                target=drain, args=(process.stderr, captured[1], 1), daemon=True
            ),
        ]
        for reader in pending_readers:
            reader.start()
            readers.append(reader)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                _stop_process(process, cleanup_grace)
                raise workflow.WorkflowError("Command cancelled")
            if output_exceeded.is_set():
                _stop_process(process, cleanup_grace)
                timed_out = False
                break
            if time.monotonic() >= deadline:
                _stop_process(process, cleanup_grace)
                timed_out = True
                break
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        else:
            timed_out = False
    except BaseException:
        group_exists = False
        group_probe_failed = False
        if os.name != "nt":
            try:
                os.killpg(process.pid, 0)
                group_exists = True
            except ProcessLookupError:
                pass
            except PermissionError:
                group_exists = True
            except OSError:
                group_probe_failed = True
        if os.name == "nt":
            _close_process_tree(process)
        if process.poll() is None or group_exists or group_probe_failed:
            _stop_process(process, cleanup_grace)
        for stream in (process.stdout, process.stderr):
            if stream:
                stream.close()
        for reader in readers:
            reader.join()
        raise
    for reader in readers:
        reader.join(timeout=1)
    if any(reader.is_alive() for reader in readers):
        _stop_process(process, cleanup_grace)
        for stream in (process.stdout, process.stderr):
            if stream:
                stream.close()
        for reader in readers:
            reader.join(timeout=1)
    process.stdout.close()
    process.stderr.close()
    _close_process_tree(process)
    if cancel_event is not None and cancel_event.is_set():
        raise workflow.WorkflowError("Command cancelled")
    return (
        None if timed_out else process.returncode,
        bytes(captured[0]),
        bytes(captured[1]),
        timed_out,
        truncated[0],
        truncated[1],
    )


def _run_project_command(
    argv: list[str], root: Path, timeout: float, on_start=None, cancel_event=None
) -> tuple[int | None, bytes, bytes, bool, bool, bool]:
    """Run baseline build and behavior code in the selected project sandbox."""
    from scripts import rea_integration

    try:
        mode = rea_integration._sandbox_mode()
    except rea_integration.IntegrationError as error:
        raise workflow.WorkflowError(str(error)) from error
    if mode == "host":
        return _run_command(argv, root, timeout, on_start, cancel_event)
    if not argv or Path(argv[0]).name not in {"node", "npm", "npx"}:
        executable = Path(argv[0]).name if argv else "<empty>"
        raise workflow.WorkflowError(
            f"No Docker project-command profile for {executable}; use node, npm, or npx, "
            "or explicitly set ANTI_REA_NODE_SANDBOX=host"
        )

    root = Path(root).resolve(strict=True)
    command = [Path(argv[0]).name]
    for argument in argv[1:]:
        flag, separator, value = argument.partition("=")
        path = Path(value if separator else argument)
        if path.is_absolute():
            try:
                relative = path.resolve(strict=False).relative_to(root)
            except ValueError as error:
                raise workflow.WorkflowError(
                    "Docker project commands cannot mount absolute paths outside the private snapshot"
                ) from error
            mapped = "/work" + ("/" + relative.as_posix() if relative.parts else "")
            argument = f"{flag}={mapped}" if separator else mapped
        command.append(argument)
    try:
        docker_command, container_name, _, output_staging = (
            rea_integration._docker_command(
                command, root, writable_cwd=True, network=False
            )
        )
    except rea_integration.IntegrationError as error:
        raise workflow.WorkflowError(str(error)) from error
    try:
        return _run_command(docker_command, root, timeout, on_start, cancel_event)
    finally:
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        output_staging.cleanup()


def _stop_process(process: subprocess.Popen, grace_period: float = 1) -> None:
    try:
        if os.name != "nt":
            deadline = time.monotonic() + grace_period
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
            while True:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(min(0.05, deadline - time.monotonic()))
        else:
            _close_process_tree(process)
            if process.poll() is None:
                process.kill()
    except ProcessLookupError:
        pass
    process.wait()


def _contain_process_tree(process: subprocess.Popen) -> None:
    """On Windows, assign a suspended process to a kill-on-close job before it runs."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry32))
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry32))
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = (wintypes.HANDLE,)
    kernel32.ResumeThread.restype = wintypes.DWORD
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        error = OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        _kill_uncontained_process(process)
        raise workflow.WorkflowError(
            f"Could not contain Windows command process tree: {error}"
        ) from error
    info = ExtendedLimitInformation()
    info.BasicLimitInformation.LimitFlags = (
        0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    try:
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
        if not kernel32.AssignProcessToJobObject(
            job, wintypes.HANDLE(int(process._handle))
        ):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
        try:
            entry = ThreadEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            thread_ids = []
            if kernel32.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == process.pid:
                        thread_ids.append(entry.th32ThreadID)
                    if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                        break
            if len(thread_ids) != 1:
                raise OSError(
                    ctypes.get_last_error(),
                    "Could not identify suspended command thread",
                )
        finally:
            kernel32.CloseHandle(snapshot)
        thread = kernel32.OpenThread(
            0x0002, False, thread_ids[0]
        )  # THREAD_SUSPEND_RESUME
        if not thread:
            raise OSError(ctypes.get_last_error(), "OpenThread failed")
        try:
            if kernel32.ResumeThread(thread) != 1:
                raise OSError(
                    ctypes.get_last_error(),
                    "ResumeThread did not resume the suspended command",
                )
        finally:
            kernel32.CloseHandle(thread)
    except OSError as error:
        kernel32.CloseHandle(job)
        _kill_uncontained_process(process)
        raise workflow.WorkflowError(
            f"Could not contain Windows command process tree: {error}"
        ) from error
    process._anti_rea_job_handle = job


def _process_creation_options(creationflags: int = 0) -> dict:
    return (
        {"creationflags": creationflags | subprocess.CREATE_SUSPENDED}
        if os.name == "nt"
        else {}
    )


def _kill_uncontained_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.kill()
    process.wait()
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def _close_process_tree(process: subprocess.Popen) -> None:
    job = getattr(process, "_anti_rea_job_handle", None)
    if job is None:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not kernel32.CloseHandle(job):
        raise workflow.WorkflowError(
            f"Could not close Windows process job: {ctypes.get_last_error()}"
        )
    process._anti_rea_job_handle = None
