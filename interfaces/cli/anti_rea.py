#!/usr/bin/env python3
"""Small machine-readable CLI for Anti-REA's shared workflow record core."""

import argparse
import importlib.util
import json
import os
import signal
import sys
import threading
import unicodedata
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core import baseline as baseline_capture
from core import (
    dependencies,
    discovery,
    execution,
    flutter_android,
    optimizer,
    recommendations,
    upstream_review,
    wasm_runtime,
    workflow,
)
from core import registry as engine_registry
from core import release as release_manifest
from interfaces.cli import skill_install

VALIDATORS = {
    "target": workflow.validate_target,
    "baseline": workflow.validate_baseline,
    "plan": workflow.validate_plan,
    "run": workflow.validate_run,
    "execution": lambda value: workflow.validate_evidence_record(value, "execution"),
    "verification": lambda value: workflow.validate_evidence_record(
        value, "verification"
    ),
    "acceptance": lambda value: workflow.validate_evidence_record(value, "acceptance"),
    "rollback": lambda value: workflow.validate_evidence_record(value, "rollback"),
}


def load(path):
    return workflow.read_json(path)


def emit(value):
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))


def display_text(value):
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
        for char in value
    )


def _doctor_report():
    checks = []
    checks.append(
        {
            "id": "python",
            "required": True,
            "status": "passed" if sys.version_info >= (3, 11) else "blocked",
            "detail": f"Python {sys.version_info.major}.{sys.version_info.minor}",
        }
    )
    for module in ("mcp", "jsonschema", "cryptography"):
        available = importlib.util.find_spec(module) is not None
        checks.append(
            {
                "id": f"python:{module}",
                "required": True,
                "status": "passed" if available else "blocked",
                "detail": "installed" if available else "missing required package",
            }
        )
    safe_fs = os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
    checks.append(
        {
            "id": "filesystem:safe_relative_open",
            "required": True,
            "status": "passed" if safe_fs else "blocked",
            "detail": "directory-relative no-follow opens available"
            if safe_fs
            else "platform lacks required no-follow directory-relative opens",
        }
    )

    for label, variable, script_getter in (
        ("bla", "ANTI_REA_BLA_RUNTIME", execution._bla_script),
        ("e2e", "ANTI_REA_E2E_RUNTIME", execution._e2e_script),
        ("rea", "ANTI_REA_REA_RUNTIME", execution._rea_script),
    ):
        configured = os.environ.get(variable)
        if not configured:
            checks.append(
                {
                    "id": f"runtime:{label}",
                    "required": False,
                    "status": "not_configured",
                    "detail": f"optional; set {variable} when needed",
                }
            )
            continue
        try:
            script = script_getter()
            spec = importlib.util.spec_from_file_location(
                f"anti_rea_doctor_{label}", script
            )
            if spec is None or spec.loader is None:
                raise workflow.WorkflowError("runtime adapter could not be loaded")
            adapter = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(adapter)
            runtime, manifest = adapter.verify_runtime(configured)
            version = manifest.get("packages") or manifest.get("npm_version")
            checks.append(
                {
                    "id": f"runtime:{label}",
                    "required": True,
                    "status": "passed",
                    "detail": "pinned runtime identity verified",
                    "path": str(runtime),
                    "version": version,
                }
            )
        except Exception as error:
            checks.append(
                {
                    "id": f"runtime:{label}",
                    "required": True,
                    "status": "blocked",
                    "detail": str(error),
                }
            )
    status = (
        "blocked"
        if any(check["required"] and check["status"] != "passed" for check in checks)
        else "ready"
    )
    return {"status": status, "checks": checks}


def _upstream_adapter(engine):
    getter = {
        "bla": execution._bla_script,
        "e2e": execution._e2e_script,
        "rea": execution._rea_script,
    }[engine]
    script = getter()
    spec = importlib.util.spec_from_file_location(
        f"anti_rea_dependency_{engine}", script
    )
    if spec is None or spec.loader is None:
        raise workflow.WorkflowError("Pinned runtime adapter could not be loaded")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


def main(argv=None):
    parser = argparse.ArgumentParser(prog="anti-rea", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    mcp = commands.add_parser("mcp", help="run the local MCP server")
    mcp_commands = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_commands.add_parser("serve", help="serve Anti-REA tools over stdio")
    commands.add_parser(
        "doctor", help="check core prerequisites and configured pinned runtimes"
    )
    commands.add_parser(
        "registry", help="list pinned adapters and their implemented operation scope"
    )
    prepare = commands.add_parser(
        "prepare-dependency",
        help="inspect project packages or verify/prepare one pinned upstream runtime",
    )
    prepare.add_argument("engine", choices=("bla", "e2e", "rea"))
    prepare.add_argument(
        "--project-root",
        required=True,
        help="project to keep separate from the runtime cache",
    )
    prepare.add_argument(
        "--cache-dir",
        help="private dependency cache outside the project (required when no runtime is supplied)",
    )
    prepare.add_argument(
        "--runtime", help="verify an existing pinned runtime instead of using the cache"
    )
    prepare.add_argument(
        "--offline",
        action="store_true",
        help="verify an existing cache entry without installing",
    )
    prepare.add_argument(
        "--inspect-only",
        action="store_true",
        help="report project npm package matches without using Node or preparing a runtime",
    )
    python_dependencies = commands.add_parser(
        "inspect-python-dependencies",
        help="inspect a PEP 751 Python lockfile without installing packages",
    )
    python_dependencies.add_argument("project")
    prepare_python = commands.add_parser(
        "prepare-python-dependencies",
        help="prepare one hashed PEP 751 wheel lock in a private cache",
    )
    prepare_python.add_argument("project")
    prepare_python.add_argument(
        "--cache-dir",
        required=True,
        help="private dependency cache outside the project",
    )
    prepare_python.add_argument(
        "--offline",
        action="store_true",
        help="verify a prepared cache entry without installing",
    )
    inspect = commands.add_parser(
        "inspect", help="perform bounded read-only project discovery"
    )
    inspect.add_argument("project")
    inspect.add_argument(
        "--store",
        help="save the manifest outside the project in this Anti-REA state directory",
    )
    wasm_probe = commands.add_parser(
        "wasm-probe",
        help="compile one WebAssembly module with Node without instantiating or executing it",
    )
    wasm_probe.add_argument("module", help="selected .wasm file (maximum 8 MiB)")
    wasm_probe.add_argument(
        "--node",
        default="node",
        help="Node executable used for compile-only validation",
    )
    wasm_probe.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="per-command timeout in seconds (maximum 60)",
    )
    skill = commands.add_parser(
        "skill",
        help="install, update, or remove the portable Skill at an explicit destination",
    )
    skill.add_argument("operation", choices=("install", "update", "uninstall"))
    skill.add_argument(
        "destination",
        help="exact Skill directory to manage; harness config is never edited",
    )
    skill.add_argument("--source", help=argparse.SUPPRESS)
    skill.add_argument(
        "--preview",
        action="store_true",
        help="show exact file changes without applying them",
    )
    skill.add_argument(
        "--yes",
        action="store_true",
        help="apply the displayed plan without an interactive confirmation",
    )
    baseline = commands.add_parser(
        "baseline", help="run a BEFORE command and hash selected artifacts"
    )
    baseline.add_argument("project")
    baseline.add_argument(
        "--store",
        required=True,
        help="private Anti-REA state directory outside the project",
    )
    baseline.add_argument("--id", required=True, dest="baseline_id")
    baseline.add_argument(
        "--artifact",
        action="append",
        required=True,
        help="project-relative output path; repeat as needed",
    )
    baseline.add_argument("--timeout", type=float, default=600)
    baseline.add_argument(
        "--build-time-trials",
        type=int,
        default=1,
        help="repeat the build on fresh private copies for timing variability (1-5; may be costly)",
    )
    baseline.add_argument(
        "--behavior-command-json",
        help="BEFORE behavior argv JSON with one {artifact} argument",
    )
    baseline.add_argument(
        "--e2e-runtime",
        help="capture BEFORE browser behavior using a prepared pinned e2e runtime",
    )
    baseline.add_argument("--e2e-config", default="e2e.config.mjs")
    baseline.add_argument("--e2e-test-file", default="tests/behavior.e2e.ts")
    baseline.add_argument(
        "--rea-runtime",
        help="capture BEFORE REA analysis using a prepared pinned runtime",
    )
    baseline.add_argument(
        "--craft-anything-cli",
        help="capture BEFORE Craft Anything triage using an installed CLI (or ANTI_REA_CRAFT_ANYTHING_CLI)",
    )
    flutter_baseline = commands.add_parser(
        "flutter-android-baseline",
        help="build and hash a Flutter Android release artifact in a private snapshot",
    )
    flutter_baseline.add_argument("project")
    flutter_baseline.add_argument(
        "--store",
        required=True,
        help="private Anti-REA state directory outside the project",
    )
    flutter_baseline.add_argument("--id", required=True, dest="baseline_id")
    flutter_baseline.add_argument(
        "--target", choices=("apk", "appbundle"), required=True
    )
    flutter_baseline.add_argument(
        "--split-debug-info",
        help="private symbol directory inside --store; required with --obfuscate",
    )
    flutter_baseline.add_argument(
        "--obfuscate",
        action="store_true",
        help="match a release that already uses Dart symbol obfuscation",
    )
    flutter_baseline.add_argument(
        "--flutter", default="flutter", help="Flutter executable"
    )
    flutter_baseline.add_argument("--timeout", type=float, default=3600)
    flutter_aot = commands.add_parser(
        "attach-flutter-aot",
        help="create a new baseline record with hash-bound REA Dart AOT inspection evidence",
    )
    flutter_aot.add_argument(
        "--store", required=True, help="private Anti-REA state directory"
    )
    flutter_aot.add_argument(
        "--baseline-id", required=True, help="captured Flutter APK baseline id"
    )
    flutter_aot.add_argument(
        "--new-baseline-id", required=True, help="new immutable baseline record id"
    )
    flutter_aot.add_argument(
        "--report", required=True, help="REA inspect_dart_aot JSON report"
    )
    flutter_aot.add_argument(
        "--rea-runtime", required=True, help="prepared pinned REA runtime directory"
    )
    flutter_aot.add_argument(
        "--abi", choices=("arm64-v8a", "armeabi-v7a", "x86_64"), required=True
    )
    flutter_probe = commands.add_parser(
        "flutter-android-probe",
        help="check Flutter, Android SDK/license, and connected-device readiness",
    )
    flutter_probe.add_argument(
        "--flutter", default="flutter", help="Flutter executable"
    )
    flutter_probe.add_argument(
        "--timeout",
        type=float,
        default=120,
        help="per-command timeout in seconds (maximum 600)",
    )
    validate = commands.add_parser(
        "validate", help="validate a versioned workflow record"
    )
    validate.add_argument("record_type", choices=sorted(VALIDATORS))
    validate.add_argument("record")
    digest = commands.add_parser(
        "hash-plan", help="print the canonical SHA-256 identity of a plan"
    )
    digest.add_argument("plan")
    save_target = commands.add_parser(
        "record-target", help="store a validated target manifest"
    )
    save_target.add_argument("target")
    save_target.add_argument("store")
    save_baseline = commands.add_parser(
        "record-baseline", help="store a validated baseline record"
    )
    save_baseline.add_argument("baseline")
    save_baseline.add_argument("store")
    save_plan = commands.add_parser(
        "record-plan", help="store a plan bound to a saved target and baseline"
    )
    save_plan.add_argument("plan")
    save_plan.add_argument("store")
    submit_plan = commands.add_parser(
        "submit-plan", help="bind a concrete plan to a baselining run for user review"
    )
    submit_plan.add_argument("run")
    submit_plan.add_argument("plan")
    submit_plan.add_argument("store")
    recommend = commands.add_parser(
        "recommend",
        help="create evidence-linked, limited recommendations from a baseline",
    )
    recommend.add_argument("target_id")
    recommend.add_argument("baseline_id")
    recommend.add_argument("plan_id")
    recommend.add_argument("store")
    recommend.add_argument(
        "--behavior-command-json", help='argv JSON with one exact "{artifact}" argument'
    )
    recommend.add_argument(
        "--e2e-behavior",
        action="store_true",
        help="include paired pinned browser checks (requires the project e2e fixture contract)",
    )
    recommend.add_argument(
        "--profile",
        choices=["low-impact", "balanced", "deep-protection", "custom"],
        default="balanced",
        help="starting profile; applies only to BLA JavaScript actions",
    )
    recommend.add_argument(
        "--bla-intensity",
        choices=["stealth", "balanced", "maximum", "bankrupt"],
        help="BLA intensity required with --profile custom",
    )
    recommend.add_argument(
        "--analysis-gate",
        action="append",
        choices=["rea", "craft-anything"],
        dest="analysis_gates",
        help="require this analysis engine for acceptance; repeat to select multiple gates",
    )
    recommend.add_argument(
        "--performance-max-ms",
        type=int,
        default=30000,
        help="maximum pinned BLA transform time per trial (default: 30000)",
    )
    recommend.add_argument(
        "--performance-max-bytes",
        type=int,
        default=64 * 1024 * 1024,
        help="maximum transformed JavaScript bytes (default: 67108864)",
    )
    recommend.add_argument(
        "--performance-max-journey-regression-percent",
        type=float,
        default=25,
        help="maximum browser journey timing regression percent when baseline timing is available (default: 25)",
    )
    execute_plan = commands.add_parser(
        "execute-plan",
        help="execute an approved action selection into a private candidate",
    )
    execute_plan.add_argument("run_id")
    execute_plan.add_argument("action_id")
    execute_plan.add_argument("store")
    execute_plan.add_argument(
        "--bla-runtime",
        default=None,
        help="pinned BLA runtime when the selected action uses BLA",
    )
    execute_plan.add_argument(
        "--rea-runtime",
        default=None,
        help="pinned REA runtime (or ANTI_REA_REA_RUNTIME)",
    )
    execute_plan.add_argument(
        "--e2e-runtime",
        default=None,
        help="pinned e2e runtime (or ANTI_REA_E2E_RUNTIME)",
    )
    execute_plan.add_argument(
        "--craft-anything-cli",
        help="installed Craft Anything CLI (or ANTI_REA_CRAFT_ANYTHING_CLI)",
    )
    resume = commands.add_parser(
        "resume",
        help="prepare a fresh run after validating saved inputs and prior outputs",
    )
    resume.add_argument("run_id", help="failed or cancelled run to resume")
    resume.add_argument("new_run_id", help="new id for the verified retry")
    resume.add_argument("store")
    rollback_candidate = commands.add_parser(
        "rollback-candidate", help="discard a run's unchanged isolated BLA candidate"
    )
    rollback_candidate.add_argument("run_id")
    rollback_candidate.add_argument("store")
    cancel = commands.add_parser("cancel", help="cancel a run before acceptance")
    cancel.add_argument("run_id")
    cancel.add_argument("store")
    status = commands.add_parser(
        "status", help="show persisted run state and linked evidence ids"
    )
    status.add_argument("run_id")
    status.add_argument("store")
    report = commands.add_parser(
        "report", help="collect persisted records linked to a run"
    )
    report.add_argument("run_id")
    report.add_argument("store")
    report.add_argument("--format", choices=("json", "markdown"), default="json")
    save_evidence = commands.add_parser(
        "record-evidence",
        help="store validated immutable execution or acceptance evidence",
    )
    save_evidence.add_argument(
        "record_type", choices=("execution", "verification", "acceptance", "rollback")
    )
    save_evidence.add_argument("record")
    save_evidence.add_argument("store")
    init_run = commands.add_parser("init-run", help="create a run in discovered state")
    init_run.add_argument("target_id")
    init_run.add_argument("run_id")
    init_run.add_argument("store")
    record_decision = commands.add_parser(
        "record-decision", help="persist an explicit plan-bound user choice"
    )
    record_decision.add_argument("run")
    record_decision.add_argument("decision")
    record_decision.add_argument("store")
    choose = commands.add_parser(
        "choose",
        help="review plan trade-offs and select compatible actions for execution",
    )
    choose.add_argument("run_id")
    choose.add_argument("store")
    choose.add_argument("--decision-id", default=None)
    start = commands.add_parser(
        "start", help="authorize a run from its matching approved plan decision"
    )
    start.add_argument("run")
    start.add_argument("store")
    transition = commands.add_parser(
        "transition", help="validate and write a run state transition"
    )
    transition.add_argument("run")
    transition.add_argument(
        "next_state",
        choices=sorted(
            {state for states in workflow.RUN_STATES.values() for state in states}
        ),
    )
    transition.add_argument("store")
    transition.add_argument(
        "--updates", help="JSON object containing transition metadata"
    )
    accept = commands.add_parser(
        "accept", help="complete a run only after bound evidence passes acceptance"
    )
    accept.add_argument("run")
    accept.add_argument("store")
    accept.add_argument(
        "--execution", required=True, help="saved execution evidence record JSON"
    )
    accept.add_argument("--verification", required=True)
    accept.add_argument("--acceptance", required=True)
    release = commands.add_parser(
        "release-manifest",
        help="create, sign, or verify an exact wheel release manifest",
    )
    release_ops = release.add_subparsers(dest="release_operation", required=True)
    release_create = release_ops.add_parser(
        "create", help="hash a built Anti-REA wheel and its packaged locks"
    )
    release_create.add_argument("wheel")
    release_create.add_argument("output")
    release_sign = release_ops.add_parser(
        "sign", help="sign a manifest using an externally managed Ed25519 key"
    )
    release_sign.add_argument("manifest")
    release_sign.add_argument("private_key")
    release_sign.add_argument("signature")
    release_verify = release_ops.add_parser(
        "verify", help="verify signature and exact wheel identity"
    )
    release_verify.add_argument("manifest")
    release_verify.add_argument("signature")
    release_verify.add_argument("public_key")
    release_verify.add_argument("wheel")
    upstream_review_command = commands.add_parser(
        "upstream-review", help="compare candidate upstream pins with the stable lock"
    )
    upstream_review_command.add_argument("candidate_manifest")
    capability_review = commands.add_parser(
        "upstream-capabilities",
        help="diff stable and candidate upstream contract ledgers",
    )
    capability_review.add_argument("stable_ledger")
    capability_review.add_argument("candidate_ledger")
    optimization_approve = commands.add_parser(
        "optimize-approve-search",
        help="validate and approve a bounded candidate search scope",
    )
    optimization_approve.add_argument(
        "search", help="JSON search scope bound to a saved plan"
    )
    optimization_approve.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_approve.add_argument(
        "--preview", action="store_true", help="validate and display without saving"
    )
    optimization_approve.add_argument(
        "--yes", action="store_true", help="approve the displayed search scope"
    )
    optimization_generate = commands.add_parser(
        "optimize-generate-candidates",
        help="generate a bounded search proposal without approving or executing it",
    )
    optimization_generate.add_argument(
        "search_template",
        help="search fields plus candidate_generation scope and estimates",
    )
    optimization_generate.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_review = commands.add_parser(
        "optimize-review",
        help="advisory review of caller-supplied optimizer measurements",
    )
    optimization_review.add_argument(
        "measurements",
        help="untrusted JSON measurements; this command does not verify accepted workflow runs",
    )
    optimization_review_accepted = commands.add_parser(
        "optimize-review-accepted",
        help="review only revalidated, accepted BLA candidate runs",
    )
    optimization_review_accepted.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_review_accepted.add_argument(
        "budgets", help="JSON object with elapsed-time and artifact-size limits"
    )
    optimization_review_accepted.add_argument(
        "--run-id",
        action="append",
        required=True,
        help="approved accepted candidate run id; repeat up to four times",
    )
    optimization_review_search = commands.add_parser(
        "optimize-review-search",
        help="review accepted runs against a persisted approved search",
    )
    optimization_review_search.add_argument("search_id")
    optimization_review_search.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_review_search.add_argument(
        "candidate_runs",
        help="JSON file mapping approved candidate IDs to accepted run IDs",
    )
    optimization_select_search = commands.add_parser(
        "optimize-select-search",
        help="persist a chosen accepted candidate from an approved search frontier",
    )
    optimization_select_search.add_argument("search_id")
    optimization_select_search.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_select_search.add_argument("candidate_id")
    optimization_select_search.add_argument(
        "candidate_runs",
        help="JSON file mapping approved candidate IDs to accepted run IDs",
    )
    optimization_select_search.add_argument(
        "decision_source", help="explicit source of the user's selection"
    )
    optimization_execute_search = commands.add_parser(
        "optimize-run-search",
        help="execute the candidates in a saved approved search within its time limits",
    )
    optimization_execute_search.add_argument("search_id")
    optimization_execute_search.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_execute_search.add_argument("--bla-runtime", default=None)
    optimization_execute_search.add_argument("--rea-runtime", default=None)
    optimization_execute_search.add_argument("--e2e-runtime", default=None)
    optimization_confirm = commands.add_parser(
        "optimize-confirm",
        help="advisory comparison of caller-supplied reevaluation evidence",
    )
    optimization_confirm.add_argument(
        "candidate", help="caller-supplied original candidate measurement JSON"
    )
    optimization_confirm.add_argument(
        "reevaluation", help="caller-supplied independent reevaluation JSON"
    )
    optimization_confirm.add_argument(
        "budgets", help="JSON object with max_elapsed_ms and max_candidate_bytes"
    )
    optimization_confirm_accepted = commands.add_parser(
        "optimize-confirm-accepted",
        help="confirm identical output from a distinct accepted BLA run",
    )
    optimization_confirm_accepted.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_confirm_accepted.add_argument("candidate_run_id")
    optimization_confirm_accepted.add_argument("reevaluation_run_id")
    optimization_confirm_accepted.add_argument(
        "budgets", help="JSON object with max_elapsed_ms and max_candidate_bytes"
    )
    optimization_confirm_search = commands.add_parser(
        "optimize-confirm-search",
        help="independently reevaluate a persisted approved-search selection",
    )
    optimization_confirm_search.add_argument(
        "store", help="Anti-REA private workflow state directory"
    )
    optimization_confirm_search.add_argument("search_id")
    optimization_confirm_search.add_argument("selection_id")
    optimization_confirm_search.add_argument("candidate_run_id")
    optimization_confirm_search.add_argument("reevaluation_run_id")
    values = list(sys.argv[1:] if argv is None else argv)
    baseline_command = []
    if values and values[0] == "baseline" and "--" in values:
        separator = values.index("--")
        baseline_command = values[separator + 1 :]
        values = values[:separator]
    args = parser.parse_args(values)
    if args.command == "mcp":
        from interfaces.mcp.server import main as mcp_main

        mcp_main()
        return 0
    try:
        if args.command == "doctor":
            report = _doctor_report()
            emit(report)
            return 2 if report["status"] == "blocked" else 0
        elif args.command == "registry":
            emit(engine_registry.get_registry())
        elif args.command == "prepare-dependency":
            if args.inspect_only:
                emit(
                    dependencies.inspect_project_dependencies(
                        args.engine, args.project_root
                    )
                )
            else:
                emit(
                    dependencies.prepare(
                        args.engine,
                        args.project_root,
                        args.cache_dir,
                        _upstream_adapter(args.engine),
                        args.runtime,
                        args.offline,
                    )
                )
        elif args.command == "inspect-python-dependencies":
            emit(dependencies.inspect_python_dependencies(args.project))
        elif args.command == "prepare-python-dependencies":
            emit(
                dependencies.prepare_python_dependencies(
                    args.project, args.cache_dir, args.offline
                )
            )
        elif args.command == "wasm-probe":
            emit(wasm_runtime.probe_module(args.module, args.node, args.timeout))
        elif args.command == "flutter-android-probe":
            emit(flutter_android.probe_android_environment(args.flutter, args.timeout))
        elif args.command == "attach-flutter-aot":
            records = Path(args.store).expanduser().resolve() / "records"
            captured = workflow.read_record(
                records / f"baseline-{args.baseline_id}.json", "baseline"
            )
            updated = flutter_android.attach_aot_inspection(
                captured, args.report, args.rea_runtime, args.abi, args.new_baseline_id
            )
            path = workflow.write_record(records, updated)
            emit(
                {
                    "status": "attached",
                    "id": updated["id"],
                    "aot_status": updated["identity"]["flutter_aot_inspection"][
                        "status"
                    ],
                    "baseline_sha256": workflow.record_hash(updated),
                    "record": str(path),
                }
            )
        elif args.command == "skill":
            preview = skill_install.plan(args.operation, args.destination, args.source)
            emit({"status": "planned", **preview})
            if args.preview:
                return 0
            if not args.yes:
                if not sys.stdin.isatty():
                    raise workflow.WorkflowError(
                        "Non-interactive installation requires --preview or --yes"
                    )
                print(
                    "Apply the displayed Skill file changes? [y/N] ",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
                if input().strip().lower() not in {"y", "yes"}:
                    emit({"status": "cancelled", "reason": "user_declined"})
                    return 0
            result = skill_install.execute(
                args.operation, args.destination, args.source, expected_plan=preview
            )
            emit({"status": "completed", **result})
        elif args.command == "release-manifest":
            if args.release_operation == "create":
                result = release_manifest.create_manifest(args.wheel, args.output)
                emit({"status": "created", "manifest": args.output, **result})
            elif args.release_operation == "sign":
                emit(
                    release_manifest.sign_manifest(
                        args.manifest, args.private_key, args.signature
                    )
                )
            else:
                emit(
                    release_manifest.verify_release(
                        args.manifest, args.signature, args.public_key, args.wheel
                    )
                )
        elif args.command == "upstream-review":
            emit(upstream_review.review(args.candidate_manifest))
        elif args.command == "upstream-capabilities":
            emit(
                upstream_review.compare_capability_files(
                    args.stable_ledger, args.candidate_ledger
                )
            )
        elif args.command == "optimize-approve-search":
            proposal = load(args.search)
            preview = optimizer.validate_search_space(
                args.store, proposal, "pending CLI approval"
            )
            emit(
                {
                    "status": "approval_required",
                    "id": preview["id"],
                    "target_id": preview["target_id"],
                    "baseline_id": preview["baseline_id"],
                    "plan_id": preview["plan_id"],
                    "baseline_sha256": preview["baseline_sha256"],
                    "source_identity_sha256": preview["source_identity_sha256"],
                    "runtime_identities": preview["runtime_identities"],
                    "plan_sha256": preview["plan_sha256"],
                    "candidate_sets": preview["candidate_sets"],
                    "budgets": preview["budgets"],
                    "stop_conditions": preview["stop_conditions"],
                }
            )
            if args.preview:
                return 0
            if not args.yes:
                if not sys.stdin.isatty():
                    raise workflow.WorkflowError(
                        "Non-interactive search approval requires --yes or --preview"
                    )
                print(
                    "Approve this exact bounded search scope? [y/N] ",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
                if input().strip().lower() not in {"y", "yes"}:
                    emit({"status": "cancelled", "reason": "user_declined"})
                    return 0
            source = "CLI --yes" if args.yes else "CLI interactive confirmation"
            emit(optimizer.approve_search_space(args.store, proposal, source))
        elif args.command == "optimize-generate-candidates":
            proposal = optimizer.generate_search_proposal(
                args.store, load(args.search_template)
            )
            emit({"status": "proposal", "approval_required": True, "search": proposal})
        elif args.command == "optimize-review":
            candidate_set = load(args.measurements)
            if not isinstance(candidate_set, dict):
                raise workflow.WorkflowError(
                    "Optimization measurement input must be a JSON object"
                )
            emit(
                optimizer.review_candidates(
                    candidate_set.get("approved_candidate_ids"),
                    candidate_set.get("measurements"),
                    candidate_set.get("budgets"),
                )
            )
        elif args.command == "optimize-confirm":
            emit(
                optimizer.confirm_independent_reevaluation(
                    load(args.candidate), load(args.reevaluation), load(args.budgets)
                )
            )
        elif args.command == "optimize-review-accepted":
            emit(
                optimizer.review_accepted_runs(
                    args.store, args.run_id, load(args.budgets)
                )
            )
        elif args.command == "optimize-review-search":
            emit(
                optimizer.review_approved_search(
                    args.store, args.search_id, load(args.candidate_runs)
                )
            )
        elif args.command == "optimize-select-search":
            emit(
                optimizer.select_approved_search_candidate(
                    args.store,
                    args.search_id,
                    args.candidate_id,
                    load(args.candidate_runs),
                    args.decision_source,
                )
            )
        elif args.command == "optimize-run-search":
            emit(
                optimizer.execute_approved_search(
                    args.store,
                    args.search_id,
                    args.bla_runtime,
                    args.rea_runtime,
                    args.e2e_runtime,
                )
            )
        elif args.command == "optimize-confirm-accepted":
            emit(
                optimizer.confirm_accepted_reevaluation(
                    args.store,
                    args.candidate_run_id,
                    args.reevaluation_run_id,
                    load(args.budgets),
                )
            )
        elif args.command == "optimize-confirm-search":
            emit(
                optimizer.confirm_approved_search_reevaluation(
                    args.store,
                    args.search_id,
                    args.selection_id,
                    args.candidate_run_id,
                    args.reevaluation_run_id,
                )
            )
        elif args.command == "inspect":
            target = discovery.inspect_project(args.project)
            if args.store:
                store = Path(args.store).expanduser().resolve()
                source = Path(target["source_root"])
                if store == source or source in store.parents:
                    raise workflow.WorkflowError(
                        "Target manifests must be stored outside the inspected project"
                    )
                path = workflow.write_record(store / "records", target)
                emit(
                    {
                        "status": "discovered",
                        "id": target["id"],
                        "components": target["components"],
                        "file_count": target["inventory"]["file_count"],
                        "unknowns": target["unknowns"],
                        "record": str(path),
                    }
                )
            else:
                emit(target)
        elif args.command in {"baseline", "flutter-android-baseline"}:
            craft_anything_cli = os.environ.get("ANTI_REA_CRAFT_ANYTHING_CLI")
            if args.command == "baseline" and not baseline_command:
                raise workflow.WorkflowError("Pass the baseline command after --")
            if args.command == "flutter-android-baseline":
                store_root = Path(args.store).expanduser().resolve()
                split_debug_info = (
                    Path(args.split_debug_info).expanduser().resolve()
                    if args.split_debug_info
                    else None
                )
                if args.obfuscate:
                    if (
                        split_debug_info is None
                        or split_debug_info.parent != store_root
                    ):
                        raise workflow.WorkflowError(
                            "Split debug information must be a direct child of the private --store directory"
                        )
                    if split_debug_info.exists() or split_debug_info.is_symlink():
                        raise workflow.WorkflowError(
                            "Split debug information path already exists"
                        )
                baseline_command = flutter_android.build_command(
                    args.project,
                    args.target,
                    split_debug_info,
                    args.flutter,
                    obfuscate=args.obfuscate,
                )
                artifacts = [
                    "build/app/outputs/flutter-apk/app-release.apk"
                    if args.target == "apk"
                    else "build/app/outputs/bundle/release/app-release.aab"
                ]
                timeout = args.timeout
                build_time_trials = 1
                behavior_command = None
                e2e_runtime = None
                e2e_config = "e2e.config.mjs"
                e2e_test_file = "tests/behavior.e2e.ts"
                rea_runtime = None
            else:
                artifacts = args.artifact
                timeout = args.timeout
                build_time_trials = args.build_time_trials
                behavior_command = (
                    json.loads(args.behavior_command_json)
                    if args.behavior_command_json
                    else None
                )
                e2e_runtime = args.e2e_runtime
                e2e_config = args.e2e_config
                e2e_test_file = args.e2e_test_file
                rea_runtime = args.rea_runtime or os.environ.get("ANTI_REA_REA_RUNTIME")
                craft_anything_cli = args.craft_anything_cli or craft_anything_cli
            cancel_event = threading.Event()
            previous_handlers = {}
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, lambda _signum, _frame: cancel_event.set())
            try:
                record, evidence = baseline_capture.capture(
                    args.project,
                    args.store,
                    baseline_command,
                    artifacts,
                    args.baseline_id,
                    timeout,
                    behavior_command,
                    e2e_runtime,
                    e2e_config,
                    e2e_test_file,
                    rea_runtime,
                    cancel_event,
                    build_time_trials=build_time_trials,
                    craft_anything_cli=craft_anything_cli,
                )
            except workflow.WorkflowError:
                if cancel_event.is_set():
                    emit(
                        {
                            "status": "cancelled",
                            "id": args.baseline_id,
                            "reason": "user_requested",
                        }
                    )
                    return 130
                raise
            finally:
                for signum, handler in previous_handlers.items():
                    signal.signal(signum, handler)
            emit(
                {
                    "status": "captured",
                    "id": record["id"],
                    "target_id": record["target_id"],
                    "artifacts": record["identity"]["artifacts"],
                    "evidence": str(evidence),
                    "build_duration_ms": record["identity"]["build_duration_ms"],
                    "build_timing": record["identity"].get("build_timing"),
                    "behavior_evidence": record["identity"]
                    .get("behavior", {})
                    .get("evidence_path"),
                    "e2e_evidence": record["identity"]
                    .get("e2e_behavior", {})
                    .get("report_path"),
                    "rea_evidence": record["identity"]
                    .get("rea_analysis", {})
                    .get("report_path"),
                }
            )
        elif args.command == "validate":
            record = VALIDATORS[args.record_type](load(args.record))
            emit(
                {"status": "valid", "record_type": args.record_type, "id": record["id"]}
            )
        elif args.command == "hash-plan":
            plan = workflow.validate_plan(load(args.plan))
            emit({"plan_id": plan["id"], "sha256": workflow.record_hash(plan)})
        elif args.command == "record-baseline":
            baseline = workflow.validate_baseline(load(args.baseline))
            records = Path(args.store) / "records"
            target = workflow.read_record(
                records / f"target-{baseline['target_id']}.json", "target"
            )
            baseline = workflow.validate_baseline_target(baseline, target)
            path = workflow.write_record(records, baseline)
            emit({"status": "saved", "id": baseline["id"], "record": str(path)})
        elif args.command == "record-target":
            target = workflow.validate_target(load(args.target))
            path = workflow.write_record(Path(args.store) / "records", target)
            emit({"status": "saved", "id": target["id"], "record": str(path)})
        elif args.command == "record-plan":
            plan = workflow.validate_plan(load(args.plan))
            records = Path(args.store) / "records"
            baseline = workflow.validate_baseline(
                workflow.read_record(
                    records / f"baseline-{plan['baseline_id']}.json", "baseline"
                )
            )
            plan = workflow.validate_plan_baseline(plan, baseline)
            path = workflow.write_record(records, plan)
            emit(
                {
                    "status": "saved",
                    "id": plan["id"],
                    "sha256": workflow.record_hash(plan),
                    "record": str(path),
                }
            )
        elif args.command == "submit-plan":
            run = workflow.validate_run(load(args.run))
            plan = workflow.validate_plan(load(args.plan))
            records = Path(args.store) / "records"
            target = workflow.read_record(
                records / f"target-{run['target_id']}.json", "target"
            )
            baseline = workflow.read_record(
                records / f"baseline-{plan['baseline_id']}.json", "baseline"
            )
            changed = workflow.submit_plan(run, target, baseline, plan)
            path = workflow.write_record(records, plan)
            workflow.write_run_state(Path(args.store) / "runs", changed, run)
            emit(
                {
                    "status": "awaiting_decision",
                    "run_id": changed["id"],
                    "plan_id": plan["id"],
                    "plan_sha256": workflow.record_hash(plan),
                    "run": str(path),
                }
            )
        elif args.command == "recommend":
            workflow._reference_id(args.target_id, "target id")
            workflow._reference_id(args.baseline_id, "baseline id")
            records = Path(args.store) / "records"
            target = workflow.read_record(
                records / f"target-{args.target_id}.json", "target"
            )
            baseline = workflow.read_record(
                records / f"baseline-{args.baseline_id}.json", "baseline"
            )
            behavior_command = (
                json.loads(args.behavior_command_json)
                if args.behavior_command_json
                else None
            )
            plan = recommendations.create_plan(
                target,
                baseline,
                args.plan_id,
                behavior_command=behavior_command,
                e2e_behavior=args.e2e_behavior,
                profile=args.profile,
                bla_intensity=args.bla_intensity,
                analysis_gates=args.analysis_gates,
                performance_budget={
                    "trials": 3,
                    "max_elapsed_ms": args.performance_max_ms,
                    "max_candidate_bytes": args.performance_max_bytes,
                    "max_journey_regression_pct": args.performance_max_journey_regression_percent,
                },
            )
            path = workflow.write_record(records, plan)
            emit(
                {
                    "status": "recommendations_ready" if plan["actions"] else "blocked",
                    "id": plan["id"],
                    "baseline_id": plan["baseline_id"],
                    "plan_sha256": workflow.record_hash(plan),
                    "profile": plan["profile"],
                    "actions": plan["actions"],
                    "analysis_policy": plan.get("analysis_policy"),
                    "blockers": plan.get("blockers", []),
                    "record": str(path),
                }
            )
        elif args.command == "execute-plan":
            runtime = args.bla_runtime or os.environ.get("ANTI_REA_BLA_RUNTIME")
            rea_runtime = args.rea_runtime or os.environ.get("ANTI_REA_REA_RUNTIME")
            e2e_runtime = args.e2e_runtime or os.environ.get("ANTI_REA_E2E_RUNTIME")
            craft_anything_cli = args.craft_anything_cli or os.environ.get(
                "ANTI_REA_CRAFT_ANYTHING_CLI"
            )
            emit(
                execution.execute_bla_action(
                    args.store,
                    args.run_id,
                    args.action_id,
                    runtime,
                    rea_runtime=rea_runtime,
                    e2e_runtime=e2e_runtime,
                    craft_anything_cli=craft_anything_cli,
                )
            )
        elif args.command == "resume":
            emit(execution.prepare_resume(args.store, args.run_id, args.new_run_id))
        elif args.command == "rollback-candidate":
            emit(execution.discard_candidate(args.store, args.run_id))
        elif args.command == "cancel":
            run_path = (
                Path(args.store)
                / "runs"
                / f"run-{workflow._reference_id(args.run_id, 'run id')}.json"
            )
            current = workflow.validate_run(workflow.read_json(run_path))
            if current["state"] == "executing":
                raise workflow.WorkflowError(
                    "An active CLI operation must be interrupted in its owning process"
                )
            if current["state"] == "verifying" and current.get("execution_id"):
                execution.discard_candidate_if_active(args.store, args.run_id)
            changed = workflow.transition_run(
                current, "cancelled", cancellation_reason="user_requested"
            )
            path = workflow.write_run_state(run_path.parent, changed, current)
            emit(
                {
                    "status": "cancelled",
                    "run_id": args.run_id,
                    "state": "cancelled",
                    "record": str(path),
                }
            )
        elif args.command == "status":
            run_path = (
                Path(args.store)
                / "runs"
                / f"run-{workflow._reference_id(args.run_id, 'run id')}.json"
            )
            run = workflow.validate_run(workflow.read_json(run_path))
            emit({"status": "ok", "run": run})
        elif args.command == "report":
            run_path = (
                Path(args.store)
                / "runs"
                / f"run-{workflow._reference_id(args.run_id, 'run id')}.json"
            )
            run = workflow.validate_run(workflow.read_json(run_path))
            report_data = workflow.assemble_run_report(
                Path(args.store) / "records", run
            )
            if args.format == "markdown":
                print(workflow.format_effectiveness_markdown(report_data))
            else:
                emit(report_data)
        elif args.command == "record-evidence":
            record = VALIDATORS[args.record_type](load(args.record))
            path = workflow.write_record(Path(args.store) / "records", record)
            emit(
                {
                    "status": "saved",
                    "record_type": args.record_type,
                    "id": record["id"],
                    "record": str(path),
                }
            )
        elif args.command == "init-run":
            run = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "run",
                "id": args.run_id,
                "target_id": args.target_id,
                "state": "discovered",
            }
            workflow.validate_run(run)
            target = workflow.read_record(
                Path(args.store) / "records" / f"target-{args.target_id}.json", "target"
            )
            workflow.validate_target(target)
            path = workflow.write_run_state(Path(args.store) / "runs", run, None)
            emit(
                {
                    "status": "created",
                    "run_id": run["id"],
                    "state": run["state"],
                    "record": str(path),
                }
            )
        elif args.command == "record-decision":
            run = workflow.validate_run(load(args.run))
            records = Path(args.store) / "records"
            plan = workflow.validate_plan(
                workflow.read_record(records / f"plan-{run['plan_id']}.json", "plan")
            )
            decision = load(args.decision)
            changed = workflow.bind_decision(run, plan, decision)
            decision = workflow.validate_decision(decision, plan)
            record_path = workflow.write_record(records, decision)
            workflow.write_run_state(Path(args.store) / "runs", changed, run)
            emit(
                {
                    "status": "recorded",
                    "decision_id": decision["id"],
                    "decision": decision["decision"],
                    "record": str(record_path),
                }
            )
        elif args.command == "choose":
            store = Path(args.store)
            run_path = (
                store
                / "runs"
                / f"run-{workflow._reference_id(args.run_id, 'run id')}.json"
            )
            run = workflow.validate_run(load(run_path))
            if run["state"] != "awaiting_decision":
                raise workflow.WorkflowError(
                    "Interactive choices require a run awaiting a decision"
                )
            records = store / "records"
            plan = workflow.validate_plan(
                workflow.read_record(records / f"plan-{run['plan_id']}.json", "plan")
            )
            print(f"Plan {plan['id']} — review actions before choosing:")
            if "profile" in plan:
                profile = plan["profile"]
                print(
                    f"Starting profile: {display_text(profile['name'])}; "
                    f"BLA intensity: {display_text(profile['bla_intensity'])}; "
                    f"scope: {display_text(profile['scope'])}"
                )
            for action in plan["actions"]:
                print(
                    f"\n[{display_text(action['id'])}] {display_text(action['finding_or_asset'])}\n"
                    f"Change: {display_text(action['change'])}\nMechanism: {display_text(action['mechanism'])}\n"
                    f"Expected benefit: {display_text(action['expected_benefit'])}\n"
                    f"Cost: {display_text(action['cost'])}\n"
                    f"Trade-offs: {display_text('; '.join(action['tradeoffs']))}\n"
                    f"Dependencies: {display_text('; '.join(action['dependencies']))}\n"
                    f"Compatibility: {display_text('; '.join(action['compatibility']))}\n"
                    f"Verification: {display_text('; '.join(action['verification']))}\n"
                    f"Limitations: {display_text('; '.join(action['limitations']))}\n"
                    f"Rollback: {display_text(action['rollback'])}"
                )
                execution_config = action.get("execution")
                if execution_config is not None:
                    execution_json = json.dumps(
                        execution_config,
                        sort_keys=True,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    print(f"Execution settings: {display_text(execution_json)}")
            choices = input(
                "Action ID(s), comma-separated; blank rejects the plan: "
            ).strip()
            selected = (
                [choice.strip() for choice in choices.split(",") if choice.strip()]
                if choices
                else []
            )
            approved = bool(selected) and input(
                "Approve these exact actions? [y/N] "
            ).strip().lower() in {"y", "yes"}
            decision = {
                "schema_version": workflow.SCHEMA_VERSION,
                "record_type": "decision",
                "id": args.decision_id or "decision-" + uuid.uuid4().hex,
                "plan_sha256": workflow.record_hash(plan),
                "selected_action_ids": selected,
                "decision": "approved" if approved else "rejected",
                "decision_source": "interactive_cli",
            }
            decision = workflow.validate_decision(decision, plan)
            changed = workflow.bind_decision(run, plan, decision)
            record_path = workflow.write_record(records, decision)
            workflow.write_run_state(store / "runs", changed, run)
            emit(
                {
                    "status": "recorded",
                    "decision_id": decision["id"],
                    "decision": decision["decision"],
                    "selected_action_ids": selected,
                    "record": str(record_path),
                }
            )
        elif args.command == "start":
            run = workflow.validate_run(load(args.run))
            records = Path(args.store) / "records"
            plan = workflow.validate_plan(
                workflow.read_record(records / f"plan-{run['plan_id']}.json", "plan")
            )
            decision = workflow.validate_decision(
                workflow.read_record(
                    records / f"decision-{run['decision_id']}.json", "decision"
                ),
                plan,
            )
            started = workflow.start_execution(run, plan, decision)
            path = workflow.write_run_state(Path(args.store) / "runs", started, run)
            emit(
                {
                    "status": "accepted_for_execution",
                    "run_id": started["id"],
                    "state": started["state"],
                    "record": str(path),
                }
            )
        elif args.command == "accept":
            run = workflow.validate_run(load(args.run))
            records = Path(args.store) / "records"
            target = workflow.read_record(
                records / f"target-{run['target_id']}.json", "target"
            )
            baseline = workflow.read_record(
                records / f"baseline-{run['baseline_id']}.json", "baseline"
            )
            plan = workflow.read_record(records / f"plan-{run['plan_id']}.json", "plan")
            decision = workflow.read_record(
                records / f"decision-{run['decision_id']}.json", "decision"
            )
            execution_record = workflow.validate_evidence_record(
                load(args.execution), "execution"
            )
            saved_execution = workflow.read_record(
                records / f"execution-{execution_record['id']}.json", "execution"
            )
            if workflow.canonical(saved_execution) != workflow.canonical(
                execution_record
            ):
                raise workflow.WorkflowError(
                    "Execution evidence file does not match the immutable stored record"
                )
            verification = load(args.verification)
            acceptance = load(args.acceptance)
            flutter_check_ids = {"flutter_aot_comparison", "flutter_android_behavior"}
            if (
                isinstance(verification, dict)
                and verification.get("id") != run.get("verification_id")
                and {
                    check.get("id")
                    for check in verification.get("checks", [])
                    if isinstance(check, dict)
                }
                == flutter_check_ids
            ):
                run = workflow.refresh_blocked_flutter_verification(
                    args.store, run["id"], verification
                )
            changed, acceptance = workflow.finalize_run(
                run,
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
            path = workflow.write_run_state(Path(args.store) / "runs", changed, run)
            quarantine = (
                execution.discard_candidate_if_active(args.store, run["id"])
                if changed["acceptance"] == "rejected"
                else None
            )
            emit(
                {
                    "status": changed["acceptance"],
                    "run_id": changed["id"],
                    "state": changed["state"],
                    "acceptance": changed["acceptance"],
                    "record": str(path),
                    **(
                        {"candidate_retained_at": quarantine["retained_at"]}
                        if quarantine and "retained_at" in quarantine
                        else {}
                    ),
                }
            )
        else:
            updates = load(args.updates) if args.updates else {}
            if not isinstance(updates, dict):
                raise workflow.WorkflowError("--updates must contain a JSON object")
            changed = workflow.transition_run(
                load(args.run), args.next_state, **updates
            )
            current = load(args.run)
            path = workflow.write_run_state(Path(args.store) / "runs", changed, current)
            emit(
                {
                    "status": "transitioned",
                    "run_id": changed["id"],
                    "state": changed["state"],
                    "record": str(path),
                }
            )
        return 0
    except (EOFError, KeyboardInterrupt):
        emit({"status": "cancelled", "error": "decision_input_closed"})
        return 130
    except FileNotFoundError as error:
        emit({"status": "failed", "error": "record_not_found", "detail": str(error)})
        return 3
    except (OSError, ValueError, json.JSONDecodeError) as error:
        emit(
            {
                "status": "failed",
                "error": "invalid_record_or_operation",
                "detail": str(error),
            }
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
