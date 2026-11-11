"""Small command planner for an explicitly selected Flutter Android release build."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
from pathlib import Path

from core import baseline, workflow

_ANDROID_SECTION = re.compile(
    r"^\[(✓|!|✗)\] Android toolchain(?:\s|$)(.*)$", re.MULTILINE
)
_ANDROID_SDK_MISSING = re.compile(
    r"android sdk (?:was )?not found|unable to locate (?:the )?android sdk", re.I
)
_ANDROID_LICENSES_MISSING = re.compile(
    r"android licenses? (?:are )?not accepted|licenses? not accepted", re.I
)
_JAVA_BINARY = re.compile(r"Java binary at:\s*(.+)", re.I)
_JAVA_VERSION = re.compile(r"Java version\s+(.+)", re.I)
_JAVA_MISSING = re.compile(
    r"(?:unable to locate|could not find|no)\s+(?:a\s+)?java (?:runtime|binary)|java (?:runtime|binary) (?:not found|unavailable)",
    re.I,
)
_IDENTITY_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+ -]{0,127}$")
_AOT_SECTION_LAYOUTS = (
    frozenset(
        {
            "_kDartVmSnapshotInstructions",
            "_kDartIsolateSnapshotInstructions",
            "_kDartVmSnapshotData",
            "_kDartIsolateSnapshotData",
        }
    ),
    frozenset({"_kDartSnapshotText", "_kDartSnapshotData"}),
)
_SDK_PATH = re.compile(r"Android SDK at:?\s*(.+)", re.I)
_SIGNER_COUNT = re.compile(r"^Number of signers:\s*(\d+)\s*$", re.MULTILINE)
_SIGNER_CERT_SHA256 = re.compile(
    r"^Signer #(\d+) certificate SHA-256 digest:\s*([a-fA-F0-9]{64})\s*$", re.MULTILINE
)
_SIGNER_KEY_SHA256 = re.compile(
    r"^Signer #(\d+) public key SHA-256 digest:\s*([a-fA-F0-9]{64})\s*$", re.MULTILINE
)


def _read_evidence(path: str | Path) -> tuple[bytes, str]:
    """Read bounded evidence without following its final symlink."""
    file_path = Path(os.path.abspath(Path(path).expanduser()))
    if not hasattr(os, "O_NOFOLLOW"):
        raise workflow.WorkflowError(
            "Safe Flutter AOT evidence authentication is unavailable"
        )
    try:
        fd = os.open(
            file_path,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise workflow.WorkflowError(
            "Flutter AOT evidence is missing, linked, or unreadable"
        ) from error
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > workflow.MAX_EVIDENCE_BYTES
        ):
            raise workflow.WorkflowError(
                "Flutter AOT evidence must be a bounded regular file"
            )
        data = bytearray()
        while chunk := os.read(fd, 1024 * 1024):
            data.extend(chunk)
            if len(data) > workflow.MAX_EVIDENCE_BYTES:
                raise workflow.WorkflowError(
                    "Flutter AOT evidence exceeds the size limit"
                )
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise workflow.WorkflowError(
                "Flutter AOT evidence changed while being read"
            )
        return bytes(data), hashlib.sha256(data).hexdigest()
    finally:
        os.close(fd)


def _verify_rea_runtime(runtime_path: str | Path) -> tuple[Path, bytes, dict]:
    from core import execution

    script = execution._rea_script()
    spec = importlib.util.spec_from_file_location(
        "anti_rea_aot_runtime_adapter", script
    )
    if spec is None or spec.loader is None:
        raise workflow.WorkflowError("Pinned REA runtime adapter is unavailable")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    runtime, manifest = adapter.verify_runtime(runtime_path)
    manifest_path = runtime / "anti-rea-rea-runtime.json"
    raw, _ = _read_evidence(manifest_path)
    if json.loads(raw) != manifest:
        raise workflow.WorkflowError("REA runtime manifest changed during verification")
    return manifest_path, raw, manifest


def attach_aot_inspection(
    baseline_record: dict,
    report_path: str | Path,
    runtime_path: str | Path,
    abi: str,
    new_baseline_id: str,
) -> dict:
    """Return a new baseline that binds one REA AOT report to its captured APK."""
    from core import workflow

    baseline_record = workflow.validate_baseline(baseline_record)
    workflow._reference_id(new_baseline_id, "baseline id")
    identity = baseline_record["identity"]
    command = identity.get("command", [])
    if (
        not identity.get("flutter_toolchain")
        or len(command) < 4
        or command[1:4] != ["build", "apk", "--release"]
    ):
        raise workflow.WorkflowError(
            "Flutter AOT evidence requires a captured Android APK baseline"
        )
    artifact_path = next(
        (path for path in identity.get("artifacts", {}) if path.endswith(".apk")), None
    )
    if artifact_path is None:
        raise workflow.WorkflowError("Flutter APK baseline artifact is missing")
    artifact = identity["artifacts"][artifact_path]
    snapshot = identity.get("build_snapshot")
    if not isinstance(snapshot, dict):
        raise workflow.WorkflowError(
            "Flutter AOT evidence requires the retained private APK snapshot"
        )
    actual_artifact = baseline._hash_artifact(Path(snapshot["path"]), artifact_path)
    if (
        actual_artifact.get("sha256") != artifact["sha256"]
        or actual_artifact.get("size") != artifact["size"]
    ):
        raise workflow.WorkflowError(
            "Captured Flutter APK changed before AOT evidence attachment"
        )
    report_file = Path(os.path.abspath(Path(report_path).expanduser()))
    report_raw, report_hash = _read_evidence(report_file)
    manifest_file, manifest_raw, manifest = _verify_rea_runtime(runtime_path)
    manifest_file_hash = hashlib.sha256(manifest_raw).hexdigest()
    try:
        report = json.loads(report_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError(
            "Flutter AOT report or REA runtime manifest is invalid JSON"
        ) from error
    if not isinstance(manifest, dict) or not all(
        isinstance(manifest.get(key), str) and manifest[key]
        for key in (
            "npm_version",
            "npm_integrity",
            "package_lock_sha256",
            "package_tree_sha256",
            "node_version",
        )
    ):
        raise workflow.WorkflowError("REA runtime manifest identity is incomplete")
    runtime_hash = hashlib.sha256(workflow.canonical(manifest)).hexdigest()
    result = {
        "artifact_path": artifact_path,
        "artifact_sha256": artifact["sha256"],
        "artifact_size": artifact["size"],
        "abi": abi,
        "operation": "inspect_dart_aot",
        "report_path": str(report_file),
        "report_sha256": report_hash,
        "runtime_manifest_path": str(manifest_file),
        "runtime_manifest_sha256": runtime_hash,
        "runtime_manifest_file_sha256": manifest_file_hash,
    }
    result["status"] = _classify_aot_report(
        report, result, str(Path(snapshot["path"]) / artifact_path)
    )
    evidence = list(baseline_record["evidence"])
    for path in (str(report_file), str(manifest_file)):
        if path not in evidence:
            evidence.append(path)
    updated = {
        **baseline_record,
        "id": new_baseline_id,
        "identity": {
            **identity,
            "snapshot_baseline_id": identity.get(
                "snapshot_baseline_id", baseline_record["id"]
            ),
            "flutter_aot_inspection": result,
        },
        "evidence": evidence,
    }
    return workflow.validate_baseline(updated)


def _unwrap_rea_cli_result(report: dict) -> dict:
    """Accept either a predicate or REA CLI's successful JSON envelope."""
    if "ok" in report:
        if report.get("ok") is not True or not isinstance(report.get("data"), dict):
            raise workflow.WorkflowError(
                "REA AOT CLI output does not contain a successful analysis result"
            )
        return report["data"]
    return report


def _classify_aot_report(
    report: dict, inspection: dict, expected_apk_path: str | None = None
) -> str:
    """Recognize only hash/ABI-bound supported or explicit unsupported REA results."""
    report = _unwrap_rea_cli_result(report)
    if report.get("operation") == "inspect_dart_aot" and report.get("is_error") is True:
        content = report.get("content")
        try:
            text = (
                content[0].get("text")
                if isinstance(content, list) and content
                else None
            )
            upstream = json.loads(text) if isinstance(text, str) else None
        except json.JSONDecodeError:
            upstream = None
        error = upstream.get("error") if isinstance(upstream, dict) else None
        details = error.get("details") if isinstance(error, dict) else None
        diagnostics = details.get("diagnostics") if isinstance(details, dict) else None
        if (
            isinstance(diagnostics, dict)
            and diagnostics.get("abi") == inspection["abi"]
            and details.get("operation") == "inspect_dart_aot"
            and details.get("path") == expected_apk_path
            and isinstance(error.get("category"), str)
            and error["category"] == "unsupported_target"
        ):
            return "unsupported"
    if (
        report.get("record_type") == "anti_rea_upstream_operation_result"
        and report.get("operation") == "inspect_dart_aot"
        and report.get("status") == "blocked"
        and report.get("artifact_sha256") == inspection["artifact_sha256"]
        and isinstance(report.get("error"), dict)
        and report["error"].get("category") == "unsupported_target"
    ):
        diagnostics = report["error"].get("details", {}).get("diagnostics", {})
        if diagnostics.get("abi") == inspection["abi"]:
            return "unsupported"
    normalized = report.get("normalized_result")
    subject_root = report.get("subject")
    subject = subject_root.get("digest") if isinstance(subject_root, dict) else None
    target = normalized.get("target") if isinstance(normalized, dict) else None
    libapp = normalized.get("libapp") if isinstance(normalized, dict) else None
    sections = libapp.get("sections") if isinstance(libapp, dict) else None
    valid_section_names = isinstance(sections, list) and all(
        isinstance(item, dict) and isinstance(item.get("name"), str)
        for item in sections
    )
    section_names = (
        {item["name"] for item in sections} if valid_section_names else set()
    )
    complete_layout = valid_section_names and any(
        section_names == layout and len(sections) == len(layout)
        for layout in _AOT_SECTION_LAYOUTS
    )
    if (
        report.get("predicate_type") == "rea.analysis"
        and report.get("operation") == "inspect_dart_aot"
        and isinstance(report.get("provider"), dict)
        and report["provider"].get("id") == "flutter"
        and isinstance(report.get("evidence_id"), str)
        and report["evidence_id"]
        and isinstance(subject_root, dict)
        and subject_root.get("format") == "apk"
        and isinstance(subject, dict)
        and subject.get("sha256") == inspection["artifact_sha256"]
        and isinstance(target, dict)
        and target.get("sha256") == inspection["artifact_sha256"]
        and target.get("bytes") == inspection["artifact_size"]
        and normalized.get("abi") == inspection["abi"]
        and isinstance(libapp, dict)
        and libapp.get("coverage") == "complete"
        and complete_layout
        and all(
            isinstance(item.get("offset"), int)
            and not isinstance(item.get("offset"), bool)
            and item["offset"] >= 0
            and isinstance(item.get("size"), int)
            and not isinstance(item.get("size"), bool)
            and item["size"] > 0
            for item in sections
        )
        and isinstance(libapp.get("sha256"), str)
        and re.fullmatch(r"[a-f0-9]{64}", libapp["sha256"])
        and isinstance(libapp.get("snapshot_hash"), str)
        and libapp["snapshot_hash"]
    ):
        return "supported"
    raise workflow.WorkflowError(
        "REA AOT report does not identify the exact APK, ABI, and inspection outcome"
    )


def capture_toolchain_identity(command: list[str], cwd: str | Path) -> dict:
    """Capture bounded Flutter/Android/JDK identity for one selected release command."""
    if (
        not isinstance(command, list)
        or len(command) < 4
        or command[1:4]
        not in (["build", "apk", "--release"], ["build", "appbundle", "--release"])
    ):
        raise workflow.WorkflowError(
            "Flutter toolchain identity requires an explicit Android release command"
        )
    executable = shutil.which(command[0])
    if executable is None:
        raise workflow.WorkflowError(
            "Flutter executable is unavailable while capturing toolchain identity"
        )

    def run(args, timeout):
        try:
            code, stdout, stderr, timed_out, out_limit, err_limit = (
                baseline._run_command(
                    [executable, *args],
                    Path(cwd),
                    timeout,
                    total_output_limit=1024 * 1024,
                )
            )
        except OSError as error:
            raise workflow.WorkflowError(
                f"Could not capture Flutter toolchain identity: {error}"
            ) from error
        if code != 0 or timed_out or out_limit or err_limit:
            raise workflow.WorkflowError(
                "Flutter toolchain identity command failed, timed out, or exceeded output limits"
            )
        return (stdout + b"\n" + stderr).decode("utf-8", errors="strict")

    try:
        version = json.loads(run(["--version", "--machine"], 30))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise workflow.WorkflowError(
            "Flutter toolchain version output is invalid"
        ) from error
    if not isinstance(version, dict):
        raise workflow.WorkflowError("Flutter toolchain version output is invalid")
    fields = {
        "framework_version": version.get("frameworkVersion"),
        "channel": version.get("channel"),
        "framework_revision": version.get("frameworkRevision"),
        "engine_revision": version.get("engineRevision"),
        "dart_sdk_version": version.get("dartSdkVersion"),
    }
    if any(
        not isinstance(v, str) or not _IDENTITY_TOKEN.fullmatch(v)
        for v in fields.values()
    ):
        raise workflow.WorkflowError(
            "Flutter framework, engine, or Dart toolchain identity is incomplete"
        )
    doctor = run(["doctor", "-v", "--suppress-analytics"], 180)
    section_match = _ANDROID_SECTION.search(doctor)
    if not section_match:
        raise workflow.WorkflowError(
            "Flutter doctor did not report the Android toolchain"
        )
    start = section_match.start()
    following = re.search(r"^\[[✓!✗]\] ", doctor[section_match.end() :], re.MULTILINE)
    section = doctor[
        start : section_match.end() + following.start() if following else len(doctor)
    ]
    sdk = re.search(r"Android SDK version ([0-9][A-Za-z0-9._+-]{0,63})", section, re.I)
    sdk_path = _SDK_PATH.search(section)
    platform = re.search(
        r"Platform (android-[0-9][A-Za-z0-9._+-]{0,63})", section, re.I
    )
    build_tools = re.search(r"build-tools ([0-9][A-Za-z0-9._+-]{0,63})", section, re.I)
    java_binary = re.search(r"Java binary at:\s*(.+)", section, re.I)
    java_version = re.search(r"Java version\s+(.+)", section, re.I)
    if not all((sdk, sdk_path, platform, build_tools, java_binary, java_version)):
        raise workflow.WorkflowError(
            "Flutter doctor Android SDK, build-tools, or JDK identity is incomplete"
        )
    binary = java_binary.group(1).strip()
    jdk = java_version.group(1).strip()
    if (
        not Path(binary).is_absolute()
        or len(binary) > 1024
        or len(jdk) > 256
        or any(ord(char) < 32 for char in binary + jdk)
    ):
        raise workflow.WorkflowError("Flutter doctor returned an invalid JDK identity")
    sdk_root = Path(sdk_path.group(1).strip()).resolve(strict=True)
    apksigner = baseline._hash_artifact(
        sdk_root, f"build-tools/{build_tools.group(1)}/lib/apksigner.jar"
    )
    return {
        "flutter": fields,
        "android": {
            "sdk_version": sdk.group(1),
            "platform_version": platform.group(1),
            "build_tools_version": build_tools.group(1),
            "apksigner_sha256": apksigner["sha256"],
        },
        "java": {"binary": binary, "version": jdk},
        "build": {
            "target": command[2],
            "command_sha256": hashlib.sha256(workflow.canonical(command)).hexdigest(),
        },
    }


def verify_apk_signature(
    apk_path: str | Path, command: list[str], expected_toolchain: dict, cwd: str | Path
) -> dict:
    """Run the captured Android SDK's apksigner against one exact APK."""
    if (
        not isinstance(expected_toolchain, dict)
        or not isinstance(command, list)
        or len(command) < 4
        or command[1:4]
        not in (["build", "apk", "--release"], ["build", "appbundle", "--release"])
    ):
        raise workflow.WorkflowError(
            "APK signature verification requires a captured Flutter Android toolchain"
        )
    current_toolchain = capture_toolchain_identity(command, cwd)
    if current_toolchain != expected_toolchain:
        raise workflow.WorkflowError(
            "Current Flutter Android toolchain differs from the captured baseline"
        )
    expected_android = expected_toolchain.get("android")
    expected_java = expected_toolchain.get("java")
    expected_build_tools_version = (
        expected_android.get("build_tools_version")
        if isinstance(expected_android, dict)
        else None
    )
    expected_apksigner_sha256 = (
        expected_android.get("apksigner_sha256")
        if isinstance(expected_android, dict)
        else None
    )
    expected_java_binary = (
        expected_java.get("binary") if isinstance(expected_java, dict) else None
    )
    if (
        not isinstance(expected_build_tools_version, str)
        or not isinstance(expected_apksigner_sha256, str)
        or not workflow._SHA256.fullmatch(expected_apksigner_sha256)
        or not isinstance(expected_java_binary, str)
        or not Path(expected_java_binary).is_absolute()
    ):
        raise workflow.WorkflowError(
            "Captured Flutter Android toolchain lacks build-tools or JDK identity"
        )
    apk = Path(apk_path).expanduser()
    if apk.is_symlink() or not apk.is_file():
        raise workflow.WorkflowError(
            "APK signature verification requires a regular, non-symlink APK"
        )
    try:
        before = baseline._hash_artifact(apk.parent, apk.name)
        flutter = shutil.which(command[0])
        if flutter is None:
            raise workflow.WorkflowError(
                "Captured Flutter executable is unavailable for APK signature verification"
            )
        code, stdout, stderr, timed_out, out_limit, err_limit = baseline._run_command(
            [flutter, "doctor", "-v", "--suppress-analytics"],
            Path(cwd),
            180,
            total_output_limit=1024 * 1024,
        )
        if code != 0 or timed_out or out_limit or err_limit:
            raise workflow.WorkflowError(
                "Flutter doctor failed while locating Android signature verification tools"
            )
        doctor = (stdout + b"\n" + stderr).decode("utf-8", errors="strict")
        sdk_match = _SDK_PATH.search(doctor)
        section_match = _ANDROID_SECTION.search(doctor)
        if not sdk_match or not section_match:
            raise workflow.WorkflowError(
                "Flutter doctor did not identify the Android SDK for signature verification"
            )
        start = section_match.start()
        following = re.search(
            r"^\[[✓!✗]\] ", doctor[section_match.end() :], re.MULTILINE
        )
        section = doctor[
            start : section_match.end() + following.start()
            if following
            else len(doctor)
        ]
        build_tools_match = re.search(
            r"build-tools ([0-9][A-Za-z0-9._+-]{0,63})", section, re.I
        )
        java_match = re.search(r"Java binary at:\s*(.+)", section, re.I)
        if (
            not build_tools_match
            or build_tools_match.group(1) != expected_build_tools_version
            or not java_match
        ):
            raise workflow.WorkflowError(
                "Android build-tools or JDK identity differs from the captured toolchain"
            )
        sdk_root = Path(sdk_match.group(1).strip()).resolve(strict=True)
        if not sdk_root.is_dir():
            raise workflow.WorkflowError(
                "Flutter doctor returned an invalid Android SDK directory"
            )
        apksigner = (
            sdk_root
            / "build-tools"
            / expected_build_tools_version
            / "lib"
            / "apksigner.jar"
        )
        if apksigner.is_symlink() or not apksigner.is_file():
            raise workflow.WorkflowError(
                "Captured Android build-tools apksigner JAR is unavailable or linked"
            )
        apksigner = apksigner.resolve(strict=True)
        try:
            apksigner.relative_to(sdk_root)
        except ValueError as error:
            raise workflow.WorkflowError(
                "Captured apksigner resolves outside the Android SDK"
            ) from error
        if (
            baseline._hash_artifact(
                sdk_root,
                f"build-tools/{expected_build_tools_version}/lib/apksigner.jar",
            )["sha256"]
            != expected_apksigner_sha256
        ):
            raise workflow.WorkflowError(
                "Android apksigner JAR digest differs from the captured baseline"
            )
        java = Path(java_match.group(1).strip()).resolve(strict=True)
        captured_java = Path(expected_java_binary).resolve(strict=True)
        if java != captured_java or not java.is_file() or not os.access(java, os.X_OK):
            raise workflow.WorkflowError(
                "Flutter doctor JDK differs from the captured toolchain or is unavailable"
            )
        env = os.environ.copy()
        env["JAVA_HOME"] = str(java.parent.parent)

        def run(args, timeout):
            code, out, err, timed_out, out_limit, err_limit = baseline._run_command(
                [str(java), "-jar", str(apksigner), *args],
                Path(cwd),
                timeout,
                env=env,
                total_output_limit=1024 * 1024,
            )
            if code != 0 or timed_out or out_limit or err_limit:
                raise workflow.WorkflowError(
                    "Pinned apksigner command failed or exceeded its execution limits"
                )
            return (out + b"\n" + err).decode("utf-8", errors="strict").strip()

        version = run(["version"], 15)
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", version):
            raise workflow.WorkflowError(
                "Android apksigner returned an invalid version"
            )
        output = run(
            ["verify", "--verbose", "--print-certs", str(apk.resolve(strict=True))], 60
        )
        signers = _SIGNER_COUNT.findall(output)
        certificates = _SIGNER_CERT_SHA256.findall(output)
        public_keys = _SIGNER_KEY_SHA256.findall(output)
        if (
            output.splitlines().count("Verifies") != 1
            or len(signers) != 1
            or int(signers[0]) < 1
            or len(certificates) != int(signers[0])
            or len(public_keys) != int(signers[0])
            or {int(index) for index, _digest in certificates}
            != set(range(1, int(signers[0]) + 1))
        ):
            raise workflow.WorkflowError(
                "Android apksigner output lacks a complete successful signer report"
            )
        after = baseline._hash_artifact(apk.parent, apk.name)
        if before.get("sha256") != after.get("sha256"):
            raise workflow.WorkflowError(
                "APK changed during cryptographic signature verification"
            )
        return {
            "apk_sha256": before["sha256"],
            "result": "Verifies",
            "signer_count": int(signers[0]),
            "certificate_sha256": [digest.lower() for _index, digest in certificates],
            "public_key_sha256": [digest.lower() for _index, digest in public_keys],
            "tool": {
                "name": "apksigner",
                "version": version,
                "build_tools_version": expected_build_tools_version,
                "jar_sha256": expected_apksigner_sha256,
            },
        }
    except workflow.WorkflowError:
        raise
    except (OSError, UnicodeDecodeError, ValueError, RuntimeError) as error:
        raise workflow.WorkflowError(
            f"APK signature verification failed: {error}"
        ) from error


def build_command(
    project: str | Path,
    target: str,
    split_debug_info: str | Path | None = None,
    flutter: str = "flutter",
    *,
    obfuscate: bool = False,
) -> list[str]:
    """Return a Flutter Android release build, with optional Dart obfuscation."""
    root = Path(project).expanduser().resolve(strict=True)
    if (
        not root.is_dir()
        or not (root / "pubspec.yaml").is_file()
        or not (root / "android").is_dir()
    ):
        raise workflow.WorkflowError(
            "Flutter Android project requires pubspec.yaml and android/ at its root"
        )
    if target not in {"apk", "appbundle"}:
        raise workflow.WorkflowError("Flutter Android target must be apk or appbundle")
    if not isinstance(obfuscate, bool):
        raise workflow.WorkflowError("Flutter obfuscation selection must be a boolean")
    debug_info = None
    if split_debug_info is not None:
        debug_info = Path(split_debug_info).expanduser().resolve()
        if debug_info == root or root in debug_info.parents:
            raise workflow.WorkflowError(
                "Split debug information must be stored outside the project"
            )
        if not obfuscate:
            raise workflow.WorkflowError("Split debug information requires --obfuscate")
    if obfuscate and debug_info is None:
        raise workflow.WorkflowError(
            "Flutter obfuscation requires a private split-debug-info path"
        )
    executable = shutil.which(flutter)
    if executable is None:
        raise workflow.WorkflowError(f"Flutter executable is unavailable: {flutter}")
    command = [executable, "build", target, "--release"]
    if obfuscate:
        command.extend(["--obfuscate", f"--split-debug-info={debug_info}"])
    return command


def probe_android_environment(
    flutter: str = "flutter", timeout_seconds: float = 120
) -> dict:
    """Report Flutter, Android SDK/license/JDK, and device readiness without changing the host."""
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= 600
    ):
        raise workflow.WorkflowError(
            "Flutter probe timeout must be greater than 0 and at most 600 seconds"
        )
    if not isinstance(flutter, str) or not flutter.strip():
        raise workflow.WorkflowError(
            "Flutter executable must be a non-empty path or command"
        )
    executable = shutil.which(flutter)
    if executable is None:
        return _probe_result(
            flutter, None, [], "unavailable", None, "unknown", "unknown"
        )

    commands = []

    def run(args, limit):
        argv = [executable, *args]
        try:
            code, stdout, stderr, timed_out, stdout_truncated, stderr_truncated = (
                baseline._run_command(
                    argv,
                    Path.cwd(),
                    min(float(timeout_seconds), limit),
                    total_output_limit=1024 * 1024,
                )
            )
        except OSError as error:
            return {"argv": argv, "status": "failed", "error": str(error)}
        record = {
            "argv": argv,
            "exit_code": code,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "status": "timed_out"
            if timed_out
            else "output_limit"
            if stdout_truncated or stderr_truncated
            else "completed"
            if code == 0
            else "failed",
        }
        commands.append(record)
        return record

    version_result = run(["--version", "--machine"], 30)
    version_data = None
    if version_result["status"] == "completed":
        try:
            value = json.loads(version_result["stdout"])
            if (
                isinstance(value, dict)
                and isinstance(value.get("frameworkVersion"), str)
                and value["frameworkVersion"]
                and isinstance(value.get("channel"), str)
                and value["channel"]
            ):
                version_data = {
                    key: value[key]
                    for key in (
                        "frameworkVersion",
                        "channel",
                        "frameworkRevision",
                        "engineRevision",
                        "dartSdkVersion",
                    )
                    if isinstance(value.get(key), str)
                }
        except json.JSONDecodeError:
            pass
    if version_data is None:
        return _probe_result(
            flutter, executable, commands, "incomplete", None, "unknown", "unknown"
        )

    doctor = run(["doctor", "-v", "--suppress-analytics"], 180)
    doctor_text = doctor.get("stdout", "") + "\n" + doctor.get("stderr", "")
    match = _ANDROID_SECTION.search(doctor_text)
    if not match:
        sdk_status, license_status = "unknown", "unknown"
        java = {"status": "unknown", "binary": None, "version": None}
    else:
        mark, detail = match.groups()
        start, end = match.span()
        next_section = re.search(r"^\[[✓!✗]\] ", doctor_text[end:], re.MULTILINE)
        section = detail + (
            doctor_text[end : end + next_section.start()]
            if next_section
            else doctor_text[end:]
        )
        java_binary = _JAVA_BINARY.search(section)
        java_version = _JAVA_VERSION.search(section)
        binary = java_binary.group(1).strip() if java_binary else ""
        version = java_version.group(1).strip() if java_version else ""
        if _JAVA_MISSING.search(section):
            java = {"status": "missing", "binary": None, "version": None}
        elif (
            binary
            and Path(binary).is_absolute()
            and len(binary) <= 1024
            and version
            and len(version) <= 256
            and not any(ord(char) < 32 for char in binary + version)
        ):
            java = {"status": "ready", "binary": binary, "version": version}
        else:
            java = {"status": "incomplete", "binary": None, "version": None}
        if _ANDROID_SDK_MISSING.search(section):
            sdk_status, license_status = "blocked", "unknown"
        elif mark == "✓":
            sdk_status, license_status = "ready", "accepted"
        elif _ANDROID_LICENSES_MISSING.search(section):
            sdk_status, license_status = "ready", "not_accepted"
        else:
            sdk_status, license_status = "incomplete", "unknown"
    if doctor["status"] in {"timed_out", "output_limit", "failed"}:
        if sdk_status == "ready":
            sdk_status = "incomplete"
        if license_status == "accepted":
            license_status = "unknown"
        java = {"status": "unknown", "binary": None, "version": None}

    devices_result = run(["devices", "--machine", "--suppress-analytics"], 60)
    devices = None
    if devices_result["status"] == "completed":
        try:
            value = json.loads(devices_result["stdout"])
            if isinstance(value, list) and all(
                isinstance(item, dict) for item in value
            ):
                android = [
                    item
                    for item in value
                    if isinstance(item.get("targetPlatform"), str)
                    and item["targetPlatform"].startswith("android")
                    and item.get("isSupported") is True
                ]
                devices = {
                    "status": "available" if android else "none_connected",
                    "count": len(android),
                    "emulator_count": sum(
                        item.get("emulator") is True for item in android
                    ),
                    "physical_count": sum(
                        item.get("emulator") is False for item in android
                    ),
                }
        except json.JSONDecodeError:
            pass
    devices_result.pop(
        "stdout", None
    )  # Device IDs can contain stable, user-specific hardware identifiers.
    if devices is None:
        devices = {
            "status": "unknown",
            "count": None,
            "emulator_count": None,
            "physical_count": None,
        }

    build_status = (
        "ready"
        if (
            sdk_status == "ready"
            and license_status == "accepted"
            and java["status"] == "ready"
        )
        else (
            "blocked"
            if "blocked" in {sdk_status, license_status}
            or license_status == "not_accepted"
            or java["status"] == "missing"
            else "incomplete"
        )
    )
    device_status = (
        "ready"
        if devices["status"] == "available"
        else ("blocked" if devices["status"] == "none_connected" else "incomplete")
    )
    status = (
        "ready"
        if build_status == "ready" and device_status == "ready"
        else ("blocked" if "blocked" in {build_status, device_status} else "incomplete")
    )
    return {
        "status": status,
        "scope": "flutter_android_toolchain_only",
        "flutter": {"executable": str(Path(executable).resolve()), **version_data},
        "checks": {
            "android_sdk": sdk_status,
            "android_licenses": license_status,
            "android_java": java,
            "android_build": build_status,
            "android_device": devices,
        },
        "commands": commands,
        "limitations": [
            "Does not build, sign, install, or run an application.",
            "Does not accept Android licenses or install toolchains.",
            "Toolchain readiness does not establish app compatibility.",
        ],
    }


def _probe_result(
    flutter: str,
    executable: str | None,
    commands: list[dict],
    status: str,
    version: dict | None,
    sdk_status: str,
    license_status: str,
) -> dict:
    return {
        "status": status,
        "scope": "flutter_android_toolchain_only",
        "flutter": (
            {"executable": str(Path(executable).resolve()), **version}
            if executable and version
            else None
        ),
        "requested_flutter": flutter,
        "checks": {
            "android_sdk": sdk_status,
            "android_licenses": license_status,
            "android_java": {"status": "unknown", "binary": None, "version": None},
            "android_build": "incomplete",
            "android_device": {
                "status": "unknown",
                "count": None,
                "emulator_count": None,
                "physical_count": None,
            },
        },
        "commands": commands,
        "limitations": [
            "Does not build, sign, install, or run an application.",
            "Does not accept Android licenses or install toolchains.",
            "Toolchain readiness does not establish app compatibility.",
        ],
    }
