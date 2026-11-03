import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import flutter_android, workflow


class FlutterAndroidCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "app"
        self.root.mkdir()
        (self.root / "pubspec.yaml").write_text("name: owned_fixture\n")
        (self.root / "android").mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_plans_obfuscated_release_build_with_private_debug_info_path(self):
        debug_info = Path(self.temp.name) / "private-debug-info"
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"):
            command = flutter_android.build_command(self.root, "appbundle", debug_info, obfuscate=True)
        self.assertEqual(command, ["/sdk/bin/flutter", "build", "appbundle", "--release",
                                   "--obfuscate", f"--split-debug-info={debug_info.resolve()}"])

    def test_plans_unobfuscated_release_baseline_without_symbol_output(self):
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"):
            command = flutter_android.build_command(self.root, "apk")
        self.assertEqual(command, ["/sdk/bin/flutter", "build", "apk", "--release"])

    def test_rejects_unknown_target_and_debug_info_inside_project(self):
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"):
            with self.assertRaisesRegex(workflow.WorkflowError, "must be apk or appbundle"):
                flutter_android.build_command(self.root, "ios", Path(self.temp.name) / "debug")
            with self.assertRaisesRegex(workflow.WorkflowError, "outside the project"):
                flutter_android.build_command(self.root, "apk", self.root / "debug")
            with self.assertRaisesRegex(workflow.WorkflowError, "requires a private split-debug-info"):
                flutter_android.build_command(self.root, "apk", obfuscate=True)
            with self.assertRaisesRegex(workflow.WorkflowError, "requires --obfuscate"):
                flutter_android.build_command(self.root, "apk", Path(self.temp.name) / "symbols")

    def test_captures_validated_flutter_android_jdk_build_identity(self):
        sdk = Path(self.temp.name) / "android-sdk"
        signer = sdk / "build-tools" / "36.0.0" / "lib" / "apksigner.jar"
        signer.parent.mkdir(parents=True)
        signer.write_bytes(b"captured signer")
        version = (0, b'{"frameworkVersion":"3.47.8","channel":"stable",'
                   b'"frameworkRevision":"abc123","engineRevision":"def456",'
                   b'"dartSdkVersion":"3.13.7"}', b"", False, False, False)
        doctor_text = ("[✓] Android toolchain - Android SDK version 36.0.0\n"
                       f"    Android SDK at: {sdk}\n"
                       "    Platform android-37, build-tools 36.0.0\n"
                       "    Java binary at: /opt/jdk/bin/java\n"
                       "    Java version OpenJDK Runtime Environment (build 17.0.1)\n")
        doctor = (0, doctor_text.encode(), b"", False, False, False)
        command = ["/sdk/bin/flutter", "build", "apk", "--release"]
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android.baseline, "_run_command", side_effect=[version, doctor]):
            identity = flutter_android.capture_toolchain_identity(command, self.root)
        self.assertEqual(identity["flutter"]["engine_revision"], "def456")
        self.assertEqual(identity["android"], {"sdk_version": "36.0.0", "platform_version": "android-37",
                                                "build_tools_version": "36.0.0",
                                                "apksigner_sha256": __import__("hashlib").sha256(
                                                    signer.read_bytes()).hexdigest()})
        self.assertEqual(identity["java"]["binary"], "/opt/jdk/bin/java")
        self.assertEqual(identity["build"]["target"], "apk")
        self.assertEqual(len(identity["build"]["command_sha256"]), 64)

    def test_rejects_non_flutter_or_non_android_project(self):
        (self.root / "android").rmdir()
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"):
            with self.assertRaisesRegex(workflow.WorkflowError, "requires pubspec.yaml and android/"):
                flutter_android.build_command(self.root, "apk", Path(self.temp.name) / "debug")

    def test_rejects_missing_flutter_executable(self):
        with patch.object(flutter_android.shutil, "which", return_value=None):
            with self.assertRaisesRegex(workflow.WorkflowError, "executable is unavailable"):
                flutter_android.build_command(self.root, "apk", Path(self.temp.name) / "debug")

    @staticmethod
    def _command(code, stdout, stderr=b"", timed_out=False):
        return (code, stdout.encode() if isinstance(stdout, str) else stdout,
                stderr.encode() if isinstance(stderr, str) else stderr, timed_out, False, False)

    def test_readiness_requires_android_sdk_licenses_and_android_device(self):
        version = self._command(0, '{"frameworkVersion":"3.47.8","channel":"stable",'
                                '"frameworkRevision":"abc","dartSdkVersion":"3.13.7"}')
        doctor = self._command(0, "[✓] Flutter (Channel stable)\n"
                               "[!] Android toolchain - Android SDK version 36.0.0\n"
                               "    • Java binary at: /opt/jdk/bin/java\n"
                               "    • Java version OpenJDK 17.0.1\n"
                               "    ! Some Android licenses not accepted.\n"
                               "[✓] Connected device (2 available)")
        devices = self._command(0, '[{"id":"macos","isSupported":true,"targetPlatform":"darwin"},'
                                '{"id":"chrome","isSupported":true,"targetPlatform":"web-javascript"}]')
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android.baseline, "_run_command", side_effect=[version, doctor, devices]) as run:
            result = flutter_android.probe_android_environment()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["checks"]["android_build"], "blocked")
        self.assertEqual(result["checks"]["android_licenses"], "not_accepted")
        self.assertEqual(result["checks"]["android_java"],
                         {"status": "ready", "binary": "/opt/jdk/bin/java", "version": "OpenJDK 17.0.1"})
        self.assertEqual(result["checks"]["android_device"]["status"], "none_connected")
        self.assertEqual(run.call_count, 3)
        self.assertTrue(all("accept" not in " ".join(call.args[0]) for call in run.call_args_list))

    def test_ready_toolchain_and_android_emulator_are_reported_separately(self):
        outputs = [self._command(0, '{"frameworkVersion":"3.47.8","channel":"stable"}'),
                   self._command(0, "[✓] Android toolchain - Android SDK version 36.0.0\n"
                                    "    • Java binary at: /configured/jdk/bin/java\n"
                                    "    • Java version OpenJDK 17.0.1"),
                   self._command(0, '[{"id":"private-device-id","isSupported":true,'
                                    '"targetPlatform":"android-arm64","emulator":true}]')]
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android.baseline, "_run_command", side_effect=outputs):
            result = flutter_android.probe_android_environment("flutter", 90)
        self.assertEqual((result["status"], result["checks"]["android_build"],
                          result["checks"]["android_device"]["status"]), ("ready", "ready", "available"))
        self.assertEqual(result["checks"]["android_device"]["emulator_count"], 1)
        self.assertEqual(result["checks"]["android_java"],
                         {"status": "ready", "binary": "/configured/jdk/bin/java", "version": "OpenJDK 17.0.1"})
        self.assertNotIn("private-device-id", json.dumps(result))

    def test_missing_jdk_blocks_android_build_even_when_licenses_are_accepted(self):
        outputs = [self._command(0, '{"frameworkVersion":"3.47.8","channel":"stable"}'),
                   self._command(0, "[!] Android toolchain - Android SDK version 36.0.0\n"
                                    "    ✗ Unable to locate a Java Runtime\n"
                                    "    • Some Android licenses not accepted."),
                   self._command(0, '[{"isSupported":true,"targetPlatform":"android-arm64","emulator":true}]')]
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android.baseline, "_run_command", side_effect=outputs):
            result = flutter_android.probe_android_environment()
        self.assertEqual(result["checks"]["android_licenses"], "not_accepted")
        self.assertEqual(result["checks"]["android_java"]["status"], "missing")
        self.assertEqual(result["checks"]["android_build"], "blocked")

    def test_missing_sdk_malformed_machine_output_and_timeout_fail_closed(self):
        version = self._command(0, '{"frameworkVersion":"3.47.8","channel":"stable"}')
        for doctor, devices, expected, build_status, device_status in (
            (self._command(0, "[!] Android toolchain - Android SDK not found"),
             self._command(0, "[]"), "blocked", "blocked", "none_connected"),
            (self._command(0, "Android doctor output changed"), self._command(0, "not json"),
             "incomplete", "incomplete", "unknown"),
            (self._command(None, "", timed_out=True), self._command(0, "[]"),
             "blocked", "incomplete", "none_connected"),
        ):
            with self.subTest(expected=expected), \
                    patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                    patch.object(flutter_android.baseline, "_run_command", side_effect=[version, doctor, devices]):
                result = flutter_android.probe_android_environment()
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["checks"]["android_build"], build_status)
                self.assertEqual(result["checks"]["android_device"]["status"], device_status)

    def test_missing_flutter_and_invalid_timeout_are_reported_without_running(self):
        with patch.object(flutter_android.shutil, "which", return_value=None):
            result = flutter_android.probe_android_environment()
        self.assertEqual(result["status"], "unavailable")
        with self.assertRaisesRegex(workflow.WorkflowError, "timeout"):
            flutter_android.probe_android_environment(timeout_seconds=601)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_aot_evidence_fifo_is_rejected_without_blocking(self):
        fifo = Path(self.temp.name) / "evidence.json"
        os.mkfifo(fifo)
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys; from core.flutter_android import _read_evidence; _read_evidence(sys.argv[1])",
             str(fifo)], capture_output=True, text=True, timeout=2,
            cwd=Path(__file__).parents[1])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Flutter AOT evidence must be a bounded regular file", result.stderr)

    def test_classifies_raw_unsupported_rea_output_only_for_bound_apk_and_abi(self):
        apk = "/private/state/baseline-before-build-snapshot/build/app.apk"
        result = {"is_error": True, "operation": "inspect_dart_aot", "content": [{"text": json.dumps({
            "error": {"category": "unsupported_target", "details": {"operation": "inspect_dart_aot",
                "path": apk, "diagnostics": {"abi": "arm64-v8a", "observed_exports": [
                    {"name": "_kDartSnapshotText"}]}}}})}]}
        inspection = {"artifact_sha256": "a" * 64, "abi": "arm64-v8a"}
        self.assertEqual(flutter_android._classify_aot_report(result, inspection, apk), "unsupported")
        with self.assertRaisesRegex(workflow.WorkflowError, "exact APK"):
            flutter_android._classify_aot_report(result, inspection, apk + ".other")
        with self.assertRaisesRegex(workflow.WorkflowError, "exact APK"):
            flutter_android._classify_aot_report(result, {**inspection, "abi": "x86_64"}, apk)

    def test_classifies_hash_bound_renamed_dart_snapshot_layout(self):
        example = Path(__file__).parents[1] / "examples/loopweek-flutter/evidence/rea-pr3662-aot-candidate.json"
        candidate = json.loads(example.read_text())
        aot = candidate["aot"]
        report = {
            "predicate_type": "rea.analysis", "operation": "inspect_dart_aot",
            "provider": {"id": "flutter"}, "evidence_id": candidate["operation"]["evidence_id"],
            "subject": {"format": "apk", "digest": {"sha256": candidate["artifact"]["sha256"]}},
            "normalized_result": {
                "target": {"sha256": candidate["artifact"]["sha256"], "bytes": candidate["artifact"]["size"]},
                "abi": aot["abi"], "libapp": aot["libapp"],
            },
        }
        inspection = {"artifact_sha256": candidate["artifact"]["sha256"],
                      "artifact_size": candidate["artifact"]["size"], "abi": aot["abi"]}
        self.assertEqual(flutter_android._classify_aot_report(report, inspection), "supported")
        cli_output = {"ok": True, "data": report, "meta": {"operation": "inspect_dart_aot"}}
        self.assertEqual(flutter_android._classify_aot_report(cli_output, inspection), "supported")
        mismatched_cli_output = json.loads(json.dumps(cli_output))
        mismatched_cli_output["data"]["normalized_result"]["target"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(workflow.WorkflowError, "exact APK"):
            flutter_android._classify_aot_report(mismatched_cli_output, inspection)
        with self.assertRaisesRegex(workflow.WorkflowError, "successful analysis result"):
            flutter_android._classify_aot_report({"ok": False, "data": report}, inspection)
        latest = json.loads((example.parent / "rea-pr3662-aot-clean-source-baseline-002.json").read_text())
        latest_aot = latest["aot"]
        latest_report = {
            "predicate_type": "rea.analysis", "operation": "inspect_dart_aot",
            "provider": {"id": "flutter"}, "evidence_id": latest["operation"]["evidence_id"],
            "subject": {"format": "apk", "digest": {"sha256": latest["artifact"]["sha256"]}},
            "normalized_result": {
                "target": {"sha256": latest["artifact"]["sha256"], "bytes": latest["artifact"]["size"]},
                "abi": latest_aot["abi"], "libapp": latest_aot["libapp"],
            },
        }
        latest_inspection = {
            "artifact_sha256": latest["artifact"]["sha256"],
            "artifact_size": latest["artifact"]["size"], "abi": latest_aot["abi"],
        }
        self.assertEqual(flutter_android._classify_aot_report(latest_report, latest_inspection), "supported")
        partial = json.loads(json.dumps(report))
        partial["normalized_result"]["libapp"]["sections"].pop()
        with self.assertRaisesRegex(workflow.WorkflowError, "exact APK"):
            flutter_android._classify_aot_report(partial, inspection)
        malformed = json.loads(json.dumps(report))
        malformed["normalized_result"]["libapp"]["sections"][0]["name"] = []
        with self.assertRaisesRegex(workflow.WorkflowError, "exact APK"):
            flutter_android._classify_aot_report(malformed, inspection)

    def test_verifies_apk_signature_with_captured_android_sdk_and_jdk(self):
        sdk = Path(self.temp.name) / "android-sdk"
        signer = sdk / "build-tools" / "36.0.0" / "lib" / "apksigner.jar"
        signer.parent.mkdir(parents=True)
        signer.write_text("fixture")
        java = Path(self.temp.name) / "jdk" / "bin" / "java"
        java.parent.mkdir(parents=True)
        java.write_text("fixture")
        java.chmod(0o755)
        apk = Path(self.temp.name) / "app.apk"
        apk.write_bytes(b"signed apk fixture")
        doctor = ("[✓] Android toolchain - Android SDK version 36.0.0\n"
                  f"    • Android SDK at: {sdk}\n"
                  "    • Platform android-37.0, build-tools 36.0.0\n"
                  f"    • Java binary at: {java}\n"
                  "    • Java version OpenJDK 17.0.1\n"
                  "[✓] Connected device (1 available)\n").encode()
        verify = ("Verifies\nVerified using v2 scheme (APK Signature Scheme v2): true\n"
                  "Number of signers: 1\n"
                  "Signer #1 certificate SHA-256 digest: " + "a" * 64 + "\n"
                  "Signer #1 public key SHA-256 digest: " + "b" * 64 + "\n").encode()
        command = ["flutter", "build", "apk", "--release"]
        toolchain = {"flutter": {"framework_version": "3.47.8", "channel": "stable",
                                 "framework_revision": "abc123", "engine_revision": "def456",
                                 "dart_sdk_version": "3.13.7"},
                     "android": {"sdk_version": "36.0.0", "platform_version": "android-37.0",
                                 "build_tools_version": "36.0.0",
                                 "apksigner_sha256": __import__("hashlib").sha256(
                                     signer.read_bytes()).hexdigest()},
                     "java": {"binary": str(java), "version": "OpenJDK 17.0.1"},
                     "build": {"target": "apk", "command_sha256": __import__("hashlib").sha256(
                         workflow.canonical(command)).hexdigest()}}
        outputs = [self._command(0, '{"frameworkVersion":"3.47.8","channel":"stable",'
                                 '"frameworkRevision":"abc123","engineRevision":"def456",'
                                 '"dartSdkVersion":"3.13.7"}'), self._command(0, doctor),
                   self._command(0, doctor), self._command(0, "0.9\n"), self._command(0, verify)]
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android.baseline, "_run_command", side_effect=outputs) as run:
            result = flutter_android.verify_apk_signature(apk, command, toolchain, self.root)
        self.assertEqual(result, {"apk_sha256": __import__("hashlib").sha256(apk.read_bytes()).hexdigest(),
                                  "result": "Verifies", "signer_count": 1,
                                  "certificate_sha256": ["a" * 64], "public_key_sha256": ["b" * 64],
                                  "tool": {"name": "apksigner", "version": "0.9",
                                           "build_tools_version": "36.0.0",
                                           "jar_sha256": __import__("hashlib").sha256(
                                               signer.read_bytes()).hexdigest()}})
        self.assertEqual(run.call_count, 5)
        self.assertTrue(all(call.args[0][0] == str(java.resolve())
                            and call.args[0][1:3] == ["-jar", str(signer.resolve())]
                            for call in run.call_args_list[-2:]))
        self.assertTrue(all(call.kwargs["total_output_limit"] == 1024 * 1024
                            for call in run.call_args_list))

    def test_apk_signature_verifier_rejects_forged_or_mismatched_reports(self):
        sdk = Path(self.temp.name) / "android-sdk"
        signer = sdk / "build-tools" / "36.0.0" / "lib" / "apksigner.jar"
        signer.parent.mkdir(parents=True)
        signer.write_text("fixture")
        java = Path(self.temp.name) / "jdk" / "bin" / "java"
        java.parent.mkdir(parents=True)
        java.write_text("fixture")
        java.chmod(0o755)
        apk = Path(self.temp.name) / "app.apk"
        apk.write_bytes(b"signed apk fixture")
        doctor = ("[✓] Android toolchain - Android SDK version 36.0.0\n"
                  f"    • Android SDK at: {sdk}\n"
                  "    • Platform android-37.0, build-tools 36.0.0\n"
                  f"    • Java binary at: {java}\n"
                  "    • Java version OpenJDK 17.0.1\n").encode()
        forged = b"Number of signers: 1\nSigner #1 certificate SHA-256 digest: " + b"a" * 64 + b"\n"
        command = ["flutter", "build", "apk", "--release"]
        toolchain = {"android": {"build_tools_version": "36.0.0",
                                  "apksigner_sha256": __import__("hashlib").sha256(
                                      signer.read_bytes()).hexdigest()},
                     "java": {"binary": str(java)}}
        outputs = [self._command(0, doctor), self._command(0, "0.9"), self._command(0, forged)]
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android, "capture_toolchain_identity", return_value=toolchain), \
                patch.object(flutter_android.baseline, "_run_command", side_effect=outputs):
            with self.assertRaisesRegex(workflow.WorkflowError, "successful signer report"):
                flutter_android.verify_apk_signature(apk, command, toolchain, self.root)

        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android, "capture_toolchain_identity", return_value=toolchain), \
                patch.object(flutter_android.baseline, "_run_command",
                             return_value=self._command(0, doctor.replace(b"build-tools 36.0.0", b"build-tools 35.0.0"))):
            with self.assertRaisesRegex(workflow.WorkflowError, "differs from the captured toolchain"):
                flutter_android.verify_apk_signature(apk, command, toolchain, self.root)

        signer.write_text("modified verifier")
        with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"), \
                patch.object(flutter_android, "capture_toolchain_identity", return_value=toolchain), \
                patch.object(flutter_android.baseline, "_run_command", return_value=self._command(0, doctor)):
            with self.assertRaisesRegex(workflow.WorkflowError, "JAR digest differs"):
                flutter_android.verify_apk_signature(apk, command, toolchain, self.root)


if __name__ == "__main__":
    unittest.main()
