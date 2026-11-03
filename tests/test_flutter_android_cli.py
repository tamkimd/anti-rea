import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from core import flutter_android, workflow
from interfaces.cli import anti_rea


@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class FlutterAndroidBaselineCliTests(unittest.TestCase):
    @staticmethod
    def toolchain_identity(command):
        return {"flutter": {"framework_version": "3.47.8", "channel": "stable",
                            "framework_revision": "a1", "engine_revision": "b2", "dart_sdk_version": "3.13.7"},
                "android": {"sdk_version": "36.0.0", "platform_version": "android-37",
                            "build_tools_version": "36.0.0", "apksigner_sha256": "f" * 64},
                "java": {"binary": "/opt/jdk/bin/java", "version": "OpenJDK 17"},
                "build": {"target": command[2], "command_sha256": hashlib.sha256(
                    workflow.canonical(command)).hexdigest()}}

    def test_readiness_cli_emits_the_shared_probe_record(self):
        record={"status":"blocked","scope":"flutter_android_toolchain_only"}
        output=StringIO()
        with patch.object(flutter_android,"probe_android_environment",return_value=record) as probe, \
                redirect_stdout(output):
            status=anti_rea.main(["flutter-android-probe","--flutter","/sdk/bin/flutter","--timeout","90"])
        self.assertEqual(status,0)
        self.assertEqual(json.loads(output.getvalue()),record)
        probe.assert_called_once_with("/sdk/bin/flutter",90.0)

    def test_command_builds_inside_capture_snapshot_and_hashes_release_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "app"
            (project / "android").mkdir(parents=True)
            (project / "pubspec.yaml").write_text("name: owned_fixture\n")
            (project / "lib").mkdir()
            (project / "lib" / "main.dart").write_text("void main() {}\n")
            store = base / "state"
            flutter = base / "flutter"
            flutter.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\n"
                "import sys\n"
                "target = sys.argv[2]\n"
                "artifact = (Path('build/app/outputs/flutter-apk/app-release.apk') if target == 'apk' else "
                "Path('build/app/outputs/bundle/release/app-release.aab'))\n"
                "artifact.parent.mkdir(parents=True, exist_ok=True)\n"
                "artifact.write_bytes(b'owned-fixture-release')\n"
                "debug = Path(next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--split-debug-info=')))\n"
                "debug.mkdir(parents=True, exist_ok=True)\n"
                "(debug / 'app.symbols').write_text('private-symbols')\n"
                "print('fixture flutter build')\n")
            flutter.chmod(0o700)
            debug_info = store / "before-android-symbols"
            output = StringIO()
            with patch.object(flutter_android.shutil, "which", return_value=str(flutter)), \
                    patch.object(flutter_android, "capture_toolchain_identity",
                                 side_effect=lambda command, cwd: self.toolchain_identity(command)), redirect_stdout(output):
                status = anti_rea.main(["flutter-android-baseline", str(project), "--store", str(store),
                                        "--id", "before-android", "--target", "apk",
                                        "--split-debug-info", str(debug_info), "--obfuscate"])
            self.assertEqual(status, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "captured")
            self.assertEqual(set(result["artifacts"]), {"build/app/outputs/flutter-apk/app-release.apk"})
            artifact = result["artifacts"]["build/app/outputs/flutter-apk/app-release.apk"]
            self.assertEqual(artifact["sha256"], hashlib.sha256(b"owned-fixture-release").hexdigest())
            snapshot = Path(result["evidence"]).parent / "baseline-before-android-build-snapshot"
            self.assertEqual((snapshot / "build/app/outputs/flutter-apk/app-release.apk").read_bytes(),
                             b"owned-fixture-release")
            self.assertFalse((project / "build").exists())
            self.assertEqual((debug_info / "app.symbols").read_text(), "private-symbols")

    def test_baseline_defaults_to_unobfuscated_release_build(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "app"
            (project / "android").mkdir(parents=True)
            (project / "pubspec.yaml").write_text("name: owned_fixture\n")
            flutter = base / "flutter"
            flutter.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\nimport sys\n"
                "assert '--obfuscate' not in sys.argv\n"
                "assert not any(arg.startswith('--split-debug-info=') for arg in sys.argv)\n"
                "artifact=Path('build/app/outputs/flutter-apk/app-release.apk')\n"
                "artifact.parent.mkdir(parents=True,exist_ok=True)\nartifact.write_bytes(b'before-apk')\n")
            flutter.chmod(0o700)
            output = StringIO()
            with patch.object(flutter_android.shutil, "which", return_value=str(flutter)), \
                    patch.object(flutter_android, "capture_toolchain_identity",
                                 side_effect=lambda command, cwd: self.toolchain_identity(command)), redirect_stdout(output):
                status = anti_rea.main(["flutter-android-baseline", str(project), "--store", str(base / "state"),
                                        "--id", "before", "--target", "apk"])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "captured")

    def test_rejects_symbol_output_outside_store_without_running_build(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "app"
            (project / "android").mkdir(parents=True)
            (project / "pubspec.yaml").write_text("name: owned_fixture\n")
            with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"):
                output = StringIO()
                with redirect_stdout(output):
                    status = anti_rea.main(["flutter-android-baseline", str(project), "--store", str(base / "state"),
                                            "--id", "blocked", "--target", "appbundle",
                                            "--split-debug-info", str(base / "outside"), "--obfuscate"])
            self.assertEqual(status, 2)
            self.assertIn("direct child of the private --store", json.loads(output.getvalue())["detail"])

    def test_cli_rejects_split_debug_info_without_obfuscation(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "app"
            (project / "android").mkdir(parents=True)
            (project / "pubspec.yaml").write_text("name: owned_fixture\n")
            with patch.object(flutter_android.shutil, "which", return_value="/sdk/bin/flutter"):
                output = StringIO()
                with redirect_stdout(output):
                    status = anti_rea.main(["flutter-android-baseline", str(project), "--store", str(base / "state"),
                                            "--id", "bad-symbols", "--target", "apk",
                                            "--split-debug-info", str(base / "state" / "symbols")])
            self.assertEqual(status, 2)
            self.assertIn("requires --obfuscate", json.loads(output.getvalue())["detail"])

    def test_attaches_hash_bound_unsupported_aot_as_new_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = root / "state"
            snapshot = store / "evidence" / "baseline-before-build-snapshot"
            apk = snapshot / "build/app/outputs/flutter-apk/app-release.apk"
            apk.parent.mkdir(parents=True)
            apk.write_bytes(b"before-apk")
            command = ["/sdk/flutter", "build", "apk", "--release"]
            toolchain = self.toolchain_identity(command)
            record = {"schema_version": "2.0", "record_type": "baseline", "id": "before",
                "target_id": "target-before", "identity": {"command": command, "flutter_toolchain": toolchain,
                    "dependency_lock_sha256": "d" * 64,
                    "artifacts": {"build/app/outputs/flutter-apk/app-release.apk": {
                        "size": len(b"before-apk"), "sha256": hashlib.sha256(b"before-apk").hexdigest()}},
                    "build_snapshot": {"path": str(snapshot), "source_tree_sha256": "a" * 64,
                        "tree_sha256": "b" * 64, "file_scope_sha256": "c" * 64}},
                "evidence": [str(root / "build.json")]}
            records = store / "records"
            workflow.write_record(records, record)
            report = root / "rea-result.json"
            report.write_text(json.dumps({"record_type": "anti_rea_upstream_operation_result",
                "operation": "inspect_dart_aot", "status": "blocked",
                "artifact_sha256": hashlib.sha256(b"before-apk").hexdigest(),
                "error": {"category": "unsupported_target", "details": {"diagnostics": {"abi": "arm64-v8a"}}}}))
            runtime_manifest = {"schema_version": "1.0", "npm_version": "6.8.0",
                "npm_integrity": "sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==",
                "package_lock_sha256": "b6cb714948a7ec224fa6f676f0e9b6f570bbabf3518a1a187be571ac8ddfe232",
                "package_tree_sha256": "e" * 64, "node_version": "v24.22.1"}
            manifest = root / "anti-rea-rea-runtime.json"
            manifest.write_text(json.dumps(runtime_manifest))
            output = StringIO()
            with patch.object(flutter_android, "_verify_rea_runtime",
                              return_value=(manifest, manifest.read_bytes(), runtime_manifest)), redirect_stdout(output):
                status = anti_rea.main(["attach-flutter-aot", "--store", str(store), "--baseline-id", "before",
                    "--new-baseline-id", "before-aot", "--report", str(report), "--rea-runtime", str(root),
                    "--abi", "arm64-v8a"])
            self.assertEqual(status, 0, output.getvalue())
            result = json.loads(output.getvalue())
            self.assertEqual(result["aot_status"], "unsupported")
            attached = workflow.read_record(records / "baseline-before-aot.json", "baseline")
            self.assertEqual(attached["identity"]["flutter_aot_inspection"]["artifact_sha256"],
                             hashlib.sha256(b"before-apk").hexdigest())

    def test_android_sdk_failure_retains_diagnostic_without_baseline_record(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "app"
            (project / "android").mkdir(parents=True)
            (project / "pubspec.yaml").write_text("name: owned_fixture\n")
            store = base / "state"
            flutter = base / "flutter"
            flutter.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "print('Android SDK not found; install platform tools', file=sys.stderr)\n"
                "raise SystemExit(1)\n")
            flutter.chmod(0o700)
            output = StringIO()
            with patch.object(flutter_android.shutil, "which", return_value=str(flutter)), redirect_stdout(output):
                status = anti_rea.main(["flutter-android-baseline", str(project), "--store", str(store),
                                        "--id", "sdk-missing", "--target", "apk",
                                        "--obfuscate", "--split-debug-info", str(store / "symbols")])
            self.assertEqual(status, 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "failed")
            self.assertIn("exited 1", result["detail"])
            self.assertFalse((store / "records" / "baseline-sdk-missing.json").exists())
            evidence = json.loads((store / "evidence" / "baseline-sdk-missing.json").read_text())
            self.assertEqual(evidence["exit_code"], 1)
            self.assertIn("Android SDK not found", evidence["stderr"])


if __name__ == "__main__":
    unittest.main()
