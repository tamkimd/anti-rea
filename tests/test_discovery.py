import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import discovery, workflow


class DiscoveryTests(unittest.TestCase):
    def test_discovery_fails_closed_without_safe_open_primitives(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(discovery.os, "O_NOFOLLOW", 0):
                with self.assertRaisesRegex(
                    discovery.DiscoveryError, "no-follow directory-relative"
                ):
                    discovery.inspect_project(directory)
            with patch.object(discovery.os, "supports_dir_fd", set()):
                with self.assertRaisesRegex(
                    discovery.DiscoveryError, "no-follow directory-relative"
                ):
                    discovery.inspect_project(directory)

    def test_wasm_metadata_binds_imports_and_exports_to_artifact_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = (
                b"\x00asm\x01\x00\x00\x00"
                + b"\x02\x07\x01\x01m\x01f\x00\x00"
                + b"\x07\x05\x01\x01x\x00\x00"
            )
            (root / "service.wasm").write_bytes(module)
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            metadata = target["wasm_modules"][0]
            self.assertEqual(metadata["status"], "parsed")
            self.assertFalse(metadata["verified"])
            self.assertEqual(
                metadata["imports"], [{"module": "m", "name": "f", "kind": "function"}]
            )
            self.assertEqual(metadata["exports"], [{"name": "x", "kind": "function"}])
            self.assertEqual(metadata["sha256"], target["files"][0]["sha256"])
            if importlib.util.find_spec("jsonschema"):
                from jsonschema import Draft202012Validator

                schema = json.loads(
                    (
                        Path(__file__).parents[1] / "schemas/workflow-v2.schema.json"
                    ).read_text()
                )
                Draft202012Validator(schema["$defs"]["target"]).validate(target)
            corrupt = {**target, "wasm_modules": [{**metadata, "sha256": "0" * 64}]}
            with self.assertRaisesRegex(workflow.WorkflowError, "WebAssembly metadata"):
                workflow.validate_target(corrupt)

    @unittest.skipUnless(shutil.which("node"), "Node runtime unavailable")
    def test_wasm_scan_matches_node_compile_without_instantiating_module(self):
        module = (
            b"\x00asm\x01\x00\x00\x00"
            + b"\x01\x04\x01\x60\x00\x00"
            + b"\x02\x07\x01\x01m\x01f\x00\x00"
            + b"\x07\x05\x01\x01x\x00\x00"
        )
        imports, exports = discovery._parse_wasm_metadata(module)
        script = (
            "const fs=require('node:fs');try{"
            "const m=new WebAssembly.Module(fs.readFileSync(0));"
            "process.stdout.write(JSON.stringify({imports:WebAssembly.Module.imports(m),"
            "exports:WebAssembly.Module.exports(m)}));"
            "}catch{process.stdout.write('compile-rejected');process.exitCode=1}"
        )
        compiled = subprocess.run(
            [shutil.which("node"), "-e", script],
            input=module,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertLessEqual(len(compiled.stdout), 4096)
        self.assertLessEqual(len(compiled.stderr), 4096)
        self.assertEqual(
            compiled.returncode, 0, compiled.stderr.decode(errors="replace")
        )
        native = json.loads(compiled.stdout)
        self.assertEqual((native["imports"], native["exports"]), (imports, exports))

        malformed = b"\x00asm\x01\x00\x00\x00\x07\x7f\x00"
        with self.assertRaises(discovery.WasmMetadataError):
            discovery._parse_wasm_metadata(malformed)
        rejected = subprocess.run(
            [shutil.which("node"), "-e", script],
            input=malformed,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertLessEqual(len(rejected.stdout), 4096)
        self.assertLessEqual(len(rejected.stderr), 4096)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, b"compile-rejected")

    def test_wasm_malformed_sections_are_incomplete_not_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "broken.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00\x07\x7f\x00")
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            metadata = target["wasm_modules"][0]
            self.assertEqual(metadata["status"], "incomplete")
            self.assertIn("section length", metadata["reason"])
            self.assertTrue(target["wasm_metadata_scan_incomplete"])

    def test_wasm_standard_section_order_and_uniqueness(self):
        def section(section_id, payload):
            return bytes((section_id, len(payload))) + payload

        header = b"\x00asm\x01\x00\x00\x00"
        valid = (
            section(13, b"\x00")
            + section(6, b"\x00")
            + section(12, b"\x00")
            + section(0, b"\x00")
            + section(10, b"\x00")
            + section(11, b"\x00")
        )
        self.assertEqual(discovery._parse_wasm_metadata(header + valid), ([], []))
        for name, sections, reason in (
            ("out-of-order", section(7, b"\x00") + section(2, b"\x00"), "out of order"),
            ("duplicate", section(1, b"\x00") + section(1, b"\x00"), "duplicate"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(discovery.WasmMetadataError, reason):
                    discovery._parse_wasm_metadata(header + sections)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "broken.wasm").write_bytes(header + sections)
                    target = discovery.inspect_project(root)
                    workflow.validate_target(target)
                    metadata = target["wasm_modules"][0]
                    self.assertEqual(metadata["status"], "incomplete")
                    self.assertIn(reason, metadata["reason"])

    def test_wasm_metadata_per_file_and_vector_limits_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            large = root / "large.wasm"
            large.write_bytes(
                b"\x00asm\x01\x00\x00\x00"
                + b"\x00" * (discovery.MAX_WASM_METADATA_BYTES + 1)
            )
            limited = root / "limited.wasm"
            payload = b"\x81\x20"
            limited.write_bytes(
                b"\x00asm\x01\x00\x00\x00\x07" + bytes([len(payload)]) + payload
            )
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            by_path = {item["path"]: item for item in target["wasm_modules"]}
            self.assertEqual(by_path["large.wasm"]["status"], "incomplete")
            self.assertIn("per-file", by_path["large.wasm"]["reason"])
            self.assertEqual(by_path["limited.wasm"]["status"], "incomplete")
            self.assertIn("export count", by_path["limited.wasm"]["reason"])

    def test_inventory_recognizes_flutter_and_keeps_links_unfollowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pubspec.yaml").write_text(
                "name: sample\nflutter:\n  uses-material-design: true\n"
            )
            (root / "lib").mkdir()
            (root / "lib" / "main.dart").write_text("void main() {}\n")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "hidden.js").write_text("not inventoried")
            (root / "outside").mkdir()
            (root / "linked").symlink_to(root / "outside", target_is_directory=True)

            manifest = discovery.inspect_project(root)
            workflow.validate_target(manifest)
            self.assertEqual(manifest["components"][0]["runtimes"], ["flutter"])
            self.assertEqual(manifest["inventory"]["file_count"], 2)
            self.assertEqual(manifest["unfollowed_symlinks"], ["linked"])
            self.assertEqual(manifest["excluded"][0]["path"], "node_modules")

    def test_oversized_pubspec_keeps_dart_or_flutter_family_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pubspec = root / "pubspec.yaml"
            pubspec.write_text(
                "name: sample\n"
                + " " * discovery.MAX_MANIFEST_BYTES
                + "flutter:\n  uses-material-design: true\n"
            )

            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            self.assertEqual(target["components"][0]["runtimes"], ["dart_or_flutter"])
            self.assertTrue(
                any(
                    "exceeded the bounded content scan" in item
                    for item in target["unknowns"]
                )
            )

    def test_unknown_project_is_classified_and_inventory_hash_is_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.bin").write_bytes(b"opaque")
            first = discovery.inspect_project(root)
            second = discovery.inspect_project(root)
            self.assertEqual(first["components"][0]["kind"], "unknown")
            self.assertTrue(first["unknowns"])
            self.assertEqual(
                first["inventory"]["sha256"], second["inventory"]["sha256"]
            )

    def test_package_declarations_create_unverified_server_framework_hints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"next": "15.0.0"}})
            )
            api = root / "services" / "api"
            api.mkdir(parents=True)
            (api / "package.json").write_text(
                json.dumps(
                    {
                        "devDependencies": {"@sveltejs/kit": "2.0.0"},
                        "optionalDependencies": {"@remix-run/node": "2.0.0"},
                        "dependencies": {"unrelated": "1.0.0"},
                    }
                )
            )

            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            if importlib.util.find_spec("jsonschema"):
                from jsonschema import Draft202012Validator

                schema = json.loads(
                    (
                        Path(__file__).parents[1] / "schemas/workflow-v2.schema.json"
                    ).read_text()
                )
                Draft202012Validator(schema["$defs"]["target"]).validate(target)
            self.assertEqual(
                [
                    (
                        hint["manifest_path"],
                        hint["package_name"],
                        hint["declared_in"],
                        hint["component_id"],
                        hint["role"],
                        hint["verified"],
                    )
                    for hint in target["framework_hints"]
                ],
                [
                    (
                        "package.json",
                        "next",
                        ["dependencies"],
                        "root",
                        "ssr_framework_candidate",
                        False,
                    ),
                    (
                        "services/api/package.json",
                        "@remix-run/node",
                        ["optionalDependencies"],
                        "services-api",
                        "ssr_framework_candidate",
                        False,
                    ),
                    (
                        "services/api/package.json",
                        "@sveltejs/kit",
                        ["devDependencies"],
                        "services-api",
                        "ssr_framework_candidate",
                        False,
                    ),
                ],
            )
            self.assertFalse(target["framework_hint_scan_incomplete"])
            self.assertTrue(
                any(
                    "server output are unverified" in item
                    for item in target["unknowns"]
                )
            )
            corrupt = {
                **target,
                "framework_hints": [
                    {
                        **target["framework_hints"][0],
                        "manifest_path": "../outside/package.json",
                    }
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "framework hints"):
                workflow.validate_target(corrupt)
            corrupt = {
                **target,
                "framework_hints": [
                    {**target["framework_hints"][0], "declared_in": [{}]}
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "framework hints"):
                workflow.validate_target(corrupt)
            corrupt = {
                **target,
                "framework_hints": [
                    {
                        **target["framework_hints"][0],
                        "package_name": "unknown-framework",
                    }
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "framework hints"):
                workflow.validate_target(corrupt)
            corrupt = {
                **target,
                "framework_hints": [
                    {**target["framework_hints"][0], "package_name": {"bad": "value"}}
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "framework hints"):
                workflow.validate_target(corrupt)
            corrupt = {
                **target,
                "framework_hints": [
                    {**target["framework_hints"][0], "component_id": "services-api"}
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "framework hints"):
                workflow.validate_target(corrupt)
            corrupt = {**target, "manifests": [{"path": []}]}
            with self.assertRaisesRegex(workflow.WorkflowError, "framework hints"):
                workflow.validate_target(corrupt)

    def test_framework_hint_scan_marks_malformed_package_metadata_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text("{invalid json")
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            self.assertEqual(target["framework_hints"], [])
            self.assertTrue(target["framework_hint_scan_incomplete"])

    def test_framework_hint_scan_marks_oversized_package_metadata_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package.json"
            package.write_text(
                '{"dependencies":{"next":"15"}}' + " " * discovery.MAX_MANIFEST_BYTES
            )
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            self.assertEqual(target["framework_hints"], [])
            self.assertTrue(target["framework_hint_scan_incomplete"])

    def test_framework_hint_result_budget_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependencies = {name: "1" for name in discovery.SSR_FRAMEWORK_PACKAGES}
            for index in range(65):
                package = root / f"package-{index}" / "package.json"
                package.parent.mkdir()
                package.write_text(json.dumps({"dependencies": dependencies}))
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            self.assertEqual(
                len(target["framework_hints"]), discovery.MAX_FRAMEWORK_HINTS
            )
            self.assertTrue(target["framework_hint_scan_incomplete"])

    def test_worker_filename_hints_are_bound_and_remain_unverified_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"name":"web"}\n')
            (root / "public").mkdir()
            (root / "src").mkdir()
            (root / "public" / "service-worker.js").write_text(
                "self.addEventListener('fetch', () => {});\n"
            )
            (root / "src" / "math.worker.ts").write_text("self.onmessage = () => {};\n")
            (root / "src" / "register.js").write_text(
                "navigator.serviceWorker.register('../public/service-worker.js');\n"
                "new Worker(new URL('./math.worker.ts', import.meta.url));\n"
                "new Worker(new URL('./math.worker.ts', import.meta.url) + suffix);\n"
                "new Worker('./from-document.js');\n"
                "new Worker('./' + dynamicName);\n"
                "new Worker(workerPath);\n"
            )
            (root / "src" / "ordinary.js").write_text("console.log('ordinary');\n")

            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            if importlib.util.find_spec("jsonschema"):
                from jsonschema import Draft202012Validator

                schema = json.loads(
                    (
                        Path(__file__).parents[1] / "schemas/workflow-v2.schema.json"
                    ).read_text()
                )
                Draft202012Validator(schema["$defs"]["target"]).validate(target)
            self.assertEqual(
                target["entrypoint_hints"],
                [
                    {
                        "path": "public/service-worker.js",
                        "role": "service_worker_candidate",
                        "basis": "filename convention; registration and reachability not verified",
                        "component_id": "root",
                    },
                    {
                        "path": "src/math.worker.ts",
                        "role": "web_worker_candidate",
                        "basis": "filename convention; registration and reachability not verified",
                        "component_id": "root",
                    },
                ],
            )
            self.assertTrue(
                any(
                    "registration and reachability are unverified" in item
                    for item in target["unknowns"]
                )
            )
            references = [
                item
                for item in target["worker_references"]
                if item["source_path"] == "src/register.js"
            ]
            self.assertEqual(
                [
                    (
                        item["kind"],
                        item["reference"],
                        item["resolved_path"],
                        item["status"],
                    )
                    for item in references
                ],
                [
                    (
                        "service_worker_registration",
                        "../public/service-worker.js",
                        None,
                        "unresolved_base_url",
                    ),
                    (
                        "web_worker_constructor",
                        "./math.worker.ts",
                        "src/math.worker.ts",
                        "resolved_in_inventory",
                    ),
                    (
                        "web_worker_constructor",
                        "./from-document.js",
                        None,
                        "unresolved_base_url",
                    ),
                ],
            )
            self.assertTrue(
                any("computed references" in item for item in target["unknowns"])
            )
            corrupt = {
                **target,
                "entrypoint_hints": [
                    {**target["entrypoint_hints"][0], "path": "../outside.js"}
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "entrypoint hints"):
                workflow.validate_target(corrupt)
            corrupt_reference = {
                **target,
                "worker_references": [
                    {**references[1], "resolved_path": "../outside.js"}
                ],
            }
            with self.assertRaisesRegex(workflow.WorkflowError, "worker references"):
                workflow.validate_target(corrupt_reference)

    def test_worker_reference_result_count_is_bounded_and_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"name":"worker-fixture"}\n')
            (root / "main.js").write_text(
                'new Worker("worker.js");\n' * (discovery.MAX_WORKER_REFERENCES + 1)
            )
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            self.assertEqual(
                len(target["worker_references"]), discovery.MAX_WORKER_REFERENCES
            )
            self.assertTrue(target["worker_reference_scan_incomplete"])

    def test_computed_worker_references_stay_unknown_without_literal_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text(
                "navigator.serviceWorker.register(workerPath);\n"
                "new Worker(workerPath);\n"
                "new Worker('./' + workerName);\n"
                "new Worker(new URL('./worker.js', import.meta.url) + suffix);\n"
            )
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            self.assertEqual(target["worker_references"], [])
            self.assertTrue(
                any("computed references" in item for item in target["unknowns"])
            )

    def test_monorepo_artifacts_are_assigned_to_the_nearest_manifest_component(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            web = root / "packages" / "web"
            api = root / "packages" / "api"
            (web / "dist").mkdir(parents=True)
            (api / "out").mkdir(parents=True)
            (web / "package.json").write_text('{"name":"web"}\n')
            (api / "go.mod").write_text("module example/api\n")
            (web / "dist" / "app.js").write_text("console.log('web')\n")
            (api / "out" / "service.wasm").write_bytes(b"wasm")
            (root / "unowned.js").write_text("console.log('unknown')\n")

            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            by_id = {component["id"]: component for component in target["components"]}
            self.assertEqual(
                by_id["packages-web"]["artifacts"], ["packages/web/dist/app.js"]
            )
            self.assertEqual(
                by_id["packages-api"]["artifacts"], ["packages/api/out/service.wasm"]
            )
            self.assertEqual(target["unassigned_artifacts"], ["unowned.js"])
            self.assertTrue(any("unowned.js" in item for item in target["unknowns"]))
            corrupt = {**target, "unassigned_artifacts": []}
            with self.assertRaisesRegex(workflow.WorkflowError, "must partition"):
                workflow.validate_target(corrupt)
            corrupt = {**target, "unassigned_artifacts": ["../outside.js"]}
            with self.assertRaisesRegex(
                workflow.WorkflowError, "unique non-empty paths"
            ):
                workflow.validate_target(corrupt)

    def test_unknown_artifacts_and_sanitized_component_id_collisions_stay_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.js").write_text("unknown")
            target = discovery.inspect_project(root)
            self.assertEqual(target["components"][0]["artifacts"], [])
            self.assertEqual(target["unassigned_artifacts"], ["payload.js"])

            for component_root in (root / "foo-bar", root / "foo" / "bar"):
                component_root.mkdir(parents=True)
                (component_root / "package.json").write_text('{"name":"component"}\n')
                output = component_root / "dist" / "app.js"
                output.parent.mkdir()
                output.write_text("bundle")
            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            by_root = {
                component["root"]: component for component in target["components"]
            }
            self.assertEqual(
                len({component["id"] for component in target["components"]}), 2
            )
            self.assertEqual(by_root["foo-bar"]["artifacts"], ["foo-bar/dist/app.js"])
            self.assertEqual(by_root["foo/bar"]["artifacts"], ["foo/bar/dist/app.js"])

    def test_root_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual"
            actual.mkdir()
            link = root / "link"
            link.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(discovery.DiscoveryError, "root symlink"):
                discovery.inspect_project(link)

    def test_apple_bundle_directories_are_explicit_artifacts_without_following_links(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "Demo.app"
            contents = app / "Contents" / "MacOS"
            contents.mkdir(parents=True)
            (contents / "Demo").write_bytes(b"binary-v1")
            external = root / "outside"
            external.write_text("secret-v1")
            (app / "Contents" / "Resources").mkdir()
            (app / "Contents" / "Resources" / "external-link").symlink_to(external)
            framework = app / "Contents" / "Frameworks" / "Demo.framework"
            framework.mkdir(parents=True)
            (framework / "Info.plist").write_text("framework")

            target = discovery.inspect_project(root)
            workflow.validate_target(target)
            self.assertIn("Demo.app", target["artifacts"])
            self.assertIn(
                "Demo.app/Contents/Frameworks/Demo.framework", target["artifacts"]
            )
            self.assertIn(
                "Demo.app/Contents/Resources/external-link",
                target["unfollowed_symlinks"],
            )
            self.assertTrue(
                any(
                    "Symlinks were observed" in unknown
                    for unknown in target["unknowns"]
                )
            )


if __name__ == "__main__":
    unittest.main()
