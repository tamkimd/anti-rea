import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import dependencies, workflow


class FakeAdapter:
    def __init__(self):
        self.bootstraps = 0
        self.npm = "11.6.2"

    def node_version(self):
        return "v24.22.1", (24, 22, 1)

    def npm_version(self):
        return self.npm

    @staticmethod
    def supported_node(parts):
        return parts[0] == 24 and parts >= (24, 22, 1)

    def bootstrap(self, runtime):
        self.bootstraps += 1
        runtime.mkdir(mode=0o700)
        (runtime / "identity.json").write_text(
            json.dumps(
                {
                    "node_version": "v24.22.1",
                    "npm_version_runtime": self.npm,
                    "package_lock_sha256": "pinned",
                    "package_tree_sha256": "tree",
                }
            )
        )

    @staticmethod
    def verify_runtime(runtime):
        marker = json.loads((Path(runtime) / "identity.json").read_text())
        if (
            marker.get("package_lock_sha256") != "pinned"
            or marker.get("package_tree_sha256") != "tree"
        ):
            raise ValueError("runtime drift")
        return Path(runtime), marker


class DependencyManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.project = base / "project"
        self.project.mkdir()
        (self.project / "package.json").write_text('{"name":"untouched"}')
        self.global_dir = base / "global"
        self.global_dir.mkdir()
        (self.global_dir / "marker").write_text("untouched")
        self.cache = base / "cache"
        self.adapter = FakeAdapter()
        self.node = patch("core.dependencies._node_identity", return_value="v24.22.1")
        self.env = patch.dict(os.environ, {}, clear=True)
        self.node.start()
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.node.stop()
        self.temp.cleanup()

    def test_prepare_then_reuse_exact_private_cache_without_project_or_global_writes(
        self,
    ):
        first = dependencies.prepare("bla", self.project, self.cache, self.adapter)
        second = dependencies.prepare("bla", self.project, self.cache, self.adapter)
        self.assertEqual((first["status"], second["status"]), ("prepared", "reused"))
        self.assertEqual(self.adapter.bootstraps, 1)
        self.assertEqual(first["license"], "MIT")
        self.assertTrue(Path(first["runtime"]).is_relative_to(self.cache.resolve()))
        self.assertEqual(
            (self.project / "package.json").read_text(), '{"name":"untouched"}'
        )
        self.assertEqual((self.global_dir / "marker").read_text(), "untouched")
        if os.name != "nt":
            self.assertEqual(
                Path(first["runtime"]).parent.parent.stat().st_mode & 0o777, 0o700
            )

    def test_cache_identity_uses_npm_from_the_adapter_environment(self):
        with patch(
            "core.dependencies.subprocess.run",
            side_effect=AssertionError("host npm must not be probed"),
        ):
            result = dependencies.prepare("bla", self.project, self.cache, self.adapter)
        self.assertEqual(result["npm_version"], "11.6.2")

    def test_adapter_npm_versions_use_distinct_cache_entries(self):
        first = dependencies.prepare("bla", self.project, self.cache, self.adapter)
        self.adapter.npm = "11.7.0"
        second = dependencies.prepare("bla", self.project, self.cache, self.adapter)
        self.assertEqual(
            (first["npm_version"], second["npm_version"]), ("11.6.2", "11.7.0")
        )
        self.assertNotEqual(first["runtime"], second["runtime"])
        self.assertEqual((first["status"], second["status"]), ("prepared", "prepared"))
        self.assertEqual(self.adapter.bootstraps, 2)

    def test_cached_runtime_must_match_the_selected_adapter_npm_version(self):
        result = dependencies.prepare("bla", self.project, self.cache, self.adapter)
        marker = Path(result["runtime"]) / "identity.json"
        value = json.loads(marker.read_text())
        value["npm_version_runtime"] = "10.0.0"
        marker.write_text(json.dumps(value))
        with self.assertRaisesRegex(workflow.WorkflowError, "different npm version"):
            dependencies.prepare("bla", self.project, self.cache, self.adapter)

    def test_cached_lock_or_tree_drift_fails_closed_without_reinstall(self):
        result = dependencies.prepare("bla", self.project, self.cache, self.adapter)
        marker = Path(result["runtime"]) / "identity.json"
        marker.write_text(
            '{"node_version":"v24.22.1","package_lock_sha256":"changed","package_tree_sha256":"tree"}'
        )
        with self.assertRaisesRegex(
            workflow.WorkflowError, "runtime verification failed: runtime drift"
        ):
            dependencies.prepare("bla", self.project, self.cache, self.adapter)
        self.assertEqual(self.adapter.bootstraps, 1)
        self.assertIn("changed", marker.read_text())

    def test_offline_miss_does_not_create_cache_and_project_nested_cache_is_refused(
        self,
    ):
        with self.assertRaisesRegex(
            workflow.WorkflowError, "Offline dependency cache miss"
        ):
            dependencies.prepare(
                "rea", self.project, self.cache, self.adapter, offline=True
            )
        self.assertFalse(self.cache.exists())
        with self.assertRaisesRegex(workflow.WorkflowError, "outside the project"):
            dependencies.prepare(
                "rea", self.project, self.project / ".anti-rea-cache", self.adapter
            )
        self.assertEqual(self.adapter.bootstraps, 0)

    def test_explicit_runtime_is_verified_without_npm_or_cache_writes(self):
        supplied = self.global_dir / "prepared-rea"
        self.adapter.bootstrap(supplied)
        with patch(
            "core.dependencies.subprocess.run",
            side_effect=AssertionError("npm must not run"),
        ):
            result = dependencies.prepare(
                "rea", self.project, None, self.adapter, runtime=supplied, offline=True
            )
        self.assertEqual((result["status"], result["source"]), ("verified", "explicit"))
        self.assertEqual(result["npm_version"], "11.6.2")
        self.assertFalse(self.cache.exists())

    def test_legacy_bla_manifest_does_not_misreport_package_version_as_npm(self):
        supplied = self.global_dir / "legacy-bla"
        self.adapter.bootstrap(supplied)
        marker = supplied / "identity.json"
        identity = json.loads(marker.read_text())
        identity.pop("npm_version_runtime")
        identity["npm_version"] = "0.1.32"
        marker.write_text(json.dumps(identity))
        result = dependencies.prepare(
            "bla", self.project, None, self.adapter, runtime=supplied, offline=True
        )
        self.assertIsNone(result["npm_version"])

    def test_e2e_package_inventory_is_not_reported_as_a_tree_hash(self):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["e2e"]
        result = dependencies._result(
            "e2e",
            pin,
            self.project,
            {"packages": {"package": "version"}},
            "v24.22.1",
            "11.6.2",
            "reused",
            "cache",
        )
        self.assertEqual(
            result["packages"],
            {
                "e2e": dependencies.json.loads(
                    (dependencies.ROOT / "locks/upstreams.json").read_text()
                )["integrations"]["e2e"]["packages"]
            },
        )
        self.assertIsNone(result["package_tree_sha256"])

    def test_project_pinned_dependencies_are_detected_but_not_trusted_for_reuse(self):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["bla"]
        identity = {"version": pin["npm_version"], "integrity": pin["npm_integrity"]}
        (self.project / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"": {}, "node_modules/bla-agents": identity},
                }
            )
        )
        package = self.project / "node_modules/bla-agents"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "bla-agents", "version": pin["npm_version"]})
        )
        with patch(
            "core.dependencies.subprocess.run",
            side_effect=AssertionError("discovery must not execute tools"),
        ):
            report = dependencies.inspect_project_dependencies("bla", self.project)
        self.assertEqual(report["status"], "inspected")
        report = report["project_dependencies"]
        self.assertEqual(report["status"], "pinned_metadata_match")
        self.assertTrue(report["lockfile_matches_pin"])
        self.assertTrue(
            report["packages"]["bla-agents"]["installed_version_matches_pin"]
        )
        self.assertFalse(report["reusable"])
        self.assertTrue((package / "package.json").is_file())

    def test_package_manager_selects_its_lockfile_and_undeclared_conflicts_are_unavailable(
        self,
    ):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["bla"]
        package = self.project / "node_modules/bla-agents"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "bla-agents", "version": pin["npm_version"]})
        )
        (self.project / "package.json").write_text(
            json.dumps(
                {
                    "packageManager": "pnpm@9.12.0",
                    "dependencies": {"bla-agents": f"^{pin['npm_version']}"},
                }
            )
        )
        (self.project / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/bla-agents": {
                            "version": pin["npm_version"],
                            "integrity": "sha512-wrong",
                        }
                    },
                }
            )
        )
        (self.project / "pnpm-lock.yaml").write_text(
            f"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      bla-agents:\n        specifier: ^{pin['npm_version']}\n        version: {pin['npm_version']}\npackages:\n"
            f"  bla-agents@{pin['npm_version']}:\n    resolution: {{integrity: {pin['npm_integrity']}}}\n"
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(
            (report["status"], report["lockfile"], report["lockfile_manager"]),
            ("pinned_metadata_match", "pnpm-lock.yaml", "pnpm"),
        )
        (self.project / "package.json").write_text(
            json.dumps({"dependencies": {"bla-agents": f"^{pin['npm_version']}"}})
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(report["status"], "unavailable")
        self.assertIsNone(report["lockfile"])

    def test_cli_inspect_only_returns_project_matches_without_runtime_or_cache(self):
        from interfaces.cli import anti_rea

        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["bla"]
        (self.project / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/bla-agents": {
                            "version": pin["npm_version"],
                            "integrity": "sha512-mismatch",
                        }
                    },
                }
            )
        )
        installed = self.project / "node_modules/bla-agents"
        installed.mkdir(parents=True)
        (installed / "package.json").write_text(
            json.dumps({"name": "bla-agents", "version": pin["npm_version"]})
        )
        with (
            patch("interfaces.cli.anti_rea.emit") as emit,
            patch(
                "core.dependencies.subprocess.run",
                side_effect=AssertionError("inspection must not execute tools"),
            ),
        ):
            self.assertEqual(
                anti_rea.main(
                    [
                        "prepare-dependency",
                        "bla",
                        "--project-root",
                        str(self.project),
                        "--inspect-only",
                    ]
                ),
                0,
            )
        report = emit.call_args.args[0]
        self.assertEqual(report["project_dependencies"]["status"], "mismatch")
        self.assertFalse(self.cache.exists())

    def test_project_tool_discovery_handles_npm_v1_and_marks_unsupported_yarn_pnpm_unverified(
        self,
    ):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["bla"]
        package = self.project / "node_modules/bla-agents"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "bla-agents", "version": pin["npm_version"]})
        )
        (self.project / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "bla-agents": {
                            "version": pin["npm_version"],
                            "integrity": pin["npm_integrity"],
                        }
                    },
                }
            )
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(report["status"], "pinned_metadata_match")
        self.assertTrue(report["lockfile_matches_pin"])
        (self.project / "package-lock.json").unlink()
        for filename, manager, contents in (
            ("yarn.lock", "yarn", "__metadata:\n  version: 6\n"),
            ("pnpm-lock.yaml", "pnpm", "lockfileVersion: '6.0'\npackages: {}\n"),
        ):
            (self.project / filename).write_text(contents)
            report = dependencies.inspect_project_dependencies("bla", self.project)[
                "project_dependencies"
            ]
            self.assertEqual(
                (report["status"], report["lockfile_manager"]),
                ("installed_unverified", manager),
            )
            self.assertIsNone(report["lockfile_matches_pin"])
            (self.project / filename).unlink()

    def test_yarn_classic_direct_lock_identity_requires_unique_version_and_integrity(
        self,
    ):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["bla"]
        package = self.project / "node_modules/bla-agents"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "bla-agents", "version": pin["npm_version"]})
        )
        (self.project / "package.json").write_text(
            json.dumps({"dependencies": {"bla-agents": f"^{pin['npm_version']}"}})
        )
        (self.project / "yarn.lock").write_text(
            f'"bla-agents@^{pin["npm_version"]}":\n  version "{pin["npm_version"]}"\n'
            f'  resolved "https://registry.npmjs.org/bla-agents/-/bla-agents-{pin["npm_version"]}.tgz"\n'
            f"  integrity {pin['npm_integrity']}\n"
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(report["status"], "pinned_metadata_match")
        self.assertTrue(report["lockfile_matches_pin"])
        (self.project / "yarn.lock").write_text(
            f'"bla-agents@^{pin["npm_version"]}":\n  version "{pin["npm_version"]}"\n'
            f"  integrity sha512-wrong\n"
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(report["status"], "mismatch")
        self.assertFalse(report["lockfile_matches_pin"])

    def test_yarn_classic_headerless_unquoted_selector_is_parsed(self):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["bla"]
        package = self.project / "node_modules/bla-agents"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "bla-agents", "version": pin["npm_version"]})
        )
        (self.project / "yarn.lock").write_text(
            f'bla-agents@^{pin["npm_version"]}:\n  version "{pin["npm_version"]}"\n'
            f"  integrity {pin['npm_integrity']}\n"
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(report["status"], "pinned_metadata_match")
        self.assertTrue(report["lockfile_matches_pin"])

    def test_pnpm_v9_direct_lock_identity_and_unsupported_version(self):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["bla"]
        package = self.project / "node_modules/bla-agents"
        package.mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "bla-agents", "version": pin["npm_version"]})
        )
        (self.project / "package.json").write_text(
            json.dumps({"dependencies": {"bla-agents": f"^{pin['npm_version']}"}})
        )
        (self.project / "pnpm-lock.yaml").write_text(
            f"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      bla-agents:\n        specifier: ^{pin['npm_version']}\n        version: {pin['npm_version']}\npackages:\n"
            f"  bla-agents@{pin['npm_version']}:\n    resolution: {{integrity: {pin['npm_integrity']}}}\n"
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(report["status"], "pinned_metadata_match")
        self.assertTrue(report["lockfile_matches_pin"])
        (self.project / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '6.0'\npackages: {}\n"
        )
        report = dependencies.inspect_project_dependencies("bla", self.project)[
            "project_dependencies"
        ]
        self.assertEqual(report["status"], "installed_unverified")
        self.assertIsNone(report["lockfile_matches_pin"])

    def test_project_dependency_discovery_reports_partial_install_and_refuses_symlinked_files(
        self,
    ):
        pin = dependencies.json.loads(
            (dependencies.ROOT / "locks/upstreams.json").read_text()
        )["integrations"]["e2e"]
        packages = pin["packages"]
        lock_packages = {"": {}}
        for name, identity in packages.items():
            lock_packages[f"node_modules/{name}"] = identity
        (self.project / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3, "packages": lock_packages})
        )
        first = next(iter(packages.items()))
        installed = self.project / "node_modules" / first[0]
        installed.mkdir(parents=True)
        (installed / "package.json").write_text(
            json.dumps({"name": first[0], "version": first[1]["version"]})
        )
        report = dependencies._project_dependency_report("e2e", self.project, pin)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["reusable"])
        self.assertEqual(
            sum(item["installed"] for item in report["packages"].values()), 1
        )
        (self.project / "package-lock.json").unlink()
        outside = Path(self.temp.name) / "outside-lock.json"
        outside.write_text(
            json.dumps({"lockfileVersion": 3, "packages": lock_packages})
        )
        (self.project / "package-lock.json").symlink_to(outside)
        report = dependencies._project_dependency_report("e2e", self.project, pin)
        self.assertEqual(report["status"], "unavailable")

    def test_packaged_upstream_lock_path_is_used_when_source_tree_is_absent(self):
        packaged = Path(self.temp.name) / "share/anti-rea/locks/upstreams.json"
        packaged.parent.mkdir(parents=True)
        packaged.write_text("{}")
        with (
            patch("core.dependencies.ROOT", Path(self.temp.name) / "source"),
            patch("core.dependencies.sysconfig.get_path", return_value=self.temp.name),
        ):
            self.assertEqual(dependencies._upstreams_path(), packaged)

    def test_inspect_python_dependencies_reports_hashed_pep751_wheels_without_writes(
        self,
    ):
        lock = self.project / "pylock.toml"
        lock.write_text(
            """lock-version = "1.0"\ncreated-by = "fixture"\nrequires-python = ">=3.11"\n\n[[packages]]\nname = "example-package"\nversion = "1.2.3"\n\n[[packages.wheels]]\nname = "example_package-1.2.3-py3-none-any.whl"\nurl = "https://example.invalid/example.whl"\n\n[packages.wheels.hashes]\nsha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n"""
        )
        before = {path.name: path.read_bytes() for path in self.project.iterdir()}
        result = dependencies.inspect_python_dependencies(self.project)
        self.assertEqual(result["status"], "inspected")
        self.assertEqual(result["lock_version"], "1.0")
        self.assertEqual(result["packages"][0]["name"], "example-package")
        self.assertEqual(result["packages"][0]["sources"][0]["sha256"], "a" * 64)
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.project.iterdir()}, before
        )

    def test_checked_in_python_lock_has_wheels_for_each_declared_platform(self):
        lock = dependencies.tomllib.loads(
            (dependencies.ROOT / "locks/pylock.toml").read_text()
        )
        packages = {item["name"]: item for item in lock["packages"]}
        tags = {
            "cffi": {
                "macosx_11_0_arm64",
                "manylinux_2_17_x86_64",
                "manylinux_2_17_aarch64",
                "win_amd64",
            },
            "cryptography": {
                "macosx_11_0_arm64",
                "manylinux_2_28_x86_64",
                "manylinux_2_28_aarch64",
                "win_amd64",
            },
            "pydantic-core": {
                "macosx_11_0_arm64",
                "manylinux_2_17_x86_64",
                "manylinux_2_17_aarch64",
                "win_amd64",
            },
            "rpds-py": {
                "macosx_11_0_arm64",
                "manylinux_2_17_x86_64",
                "manylinux_2_17_aarch64",
                "win_amd64",
            },
        }
        for name, platforms in tags.items():
            filenames = [wheel["name"] for wheel in packages[name]["wheels"]]
            self.assertTrue(
                all(
                    any(platform in filename for filename in filenames)
                    for platform in platforms
                ),
                name,
            )
            self.assertTrue(
                all(
                    dependencies.re.fullmatch(
                        r"[a-f0-9]{64}", wheel["hashes"]["sha256"]
                    )
                    for wheel in packages[name]["wheels"]
                ),
                name,
            )

    def test_inspect_python_dependencies_fails_closed_on_ambiguous_locks(
        self,
    ):
        (self.project / "pylock.toml").write_text(
            'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="a"\n'
        )
        (self.project / "pylock.test.toml").write_text(
            'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="b"\n'
        )
        self.assertEqual(
            dependencies.inspect_python_dependencies(self.project)["status"],
            "unavailable",
        )

    def test_prepare_python_lock_installs_complete_hashed_wheel_set_and_reuses_offline(
        self,
    ):
        import hashlib
        import zipfile

        packages = []
        marker = Path(self.temp.name) / "pth-executed"
        for name, version in (("alpha", "1.0"), ("beta", "2.0")):
            wheel = self.project / f"{name}-{version}-py3-none-any.whl"
            dist = f"{name}-{version}.dist-info"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    dist + "/WHEEL",
                    "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                )
                archive.writestr(
                    dist + "/METADATA",
                    f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
                )
                archive.writestr(dist + "/RECORD", "")
                if name == "alpha":
                    archive.writestr(
                        "alpha.pth",
                        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')\n",
                    )
            sources = [
                (wheel.name, wheel.name, hashlib.sha256(wheel.read_bytes()).hexdigest())
            ]
            if name == "alpha":
                platform_wheel = self.project / "alpha-1.0-cp311-cp311-win_amd64.whl"
                with zipfile.ZipFile(platform_wheel, "w") as archive:
                    archive.writestr(
                        dist + "/WHEEL",
                        "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: cp311-cp311-win_amd64\n",
                    )
                    archive.writestr(
                        dist + "/METADATA",
                        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
                    )
                    archive.writestr(dist + "/RECORD", "")
                sources.append(
                    (
                        platform_wheel.name,
                        platform_wheel.name,
                        hashlib.sha256(platform_wheel.read_bytes()).hexdigest(),
                    )
                )
            packages.append((name, version, sources))
        lock = ['lock-version = "1.0"', 'created-by = "test"']
        for name, version, sources in packages:
            lock.extend(
                ["", "[[packages]]", f'name = "{name}"', f'version = "{version}"']
            )
            for filename, wheel_path, digest in sources:
                lock.extend(
                    [
                        "",
                        "[[packages.wheels]]",
                        f'name = "{filename}"',
                        f'path = "{wheel_path}"',
                        "",
                        "[packages.wheels.hashes]",
                        f'sha256 = "{digest}"',
                    ]
                )
        (self.project / "pylock.toml").write_text("\n".join(lock) + "\n")
        result = dependencies.prepare_python_dependencies(self.project, self.cache)
        self.assertEqual(result["status"], "prepared")
        self.assertTrue(
            (
                Path(result["runtime"])
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages"
                / "alpha-1.0.dist-info"
            ).exists()
        )
        self.assertFalse(marker.exists())
        reused = dependencies.prepare_python_dependencies(
            self.project, self.cache, offline=True
        )
        self.assertEqual(reused["status"], "reused")
        self.assertEqual(reused["site_packages_sha256"], result["site_packages_sha256"])
        cfg = Path(result["runtime"]) / "pyvenv.cfg"
        cfg.write_text(cfg.read_text() + "tampered = true\n")
        with self.assertRaisesRegex(
            workflow.WorkflowError, "environment files changed"
        ):
            dependencies.prepare_python_dependencies(
                self.project, self.cache, offline=True
            )

    def test_python_cache_rejects_symlinked_parent_that_resolves_into_project(self):
        (self.project / "pylock.toml").write_text(
            'lock-version="1.0"\ncreated-by="fixture"\npackages=[]\n'
        )
        link = Path(self.temp.name) / "project-link"
        link.symlink_to(self.project, target_is_directory=True)
        with self.assertRaisesRegex(workflow.WorkflowError, "outside the project"):
            dependencies.prepare_python_dependencies(self.project, link / "cache")
        self.assertFalse((self.project / "cache").exists())

    def test_prepare_python_lock_rejects_tampered_hash_and_markers(self):
        lock = self.project / "pylock.toml"
        lock.write_text(
            """lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="x"\nversion="1.0"\nmarker="python_version > 3"\n[[packages.wheels]]\nname="x-1.0-py3-none-any.whl"\nurl="https://example.invalid/x.whl"\n[packages.wheels.hashes]\nsha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n"""
        )
        with self.assertRaisesRegex(workflow.WorkflowError, "unconditional wheel"):
            dependencies.prepare_python_dependencies(self.project, self.cache)
        lock.write_text(lock.read_text().replace('marker="python_version > 3"\n', ""))
        with self.assertRaises(workflow.WorkflowError):
            dependencies.prepare_python_dependencies(self.project, self.cache)

    def test_inspect_python_dependencies_fails_closed_on_ambiguous_or_unsupported_locks(
        self,
    ):
        (self.project / "pylock.toml").write_text(
            'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="a"\n'
        )
        (self.project / "pylock.test.toml").write_text(
            'lock-version="1.0"\ncreated-by="fixture"\n[[packages]]\nname="b"\n'
        )
        self.assertEqual(
            dependencies.inspect_python_dependencies(self.project)["status"],
            "unavailable",
        )
        (self.project / "pylock.test.toml").unlink()
        (self.project / "pylock.toml").write_text(
            'lock-version="2.0"\ncreated-by="fixture"\npackages=[]\n'
        )
        self.assertEqual(
            dependencies.inspect_python_dependencies(self.project)["status"],
            "unavailable",
        )

    def test_cli_inspects_python_lock_without_preparing_dependencies(self):
        (self.project / "pylock.toml").write_text(
            """lock-version = "1.0"\ncreated-by = "fixture"\n\n[[packages]]\nname = "example-package"\nversion = "1.2.3"\n\n[[packages.wheels]]\nname = "example_package-1.2.3-py3-none-any.whl"\n\n[packages.wheels.hashes]\nsha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n"""
        )
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "inspect-python-dependencies",
                str(self.project),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "inspected")

    def test_cli_prepares_python_dependency_lock(self):
        (self.project / "pylock.toml").write_text(
            'lock-version="1.0"\ncreated-by="fixture"\npackages=[]\n'
        )
        cli = Path(__file__).parents[1] / "interfaces/cli/anti_rea.py"
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "prepare-python-dependencies",
                str(self.project),
                "--cache-dir",
                str(self.cache),
                "--offline",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "Offline Python dependency cache miss", json.loads(result.stdout)["detail"]
        )


if __name__ == "__main__":
    unittest.main()
