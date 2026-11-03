import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core import registry, workflow
from interfaces.cli import anti_rea


class EngineRegistryTests(unittest.TestCase):
    def test_registry_lists_only_implemented_adapters_and_locked_identity(self):
        record = registry.get_registry()
        self.assertEqual(record["record_type"], "engine_registry")
        entries = {engine["id"]: engine for engine in record["engines"]}
        self.assertEqual(set(entries), {"bla", "rea", "e2e", "source-map-candidate",
                                        "flutter-android-build", "wasm-compile-probe"})
        self.assertEqual(entries["bla"]["packages"]["bla-agents"]["version"], "1.6.3")
        self.assertEqual(entries["bla"]["operations"]["execute"]["status"], "partial")
        self.assertEqual(entries["rea"]["operations"]["plan"]["status"], "unavailable")
        self.assertEqual(entries["e2e"]["supported_artifacts"], ["Owned fixture-compatible local web projects"])
        self.assertIn("served release", " ".join(entries["source-map-candidate"]["limitations"]))
        self.assertEqual(entries["flutter-android-build"]["operations"]["probe"]["status"], "partial")
        self.assertIn("licenses", " ".join(entries["flutter-android-build"]["limitations"]))
        self.assertEqual(entries["wasm-compile-probe"]["operations"]["execute"]["status"], "unavailable")
        self.assertIn("host bindings", " ".join(entries["wasm-compile-probe"]["limitations"]))
        for entry in (entries["bla"], entries["rea"], entries["e2e"]):
            self.assertEqual(set(entry["operations"]), set(registry._OPERATIONS))
            self.assertIn("Source/package equivalence is not verified.", entry["limitations"])

    def test_registry_rejects_missing_or_unpinned_package_locks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "locks").mkdir()
            (root / "integrations/bla").mkdir(parents=True)
            lock = root / "locks/upstreams.json"
            source = json.loads((Path(__file__).parents[1] / "locks/upstreams.json").read_text())
            lock.write_text(json.dumps(source))
            with patch.object(registry, "_lock_root", return_value=root):
                with self.assertRaisesRegex(workflow.WorkflowError, "identity is invalid"):
                    registry.get_registry()

    def test_registry_rejects_in_root_package_lock_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "locks").mkdir()
            source = json.loads((Path(__file__).parents[1] / "locks/upstreams.json").read_text())
            for engine, pin in source["integrations"].items():
                if engine not in {"bla", "rea", "e2e"}:
                    continue
                package_lock = root / pin["package_lock"]
                package_lock.parent.mkdir(parents=True, exist_ok=True)
                raw = f"test lock {engine}".encode()
                pin["package_lock_sha256"] = hashlib.sha256(raw).hexdigest()
                if engine == "bla":
                    target = package_lock.with_name("matching-lock.json")
                    target.write_bytes(raw)
                    package_lock.symlink_to(target.name)
                else:
                    package_lock.write_bytes(raw)
            (root / "locks/upstreams.json").write_text(json.dumps(source))
            with patch.object(registry, "_lock_root", return_value=root):
                with self.assertRaisesRegex(workflow.WorkflowError, "identity is invalid for bla"):
                    registry.get_registry()

    def test_registry_rejects_symlinked_upstream_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            locks = root / "locks"
            locks.mkdir()
            target = locks / "pinned.json"
            target.write_text((Path(__file__).parents[1] / "locks/upstreams.json").read_text())
            (locks / "upstreams.json").symlink_to(target.name)
            with patch.object(registry, "_lock_root", return_value=root):
                with self.assertRaisesRegex(workflow.WorkflowError, "manifest must be a regular file"):
                    registry.get_registry()

    def test_registry_rejects_symlinked_locks_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external"
            external.mkdir()
            (external / "upstreams.json").write_text(
                (Path(__file__).parents[1] / "locks/upstreams.json").read_text())
            (root / "locks").symlink_to(external, target_is_directory=True)
            with patch.object(registry, "_lock_root", return_value=root):
                with self.assertRaisesRegex(workflow.WorkflowError, "manifest must be a regular file"):
                    registry.get_registry()

    def test_cli_registry_is_machine_readable(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["registry"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue()), registry.get_registry())

    def test_registry_validator_rejects_missing_operations_and_duplicate_ids(self):
        record = registry.get_registry()
        record["engines"][0]["operations"].pop("cleanup")
        with self.assertRaisesRegex(workflow.WorkflowError, "incomplete or invalid"):
            registry.validate_registry(record)
        record = registry.get_registry()
        record["engines"][1]["id"] = record["engines"][0]["id"]
        with self.assertRaisesRegex(workflow.WorkflowError, "incomplete or invalid"):
            registry.validate_registry(record)


if __name__ == "__main__":
    unittest.main()
