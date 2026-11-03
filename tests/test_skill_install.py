import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from interfaces.cli import skill_install


class SkillInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        (self.source / "references").mkdir(parents=True)
        (self.source / "SKILL.md").write_text("skill v1\n")
        (self.source / "references" / "workflow.md").write_text("workflow v1\n")
        self.destination = self.root / "installed" / "anti-rea"
        self.destination.parent.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_preview_install_update_and_uninstall_are_manifest_bound(self):
        install_plan = skill_install.plan("install", self.destination, self.source)
        paths = {item["path"] for item in install_plan["changes"]}
        self.assertEqual(paths, {"SKILL.md", "references/workflow.md", skill_install.MANIFEST})
        self.assertFalse(self.destination.exists())
        skill_install.execute("install", self.destination, self.source, expected_plan=install_plan)
        self.assertEqual((self.destination / "SKILL.md").read_text(), "skill v1\n")

        (self.source / "SKILL.md").write_text("skill v2\n")
        (self.source / "references" / "acceptance.md").write_text("acceptance\n")
        update_plan = skill_install.plan("update", self.destination, self.source)
        changes = {(item["action"], item["path"]) for item in update_plan["changes"]}
        self.assertIn(("replace", "SKILL.md"), changes)
        self.assertIn(("create", "references/acceptance.md"), changes)
        skill_install.execute("update", self.destination, self.source, expected_plan=update_plan)
        self.assertEqual((self.destination / "SKILL.md").read_text(), "skill v2\n")

        uninstall_plan = skill_install.plan("uninstall", self.destination)
        self.assertIn(("delete", "SKILL.md"), {(item["action"], item["path"])
                                                for item in uninstall_plan["changes"]})
        skill_install.execute("uninstall", self.destination, expected_plan=uninstall_plan)
        self.assertFalse(self.destination.exists())

    def test_install_refuses_existing_destination_and_update_refuses_modified_files(self):
        self.destination.mkdir()
        (self.destination / "user-file").write_text("keep")
        with self.assertRaisesRegex(skill_install.SkillInstallError, "existing destination"):
            skill_install.plan("install", self.destination, self.source)
        self.assertEqual((self.destination / "user-file").read_text(), "keep")
        (self.destination / "user-file").unlink()
        self.destination.rmdir()
        skill_install.execute("install", self.destination, self.source)
        (self.destination / "SKILL.md").write_text("user edit")
        for operation in ("update", "uninstall"):
            with self.assertRaisesRegex(skill_install.SkillInstallError, "modified"):
                skill_install.plan(operation, self.destination, self.source if operation == "update" else None)
        self.assertEqual((self.destination / "SKILL.md").read_text(), "user edit")

    def test_update_rejects_extra_files_and_uninstall_rejects_empty_extra_directories(self):
        skill_install.execute("install", self.destination, self.source)
        (self.destination / "user-file").write_text("keep")
        with self.assertRaisesRegex(skill_install.SkillInstallError, "unowned"):
            skill_install.plan("update", self.destination, self.source)
        (self.destination / "user-file").unlink()
        (self.destination / "empty-user-directory").mkdir()
        with self.assertRaisesRegex(skill_install.SkillInstallError, "unowned"):
            skill_install.plan("uninstall", self.destination)
        self.assertTrue((self.destination / "empty-user-directory").is_dir())

    def test_refuses_symlinks_and_manifest_path_traversal(self):
        skill_install.execute("install", self.destination, self.source)
        (self.destination / "references" / "linked.md").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(skill_install.SkillInstallError, "symlink"):
            skill_install.plan("uninstall", self.destination)
        (self.destination / "references" / "linked.md").unlink()
        marker = self.destination / skill_install.MANIFEST
        manifest = json.loads(marker.read_text())
        manifest["files"][0]["path"] = "../outside"
        marker.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(skill_install.SkillInstallError, "unsafe relative path"):
            skill_install.plan("uninstall", self.destination)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_source_reader_rejects_fifo_without_blocking(self):
        source_file = self.source / "SKILL.md"
        source_file.unlink()
        os.mkfifo(source_file)
        code = (
            "import os, sys; from interfaces.cli.skill_install import _read_at; "
            "root = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY); "
            "_read_at(root, 'SKILL.md')"
        )
        result = subprocess.run([sys.executable, "-c", code, str(self.source.resolve())],
                                capture_output=True, text=True, timeout=2,
                                cwd=Path(__file__).parents[1])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Skill install contains a non-regular file", result.stderr)

    def test_preview_must_still_match_before_execution(self):
        preview = skill_install.plan("install", self.destination, self.source)
        (self.source / "SKILL.md").write_text("changed after preview")
        with self.assertRaisesRegex(skill_install.SkillInstallError, "changed after"):
            skill_install.execute("install", self.destination, self.source, expected_plan=preview)
        self.assertFalse(self.destination.exists())

    def test_update_and_uninstall_revalidate_after_moving_install(self):
        for operation in ("update", "uninstall"):
            with self.subTest(operation=operation):
                skill_install.execute("install", self.destination, self.source)
                if operation == "update":
                    (self.source / "SKILL.md").write_text("new version\n")
                preview = skill_install.plan(operation, self.destination, self.source if operation == "update" else None)
                read_owned = skill_install._owned_files_fd
                calls = 0

                def add_late_user_file(root_fd):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        fd = skill_install.os.open("late-user-file", skill_install.os.O_WRONLY | skill_install.os.O_CREAT
                                                   | skill_install.os.O_EXCL, 0o600, dir_fd=root_fd)
                        skill_install.os.write(fd, b"preserve me")
                        skill_install.os.close(fd)
                    return read_owned(root_fd)

                with patch.object(skill_install, "_owned_files_fd", add_late_user_file):
                    with self.assertRaisesRegex(skill_install.SkillInstallError, "unowned"):
                        skill_install.execute(operation, self.destination,
                                              self.source if operation == "update" else None,
                                              expected_plan=preview)
                self.assertEqual((self.destination / "late-user-file").read_bytes(), b"preserve me")
                self.assertTrue((self.destination / "SKILL.md").is_file())
                (self.destination / "late-user-file").unlink()
                skill_install.execute("uninstall", self.destination)


if __name__ == "__main__":
    unittest.main()
