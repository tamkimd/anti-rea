import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from interfaces.cli import anti_rea


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


class SkillCLITests(unittest.TestCase):
    def test_preview_and_confirmed_install_report_exact_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"source";source.mkdir()
            (source/"SKILL.md").write_text("instructions\n")
            destination=root/"skills"/"anti-rea"
            destination.parent.mkdir()
            output=io.StringIO()
            with patch("sys.stdout",output):
                self.assertEqual(anti_rea.main(["skill","install",str(destination),"--source",str(source),"--preview"]),0)
            preview=json.loads(output.getvalue())
            self.assertEqual(preview["status"],"planned")
            self.assertEqual({item["path"] for item in preview["changes"]},{"SKILL.md",".anti-rea-install.json"})
            self.assertFalse(destination.exists())

            output=io.StringIO()
            with patch("sys.stdout",output):
                self.assertEqual(anti_rea.main(["skill","install",str(destination),"--source",str(source),"--yes"]),0)
            records=[json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual([record["status"] for record in records],["planned","completed"])
            self.assertEqual((destination/"SKILL.md").read_text(),"instructions\n")

    def test_interactive_decline_does_not_change_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"source";source.mkdir()
            (source/"SKILL.md").write_text("instructions\n")
            destination=root/"skills"/"anti-rea";destination.parent.mkdir()
            output=io.StringIO()
            with patch("sys.stdout",output),patch("sys.stdin",TerminalInput("n\n")):
                self.assertEqual(anti_rea.main(["skill","install",str(destination),"--source",str(source)]),0)
            records=[json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(records[-1]["status"],"cancelled")
            self.assertFalse(destination.exists())

    def test_noninteractive_apply_requires_explicit_yes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"source";source.mkdir()
            (source/"SKILL.md").write_text("instructions\n")
            destination=root/"skills"/"anti-rea";destination.parent.mkdir()
            output=io.StringIO()
            with patch("sys.stdout",output),patch("sys.stdin",io.StringIO("")):
                self.assertEqual(anti_rea.main(["skill","install",str(destination),"--source",str(source)]),2)
            self.assertFalse(destination.exists())
            self.assertIn("Non-interactive installation requires",output.getvalue())

    def test_script_entrypoint_previews_refuses_noninteractive_apply_and_installs_with_yes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"source";references=source/"references"
            references.mkdir(parents=True)
            (source/"SKILL.md").write_text("instructions\n")
            (references/"workflow.md").write_text("workflow\n")
            destination=root/"skills"/"anti-rea";destination.parent.mkdir()
            cli=Path(__file__).parents[1]/"interfaces"/"cli"/"anti_rea.py"
            command=[sys.executable,str(cli),"skill","install",str(destination),"--source",str(source)]

            preview=subprocess.run([*command,"--preview"],capture_output=True,text=True)
            self.assertEqual(preview.returncode,0,preview.stderr)
            self.assertEqual(json.loads(preview.stdout)["status"],"planned")
            self.assertFalse(destination.exists())

            refused=subprocess.run(command,capture_output=True,text=True,input="")
            self.assertEqual(refused.returncode,2)
            self.assertIn("Non-interactive installation requires",refused.stdout)
            self.assertFalse(destination.exists())

            applied=subprocess.run([*command,"--yes"],capture_output=True,text=True)
            self.assertEqual(applied.returncode,0,applied.stderr)
            self.assertEqual([json.loads(line)["status"] for line in applied.stdout.splitlines()],
                             ["planned","completed"])
            self.assertEqual((destination/"SKILL.md").read_text(),"instructions\n")
            self.assertEqual((destination/"references"/"workflow.md").read_text(),"workflow\n")


if __name__ == "__main__":
    unittest.main()
