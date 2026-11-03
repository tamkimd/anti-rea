import contextlib
import importlib.util
import io
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from interfaces.cli import anti_rea


class DoctorCLITests(unittest.TestCase):
    def test_optional_runtimes_are_reported_without_blocking_or_writing(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            before = set(Path(directory).iterdir())
            with contextlib.redirect_stdout(output):
                status = anti_rea.main(["doctor"])
            report = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(report["status"], "ready")
            self.assertEqual({check["id"] for check in report["checks"]
                              if check["status"] == "not_configured"},
                             {"runtime:bla", "runtime:e2e", "runtime:rea"})
            self.assertEqual(set(Path(directory).iterdir()), before)

    def test_invalid_configured_runtime_blocks_doctor(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,
                {"ANTI_REA_BLA_RUNTIME": str(Path(directory) / "missing")}, clear=True):
            with contextlib.redirect_stdout(output):
                status = anti_rea.main(["doctor"])
        report = json.loads(output.getvalue())
        bla = next(check for check in report["checks"] if check["id"] == "runtime:bla")
        self.assertEqual((status, report["status"], bla["status"]), (2, "blocked", "blocked"))

    def test_configured_runtime_reports_verified_package_versions(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            adapter = root / "adapter.py"
            adapter.write_text("def verify_runtime(path):\n    from pathlib import Path\n    return Path(path), {'packages': {'engine': {'version': '1.2.3'}}}\n")
            with patch.dict(os.environ, {"ANTI_REA_E2E_RUNTIME": str(runtime)}, clear=True), \
                    patch.object(anti_rea.execution, "_e2e_script", return_value=adapter), \
                    contextlib.redirect_stdout(output):
                status = anti_rea.main(["doctor"])
        report = json.loads(output.getvalue())
        e2e = next(check for check in report["checks"] if check["id"] == "runtime:e2e")
        self.assertEqual((status, e2e["status"], e2e["version"]), (0, "passed", {"engine": {"version": "1.2.3"}}))

    def test_missing_required_python_package_blocks_doctor(self):
        output = io.StringIO()
        original = importlib.util.find_spec
        def find_spec(name, *args, **kwargs):
            return None if name == "mcp" else original(name, *args, **kwargs)
        with patch.dict(os.environ, {}, clear=True), patch.object(anti_rea.importlib.util, "find_spec", find_spec):
            with contextlib.redirect_stdout(output):
                status = anti_rea.main(["doctor"])
        report = json.loads(output.getvalue())
        mcp = next(check for check in report["checks"] if check["id"] == "python:mcp")
        self.assertEqual((status, report["status"], mcp["status"]), (2, "blocked", "blocked"))


if __name__ == "__main__":
    unittest.main()
