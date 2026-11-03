import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from core import workflow
from interfaces.cli import anti_rea


class ReportCLITests(unittest.TestCase):
    def test_report_includes_validated_target_context(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            target = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "target",
                      "id": "target-report", "components": [{"id": "app", "kind": "fixture",
                      "root": ".", "artifacts": []}],
                      "manifests": [], "artifacts": [], "unassigned_artifacts": [], "files": [], "excluded": [],
                      "unfollowed_symlinks": [], "inventory": {"file_count": 0, "total_bytes": 0,
                      "sha256": "a" * 64}, "unknowns": []}
            workflow.write_record(store / "records", target)
            run = {"schema_version": workflow.SCHEMA_VERSION, "record_type": "run", "id": "report-run",
                   "target_id": target["id"], "state": "discovered"}
            workflow.write_run_state(store / "runs", run, None)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = anti_rea.main(["report", run["id"], str(store)])

            report = json.loads(output.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(report["target"], target)


if __name__ == "__main__":
    unittest.main()
