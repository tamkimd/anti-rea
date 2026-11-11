import contextlib
import io
import json
import unittest
from unittest.mock import patch

from interfaces.cli import anti_rea


class CraftAnythingCliTests(unittest.TestCase):
    def test_execute_plan_passes_explicit_craft_anything_cli(self):
        output = io.StringIO()
        with (
            patch.object(
                anti_rea.execution, "execute_bla_action", return_value={"status": "ok"}
            ) as execute,
            contextlib.redirect_stdout(output),
        ):
            result = anti_rea.main(
                [
                    "execute-plan",
                    "run-r",
                    "action-r",
                    "/tmp/state",
                    "--craft-anything-cli",
                    "/opt/craft-anything-cli",
                    "--craft-anything-timeout",
                    "23",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue()), {"status": "ok"})
        self.assertEqual(
            execute.call_args.kwargs["craft_anything_executable"],
            "/opt/craft-anything-cli",
        )
        self.assertEqual(execute.call_args.kwargs["craft_anything_timeout"], 23)

    def test_execute_plan_uses_craft_anything_environment_default(self):
        with (
            patch.dict("os.environ", {"ANTI_REA_CRAFT_ANYTHING_CLI": "/env/craft"}),
            patch.object(
                anti_rea.execution,
                "execute_bla_action",
                return_value={"status": "ok"},
            ) as execute,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                anti_rea.main(["execute-plan", "run-r", "action-r", "/tmp/state"]),
                0,
            )

        self.assertEqual(
            execute.call_args.kwargs["craft_anything_executable"], "/env/craft"
        )

    def test_recommend_can_run_analyzers_without_making_them_gates(self):
        plan = {
            "id": "plan-r",
            "baseline_id": "baseline-r",
            "profile": {"name": "balanced"},
            "actions": [],
        }
        with (
            patch.object(
                anti_rea.workflow,
                "read_record",
                side_effect=[{"id": "target-r"}, {"id": "baseline-r"}],
            ),
            patch.object(
                anti_rea.recommendations, "create_plan", return_value=plan
            ) as create_plan,
            patch.object(anti_rea.workflow, "write_record", return_value="/tmp/plan"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = anti_rea.main(
                [
                    "recommend",
                    "target-r",
                    "baseline-r",
                    "plan-r",
                    "/tmp/state",
                    "--no-analysis-gates",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(create_plan.call_args.kwargs["analysis_gates"], [])


if __name__ == "__main__":
    unittest.main()
