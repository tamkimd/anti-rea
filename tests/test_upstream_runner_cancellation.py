import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import e2e_integration as e2e
from scripts import rea_integration as rea


@unittest.skipUnless(os.name == "posix", "process-group cancellation is POSIX-specific")
@patch.dict(os.environ, {"ANTI_REA_NODE_SANDBOX": "host"})
class UpstreamRunnerCancellationTests(unittest.TestCase):
    def test_interrupt_kills_term_ignoring_descendants_without_capture_pipes(self):
        for runner in (e2e, rea):
            with (
                self.subTest(runner=runner.__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                child_pid_file = root / "child.pid"
                child_ready_file = root / "child.ready"
                ignoring_child = (
                    "import pathlib, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                    f"pathlib.Path({str(child_ready_file)!r}).write_text('ready'); time.sleep(60)"
                )
                code = (
                    "import pathlib, subprocess, sys, time\n"
                    f"child=subprocess.Popen([sys.executable, '-c', {ignoring_child!r}], "
                    "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                    f"ready=pathlib.Path({str(child_ready_file)!r})\n"
                    "deadline=time.monotonic()+5\n"
                    "while not ready.exists() and time.monotonic()<deadline:\n"
                    "    time.sleep(0.01)\n"
                    "if not ready.exists(): raise RuntimeError('child did not initialize')\n"
                    f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid))\n"
                    "time.sleep(60)"
                )
                command = [sys.executable, "-c", code]
                real_popen, real_killpg, real_sleep = (
                    subprocess.Popen,
                    os.killpg,
                    time.sleep,
                )
                processes, killed_groups = [], []

                class InterruptingProcess:
                    def __init__(self, process):
                        self.process = process
                        self.interrupted = False

                    def interrupt_after_child_starts(self):
                        deadline = time.monotonic() + 5
                        while (
                            not child_pid_file.exists() and time.monotonic() < deadline
                        ):
                            real_sleep(0.01)
                        if not child_pid_file.exists():
                            raise AssertionError("nested process did not start")
                        self.interrupted = True
                        raise KeyboardInterrupt

                    def communicate(self, *args, **kwargs):
                        if runner is rea and not self.interrupted:
                            self.interrupt_after_child_starts()
                        return self.process.communicate(*args, **kwargs)

                    def poll(self):
                        if not self.interrupted:
                            self.interrupt_after_child_starts()
                        return self.process.poll()

                    def __getattr__(self, name):
                        return getattr(self.process, name)

                def start_process(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    processes.append(process)
                    return InterruptingProcess(process)

                def kill_group(group, sig):
                    killed_groups.append((group, sig))
                    return real_killpg(group, sig)

                previous_term = signal.getsignal(signal.SIGTERM)
                with (
                    patch.object(runner.subprocess, "Popen", side_effect=start_process),
                    patch.object(runner.os, "killpg", side_effect=kill_group),
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        if runner is e2e:
                            e2e.run_bounded(command, root, 30)
                        else:
                            rea.run_bounded(command, root, 30, 1024, 1024)

                self.assertEqual(signal.getsignal(signal.SIGTERM), previous_term)
                self.assertEqual(len(processes), 1)
                self.assertIsNotNone(processes[0].poll())
                self.assertIn((processes[0].pid, signal.SIGTERM), killed_groups)
                self.assertIn((processes[0].pid, signal.SIGKILL), killed_groups)
                child_pid = int(child_pid_file.read_text())
                deadline = time.monotonic() + 2
                child_live = True
                while child_live and time.monotonic() < deadline:
                    state = subprocess.run(
                        ["ps", "-o", "stat=", "-p", str(child_pid)],
                        capture_output=True,
                        text=True,
                        check=False,
                    ).stdout.strip()
                    child_live = bool(state) and not state.startswith("Z")
                    if child_live:
                        real_sleep(0.05)
                self.assertFalse(
                    child_live, f"descendant {child_pid} remained live after cleanup"
                )

    def test_interrupts_stop_child_process_groups_and_restore_sigterm_handlers(self):
        for runner in (e2e, rea):
            for interruption in ("keyboard", "sigterm"):
                with (
                    self.subTest(runner=runner.__name__, interruption=interruption),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    child_pid_file = root / "child.pid"
                    code = (
                        "import pathlib, subprocess, sys, time; "
                        "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
                        "time.sleep(60)"
                    )
                    command = [sys.executable, "-c", code]
                    real_popen, real_killpg, real_sleep = (
                        subprocess.Popen,
                        os.killpg,
                        time.sleep,
                    )
                    processes, process_ids, killed_groups = [], [], []

                    class InterruptingProcess:
                        def __init__(self, process, target_runner):
                            self.process = process
                            self.runner = target_runner
                            self.interrupted = False

                        def interrupt_after_child_starts(self):
                            deadline = time.monotonic() + 5
                            while (
                                not child_pid_file.exists()
                                and time.monotonic() < deadline
                            ):
                                real_sleep(0.01)
                            if not child_pid_file.exists():
                                raise AssertionError("nested process did not start")
                            self.interrupted = True
                            if interruption == "keyboard":
                                raise KeyboardInterrupt
                            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

                        def communicate(self, *args, **kwargs):
                            return self.process.communicate(*args, **kwargs)

                        def poll(self):
                            if not self.interrupted:
                                self.interrupt_after_child_starts()
                            return self.process.poll()

                        def __getattr__(self, name):
                            return getattr(self.process, name)

                    def start_process(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        processes.append(process)
                        process_ids.append(process.pid)
                        return InterruptingProcess(process, runner)

                    def kill_group(group, sig):
                        killed_groups.append((group, sig))
                        return real_killpg(group, sig)

                    previous_term = signal.getsignal(signal.SIGTERM)
                    expected = (
                        KeyboardInterrupt
                        if interruption == "keyboard"
                        else runner.IntegrationError
                    )
                    with (
                        patch.object(
                            runner.subprocess, "Popen", side_effect=start_process
                        ),
                        patch.object(runner.os, "killpg", side_effect=kill_group),
                    ):
                        with self.assertRaises(expected):
                            if runner is e2e:
                                e2e.run_bounded(command, root, 30)
                            else:
                                rea.run_bounded(command, root, 30, 1024, 1024)

                    self.assertEqual(signal.getsignal(signal.SIGTERM), previous_term)
                    self.assertTrue(process_ids)
                    self.assertTrue(
                        all(process.poll() is not None for process in processes)
                    )
                    self.assertIn((process_ids[0], signal.SIGTERM), killed_groups)

    def test_timeout_results_remain_distinct_after_process_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-c", "import time; time.sleep(30)"]
            with self.assertRaisesRegex(e2e.IntegrationError, "timed out"):
                e2e.run_bounded(command, directory, 0.05)
            with self.assertRaises(subprocess.TimeoutExpired):
                rea.run_bounded(command, directory, 0.05, 1024, 1024)


if __name__ == "__main__":
    unittest.main()
