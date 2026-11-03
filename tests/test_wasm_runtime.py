import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import wasm_runtime, workflow
from interfaces.cli import anti_rea

MODULE = (
    b"\x00asm\x01\x00\x00\x00"
    + b"\x01\x04\x01\x60\x00\x00"
    + b"\x02\x07\x01\x01m\x01f\x00\x00"
    + b"\x07\x05\x01\x01x\x00\x00"
)


class WasmRuntimeProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.module = Path(self.temp.name).resolve() / "service.wasm"
        self.module.write_bytes(MODULE)

    @unittest.skipUnless(shutil.which("node"), "Node runtime unavailable")
    def test_compile_probe_matches_parser_without_instantiating_module(self):
        result = wasm_runtime.probe_module(self.module)
        self.assertEqual(result["status"], "compiled")
        self.assertEqual(result["verification_scope"], "compile_only_no_instantiation")
        self.assertEqual(result["metadata_source"], "anti_rea_static_parser")
        self.assertEqual(
            result["imports"], [{"module": "m", "name": "f", "kind": "function"}]
        )
        self.assertEqual(result["exports"], [{"name": "x", "kind": "function"}])

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = anti_rea.main(["wasm-probe", str(self.module)])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "compiled")

    @unittest.skipUnless(shutil.which("node"), "Node runtime unavailable")
    def test_malformed_module_is_rejected_by_node(self):
        self.module.write_bytes(b"\x00asm\x01\x00\x00\x00\x07\x7f\x00")
        result = wasm_runtime.probe_module(self.module)
        self.assertEqual(result["status"], "compile_rejected")
        self.assertIn("parser_error", result)
        self.assertEqual(result["verification_scope"], "compile_only_no_instantiation")

    @unittest.skipUnless(shutil.which("node"), "Node runtime unavailable")
    def test_ambient_node_options_cannot_execute_code_in_compile_probe(self):
        marker = Path(self.temp.name) / "node-options-loaded"
        preload = Path(self.temp.name) / "preload.cjs"
        preload.write_text(
            "require('node:fs').writeFileSync("
            + json.dumps(str(marker))
            + ", 'loaded')",
            encoding="utf-8",
        )
        with patch.dict(os.environ, {"NODE_OPTIONS": "--require=" + str(preload)}):
            result = wasm_runtime.probe_module(self.module)
        self.assertEqual(result["status"], "compiled")
        self.assertFalse(marker.exists())

    @unittest.skipUnless(shutil.which("node"), "Node runtime unavailable")
    def test_timeout_is_reported_without_claiming_compile_success(self):
        with patch.object(
            wasm_runtime,
            "_bounded",
            side_effect=[
                (
                    0,
                    subprocess.check_output([shutil.which("node"), "--version"]),
                    b"",
                    False,
                    False,
                    False,
                ),
                (None, b"", b"", True, False, False),
            ],
        ):
            result = wasm_runtime.probe_module(self.module, timeout_seconds=1)
        self.assertEqual(result["status"], "timed_out")
        self.assertEqual(result["verification_scope"], "compile_only_no_instantiation")

    @unittest.skipUnless(shutil.which("node"), "Node runtime unavailable")
    def test_large_names_do_not_expand_node_output_or_break_probe(self):
        name = b"n" * 5000
        # Use a valid export section with multi-byte section and name lengths.
        size = len(name) + 5
        self.module.write_bytes(
            b"\x00asm\x01\x00\x00\x00\x02\x08\x01\x01m\x01m\x02\x00\x00\x07"
            + bytes(
                [
                    size & 0x7F | 0x80,
                    size >> 7,
                    1,
                    len(name) & 0x7F | 0x80,
                    len(name) >> 7,
                ]
            )
            + name
            + b"\x02\x00"
        )
        result = wasm_runtime.probe_module(self.module)
        self.assertEqual(result["status"], "compiled")
        self.assertIn("parser_error", result)

    def test_rejects_symlinks_oversize_modules_and_unbounded_timeouts(self):
        link = Path(self.temp.name) / "link.wasm"
        link.symlink_to(self.module)
        with self.assertRaisesRegex(workflow.WorkflowError, "not a symlink"):
            wasm_runtime.probe_module(link)
        with patch.object(wasm_runtime, "MAX_MODULE_BYTES", 4):
            with self.assertRaisesRegex(workflow.WorkflowError, "probe limit"):
                wasm_runtime.probe_module(self.module)
        with self.assertRaisesRegex(workflow.WorkflowError, "timeout"):
            wasm_runtime.probe_module(self.module, timeout_seconds=61)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_wasm_probe_rejects_fifo_without_blocking(self):
        fifo = Path(self.temp.name).resolve() / "module.wasm"
        os.mkfifo(fifo)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from core.wasm_runtime import probe_module; probe_module(sys.argv[1])",
                str(fifo),
            ],
            capture_output=True,
            text=True,
            timeout=2,
            cwd=Path(__file__).parents[1],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WASM probe requires a regular file", result.stderr)

    def test_rejects_module_changed_during_read(self):
        read = os.read
        changed = False

        def mutate_after_first_read(fd, size):
            nonlocal changed
            chunk = read(fd, size)
            if chunk and not changed:
                changed = True
                self.module.write_bytes(MODULE + b"x")
            return chunk

        with patch.object(wasm_runtime.os, "read", side_effect=mutate_after_first_read):
            with self.assertRaisesRegex(
                workflow.WorkflowError, "changed while being read"
            ):
                wasm_runtime.probe_module(self.module)

    def test_refuses_when_safe_directory_relative_open_is_unavailable(self):
        with patch.object(wasm_runtime.os, "O_NOFOLLOW", 0):
            with self.assertRaisesRegex(workflow.WorkflowError, "unavailable"):
                wasm_runtime.probe_module(self.module)


if __name__ == "__main__":
    unittest.main()
