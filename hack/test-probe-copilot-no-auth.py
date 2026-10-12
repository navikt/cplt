#!/usr/bin/env python3
"""Offline checks for probe cleanup and its token-persistence assertion."""

import contextlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest


probe = runpy.run_path(str(Path(__file__).with_name("probe-copilot-no-auth.py")))


class ProbeTests(unittest.TestCase):
    def test_timeout_kills_and_reaps_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = """
import os, signal, sys, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path('pid').write_text(str(os.getpid()))
if os.fork() == 0:
    time.sleep(3)
    Path('leaked').write_text('descendant survived')
    os._exit(0)
time.sleep(30)
"""
            with self.assertRaises(subprocess.TimeoutExpired):
                probe["run"]([sys.executable, "-c", code], env=os.environ.copy(),
                             cwd=root, timeout=0.5)
            pid = int((root / "pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            time.sleep(1)
            self.assertFalse((root / "leaked").exists())

    def test_persistence_scan_skips_fifo_and_symlink_and_detects_split_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.write_text("fixture-secret")
            tree = root / "probe"
            tree.mkdir()
            (tree / "link").symlink_to(outside)
            os.mkfifo(tree / "fifo")
            with contextlib.redirect_stdout(io.StringIO()):
                probe["assert_not_persisted"](tree, "fixture-secret")
            (tree / "stored").write_bytes(b"x" * (1024 * 1024 - 4) + b"fixture-secret")
            with self.assertRaisesRegex(SystemExit, "injected token appeared"):
                probe["assert_not_persisted"](tree, "fixture-secret")


if __name__ == "__main__":
    unittest.main()
