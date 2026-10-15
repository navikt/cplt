#!/usr/bin/env python3
"""Offline regression checks. No real gh lookup, Copilot request or OAuth."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("probe", Path(__file__).with_name("probe-copilot-no-auth.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_both_authenticated_commands_enforce_no_tools(self):
        for interactive in (False, True):
            results = [subprocess.CompletedProcess([], 0, "1.0.94\n", ""),
                       subprocess.CompletedProcess([], 0, '(version 1)\n(deny default)\n', ""),
                       subprocess.CompletedProcess([], 0, "CPLTAUTH7429", "")]
            argv = ["probe", "--cplt", sys.executable, "--copilot", sys.executable, "--authenticated-gh"]
            if interactive:
                argv.append("--interactive")
            with patch.object(sys, "argv", argv), \
                    patch.object(probe.platform, "system", return_value="Darwin"), \
                    patch.object(probe, "run", side_effect=results) as run, \
                    patch.object(probe, "interactive") as tui, \
                    patch.object(probe, "stored_gh_token", return_value="synthetic-token"), \
                    patch.object(probe, "assert_not_persisted"), \
                    patch.object(probe.signal, "signal"), contextlib.redirect_stdout(io.StringIO()):
                probe.main()
                command = (tui if interactive else run).call_args.args[0]
                self.assertIn("--disable-builtin-mcps", command)
                self.assertIn("--available-tools=", command)
                denies = [command[i + 1] for i, arg in enumerate(command) if arg == "--deny-tool"]
                self.assertEqual(denies, ["shell", "write", "url"])

    def test_stored_lookup_strips_overrides_and_withholds_failure_output(self):
        ambient = dict.fromkeys(("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_REPO"), "ambient-secret")
        ambient["HOME"] = "/synthetic/home"
        with patch.dict(os.environ, ambient, clear=True), \
                patch.object(Path, "is_file", return_value=True), \
                patch.object(Path, "resolve", lambda path: path), \
                patch.object(os, "access", return_value=True), \
                patch.object(probe, "run") as run, contextlib.redirect_stdout(io.StringIO()) as output:
            run.return_value = subprocess.CompletedProcess([], 0, "synthetic-stored-secret\n", "")
            self.assertEqual(probe.stored_gh_token(), "synthetic-stored-secret")
            command, = run.call_args.args
            self.assertEqual(command[1:], ["auth", "token", "--hostname", "github.com"])
            self.assertFalse(set(ambient) - {"HOME"} & set(run.call_args.kwargs["env"]))
            run.return_value = subprocess.CompletedProcess([], 1, "synthetic-stored-secret", "private-error")
            with self.assertRaises(SystemExit) as error:
                probe.stored_gh_token()
            self.assertNotIn("secret", str(error.exception))
            self.assertNotIn("private-error", str(error.exception))
            self.assertNotIn("secret", output.getvalue())

    def test_persistence_check_skips_symlinks_and_fifos_and_checks_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret").write_text("synthetic-secret")
            tree = root / "tree"
            tree.mkdir()
            (tree / "symlink").symlink_to(outside / "secret")
            os.mkfifo(tree / "fifo")
            probe.assert_not_persisted(tree, "synthetic-secret")
            (tree / "regular").write_bytes(b"x" * (1024 * 1024 - 4) + b"synthetic-secret")
            with self.assertRaisesRegex(SystemExit, "persisted|storage"):
                probe.assert_not_persisted(tree, "synthetic-secret")

    def test_full_launch_gate_never_retrieves_token_without_service_deny(self):
        results = [subprocess.CompletedProcess([], 0, "1.0.94\n", ""),
                   subprocess.CompletedProcess([], 0, '(version 1)\n(deny default)\n(allow mach-lookup)\n', "")]
        with patch.object(sys, "argv", ["probe", "--cplt", sys.executable, "--copilot", sys.executable,
                                        "--authenticated-gh", "--full-launch"]), \
                patch.object(probe.platform, "system", return_value="Darwin"), \
                patch.object(probe, "run", side_effect=results), \
                patch.object(probe, "stored_gh_token") as lookup, \
                patch.object(probe.signal, "signal"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "BLOCKED"):
                probe.main()
            lookup.assert_not_called()

    def test_timeout_kills_and_reaps_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            pidfile = Path(temporary) / "pids"
            source = "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); child=os.fork(); open(__import__('sys').argv[1], 'w').write(str(os.getpid())+' '+str(child)) if child else None; time.sleep(60)"
            with self.assertRaises(subprocess.TimeoutExpired):
                probe.run([sys.executable, "-c", source, str(pidfile)], env={"PATH": "/usr/bin:/bin"}, cwd=temporary, timeout=1)
            parent, child = map(int, pidfile.read_text().split())
            with self.assertRaises(ProcessLookupError):
                os.kill(parent, 0)
            # A killed orphan may remain a zombie briefly; it must never be runnable.
            result = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(child)], capture_output=True, text=True)
            self.assertTrue(not result.stdout.strip() or result.stdout.strip().startswith("Z"))

    @unittest.skipUnless(sys.platform == "darwin", "PTY queries exercise the macOS observer")
    def test_tui_waits_for_input_and_hides_account_with_ansi_answer(self):
        source = r'''
import os,time,tty
tty.setraw(0)
def read_until(end):
    value=b""
    while not value.endswith(end): value+=os.read(0,1)
    return value
os.write(1,b"\x1b["); time.sleep(.1); os.write(1,b"6n")
assert read_until(b"R")==b"\x1b[1;1R"
os.write(1,b"Do you trust the files in this folder?")
time.sleep(.1); os.write(1,b"to select")
assert read_until(b"\r")==b"\r"
os.write(1,b"Interactive")
assert b"/user show" in read_until(b"\x1b[201~")
time.sleep(.1); os.write(1,b"/user show")
assert read_until(b"\r")==b"\r"
os.write(1,b"Signed in to https://github.com as private-account")
assert b"7429" in read_until(b"\x1b[201~")
time.sleep(.1); os.write(1,b"7429")
assert read_until(b"\r")==b"\r"
os.write(1,b"CPLT\x1b[31mAUTH7429")
time.sleep(60)
'''
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()) as output:
            probe.interactive([sys.executable, "-c", source], {"PATH": "/usr/bin:/bin"}, temporary,
                              True, "CPLT and AUTH and 7429")
            self.assertIn("authenticated model response", output.getvalue())
            self.assertNotIn("private-account", output.getvalue())


if __name__ == "__main__":
    unittest.main()
