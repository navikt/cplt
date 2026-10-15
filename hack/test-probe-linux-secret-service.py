#!/usr/bin/env python3
"""Offline evidence checks: python3 -B hack/test-probe-linux-secret-service.py."""

import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote
from xml.etree import ElementTree

path = Path(__file__).with_name('probe-linux-secret-service.py')
spec = importlib.util.spec_from_file_location('probe', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_special_fixture_path_reaches_valid_bus_config(self):
        with tempfile.TemporaryDirectory(prefix='bus &<>,;% ') as tmp:
            root = Path(tmp)
            def inspect_spawn(_processes, args, **_kwargs):
                config = Path(args[-1].removeprefix('--config-file='))
                address = ElementTree.parse(config).findtext('listen')
                self.assertEqual(unquote(address.removeprefix('unix:path=')), str(root / 'run/bus'))
                self.assertNotIn('&', address)
                self.assertNotIn(',', address)
                raise RuntimeError('config inspected')
            handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
            try:
                with patch.object(probe.sys, 'platform', 'linux'), \
                        patch.object(probe.sys, 'argv', ['probe', str(path)]), \
                        patch.object(probe.os, 'getuid', return_value=1001), \
                        patch.object(probe.os, 'geteuid', return_value=1001), \
                        patch.object(probe.shutil, 'which', return_value='/fixture/tool'), \
                        patch.object(probe.tempfile, 'TemporaryDirectory') as directory, \
                        patch.object(probe, 'spawn', side_effect=inspect_spawn):
                    directory.return_value.__enter__.return_value = tmp
                    with self.assertRaisesRegex(RuntimeError, 'config inspected'):
                        probe.main()
            finally:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)

    def test_uid_and_euid_root_are_refused_before_setup(self):
        for uid, euid in [(0, 1001), (1001, 0)]:
            with self.subTest(uid=uid, euid=euid), \
                    patch.object(probe.sys, 'platform', 'linux'), \
                    patch.object(probe.os, 'getuid', return_value=uid), \
                    patch.object(probe.os, 'geteuid', return_value=euid), \
                    patch.object(probe.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(SystemExit, 'non-root'):
                    probe.main()
                spawn.assert_not_called()

    def test_negative_evidence_requires_child_and_exact_diagnostic(self):
        diagnostic = 'cat: /fixture/login.keyring: Permission denied'
        for code, stdout, stderr in [(1, '', diagnostic),
                                     (1, 'CHILD_ENTERED\n', 'cat: /other: Permission denied'),
                                     (127, 'CHILD_ENTERED\n', diagnostic),
                                     (1, 'CHILD_ENTERED\n', 'Cannot autolaunch D-Bus')]:
            with self.subTest(code=code, stdout=stdout, stderr=stderr):
                with self.assertRaisesRegex(RuntimeError, 'expected operation failure'):
                    probe.denied_operation(subprocess.CompletedProcess([], code, stdout, stderr), diagnostic)
        probe.denied_operation(subprocess.CompletedProcess([], 1, 'CHILD_ENTERED\n', diagnostic), diagnostic)

    def test_evidence_survives_optimized_python(self):
        result = subprocess.run([sys.executable, '-O', '-c',
                                 f"import runpy; p=runpy.run_path({str(path)!r}); p['require'](False, 'evidence rejected')"],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('evidence rejected', result.stderr)

    def test_sigterm_exits_as_failure(self):
        with patch.object(probe, 'interrupted', 0):
            probe.terminate(signal.SIGTERM, None)
            probe.terminate(signal.SIGINT, None)
            with self.assertRaises(SystemExit) as error:
                probe.checkpoint()
            self.assertEqual(error.exception.code, 143)

    def test_termination_between_spawn_and_registration_keeps_child_owned(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            processes = []
            child = Mock()
            def interrupted_spawn():
                os.kill(os.getpid(), sig)
                return child
            previous = signal.signal(sig, probe.terminate)
            try:
                with patch.object(probe, 'interrupted', 0), \
                        patch.object(probe.subprocess, 'Popen', side_effect=interrupted_spawn):
                    with self.assertRaises(SystemExit) as error:
                        probe.spawn(processes)
                self.assertEqual(error.exception.code, 128 + sig)
                self.assertEqual(processes, [child])
            finally:
                signal.signal(sig, previous)

    def test_cleanup_survives_repeated_signals_and_attempts_all_groups_on_errors(self):
        children = [Mock(pid=101), Mock(pid=102)]
        children[1].wait.side_effect = subprocess.TimeoutExpired('fixture', 5)
        def interrupted_kill(pid, _sig):
            signal.raise_signal(signal.SIGTERM)
            signal.raise_signal(signal.SIGTERM)
            signal.raise_signal(signal.SIGINT)
            if pid == 102:
                raise PermissionError('fixture cleanup error')
        handlers = {sig: signal.signal(sig, probe.terminate) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            with patch.object(probe, 'interrupted', 0), \
                    patch.object(probe.os, 'killpg', side_effect=interrupted_kill) as kill:
                with self.assertRaises(ExceptionGroup) as error:
                    probe.cleanup(children)
            self.assertEqual(len(error.exception.exceptions), 2)
            self.assertEqual([call.args[0] for call in kill.call_args_list], [102, 101])
            for child in children:
                child.wait.assert_called_once_with(timeout=5)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)

    def test_first_cancellation_during_successful_cleanup_is_not_lost(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            children = [Mock(pid=101), Mock(pid=102)]
            previous = signal.signal(sig, probe.terminate)
            try:
                with patch.object(probe, 'interrupted', 0), \
                        patch.object(probe.os, 'killpg', side_effect=lambda *_: signal.raise_signal(sig)) as kill:
                    probe.cleanup(children)
                    self.assertEqual(kill.call_count, 2)
                    for child in children:
                        child.wait.assert_called_once_with(timeout=5)
                    with self.assertRaises(SystemExit) as error:
                        probe.checkpoint()
                    self.assertEqual(error.exception.code, 128 + sig)
            finally:
                signal.signal(sig, previous)


if __name__ == '__main__':
    unittest.main()
