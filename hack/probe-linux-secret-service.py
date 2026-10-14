#!/usr/bin/env python3
"""Optional Linux probe: python3 hack/probe-linux-secret-service.py /absolute/cplt.

Requires dbus-daemon, gnome-keyring-daemon, secret-tool and gdbus. Run as non-root
outside /tmp. Uses a private bus with service activation disabled and dummy data.
Records the current Landlock-only gap; this is not a Copilot login test.
"""

import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote
from xml.sax.saxutils import escape


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def denied_operation(result, diagnostic):
    require(result.returncode == 1 and result.stdout == 'CHILD_ENTERED\n'
            and diagnostic in result.stderr.splitlines(),
            'negative case did not reach the expected operation failure')


interrupted = 0


def terminate(signum, _frame):
    global interrupted
    interrupted = interrupted or signum


def checkpoint():
    if interrupted:
        raise SystemExit(128 + interrupted)


def spawn(processes, *args, **kwargs):
    # Pending termination must see the child registered before unwinding.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        process = subprocess.Popen(*args, **kwargs)
        processes.append(process)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    checkpoint()
    return process


def cleanup(processes):
    errors = []
    for process in reversed(processes):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # The owned process group has already exited.
        except Exception as error:
            errors.append(error)
        try:
            process.wait(timeout=5)
        except Exception as error:
            errors.append(error)
    if errors:
        raise ExceptionGroup('daemon cleanup failed', errors)


def main():
    global interrupted
    interrupted = 0
    if sys.platform != 'linux' or os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit('Run on Linux as a non-root user')
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    cplt = Path(sys.argv[1]).resolve(strict=True)
    tools = {name: shutil.which(name, path='/usr/bin:/bin') for name in
             ('dbus-daemon', 'gnome-keyring-daemon', 'secret-tool', 'gdbus')}
    if not all(tools.values()):
        raise SystemExit('Missing dependencies: ' + ', '.join(k for k, v in tools.items() if not v))
    if Path.cwd().is_relative_to('/tmp'):
        raise SystemExit('Run outside /tmp: Landlock grants that tree read/write')
    with tempfile.TemporaryDirectory(prefix='.secret-service-', dir=Path.cwd()) as tmp:
        home = Path(tmp)
        runtime, project = home / 'run', home / 'project'
        runtime.mkdir(mode=0o700)
        project.mkdir()
        env = {'HOME': tmp, 'PATH': '/usr/bin:/bin', 'XDG_RUNTIME_DIR': str(runtime),
               'XDG_DATA_HOME': str(home / '.local/share'), 'XDG_CONFIG_HOME': str(home / '.config'),
               'CPLT_CONFIG': '/dev/null/nonexistent', 'NO_COLOR': '1', 'LC_ALL': 'C'}
        address = 'unix:path=' + quote(str(runtime / 'bus'), safe='/')
        config = home / 'bus.conf'
        config.write_text('<busconfig><type>session</type><listen>' + escape(address) +
                          '</listen><policy context="default"><allow send_destination="*"/>'
                          '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>')
        processes = []

        def run(args, data=None):
            checkpoint()
            result = subprocess.run(args, env=env, cwd=project, input=data,
                                    capture_output=True, text=True, timeout=15)
            checkpoint()
            return result

        def sandbox(script, flags=(), args=()):
            return run([str(cplt), '--agent', 'shell', '--yes', '--quiet', '--no-audit',
                        '--no-proxy', '--no-bubblewrap', '--no-gh-guard', '--no-git-guard',
                        *flags, '--', '-c', script, 'fixture', *args])

        try:
            spawn(processes, [tools['dbus-daemon'], '--nofork', '--config-file=' + str(config)],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
            env['DBUS_SESSION_BUS_ADDRESS'] = address
            for _ in range(100):
                checkpoint()
                if (runtime / 'bus').exists():
                    break
                time.sleep(.05)
            daemon = spawn(processes, [tools['gnome-keyring-daemon'], '--foreground', '--unlock',
                                       '--components=secrets'], env=env, stdin=subprocess.PIPE,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      start_new_session=True)
            daemon.stdin.write(b'fixture-password\n')
            daemon.stdin.close()
            for _ in range(100):
                ready = run([tools['gdbus'], 'call', '--session', '--dest', 'org.freedesktop.secrets',
                             '--object-path', '/org/freedesktop/secrets', '--method',
                             'org.freedesktop.DBus.Peer.Ping'])
                if ready.returncode == 0:
                    break
                time.sleep(.05)
            require(ready.returncode == 0, 'private Secret Service did not start')
            lookup = 'secret-tool lookup service copilot-cli account fixture-bob'
            token = 'fixture-not-a-github-token'
            stored = run([tools['secret-tool'], 'store', '--label=cplt dummy credential',
                          'service', 'copilot-cli', 'account', 'fixture-bob'], token)
            require(stored.returncode == 0, 'dummy credential store failed')
            outside = run(['/bin/sh', '-c', lookup])
            require(outside.returncode == 0 and outside.stdout.strip() == token, 'outside lookup failed')
            cases = [('default discovery', 'test -z "$DBUS_SESSION_BUS_ADDRESS" && ' + lookup, ()),
                     ('explicit address', lookup, ('--pass-env', 'DBUS_SESSION_BUS_ADDRESS')),
                     ('denied socket path', lookup, ('--pass-env', 'DBUS_SESSION_BUS_ADDRESS',
                                                    '--deny-path', str(runtime / 'bus')))]
            for label, script, flags in cases:
                result = sandbox(script, flags)
                require(result.returncode == 0 and result.stdout.strip() == token, label + ': gap changed')
                print('OBSERVED readable dummy credential: ' + label)
            keyrings = list((home / '.local/share/keyrings').glob('*.keyring'))
            require(keyrings, 'no persistent dummy keyring file')
            denied = sandbox('echo CHILD_ENTERED; exec /usr/bin/cat "$1"', args=(str(keyrings[0]),))
            diagnostic = f'cat: {keyrings[0]}: Permission denied'
            if diagnostic not in denied.stderr.splitlines():
                diagnostic = f"cat: '{keyrings[0]}': Permission denied"
            denied_operation(denied, diagnostic)
            missing = sandbox('unset XDG_RUNTIME_DIR; echo CHILD_ENTERED; exec ' + lookup)
            diagnostic = next((line for line in missing.stderr.splitlines() if line ==
                               'secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY'
                               or line.startswith('secret-tool: Cannot spawn a message bus without a machine-id:')), '')
            require(diagnostic, 'secret-tool did not report a bus discovery failure')
            denied_operation(missing, diagnostic)
            print('PASS keyring file denied; no-address/no-runtime discovery fails')
        finally:
            cleanup(processes)
        checkpoint()


if __name__ == '__main__':
    main()
