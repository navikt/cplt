#!/usr/bin/env python3
"""Run real Copilot with empty state and kernel-denied credential access on macOS."""

import argparse
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import signal
import stat
import subprocess
import tempfile
import time


def run(command, *, env, cwd, timeout):
    with subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
            return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        finally:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            except ProcessLookupError:
                pass
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()


def stored_gh_token():
    """Use the resolver's trusted paths, not PATH or ambient token overrides."""
    for directory in ("/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"):
        candidate = Path(directory) / "gh"
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        gh = candidate.resolve()
        if not any(gh.is_relative_to(Path(root).resolve()) for root in
                   ("/usr/bin", "/bin", "/usr/local", "/opt/homebrew")):
            continue
        env = {key: os.environ[key] for key in ("HOME", "GH_CONFIG_DIR", "XDG_CONFIG_HOME")
               if key in os.environ}
        env["PATH"] = "/usr/bin:/bin"
        try:
            result = run([str(gh), "auth", "token", "--hostname", "github.com"],
                         env=env, cwd="/", timeout=5)
        except subprocess.TimeoutExpired:
            raise SystemExit("FAIL: host gh token lookup timed out") from None
        token = result.stdout.strip()
        if result.returncode or not token or any(char.isspace() for char in token):
            raise SystemExit("FAIL: trusted gh has no usable stored github.com token")
        print(f"CREDENTIAL_SOURCE=stored gh token on github.com via {gh}")
        return token
    raise SystemExit("FAIL: gh is not installed in a trusted binary directory")


def assert_not_persisted(root, token):
    """Check only probe-created files; never read the user's credential files."""
    needle = token.encode()
    for directory, _, files in os.walk(root, followlinks=False):
        for name in files:
            path = Path(directory) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                continue
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    continue
                previous = b""
                while chunk := source.read(1024 * 1024):
                    data = previous + chunk
                    if needle in data:
                        raise SystemExit("FAIL: injected token appeared in probe-created storage")
                    previous = data[-len(needle):]
    print("TOKEN_PERSISTENCE=absent from probe-created files")


def interactive(command, env, project, authenticated, prompt, startup_only=False, cancel_launch=False):
    """Keep PTY output in memory; print only recognized state transitions."""
    master, slave = pty.openpty()
    import fcntl
    import struct
    import termios
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

    def session():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    try:
        child = subprocess.Popen(command, env=env, cwd=project, stdin=slave,
                                 stdout=slave, stderr=slave, preexec_fn=session)
    except BaseException:
        os.close(slave)
        os.close(master)
        raise
    os.close(slave)
    transcript = b""
    pending = b""
    stage = "trust"
    screen = b""
    changed = time.monotonic()
    deadline = changed + 90
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                transcript += chunk
                if len(transcript) > 8 * 1024 * 1024:
                    raise SystemExit("FAIL: interactive output exceeded 8 MiB; raw output withheld")
                pending += chunk
                for query, response in (
                    (b"\x1b[6n", b"\x1b[1;1R"),
                    (b"\x1b[?u", b"\x1b[?0u"),
                    (b"\x1b[c", b"\x1b[?1;2c"),
                    (b"\x1b[>c", b"\x1b[>0;0;0c"),
                    (b"\x1b[>q", b"\x1bP>|cplt-probe\x1b\\"),
                    (b"\x1b]10;?\x1b\\", b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\"),
                    (b"\x1b]11;?\x1b\\", b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
                ):
                    count = pending.count(query)
                    if count:
                        os.write(master, response * count)
                        pending = pending.replace(query, b"")
                pending = pending[-32:]
            screen = re.sub(rb"\x1b\[[0-9;?]*[ -/]*[@-~]", b"", transcript)
            screen = re.sub(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", b"", screen)
            if cancel_launch:
                if stage == "trust" and b"[y/N]" in screen:
                    os.write(master, b"n\n")
                    print("CANCELLATION=cplt launch confirmation declined")
                    stage = "cancelled"
                if stage == "cancelled" and b"Aborted by user" in screen:
                    child.wait(timeout=5)
                    if child.returncode == 0:
                        raise SystemExit("FAIL: declined cplt launch exited successfully")
                    print("CANCELLATION=nonzero exit before agent launch; no OAuth started")
                    return
                continue
            if b"System vault not available" in screen:
                raise SystemExit("FAIL: interactive vault prompt")
            if not authenticated and re.search(rb"sign in|/login|not authenticated", screen, re.I):
                print("INTERACTIVE=sign-in guidance")
                return
            if stage == "trust" and b"Do you trust the files in this folder" in screen and b"to select" in screen:
                time.sleep(0.5)
                os.write(master, b"\r")
                print("INTERACTIVE=empty-project trust approved after menu readiness")
                stage, changed = "startup", time.monotonic()
                transcript = b""
            elif stage == "startup" and b"Interactive" in screen and time.monotonic() - changed > 1:
                os.write(master, b"\x1b[200~/user show\x1b[201~")
                stage, changed = "account-input", time.monotonic()
                transcript = b""
            elif stage == "account-input" and b"/user show" in screen and time.monotonic() - changed > 1:
                os.write(master, b"\r")
                print("INTERACTIVE=/user show submitted")
                stage, changed = "account", time.monotonic()
                transcript = b""
            elif stage == "account" and re.search(rb"Signed in to https://github\.com as [\w-]+", screen):
                print("AUTH_STATUS=signed in to github.com; account name withheld")
                if startup_only:
                    return
                os.write(master, b"\x1b[200~" + prompt.encode() + b"\x1b[201~")
                stage, changed = "prompt-input", time.monotonic()
                transcript = b""
            elif stage == "prompt-input" and b"7429" in screen and time.monotonic() - changed > 1:
                os.write(master, b"\r")
                print("INTERACTIVE=normal prompt submitted")
                stage = "answer"
                transcript = b""
            elif stage == "answer" and b"CPLTAUTH7429" in re.sub(rb"\s+", b"", screen):
                if b"CPLTAUTH7429" in re.sub(rb"\s+", b"", prompt.encode()):
                    raise SystemExit("FAIL: expected answer is contained in the input prompt")
                print("INTERACTIVE=authenticated model response")
                return
            if child.poll() is not None:
                break
        for marker in (b"Do you trust", b"Thinking", b"Loading", b"Error", b"/user show", b"CPLT", b"AUTH", b"7429", b"to select", b"AIC used", b"Reply with the concatenation", b"Signed in", b"Total usage"):
            if marker in screen:
                print(f"INTERACTIVE_OBSERVED={marker.decode()}")
        raise SystemExit(f"FAIL: interactive result missing at stage {stage}; raw output withheld")
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        os.close(master)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cplt", type=Path, required=True)
    parser.add_argument("--copilot", type=Path, required=True)
    parser.add_argument("--interactive", action="store_true", help="accept only the empty project's trust prompt, then observe sign-in guidance or the authenticated response")
    parser.add_argument("--authenticated-gh", action="store_true", help="explicitly retrieve gh's stored github.com token host-side and inject GH_TOKEN in memory only")
    parser.add_argument("--startup-only", action="store_true", help="interactive /user show only, without a model request")
    parser.add_argument("--isolation-only", action="store_true", help="compare standalone Copilot under credential isolation without the generated cplt profile")
    parser.add_argument("--full-launch", action="store_true", help="run cplt's full headless pipeline only if its own profile enforces credential isolation")
    parser.add_argument("--cancel-launch", action="store_true", help="decline real cplt's launch confirmation without retrieving a token or starting OAuth")
    parser.add_argument("--nav-pilot", type=Path, help="with --full-launch, check the installed nav-pilot's empty-state launch gate without a model request")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("this probe requires macOS Seatbelt")
    if args.startup_only and not (args.interactive and args.authenticated_gh):
        parser.error("--startup-only requires --interactive --authenticated-gh")
    if args.full_launch and (not args.authenticated_gh or args.interactive or args.isolation_only):
        parser.error("--full-launch requires --authenticated-gh and headless generated-profile mode")
    if args.cancel_launch and (args.authenticated_gh or args.interactive or args.full_launch or args.isolation_only):
        parser.error("--cancel-launch cannot be combined with authentication or other launch modes")
    if args.nav_pilot and not args.full_launch:
        parser.error("--nav-pilot requires --full-launch")
    cplt, copilot = args.cplt.resolve(strict=True), args.copilot.resolve(strict=True)
    # Convert termination into unwinding so PTY children and temporary state are cleaned up.
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    real_home = Path.home().resolve()
    with tempfile.TemporaryDirectory(prefix="cplt-no-auth-") as temporary:
        root = Path(temporary).resolve()
        home = root / "home"
        project = root / "project"
        for directory in (home, project, home / "gh", home / "tmp"):
            directory.mkdir(parents=True)
        config = root / "cplt.toml"
        config.write_text("[sandbox]\nkeychain_substitute = " + ("true" if args.full_launch else "false") + "\nscratch_dir = false\n[gh_guard]\nenabled = false\n")
        profile = root / "credentials-denied.sb"
        # Deny OS-home lookup too; HOME does not redirect native account APIs.
        profile.write_text(
            '(version 1)\n(allow default)\n'
            f'(deny file-read* file-write* (subpath {json.dumps(str(real_home))}))\n'
            f'(allow file-read* (literal {json.dumps(str(cplt))}))\n'
            f'(allow file-read* (literal {json.dumps(str(copilot))}))\n'
            '(deny mach-lookup (global-name "com.apple.securityd"))\n'
            '(deny process-exec (regex #"/gh$"))\n'
        )
        env = {
            "HOME": str(home),
            "PATH": f"{copilot.parent}:/usr/bin:/bin",
            "CPLT_CONFIG": str(config),
            "GH_CONFIG_DIR": str(home / "gh"),
            "COPILOT_HOME": str(home / ".copilot"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local/share"),
            "XDG_STATE_HOME": str(home / ".local/state"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "TMPDIR": str(home / "tmp"),
            "NO_COLOR": "1",
            "TERM": "dumb",
        }
        sandbox = ["/usr/bin/sandbox-exec", "-f", str(profile)]
        launch = [str(cplt), "--agent", "copilot", "--no-proxy", "--no-gh-guard",
                  "--no-scratch-dir"]
        if args.full_launch or args.cancel_launch:
            launch += ["--deny-path", str(real_home),
                       "--deny-path", str(real_home / "Library/Keychains")]
        if args.cancel_launch:
            print(f"CPLT_BINARY={cplt}")
            interactive(launch + ["--", "--version"], env, project, False, "", cancel_launch=True)
            print("PASS: real cplt cancellation probe")
            return
        warmup = run(
            sandbox + [str(copilot), "--no-auto-update", "--version"],
            env=env, cwd=project, timeout=60,
        )
        if warmup.returncode:
            raise SystemExit("FAIL: isolated runtime extraction")
        version = re.search(r"\b\d+\.\d+\.\d+(?:-[\w.-]+)?", warmup.stdout)
        if not version:
            raise SystemExit("FAIL: isolated runtime version was not recognized")
        print(f"COPILOT_VERSION={version.group().rstrip('.')}")
        generation_env = dict(env)
        if args.full_launch:
            # Profile policy depends on token presence, not validity. Do not retrieve a real one before this gate.
            generation_env["GH_TOKEN"] = "synthetic-profile-presence-only"
        generated = run(
            (launch if args.full_launch else sandbox + launch) + ["--print-profile"],
            env=generation_env, cwd=project, timeout=30,
        )
        start = generated.stdout.find("(version 1)")
        if generated.returncode or start < 0:
            raise SystemExit("FAIL: profile generation")
        if args.full_launch:
            print(f"CPLT_BINARY={cplt}")
            print("FULL_LAUNCH_PREFLIGHT=real-home and actual Keychain file denies requested; gh guard disabled")
            if '(deny mach-lookup (global-name "com.apple.securityd"))' not in generated.stdout[start:]:
                print("KEYCHAIN_API_ISOLATION=not established; broad mach-lookup remains allowed")
                if args.nav_pilot:
                    nav = args.nav_pilot.resolve(strict=True)
                    if not any(nav.is_relative_to(Path(root).resolve()) for root in ("/usr/bin", "/usr/local", "/opt/homebrew")):
                        raise SystemExit("BLOCKED: nav-pilot is outside trusted install prefixes")
                    nav_env = dict(env)
                    nav_env.update({"PATH": f"{cplt.parent}:{copilot.parent}:/opt/homebrew/bin:/usr/bin:/bin",
                                    "NAV_PILOT_CONFIG": str(root / "nav-pilot.toml"),
                                    "DO_NOT_TRACK": "1", "NAV_PILOT_TELEMETRY_ENABLED": "false"})
                    (root / "nav-pilot.toml").write_text("auto_update = false\nauto_launch = true\n")
                    result = run([str(nav), "--client", "copilot", "--", "--version"],
                                 env=nav_env, cwd=project, timeout=30)
                    print(f"NAV_PILOT_BINARY={nav}")
                    print(f"NAV_PILOT_EXIT_STATUS={result.returncode}")
                    if result.returncode == 2 and "nothing is installed" in result.stdout + result.stderr:
                        print("NAV_PILOT_STAGE=empty-state install gate refused launch before cplt; no install or OAuth performed")
                    else:
                        print("NAV_PILOT_STAGE=unexpected preflight result; raw output withheld")
                raise SystemExit("BLOCKED: full cplt launch cannot enforce this probe's securityd deny; no real token retrieved or model request sent")
        # Apply one profile: macOS refuses nesting sandbox-exec.
        restrictions = profile.read_text().split("(allow default)\n", 1)[1]
        if not args.isolation_only:
            profile.write_text(generated.stdout[start:] + "\n" + restrictions)
        print("PROFILE_MODE=" + ("credential-isolation-only" if args.isolation_only else "generated-cplt"))
        env["COPILOT_CLI_SANDBOX_SUPPORT_OVERRIDE"] = "unsupported"
        # No token reaches extraction or profile generation, and none is an argv value.
        token = stored_gh_token() if args.authenticated_gh else None
        if token:
            env["GH_TOKEN"] = token
        prompt = "Reply with the concatenation of CPLT and AUTH and 7429, with no spaces or other text. Do not use tools."
        answer = "CPLTAUTH7429"
        if args.interactive:
            command = sandbox + [str(copilot), "--no-auto-update", "--disable-builtin-mcps"]
            env["TERM"] = "xterm-256color"
            try:
                interactive(command, env, project, bool(token), prompt, args.startup_only)
            finally:
                if token:
                    assert_not_persisted(root, token)
            print("PASS: real Copilot interactive probe")
            return
        command = (launch + ["--yes", "--quiet", "--"] if args.full_launch else sandbox + [str(copilot)]) + ["--no-auto-update", "-s", "-p", prompt]
        try:
            result = run(
                command, env=env, cwd=project, timeout=90,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit("FAIL: Copilot request exceeded 90 seconds") from None
        finally:
            if token:
                assert_not_persisted(root, token)
        print(f"EXIT_STATUS={result.returncode}")
        if token:
            if token in result.stdout + result.stderr:
                raise SystemExit("FAIL: injected token appeared in captured output")
            if result.returncode or result.stdout.strip() != answer:
                raise SystemExit("FAIL: authenticated request did not return the exact expected response; raw output withheld")
            print("PASS: real Copilot answered with empty state and denied Keychain")
            return
        if result.returncode == 0:
            raise SystemExit("FAIL: a credential-free request unexpectedly succeeded")
        if "Error: No authentication information found." not in result.stdout + result.stderr:
            raise SystemExit("FAIL: request failed without an authentication diagnostic")
        print("PASS: real Copilot refused a request without credentials")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("FAIL: probe interrupted; child cleanup completed") from None
