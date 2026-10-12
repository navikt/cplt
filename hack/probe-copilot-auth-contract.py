#!/usr/bin/env python3
"""Check pinned public Copilot schemas and isolated synthetic native metadata."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import tempfile


PINS = {"1.0.94-5": "fdeb5949", "1.0.95": "f5ba5057"}
TEMP = Path(tempfile.gettempdir())

NATIVE_CHECK = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const {spawnSync} = require('node:child_process');
const [addon, root, forbidden] = process.argv.slice(2);
assert.throws(() => fs.readFileSync(forbidden));
assert(spawnSync('/usr/bin/security', ['help']).error);
console.log('STEP filesystem/subprocess isolation');
const awaitBlocked = new Promise((resolve, reject) => {
  const socket = net.connect({host: '127.0.0.1', port: 9});
  socket.once('error', error => {
    socket.destroy();
    ['EPERM', 'EACCES'].includes(error.code) ? resolve() : reject(error);
  });
  socket.once('connect', () => {socket.destroy(); reject(Error('network allowed'));});
});
awaitBlocked.then(async () => {
  console.log('STEP network isolation');
  let v;
  try {v = require(addon);} catch (error) {
    console.log('STEP native load failure code=' + (error.code || 'none') +
                ' abi=' + /NODE_MODULE_VERSION|Module did not self-register/.test(error.message) +
                ' dlopen=' + /dlopen/.test(error.message));
    throw error;
  }
  console.log('STEP native module loaded');
  const context = {configDir: root, homeDirectory: process.env.HOME,
                   environment: process.env};
  const state = await v.globalStateLoadForContext(context);
  console.log('STEP global state loaded');
  assert.deepEqual(JSON.parse(JSON.stringify(state.lastLoggedInUser)), {host: 'https://github.com', login: 'fixture-bob'});
  assert.equal(state.loggedInUsers.length, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(state.authTokens)), {});
  const selected = await v.authGetLastLoggedInUserForContext(context);
  console.log('STEP last-sign-in read');
  assert.deepEqual(JSON.parse(selected), JSON.parse(JSON.stringify(state.lastLoggedInUser)));
  assert(v.authIsAuthInfoEqual(JSON.stringify({type:'user', ...state.lastLoggedInUser}),
                             JSON.stringify({type:'user', ...state.lastLoggedInUser})));
  assert(!v.authIsAuthInfoEqual(JSON.stringify({type:'user', ...state.lastLoggedInUser}),
                              JSON.stringify({type:'env', host:'https://github.com',
                                              token:'synthetic-not-a-credential', envVar:'COPILOT_GITHUB_TOKEN'})));
  const fixture = JSON.parse(fs.readFileSync(root + '/config.json', 'utf8'));
  for (const [label, credential, retained] of [
    ['object', {token:'synthetic-not-a-credential'}, true],
    ['expiry', {token:'synthetic-not-a-credential', expiresAt:'2099-01-01T00:00:00Z'}, true],
    ['string', 'synthetic-not-a-credential', false],
    ['empty', {token:''}, false],
    ['invalid-expiry', {token:'synthetic-not-a-credential', expiresAt:'tomorrow'}, false],
  ]) {
    const directory = root + '/' + label;
    fs.mkdirSync(directory);
    fs.writeFileSync(directory + '/config.json', JSON.stringify({...fixture,
      authTokens:{'https://github.com:fixture-bob':credential}}));
    const loaded = await v.globalStateLoadForContext({...context, configDir:directory});
    const value = loaded.authTokens?.['https://github.com:fixture-bob'];
    assert.equal(value !== undefined, retained);
    if (retained) assert.deepEqual(JSON.parse(JSON.stringify(value)), credential);
    console.log('STEP credential ' + label + ' retained=' + retained);
  }
  console.log('PASS native serialization: config fallback retains token objects and UTC expiry; drops raw strings, empty tokens and invalid expiry');
  console.log('PASS native: last-sign-in metadata roundtrip; env token does not change that read; raw binding retains empty authTokens unlike RPC schema; user/env identities differ');
}).catch(() => {console.error('FAIL isolated native assertions; raw output withheld'); process.exitCode=1;});
"""


def regular_bytes(path, limit):
    """Reject links/FIFOs before consuming package or fixture bytes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("expected a regular file")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file exceeds probe limit")
        return data


def schema_checks(package):
    manifest = json.loads(regular_bytes(package / "package.json", 16384))
    version = manifest["version"]
    if PINS.get(version) != manifest.get("buildMetadata", {}).get("gitCommit"):
        raise ValueError("unsupported version/build; review public code before adding a pin")
    raw = regular_bytes(package / "schemas/api.schema.json", 8 * 1024 * 1024)
    definitions = json.loads(raw)["definitions"]
    user, env = definitions["UserAuthInfo"], definitions["EnvAuthInfo"]
    assert user["required"] == ["type", "host", "login"]
    assert "token" not in user["properties"]
    assert set(env["required"]) == {"type", "host", "token", "envVar"}
    assert definitions["LoggedInUser"]["required"] == ["host", "login"]
    state = definitions["GlobalStateLoadResult"]["properties"]
    assert state["lastLoggedInUser"]["description"] == "Account used for the most recent sign-in."
    assert "authTokens" not in state
    assert definitions["AuthReadQuery"]["stability"] == "experimental"
    active = definitions["AuthReadValue"]["anyOf"][0]["properties"]
    assert active["authInfo"]["$ref"] == "#/definitions/AuthIdentity"
    assert "token" not in definitions["AuthIdentity"]["properties"]
    result = definitions["GitHubTokenAcquireResult"]["anyOf"][0]
    assert result["properties"]["expiresIn"]["minimum"] == 3601
    assert "expiresIn" in result["required"]
    print(f"PIN version={version} commit={PINS[version]} schema_sha256={hashlib.sha256(raw).hexdigest()}")
    print("PASS schema: user/env distinction; last-sign-in is not active-account contract; explicit SDK expiry callback")


def isolation_profile(root, protected, node):
    """Only the executable itself may override a protected-home read deny."""
    if any(root.is_relative_to(path) or path.is_relative_to(root) for path in protected):
        raise ValueError("temporary grant overlaps protected storage")
    return (
        '(version 1)\n(allow default)\n'
        '(deny network*)\n(deny mach-lookup)\n(deny process-fork)\n'
        + ''.join(f'(deny file-read* file-write* (subpath {json.dumps(str(path))}))\n'
                  for path in protected)
        + '(deny file-read* file-write* (subpath "/Library/Keychains"))\n'
        + f'(allow file-read* (literal {json.dumps(str(node))}))\n'
        + f'(allow file-read* file-write* (subpath {json.dumps(str(root))}))\n'
    )


def layout_checks(root, protected, node, env):
    """Exercise the former broad grants against synthetic credential canaries."""
    script = root / "layouts.cjs"
    script.write_text(
        "const fs=require('node:fs'),assert=require('node:assert/strict');"
        "try{for(const p of process.argv.slice(2))assert.throws(()=>fs.readFileSync(p));}"
        "catch{console.log('FAIL canary was readable');process.exit(1);}"
        "console.log('PASS protected synthetic home canaries');"
    )
    node_bytes = regular_bytes(node, 256 * 1024 * 1024)
    fake_home = protected / "home"
    canaries = []
    for directory in (fake_home, fake_home / ".local", fake_home / "Library/Caches/copilot/pkg"):
        directory.mkdir(parents=True, exist_ok=True)
        canary = directory / "synthetic-credential"
        canary.write_text("synthetic-only")
        canaries.append(str(canary))
    for relative in ("bin/node", ".local/bin/node"):
        executable = fake_home / relative
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(node_bytes)
        executable.chmod(0o700)
        sibling = executable.parent / "synthetic-credential"
        sibling.write_text("synthetic-only")
        profile = root / "layouts.sb"
        profile.write_text(isolation_profile(root, [protected, Path.home().resolve()], executable))
        result = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(profile), str(executable), str(script),
             *canaries, str(sibling)], env=env, cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15,
        )
        if result.returncode or result.stdout.strip() != "PASS protected synthetic home canaries":
            raise ValueError("synthetic home layout isolation failed; raw output withheld")
        # A regression to the old inferred root must make these canaries fail.
        profile.write_text(profile.read_text() +
                           f'(allow file-read* (subpath {json.dumps(str(executable.parent.parent))}))\n')
        regression = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(profile), str(executable), str(script), *canaries],
            env=env, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=15,
        )
        if regression.returncode != 1 or regression.stdout.strip() != "FAIL canary was readable":
            raise ValueError("canaries did not detect the previous broad-grant regression")
        profile.write_text(isolation_profile(root, [protected, Path.home().resolve()], executable) +
                           f'(allow file-read* (subpath {json.dumps(str(fake_home))}))\n')
        package_overlap = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(profile), str(executable), str(script), *canaries],
            env=env, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=15,
        )
        if package_overlap.returncode != 1 or package_overlap.stdout.strip() != "FAIL canary was readable":
            raise ValueError("canaries did not detect a package grant overlapping home")
    print("PASS layouts: ~/bin and ~/.local/bin execute; node siblings, home and package-parent canaries denied")
    print("PASS regression: old inferred subtree grants reopen synthetic canaries and fail assertions")


def isolated_native(package, node):
    if platform.system() != "Darwin":
        raise ValueError("native experiment requires macOS Seatbelt")
    if not TEMP.is_dir():
        raise ValueError("approved temporary parent is unavailable")
    addon = package / "prebuilds/darwin-arm64/runtime.node"
    addon_bytes = regular_bytes(addon, 128 * 1024 * 1024)
    digest = hashlib.sha256(addon_bytes).hexdigest()
    with tempfile.TemporaryDirectory(prefix="copilot-contract-", dir=TEMP) as temporary, \
            tempfile.TemporaryDirectory(prefix="copilot-contract-denied-", dir=TEMP) as denied:
        root = Path(temporary).resolve()
        canary = Path(denied) / "synthetic-canary"
        canary.write_text("synthetic-file-must-be-unreadable")
        isolated_addon = root / "runtime.node"
        isolated_addon.write_bytes(addon_bytes)
        home, config = root / "home", root / "config"
        home.mkdir()
        config.mkdir()
        fixture = {"lastLoggedInUser": {"host": "https://github.com", "login": "fixture-bob"},
                   "loggedInUsers": [{"host": "https://github.com", "login": login}
                                     for login in ("fixture-alice", "fixture-bob")],
                   "authTokens": {}}
        (config / "config.json").write_text(json.dumps(fixture))
        link, fifo = root / "link", root / "fifo"
        link.symlink_to(config / "config.json")
        os.mkfifo(fifo)
        for path in (link, fifo):
            try:
                regular_bytes(path, 16384)
            except (OSError, ValueError):
                continue
            raise ValueError("fixture reader accepted a symlink or FIFO")
        print("PASS fixture reader: symlink and FIFO refused without blocking")
        script = root / "check.cjs"
        script.write_text(NATIVE_CHECK)
        profile = root / "isolation.sb"
        real_home = Path.home().resolve()
        profile.write_text(isolation_profile(root, [real_home, Path(denied).resolve()], node))
        env = {"HOME": str(home), "COPILOT_HOME": str(config),
               "PATH": "/usr/bin:/bin", "TMPDIR": str(root),
               "XDG_CONFIG_HOME": str(home), "XDG_CACHE_HOME": str(home),
               "GH_CONFIG_DIR": str(home / "gh"),
               "COPILOT_GITHUB_TOKEN": "synthetic-not-a-credential"}
        layout_checks(root, Path(denied).resolve(), node, env)
        command = ["/usr/bin/sandbox-exec", "-f", str(profile), str(node), str(script),
                   str(isolated_addon), str(config), str(canary)]
        with subprocess.Popen(command, env=env, cwd=root, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, start_new_session=True) as child:
            try:
                stdout, _ = child.communicate(timeout=30)
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
        for line in stdout.splitlines():
            if line.startswith(("STEP ", "PASS native")):
                print(line)
        if child.returncode or "PASS native:" not in stdout:
            raise ValueError("isolated native check failed; raw output withheld")
        print(f"PIN runtime_sha256={digest}")
        print("PASS isolation: outside-fixture read, subprocesses and TCP connect denied; home denied except exact Node file; all Mach lookup denied")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True, help="public extracted program directory")
    parser.add_argument("--node", type=Path, help="absolute installed Node path; enables isolated native checks")
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    schema_checks(package)
    if args.node:
        if not args.node.is_absolute():
            parser.error("--node must be absolute")
        isolated_native(package, args.node.resolve(strict=True))
    print("BLOCKED extraction: secure-store serialization, authoritative active selection and standalone renewal unproven")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"FAIL: {type(error).__name__}; contract check did not pass") from None
