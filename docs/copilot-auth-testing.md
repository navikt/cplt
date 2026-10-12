# Copilot authentication acceptance tests

Use the existing macOS account for credential-denial probes below. A temporary
`HOME` does **not** isolate the login Keychain, so the probe also denies credential
access in Seatbelt. It does not log the user out or change stored credentials.

Tests that change credentials, revoke tokens, switch accounts or modify Keychain
settings need a disposable account, or an explicitly agreed interactive session
with the existing user and a tested re-login path. Credential denial proves
missing/unreachable-credential behavior, not logout, revocation or renewal.

Record the cplt, nav-pilot, Copilot and gh versions, OS version, selected standalone
Copilot path, credential source, GitHub host/account, and pass/fail evidence for
each case. Do not record tokens, device codes, private prompts, or raw debug logs.
Repeat on the reported Copilot 1.0.86 and the supported current version. A result
on one version is not evidence for the other.

## Automated checks

```sh
mise run check
CPLT_TEST_REQUIRE_SANDBOX=1 mise run test:e2e-projects
python3 hack/test-probe-copilot-no-auth.py
```

`copilot_auth_handover_keeps_keychain_only_without_a_substitute` uses an isolated
home, gh configuration and fake Copilot. It proves token forwarding, no token in
launch output, and kernel-enforced file read/write behavior for the Keychain
directory with substitution on/off and with no credential. It does not prove
Keychain API enforcement, OAuth sign-in, token validity, account choice or renewal.

The offline probe checks verify timeout cleanup kills the process group and reaps
the child, and that the persistence scan skips symlinks/FIFOs and detects a token
across read boundaries. They do not run Copilot or retrieve credentials.

## Baseline and reported failure

### Simulate unavailable credentials with the existing user

```sh
mise run build
python3 hack/probe-copilot-no-auth.py --cplt target/debug/cplt --copilot /opt/homebrew/bin/copilot
python3 hack/probe-copilot-no-auth.py --cplt target/debug/cplt --copilot /opt/homebrew/bin/copilot --interactive
```

Use the absolute standalone Copilot path from doctor. The probe clears the
environment, uses temporary Copilot/XDG/gh state, denies read/write access to the
real home and `com.apple.securityd`, and denies executing gh. Only the two selected
executables receive literal read exceptions if installed under the real home. Extraction
and profile generation run under those restrictions too. macOS refuses nested
`sandbox-exec`, so the real CLI runs under one generated cplt profile with the
extra credential denies appended. This tests the CLI/profile, not the full
cplt launch pipeline. The default mode performs no authenticated model request.

The interactive probe uses Python's PTY support. It accepts only the trust prompt
for its empty temporary project, then observes sign-in guidance and interrupts
the CLI. It neither completes OAuth nor accepts plaintext storage. If a prompt
changes or startup times out, the probe fails rather than claiming success.

Observed on macOS on 2026-10-12 with isolated Copilot **1.0.94-5**:

| Probe | Result |
| --- | --- |
| Headless request | Exit 1, `Error: No authentication information found.` Recovery mentions `/login`, token env variables and `gh auth login`. |
| Interactive startup | Empty-project trust prompt, then sign-in guidance. No automatic plaintext-storage offer observed before sign-in. |

The existing home reported **1.0.95**; the empty home extracted **1.0.94-5** from
the same executable. Always record the version actually used in the isolated
run. This is not evidence for the reported **1.0.86**, secure token persistence,
or the vault prompt after completing OAuth.

### Existing gh login with empty Copilot state

```sh
python3 hack/probe-copilot-no-auth.py --cplt target/debug/cplt --copilot /opt/homebrew/bin/copilot --authenticated-gh
python3 hack/probe-copilot-no-auth.py --cplt target/debug/cplt --copilot /opt/homebrew/bin/copilot --authenticated-gh --interactive
python3 hack/probe-copilot-no-auth.py --cplt target/debug/cplt --copilot /opt/homebrew/bin/copilot --authenticated-gh --interactive --startup-only
python3 hack/probe-copilot-no-auth.py --cplt target/debug/cplt --copilot /opt/homebrew/bin/copilot --authenticated-gh --interactive --startup-only --isolation-only
```

`--authenticated-gh` explicitly retrieves the existing stored github.com token
through gh in cplt's trusted macOS binary directories. It checks the resolved
binary's trusted prefix, pins `--hostname github.com`, and supplies a small host
environment without any of the three token overrides. It does not query Copilot
credentials. The token stays in memory and is passed as `GH_TOKEN` only after
runtime extraction and profile generation. It is never an argument or printed.

Both modes start with empty Copilot state and retain the real-home, Keychain and
child-gh denies. Headless mode requires exit 0 and the exact model response
`CPLTAUTH7429`. The prompt describes that answer in separate pieces, so merely
echoing the prompt cannot pass. Interactive mode uses a PTY, accepts only the
empty-project trust prompt, queries `/user show`, and requires the same answer
after submitting a normal prompt. It answers cursor-position, keyboard-protocol,
terminal-identification and foreground/background color queries. It waits for
the trust menu, interactive input and echoed pasted text before pressing Enter.
`--startup-only` requires `/user show` to confirm github.com authentication and
sends no model prompt. Only the assertion is printed; the account name is withheld.
`--isolation-only` compares standalone startup under the credential denies without
the generated cplt profile. It still denies real-home and Keychain access.
Built-in MCP servers
are disabled in interactive mode to keep this a model-authentication probe.
No `/login`, `/logout`, account switch or OAuth completion is performed.

Raw child output is withheld, including on failure. The probe scans only its
temporary files for the injected token and fails if it was persisted. That check
also runs after an authenticated timeout or interactive failure. Processes are
terminated and reaped, and temporary state is removed. This establishes absence
of the exact injected token in the probe tree, not absence of every possible
derived credential or a Security framework read/write test.

Observed on **2026-10-12**, macOS **26.7.1**, build **25G241**, cplt **0.0.0**
from `target/debug/cplt`, gh **2.102.0**, standalone executable
`/opt/homebrew/bin/copilot`, isolated Copilot **1.0.94-5**:

| Probe | Result |
| --- | --- |
| Authenticated headless | PASS. Exit 0 and exact expected model response. Injected token absent from probe-created files and captured stdout/stderr. |
| Original authenticated interactive | Inconclusive. The Expect observer with `-i` reached the trust prompt but did not recognize a response within 90 seconds. This was not an authentication failure diagnostic. |
| Authenticated interactive `/user show`, generated profile | PASS. Trust menu approved, interactive input reached, `/user show` submitted and github.com sign-in confirmed. Token absent from probe-created files. |
| Authenticated interactive `/user show`, isolation-only profile | PASS. Same sequence and sign-in assertion without the generated cplt profile. Token absent from probe-created files. |
| Normal interactive model prompt, diagnostic round | Two submissions only. `/user show` confirmed sign-in; the prompt appeared, but no answer was recognized. No further model requests were made. The later observer waits for echoed input before Enter; its model-response path has not been retested under this request limit. |
| No-auth headless rerun | PASS. Exit 1 with `Error: No authentication information found.` |
| No-auth interactive rerun | PASS. Empty-project trust prompt followed by sign-in guidance. |

Interactive sign-in is now established for a gh-derived token both with and
without the generated profile. The model-response timeout remains inconclusive:
the previous observer did not wait for pasted input to render before Enter and
its earlier regex could consume terminal-query bytes. Neither the old timeout
nor the two diagnostic submissions establishes a product bug. The headless
result proves one request with a gh-derived token under the generated profile;
it does not prove cplt's handover wiring, nav-pilot, account selection, long-session
renewal, or Copilot-stored credential handoff. One diagnostic `/user show` screen
exposed account metadata, not credentials; repeatable output now withholds the
account name. Full cplt launch is not compared here: macOS rejects nesting its
Seatbelt launch under the outer credential-isolation profile. The existing-home
**1.0.95** runtime was inspected as installed code and with `login --help`, not
used for an existing-state model request.

### Browser launch and host recovery

On macOS, generated profiles start with `(deny default)` and omit
`(allow lsopen)` unless `allow_browser` is enabled. See
`src/sandbox_profile.rs:958-999`. `/usr/bin/open` itself can execute; the restricted
operation is Launch Services opening the target. Direct CoreServices callers use
the same operation. This is a profile mechanism, not a measurement of the reported
nav-pilot session's effective configuration. `--allow-browser` grants unscoped
Launch Services, allowing applications to start outside the sandbox; it is not
a URL-only grant.

Installed `copilot login --help` confirms that local desktops default to a browser
flow with a loopback callback, and `--device-code` forces a device flow. A copied
URL from a web flow still belongs to that flow and its originating process;
copying it does not turn it into a device flow. Cmd-click, OSC hyperlinks, text
selection and IntelliJ's link detection are terminal/IDE behavior. Failure to
recognize or open a clicked link is not evidence of a kernel clipboard or URL-copy
restriction.

For a user whose sandboxed `/login` cannot open a browser, run authentication in
a normal host terminal, then restart nav-pilot:

```sh
(
  unset COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN GH_HOST GH_REPO
  gh auth login --hostname github.com --web &&
    gh auth status --hostname github.com &&
    nav-pilot --client copilot
)
```

The subshell preserves the caller's environment and keeps inherited token and
host/repository overrides out of both login and restart. Before restarting,
optionally check the account with `gh api --hostname github.com user --jq .login`
and confirm `gh auth status` reports secure credential storage, within that same
subshell. Do not print a token.

Complete that login as the user and retain secure credential storage. The probe
validated that an existing gh login supplies a token accepted by headless Copilot
and by interactive `/user show` with Keychain denied. The exact nav-pilot handover
and a restarted interactive model request remain separate acceptance checks.
Do not run `/login` again merely because the sandbox cannot open a browser.

For direct Copilot host authentication with a manually opened device URL:

```sh
(
  unset COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN GH_HOST GH_REPO
  /opt/homebrew/bin/copilot login --device-code
)
```

Use the standalone path from doctor if different. This recovery syntax and flow
are validated by installed public help, not by completing OAuth in this session.
No login, logout, OAuth completion or real credential write was performed during
the diagnostic round. A host Copilot login also does not prove that a sandbox
with Keychain denied can use Copilot's stored credential; gh-token handover is
the path actually tested here.

### Incident-only full-pipeline preflight and cancellation

```sh
python3 hack/probe-copilot-no-auth.py --cplt /opt/homebrew/bin/cplt --copilot /opt/homebrew/bin/copilot --authenticated-gh --full-launch --nav-pilot /opt/homebrew/bin/nav-pilot
python3 hack/probe-copilot-no-auth.py --cplt /opt/homebrew/bin/cplt --copilot /opt/homebrew/bin/copilot --cancel-launch
```

Observed on 2026-10-12 with installed cplt
**2026.10.08-190103-d4ae77a**, nav-pilot **2026.10.08-185134-97d6749**,
commit `97d67490e585d0ab6ecb634ce4855acac28fd230`, and the same standalone
Copilot executable extracting **1.0.94-5** into the empty home. cplt resolved to
`/opt/homebrew/Cellar/cplt/2026.10.08-190103-d4ae77a/bin/cplt`; nav-pilot resolved
to `/opt/homebrew/Cellar/nav-pilot/2026.10.08-185134-97d6749/bin/nav-pilot`.

| Stage | Actual evidence |
| --- | --- |
| Copilot extraction | Real executable, empty temporary home, outer credential-denial profile, `--no-auto-update --version`. |
| Installed cplt full-launch profile | Generated with `keychain_substitute = true`, synthetic token-presence marker, gh guard and scratch disabled, `--deny-path` for the real home and actual Keychains directory. No real token retrieved. |
| Keychain API isolation gate | BLOCKED. Profile still allows `mach-lookup` broadly and has no `com.apple.securityd` deny. File denies alone do not establish that the existing login Keychain is unreachable through the service. No supported CLI/config setting supplies that deny. |
| Installed nav-pilot empty-state gate | Actual `nav-pilot --client copilot -- --version` exited 2 with `nothing is installed`, before cplt launch. `NAV_PILOT_CONFIG` named a temporary config with `auto_update = false`; telemetry was disabled. No fabricated install state, package installation or sync. |
| Full cplt confirmation cancellation | Actual installed cplt reached `[y/N]`; the PTY sent `n`. Observed `Aborted by user` and nonzero exit before agent launch. No token retrieval, login command or OAuth initiation. |

No paid model requests were made in this round. The full cplt and nav-pilot model
chains remain **unverified**, not failed authentication tests. An outer
`securityd` denial cannot be combined with cplt's own Seatbelt launch because
macOS rejects nested sandbox profiles. Passing an explicit valid token bypasses
the resolver's stored-token lookup, but does not enforce the missing service
deny. A real full-launch probe must stop here until that isolation can be supplied
by the launched profile, or use a disposable OS account.

The probe's `--full-launch` gate runs before real-token retrieval. Its optional
`--nav-pilot` check only observes the empty install gate; it is not evidence that
nav-pilot invoked cplt. `--cancel-launch` proves cplt launch cancellation, not
cancellation of an OAuth flow or the vault-storage prompt.

On an affected user's **already installed** setup, a manual one-command smoke
test in a normal host terminal can exercise each real chain with the existing
credential. Run at most one request per chain, approve only the cplt launch
confirmation, and cancel if a new login or storage prompt appears:

```sh
(
  unset COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN GH_HOST GH_REPO
  cplt --agent copilot -- --no-auto-update --disable-builtin-mcps -s -p "Reply with OK only. Do not use tools."
)
```

```sh
(
  unset COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN GH_HOST GH_REPO
  nav-pilot --client copilot -- --no-auto-update --disable-builtin-mcps -s -p "Reply with OK only. Do not use tools."
)
```

These manual commands use the user's normal installed state; they do not claim
Keychain isolation. Record versions, the effective credential source from cplt's
summary, exit status and `OK`. Do not export or print a token, run `/logout`, or
claim a fresh host login occurred. The evidence above used existing credentials
only in earlier authorized probes.

### Installed-code and documentation contract

Inspected the public installed package files under
`~/Library/Caches/copilot/pkg/darwin-arm64/{1.0.94-5,1.0.95}/`, specifically
`package.json`, `cli-main.js` and bundled native modules. No `~/.copilot` auth
files or Copilot Keychain secrets were read. The 1.0.94-5 package records build
commit `fdeb5949`.

| Question | Established | Still unknown |
| --- | --- | --- |
| Supported environment handoff | Bundled help and GitHub's command reference specify `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, then `GITHUB_TOKEN`. Explicit env tokens take precedence over stored credentials. Headless `GH_TOKEN` worked in the probe. | Whether a particular stored Copilot credential can be passed unchanged through those variables. |
| Stored representation | GitHub documents an authentication token in the system credential store. The JS delegates core GitHub authentication to native `ProcessAuthHandle`; native strings identify `copilot-cli`, `loggedInUsers` and `lastLoggedInUser`. | The exact Keychain value format, encoding, selected-account schema, expiry fields and refresh material. Binary strings do not prove these. |
| Renewal | Native strings include cached-user refresh and credential-rotation paths. | The Copilot GitHub base-token/API-token renewal contract, renewal timing, and whether env handoff preserves renewal. No renewal boundary was observed. |
| Account selection | Explicit environment-token precedence is documented. Interactive JS tracks a `selectionId` and uses `expectedSelectionId` when refreshing models after a user switch. | Which persisted account is active among several Keychain items, and the effects of `/user switch`, `/login` or `/logout` with an injected token. |
| Vault failure | Readable JS offers plaintext storage after secure storage cannot be accessed and says declining cancels sign-in without changing account state. | The actual prompt after completed OAuth with this denied profile; OAuth was not completed. |

The readable `getPassword`/`setPassword` and `refresh_token` code in
`cli-main.js` includes Microsoft authentication persistence. It is not evidence
that Copilot's GitHub Keychain item is a raw token, an MSAL cache, or a refreshable
JSON credential. MCP OAuth refresh paths likewise do not prove GitHub model-token
renewal. There is no established stored-credential extraction contract yet.

Sources, accessed 2026-10-12:

- [GitHub Copilot CLI command reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference), `copilot login` and environment authentication.
- [GitHub Copilot CLI README](https://github.com/github/copilot-cli/blob/main/README.md), fine-grained PAT with `Copilot Requests` permission.
- Installed `cli-main.js`, environment help and interactive account-switch handling. The installed help also documents a Codespaces exception for auto-injected `GITHUB_TOKEN`; explicit token variables still take precedence.

### Authenticated lifecycle tests

In the disposable account, authenticate gh on the host with secure storage. Check
the account, then try a normal prompt without invoking `/login`:

```sh
(
  unset COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN GH_HOST GH_REPO
  gh auth login --hostname github.com --web &&
    gh auth status --hostname github.com &&
    gh api --hostname github.com user --jq .login &&
    cplt doctor --agent copilot &&
    cplt --agent copilot -- -p "Reply with OK only" &&
    cplt --agent copilot
)
```

These are procedures for the disposable account, not completed OAuth evidence.
The subshell preserves the caller's environment. Confirm secure storage from
`gh auth status` before continuing; cancel any plaintext-storage offer.

Repeat through nav-pilot. Record whether the vault prompt appears automatically
or only after `/login`, and the error immediately before it. Cancel the plaintext
storage offer. Use the standalone Copilot executable's absolute path to test
outside cplt; shell aliases and PATH shims can otherwise run cplt again.
For the same-token comparison, keep all five variables above unset while
retrieving gh's stored token, then set only `GH_TOKEN` for the standalone
command. An inherited `COPILOT_GITHUB_TOKEN` would override it.

## Required lifecycle evidence

| Case | Acceptance criterion |
| --- | --- |
| No gh or Copilot login | Current cplt keeps the Keychain grant. Host sign-in stores credentials securely; ordinary startup afterward answers a prompt. |
| gh login only | Current macOS cplt passes the gh token, removes the Keychain grant and answers a prompt without a new sign-in. |
| Copilot login only | Current cplt keeps the Keychain grant and Copilot uses its stored login. |
| gh Alice, Copilot Bob | Record the actual identity. A proposed Copilot-first handover must keep Bob and leave gh/git as Alice. |
| Multiple Copilot accounts | The selected account is explicit and stable across restart. A matching stored item alone is insufficient. |
| Enterprise host | Account and host stay paired; no implicit switch to github.com. |
| Stale/revoked token | Failure names the credential source and host-side recovery. No silent switch or plaintext fallback. |
| Locked Keychain, denied ACL, cancelled prompt | No credential leak or hang; recovery distinguishes storage failure from GitHub rejection. |
| Long interactive session | Continue through an observed Copilot API/session-token renewal; record timestamps and successful requests before/after. Test base-token expiry separately if applicable. |
| `/login`, `/user switch`, `/logout` | Record storage, active identity and next-launch effects with an injected token. Do not assume these commands override env authentication. |
| Host logout during a session | Record existing-session and restart behavior. Local credential removal is not server-side revocation. |
| gh/git | Guarded `gh api user` and an HTTPS push to a disposable feature branch use the intended gh identity. |
| MCP OAuth | Existing login, first login and renewal have an explicit outcome without a Keychain grant. |
| Linux | Repeat handover and recovery with the Secret Service masked; macOS substitution is not a Linux implementation. |

## Before implementing Copilot Keychain extraction

Establish the secret representation using the disposable credential only, without
printing it. Determine whether it is a raw token or a structured credential, its
expiry/refresh contract, and the supported handoff for the pinned Copilot version.
Current one-shot gh-token evidence does not establish this contract.

Use a disposable Keychain with a dummy `copilot-cli` item to test the actual
Security framework read **and write** APIs. Prove both work outside the sandbox
and fail inside the denied profile. A file-read probe does not settle API access.
Keep search-list/default-Keychain changes confined to the disposable OS account.

For a proposed handover, run the lifecycle matrix with `COPILOT_GITHUB_TOKEN` and
separate gh credentials. Also cover both nav-pilot launch paths, auth modes,
`deny.env`, guard-off behavior, malformed metadata, symlinks and FIFOs. Ship opt-in
until the evidence satisfies the staged-rollout rules in `AGENTS.md`.
