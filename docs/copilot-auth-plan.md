# Copilot host-auth implementation plan

Updated 2026-10-12. Target: Copilot persists its selected credential securely on
the host. cplt retrieves that credential before launch and passes it as
`COPILOT_GITHUB_TOKEN`, without granting the agent broad Keychain access.
The credential and refresh contract must be proven before extraction is
implemented or the new behavior becomes a default.

Incident packaging draft: [#757](https://github.com/navikt/cplt/pull/757).

## Status ledger

Statuses describe evidence, not effort. Close a milestone only when its gate has
recorded results. Append versions, commands, sanitized outcomes and review links
here as work progresses; never include credentials or raw auth logs.

| Milestone | Status | Evidence or remaining gate |
| --- | --- | --- |
| M1 Reproduction and credential contract | Basic auth verified; public-code research recorded | No-auth probes, valid-gh headless request and interactive `/user show` pass on isolated 1.0.94-5. Contract document records different env/stored representations; exact selection, serialization and renewal remain unproven. |
| M2 cplt opt-in implementation | Future extraction blocked by M1; incident fixes implemented | Doctor/cache corrections use bounded host-pinned, env-cleared lookup, shared config-path resolution and effective denied-env handling on all backends. Selected Copilot-store extraction remains planned. |
| M3 nav-pilot modes and onboarding | Incident candidate implemented and checked | All three CLI review blockers fixed; Go checks, 93 script cases and budget checks pass. No insecure advice; clean five-variable recovery commands and `env_only`/`gh_only` warnings. Host OAuth/restart acceptance remains open. |
| M4 Automated and live acceptance | Checks pass; full-chain/live limits recorded | 414 unit, 1586 lib, 178 guard and 13 hardening tests pass. Basic auth verified; prelaunch cancellation passes. Full-chain probe stopped before real token; zero paid prompts in the final round. Full lifecycle remains open. |
| M5 Site and user documentation | Guide source ready; unpublished | Site 801 checks and smoke pass; browser anchor in generated inventory. Four auth-doc issues fixed, including recovery injection and prior-setting restoration. Safe existing-user no-tools smoke commands documented. |
| M6 Independent review and staged rollout | Incident review blockers fixed; promotion pending | Available general agents used because explicit model selection was unavailable. Three CLI blockers and four auth-doc issues fixed. Host acceptance and future #264 promotion evidence remain required. cplt incident packaging is authorized as a draft PR. |

Latest cross-repository results above are supplied by the coordinating agents.
Public/installed-code research is recorded in
[copilot-auth-contract.md](copilot-auth-contract.md), without credential reads.
nav-pilot host-side recovery is implemented and checked.

### Immediate incident release readiness

Basic gh-token account auth, doctor/cache corrections, serial regression checks
and site/browser guidance are verified. The incident candidate is implemented
and checked, with reported CLI and auth-doc review blockers fixed. Host OAuth,
secure persistence and restart acceptance remain open. Guide source is ready but
unpublished. cplt incident packaging is authorized as a draft PR. The full credential
lifecycle is not complete.

Interactive `/user show` establishes account auth. Interactive model output is
separate and remains unverified under the two-request cap; the harness correction
has only synthetic verification. Do not treat that gap as failure of the passing
basic account-auth check. Future secure-store extraction and default promotion
remain gated on M1/M4 lifecycle evidence and #264.

## Immediate priority: validated host-side recovery

New Slack reports describe `/login` in nav-pilot failing to open a browser after
Homebrew updates. Copying the URL behaves differently from Cmd-click and from
IntelliJ. Host GitHub terminal login reportedly helps, but the exact CLI command
and versions are unknown. Whether the reporter used `gh` is still unknown.

Browser launch through `lsopen` is denied by default unless `--allow-browser`
is enabled; this is the documented mechanism. Terminal hyperlink handling is
outside the kernel sandbox. These findings explain the mechanisms but do not
establish the exact cause of each Slack report.

Record the actual standalone executable/version, nav-pilot path, terminal/editor,
prompt source and attempted browser action. Validate a host-side sign-in and
restart path with the user, including secure persistence and the intended
identity. Do not prescribe the reported terminal-login workaround as proven
recovery until its exact command and outcome are known.

Onboarding acceptance now requires:

- The default path completes sign-in without manual terminal-link hacks.
- Prompts identify the tool/source and give a useful next action when browser
  opening or storage fails.
- The user can cancel without accepting plaintext storage or losing the existing
  login. Restart after successful host recovery reaches an authenticated request.

These recovery gates take priority over future secure-store extraction.
Recovery guidance now includes clean commands clearing all five auth-affecting
variables, explicit `env_only`/`gh_only` warnings, injection where needed and
restoration of the prior setting. It contains no insecure-storage advice.

## Current evidence and limits

The source of lifecycle requirements and reproduction commands is
[copilot-auth-testing.md](copilot-auth-testing.md).

- On macOS on 2026-10-12, isolated Copilot **1.0.94-5** exited 1 headlessly with
  `Error: No authentication information found.` Recovery mentioned `/login`,
  token environment variables and `gh auth login`.
- Interactive startup showed the empty-project trust prompt and sign-in guidance.
  No automatic plaintext-storage offer appeared before sign-in. The probe did
  not complete OAuth or make an authenticated model request.
- Both no-auth probes pass. An authenticated headless request with a valid gh
  token, empty state and Keychain denied passes on **1.0.94-5**. Authenticated
  interactive `/user show` also passes with the gh token under both the generated
  cplt profile and isolation-only profile. Basic account auth is verified.
- Interactive model prompt response remains unverified under the two-request
  cap. The harness fix has synthetic verification only. This is not an open
  basic account-auth failure, and none of these checks proves live OAuth renewal.
- The existing home reported **1.0.95**; the same executable extracted
  **1.0.94-5** with an empty home. Neither result reproduces **1.0.86**.
  The fake agent advertising `1.0.86` is not real-version evidence.
- The probe clears environment/state and denies real-home access, securityd and
  gh execution. A temporary `HOME` alone does not isolate the login Keychain.
  macOS prohibits nested `sandbox-exec`, so the probe runs the CLI under one
  generated cplt profile plus credential denies, not the full launch pipeline.
- There is **no live OAuth renewal evidence**. A one-shot request with a gh token
  does not prove secure Copilot persistence, base-token lifetime, refresh-token
  handling, or long-session renewal with an injected Copilot credential.
- The final full-chain probe stopped before passing a real token. The generated
  profile's broad Mach service grants prevented required isolation through the
  supported flag; nested SBPL execution is forbidden. This is a probe limitation,
  not a failed authenticated full-chain run.
- Installed nav-pilot with empty state had no package and exited 2. That does not
  establish auth behavior of a functioning installed launch chain. The final
  round used **zero paid prompts**.
- cplt's y/n cancellation check passes with prelaunch `aborted`. This proves
  prelaunch cancellation only, not OAuth cancellation. Safe manual cplt/nav-pilot
  no-tools smoke commands for the existing normal user are documented in the
  acceptance guide; host OAuth/restart acceptance is still open.

### Public-code contract findings

[copilot-auth-contract.md](copilot-auth-contract.md) records version-scoped
evidence from 1.0.86, 1.0.94-5 and 1.0.95 program artifacts, without credential
reads. Env auth and stored user auth use different representations.
`activeAccount` is experimental; `lastLoggedInUser` is not authoritative current
selection. Secure-store secret serialization remains unproven.

The SDK has a renewable token-provider callback. This does not guarantee renewal
of a standalone env token or Copilot API/session token. Extraction remains gated
on selection, serialization and renewal together; do not implement it by guessing
from item names, last-login metadata or SDK behavior.

The resolver still does not implement the target secure-store contract.
Doctor/cache corrections are now implemented: bounded,
host-pinned, env-cleared gh lookup honors `GH_CONFIG_DIR` and XDG config selection
through `XDG_CONFIG_HOME`; effective denied-env handling is fixed on all backends.

| Code | Current behavior |
| --- | --- |
| `src/agent.rs`, `keychain_substitute_env_vars` | Explicit Copilot token order is `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`; denied and blank values do not qualify. The comment records a one-shot gh-token probe on 1.0.89. |
| `src/sandbox.rs`, `keychain_substitute` | Uses explicit env first, then stored gh token on macOS. It does not extract Copilot's stored secret. No substitute keeps the broad Keychain grant. |
| `src/sandbox.rs`, `copilot_keychain_acct` | Reads attributes for service `copilot-cli`, trying the gh-matching account before any item. This is a mismatch guard, not proof of Copilot's selected account. Unknown account metadata currently permits gh substitution. |
| `src/sandbox_exec.rs`, `extract_gh_token` | Trusted gh executable, `github.com` pinned, token env stripped, bounded wait. This does not implement enterprise-host selection. |
| `src/sandbox_exec.rs`, injection/cache paths | Copilot handover and gh execution have several token channels. `COPILOT_GITHUB_TOKEN` alone does not authenticate gh; the gh exec cache must remain separate. |

`sandbox.keychain_substitute` is already default-on for Copilot and Claude.
The new Copilot-store resolver needs its own default-off gate; changing this
existing key's meaning would change working launches.

## Contract decisions

These are target requirements. M1 must establish the supported mechanism.

1. Resolve Copilot auth once per launch through the shared parent-side resolver.
   Both launch paths, doctor and summaries must agree on the result. Preserve
   effective explicit env precedence, then use the explicitly selected Copilot
   host/account, then permit gh fallback only when no Copilot selection exists.
2. A selected credential that is unavailable, locked, cancelled, malformed,
   expired or rejected is an error, not permission to try another account.
   Ambiguous selection also fails with host-side recovery. No silent identity
   switch, implicit enterprise-to-`github.com` fallback, or plaintext fallback.
3. Read only the exact selected secure-store item outside the sandbox. Do not
   choose the first matching item or the account that happens to match gh.
   Treat agent-writable selection metadata as untrusted; validate bounded regular
   files with `untrusted::read_untrusted`, including symlink/FIFO rejection.
4. Inject the selected Copilot credential only as `COPILOT_GITHUB_TOKEN`.
   Respect `deny.env`; a denied target must fail visibly rather than reroute the
   credential through `GH_TOKEN`, `GITHUB_TOKEN`, or a scratch cache. Diagnose
   incompatible config at the earliest point that can reject it.
5. Keep gh/git credentials and host selection independent. With gh Alice and
   Copilot Bob, Copilot remains Bob while guarded gh and HTTPS git use Alice.
   Never copy Bob's credential into gh caches or credential helpers. Record
   guard-off/no-scratch limitations and reject unsupported combinations rather
   than promise an identity that cannot be honored.
6. Persist credentials only in the host's secure store. cplt does not create a
   second plaintext store. Never print secrets, put them in argv, or expose them
   through profile output, doctor, errors or audit logs. An injected token is
   available to sandboxed descendants; this reduces vault access, not access to
   that token by the agent.
7. Prove whether the stored value is a raw base token or a structured refresh
   credential, how it expires, who renews it and where rotated values persist.
   Separately prove Copilot API/session-token renewal from the injected base
   token. If refresh needs vault writes, launch-time extraction alone is not
   sufficient. Approve a supported host recovery/refresh mechanism before M2.
8. Linux needs a proven host Secret Service handover with the session bus still
   masked, or an explicit unsupported outcome for the opt-in setting. macOS
   extraction is not evidence of Linux support. MCP OAuth needs its own outcome.

## Milestones and acceptance gates

### M1 Reproduce and prove the contract

- Run the documented missing-auth probes on real **1.0.86** and the supported
  current standalone version. Record the actual isolated version and executable.
- With user participation, verify host OAuth sign-in, secure persistence and
  ordinary startup inside/outside cplt and through nav-pilot. Record whether the
  vault offer appears automatically or only after `/login`; cancel plaintext.
- Determine selected-account/host metadata, exact item query, secret format and
  supported env handoff without printing a secret. Test multiple accounts and
  enterprise host pairing, including ambiguous or missing selection.
- Record the base-token expiry/refresh contract and live API/session-token
  renewal with timestamps and successful requests before/after. Document what
  `/login`, `/user switch` and `/logout` do when env auth is present.

Gate: versioned evidence explains the original failure and proves a supported
selected-credential handoff, secure persistence and renewal/recovery contract.
A sign-in prompt or successful one-shot request cannot close M1.

### M2 Implement cplt opt-in

- After M1, add a default-off config key through registry, resolution and
  validation. Name the key in this ledger when agreed. Reject unsupported
  platforms/settings at config-set or resolve time.
- Reuse the shared resolver and existing secret handling. Return source,
  host/account and distinct failure reasons alongside the secret, without
  serializing the secret into diagnostics. Bound secure-store access and cancel
  or time out safely.
- Wire resolver output through both launch paths and the prepared sandbox.
  Remove broad Keychain access in the new mode; missing auth directs host
  onboarding rather than silently restoring the grant. Keep gh/git channels
  independent and document descendant-env exposure in `SECURITY.md`.

Gate: target precedence and failure semantics have runnable tests; every config
key has a consumer. With the new key unset, profiles are byte-identical to the
previous release and launch behavior remains unchanged, demonstrated by a
baseline comparison. The opt-in path has tested one-step recovery.

### M3 nav-pilot modes and onboarding

Existing nav-pilot modes had 22 passing regression cases. Latest CLI verification
passes Go checks, 93 script cases and budget checks after all three review
blockers were fixed. Documentation clarifies exclusive modes and unsupported
combinations; `env_only`/`gh_only` warnings and clean five-variable recovery
commands are implemented without insecure advice.
This does not implement the future selected secure-store credential contract.
Host-side onboarding is implemented; live host OAuth/restart acceptance is open.

- Validate both launch paths against the browser-login reports and immediate
  recovery gates above. Record the exact host login command that succeeds.
- Onboarding runs standalone Copilot OAuth on the host with user participation,
  verifies secure persistence and selected host/account, then checks cplt launch.
  Explain Copilot identity separately from gh/git identity and explicit env
  overrides. Never recommend plaintext storage or broad Keychain access as the
  normal path.
- Diagnose missing login, locked/denied storage, invalid token and unsupported
  refresh with source-specific host commands. Reuse M1's proven recovery and
  test restart after onboarding and account selection.

Gate: both paths honor the same selected identity and mode; onboarding reaches
an authenticated sandboxed request with secure host persistence and no broad
vault grant. Existing users can recover without losing their stored login.
The default onboarding path needs no terminal-link hacks, prompts name their
source and useful action, and cancellation never requires plaintext storage.

### M4 Automated enforcement and live lifecycle

Existing checks include profile/resolver tests in `src/sandbox_profile.rs`,
account-mismatch tests in `src/sandbox.rs`, token lookup/cache tests in
`src/sandbox_exec.rs`, and
`copilot_auth_handover_keeps_keychain_only_without_a_substitute` in
`tests/e2e_projects.rs`. The latter proves fake-token forwarding, output redaction
and kernel-enforced Keychain-directory file reads/writes with substitution
on/off/missing. It does not prove Security framework API denial, OAuth, token
validity, selected identity or renewal. Test existence is not a recorded pass.

Latest serial checks on 2026-10-12: `mise run check` passed fmt, clippy, 414 unit
and 1586 lib tests; 178 guard and 13 hardening tests also passed. The earlier
concurrency timing flake in
`agent::tests::opencode_v2_unknown_probe_is_retried_and_not_cached` passed in
isolation and subsequent full checks. It is not an outstanding incident blocker.
These checks do not prove the full auth lifecycle.

- Add resolver/config tests for precedence, selected-account errors, enterprise
  pairing, `deny.env`, malformed/oversized metadata, symlinks and FIFOs.
- Prove actual Security framework read **and write** APIs work outside and fail
  inside the denied sandbox, using dummy items and a disposable Keychain. Keep
  search-list/default-Keychain changes confined to a disposable OS account.
- Exercise the full binary pipeline and realistic workflows with isolated
  fixtures using `tests/common/mod.rs`; require kernel enforcement rather than
  accepting a skipped suite. Cover guard-off, no scratch, separate gh/git
  identities and both nav-pilot launch paths.
- Complete the live matrix in [copilot-auth-testing.md](copilot-auth-testing.md),
  including stale/revoked tokens, locked store/ACL/cancellation, long sessions,
  host logout/restart, MCP OAuth and Linux with Secret Service masked. Use a
  disposable feature branch for the authorized HTTPS push test.

Gate: `mise run check`, applicable integration suites and
`CPLT_TEST_REQUIRE_SANDBOX=1 mise run test:e2e-projects` pass. Run
`mise run test` when gh/git guard changes are included. Record live outcomes
separately; ignored smoke tests and simulated denial cannot establish renewal.

### M5 Site and documentation

The existing site blocker is resolved: old domains were fixed, full 801 checks
and smoke passed. Browser guidance and its anchor were added to the generated
inventory. Retain the coordinating work's command/output evidence.
Four auth-documentation issues are fixed, including recovery injection and
restoration of prior settings. The guide source is ready but unpublished.

- Align site, cplt docs and nav-pilot onboarding on source precedence, selected
  identity, platform coverage, env exposure and the tested recovery. Distinguish
  current defaults from the opt-in implementation.
- Validate the implemented host-onboarding action against the new recovery gates
  before claiming incident recovery complete.

Gate: the site check/build passes, links resolve, and published guidance agrees
with tested behavior. No documentation claim that OAuth renewal works without
M1/M4 evidence.

### M6 Independent review and staged rollout

Independent review used available general agents; explicit model selection was
unavailable. Do not label these reviews as a requested model-specific review.
All three reported CLI blockers and four auth-doc issues are fixed and checked.
This closes those findings, not future extraction review or live host acceptance.

- Obtain independent security/correctness review of item selection, refresh,
  hostile metadata, secret exposure, gh/git separation and failure recovery.
  Record findings and their disposition before a rollout decision.
- In a later authorized implementation PR, add the default-off key and its
  promotion criteria to [#264](https://github.com/navikt/cplt/issues/264).
  Include profile byte-identity evidence and the recovery test.
- Enable opt-in gradually. A separate default-flip decision requires every
  promotion criterion, supported-version lifecycle evidence, passing site
  checks and maintainer sign-off. Link #264 and move the row to
  "Already flipped" only with that decision.

Gate: independent review findings are resolved and maintainers approve the
evidence-based promotion. Default remains unchanged until then.

## Open blockers and authorization

### cplt packaging review, 2026-10-12

Base: `origin/main`, `05e18eff2027fc9b240ed24902349e31ed9e866c`.
Reviewed staged, unstaged and all untracked files, plus every included commit.
Sibling results above remain reports from coordinating agents, not fresh checks
from this packaging session.

| Axis | Finding or evidence limit |
| --- | --- |
| Correctness | Traced shared gh retrieval, all three backend deny sweeps and cache gating. A soon-to-be-denied token no longer suppresses the exec cache. Offline probe tests verify timeout process-group cleanup and child reaping; interactive terminal behavior remains version-specific. |
| Regression | Doctor and launch share host-pinned retrieval. Removed duplicate config lookup by reusing the policy helper. Guard/project suites pass; Linux runtime effects remain for CI. |
| Edge cases | Existing hung-child, retained-stdout and nonzero-exit checks pass. Added symlink/FIFO and split-token scan checks. A retained Keychain grant and unknown account metadata still do not prove a usable or selected login. |
| Requirement coverage | Incident diagnosis, cache correction and recovery procedures have code/test evidence. Host OAuth, secure persistence and restart acceptance remain a warning; one-shot account auth cannot close them. |
| Repository standards | fmt, clippy and isolated tests pass. Corrected stale attribution/authorization. Known OpenCode subprocess timing flake recurred with concurrent mise tasks and passed with serialized tasks. |
| Scope | Every hunk serves incident packaging or its verification. Contract research is evidence for a future gate, not extraction code. No new config key, default promotion or sibling edit. |

Blast radius: shared gh discovery/token-cache setup for all agents on macOS and
Linux, plus Copilot recovery docs and an opt-in macOS diagnostic script. No Nais
tenant/on-prem deployment or canary applies. Linux Secret Service and MCP renewal
remain unverified; macOS file-denial tests do not prove Security framework API
denial. No generated files changed. Merging into main with successful CI triggers
four-target release archives, Linux .deb packages and a published GitHub release.

Fresh gates, all final commands exited 0:

- `RUST_TEST_THREADS=1 mise run --jobs 1 check`: fmt, clippy, 414 unit and 1586 lib.
- `CPLT_TEST_REQUIRE_SANDBOX=1 RUST_TEST_THREADS=1 mise run test:e2e-projects`: 76.
- `CPLT_TEST_REQUIRE_SANDBOX=1 RUST_TEST_THREADS=1 cargo test --test e2e_guards --test e2e_git_hardening -- --nocapture`: 178 guard and 13 hardening.
- `python3 hack/test-probe-copilot-no-auth.py`: 2 offline checks, no credentials.
- `git diff --check`: clean.

Earlier attempts: the config-helper re-export was missing and failed compilation,
then was fixed; concurrent-task `check` hit the known OpenCode timing flake; the
first project run exceeded the tool's 120-second timeout. The final project run
passed with a longer runner timeout. Prior live probes remain recorded evidence,
not rerun here. No login was performed.

Verdict: **CONCERNS**. Live recovery/lifecycle and Linux credential-store coverage
remain open warnings. No unresolved implementation blocker for the incident draft.

| Scope | Open gate | What closes it |
| --- | --- | --- |
| Immediate incident | Host OAuth/restart acceptance open | User-assisted host sign-in, secure persistence, OAuth cancellation and restart without link hacks. Prelaunch `aborted` is not OAuth cancellation. Record Slack CLI/version, terminal/editor and whether `gh` was used. |
| Full launch chain | Isolation-safe real-token probe unavailable | A supported isolation method that contains broad Mach grants without nested SBPL, or agreed safe existing-user manual smoke. Empty installed nav-pilot exited 2 because no package was available. |
| Model workflow | Interactive model response unverified | Live response evidence within the agreed request budget; synthetic harness checks alone are insufficient. Does not block basic account-auth conclusion. |
| Full lifecycle | Original 1.0.86 behavior not reproduced | Real-version headless/interactive and relevant post-OAuth evidence. |
| Full lifecycle | Selection, serialization and renewal unresolved | Close the version-scoped gates in `copilot-auth-contract.md`; experimental active-account and SDK callback evidence alone do not support standalone extraction. |
| Full lifecycle | Live OAuth requires user | Agreed interactive host sign-in session with secure storage verified. |
| Full lifecycle | gh/git independence across modes not proven | Alice/Bob lifecycle plus guarded gh and authorized HTTPS push evidence; explicit unsupported combinations. |
| Full lifecycle | Linux/MCP coverage unknown | Proven handover/renewal, or explicit scope and unsupported-setting diagnostics. |

The user authorizes existing-user **simulated denied-access tests**. They need
no logout and must not change stored credentials. Interactive OAuth requires
the user. Credential changes, revocation, account switching and Keychain setting
changes need a disposable account or a separately agreed interactive session
with tested recovery. Simulated denial proves neither logout nor live renewal.

The coordinating user authorizes packaging the existing cplt incident changes,
commits, a normal branch push and a draft PR. Sibling repositories are outside
this packaging task. Live authentication remains user-assisted; merge, release
promotion and future credential extraction are not authorized.
