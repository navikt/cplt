# Copilot authentication contract evidence

Direct credential extraction is blocked until selection, serialization and renewal
are verified together. A documented token input is not a credential-export contract.

## Provenance

Public program code inspected on 2026-10-12, without executing authentication or
reading user configuration, credentials or Keychain items. Archives were inspected
in memory. Version support beyond these artifacts is unproven.

| Artifact | Version | Evidence |
| --- | --- | --- |
| Homebrew standalone SEA executable | `1.0.94-5` | Embedded `copilot.tgz`; `package/package.json`, commit `fdeb5949` |
| Extracted program package | `1.0.95` | `package.json`, commit `f5ba5057`; JS, generated schema and native module |
| Public npm `@github/copilot-darwin-arm64` archive | `1.0.86` | Embedded `package/app.js` and `prebuilds/darwin-arm64/runtime.node` |

References below are relative to the `1.0.95` program package. The loader can select
a newer cached package: `index.js:10–11`. The executable's installation version
alone does not identify the application version used at launch.

## Identity and selection

| Interface | Verified meaning |
| --- | --- |
| `UserAuthInfo` | `type: "user"`, `host`, `login`; optional `copilotUser`. OAuth token stays in the runtime secret store keyed by host+login. |
| `EnvAuthInfo` | `type: "env"`, `host`, `token`, `envVar`; optional `login` and `copilotUser`. Environment handoff changes the authentication representation. |
| `lastLoggedInUser` | Most recent sign-in, not documented as authoritative current selection. |
| `loggedInUsers` | Account roster: required `host`/`login`, optional `kind`/`derivedFrom`; marked internal. |
| `session.accounts.get({sessionId,query:{kind:"activeAccount"}})` | Experimental session-scoped active-account read returning account status and credential-free identity. |

Schema references: `schemas/api.schema.json:23836–23873`, `25699–25710`,
`28138–28164`, `55934–55962`, `17185–17300`. `AccountStatus` includes `active`,
`selectionId` and provider kind (`14845–14884`). The UI uses active-account reads
and native account switching (`cli-main.js:3107`, `3137`). Reading last-sign-in
metadata alone does not reproduce that native selection logic.

## Persistence and renewal

Secure-store serialization remains unconfirmed. GitHub persistence and resolution
are native; no Rust source or source maps were found. Native `StoredCredential`,
`authTokens` and diagnostics describing `{token, expiresAt?, accountType?}` show
structured credential handling, but do not prove the Keychain item's bytes,
account-name encoding, migration behavior or refresh persistence. No
`storedCopilot` identifier was found in the inspected bundles/schema/native strings.

The SDK explicitly supports `gitHubTokenProvider`: `initial`/`refresh` requests,
`accessToken` and required `expiresIn >= 3601`. Refresh preflight occurs when one
hour or less remains. Its comment says production GitHub tokens typically last
eight hours; this is not evidence of stored Copilot OAuth lifetime.

References: `copilot-sdk/types.d.ts:18–35`,
`schemas/api.schema.json:14432–14435`, `25474–25563`.
Standalone environment-token base renewal and Copilot API/session-token renewal
were not proven. MCP/MSAL refresh code is not GitHub credential renewal evidence.

## Login and logout

`cli-main.js:3185–3198` routes stdin tokens or, without an explicit flow,
environment tokens to `ProcessAuthHandle.loginWithToken`. Stdin is bounded to
64 KiB. Explicit device/web flow bypasses that environment-token selection.
Persistence may request plaintext consent; non-TTY consent is refused. Unsaved
credentials exit 1. Organization-policy rejection can discard the credential.

`/logout` refuses environment/token authentication and directs the user to change
the source (`cli-main.js:1598`). It manages stored user/provider accounts;
`1.0.86` accepts only stored user auth there. Experimental `account.logout`
documents removal from Keychain and persisted state
(`schemas/api.schema.json:382–393`). Server-side revocation was not established.

## Runnable synthetic evidence

`hack/probe-copilot-auth-contract.py` checks the public generated schema. Adding
`--node` executes synthetic metadata and native session checks from a copied module,
inside Seatbelt with network, Mach lookup, subprocesses and real-home access
denied except for an exact read grant on the selected Node executable. There is
no Node-parent or package-subtree grant; the bounded native module is copied into
the fixture. A Node installation requiring other home-resident libraries fails
closed. Temporary fixture grants overlapping protected storage are refused.
It clears the environment, creates disposable config fixtures, verifies
outside-fixture read/TCP/subprocess denial and rejects symlink/FIFO fixture reads.
The session experiment attempts native credential resolution using only dummy
tokens and fixture state, with Keychain services and network denied. It never
runs login, logout or model requests. No Keychain is created or made accessible:
no explicit isolated-store override has been established for Copilot's lookup.

The earlier probe granted Node's inferred installation root and the package
subtree after the home deny. Its isolation claim was too broad: `~/bin/node`
could reopen the whole home. Corrected kernel checks use copied executables in
synthetic `~/bin` and `~/.local/bin` layouts. Home, executable-sibling and
package-parent credential canaries stay unreadable. Negative controls restore
the old inferred root or an overlapping package grant and make the assertions
fail. Only synthetic files are used for these controls.

```sh
python3 hack/probe-copilot-auth-contract.py --package "$PUBLIC_PACKAGE"
python3 hack/probe-copilot-auth-contract.py --package "$PUBLIC_PACKAGE" --node "$ABSOLUTE_NODE"
python3 hack/probe-copilot-auth-contract.py --standalone /opt/homebrew/bin/copilot --node "$ABSOLUTE_NODE"
```

On 2026-10-12, `1.0.94-5` and `1.0.95` passed native metadata and serialization
checks with Node 24. Both retain synthetic `authTokens` values shaped as
`{token: nonempty string}` or `{token, expiresAt: "2099-01-01T00:00:00Z"}` in
fresh config directories. Raw strings, empty tokens and invalid expiry strings
are dropped. This proves config-fallback parsing, **not Keychain serialization**,
credential validity, expiry enforcement or renewal. Separate fixture directories
are necessary because native global-state reads cache earlier results.

The raw `globalStateLoadForContext` binding retains `authTokens`, unlike the
published RPC result schema. Do not infer raw-binding redaction from that schema.
`authGetLastLoggedInUserForContext` returns synthetic last-sign-in metadata even
with a dummy `COPILOT_GITHUB_TOKEN` present. It does not resolve effective
authentication or prove active-account selection. Native identity comparison
distinguishes stored user and environment identities.

| Version | Schema SHA-256 | Native runtime SHA-256 |
| --- | --- | --- |
| `1.0.94-5` | `8053220e3f7939999ba01ea5dbe31ead0534f46f77e360fb45658253559d661e` | `64e83554d1fc455a3b0b5c1b5a92900ffadd586ee3864241d87334005a6a511f` |
| `1.0.95` | `74e36b714b7b0290e6277625360086735d164df1462266b5cba654507f07a219` | `e6d701d5e79c2848c648194739bec1f418da0b6e193bc47a850bf7e427dd11df` |
| `1.0.96-2` | `e097216f866cc9215ce9e1ebfd64b5fb3e7eea4ea10e1f8650902c3fc940e526` | `0ddd9ea39981870ce8241f2f95d24ce085572e82407d463c500f139ed6c8aa4f` |
| `1.0.97-2` | `b4a368552e04cf508301897fd2c19534462f0e31505a5ad72b5b49274889a609` | `ac5ea364f0c159667ba74957d66053a79a85c12601179f39e8a1d6ebf7f6c3b8` |

## Native session experiment

The standalone input reads only three bounded regular members from the public
SEA archive: manifest, generated schema and native runtime. It bounds total
gzip expansion to 256 MiB before tar parsing, including
unrelated members and extended metadata. The reviewed `1.0.97-2` tar is
177,036,288 bytes. It never launches
the installed loader or downloads a package. Native execution requires the
version/build pin and reviewed runtime SHA-256. Other artifacts fail closed.
`1.0.94-5` remains schema-only in this probe; native session runs explicitly
require `1.0.95`, `1.0.96-2` or `1.0.97-2`. Its earlier metadata results above are
historical, not a session-compatibility claim.

The experiment follows the public host setup in `1.0.96-2/cli-main.js:1486`:
`sessionHostChannelOpen`, `JsonrpcServerHandle`, `setSessionsContext`,
`setSdkSessionConfig`, and `setAuthManagerConfig`. It constructs the actual native
session using `sessionCreate` and the construction payload from
`cli-main.js:1679`, then calls `initializeSession`. This is a native fixture, not
the complete CLI host lifecycle. No fake authentication responses or injected
`copilotUser` metadata are used.

`session.accounts.get` requires `sessionId`; plain `accounts.get` is not the RPC.
References: `1.0.96-2/schemas/api.schema.json:2994–3034` and
`copilot-sdk/generated/rpc.d.ts:31792–31808`. Earlier bare-server experiments
returned `Session has no GitHub auth service configured` until native construction
was added. `account.getCurrentAuth` on that bare server required native server
context; this does not prove an export interface.

On 2026-10-13, the following cases passed on `1.0.95`, `1.0.96-2` and `1.0.97-2`, each in a
fresh process/config directory. The current standalone build is `1bc7ab07`;
the cached `1.0.96-2` build is `8227e3a7`.

| Fixture | Native construction/initialization | `activeAccount` after resolution |
| --- | --- | --- |
| Empty roster | succeeded | `null` |
| Two accounts, one host | succeeded | `null` |
| Same login on two hosts | succeeded | `null` |
| Last-sign-in absent from roster | succeeded | `null` |
| Dummy OAuth-shaped environment override | succeeded | `null` |
| Synthetic config-fallback token object | succeeded | `null` |
| Synthetic expired fallback token | succeeded | `null` |

Both `ProcessAuthHandle.current()` and `currentAndApplyToSession()` returned
exactly `null` under these restrictions. PASS requires initialization to return
`true`, both calls to complete without exceptions, successful RPC dispatch and
`status.isAuthenticated: false`. Unexpected errors fail; they are not negative
identity evidence. It does not identify which denied dependency or validation
step prevented resolution. The synthetic fallback key is a parser fixture, not
a verified native host/login store-key encoding.

Successful selected-account export and base/API-token renewal remain unproven.
The next live gate needs a disposable, user-approved identity and a verified
exact-account export path, followed by separate expiry/rotation tests. Do not
enumerate unrelated account tokens or silently fall back to gh. No production
extraction or default change follows from these negative offline results.

Seven offline regression tests cover public SEA parsing, bounded expansion, malformed compression, truncated-input
sanitization, hash refusal, old-version refusal and false initialization/errors
from either resolution call. `mise run test:probe` and Linux/macOS CI run them;
Node is required for the synthetic JS check.

## Remaining extraction gate

Before implementing, prove on a pinned version:

- Exact selected account/host and store query, including overrides and ambiguity.
- Serialization and expiry/rotation using disposable synthetic store fixtures.
- Exact-account export without enumerating unrelated secrets. Experimental
  `account.getAllUsers` has an optional token field (`14532–14553`), not a proven
  supported extraction interface.
- Separate base-credential and Copilot API/session renewal under env handoff.
- Logout, account switching, expired/revoked credentials and host-side recovery.

Only then retrieve the exact selected credential and inject it as
`COPILOT_GITHUB_TOKEN`, keeping gh credentials separate. Missing, denied or failed
selection must not choose another identity. If renewal needs a host callback or
vault writes, launch-time extraction alone is insufficient. Ship behind a new
default-off gate with version-scoped acceptance evidence.
