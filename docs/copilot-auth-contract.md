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
| `accounts.get({query:{kind:"activeAccount"}})` | Experimental active-account read returning account status and credential-free identity. |

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

## Extraction implementation gate

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
