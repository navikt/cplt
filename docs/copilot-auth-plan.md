# Copilot CLI authentication plan

## Target architecture

`cplt` resolves the selected GitHub Copilot CLI credential on the host before sandbox entry and passes it into the sandbox through `COPILOT_GITHUB_TOKEN`. The sandboxed agent never gets blanket read access to `~/Library/Keychains` on macOS or the D-Bus Secret Service socket on Linux. `gh` and `git` keep their own host-managed credential path through the `gh` guard and one-shot `.gh-token` cache, so Copilot and `gh` never silently switch each other's identity.

## Merged baseline

- `#757` and `#760` verify real `gh auth token --hostname github.com` retrieval in `cplt doctor`, pin host lookup, and warn on Linux when native keyring access is not guaranteed.
- `#765` stops passing `GH_TOKEN` or `GITHUB_TOKEN` into non-Copilot agents when the `gh` guard can serve `gh` directly.
- `#766` runs the offline contract probe `hack/probe-copilot-auth-contract.py` in `mise run check` to verify Copilot CLI `1.0.94-5` and `1.0.95` schema and native addon gates.
- `#768` checks PR descriptions against `.github/pull_request_template.md` in CI and requires explicit rollout and platform parity sections.

## Next steps

| Priority | Deliverable | Acceptance gate |
| --- | --- | --- |
| 1 | Selected-credential contract | Reliable account and host selection from `~/.copilot/config.json` and Keychain attributes, exact-item retrieval, known format, and explicit failure on ambiguity |
| 2 | Default-off `cplt` resolver | Pass only `COPILOT_GITHUB_TOKEN`, honour `deny.env` and `pass_env`, keep `gh` and `git` identity separate, and preserve byte-identical profiles when unset |
| 3 | Lifecycle validation | Restart, stale credentials, storage cancellation, account switching, and token renewal |
| 4 | Linux endpoint enforcement | Test on namespace-capable Linux, and enforce a defined Secret Service boundary or refuse strict mode |
| 5 | `nav-pilot` integration and pilot | Fresh onboarding, both launch paths, clear recovery commands, updated guides, and Astra security review |

## Selected-credential contract rules

1. Read `~/.copilot/config.json` with `untrusted::read_untrusted` so a planted symlink, FIFO, or oversized file in `~/.copilot` never blocks or leaks host files.
2. Resolve the active Copilot account from `lastLoggedInUser` and `loggedInUsers` by reading `host` and `login`. Refuse substitution when `lastLoggedInUser` is missing from a non-empty `loggedInUsers` list or when multiple accounts exist without `lastLoggedInUser`.
3. Compare the selected Copilot account and host against both `gh`'s `github.com` login and the `copilot-cli` Keychain item attributes before substituting a token.
4. On Linux, treat a native stored login in `~/.copilot/config.json` as requiring an injected environment token or `copilot logout` on the host, because Copilot queries Secret Service before falling back to `gh auth token`.

## Verification split

Immediate work runs offline in `mise run check` with pinned resolver-contract fixtures and synthetic multi-account, enterprise-host, symlink, and FIFO tests. These tests need no live credential access.

Fresh OAuth login, live account switching, and token revocation tests require interactive user participation. Promoting a default-off resolver key to on by default remains a separate staged rollout decision under issue `#264`.
