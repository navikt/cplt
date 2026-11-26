# Contributing

Contributions are welcome. For a large change, open an issue first to discuss the approach.

## Get started

1. Fork [navikt/cplt](https://github.com/navikt/cplt) on GitHub.
2. Clone your fork, replacing `YOUR_GITHUB_USERNAME` with your GitHub username:

   ```bash
   git clone https://github.com/YOUR_GITHUB_USERNAME/cplt.git
   cd cplt
   ```

3. Install Python 3 and Node.js separately, ensuring `python3` and `node` are on your PATH, then install the pinned Rust toolchain with [mise](https://mise.jdx.dev/):

   ```bash
   mise install
   ```

   The project uses Rust `1.94`.

4. Enable the Git hooks and run the checks:

   ```bash
   git config core.hooksPath hack
   mise run check
   ```

The hooks run formatting and Clippy checks before commits. `mise run check` runs formatting, Clippy, unit and library tests, and the offline probe checks.

## Linux sandbox from a Mac

The Landlock, seccomp and bubblewrap code only runs on Linux. To build and test it from a Mac, use the Debian container in `hack/linux-dev.sh`. It needs docker; [colima](https://github.com/abiosoft/colima) works. Podman is not supported.

```bash
mise run linux:check             # cargo build + clippy for Linux
mise run linux:test-integration  # tests/integration_linux.rs with the CI job's listener and session bus
mise run linux:test-all          # cargo test --no-fail-fast, as the CI Linux job runs it
mise run linux:shell             # shell in the container
sh hack/linux-dev.sh run cargo test --lib seccomp   # any other command
```

The checkout is mounted at `/work/cplt`. `target/` is the volume `cplt-linuxdev-target`, laid over the checkout's own `target/`, and the cargo home is the volume `cplt-linuxdev-cargo`. Builds are cached and kept apart from the macOS build. Tests run as a non-root user with your uid. The container drops the default seccomp and AppArmor profiles and the `/proc` masks, because bubblewrap needs user namespaces, `mount` and a fresh `/proc`. It adds no capabilities and does not run privileged. It raises the open-file limit to 65536, because colima's default of 1024 is too low for the full suite.

`linux:test-all` fails 3 lib tests on a colima Mac. CI passes them. Two make a FIFO or clean up a scratch dir inside the checkout, and the macOS file share does not support that. These are `linked_overlay_with_unsafe_target_is_refused` and `doctor_bubblewrap_state_probes_file_deny_masks`. The third is `nested_git_unreadable_dir_changed_behind_chmod_is_an_error`, which also fails in the container; the cause is not known.

## Output policy

Every line cplt prints at launch or exit belongs to one of four tiers. Pick the tier before you add a line.

- **Act now:** always shown, kept short. The user has to do something, or there is a risk. Examples: untrusted `.cplt.toml` keys, `⚠ GPG signing allowed`, a refused launch.
- **Changed:** shown once when something changed since the last launch in this project, then silent. `src/launch_state.rs` records what was shown. The sandbox table and the nested-repo hint work this way. The launch prompt does too, keyed on what the user last said yes to: a TTY launch whose profile matches the last confirmed one (topic `confirmed-<agent>`, recorded only when someone saw the full table on a TTY and confirmed it, and never while `.cplt.toml` keys await approval) skips `Proceed?`.
- **Steady state:** silent, or one summary line at most.
- **Detail:** only on request: `--verbose`, `--print-profile` or `cplt doctor`.

`--quiet` and `sandbox.quiet` still hide everything but the act-now tier.

## Pull requests

Create a branch for your change, push it to your fork, and open a pull request against `navikt/cplt`. Maintainers will review it and help get it ready to merge.
If you have a large change, open an issue before creating a pull request
