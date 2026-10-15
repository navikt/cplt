# Contributing

Contributions are welcome. For a large change, open an issue first to discuss the approach.

## Get started

1. Fork [navikt/cplt](https://github.com/navikt/cplt) on GitHub.
2. Clone your fork, replacing `YOUR_GITHUB_USERNAME` with your GitHub username:

   ```bash
   git clone https://github.com/YOUR_GITHUB_USERNAME/cplt.git
   cd cplt
   ```

3. Install the pinned Rust toolchain and other project tools with [mise](https://mise.jdx.dev/):

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

## Pull requests

Create a branch for your change, push it to your fork, and open a pull request against `navikt/cplt`. Maintainers will review it and help get it ready to merge.
If you have a large change, open an issue before creating a pull request
