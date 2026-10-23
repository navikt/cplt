#!/usr/bin/env python3
"""Validate PR descriptions against .github/pull_request_template.md and verify code checks on body edits."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

REQUIRED_HEADINGS = (
    "## Summary",
    "## Risk profile & rollout",
    "## Platform parity",
    "## Security considerations",
    "## Test plan",
)

exempt_authors = ("dependabot[bot]", "github-actions[bot]")

REQUIRED_CODE_JOBS = (
    "unit-tests",
    "integration-tests",
    "opencode-v2-e2e",
    "opencode-v2-e2e-linux",
    "linux-integration-tests",
    "mcp-broker-e2e-ubuntu-22.04",
    "mcp-broker-e2e-ubuntu-24.04",
    "doctor-fix-e2e",
)

TEMPLATE_EXAMPLE = """```markdown
## Summary

Describe what this change does and why it is needed.

## Risk profile & rollout

- [x] No breaking user-facing changes
- [ ] Breaking change with automatic fallback or documented one-step recovery
- [ ] Gated behind a default-off config key tracked in #264, and the unset profile is byte-identical

## Platform parity

N/A (or describe macOS Seatbelt and Linux Landlock, seccomp, and bubblewrap behavior)

## Security considerations

None (or describe changes to sandbox rules, environment filtering, command guards, network policy, or untrusted file handling)

## Test plan

- `mise run check`
```"""


def strip_fenced_code(text: str) -> str:
    out: list[str] = []
    fence_char: str | None = None
    fence_len = 0
    for line in text.splitlines():
        if fence_char is None:
            match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                fence_char = match.group(1)[0]
                fence_len = len(match.group(1))
                out.append("CODE_BLOCK")
            else:
                out.append(line)
        elif re.match(rf"^ {{0,3}}{re.escape(fence_char)}{{{fence_len},}}\s*$", line):
            fence_char = None
            fence_len = 0
    return "\n".join(out)


def validate_body(raw: str) -> list[str]:
    body = re.sub(r"<!--(?:.*?-->|.*$)", "", raw or "", flags=re.DOTALL)
    body_no_code = strip_fenced_code(body)

    positions: dict[str, tuple[int, int]] = {}
    errors: list[str] = []
    for heading in REQUIRED_HEADINGS:
        matches = list(re.finditer(rf"(?m)^{re.escape(heading)}\s*$", body_no_code))
        if not matches:
            errors.append(f"Missing required section heading '{heading}' in PR description")
        elif len(matches) > 1:
            errors.append(f"Duplicate section heading '{heading}' in PR description")
        else:
            positions[heading] = (matches[0].start(), matches[0].end())

    if not errors:
        ordered = sorted(positions.items(), key=lambda kv: kv[1][0])
        for idx, (heading, (_, end_pos)) in enumerate(ordered):
            next_start = ordered[idx + 1][1][0] if idx + 1 < len(ordered) else len(body_no_code)
            section = body_no_code[end_pos:next_start]
            next_h2 = re.search(r"(?m)^##\s+", section)
            if next_h2:
                section = section[: next_h2.start()]
            if heading == "## Risk profile & rollout":
                if not re.search(r"(?m)^\s*[-*+]\s*\[[xX]\]\s+\S+", section):
                    errors.append("Section '## Risk profile & rollout' must have at least one checked option")
            elif not section.strip():
                errors.append(f"Section '{heading}' must not be empty")

    return errors


def format_remediation(errors: list[str], pr_number: str = "") -> str:
    bullet_errors = "\n".join(f"- {err}" for err in errors)
    cli_hint = f"gh pr edit {pr_number} --body-file <file>" if pr_number else "gh pr edit --body-file <file>"
    return (
        "### PR description check failed\n\n"
        f"{bullet_errors}\n\n"
        "> [!NOTE]\n"
        "> Do **not** click **Fix with Copilot** on this check. That launches a coding agent on a new branch, whereas this check only validates the PR description text on GitHub.\n\n"
        "**How to make this check turn green (~5 seconds, no test re-run):**\n"
        f"1. Edit the PR description on GitHub (or run `{cli_hint}`).\n"
        "2. Ensure every section below is present and non-empty (`N/A` or `None` is fine when a section does not apply).\n"
        "3. Save the description. `PR body template check` and `ci-ok` will re-run automatically in ~5 seconds without re-running the test suite.\n\n"
        f"{TEMPLATE_EXAMPLE}\n"
    )


def write_step_summary(markdown: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with Path(summary_path).open("a", encoding="utf-8") as handle:
        handle.write(markdown)
        if not markdown.endswith("\n"):
            handle.write("\n")


def run_gh_api(args: list[str]) -> str:
    proc = subprocess.run(
        ["gh", "api", *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        raise RuntimeError(f"gh api {' '.join(args)} failed: {detail}")
    return proc.stdout


def fetch_live_pr_body(repo: str, pr_number: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError(f"Invalid GITHUB_REPOSITORY: {repo!r}")
    if not re.fullmatch(r"[0-9]+", pr_number):
        raise ValueError(f"Invalid PR_NUMBER: {pr_number!r}")
    out = run_gh_api([f"repos/{repo}/pulls/{pr_number}"])
    payload = json.loads(out)
    return payload.get("body") or ""


def verify_code_checks(repo: str, head_sha: str) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError(f"Invalid GITHUB_REPOSITORY: {repo!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", head_sha):
        raise ValueError(f"Invalid HEAD_SHA: {head_sha!r}")

    out = run_gh_api(
        [
            "--paginate",
            f"repos/{repo}/commits/{head_sha}/check-runs?per_page=100",
            "--jq",
            ".check_runs[] | {id, name, status, conclusion, app_slug: .app.slug}",
        ]
    )

    latest_by_name: dict[str, dict[str, object]] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        run = json.loads(line)
        if run.get("app_slug") != "github-actions":
            continue
        if run.get("conclusion") == "skipped":
            continue
        name = str(run.get("name") or "")
        run_id = int(run.get("id") or 0)
        prev = latest_by_name.get(name)
        if prev is None or run_id > int(prev.get("id") or 0):
            latest_by_name[name] = run

    errors: list[str] = []
    short_sha = head_sha[:7]
    for job in REQUIRED_CODE_JOBS:
        run = latest_by_name.get(job)
        if run is None:
            errors.append(
                f"ci-ok: required check '{job}' has not started on {short_sha}; "
                "ci-ok will turn green automatically when the CI test run finishes"
            )
            continue
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status != "completed":
            errors.append(
                f"ci-ok: required check '{job}' is still {status} on {short_sha}; "
                "ci-ok will turn green automatically when the CI test run finishes"
            )
        elif conclusion != "success":
            errors.append(
                f"ci-ok: required check '{job}' did not succeed on {short_sha} (conclusion: {conclusion})"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, help="Validate a local PR description markdown file")
    parser.add_argument(
        "--fetch-live",
        action="store_true",
        help="Fetch the live PR body from the GitHub API instead of only reading PR_BODY",
    )
    parser.add_argument(
        "--verify-code-checks",
        action="store_true",
        help="Also verify that all required code check-runs on HEAD_SHA have completed with success",
    )
    args = parser.parse_args(argv)

    if args.file is not None:
        raw = args.file.read_text(encoding="utf-8")
        errors = validate_body(raw)
        if errors:
            for err in errors:
                print(f"ERROR: {err}", file=sys.stderr)
            print("\n" + format_remediation(errors), file=sys.stderr)
            return 1
        print("PR description satisfies all required template sections.")
        return 0

    event_name = os.environ.get("EVENT_NAME", "")
    if event_name != "pull_request":
        print("Not a pull_request event, skipping PR body check.")
        return 0

    author = os.environ.get("PR_AUTHOR", "")
    if author not in exempt_authors:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        pr_number = os.environ.get("PR_NUMBER", "")
        if args.fetch_live:
            try:
                raw = fetch_live_pr_body(repo, pr_number)
            except Exception as exc:
                print(f"::error::Failed to fetch live PR description: {exc}")
                return 1
        else:
            raw = os.environ.get("PR_BODY") or ""

        errors = validate_body(raw)
        if errors:
            for err in errors:
                print(
                    "::error title=Edit PR description on GitHub (not code)::"
                    f"{err}. Edit the PR description on the PR page and save to re-run in ~5s "
                    "(do not use 'Fix with Copilot'; no repository files need changing)."
                )
            remediation = format_remediation(errors, pr_number)
            print("\n" + remediation)
            write_step_summary(remediation)
            return 1
        print("PR description satisfies all required template sections.")
    else:
        print(f"Automated PR author {author}, skipping PR body check.")

    if args.verify_code_checks:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        head_sha = os.environ.get("HEAD_SHA", "")
        # A body edit right after a push starts this run while the code run's
        # tests are still going. Failing now leaves a failed ci-ok check that
        # GitHub keeps counting even after the code run's ci-ok succeeds, so
        # wait for the tests to finish instead (CI_OK_WAIT_SECONDS, default 0).
        deadline = time.monotonic() + int(os.environ.get("CI_OK_WAIT_SECONDS", "0"))
        while True:
            try:
                check_errors = verify_code_checks(repo, head_sha)
            except Exception as exc:
                print(f"::error::Failed to verify code check-runs on {head_sha[:7]}: {exc}")
                return 1
            pending = any(" is still " in e or " has not started " in e for e in check_errors)
            if not pending or time.monotonic() >= deadline:
                break
            print(f"ci-ok: code checks on {head_sha[:7]} not finished yet, waiting...", flush=True)
            time.sleep(20)
        if check_errors:
            for err in check_errors:
                print(f"::error::{err}")
            return 1
        print(f"ci-ok: all required code checks succeeded on {head_sha[:7]}.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
