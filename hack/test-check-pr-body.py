#!/usr/bin/env python3
"""Offline unit tests for hack/check-pr-body.py."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("check_pr_body", Path(__file__).with_name("check-pr-body.py"))
assert spec is not None and spec.loader is not None
check_pr_body = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_pr_body)

VALID_BODY = """## Summary

Fast PR body re-check on edits.

## Risk profile & rollout

- [x] No breaking user-facing changes
- [ ] Breaking change with automatic fallback or documented one-step recovery
- [ ] Gated behind a default-off config key tracked in #264, and the unset profile is byte-identical

## Platform parity

N/A

## Security considerations

None

## Test plan

- `mise run check`
"""


class CheckPrBodyTests(unittest.TestCase):
    def test_valid_body_passes(self):
        self.assertEqual(check_pr_body.validate_body(VALID_BODY), [])

    def test_unpopulated_template_fails_with_empty_sections_and_unchecked_risk(self):
        template_path = Path(__file__).resolve().parent.parent / ".github" / "pull_request_template.md"
        raw = template_path.read_text(encoding="utf-8")
        errors = check_pr_body.validate_body(raw)
        self.assertIn("Section '## Summary' must not be empty", errors)
        self.assertIn("Section '## Risk profile & rollout' must have at least one checked option", errors)
        self.assertIn("Section '## Platform parity' must not be empty", errors)
        self.assertIn("Section '## Security considerations' must not be empty", errors)
        self.assertIn("Section '## Test plan' must not be empty", errors)

    def test_fenced_code_and_unclosed_html_comment_do_not_spoof_sections(self):
        spoofed = """## Summary

```markdown
## Risk profile & rollout
- [x] Fake checkbox inside code fence
## Platform parity
Fake
## Security considerations
Fake
## Test plan
Fake
```
<!-- unclosed comment
## Risk profile & rollout
- [x] Hidden in comment
"""
        errors = check_pr_body.validate_body(spoofed)
        self.assertIn("Missing required section heading '## Risk profile & rollout' in PR description", errors)

    def test_failure_writes_step_summary_and_remediation(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary_file = Path(tmp) / "summary.md"
            env = {
                "EVENT_NAME": "pull_request",
                "PR_AUTHOR": "octocat",
                "PR_NUMBER": "770",
                "PR_BODY": "## Summary\n\nOnly summary.\n",
                "GITHUB_STEP_SUMMARY": str(summary_file),
            }
            out = io.StringIO()
            with patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out):
                rc = check_pr_body.main([])
            self.assertEqual(rc, 1)
            stdout_text = out.getvalue()
            self.assertIn(
                "::error title=Edit PR description on GitHub (not code)::"
                "Missing required section heading '## Risk profile & rollout'",
                stdout_text,
            )
            self.assertIn("gh pr edit 770 --body-file <file>", stdout_text)
            summary_text = summary_file.read_text(encoding="utf-8")
            self.assertIn("### PR description check failed", summary_text)
            self.assertIn("Fix with Copilot", summary_text)
            self.assertIn("## Risk profile & rollout", summary_text)

    def test_fetch_live_and_verify_code_checks_uses_latest_run_per_job(self):
        check_runs_lines = "\n".join(
            json.dumps(r)
            for r in [
                {"id": 10, "name": "unit-tests", "status": "completed", "conclusion": "failure", "app_slug": "github-actions"},
                {"id": 20, "name": "unit-tests", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
                {"id": 21, "name": "integration-tests", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
                {"id": 22, "name": "opencode-v2-e2e", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
                {"id": 23, "name": "opencode-v2-e2e-linux", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
                {"id": 24, "name": "linux-integration-tests", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
                {"id": 50, "name": "unit-tests", "status": "completed", "conclusion": "skipped", "app_slug": "github-actions"},
                {"id": 51, "name": "integration-tests", "status": "completed", "conclusion": "skipped", "app_slug": "github-actions"},
            ]
        )

        def fake_gh_api(args):
            if args == ["repos/navikt/cplt/pulls/771"]:
                return json.dumps({"body": VALID_BODY})
            self.assertIn("repos/navikt/cplt/commits/abcdef1234567/check-runs?per_page=100", args)
            return check_runs_lines

        env = {
            "EVENT_NAME": "pull_request",
            "PR_AUTHOR": "octocat",
            "GITHUB_REPOSITORY": "navikt/cplt",
            "PR_NUMBER": "771",
            "HEAD_SHA": "abcdef1234567",
        }
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(
            check_pr_body, "run_gh_api", side_effect=fake_gh_api
        ), contextlib.redirect_stdout(out):
            rc = check_pr_body.main(["--fetch-live", "--verify-code-checks"])
        self.assertEqual(rc, 0)
        self.assertIn("ci-ok: all required code checks succeeded on abcdef1.", out.getvalue())

    def test_verify_code_checks_fails_when_newer_run_failed_or_in_progress(self):
        check_runs_lines = "\n".join(
            json.dumps(r)
            for r in [
                {"id": 10, "name": "unit-tests", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
                {"id": 30, "name": "unit-tests", "status": "completed", "conclusion": "failure", "app_slug": "github-actions"},
                {"id": 40, "name": "unit-tests", "status": "completed", "conclusion": "skipped", "app_slug": "github-actions"},
                {"id": 21, "name": "integration-tests", "status": "in_progress", "conclusion": None, "app_slug": "github-actions"},
                {"id": 41, "name": "integration-tests", "status": "completed", "conclusion": "skipped", "app_slug": "github-actions"},
                {"id": 22, "name": "opencode-v2-e2e", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
                {"id": 23, "name": "opencode-v2-e2e-linux", "status": "completed", "conclusion": "success", "app_slug": "github-actions"},
            ]
        )
        with patch.object(check_pr_body, "run_gh_api", return_value=check_runs_lines):
            errors = check_pr_body.verify_code_checks("navikt/cplt", "abcdef1234567")
        self.assertEqual(len(errors), 3)
        self.assertTrue(any("'unit-tests' did not succeed" in e for e in errors))
        self.assertTrue(any("'integration-tests' is still in_progress" in e for e in errors))
        self.assertTrue(any("'linux-integration-tests' has not started" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
