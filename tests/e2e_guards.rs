//! End-to-end tests for gh-guard and git-guard command interception.
//!
//! These tests exercise the `cplt gh-gate` and `cplt git-gate` subcommands
//! directly, verifying that policy decisions (block/allow) are enforced
//! correctly at the binary level.
//!
//! Security properties verified:
//! - Destructive gh commands (pr merge, repo delete) are blocked
//! - Safe gh commands (pr list, issue view) are allowed
//! - Cross-repo scope violations are detected and blocked
//! - `gh auth token` exfiltration is blocked
//! - Unknown commands default to blocked
//! - git push is blocked when prevent_push=true
//! - git force-push is blocked when prevent_force_push=true
//! - git read operations (status, log, diff) always pass
//! - Policy bypass attempts (argument injection, flag hiding) fail
//!
//! Run: cargo test --test e2e_guards
//!
//! These tests do NOT require sandbox-exec or macOS — they test the gate
//! subcommands directly and work on macOS and Linux.

use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cplt"))
}

/// Run `cplt gh-gate` with default block policy.
/// Returns (stdout, stderr, exit_success).
fn gh_gate(args: &[&str]) -> (String, String, bool) {
    gh_gate_with_opts(args, &[])
}

/// Run `cplt gh-gate` with extra policy flags.
fn gh_gate_with_opts(args: &[&str], opts: &[&str]) -> (String, String, bool) {
    let mut cmd = Command::new(binary_path());
    cmd.arg("gh-gate")
        .arg("--real-gh")
        .arg("/usr/bin/true") // if allowed, exec this harmless binary
        .args(opts)
        .arg("--")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"));

    let output = cmd.output().expect("cplt gh-gate should run");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

/// Run `cplt git-gate` with given policy.
fn git_gate(args: &[&str], prevent_push: bool, prevent_force_push: bool) -> (String, String, bool) {
    git_gate_with_mode(args, prevent_push, prevent_force_push, "block")
}

/// Run `cplt git-gate` with protect-default-branch-only mode.
fn git_gate_protect_default(args: &[&str]) -> (String, String, bool) {
    let mut cmd = Command::new(binary_path());
    cmd.arg("git-gate")
        .arg("--real-git")
        .arg("/usr/bin/true")
        .arg("--mode=block")
        .arg("--prevent-push=true")
        .arg("--prevent-force-push=true")
        .arg("--protect-default-branch-only=true")
        .arg("--")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"));

    let output = cmd.output().expect("cplt git-gate should run");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

/// Run `cplt git-gate` with given policy and mode.
fn git_gate_with_mode(
    args: &[&str],
    prevent_push: bool,
    prevent_force_push: bool,
    mode: &str,
) -> (String, String, bool) {
    let mut cmd = Command::new(binary_path());
    cmd.arg("git-gate")
        .arg("--real-git")
        .arg("/usr/bin/true")
        .arg(format!("--mode={mode}"))
        .arg(format!("--prevent-push={prevent_push}"))
        .arg(format!("--prevent-force-push={prevent_force_push}"))
        .arg("--")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"));

    let output = cmd.output().expect("cplt git-gate should run");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

// ============================================================
// gh-gate: Safe commands (should be ALLOWED)
// ============================================================

#[test]
fn gh_gate_allows_pr_list() {
    let (_, _, ok) = gh_gate(&["pr", "list"]);
    assert!(ok, "gh pr list should be allowed");
}

#[test]
fn gh_gate_allows_pr_view() {
    let (_, _, ok) = gh_gate(&["pr", "view", "123"]);
    assert!(ok, "gh pr view should be allowed");
}

#[test]
fn gh_gate_allows_issue_list() {
    let (_, _, ok) = gh_gate(&["issue", "list"]);
    assert!(ok, "gh issue list should be allowed");
}

#[test]
fn gh_gate_allows_pr_create() {
    let (_, _, ok) = gh_gate(&["pr", "create", "--title", "fix bug", "--body", "desc"]);
    assert!(ok, "gh pr create should be allowed");
}

#[test]
fn gh_gate_allows_pr_comment() {
    let (_, _, ok) = gh_gate(&["pr", "comment", "42", "--body", "LGTM"]);
    assert!(ok, "gh pr comment should be allowed");
}

#[test]
fn gh_gate_allows_api_get() {
    let (_, _, ok) = gh_gate(&["api", "/repos/navikt/cplt/pulls"]);
    assert!(ok, "gh api GET should be allowed");
}

// ============================================================
// gh-gate: Destructive commands (should be BLOCKED)
// ============================================================

#[test]
fn gh_gate_blocks_repo_delete() {
    let (_, stderr, ok) = gh_gate(&["repo", "delete", "navikt/cplt"]);
    assert!(!ok, "gh repo delete should be blocked");
    assert!(stderr.contains("BLOCKED"), "should show BLOCKED: {stderr}");
}

#[test]
fn gh_gate_blocks_repo_edit() {
    let (_, stderr, ok) = gh_gate(&["repo", "edit", "--visibility", "private"]);
    assert!(!ok, "gh repo edit should be blocked");
    assert!(stderr.contains("BLOCKED"), "should show BLOCKED: {stderr}");
}

#[test]
fn gh_gate_blocks_repo_archive() {
    let (_, stderr, ok) = gh_gate(&["repo", "archive"]);
    assert!(!ok, "gh repo archive should be blocked");
    assert!(stderr.contains("BLOCKED"), "should show BLOCKED: {stderr}");
}

#[test]
fn gh_gate_blocks_repo_fork() {
    let (_, stderr, ok) = gh_gate(&["repo", "fork"]);
    assert!(!ok, "gh repo fork should be blocked");
    assert!(stderr.contains("BLOCKED"), "should show BLOCKED: {stderr}");
}

// pr merge is always blocked (human decision), pr close is ScopeCheck
#[test]
fn gh_gate_blocks_pr_merge_always() {
    let (_, stderr, ok) = gh_gate(&["pr", "merge", "42"]);
    assert!(!ok, "gh pr merge should ALWAYS be blocked (human decision)");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn gh_gate_allows_pr_close_in_scope() {
    let (_, _, ok) = gh_gate(&["pr", "close", "42"]);
    assert!(ok, "gh pr close (in-scope) should be allowed");
}

#[test]
fn gh_gate_blocks_pr_merge_cross_repo() {
    let (_, stderr, ok) = gh_gate(&["pr", "merge", "42", "-R", "evil-org/other"]);
    assert!(!ok, "gh pr merge cross-repo should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn gh_gate_allows_issue_close_in_scope() {
    let (_, _, ok) = gh_gate(&["issue", "close", "99"]);
    assert!(ok, "gh issue close (in-scope) should be allowed");
}

#[test]
fn gh_gate_blocks_issue_close_cross_repo() {
    let (_, stderr, ok) = gh_gate(&["issue", "close", "99", "-R", "evil-org/other"]);
    assert!(!ok, "gh issue close cross-repo should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

// ============================================================
// gh-gate: Auth token exfiltration prevention
// ============================================================

#[test]
fn gh_gate_blocks_auth_token() {
    let (_, stderr, ok) = gh_gate(&["auth", "token"]);
    assert!(!ok, "gh auth token should be blocked");
    assert!(
        stderr.contains("BLOCKED"),
        "should mention blocked: {stderr}"
    );
}

#[test]
fn gh_gate_blocks_auth_token_with_hostname() {
    let (_, stderr, ok) = gh_gate(&["auth", "token", "--hostname", "github.com"]);
    assert!(!ok, "gh auth token with hostname should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn gh_gate_allows_auth_status() {
    let (_, _, ok) = gh_gate(&["auth", "status"]);
    assert!(ok, "gh auth status should be allowed (not exfiltration)");
}

#[test]
fn gh_gate_auth_token_allowed_when_disabled() {
    let (_, _, ok) = gh_gate_with_opts(&["auth", "token"], &["--no-block-auth-token"]);
    assert!(
        ok,
        "gh auth token should be allowed when --no-block-auth-token"
    );
}

// ============================================================
// gh-gate: Unknown commands (default: block)
// ============================================================

#[test]
fn gh_gate_blocks_unknown_command() {
    let (_, stderr, ok) = gh_gate(&["totally-new-command", "arg1"]);
    assert!(!ok, "unknown gh commands should be blocked by default");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn gh_gate_allows_unknown_when_policy_allows() {
    let (_, _, ok) = gh_gate_with_opts(&["totally-new-command"], &["--unknown-command=allow"]);
    assert!(ok, "unknown commands should pass when policy is 'allow'");
}

// ============================================================
// gh-gate: Scope check (cross-repo access)
// ============================================================

#[test]
fn gh_gate_allows_pr_list_cross_repo() {
    // pr list is Decision::Allow (read-only), so -R flag doesn't matter
    let (_, _, ok) = gh_gate(&["pr", "list", "-R", "evil-org/other-repo"]);
    assert!(ok, "gh pr list is read-only, allowed even cross-repo");
}

#[test]
fn gh_gate_blocks_cross_repo_pr_close() {
    let (_, stderr, ok) = gh_gate(&["pr", "close", "42", "-R", "evil-org/other-repo"]);
    assert!(
        !ok,
        "cross-repo gh pr close should be blocked by scope check"
    );
    assert!(stderr.contains("BLOCKED"), "should mention scope: {stderr}");
}

#[test]
fn gh_gate_blocks_cross_repo_pr_merge() {
    let (_, stderr, ok) = gh_gate(&["pr", "merge", "42", "--repo", "evil-org/other-repo"]);
    assert!(!ok, "cross-repo pr merge should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn gh_gate_allows_same_repo_pr_close() {
    // navikt/cplt is the git remote of the test project dir
    let (_, _, ok) = gh_gate(&["pr", "close", "42", "-R", "navikt/cplt"]);
    assert!(ok, "same-repo pr close should be allowed");
}

#[test]
fn gh_gate_scope_check_disabled() {
    let (_, _, ok) = gh_gate_with_opts(
        &["pr", "close", "42", "-R", "evil-org/other"],
        &["--no-scope-check"],
    );
    assert!(ok, "cross-repo should pass when scope check disabled");
}

#[test]
fn gh_gate_blocks_cross_repo_api_endpoint() {
    // API GET to a different repo's endpoint — scope check blocks it
    let (_, stderr, ok) = gh_gate(&["api", "/repos/evil-org/other-repo/pulls"]);
    assert!(
        !ok,
        "cross-repo API GET via URL path should be blocked: stderr={stderr}"
    );
}

#[test]
fn gh_gate_allows_same_repo_api_endpoint() {
    let (_, _, ok) = gh_gate(&["api", "/repos/navikt/cplt/pulls"]);
    assert!(ok, "same-repo API GET via URL path should be allowed");
}

#[test]
fn gh_gate_allows_relative_api_endpoint() {
    // Relative paths (no leading /repos/) are resolved by gh to current repo
    let (_, _, ok) = gh_gate(&["api", "pulls/67/comments"]);
    assert!(
        ok,
        "relative API paths should be allowed (resolved to current repo)"
    );
}

#[test]
fn gh_gate_blocks_non_repo_api_endpoint() {
    // Endpoints like /user, /orgs don't target the current repo — blocked for security
    let (_, stderr, ok) = gh_gate(&["api", "/user"]);
    assert!(!ok, "non-repo API endpoints should be blocked");
    assert!(
        stderr.contains("BLOCKED") || stderr.contains("blocked"),
        "should indicate blocked: {stderr}"
    );
}

// ============================================================
// gh-gate: Enforcement modes
// ============================================================

#[test]
fn gh_gate_warn_mode_allows_blocked_command() {
    let (_, stderr, ok) = gh_gate_with_opts(&["pr", "merge", "42"], &["--mode=warn"]);
    // In warn mode, the command is allowed through (exec /usr/bin/true → success)
    assert!(ok, "warn mode should allow through");
    assert!(stderr.contains("WARNING"), "should show warning: {stderr}");
}

#[test]
fn gh_gate_audit_mode_allows_blocked_command() {
    let (_, stderr, ok) = gh_gate_with_opts(&["pr", "merge", "42"], &["--mode=audit"]);
    assert!(ok, "audit mode should allow through");
    assert!(
        stderr.contains("[audit]"),
        "should show audit log: {stderr}"
    );
}

// ============================================================
// gh-gate: API mutation detection
// ============================================================

#[test]
fn gh_gate_blocks_api_post_with_dash_x() {
    let (_, stderr, ok) = gh_gate(&["api", "-X", "POST", "/repos/navikt/cplt/issues"]);
    assert!(!ok, "gh api POST should be blocked (mutating): {stderr}");
}

#[test]
fn gh_gate_blocks_api_post_combined_flag() {
    let (_, stderr, ok) = gh_gate(&["api", "-XPOST", "/repos/navikt/cplt/issues"]);
    assert!(!ok, "gh api -XPOST should be blocked (mutating): {stderr}");
}

#[test]
fn gh_gate_blocks_api_delete() {
    let (_, _, ok) = gh_gate(&["api", "-XDELETE", "/repos/navikt/cplt/issues/1"]);
    assert!(!ok, "gh api DELETE should be blocked");
}

#[test]
fn gh_gate_blocks_api_with_input_flags() {
    let (_, _, ok) = gh_gate(&["api", "/repos/navikt/cplt/issues", "-f", "title=pwned"]);
    assert!(!ok, "gh api with -f (implies POST) should be blocked");
}

// ============================================================
// gh-gate: allow_api_write opt-in
// ============================================================

#[test]
fn gh_gate_allow_api_write_permits_post_in_scope() {
    // With --allow-api-write, POST to current repo's PR comment replies should be allowed.
    // This is the real-world use case: agent posts inline review comment replies.
    let (_, stderr, ok) = gh_gate_with_opts(
        &[
            "api",
            "repos/navikt/cplt/pulls/comments/3333053793/replies",
            "--method",
            "POST",
            "--field",
            "body=Fixed in abc123",
        ],
        &["--allow-api-write"],
    );
    assert!(
        ok,
        "gh api POST to current repo's PR comment replies should be allowed with allow_api_write: {stderr}"
    );
}

#[test]
fn gh_gate_allow_api_write_still_blocks_graphql() {
    // GraphQL must remain blocked even with --allow-api-write — arbitrary mutations
    // cannot be statically scope-checked.
    let (_, _, ok) = gh_gate_with_opts(&["api", "graphql"], &["--allow-api-write"]);
    assert!(
        !ok,
        "gh api graphql must be blocked even with allow_api_write"
    );
}

#[test]
fn gh_gate_allow_api_write_blocks_cross_repo_post() {
    // Scope check must still apply: POST to another repo is blocked.
    let (_, _, ok) = gh_gate_with_opts(
        &[
            "api",
            "repos/evil-org/other-repo/issues",
            "--method",
            "POST",
            "--field",
            "title=pwned",
        ],
        &["--allow-api-write"],
    );
    assert!(
        !ok,
        "gh api POST to a different repo must still be blocked by scope check"
    );
}

#[test]
fn gh_gate_default_still_blocks_api_post() {
    // Regression: default (no --allow-api-write) must still block writes.
    let (_, _, ok) = gh_gate(&[
        "api",
        "repos/navikt/cplt/pulls/comments/123/replies",
        "--method",
        "POST",
        "--field",
        "body=test",
    ]);
    assert!(
        !ok,
        "gh api POST must be blocked by default (no allow_api_write)"
    );
}

#[test]
fn gh_gate_allows_empty_args() {
    // `gh` with no args shows help — harmless, should be allowed
    let (_, _, ok) = gh_gate(&[]);
    assert!(ok, "empty args (shows help) should be allowed");
}

#[test]
fn gh_gate_allows_only_flags() {
    // `gh --help`, `gh --version` — informational, always allowed
    let (_, _, ok) = gh_gate(&["--verbose", "--help"]);
    assert!(ok, "only flags (e.g. --help) should be allowed");
}

#[test]
fn gh_gate_allows_help_command() {
    let (_, _, ok) = gh_gate(&["help"]);
    assert!(ok, "gh help should be allowed");
}

#[test]
fn gh_gate_allows_version_command() {
    let (_, _, ok) = gh_gate(&["version"]);
    assert!(ok, "gh version should be allowed");
}

// -- Input flag bypass via =value form --

#[test]
fn gh_gate_blocks_field_equals_form() {
    // Agent tries: gh api /repos/x/y/issues --field=title=pwned
    let (_, _, ok) = gh_gate(&["api", "/repos/navikt/cplt/issues", "--field=title=pwned"]);
    assert!(
        !ok,
        "--field=value form must be detected as write operation"
    );
}

#[test]
fn gh_gate_blocks_raw_field_equals_form() {
    let (_, _, ok) = gh_gate(&[
        "api",
        "/repos/navikt/cplt/issues",
        "--raw-field=body=hacked",
    ]);
    assert!(!ok, "--raw-field=value form must be detected as write");
}

#[test]
fn gh_gate_blocks_input_equals_form() {
    let (_, _, ok) = gh_gate(&["api", "/repos/navikt/cplt/issues", "--input=-"]);
    assert!(!ok, "--input=- form must be detected as write");
}

#[test]
fn gh_gate_blocks_short_f_combined() {
    // Agent tries: gh api /repos/x/y/issues -ftitle=pwned
    let (_, _, ok) = gh_gate(&["api", "/repos/navikt/cplt/issues", "-ftitle=pwned"]);
    assert!(!ok, "-f<value> combined form must be detected as write");
}

#[test]
fn gh_gate_blocks_short_f_uppercase_combined() {
    let (_, _, ok) = gh_gate(&["api", "/repos/navikt/cplt/issues", "-Ftitle=pwned"]);
    assert!(!ok, "-F<value> combined form must be detected as write");
}

// -- GraphQL bypass --

#[test]
fn gh_gate_blocks_graphql_endpoint() {
    // Agent tries: echo '{"query":"mutation{...}"}' | gh api graphql
    let (_, stderr, ok) = gh_gate(&["api", "graphql"]);
    assert!(
        !ok,
        "gh api graphql must be blocked (arbitrary mutations via stdin)"
    );
    assert!(
        stderr.contains("graphql"),
        "should mention graphql: {stderr}"
    );
}

#[test]
fn gh_gate_blocks_graphql_with_slash() {
    let (_, _, ok) = gh_gate(&["api", "/graphql"]);
    assert!(!ok, "gh api /graphql must be blocked");
}

#[test]
fn gh_gate_blocks_graphql_trailing_slash() {
    // Trailing slash should not bypass the graphql block
    let (_, _, ok) = gh_gate(&["api", "graphql/"]);
    assert!(!ok, "gh api graphql/ must be blocked");
    let (_, _, ok) = gh_gate(&["api", "/graphql/"]);
    assert!(!ok, "gh api /graphql/ must be blocked");
}

#[test]
fn gh_gate_blocks_graphql_with_query_params() {
    let (_, _, ok) = gh_gate(&["api", "graphql?foo=bar"]);
    assert!(!ok, "gh api graphql?foo=bar must be blocked");
}

#[test]
fn gh_gate_blocks_graphql_with_method() {
    // Even explicit GET to graphql should be blocked (mutations can be sent as GET with query param)
    let (_, _, ok) = gh_gate(&["api", "-XGET", "graphql"]);
    assert!(!ok, "gh api GET graphql must still be blocked");
}

// ============================================================
// git-gate: Read operations (should be ALLOWED)
// ============================================================

#[test]
fn git_gate_allows_status() {
    let (_, _, ok) = git_gate(&["status"], true, true);
    assert!(ok, "git status should always be allowed");
}

#[test]
fn git_gate_allows_log() {
    let (_, _, ok) = git_gate(&["log", "--oneline", "-10"], true, true);
    assert!(ok, "git log should always be allowed");
}

#[test]
fn git_gate_allows_diff() {
    let (_, _, ok) = git_gate(&["diff", "HEAD~1"], true, true);
    assert!(ok, "git diff should always be allowed");
}

#[test]
fn git_gate_allows_fetch() {
    let (_, _, ok) = git_gate(&["fetch", "origin"], true, true);
    assert!(ok, "git fetch should always be allowed");
}

#[test]
fn git_gate_allows_pull() {
    let (_, _, ok) = git_gate(&["pull"], true, true);
    assert!(ok, "git pull should always be allowed");
}

#[test]
fn git_gate_allows_branch() {
    let (_, _, ok) = git_gate(&["branch", "-a"], true, true);
    assert!(ok, "git branch should always be allowed");
}

// ============================================================
// git-gate: Local write operations (should be ALLOWED)
// ============================================================

#[test]
fn git_gate_allows_commit() {
    let (_, _, ok) = git_gate(&["commit", "-m", "fix bug"], true, true);
    assert!(ok, "git commit should be allowed (local write)");
}

#[test]
fn git_gate_allows_add() {
    let (_, _, ok) = git_gate(&["add", "."], true, true);
    assert!(ok, "git add should be allowed");
}

#[test]
fn git_gate_allows_checkout() {
    let (_, _, ok) = git_gate(&["checkout", "-b", "feature"], true, true);
    assert!(ok, "git checkout should be allowed");
}

#[test]
fn git_gate_allows_merge() {
    let (_, _, ok) = git_gate(&["merge", "main"], true, true);
    assert!(ok, "git merge should be allowed");
}

#[test]
fn git_gate_allows_rebase() {
    let (_, _, ok) = git_gate(&["rebase", "main"], true, true);
    assert!(ok, "git rebase should be allowed");
}

#[test]
fn git_gate_allows_stash() {
    let (_, _, ok) = git_gate(&["stash"], true, true);
    assert!(ok, "git stash should be allowed");
}

// ============================================================
// git-gate: Push blocking (prevent_push=true)
// ============================================================

#[test]
fn git_gate_blocks_push() {
    let (_, stderr, ok) = git_gate(&["push"], true, true);
    assert!(!ok, "git push should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn git_gate_blocks_push_with_remote() {
    let (_, stderr, ok) = git_gate(&["push", "origin", "main"], true, true);
    assert!(!ok, "git push origin main should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn git_gate_blocks_push_force() {
    let (_, stderr, ok) = git_gate(&["push", "--force", "origin", "main"], true, true);
    assert!(!ok, "git push --force should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn git_gate_blocks_send_pack() {
    let (_, stderr, ok) = git_gate(&["send-pack", "origin"], true, true);
    assert!(!ok, "git send-pack should be blocked (push equivalent)");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

// ============================================================
// git-gate: Push allowed, force-push blocked
// ============================================================

#[test]
fn git_gate_allows_push_when_not_prevented() {
    let (_, _, ok) = git_gate(&["push", "origin", "main"], false, false);
    assert!(ok, "git push should be allowed when prevent_push=false");
}

#[test]
fn git_gate_blocks_force_push_when_prevented() {
    let (_, stderr, ok) = git_gate(&["push", "--force", "origin", "main"], false, true);
    assert!(
        !ok,
        "git push --force should be blocked when prevent_force_push=true"
    );
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn git_gate_blocks_force_with_lease() {
    let (_, stderr, ok) = git_gate(
        &["push", "--force-with-lease", "origin", "main"],
        false,
        true,
    );
    assert!(
        !ok,
        "git push --force-with-lease should be blocked: {stderr}"
    );
}

#[test]
fn git_gate_blocks_force_if_includes() {
    let (_, stderr, ok) = git_gate(
        &["push", "--force-if-includes", "origin", "main"],
        false,
        true,
    );
    assert!(!ok, "git push --force-if-includes should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn git_gate_blocks_short_force_flag() {
    let (_, stderr, ok) = git_gate(&["push", "-f", "origin", "main"], false, true);
    assert!(!ok, "git push -f should be blocked: {stderr}");
}

#[test]
fn git_gate_allows_non_force_push_when_only_force_prevented() {
    let (_, _, ok) = git_gate(&["push", "origin", "main"], false, true);
    assert!(
        ok,
        "regular push should be allowed when only force-push is prevented"
    );
}

// ============================================================
// git-gate: Enforcement modes
// ============================================================

#[test]
fn git_gate_warn_mode_allows_push() {
    let (_, stderr, ok) = git_gate_with_mode(&["push"], true, true, "warn");
    assert!(ok, "warn mode should allow through");
    assert!(stderr.contains("WARNING"), "should warn: {stderr}");
}

#[test]
fn git_gate_audit_mode_allows_push() {
    let (_, stderr, ok) = git_gate_with_mode(&["push"], true, true, "audit");
    assert!(ok, "audit mode should allow through");
    assert!(stderr.contains("[audit]"), "should audit log: {stderr}");
}

// ============================================================
// git-gate: Bypass attempts (security regression tests)
// ============================================================

#[test]
fn git_gate_blocks_push_with_refspec() {
    let (_, _, ok) = git_gate(&["push", "origin", "HEAD:refs/heads/main"], true, true);
    assert!(!ok, "git push with refspec should still be blocked");
}

#[test]
fn git_gate_blocks_push_with_set_upstream() {
    let (_, _, ok) = git_gate(&["push", "--set-upstream", "origin", "feature"], true, true);
    assert!(!ok, "git push --set-upstream should still be blocked");
}

#[test]
fn git_gate_blocks_push_u_shorthand() {
    let (_, _, ok) = git_gate(&["push", "-u", "origin", "feature"], true, true);
    assert!(!ok, "git push -u should still be blocked");
}

// -- Force-push =value form bypass --

#[test]
fn git_gate_blocks_force_with_lease_equals_ref() {
    // Agent tries: git push --force-with-lease=main origin main
    let (_, stderr, ok) = git_gate(
        &["push", "--force-with-lease=main", "origin", "main"],
        false,
        true,
    );
    assert!(
        !ok,
        "--force-with-lease=<ref> must be detected as force push: {stderr}"
    );
}

#[test]
fn git_gate_blocks_force_if_includes_equals_ref() {
    let (_, _, ok) = git_gate(
        &["push", "--force-if-includes=HEAD~3", "origin", "main"],
        false,
        true,
    );
    assert!(
        !ok,
        "--force-if-includes=<ref> must be detected as force push"
    );
}

// ============================================================
// git-gate: protect-default-branch-only mode
// ============================================================

#[test]
fn git_gate_protect_default_blocks_push_to_main() {
    let (_, stderr, ok) = git_gate_protect_default(&["push", "origin", "main"]);
    assert!(!ok, "push to main should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn git_gate_protect_default_blocks_push_to_master() {
    let (_, stderr, ok) = git_gate_protect_default(&["push", "origin", "master"]);
    assert!(!ok, "push to master should be blocked");
    assert!(stderr.contains("BLOCKED"), "should block: {stderr}");
}

#[test]
fn git_gate_protect_default_allows_push_to_feature_branch() {
    let (_, _, ok) = git_gate_protect_default(&["push", "origin", "feature/my-work"]);
    assert!(ok, "push to feature branch should be allowed");
}

#[test]
fn git_gate_protect_default_allows_push_to_copilot_branch() {
    let (_, _, ok) = git_gate_protect_default(&["push", "origin", "copilot/fix-123"]);
    assert!(ok, "push to copilot branch should be allowed");
}

#[test]
fn git_gate_protect_default_blocks_bare_push() {
    // Bare push can't verify branch (real-git=/usr/bin/true) → fail closed
    let (_, _, ok) = git_gate_protect_default(&["push"]);
    assert!(
        !ok,
        "bare git push should be blocked when branch can't be resolved"
    );
}

#[test]
fn git_gate_protect_default_blocks_push_with_remote_only() {
    // `git push origin` — can't verify branch → fail closed
    let (_, _, ok) = git_gate_protect_default(&["push", "origin"]);
    assert!(
        !ok,
        "push with only remote should be blocked when branch can't be resolved"
    );
}

#[test]
fn git_gate_protect_default_blocks_refspec_to_main() {
    let (_, _, ok) = git_gate_protect_default(&["push", "origin", "HEAD:refs/heads/main"]);
    assert!(!ok, "push with refspec targeting main should be blocked");
}

#[test]
fn git_gate_protect_default_allows_refspec_to_feature() {
    let (_, _, ok) =
        git_gate_protect_default(&["push", "origin", "HEAD:refs/heads/feature/branch"]);
    assert!(ok, "push with refspec targeting feature should be allowed");
}

#[test]
fn git_gate_protect_default_blocks_origin_slash_main() {
    let (_, _, ok) = git_gate_protect_default(&["push", "origin", "origin/main"]);
    assert!(!ok, "push to origin/main should be blocked");
}

// ── Security hardening tests ────────────────────────────────────

#[test]
fn git_gate_blocks_alias_via_dash_c() {
    // `-c alias.p=push` must be caught to prevent bypass
    let (_, stderr, ok) = git_gate(&["-c", "alias.p=push", "p", "origin", "main"], true, true);
    assert!(!ok, "git -c alias.p=push should be blocked: {stderr}");
}

#[test]
fn git_gate_blocks_unknown_subcommand_when_push_prevented() {
    // Unknown subcommands blocked to prevent alias-based bypass
    let (_, _, ok) = git_gate(
        &["subtree", "push", "--prefix=lib", "origin", "main"],
        true,
        true,
    );
    assert!(!ok, "git subtree push should be blocked");
    let (_, _, ok) = git_gate(&["random-extension"], true, true);
    assert!(
        !ok,
        "unknown git subcommand should be blocked when push prevented"
    );
}

#[test]
fn git_gate_protect_default_blocks_force_push_to_feature() {
    // Force push to feature branch must be blocked when prevent_force_push=true
    let (_, _, ok) = git_gate_protect_default(&["push", "--force", "origin", "feature-branch"]);
    assert!(!ok, "force push to feature branch should be blocked");
    let (_, _, ok) = git_gate_protect_default(&["push", "-f", "origin", "my-feature"]);
    assert!(!ok, "-f to feature branch should be blocked");
    let (_, _, ok) = git_gate_protect_default(&["push", "--force-with-lease", "origin", "feature"]);
    assert!(!ok, "--force-with-lease to feature should be blocked");
}

#[test]
fn git_gate_protect_default_blocks_multi_refspec_with_main() {
    // `git push origin feature main` should be blocked (main is a default branch)
    let (_, _, ok) = git_gate_protect_default(&["push", "origin", "feature", "main"]);
    assert!(!ok, "multi-refspec including main should be blocked");
    let (_, _, ok) = git_gate_protect_default(&[
        "push",
        "origin",
        "HEAD:refs/heads/feature",
        "HEAD:refs/heads/master",
    ]);
    assert!(!ok, "multi-refspec including master should be blocked");
}

// ============================================================
// Full wrapper script integration (sandbox → wrapper → gate)
// ============================================================

#[cfg(target_os = "macos")]
mod sandbox_integration {
    use super::*;
    use std::fs;

    fn sandbox_exec_available() -> bool {
        Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    macro_rules! require_sandbox {
        () => {
            if !sandbox_exec_available() {
                eprintln!("SKIPPED: sandbox-exec not available");
                return;
            }
        };
    }

    /// Create a temp dir inside the cplt repo (not /tmp): the sandbox denies
    /// process-exec under /private/tmp and /private/var/folders, so the fake
    /// wrapper/agent scripts here must live in an exec-allowed location.
    ///
    /// Backed by `tempfile::TempDir`, so it auto-deletes on drop — including on
    /// panic (Drop runs during unwind). The `.cplt-e2e-` prefix keeps the single
    /// defensive `.gitignore` pattern effective if a run is SIGKILLed.
    fn temp_project(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!(".cplt-e2e-guard-{name}-"))
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("create temp dir")
    }

    /// Test the full pipeline: fake agent script calls gh wrapper → cplt gh-gate → blocked.
    #[test]
    fn wrapper_blocks_gh_pr_merge_in_sandbox() {
        require_sandbox!();

        let tmp = temp_project("gh-wrapper");
        let cplt = binary_path();
        let cplt_str = cplt.to_string_lossy();

        // Create a git repo so scope check can detect the remote
        let run_git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(tmp.path())
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@test.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@test.com")
                .output()
                .expect("git");
        };
        run_git(&["init", "-b", "main"]);
        run_git(&["commit", "--allow-empty", "-m", "init"]);
        run_git(&[
            "remote",
            "add",
            "origin",
            "https://github.com/navikt/cplt.git",
        ]);

        // Create gh wrapper script (same as cplt would generate)
        let wrapper_content = format!(
            "#!/bin/sh\nexec {cplt_str} gh-gate --real-gh /usr/bin/true --mode=block --scope-check --block-auth-token --unknown-command=block -- \"$@\"\n"
        );
        let bin_dir = tmp.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let wrapper_path = bin_dir.join("gh");
        fs::write(&wrapper_path, &wrapper_content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wrapper_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create fake agent that tries destructive operations via the wrapper
        let agent_script = format!(
            r#"#!/bin/sh
set -eu
cd {project}

# Try pr merge (should fail)
if {bin_dir}/gh pr merge 42 2>/dev/null; then
    echo "RESULT:pr_merge:ALLOWED"
else
    echo "RESULT:pr_merge:BLOCKED"
fi

# Try pr list (should succeed)
if {bin_dir}/gh pr list 2>/dev/null; then
    echo "RESULT:pr_list:ALLOWED"
else
    echo "RESULT:pr_list:BLOCKED"
fi

# Try auth token (should fail)
if {bin_dir}/gh auth token 2>/dev/null; then
    echo "RESULT:auth_token:ALLOWED"
else
    echo "RESULT:auth_token:BLOCKED"
fi

# Try cross-repo (should fail — pr close is ScopeCheck, not Allow)
if {bin_dir}/gh pr close 99 -R evil-org/other-repo 2>/dev/null; then
    echo "RESULT:cross_repo:ALLOWED"
else
    echo "RESULT:cross_repo:BLOCKED"
fi
"#,
            project = tmp.path().display(),
            bin_dir = bin_dir.display(),
        );

        let agent_path = tmp.path().join("agent.sh");
        fs::write(&agent_path, &agent_script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&agent_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let output = Command::new("/bin/sh")
            .arg(&agent_path)
            .current_dir(tmp.path())
            .output()
            .expect("agent script should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stdout.contains("RESULT:pr_merge:BLOCKED"),
            "pr merge should be blocked.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:pr_list:ALLOWED"),
            "pr list should be allowed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:auth_token:BLOCKED"),
            "auth token should be blocked.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:cross_repo:BLOCKED"),
            "cross-repo should be blocked.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    /// Test git wrapper blocks push but allows read ops.
    #[test]
    fn wrapper_blocks_git_push_in_sandbox() {
        require_sandbox!();

        let tmp = temp_project("git-wrapper");
        let cplt = binary_path();
        let cplt_str = cplt.to_string_lossy();

        // Create git wrapper script
        let wrapper_content = format!(
            "#!/bin/sh\nexec {cplt_str} git-gate --real-git /usr/bin/true --mode=block --prevent-push=true --prevent-force-push=true -- \"$@\"\n"
        );
        let bin_dir = tmp.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let wrapper_path = bin_dir.join("git");
        fs::write(&wrapper_path, &wrapper_content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wrapper_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create fake agent that tests git operations via the wrapper
        let agent_script = format!(
            r#"#!/bin/sh
set -eu

# Try push (should fail)
if {bin_dir}/git push origin main 2>/dev/null; then
    echo "RESULT:push:ALLOWED"
else
    echo "RESULT:push:BLOCKED"
fi

# Try force push (should fail)
if {bin_dir}/git push --force origin main 2>/dev/null; then
    echo "RESULT:force_push:ALLOWED"
else
    echo "RESULT:force_push:BLOCKED"
fi

# Try send-pack (should fail)
if {bin_dir}/git send-pack origin 2>/dev/null; then
    echo "RESULT:send_pack:ALLOWED"
else
    echo "RESULT:send_pack:BLOCKED"
fi

# Try status (should succeed)
if {bin_dir}/git status 2>/dev/null; then
    echo "RESULT:status:ALLOWED"
else
    echo "RESULT:status:BLOCKED"
fi

# Try log (should succeed)
if {bin_dir}/git log --oneline 2>/dev/null; then
    echo "RESULT:log:ALLOWED"
else
    echo "RESULT:log:BLOCKED"
fi

# Try commit (should succeed — local write)
if {bin_dir}/git commit -m "test" 2>/dev/null; then
    echo "RESULT:commit:ALLOWED"
else
    echo "RESULT:commit:BLOCKED"
fi
"#,
            bin_dir = bin_dir.display(),
        );

        let agent_path = tmp.path().join("agent.sh");
        fs::write(&agent_path, &agent_script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&agent_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let output = Command::new("/bin/sh")
            .arg(&agent_path)
            .current_dir(tmp.path())
            .output()
            .expect("agent script should run");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stdout.contains("RESULT:push:BLOCKED"),
            "push should be blocked.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:force_push:BLOCKED"),
            "force push should be blocked.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:send_pack:BLOCKED"),
            "send-pack should be blocked.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:status:ALLOWED"),
            "status should be allowed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:log:ALLOWED"),
            "log should be allowed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("RESULT:commit:ALLOWED"),
            "commit should be allowed.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}
