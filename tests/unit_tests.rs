//! Unit tests for sandbox profile generation, domain blocking, and IP checks.
//!
//! These tests verify core logic without invoking sandbox-exec,
//! so they run on any platform (Linux CI, macOS, etc.).

use cplt::discover::copilot_pkg_dir;
use cplt::is_unsafe_root;
use cplt::proxy::{is_blocked_in_content, is_domain_match, is_private_hostname, is_private_ip};
use cplt::sandbox::{
    HardeningCategory, ProfileOptions, SandboxConfig, build_sandbox_env, generate_policy,
    generate_profile, tool_override_path_is_safe, tool_path_env_overrides, validate_sbpl_path,
};

// ============================================================
// Unsafe root detection
// ============================================================

#[test]
fn rejects_filesystem_root() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/"), home));
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_users_dir() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/Users"), home));
}

#[test]
fn rejects_tmp() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/tmp"), home));
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_private_tmp() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/private/tmp"), home));
}

#[test]
fn rejects_var() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/var"), home));
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_private_var() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/private/var"), home));
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_applications() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/Applications"), home));
}

#[cfg(target_os = "macos")]
#[test]
fn rejects_system() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/System"), home));
}

#[test]
fn rejects_home_dir() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(home, home));
}

#[test]
fn allows_project_subdir() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(!is_unsafe_root(
        std::path::Path::new("/Users/testuser/projects/my-app"),
        home
    ));
}

#[test]
fn allows_deep_project_path() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(!is_unsafe_root(
        std::path::Path::new("/Users/testuser/go/src/github.com/org/repo"),
        home
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_linux_unsafe_roots() {
    let home = std::path::Path::new("/home/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/home"), home));
    assert!(is_unsafe_root(std::path::Path::new("/proc"), home));
    assert!(is_unsafe_root(std::path::Path::new("/sys"), home));
    assert!(is_unsafe_root(std::path::Path::new("/boot"), home));
    assert!(is_unsafe_root(std::path::Path::new("/usr"), home));
    assert!(is_unsafe_root(std::path::Path::new("/etc"), home));
    assert!(is_unsafe_root(std::path::Path::new("/var/tmp"), home));
}

// ============================================================
// Domain blocking (using real proxy::is_blocked_in_content)
// ============================================================

#[test]
fn blocks_exact_domain_match() {
    let blocklist = "evil.com\npastebin.com\n";
    assert!(is_blocked_in_content("evil.com", blocklist));
    assert!(is_blocked_in_content("pastebin.com", blocklist));
}

#[test]
fn blocks_subdomain_match() {
    let blocklist = "evil.com\n";
    assert!(is_blocked_in_content("sub.evil.com", blocklist));
    assert!(is_blocked_in_content("deep.sub.evil.com", blocklist));
}

#[test]
fn does_not_block_partial_match() {
    let blocklist = "evil.com\n";
    assert!(!is_blocked_in_content("notevil.com", blocklist));
    assert!(!is_blocked_in_content("evil.com.safe.org", blocklist));
}

#[test]
fn allows_unlisted_domain() {
    let blocklist = "evil.com\n";
    assert!(!is_blocked_in_content("good.com", blocklist));
    assert!(!is_blocked_in_content("api.github.com", blocklist));
}

#[test]
fn ignores_comments_and_empty_lines() {
    let blocklist = "# This is a comment\n\nevil.com\n  # Another comment\n";
    assert!(is_blocked_in_content("evil.com", blocklist));
    assert!(!is_blocked_in_content("good.com", blocklist));
}

#[test]
fn case_insensitive_blocking() {
    let blocklist = "Evil.COM\n";
    assert!(is_blocked_in_content("evil.com", blocklist));
    assert!(is_blocked_in_content("EVIL.COM", blocklist));
    assert!(is_blocked_in_content("Evil.Com", blocklist));
}

#[test]
fn empty_blocklist_blocks_nothing() {
    assert!(!is_blocked_in_content("evil.com", ""));
    assert!(!is_blocked_in_content("anything.org", "# only comments\n"));
}

#[test]
fn trailing_dot_normalized_in_blocklist() {
    let blocklist = "evil.com\n";
    assert!(is_blocked_in_content("evil.com.", blocklist));
    assert!(is_blocked_in_content("sub.evil.com.", blocklist));
}

#[test]
fn trailing_dot_in_blocklist_pattern() {
    let blocklist = "evil.com.\n";
    assert!(is_blocked_in_content("evil.com", blocklist));
    assert!(is_blocked_in_content("evil.com.", blocklist));
}

// ============================================================
// Domain allowlist matching
// ============================================================

#[test]
fn allowlist_exact_match() {
    let domains = vec![
        "api.github.com".to_string(),
        "copilot.github.com".to_string(),
    ];
    assert!(is_domain_match("api.github.com", &domains));
    assert!(is_domain_match("copilot.github.com", &domains));
    assert!(!is_domain_match("evil.com", &domains));
}

#[test]
fn allowlist_subdomain_match() {
    let domains = vec!["github.com".to_string()];
    assert!(is_domain_match("api.github.com", &domains));
    assert!(is_domain_match("api.business.github.com", &domains));
    assert!(!is_domain_match("notgithub.com", &domains));
}

#[test]
fn allowlist_case_insensitive() {
    let domains = vec!["api.github.com".to_string()];
    assert!(is_domain_match("API.GITHUB.COM", &domains));
    assert!(is_domain_match("Api.GitHub.Com", &domains));
}

#[test]
fn allowlist_trailing_dot_normalized() {
    let domains = vec!["api.github.com".to_string()];
    assert!(is_domain_match("api.github.com.", &domains));
}

#[test]
fn allowlist_empty_allows_nothing() {
    let domains: Vec<String> = vec![];
    // Empty allowlist check is done in handle_connect (short-circuit),
    // but is_domain_match itself returns false for empty list.
    assert!(!is_domain_match("anything.com", &domains));
}

#[test]
fn allowlist_no_partial_match() {
    let domains = vec!["github.com".to_string()];
    assert!(!is_domain_match("mygithub.com", &domains));
    assert!(!is_domain_match("github.com.evil.org", &domains));
}

// ============================================================
// Private IP / localhost detection (using real proxy functions)
// ============================================================

#[test]
fn detects_ipv4_loopback() {
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert!(is_private_ip(&ip));
    let ip2: std::net::IpAddr = "127.0.0.2".parse().unwrap();
    assert!(is_private_ip(&ip2));
}

#[test]
fn detects_ipv4_private_ranges() {
    for addr in &["10.0.0.1", "172.16.0.1", "192.168.1.1"] {
        let ip: std::net::IpAddr = addr.parse().unwrap();
        assert!(is_private_ip(&ip), "should detect {addr} as private");
    }
}

#[test]
fn detects_ipv4_link_local() {
    let ip: std::net::IpAddr = "169.254.1.1".parse().unwrap();
    assert!(is_private_ip(&ip));
}

#[test]
fn detects_ipv4_unspecified() {
    let ip: std::net::IpAddr = "0.0.0.0".parse().unwrap();
    assert!(is_private_ip(&ip));
}

#[test]
fn detects_ipv6_loopback() {
    let ip: std::net::IpAddr = "::1".parse().unwrap();
    assert!(is_private_ip(&ip));
}

#[test]
fn allows_public_ipv4() {
    for addr in &["8.8.8.8", "140.82.121.3"] {
        let ip: std::net::IpAddr = addr.parse().unwrap();
        assert!(!is_private_ip(&ip), "should allow public {addr}");
    }
}

#[test]
fn detects_localhost_hostname() {
    assert!(is_private_hostname("localhost"));
    assert!(is_private_hostname("sub.localhost"));
}

#[test]
fn detects_dot_local_hostname() {
    assert!(is_private_hostname("myhost.local"));
}

#[test]
fn allows_normal_hostnames() {
    assert!(!is_private_hostname("api.github.com"));
    assert!(!is_private_hostname("registry.npmjs.org"));
}

// ============================================================
// New: CGNAT, ULA, IPv4-mapped v6
// ============================================================

#[test]
fn detects_cgnat_range() {
    let ip: std::net::IpAddr = "100.64.0.1".parse().unwrap();
    assert!(is_private_ip(&ip), "CGNAT (100.64/10) should be private");
    let ip2: std::net::IpAddr = "100.127.255.254".parse().unwrap();
    assert!(is_private_ip(&ip2));
}

#[test]
fn detects_benchmarking_range() {
    let ip: std::net::IpAddr = "198.18.0.1".parse().unwrap();
    assert!(
        is_private_ip(&ip),
        "Benchmarking (198.18/15) should be private"
    );
}

#[test]
fn detects_reserved_v4() {
    let ip: std::net::IpAddr = "240.0.0.1".parse().unwrap();
    assert!(is_private_ip(&ip), "Reserved (240/4) should be private");
}

#[test]
fn detects_ipv6_ula() {
    let ip: std::net::IpAddr = "fd12:3456:789a::1".parse().unwrap();
    assert!(is_private_ip(&ip), "ULA (fc00::/7) should be private");
}

#[test]
fn detects_ipv6_link_local() {
    let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
    assert!(
        is_private_ip(&ip),
        "Link-local v6 (fe80::/10) should be private"
    );
}

// ============================================================
// allow_private_domains — config merge and proxy bypass logic
// ============================================================

#[test]
fn allow_private_domains_merge_cli_and_toml() {
    use cplt::config::{CliFlags, Config};
    let toml = "[proxy]\nallow_private_domains = [\"intern.nav.no\"]\n";
    let cli = CliFlags {
        allow_private_domains: vec!["dev.corp.example.com".to_string()],
        ..Default::default()
    };
    let resolved = Config::parse(toml).unwrap().merge(cli).unwrap();
    assert!(
        resolved
            .allow_private_domains
            .contains(&"intern.nav.no".to_string())
    );
    assert!(
        resolved
            .allow_private_domains
            .contains(&"dev.corp.example.com".to_string())
    );
}

#[test]
fn allow_private_domains_deduplicates() {
    use cplt::config::{CliFlags, Config};
    let toml = "[proxy]\nallow_private_domains = [\"intern.nav.no\", \"intern.nav.no\"]\n";
    let resolved = Config::parse(toml)
        .unwrap()
        .merge(CliFlags::default())
        .unwrap();
    assert_eq!(
        resolved
            .allow_private_domains
            .iter()
            .filter(|d| *d == "intern.nav.no")
            .count(),
        1
    );
}

#[test]
fn allow_private_domains_rejects_empty_string() {
    use cplt::config::{CliFlags, Config};
    let toml = "[proxy]\nallow_private_domains = [\"\"]\n";
    let result = Config::parse(toml).unwrap().merge(CliFlags::default());
    assert!(result.is_err(), "empty domain should be rejected");
}

// #126 Tier 2: `allow_private_domains_bypasses_private_ip_check` used to live
// here, but it only re-implemented the guard's boolean expression with local
// constants and never drove `handle_connect`, so deleting the real private-IP
// SSRF guard left it green (vacuous). `handle_connect` and the test-only DNS
// resolver are private to the `cplt` crate and cannot be reached from this
// external integration-test crate, so the real end-to-end replacement lives in
// `src/proxy.rs`: `proxy_blocks_private_ip_resolution_when_not_allowlisted` and
// `proxy_allowlist_bypasses_private_ip_block`. The `is_domain_match` suffix
// semantics this test also touched are still covered below.
#[test]
fn proxy_upstream_parsed_from_config() {
    use cplt::config::{CliFlags, Config};
    let toml = "[proxy]\nupstream = \"http://corp-proxy.example.com:8080\"\n";
    let resolved = Config::parse(toml)
        .unwrap()
        .merge(CliFlags::default())
        .unwrap();
    let up = resolved.proxy_upstream.expect("upstream should be set");
    assert_eq!(up.host, "corp-proxy.example.com");
    assert_eq!(up.port, 8080);
}

#[test]
fn proxy_upstream_cli_overrides_config() {
    use cplt::config::{CliFlags, Config};
    let toml = "[proxy]\nupstream = \"http://config-proxy.example.com:8080\"\n";
    let cli = CliFlags {
        proxy_upstream: Some("http://cli-proxy.example.com:3128".to_string()),
        ..Default::default()
    };
    let resolved = Config::parse(toml).unwrap().merge(cli).unwrap();
    let up = resolved.proxy_upstream.expect("upstream should be set");
    assert_eq!(up.host, "cli-proxy.example.com");
    assert_eq!(up.port, 3128);
}

#[test]
fn proxy_upstream_none_when_unset() {
    use cplt::config::{CliFlags, Config};
    let resolved = Config::parse("[proxy]\nenabled = true\n")
        .unwrap()
        .merge(CliFlags::default())
        .unwrap();
    assert!(resolved.proxy_upstream.is_none());
}

#[test]
fn proxy_upstream_invalid_url_rejected() {
    use cplt::config::{CliFlags, Config};
    // Missing port and unsupported scheme must both fail config loading (fail-closed).
    let toml = "[proxy]\nupstream = \"http://corp-proxy.example.com\"\n";
    assert!(
        Config::parse(toml)
            .unwrap()
            .merge(CliFlags::default())
            .is_err()
    );
    let toml = "[proxy]\nupstream = \"https://corp-proxy.example.com:8080\"\n";
    assert!(
        Config::parse(toml)
            .unwrap()
            .merge(CliFlags::default())
            .is_err()
    );
}

#[test]
fn config_show_redacts_upstream_credentials() {
    // `cplt config show`/`explain` print proxy.upstream through
    // redact_upstream_url. A URL carrying `user:pass@` must never leak the
    // password to the terminal (these summaries get pasted into issues/CI),
    // but the host:port must stay visible so the summary is still useful.
    let shown = cplt::proxy::redact_upstream_url("http://alice:s3cret@corp.example.com:8080");
    assert!(
        !shown.contains("s3cret"),
        "password leaked in config show: {shown}"
    );
    assert!(
        shown.contains("corp.example.com:8080"),
        "host should remain visible: {shown}"
    );
    assert_eq!(shown, "http://alice:***@corp.example.com:8080");
}

#[test]
fn config_show_upstream_without_credentials_unchanged() {
    // A no-userinfo upstream has no secret, so config show displays it verbatim.
    assert_eq!(
        cplt::proxy::redact_upstream_url("http://corp.example.com:8080"),
        "http://corp.example.com:8080"
    );
}

#[test]
fn allow_private_domains_suffix_match() {
    use cplt::proxy::is_domain_match;
    let list = vec!["intern.nav.no".to_string()];
    // Suffix match covers all subdomains
    assert!(is_domain_match("mcp-onboarding.intern.nav.no", &list));
    assert!(is_domain_match("api.intern.nav.no", &list));
    assert!(is_domain_match("intern.nav.no", &list));
    // Non-matching domains
    assert!(!is_domain_match("evil.com", &list));
    assert!(!is_domain_match("notintern.nav.no", &list));
}

// ============================================================
// SBPL path validation
// ============================================================

#[test]
fn sbpl_path_rejects_newline() {
    let path = std::path::Path::new("/tmp/evil\n(allow file-read* (subpath \"/\"))");
    assert!(validate_sbpl_path(path).is_err());
}

#[test]
fn sbpl_path_rejects_null_byte() {
    let path = std::path::Path::new("/tmp/evil\0rest");
    assert!(validate_sbpl_path(path).is_err());
}

#[test]
fn sbpl_path_rejects_quotes() {
    let path = std::path::Path::new("/tmp/evil\"path");
    assert!(validate_sbpl_path(path).is_err());
}

#[test]
fn sbpl_path_rejects_parens() {
    let path = std::path::Path::new("/tmp/evil(path)");
    assert!(validate_sbpl_path(path).is_err());
}

#[test]
fn sbpl_path_allows_normal_path() {
    let path = std::path::Path::new("/Users/test/projects/my-app");
    assert!(validate_sbpl_path(path).is_ok());
}

// ============================================================
// Profile content verification (using real generate_profile)
// ============================================================

#[test]
fn profile_contains_deny_default() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(p.contains("(deny default)"));
}

#[test]
fn profile_allows_tty_ioctl() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow file-ioctl)"),
        "Profile must allow file-ioctl for terminal raw mode"
    );
}

#[test]
fn landlock_policy_device_files_have_ioctl() {
    // Regression test: Landlock ABI v5 (kernel ≥ 6.8) enforces IoctlDev for
    // character devices. Without IoctlDev on /dev/tty, /dev/ptmx, and /dev/pts,
    // tcsetattr() and forkpty(3) are denied — the terminal stays in cooked/echo
    // mode, OSC colour-query responses are echoed as visible text, and Copilot's
    // TUI hangs. /dev/ptmx is the PTY master multiplexer; ioctl is required for
    // TIOCGPTN and TIOCSPTLCK (used by forkpty/grantpt/unlockpt).
    let policy = generate_policy(&SandboxConfig {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/home/test"),
        extra_read: &[],
        extra_write: &[],
        extra_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
        use_bubblewrap: None,
    });

    let device_paths = ["/dev/tty", "/dev/ptmx", "/dev/pts"];
    for dev in &device_paths {
        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == std::path::Path::new(dev))
            .unwrap_or_else(|| panic!("Device rule for {dev} must exist in Landlock policy"));
        assert!(
            rule.access.ioctl,
            "{dev}: ioctl must be true — tcsetattr() requires IoctlDev on ABI v5+ (kernel ≥ 6.8)"
        );
    }

    // Non-device paths must NOT have ioctl set (least-privilege).
    let non_device_paths = ["/tmp", "/proc/self"];
    for path in &non_device_paths {
        if let Some(rule) = policy
            .fs_rules
            .iter()
            .find(|r| r.path == std::path::Path::new(path))
        {
            assert!(
                !rule.access.ioctl,
                "{path}: ioctl should be false for non-device paths"
            );
        }
    }
}

#[test]
fn profile_grants_project_access() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(p.contains("(allow file-read* (subpath \"/projects/app\"))"));
    assert!(p.contains("(allow file-write* (subpath \"/projects/app\"))"));
    assert!(
        p.contains("(allow file-map-executable (subpath \"/projects/app\"))"),
        "Project dir must allow file-map-executable for native Node addons"
    );
}

#[test]
fn profile_grants_copilot_config_access() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(p.contains("(allow file-read* (subpath \"/Users/test/.copilot\"))"));
}

#[test]
fn profile_grants_claude_config_access() {
    temp_env::with_var_unset("CLAUDE_CONFIG_DIR", || {
        let home = std::path::Path::new("/Users/test");
        let agent_dirs = cplt::agent::Agent::Claude.config_dirs(home);
        let p = generate_profile(&ProfileOptions {
            project_dir: std::path::Path::new("/projects/app"),
            home_dir: home,
            extra_read: &[],
            extra_write: &[],
            allow_socket: &[],
            extra_deny: &[],
            existing_home_tool_dirs: None,
            existing_app_dirs: None,
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            proxy_forced: false,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            java_home: None,
            git_hooks_path: None,
            git_common_dir: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
            allow_jvm_attach: false,
            allow_docker: false,
            electron_app_dir: None,
            agent: cplt::agent::Agent::Claude,
            agent_dirs: &agent_dirs,
            allow_cache_exec: &[],
            allow_cache_exec_any: false,
            allow_browser: false,
        });
        // Config dir + top-level config file are readable and writable.
        assert!(p.contains("(allow file-read* (subpath \"/Users/test/.claude\"))"));
        assert!(p.contains("(allow file-write* (subpath \"/Users/test/.claude\"))"));
        assert!(p.contains("(allow file-read* (subpath \"/Users/test/.claude.json\"))"));
        assert!(p.contains("(allow file-write* (subpath \"/Users/test/.claude.json\"))"));
        // Writable config dir must not be executable (persistence guard).
        assert!(p.contains("(deny process-exec (subpath \"/Users/test/.claude\"))"));
        // Auto-executing artifacts are write-denied (host-persistence guard);
        // the deny is emitted after the dir-wide allow, so SBPL last-match-wins
        // lets it override.
        assert!(p.contains("(deny file-write* (subpath \"/Users/test/.claude/statusline.sh\"))"));
        assert!(p.contains("(deny file-write* (subpath \"/Users/test/.claude/plugins\"))"));
    });
}

#[test]
fn profile_denies_sensitive_dirs() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    for dir in &[
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".nais",
        ".password-store",
        ".config/gcloud",
        ".config/op",
        ".terraform.d",
    ] {
        assert!(
            p.contains(&format!(
                "(deny file-read* (subpath \"/Users/test/{dir}\"))"
            )),
            "should deny read to {dir}"
        );
        assert!(
            p.contains(&format!(
                "(deny file-write* (subpath \"/Users/test/{dir}\"))"
            )),
            "should deny write to {dir}"
        );
    }
}

#[test]
fn profile_denies_sensitive_files() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    for file in &[".netrc", ".pypirc", ".gem/credentials", ".vault-token"] {
        assert!(
            p.contains(&format!(
                "(deny file-read* (literal \"/Users/test/{file}\"))"
            )),
            "should deny read to {file}"
        );
    }
}

#[test]
fn profile_denies_credential_files_in_tool_dirs() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    // These credential files inside allowed tool dirs must be denied
    for file in &[
        ".m2/settings.xml",
        ".m2/settings-security.xml",
        ".gradle/gradle.properties",
        ".cargo/credentials",
        ".cargo/credentials.toml",
        ".npmrc",
    ] {
        assert!(
            p.contains(&format!(
                "(deny file-read* (literal \"/Users/test/{file}\"))"
            )),
            "should deny read to {file}"
        );
        assert!(
            p.contains(&format!(
                "(deny file-write* (literal \"/Users/test/{file}\"))"
            )),
            "should deny write to {file}"
        );
    }

    // Parent dirs must still be allowed (dependency caches)
    assert!(
        p.contains("(allow file-read* (subpath \"/Users/test/.m2\"))"),
        ".m2 dir should still be allowed"
    );
    assert!(
        p.contains("(allow file-read* (subpath \"/Users/test/.gradle\"))"),
        ".gradle dir should still be allowed"
    );
}

#[test]
fn profile_allows_credential_files_when_user_opts_in() {
    use std::path::PathBuf;

    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[
            PathBuf::from("/Users/test/.m2/settings.xml"),
            PathBuf::from("/Users/test/.gradle/gradle.properties"),
            PathBuf::from("/Users/test/.npmrc"),
        ],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    // The deny should still be present (defense in depth)
    assert!(
        p.contains("(deny file-read* (literal \"/Users/test/.m2/settings.xml\"))"),
        "deny rule should still be emitted"
    );

    // But a re-allow should come AFTER the deny (SBPL last-match-wins)
    let deny_pos = p
        .find("(deny file-read* (literal \"/Users/test/.m2/settings.xml\"))")
        .unwrap();
    let allow_pos = p
        .find("(allow file-read* (literal \"/Users/test/.m2/settings.xml\"))")
        .expect("should have a post-deny re-allow for settings.xml");
    assert!(
        allow_pos > deny_pos,
        "re-allow must come AFTER deny (SBPL last-match-wins)"
    );

    // Same for gradle
    let deny_pos = p
        .find("(deny file-read* (literal \"/Users/test/.gradle/gradle.properties\"))")
        .unwrap();
    let allow_pos = p
        .find("(allow file-read* (literal \"/Users/test/.gradle/gradle.properties\"))")
        .expect("should have a post-deny re-allow for gradle.properties");
    assert!(
        allow_pos > deny_pos,
        "re-allow must come AFTER deny for gradle.properties"
    );

    // Same for npmrc
    let deny_pos = p
        .find("(deny file-read* (literal \"/Users/test/.npmrc\"))")
        .unwrap();
    let allow_pos = p
        .find("(allow file-read* (literal \"/Users/test/.npmrc\"))")
        .expect("should have a post-deny re-allow for .npmrc");
    assert!(
        allow_pos > deny_pos,
        "re-allow must come AFTER deny for .npmrc"
    );

    // Files NOT in extra_read should remain denied without override
    assert!(
        !p.contains("(allow file-read* (literal \"/Users/test/.cargo/credentials\"))"),
        ".cargo/credentials should NOT be re-allowed (not in extra_read)"
    );
}

/// Regression test: allow.read for a file inside a DENIED_DOTFILES directory
/// must produce a targeted re-allow AFTER the subpath deny.
/// Bug: gcloud ADC file blocked despite allow.read approval (SBPL ordering issue).
#[test]
fn profile_extra_read_overrides_denied_dotfile_directory() {
    use std::path::PathBuf;

    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[PathBuf::from(
            "/Users/test/.config/gcloud/application_default_credentials.json",
        )],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    // The deny for .config/gcloud (DENIED_DOTFILES) should still exist
    assert!(
        p.contains("(deny file-read* (subpath \"/Users/test/.config/gcloud\"))"),
        "deny rule for .config/gcloud should still be emitted"
    );

    // A targeted re-allow must come AFTER the subpath deny (SBPL last-match-wins)
    let deny_pos = p
        .find("(deny file-read* (subpath \"/Users/test/.config/gcloud\"))")
        .unwrap();
    let allow_pos = p
        .find("(allow file-read* (literal \"/Users/test/.config/gcloud/application_default_credentials.json\"))")
        .expect("should have a post-deny re-allow for gcloud ADC file");
    assert!(
        allow_pos > deny_pos,
        "re-allow must come AFTER the subpath deny (SBPL last-match-wins)"
    );
}

#[test]
fn profile_extra_read_overrides_multiple_denied_dotfile_dirs() {
    use std::path::PathBuf;

    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[
            PathBuf::from("/Users/test/.config/gcloud/application_default_credentials.json"),
            PathBuf::from("/Users/test/.aws/credentials"),
        ],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    // Both denied dotfile dirs should still have their deny rules
    assert!(p.contains("(deny file-read* (subpath \"/Users/test/.config/gcloud\"))"));
    assert!(p.contains("(deny file-read* (subpath \"/Users/test/.aws\"))"));

    // Both should have re-allows AFTER their respective denies
    let gcloud_deny = p
        .find("(deny file-read* (subpath \"/Users/test/.config/gcloud\"))")
        .unwrap();
    let gcloud_allow = p
        .find("(allow file-read* (literal \"/Users/test/.config/gcloud/application_default_credentials.json\"))")
        .expect("gcloud ADC re-allow missing");
    assert!(gcloud_allow > gcloud_deny);

    let aws_deny = p
        .find("(deny file-read* (subpath \"/Users/test/.aws\"))")
        .unwrap();
    let aws_allow = p
        .find("(allow file-read* (literal \"/Users/test/.aws/credentials\"))")
        .expect("aws credentials re-allow missing");
    assert!(aws_allow > aws_deny);
}

#[test]
fn profile_restricts_outbound_tcp() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(deny network-outbound (remote tcp))"),
        "Profile must deny general TCP before port allows"
    );
    assert!(
        p.contains("(allow network-outbound (remote ip \"*:443\"))"),
        "Profile must allow port 443"
    );
    assert!(
        !p.contains("(allow network-outbound (remote ip \"*:80\"))"),
        "Profile must NOT allow port 80 by default (HTTPS only)"
    );
    assert!(
        p.contains("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))"),
        "Profile must allow DNS resolution"
    );
    assert!(
        !p.contains("(allow network-outbound (remote unix-socket))"),
        "Profile must NOT allow unix-socket (blocks SSH agent)"
    );
    assert!(
        p.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
        "Profile must block localhost outbound"
    );
    assert!(
        !p.contains("(allow lsopen)"),
        "Profile must NOT allow lsopen by default (requires --allow-browser)"
    );
}

#[test]
fn profile_extra_ports_adds_allows() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[8080, 3000],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow network-outbound (remote ip \"*:8080\"))"),
        "Profile must allow extra port 8080"
    );
    assert!(
        p.contains("(allow network-outbound (remote ip \"*:3000\"))"),
        "Profile must allow extra port 3000"
    );
    assert!(
        p.contains("(allow network-outbound (remote ip \"*:443\"))"),
        "Profile must still allow port 443"
    );
}

#[test]
fn profile_allow_browser_enables_lsopen() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: true,
    });
    assert!(
        p.contains("(allow lsopen)"),
        "Profile must allow lsopen when --allow-browser is set"
    );
}

#[test]
fn profile_proxy_port_allows_localhost() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: Some(18080),
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow network-outbound (remote ip \"localhost:18080\"))"),
        "Profile must allow localhost proxy port"
    );
    assert!(
        p.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
        "Profile must still have general localhost deny"
    );
}

#[test]
fn profile_allow_localhost_opens_specific_ports() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[3000, 8080],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow network-outbound (remote ip \"localhost:3000\"))"),
        "Profile must allow localhost:3000"
    );
    assert!(
        p.contains("(allow network-outbound (remote ip \"localhost:8080\"))"),
        "Profile must allow localhost:8080"
    );
    assert!(
        p.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
        "Profile must still deny general localhost"
    );
    // The localhost allows must come AFTER the localhost deny
    let deny_pos = p
        .find("(deny network-outbound (remote ip \"localhost:*\"))")
        .unwrap();
    let allow_pos = p
        .find("(allow network-outbound (remote ip \"localhost:3000\"))")
        .unwrap();
    assert!(
        allow_pos > deny_pos,
        "localhost allows must come after localhost deny for last-match-wins"
    );
}

#[test]
fn profile_deny_rules_come_after_allow_rules() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    let allow_pos = p
        .find("(allow file-read* (subpath \"/projects/app\"))")
        .unwrap();
    let deny_pos = p
        .find("(deny file-read* (subpath \"/Users/test/.ssh\"))")
        .unwrap();
    assert!(
        deny_pos > allow_pos,
        "deny rules must come after allow rules for correct Seatbelt evaluation"
    );
}

#[test]
fn profile_allows_gh_config_read_only() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow file-read* (literal \"/Users/test/.config/gh/hosts.yml\"))"),
        "should allow read to .config/gh/hosts.yml"
    );
    assert!(
        p.contains("(allow file-read* (literal \"/Users/test/.config/gh/config.yml\"))"),
        "should allow read to .config/gh/config.yml"
    );
    assert!(
        !p.contains("(subpath \"/Users/test/.config/gh\")"),
        "should NOT allow subpath access to entire .config/gh directory"
    );
}

#[test]
fn profile_allows_file_map_executable_for_copilot() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.copilot\"))"),
        "should allow file-map-executable for native Node.js addons (keytar.node, pty.node)"
    );
}

// ============================================================
// Sensitive project file deny (.env, .pem, .key)
// ============================================================

#[test]
fn profile_denies_env_files_by_default() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.env$"))"#),
        "should deny read .env files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-write* (regex #"/\.env$"))"#),
        "should deny write .env files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.env\..*"))"#),
        "should deny read .env.* files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-write* (regex #"/\.env\..*"))"#),
        "should deny write .env.* files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.pem$"))"#),
        "should deny read .pem files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-write* (regex #"/\.pem$"))"#),
        "should deny write .pem files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.key$"))"#),
        "should deny read .key files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-write* (regex #"/\.key$"))"#),
        "should deny write .key files: {p}"
    );
}

#[test]
fn profile_allows_env_files_when_flag_set() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: true,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        !p.contains(r#"deny file-read* (regex #"/projects/app/"#),
        "should NOT deny project env files when allow_env_files is true"
    );
}

#[test]
fn profile_env_deny_comes_after_project_allow() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    let project_allow = p
        .find("(allow file-read* (subpath \"/projects/app\"))")
        .unwrap();
    let project_write_allow = p
        .find("(allow file-write* (subpath \"/projects/app\"))")
        .unwrap();
    let env_deny = p.find(r#"(deny file-read* (regex #"/\.env$"))"#).unwrap();
    let env_write_deny = p.find(r#"(deny file-write* (regex #"/\.env$"))"#).unwrap();
    assert!(
        env_deny > project_allow,
        "env read deny must come AFTER project read allow for SBPL last-match-wins"
    );
    assert!(
        env_write_deny > project_write_allow,
        "env write deny must come AFTER project write allow for SBPL last-match-wins"
    );
}

#[test]
fn profile_env_deny_comes_after_user_allows() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[std::path::PathBuf::from("/projects")],
        extra_write: &[std::path::PathBuf::from("/projects")],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    let user_read_allow = p
        .find("(allow file-read* (subpath \"/projects\"))")
        .unwrap();
    let user_write_allow = p
        .find("(allow file-write* (subpath \"/projects\"))")
        .unwrap();

    // .env denies must come after user allows
    let env_deny = p.find(r#"(deny file-read* (regex #"/\.env$"))"#).unwrap();
    let env_dot_deny = p
        .find(r#"(deny file-read* (regex #"/\.env\..*"))"#)
        .unwrap();
    assert!(
        env_deny > user_read_allow,
        "env deny must come AFTER user allow for SBPL last-match-wins"
    );
    assert!(
        env_dot_deny > user_read_allow,
        ".env.* deny must come AFTER user allow for SBPL last-match-wins"
    );

    // Git persistence denies must come after user write allows
    let hooks_deny = p
        .find("(deny file-write* (subpath \"/projects/app/.git/hooks\"))")
        .unwrap();
    let git_config_deny = p
        .find("(deny file-write* (literal \"/projects/app/.git/config\"))")
        .unwrap();
    let gitmodules_deny = p
        .find("(deny file-write* (literal \"/projects/app/.gitmodules\"))")
        .unwrap();
    let cplt_toml_deny = p
        .find("(deny file-write* (literal \"/projects/app/.cplt.toml\"))")
        .unwrap();

    assert!(
        hooks_deny > user_write_allow,
        ".git/hooks deny must come AFTER user write allow for SBPL last-match-wins"
    );
    assert!(
        git_config_deny > user_write_allow,
        ".git/config deny must come AFTER user write allow for SBPL last-match-wins"
    );
    assert!(
        gitmodules_deny > user_write_allow,
        ".gitmodules deny must come AFTER user write allow for SBPL last-match-wins"
    );
    assert!(
        cplt_toml_deny > user_write_allow,
        ".cplt.toml deny must come AFTER user write allow for SBPL last-match-wins"
    );
}

// ============================================================
// Allow-localhost-any
// ============================================================

#[test]
fn profile_allows_all_localhost_when_flag_set() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: true,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        !p.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
        "Profile must NOT deny localhost when allow_localhost_any is set"
    );
    // Without allow_jvm_attach, uses "localhost:*" (works for Node.js, Python, Go)
    assert!(
        p.contains("(allow network-outbound (remote ip \"localhost:*\"))"),
        "Profile must allow localhost outbound (non-JVM mode)"
    );
    assert!(
        !p.contains("(allow network-outbound (remote tcp \"*:*\"))"),
        "Profile must NOT allow all TCP without allow_jvm_attach"
    );
    // Should still have the general TCP deny and port allows
    assert!(
        p.contains("(deny network-outbound (remote tcp))"),
        "Profile must still deny general TCP"
    );
    assert!(
        p.contains("(allow network-outbound (remote ip \"*:443\"))"),
        "Profile must still allow port 443"
    );
}

#[test]
fn profile_allows_all_tcp_outbound_when_jvm_and_localhost_any() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: true,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: true,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // With preferIPv4Stack=true in JAVA_TOOL_OPTIONS, Java uses AF_INET4 and
    // "localhost:*" works. No need for the old "*:*" nuclear option.
    assert!(
        p.contains("(allow network-outbound (remote ip \"localhost:*\"))"),
        "Profile must allow localhost when allow_localhost_any is set"
    );
    assert!(
        !p.contains("(allow network-outbound (remote tcp \"*:*\"))"),
        "Profile must NOT use '*:*' anymore — preferIPv4Stack makes it unnecessary"
    );
    assert!(
        !p.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
        "Profile must NOT deny localhost"
    );
}

// ============================================================
// ~/.copilot/pkg write protection (persistence prevention)
// ============================================================

#[test]
fn profile_denies_write_to_copilot_pkg() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Must allow write to ~/.copilot (session state, config)
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.copilot\"))"),
        "Profile must allow write to ~/.copilot"
    );
    // Must deny write to ~/.copilot/pkg (native modules — persistence vector)
    assert!(
        p.contains("(deny file-write* (subpath \"/Users/test/.copilot/pkg\"))"),
        "Profile must deny write to ~/.copilot/pkg (prevents persistence via native module replacement)"
    );
    // Deny must come AFTER allow (last-match-wins)
    let allow_pos = p
        .find("(allow file-write* (subpath \"/Users/test/.copilot\"))")
        .unwrap();
    let deny_pos = p
        .find("(deny file-write* (subpath \"/Users/test/.copilot/pkg\"))")
        .unwrap();
    assert!(
        deny_pos > allow_pos,
        "Deny of ~/.copilot/pkg must come after allow of ~/.copilot (last-match-wins)"
    );
}

#[test]
fn home_tool_dirs_has_all_runtime_entries() {
    use cplt::sandbox::HOME_TOOL_DIRS;

    let paths: Vec<&str> = HOME_TOOL_DIRS.iter().map(|d| d.path).collect();

    // Executables: full exec
    for expected in &[
        ".local/bin",
        ".mise",
        ".asdf",
        ".nvm",
        ".pyenv",
        ".cargo/bin",
        ".rustup",
        ".sdkman",
        "go/bin",
    ] {
        assert!(
            paths.contains(expected),
            "HOME_TOOL_DIRS missing {expected}"
        );
    }

    // Dependency stores: map_exec only
    for expected in &[
        ".gradle",
        ".m2",
        ".konan",
        ".nuget",
        ".dotnet",
        "go/pkg",
        ".cargo/registry",
        ".cargo/git",
    ] {
        assert!(
            paths.contains(expected),
            "HOME_TOOL_DIRS missing {expected}"
        );
    }

    // Write-only caches
    for expected in &[".yarn", "Library/Caches"] {
        assert!(
            paths.contains(expected),
            "HOME_TOOL_DIRS missing {expected}"
        );
    }

    // pnpm with full exec+write
    assert!(
        paths.contains(&"Library/pnpm"),
        "HOME_TOOL_DIRS missing Library/pnpm"
    );

    // pnpm config dirs are handled by AppDirs, not HOME_TOOL_DIRS
    assert!(
        !paths.contains(&"Library/Preferences/pnpm"),
        "Library/Preferences/pnpm should NOT be in HOME_TOOL_DIRS (handled by AppDirs)"
    );
    assert!(
        !paths.contains(&".config/pnpm"),
        ".config/pnpm should NOT be in HOME_TOOL_DIRS (handled by AppDirs)"
    );
}

// ============================================================
// Environment variable allowlist
// ============================================================

#[test]
fn env_allowlist_includes_essential_vars() {
    use cplt::sandbox::{ENV_ALLOWLIST, ENV_PREFIX_ALLOWLIST};

    // Core system vars
    assert!(ENV_ALLOWLIST.contains(&"HOME"));
    assert!(ENV_ALLOWLIST.contains(&"PATH"));
    assert!(ENV_ALLOWLIST.contains(&"TERM"));
    assert!(ENV_ALLOWLIST.contains(&"SHELL"));
    assert!(ENV_ALLOWLIST.contains(&"USER"));

    // Copilot auth (accepted trade-off)
    assert!(ENV_ALLOWLIST.contains(&"GH_TOKEN"));
    assert!(ENV_ALLOWLIST.contains(&"GITHUB_TOKEN"));
    assert!(ENV_ALLOWLIST.contains(&"COPILOT_GITHUB_TOKEN"));

    // Tool paths
    assert!(ENV_ALLOWLIST.contains(&"JAVA_HOME"));
    assert!(ENV_ALLOWLIST.contains(&"GOPATH"));
    assert!(ENV_ALLOWLIST.contains(&"CARGO_HOME"));

    // Java/Maven build options (consistent with NODE_OPTIONS)
    assert!(ENV_ALLOWLIST.contains(&"MAVEN_OPTS"));
    assert!(ENV_ALLOWLIST.contains(&"JAVA_TOOL_OPTIONS"));

    // Prefixes
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"LC_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"COPILOT_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"MISE_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"OTEL_"));
}

#[test]
fn env_allowlist_excludes_dangerous_vars() {
    use cplt::sandbox::{ENV_ALLOWLIST, ENV_PREFIX_ALLOWLIST};

    // Cloud credentials
    assert!(!ENV_ALLOWLIST.contains(&"AWS_SECRET_ACCESS_KEY"));
    assert!(!ENV_ALLOWLIST.contains(&"AWS_ACCESS_KEY_ID"));
    assert!(!ENV_ALLOWLIST.contains(&"AWS_SESSION_TOKEN"));
    assert!(!ENV_ALLOWLIST.contains(&"AZURE_CLIENT_SECRET"));
    assert!(!ENV_ALLOWLIST.contains(&"GOOGLE_APPLICATION_CREDENTIALS"));

    // Package registry tokens
    assert!(!ENV_ALLOWLIST.contains(&"NPM_TOKEN"));
    assert!(!ENV_ALLOWLIST.contains(&"NODE_AUTH_TOKEN"));
    assert!(!ENV_ALLOWLIST.contains(&"PYPI_TOKEN"));

    // Database / service credentials
    assert!(!ENV_ALLOWLIST.contains(&"DATABASE_URL"));
    assert!(!ENV_ALLOWLIST.contains(&"VAULT_TOKEN"));
    assert!(!ENV_ALLOWLIST.contains(&"CONSUL_HTTP_TOKEN"));

    // SSH agent
    assert!(!ENV_ALLOWLIST.contains(&"SSH_AUTH_SOCK"));
    assert!(!ENV_ALLOWLIST.contains(&"SSH_AGENT_PID"));

    // No dangerous prefixes
    assert!(!ENV_PREFIX_ALLOWLIST.contains(&"AWS_"));
    assert!(!ENV_PREFIX_ALLOWLIST.contains(&"AZURE_"));
    assert!(!ENV_PREFIX_ALLOWLIST.contains(&"VAULT_"));
}

#[test]
fn env_allowlist_includes_new_runtime_vars() {
    use cplt::sandbox::{ENV_ALLOWLIST, ENV_PREFIX_ALLOWLIST};

    // Python
    assert!(ENV_ALLOWLIST.contains(&"PYENV_ROOT"));
    assert!(ENV_ALLOWLIST.contains(&"PYTHONDONTWRITEBYTECODE"));
    assert!(ENV_ALLOWLIST.contains(&"VIRTUAL_ENV"));

    // pnpm
    assert!(ENV_ALLOWLIST.contains(&"PNPM_HOME"));
    assert!(ENV_ALLOWLIST.contains(&"NPM_CONFIG_USERCONFIG"));

    // .NET / dotnet CLI
    assert!(ENV_ALLOWLIST.contains(&"DOTNET_CLI_HOME"));
    assert!(ENV_ALLOWLIST.contains(&"DOTNET_ROOT"));

    // Prefixes
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"PYENV_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"YARN_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"COREPACK_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"FNM_"));
}

#[test]
fn env_allowlist_includes_terminal_multiplexers() {
    use cplt::sandbox::ENV_ALLOWLIST;

    // tmux — without TMUX set, Node.js/ink sends bare OSC 10/11 color queries
    // that tmux intercepts but can't deliver back, causing a visible hang.
    assert!(ENV_ALLOWLIST.contains(&"TMUX"));
    assert!(ENV_ALLOWLIST.contains(&"TMUX_PANE"));

    // GNU screen
    assert!(ENV_ALLOWLIST.contains(&"STY"));

    // Zellij
    assert!(ENV_ALLOWLIST.contains(&"ZELLIJ"));
    assert!(ENV_ALLOWLIST.contains(&"ZELLIJ_SESSION_NAME"));

    // Terminal emulator identification
    assert!(ENV_ALLOWLIST.contains(&"VTE_VERSION"));
    assert!(ENV_ALLOWLIST.contains(&"KITTY_WINDOW_ID"));
    assert!(ENV_ALLOWLIST.contains(&"WEZTERM_PANE"));
    assert!(ENV_ALLOWLIST.contains(&"GHOSTTY_RESOURCES_DIR"));

    // OSC 8 hyperlink support
    assert!(ENV_ALLOWLIST.contains(&"FORCE_HYPERLINK"));
}

// ============================================================
// Deny exec from temp directories (write-then-exec prevention)
// ============================================================

#[test]
fn profile_denies_exec_from_tmp() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Must allow read+write to /tmp (needed for temp files)
    assert!(
        p.contains("(allow file-write* (subpath \"/private/tmp\"))"),
        "Profile must allow write to /tmp"
    );
    // Must deny direct execution from /tmp
    assert!(
        p.contains("(deny process-exec (subpath \"/private/tmp\"))"),
        "Profile must deny process-exec from /tmp"
    );
    assert!(
        p.contains("(deny file-map-executable (subpath \"/private/tmp\"))"),
        "Profile must deny file-map-executable from /tmp"
    );
    // Must deny direct execution from /var/folders
    assert!(
        p.contains("(deny process-exec (subpath \"/private/var/folders\"))"),
        "Profile must deny process-exec from /var/folders"
    );
    assert!(
        p.contains("(deny file-map-executable (subpath \"/private/var/folders\"))"),
        "Profile must deny file-map-executable from /var/folders"
    );
    // Must NOT contain JVM Attach API socket rules by default (opt-in via --allow-jvm-attach)
    assert!(
        !p.contains(".java_pid"),
        "Default profile must NOT contain .java_pid socket rules — JVM attach is opt-in"
    );
}

#[test]
fn profile_allows_jvm_attach_when_flag_set() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: true,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Must allow unix socket bind+inbound+connect for JVM Attach API (.java_pid*)
    // Three operations needed: bind (create socket), inbound (accept), outbound (connect)
    // Two paths: /tmp (legacy) and /var/folders (macOS confstr temp dir)
    assert!(
        p.contains(
            r#"(allow network-bind (local unix-socket (regex #"^/private/tmp/\.java_pid")))"#
        ),
        "Profile must allow unix socket bind for JVM Attach API in /tmp"
    );
    assert!(
        p.contains(
            r#"(allow network-inbound (local unix-socket (regex #"^/private/tmp/\.java_pid")))"#
        ),
        "Profile must allow unix socket inbound for JVM Attach API in /tmp"
    );
    assert!(
        p.contains(
            r#"(allow network-outbound (remote unix-socket (regex #"^/private/tmp/\.java_pid")))"#
        ),
        "Profile must allow unix socket connect for JVM Attach API in /tmp"
    );
    assert!(
        p.contains(
            r#"(allow network-bind (local unix-socket (regex #"^/private/var/folders/.+/T/\.java_pid")))"#
        ),
        "Profile must allow unix socket bind for JVM Attach API in /var/folders"
    );
    assert!(
        p.contains(
            r#"(allow network-inbound (local unix-socket (regex #"^/private/var/folders/.+/T/\.java_pid")))"#
        ),
        "Profile must allow unix socket inbound for JVM Attach API in /var/folders"
    );
    assert!(
        p.contains(
            r#"(allow network-outbound (remote unix-socket (regex #"^/private/var/folders/.+/T/\.java_pid")))"#
        ),
        "Profile must allow unix socket connect for JVM Attach API in /var/folders"
    );
    // Must NOT have broad subpath unix socket rules (would expose SSH agent)
    assert!(
        !p.contains("unix-socket (subpath \"/private/tmp\")"),
        "Profile must NOT have broad subpath unix-socket rule — exposes SSH_AUTH_SOCK"
    );
}

// ============================================================
// TCP bind uses localhost (SBPL limitation: cannot restrict to loopback only)
// ============================================================

#[test]
fn profile_allows_localhost_tcp_bind() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/tmp/proj"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // We use "*:*" instead of "localhost:*" because Java NIO uses IPv6 sockets
    // with IPv4-mapped addresses (::ffff:127.0.0.1) which "localhost" doesn't match.
    assert!(
        p.contains(r#"(allow network-bind (local ip "*:*"))"#),
        "Profile must allow bind on all local addresses (for Java IPv4-mapped)"
    );
    assert!(
        p.contains(r#"(allow network-inbound (local ip "*:*"))"#),
        "Profile must allow inbound on all local addresses (for Java IPv4-mapped)"
    );
}

// ============================================================
// Cross-platform parity: config options must affect both backends
// ============================================================

#[test]
fn allow_localhost_any_affects_both_backends() {
    // macOS: allow_localhost_any should produce unrestricted localhost rules
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/tmp/proj"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: true,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // macOS SBPL should allow all localhost ports.
    // #126 Tier 2: dropped the always-true `|| p.contains("network-outbound")`
    // disjunct (every profile contains that substring) so this now actually
    // asserts the unrestricted localhost outbound rule is present.
    assert!(
        p.contains(r#"(allow network-outbound (remote ip "localhost:*"))"#),
        "macOS profile should have unrestricted localhost outbound when allow_localhost_any=true"
    );

    // Linux: allow_localhost_any should disable net_connect restriction
    let landlock_policy = generate_policy(&SandboxConfig {
        project_dir: std::path::Path::new("/tmp/proj"),
        home_dir: std::path::Path::new("/home/test"),
        extra_read: &[],
        extra_write: &[],
        extra_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: true,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
        use_bubblewrap: None,
    });
    assert!(
        !landlock_policy.restrict_net_connect,
        "Linux Landlock should disable ConnectTcp restriction when allow_localhost_any=true"
    );
}

/// Verify that config options affecting network/filesystem behavior
/// are consistently applied to both macOS SBPL and Linux Landlock backends.
/// Platform-specific options are documented but not required to be cross-platform.
#[test]
fn config_options_parity_across_backends() {
    use std::path::{Path, PathBuf};

    let project = Path::new("/tmp/proj");
    let home = Path::new("/home/test");
    let extra_read = vec![PathBuf::from("/extra/read")];
    let extra_write = vec![PathBuf::from("/extra/write")];
    let ports = vec![8443u16];
    let lh_ports = vec![3000u16];
    let scratch = PathBuf::from("/tmp/scratch");

    let config = SandboxConfig {
        project_dir: project,
        home_dir: home,
        extra_read: &extra_read,
        extra_write: &extra_write,
        extra_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &ports,
        localhost_ports: &lh_ports,
        proxy_port: Some(9090),
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: Some(&scratch),
        allow_tmp_exec: true,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: true,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
        use_bubblewrap: None,
    };

    // ── Landlock policy ──
    let ll = generate_policy(&config);

    // extra_ports → ConnectTcp net rules
    assert!(
        ll.net_rules.iter().any(|r| r.port == 8443),
        "Landlock: extra_ports should add ConnectTcp rule"
    );
    // localhost_ports → ConnectTcp net rules
    assert!(
        ll.net_rules.iter().any(|r| r.port == 3000),
        "Landlock: localhost_ports should add ConnectTcp rule"
    );
    // proxy_port → ConnectTcp net rules
    assert!(
        ll.net_rules.iter().any(|r| r.port == 9090),
        "Landlock: proxy_port should add ConnectTcp rule"
    );
    // extra_read → FsRule with read access
    assert!(
        ll.fs_rules
            .iter()
            .any(|r| r.path == Path::new("/extra/read") && r.access.read),
        "Landlock: extra_read should create read FsRule"
    );
    // extra_write → FsRule with write access
    assert!(
        ll.fs_rules
            .iter()
            .any(|r| r.path == Path::new("/extra/write") && r.access.write),
        "Landlock: extra_write should create write FsRule"
    );
    // scratch_dir → FsRule with write + execute
    assert!(
        ll.fs_rules
            .iter()
            .any(|r| r.path == scratch && r.access.write && r.access.execute),
        "Landlock: scratch_dir should have write+execute"
    );
    // allow_tmp_exec → /tmp gets execute
    assert!(
        ll.fs_rules
            .iter()
            .any(|r| r.path == Path::new("/tmp") && r.access.execute),
        "Landlock: allow_tmp_exec should grant /tmp execute"
    );
    // restrict_net_connect is true by default
    assert!(
        ll.restrict_net_connect,
        "Landlock: default should restrict net connect"
    );

    // ── macOS SBPL profile ──
    let profile = generate_profile(&ProfileOptions {
        project_dir: project,
        home_dir: home,
        extra_read: &extra_read,
        extra_write: &extra_write,
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &ports,
        localhost_ports: &lh_ports,
        proxy_port: Some(9090),
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: Some(&scratch),
        allow_tmp_exec: true,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: true,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    // extra_ports → SBPL port allow
    assert!(
        profile.contains("8443"),
        "SBPL: extra_ports should appear in profile"
    );
    // localhost_ports → SBPL localhost allow
    assert!(
        profile.contains("localhost:3000"),
        "SBPL: localhost_ports should create outbound rule"
    );
    // proxy_port → SBPL proxy allow
    assert!(
        profile.contains("localhost:9090"),
        "SBPL: proxy_port should create outbound rule"
    );
    // extra_read → SBPL file-read allow
    assert!(
        profile.contains("/extra/read"),
        "SBPL: extra_read should appear in profile"
    );
    // extra_write → SBPL file-write allow
    assert!(
        profile.contains("/extra/write"),
        "SBPL: extra_write should appear in profile"
    );
    // scratch_dir → SBPL allows
    assert!(
        profile.contains("/tmp/scratch"),
        "SBPL: scratch_dir should appear in profile"
    );
    // allow_gpg_signing → SBPL gnupg rules
    assert!(
        profile.contains(".gnupg"),
        "SBPL: allow_gpg_signing should add gnupg rules"
    );
    // allow_jvm_attach → SBPL java_pid pattern
    assert!(
        profile.contains("java_pid"),
        "SBPL: allow_jvm_attach should add JVM socket rule"
    );
}

// ============================================================
// Deny git persistence vectors (.git/hooks, .git/config, .gitmodules)
// ============================================================

#[test]
fn profile_denies_git_persistence_vectors() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Must deny writes to .git/hooks (post-checkout etc. run outside sandbox)
    assert!(
        p.contains("(deny file-write* (subpath \"/projects/app/.git/hooks\"))"),
        "Profile must deny write to .git/hooks"
    );
    // Must deny writes to .git/config (hooksPath redirect, URL hijacking)
    assert!(
        p.contains("(deny file-write* (literal \"/projects/app/.git/config\"))"),
        "Profile must deny write to .git/config"
    );
    // Must deny writes to .gitmodules (supply chain via submodule URLs)
    assert!(
        p.contains("(deny file-write* (literal \"/projects/app/.gitmodules\"))"),
        "Profile must deny write to .gitmodules"
    );
    // Git persistence denies must come after project allow (more specific wins)
    let allow_pos = p
        .find("(allow file-write* (subpath \"/projects/app\"))")
        .unwrap();
    let hooks_pos = p
        .find("(deny file-write* (subpath \"/projects/app/.git/hooks\"))")
        .unwrap();
    assert!(
        hooks_pos > allow_pos,
        "Git hooks deny must come after project allow"
    );
}

#[test]
fn profile_denies_write_to_cplt_toml() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(deny file-write* (literal \"/projects/app/.cplt.toml\"))"),
        "Profile must deny write to .cplt.toml to prevent agent tampering"
    );
}

// ============================================================
// HomeToolDir permissions in profile
// ============================================================

/// Helper to generate a default profile for permission tests.
fn default_profile() -> String {
    generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    })
}

#[test]
fn profile_library_caches_no_exec() {
    let p = default_profile();
    assert!(
        p.contains("(allow file-read* (subpath \"/Users/test/Library/Caches\"))"),
        "Library/Caches should have file-read*"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/Library/Caches\"))"),
        "Library/Caches should have file-write*"
    );
    assert!(
        !p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches\"))"),
        "Library/Caches must NOT have process-exec allow"
    );
    assert!(
        !p.contains("(allow file-map-executable (subpath \"/Users/test/Library/Caches\"))"),
        "Library/Caches must NOT have file-map-executable allow"
    );
    // Explicit denies must be present (blanket process-exec allow means absence of allow is not enough)
    assert!(
        p.contains("(deny process-exec (subpath \"/Users/test/Library/Caches\"))"),
        "Library/Caches must have explicit process-exec DENY"
    );
    assert!(
        p.contains("(deny file-map-executable (subpath \"/Users/test/Library/Caches\"))"),
        "Library/Caches must have explicit file-map-executable DENY"
    );
}

#[test]
fn profile_denies_non_dev_cache_dirs() {
    let p = default_profile();
    // Browser and system app caches must be denied
    assert!(
        p.contains(r#"(deny file-read* (regex #"^/Users/test/Library/Caches/com\.apple\."))"#),
        "Profile must deny com.apple.* caches"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"^/Users/test/Library/Caches/com\.google\."))"#),
        "Profile must deny com.google.* caches"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"^/Users/test/Library/Caches/org\.mozilla\."))"#),
        "Profile must deny org.mozilla.* caches"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"^/Users/test/Library/Caches/Firefox"))"#),
        "Profile must deny Firefox caches"
    );
    // Xcode dev tools must be re-allowed
    assert!(
        p.contains(r#"(allow file-read* (regex #"^/Users/test/Library/Caches/com\.apple\.dt\."))"#),
        "Profile must re-allow Xcode dev tool caches"
    );
    // Xcode re-allow must come AFTER the com.apple. deny
    let deny_pos = p
        .find(r#"(deny file-read* (regex #"^/Users/test/Library/Caches/com\.apple\."))"#)
        .expect("com.apple deny must exist");
    let allow_pos = p
        .find(r#"(allow file-read* (regex #"^/Users/test/Library/Caches/com\.apple\.dt\."))"#)
        .expect("Xcode re-allow must exist");
    assert!(
        allow_pos > deny_pos,
        "Xcode re-allow must come AFTER com.apple deny (last-match-wins)"
    );
}

#[test]
fn profile_cargo_has_exec() {
    let p = default_profile();
    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/.cargo/bin\"))"),
        ".cargo/bin should have process-exec for cargo, rustc, etc."
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.cargo/bin\"))"),
        ".cargo/bin should have file-map-executable"
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.cargo/registry\"))"),
        ".cargo/registry should have file-map-executable for proc-macro dylibs"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.cargo/registry\"))"),
        ".cargo/registry should be writable for cargo build"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.cargo/git\"))"),
        ".cargo/git should be writable for git deps"
    );
    // .cargo/bin must NOT be writable (persistence attack prevention)
    assert!(
        !p.contains("(allow file-write* (subpath \"/Users/test/.cargo/bin\"))"),
        ".cargo/bin must not be writable — prevents trojan persistence"
    );
}

#[test]
fn profile_nvm_has_exec() {
    let p = default_profile();
    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/.nvm\"))"),
        ".nvm should have process-exec for node, npm shims"
    );
}

#[test]
fn profile_fnm_has_exec() {
    // fnm (Fast Node Manager) stores Node.js at ~/.local/share/fnm/node-versions/.
    // Node binaries and bundled JS modules (corepack/yarn/npm) must be executable
    // inside the sandbox — regression for EPERM on corepack/yarn.js.
    let p = default_profile();
    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/.local/share/fnm\"))"),
        "fnm node-versions dir should have process-exec so `yarn`/`node` can be launched"
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.local/share/fnm\"))"),
        "fnm dir should have file-map-executable for native addons"
    );
}

#[test]
fn profile_gradle_has_map_exec_only() {
    let p = default_profile();
    assert!(
        !p.contains("(allow process-exec (subpath \"/Users/test/.gradle\"))"),
        ".gradle should NOT have process-exec allow"
    );
    assert!(
        p.contains("(deny process-exec (subpath \"/Users/test/.gradle\"))"),
        ".gradle should have explicit process-exec DENY (writable dir)"
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.gradle\"))"),
        ".gradle should have file-map-executable for JNI native libs"
    );
    assert!(
        !p.contains("(deny file-map-executable (subpath \"/Users/test/.gradle\"))"),
        ".gradle should NOT deny file-map-executable (JNI needs it)"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.gradle\"))"),
        ".gradle should have file-write* for build caches"
    );
}

#[test]
fn profile_m2_has_map_exec_only() {
    let p = default_profile();
    assert!(
        !p.contains("(allow process-exec (subpath \"/Users/test/.m2\"))"),
        ".m2 should NOT have process-exec"
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.m2\"))"),
        ".m2 should have file-map-executable for JNI native libs"
    );
}

#[test]
fn profile_pyenv_has_exec() {
    let p = default_profile();
    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/.pyenv\"))"),
        ".pyenv should have process-exec for python shims and interpreters"
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.pyenv\"))"),
        ".pyenv should have file-map-executable for native extensions"
    );
}

#[test]
fn profile_yarn_is_write_only() {
    let p = default_profile();
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.yarn\"))"),
        ".yarn should have file-write* for global cache"
    );
    assert!(
        !p.contains("(allow process-exec (subpath \"/Users/test/.yarn\"))"),
        ".yarn should NOT have process-exec (JS-only packages)"
    );
    assert!(
        !p.contains("(allow file-map-executable (subpath \"/Users/test/.yarn\"))"),
        ".yarn should NOT have file-map-executable"
    );
    assert!(
        p.contains("(deny process-exec (subpath \"/Users/test/.yarn\"))"),
        ".yarn should have explicit process-exec DENY (writable dir)"
    );
    assert!(
        p.contains("(deny file-map-executable (subpath \"/Users/test/.yarn\"))"),
        ".yarn should have explicit file-map-executable DENY (writable dir)"
    );
}

#[test]
fn profile_konan_has_map_exec_only() {
    let p = default_profile();
    assert!(
        !p.contains("(allow process-exec (subpath \"/Users/test/.konan\"))"),
        ".konan should NOT have process-exec"
    );
    assert!(
        p.contains("(deny process-exec (subpath \"/Users/test/.konan\"))"),
        ".konan should have explicit process-exec DENY (writable dir)"
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.konan\"))"),
        ".konan should have file-map-executable for Kotlin Native libs"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.konan\"))"),
        ".konan should have file-write* for compilation artifacts"
    );
}

// ============================================================
// build_sandbox_env — hardening env injection
// ============================================================

fn make_env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn env_sanitized_injects_hardening_vars() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    let npm = env
        .vars
        .iter()
        .find(|(k, _)| k == "npm_config_ignore_scripts");
    assert!(npm.is_some(), "should inject npm_config_ignore_scripts");
    assert_eq!(npm.unwrap().1, "true");

    let yarn = env.vars.iter().find(|(k, _)| k == "YARN_ENABLE_SCRIPTS");
    assert!(yarn.is_some(), "should inject YARN_ENABLE_SCRIPTS");
    assert_eq!(yarn.unwrap().1, "false");

    let git = env.vars.iter().find(|(k, _)| k == "GIT_TERMINAL_PROMPT");
    assert!(git.is_some(), "should inject GIT_TERMINAL_PROMPT");
    assert_eq!(git.unwrap().1, "0");

    let trust_lock = env.vars.iter().find(|(k, _)| k == "__CPLT_TRUST_LOCKED");
    assert!(
        trust_lock.is_some(),
        "should inject __CPLT_TRUST_LOCKED to block cplt trust inside sandbox"
    );
    assert_eq!(trust_lock.unwrap().1, "1");

    let autoupdate = env.vars.iter().find(|(k, _)| k == "DISABLE_AUTOUPDATER");
    assert!(
        autoupdate.is_some(),
        "should inject DISABLE_AUTOUPDATER to block agent self-update inside sandbox"
    );
    assert_eq!(autoupdate.unwrap().1, "1");
}

#[test]
fn env_claude_injects_autoupdater_and_suppresses_copilot_vars() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("GH_TOKEN", "gh-secret"),
        ("COPILOT_GITHUB_TOKEN", "copilot-secret"),
        ("COPILOT_FOO", "x"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Claude);

    // Auto-update disabled (no --no-auto-update flag exists for Claude Code)
    let autoupdate = env.vars.iter().find(|(k, _)| k == "DISABLE_AUTOUPDATER");
    assert_eq!(
        autoupdate.map(|(_, v)| v.as_str()),
        Some("1"),
        "DISABLE_AUTOUPDATER should be injected for Claude"
    );

    // Copilot-only auth vars must not leak to a non-Copilot agent
    for leaked in &["GH_TOKEN", "COPILOT_GITHUB_TOKEN", "COPILOT_FOO"] {
        assert!(
            !env.vars.iter().any(|(k, _)| k == leaked),
            "{leaked} should be suppressed for Claude"
        );
    }
}

#[test]
fn env_sanitized_injects_telemetry_opt_out_vars() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    for (name, expected) in &[
        ("DO_NOT_TRACK", "1"),
        ("NEXT_TELEMETRY_DISABLED", "1"),
        ("TURBO_TELEMETRY_DISABLED", "1"),
        ("CHECKPOINT_DISABLE", "1"),
        ("GATSBY_TELEMETRY_DISABLED", "1"),
        ("OMO_DISABLE_POSTHOG", "1"),
    ] {
        let found = env.vars.iter().find(|(k, _)| k == name);
        assert!(found.is_some(), "should inject {name}");
        assert_eq!(found.unwrap().1, *expected, "{name} should be {expected}");
    }
}

#[test]
fn env_sanitized_telemetry_opt_out_can_be_disabled() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let disabled = vec![HardeningCategory::TelemetryOptOut];
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &disabled,
        None,
        cplt::agent::Agent::Copilot,
    );

    for name in &[
        "DO_NOT_TRACK",
        "NEXT_TELEMETRY_DISABLED",
        "TURBO_TELEMETRY_DISABLED",
        "CHECKPOINT_DISABLE",
        "GATSBY_TELEMETRY_DISABLED",
        "OMO_DISABLE_POSTHOG",
    ] {
        assert!(
            !env.vars.iter().any(|(k, _)| k == name),
            "{name} should not be injected when TelemetryOptOut is disabled"
        );
    }
    // Other categories should still be active
    assert!(
        env.vars.iter().any(|(k, _)| k == "GIT_TERMINAL_PROMPT"),
        "git hardening should remain active when telemetry opt-out is disabled"
    );
    assert!(
        env.vars
            .iter()
            .any(|(k, _)| k == "npm_config_ignore_scripts"),
        "lifecycle scripts hardening should remain active"
    );
}

#[test]
fn env_sanitized_lifecycle_opt_out_skips_npm_yarn() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let disabled = vec![HardeningCategory::LifecycleScripts];
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &disabled,
        None,
        cplt::agent::Agent::Copilot,
    );

    assert!(
        !env.vars
            .iter()
            .any(|(k, _)| k == "npm_config_ignore_scripts"),
        "should not inject npm_config_ignore_scripts when lifecycle scripts allowed"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "YARN_ENABLE_SCRIPTS"),
        "should not inject YARN_ENABLE_SCRIPTS when lifecycle scripts allowed"
    );
    // Git hardening should still be active
    assert!(
        env.vars.iter().any(|(k, _)| k == "GIT_TERMINAL_PROMPT"),
        "git hardening should remain active even when lifecycle scripts allowed"
    );
}

#[test]
fn env_inherit_injects_hardening_vars() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let env = build_sandbox_env(&parent, &[], true, &[], None, cplt::agent::Agent::Copilot);

    assert!(!env.clear_first, "inherit mode should not clear env");
    let npm = env
        .vars
        .iter()
        .find(|(k, _)| k == "npm_config_ignore_scripts");
    assert!(
        npm.is_some(),
        "inherit mode should still inject hardening vars"
    );
    assert_eq!(npm.unwrap().1, "true");
}

#[test]
fn env_pass_env_preserves_user_override() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("npm_config_ignore_scripts", "false"),
    ]);
    let extra = vec!["npm_config_ignore_scripts".to_string()];
    let env = build_sandbox_env(
        &parent,
        &extra,
        false,
        &[],
        None,
        cplt::agent::Agent::Copilot,
    );

    let npm: Vec<_> = env
        .vars
        .iter()
        .filter(|(k, _)| k == "npm_config_ignore_scripts")
        .collect();
    assert_eq!(
        npm.len(),
        1,
        "should have exactly one npm_config_ignore_scripts"
    );
    assert_eq!(
        npm[0].1, "false",
        "user's explicit --pass-env value should be preserved, not overridden by hardening"
    );
}

#[test]
fn env_inherit_pass_env_preserves_user_override() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("npm_config_ignore_scripts", "false"),
    ]);
    let extra = vec!["npm_config_ignore_scripts".to_string()];
    let env = build_sandbox_env(
        &parent,
        &extra,
        true,
        &[],
        None,
        cplt::agent::Agent::Copilot,
    );

    // In inherit mode with --pass-env, the user's value is inherited
    // and hardening should NOT override it
    assert!(
        !env.vars
            .iter()
            .any(|(k, v)| k == "npm_config_ignore_scripts" && v == "true"),
        "hardening should not override user's explicit --pass-env value in inherit mode"
    );
}

#[test]
fn env_sanitized_clears_first() {
    let parent = make_env(&[("HOME", "/Users/test"), ("SECRET_TOKEN", "abc123")]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    assert!(env.clear_first, "sanitized mode should clear env first");
    assert!(
        !env.vars.iter().any(|(k, _)| k == "SECRET_TOKEN"),
        "SECRET_TOKEN should not pass through in sanitized mode"
    );
}

#[test]
fn env_lang_prefix_does_not_leak_langchain_keys() {
    // Regression: the LANG prefix in ENV_PREFIX_ALLOWLIST matched LANGCHAIN_API_KEY,
    // LANGFUSE_SECRET_KEY, LANGSMITH_API_KEY — leaking AI/ML API keys.
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("LANG", "en_US.UTF-8"),
        ("LANGUAGE", "en"),
        ("LANGCHAIN_API_KEY", "sk-secret-langchain"),
        ("LANGFUSE_SECRET_KEY", "sk-secret-langfuse"),
        ("LANGSMITH_API_KEY", "sk-secret-langsmith"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    // LANG and LANGUAGE should pass through (explicit allowlist)
    assert!(
        env.vars.iter().any(|(k, _)| k == "LANG"),
        "LANG should be in the sanitized env"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "LANGUAGE"),
        "LANGUAGE should be in the sanitized env"
    );

    // LANGCHAIN/LANGFUSE/LANGSMITH keys must NOT leak
    assert!(
        !env.vars.iter().any(|(k, _)| k == "LANGCHAIN_API_KEY"),
        "LANGCHAIN_API_KEY must not leak through LANG prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "LANGFUSE_SECRET_KEY"),
        "LANGFUSE_SECRET_KEY must not leak through LANG prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "LANGSMITH_API_KEY"),
        "LANGSMITH_API_KEY must not leak through LANG prefix"
    );
}

#[test]
fn env_yarn_prefix_does_not_bypass_hardening() {
    // Regression: YARN_ENABLE_SCRIPTS=true from parent env passed through via
    // the YARN_ prefix, then prevented hardening injection because the var was
    // already present in env.vars.
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("YARN_ENABLE_SCRIPTS", "true"),
        ("YARN_CACHE_FOLDER", "/some/cache"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    // YARN_ENABLE_SCRIPTS must be overridden to "false" by hardening
    let yarn: Vec<_> = env
        .vars
        .iter()
        .filter(|(k, _)| k == "YARN_ENABLE_SCRIPTS")
        .collect();
    assert_eq!(
        yarn.len(),
        1,
        "should have exactly one YARN_ENABLE_SCRIPTS (no duplicates)"
    );
    assert_eq!(
        yarn[0].1, "false",
        "hardening must override parent's YARN_ENABLE_SCRIPTS=true to false"
    );

    // Other YARN_ vars should still pass through
    assert!(
        env.vars.iter().any(|(k, _)| k == "YARN_CACHE_FOLDER"),
        "non-hardening YARN_ vars should pass through"
    );
}

#[test]
fn env_prefix_denies_secret_suffixes() {
    // YARN_NPM_AUTH_TOKEN, COPILOT_SECRET_KEY, etc. must NOT leak
    // through the prefix allowlist even though YARN_ and COPILOT_ are allowed.
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        // YARN_ prefix — config vars should pass, auth tokens should not
        ("YARN_CACHE_FOLDER", "/some/cache"),
        ("YARN_NPM_AUTH_TOKEN", "npm_secret_token_123"),
        ("YARN_NPM_AUTH_TYPE", "authToken"),
        // COPILOT_ prefix — config vars should pass, secrets should not
        ("COPILOT_DEBUG", "1"),
        ("COPILOT_SECRET_KEY", "sk-secret-copilot"),
        ("COPILOT_API_KEY", "key-secret"),
        // NVM_ prefix — dir should pass, hypothetical token should not
        ("NVM_DIR", "/Users/test/.nvm"),
        ("NVM_AUTH_TOKEN", "nvm-secret"),
        // MISE_ prefix
        ("MISE_ENV", "production"),
        ("MISE_TOKEN", "mise-secret"),
        // SDKMAN_ prefix
        ("SDKMAN_DIR", "/Users/test/.sdkman"),
        ("SDKMAN_CREDENTIALS", "sdk-secret"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    // Safe config vars must pass through
    assert!(
        env.vars.iter().any(|(k, _)| k == "YARN_CACHE_FOLDER"),
        "YARN_CACHE_FOLDER should pass through"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "COPILOT_DEBUG"),
        "COPILOT_DEBUG should pass through"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "NVM_DIR"),
        "NVM_DIR should pass through"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "MISE_ENV"),
        "MISE_ENV should pass through"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "SDKMAN_DIR"),
        "SDKMAN_DIR should pass through"
    );

    // Secret-bearing vars must be blocked
    assert!(
        !env.vars.iter().any(|(k, _)| k == "YARN_NPM_AUTH_TOKEN"),
        "YARN_NPM_AUTH_TOKEN must not leak through YARN_ prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "COPILOT_SECRET_KEY"),
        "COPILOT_SECRET_KEY must not leak through COPILOT_ prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "COPILOT_API_KEY"),
        "COPILOT_API_KEY must not leak through COPILOT_ prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "NVM_AUTH_TOKEN"),
        "NVM_AUTH_TOKEN must not leak through NVM_ prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "MISE_TOKEN"),
        "MISE_TOKEN must not leak through MISE_ prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "SDKMAN_CREDENTIALS"),
        "SDKMAN_CREDENTIALS must not leak through SDKMAN_ prefix"
    );
}

#[test]
fn env_yarn_npm_auth_ident_is_stripped() {
    // Yarn Berry's YARN_NPM_AUTH_IDENT is a base64 `user:password` registry
    // credential. It must be stripped by the _IDENT deny-suffix even though the
    // YARN_ prefix is allowlisted, while benign YARN_ config vars still pass.
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("YARN_NPM_AUTH_IDENT", "dXNlcjpwYXNzd29yZA=="),
        ("YARN_CACHE_FOLDER", "/some/cache"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    assert!(
        !env.vars.iter().any(|(k, _)| k == "YARN_NPM_AUTH_IDENT"),
        "YARN_NPM_AUTH_IDENT (base64 user:pass) must not leak through YARN_ prefix"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "YARN_CACHE_FOLDER"),
        "benign YARN_ config var should still pass through"
    );
}

#[test]
fn env_explicit_allowlist_bypasses_suffix_deny() {
    // GH_TOKEN and GITHUB_TOKEN are in the explicit ENV_ALLOWLIST and must pass
    // through even though they end in _TOKEN.
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("GH_TOKEN", "ghp_abc123"),
        ("GITHUB_TOKEN", "ghp_def456"),
        ("COPILOT_GITHUB_TOKEN", "ghp_ghi789"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    assert!(
        env.vars.iter().any(|(k, _)| k == "GH_TOKEN"),
        "GH_TOKEN is explicitly allowlisted and must pass through"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "GITHUB_TOKEN"),
        "GITHUB_TOKEN is explicitly allowlisted and must pass through"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "COPILOT_GITHUB_TOKEN"),
        "COPILOT_GITHUB_TOKEN is explicitly allowlisted and must pass through"
    );
}

#[test]
fn env_otel_prefix_passthrough_and_secret_suffix_strip() {
    // a) OTEL_EXPORTER_OTLP_ENDPOINT passes through in sanitized (non-inherit) mode.
    // b) COPILOT_OTEL_ENABLED passes through (covered by the COPILOT_ prefix).
    // c) OTEL_FOO_TOKEN is stripped — deny-suffix wins over the OTEL_ prefix.
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
        ("OTEL_SERVICE_NAME", "my-service"),
        ("COPILOT_OTEL_ENABLED", "true"),
        ("OTEL_FOO_TOKEN", "secret-otel-token"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    assert!(
        env.vars
            .iter()
            .any(|(k, _)| k == "OTEL_EXPORTER_OTLP_ENDPOINT"),
        "OTEL_EXPORTER_OTLP_ENDPOINT should pass through via OTEL_ prefix"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "OTEL_SERVICE_NAME"),
        "OTEL_SERVICE_NAME should pass through via OTEL_ prefix"
    );
    assert!(
        env.vars.iter().any(|(k, _)| k == "COPILOT_OTEL_ENABLED"),
        "COPILOT_OTEL_ENABLED should pass through via COPILOT_ prefix"
    );
    assert!(
        !env.vars.iter().any(|(k, _)| k == "OTEL_FOO_TOKEN"),
        "OTEL_FOO_TOKEN must be stripped by the _TOKEN deny-suffix despite OTEL_ prefix"
    );
}

#[test]
fn env_otel_passes_through_for_opencode_agent() {
    // OpenCode has native OpenTelemetry support. OTEL_* vars are not Copilot-specific,
    // so they must pass through for non-Copilot agents (only COPILOT_* and the GitHub
    // tokens are suppressed for non-Copilot agents). COPILOT_OTEL_* is suppressed here.
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example.com"),
        ("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer abc123"),
        ("OTEL_RESOURCE_ATTRIBUTES", "user.name=test"),
        ("COPILOT_OTEL_ENABLED", "true"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::OpenCode);

    for var in [
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_HEADERS",
        "OTEL_RESOURCE_ATTRIBUTES",
    ] {
        assert!(
            env.vars.iter().any(|(k, _)| k == var),
            "{var} should pass through to OpenCode via OTEL_ prefix"
        );
    }
    assert!(
        !env.vars.iter().any(|(k, _)| k == "COPILOT_OTEL_ENABLED"),
        "COPILOT_OTEL_ENABLED must be suppressed for non-Copilot agents"
    );
}

// ============================================================
// Scratch dir SBPL rules
// ============================================================

#[test]
fn profile_scratch_dir_adds_all_permissions() {
    let scratch = std::path::Path::new("/Users/test/Library/Caches/cplt/tmp/abc123");
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: Some(scratch),
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    let scratch_str = scratch.to_string_lossy();
    assert!(
        p.contains(&format!("(allow file-read* (subpath \"{scratch_str}\"))")),
        "scratch dir should have file-read*"
    );
    assert!(
        p.contains(&format!("(allow file-write* (subpath \"{scratch_str}\"))")),
        "scratch dir should have file-write*"
    );
    assert!(
        p.contains(&format!("(allow process-exec (subpath \"{scratch_str}\"))")),
        "scratch dir should have process-exec"
    );
    assert!(
        p.contains(&format!(
            "(allow file-map-executable (subpath \"{scratch_str}\"))"
        )),
        "scratch dir should have file-map-executable"
    );
}

#[test]
fn profile_no_scratch_dir_omits_rules() {
    let p = default_profile();
    assert!(
        !p.contains("scratch"),
        "default profile should not mention scratch dir"
    );
}

// ============================================================
// allow-tmp-exec SBPL rules
// ============================================================

#[test]
fn profile_allow_tmp_exec_removes_denies() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: true,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    assert!(
        !p.contains("(deny process-exec (subpath \"/private/tmp\"))"),
        "allow-tmp-exec should remove /private/tmp exec deny"
    );
    assert!(
        !p.contains("(deny file-map-executable (subpath \"/private/tmp\"))"),
        "allow-tmp-exec should remove /private/tmp map-exec deny"
    );
    assert!(
        !p.contains("(deny process-exec (subpath \"/private/var/folders\"))"),
        "allow-tmp-exec should remove /private/var/folders exec deny"
    );
    assert!(
        !p.contains("(deny file-map-executable (subpath \"/private/var/folders\"))"),
        "allow-tmp-exec should remove /private/var/folders map-exec deny"
    );
    // Read/write should still be allowed
    assert!(
        p.contains("(allow file-read* (subpath \"/private/tmp\"))"),
        "tmp read should still be allowed"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/private/tmp\"))"),
        "tmp write should still be allowed"
    );
}

#[test]
fn profile_default_has_tmp_exec_denies() {
    let p = default_profile();
    assert!(
        p.contains("(deny process-exec (subpath \"/private/tmp\"))"),
        "default profile should deny exec from /private/tmp"
    );
    assert!(
        p.contains("(deny process-exec (subpath \"/private/var/folders\"))"),
        "default profile should deny exec from /private/var/folders"
    );
}

// ============================================================
// Copilot Caches native module carve-out
// ============================================================

#[test]
fn profile_allows_copilot_caches_map_exec() {
    let p = default_profile();
    assert!(
        p.contains(
            "(allow file-map-executable (subpath \"/Users/test/Library/Caches/copilot/pkg\"))"
        ),
        "Profile must allow file-map-executable for Copilot Caches native modules"
    );
    // The general Library/Caches deny must still be present
    assert!(
        p.contains("(deny file-map-executable (subpath \"/Users/test/Library/Caches\"))"),
        "General Library/Caches map-exec deny must still be present"
    );
}

#[test]
fn profile_copilot_caches_carveout_after_deny() {
    let p = default_profile();
    let deny_pos = p
        .find("(deny file-map-executable (subpath \"/Users/test/Library/Caches\"))")
        .expect("Library/Caches deny must exist");
    let allow_pos = p
        .find("(allow file-map-executable (subpath \"/Users/test/Library/Caches/copilot/pkg\"))")
        .expect("Copilot Caches carve-out must exist");
    assert!(
        allow_pos > deny_pos,
        "Copilot Caches carve-out must come AFTER the general deny (last-match-wins)"
    );
}

#[test]
fn profile_allows_copilot_caches_process_exec() {
    let p = default_profile();
    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches/copilot/pkg\"))"),
        "Profile must allow process-exec for Copilot Caches helper binaries (spawn-helper, rg)"
    );
    // General Library/Caches deny must still be present
    assert!(
        p.contains("(deny process-exec (subpath \"/Users/test/Library/Caches\"))"),
        "General Library/Caches process-exec deny must still be present"
    );
}

#[test]
fn profile_copilot_caches_exec_carveout_after_deny() {
    let p = default_profile();
    let deny_pos = p
        .find("(deny process-exec (subpath \"/Users/test/Library/Caches\"))")
        .expect("Library/Caches process-exec deny must exist");
    let allow_pos = p
        .find("(allow process-exec (subpath \"/Users/test/Library/Caches/copilot/pkg\"))")
        .expect("Copilot Caches process-exec carve-out must exist");
    assert!(
        allow_pos > deny_pos,
        "Copilot Caches process-exec carve-out must come AFTER the general deny (last-match-wins)"
    );
}

#[test]
fn profile_denies_write_to_copilot_caches_pkg() {
    let p = default_profile();
    // Must deny writes to prevent write-then-exec (binary-drop staging attack)
    assert!(
        p.contains("(deny file-write* (subpath \"/Users/test/Library/Caches/copilot/pkg\"))"),
        "Profile must deny file-write* to ~/Library/Caches/copilot/pkg (prevents binary-drop staging)"
    );
    // The deny must come after the broad Library/Caches write allow
    let allow_pos = p
        .find("(allow file-write* (subpath \"/Users/test/Library/Caches\"))")
        .expect("Library/Caches write allow must exist");
    let deny_pos = p
        .find("(deny file-write* (subpath \"/Users/test/Library/Caches/copilot/pkg\"))")
        .expect("Copilot Caches pkg write deny must exist");
    assert!(
        deny_pos > allow_pos,
        "Copilot Caches pkg write deny must come AFTER Library/Caches write allow (last-match-wins)"
    );
}

// ============================================================
// copilot_install_dir — non-standard Copilot install locations
// ============================================================

#[test]
fn profile_allows_copilot_install_dir() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: Some(std::path::Path::new(
            "/Users/test/n/lib/node_modules/@github/copilot",
        )),
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains(
            "(allow file-read* (subpath \"/Users/test/n/lib/node_modules/@github/copilot\"))"
        ),
        "Profile must allow reading the Copilot installation directory"
    );
    assert!(
        p.contains(
            "(allow file-map-executable (subpath \"/Users/test/n/lib/node_modules/@github/copilot\"))"
        ),
        "Profile must allow file-map-executable for native addons in Copilot install dir"
    );
}

#[test]
fn profile_allows_vscode_copilot_path() {
    // VS Code bundles Copilot CLI at ~/Library/Application Support/Code/.../copilotCli/
    // When copilot_pkg_dir() returns None, main.rs falls back to the binary's parent dir
    let vscode_dir = "/Users/test/Library/Application Support/Code/User/globalStorage/github.copilot-chat/copilotCli";
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: Some(std::path::Path::new(vscode_dir)),
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains(&format!("(allow file-read* (subpath \"{vscode_dir}\"))")),
        "Profile must allow reading VS Code Copilot CLI directory (path with spaces)"
    );
    assert!(
        p.contains(&format!(
            "(allow file-map-executable (subpath \"{vscode_dir}\"))"
        )),
        "Profile must allow file-map-executable for VS Code Copilot CLI"
    );
}

#[test]
fn profile_no_copilot_install_dir_omits_section() {
    let p = default_profile();
    assert!(
        !p.contains("Copilot CLI installation directory"),
        "Default profile should not have copilot install dir section"
    );
}

#[test]
fn profile_allows_electron_app_bundle() {
    let electron_dir = "/Applications/Visual Studio Code.app/Contents";
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: Some(std::path::Path::new(electron_dir)),
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains(&format!("(allow file-read* (subpath \"{electron_dir}\"))")),
        "Profile must allow reading Electron app bundle"
    );
    assert!(
        p.contains(&format!(
            "(allow file-map-executable (subpath \"{electron_dir}\"))"
        )),
        "Profile must allow file-map-executable for Electron framework"
    );
    assert!(
        p.contains("Electron app bundle"),
        "Profile should have Electron section comment"
    );
}

#[test]
fn profile_no_electron_app_omits_section() {
    let p = default_profile();
    assert!(
        !p.contains("Electron app bundle"),
        "Default profile should not have Electron section"
    );
}

// ============================================================
// copilot_pkg_dir — package root detection for non-standard installs
// ============================================================

#[test]
fn pkg_dir_finds_copilot_package() {
    let tmp = std::env::temp_dir().join(format!("cplt-test-pkg-{}", std::process::id()));
    let pkg = tmp.join("lib/node_modules/@github/copilot");
    let bin = pkg.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name": "@github/copilot", "version": "1.0.0"}"#,
    )
    .unwrap();
    let binary = bin.join("copilot");
    std::fs::write(&binary, "#!/usr/bin/env node").unwrap();

    let home = std::path::Path::new("/Users/test");
    let result = copilot_pkg_dir(&binary, home);
    assert_eq!(result, Some(pkg.clone()));

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn pkg_dir_returns_none_for_standalone_binary() {
    let tmp = std::env::temp_dir().join(format!("cplt-test-standalone-{}", std::process::id()));
    let bin = tmp.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let binary = bin.join("copilot");
    std::fs::write(&binary, "#!/bin/sh\nexec node").unwrap();

    let home = std::path::Path::new("/Users/test");
    let result = copilot_pkg_dir(&binary, home);
    assert_eq!(result, None);

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn pkg_dir_rejects_wrong_package_name() {
    let tmp = std::env::temp_dir().join(format!("cplt-test-wrong-{}", std::process::id()));
    let pkg = tmp.join("my-app");
    let bin = pkg.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name": "not-copilot", "version": "1.0.0"}"#,
    )
    .unwrap();
    let binary = bin.join("copilot");
    std::fs::write(&binary, "#!/usr/bin/env node").unwrap();

    let home = std::path::Path::new("/Users/test");
    let result = copilot_pkg_dir(&binary, home);
    assert_eq!(result, None);

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn pkg_dir_rejects_home_dir_as_root() {
    let tmp = std::env::temp_dir().join(format!("cplt-test-home-{}", std::process::id()));
    std::fs::create_dir_all(tmp.join("bin")).unwrap();
    // Put package.json at the "home" dir level — should be rejected as unsafe root
    std::fs::write(tmp.join("package.json"), r#"{"name": "@github/copilot"}"#).unwrap();
    let binary = tmp.join("bin/copilot");
    std::fs::write(&binary, "#!/usr/bin/env node").unwrap();

    // Treat tmp itself as the home directory
    let result = copilot_pkg_dir(&binary, &tmp);
    assert_eq!(result, None, "should reject when package root equals HOME");

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn pkg_dir_finds_package_multiple_levels_up() {
    // Simulates pnpm-style deep nesting: .pnpm/@github+copilot@1.0.0/node_modules/@github/copilot/bin/copilot
    let tmp = std::env::temp_dir().join(format!("cplt-test-deep-{}", std::process::id()));
    let pkg = tmp.join("store/node_modules/@github/copilot");
    let bin = pkg.join("dist/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(pkg.join("package.json"), r#"{"name": "@github/copilot"}"#).unwrap();
    let binary = bin.join("copilot");
    std::fs::write(&binary, "#!/usr/bin/env node").unwrap();

    let home = std::path::Path::new("/Users/test");
    let result = copilot_pkg_dir(&binary, home);
    // dist/bin/copilot → dist/ → @github/copilot/ (has package.json) — 2 levels up
    assert_eq!(result, Some(pkg.clone()));

    std::fs::remove_dir_all(&tmp).unwrap();
}

// ============================================================
// git_hooks_path — global git hooks profile emission
// ============================================================

#[test]
fn profile_allows_git_hooks_path() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: Some(std::path::Path::new("/Users/test/.config/git/hooks")),
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow file-read* (subpath \"/Users/test/.config/git/hooks\"))"),
        "Profile must allow reading global git hooks"
    );
    assert!(
        p.contains("(deny file-write* (subpath \"/Users/test/.config/git/hooks\"))"),
        "Profile must deny writing to git hooks (persistence attack prevention)"
    );
    assert!(
        p.contains("Global git hooks"),
        "Profile must have git hooks section comment"
    );
}

#[test]
fn profile_no_git_hooks_path_omits_section() {
    let p = default_profile();
    assert!(
        !p.contains("Global git hooks"),
        "Default profile should not have git hooks section"
    );
}

// ============================================================
// git_common_dir — worktree shared directory profile emission
// ============================================================

#[test]
fn profile_allows_git_worktree_common_dir() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/feature-branch"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: Some(std::path::Path::new("/Users/test/repos/main-repo/.git")),
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow file-read* (subpath \"/Users/test/repos/main-repo/.git\"))"),
        "Profile must allow reading worktree common dir"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/repos/main-repo/.git\"))"),
        "Profile must allow writing worktree common dir"
    );
    assert!(
        p.contains("(deny file-write* (subpath \"/Users/test/repos/main-repo/.git/hooks\"))"),
        "Profile must deny writing to hooks in common dir"
    );
    assert!(
        p.contains("(deny file-write* (literal \"/Users/test/repos/main-repo/.git/config\"))"),
        "Profile must deny writing to config in common dir"
    );
}

#[test]
fn profile_no_git_common_dir_omits_section() {
    let p = default_profile();
    assert!(
        !p.contains("Git worktree shared"),
        "Default profile should not have worktree section"
    );
}

// ============================================================
// git signing hardening — GIT_CONFIG env vars disable signing
// ============================================================

#[test]
fn env_git_signing_disabled_by_default() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);
    let get = |name: &str| {
        env.vars
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(get("GIT_CONFIG_COUNT"), Some("2"));
    assert_eq!(get("GIT_CONFIG_KEY_0"), Some("commit.gpgsign"));
    assert_eq!(get("GIT_CONFIG_VALUE_0"), Some("false"));
    assert_eq!(get("GIT_CONFIG_KEY_1"), Some("tag.gpgsign"));
    assert_eq!(get("GIT_CONFIG_VALUE_1"), Some("false"));
}

#[test]
fn env_git_signing_enabled_skips_signing_vars() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &[HardeningCategory::GitSigning],
        None,
        cplt::agent::Agent::Copilot,
    );
    let get = |name: &str| {
        env.vars
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    // Signing vars should be absent when GitSigning category is disabled
    assert_eq!(
        get("GIT_CONFIG_COUNT"),
        None,
        "GIT_CONFIG_COUNT should not be set when GPG signing is allowed"
    );
    assert_eq!(get("GIT_CONFIG_KEY_0"), None);
    assert_eq!(get("GIT_CONFIG_VALUE_0"), None);
    // GIT_TERMINAL_PROMPT should still be set (it's GitHardening, not GitSigning)
    assert_eq!(
        get("GIT_TERMINAL_PROMPT"),
        Some("0"),
        "GIT_TERMINAL_PROMPT must remain set even when GPG signing is allowed"
    );
}

#[test]
fn env_gpg_tty_passed_through() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("GPG_TTY", "/dev/ttys001"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);
    let get = |name: &str| {
        env.vars
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(
        get("GPG_TTY"),
        Some("/dev/ttys001"),
        "GPG_TTY should be in the allowlist"
    );
}

// ============================================================
// GPG signing — profile SBPL rules
// ============================================================

#[test]
fn profile_gpg_signing_disabled_by_default() {
    let p = default_profile();
    assert!(
        !p.contains("GPG signing"),
        "GPG signing section should not appear when disabled"
    );
    assert!(
        !p.contains("S.gpg-agent"),
        "GPG agent socket should not be allowed when disabled"
    );
}

#[test]
fn profile_gpg_signing_allows_public_keyring() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow file-read* (literal \"/Users/test/.gnupg/pubring.kbx\"))"),
        "Must allow reading public keyring"
    );
    assert!(
        p.contains("(allow file-read* (literal \"/Users/test/.gnupg/trustdb.gpg\"))"),
        "Must allow reading trust database"
    );
    assert!(
        p.contains("(allow file-read* (literal \"/Users/test/.gnupg/gpg.conf\"))"),
        "Must allow reading GPG config"
    );
}

#[test]
fn profile_gpg_signing_allows_agent_socket() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow network-outbound (literal \"/Users/test/.gnupg/S.gpg-agent\"))"),
        "Must allow connecting to GPG agent socket"
    );
    // GnuPG 2.4+ keyboxd socket for public key lookups
    assert!(
        p.contains("(allow network-outbound (literal \"/Users/test/.gnupg/S.keyboxd\"))"),
        "Must allow connecting to keyboxd socket for GnuPG 2.4+"
    );
}

#[test]
fn profile_gpg_signing_denies_private_keys() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(deny file-read* (subpath \"/Users/test/.gnupg/private-keys-v1.d\"))"),
        "Private keys must remain denied even with GPG signing enabled"
    );
    assert!(
        p.contains("(deny file-write* (subpath \"/Users/test/.gnupg\"))"),
        "Write access to .gnupg must be denied"
    );
}

#[test]
fn profile_gpg_signing_rules_come_after_deny() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    let deny_pos = p
        .find("(deny file-read* (subpath \"/Users/test/.gnupg\"))")
        .expect("must have .gnupg deny rule");
    let allow_pos = p
        .find("(allow file-read* (literal \"/Users/test/.gnupg/pubring.kbx\"))")
        .expect("must have GPG signing allow rule");
    assert!(
        allow_pos > deny_pos,
        "GPG signing allows must come after .gnupg deny rules for correct SBPL last-match-wins"
    );
    // Private key deny must come after the GPG allows
    let privkey_deny = p
        .find("(deny file-read* (subpath \"/Users/test/.gnupg/private-keys-v1.d\"))")
        .expect("must have private key deny");
    assert!(
        privkey_deny > allow_pos,
        "Private key deny must come after GPG signing allows"
    );
}

#[test]
fn profile_gpg_signing_uses_literal_not_subpath() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Must use literal (exact file), never subpath (recursive) for GPG allows
    assert!(
        !p.contains("(allow file-read* (subpath \"/Users/test/.gnupg\"))"),
        "Must use literal, never subpath, for GPG file allows"
    );
}

#[test]
fn profile_gpg_signing_deny_path_wins() {
    let deny = vec![std::path::PathBuf::from("/Users/test/.gnupg")];
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &deny,
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // When user explicitly denies ~/.gnupg, GPG allows should NOT appear
    assert!(
        !p.contains("(allow file-read* (literal \"/Users/test/.gnupg/pubring.kbx\"))"),
        "explicit --deny-path ~/.gnupg should override --allow-gpg-signing"
    );
    assert!(
        p.contains("--deny-path overlaps"),
        "profile should note that deny-path overrode GPG signing"
    );
}

#[test]
fn profile_gpg_signing_denies_legacy_secring() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(deny file-read* (literal \"/Users/test/.gnupg/secring.gpg\"))"),
        "legacy secring.gpg must be explicitly denied"
    );
}

#[test]
fn profile_gpg_signing_allows_socket_file_read() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: true,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Socket needs file-read* for inode lookup before connect(2)
    assert!(
        p.contains("(allow file-read* (literal \"/Users/test/.gnupg/S.gpg-agent\"))"),
        "GPG agent socket should have file-read* for inode lookup"
    );
}

// ============================================================
// build_sandbox_env — scratch dir env injection
// ============================================================

#[test]
fn env_scratch_dir_sets_tmpdir_vars() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("PATH", "/usr/bin"),
        ("TMPDIR", "/private/var/folders/old"),
    ]);
    let scratch = std::path::Path::new("/Users/test/Library/Caches/cplt/tmp/session123");
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let tmpdir = env.vars.iter().find(|(k, _)| k == "TMPDIR");
    assert!(tmpdir.is_some(), "TMPDIR should be set");
    assert_eq!(
        tmpdir.unwrap().1,
        scratch.to_string_lossy(),
        "TMPDIR should point to scratch dir"
    );

    let gotmpdir = env.vars.iter().find(|(k, _)| k == "GOTMPDIR");
    assert!(gotmpdir.is_some(), "GOTMPDIR should be set");
    assert_eq!(gotmpdir.unwrap().1, scratch.to_string_lossy());

    let tmp = env.vars.iter().find(|(k, _)| k == "TMP");
    assert!(tmp.is_some(), "TMP should be set");

    let temp = env.vars.iter().find(|(k, _)| k == "TEMP");
    assert!(temp.is_some(), "TEMP should be set");

    let gocache = env.vars.iter().find(|(k, _)| k == "GOCACHE");
    assert!(gocache.is_some(), "GOCACHE should be set");
    assert_eq!(
        gocache.unwrap().1,
        scratch.to_string_lossy(),
        "GOCACHE should point to scratch dir for exec permissions"
    );
}

#[test]
fn env_scratch_dir_no_duplicate_tmpdir() {
    let parent = make_env(&[("HOME", "/Users/test"), ("TMPDIR", "/old/tmp")]);
    let scratch = std::path::Path::new("/new/scratch");
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let tmpdir_count = env.vars.iter().filter(|(k, _)| k == "TMPDIR").count();
    assert_eq!(tmpdir_count, 1, "TMPDIR should appear exactly once");
}

#[test]
fn env_scratch_dir_respects_pass_env_override() {
    let parent = make_env(&[("HOME", "/Users/test"), ("TMPDIR", "/custom/tmp")]);
    let extra = vec!["TMPDIR".to_string()];
    let scratch = std::path::Path::new("/scratch/dir");
    let env = build_sandbox_env(
        &parent,
        &extra,
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let tmpdir = env.vars.iter().find(|(k, _)| k == "TMPDIR");
    assert!(tmpdir.is_some());
    assert_eq!(
        tmpdir.unwrap().1,
        "/custom/tmp",
        "user's explicit --pass-env TMPDIR should override scratch dir"
    );
}

#[test]
fn env_no_scratch_dir_passes_system_tmpdir() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("TMPDIR", "/private/var/folders/xx"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    let tmpdir = env.vars.iter().find(|(k, _)| k == "TMPDIR");
    assert!(tmpdir.is_some());
    assert_eq!(
        tmpdir.unwrap().1,
        "/private/var/folders/xx",
        "without scratch dir, system TMPDIR should pass through"
    );
}

// ============================================================
// build_sandbox_env — JAVA_TOOL_OPTIONS tmpdir injection
// ============================================================

#[test]
fn env_scratch_dir_injects_java_tool_options() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let scratch = std::path::Path::new("/scratch/session123");
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let jto = env.vars.iter().find(|(k, _)| k == "JAVA_TOOL_OPTIONS");
    assert!(jto.is_some(), "JAVA_TOOL_OPTIONS should be injected");
    let val = &jto.unwrap().1;
    assert!(
        val.contains("-Djava.io.tmpdir=/scratch/session123"),
        "should contain java.io.tmpdir: {val}"
    );
    assert!(
        val.contains("-Djansi.tmpdir=/scratch/session123"),
        "should contain jansi.tmpdir: {val}"
    );
    assert!(
        val.contains("-Djava.rmi.server.hostname=localhost"),
        "should contain rmi hostname: {val}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        val.contains("-Djava.net.preferIPv4Stack=true"),
        "should contain preferIPv4Stack on macOS: {val}"
    );
}

#[test]
fn env_scratch_dir_appends_to_existing_java_tool_options() {
    let parent = make_env(&[("HOME", "/Users/test"), ("JAVA_TOOL_OPTIONS", "-Xmx512m")]);
    let scratch = std::path::Path::new("/scratch/session123");
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let jto = env.vars.iter().find(|(k, _)| k == "JAVA_TOOL_OPTIONS");
    assert!(jto.is_some());
    let val = &jto.unwrap().1;
    assert!(
        val.starts_with("-Xmx512m "),
        "should preserve existing flags: {val}"
    );
    assert!(
        val.contains("-Djava.io.tmpdir=/scratch/session123"),
        "should append java.io.tmpdir: {val}"
    );
}

#[test]
fn env_scratch_dir_java_tool_options_respects_pass_env() {
    let parent = make_env(&[("HOME", "/Users/test"), ("JAVA_TOOL_OPTIONS", "-Xmx1g")]);
    let extra = vec!["JAVA_TOOL_OPTIONS".to_string()];
    let scratch = std::path::Path::new("/scratch/session123");
    let env = build_sandbox_env(
        &parent,
        &extra,
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let jto = env.vars.iter().find(|(k, _)| k == "JAVA_TOOL_OPTIONS");
    assert!(jto.is_some());
    assert_eq!(
        jto.unwrap().1,
        "-Xmx1g",
        "--pass-env JAVA_TOOL_OPTIONS should prevent injection"
    );
}

#[test]
fn env_no_scratch_dir_no_java_tool_options_injected() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);

    let jto = env.vars.iter().find(|(k, _)| k == "JAVA_TOOL_OPTIONS");
    assert!(
        jto.is_none(),
        "without scratch dir, JAVA_TOOL_OPTIONS should not be injected"
    );
}

#[test]
fn env_scratch_dir_no_jansi_tmpdir_env_var() {
    // JANSI_TMPDIR env var is NOT a thing — Jansi uses System.getProperty("jansi.tmpdir").
    // Verify we don't set it as an env var anymore.
    let parent = make_env(&[("HOME", "/Users/test")]);
    let scratch = std::path::Path::new("/scratch/session123");
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let jansi = env.vars.iter().find(|(k, _)| k == "JANSI_TMPDIR");
    assert!(
        jansi.is_none(),
        "JANSI_TMPDIR env var should not be set (Jansi reads a Java system property, not an env var)"
    );
}

// ============================================================
// build_sandbox_env — GRADLE_MACOS_SANDBOX injection (macOS only)
// ============================================================

#[cfg(target_os = "macos")]
#[test]
fn env_injects_gradle_macos_sandbox_off() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let scratch = std::path::Path::new("/scratch/session123");
    let env = build_sandbox_env(
        &parent,
        &[],
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let gradle = env.vars.iter().find(|(k, _)| k == "GRADLE_MACOS_SANDBOX");
    assert!(
        gradle.is_some(),
        "GRADLE_MACOS_SANDBOX should be injected on macOS"
    );
    assert_eq!(gradle.unwrap().1, "off");
}

#[cfg(target_os = "macos")]
#[test]
fn env_gradle_macos_sandbox_respects_pass_env() {
    let parent = make_env(&[("HOME", "/Users/test"), ("GRADLE_MACOS_SANDBOX", "on")]);
    let extra = vec!["GRADLE_MACOS_SANDBOX".to_string()];
    let scratch = std::path::Path::new("/scratch/session123");
    let env = build_sandbox_env(
        &parent,
        &extra,
        false,
        &[],
        Some(scratch),
        cplt::agent::Agent::Copilot,
    );

    let gradle = env.vars.iter().find(|(k, _)| k == "GRADLE_MACOS_SANDBOX");
    // With --pass-env, user's value should be preserved
    assert!(gradle.is_some());
    assert_eq!(
        gradle.unwrap().1,
        "on",
        "--pass-env should prevent injection of GRADLE_MACOS_SANDBOX=off"
    );
}

// ============================================================
// NODE_OPTIONS sanitization — strip dangerous preload flags
// ============================================================

#[test]
fn env_node_options_strips_require() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        (
            "NODE_OPTIONS",
            "--require /tmp/evil.js --max-old-space-size=4096",
        ),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);
    let node_opts = env.vars.iter().find(|(k, _)| k == "NODE_OPTIONS");
    assert!(node_opts.is_some());
    assert_eq!(node_opts.unwrap().1, "--max-old-space-size=4096");
}

#[test]
fn env_node_options_strips_loader() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("NODE_OPTIONS", "--loader=./evil.mjs --no-warnings"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);
    let node_opts = env.vars.iter().find(|(k, _)| k == "NODE_OPTIONS");
    assert!(node_opts.is_some());
    assert_eq!(node_opts.unwrap().1, "--no-warnings");
}

#[test]
fn env_node_options_strips_import() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        (
            "NODE_OPTIONS",
            "--import ./register.js --dns-result-order=ipv4first",
        ),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);
    let node_opts = env.vars.iter().find(|(k, _)| k == "NODE_OPTIONS");
    assert!(node_opts.is_some());
    assert_eq!(node_opts.unwrap().1, "--dns-result-order=ipv4first");
}

#[test]
fn env_node_options_removes_entirely_if_only_dangerous() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        ("NODE_OPTIONS", "--require /tmp/evil.js -r ./other.js"),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);
    let node_opts = env.vars.iter().find(|(k, _)| k == "NODE_OPTIONS");
    assert!(
        node_opts.is_none(),
        "NODE_OPTIONS should be removed entirely when only dangerous flags remain"
    );
}

#[test]
fn env_node_options_preserves_safe_flags() {
    let parent = make_env(&[
        ("HOME", "/Users/test"),
        (
            "NODE_OPTIONS",
            "--max-old-space-size=8192 --openssl-legacy-provider --no-warnings",
        ),
    ]);
    let env = build_sandbox_env(&parent, &[], false, &[], None, cplt::agent::Agent::Copilot);
    let node_opts = env.vars.iter().find(|(k, _)| k == "NODE_OPTIONS");
    assert!(node_opts.is_some());
    assert_eq!(
        node_opts.unwrap().1,
        "--max-old-space-size=8192 --openssl-legacy-provider --no-warnings"
    );
}

#[test]
fn config_parses_scratch_dir() {
    use cplt::config::Config;
    let config: Config = toml::from_str("[sandbox]\nscratch_dir = true\n").unwrap();
    assert_eq!(config.sandbox.scratch_dir, Some(true));
}

#[test]
fn config_parses_allow_tmp_exec() {
    use cplt::config::Config;
    let config: Config = toml::from_str("[sandbox]\nallow_tmp_exec = true\n").unwrap();
    assert_eq!(config.sandbox.allow_tmp_exec, Some(true));
}

// ============================================================
// Config validation (unknown key detection)
// ============================================================

#[test]
fn validate_catches_typo_in_sandbox_key() {
    use cplt::config::{DiagnosticLevel, validate_config};
    let diagnostics = validate_config("[sandbox]\ninherit_evn = true\n");
    assert!(diagnostics.iter().any(|d| {
        d.level == DiagnosticLevel::Error
            && d.message.contains("inherit_evn")
            && d.message.contains("did you mean")
    }));
}

#[test]
fn validate_catches_unknown_proxy_key() {
    use cplt::config::{DiagnosticLevel, validate_config};
    // `tiemout` is a typo of the real `timeout` field — it must be flagged.
    let diagnostics = validate_config("[proxy]\nenabled = true\ntiemout = 30\n");
    assert!(
        diagnostics
            .iter()
            .any(|d| { d.level == DiagnosticLevel::Error && d.message.contains("tiemout") })
    );
}

#[test]
fn validate_accepts_all_valid_keys() {
    use cplt::config::validate_config;
    let toml = r#"
[proxy]
enabled = false
port = 18080
blocked_domains = "file.txt"
allowed_domains = "file.txt"
log_file = "log.txt"

[allow]
read = []
write = []
ports = []
localhost = []

[deny]
paths = []

[sandbox]
validate = true
allow_env_files = false
allow_localhost_any = false
pass_env = []
inherit_env = false
allow_lifecycle_scripts = false
allow_gpg_signing = false
allow_tmp_exec = false
scratch_dir = false
quiet = false
allow_cache_exec = []
allow_cache_exec_any = false
"#;
    let diagnostics = validate_config(toml);
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.level == cplt::config::DiagnosticLevel::Error)
        .collect();
    assert!(errors.is_empty(), "all valid keys should pass: {errors:?}");
}

#[test]
fn config_from_str_round_trips() {
    use cplt::config::Config;
    let toml = "[proxy]\nenabled = true\nport = 1234\n";
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.proxy.enabled, Some(true));
    assert_eq!(config.proxy.port, Some(1234));
}

// ============================================================
// Docker access (--allow-docker)
// ============================================================

#[test]
fn profile_docker_disabled_by_default() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // .docker should be denied
    assert!(
        p.contains(r#"(deny file-read* (subpath "/Users/test/.docker"))"#),
        "Profile must deny .docker by default"
    );
    // No docker socket allows
    assert!(
        !p.contains("docker.sock"),
        "Profile must not mention docker.sock when allow_docker is false"
    );
}

#[test]
fn profile_docker_enabled_allows_config_and_sockets() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: true,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Should allow read of ~/.docker
    assert!(
        p.contains(r#"(allow file-read* (subpath "/Users/test/.docker"))"#),
        "Profile must allow reading ~/.docker when --allow-docker is set"
    );
    // Should deny write to ~/.docker
    assert!(
        p.contains(r#"(deny file-write* (subpath "/Users/test/.docker"))"#),
        "Profile must deny write to ~/.docker"
    );
    // Should re-deny sensitive trust directory
    assert!(
        p.contains(r#"(deny file-read* (subpath "/Users/test/.docker/trust/private"))"#),
        "Profile must re-deny ~/.docker/trust/private"
    );
    // Should allow Colima socket
    assert!(
        p.contains(
            r#"(allow network-outbound (literal "/Users/test/.colima/default/docker.sock"))"#
        ),
        "Profile must allow outbound to Colima Docker socket"
    );
    // Should allow /private/var/run/docker.sock
    assert!(
        p.contains(r#"(allow network-outbound (literal "/private/var/run/docker.sock"))"#),
        "Profile must allow outbound to /private/var/run/docker.sock"
    );
    // Should allow OrbStack socket
    assert!(
        p.contains(r#"(allow network-outbound (literal "/Users/test/.orbstack/run/docker.sock"))"#),
        "Profile must allow outbound to OrbStack Docker socket"
    );
    // Should allow Podman Machine socket
    assert!(
        p.contains(r#"(allow network-outbound (literal "/Users/test/.local/share/containers/podman/machine/podman.sock"))"#),
        "Profile must allow outbound to Podman Machine socket"
    );
    // Should allow read of ~/.config/containers (Podman config)
    assert!(
        p.contains(r#"(allow file-read* (subpath "/Users/test/.config/containers"))"#),
        "Profile must allow reading ~/.config/containers for Podman config"
    );
}

#[test]
fn profile_docker_skipped_when_deny_path_overlaps() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[std::path::PathBuf::from("/Users/test/.docker")],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: true,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    // Docker allows should be skipped — deny-path wins
    assert!(
        p.contains("Docker access skipped"),
        "Profile must skip docker rules when --deny-path overlaps"
    );
    assert!(
        !p.contains(r#"(allow file-read* (subpath "/Users/test/.docker"))"#),
        "Profile must not allow .docker when deny-path overlaps"
    );
}

#[test]
fn profile_socket_allows_rules() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[std::path::PathBuf::from(
            "/Users/test/.codex/codex-lsp/daemon/daemon.sock",
        )],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    assert!(
        p.contains(
            r#"(allow file-read* (literal "/Users/test/.codex/codex-lsp/daemon/daemon.sock"))"#
        ),
        "Profile must allow read access to the socket path"
    );
    assert!(
        p.contains(
            r#"(allow file-write* (literal "/Users/test/.codex/codex-lsp/daemon/daemon.sock"))"#
        ),
        "Profile must allow write access to the socket path"
    );
    assert!(
        p.contains(r#"(allow network-outbound (remote unix-socket (literal "/Users/test/.codex/codex-lsp/daemon/daemon.sock")))"#),
        "Profile must allow network-outbound to the socket path"
    );
    assert!(
        p.contains(r#"(allow network-bind (local unix-socket (literal "/Users/test/.codex/codex-lsp/daemon/daemon.sock")))"#),
        "Profile must allow network-bind to the socket path"
    );
    assert!(
        p.contains(r#"(allow network-inbound (local unix-socket (literal "/Users/test/.codex/codex-lsp/daemon/daemon.sock")))"#),
        "Profile must allow network-inbound to the socket path"
    );
}

#[test]
fn profile_socket_skipped_when_deny_path_overlaps() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[std::path::PathBuf::from(
            "/Users/test/.codex/codex-lsp/daemon/daemon.sock",
        )],
        extra_deny: &[std::path::PathBuf::from("/Users/test/.codex")],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    assert!(
        p.contains("Socket access skipped: --deny-path overlaps with /Users/test/.codex/codex-lsp/daemon/daemon.sock"),
        "Profile must skip the socket rules when a parent directory is denied"
    );
    // #126 Tier 2: socket allows are emitted with `(literal ...)`, never
    // `(subpath ...)`, so the old `!contains(subpath …)` assertion targeted a
    // rule form that is never generated and could never catch a regression.
    // Target the actual `(literal ...)` form the socket rules use.
    assert!(
        !p.contains(
            r#"(allow file-read* (literal "/Users/test/.codex/codex-lsp/daemon/daemon.sock"))"#
        ),
        "Profile must not contain socket allows when parent dir is denied"
    );
    assert!(
        !p.contains(
            r#"(allow network-outbound (remote unix-socket (literal "/Users/test/.codex/codex-lsp/daemon/daemon.sock")))"#
        ),
        "Profile must not contain socket network allows when parent dir is denied"
    );
}

#[test]
fn profile_allow_cache_exec_subdir_adds_carveout() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &["ms-playwright".to_string()],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches/ms-playwright\"))"),
        "allow-cache-exec should add process-exec for the subdir"
    );
    assert!(
        p.contains(
            "(allow file-map-executable (subpath \"/Users/test/Library/Caches/ms-playwright\"))"
        ),
        "allow-cache-exec should add file-map-executable for the subdir"
    );
    assert!(
        !p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches\"))"),
        "allow-cache-exec should not allow exec from all of Library/Caches"
    );
}

#[test]
fn profile_allow_cache_exec_any_allows_all_caches() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: true,
        allow_browser: false,
    });

    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches\"))"),
        "allow-cache-exec-any should allow exec from all of Library/Caches"
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/Library/Caches\"))"),
        "allow-cache-exec-any should allow file-map-executable from all of Library/Caches"
    );
}

#[test]
fn profile_default_denies_cache_exec() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    assert!(
        !p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches\"))"),
        "by default, exec from Library/Caches must be blocked"
    );
}

#[test]
fn profile_allow_cache_exec_multiple_subdirs() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &["ms-playwright".to_string(), "pnpm/dlx".to_string()],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches/ms-playwright\"))")
    );
    assert!(p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches/pnpm/dlx\"))"));
    assert!(!p.contains("(allow process-exec (subpath \"/Users/test/Library/Caches\"))"));
}

#[test]
fn config_parses_allow_cache_exec() {
    use cplt::config::Config;
    let toml = "[sandbox]\nallow_cache_exec = [\"ms-playwright\", \"pnpm/dlx\"]\n";
    let config = Config::parse(toml).unwrap();
    assert_eq!(
        config.sandbox.allow_cache_exec,
        vec!["ms-playwright", "pnpm/dlx"]
    );
}

#[test]
fn config_parses_allow_cache_exec_any() {
    use cplt::config::Config;
    let toml = "[sandbox]\nallow_cache_exec_any = true\n";
    let config = Config::parse(toml).unwrap();
    assert_eq!(config.sandbox.allow_cache_exec_any, Some(true));
}

#[test]
fn config_validates_allow_cache_exec_keys() {
    use cplt::config::{DiagnosticLevel, validate_config};
    let toml = "[sandbox]\nallow_cache_exec = [\"ms-playwright\"]\nallow_cache_exec_any = false\n";
    let diagnostics = validate_config(toml);
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.level == DiagnosticLevel::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "allow_cache_exec keys should be valid: {errors:?}"
    );
}

#[test]
fn allow_cache_exec_rejects_empty_string() {
    use cplt::config::{CliFlags, Config};
    let cases = [
        "[sandbox]\nallow_cache_exec = [\"\"]\n",
        "[sandbox]\nallow_cache_exec = [\"   \"]\n",
    ];
    for toml in cases {
        let result = Config::parse(toml).unwrap().merge(CliFlags::default());
        assert!(
            result.is_err(),
            "empty allow_cache_exec subdir should be rejected: {toml:?}"
        );
    }
}

#[test]
fn allow_cache_exec_rejects_path_traversal() {
    use cplt::config::{CliFlags, Config};
    let cases = ["../Applications", "ms-playwright/../../usr", ".", ".."];
    for bad in cases {
        let toml = format!("[sandbox]\nallow_cache_exec = [\"{bad}\"]\n");
        let result = Config::parse(&toml).unwrap().merge(CliFlags::default());
        assert!(
            result.is_err(),
            "allow_cache_exec subdir {bad:?} should be rejected as path traversal"
        );
    }
}

#[test]
fn allow_cache_exec_rejects_unsafe_chars() {
    use cplt::config::{CliFlags, Config};
    // \\ and \n are representable in TOML strings
    let cases = [
        "[sandbox]\nallow_cache_exec = [\"bad\\\\subdir\"]\n",
        "[sandbox]\nallow_cache_exec = [\"bad\\nsubdir\"]\n",
    ];
    for toml in cases {
        let result = Config::parse(toml).unwrap().merge(CliFlags::default());
        assert!(
            result.is_err(),
            "unsafe subdir should be rejected: {toml:?}"
        );
    }
}

#[test]
fn profile_cache_exec_carveout_comes_after_exec_deny() {
    // The carve-out must appear after the broad exec-deny rules for last-match-wins to work.
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &["ms-playwright".to_string()],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    let deny_pos = p
        .find("(deny process-exec")
        .expect("profile must contain a process-exec deny rule");
    let allow_pos = p
        .find("(allow process-exec (subpath \"/Users/test/Library/Caches/ms-playwright\"))")
        .expect("profile must contain the cache-exec carve-out");
    assert!(
        allow_pos > deny_pos,
        "cache-exec carve-out must appear after exec deny rules for last-match-wins to apply"
    );
}

#[test]
fn validate_config_warns_on_allow_cache_exec_any() {
    use cplt::config::{DiagnosticLevel, validate_config};
    let toml = "[sandbox]\nallow_cache_exec_any = true\n";
    let diagnostics = validate_config(toml);
    let has_warning = diagnostics
        .iter()
        .any(|d| d.level == DiagnosticLevel::Warning && d.message.contains("allow_cache_exec_any"));
    assert!(
        has_warning,
        "validate_config should warn when allow_cache_exec_any = true"
    );
}

// ── repo_key_target mapping tests ────────────────────────────────────

#[test]
fn repo_key_target_maps_sandbox_booleans_to_propose() {
    use cplt::config::{RepoKeyTarget, lookup_key, repo_key_target};

    let propose_keys = [
        "sandbox.allow_jvm_attach",
        "sandbox.allow_localhost_any",
        "sandbox.allow_docker",
        "sandbox.allow_tmp_exec",
        "sandbox.allow_gpg_signing",
        "sandbox.allow_lifecycle_scripts",
        "sandbox.allow_browser",
        "sandbox.allow_env_files",
    ];

    for key_str in propose_keys {
        let info = lookup_key(key_str).unwrap();
        assert_eq!(
            repo_key_target(info),
            Some(RepoKeyTarget::ProposeBool),
            "{key_str} should map to ProposeBool"
        );
    }
}

#[test]
fn repo_key_target_maps_allow_arrays_to_propose_allow() {
    use cplt::config::{RepoKeyTarget, lookup_key, repo_key_target};

    let cases = [
        ("allow.read", "read"),
        ("allow.write", "write"),
        ("allow.ports", "ports"),
        ("allow.localhost", "localhost"),
    ];

    for (key_str, expected_field) in cases {
        let info = lookup_key(key_str).unwrap();
        assert_eq!(
            repo_key_target(info),
            Some(RepoKeyTarget::ProposeAllow(expected_field)),
            "{key_str} should map to ProposeAllow(\"{expected_field}\")"
        );
    }
}

#[test]
fn repo_key_target_maps_deny_keys() {
    use cplt::config::{RepoKeyTarget, lookup_key, repo_key_target};

    let info = lookup_key("deny.paths").unwrap();
    assert_eq!(repo_key_target(info), Some(RepoKeyTarget::Deny("paths")));

    let info = lookup_key("deny.env").unwrap();
    assert_eq!(repo_key_target(info), Some(RepoKeyTarget::Deny("env")));
}

#[test]
fn repo_key_target_maps_proxy_private_domains() {
    use cplt::config::{RepoKeyTarget, lookup_key, repo_key_target};

    let info = lookup_key("proxy.allow_private_domains").unwrap();
    assert_eq!(
        repo_key_target(info),
        Some(RepoKeyTarget::ProposeProxy("allow_private_domains"))
    );
}

#[test]
fn repo_key_target_rejects_machine_specific_keys() {
    use cplt::config::{lookup_key, repo_key_target};

    let rejected = [
        "sandbox.quiet",
        "sandbox.validate",
        "sandbox.scratch_dir",
        "sandbox.inherit_env",
        "sandbox.pass_env",
        "proxy.enabled",
        "proxy.port",
        "proxy.log_file",
        "proxy.log_level",
        "proxy.blocked_domains",
        "proxy.allowed_domains",
    ];

    for key_str in rejected {
        let info = lookup_key(key_str).unwrap();
        assert_eq!(
            repo_key_target(info),
            None,
            "{key_str} should be rejected in repo config"
        );
    }
}

#[test]
fn set_repo_value_propose_bool_true() {
    use cplt::config::{lookup_key, repo_key_target, set_repo_value_in_doc};

    let mut doc = toml_edit::DocumentMut::new();
    let info = lookup_key("sandbox.allow_jvm_attach").unwrap();
    let target = repo_key_target(info).unwrap();

    set_repo_value_in_doc(&mut doc, info, target, "true", false).unwrap();

    let output = doc.to_string();
    assert!(
        output.contains("[propose]"),
        "should have [propose]: {output}"
    );
    assert!(
        output.contains("allow_jvm_attach = true"),
        "should have key=true: {output}"
    );
}

#[test]
fn set_repo_value_propose_bool_false_rejected() {
    use cplt::config::{lookup_key, repo_key_target, set_repo_value_in_doc};

    let mut doc = toml_edit::DocumentMut::new();
    let info = lookup_key("sandbox.allow_jvm_attach").unwrap();
    let target = repo_key_target(info).unwrap();

    let result = set_repo_value_in_doc(&mut doc, info, target, "false", false);
    assert!(result.is_err(), "false should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("no effect"),
        "error should mention no effect"
    );
}

#[test]
fn set_repo_value_propose_allow_array() {
    use cplt::config::{lookup_key, repo_key_target, set_repo_value_in_doc};

    let mut doc = toml_edit::DocumentMut::new();
    let info = lookup_key("allow.read").unwrap();
    let target = repo_key_target(info).unwrap();

    set_repo_value_in_doc(&mut doc, info, target, "~/.gradle", false).unwrap();
    set_repo_value_in_doc(&mut doc, info, target, "~/.m2", false).unwrap();
    // Duplicate should be idempotent
    set_repo_value_in_doc(&mut doc, info, target, "~/.gradle", false).unwrap();

    let output = doc.to_string();
    assert!(
        output.contains("[propose.allow]"),
        "needs section: {output}"
    );
    assert_eq!(
        output.matches("~/.gradle").count(),
        1,
        "no duplicates: {output}"
    );
    assert!(output.contains("~/.m2"), "second value: {output}");
}

#[test]
fn set_repo_value_propose_port_array() {
    use cplt::config::{lookup_key, repo_key_target, set_repo_value_in_doc};

    let mut doc = toml_edit::DocumentMut::new();
    let info = lookup_key("allow.ports").unwrap();
    let target = repo_key_target(info).unwrap();

    set_repo_value_in_doc(&mut doc, info, target, "8080", false).unwrap();
    set_repo_value_in_doc(&mut doc, info, target, "9090", false).unwrap();

    let output = doc.to_string();
    assert!(output.contains("8080"), "should have 8080: {output}");
    assert!(output.contains("9090"), "should have 9090: {output}");
}

#[test]
fn set_repo_value_deny_paths() {
    use cplt::config::{lookup_key, repo_key_target, set_repo_value_in_doc};

    let mut doc = toml_edit::DocumentMut::new();
    let info = lookup_key("deny.paths").unwrap();
    let target = repo_key_target(info).unwrap();

    set_repo_value_in_doc(&mut doc, info, target, "~/secrets", false).unwrap();

    let output = doc.to_string();
    assert!(output.contains("[deny]"), "needs [deny]: {output}");
    assert!(output.contains("\"~/secrets\""), "needs path: {output}");
}

#[test]
fn set_repo_value_unset_removes_bool() {
    use cplt::config::{lookup_key, repo_key_target, set_repo_value_in_doc};

    let mut doc = toml_edit::DocumentMut::new();
    let info = lookup_key("sandbox.allow_jvm_attach").unwrap();
    let target = repo_key_target(info).unwrap();

    // Set then unset
    set_repo_value_in_doc(&mut doc, info, target, "true", false).unwrap();
    set_repo_value_in_doc(&mut doc, info, target, "", true).unwrap();

    let output = doc.to_string();
    assert!(
        !output.contains("allow_jvm_attach"),
        "key should be gone: {output}"
    );
}

#[test]
fn set_repo_value_unset_removes_array_element() {
    use cplt::config::{lookup_key, repo_key_target, set_repo_value_in_doc};

    let mut doc = toml_edit::DocumentMut::new();
    let info = lookup_key("allow.read").unwrap();
    let target = repo_key_target(info).unwrap();

    set_repo_value_in_doc(&mut doc, info, target, "~/.gradle", false).unwrap();
    set_repo_value_in_doc(&mut doc, info, target, "~/.m2", false).unwrap();
    // Remove one element
    set_repo_value_in_doc(&mut doc, info, target, "~/.gradle", true).unwrap();

    let output = doc.to_string();
    assert!(!output.contains("~/.gradle"), "removed: {output}");
    assert!(output.contains("~/.m2"), "kept: {output}");
}

// ============================================================
// Chromium runtime rules (allow_cache_exec = ["ms-playwright"] or subpath)
// ============================================================

#[test]
fn chromium_runtime_rules_emitted_for_ms_playwright() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &["ms-playwright".to_string()],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow syscall*)"),
        "syscall* required for Chromium Mach traps"
    );
    assert!(
        p.contains("(allow system-socket (socket-domain AF_UNIX))"),
        "system-socket must be scoped to AF_UNIX for Chromium IPC"
    );
    assert!(
        p.contains("(allow iokit-open-user-client)"),
        "iokit-open-user-client required for GPU probing"
    );
    assert!(
        p.contains(r#"(allow mach-register (global-name-regex #"^org\.chromium\..+$"))"#),
        "mach-register must be anchored with ^...$ and scoped to org.chromium.*"
    );
    assert!(
        p.contains(r#"(regex #"^/private/var/folders/[^/]+/[^/]+/T/com\.google\.chrome\.for\.testing\.[^/]+/SingletonSocket$")"#),
        "SingletonSocket regex must use [^/]+/[^/]+ for var/folders segments and be fully anchored"
    );
}

#[test]
fn chromium_runtime_rules_emitted_for_ms_playwright_subpath() {
    // A user who pins a versioned subdirectory in allow_cache_exec should also
    // get the Chromium runtime rules — without them, Chrome segfaults even though
    // process-exec is allowed for the binary.
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &["ms-playwright/chromium-1217".to_string()],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains("(allow syscall*)"),
        "syscall* must be present for subpath entry"
    );
    assert!(
        p.contains("(allow system-socket (socket-domain AF_UNIX))"),
        "system-socket must be scoped to AF_UNIX for subpath entry"
    );
    assert!(
        p.contains(r#"(regex #"^/private/var/folders/[^/]+/[^/]+/T/com\.google\.chrome\.for\.testing\.[^/]+/SingletonSocket$")"#),
        "SingletonSocket regex must use [^/]+/[^/]+ for subpath entry"
    );
}

#[test]
fn chromium_runtime_rules_absent_by_default() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        !p.contains("(allow syscall*)"),
        "syscall* must not be emitted by default"
    );
    assert!(
        !p.contains("SingletonSocket"),
        "SingletonSocket rules must not be emitted by default"
    );
}

#[test]
fn chromium_runtime_rules_absent_for_unrelated_cache_exec() {
    // An unrelated allow_cache_exec entry must not trigger Chromium runtime rules.
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &["some-other-tool".to_string()],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        !p.contains("(allow syscall*)"),
        "syscall* must not be emitted for unrelated allow_cache_exec entry"
    );
    assert!(
        !p.contains("SingletonSocket"),
        "SingletonSocket rules must not be emitted for unrelated allow_cache_exec entry"
    );
}

#[test]
fn chromium_runtime_rules_absent_for_cache_exec_any_alone() {
    // allow_cache_exec_any grants broad process-exec but must NOT trigger the
    // Chromium-specific IPC/syscall rules without an explicit "ms-playwright" entry.
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: true,
        allow_browser: false,
    });
    assert!(
        !p.contains("(allow syscall*)"),
        "syscall* must not be emitted when only allow_cache_exec_any is set"
    );
    assert!(
        !p.contains("SingletonSocket"),
        "SingletonSocket rules must not be emitted when only allow_cache_exec_any is set"
    );
}

#[test]
fn chromium_runtime_rules_absent_for_near_miss_names() {
    // Near-miss entries that look similar to "ms-playwright" but differ in the
    // first path component must NOT trigger Chromium runtime rules. This guards
    // against future refactors that might loosen the check (e.g., contains() or
    // starts_with without the trailing slash).
    for name in &[
        "ms-playwright-evil",
        "ms-playwrightx",
        "MS-PLAYWRIGHT",
        "not-ms-playwright",
        "xms-playwright",
    ] {
        let p = generate_profile(&ProfileOptions {
            project_dir: std::path::Path::new("/projects/app"),
            home_dir: std::path::Path::new("/Users/test"),
            extra_read: &[],
            extra_write: &[],
            allow_socket: &[],
            extra_deny: &[],
            existing_home_tool_dirs: None,
            existing_app_dirs: None,
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            proxy_forced: false,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            java_home: None,
            git_hooks_path: None,
            git_common_dir: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
            allow_jvm_attach: false,
            allow_docker: false,
            electron_app_dir: None,
            agent: cplt::agent::Agent::Copilot,
            agent_dirs: &[],
            allow_cache_exec: &[name.to_string()],
            allow_cache_exec_any: false,
            allow_browser: false,
        });
        assert!(
            !p.contains("(allow syscall*)"),
            "syscall* must not be emitted for near-miss entry {name:?}"
        );
        assert!(
            !p.contains("SingletonSocket"),
            "SingletonSocket must not be emitted for near-miss entry {name:?}"
        );
    }
}

// ============================================================
// existing_app_dirs filtering — SBPL profile
// ============================================================

#[test]
fn existing_app_dirs_none_includes_all() {
    // Resolve a known mise app dir path at test time
    let data_path =
        cplt::sandbox::AppDirKind::Data.resolve("", "", "mise", std::path::Path::new("/home/test"));
    let Some(data_path) = data_path else {
        // No home dir in this environment — skip
        return;
    };
    let data_str = data_path.to_string_lossy().to_string();

    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/tmp/proj"),
        home_dir: std::path::Path::new("/home/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains(&data_str),
        "With existing_app_dirs=None, mise data dir path should appear in profile"
    );
}

#[test]
fn existing_app_dirs_matching_includes_dir() {
    let data_path =
        cplt::sandbox::AppDirKind::Data.resolve("", "", "mise", std::path::Path::new("/home/test"));
    let Some(data_path) = data_path else {
        return;
    };
    let data_str = data_path.to_string_lossy().to_string();

    let existing = vec![data_str.clone()];
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/tmp/proj"),
        home_dir: std::path::Path::new("/home/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: Some(&existing),
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains(&data_str),
        "With existing_app_dirs containing a matching path, mise data dir should appear in profile"
    );
}

#[test]
fn existing_app_dirs_nonmatching_excludes_dir() {
    // Resolve any mise path to confirm what we'd expect to see
    let data_path =
        cplt::sandbox::AppDirKind::Data.resolve("", "", "mise", std::path::Path::new("/home/test"));
    let Some(data_path) = data_path else {
        return;
    };
    let data_str = data_path.to_string_lossy().to_string();

    let existing = vec!["/nonexistent".to_string()];
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/tmp/proj"),
        home_dir: std::path::Path::new("/home/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: Some(&existing),
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        !p.contains(&data_str),
        "With existing_app_dirs containing only non-matching paths, mise data dir should NOT appear in profile"
    );
}

#[test]
fn existing_app_dirs_per_path_filtering() {
    // Resolve two distinct mise paths from different categories
    let data_path =
        cplt::sandbox::AppDirKind::Data.resolve("", "", "mise", std::path::Path::new("/home/test"));
    let config_path = cplt::sandbox::AppDirKind::Config.resolve(
        "",
        "",
        "mise",
        std::path::Path::new("/home/test"),
    );
    let (Some(data_path), Some(config_path)) = (data_path, config_path) else {
        return;
    };
    let data_str = data_path.to_string_lossy().to_string();
    let config_str = config_path.to_string_lossy().to_string();

    // Only the data dir is "existing" — config dir is absent
    let existing = vec![data_str.clone()];
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/tmp/proj"),
        home_dir: std::path::Path::new("/home/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: Some(&existing),
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        p.contains(&data_str),
        "mise data dir (present in existing_app_dirs) should appear in profile"
    );
    assert!(
        !p.contains(&config_str),
        "mise config dir (absent from existing_app_dirs) should NOT appear in profile — per-path filtering must work"
    );
}

#[test]
fn profile_opencode_config_dir_write_scoped_to_auth_json() {
    use cplt::agent::AgentDir;
    use std::path::PathBuf;

    let config_dir = PathBuf::from("/Users/test/.config/opencode");
    let data_dir = PathBuf::from("/Users/test/.local/share/opencode");
    let state_dir = PathBuf::from("/Users/test/.local/state/opencode");
    let cache_dir = PathBuf::from("/Users/test/.cache/opencode");

    let agent_dirs = vec![
        AgentDir {
            path: config_dir.clone(),
            write: false,
            map_exec: false,
            process_exec: false,
            write_files: vec!["auth.json"],
        },
        AgentDir {
            path: data_dir.clone(),
            write: true,
            map_exec: false,
            process_exec: false,
            write_files: vec![],
        },
        AgentDir {
            path: state_dir.clone(),
            write: true,
            map_exec: false,
            process_exec: false,
            write_files: vec![],
        },
        AgentDir {
            path: cache_dir.clone(),
            write: true,
            map_exec: false,
            process_exec: false,
            write_files: vec![],
        },
        AgentDir {
            path: cache_dir.join("bin"),
            write: false,
            map_exec: false,
            process_exec: true,
            write_files: vec![],
        },
    ];

    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::OpenCode,
        agent_dirs: &agent_dirs,
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });

    // Config dir should be readable but NOT writable at subpath level
    assert!(
        p.contains("(allow file-read* (subpath \"/Users/test/.config/opencode\"))"),
        "config dir should be readable"
    );
    assert!(
        !p.contains("(allow file-write* (subpath \"/Users/test/.config/opencode\"))"),
        "config dir should NOT have subpath write — only auth.json gets write"
    );

    // auth.json should have a literal file-write* rule
    assert!(
        p.contains("(allow file-write* (literal \"/Users/test/.config/opencode/auth.json\"))"),
        "auth.json should have literal write access"
    );

    // Data and state dirs should have full subpath write
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.local/share/opencode\"))"),
        "data dir should have subpath write"
    );
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.local/state/opencode\"))"),
        "state dir should have subpath write"
    );

    // Cache dir should be writable (for downloading tools)
    assert!(
        p.contains("(allow file-write* (subpath \"/Users/test/.cache/opencode\"))"),
        "cache dir should have subpath write"
    );

    // Cache/bin should allow exec for managed tool binaries
    assert!(
        p.contains("(allow process-exec (subpath \"/Users/test/.cache/opencode/bin\"))"),
        "cache/bin should allow process-exec"
    );
    // Cache/bin should NOT be writable (write+exec = persistence risk)
    assert!(
        p.contains("(deny file-write* (subpath \"/Users/test/.cache/opencode/bin\"))"),
        "cache/bin should deny writes (exec-only dir)"
    );
}

// ============================================================
// Clipboard deny policy (profile-generation tests)
// ============================================================

#[test]
fn deny_clipboard_emits_pasteboard_deny_after_allow() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: true,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    let allow = p
        .find("(allow mach-lookup)")
        .expect("blanket allow present");
    let deny = p
        .find("(deny mach-lookup")
        .expect("pasteboard deny present");
    assert!(
        deny > allow,
        "pasteboard deny must come AFTER the mach-lookup allow (last-match-wins)"
    );
    assert!(p.contains(r#"global-name-regex #"^com\.apple\.pasteboard(\.|$)""#));
}

#[test]
fn no_deny_clipboard_by_default() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        allow_socket: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        existing_app_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        proxy_forced: false,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        java_home: None,
        git_hooks_path: None,
        git_common_dir: None,
        allow_gpg_signing: false,
        deny_clipboard: false,
        allow_jvm_attach: false,
        allow_docker: false,
        electron_app_dir: None,
        agent: cplt::agent::Agent::Copilot,
        agent_dirs: &[],
        allow_cache_exec: &[],
        allow_cache_exec_any: false,
        allow_browser: false,
    });
    assert!(
        !p.contains("com.apple.pasteboard"),
        "pasteboard deny rule must not appear by default"
    );
}

// ── Config coverage tests ─────────────────────────────────────────────────────

/// Ensures every scalar key registered in CONFIG_KEYS appears in `config show`
/// output. If you add a new key to the registry, `display_config` must also
/// render it — otherwise this test fails.
///
/// Array-of-tables keys are excluded because they are structured differently in
/// the output (e.g. `[[git_guard.allow_push]]` entries are not rendered as
/// `key = value` lines by `display_config`).
#[test]
fn config_show_covers_all_registry_keys() {
    use cplt::config::{ConfigValueType, all_config_keys};

    // For each scalar key, verify lookup_key succeeds (registry is self-consistent)
    // and get_config_value returns a non-empty default.
    for key_info in all_config_keys() {
        if matches!(key_info.value_type, ConfigValueType::ArrayOfTables) {
            continue;
        }
        let dotted = format!("{}.{}", key_info.section, key_info.key);
        let result = cplt::config::lookup_key(&dotted);
        assert!(
            result.is_ok(),
            "registry key '{dotted}' cannot be looked up — lookup_key is broken"
        );
        let (_default_val, from_file) = cplt::config::get_config_value(result.unwrap(), None);
        assert!(
            !from_file,
            "registry key '{dotted}' reports from_file=true without a config file"
        );
    }
}

/// Ensures validate_accepts_all_valid_keys stays in sync with the registry.
/// Every non-array-of-tables key must appear in the TOML below — this forces
/// authors to update the test when adding a new key.
#[test]
fn registry_keys_match_validate_all_valid_keys_fixture() {
    use cplt::config::{ConfigValueType, all_config_keys};

    // Sections/keys intentionally excluded from the validation fixture
    // (repo-only keys, deprecated keys, or array-of-tables):
    let excluded = &[
        "deny.env",         // repo-local only
        "sandbox.gh_proxy", // deprecated
    ];

    let toml = r#"
[proxy]
enabled = false
forced = false
port = 18080
upstream = "http://corp-proxy.example.com:8080"
blocked_domains = "file.txt"
allowed_domains = "file.txt"
log_file = "log.txt"
log_level = "none"
timeout = 60
allow_private_domains = []

[allow]
read = []
write = []
socket = []
ports = []
localhost = []

[deny]
paths = []

[sandbox]
agent = "copilot"
validate = true
allow_env_files = false
allow_localhost_any = false
pass_env = []
inherit_env = false
allow_lifecycle_scripts = false
allow_gpg_signing = false
allow_tmp_exec = false
scratch_dir = false
use_bubblewrap = false
quiet = false
yes = false
allow_jvm_attach = false
allow_docker = false
allow_cache_exec = []
allow_cache_exec_any = false
allow_browser = false
git_push_prevention = false

[gh_guard]
enabled = false
mode = "warn"
scope_check = true
block_auth_token = true
inject_token = false
unknown_command = "warn"
allow_api_write = false

[git_guard]
enabled = false
mode = "warn"
prevent_push = true
prevent_force_push = true
protect_default_branch_only = false

[audit]
enabled = false
destination = "stderr"
level = "blocked"
format = "text"
"#;

    // Parse the fixture so coverage is checked per-section, not by a bare
    // substring. A plain `"{key} ="` grep matches ANYWHERE in the fixture, so
    // keys that recur across sections (e.g. `enabled`, `mode`, `port`) let a
    // key missing from ITS OWN section pass because a same-named key exists
    // under a different section. Parsing forces each registry `section.key` to
    // actually appear under `[section]`.
    let parsed: toml::Value = toml::from_str(toml).expect("fixture TOML must parse");

    for key_info in all_config_keys() {
        if matches!(key_info.value_type, ConfigValueType::ArrayOfTables) {
            continue;
        }
        let dotted = format!("{}.{}", key_info.section, key_info.key);
        if excluded.contains(&dotted.as_str()) {
            continue;
        }
        // #126 Tier 2 / #129: require `key` under its OWN `[section]` table, not
        // merely somewhere in the fixture. This makes the guard force the
        // fixture to cover every distinct section.key pair.
        let covered = parsed
            .get(key_info.section)
            .and_then(|section| section.get(key_info.key))
            .is_some();
        assert!(
            covered,
            "registry key '{dotted}' is not covered under its own [{}] section in \
             the fixture TOML in \
             `registry_keys_match_validate_all_valid_keys_fixture` — add it",
            key_info.section
        );
    }
}

// ============================================================
// Tool-path env var overrides (GOPATH, CARGO_HOME, NODE_PATH, ...)
// ============================================================

fn env_pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn tool_path_gopath_custom_yields_writable_rule() {
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("GOPATH", "/custom/gopath")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert_eq!(overrides.len(), 1, "GOPATH override should be emitted");
    assert_eq!(
        overrides[0].path,
        std::path::PathBuf::from("/custom/gopath")
    );
    assert!(overrides[0].write, "GOPATH is a build cache → read+write");
}

#[test]
fn tool_path_node_path_yields_read_only_rule() {
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("NODE_PATH", "/custom/node_modules")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert_eq!(overrides.len(), 1);
    assert_eq!(
        overrides[0].path,
        std::path::PathBuf::from("/custom/node_modules")
    );
    assert!(
        !overrides[0].write,
        "NODE_PATH is a lookup path → read-only"
    );
}

#[test]
fn tool_path_unset_env_vars_add_nothing() {
    let home = std::path::Path::new("/home/tester");
    let env: Vec<(String, String)> = Vec::new();
    let overrides = tool_path_env_overrides(&env, home);
    assert!(
        overrides.is_empty(),
        "no tool-path env vars set → no overrides"
    );
}

#[test]
fn tool_path_empty_value_adds_nothing() {
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("GOPATH", "")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert!(overrides.is_empty(), "empty value → treated as unset");
}

#[test]
fn tool_path_default_value_not_double_added() {
    // GOPATH pointing at the default ~/go is already covered by HOME_TOOL_DIRS
    // (go/bin, go/pkg), so it must not produce an extra override.
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("GOPATH", "/home/tester/go")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert!(
        overrides.is_empty(),
        "default GOPATH must not be double-added, got: {overrides:?}"
    );
}

#[test]
fn tool_path_default_value_via_tilde_not_double_added() {
    // The tilde form of the default must also resolve to ~/go and be skipped.
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("CARGO_HOME", "~/.cargo")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert!(
        overrides.is_empty(),
        "default CARGO_HOME (~/.cargo) must not be double-added, got: {overrides:?}"
    );
}

#[test]
fn tool_path_tilde_is_expanded_to_home() {
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("CARGO_HOME", "~/alt-cargo")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert_eq!(overrides.len(), 1);
    assert_eq!(
        overrides[0].path,
        std::path::PathBuf::from("/home/tester/alt-cargo")
    );
    assert!(overrides[0].write);
}

#[test]
fn tool_path_multiple_vars_mapped_by_access() {
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[
        ("GOPATH", "/custom/gopath"),
        ("CARGO_HOME", "/custom/cargo"),
        ("NODE_PATH", "/custom/lookup"),
        ("PIP_CACHE_DIR", "/custom/pip"),
    ]);
    let overrides = tool_path_env_overrides(&env, home);
    let write: Vec<&std::path::Path> = overrides
        .iter()
        .filter(|o| o.write)
        .map(|o| o.path.as_path())
        .collect();
    let read: Vec<&std::path::Path> = overrides
        .iter()
        .filter(|o| !o.write)
        .map(|o| o.path.as_path())
        .collect();
    assert!(write.contains(&std::path::Path::new("/custom/gopath")));
    assert!(write.contains(&std::path::Path::new("/custom/cargo")));
    assert!(write.contains(&std::path::Path::new("/custom/pip")));
    assert_eq!(read, vec![std::path::Path::new("/custom/lookup")]);
}

#[test]
fn tool_path_same_path_write_wins_over_read() {
    // If a read-only var and a write var resolve to the same custom path,
    // the write grant must win (deduped to a single writable override).
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("NODE_PATH", "/shared/dir"), ("GOPATH", "/shared/dir")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert_eq!(overrides.len(), 1, "same path must be deduplicated");
    assert_eq!(overrides[0].path, std::path::PathBuf::from("/shared/dir"));
    assert!(overrides[0].write, "write grant wins over read");
}

// --- List-valued tool-path env vars (colon-separated on Unix) ---------------
// GOPATH and NODE_PATH are OS path lists (`GOPATH=/a:/b`); each segment must
// become its own override. Single-path vars are never split.

#[test]
fn tool_path_gopath_list_yields_one_override_per_segment() {
    // GOPATH=/a:/b → two writable overrides, one per directory in the list.
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("GOPATH", "/a:/b")]);
    let overrides = tool_path_env_overrides(&env, home);
    let paths: Vec<&std::path::Path> = overrides.iter().map(|o| o.path.as_path()).collect();
    assert_eq!(overrides.len(), 2, "each GOPATH segment → its own override");
    assert!(paths.contains(&std::path::Path::new("/a")));
    assert!(paths.contains(&std::path::Path::new("/b")));
    assert!(
        overrides.iter().all(|o| o.write),
        "GOPATH segments are build roots → read+write"
    );
}

#[test]
fn tool_path_node_path_list_yields_read_only_per_segment() {
    // NODE_PATH=/x:/y → two read-only overrides, one per lookup directory.
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("NODE_PATH", "/x:/y")]);
    let overrides = tool_path_env_overrides(&env, home);
    let paths: Vec<&std::path::Path> = overrides.iter().map(|o| o.path.as_path()).collect();
    assert_eq!(
        overrides.len(),
        2,
        "each NODE_PATH segment → its own override"
    );
    assert!(paths.contains(&std::path::Path::new("/x")));
    assert!(paths.contains(&std::path::Path::new("/y")));
    assert!(
        overrides.iter().all(|o| !o.write),
        "NODE_PATH segments are lookup paths → read-only"
    );
}

#[test]
fn tool_path_list_empty_segments_are_ignored() {
    // Doubled (`/a::/b`) and trailing (`/b:`) separators produce empty segments
    // that must be skipped rather than resolving to HOME (join of an empty path).
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("GOPATH", "/a::/b:")]);
    let overrides = tool_path_env_overrides(&env, home);
    let paths: Vec<&std::path::Path> = overrides.iter().map(|o| o.path.as_path()).collect();
    assert_eq!(
        overrides.len(),
        2,
        "empty segments must be skipped, got: {overrides:?}"
    );
    assert!(paths.contains(&std::path::Path::new("/a")));
    assert!(paths.contains(&std::path::Path::new("/b")));
    assert!(
        !paths.contains(&home),
        "an empty segment must NOT resolve to HOME"
    );
}

#[test]
fn tool_path_single_path_var_with_colon_is_not_split() {
    // A single-path var (CARGO_HOME) is never split, so a `:` in a weird-but-real
    // directory name is preserved verbatim as one path.
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("CARGO_HOME", "/weird:dir/cargo")]);
    let overrides = tool_path_env_overrides(&env, home);
    assert_eq!(overrides.len(), 1, "single-path var must not be split");
    assert_eq!(
        overrides[0].path,
        std::path::PathBuf::from("/weird:dir/cargo")
    );
    assert!(overrides[0].write);
}

#[test]
fn tool_path_list_per_segment_safety_guard_drops_unsafe_segment() {
    // GOPATH=/custom:/ → the list splits into /custom and /. tool_path_env_overrides
    // emits both; the per-segment safety guard keeps /custom and drops the root.
    let home = std::path::Path::new("/home/tester");
    let env = env_pairs(&[("GOPATH", "/custom:/")]);
    let overrides = tool_path_env_overrides(&env, home);
    let kept: Vec<&std::path::Path> = overrides
        .iter()
        .map(|o| o.path.as_path())
        .filter(|p| tool_override_path_is_safe(p, home))
        .collect();
    assert_eq!(
        kept,
        vec![std::path::Path::new("/custom")],
        "only the safe segment survives the per-segment guard"
    );
    assert!(
        !tool_override_path_is_safe(std::path::Path::new("/"), home),
        "the `/` segment must be dropped by the guard"
    );
}

// --- Safety guard: reject over-broad tool-path overrides -------------------
// tool_override_path_is_safe() is the choke point that stops an ambient env var
// (e.g. GOPATH=$HOME or GOPATH=/) from silently widening the sandbox. It runs on
// the already-canonicalized path, so `..` has been collapsed by then.

#[test]
fn tool_override_home_dir_is_dropped() {
    // GOPATH=$HOME → granting write to the entire home dir defeats the sandbox.
    let home = std::path::Path::new("/home/tester");
    assert!(
        !tool_override_path_is_safe(home, home),
        "an override resolving to HOME itself must be dropped"
    );
}

#[test]
fn tool_override_filesystem_root_is_dropped() {
    // GOPATH=/ → granting the whole filesystem must be dropped.
    let home = std::path::Path::new("/home/tester");
    assert!(
        !tool_override_path_is_safe(std::path::Path::new("/"), home),
        "an override resolving to / must be dropped"
    );
}

#[test]
fn tool_override_home_ancestor_is_dropped() {
    // A relative value like GOPATH=../../.. canonicalizes to an ancestor of HOME
    // (e.g. /home or /). Any ancestor of HOME is an over-grant and must be
    // dropped — this holds cross-platform (is_unsafe_root does not list /home on
    // macOS, so the HOME-ancestor check is what catches it there).
    let home = std::path::Path::new("/home/tester");
    for ancestor in ["/home", "/"] {
        assert!(
            !tool_override_path_is_safe(std::path::Path::new(ancestor), home),
            "ancestor of HOME ({ancestor}) must be dropped"
        );
    }
}

#[test]
fn tool_override_escaped_path_to_unsafe_root_is_dropped() {
    // GOPATH=../../../../etc canonicalizes to /etc — resolve_tool_path's
    // join-to-HOME does NOT contain it once `..` collapses. The guard catches the
    // effective (canonicalized) grant. /tmp is an unsafe root everywhere; /etc is
    // one on Linux.
    let home = std::path::Path::new("/home/tester");
    assert!(
        !tool_override_path_is_safe(std::path::Path::new("/tmp"), home),
        "an override resolving to /tmp must be dropped"
    );
    #[cfg(target_os = "linux")]
    assert!(
        !tool_override_path_is_safe(std::path::Path::new("/etc"), home),
        "an override escaping HOME to a system root must be dropped"
    );
}

#[test]
fn tool_override_normal_custom_dir_is_kept() {
    // The feature must still work: a real custom tool dir that is neither a root
    // nor HOME/an ancestor stays granted — both outside and inside HOME.
    let home = std::path::Path::new("/home/tester");
    assert!(
        tool_override_path_is_safe(std::path::Path::new("/opt/custom-gopath"), home),
        "a normal custom dir outside HOME must be granted"
    );
    assert!(
        tool_override_path_is_safe(std::path::Path::new("/home/tester/go-alt"), home),
        "a normal custom SUBdir of HOME must be granted"
    );
}
