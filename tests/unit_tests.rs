//! Unit tests for sandbox profile generation, domain blocking, and IP checks.
//!
//! These tests verify core logic without invoking sandbox-exec,
//! so they run on any platform (Linux CI, macOS, etc.).

use cplt::discover::copilot_pkg_dir;
use cplt::is_unsafe_root;
use cplt::proxy::{is_blocked_in_content, is_domain_match, is_private_hostname, is_private_ip};
use cplt::sandbox::{
    HardeningCategory, ProfileOptions, build_sandbox_env, generate_profile, validate_sbpl_path,
};

// ============================================================
// Unsafe root detection
// ============================================================

#[test]
fn rejects_filesystem_root() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/"), home));
}

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

#[test]
fn rejects_private_var() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/private/var"), home));
}

#[test]
fn rejects_applications() {
    let home = std::path::Path::new("/Users/testuser");
    assert!(is_unsafe_root(std::path::Path::new("/Applications"), home));
}

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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
    });
    assert!(
        p.contains("(allow file-ioctl)"),
        "Profile must allow file-ioctl for terminal raw mode"
    );
}

#[test]
fn profile_grants_project_access() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
    });
    assert!(p.contains("(allow file-read* (subpath \"/Users/test/.copilot\"))"));
}

#[test]
fn profile_denies_sensitive_dirs() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
    });
    for file in &[
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".gem/credentials",
        ".vault-token",
    ] {
        assert!(
            p.contains(&format!(
                "(deny file-read* (literal \"/Users/test/{file}\"))"
            )),
            "should deny read to {file}"
        );
    }
}

#[test]
fn profile_restricts_outbound_tcp() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
}

#[test]
fn profile_extra_ports_adds_allows() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[8080, 3000],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
fn profile_proxy_port_allows_localhost() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: Some(18080),
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[3000, 8080],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
    });
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.env$"))"#),
        "should deny .env files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.env\..*"))"#),
        "should deny .env.* files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.pem$"))"#),
        "should deny .pem files: {p}"
    );
    assert!(
        p.contains(r#"(deny file-read* (regex #"/\.key$"))"#),
        "should deny .key files: {p}"
    );
}

#[test]
fn profile_allows_env_files_when_flag_set() {
    let p = generate_profile(&ProfileOptions {
        project_dir: std::path::Path::new("/projects/app"),
        home_dir: std::path::Path::new("/Users/test"),
        extra_read: &[],
        extra_write: &[],
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: true,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
    });
    let project_allow = p
        .find("(allow file-read* (subpath \"/projects/app\"))")
        .unwrap();
    let env_deny = p.find(r#"(deny file-read* (regex #"/\.env$"))"#).unwrap();
    assert!(
        env_deny > project_allow,
        "env deny must come AFTER project allow for SBPL last-match-wins"
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: true,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
    });
    assert!(
        !p.contains("(deny network-outbound (remote ip \"localhost:*\"))"),
        "Profile must NOT deny localhost when allow_localhost_any is set"
    );
    assert!(
        p.contains("(allow network-outbound (remote ip \"localhost:*\"))"),
        "Profile must explicitly ALLOW all localhost when allow_localhost_any is set"
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        ".local", ".mise", ".nvm", ".pyenv", ".cargo", ".rustup", ".sdkman", "go/bin",
    ] {
        assert!(
            paths.contains(expected),
            "HOME_TOOL_DIRS missing {expected}"
        );
    }

    // Dependency stores: map_exec only
    for expected in &[".gradle", ".m2", ".konan", "go/pkg"] {
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

    // Prefixes
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"LC_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"COPILOT_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"MISE_"));
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

    // Prefixes
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"PYENV_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"YARN_"));
    assert!(ENV_PREFIX_ALLOWLIST.contains(&"COREPACK_"));
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        p.contains("(allow process-exec (subpath \"/Users/test/.cargo\"))"),
        ".cargo should have process-exec for cargo, rustc, etc."
    );
    assert!(
        p.contains("(allow file-map-executable (subpath \"/Users/test/.cargo\"))"),
        ".cargo should have file-map-executable for native libs"
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
    let env = build_sandbox_env(&parent, &[], false, &[], None);

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
}

#[test]
fn env_sanitized_lifecycle_opt_out_skips_npm_yarn() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let disabled = vec![HardeningCategory::LifecycleScripts];
    let env = build_sandbox_env(&parent, &[], false, &disabled, None);

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
    let env = build_sandbox_env(&parent, &[], true, &[], None);

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
    let env = build_sandbox_env(&parent, &extra, false, &[], None);

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
    let env = build_sandbox_env(&parent, &extra, true, &[], None);

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
    let env = build_sandbox_env(&parent, &[], false, &[], None);

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
    let env = build_sandbox_env(&parent, &[], false, &[], None);

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
    let env = build_sandbox_env(&parent, &[], false, &[], None);

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
    let env = build_sandbox_env(&parent, &[], false, &[], None);

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
    let env = build_sandbox_env(&parent, &[], false, &[], None);

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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: Some(scratch),
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: true,
        copilot_install_dir: None,
        git_hooks_path: None,
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: Some(std::path::Path::new(
            "/Users/test/n/lib/node_modules/@github/copilot",
        )),
        git_hooks_path: None,
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
fn profile_no_copilot_install_dir_omits_section() {
    let p = default_profile();
    assert!(
        !p.contains("Copilot CLI installation directory"),
        "Default profile should not have copilot install dir section"
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
        extra_deny: &[],
        existing_home_tool_dirs: None,
        extra_ports: &[],
        localhost_ports: &[],
        proxy_port: None,
        allow_env_files: false,
        allow_localhost_any: false,
        scratch_dir: None,
        allow_tmp_exec: false,
        copilot_install_dir: None,
        git_hooks_path: Some(std::path::Path::new("/Users/test/.config/git/hooks")),
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
// git signing hardening — GIT_CONFIG env vars disable signing
// ============================================================

#[test]
fn env_git_signing_disabled_by_default() {
    let parent = make_env(&[("HOME", "/Users/test"), ("PATH", "/usr/bin")]);
    let env = build_sandbox_env(&parent, &[], false, &[], None);
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
    let env = build_sandbox_env(&parent, &[], false, &[], Some(scratch));

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
}

#[test]
fn env_scratch_dir_no_duplicate_tmpdir() {
    let parent = make_env(&[("HOME", "/Users/test"), ("TMPDIR", "/old/tmp")]);
    let scratch = std::path::Path::new("/new/scratch");
    let env = build_sandbox_env(&parent, &[], false, &[], Some(scratch));

    let tmpdir_count = env.vars.iter().filter(|(k, _)| k == "TMPDIR").count();
    assert_eq!(tmpdir_count, 1, "TMPDIR should appear exactly once");
}

#[test]
fn env_scratch_dir_respects_pass_env_override() {
    let parent = make_env(&[("HOME", "/Users/test"), ("TMPDIR", "/custom/tmp")]);
    let extra = vec!["TMPDIR".to_string()];
    let scratch = std::path::Path::new("/scratch/dir");
    let env = build_sandbox_env(&parent, &extra, false, &[], Some(scratch));

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
    let env = build_sandbox_env(&parent, &[], false, &[], None);

    let tmpdir = env.vars.iter().find(|(k, _)| k == "TMPDIR");
    assert!(tmpdir.is_some());
    assert_eq!(
        tmpdir.unwrap().1,
        "/private/var/folders/xx",
        "without scratch dir, system TMPDIR should pass through"
    );
}

// ============================================================
// Config parsing — new options
// ============================================================

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
    let diagnostics = validate_config("[proxy]\nenabled = true\ntimeout = 30\n");
    assert!(
        diagnostics
            .iter()
            .any(|d| { d.level == DiagnosticLevel::Error && d.message.contains("timeout") })
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
allow_tmp_exec = false
scratch_dir = false
quiet = false
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
