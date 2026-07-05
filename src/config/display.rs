//! Human-readable config display and `cplt config explain`.

use super::path::config_path;
use super::registry::{ConfigKeyInfo, type_label};
use super::types::LoadedConfig;
use crate::ui;

/// Print explanation of a single config key, showing type and current value inline.
pub fn explain_key(key_info: &ConfigKeyInfo, loaded: Option<&LoadedConfig>) {
    let blue = ui::stdout_color(ui::BLUE);
    let bold = ui::stdout_color(ui::BOLD);
    let dim = ui::stdout_color(ui::DIM);
    let yellow = ui::stdout_color(ui::YELLOW);
    let nc = ui::stdout_color(ui::RESET);

    let default_display = if key_info.default_display.is_empty() {
        "(unset)"
    } else {
        key_info.default_display
    };

    let (current_value, from_file) = get_config_value(key_info, loaded);
    let type_str = type_label(key_info.value_type);

    println!("{bold}{}.{}{nc}", key_info.section, key_info.key);
    println!("  {}", key_info.description);

    // Type and value on one line: "  bool  false" or "  bool  true  (default: false)"
    if from_file {
        // Highlight dangerous keys set to true in yellow so the risk is visible.
        let value_color = if key_info.dangerous && current_value == "true" {
            yellow
        } else {
            bold
        };
        println!(
            "  {dim}{type_str}{nc}  {value_color}{current_value}{nc}  {dim}(default: {default_display}){nc}"
        );
    } else {
        println!("  {dim}{type_str}  {current_value}{nc}");
    }

    if key_info.dangerous {
        println!("  {yellow}Requires --force to enable{nc}");
    }
    println!(
        "  {blue}Set:{nc}  cplt config set {}.{} <value>",
        key_info.section, key_info.key
    );
}

/// Print explanation of all config keys, grouped by section.
/// Shows the effective value inline: dim for default, bold for config-file override.
pub fn explain_all(loaded: Option<&LoadedConfig>) {
    use super::registry::CONFIG_KEYS;

    let blue = ui::stdout_color(ui::BLUE);
    let bold = ui::stdout_color(ui::BOLD);
    let dim = ui::stdout_color(ui::DIM);
    let yellow = ui::stdout_color(ui::YELLOW);
    let nc = ui::stdout_color(ui::RESET);

    let mut current_section = "";
    for key in CONFIG_KEYS {
        if key.section != current_section {
            if !current_section.is_empty() {
                println!();
            }
            println!("{blue}[{bold}{}{nc}{blue}]{nc}", key.section);
            current_section = key.section;
        }
        let danger = if key.dangerous {
            format!(" {yellow}⚠{nc}")
        } else {
            String::new()
        };
        let (current_value, from_file) = get_config_value(key, loaded);
        // Dim for default value, bold for override; yellow if dangerous key is enabled.
        let value_color = if !from_file {
            dim
        } else if key.dangerous && current_value == "true" {
            yellow
        } else {
            bold
        };
        let display_value = if current_value.is_empty() {
            "(unset)".to_string()
        } else {
            current_value
        };
        println!(
            "  {bold}{:<25}{nc} {dim}{:<20}{nc} {value_color}{:<14}{nc} {}{danger}",
            format!("{}.{}", key.section, key.key),
            format!("({})", type_label(key.value_type)),
            display_value,
            key.description.trim_start_matches("⚠️  DANGEROUS: "),
        );
    }
}

/// Get the effective value of a config key.
/// Returns `(value_string, is_from_file)`.
#[allow(clippy::collapsible_if)]
pub fn get_config_value(key_info: &ConfigKeyInfo, loaded: Option<&LoadedConfig>) -> (String, bool) {
    if let Some(loaded) = loaded {
        if let Ok(root) = loaded.raw.parse::<toml::Table>() {
            if let Some(section) = root.get(key_info.section) {
                if let Some(val) = section.get(key_info.key) {
                    return (format_toml_value(val), true);
                }
            }
        }
    }

    (key_info.default_display.to_string(), false)
}

fn format_toml_value(val: &toml::Value) -> String {
    match val {
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::String(s) => s.clone(),
        toml::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_toml_value).collect();
            format!("[{}]", items.join(", "))
        }
        other => other.to_string(),
    }
}

// ── Config display (effective config) ────────────────────────────────

/// Display the effective configuration from a config file merged with defaults.
/// Shows what cplt would use at runtime (without CLI flag overrides).
pub fn display_config(loaded: Option<&LoadedConfig>) {
    let blue = ui::stdout_color(ui::BLUE);
    let dim = ui::stdout_color(ui::DIM);
    let green = ui::stdout_color(ui::GREEN);
    let yellow = ui::stdout_color(ui::YELLOW);
    let nc = ui::stdout_color(ui::RESET);

    let config = loaded.map(|l| &l.config);
    let c = config.cloned().unwrap_or_default();

    // Source label helper
    let src =
        |has_file_value: bool| -> &'static str { if has_file_value { "" } else { " (default)" } };

    println!("{blue}[cplt]{nc} ── Effective Configuration ──────────────────────");
    println!();

    // Config file path
    if let Some(l) = loaded {
        println!("{blue}[cplt]{nc}  {dim}File:{nc}  {}", l.path.display());
    } else if let Some(p) = config_path() {
        println!(
            "{blue}[cplt]{nc}  {dim}File:{nc}  {dim}(not found: {}){nc}",
            p.display()
        );
    } else {
        println!("{blue}[cplt]{nc}  {dim}File:{nc}  {dim}(no config path — $HOME not set){nc}");
    }
    println!();

    // [proxy]
    println!("{blue}[cplt]{nc}  {dim}[proxy]{nc}");
    let proxy_enabled = c.proxy.enabled.unwrap_or(true);
    println!(
        "{blue}[cplt]{nc}    enabled          = {}{}{nc}{}",
        if proxy_enabled { green } else { yellow },
        proxy_enabled,
        src(c.proxy.enabled.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    port             = {}{}",
        c.proxy.port.unwrap_or(0),
        src(c.proxy.port.is_some())
    );
    if let Some(ref bd) = c.proxy.blocked_domains {
        println!("{blue}[cplt]{nc}    blocked_domains  = \"{bd}\"");
    }
    if let Some(ref ad) = c.proxy.allowed_domains {
        println!("{blue}[cplt]{nc}    allowed_domains  = \"{ad}\"");
    }
    if let Some(ref lf) = c.proxy.log_file {
        println!("{blue}[cplt]{nc}    log_file         = \"{lf}\"");
    }
    println!(
        "{blue}[cplt]{nc}    log_level        = \"{}\"{}",
        c.proxy.log_level.as_deref().unwrap_or("none"),
        src(c.proxy.log_level.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    timeout          = {}{}",
        c.proxy.timeout.unwrap_or(60),
        src(c.proxy.timeout.is_some())
    );
    println!();

    // [allow]
    println!("{blue}[cplt]{nc}  {dim}[allow]{nc}");
    if c.allow.read.is_empty() {
        println!("{blue}[cplt]{nc}    read             = {dim}[]{nc}");
    } else {
        println!("{blue}[cplt]{nc}    read             = {:?}", c.allow.read);
    }
    if c.allow.write.is_empty() {
        println!("{blue}[cplt]{nc}    write            = {dim}[]{nc}");
    } else {
        println!(
            "{blue}[cplt]{nc}    write            = {yellow}{:?}{nc}",
            c.allow.write
        );
    }
    if c.allow.ports.is_empty() {
        println!("{blue}[cplt]{nc}    ports            = {dim}[]{nc}");
    } else {
        println!("{blue}[cplt]{nc}    ports            = {:?}", c.allow.ports);
    }
    if c.allow.localhost.is_empty() {
        println!("{blue}[cplt]{nc}    localhost         = {dim}[]{nc}");
    } else {
        println!(
            "{blue}[cplt]{nc}    localhost         = {:?}",
            c.allow.localhost
        );
    }
    println!();

    // [deny]
    println!("{blue}[cplt]{nc}  {dim}[deny]{nc}");
    if c.deny.paths.is_empty() {
        println!("{blue}[cplt]{nc}    paths            = {dim}[]{nc}");
    } else {
        println!("{blue}[cplt]{nc}    paths            = {:?}", c.deny.paths);
    }
    println!();

    // [sandbox]
    println!("{blue}[cplt]{nc}  {dim}[sandbox]{nc}");
    let validate = c.sandbox.validate.unwrap_or(true);
    println!(
        "{blue}[cplt]{nc}    validate              = {}{}",
        validate,
        src(c.sandbox.validate.is_some())
    );
    let allow_env_files = c.sandbox.allow_env_files.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_env_files       = {}{}",
        allow_env_files,
        src(c.sandbox.allow_env_files.is_some())
    );
    let allow_localhost_any = c.sandbox.allow_localhost_any.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_localhost_any    = {}{}",
        allow_localhost_any,
        src(c.sandbox.allow_localhost_any.is_some())
    );
    if !c.sandbox.pass_env.is_empty() {
        println!(
            "{blue}[cplt]{nc}    pass_env              = {:?}",
            c.sandbox.pass_env
        );
    }
    let inherit_env = c.sandbox.inherit_env.unwrap_or(false);
    if inherit_env {
        let red = ui::stdout_color(ui::RED);
        println!("{blue}[cplt]{nc}    inherit_env           = {red}true{nc} ⚠ DANGEROUS");
    } else {
        println!(
            "{blue}[cplt]{nc}    inherit_env           = false{}",
            src(c.sandbox.inherit_env.is_some())
        );
    }
    let allow_lifecycle = c.sandbox.allow_lifecycle_scripts.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_lifecycle_scripts = {}{}",
        allow_lifecycle,
        src(c.sandbox.allow_lifecycle_scripts.is_some())
    );
    let allow_gpg = c.sandbox.allow_gpg_signing.unwrap_or(false);
    if allow_gpg {
        let red = ui::stdout_color(ui::RED);
        println!("{blue}[cplt]{nc}    allow_gpg_signing     = {red}true{nc} ⚠ DANGEROUS");
    } else {
        println!(
            "{blue}[cplt]{nc}    allow_gpg_signing     = false{}",
            src(c.sandbox.allow_gpg_signing.is_some())
        );
    }
    let allow_docker = c.sandbox.allow_docker.unwrap_or(false);
    if allow_docker {
        let red = ui::stdout_color(ui::RED);
        println!("{blue}[cplt]{nc}    allow_docker          = {red}true{nc} ⚠ DANGEROUS");
    } else {
        println!(
            "{blue}[cplt]{nc}    allow_docker          = false{}",
            src(c.sandbox.allow_docker.is_some())
        );
    }
    let allow_tmp = c.sandbox.allow_tmp_exec.unwrap_or(false);
    if allow_tmp {
        let red = ui::stdout_color(ui::RED);
        println!("{blue}[cplt]{nc}    allow_tmp_exec        = {red}true{nc} ⚠ DANGEROUS");
    } else {
        println!(
            "{blue}[cplt]{nc}    allow_tmp_exec        = false{}",
            src(c.sandbox.allow_tmp_exec.is_some())
        );
    }
    let allow_browser = c.sandbox.allow_browser.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_browser         = {}{}",
        allow_browser,
        src(c.sandbox.allow_browser.is_some())
    );
    let scratch = c.sandbox.scratch_dir.unwrap_or(true);
    println!(
        "{blue}[cplt]{nc}    scratch_dir           = {}{}",
        scratch,
        src(c.sandbox.scratch_dir.is_some())
    );
    match c.sandbox.use_bubblewrap {
        Some(v) => println!(
            "{blue}[cplt]{nc}    use_bubblewrap        = {v}{}",
            src(true)
        ),
        None => println!("{blue}[cplt]{nc}    use_bubblewrap        = auto-detect"),
    }
    let quiet = c.sandbox.quiet.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    quiet                 = {}{}",
        quiet,
        src(c.sandbox.quiet.is_some())
    );
    let gh_proxy_deprecated = c.sandbox.gh_proxy.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    gh_proxy              = {}{} {dim}(deprecated, use [gh_guard]){nc}",
        gh_proxy_deprecated,
        src(c.sandbox.gh_proxy.is_some())
    );
    let git_push_prevention = c.sandbox.git_push_prevention.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    git_push_prevention   = {}{} {dim}(deprecated, use [git_guard]){nc}",
        git_push_prevention,
        src(c.sandbox.git_push_prevention.is_some())
    );

    // [gh_guard] section
    println!("{blue}[cplt]{nc}");
    println!("{blue}[cplt]{nc}  [gh_guard]");
    println!(
        "{blue}[cplt]{nc}    enabled               = {}{}",
        c.gh_guard.enabled.unwrap_or(false),
        src(c.gh_guard.enabled.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    mode                  = {}{}",
        c.gh_guard.mode.unwrap_or_default(),
        src(c.gh_guard.mode.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    scope_check           = {}{}",
        c.gh_guard.scope_check.unwrap_or(true),
        src(c.gh_guard.scope_check.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    block_auth_token      = {}{}",
        c.gh_guard.block_auth_token.unwrap_or(true),
        src(c.gh_guard.block_auth_token.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    inject_token          = {}{}",
        c.gh_guard.inject_token.unwrap_or(false),
        src(c.gh_guard.inject_token.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    unknown_command       = {}{}",
        c.gh_guard.unknown_command.unwrap_or_default(),
        src(c.gh_guard.unknown_command.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    allow_api_write       = {}{}",
        c.gh_guard.allow_api_write.unwrap_or(false),
        src(c.gh_guard.allow_api_write.is_some())
    );

    // [git_guard] section
    println!("{blue}[cplt]{nc}");
    println!("{blue}[cplt]{nc}  [git_guard]");
    println!(
        "{blue}[cplt]{nc}    enabled               = {}{}",
        c.git_guard.enabled.unwrap_or(false),
        src(c.git_guard.enabled.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    mode                  = {}{}",
        c.git_guard.mode.unwrap_or_default(),
        src(c.git_guard.mode.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    prevent_push          = {}{}",
        c.git_guard.prevent_push.unwrap_or(true),
        src(c.git_guard.prevent_push.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    prevent_force_push    = {}{}",
        c.git_guard.prevent_force_push.unwrap_or(true),
        src(c.git_guard.prevent_force_push.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    protect_default_branch_only = {}{}",
        c.git_guard.protect_default_branch_only.unwrap_or(false),
        src(c.git_guard.protect_default_branch_only.is_some())
    );
    if !c.git_guard.allow_push.is_empty() {
        println!(
            "{blue}[cplt]{nc}    allow_push            = [{} rules]",
            c.git_guard.allow_push.len()
        );
    }

    // [audit] section
    println!("{blue}[cplt]{nc}");
    println!("{blue}[cplt]{nc}  [audit]");
    println!(
        "{blue}[cplt]{nc}    enabled               = {}{}",
        c.audit.enabled.unwrap_or(false),
        src(c.audit.enabled.is_some())
    );
    if let Some(ref dest) = c.audit.destination {
        println!("{blue}[cplt]{nc}    destination           = {dest}");
    }

    println!("{blue}[cplt]{nc} ──────────────────────────────────────────────────────");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn get_config_value_returns_default_when_no_file() {
        let info = crate::config::lookup_key("sandbox.quiet").unwrap();
        let (val, from_file) = get_config_value(info, None);
        assert_eq!(val, "false");
        assert!(!from_file);
    }

    #[test]
    fn get_config_value_returns_file_value() {
        let info = crate::config::lookup_key("sandbox.quiet").unwrap();
        let loaded = LoadedConfig {
            config: Config::parse("[sandbox]\nquiet = true\n").unwrap(),
            raw: "[sandbox]\nquiet = true\n".to_string(),
            path: std::path::PathBuf::from("/tmp/fake"),
        };
        let (val, from_file) = get_config_value(info, Some(&loaded));
        assert_eq!(val, "true");
        assert!(from_file);
    }

    #[test]
    fn get_config_value_returns_array_from_file() {
        let info = crate::config::lookup_key("allow.ports").unwrap();
        let raw = "[allow]\nports = [8080, 9090]\n";
        let loaded = LoadedConfig {
            config: Config::parse(raw).unwrap(),
            raw: raw.to_string(),
            path: std::path::PathBuf::from("/tmp/fake"),
        };
        let (val, from_file) = get_config_value(info, Some(&loaded));
        assert!(from_file);
        assert!(val.contains("8080"));
        assert!(val.contains("9090"));
    }
}
