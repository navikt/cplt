//! Human-readable config display and `cplt config explain`.

use super::path::config_path;
use super::registry::{ConfigKeyInfo, ConfigLayer, ResolvedBools, type_label};
use super::types::{CliFlags, Config, EnforcementMode, LoadedConfig, Preset, UnknownCommandPolicy};
use crate::ui;

/// Print explanation of a single config key, showing type and current value inline.
pub fn explain_key(
    key_info: &ConfigKeyInfo,
    loaded: Option<&LoadedConfig>,
    local: Option<&LoadedConfig>,
) {
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

    let (current_value, layer) = get_config_value(key_info, loaded, local);
    let from_file = layer != ConfigLayer::Baseline;
    let current_value = redact_sensitive_value(key_info, current_value);
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
            "  {dim}{type_str}{nc}  {value_color}{current_value}{nc}  {dim}({layer}, default: {default_display}){nc}"
        );
    } else {
        println!("  {dim}{type_str}  {current_value}{nc}");
    }

    if key_info.dangerous {
        println!("  {yellow}Requires --force to enable{nc}");
    }
    // The layer this key actually accepts, not a generic invocation: for a
    // local- or repo-only key the plain form is refused, so printing it sent
    // the reader to a dead end (#438).
    println!(
        "  {blue}Set:{nc}  cplt config set {}{}.{} <value>",
        super::registry::layer_only_flag(key_info)
            .map(|flag| format!("{flag} "))
            .unwrap_or_default(),
        key_info.section,
        key_info.key
    );
}

/// Print explanation of all config keys, grouped by section.
/// Shows the effective value inline: dim for default, bold for config-file override.
pub fn explain_all(loaded: Option<&LoadedConfig>, local: Option<&LoadedConfig>) {
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
        let (current_value, layer) = get_config_value(key, loaded, local);
        let from_file = layer != ConfigLayer::Baseline;
        let current_value = redact_sensitive_value(key, current_value);
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

/// Get the effective value of a config key, and the layer it came from.
///
/// A bool cannot say which of two files a value came from, which is why this
/// returns the layer: local, global, or `Baseline` for "no file set it".
/// The order is the resolver's own — local above global — read off the raw
/// documents, because this reports what the FILES say and there is no merge to
/// consult. `ConfigLayer::Baseline` here means "not in any file"; it does not
/// distinguish a preset baseline from a hardcoded default.
pub fn get_config_value(
    key_info: &ConfigKeyInfo,
    loaded: Option<&LoadedConfig>,
    local: Option<&LoadedConfig>,
) -> (String, ConfigLayer) {
    for (file, layer) in [(local, ConfigLayer::Local), (loaded, ConfigLayer::Global)] {
        if let Some(file) = file
            && let Ok(root) = file.raw.parse::<toml::Table>()
            && let Some(val) = root
                .get(key_info.section)
                .and_then(|section| section.get(key_info.key))
        {
            return (format_toml_value(val), layer);
        }
    }

    (key_info.default_display.to_string(), ConfigLayer::Baseline)
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

/// Redact credential-bearing values before they are printed in a summary
/// (`config show` / `config explain`). Currently only `proxy.upstream` can
/// carry a `user:pass@` secret. `config get <key>` deliberately does NOT go
/// through this — asking for a single key by name returns the raw value the
/// user themselves stored.
fn redact_sensitive_value(key_info: &ConfigKeyInfo, value: String) -> String {
    if key_info.section == "proxy" && key_info.key == "upstream" {
        crate::proxy::redact_upstream_url(&value)
    } else {
        value
    }
}

// ── Config display (effective config) ────────────────────────────────

/// Display the effective configuration from a config file merged with defaults.
/// Shows what cplt would use at runtime (without CLI flag overrides).
pub fn display_config(loaded: Option<&LoadedConfig>, local: Option<&LoadedConfig>) {
    let blue = ui::stdout_color(ui::BLUE);
    let dim = ui::stdout_color(ui::DIM);
    let green = ui::stdout_color(ui::GREEN);
    let yellow = ui::stdout_color(ui::YELLOW);
    let nc = ui::stdout_color(ui::RESET);

    let global = loaded.map(|l| l.config.clone()).unwrap_or_default();
    let local_config = local.map(|l| &l.config);
    // Values come from the same overlay the launch uses, not a second ladder
    // written here: a local `Some` wins, lists union.
    let c = match local_config {
        Some(l) => global.overlay(l),
        None => global.clone(),
    };
    // Which layer each key came from. Booleans get the answer from the
    // resolver itself (`ResolvedBools::layer`), which is the whole point of it
    // returning the layer — a private ladder here is what #410 was. Everything
    // else is not on the ladder, so the local file's own document answers
    // "did local set this key", and the caller passes the global answer in.
    // The baseline comes off the overlay, not a hand-rolled `or_else` ladder:
    // local beats global for every scalar, `preset` included, and the ladder
    // here had it backwards. `guard_lines` reads `c.sandbox.preset` for the
    // same reason — one merge decides, in both places.
    let bools = ResolvedBools::resolve(
        &CliFlags::default(),
        local_config,
        &global,
        c.sandbox.preset.unwrap_or(Preset::Standard).baseline(),
    );
    let local_doc = local.and_then(|l| l.raw.parse::<toml::Table>().ok());
    let local_sets = |section: &str, key: &str| {
        local_doc
            .as_ref()
            .is_some_and(|root| root.get(section).and_then(|table| table.get(key)).is_some())
    };
    let src = |section: &str, key: &str, has_file_value: bool| -> &'static str {
        match bools.layer(section, key) {
            Some(ConfigLayer::Local) => " (local)",
            Some(ConfigLayer::Baseline) => " (default)",
            Some(_) => "",
            None if local_sets(section, key) => " (local)",
            None if has_file_value => "",
            None => " (default)",
        }
    };

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
        println!("{blue}[cplt]{nc}  {dim}File:{nc}  {dim}(no config path, $HOME not set){nc}");
    }
    // Only when a local file was actually APPLIED — a missing one, or one the
    // remote tripwire stopped, leaves `local` None and must not claim a layer
    // that did nothing. `cplt config path --local` prints the path either way.
    if let Some(l) = local {
        println!("{blue}[cplt]{nc}  {dim}Local:{nc} {}", l.path.display());
    }
    println!();

    // [proxy]
    println!("{blue}[cplt]{nc}  {dim}[proxy]{nc}");
    let proxy_enabled = c.proxy.enabled.unwrap_or(true);
    println!(
        "{blue}[cplt]{nc}    enabled          = {}{}{nc}{}",
        if proxy_enabled { green } else { yellow },
        proxy_enabled,
        src("proxy", "enabled", c.proxy.enabled.is_some())
    );
    let proxy_forced = c.proxy.forced.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    forced           = {}{}{nc}{}",
        if proxy_forced { yellow } else { green },
        proxy_forced,
        src("proxy", "forced", c.proxy.forced.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    port             = {}{}",
        c.proxy.port.unwrap_or(0),
        src("proxy", "port", c.proxy.port.is_some())
    );
    if let Some(ref bd) = c.proxy.blocked_domains {
        println!("{blue}[cplt]{nc}    blocked_domains  = \"{bd}\"");
    }
    if let Some(ref ad) = c.proxy.allowed_domains {
        println!("{blue}[cplt]{nc}    allowed_domains  = \"{ad}\"");
    }
    let default_allowlist = c.proxy.default_allowlist.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    default_allowlist = {}{}{nc}{}",
        if default_allowlist { green } else { yellow },
        default_allowlist,
        src(
            "proxy",
            "default_allowlist",
            c.proxy.default_allowlist.is_some()
        )
    );
    if let Some(ref lf) = c.proxy.log_file {
        println!("{blue}[cplt]{nc}    log_file         = \"{lf}\"");
    }
    if let Some(ref up) = c.proxy.upstream {
        // Redact `user:pass@` userinfo — this summary is routinely pasted into
        // issues/CI logs. The real Proxy-Authorization sent upstream is derived
        // from the untouched URL at parse time and is unaffected.
        println!(
            "{blue}[cplt]{nc}    upstream         = \"{}\"",
            crate::proxy::redact_upstream_url(up)
        );
    }
    // No-proxy bypass list — plain hostnames, no secrets to redact.
    if let Some(ref np) = c.proxy.upstream_no_proxy
        && !np.is_empty()
    {
        println!("{blue}[cplt]{nc}    upstream_no_proxy = {np:?}");
    }
    println!(
        "{blue}[cplt]{nc}    log_level        = \"{}\"{}",
        c.proxy.log_level.as_deref().unwrap_or("none"),
        src("proxy", "log_level", c.proxy.log_level.is_some())
    );
    println!(
        "{blue}[cplt]{nc}    timeout          = {}{}",
        c.proxy.timeout.unwrap_or(60),
        src("proxy", "timeout", c.proxy.timeout.is_some())
    );
    // [proxy.subscriptions] — blocklist subscriptions (issue #144, Phase 1).
    // Global-only, tighten-only. Shown only when configured.
    if !c.proxy.subscriptions.blocklists.is_empty() {
        println!(
            "{blue}[cplt]{nc}    subscriptions.refresh   = \"{}\"",
            c.proxy.subscriptions.refresh.as_deref().unwrap_or("manual")
        );
        println!(
            "{blue}[cplt]{nc}    subscriptions.blocklists = ({} list(s))",
            c.proxy.subscriptions.blocklists.len()
        );
        for source in &c.proxy.subscriptions.blocklists {
            let pin = if source.sha256().is_some() {
                " (sha256 pinned)"
            } else {
                ""
            };
            println!("{blue}[cplt]{nc}      - {}{pin}", source.url());
        }
    }
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
    if c.allow.exec.is_empty() {
        println!("{blue}[cplt]{nc}    exec             = {dim}[]{nc}");
    } else {
        let red = ui::color(ui::RED);
        println!(
            "{blue}[cplt]{nc}    exec             = {red}{:?}{nc} \u{26a0} DANGEROUS",
            c.allow.exec
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
    match c.sandbox.preset {
        Some(preset) => println!(
            "{blue}[cplt]{nc}    preset                = {preset}{}",
            src("sandbox", "preset", true)
        ),
        None => println!("{blue}[cplt]{nc}    preset                = {dim}standard (default){nc}"),
    }
    // The local layer is the only one that can set this — the global loader
    // drops it — and it is the one key whose whole job is to name a repository
    // the user has stopped thinking about. Leaving it off this screen made the
    // effective config silent about exactly that.
    if c.sandbox.repo_dirs.is_empty() {
        println!("{blue}[cplt]{nc}    repo_dirs             = {dim}[]{nc}");
    } else {
        println!(
            "{blue}[cplt]{nc}    repo_dirs             = {:?}{}",
            c.sandbox.repo_dirs,
            src("sandbox", "repo_dirs", false)
        );
    }
    let validate = c.sandbox.validate.unwrap_or(true);
    println!(
        "{blue}[cplt]{nc}    validate              = {}{}",
        validate,
        src("sandbox", "validate", c.sandbox.validate.is_some())
    );
    let allow_env_files = c.sandbox.allow_env_files.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_env_files       = {}{}",
        allow_env_files,
        src(
            "sandbox",
            "allow_env_files",
            c.sandbox.allow_env_files.is_some()
        )
    );
    let allow_localhost_any = c.sandbox.allow_localhost_any.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_localhost_any    = {}{}",
        allow_localhost_any,
        src(
            "sandbox",
            "allow_localhost_any",
            c.sandbox.allow_localhost_any.is_some()
        )
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
        println!(
            "{blue}[cplt]{nc}    inherit_env           = {red}true{nc} ⚠ DANGEROUS{}",
            src("sandbox", "inherit_env", c.sandbox.inherit_env.is_some())
        );
    } else {
        println!(
            "{blue}[cplt]{nc}    inherit_env           = false{}",
            src("sandbox", "inherit_env", c.sandbox.inherit_env.is_some())
        );
    }
    let allow_lifecycle = c.sandbox.allow_lifecycle_scripts.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_lifecycle_scripts = {}{}",
        allow_lifecycle,
        src(
            "sandbox",
            "allow_lifecycle_scripts",
            c.sandbox.allow_lifecycle_scripts.is_some()
        )
    );
    let allow_gpg = c.sandbox.allow_gpg_signing.unwrap_or(false);
    if allow_gpg {
        let red = ui::stdout_color(ui::RED);
        println!(
            "{blue}[cplt]{nc}    allow_gpg_signing     = {red}true{nc} ⚠ DANGEROUS{}",
            src(
                "sandbox",
                "allow_gpg_signing",
                c.sandbox.allow_gpg_signing.is_some()
            )
        );
    } else {
        println!(
            "{blue}[cplt]{nc}    allow_gpg_signing     = false{}",
            src(
                "sandbox",
                "allow_gpg_signing",
                c.sandbox.allow_gpg_signing.is_some()
            )
        );
    }
    let allow_docker = c.sandbox.allow_docker.unwrap_or(false);
    if allow_docker {
        let red = ui::stdout_color(ui::RED);
        println!(
            "{blue}[cplt]{nc}    allow_docker          = {red}true{nc} ⚠ DANGEROUS{}",
            src("sandbox", "allow_docker", c.sandbox.allow_docker.is_some())
        );
    } else {
        println!(
            "{blue}[cplt]{nc}    allow_docker          = false{}",
            src("sandbox", "allow_docker", c.sandbox.allow_docker.is_some())
        );
    }
    let allow_tmp = c.sandbox.allow_tmp_exec.unwrap_or(false);
    if allow_tmp {
        let red = ui::stdout_color(ui::RED);
        println!(
            "{blue}[cplt]{nc}    allow_tmp_exec        = {red}true{nc} ⚠ DANGEROUS{}",
            src(
                "sandbox",
                "allow_tmp_exec",
                c.sandbox.allow_tmp_exec.is_some()
            )
        );
    } else {
        println!(
            "{blue}[cplt]{nc}    allow_tmp_exec        = false{}",
            src(
                "sandbox",
                "allow_tmp_exec",
                c.sandbox.allow_tmp_exec.is_some()
            )
        );
    }
    let allow_browser = c.sandbox.allow_browser.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    allow_browser         = {}{}",
        allow_browser,
        src(
            "sandbox",
            "allow_browser",
            c.sandbox.allow_browser.is_some()
        )
    );
    let keychain_substitute = c.sandbox.keychain_substitute.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    keychain_substitute   = {}{} {dim}(experimental){nc}",
        keychain_substitute,
        src(
            "sandbox",
            "keychain_substitute",
            c.sandbox.keychain_substitute.is_some()
        )
    );
    // The brief and its AGENTS.md layer had no rows at all, so a user who set
    // `sandbox.brief = true` saw nothing here and had to reach for
    // `config get` to confirm it. A key that changes behaviour and is absent
    // from the command whose job is to report effective configuration is the
    // same defect as a key that reports the wrong value.
    let brief = c.sandbox.brief.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    brief                 = {}{} {dim}(experimental){nc}",
        brief,
        src("sandbox", "brief", c.sandbox.brief.is_some())
    );
    // Gated on the brief, so say when it is set and inert rather than printing
    // a `true` the launch will not act on.
    let agents_md = c.sandbox.agents_md.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    agents_md             = {}{}{} {dim}(experimental){nc}",
        agents_md,
        if agents_md && !brief {
            " (inert: needs brief)"
        } else {
            ""
        },
        src("sandbox", "agents_md", c.sandbox.agents_md.is_some())
    );
    let scratch = c.sandbox.scratch_dir.unwrap_or(true);
    println!(
        "{blue}[cplt]{nc}    scratch_dir           = {}{}",
        scratch,
        src("sandbox", "scratch_dir", c.sandbox.scratch_dir.is_some())
    );
    let audit = c.sandbox.audit.unwrap_or(true);
    println!(
        "{blue}[cplt]{nc}    audit                 = {}{}",
        audit,
        src("sandbox", "audit", c.sandbox.audit.is_some())
    );
    match c.sandbox.use_bubblewrap {
        Some(v) => println!(
            "{blue}[cplt]{nc}    use_bubblewrap        = {v}{}",
            src("sandbox", "use_bubblewrap", true)
        ),
        None => println!("{blue}[cplt]{nc}    use_bubblewrap        = auto-detect"),
    }
    let quiet = c.sandbox.quiet.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    quiet                 = {}{}",
        quiet,
        src("sandbox", "quiet", c.sandbox.quiet.is_some())
    );
    let gh_proxy_deprecated = c.sandbox.gh_proxy.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    gh_proxy              = {}{} {dim}(deprecated, use [gh_guard]){nc}",
        gh_proxy_deprecated,
        src("sandbox", "gh_proxy", c.sandbox.gh_proxy.is_some())
    );
    let git_push_prevention = c.sandbox.git_push_prevention.unwrap_or(false);
    println!(
        "{blue}[cplt]{nc}    git_push_prevention   = {}{} {dim}(deprecated, use [git_guard]){nc}",
        git_push_prevention,
        src(
            "sandbox",
            "git_push_prevention",
            c.sandbox.git_push_prevention.is_some()
        )
    );

    for line in guard_lines(&global, local_config) {
        println!("{blue}[cplt]{nc}{line}");
    }

    println!("{blue}[cplt]{nc} ──────────────────────────────────────────────────────");
}

/// Whether a local config sets one of the two enum-valued guard keys that the
/// boolean ladder does not cover.
fn local_mode_is_set(local: &Config, section: &str, key: &str) -> bool {
    match (section, key) {
        ("gh_guard", "mode") => local.gh_guard.mode.is_some(),
        ("gh_guard", "unknown_command") => local.gh_guard.unknown_command.is_some(),
        ("git_guard", "mode") => local.git_guard.mode.is_some(),
        _ => false,
    }
}

/// The `[gh_guard]` / `[git_guard]` block of `config show`, without the
/// `[cplt]` prefix so a test can compare it against the resolver's own output.
///
/// Every effective value here comes from [`ResolvedBools`] with an empty
/// [`CliFlags`] — the same table the resolver uses — rather than a hand-written
/// `unwrap_or(<literal>)`. `config show` reports what is in force; a private
/// fallback ladder here is free to drift from the real one, and did: both
/// guards have defaulted ON since #335 while this screen kept printing
/// `false`. Reusing the table makes that class of bug unrepresentable, and
/// picks up the deprecated `sandbox.gh_proxy` / `sandbox.git_push_prevention`
/// spellings for free, since the registry folds them in at the config layer.
/// The `⚠ DANGEROUS` suffix for a key that is on and that `config set` refuses
/// without `--force`. Plain text, not coloured: these rows are built as strings
/// and coloured by the caller, and a marker that only appears in a terminal is
/// not one a user can paste into a support thread.
fn danger_suffix(on: bool) -> &'static str {
    if on { " ⚠ DANGEROUS" } else { "" }
}

fn guard_lines(global: &Config, local: Option<&Config>) -> Vec<String> {
    let c = match local {
        Some(l) => global.overlay(l),
        None => global.clone(),
    };
    let c = &c;
    let baseline = c.sandbox.preset.unwrap_or(Preset::Standard).baseline();
    let b = ResolvedBools::resolve(&CliFlags::default(), local, global, baseline);
    // Booleans read their layer straight off the resolver. The two enum-valued
    // keys here (`mode`) are not on the ladder, so they ask the local config
    // directly — one `is_some()`, not a fallback chain.
    let src = |section: &str, key: &str, has_file_value: bool| -> &'static str {
        match b.layer(section, key) {
            Some(ConfigLayer::Local) => " (local)",
            Some(ConfigLayer::Baseline) => " (default)",
            Some(_) => "",
            None if local.is_some_and(|l| local_mode_is_set(l, section, key)) => " (local)",
            None if has_file_value => "",
            None => " (default)",
        }
    };

    vec![
        String::new(),
        "  [gh_guard]".to_string(),
        format!(
            "    enabled               = {}{}",
            b.gh_guard_enabled,
            // The deprecated spelling is a file value too: the registry reads
            // `enabled.or(sandbox.gh_proxy)`, so "(default)" must follow it.
            src(
                "gh_guard",
                "enabled",
                c.gh_guard.enabled.is_some() || c.sandbox.gh_proxy.is_some(),
            )
        ),
        format!(
            // Literal, not a baseline: no preset varies the gh guard's mode, so
            // the resolver hardcodes `Block` for it. The git guard's mode two
            // sections below IS preset-controlled and reads the baseline. The
            // asymmetry is real, not an oversight — mirror whatever the
            // resolver does for each key.
            "    mode                  = {}{}",
            c.gh_guard.mode.unwrap_or(EnforcementMode::Block),
            src("gh_guard", "mode", c.gh_guard.mode.is_some())
        ),
        format!(
            "    scope_check           = {}{}",
            b.gh_scope_check,
            src("gh_guard", "scope_check", c.gh_guard.scope_check.is_some())
        ),
        format!(
            "    block_auth_token      = {}{}",
            b.gh_block_auth_token,
            src(
                "gh_guard",
                "block_auth_token",
                c.gh_guard.block_auth_token.is_some()
            )
        ),
        // Marked when on, because `config set` refuses both of these without
        // `--force`. A tool that demands a force-confirm to enable something
        // and then lists it as unremarkable is telling the reader two things.
        format!(
            "    inject_token          = {}{}{}",
            b.gh_inject_token,
            danger_suffix(b.gh_inject_token),
            src(
                "gh_guard",
                "inject_token",
                c.gh_guard.inject_token.is_some()
            )
        ),
        format!(
            "    unknown_command       = {}{}",
            c.gh_guard
                .unknown_command
                .unwrap_or(UnknownCommandPolicy::Block),
            src(
                "gh_guard",
                "unknown_command",
                c.gh_guard.unknown_command.is_some()
            )
        ),
        format!(
            "    allow_api_write       = {}{}{}",
            b.gh_allow_api_write,
            danger_suffix(b.gh_allow_api_write),
            src(
                "gh_guard",
                "allow_api_write",
                c.gh_guard.allow_api_write.is_some()
            )
        ),
        String::new(),
        "  [git_guard]".to_string(),
        format!(
            "    enabled               = {}{}",
            b.git_guard_enabled,
            src(
                "git_guard",
                "enabled",
                c.git_guard.enabled.is_some() || c.sandbox.git_push_prevention.is_some(),
            )
        ),
        format!(
            "    mode                  = {}{}",
            c.git_guard.mode.unwrap_or(baseline.git_guard_mode),
            src("git_guard", "mode", c.git_guard.mode.is_some())
        ),
        format!(
            "    prevent_push          = {}{}",
            b.git_prevent_push,
            src(
                "git_guard",
                "prevent_push",
                c.git_guard.prevent_push.is_some()
            )
        ),
        format!(
            "    prevent_force_push    = {}{}",
            b.git_prevent_force_push,
            src(
                "git_guard",
                "prevent_force_push",
                c.git_guard.prevent_force_push.is_some()
            )
        ),
        format!(
            "    protect_default_branch_only = {}{}",
            b.git_protect_default_branch_only,
            src(
                "git_guard",
                "protect_default_branch_only",
                c.git_guard.protect_default_branch_only.is_some()
            )
        ),
    ]
    .into_iter()
    .chain((!c.git_guard.allow_push.is_empty()).then(|| {
        format!(
            "    allow_push            = [{} rules]",
            c.git_guard.allow_push.len()
        )
    }))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_config_value_returns_default_when_no_file() {
        let info = crate::config::lookup_key("sandbox.quiet").unwrap();
        let (val, layer) = get_config_value(info, None, None);
        assert_eq!(val, "false");
        assert_eq!(layer, ConfigLayer::Baseline);
    }

    #[test]
    fn get_config_value_returns_file_value() {
        let info = crate::config::lookup_key("sandbox.quiet").unwrap();
        let loaded = LoadedConfig {
            config: Config::parse("[sandbox]\nquiet = true\n").unwrap(),
            raw: "[sandbox]\nquiet = true\n".to_string(),
            path: std::path::PathBuf::from("/tmp/fake"),
        };
        let (val, layer) = get_config_value(info, Some(&loaded), None);
        assert_eq!(val, "true");
        assert_eq!(layer, ConfigLayer::Global);
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
        let (val, layer) = get_config_value(info, Some(&loaded), None);
        assert_eq!(layer, ConfigLayer::Global);
        assert!(val.contains("8080"));
        assert!(val.contains("9090"));
    }

    #[test]
    fn get_config_value_renders_upstream_no_proxy_list() {
        // `config show` / `explain` render proxy.upstream_no_proxy as a plain
        // list of hostnames (no secrets to redact).
        let info = crate::config::lookup_key("proxy.upstream_no_proxy").unwrap();
        let raw = "[proxy]\nupstream_no_proxy = [\"internal.example.com\", \"corp.example\"]\n";
        let loaded = LoadedConfig {
            config: Config::parse(raw).unwrap(),
            raw: raw.to_string(),
            path: std::path::PathBuf::from("/tmp/fake"),
        };
        let (val, layer) = get_config_value(info, Some(&loaded), None);
        assert_eq!(layer, ConfigLayer::Global);
        assert!(val.contains("internal.example.com"), "got: {val}");
        assert!(val.contains("corp.example"), "got: {val}");
    }

    /// `config show` is the screen an operator reads to check whether their
    /// machine is enforcing, so a wrong answer here is the worst kind. #410:
    /// both guards have defaulted ON since #335 while this screen printed
    /// `false`, because it carried its own `unwrap_or(false)` instead of the
    /// preset baseline the resolver uses. Pin every guard line against the
    /// real resolver, under every preset, so the two cannot drift again.
    #[test]
    fn guard_lines_match_the_resolved_policy() {
        for toml in [
            "",
            "[sandbox]\npreset = \"standard\"\n",
            "[sandbox]\npreset = \"strict\"\n",
            "[sandbox]\npreset = \"permissive\"\n",
            "[sandbox]\npreset = \"full-trust\"\n",
            // Deprecated spellings: the registry folds them into `enabled`.
            "[sandbox]\ngh_proxy = true\ngit_push_prevention = true\n",
            // Explicit values must still win over the baseline.
            "[gh_guard]\nenabled = false\nmode = \"warn\"\n\n[git_guard]\nenabled = false\nmode = \"audit\"\n",
        ] {
            let c = Config::parse(toml).unwrap();
            let r = c.merge(CliFlags::default()).unwrap();
            let lines = guard_lines(&c, None);
            let gh = section(&lines, "[gh_guard]");
            let git = section(&lines, "[git_guard]");

            for (key, shown, resolved) in [
                (
                    "gh_guard.enabled",
                    &gh["enabled"],
                    r.gh_guard.enabled.to_string(),
                ),
                ("gh_guard.mode", &gh["mode"], r.gh_guard.mode.to_string()),
                (
                    "gh_guard.scope_check",
                    &gh["scope_check"],
                    r.gh_guard.scope_check.to_string(),
                ),
                (
                    "gh_guard.block_auth_token",
                    &gh["block_auth_token"],
                    r.gh_guard.block_auth_token.to_string(),
                ),
                (
                    "gh_guard.inject_token",
                    &gh["inject_token"],
                    r.gh_guard.inject_token.to_string(),
                ),
                (
                    "gh_guard.unknown_command",
                    &gh["unknown_command"],
                    r.gh_guard.unknown_command.to_string(),
                ),
                (
                    "gh_guard.allow_api_write",
                    &gh["allow_api_write"],
                    r.gh_guard.allow_api_write.to_string(),
                ),
                (
                    "git_guard.enabled",
                    &git["enabled"],
                    r.git_guard.enabled.to_string(),
                ),
                ("git_guard.mode", &git["mode"], r.git_guard.mode.to_string()),
                (
                    "git_guard.prevent_push",
                    &git["prevent_push"],
                    r.git_guard.prevent_push.to_string(),
                ),
                (
                    "git_guard.prevent_force_push",
                    &git["prevent_force_push"],
                    r.git_guard.prevent_force_push.to_string(),
                ),
                (
                    "git_guard.protect_default_branch_only",
                    &git["protect_default_branch_only"],
                    r.git_guard.protect_default_branch_only.to_string(),
                ),
            ] {
                assert_eq!(
                    *shown, resolved,
                    "{key}: `config show` says {shown}, the resolver enforces {resolved} \
                     (config: {toml:?})"
                );
            }
        }
    }

    /// The literal the #410 report named: an empty user config enforces both
    /// guards, so the screen must say `true`, marked as coming from the default.
    #[test]
    fn empty_config_shows_both_guards_enabled_by_default() {
        let lines = guard_lines(&Config::default(), None);
        assert!(
            lines.contains(&"    enabled               = true (default)".to_string()),
            "expected an enabled=true (default) line in {lines:#?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.trim_start().starts_with("enabled "))
                .count(),
            2,
            "both guard sections must render an `enabled` line"
        );
    }

    /// A deprecated spelling is a value from the file, not a default: it turns
    /// the guard on, so the line must not be annotated `(default)`.
    #[test]
    fn deprecated_spellings_are_not_labelled_default() {
        let c = Config::parse("[sandbox]\ngh_proxy = true\ngit_push_prevention = true\n").unwrap();
        let lines = guard_lines(&c, None);
        for l in lines
            .iter()
            .filter(|l| l.trim_start().starts_with("enabled "))
        {
            assert_eq!(l.trim(), "enabled               = true", "line: {l:?}");
        }
    }

    /// `key = value` pairs of one rendered guard section, `(default)` stripped.
    fn section(lines: &[String], header: &str) -> std::collections::HashMap<String, String> {
        lines
            .iter()
            .skip_while(|l| l.trim() != header)
            .skip(1)
            .take_while(|l| l.contains('='))
            .map(|l| {
                let (k, v) = l.split_once('=').unwrap();
                (
                    k.trim().to_string(),
                    v.replace("(default)", "").trim().to_string(),
                )
            })
            .collect()
    }
}
