//! User configuration loaded from `~/.config/cplt/config.toml`.
//!
//! The config file is optional — cplt works without it.
//! CLI flags always override config values for scalar fields.
//! For list fields (allow/deny paths), CLI and config values are merged (union).
//!
//! Override config location with `CPLT_CONFIG` env var.

mod display;
mod editing;
mod error;
mod loading;
mod path;
mod registry;
mod repo;
mod types;
mod validation;

// Re-export public API
pub use display::{display_config, explain_all, explain_key, get_config_value};
pub use editing::{
    ConfigSetOp, append_value_in_doc, get_value_from_doc, remove_array_element_in_doc,
    set_value_in_doc, unset_value_in_doc,
};
pub use error::ConfigError;
pub use path::{collapse_tilde, config_dir, config_path, default_config_contents, expand_tilde};
pub use registry::{ConfigKeyInfo, ConfigValueType, all_config_keys, lookup_key};
pub use repo::{RepoKeyTarget, repo_key_rejection_reason, repo_key_target, set_repo_value_in_doc};
pub use types::{
    AllowConfig, AuditConfig, CliFlags, Config, DenyConfig, EnforcementMode, FeatureToggle,
    GhGuardConfig, GhGuardPolicy, GitGuardConfig, GitGuardPolicy, GitPushRule, LoadedConfig,
    Preset, ProxyConfig, Resolved, ResolvedPushRule, SandboxConfig, UnknownCommandPolicy,
};
pub use validation::{ConfigDiagnostic, DiagnosticLevel, validate_config};
