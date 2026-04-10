//! Sandbox profile generation, environment hardening, and execution.
//!
//! Split into submodules for maintainability:
//! - `policy`: constants, types, and validation (deny lists, env allowlists, tool dirs)
//! - `profile`: SBPL profile generation (`generate_profile`)
//! - `env`: environment variable construction (`build_sandbox_env`)
//! - `exec`: sandbox execution and validation (`exec`, `validate`)
//!
//! Submodules use `#[path]` because the sandbox blocks directory creation.
//! To reorganize to standard `src/sandbox/mod.rs` layout, move the files
//! into `src/sandbox/` and remove the `#[path]` attributes.

#[path = "sandbox_env.rs"]
mod env;
#[path = "sandbox_exec.rs"]
mod exec;
#[path = "sandbox_policy.rs"]
mod policy;
#[path = "sandbox_profile.rs"]
mod profile;

// Re-export the public API — explicit list to prevent accidental API widening.

// Policy: constants, types, validation
pub use policy::{
    DENIED_DOTFILES, DENIED_FILES, ENV_ALLOWLIST, ENV_PREFIX_ALLOWLIST, HARDENING_ENV_VARS,
    HOME_TOOL_DIRS, HardeningCategory, HardeningEnvVar, HomeToolDir, validate_sbpl_path,
};

// Profile generation
pub use profile::{ProfileOptions, generate_profile};

// Environment construction
pub use env::{SandboxEnv, build_sandbox_env};

// Sandbox execution and validation
pub use exec::{exec, validate};
