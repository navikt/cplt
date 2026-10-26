//! #851: where config.toml, trust/ and local/ live when `XDG_CONFIG_HOME` is
//! set. Every test runs against a scratch HOME from `tests/common` with
//! `XDG_CONFIG_HOME` inside it, so nothing touches the real HOME or XDG dirs.

mod common;

use std::path::{Path, PathBuf};

use cplt::config::{approval_dirs, config_dir, config_path, local_path, local_write_path};
use cplt::trust::{TrustEntry, load_trust, repo_fingerprint, revoke_trust, save_trust};

/// `(home, legacy root, xdg root)` with `f` run under that HOME and XDG.
fn with_roots(label: &str, f: impl FnOnce(&Path, &Path, &Path)) {
    let home = std::fs::canonicalize(common::make_config_home(label)).unwrap();
    let xdg = home.join("xdg");
    let (legacy_root, xdg_root) = (home.join(".config/cplt"), xdg.join("cplt"));
    temp_env::with_vars(
        [
            ("HOME", Some(home.as_os_str())),
            ("XDG_CONFIG_HOME", Some(xdg.as_os_str())),
            ("CPLT_CONFIG", None),
        ],
        || f(&home, &legacy_root, &xdg_root),
    );
    let _ = std::fs::remove_dir_all(&home);
}

fn entry(path: &str) -> TrustEntry {
    let mut e = TrustEntry::default();
    e.repo.path = path.into();
    e
}

fn plant_trust(root: &Path, project: &Path, path: &str) -> PathBuf {
    let file = root
        .join("trust")
        .join(format!("{}.toml", repo_fingerprint(project)));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, toml::to_string(&entry(path)).unwrap()).unwrap();
    file
}

#[test]
fn xdg_missing_keeps_the_legacy_root() {
    with_roots("root-missing", |_, legacy, xdg| {
        assert_eq!(config_dir(), Some(legacy.to_path_buf()));
        assert_eq!(config_path(), Some(legacy.join("config.toml")));
        // An empty XDG dir does not move anything either.
        std::fs::create_dir_all(xdg).unwrap();
        assert_eq!(config_dir(), Some(legacy.to_path_buf()));
    });
}

#[test]
fn xdg_with_config_or_trust_is_the_root() {
    for marker in ["config.toml", "trust"] {
        with_roots("root-exists", |_, legacy, xdg| {
            std::fs::create_dir_all(xdg).unwrap();
            if marker == "trust" {
                std::fs::create_dir_all(xdg.join(marker)).unwrap();
            } else {
                std::fs::write(xdg.join(marker), "").unwrap();
            }
            assert_eq!(config_dir(), Some(xdg.to_path_buf()), "{marker}");
            assert_eq!(
                approval_dirs(),
                vec![xdg.to_path_buf(), legacy.to_path_buf()]
            );
        });
    }
}

#[test]
fn approvals_are_read_from_both_roots_and_written_to_the_resolved_one() {
    with_roots("root-union", |home, legacy, xdg| {
        let project = home.join("project");
        std::fs::create_dir_all(&project).unwrap();
        // An existing user: approval in legacy, config moved to XDG later.
        let old = plant_trust(legacy, &project, "legacy");
        std::fs::create_dir_all(xdg).unwrap();
        std::fs::write(xdg.join("config.toml"), "").unwrap();
        assert_eq!(load_trust(&project).unwrap().repo.path, "legacy");

        // A new approval goes to the resolved root and wins over the old one.
        save_trust(&project, &entry("xdg")).unwrap();
        assert!(
            xdg.join("trust")
                .join(format!("{}.toml", repo_fingerprint(&project)))
                .exists()
        );
        assert_eq!(load_trust(&project).unwrap().repo.path, "xdg");

        // Revoking removes every copy, or the other would keep it trusted.
        revoke_trust(&project).unwrap();
        assert!(!old.exists());
        assert!(load_trust(&project).is_none());

        // local/: read from the legacy root, written to the resolved one.
        let legacy_local = legacy
            .join("local")
            .join(local_write_path(&project).unwrap().file_name().unwrap());
        std::fs::create_dir_all(legacy_local.parent().unwrap()).unwrap();
        std::fs::write(&legacy_local, "").unwrap();
        assert_eq!(local_path(&project), Some(legacy_local));
        assert!(local_write_path(&project).unwrap().starts_with(xdg));
    });
}

#[test]
fn an_earlier_pin_keeps_config_and_approvals_out_of_xdg() {
    with_roots("root-marker", |home, legacy, xdg| {
        let project = home.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(xdg).unwrap();
        std::fs::write(xdg.join("config.toml"), "").unwrap();
        plant_trust(xdg, &project, "forged");
        std::fs::create_dir_all(legacy).unwrap();
        std::fs::write(legacy.join(cplt::sandbox::XDG_PINNED_MARKER), "").unwrap();
        assert_eq!(config_dir(), Some(legacy.to_path_buf()));
        assert_eq!(approval_dirs(), vec![legacy.to_path_buf()]);
        assert!(
            load_trust(&project).is_none(),
            "the XDG copy is not trusted"
        );
    });
}

#[test]
fn cplt_config_keeps_one_root() {
    with_roots("root-custom", |home, _, xdg| {
        std::fs::create_dir_all(xdg.join("trust")).unwrap();
        let custom = home.join("custom/config.toml");
        temp_env::with_var("CPLT_CONFIG", Some(&custom), || {
            assert_eq!(config_dir(), Some(home.join("custom")));
            assert_eq!(approval_dirs(), vec![home.join("custom")]);
        });
    });
}
