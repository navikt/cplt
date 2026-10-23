//! #830: the legacy-state pin is process-wide, so it is tested in its own
//! binary where it cannot leak into the XDG tests in the library.

use std::path::PathBuf;

use cplt::sandbox::{CPLT_STATE_DIR, cplt_state_dir, pin_legacy_state_dir_if_inside};

#[test]
fn xdg_inside_allow_write_pins_state_to_the_legacy_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let granted = tmp.path().join("granted");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let xdg = granted.join("cfg");
    let env = |name: &str| (name == "XDG_CONFIG_HOME").then(|| xdg.clone().into_os_string());
    let legacy = home.join(CPLT_STATE_DIR);

    assert_eq!(cplt_state_dir(&env, &home), xdg.join("cplt"));
    let pinned = pin_legacy_state_dir_if_inside(&env, &home, &[PathBuf::from(&granted)]);
    assert_eq!(pinned, Some((xdg.join("cplt"), granted.clone())));
    assert_eq!(cplt_state_dir(&env, &home), legacy);
    // Reported once.
    assert_eq!(
        pin_legacy_state_dir_if_inside(&env, &home, &[granted]),
        None
    );

    // launch_state reads the process env; point it at the same XDG dir.
    temp_env::with_var("XDG_CONFIG_HOME", Some(&xdg), || {
        assert!(cplt::launch_state::changed(&home, &project, "nested", "a"));
        assert!(!cplt::launch_state::changed(&home, &project, "nested", "a"));
    });
    assert!(legacy.join("launch").read_dir().unwrap().next().is_some());
    assert!(
        !xdg.join("cplt").exists(),
        "nothing written under the grant"
    );
}
