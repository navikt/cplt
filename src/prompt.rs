use cplt::ui;

/// Prompt the user to confirm the sandbox configuration.
///
/// Returns Ok(()) if the user confirms, Err with message if they decline or
/// if no TTY is available without --yes.
pub fn prompt_confirm(auto_yes: bool, quiet: bool) -> Result<(), String> {
    if auto_yes {
        if !quiet {
            ui::info("Auto-confirmed (--yes)");
        }
        return Ok(());
    }

    // Try to open /dev/tty for the controlling terminal.
    // This works even if stdin is piped.
    let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return Err(
            "No TTY available for confirmation. Use --yes for non-interactive runs.".to_string(),
        );
    };

    if quiet {
        eprint!(
            "{}[cplt]{} Proceed with sandboxed Copilot? (run without --quiet to review config) [y/N] ",
            ui::color(ui::BLUE),
            ui::color(ui::RESET)
        );
    } else {
        eprint!(
            "{}[cplt]{} Proceed? [y/N] ",
            ui::color(ui::BLUE),
            ui::color(ui::RESET)
        );
    }

    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(tty);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return Err("Failed to read confirmation input".to_string());
    }

    let answer = line.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        Ok(())
    } else {
        Err("Aborted by user".to_string())
    }
}
