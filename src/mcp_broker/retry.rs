//! Retry policy for OAuth token refresh.

use std::time::Duration;

const MAX_ATTEMPTS: u32 = 3;
const MAX_WAIT: Duration = Duration::from_secs(60);
const DEFAULT_WAIT: Duration = Duration::from_secs(1);

/// Return how long to wait before the next OAuth token refresh attempt, or the
/// user-facing re-login error when retries are exhausted or inappropriate.
///
/// Owner decision 2026-11-17: a 503 is never treated as `invalid_grant` and
/// never deletes the token.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn refresh_retry(
    attempts_made: u32,
    status: u16,
    retry_after: Option<&str>,
    id: &str,
) -> Result<Duration, String> {
    let err = || {
        let id = id.escape_debug().to_string();
        format!("token refresh for {id} failed; log in again: cplt mcp login {id}")
    };
    if !matches!(status, 429 | 503) || attempts_made >= MAX_ATTEMPTS {
        return Err(err());
    }
    let wait = match retry_after.map(str::trim).filter(|s| !s.is_empty()) {
        None => DEFAULT_WAIT,
        // Digits only: u64::from_str would also take "+5".
        Some(s) => match s
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| s.parse::<u64>())
        {
            Some(Ok(secs)) => {
                // Floor at the default so "0" cannot spin.
                let d = Duration::from_secs(secs).max(DEFAULT_WAIT);
                if d > MAX_WAIT {
                    return Err(err());
                }
                d
            }
            // Digits too large for u64 are far over the cap.
            Some(Err(_)) => return Err(err()),
            // HTTP-date or garbage falls back to the short default wait.
            _ => DEFAULT_WAIT,
        },
    };
    Ok(wait)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_parsing_and_bounds() {
        for v in ["0", "+5", "-1"] {
            assert_eq!(refresh_retry(0, 503, Some(v), "x"), Ok(DEFAULT_WAIT), "{v}");
        }
        assert_eq!(
            refresh_retry(0, 503, Some("5"), "com.example/srv"),
            Ok(Duration::from_secs(5))
        );
        assert_eq!(
            refresh_retry(1, 429, Some(" 60 "), "com.example/srv"),
            Ok(Duration::from_secs(60))
        );
        assert!(refresh_retry(0, 503, Some("61"), "com.example/srv").is_err());
        // Overflowing u64 is over the cap, not the 1 s default.
        assert!(refresh_retry(0, 503, Some("99999999999999999999999"), "x").is_err());
        assert_eq!(
            refresh_retry(0, 503, None, "com.example/srv"),
            Ok(Duration::from_secs(1))
        );
        assert_eq!(
            refresh_retry(
                0,
                429,
                Some("Wed, 21 Oct 2015 07:28:00 GMT"),
                "com.example/srv"
            ),
            Ok(Duration::from_secs(1))
        );
        assert_eq!(
            refresh_retry(0, 429, Some("garbage"), "com.example/srv"),
            Ok(Duration::from_secs(1))
        );
    }

    #[test]
    fn stops_after_max_attempts_and_on_non_retryable_status() {
        let e = refresh_retry(3, 503, Some("1"), "com.example/srv").unwrap_err();
        assert!(e.contains("cplt mcp login com.example/srv"), "{e}");
        for status in [400, 401, 500] {
            let e = refresh_retry(0, status, Some("1"), "com.example/srv").unwrap_err();
            assert!(
                e.contains("cplt mcp login com.example/srv"),
                "{status}: {e}"
            );
        }
    }

    #[test]
    fn error_escapes_server_id() {
        let e = refresh_retry(0, 500, None, "bad\nid\x1b").unwrap_err();
        assert!(!e.contains('\n') && !e.contains('\x1b'), "{e}");
        assert!(e.contains("cplt mcp login bad\\nid\\u{1b}"), "{e}");
    }
}
