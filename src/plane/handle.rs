//! An opaque handle for a caller, drawn once here for both ends of the
//! operate plane: the callers a host's runtime holds (`plane::held`) and
//! the callers a node holds for a relay (`plane::vouched`) — a number from
//! the operating system's random source (`codec::random`), never 0, which
//! is no one, so a handle is never guessed (ADR-0009, amendment
//! 2026-11-01); and the clock both end one by.

use std::time::{SystemTime, UNIX_EPOCH};

/// A handle `taken` does not already name, never 0.
#[must_use]
pub fn drawn(taken: impl Fn(u64) -> bool) -> u64 {
    loop {
        let drawn = u64::from_ne_bytes(codec::random::array());
        if drawn != 0 && !taken(drawn) {
            return drawn;
        }
    }
}

/// Now, in seconds since the Unix epoch.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_is_never_0_nor_one_taken() {
        let first = drawn(|_| false);
        assert_ne!(first, 0);
        assert_ne!(drawn(|taken| taken == first), first);
        assert!(now() > 1_700_000_000);
    }
}
