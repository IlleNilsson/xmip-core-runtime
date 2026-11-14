//! A node's Receive Location asked again until it listens: it binds on its
//! first receive, after the node has started, and nothing else says when
//! that was (`receiving`). Every test that sends to a node it just started,
//! or connects to one, asks through this rule, placed once. Until
//! 2026-11-14 it was written three times — the root crate's service tests,
//! the running tests, the Ledger's drain — and the timing program's
//! warm-up connect asked once: Windows used to ask a refused connect again
//! for two seconds itself, which hid the race, and `net::connect` answers a
//! refusal at once since that day.

use std::time::{Duration, Instant};

/// How long a Receive Location is asked again before a test gives up.
const BOUND: Duration = Duration::from_secs(5);

/// What `attempt` gives at `target`, asked again while it fails in a way
/// asking again may mend — a refusal, the Location there not bound yet.
/// Bounded, and never a sleep.
///
/// # Panics
///
/// Where `attempt` fails in a way asking again will not mend, or still
/// fails once [`BOUND`] has passed.
pub fn until_listening<T>(target: &str, mut attempt: impl FnMut() -> transport::Result<T>) -> T {
    let deadline = Instant::now() + BOUND;
    loop {
        match attempt() {
            Ok(done) => return done,
            Err(refused) if refused.retryable && Instant::now() < deadline => {
                std::thread::yield_now();
            }
            Err(failed) => panic!("nothing took it at {target}: {failed:?}"),
        }
    }
}
