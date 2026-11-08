//! What bounds a node's operate listener against a caller that holds it up
//! rather than asks it anything: how many connections it answers at once,
//! how many of them may be in their handshake, and how long a handshake may
//! take in all (`[tuning] operate_connections`, `operate_handshakes` and
//! `operate_handshake`, per cluster and per node; ADR-0031, amendment
//! 2026-10-03). A connection past either count is closed as it is accepted,
//! and the first of a run of them told to the node's audit. A handshake is
//! bounded in all, not read by read, so a client dribbling a byte at a time
//! is cut at the deadline as one saying nothing is. An accept that fails —
//! out of handles, a connection reset before it was taken — is asked again
//! after a pause that doubles while it keeps failing ([`Backoff`]), never in
//! a loop holding a processor.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::secure_listener::HANDSHAKE_WITHIN;

/// How many connections a listener answers at once, by default.
pub const CONNECTIONS: usize = 256;

/// How many of them may be in their handshake at once, by default.
pub const HANDSHAKES: usize = 32;

/// The shortest and the longest pause after an accept that failed.
const PAUSES: (Duration, Duration) = (Duration::from_millis(1), Duration::from_millis(100));

/// What bounds one listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The connections answered at once.
    pub connections: usize,
    /// The handshakes in progress at once.
    pub handshakes: usize,
    /// How long one handshake may take in all.
    pub handshake_within: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: CONNECTIONS,
            handshakes: HANDSHAKES,
            handshake_within: HANDSHAKE_WITHIN,
        }
    }
}

/// One handshake in progress, counted until it is dropped.
pub(crate) struct Handshaking(Arc<AtomicUsize>);

impl Handshaking {
    /// A handshake begun on `counted`, where fewer than `most` are.
    pub(crate) fn begun(counted: &Arc<AtomicUsize>, most: usize) -> Option<Self> {
        counted
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                (now < most).then_some(now + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(counted)))
    }
}

impl Drop for Handshaking {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The pause before an accept is asked again.
#[derive(Default)]
pub(crate) struct Backoff(Option<Duration>);

impl Backoff {
    /// An accept failed: wait, longer each time it fails again in a row.
    pub(crate) fn failed(&mut self) {
        let pause = self.0.map_or(PAUSES.0, |last| (last * 2).min(PAUSES.1));
        self.0 = Some(pause);
        std::thread::sleep(pause);
    }

    /// An accept succeeded: the next failure pauses least again.
    pub(crate) const fn succeeded(&mut self) {
        self.0 = None;
    }
}

/// The socket under a handshake, each read and write waiting no longer
/// than what is left until `until`.
struct Bounded<'a> {
    tcp: &'a TcpStream,
    until: Instant,
}

impl Bounded<'_> {
    fn left(&self) -> std::io::Result<Duration> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "the handshake ran past its deadline",
            ));
        }
        Ok(left)
    }
}

impl Read for Bounded<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.left()?))?;
        let mut tcp = self.tcp;
        tcp.read(buffer)
    }
}

impl Write for Bounded<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.left()?))?;
        let mut tcp = self.tcp;
        tcp.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut tcp = self.tcp;
        tcp.flush()
    }
}

/// `guarded`'s handshake driven to its end within `within` in all.
///
/// # Errors
///
/// The handshake failed, or did not end within `within`, in words.
pub(crate) fn handshaken(guarded: &mut tls::GuardedServer, within: Duration) -> Result<(), String> {
    let until = Instant::now() + within;
    let mut bounded = Bounded {
        tcp: &guarded.sock,
        until,
    };
    while guarded.conn.is_handshaking() {
        if let Err(error) = guarded.conn.complete_io(&mut bounded) {
            return Err(if Instant::now() >= until {
                format!("the handshake took longer than {within:?}")
            } else {
                format!("the handshake: {error}")
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_admits_up_to_its_most_and_frees_a_place_as_one_ends() {
        let counted = Arc::new(AtomicUsize::new(0));
        let first = Handshaking::begun(&counted, 2).expect("one");
        let second = Handshaking::begun(&counted, 2).expect("two");
        assert!(
            Handshaking::begun(&counted, 2).is_none(),
            "the third refused"
        );
        drop(first);
        let third = Handshaking::begun(&counted, 2).expect("a place freed");
        drop((second, third));
        assert_eq!(counted.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_accept_that_keeps_failing_waits_longer_each_time_and_at_most_the_longest() {
        let mut backoff = Backoff::default();
        let began = Instant::now();
        for _ in 0..3 {
            backoff.failed();
        }
        assert_eq!(backoff.0, Some(Duration::from_millis(4)));
        assert!(began.elapsed() >= Duration::from_millis(7));
        backoff.0 = Some(PAUSES.1);
        backoff.failed();
        assert_eq!(backoff.0, Some(PAUSES.1));
        backoff.succeeded();
        assert_eq!(backoff.0, None);
    }
}
