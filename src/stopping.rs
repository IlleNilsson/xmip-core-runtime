//! A node's stop, raised once and heard at once: by what looks between
//! two pieces of work ([`Stopping::raised`]), and by what waits between
//! them ([`Stopping::wait`]) — a Receive Location resting before it polls
//! again — which the raise wakes rather than leaving it to its time
//! (`runtime-model.md` section 5, *How a receive runs*). A Location whose
//! far end tells it of a change — a drop directory the operating system
//! watches — rests until that word as well ([`Stopping::rest`]): its
//! [`Nudge`] wakes it from the thread that hears it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use xcore::wake::Wake;

/// A node's stop: lowered until [`Stopping::raise`], raised for good.
/// Cloned, it is the same stop.
#[derive(Clone, Debug, Default)]
pub struct Stopping(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    raised: AtomicBool,
    lock: Mutex<()>,
    wake: Wake,
}

/// One resting Location's word that its far end changed, told from any
/// thread: it ends the Location's rest at once, and a word told while it
/// was not resting ends the next rest at once, so none is lost.
#[derive(Clone, Debug)]
pub struct Nudge {
    stopping: Stopping,
    told: Arc<AtomicBool>,
}

impl Nudge {
    /// Tell the Location its far end changed.
    pub fn tell(&self) {
        let inner = &self.stopping.0;
        // Under the lock a resting Location checks it under, as a raise.
        let _held = inner.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.told.store(true, Ordering::Release);
        inner.wake.notify_all();
    }
}

impl Stopping {
    /// Raise the stop, and wake everything waiting on it.
    pub fn raise(&self) {
        // Stored and announced under the lock a waiter checks it under, so
        // a waiter about to wait cannot miss the wake.
        let inner = &self.0;
        let _held = inner.lock.lock().unwrap_or_else(PoisonError::into_inner);
        inner.raised.store(true, Ordering::Release);
        inner.wake.notify_all();
    }

    /// Whether the stop is raised.
    #[must_use]
    pub fn raised(&self) -> bool {
        self.0.raised.load(Ordering::Acquire)
    }

    /// A word a resting Location may be told by ([`Stopping::rest`]).
    #[must_use]
    pub fn nudge(&self) -> Nudge {
        Nudge {
            stopping: self.clone(),
            told: Arc::default(),
        }
    }

    /// Wait `rest`, or until the stop is raised, whichever is first; say
    /// whether it is raised.
    #[must_use]
    pub fn wait(&self, rest: Duration) -> bool {
        self.rest(rest, None)
    }

    /// Wait `rest`, or until the stop is raised or `nudge` told, whichever
    /// is first; say whether the stop is raised. A word told before the
    /// rest began ends it at once, and is heard once.
    #[must_use]
    pub fn rest(&self, rest: Duration, nudge: Option<&Nudge>) -> bool {
        let told = || nudge.is_some_and(|nudge| nudge.told.swap(false, Ordering::AcqRel));
        if rest.is_zero() || told() {
            return self.raised();
        }
        let inner = &self.0;
        let held = inner.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = inner
            .wake
            .wait_timeout_while(&inner.lock, held, rest, |()| !self.raised() && !told());
        self.raised()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn a_wait_ends_when_its_rest_is_over_and_says_the_stop_is_not_raised() {
        let stopping = Stopping::default();
        assert!(!stopping.wait(Duration::from_millis(1)));
        assert!(!stopping.wait(Duration::ZERO));
        assert!(!stopping.raised());
    }

    #[test]
    fn a_raise_wakes_a_wait_of_an_hour() {
        let stopping = Stopping::default();
        let (waiting, told) = mpsc::channel();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                waiting.send(()).expect("told");
                stopping.wait(Duration::from_secs(3600))
            });
            told.recv().expect("the waiter runs");
            stopping.raise();
            // Joined, it was woken: an hour's wait would hold the test.
            assert!(waiter.join().expect("the waiter ends"));
        });
        assert!(stopping.wait(Duration::from_secs(3600)), "raised for good");
    }

    #[test]
    fn a_nudge_ends_a_rest_of_an_hour_and_one_told_before_ends_the_next() {
        let stopping = Stopping::default();
        let nudge = stopping.nudge();
        nudge.tell();
        assert!(!stopping.rest(Duration::from_secs(3600), Some(&nudge)));
        let (waiting, told) = mpsc::channel();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                waiting.send(()).expect("told");
                stopping.rest(Duration::from_secs(3600), Some(&nudge))
            });
            told.recv().expect("the waiter runs");
            nudge.tell();
            assert!(!waiter.join().expect("the waiter ends"), "not stopped");
        });
        assert!(
            !stopping.rest(Duration::from_millis(1), Some(&nudge)),
            "heard once"
        );
    }
}
