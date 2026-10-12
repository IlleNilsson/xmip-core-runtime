//! A node's stop, raised once and heard at once: by what looks between
//! two pieces of work ([`Stopping::raised`]), and by what waits between
//! them ([`Stopping::wait`]) — a Receive Location resting before it polls
//! again — which the raise wakes rather than leaving it to its time
//! (`runtime-model.md` section 5, *How a receive runs*).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

/// A node's stop: lowered until [`Stopping::raise`], raised for good.
#[derive(Debug, Default)]
pub struct Stopping {
    raised: AtomicBool,
    lock: Mutex<()>,
    wake: Condvar,
}

impl Stopping {
    /// Raise the stop, and wake everything waiting on it.
    pub fn raise(&self) {
        // Stored and announced under the lock a waiter checks it under, so
        // a waiter about to wait cannot miss the wake.
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.raised.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    /// Whether the stop is raised.
    #[must_use]
    pub fn raised(&self) -> bool {
        self.raised.load(Ordering::Acquire)
    }

    /// Wait `rest`, or until the stop is raised, whichever is first; say
    /// whether it is raised.
    #[must_use]
    pub fn wait(&self, rest: Duration) -> bool {
        if rest.is_zero() {
            return self.raised();
        }
        let held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .wake
            .wait_timeout_while(held, rest, |()| !self.raised())
            .unwrap_or_else(PoisonError::into_inner);
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
}
