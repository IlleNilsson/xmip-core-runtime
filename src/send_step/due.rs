//! When a queue's earliest retry is due, kept per queue rather than per
//! Journey waiting (the owner, 2026-10-16; open problem 43): what the send
//! step wakes for, and how many wait, as each queue's last read showed.

use std::time::Instant;
/// When a queue's earliest retry is due, on this node's clock — Xmip
/// Storage's due time read as a duration from when the read was asked — and
/// how many wait for one, as its last read showed: what the node wakes for,
/// one per queue however many wait.
#[derive(Clone, Debug)]
pub(super) struct Due {
    pub(super) port: String,
    pub(super) at: Option<Instant>,
    pub(super) waiting: u64,
}

impl Due {
    /// None waiting yet, in the queue of the Send Port `port`.
    pub(super) fn of(port: &str) -> Self {
        Self {
            port: port.to_string(),
            at: None,
            waiting: 0,
        }
    }

    /// One more waiting, due at `at`: the earliest kept.
    pub(super) fn waits(&mut self, at: Instant) {
        self.at = Some(self.at.map_or(at, |was| was.min(at)));
        self.waiting += 1;
    }
}

impl super::SendStep {
    /// What a scan of `queue` found waiting, `waits`: the queue's due time
    /// and count as it found them where it read `whole` the queue, else the
    /// earlier of its due time and what it found.
    pub(super) fn waited(&self, queue: u128, waits: Due, whole: bool) {
        let mut state = self.lock();
        let due = state
            .due
            .entry(queue)
            .or_insert_with(|| Due::of(&waits.port));
        if whole {
            *due = waits;
        } else if let Some(at) = waits.at {
            due.at = Some(due.at.map_or(at, |was| was.min(at)));
            due.waiting = due.waiting.max(waits.waiting);
        }
        drop(state);
        self.wake.notify_all();
    }
}
