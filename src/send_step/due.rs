//! When a queue's earliest retry is due, kept per queue rather than per
//! Message waiting (the owner, 2026-10-16; open problem 43): what the send
//! step wakes for, and how many wait, as each queue's last read showed and
//! as each hand-on since that read began noted.

use std::time::Instant;
/// When a queue's earliest retry is due, on this node's clock — Xmip
/// Storage's due time read as a duration from when the read was asked, or
/// a hand-on's backoff from when Xmip Storage took it — and how many wait
/// for one, as its last read showed: what the node wakes for, one per
/// queue however many wait.
#[derive(Clone, Debug)]
pub(super) struct Due {
    pub(super) port: String,
    pub(super) at: Option<Instant>,
    pub(super) waiting: u64,
    /// The earliest due time a hand-on noted since the queue's last read
    /// began: a read of the whole queue may have passed its place before
    /// Xmip Storage took that hand-on, so the read's answer does not drop
    /// it. Until 2026-10-16 it did, and a short backoff waited for the
    /// next `[tuning] send_scan`, a second by default, after it was due.
    noted: Option<Instant>,
}

impl Due {
    /// None waiting yet, in the queue of the Send Port `port`.
    pub(super) fn of(port: &str) -> Self {
        Self {
            port: port.to_string(),
            at: None,
            waiting: 0,
            noted: None,
        }
    }

    /// Woken for at `at`, the earliest kept: a retry the queue's read found
    /// not yet due, which the read counts by Xmip Storage's count of them
    /// (`super::reading`).
    pub(super) fn wakes_at(&mut self, at: Instant) {
        self.at = Some(earlier(self.at, at));
    }

    /// One more waiting, due at `at`, as its hand-on noted it once Xmip
    /// Storage took it: kept across the read under way.
    pub(super) fn noted(&mut self, at: Instant) {
        self.waiting += 1;
        self.wakes(at);
    }

    /// Woken for at `at`, kept across the read under way, and not counted:
    /// a retry a scan's claim found not yet due, which the queue's read
    /// counts (`runtime-model.md` section 10, corrected 2026-10-17).
    pub(super) fn wakes(&mut self, at: Instant) {
        self.at = Some(earlier(self.at, at));
        self.noted = Some(earlier(self.noted, at));
    }
}

/// The earlier of `was`, where there is one, and `at`.
fn earlier(was: Option<Instant>, at: Instant) -> Instant {
    was.map_or(at, |was| was.min(at))
}

impl super::State {
    /// When the dispatching wakes with nothing handed or asked: the
    /// earliest retry due in any queue, or `until`, the next scan.
    pub(super) fn wakes_at(&self, until: Instant) -> Instant {
        self.due
            .values()
            .filter_map(|due| due.at)
            .fold(until, Instant::min)
    }
}

impl super::SendStep {
    /// A read of `queue` begins: what a hand-on noted before now, the read
    /// finds in Xmip Storage.
    pub(super) fn reading(&self, queue: u128) {
        if let Some(due) = self.lock().due.get_mut(&queue) {
            due.noted = None;
        }
    }

    /// The retry at a place of `queue`, the queue of the Send Port `port`,
    /// found not yet due under a scan's claim: woken for at `at`.
    pub(super) fn not_due(&self, (port, queue): (&str, u128), at: Instant) {
        self.lock()
            .due
            .entry(queue)
            .or_insert_with(|| Due::of(port))
            .wakes(at);
        self.wake.notify_all();
    }

    /// What a scan of `queue` found waiting, `waits`: the queue's due time
    /// and count as it found them where it read `whole` the queue — with
    /// every due time a hand-on noted since the read began — else the
    /// earlier of its due time and what it found.
    pub(super) fn waited(&self, queue: u128, waits: Due, whole: bool) {
        let mut state = self.lock();
        let due = state
            .due
            .entry(queue)
            .or_insert_with(|| Due::of(&waits.port));
        if whole {
            let noted = due.noted;
            *due = waits;
            if let Some(at) = noted {
                due.at = Some(earlier(due.at, at));
                due.noted = noted;
            }
        } else if let Some(at) = waits.at {
            due.at = Some(earlier(due.at, at));
            due.waiting = due.waiting.max(waits.waiting);
        }
        drop(state);
        self.wake.notify_all();
    }
}

#[cfg(any(test, feature = "test-support"))]
impl super::SendStep {
    /// How late this send step, nothing dispatching it, wakes for a queue's
    /// retry due `after` from now: what the module's timing program holds
    /// to the millisecond rule (`tests/measured`). A test's, never a node's.
    ///
    /// # Panics
    ///
    /// Where the wake asks for another queue than the one due.
    #[must_use]
    pub fn woken_late(&self, after: std::time::Duration) -> std::time::Duration {
        const QUEUE: u128 = 1;
        let due = Instant::now() + after;
        self.lock()
            .due
            .entry(QUEUE)
            .or_insert_with(|| Due::of("Out"))
            .at = Some(due);
        let (_, _, asked) = self.next(Instant::now() + std::time::Duration::from_secs(10));
        let late = Instant::now().saturating_duration_since(due);
        assert_eq!(asked, vec![QUEUE], "woken for the retry");
        late
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::Due;
    use crate::send_step::fixture::step;

    /// A read of the whole queue that passed a Message's place before its
    /// hand-on landed, answering after the hand-on noted its due time: the
    /// node still wakes for that due time, exactly, not at the next scan,
    /// and the queue is read again then.
    #[test]
    fn a_hand_on_during_a_read_is_woken_for_at_its_due_time() {
        let step = step();
        let queue = 1;
        step.reading(queue);
        let due = Instant::now() + Duration::from_millis(20);
        step.lock()
            .due
            .entry(queue)
            .or_insert_with(|| Due::of("Out"))
            .noted(due);
        step.waited(queue, Due::of("Out"), true);
        let scan = Instant::now() + Duration::from_secs(10);

        assert_eq!(step.lock().wakes_at(scan), due, "woken at its due time");
        let (closed, _, asked) = step.next(scan);
        let woke = Instant::now();

        assert!(!closed);
        assert_eq!(asked, vec![queue], "the queue is read again");
        assert!(woke >= due, "not before it is due");
        assert!(woke < scan, "nor at the next scan");
    }

    /// What a hand-on noted before a read began, the read finds: a read of
    /// the whole queue that found nothing waiting forgets it.
    #[test]
    fn a_read_begun_after_a_hand_on_answers_for_it() {
        let step = step();
        let queue = 1;
        let due = Instant::now() + Duration::from_secs(60);
        step.lock()
            .due
            .entry(queue)
            .or_insert_with(|| Due::of("Out"))
            .noted(due);
        step.reading(queue);
        step.waited(queue, Due::of("Out"), true);

        assert_eq!(step.lock().due[&queue].at, None);
    }
}
