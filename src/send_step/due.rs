//! When a queue's earliest retry is due, kept per queue rather than per
//! Message waiting (the owner, 2026-10-16; open problem 43): what the send
//! step wakes for, and how many wait, as each queue's last read showed and
//! as each hand-on since that read began noted.
//!
//! **Counted by the newest read** (corrected 2026-11-12). How many wait is
//! what the latest begun of two reads said: a read of the whole queue, and
//! the read of its retries a hand-on that set a Message waiting makes once
//! Xmip Storage took it (`super::reading::waiting`), which begins after that
//! hand-on and so counts it, once. A read begun before the one that set the
//! count says nothing of how many wait, however late it ends. Until
//! 2026-11-12 a read's count replaced the count and each hand-on added one
//! to it, so a read begun before a hand-on landed lost it and one that
//! ended between a hand-on and its note counted it twice; that day's first
//! correction kept the count no lower than the hand-ons noted since the
//! read began, which said three where three were found and a fourth noted.

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
    /// When the read that set `waiting` began.
    counted: Option<Instant>,
}

impl Due {
    /// None waiting yet, in the queue of the Send Port `port`.
    pub(super) fn of(port: &str) -> Self {
        Self {
            port: port.to_string(),
            at: None,
            waiting: 0,
            noted: None,
            counted: None,
        }
    }

    /// Woken for at `at`, the earliest kept: a retry the queue's read found
    /// not yet due, which the read counts by Xmip Storage's count of them
    /// (`super::reading`).
    pub(super) fn wakes_at(&mut self, at: Instant) {
        self.at = Some(earlier(self.at, at));
    }

    /// `waiting` wait, as a read begun at `began` found them: kept where no
    /// read begun later counted them.
    pub(super) fn count(&mut self, began: Instant, waiting: u64) {
        if self.counted.is_none_or(|counted| began >= counted) {
            self.waiting = waiting;
            self.counted = Some(began);
        }
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
    /// finds in Xmip Storage. When it began.
    pub(super) fn reading(&self, queue: u128) -> Instant {
        let began = Instant::now();
        if let Some(due) = self.lock().due.get_mut(&queue) {
            due.noted = None;
        }
        began
    }

    /// A hand-on that set a Message of `queue`, the queue of the Send Port
    /// `port`, waiting for a retry due at `at`, once Xmip Storage took it:
    /// woken for at that time, kept across a read under way, and how many
    /// wait read now, after it (`super::reading::waiting`); where Xmip
    /// Storage does not answer, one more than were counted.
    pub(super) fn noted(&self, (port, queue): (&str, u128), at: Instant) {
        self.lock()
            .due
            .entry(queue)
            .or_insert_with(|| Due::of(port))
            .wakes(at);
        let began = Instant::now();
        let read = super::reading::waiting(self, queue);
        let mut state = self.lock();
        let due = state.due.entry(queue).or_insert_with(|| Due::of(port));
        match read {
            Ok(waiting) => due.count(began, waiting),
            Err(_) => due.waiting += 1,
        }
        drop(state);
        self.wake.notify_all();
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

    /// What a scan of `queue`, begun at `began`, found waiting, `waits`: the
    /// queue's due time as it found it where it read `whole` the queue —
    /// with every due time a hand-on noted since the read began — and how
    /// many wait where no read begun later counted them; else the earlier
    /// of its due time and what it found.
    pub(super) fn waited(&self, queue: u128, (waits, began): (Due, Instant), whole: bool) {
        let mut state = self.lock();
        let due = state
            .due
            .entry(queue)
            .or_insert_with(|| Due::of(&waits.port));
        if whole {
            let noted = due.noted;
            due.at = waits.at;
            due.noted = None;
            due.count(began, waits.waiting);
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
        let (_, _, (asked, _)) = self.next(Instant::now() + std::time::Duration::from_secs(10));
        let late = Instant::now().saturating_duration_since(due);
        assert_eq!(asked, vec![QUEUE], "woken for the retry");
        late
    }

    /// How many scans of every queue it made: what a test waits for before
    /// another node publishes, so only a wake can send what it publishes.
    #[must_use]
    pub fn scans(&self) -> u64 {
        self.lock().scans
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use persist::fixture::crowd::{QUEUE, crowded};
    use persist::storage::XmipStorage;

    use super::Due;
    use crate::send_step::SendStep;
    use crate::send_step::fixture::step;
    use crate::tuning::Tuning;

    /// A send step over a Storage node holding three Messages due in
    /// [`QUEUE`], `waiting` waiting an hour for a retry and one failed.
    fn over(waiting: u128) -> SendStep {
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node_scope(0);
        let storage: Arc<dyn XmipStorage> = Arc::new(crowded(&node, waiting, 1));
        SendStep::new((&cluster.scope(), &node), storage, &Tuning::default(), None)
    }

    /// A hand-on that set a Message of [`QUEUE`] waiting an hour, noted.
    fn noted(step: &SendStep) {
        step.noted(("Out", QUEUE), Instant::now() + Duration::from_secs(3600));
    }

    /// What a read of the whole queue finds: `waiting` waiting.
    fn found(waiting: u64) -> Due {
        let mut found = Due::of("Out");
        found.waiting = waiting;
        found
    }

    fn waiting(step: &SendStep) -> u64 {
        step.lock().due[&QUEUE].waiting
    }

    /// A read of the whole queue that passed a Message's place before its
    /// hand-on landed, answering after the hand-on noted its due time: the
    /// node still wakes for that due time, exactly, not at the next scan,
    /// and the queue is read again then.
    #[test]
    fn a_hand_on_during_a_read_is_woken_for_at_its_due_time() {
        let step = step();
        let began = step.reading(QUEUE);
        let due = Instant::now() + Duration::from_millis(20);
        step.noted(("Out", QUEUE), due);
        step.waited(QUEUE, (Due::of("Out"), began), true);
        let scan = Instant::now() + Duration::from_secs(10);

        assert_eq!(step.lock().wakes_at(scan), due, "woken at its due time");
        let (closed, _, (asked, _)) = step.next(scan);
        let woke = Instant::now();

        assert!(!closed);
        assert_eq!(asked, vec![QUEUE], "the queue is read again");
        assert!(woke >= due, "not before it is due");
        assert!(woke < scan, "nor at the next scan");
    }

    /// How many wait is every retry Xmip Storage holds less those due, the
    /// failed apart, read past the Messages due since they were held.
    #[test]
    fn how_many_wait_is_every_retry_held_but_those_due_and_the_failed() {
        let step = over(4);
        let read = crate::send_step::reading::waiting(&step, QUEUE);
        assert_eq!(read.expect("answered"), 4);
    }

    /// Two found waiting by a read before a third hand-on landed, and that
    /// hand-on noted: three wait, as Xmip Storage holds them after it.
    #[test]
    fn a_hand_on_after_a_read_that_found_two_waiting_counts_three() {
        let step = over(3);
        let began = step.reading(QUEUE);
        step.waited(QUEUE, (found(2), began), true);
        assert_eq!(waiting(&step), 2, "as the read found");
        noted(&step);
        assert_eq!(waiting(&step), 3, "the one it set waiting counted once");
    }

    /// A read begun before a hand-on's count, however late it ends, says
    /// nothing of how many wait; one begun after it does.
    #[test]
    fn a_read_begun_before_the_count_says_nothing_of_how_many_wait() {
        let step = over(2);
        let stale = step.reading(QUEUE);
        noted(&step);
        step.waited(QUEUE, (found(1), stale), true);
        assert_eq!(waiting(&step), 2, "the newer count kept");
        let fresh = step.reading(QUEUE);
        step.waited(QUEUE, (found(5), fresh), true);
        assert_eq!(waiting(&step), 5, "a newer read's count");
    }

    /// What a hand-on noted before a read began, the read finds: a read of
    /// the whole queue that found nothing waiting forgets it.
    #[test]
    fn a_read_begun_after_a_hand_on_answers_for_it() {
        let step = step();
        noted(&step);
        let began = step.reading(QUEUE);
        step.waited(QUEUE, (Due::of("Out"), began), true);

        assert_eq!(step.lock().due[&QUEUE].at, None);
        assert_eq!(waiting(&step), 0);
    }
}
