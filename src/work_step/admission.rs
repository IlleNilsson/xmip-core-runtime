//! Admission to the Work pool: the one door every turn of the Work Process
//! step goes through (ADR-0066, amendment 2026-11-12), as the send step's
//! admission is its own.
//!
//! **What the step holds is bounded by the pool's threads.** A Journey is
//! taken for a turn only under a place in the Work pool: the turns this
//! node holds, queued in the pool or running, are never more than the
//! pool's most threads, so the pool's queue never holds more than it can
//! run — the bulkhead of ADR-0018 clause 11. **Each Work Process with work
//! holds no more than its share**, the pool's places divided among them
//! ([`share`]): one alone has the whole pool, and a backlog in one holds
//! back another's first turn by one turn at most, never by the backlog.
//! What has no place stays durable and unclaimed in its queue, read on from
//! there the moment a turn ends (`super::reading`). Until 2026-11-12 a queue
//! was read wholly into memory and every entry of it handed to the pool,
//! however many.
//!
//! **However a turn ends, its place is given back** ([`Owning`]). A turn
//! that unwound past its own catch (`super::turning`) is audited and left
//! to its claim's lapse, taken up again by a later read; until 2026-11-12
//! it stayed owned here and every read passed it over until the node
//! restarted.

use xcore::JourneyId;

use super::{State, WorkStep};

/// What an admission answered.
pub(super) enum Admitted<'a> {
    /// A place in the Work pool, owned until the guard is dropped.
    Turn(Owning<'a>),
    /// In a turn on this node already: moved past.
    Held,
    /// No place: in the pool, or in its Work Process's share.
    Full,
}

/// A Journey this node holds in a turn, from its admission until its turn
/// ends, however it ends: its place in the Work pool and its local
/// ownership are given back on every exit, and a turn that unwound is
/// audited and left to its claim's lapse, so a later read takes it up.
pub(super) struct Owning<'a> {
    step: &'a WorkStep,
    journey: JourneyId,
    /// Its Work Process, by its place in `WorkStep::running`.
    at: usize,
    /// How many turns this node had written as it was admitted.
    since: u64,
    /// Set once its turn returned: whether it was written.
    ended: Option<bool>,
}

impl Owning<'_> {
    /// The turn ended by its own word, `done` where it was written.
    pub(super) fn ended(mut self, done: bool) {
        self.ended = Some(done);
    }
}

impl Drop for Owning<'_> {
    fn drop(&mut self) {
        let done = self.ended.unwrap_or_else(|| {
            self.step.unwinding(self.journey, self.at);
            false
        });
        self.step.disown(self.journey, self.at, (done, self.since));
    }
}

impl WorkStep {
    /// `journey`, of the Work Process at `at`, admitted for a turn where the
    /// pool, and that Work Process's `share` of it, has a place.
    pub(super) fn admit(&self, journey: JourneyId, at: usize, share: usize) -> Admitted<'_> {
        let mut state = self.lock();
        if state.owned.contains(&journey) {
            return Admitted::Held;
        }
        let full = state.owned.len() >= self.limits.most.max(1);
        if full || state.readings[at].held >= share {
            return Admitted::Full;
        }
        state.owned.insert(journey);
        state.readings[at].held += 1;
        Admitted::Turn(Owning {
            step: self,
            journey,
            at,
            since: state.written,
            ended: None,
        })
    }

    /// `journey`, of the Work Process at `at`, let go of after its turn,
    /// `done` where it was written, admitted since this node had written
    /// `since` turns; its place freed, so every reading that waited for one
    /// reads on.
    fn disown(&self, journey: JourneyId, at: usize, (done, since): (bool, u64)) {
        let mut state = self.lock();
        state.owned.remove(&journey);
        let reading = &mut state.readings[at];
        reading.held = reading.held.saturating_sub(1);
        if done {
            state.written += 1;
        }
        // After a written turn the next of its queue may go on now. One
        // that waits is read again only where another turn was written
        // while it was held — what it waited for may have moved on, and the
        // read that turn asked passed over it while held here (found
        // 2026-11-12, once a scan no longer came every second); else the
        // next written turn's read finds it: never a loop of reads.
        if done || state.written != since {
            state.readings[at].asked(None);
        }
        state.freed();
        drop(state);
        self.wake.notify_all();
    }

    /// The turn of `journey`, of the Work Process at `at`, unwound past its
    /// own catch: counted and audited at the stage `process`, its claim, if
    /// one was taken, left to lapse.
    fn unwinding(&self, journey: JourneyId, at: usize) {
        self.lock().unwound += 1;
        let name = self
            .running
            .get(at)
            .map_or("", |running| running.name.as_str());
        self.failed(&format!(
            "{name}: the turn of the Journey {journey} unwound before it ended; \
             taken up again once its claim lapses"
        ));
    }
}

impl State {
    /// A place in the Work pool freed: every reading that waited for one
    /// reads on.
    fn freed(&mut self) {
        for reading in &mut self.readings {
            reading.freed();
        }
    }
}

/// The places of a pool of `most` shared among the `busy` Work Processes
/// with work: one alone has them all, and each has one at least.
pub(super) fn share(most: usize, busy: usize) -> usize {
    most.max(1).div_ceil(busy.max(1))
}

#[cfg(test)]
mod tests {
    use super::share;

    #[test]
    fn the_pool_is_shared_among_the_work_processes_with_work() {
        assert_eq!(share(8, 1), 8, "one alone has the whole pool");
        assert_eq!(share(8, 3), 3);
        assert_eq!(share(2, 5), 1, "each has one at least");
        assert_eq!(share(0, 0), 1);
    }
}
