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

use super::quantum::Quantum;
use super::{State, WorkStep};
use crate::sequence::Queued;

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
    /// What was taken up: taken up again where its turn unwinds.
    queued: Option<Queued>,
}

impl Owning<'_> {
    /// The guard of a turn of `queued`.
    pub(super) fn of(mut self, queued: Queued) -> Self {
        self.queued = Some(queued);
        self
    }

    /// The turn ended by its own word, `done` where it was written.
    pub(super) fn ended(mut self, done: bool) {
        self.ended = Some(done);
    }
}

impl Drop for Owning<'_> {
    /// Its place given back first, then a turn that unwound counted: what
    /// reads it unwound reads it let go of, so a read asked then takes it up
    /// (2026-11-15: counted first, a read asked between the two passed it
    /// over as still in a turn here, and nothing asked again).
    fn drop(&mut self) {
        self.step.disown(
            self.journey,
            self.at,
            (self.ended == Some(true), self.since),
        );
        if self.ended.is_none() {
            self.step
                .unwinding(self.journey, self.at, self.queued.take());
        }
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
            queued: None,
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
        // After a written turn who heads its sequences now is handed over
        // (`super::quantum`), and what it published wakes the step's watch.
        // One that waits is taken up again only where another turn was
        // written while it was held — what it waited for may have moved on,
        // and what that turn moved was told while it was held here (found
        // 2026-11-12, once a scan no longer came every second): never a loop
        // of turns.
        if !done && state.written != since {
            state.readings[at].again_now(journey);
        }
        state.freed();
        drop(state);
        self.wake.notify_all();
    }

    /// How the quantum of the Work Process at `at`, within `share`, went,
    /// `went`, kept for its next. One that found no place waits for one only
    /// while none is free, as the lock its turns give their places back
    /// under says: every turn its round admitted may have ended before the
    /// round was kept, and then none is left to free one (found 2026-11-15: a
    /// pass behind a page another node held stood waiting for good).
    pub(super) fn round_went(&self, (at, share): (usize, usize), went: Quantum) {
        let mut state = self.lock();
        let full = state.owned.len() >= self.limits.most.max(1);
        let room = !full && state.readings[at].held < share;
        let reading = &mut state.readings[at];
        reading.went(went.went, (went.fresh, went.refill));
        for queued in went.ready {
            reading.ready(queued);
        }
        for queued in went.loose {
            reading.park(queued);
        }
        if went.starved {
            reading.starve();
        }
        if room {
            reading.freed();
        }
    }

    /// The turn of `journey`, of the Work Process at `at`, unwound past its
    /// own catch: counted and audited at the stage `process`, its claim, if
    /// one was taken, left to lapse, and what was taken up, `queued`, taken
    /// up again in the next round.
    fn unwinding(&self, journey: JourneyId, at: usize, queued: Option<Queued>) {
        {
            let mut state = self.lock();
            state.unwound += 1;
            if let Some(queued) = queued {
                state.readings[at].ready(queued);
            }
        }
        self.wake.notify_all();
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
    use std::sync::Arc;
    use std::time::Duration;

    use persist::fixture::Memory;
    use persist::storage::{Embedded, XmipStorage};
    use secret::{Held, KekName};

    use super::super::reading::{Reading, Went};
    use super::*;
    use crate::pool::Limits;

    /// A quantum whose read found no place at the entry at its third place.
    fn starved() -> Quantum {
        Quantum {
            went: Some(Went::Starved((0, 2))),
            ..Quantum::default()
        }
    }

    #[test]
    fn the_pool_is_shared_among_the_work_processes_with_work() {
        assert_eq!(share(8, 1), 8, "one alone has the whole pool");
        assert_eq!(share(8, 3), 3);
        assert_eq!(share(2, 5), 1, "each has one at least");
        assert_eq!(share(0, 0), 1);
    }

    /// A step of a pool of `most` places, one Work Process's queue being
    /// read from the start.
    fn step(most: usize) -> WorkStep {
        let keys = Held::new(secret::fixture::Memory::default());
        let kek = KekName::new("storage").expect("a name");
        let node = Embedded::open(
            Memory::default(),
            Memory::default(),
            Memory::default(),
            &keys,
            &kek,
        );
        let storage: Arc<dyn XmipStorage> = Arc::new(node.expect("opened"));
        let cluster = configure::fixture::test_cluster();
        let limits = Limits {
            most,
            idle: Duration::from_secs(60),
        };
        let step = WorkStep::new(
            (&cluster.scope(), &cluster.node_scope(0)),
            storage,
            (limits, super::super::WORK_SCAN),
            None,
            Vec::new(),
        );
        let mut reading = Reading::default();
        reading.asked(None);
        let _ = reading.reads();
        step.lock().readings.push(reading);
        step
    }

    fn turn(admitted: Admitted<'_>) -> Owning<'_> {
        match admitted {
            Admitted::Turn(owning) => owning,
            Admitted::Held | Admitted::Full => panic!("admitted for a turn"),
        }
    }

    fn reads_on(step: &WorkStep) -> bool {
        step.lock().readings[0].goes_on()
    }

    #[test]
    fn a_round_that_found_no_place_reads_on_where_its_turns_all_ended_before_it_was_kept() {
        let step = step(2);
        let ids = [1, 2, 3].map(JourneyId::new);
        let first = turn(step.admit(ids[0], 0, 2));
        let second = turn(step.admit(ids[1], 0, 2));
        assert!(matches!(step.admit(ids[2], 0, 2), Admitted::Full));
        // Both turns end before the round that admitted them is kept.
        first.ended(false);
        second.ended(false);
        step.round_went((0, 2), starved());
        assert!(
            reads_on(&step),
            "a place is free, and no turn left to free one"
        );

        // A round that finds every place held waits, until a turn ends.
        let _ = step.lock().readings[0].reads();
        let first = turn(step.admit(ids[0], 0, 2));
        let second = turn(step.admit(ids[1], 0, 2));
        step.round_went((0, 2), starved());
        assert!(!reads_on(&step), "every place held: it waits for one");
        first.ended(false);
        assert!(reads_on(&step), "a turn ended: it reads on");
        second.ended(false);
    }
}
