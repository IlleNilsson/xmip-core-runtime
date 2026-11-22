//! The Work Process step's dispatching: each queue of a Work Process this
//! node runs read a page a round from where its reads have gone, oldest
//! first, what is due — a Message bound for it, or one whose timer has come
//! — and each that may go on now admitted for a turn on the Work pool under
//! a place, each Work Process within its share (ADR-0066, amendments
//! 2026-11-12 and 2026-11-22; `super::admission`, `super::reading`,
//! `super::quantum`).
//!
//! **A round is one quantum per Work Process with something to do**, in
//! rotation, the first of each round moved on by one: who heads a sequence
//! whose head moved handed over, at most a page of a sequence it cut and a
//! page of its read, and no more turns than its share. So a backlog in one
//! Work Process holds back no turn of another, the dispatching reads a page
//! before its first turn however long a backlog is, and a Message behind a
//! head waits there, kept, unread, until the head moves.
//!
//! **A scan and a timer come due on the step's Clock** (ADR-0068,
//! amendment 2026-11-15): kept as its readings, waited for in real time,
//! and judged on a reading taken after the wait. The scan reads each head
//! it keeps Messages behind and what arrived, never its queue again.

use std::thread::Scope;
use std::time::Duration;

use xcore::clock::{between, nanos};

use super::WorkStep;
use super::admission::share;
use super::quantum::quantum;
use super::reading;
use super::turning::{Turned, turn};
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use crate::pool::Pool;

/// The Work Process step of `runtime` dispatching on its Work pool in
/// `scope` until it is closed: every queue read as it starts and on at each
/// `[tuning] work_scan`, one read when asked — another node put a Message
/// in it among them, read from what is due in it as the wake brought it —
/// a head it keeps Messages behind handed over once it moves, and a queue
/// read when its earliest timer is due; a page of each a round.
pub fn dispatch<'scope, 'env>(
    scope: &'scope Scope<'scope, 'env>,
    runtime: &'env Runtime<'env>,
    pickup: &'env Pickup,
) {
    let step = runtime.work;
    if step.running.is_empty() {
        return;
    }
    let pool = Pool::new(scope, step.limits);
    // Each queue another node puts a Message in, read at once; the scan of
    // them all stays, at its interval, the bound on one wait.
    let queues: Vec<u128> = step.running.iter().map(|running| running.queue).collect();
    scope.spawn(move || {
        let woken = |queue, woken| step.woken(queue, woken);
        step.watch.run(
            step.storage.as_ref(),
            (&queues, step.scan),
            step.clock.as_ref(),
            &woken,
        );
    });
    let mut next_scan = step.clock.monotonic_nanos();
    while let Some(round) = step.next(next_scan) {
        for &at in &round.order {
            quantum(
                &pool,
                (runtime, pickup),
                (&step.running[at], at),
                round.share,
            );
        }
        if round.all {
            next_scan = step
                .clock
                .monotonic_nanos()
                .saturating_add(nanos(step.scan));
            step.lock().scans += 1;
        }
    }
}

/// One round of the dispatching: the Work Processes that read, in the
/// order they read, each one's share of the Work pool, and whether every
/// queue was asked afresh by the scan.
struct Round {
    order: Vec<usize>,
    share: usize,
    all: bool,
}

impl WorkStep {
    /// Wait until a reading goes on, a timer is due, it is closed or
    /// `until`, a reading of its clock, and the round to dispatch; `None`
    /// once closed. Where `until` has passed every reading is asked afresh:
    /// the scan of every queue.
    fn next(&self, until: i128) -> Option<Round> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return None;
            }
            let now = self.clock.monotonic_nanos();
            let wakes = state.wakes(until);
            if wakes <= now || state.readings.iter().any(|reading| reading.goes_on()) {
                break;
            }
            state = self
                .wake
                .wait_timeout(&self.state, state, between(now, wakes))
                .0;
        }
        let now = self.clock.monotonic_nanos();
        let due = state.came(now);
        for (at, running) in self.running.iter().enumerate() {
            if due.contains(&running.queue) {
                state.readings[at].asked(None);
            }
        }
        let all = until <= now;
        if all {
            for reading in &mut state.readings {
                reading.afresh();
            }
        }
        let busy = state
            .readings
            .iter()
            .filter(|reading| reading.wants())
            .count();
        let count = state.readings.len();
        let first = state.first % count.max(1);
        let order = (0..count)
            .map(|n| (first + n) % count)
            .filter(|at| state.readings[*at].goes_on())
            .collect();
        state.first = (first + 1) % count.max(1);
        Some(Round {
            order,
            share: share(self.limits.most, busy),
            all,
        })
    }

    /// `queue` has a timer due `after` from now, as a read of it showed:
    /// read again then, unless one is due sooner.
    pub(super) fn noted(&self, queue: u128, after: Duration) {
        let at = self.clock.monotonic_nanos().saturating_add(nanos(after));
        let mut state = self.lock();
        match state.due.iter_mut().find(|(known, _)| *known == queue) {
            Some((_, known)) => *known = (*known).min(at),
            None => state.due.push((queue, at)),
        }
    }
}

impl super::State {
    /// When the dispatching next has something to do, a reading of the
    /// step's clock: the earliest timer due, or `until`, the next scan.
    fn wakes(&self, until: i128) -> i128 {
        self.due
            .iter()
            .map(|(_, at)| *at)
            .chain([until])
            .min()
            .unwrap_or(until)
    }

    /// The queues whose timer came by `now`, taken off what is due.
    fn came(&mut self, now: i128) -> Vec<u128> {
        let mut due = Vec::new();
        self.due.retain(|(queue, at)| {
            let came = *at <= now;
            if came {
                due.push(*queue);
            }
            !came
        });
        due
    }
}

/// Every Message due in each queue of `runtime`'s work step taken a turn
/// of, oldest first, on this thread: each queue read wholly, with no pool
/// and no admission; how each turn ended. A test's, its queue its own.
pub fn turn_due(runtime: &Runtime<'_>, pickup: &Pickup) -> Vec<Turned> {
    let step = runtime.work;
    let mut turned = Vec::new();
    for running in &step.running {
        for held in reading::wholly(step, running.queue)
            .into_iter()
            .filter(|held| !held.failed)
        {
            turned.push(turn(runtime, pickup, running, &held));
        }
    }
    turned
}

#[cfg(test)]
mod tests {
    use xcore::Clock;
    use xcore::clock::Stepped;

    use super::super::State;
    use super::*;

    #[test]
    fn a_timer_comes_due_on_the_steps_clock_and_the_earliest_wakes_the_dispatching() {
        let clock = Stepped::default();
        let after = |span: Duration| clock.monotonic_nanos() + nanos(span);
        let mut state = State {
            due: vec![
                (7, after(Duration::from_secs(5))),
                (8, after(Duration::from_secs(9))),
            ],
            ..State::default()
        };
        let scan = after(Duration::from_mins(1));
        assert_eq!(state.wakes(scan), nanos(Duration::from_secs(5)));
        let short = Duration::from_secs(5).checked_sub(Duration::from_nanos(1));
        clock.pass(short.expect("seconds"));
        assert_eq!(state.came(clock.monotonic_nanos()), [] as [u128; 0]);
        clock.pass(Duration::from_nanos(1));
        assert_eq!(state.came(clock.monotonic_nanos()), [7], "due at its span");
        assert_eq!(state.wakes(scan), nanos(Duration::from_secs(9)));
        clock.pass(Duration::from_mins(1));
        assert_eq!(state.came(clock.monotonic_nanos()), [8]);
        assert_eq!(state.wakes(scan), scan, "the scan, nothing else due");
    }
}
