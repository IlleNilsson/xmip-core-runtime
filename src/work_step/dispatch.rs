//! The Work Process step's dispatching: each queue of a Work Process this
//! node runs read a page a round from where its pass stands, oldest first,
//! what is due — a Message bound for it, or one whose timer has come — and
//! each that may go on now admitted for a turn on the Work pool under a
//! place, each Work Process within its share (ADR-0066, amendment
//! 2026-11-12; `super::admission`, `super::reading`).
//!
//! **A round is one quantum per Work Process with something to read**, in
//! rotation, the first of each round moved on by one: at most its head
//! page, where it was asked while its pass was under way, and one page of
//! its pass, and no more turns than its share. So a backlog in one Work
//! Process holds back no turn of another, and the dispatching reads a page
//! before its first turn however long a backlog is.

use std::collections::HashSet;
use std::panic::{self, AssertUnwindSafe};
use std::thread::Scope;
use std::time::{Duration, Instant};

use persist::storage::Held;

use super::admission::{Admitted, Owning, share};
use super::reading::{self, PageFrom, Went};
use super::turning::{Turned, turn};
use super::{Running, WorkStep};
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use crate::pool::Pool;

/// The Work Process step of `runtime` dispatching on its Work pool in
/// `scope` until it is closed: every queue read as it starts and at each
/// `[tuning] work_scan`, one read when asked — another node put a Message
/// in it among them, read from what is due in it as the wake brought it —
/// and when its earliest timer is due; a page of each a round.
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
        step.watch
            .run(step.storage.as_ref(), &queues, step.scan, &woken);
    });
    let mut next_scan = Instant::now();
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
            next_scan = Instant::now() + step.scan;
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
    /// `until`, and the round to dispatch; `None` once closed. Where `until`
    /// has passed every reading is asked afresh: the scan of every queue.
    fn next(&self, until: Instant) -> Option<Round> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return None;
            }
            let now = Instant::now();
            let wakes = state
                .due
                .iter()
                .map(|(_, at)| *at)
                .chain([until])
                .min()
                .unwrap_or(until);
            if wakes <= now || state.readings.iter().any(|reading| reading.goes_on()) {
                break;
            }
            state = self.wake.wait_until(&self.state, state, wakes).0;
        }
        let now = Instant::now();
        let mut due = Vec::new();
        state.due.retain(|(queue, at)| {
            let came = *at <= now;
            if came {
                due.push(*queue);
            }
            !came
        });
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
        let at = Instant::now() + after;
        let mut state = self.lock();
        match state.due.iter_mut().find(|(known, _)| *known == queue) {
            Some((_, known)) => *known = (*known).min(at),
            None => state.due.push((queue, at)),
        }
    }
}

/// How the entries of one page were offered: each, or up to the one at
/// this place, which found no place.
enum Offered {
    Each,
    Full((u64, u64)),
}

/// The Work Process `running`, at `at`, read for one round within `share`
/// of the Work pool: one page of its pass and its head, where it was asked
/// while its pass was under way; each entry that may go on now admitted and
/// taken a turn of. Where no place is left its pass stops on that entry and
/// waits for one, and a head that finds none is left to the pass from the
/// start its ask began.
///
/// On the pool the pass goes first, the head taking what places are left,
/// so the pass moves on every round a place is free: a head read first,
/// whose page began with turns that only wait, took every place as each
/// freed and starved the pass behind it for good (found 2026-11-12 by
/// `tests/ledger/work_bounded.rs`). A Work Process whose turns are taken on
/// this thread reads its head first, in its queue's order: each of its turns
/// gives its place back before the next is offered.
fn quantum<'env>(
    pool: &Pool<'_, 'env>,
    on: (&'env Runtime<'env>, &'env Pickup),
    (running, at): (&'env Running, usize),
    share: usize,
) {
    let step = on.0.work;
    let read = step.lock().readings[at].reads();
    // A Work Process naming a Correlation takes its turns here, in its
    // queue's order, so the place each takes once its Stream heads follows
    // the Ledger's order (`crate::sequence::heading`).
    let to = route::Subscriber::WorkProcess(running.name.clone());
    let sequenced = !crate::sequence::points_of(on.0.sends, &to).is_empty();
    let mut offering = Offering {
        pool,
        on,
        running: (running, at),
        share,
        sequenced,
        seen: HashSet::new(),
    };
    let (went, headed) = if sequenced {
        let headed = read.head.map(|first| offering.read(((0, 0), first)));
        (offering.after(headed, read.pass), headed)
    } else {
        let went = read.pass.map(|from| offering.read(from));
        (
            went,
            offering.after(went, read.head.map(|first| ((0, 0), first))),
        )
    };
    let mut state = step.lock();
    let reading = &mut state.readings[at];
    if let Some(went) = went {
        reading.went(went);
    }
    match headed {
        Some(Went::Unanswered) => reading.went(Went::Unanswered),
        Some(Went::Starved(_)) => {
            reading.headed();
            reading.starve();
        }
        Some(Went::On(_)) => reading.headed(),
        None => {}
    }
}

/// What one quantum offers its entries to: the pool, the Work Process
/// and its share, and what it offered already.
struct Offering<'p, 'scope, 'env> {
    pool: &'p Pool<'scope, 'env>,
    on: (&'env Runtime<'env>, &'env Pickup),
    running: (&'env Running, usize),
    share: usize,
    sequenced: bool,
    seen: HashSet<xcore::JourneyId>,
}

impl Offering<'_, '_, '_> {
    /// The page `then` read and offered where the one read before it,
    /// `first`, was offered whole or none was read: how it went.
    fn after(&mut self, first: Option<Went>, then: Option<PageFrom>) -> Option<Went> {
        match first {
            None | Some(Went::On(_)) => then.map(|from| self.read(from)),
            Some(_) => None,
        }
    }

    /// One page of its queue read `from` where it stands — with the page a
    /// wake brought, where it did — and offered: how it went.
    fn read(&mut self, from: PageFrom) -> Went {
        let (running, _) = self.running;
        match reading::page(self.on.0.work, running.queue, from) {
            Ok((held, next)) => match self.offer(held) {
                Offered::Each => Went::On(next),
                Offered::Full(stays) => Went::Starved(stays),
            },
            Err(_) => Went::Unanswered,
        }
    }

    /// Each of `page` offered in queue order: one that failed, was offered
    /// already or is in a turn here moved past, each other admitted and
    /// taken a turn of, until one finds no place.
    fn offer(&mut self, page: Vec<Held>) -> Offered {
        let ((runtime, pickup), (running, at)) = (self.on, self.running);
        for held in page {
            if held.failed || !self.seen.insert(held.hold.journey) {
                continue;
            }
            let owning = match runtime.work.admit(held.hold.journey, at, self.share) {
                Admitted::Turn(owning) => owning,
                Admitted::Held => continue,
                Admitted::Full => return Offered::Full((held.due_at(), held.sequence)),
            };
            if self.sequenced {
                // Its turn on this thread, which outlives a panic in it as
                // the pool's threads do: the guard gives its place back.
                let turned = || settled((runtime, pickup), running, (&held, owning));
                let _ = panic::catch_unwind(AssertUnwindSafe(turned));
            } else {
                take(self.pool, (runtime, pickup), running, (held, owning));
            }
        }
        Offered::Each
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

fn take<'env>(
    pool: &Pool<'_, 'env>,
    on: (&'env Runtime<'env>, &'env Pickup),
    running: &'env Running,
    (held, owning): (Held, Owning<'env>),
) {
    pool.run(Box::new(move || {
        settled(on, running, (&held, owning));
    }));
}

/// A turn of the Message `held` names taken under the place `owning`
/// holds, what it ended as told, and the place given back.
fn settled(
    (runtime, pickup): (&Runtime<'_>, &Pickup),
    running: &Running,
    (held, owning): (&Held, Owning<'_>),
) {
    let step = runtime.work;
    let turned = turn(runtime, pickup, running, held);
    match &turned {
        Turned::Failed(why) => step.failed(&format!("{}: {why}", running.name)),
        Turned::Unwritten(why) => step.failed(why),
        // What it waits on, waited on: its queue read the moment any node
        // moves one (open problem 46, 2026-11-12).
        Turned::Waits { on, .. } if !on.is_empty() => step.watch.wait_on(on, running.queue),
        _ => {}
    }
    let done = matches!(turned, Turned::Done);
    owning.ended(done);
    // A turn may have ended what a Stream held a sequence for: what waits
    // behind it in either step may go on now.
    if done {
        runtime.send.rescan();
        step.ask_every();
    }
}
