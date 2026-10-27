//! The Work Process step's dispatching: each queue of a Work Process this
//! node runs read, oldest first, what is due — a Journey bound for it, or
//! one whose timer has come — and each that may go on now taken a turn of
//! on the Work pool.

use std::collections::HashSet;
use std::thread::Scope;
use std::time::{Duration, Instant};

use persist::storage::{DuePart, Held};
use xcore::JourneyId;

use super::turning::{Turned, turn};
use super::{Running, WorkStep};
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use crate::pool::Pool;

/// The most entries of a queue read at once.
const PAGE: u32 = 64;

/// The Work Process step of `runtime` dispatching on its Work pool in
/// `scope` until it is closed: every queue read as it starts, at each
/// `[tuning]` scan, when asked, and when its earliest timer is due.
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
    let mut next_scan = Instant::now();
    loop {
        let (closed, asked) = step.next(next_scan);
        if closed {
            return;
        }
        let now = Instant::now();
        let all = next_scan <= now;
        for running in &step.running {
            if all || asked.contains(&running.queue) {
                scan(&pool, runtime, pickup, running);
            }
        }
        if all {
            next_scan = now + step.scan;
        }
    }
}

impl WorkStep {
    /// Wait until asked, a timer is due, closed or `until`: whether closed,
    /// and the queues to read.
    fn next(&self, until: Instant) -> (bool, Vec<u128>) {
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let wakes = state
                .due
                .iter()
                .map(|(_, at)| *at)
                .chain([until])
                .min()
                .unwrap_or(until);
            if state.closed || !state.asked.is_empty() || wakes <= now {
                break;
            }
            state = self.wake.wait_until(&self.state, state, wakes).0;
        }
        let now = Instant::now();
        let mut asked = std::mem::take(&mut state.asked);
        state.due.retain(|(queue, at)| {
            let due = *at <= now;
            if due && !asked.contains(queue) {
                asked.push(*queue);
            }
            !due
        });
        (state.closed, asked)
    }

    fn noted(&self, queue: u128, after: Duration) {
        let at = Instant::now() + after;
        let mut state = self.lock();
        match state.due.iter_mut().find(|(known, _)| *known == queue) {
            Some((_, known)) => *known = (*known).min(at),
            None => state.due.push((queue, at)),
        }
    }
}

/// `running`'s queue read, what is due taken a turn of on `pool`, each
/// Journey claimed first; one this node holds in a turn already passed
/// over.
fn scan<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    pickup: &'env Pickup,
    running: &'env Running,
) {
    let step = runtime.work;
    let Ok(due) = step
        .storage
        .read_due(running.queue, DuePart::Due, (0, 0), PAGE)
    else {
        return;
    };
    if let Some(next) = due.next_due_unix_nanos {
        let after = u64::try_from(next - due.read_unix_nanos).unwrap_or(0);
        step.noted(running.queue, Duration::from_nanos(after));
    }
    // A Work Process naming a Correlation takes its turns here, in its
    // queue's order, so the place each takes once its Stream heads follows
    // the Ledger's order (`crate::sequence::heading`).
    let to = route::Subscriber::WorkProcess(running.name.clone());
    let sequenced = !crate::sequence::points_of(runtime.sends, &to).is_empty();
    let mut seen = HashSet::new();
    for held in due.held {
        if held.failed || !seen.insert(held.hold.journey) || !step.own(held.hold.journey) {
            continue;
        }
        if sequenced {
            settled(runtime, pickup, running, &held);
        } else {
            take(pool, runtime, pickup, running, held);
        }
    }
}

/// Every Journey due in each queue of `runtime`'s work step taken a turn
/// of, oldest first, on this thread: one scan, as the dispatching does it,
/// with no pool; how each turn ended.
pub fn turn_due(runtime: &Runtime<'_>, pickup: &Pickup) -> Vec<Turned> {
    let step = runtime.work;
    let mut turned = Vec::new();
    for running in &step.running {
        let Ok(due) = step
            .storage
            .read_due(running.queue, DuePart::Due, (0, 0), PAGE)
        else {
            continue;
        };
        for held in due.held.into_iter().filter(|held| !held.failed) {
            turned.push(turn(runtime, pickup, running, &held));
        }
    }
    turned
}

fn take<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    pickup: &'env Pickup,
    running: &'env Running,
    held: Held,
) {
    pool.run(Box::new(move || settled(runtime, pickup, running, &held)));
}

/// A turn of the Journey `held` names taken, and what it ended as told.
fn settled(runtime: &Runtime<'_>, pickup: &Pickup, running: &Running, held: &Held) {
    let step = runtime.work;
    let journey: JourneyId = held.hold.journey;
    let turned = turn(runtime, pickup, running, held);
    match &turned {
        Turned::Failed(why) => step.failed(&format!("{}: {why}", running.name)),
        Turned::Unwritten(why) => step.failed(why),
        _ => {}
    }
    let done = matches!(turned, Turned::Done);
    step.disown(journey, running.queue, done);
    // A turn may have ended what a Stream held a sequence for: what waits
    // behind it in either step may go on now.
    if done {
        runtime.send.rescan();
        step.ask_every();
    }
}
