//! The Work Process step's dispatching: each queue of a Work Process this
//! node runs read, oldest first, what is due — a Message bound for it, or
//! one whose timer has come — and each that may go on now taken a turn of
//! on the Work pool.

use std::collections::HashSet;
use std::thread::Scope;
use std::time::{Duration, Instant};

use persist::storage::{DuePart, DueQueue, Held};
use xcore::JourneyId;

use super::turning::{Turned, turn};
use super::{Running, WorkStep};
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use crate::pool::Pool;

/// The most entries of a queue read at once: as many as a wake brings.
const PAGE: u32 = crate::queue_watch::DUE;

/// The Work Process step of `runtime` dispatching on its Work pool in
/// `scope` until it is closed: every queue read as it starts and at each
/// `[tuning] work_scan`, one read when asked — another node put a Message
/// in it among them, read from what is due in it as the wake brought it —
/// and when its earliest timer is due.
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
    loop {
        let (closed, asked, mut woken) = step.next(next_scan);
        if closed {
            return;
        }
        let now = Instant::now();
        let all = next_scan <= now;
        for running in &step.running {
            if all || asked.contains(&running.queue) {
                // Read wholly, a queue is read afresh, not from a wake.
                let first = woken
                    .iter()
                    .position(|(queue, _)| *queue == running.queue)
                    .map(|at| woken.swap_remove(at).1)
                    .filter(|_| !all);
                scan(&pool, runtime, pickup, (running, first));
            }
        }
        if all {
            next_scan = now + step.scan;
            step.lock().scans += 1;
        }
    }
}

/// What a step's dispatching wakes to: whether closed, the queues to read,
/// and what is due in those a wake brought it of.
type Next = (bool, Vec<u128>, Vec<(u128, DueQueue)>);

impl WorkStep {
    /// Wait until asked, a timer is due, closed or `until`: whether closed,
    /// the queues to read, and what a wake brought of them.
    fn next(&self, until: Instant) -> Next {
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
        let woken = std::mem::take(&mut state.woken);
        (state.closed, asked, woken)
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

/// `running`'s queue read to its end — from `first`, what is due in it as a
/// wake brought it, where one did — what is due taken a turn of on `pool`,
/// each Message claimed first; one this node holds in a turn already passed
/// over.
fn scan<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    pickup: &'env Pickup,
    (running, first): (&'env Running, Option<DueQueue>),
) {
    let step = runtime.work;
    // A Work Process naming a Correlation takes its turns here, in its
    // queue's order, so the place each takes once its Stream heads follows
    // the Ledger's order (`crate::sequence::heading`).
    let to = route::Subscriber::WorkProcess(running.name.clone());
    let sequenced = !crate::sequence::points_of(runtime.sends, &to).is_empty();
    let mut seen = HashSet::new();
    for held in due(step, running.queue, first) {
        if held.failed || !seen.insert(held.hold.journey) {
            continue;
        }
        let Some(since) = step.own(held.hold.journey) else {
            continue;
        };
        if sequenced {
            settled(runtime, pickup, running, (&held, since));
        } else {
            take(pool, runtime, pickup, running, (held, since));
        }
    }
}

/// Every Message due in each queue of `runtime`'s work step taken a turn
/// of, oldest first, on this thread: one scan, as the dispatching does it,
/// with no pool; how each turn ended.
pub fn turn_due(runtime: &Runtime<'_>, pickup: &Pickup) -> Vec<Turned> {
    let step = runtime.work;
    let mut turned = Vec::new();
    for running in &step.running {
        for held in due(step, running.queue, None)
            .into_iter()
            .filter(|held| !held.failed)
        {
            turned.push(turn(runtime, pickup, running, &held));
        }
    }
    turned
}

/// What is due in `queue`, oldest first, read a page at a time to its end
/// as the send step reads its own (`crate::send_step`) — its first `first`,
/// as a wake brought it, where one did: a page of Messages that wait on
/// their Instances never hides one behind it that may go on. When the
/// earliest retry not yet due is due noted; where Xmip Storage does not
/// answer, what was read so far, the rest left for the next scan.
fn due(step: &WorkStep, queue: u128, mut first: Option<DueQueue>) -> Vec<Held> {
    let mut read = Vec::new();
    let mut from = Some((0, 0));
    while let Some(at) = from {
        let page = match first.take() {
            Some(page) => page,
            None => match step.storage.read_due(queue, DuePart::Due, at, PAGE) {
                Ok(page) => page,
                Err(_) => break,
            },
        };
        if let Some(left) = page.next_due_in() {
            step.noted(queue, left);
        }
        from = page
            .held
            .last()
            .filter(|_| page.held.len() == PAGE as usize)
            .map(DueQueue::after);
        read.extend(page.held);
    }
    read
}

fn take<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    pickup: &'env Pickup,
    running: &'env Running,
    (held, since): (Held, u64),
) {
    pool.run(Box::new(move || {
        settled(runtime, pickup, running, (&held, since));
    }));
}

/// A turn of the Message `held` names taken, owned since this node had
/// written `since` turns, and what it ended as told.
fn settled(runtime: &Runtime<'_>, pickup: &Pickup, running: &Running, (held, since): (&Held, u64)) {
    let step = runtime.work;
    let journey: JourneyId = held.hold.journey;
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
    step.disown(journey, running.queue, (done, since));
    // A turn may have ended what a Stream held a sequence for: what waits
    // behind it in either step may go on now.
    if done {
        runtime.send.rescan();
        step.ask_every();
    }
}
