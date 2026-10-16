//! The send step's dispatching: what is handed to it, and what a scan of
//! its queues finds — a queue read again when its earliest retry is due —
//! each sent on the Send pool; and the claims of work in flight renewed.

use std::thread::Scope;
use std::time::Instant;

use route::Subscriber;
use xcore::JourneyId;

use super::due::Due;
use super::pass::{Ended, abandoned, blocks, send};
use super::scan::{self, Ready, Unclaimed, scan};
use super::{Departure, SendStep, Settled};
use crate::message_path::Runtime;
use crate::pool::Pool;

/// The send step of `runtime` dispatching on its Send pool in `scope`,
/// until it is closed and what was handed to it is sent; `settled` is told
/// how each pass ended. Every queue this node sends is read as it starts,
/// for no more than the pool can take; one read when the pool had no room
/// is read again as soon as a place frees, and one whose earliest retry is
/// due as soon as it is. The claims of work in flight are
/// renewed on a thread of their own, so no scan of a backlog, however
/// long, holds a renewal back.
pub fn dispatch<'scope, 'env>(
    scope: &'scope Scope<'scope, 'env>,
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
) {
    let step = runtime.send;
    let pool = Pool::new(scope, step.limits);
    let served: Vec<(Subscriber, u128)> = runtime
        .sends
        .served()
        .into_iter()
        .map(|to| {
            let queue = step.queue(&to);
            (to, queue)
        })
        .collect();
    step.lock().ports = served
        .iter()
        .map(|(to, _)| (to.name().to_string(), blocks(runtime, to)))
        .collect();
    scope.spawn(move || step.renewing());
    let mut next_scan = Instant::now();
    loop {
        let (closed, handed, asked) = step.next(next_scan);
        for departure in handed {
            run(&pool, runtime, settled, departure);
        }
        if closed {
            return;
        }
        let now = Instant::now();
        let all = next_scan <= now;
        for (to, queue) in &served {
            if !all && !asked.contains(queue) {
                continue;
            }
            // Its failed Journeys as Xmip Storage counts them, room or none.
            step.read_failed((to.name(), *queue), false);
            // No room: read again the moment a place frees, not at the
            // next scan.
            if step.room() == 0 {
                step.starve(*queue);
                continue;
            }
            for ready in scan(runtime, to, *queue) {
                match ready {
                    Ready::Claimed(departure) => run(&pool, runtime, settled, *departure),
                    Ready::Unclaimed(unclaimed) => take(&pool, runtime, settled, unclaimed),
                }
            }
        }
        if all {
            next_scan = now + step.scan;
        }
    }
}

impl SendStep {
    /// Wait for something to do — handed, asked, a queue's retry due,
    /// closed — or `until`: whether the step is closed, what was handed and
    /// which queues are to be read, a queue whose retry is due among them.
    fn next(&self, until: Instant) -> (bool, Vec<Departure>, Vec<u128>) {
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let earliest = state.due.values().filter_map(|due| due.at).min();
            let ready = state.closed
                || !state.handed.is_empty()
                || !state.asked.is_empty()
                || earliest.is_some_and(|at| at <= now)
                || until <= now;
            if ready {
                break;
            }
            let wait = earliest.map_or(until, |at| at.min(until)) - now;
            state = self
                .wake
                .wait_timeout(state, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        let now = Instant::now();
        let handed = state.handed.drain(..).collect();
        let mut asked = std::mem::take(&mut state.asked);
        for (queue, due) in &mut state.due {
            if due.at.is_some_and(|at| at <= now) {
                due.at = None;
                if !asked.contains(queue) {
                    asked.push(*queue);
                }
            }
        }
        (state.closed, handed, asked)
    }

    /// How `departure`'s pass ended, settled: counted, or let go of — a
    /// retry's due time noted for its queue, a failure's Port's window read
    /// again — and only then told, so whoever is told reads figures that
    /// already hold it. Nothing it settles stays owned: a Journey waiting
    /// for a retry holds no claim and no place.
    fn settle(&self, settled: Settled<'_>, departure: Departure, ended: Ended) {
        let id = departure.work.journey.journey_id();
        let mut state = self.lock();
        if departure.sequence.is_some() && !state.asked.contains(&departure.queue) {
            state.asked.push(departure.queue);
        }
        match &ended {
            Ended::Waiting { after, .. } => {
                let port = departure.to.name();
                state
                    .due
                    .entry(departure.queue)
                    .or_insert_with(|| Due::of(port))
                    .waits(Instant::now() + *after);
            }
            Ended::Untried => {
                drop(state);
                let _ = self.storage.release(&departure.claim);
                state = self.lock();
                if !state.asked.contains(&departure.queue) {
                    state.asked.push(departure.queue);
                }
            }
            Ended::Completed(_) => {
                let port = departure.to.name().to_string();
                state.figures.entry(port).or_default().sent += 1;
            }
            Ended::Failed { reason, .. } => {
                let port = departure.to.name().to_string();
                let figures = state.figures.entry(port).or_default();
                figures.failed += 1;
                figures.last_failure = Some((id.to_string(), reason.clone()));
                self.failed(&format!("the Journey {id} to {}: {reason}", departure.to));
            }
            Ended::Lost(_) => {
                drop(state);
                self.lost(&departure, "its claim was another's at its hand-on");
                settled(&departure, &ended);
                return;
            }
            Ended::Unwritten(why) => self.failed(why),
        }
        state.owned.remove(&id);
        state.freed();
        drop(state);
        if matches!(ended, Ended::Failed { .. }) {
            self.read_failed((departure.to.name(), departure.queue), false);
        }
        settled(&departure, &ended);
        self.wake.notify_all();
    }

    pub(super) fn failed(&self, problem: &str) {
        if let Some(audit) = &self.audit {
            let _ = audit.failed("send", &format!("{}: {problem}", self.node));
        }
    }
}

/// `departure` sent on `pool`, and its pass settled — also where its send
/// panics ([`Sending`]).
pub(super) fn run<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    departure: Departure,
) {
    pool.run(Box::new(move || sent(runtime, settled, departure)));
}

/// `unclaimed` claimed and read on a thread of `pool`, under the place
/// admitted for it, and sent there: a backlog's claims are taken side by
/// side, sharing their commits, never one by one on the dispatching, which
/// cost a commit's sync each until 2026-10-06. Where it is not this node's
/// to send after all, or its claim panics, its place is given back
/// ([`Taking`]).
fn take<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    unclaimed: Unclaimed,
) {
    pool.run(Box::new(move || {
        let mut taking = Taking {
            runtime,
            journey: Some(unclaimed.journey()),
        };
        if let Some(departure) = scan::take(runtime, &unclaimed) {
            taking.journey = None;
            sent(runtime, settled, departure);
        }
    }));
}

/// `departure` sent, and its pass settled — also where its send panics.
fn sent<'env>(runtime: &'env Runtime<'env>, settled: Settled<'env>, departure: Departure) {
    let mut sending = Sending {
        runtime,
        settled,
        departure: Some(departure),
    };
    let Some(departure) = sending.departure.as_mut() else {
        return;
    };
    let ended = send(runtime, departure);
    if let Some(departure) = sending.departure.take() {
        runtime.send.settle(settled, departure, ended);
    }
}

/// A Journey a scan found, being claimed on a send thread: its place given
/// back unless it was claimed and owned, however the claim ended.
struct Taking<'env> {
    runtime: &'env Runtime<'env>,
    journey: Option<JourneyId>,
}

impl Drop for Taking<'_> {
    fn drop(&mut self) {
        if let Some(journey) = self.journey.take() {
            self.runtime.send.untake(journey);
        }
    }
}

/// One Journey on a send thread, settled however its send ends. Sent to
/// its end, it is settled by what the send wrote. A send that panicked is
/// settled on the way out: written Failed with why — kept in its queue for
/// an operator — its claim ended, audited, and let go of, so it is never
/// left owned with its claim renewed and passed over by every scan, as it
/// was until 2026-10-05.
struct Sending<'env> {
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    departure: Option<Departure>,
}

impl Drop for Sending<'_> {
    fn drop(&mut self) {
        let Some(mut departure) = self.departure.take() else {
            return;
        };
        let why = "its send thread panicked before its hand-on was written";
        let ended = abandoned(self.runtime, &mut departure, why);
        self.runtime.send.settle(self.settled, departure, ended);
    }
}
