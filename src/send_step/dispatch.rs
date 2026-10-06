//! The send step's dispatching: what is handed to it, what is due, and what
//! a scan of its queues finds, each sent on the Send pool; the claims of
//! work in flight renewed; and what a stop gives back.

use std::thread::Scope;
use std::time::Instant;

use route::Subscriber;
use xcore::JourneyId;

use super::pass::{Ended, abandoned, blocks, send};
use super::renewal::resume;
use super::scan::{self, Ready, Unclaimed, scan};
use super::{Departure, SendStep, Settled};
use crate::message_path::Runtime;
use crate::pool::Pool;

/// The send step of `runtime` dispatching on its Send pool in `scope`,
/// until it is closed and what was handed to it is sent; `settled` is told
/// how each pass ended. Every queue this node sends is read as it starts,
/// for no more than the pool can take; one read when the pool had no room
/// is read again as soon as a place frees. The claims of work in flight are
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
        let (closed, handed, due, asked) = step.next(next_scan);
        for departure in handed {
            run(&pool, runtime, settled, departure);
        }
        if closed {
            step.give_back(due);
            return;
        }
        for departure in due {
            resume(&pool, runtime, settled, departure);
        }
        let now = Instant::now();
        let all = next_scan <= now;
        for (to, queue) in &served {
            if !all && !asked.contains(queue) {
                continue;
            }
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
    /// Wait for something to do — handed, due, asked, closed — or `until`:
    /// whether the step is closed, what was handed, what is due and which
    /// queues were asked for.
    fn next(&self, until: Instant) -> (bool, Vec<Departure>, Vec<Departure>, Vec<u128>) {
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let earliest = state.due.iter().map(|(at, _)| *at).min();
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
        let (due, waiting) = std::mem::take(&mut state.due)
            .into_iter()
            .partition(|(at, _)| *at <= now);
        state.due = waiting;
        let asked = std::mem::take(&mut state.asked);
        let due = due.into_iter().map(|(_, departure)| departure).collect();
        (state.closed, handed, due, asked)
    }

    /// Give back the claim of everything waiting for its due time, `due`
    /// among it: a stop drains rather than letting its claims lapse
    /// (ADR-0018 clause 12).
    fn give_back(&self, due: Vec<Departure>) {
        let waiting = std::mem::take(&mut self.lock().due);
        let waiting = waiting.into_iter().map(|(_, departure)| departure);
        for departure in waiting.chain(due) {
            let _ = self.storage.release(&departure.claim);
            self.lock()
                .owned
                .remove(&departure.work.journey.journey_id());
        }
        self.wake.notify_all();
    }

    /// How `departure`'s pass ended, settled: counted, kept until its due
    /// time, or let go of.
    fn settle(&self, settled: Settled<'_>, departure: Departure, ended: Ended) {
        settled(&departure, &ended);
        let id = departure.work.journey.journey_id();
        let mut state = self.lock();
        if departure.sequence.is_some() && !state.asked.contains(&departure.queue) {
            state.asked.push(departure.queue);
        }
        match ended {
            Ended::Waiting { after, .. } if !state.closed => {
                drop(state);
                // Its hand-on confirmed the claim to its due time.
                self.confirm(&departure);
                state = self.lock();
                state.due.push((Instant::now() + after, departure));
                drop(state);
                self.wake.notify_all();
                return;
            }
            Ended::Waiting { .. } => {
                drop(state);
                let _ = self.storage.release(&departure.claim);
                state = self.lock();
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
                return;
            }
            Ended::Unwritten(why) => self.failed(&why),
        }
        state.owned.remove(&id);
        state.freed();
        drop(state);
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
