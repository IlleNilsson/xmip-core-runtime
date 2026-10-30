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
    step.lock().served = served.iter().map(|(_, queue)| *queue).collect();
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
            // Its failed Messages as Xmip Storage counts them, room or none.
            step.read_failed((to.name(), *queue), false);
            // No room: read again the moment a place frees, not at the
            // next scan.
            if step.room() == 0 {
                step.starve(*queue);
                continue;
            }
            for ready in scan(runtime, to, *queue) {
                match ready {
                    Ready::Unclaimed(unclaimed) => take(&pool, runtime, settled, unclaimed),
                    Ready::Claimed(departure) => {
                        pool.run(Box::new(move || sent(runtime, settled, *departure)));
                    }
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
    pub(super) fn next(&self, until: Instant) -> (bool, Vec<Departure>, Vec<u128>) {
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let wakes = state.wakes_at(until);
            let ready = state.closed
                || state.rescan
                || !state.handed.is_empty()
                || !state.asked.is_empty()
                || wakes <= now;
            if ready {
                break;
            }
            state = self.wake.wait_until(&self.state, state, wakes).0;
        }
        let now = Instant::now();
        if std::mem::take(&mut state.rescan) {
            let served = state.served.clone();
            state.asked.extend(served);
        }
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
    /// already hold it. Nothing it settles stays owned: a Message waiting
    /// for a retry holds no claim and no place.
    fn settle(&self, settled: Settled<'_>, departure: Departure, ended: Ended) {
        let id = departure.work.journey.journey_id();
        let mut state = self.lock();
        match &ended {
            Ended::Waiting { after, .. } => {
                // Its backoff from now, once Xmip Storage took its hand-on:
                // never before Xmip Storage's own due time, and kept across
                // a read of its queue under way, which may have passed its
                // place before the hand-on landed.
                let port = departure.to.name();
                state
                    .due
                    .entry(departure.queue)
                    .or_insert_with(|| Due::of(port))
                    .noted(Instant::now() + *after);
            }
            Ended::Behind => {
                drop(state);
                let _ = self.storage.release(&departure.claim);
                // One that only waits for its places, its Stream and its
                // Group delivery heading: its queue read at once, so the
                // scan takes them in order now.
                let journey = &departure.work.journey;
                let ask = journey.sequences.is_empty()
                    && crate::sequence::stream_heads(self.storage.as_ref(), journey)
                        .unwrap_or(false)
                    && crate::sequence::group_heads(self.storage.as_ref(), journey)
                        .unwrap_or(false);
                state = self.lock();
                if ask && !state.asked.contains(&departure.queue) {
                    state.asked.push(departure.queue);
                    self.wake.notify_all();
                }
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
                self.failed(&format!(
                    "the Message of the Journey {id} to {}: {reason}",
                    departure.to
                ));
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
    let sequenced = departure
        .work
        .journey
        .received()
        .is_some_and(|received| !received.sequences.is_empty())
        || departure.work.journey.group.is_some()
        || !crate::sequence::points_of(runtime.sends, &departure.to).is_empty();
    let closed = sequenced && matches!(ended, Ended::Completed(_) | Ended::Failed { .. });
    if let Some(departure) = sending.departure.take() {
        runtime.send.settle(settled, departure, ended);
    }
    // A Message of a Stream that holds a sequence has ended its Journey: what waits
    // behind it in either step may go on now (`crate::sequence`).
    if closed {
        runtime.send.rescan();
        runtime.work.ask_every();
    }
}

/// A Message a scan found, being claimed on a send thread: its place given
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

/// One Message on a send thread, settled however its send ends. Sent to
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
