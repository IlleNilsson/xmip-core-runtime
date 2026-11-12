//! The send step's dispatching: what is handed to it, and what a scan of
//! its queues finds — a queue read again when its earliest retry is due,
//! and the moment another node puts a Message in it, or moves what a
//! Message it passed over waits on — each sent on the Send pool; and the
//! claims of work in flight renewed.

use std::thread::Scope;
use std::time::Instant;

use route::Subscriber;
use xcore::JourneyId;

use super::pass::{Ended, abandoned, blocks, send};
use super::scan::{self, Ready, Unclaimed, scan};
use super::{Departure, SendStep, Settled};
use crate::message_path::Runtime;
use crate::pool::Pool;
use crate::queue_watch::Woken;

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
    // Each queue another node puts a Message in, read at once from what is
    // due in it as the wake brought it; the scan of them all stays, at its
    // interval, the bound on one wait.
    let queues: Vec<u128> = served.iter().map(|(_, queue)| *queue).collect();
    scope.spawn(move || {
        let woken = |queue, woken| step.woken(queue, woken);
        step.watch
            .run(step.storage.as_ref(), &queues, step.scan, &woken);
    });
    let mut next_scan = Instant::now();
    loop {
        let (closed, handed, (asked, mut woken)) = step.next(next_scan);
        for departure in handed {
            run(&pool, runtime, settled, departure);
        }
        if closed {
            return;
        }
        let now = Instant::now();
        let all = next_scan <= now;
        for (to, queue) in &served {
            let failed = all || asked.contains(queue);
            let wake = woken
                .iter()
                .position(|(kept, _)| kept == queue)
                .map(|at| woken.swap_remove(at).1);
            if !failed && wake.is_none() {
                continue;
            }
            // Its failed Messages as Xmip Storage counts them, room or none;
            // not where only a write that put a Message in it woke it, which
            // fails none: an operator's Retry on another node, which clears
            // one, is read at the next scan, as before 2026-11-12.
            if failed {
                step.read_failed((to.name(), *queue), false);
            }
            // No room: read again the moment a place frees, not at the
            // next scan.
            if step.room() == 0 {
                step.starve(*queue);
                continue;
            }
            // Read wholly, it reads what is due itself, not as a wake left it.
            let wake = wake.filter(|_| !failed).map(|wake| (wake, now));
            for ready in scan(runtime, to, *queue, wake) {
                match ready {
                    Ready::Unclaimed(unclaimed) => take(&pool, runtime, settled, *unclaimed),
                    Ready::Claimed(departure) => {
                        pool.run(Box::new(move || sent(runtime, settled, *departure)));
                    }
                }
            }
        }
        if all {
            next_scan = now + step.scan;
            step.lock().scans += 1;
        }
    }
}

/// Which queues to read: each wholly, and each another node's write woke,
/// with what the wake brought.
pub(super) type ToRead = (Vec<u128>, Vec<(u128, Woken)>);

impl SendStep {
    /// Wait for something to do — handed, asked, woken, a queue's retry
    /// due, closed — or `until`: whether the step is closed, what was handed
    /// and which queues are to be read ([`ToRead`]), a queue whose retry is
    /// due among those read wholly.
    pub(super) fn next(&self, until: Instant) -> (bool, Vec<Departure>, ToRead) {
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let wakes = state.wakes_at(until);
            let ready = state.closed
                || state.rescan
                || !state.handed.is_empty()
                || !state.asked.is_empty()
                || !state.woken.is_empty()
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
        let woken = std::mem::take(&mut state.woken);
        (state.closed, handed, (asked, woken))
    }

    /// How `departure`'s pass ended, settled: counted, or let go of — a
    /// retry's due time noted for its queue, a failure's Port's window read
    /// again — and only then told, so whoever is told reads figures that
    /// already hold it. Nothing it settles stays owned: a Message waiting
    /// for a retry holds no claim and no place.
    fn settle(&self, settled: Settled<'_>, departure: Departure, ended: Ended) {
        let id = departure.work.journey.journey_id();
        // Before its claim is given back: what it is sent under, waited on.
        departure.settled();
        let mut state = self.lock();
        match &ended {
            Ended::Waiting { after, .. } => {
                // Its backoff from now, once Xmip Storage took its hand-on:
                // never before Xmip Storage's own due time, and kept across
                // a read of its queue under way, which may have passed its
                // place before the hand-on landed; and how many wait read
                // after it, so it is counted once.
                drop(state);
                let at = Instant::now() + *after;
                self.noted((departure.to.name(), departure.queue), at);
                state = self.lock();
            }
            Ended::Behind => {
                drop(state);
                let _ = self.storage.release(&departure.claim);
                // What it waits behind, its head as read now: where it
                // heads every sequence it holds a place in now — one that
                // only waits for its places among them — its queue is read
                // at once, so the scan takes it in order; else each head is
                // waited on, and its queue read the moment any node moves
                // one (open problem 46, 2026-11-12: until then a head
                // another node moved was found at the next scan).
                let behind =
                    crate::sequence::behind(self.storage.as_ref(), &departure.work.journey);
                match behind {
                    Ok(waits) if !waits.is_empty() => self.watch.wait_on(&waits, departure.queue),
                    Ok(_) => self.ask(departure.queue),
                    Err(_) => {}
                }
                state = self.lock();
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
                state.figures.entry(port.clone()).or_default().sent += 1;
                let timed = state.timed.entry(port).or_default();
                timed.sent(departure.steps.clone(), departure.handed);
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
    departure.steps.taken_up();
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
