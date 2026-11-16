//! The send step's dispatching: what is handed to it, and what a scan of
//! its queues finds — a queue read again when its earliest retry is due,
//! and the moment another node puts a Message in it, or moves what a
//! Message it passed over waits on — each sent on the Send pool
//! (`super::sent`); each pass settled; and the claims of work in flight
//! renewed.

use std::thread::Scope;

use route::Subscriber;
use xcore::clock::{between, nanos};

use super::pass::{Ended, blocks};
use super::scan::{Ready, scan};
use super::sent::{run, sent, take};
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
    // The claims of what it sends renewed first: a Publication claims as
    // soon as the node receives, whatever this thread does meanwhile.
    scope.spawn(move || step.renewing());
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
    // Each queue another node puts a Message in, read at once from what is
    // due in it as the wake brought it; the scan of them all stays, at its
    // interval, the bound on one wait.
    let queues: Vec<u128> = served.iter().map(|(_, queue)| *queue).collect();
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
    loop {
        let (closed, handed, (asked, mut woken)) = step.next(next_scan);
        for departure in handed {
            run(&pool, runtime, settled, departure);
        }
        if closed {
            return;
        }
        let now = step.clock.monotonic_nanos();
        let all = next_scan <= now;
        if all {
            // The bound on a wake that never came: what waits behind a head
            // is read again with the rest (`super::behind`).
            step.lock().behind.forget();
        }
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
            next_scan = now.saturating_add(nanos(step.scan));
            step.lock().scans += 1;
        }
    }
}

/// Which queues to read: each wholly, and each another node's write woke,
/// with what the wake brought.
pub(super) type ToRead = (Vec<u128>, Vec<(u128, Woken)>);

impl SendStep {
    /// Wait for something to do — handed, asked, woken, a queue's retry
    /// due, closed — or `until`, a reading of its Clock: whether the step is
    /// closed, what was handed and which queues are to be read ([`ToRead`]),
    /// a queue whose retry is due among those read wholly.
    pub(super) fn next(&self, until: i128) -> (bool, Vec<Departure>, ToRead) {
        let mut state = self.lock();
        loop {
            let now = self.clock.monotonic_nanos();
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
            state = self
                .wake
                .wait_timeout(&self.state, state, between(now, wakes))
                .0;
        }
        let now = self.clock.monotonic_nanos();
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
        state.took_pages(&woken);
        (state.closed, handed, (asked, woken))
    }

    /// How `departure`'s pass ended, settled: counted, or let go of — a
    /// retry's due time noted for its queue, a failure's Port's window read
    /// again — and only then told, so whoever is told reads figures that
    /// already hold it. Nothing it settles stays owned: a Message waiting
    /// for a retry holds no claim and no place. What waited beside it is
    /// the caller's to pass on now (`super::beside`).
    pub(super) fn settle(
        &self,
        settled: Settled<'_>,
        departure: Departure,
        ended: Ended,
    ) -> Option<Departure> {
        let id = departure.work.journey.journey_id();
        // Before its claim is given back: what it is sent under, waited on.
        departure.settled();
        // Its pass ended, its hand-on answered where it wrote one: no longer
        // ahead here.
        let next = if matches!(ended, Ended::Behind) {
            None
        } else {
            self.passed_on(&departure)
        };
        let mut state = self.lock();
        match &ended {
            Ended::Waiting { after, .. } => {
                // Its backoff from now, once Xmip Storage took its hand-on:
                // never before Xmip Storage's own due time, and kept across
                // a read of its queue under way, which may have passed its
                // place before the hand-on landed; and how many wait read
                // after it, so it is counted once.
                drop(state);
                let at = self.clock.monotonic_nanos().saturating_add(nanos(*after));
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
                // Known to wait, so no read of its queue claims it again
                // before one of them moves (`super::behind`); owned here
                // until it is let go of below, so no read takes it meanwhile.
                if let Ok(waits) = &behind
                    && !waits.is_empty()
                {
                    let heads = waits.iter().map(|wait| wait.watched).collect();
                    self.lock().behind.waits(id, departure.queue, heads);
                    self.watch.wait_on(waits, departure.queue);
                }
                // Its queue read again once it is let go of, below, under
                // the same lock: a read begun while it was still owned here —
                // one a head's move or what it heads now asked for — passed it
                // over, and nothing else would ask (found 2026-11-15, the
                // ledger suite run four copies at once).
                state = self.lock();
                if behind.is_ok() && !state.asked.contains(&departure.queue) {
                    state.asked.push(departure.queue);
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
                return next;
            }
            Ended::Unwritten(why) => self.failed(why),
        }
        state.let_go((id, departure.queue), self.letting_go());
        state.freed();
        drop(state);
        if matches!(ended, Ended::Failed { .. }) {
            self.read_failed((departure.to.name(), departure.queue), false);
        }
        settled(&departure, &ended);
        self.wake.notify_all();
        next
    }

    pub(super) fn failed(&self, problem: &str) {
        if let Some(audit) = &self.audit {
            let _ = audit.failed("send", &format!("{}: {problem}", self.node));
        }
    }
}
