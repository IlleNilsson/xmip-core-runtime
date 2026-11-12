//! A step's watch in Xmip Storage (open problem 46; ADR-0018, amendments
//! 2026-11-12): what wakes the send step, and the Work Process step, for a
//! Message another node put in a queue it takes from, at once, where until
//! 2026-11-12 it was found at the step's next scan, a second by default;
//! and for what a Journey it passed over waits on — a sequence's head, an
//! Instance, a key of the Instance Key table — once another node moves it.
//!
//! The watch waits on every queue of the step at once, each with where it
//! saw its tail stand last (`persist::storage::Position`), and on each more
//! the step names ([`QueueWatch::wait_on`]), with where the step read it.
//! Each queue that moved is handed to the step with the first of what is
//! due in it, read by the Storage node as it answered
//! (`persist::storage::Moved`), so the step claims without a read of its
//! own first; each more that moved is let go of, and the queues named with
//! it handed to the step to read. A more named while a wait is under way
//! renews it ([`Waiter::renew`]), so it is waited on at once. The step's
//! scan of every queue stays, at its interval — `[tuning] send_scan` and
//! `work_scan` — which is now only the bound on one wait: what no write
//! tells, a claim that lapsed on a node that died, is found there. Three
//! things keep it from asking without pause, each found 2026-11-12: a wait
//! no Storage node answers — each that is stopping or the primary no more
//! refuses it, and the next is asked at once — rests its bound before it is
//! asked again; one answered with nothing before its bound, and renewed by
//! nothing — a Storage node holds none longer than its `[tuning]
//! storage_wait` — rests the rest of it; and a bound of nothing is no watch
//! at all, the configuration refusing one besides (`[tuning]` takes no
//! duration of nothing). The step's stop ends the watch at once
//! ([`Waiter::stop`]).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use persist::storage::{DueQueue, Position, Waiter, Watched, XmipStorage};
use xcore::lock::Locked;

/// The most of what is due in a queue that moved a wait's answer carries:
/// a page, as many as the steps read of a queue at once, which read on from
/// it.
pub(crate) const DUE: u32 = 64;

/// What a step's watch waits as, and what more it waits on than the
/// step's queues.
#[derive(Debug)]
pub(crate) struct QueueWatch {
    waiter: Arc<Waiter>,
    more: Mutex<More>,
}

/// Each more waited on, where the step read it, and the queues to read once
/// it moves.
#[derive(Debug, Default)]
struct More {
    waits: Vec<(Position, Vec<u128>)>,
}

/// A queue the watch hands its step: what is due in it, where the wait
/// answered with that, and when the answer came.
#[derive(Clone, Debug)]
pub(crate) struct Woken {
    pub(crate) due: Option<DueQueue>,
    pub(crate) at: Instant,
}

impl QueueWatch {
    /// The watch of the node whose claims name `node`: a Publication that
    /// node claims every Message of in the same write does not wake it
    /// (`persist::storage::Waiter`).
    pub(crate) fn of(node: &str) -> Self {
        Self {
            waiter: Arc::new(Waiter::of(node)),
            more: Mutex::default(),
        }
    }

    /// Stopped: its wait ends now, and no other is asked.
    pub(crate) fn stop(&self) {
        self.waiter.stop();
    }

    /// Each of `positions` waited on as well, as the step read it, and
    /// `queue` read once one moves: what a Journey of `queue` the step passed
    /// over waits on. One newly named renews the wait under way, or the rest
    /// after it, so it is waited on at once; a wait asked after it was named
    /// names it, and is not renewed (`Waiter::asking`).
    pub(crate) fn wait_on(&self, positions: &[Position], queue: u128) {
        let mut more = self.more.locked();
        let mut named = false;
        for position in positions {
            match more
                .waits
                .iter_mut()
                .find(|(kept, _)| kept.watched == position.watched)
            {
                Some((kept, queues)) => {
                    kept.at = position.at;
                    if !queues.contains(&queue) {
                        queues.push(queue);
                    }
                }
                None => {
                    more.waits.push((*position, vec![queue]));
                    named = true;
                }
            }
        }
        drop(more);
        if named {
            self.waiter.renew();
        }
    }

    /// `queues` of `storage` watched until it is stopped, each wait for at
    /// most `bound`: each queue a write moved past where the watch saw it
    /// last handed to `ask` at once, with what is due in it; each more that
    /// moved let go of, and its queues handed to `ask`. No queue, or a
    /// bound of nothing, no watch.
    pub(crate) fn run(
        &self,
        storage: &dyn XmipStorage,
        queues: &[u128],
        bound: Duration,
        ask: &dyn Fn(u128, Woken),
    ) {
        if queues.is_empty() || bound.is_zero() {
            return;
        }
        // Where each was seen last: nowhere yet, so the first wait answers
        // at once with every queue that holds anything, read by the step's
        // first scan as well.
        let mut tails: Vec<Position> = queues.iter().map(|&q| Position::queue(q, 0)).collect();
        while !self.waiter.is_stopped() {
            // What is named from here on renews this wait; what was named
            // before it, it names.
            self.waiter.asking();
            let seen = self.seen(&tails);
            let asked = Instant::now();
            match storage.wait_queues(&seen, (bound, DUE), &self.waiter) {
                // Renewed, the rest ends at once.
                Ok(moved) if moved.is_empty() => {
                    self.waiter.rest(bound.saturating_sub(asked.elapsed()));
                }
                Ok(moved) => {
                    let at = Instant::now();
                    for one in moved {
                        let queue = match one.position.watched {
                            Watched::Queue(queue) => queue,
                            other => {
                                for queue in self.moved(other) {
                                    ask(queue, Woken { due: None, at });
                                }
                                continue;
                            }
                        };
                        for kept in tails
                            .iter_mut()
                            .filter(|kept| kept.watched == one.position.watched)
                        {
                            kept.at = one.position.at;
                        }
                        ask(queue, Woken { due: one.due, at });
                    }
                }
                Err(_) => self.waiter.rest(bound),
            }
        }
    }

    /// What a wait names now: the step's queues where `tails` saw them,
    /// and each more as the step read it.
    fn seen(&self, tails: &[Position]) -> Vec<Position> {
        let more = self.more.locked();
        tails
            .iter()
            .copied()
            .chain(more.waits.iter().map(|(position, _)| *position))
            .collect()
    }

    /// `watched` moved: let go of, and the queues to read now it has.
    fn moved(&self, watched: Watched) -> Vec<u128> {
        let mut more = self.more.locked();
        let mut queues = Vec::new();
        more.waits.retain(|(position, named)| {
            let gone = position.watched == watched;
            if gone {
                queues.extend(named.iter().copied());
            }
            !gone
        });
        queues
    }

    /// How many more it waits on now: a test's.
    #[cfg(test)]
    fn waiting_on_more(&self) -> usize {
        self.more.locked().waits.len()
    }
}

#[cfg(test)]
mod tests;
