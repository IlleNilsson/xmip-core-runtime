//! One quantum of the Work Process step's dispatching: one Work Process's
//! round within its share of the Work pool (ADR-0066, amendments
//! 2026-11-12 and 2026-11-22; `super::dispatch`).
//!
//! **What a round does costs with its sequences, never with its backlog**
//! (open problem 93). Each head it keeps Messages behind that moved is read
//! again and who heads it now handed over; a sequence it cut is read on a
//! page; its queue is read a page from where its reads have gone; what waited
//! for a place, and what is loose where asked, is taken up again. Each
//! that may go on now is admitted and taken a turn of, in its queue's order;
//! one behind a head is kept by the head, never claimed, read or turned
//! (`crate::sequence::Heads`). Where no place is left the rest wait for one:
//! those taken up kept ready, its read stopped on the first it read.

use std::collections::HashSet;
use std::panic::{self, AssertUnwindSafe};

use persist::storage::{Held, Watched};
use xcore::lock::Locked;

use super::admission::{Admitted, Owning};
use super::reading::{self, PageFrom, Reads, Went};
use super::turning::{Turned, turn};
use super::{Running, WorkStep};
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use crate::pool::Pool;
use crate::sequence::{Heads, Met, Positions, Queued, TakenUp};

/// How one quantum went, kept for the next: its read as its page went, how
/// far its reads have gone, whether a sequence it cut may be read on, what
/// it took up and found no place for, and whether it waits for one.
#[derive(Debug, Default)]
pub(super) struct Quantum {
    pub(super) went: Option<Went>,
    pub(super) fresh: Option<u64>,
    pub(super) refill: bool,
    pub(super) ready: Vec<Queued>,
    /// Taken up and not read again, Xmip Storage not answering: loose, taken
    /// up again once asked or at the scan, never at every round.
    pub(super) loose: Vec<Queued>,
    pub(super) starved: bool,
}

/// What an offer left: those taken up to offer first once a place frees,
/// those loose, and where its read is to stay.
#[derive(Default)]
struct Left {
    ready: Vec<Queued>,
    loose: Vec<Queued>,
    stop: Option<(u64, u64)>,
}

/// A Message a quantum takes up, as kept, with its entry where its read
/// brought it.
struct Found {
    queued: Queued,
    held: Option<Held>,
}

/// The Work Process `running`, at `at`, taken a quantum of within `share` of
/// the Work pool. A Work Process naming a Correlation takes its turns on
/// this thread, in its queue's order, so the place each takes once its
/// Stream heads follows the Ledger's order (`crate::sequence::heading`).
pub(super) fn quantum<'env>(
    pool: &Pool<'_, 'env>,
    on: (&'env Runtime<'env>, &'env Pickup),
    (running, at): (&'env Running, usize),
    share: usize,
) {
    let step = on.0.work;
    let reads = step.lock().readings[at].reads();
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
    let went = offering.round(reads);
    step.round_went((at, share), went);
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
    /// The round `reads` asks: how it went.
    fn round(&mut self, reads: Reads) -> Quantum {
        let step = self.on.0.work;
        let (running, at) = self.running;
        let mut found: Vec<Found> = Vec::new();
        let mut waits = Positions::new();
        let refill = {
            let mut heads = step.heads[at].locked();
            if reads.every {
                heads.moved_every();
            }
            if reads.refill
                && let Some(cut) = heads.refill()
            {
                self.refill(&mut heads, cut, reads.fresh);
            }
            if heads.to_hand()
                && let Ok((goes, ahead)) = heads.handed(step.storage.as_ref())
            {
                found.extend(goes.into_iter().map(|queued| Found { queued, held: None }));
                waits.extend(ahead);
            }
            heads.refill().is_some()
        };
        found.extend(
            reads
                .again
                .into_iter()
                .map(|queued| Found { queued, held: None }),
        );
        let (went, fresh) = match reads.read {
            Some(from) => self.read(from, &mut found, &mut waits),
            None => (None, None),
        };
        if !waits.is_empty() {
            step.watch.wait_on(&waits, running.queue);
        }
        let Left { ready, loose, stop } = self.offer(found);
        Quantum {
            went: stop.map(Went::Starved).or(went),
            fresh: fresh.map(|fresh| match stop {
                Some((0, place)) => fresh.min(place),
                _ => fresh,
            }),
            refill,
            starved: !ready.is_empty() || stop.is_some(),
            ready,
            loose,
        }
    }

    /// One page of its queue read `from` where its read stands — with the
    /// page a wake brought, where it did — each entry met by what it knows
    /// of its sequences: those that go on now found, the heads those behind
    /// wait on named. How it went, and how far its reads have gone.
    fn read(
        &mut self,
        from: PageFrom,
        found: &mut Vec<Found>,
        waits: &mut Positions,
    ) -> (Option<Went>, Option<u64>) {
        let step = self.on.0.work;
        let (running, at) = self.running;
        let Ok((page, next)) = reading::page(step, running.queue, from) else {
            return (Some(Went::Unanswered), None);
        };
        let mut heads = step.heads[at].locked();
        let mut fresh = None;
        for held in page {
            let at = (held.due_at(), held.sequence);
            if !held.failed {
                let queued = queued(&held);
                match heads.met(step.storage.as_ref(), queued.clone()) {
                    Ok((Met::Goes, _)) => found.push(Found {
                        queued,
                        held: Some(held),
                    }),
                    Ok((Met::Waits, ahead)) => waits.extend(ahead),
                    Ok((Met::Known | Met::Unkept, _)) => {}
                    Ok((Met::Full, _)) => return (Some(Went::Starved(at)), fresh),
                    Err(_) => return (Some(Went::Unanswered), fresh),
                }
            }
            if at.0 == 0 {
                fresh = Some(at.1.saturating_add(1));
            }
        }
        (Some(Went::On(next)), fresh)
    }

    /// A page of the sequence `cut` names read on from where it was cut, up
    /// to where its reads have gone, `fresh`: its Messages kept behind its
    /// head. Read again at the next round Xmip Storage does not answer.
    fn refill(&self, heads: &mut Heads, (sequence, cut): (u128, u64), fresh: u64) {
        let step = self.on.0.work;
        let (running, _) = self.running;
        let Ok((page, _)) = reading::page(step, running.queue, ((0, cut), None)) else {
            return;
        };
        // Read on from after the last due since it was held, however short
        // the page: none read, none is left before where its reads have gone.
        let next = page
            .iter()
            .rev()
            .find(|held| held.due_at() == 0)
            .map(|last| last.sequence.saturating_add(1));
        let read: Vec<Queued> = page
            .iter()
            .filter(|held| !held.failed)
            .map(queued)
            .collect();
        heads.refilled(sequence, &read, (next, fresh));
    }

    /// Each of `found` offered in its queue's order: one that failed, gone or
    /// offered already moved past, each other admitted and taken a turn of,
    /// until one finds no place. What is left: those taken up, to be offered
    /// first once a place frees — one handed over while its last turn here
    /// still holds its place among them; those Xmip Storage did not read
    /// again, loose; and where the first left of those its read brought holds
    /// no place in a sequence, where its read is to stay.
    fn offer(&mut self, mut found: Vec<Found>) -> Left {
        let ((runtime, pickup), (running, at)) = (self.on, self.running);
        found.sort_by_key(|one| one.queued.place());
        let mut left = Left::default();
        let mut full = false;
        for Found { queued, held } in found {
            if full {
                left.place((queued, held.is_some()));
                continue;
            }
            let from_read = held.is_some();
            let held = match held {
                Some(held) => held,
                None => match self.fetch(&queued) {
                    Some(Some(held)) => held,
                    Some(None) => {
                        runtime.work.heads[at]
                            .locked()
                            .ended(&queued, TakenUp::Gone);
                        continue;
                    }
                    None => {
                        left.loose.push(queued);
                        continue;
                    }
                },
            };
            if held.failed {
                // Failed since it was kept: it waits for an operator, its
                // sequence as its Correlation says.
                runtime.work.heads[at]
                    .locked()
                    .ended(&queued, TakenUp::Gone);
                continue;
            }
            if !self.seen.insert(held.hold.journey) {
                continue;
            }
            let owning = match runtime.work.admit(held.hold.journey, at, self.share) {
                Admitted::Turn(owning) => owning.of(queued),
                // In a turn here: one its read brought is that turn's; one
                // handed over was kept again by that turn, whose place is
                // given back the moment it ends.
                Admitted::Held => {
                    if !from_read {
                        left.ready.push(queued);
                    }
                    continue;
                }
                Admitted::Full => {
                    full = true;
                    left.place((queued, from_read));
                    continue;
                }
            };
            if self.sequenced {
                // Its turn on this thread, which outlives a panic in it as
                // the pool's threads do: the guard gives its place back.
                let turned = || settled((runtime, pickup), (running, at), (&held, owning));
                let _ = panic::catch_unwind(AssertUnwindSafe(turned));
            } else {
                take(self.pool, (runtime, pickup), (running, at), (held, owning));
            }
        }
        left
    }

    /// The entry `queued` names, read again from its queue: `None` where
    /// Xmip Storage did not answer, `Some(None)` where it is gone from its
    /// place, or not due.
    fn fetch(&self, queued: &Queued) -> Option<Option<Held>> {
        let step = self.on.0.work;
        let (running, _) = self.running;
        let read = step
            .storage
            .read_held(running.queue, queued.place(), 1)
            .ok()?;
        Some(read.held.into_iter().next().filter(|held| {
            held.hold.journey == queued.journey && read_due(held, read.read_unix_nanos)
        }))
    }
}

/// Whether `held`, read at `read` on Xmip Storage's clock, is due.
fn read_due(held: &Held, read: i128) -> bool {
    held.due_in(read).is_none()
}

impl Left {
    /// `queued`, left with no place: kept ready where it was taken up —
    /// handed over, taken up again, or holding a place in a sequence — and,
    /// where its `read` brought it and it holds none, where that read is to
    /// stay, the first of those in its order.
    fn place(&mut self, (queued, read): (Queued, bool)) {
        if read && queued.places.is_empty() {
            self.stop = Some(self.stop.map_or(queued.at, |at| at.min(queued.at)));
        } else {
            self.ready.push(queued);
        }
    }
}

/// `held` as a step keeps it; one whose queue keeps no [`crate::sequence::Kept`]
/// beside it holds no place, and its turn says what it is.
fn queued(held: &Held) -> Queued {
    Queued::of(held).unwrap_or_else(|_| Queued {
        journey: held.hold.journey,
        at: (held.due_at(), held.sequence),
        places: Vec::new(),
    })
}

fn take<'env>(
    pool: &Pool<'_, 'env>,
    on: (&'env Runtime<'env>, &'env Pickup),
    running: (&'env Running, usize),
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
    (running, at): (&Running, usize),
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
    let queued = queued(held);
    step.took(at, &queued, &turned);
    let done = matches!(turned, Turned::Done);
    owning.ended(done);
    // A turn may have ended what a Stream held a sequence for: what waits
    // behind it in either step may go on now.
    if done {
        runtime.send.rescan();
        step.moved_beside(Some(at), &queued.places);
    }
}

impl WorkStep {
    /// The turn of `queued`, of the Work Process at `at`, ended as `turned`
    /// says: gone from where it waited, kept behind a head it keeps after
    /// all, or loose, waiting on what is no head of a sequence it keeps.
    fn took(&self, at: usize, queued: &Queued, turned: &Turned) {
        let behind_a_kept_head = |on: &Positions| {
            on.iter().any(|position| match position.watched {
                Watched::Head(head) => queued.places.iter().any(|(held, _)| *held == head),
                _ => false,
            })
        };
        let taken = match turned {
            Turned::Done | Turned::Failed(_) => Some(TakenUp::Gone),
            Turned::Waits { on, .. } if behind_a_kept_head(on) => Some(TakenUp::Back),
            Turned::Waits { .. } | Turned::Unwritten(_) => None,
        };
        match taken {
            Some(_) if queued.places.is_empty() => {}
            Some(how) => {
                self.heads[at].locked().ended(queued, how);
                self.lock().readings[at].hand();
            }
            None => self.lock().readings[at].park(queued.clone()),
        }
    }
}
