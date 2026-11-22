//! What a Work Process's step knows of its queue between the rounds of its
//! dispatching (ADR-0066, amendments 2026-11-12 and 2026-11-22): one
//! [`Reading`] per Work Process — where its read of what is due goes on,
//! how far its reads have gone, the page a wake brought, whether a head
//! moved, and what it took up that waits for a place or for what is no
//! head — beside what it knows of its queue's sequences
//! (`crate::sequence::Heads`, `super::WorkStep`'s own).
//!
//! **A queue is read once, a page a round, from where its reads have gone.**
//! Its first read starts at the start of what is due; every later one reads
//! on from where the last one ended — what arrived since, the watch waking
//! it (`crate::queue_watch`), and the retries that are due. What waits
//! behind a sequence's head is kept by the head, never read again, and
//! handed over once the head moves; a page a round, never wholly into
//! memory. Until 2026-11-22 every ask began a pass from the start, each
//! entry taken a turn of, so a backlog of 10,777 behind its Receive
//! Locations' sequences went through at two to four a minute (open problem
//! 93).
//!
//! The cursor is `persist::storage::DueQueue::after`: a read from `(0, n)`
//! reads what is due since it was held from place `n`, then the retries
//! that are due. How far its reads have gone is a node's convenience, never
//! the truth (`runtime-model.md` section 22): lost on a restart, it costs a
//! read from the start, and nothing else.

use persist::PersistError;
use persist::storage::{DuePart, DueQueue, Held};

use super::WorkStep;
use crate::sequence::Queued;

/// The most entries of a queue read at once: as many as a wake brings.
pub(super) const PAGE: u32 = crate::queue_watch::DUE;

/// How the read of one Work Process's queue stands between rounds.
#[derive(Debug, Default)]
pub(super) struct Reading {
    /// Where its read goes on, oldest first: `None` where none is under way.
    from: Option<(u64, u64)>,
    /// The place after the last Message due since it was held that its
    /// reads offered: where a read of what arrived since starts.
    fresh: u64,
    /// What is due in it as a wake brought it: a read from the start reads
    /// it in place of asking Xmip Storage.
    first: Option<DueQueue>,
    /// Asked while its read was under way: read on once it ends.
    again: bool,
    /// A head it keeps Messages behind moved: hand over who heads now.
    hand: bool,
    /// Every head read again: the scan, the bound on a wake that never came.
    every: bool,
    /// A sequence it cut may be read on.
    refill: bool,
    /// Taken up and waiting on what is no head of a sequence it keeps — an
    /// Instance, a key, another's claim, Xmip Storage's answer: taken up
    /// again once one moves, or at the scan.
    loose: Vec<Queued>,
    /// What is loose taken up again now.
    loosened: bool,
    /// Taken up and no place for them yet: offered first once one frees.
    ready: Vec<Queued>,
    /// Its share or the pool had no place: read on once a turn ends.
    starved: bool,
    /// Its turns admitted and not yet ended.
    pub(super) held: usize,
}

/// What one round does of a queue.
#[derive(Debug, Default)]
pub(super) struct Reads {
    /// Every head read again first; any that moved is handed over in every
    /// round (`crate::sequence::Heads::handed`).
    pub(super) every: bool,
    /// Read on a sequence it cut.
    pub(super) refill: bool,
    /// Taken up again: what waited for a place, and what is loose where it
    /// was asked.
    pub(super) again: Vec<Queued>,
    /// A page of its read, from where it stands, with the page a wake
    /// brought where it reads from the start.
    pub(super) read: Option<PageFrom>,
    /// Where its reads have gone: what a sequence it cut is read on up to.
    pub(super) fresh: u64,
}

/// Where a page is read from, and the page a wake brought, read in place of
/// asking where it did.
pub(super) type PageFrom = ((u64, u64), Option<DueQueue>);

/// A page read: its entries, oldest first, and where the next page starts,
/// `None` at the end of what is due.
pub(super) type Page = (Vec<Held>, Option<(u64, u64)>);

/// How the page of a read went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Went {
    /// Each entry offered: where the read goes on, `None` at its end.
    On(Option<(u64, u64)>),
    /// The entry at this place found no place, or no more is kept: the
    /// read stays on it.
    Starved((u64, u64)),
    /// Xmip Storage did not answer: the read ends, read on at the next ask
    /// or scan from where its reads had gone.
    Unanswered,
}

impl Reading {
    /// Asked to read its queue — a Publication, a wake bringing `first`, a
    /// timer due, a turn ended, a scan: where no read is under way one
    /// begins where its reads have gone, else it reads on once that ends.
    pub(super) fn asked(&mut self, first: Option<DueQueue>) {
        if first.is_some() && self.fresh == 0 {
            self.first = first;
        }
        if self.from.is_some() {
            self.again = true;
        } else {
            self.from = Some((0, self.fresh));
        }
    }

    /// Asked by the periodic scan: every head read again, what is loose
    /// taken up again, and what arrived read, never from a wake's page.
    pub(super) fn afresh(&mut self) {
        self.first = None;
        self.every = true;
        self.loosened = true;
        self.asked(None);
    }

    /// A head it keeps Messages behind moved.
    pub(super) const fn hand(&mut self) {
        self.hand = true;
    }

    /// What is loose taken up again: what one waits on moved.
    pub(super) const fn loosen(&mut self) {
        self.loosened = true;
    }

    /// `queued` waits on what is no head of a sequence it keeps.
    pub(super) fn park(&mut self, queued: Queued) {
        self.loose.push(queued);
    }

    /// The loose Message of `journey` taken up again in the next round:
    /// another turn was written while it was held.
    pub(super) fn again_now(&mut self, journey: xcore::JourneyId) {
        if let Some(at) = self.loose.iter().position(|one| one.journey == journey) {
            let one = self.loose.swap_remove(at);
            self.ready.push(one);
        }
    }

    /// `queued` taken up again in the next round: its turn unwound, or it
    /// found no place.
    pub(super) fn ready(&mut self, queued: Queued) {
        self.ready.push(queued);
    }

    /// What this round reads, nothing while it waits for a place.
    pub(super) fn reads(&mut self) -> Reads {
        if self.starved {
            return Reads::default();
        }
        let mut again = std::mem::take(&mut self.ready);
        if std::mem::take(&mut self.loosened) {
            again.append(&mut self.loose);
        }
        let read = self.from.map(|from| {
            let first = if from == (0, 0) {
                self.first.take()
            } else {
                None
            };
            (from, first)
        });
        self.hand = false;
        Reads {
            every: std::mem::take(&mut self.every),
            refill: std::mem::take(&mut self.refill),
            again,
            read,
            fresh: self.fresh,
        }
    }

    /// Its read as its page `went`, its reads gone as far as `fresh` says,
    /// and whether a sequence it cut may be read on.
    pub(super) fn went(&mut self, went: Option<Went>, (fresh, refill): (Option<u64>, bool)) {
        if let Some(fresh) = fresh {
            self.fresh = self.fresh.max(fresh);
        }
        self.refill |= refill;
        match went {
            Some(Went::On(Some(next))) => self.from = Some(next),
            Some(Went::On(None)) => {
                self.from = std::mem::take(&mut self.again).then_some((0, self.fresh));
            }
            Some(Went::Starved(at)) => {
                self.from = Some(at);
                self.starved = true;
            }
            Some(Went::Unanswered) => {
                self.from = None;
                self.first = None;
                self.again = false;
            }
            None => {}
        }
    }

    /// No place for what it took up: it waits for one, its read kept where
    /// it stands.
    pub(super) const fn starve(&mut self) {
        self.starved = true;
    }

    /// A place freed: it reads on.
    pub(super) const fn freed(&mut self) {
        self.starved = false;
    }

    /// Whether it has more to do now: what keeps the dispatching from
    /// waiting.
    pub(super) fn goes_on(&self) -> bool {
        !self.starved && self.to_do()
    }

    /// Whether it has work, read or to read: what the pool is shared among.
    pub(super) fn wants(&self) -> bool {
        self.held > 0 || self.to_do()
    }

    /// Whether anything is left to read, hand over or take up again.
    fn to_do(&self) -> bool {
        self.from.is_some()
            || self.hand
            || self.every
            || self.refill
            || !self.ready.is_empty()
            || (self.loosened && !self.loose.is_empty())
    }
}

/// One page of what is due in `queue` from `from` — or `first`, as a wake
/// brought it — and where the next page starts, `None` at its end; when
/// its earliest retry not yet due is due noted. A page that read anything
/// is read on from: one shorter than asked is no end, since an entry let go
/// of between the range of the queue's index and the read of the entry
/// itself is passed over (found 2026-11-22: a sequence read on from a short
/// page took it for its end, and its later Messages waited for good).
///
/// # Errors
///
/// Where Xmip Storage did not answer.
pub(super) fn page(
    step: &WorkStep,
    queue: u128,
    (from, first): PageFrom,
) -> Result<Page, PersistError> {
    let page = match first {
        Some(page) => page,
        None => step.storage.read_due(queue, DuePart::Due, from, PAGE)?,
    };
    if let Some(left) = page.next_due_in() {
        step.noted(queue, left);
    }
    let next = page.held.last().map(DueQueue::after);
    Ok((page.held, next))
}

/// What is due in `queue`, oldest first, read a page at a time to its end:
/// a test's whole read, bounded by the test's own queue
/// (`super::dispatch::turn_due`). Where Xmip Storage does not answer, what
/// was read so far.
pub(super) fn wholly(step: &WorkStep, queue: u128) -> Vec<Held> {
    let mut read = Vec::new();
    let mut from = Some((0, 0));
    while let Some(at) = from {
        let Ok((held, next)) = page(step, queue, (at, None)) else {
            break;
        };
        read.extend(held);
        from = next;
    }
    read
}

#[cfg(test)]
mod tests;
