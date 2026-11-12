//! What is left to read of a Work Process's queue, kept between the rounds
//! of the Work Process step's dispatching (ADR-0066, amendment 2026-11-12):
//! one [`Reading`] per Work Process — where its pass goes on, the page a
//! wake brought, whether its head is read first, whether it goes again from
//! the start, and whether it waits for a place in the Work pool — named as
//! the send step's own reading is.
//!
//! **A queue is read a page a round, never wholly into memory.** What is not
//! read yet stays in the Ledger. The cursor is a node's convenience, never
//! the truth (`runtime-model.md` section 22): lost on a restart, it costs a
//! read again and nothing else.
//!
//! The cursor is `persist::storage::DueQueue::after`: a pass from `(0, n)`
//! reads what is due since it was held from place `n`, then the retries
//! that are due; one from `(due, n)` reads only retries. A Message published
//! while a pass stands among the retries is reached by the pass that its
//! ask starts once this one ends, and an older entry that falls due behind
//! the cursor is read at once by the head ([`Reading::asked`]).

use persist::PersistError;
use persist::storage::{DuePart, DueQueue, Held};

use super::WorkStep;

/// The most entries of a queue read at once: as many as a wake brings.
pub(super) const PAGE: u32 = crate::queue_watch::DUE;

/// Where a pass starts: the first entry due since it was held.
const START: (u64, u64) = (0, 0);

/// How the read of one Work Process's queue stands between rounds.
#[derive(Debug, Default)]
pub(super) struct Reading {
    /// Where its pass goes on, oldest first: `None` where none is under way.
    from: Option<(u64, u64)>,
    /// What is due in it as a wake brought it: the next read from the start
    /// reads it in place of asking Xmip Storage.
    first: Option<DueQueue>,
    /// Asked while its pass was under way: its head read before the pass
    /// goes on.
    head: bool,
    /// Asked while its pass was under way: another pass, from the start,
    /// once this one ends.
    again: bool,
    /// Its share or the pool had no place: read on once a turn ends.
    starved: bool,
    /// Its turns admitted and not yet ended.
    pub(super) held: usize,
}

/// What one round reads of a queue.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Reads {
    /// Its head, from the start, with the page a wake brought: where it was
    /// asked while its pass was under way.
    pub(super) head: Option<Option<DueQueue>>,
    /// Its pass, from where it stands, with the page a wake brought where it
    /// stands at the start.
    pub(super) pass: Option<PageFrom>,
}

/// Where a page is read from, and the page a wake brought, read in place of
/// asking where it did.
pub(super) type PageFrom = ((u64, u64), Option<DueQueue>);

/// A page read: its entries, oldest first, and where the next page starts,
/// `None` at the end of what is due.
pub(super) type Page = (Vec<Held>, Option<(u64, u64)>);

/// How the page of a pass went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Went {
    /// Each entry offered: where the pass goes on, `None` at its end.
    On(Option<(u64, u64)>),
    /// The entry at this place found no place: the pass stays on it.
    Starved((u64, u64)),
    /// Xmip Storage did not answer: the pass ends, read again at the next
    /// ask or scan.
    Unanswered,
}

impl Reading {
    /// Asked to read its queue — a Publication, a wake bringing `first`, a
    /// timer due, a turn ended, a scan. Where no pass is under way one
    /// begins at the start; where one is, its head is read first and
    /// another pass follows from the start once it ends.
    pub(super) fn asked(&mut self, first: Option<DueQueue>) {
        if first.is_some() {
            self.first = first;
        }
        if self.from.is_some() {
            self.head = true;
            self.again = true;
        } else {
            self.from = Some(START);
        }
    }

    /// Asked by the periodic scan: read afresh, never from a wake's page.
    pub(super) fn afresh(&mut self) {
        self.first = None;
        self.asked(None);
    }

    /// What this round reads: its head where asked, and its pass; nothing
    /// while it waits for a place. A pass at the start reads the head itself
    /// and everything asked before it, so neither is read again for it.
    pub(super) fn reads(&mut self) -> Reads {
        if self.starved {
            return Reads::default();
        }
        if self.from == Some(START) {
            self.head = false;
            self.again = false;
        }
        let head = self.head.then(|| self.first.take());
        let pass = self.from.map(|from| {
            let first = if from == START {
                self.first.take()
            } else {
                None
            };
            (from, first)
        });
        Reads { head, pass }
    }

    /// Its pass as its page `went`.
    pub(super) fn went(&mut self, went: Went) {
        match went {
            Went::On(Some(next)) => self.from = Some(next),
            Went::On(None) => {
                self.from = std::mem::take(&mut self.again).then_some(START);
                if self.from.is_some() {
                    self.head = false;
                }
            }
            Went::Starved(at) => {
                self.from = Some(at);
                self.starved = true;
            }
            Went::Unanswered => {
                self.from = None;
                self.first = None;
                self.head = false;
                self.again = false;
            }
        }
    }

    /// Its head read: each entry offered, or as many as found a place, the
    /// rest left to the pass from the start that the ask which set it began
    /// (`again`), so a head that finds no place is never read over and over.
    pub(super) fn headed(&mut self) {
        self.head = false;
    }

    /// No place for what its head read: it waits for one, its pass kept
    /// where it stands.
    pub(super) fn starve(&mut self) {
        self.starved = true;
    }

    /// A place freed: it reads on.
    pub(super) fn freed(&mut self) {
        self.starved = false;
    }

    /// Whether it has more to read now: what keeps the dispatching from
    /// waiting.
    pub(super) const fn goes_on(&self) -> bool {
        !self.starved && (self.from.is_some() || self.head)
    }

    /// Whether it has work, read or to read: what the pool is shared among.
    pub(super) const fn wants(&self) -> bool {
        self.held > 0 || self.from.is_some() || self.head
    }
}

/// One page of what is due in `queue` from `from` — or `first`, as a wake
/// brought it — and where the next page starts, `None` at its end; when
/// its earliest retry not yet due is due noted.
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
    let next = page
        .held
        .last()
        .filter(|_| page.held.len() == PAGE as usize)
        .map(DueQueue::after);
    Ok((page.held, next))
}

/// What is due in `queue`, oldest first, read a page at a time to its end:
/// a test's whole read, bounded by the test's own queue
/// (`super::dispatch::turn_due`). Where Xmip Storage does not answer, what
/// was read so far.
pub(super) fn wholly(step: &WorkStep, queue: u128) -> Vec<Held> {
    let mut read = Vec::new();
    let mut from = Some(START);
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
mod tests {
    use super::*;

    /// A page a wake brought: told apart by its clock.
    fn woken() -> DueQueue {
        DueQueue {
            read_unix_nanos: 7,
            ..DueQueue::default()
        }
    }

    #[test]
    fn a_pass_begins_where_none_is_under_way_and_reads_a_wakes_page_first() {
        let mut reading = Reading::default();
        assert!(!reading.goes_on() && !reading.wants(), "nothing asked");
        reading.asked(Some(woken()));
        assert!(reading.goes_on() && reading.wants());
        let read = reading.reads();
        assert_eq!(read.head, None, "the pass reads its head itself");
        assert_eq!(read.pass, Some((START, Some(woken()))));
        reading.went(Went::On(None));
        assert!(!reading.goes_on(), "read to its end");
    }

    #[test]
    fn asked_while_a_pass_is_under_way_its_head_is_read_and_it_goes_again_once_it_ends() {
        let mut reading = Reading::default();
        reading.asked(None);
        let _ = reading.reads();
        reading.went(Went::On(Some((0, 64))));
        reading.asked(Some(woken()));
        let read = reading.reads();
        assert_eq!(read.head, Some(Some(woken())), "its head, from the wake");
        assert_eq!(
            read.pass,
            Some(((0, 64), None)),
            "its pass, from its cursor"
        );
        reading.headed();
        reading.went(Went::On(None));
        let again = reading.reads();
        assert_eq!(again.head, None);
        assert_eq!(again.pass, Some((START, None)), "again, from the start");
        reading.went(Went::On(None));
        assert!(!reading.goes_on(), "asked nothing since: it ends");
    }

    #[test]
    fn a_starved_pass_goes_on_from_the_entry_that_found_no_place_once_one_frees() {
        let mut reading = Reading::default();
        reading.asked(None);
        let _ = reading.reads();
        reading.held = 2;
        reading.went(Went::Starved((0, 7)));
        assert!(!reading.goes_on(), "it waits for a place");
        assert!(reading.wants(), "its share is still wanted");
        assert_eq!(reading.reads(), Reads::default(), "nothing while starved");
        reading.freed();
        assert_eq!(reading.reads().pass, Some(((0, 7), None)));
    }

    #[test]
    fn a_periodic_scan_reads_afresh_not_from_a_wake() {
        let mut reading = Reading::default();
        reading.asked(Some(woken()));
        reading.afresh();
        assert_eq!(reading.reads().pass, Some((START, None)));
        reading.went(Went::On(Some((0, 64))));
        reading.asked(Some(woken()));
        reading.afresh();
        assert_eq!(reading.reads().head, Some(None), "its head read afresh");
    }

    #[test]
    fn a_pass_storage_does_not_answer_ends_until_the_next_ask() {
        let mut reading = Reading::default();
        reading.asked(None);
        let _ = reading.reads();
        reading.went(Went::On(Some((0, 64))));
        reading.asked(None);
        reading.went(Went::Unanswered);
        assert!(
            !reading.goes_on() && !reading.wants(),
            "ended, head and again too"
        );
        reading.asked(None);
        assert_eq!(reading.reads().pass, Some((START, None)));
    }
}
