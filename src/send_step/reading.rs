//! What a scan reads of a queue: only what is due (the owner, 2026-10-19:
//! *a send scan reads only what is due*), through Xmip Storage's index of
//! when each Message is due (`persist::storage::DueQueue`), so its cost
//! follows what is due, not what is held.
//!
//! A queue is read a page at a time, what is due in the order it fell due,
//! and the reading stops where the Send pool is full. What goes one at a
//! time per key is not this reading's: a Message that does not head its
//! sequence is passed by its send (`crate::sequence`).
//!
//! **A wake brings its first page** (2026-11-12): where another node's write
//! woke the queue, the wait's answer carried what is due in it, read by the
//! Storage node as it answered (`persist::storage::Moved`), and the reading
//! starts from that page instead of asking for it — a round trip less
//! after every wake, 0.14 ms over loopback (open problem 46). What it read
//! may be older than the claim taken on it, as any page may: each claim
//! reads its Message's place again (`super::under_claim`).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use persist::PersistError;
use persist::storage::{DuePart, DueQueue, Held};
use schedule::due::Due;

use super::SendStep;
use crate::queue_watch::Woken;

/// The most entries of a queue read at once: as many as a wake brings.
const PAGE: u32 = crate::queue_watch::DUE;

/// One entry a scan read: the entry, how long it still waits for its due
/// time where it is not due, and when the read of it was asked.
pub(super) type Read = (Held, Option<Duration>, Instant);

/// What is left to read of a queue, and what was read of it so far.
pub(super) struct Reading<'a> {
    step: &'a SendStep,
    queue: u128,
    read: VecDeque<Read>,
    /// Where the next page of what is due starts; `None` once read to its
    /// end.
    from: Option<(u64, u64)>,
    /// How many keep a retry's due time, and of those how many were read
    /// due.
    retrying: u64,
    due_retries: u64,
    /// Its first page as a wake brought it, read in place of asking.
    first: Option<(DueQueue, Instant)>,
    /// What the read of the latest page took: none where a wake brought it.
    took: Option<Duration>,
}

impl<'a> Reading<'a> {
    /// `queue` of `step` to read, from what `woken` brought of it where a
    /// wake brought what is due in it.
    pub(super) fn of(step: &'a SendStep, queue: u128, woken: Option<Woken>) -> Self {
        Self {
            step,
            queue,
            read: VecDeque::new(),
            from: Some((0, 0)),
            retrying: 0,
            due_retries: 0,
            first: woken.and_then(|woken| Some((woken.due?, woken.at))),
            took: None,
        }
    }

    /// What the read of the latest page took: none where a wake brought it.
    pub(super) const fn took(&self) -> Option<Duration> {
        self.took
    }

    /// The next entry read, or `None` where the queue is read to its end;
    /// what waits for a retry noted in `waits` as it is read — when the
    /// earliest is due, and, once read to the end, how many wait.
    ///
    /// # Errors
    ///
    /// Where Xmip Storage did not answer: the rest waits for the next scan.
    pub(super) fn next(&mut self, waits: &mut Due) -> Result<Option<Read>, PersistError> {
        if self.read.is_empty() && self.from.is_some() {
            self.page(waits)?;
        }
        let next = self.read.pop_front();
        if next.is_none() {
            waits.waiting = left(self.retrying, self.due_retries);
        }
        Ok(next)
    }

    /// The next page of what is due.
    fn page(&mut self, waits: &mut Due) -> Result<(), PersistError> {
        let Some(from) = self.from else {
            return Ok(());
        };
        let (asked, page) = self.part(DuePart::Due, from, waits)?;
        self.from = page
            .held
            .last()
            .filter(|_| page.held.len() == PAGE as usize)
            .map(DueQueue::after);
        self.due_retries += due_retries(&page);
        self.read.extend(read(&page, asked));
        Ok(())
    }

    /// One page of `part` from `from` — the first as a wake brought it,
    /// where one did — and when it was asked; the earliest retry not yet
    /// due noted in `waits`.
    fn part(
        &mut self,
        part: DuePart,
        from: (u64, u64),
        waits: &mut Due,
    ) -> Result<(Instant, DueQueue), PersistError> {
        let (asked, page) = match self.first.take() {
            Some((page, answered)) => {
                self.took = None;
                (answered, page)
            }
            None => {
                let asked = Instant::now();
                let page = self.step.storage.read_due(self.queue, part, from, PAGE)?;
                self.took = Some(asked.elapsed());
                (asked, page)
            }
        };
        self.retrying = page.retrying;
        if let Some(left) = page.next_due_in() {
            waits.wakes_at(asked + left);
        }
        Ok((asked, page))
    }
}

/// How many Messages of `queue` wait for a retry not yet due, as Xmip Storage
/// holds them now: every retry it counts, less those due, read past every
/// Message due since it was held, a page at a time — so no more is read
/// than the retries due (`super::due`, counted by the newest read).
///
/// # Errors
///
/// Where Xmip Storage did not answer.
pub(super) fn waiting(step: &SendStep, queue: u128) -> Result<u64, PersistError> {
    // A Message due since it was held is due at the epoch: past them all.
    let mut from = (1, 0);
    let mut due = 0;
    loop {
        let page = step.storage.read_due(queue, DuePart::Due, from, PAGE)?;
        due += due_retries(&page);
        match page
            .held
            .last()
            .filter(|_| page.held.len() == PAGE as usize)
        {
            Some(last) => from = DueQueue::after(last),
            None => return Ok(left(page.retrying, due)),
        }
    }
}

/// How many of `retrying`, every retry Xmip Storage counts in a queue, wait
/// for their due time, `due` of them being due.
const fn left(retrying: u64, due: u64) -> u64 {
    retrying.saturating_sub(due)
}

/// How many of `page` keep a retry's due time.
fn due_retries(page: &DueQueue) -> u64 {
    let retries = page
        .held
        .iter()
        .filter(|held| held.due_unix_nanos.is_some());
    u64::try_from(retries.count()).unwrap_or(u64::MAX)
}

/// Each entry of `page`, asked at `asked`, with how long it still waits.
fn read(page: &DueQueue, asked: Instant) -> impl Iterator<Item = Read> + '_ {
    page.held
        .iter()
        .map(move |held| (held.clone(), page.due_in(held), asked))
}
