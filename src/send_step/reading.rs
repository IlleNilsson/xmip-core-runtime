//! What a scan reads of a queue: only what is due (the owner, 2026-10-19:
//! *a send scan reads only what is due*), through Xmip Storage's index of
//! when each Journey is due (`persist::storage::DueQueue`), so its cost
//! follows what is due, not what is held.
//!
//! A queue is read a page at a time, what is due in the order it fell due,
//! and the reading stops where the Send pool is full. What goes one at a
//! time per key is not this reading's: a Journey that does not head its
//! sequence is passed by its send (`crate::sequence`).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use persist::PersistError;
use persist::storage::{DuePart, DueQueue, Held};

use super::SendStep;
use super::due::Due;

/// The most entries of a queue read at once.
const PAGE: u32 = 64;

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
}

impl<'a> Reading<'a> {
    /// `queue` of `step` to read.
    pub(super) fn of(step: &'a SendStep, queue: u128) -> Self {
        Self {
            step,
            queue,
            read: VecDeque::new(),
            from: Some((0, 0)),
            retrying: 0,
            due_retries: 0,
        }
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
            waits.waiting = self.retrying.saturating_sub(self.due_retries);
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

    /// One page of `part` from `from`, and when it was asked; the earliest
    /// retry not yet due noted in `waits`.
    fn part(
        &mut self,
        part: DuePart,
        from: (u64, u64),
        waits: &mut Due,
    ) -> Result<(Instant, DueQueue), PersistError> {
        let asked = Instant::now();
        let page = self.step.storage.read_due(self.queue, part, from, PAGE)?;
        self.retrying = page.retrying;
        if let Some(left) = page.next_due_in() {
            waits.wakes_at(asked + left);
        }
        Ok((asked, page))
    }
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
