//! What a step knows of the heads of the sequences its queue's Messages
//! wait in, and of each the Messages behind its head, in their order
//! (ADR-0066, amendment 2026-11-22; open problem 93: a Work Process's pass
//! took a turn of every entry it read, each claimed, read, asked and given
//! back, and completed one Message a sequence, so 10,777 sales orders went
//! through at two to four a minute).
//!
//! **Each head read once; its successor handed over.** An entry read from
//! the queue says the sequences its Stream holds a place in
//! ([`super::Kept`]), kept as a [`Queued`]: identifiers only. The
//! first of a sequence the step meets is taken up as before, its turn
//! asking the Ledger under its claim; every later one is kept here behind
//! it, and the sequence's head is read once ([`super::read_head`]). One
//! behind the head is not claimed, read or turned: the step waits on the
//! head ([`Positions`]), and once it moves — the watch says so, or a turn
//! here ended — the head is read again and the one now heading is handed
//! over ([`Heads::handed`]), no read of the queue. What a step does costs
//! with its sequences, never with what waits behind them.
//!
//! **Bounded.** At most [`KEPT`] Messages are kept a sequence: past them the
//! sequence is cut, its later ones read again from where it was cut once
//! those kept are gone ([`Heads::refill`]), a range of the queue from there.
//! At most [`MOST`] are kept a queue: a read meeting more stops until some
//! are gone ([`Met::Full`]).
//!
//! **A hint, never the truth.** What is handed over is claimed and asked
//! under its claim as every turn is (`super::heading`): one gone, moved on or
//! another's is let go of ([`Heads::ended`]), one found behind kept again.
//! Lost on a restart, it costs a read of the queue from its start.

use std::collections::{HashMap, HashSet, VecDeque};

use persist::storage::{Position, XmipStorage};
use xcore::JourneyId;

use super::head::{HeadRead, Stands, read_head};
use super::queued::Queued;

/// The most Messages kept behind one sequence's head: a page of a queue.
pub const KEPT: usize = crate::queue_watch::DUE as usize;

/// The most Messages kept for one queue.
pub const MOST: usize = 65_536;

/// What a step makes of an entry its read of the queue met ([`Heads::met`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Met {
    /// Kept already, or taken up: passed.
    Known,
    /// To be taken up now: it heads its sequences, holds a place in none,
    /// or is the first of its sequence met.
    Goes,
    /// Kept behind its sequence's head.
    Waits,
    /// Past where its sequence is cut: read again once it is read on.
    Unkept,
    /// As many as a queue keeps are kept: the read stops at it.
    Full,
}

/// Each head to wait on, as read: once it moves, what waits behind it is
/// handed over.
pub type Positions = Vec<Position>;

/// How a Message taken up ended, as its step tells it ([`Heads::ended`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakenUp {
    /// Gone from where it waited: written, failed, or no Message to take
    /// up any more. What it held may have moved.
    Gone,
    /// Behind a head after all: kept again.
    Back,
}

/// What is known of the head of one sequence as read.
#[derive(Clone, Debug, Default)]
enum Seen {
    /// Never read: the first of it met is taken up as before.
    #[default]
    Unread,
    /// Moved since it was read: read again once it is asked.
    Stale,
    /// As read, and whether it was named to wait on.
    Read(HeadRead, bool),
}

/// One sequence: its head as read, the Messages kept behind it in their
/// order, where it is cut, and how many of it are taken up.
#[derive(Debug, Default)]
struct Lane {
    head: Seen,
    waiting: VecDeque<Queued>,
    cut: Option<u64>,
    taken: usize,
}

/// What a step knows of the sequences of one queue.
#[derive(Debug, Default)]
pub struct Heads {
    lanes: HashMap<u128, Lane>,
    /// The Messages kept behind a head, and those taken up and not ended.
    known: HashSet<JourneyId>,
    kept: usize,
    /// The sequences whose first kept Message is to be asked again.
    check: Vec<u128>,
}

impl Heads {
    /// `queued`, met by a read of its queue: kept behind its head, or to be
    /// taken up ([`Met`]), its head read where it is not known and it is not
    /// the first of it met; each head newly found ahead of it to wait on.
    ///
    /// # Errors
    /// Xmip Storage did not answer a head's read, in words.
    pub fn met(
        &mut self,
        storage: &dyn XmipStorage,
        queued: Queued,
    ) -> Result<(Met, Positions), String> {
        if self.known.contains(&queued.journey) {
            return Ok((Met::Known, Vec::new()));
        }
        if queued.places.is_empty() {
            return Ok((Met::Goes, Vec::new()));
        }
        let place = queued.place();
        let unkept = queued.places.iter().any(|(queue, _)| {
            self.lanes.get(queue).is_some_and(|lane| {
                lane.cut.is_some_and(|cut| place >= cut) || lane.waiting.len() >= KEPT
            })
        });
        if unkept {
            for (queue, _) in &queued.places {
                let lane = self.lanes.entry(*queue).or_default();
                lane.cut = Some(lane.cut.map_or(place, |cut| cut.min(place)));
            }
            return Ok((Met::Unkept, Vec::new()));
        }
        if self.kept >= MOST {
            return Ok((Met::Full, Vec::new()));
        }
        self.keep(&queued, None);
        match self.standing(storage, &queued)? {
            None => {
                self.take(&queued);
                Ok((Met::Goes, Vec::new()))
            }
            Some(positions) => Ok((Met::Waits, positions)),
        }
    }

    /// The head of `queue` moved, or may have: read again once asked, and
    /// what waits first behind it asked. Whether it keeps anything of it.
    pub fn moved(&mut self, queue: u128) -> bool {
        let Some(lane) = self.lanes.get_mut(&queue) else {
            return false;
        };
        lane.head = Seen::Stale;
        self.check.push(queue);
        true
    }

    /// The head of `queue` stands at `at` now, as the watch says: read again
    /// once asked where it was read before it got there, else nothing, its
    /// move told already. Whether it keeps anything of it.
    pub fn moved_to(&mut self, queue: u128, at: u64) -> bool {
        match self.lanes.get(&queue).map(|lane| &lane.head) {
            None => false,
            Some(Seen::Read(read, _)) if read.at() >= at => true,
            Some(_) => self.moved(queue),
        }
    }

    /// Every head read again once asked: the bound on a wake that never
    /// came.
    pub fn moved_every(&mut self) {
        let queues: Vec<u128> = self.lanes.keys().copied().collect();
        for queue in queues {
            self.moved(queue);
        }
    }

    /// Whether a head moved since it was asked.
    #[must_use]
    pub fn to_hand(&self) -> bool {
        !self.check.is_empty()
    }

    /// Each Message now heading every sequence it holds a place in, of those
    /// whose head moved, taken up; each head found ahead of the next to wait
    /// on. One read of each moved head, none of the queue.
    ///
    /// # Errors
    /// Xmip Storage did not answer a head's read, in words: what was not
    /// asked yet is asked the next time.
    pub fn handed(
        &mut self,
        storage: &dyn XmipStorage,
    ) -> Result<(Vec<Queued>, Positions), String> {
        let mut check = std::mem::take(&mut self.check);
        check.sort_unstable();
        check.dedup();
        let (mut goes, mut waits) = (Vec::new(), Vec::new());
        for (at, queue) in check.iter().enumerate() {
            while let Some(front) = self.front(*queue) {
                match self.standing(storage, &front) {
                    Ok(None) => {
                        self.take(&front);
                        goes.push(front);
                    }
                    Ok(Some(positions)) => {
                        waits.extend(positions);
                        break;
                    }
                    Err(why) => {
                        self.check.extend(&check[at..]);
                        return Err(why);
                    }
                }
            }
            self.forget_if_done(*queue);
        }
        Ok((goes, waits))
    }

    /// `queued`, taken up, ended as `how` says: what it held asked again,
    /// and kept again where it is behind after all.
    pub fn ended(&mut self, queued: &Queued, how: TakenUp) {
        if !self.known.remove(&queued.journey) {
            return;
        }
        for (queue, _) in &queued.places {
            if let Some(lane) = self.lanes.get_mut(queue) {
                lane.taken = lane.taken.saturating_sub(1);
            }
            self.moved(*queue);
        }
        if how == TakenUp::Back {
            self.keep(queued, None);
        }
    }

    /// A sequence whose kept Messages are gone and that is cut: where to read
    /// its queue on from for the rest of it.
    #[must_use]
    pub fn refill(&self) -> Option<(u128, u64)> {
        self.lanes
            .iter()
            .filter(|(_, lane)| lane.waiting.is_empty())
            .find_map(|(queue, lane)| Some((*queue, lane.cut?)))
    }

    /// `page`, read for the sequence `queue` from where it was cut, before
    /// `frontier`, where the step's own read stands: its Messages there kept,
    /// up to [`KEPT`], and the sequence cut again where the next page starts,
    /// `next`, or no more once the page reached `frontier` or the end.
    pub fn refilled(&mut self, queue: u128, page: &[Queued], (next, frontier): (Option<u64>, u64)) {
        let Some(cut) = self.lanes.get(&queue).and_then(|lane| lane.cut) else {
            return;
        };
        let mut cut_at = next.filter(|next| *next < frontier);
        for queued in page {
            let place = queued.place();
            if place < cut || !queued.places.iter().any(|(held, _)| *held == queue) {
                continue;
            }
            if place >= frontier {
                cut_at = None;
                break;
            }
            let full = self
                .lanes
                .get(&queue)
                .is_none_or(|lane| lane.waiting.len() >= KEPT);
            if full || self.kept >= MOST {
                cut_at = Some(place);
                break;
            }
            if !self.known.contains(&queued.journey) {
                self.keep(queued, Some(queue));
            }
        }
        if let Some(lane) = self.lanes.get_mut(&queue) {
            lane.cut = cut_at;
        }
        self.check.push(queue);
    }

    /// How many Messages it keeps behind a head now.
    #[must_use]
    pub const fn kept(&self) -> usize {
        self.kept
    }

    /// `queued` kept behind its head in each sequence it holds a place in —
    /// or only `in_lane` — in its place's order.
    fn keep(&mut self, queued: &Queued, in_lane: Option<u128>) {
        for (queue, _) in &queued.places {
            if in_lane.is_some_and(|lane| lane != *queue) {
                continue;
            }
            let lane = self.lanes.entry(*queue).or_default();
            let at = lane
                .waiting
                .partition_point(|kept| kept.place() < queued.place());
            lane.waiting.insert(at, queued.clone());
        }
        self.known.insert(queued.journey);
        self.kept += 1;
    }

    /// `queued`, heading its sequences, taken up: no longer kept, taken.
    fn take(&mut self, queued: &Queued) {
        for (queue, _) in &queued.places {
            if let Some(lane) = self.lanes.get_mut(queue) {
                lane.waiting.retain(|kept| kept.journey != queued.journey);
                lane.taken += 1;
            }
        }
        self.kept = self.kept.saturating_sub(1);
    }

    /// The first kept behind the head of `queue`.
    fn front(&self, queue: u128) -> Option<Queued> {
        self.lanes.get(&queue)?.waiting.front().cloned()
    }

    /// A sequence with nothing kept, cut or taken up, forgotten.
    fn forget_if_done(&mut self, queue: u128) {
        let done = self
            .lanes
            .get(&queue)
            .is_some_and(|lane| lane.waiting.is_empty() && lane.cut.is_none() && lane.taken == 0);
        if done {
            self.lanes.remove(&queue);
        }
    }

    /// Whether `queued`, kept, heads every sequence it holds a place in, each
    /// head not known read now: `None` where it does, or it is the first met
    /// of a sequence never read; else each head newly found ahead of it.
    fn standing(
        &mut self,
        storage: &dyn XmipStorage,
        queued: &Queued,
    ) -> Result<Option<Positions>, String> {
        let mut behind = false;
        let mut positions = Vec::new();
        for (queue, holder) in &queued.places {
            let Some(lane) = self.lanes.get_mut(queue) else {
                continue;
            };
            // Behind one kept ahead of it: asked once that one is gone.
            if lane
                .waiting
                .front()
                .is_some_and(|front| front.place() < queued.place())
            {
                behind = true;
                continue;
            }
            if matches!(lane.head, Seen::Unread) && lane.taken == 0 {
                continue;
            }
            if !matches!(lane.head, Seen::Read(..)) {
                lane.head = Seen::Read(read_head(storage, *queue)?, false);
            }
            if let Seen::Read(read, waited) = &mut lane.head
                && let Stands::Behind(at) = read.stands(*queue, *holder)
            {
                behind = true;
                if !*waited {
                    *waited = true;
                    positions.push(at);
                }
            }
        }
        Ok(behind.then_some(positions))
    }
}

#[cfg(test)]
mod tests;
