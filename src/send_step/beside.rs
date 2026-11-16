//! The next of a sequence waits beside the one ahead of it that this node
//! is sending now (ADR-0018, amendment 2026-11-15; `runtime-model.md`
//! section 3, *Sequences*: decided 2026-11-15, *the send side keeps up*).
//!
//! **One beside each send under way.** A Message whose pass finds it behind
//! a Stream ahead of it in a sequence, where the one heading that sequence
//! is in a send on this node and the Message is the next there — second in
//! each sequence it waits in, the one heading it this node's — keeps its
//! claim and waits in memory beside it: owned, its claim renewed, its place
//! in the Send pool held, no thread. The moment the one ahead's pass ends
//! here, its hand-on answered and durable, the one beside it is passed
//! again on the same thread: its sequences read from the Ledger, and sent
//! where it heads them. So the next send of a sequence costs no release, no
//! claim again and no sync of its own; until 2026-11-15 it gave its claim
//! back, and was claimed and read again from its queue once the head moved,
//! a sync's wait more before its first byte.
//!
//! **Its first byte waits for its predecessor's hand-on to be durable** (the
//! owner, 2026-11-15: *Wait for the disk*, so the order survives any crash),
//! by the one rule every send keeps, whoever sent the one ahead: its read
//! of its sequences says when the write that let it head is durable, where
//! it is not yet, and its first byte waits for that
//! (`crate::sequence::may_go`). One that reads that it heads them while the
//! one ahead is still in its send here goes on its own thread and waits
//! there; until the Ledger said it, it waited beside that send instead.
//!
//! **Everything else gives its claim back**, as before: one behind a Stream
//! no send here heads, one further behind, one where another waits beside
//! already, and all of them once the step closes. As a Message heads its
//! sequences here, and again as its pass ends with nothing beside it, the
//! next behind it is taken up from its queue at once (`super::behind`), so a
//! sequence that fell behind is carried one beside the other again.

use persist::storage::{Position, Watched};

use super::{Departure, SendStep};

/// What a pass found behind is to do ([`SendStep::wait_beside`]).
pub(super) enum Beside {
    /// Waiting beside the one ahead of it in its send here, under its claim.
    Waits,
    /// Heading its sequences by now, none ahead of it in a send here — or
    /// behind one no send here heads any more: to be passed again at once,
    /// its sequences read anew, its claim kept.
    Goes(Departure),
    /// Behind, as its pass found it: its claim to be given back.
    Behind(Departure),
}

impl SendStep {
    /// `departure` heads every sequence it holds and goes on to its send:
    /// the one ahead in each, here, until its pass ends; and the next
    /// behind it in each taken up from its queue now, to wait beside it.
    pub(super) fn heads_here(&self, departure: &Departure) {
        let id = departure.work.journey.journey_id();
        let mut state = self.lock();
        let mut read = Vec::new();
        for (queue, holder) in crate::sequence::held_by(&departure.work.journey) {
            state.ahead.insert(queue, (id, holder));
            read.extend(state.behind.take_up(Watched::Head(queue)));
        }
        drop(state);
        for queue in read {
            self.ask(queue);
        }
    }

    /// `departure`, its pass behind `waits`, each read again: kept beside
    /// the one ahead of it, where that is one Message in its send here,
    /// `departure` the next behind it in each sequence it does not head, and
    /// none beside it yet; to be passed again now, where it heads them all
    /// by now, or the one it was read behind is in no send here any more —
    /// its pass may have ended since; behind otherwise, its claim the
    /// caller's to give back.
    pub(super) fn wait_beside(&self, departure: Departure, waits: &[Position]) -> Beside {
        let places: Vec<(u128, u128)> = crate::sequence::held_by(&departure.work.journey).collect();
        // Each sequence it waits in read now: by now its own, or the one
        // heading it and `departure` the next there.
        let mut second_to = Vec::with_capacity(waits.len());
        for wait in waits {
            let Watched::Head(queue) = wait.watched else {
                return Beside::Behind(departure);
            };
            let Some(member) = places
                .iter()
                .find(|(held, _)| *held == queue)
                .map(|(_, member)| *member)
            else {
                return Beside::Behind(departure);
            };
            let Ok(page) = self.storage.read_held(queue, 0, 2) else {
                return Beside::Behind(departure);
            };
            let mut holders = page.held.iter().map(|held| held.hold.journey.value());
            match (holders.next(), holders.next()) {
                (Some(first), _) if first == member => {}
                (Some(first), Some(second)) if second == member => second_to.push((queue, first)),
                _ => return Beside::Behind(departure),
            }
        }
        let id = departure.work.journey.journey_id();
        let mut state = self.lock();
        if state.closed {
            return Beside::Behind(departure);
        }
        // The one ahead of it in each sequence, in its send here: one, or
        // none at all.
        let mut ahead_of_it = None;
        for (queue, _) in &places {
            let next_to = second_to
                .iter()
                .find(|(waited, _)| waited == queue)
                .map(|(_, first)| *first);
            let here = state.ahead.get(queue).filter(|(ahead, _)| *ahead != id);
            let one = match (next_to, here) {
                (Some(first), Some((ahead, holder))) if *holder == first => *ahead,
                // Behind another than the one heading it here.
                (Some(_), Some(_)) => return Beside::Behind(departure),
                // Behind one no send here heads now — maybe one whose pass
                // ended here since the read: its sequences are read again.
                (Some(_), None) => return Beside::Goes(departure),
                // Heading it, where the one before it may still be in its
                // send here: its read of its sequences says when that one's
                // hand-on is durable (`crate::sequence::may_go`).
                (None, _) => continue,
            };
            match ahead_of_it {
                Some(known) if known != one => return Beside::Behind(departure),
                _ => ahead_of_it = Some(one),
            }
        }
        let Some(ahead) = ahead_of_it else {
            return Beside::Goes(departure);
        };
        if state.beside.contains_key(&ahead) {
            return Beside::Behind(departure);
        }
        state.beside.insert(ahead, departure);
        Beside::Waits
    }

    /// The pass of `departure` ended — its hand-on answered, or nothing
    /// written: no longer ahead here, and the one waiting beside it to be
    /// passed again now, by the caller; given back instead where the step
    /// closed. Where none waits beside it, the next behind it is taken up
    /// from its queue now.
    pub(super) fn passed_on(&self, departure: &Departure) -> Option<Departure> {
        let id = departure.work.journey.journey_id();
        let mut state = self.lock();
        let mut ended = Vec::new();
        state.ahead.retain(|queue, (ahead, _)| {
            let gone = *ahead == id;
            if gone {
                ended.push(*queue);
            }
            !gone
        });
        let Some(mut next) = state.beside.remove(&id) else {
            let mut read = Vec::new();
            for queue in ended {
                read.extend(state.behind.take_up(Watched::Head(queue)));
            }
            drop(state);
            for queue in read {
                self.ask(queue);
            }
            return None;
        };
        if state.closed {
            let place = (next.work.journey.journey_id(), next.queue);
            state.let_go(place, self.letting_go());
            state.freed();
            drop(state);
            let _ = self.storage.release(&next.claim);
            self.wake.notify_all();
            return None;
        }
        next.steps.ready();
        Some(next)
    }

    /// `departure`, waiting beside one whose pass ended where it cannot be
    /// passed on at once — a send thread unwinding — handed to the pool.
    pub(super) fn hand_back(&self, mut departure: Departure) {
        departure.steps.ready();
        self.lock().handed.push_back(departure);
        self.wake.notify_all();
    }
}
