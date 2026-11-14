//! A scan of a queue the node sends: what is due in it that no live claim
//! holds, claimed in the order it fell due, each under a place the Send
//! pool admits, and none past the last place it has. Only what is due is
//! read (the owner, 2026-10-19). A Message that failed stays in its queue
//! for an operator, in a part of the queue's index of its own, never read,
//! and counted in the queue's index of failed Messages; a Retry moves it to
//! a new place. What goes one at a time per key is the sequence's: a
//! Message that does not head its sequence is passed by its send and taken
//! up again once it does (`crate::sequence`). Every claim a scan takes
//! reads the Message's place again under it, its due time with it, and
//! sends only what is still there, due and to be sent.

use std::collections::HashSet;
use std::time::Instant;

use context::IdentityFacts;
use persist::storage::{Claim, Durable};
use route::Subscriber;
use schedule::due::Due;
use xcore::JourneyId;

use super::found::Found;
use super::reading::Reading;
use super::steps::{Step, Steps};
use super::under_claim::{Under, under_claim};
use super::{Departure, Owned};
use crate::departure::Progress;
use crate::generation::ReceivedWork;
use crate::message_path::Runtime;
use crate::queue_watch::Woken;

/// What is due in `queue`, bound for `to`, that this node is to send now —
/// each under a place its Send pool admits, and where none is left the
/// queue starved until one frees — read in the order it fell due, only
/// what is due ([`Reading`]), from what a wake brought of it where `woken`
/// says, with when its read began, each that no live claim holds claimed.
/// On a Sequential Send Port only the oldest of each sequence that nothing
/// is in flight, waiting or blocked before it, read before it is claimed
/// and again once it is, its queue read in its order with what waits for a
/// retry and, where it blocks, what failed. A retry not yet due is passed
/// over unclaimed, the queue woken for its due time ([`Due`]); a read to
/// the end of what is due forgets every place passed over that is gone
/// from it.
pub(super) fn scan(
    runtime: &Runtime<'_>,
    to: &Subscriber,
    queue: u128,
    woken: Option<(Woken, Instant)>,
) -> Vec<Ready> {
    let mut waits = Due::of(to.name());
    let began = runtime.send.reading(queue);
    let (found, whole) = scanning(runtime, (to, queue), &mut waits, woken);
    runtime.send.waited(queue, (waits, began), whole);
    found
}

/// [`scan`]'s reading, the retries it found not yet due kept in `waits`:
/// what it found to send, and whether it read the whole queue.
fn scanning(
    runtime: &Runtime<'_>,
    (to, queue): (&Subscriber, u128),
    waits: &mut Due,
    woken: Option<(Woken, Instant)>,
) -> (Vec<Ready>, bool) {
    let step = runtime.send;
    let sequenced = !crate::sequence::points_of(runtime.sends, to).is_empty()
        || crate::sequence::grouped(runtime.sends, to);
    let mut present = HashSet::new();
    let mut found = Vec::new();
    // What each it finds took so far: the wake reaching this read.
    let mut steps = Steps::default();
    if let Some((woken, read)) = &woken {
        steps.set(Step::Woken, read.saturating_duration_since(woken.at));
    }
    let mut reading = Reading::of(step, queue, woken.map(|(woken, _)| woken));
    let mut answered = false;
    loop {
        let next = match reading.next(waits) {
            Ok(next) => next,
            Err(why) => {
                step.queue_read(to.name(), Some(why.to_string()));
                return (found, false);
            }
        };
        if !answered {
            answered = true;
            step.queue_read(to.name(), None);
        }
        let Some((held, due_in, asked)) = next else {
            step.read_whole(queue, &present);
            return (found, true);
        };
        let id = held.hold.journey;
        let place = (id, held.sequence);
        present.insert(place);
        if held.failed {
            continue;
        }
        if let Some(left) = due_in {
            // Its retry is not due: nothing claims it.
            waits.wakes_at(asked + left);
            continue;
        }
        let known = {
            let state = step.lock();
            state.owned.contains_key(&id)
                || state.taking.contains(&id)
                || state
                    .passed
                    .get(&queue)
                    .is_some_and(|set| set.contains(&place))
        };
        if known {
            continue;
        }
        if step.admit(1) == 0 {
            // The pool is full: the rest waits unclaimed, read again
            // once a place frees, so nothing claimed lapses behind a
            // backlog and nothing waits in memory.
            step.starve(queue);
            return (found, false);
        }
        step.lock().taking.insert(id);
        let mut unclaimed = Unclaimed {
            to: to.clone(),
            queue,
            place,
            body: held.hold.body.clone(),
            steps: steps.clone(),
        };
        if let Some(due) = reading.took() {
            unclaimed.steps.set(Step::Due, due);
        }
        unclaimed.steps.ready();
        if sequenced {
            // Claimed here, in the queue's order, so the places a Message
            // takes once its Stream heads follow the Ledger's order: no
            // two send threads race for them (`crate::sequence::heading`).
            match placed(runtime, &unclaimed) {
                Some(mut departure) => {
                    departure.steps.ready();
                    found.push(Ready::Claimed(Box::new(departure)));
                }
                None => step.untake(id),
            }
        } else {
            // Claimed on a send thread, so a backlog's claims share their
            // commits rather than wait one by one here.
            found.push(Ready::Unclaimed(Box::new(unclaimed)));
        }
    }
}

/// `unclaimed`, on a destination naming a Correlation, claimed and its
/// places taken where it still waits for them and its Stream heads.
fn placed(runtime: &Runtime<'_>, unclaimed: &Unclaimed) -> Option<Departure> {
    let mut departure = take(runtime, unclaimed)?;
    if crate::sequence::waits_for_places(runtime.sends, &departure.work.journey, &departure.to) {
        // Behind another Stream or not, its pass says: one still waiting
        // for its places is passed, its claim given back.
        let _ = crate::sequence::heading(
            runtime.storage.as_ref(),
            (runtime.work.cluster(), runtime.sends, runtime.gathering),
            (
                &mut departure.work.journey,
                &departure.work.message,
                &departure.to,
            ),
            (&departure.claim, runtime.send.lease()),
        );
    }
    Some(departure)
}

/// What a scan found to send.
pub(super) enum Ready {
    /// Under a place admitted, to be claimed and read on a send thread.
    Unclaimed(Box<Unclaimed>),
    /// Claimed already, in the queue's order, its places taken.
    Claimed(Box<Departure>),
}

/// A Message a scan found that no live claim holds: where it leads, its
/// queue, its place, what is kept beside it, and what finding it took.
pub(super) struct Unclaimed {
    to: Subscriber,
    queue: u128,
    place: (JourneyId, u64),
    body: Vec<u8>,
    steps: Steps,
}

impl Unclaimed {
    /// Its Journey's identifier.
    pub(super) const fn journey(&self) -> JourneyId {
        self.place.0
    }
}

/// `unclaimed` claimed, then read: owned and ready to send, or `None`
/// where another holds it, it is not to be sent, or Xmip Storage did not
/// answer — its place then the caller's to give back
/// ([`super::SendStep::untake`]); a later scan reads it again.
pub(super) fn take(runtime: &Runtime<'_>, unclaimed: &Unclaimed) -> Option<Departure> {
    let Unclaimed {
        to,
        queue,
        place,
        body,
        steps,
    } = unclaimed;
    let mut steps = steps.clone();
    steps.taken_up();
    match claimed_first(runtime, (to, *queue), *place, (body, &mut steps)) {
        Taken::One(one) => Some(owned(runtime.send, to, *queue, (*one, steps))),
        Taken::Passed | Taken::Unanswered => None,
    }
}

/// What a claim took, owned by this node in the place admitted for it, as
/// the departure it is sent as, with what its send took so far: its claim
/// surely held a lease from when it was asked.
fn owned(
    step: &super::SendStep,
    to: &Subscriber,
    queue: u128,
    (one, steps): (Took, Steps),
) -> Departure {
    let (work, facts, (claim, durable), asked) = one;
    let departure = Departure {
        progress: Progress::of(work.journey.attempts),
        work,
        facts,
        to: to.clone(),
        queue,
        claim,
        until: asked + step.lease,
        durable: Some(durable),
        handed: false,
        spent: None,
        measured: None,
        steps,
    };
    step.own(departure.work.journey.journey_id(), Owned::of(&departure));
    departure
}

/// What a claim took: the Journey and its Message, the identity it arrived
/// with, the claim with when it is durable, and when the claim was asked.
type Took = (ReceivedWork, IdentityFacts, (Claim, Durable), Instant);

impl super::SendStep {
    /// The Message at `place` in `queue` passed over by every scan after.
    fn passed(&self, queue: u128, place: (JourneyId, u64)) {
        self.lock().passed.entry(queue).or_default().insert(place);
    }
}

/// What a scan made of one entry.
enum Taken {
    One(Box<Took>),
    Passed,
    /// Xmip Storage did not answer: the rest of the queue waits for the
    /// next scan.
    Unanswered,
}

/// An entry of a queue, at its `place`, bound for `to`: claimed ahead of
/// its sync, then read with its place under the readable claim
/// ([`under_claim`]), each timed in `steps`: the claim's answer, never its
/// sync, which the send waits on before its far end sees anything (ADR-0018,
/// amendment 2026-11-12).
fn claimed_first(
    runtime: &Runtime<'_>,
    (to, queue): (&Subscriber, u128),
    place: (JourneyId, u64),
    (body, steps): (&[u8], &mut Steps),
) -> Taken {
    let step = runtime.send;
    let id = place.0;
    let token = runtime.ids.next_u128();
    let asked = Instant::now();
    let claimed = step.storage.claim_ahead(id, &step.node, token, step.lease);
    steps.set(Step::Claim, asked.elapsed());
    let (claim, durable) = match claimed {
        Ok((Some(claim), durable)) => (claim, durable),
        Ok((None, _)) => return Taken::Passed,
        Err(_) => return Taken::Unanswered,
    };
    let under = under_claim(runtime, queue, place, (body, steps));
    if let Under::Waiting(found) = under {
        let (work, facts) = *found;
        return Taken::One(Box::new((work, facts, (claim, durable), asked)));
    }
    // Given back once durable, so the claim's word is read, never dropped.
    let _ = durable.wait();
    let _ = step.storage.release(&claim);
    match under {
        Under::Waiting(_) | Under::Moved => Taken::Passed,
        Under::NotDue(at) => {
            step.not_due((to.name(), queue), at);
            Taken::Passed
        }
        Under::Not(Found::Unreadable(why)) => {
            step.passed(queue, place);
            step.failed(&format!(
                "the Message of the Journey {id} is not sent: {why}"
            ));
            Taken::Passed
        }
        Under::Not(_) => {
            step.passed(queue, place);
            Taken::Passed
        }
        Under::Unanswered => Taken::Unanswered,
    }
}
