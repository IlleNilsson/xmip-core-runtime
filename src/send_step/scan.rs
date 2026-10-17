//! A scan of a queue the node sends: what waits in it that no live claim
//! holds, claimed oldest first — on a Sequential Send Port only the oldest
//! of each sequence nothing is in flight or blocked before — each under a
//! place the Send pool admits, and none past the last place it has. A
//! Journey that failed stays in its queue for an operator, passed over by
//! its place's mark in the Ledger without its Journey being read — unless
//! it blocks its sequence, which is read to know which — and counted in the
//! queue's index of failed Journeys; a Retry moves it to a new place, or,
//! where it blocks its sequence, makes it one to send where it is. Every
//! claim a scan takes reads the Journey's place again under it, its due
//! time with it, and sends only what is still there, due and to be sent.

use std::collections::HashSet;
use std::time::Instant;

use configure::OnFailure;
use context::IdentityFacts;
use persist::storage::Claim;
use route::Subscriber;
use xcore::JourneyId;

use super::due::Due;
use super::pass::{Found, read, sequence};
use super::under_claim::{Under, under_claim};
use super::{Departure, Owned};
use crate::departure::Progress;
use crate::generation::ReceivedWork;
use crate::message_path::Runtime;
use crate::sending::Destination;

/// The most entries of a queue read at once.
const PAGE: u32 = 64;

/// What waits in `queue`, bound for `to`, that this node is to send now —
/// each under a place its Send pool admits, and where none is left the
/// queue starved until one frees — read oldest first, each that no live
/// claim holds claimed. On a Sequential Send Port only the
/// oldest of each sequence that nothing is in flight, waiting or blocked
/// before it, read before it is claimed and again once it is. A place
/// marked failed is passed over unread, unless it blocks its sequence; a
/// place whose retry is not yet due is passed over unclaimed, its due time
/// noted for the queue ([`Due`]); a read of the whole queue forgets every
/// place passed over that is gone from it.
pub(super) fn scan(runtime: &Runtime<'_>, to: &Subscriber, queue: u128) -> Vec<Ready> {
    let mut waits = Due::of(to.name());
    runtime.send.reading(queue);
    let (found, whole) = scanning(runtime, (to, queue), &mut waits);
    runtime.send.waited(queue, waits, whole);
    found
}

/// [`scan`]'s reading, the retries it found not yet due kept in `waits`:
/// what it found to send, and whether it read the whole queue.
fn scanning(
    runtime: &Runtime<'_>,
    (to, queue): (&Subscriber, u128),
    waits: &mut Due,
) -> (Vec<Ready>, bool) {
    let step = runtime.send;
    let ordered = match runtime.sends.to(to) {
        Destination::Ports(ports) => ports.iter().find_map(|port| {
            port.sequence()
                .map(|(key, on_failure)| (key.map(str::to_string), on_failure))
        }),
        Destination::Process | Destination::Nowhere => None,
    };
    let blocking = matches!(ordered, Some((_, OnFailure::Block)));
    let mut busy: HashSet<String> = step
        .lock()
        .owned
        .values()
        .filter(|owned| owned.queue == queue)
        .filter_map(|owned| owned.sequence.clone())
        .collect();
    let mut present = HashSet::new();
    let mut found = Vec::new();
    let mut from = 0;
    loop {
        let asked = Instant::now();
        let page = match step.storage.read_held(queue, from, PAGE) {
            Ok(page) => page,
            Err(why) => {
                step.queue_read(to.name(), Some(why.to_string()));
                return (found, false);
            }
        };
        step.queue_read(to.name(), None);
        let read_all = page.held.len() < PAGE as usize;
        for held in &page.held {
            from = held.sequence + 1;
            let id = held.hold.journey;
            let place = (id, held.sequence);
            present.insert(place);
            if held.failed && !blocking {
                continue;
            }
            if let Some(left) = page.due_in(held) {
                // Its retry is not due: nothing claims it, and on a
                // Sequential Port its sequence waits behind it.
                waits.waits(asked + left);
                let Some((key, _)) = &ordered else {
                    continue;
                };
                match read(runtime, id, &held.hold.body) {
                    Ok(Found::Waiting(waiting)) => {
                        busy.insert(sequence(&waiting.0.message, key.as_deref()));
                    }
                    Ok(_) => {}
                    Err(_) => return (found, false),
                }
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
            let body = &held.hold.body;
            let Some((key, on_failure)) = &ordered else {
                // Claimed on a send thread, so a backlog's claims share
                // their commits rather than wait one by one here.
                step.lock().taking.insert(id);
                found.push(Ready::Unclaimed(Unclaimed {
                    to: to.clone(),
                    queue,
                    place,
                    body: body.clone(),
                }));
                continue;
            };
            let taken = in_sequence(
                runtime,
                (to, queue),
                (place, body),
                (key.as_deref(), *on_failure),
                &mut busy,
            );
            match taken {
                Taken::One(one) => {
                    found.push(Ready::Claimed(Box::new(owned(step, to, queue, *one))))
                }
                Taken::Passed => step.withdraw(1),
                Taken::Unanswered => {
                    step.withdraw(1);
                    return (found, false);
                }
            }
        }
        if read_all {
            step.read_whole(queue, &present);
            return (found, true);
        }
    }
}

/// What a scan found to send.
pub(super) enum Ready {
    /// Claimed and read, in its place in a sequence.
    Claimed(Box<Departure>),
    /// Under a place admitted, to be claimed and read on a send thread.
    Unclaimed(Unclaimed),
}

/// A Journey a scan found that no live claim holds, in a queue that is not
/// ordered: where it leads, its queue, its place and what is kept beside it.
pub(super) struct Unclaimed {
    to: Subscriber,
    queue: u128,
    place: (JourneyId, u64),
    body: Vec<u8>,
}

impl Unclaimed {
    /// The Journey.
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
    } = unclaimed;
    match claimed_first(runtime, (to, *queue), *place, body) {
        Taken::One(one) => Some(owned(runtime.send, to, *queue, *one)),
        Taken::Passed | Taken::Unanswered => None,
    }
}

/// What a claim took, owned by this node in the place admitted for it, as
/// the departure it is sent as: its claim surely held a lease from when it
/// was asked.
fn owned(step: &super::SendStep, to: &Subscriber, queue: u128, one: Took) -> Departure {
    let (work, facts, claim, sequence, asked) = one;
    let departure = Departure {
        progress: Progress::of(work.journey.attempts),
        work,
        facts,
        to: to.clone(),
        queue,
        claim,
        sequence,
        until: asked + step.lease,
    };
    step.own(departure.work.journey.journey_id(), Owned::of(&departure));
    departure
}

/// What a claim took: the Journey and its Message, the identity it arrived
/// with, the claim, its sequence on a Sequential Send Port, and when the
/// claim was asked.
type Took = (ReceivedWork, IdentityFacts, Claim, Option<String>, Instant);

impl super::SendStep {
    /// The Journey at `place` in `queue` passed over by every scan after.
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

/// An entry of a queue that is not ordered, at its `place`, bound for `to`:
/// claimed, then read with its place ([`under_claim`]).
fn claimed_first(
    runtime: &Runtime<'_>,
    (to, queue): (&Subscriber, u128),
    place: (JourneyId, u64),
    body: &[u8],
) -> Taken {
    let step = runtime.send;
    let id = place.0;
    let token = runtime.ids.next_u128();
    let asked = Instant::now();
    let claim = match step.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Taken::Passed,
        Err(_) => return Taken::Unanswered,
    };
    let under = under_claim(runtime, queue, place, body);
    if let Under::Waiting(found) = under {
        let (work, facts) = *found;
        return Taken::One(Box::new((work, facts, claim, None, asked)));
    }
    let _ = step.storage.release(&claim);
    match under {
        Under::Waiting(_) | Under::Moved => Taken::Passed,
        Under::NotDue(at) => {
            step.not_due((to.name(), queue), at);
            Taken::Passed
        }
        Under::Not(Found::Unreadable(why)) => {
            step.passed(queue, place);
            step.failed(&format!("the Journey {id} is not sent: {why}"));
            Taken::Passed
        }
        Under::Not(_) => {
            step.passed(queue, place);
            Taken::Passed
        }
        Under::Unanswered => Taken::Unanswered,
    }
}

/// An entry of a Sequential Send Port's queue: read, its sequence told,
/// and claimed only where nothing of its sequence before it is in flight,
/// held by another, or failed and blocking (`busy`) — and, once claimed,
/// read again with its place ([`under_claim`]): another node may have sent
/// it and let go of its place between the first read and the claim, or
/// handed it on to wait for a retry.
fn in_sequence(
    runtime: &Runtime<'_>,
    (to, queue): (&Subscriber, u128),
    (place, body): ((JourneyId, u64), &[u8]),
    (key, on_failure): (Option<&str>, OnFailure),
    busy: &mut HashSet<String>,
) -> Taken {
    let step = runtime.send;
    let id = place.0;
    let work = match read(runtime, id, body) {
        Ok(Found::Waiting(found)) => {
            let (work, _) = *found;
            work
        }
        // Blocking, it is read at every scan, its place marked failed or
        // not: a Retry keeps its place.
        Ok(Found::Failed(work)) if on_failure == OnFailure::Block => {
            busy.insert(sequence(&work.message, key));
            return Taken::Passed;
        }
        Ok(Found::Failed(_) | Found::Finished) => {
            step.passed(queue, place);
            return Taken::Passed;
        }
        Ok(Found::Unreadable(why)) => {
            step.passed(queue, place);
            step.failed(&format!("the Journey {id} is not sent: {why}"));
            return Taken::Passed;
        }
        Err(_) => return Taken::Unanswered,
    };
    let told = sequence(&work.message, key);
    if !busy.insert(told.clone()) {
        return Taken::Passed;
    }
    let token = runtime.ids.next_u128();
    let asked = Instant::now();
    let claim = match step.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Taken::Passed,
        Err(_) => return Taken::Unanswered,
    };
    let under = under_claim(runtime, queue, place, body);
    if let Under::Waiting(found) = under {
        let (work, facts) = *found;
        return Taken::One(Box::new((work, facts, claim, Some(told), asked)));
    }
    let _ = step.storage.release(&claim);
    match under {
        // Moved or settled meanwhile: read afresh at the next scan, its
        // sequence held until then.
        Under::Waiting(_) | Under::Moved | Under::Not(_) => Taken::Passed,
        Under::NotDue(at) => {
            step.not_due((to.name(), queue), at);
            Taken::Passed
        }
        Under::Unanswered => Taken::Unanswered,
    }
}
