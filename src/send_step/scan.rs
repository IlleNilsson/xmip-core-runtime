//! A scan of a queue the node sends: what waits in it that no live claim
//! holds, claimed oldest first — on a Sequential Send Port only the oldest
//! of each sequence nothing is in flight or blocked before — each under a
//! place the Send pool admits, and none past the last place it has. A
//! Journey that failed stays in its queue for an operator, passed over at
//! its place and kept as its Port's evidence; a Retry moves it to a new
//! one, or, where it blocks its sequence, makes it one to send where it is.

use std::collections::HashSet;

use configure::OnFailure;
use context::IdentityFacts;
use persist::storage::Claim;
use route::Subscriber;
use xcore::JourneyId;

use super::pass::{Found, read, sequence};
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
/// oldest of each sequence that nothing is in flight or blocked before it,
/// read before it is claimed and again once it is. Every Journey read
/// Failed is kept as its Port's evidence; a read of the whole queue forgets
/// what failed there and is gone from it.
pub(super) fn scan(runtime: &Runtime<'_>, to: &Subscriber, queue: u128) -> Vec<Ready> {
    let step = runtime.send;
    let ordered = match runtime.sends.to(to) {
        Destination::Ports(ports) => ports.iter().find_map(|port| {
            port.sequence()
                .map(|(key, on_failure)| (key.map(str::to_string), on_failure))
        }),
        Destination::Process | Destination::Nowhere => None,
    };
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
        let Ok(page) = step.storage.read_held(queue, from, PAGE) else {
            return found;
        };
        let read_all = page.held.len() < PAGE as usize;
        for held in page.held {
            from = held.sequence + 1;
            let id = held.hold.journey;
            let place = (id, held.sequence);
            present.insert(place);
            let known = {
                let state = step.lock();
                state.owned.contains_key(&id)
                    || state.taking.contains(&id)
                    || state.passed.contains(&place)
            };
            if known {
                continue;
            }
            if step.admit(1) == 0 {
                // The pool is full: the rest waits unclaimed, read again
                // once a place frees, so nothing claimed lapses behind a
                // backlog and nothing waits in memory.
                step.starve(queue);
                return found;
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
                    return found;
                }
            }
        }
        if read_all {
            step.read_whole(to.name(), &present);
            return found;
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
    match claimed_first(runtime, to, *place, body) {
        Taken::One(one) => Some(owned(runtime.send, to, *queue, *one)),
        Taken::Passed | Taken::Unanswered => None,
    }
}

/// What a claim took, owned by this node in the place admitted for it, as
/// the departure it is sent as.
fn owned(
    step: &super::SendStep,
    to: &Subscriber,
    queue: u128,
    (work, facts, claim, sequence): (ReceivedWork, IdentityFacts, Claim, Option<String>),
) -> Departure {
    let owned = Owned {
        claim: claim.clone(),
        queue,
        sequence: sequence.clone(),
    };
    step.own(work.journey.journey_id(), owned);
    Departure {
        progress: Progress::of(work.journey.attempts),
        work,
        facts,
        to: to.clone(),
        queue,
        claim,
        sequence,
    }
}

/// What a scan made of one entry.
enum Taken {
    One(Box<(ReceivedWork, IdentityFacts, Claim, Option<String>)>),
    Passed,
    /// Xmip Storage did not answer: the rest of the queue waits for the
    /// next scan.
    Unanswered,
}

/// What a scan read of the Journey at `place` bound for `to`, kept as its
/// Port's evidence: Failed with why, or no longer failing.
fn noted(runtime: &Runtime<'_>, to: &Subscriber, place: (JourneyId, u64), found: &Found) {
    let step = runtime.send;
    match found {
        Found::Failed(work) => {
            let reason = work
                .journey
                .entries()
                .last()
                .map(|entry| entry.outcome.clone())
                .unwrap_or_default();
            step.found_failing(to.name(), place.1, place.0, reason);
        }
        Found::Waiting(_) | Found::Finished | Found::Unreadable(_) => {
            step.not_failing(to.name(), place.0);
        }
    }
}

/// An entry of a queue that is not ordered, at its `place`: claimed, then
/// read.
fn claimed_first(
    runtime: &Runtime<'_>,
    to: &Subscriber,
    place: (JourneyId, u64),
    body: &[u8],
) -> Taken {
    let step = runtime.send;
    let id = place.0;
    let token = runtime.ids.next_u128();
    let claim = match step.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Taken::Passed,
        Err(_) => return Taken::Unanswered,
    };
    let found = read(runtime, id, body);
    if let Ok(found) = &found {
        noted(runtime, to, place, found);
    }
    match found {
        Ok(Found::Waiting(found)) => {
            let (work, facts) = *found;
            Taken::One(Box::new((work, facts, claim, None)))
        }
        Ok(Found::Failed(_) | Found::Finished) => {
            let _ = step.storage.release(&claim);
            step.lock().passed.insert(place);
            Taken::Passed
        }
        Ok(Found::Unreadable(why)) => {
            let _ = step.storage.release(&claim);
            step.lock().passed.insert(place);
            step.failed(&format!("the Journey {id} is not sent: {why}"));
            Taken::Passed
        }
        Err(_) => {
            let _ = step.storage.release(&claim);
            Taken::Unanswered
        }
    }
}

/// An entry of a Sequential Send Port's queue: read, its sequence told,
/// and claimed only where nothing of its sequence before it is in flight,
/// held by another, or failed and blocking (`busy`) — and, once claimed,
/// read again with its place: another node may have sent it and let go of
/// its place between the first read and the claim.
fn in_sequence(
    runtime: &Runtime<'_>,
    (to, queue): (&Subscriber, u128),
    (place, body): ((JourneyId, u64), &[u8]),
    (key, on_failure): (Option<&str>, OnFailure),
    busy: &mut HashSet<String>,
) -> Taken {
    let step = runtime.send;
    let id = place.0;
    let found = read(runtime, id, body);
    if let Ok(found) = &found {
        noted(runtime, to, place, found);
    }
    let work = match found {
        Ok(Found::Waiting(found)) => {
            let (work, _) = *found;
            work
        }
        // Blocking, it is read at every scan: a Retry keeps its place.
        Ok(Found::Failed(work)) if on_failure == OnFailure::Block => {
            busy.insert(sequence(&work.message, key));
            return Taken::Passed;
        }
        Ok(Found::Failed(_) | Found::Finished) => {
            step.lock().passed.insert(place);
            return Taken::Passed;
        }
        Ok(Found::Unreadable(why)) => {
            step.lock().passed.insert(place);
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
    let claim = match step.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Taken::Passed,
        Err(_) => return Taken::Unanswered,
    };
    match still_waiting(runtime, queue, place, body) {
        Some(Ok(found)) => {
            let (work, facts) = found;
            Taken::One(Box::new((work, facts, claim, Some(told))))
        }
        // Moved meanwhile: read afresh at the next scan, its sequence held
        // until then.
        Some(Err(())) => {
            let _ = step.storage.release(&claim);
            Taken::Passed
        }
        None => {
            let _ = step.storage.release(&claim);
            Taken::Unanswered
        }
    }
}

/// The Journey at `place` in `queue`, read under this node's claim: still
/// at its place and still to be sent, or not (`Err`); `None` where Xmip
/// Storage did not answer.
fn still_waiting(
    runtime: &Runtime<'_>,
    queue: u128,
    (id, at): (JourneyId, u64),
    body: &[u8],
) -> Option<Result<(ReceivedWork, IdentityFacts), ()>> {
    let page = runtime.send.storage.read_held(queue, at, 1).ok()?;
    let held = page
        .held
        .first()
        .is_some_and(|held| held.sequence == at && held.hold.journey == id);
    if !held {
        return Some(Err(()));
    }
    match read(runtime, id, body).ok()? {
        Found::Waiting(found) => Some(Ok(*found)),
        Found::Failed(_) | Found::Finished | Found::Unreadable(_) => Some(Err(())),
    }
}
