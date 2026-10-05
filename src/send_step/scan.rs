//! A scan of a queue the node sends: what waits in it that no live claim
//! holds, claimed oldest first — on a Sequential Send Port only the oldest
//! of each sequence nothing is in flight or blocked before. A Journey that
//! failed stays in its queue for an operator, passed over at its place; a
//! Retry moves it to a new one, or, where it blocks its sequence, makes it
//! one to send where it is.

use std::collections::HashSet;

use configure::OnFailure;
use route::Subscriber;

use super::pass::{Found, read, sequence};
use super::{Departure, Owned};
use crate::departure::Progress;
use crate::message_path::Runtime;
use crate::sending::Destination;

/// The most entries of a queue read at once.
const PAGE: u32 = 64;

/// What waits in `queue`, bound for `to`, that this node is to send now:
/// read oldest first, each that no live claim holds claimed. On a
/// Sequential Send Port only the oldest of each sequence that nothing is in
/// flight or blocked before it, read before it is claimed.
pub(super) fn scan(runtime: &Runtime<'_>, to: &Subscriber, queue: u128) -> Vec<Departure> {
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
            let known = {
                let state = step.lock();
                state.owned.contains_key(&id) || state.passed.contains(&place)
            };
            if known {
                continue;
            }
            let body = &held.hold.body;
            let taken = match &ordered {
                Some((key, on_failure)) => in_sequence(
                    runtime,
                    (place, body),
                    (key.as_deref(), *on_failure),
                    &mut busy,
                ),
                None => claimed_first(runtime, place, body),
            };
            match taken {
                Taken::One(one) => {
                    let (work, facts, claim, sequence) = *one;
                    let progress = Progress::of(work.journey.attempts);
                    step.lock().owned.insert(
                        id,
                        Owned {
                            claim: claim.clone(),
                            queue,
                            sequence: sequence.clone(),
                        },
                    );
                    found.push(Departure {
                        work,
                        facts,
                        to: to.clone(),
                        queue,
                        claim,
                        progress,
                        sequence,
                    });
                }
                Taken::Passed => {}
                Taken::Unanswered => return found,
            }
        }
        if read_all {
            return found;
        }
    }
}

/// What a scan made of one entry.
enum Taken {
    One(
        Box<(
            crate::generation::ReceivedWork,
            context::IdentityFacts,
            persist::storage::Claim,
            Option<String>,
        )>,
    ),
    Passed,
    /// Xmip Storage did not answer: the rest of the queue waits for the
    /// next scan.
    Unanswered,
}

/// An entry of a queue that is not ordered, at its `place`: claimed, then
/// read.
fn claimed_first(runtime: &Runtime<'_>, place: (xcore::JourneyId, u64), body: &[u8]) -> Taken {
    let step = runtime.send;
    let id = place.0;
    let token = runtime.ids.next_u128();
    let claim = match step.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Taken::Passed,
        Err(_) => return Taken::Unanswered,
    };
    match read(runtime, id, body) {
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
/// held by another, or failed and blocking (`busy`).
fn in_sequence(
    runtime: &Runtime<'_>,
    (place, body): ((xcore::JourneyId, u64), &[u8]),
    (key, on_failure): (Option<&str>, OnFailure),
    busy: &mut HashSet<String>,
) -> Taken {
    let step = runtime.send;
    let id = place.0;
    let (work, facts) = match read(runtime, id, body) {
        Ok(Found::Waiting(found)) => *found,
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
    match step.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => Taken::One(Box::new((work, facts, claim, Some(told)))),
        Ok(None) => Taken::Passed,
        Err(_) => Taken::Unanswered,
    }
}
