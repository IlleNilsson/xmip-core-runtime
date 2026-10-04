//! A Journey a paused Subscription held, picked up once it is resumed
//! (ADR-0013, amendment 2026-09-30; `runtime-model.md` section 9).
//!
//! **Picked up is moved on.** A held Journey goes where every Journey that
//! is not held goes at its Publication: to the queue of the Send Port it
//! leads to, from which the send step sends it (`crate::send_step`). The
//! move is one hand-on under a claim — its place in the Subscription's
//! queue let go of, its place at the end of the Send Port's taken — so a
//! held Journey is in one queue or the other, never both and never
//! neither. Where this node sends that Port, the claim is kept and the
//! Journey handed to the Send pool at once; otherwise it waits in the
//! Port's queue for a node that does.
//!
//! **Everything is read back from the Ledger.** The Journey, its Message
//! and the Message's Stream were written by the receive; what the hold kept
//! beside the Journey is the identity arrival concluded, in its one binary
//! form (`context::facts_record`), and it moves with it. So a Journey held
//! before a restart, or on another node, departs as it would have then.
//! Departure authorizes again, now, as it always does. A read or a write
//! Xmip Storage did not answer leaves it, and everything after it in its
//! queue, to be read again from its place, so nothing is passed over that
//! was not read.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use persist::storage::{HandOn, Hold};

use crate::departure::Progress;
use crate::message_path::Runtime;
use crate::pickup::{Pickup, Released};
use crate::send_step::{self, Departure, read};

/// How long the node waits for something to pick up before it looks
/// whether it is stopping: a resume or a hold wakes it at once.
const WAIT: Duration = Duration::from_millis(50);

/// The most held Journeys taken at once.
const MOST: usize = 64;

/// What the node picks up, as it is let go of, until it stops. A
/// Subscription whose held Journey is to be read again has the rest of
/// what it let go of this time read again too, so its order holds.
pub(crate) fn pick_up_released(runtime: &Runtime<'_>, pickup: &Pickup, stopping: &AtomicBool) {
    while !stopping.load(Ordering::Acquire) {
        let mut stalled: Vec<String> = Vec::new();
        for released in pickup.released(WAIT, MOST) {
            if stalled.contains(&released.subscription) {
                pickup.again(&released);
                continue;
            }
            if pick_up(runtime, pickup, &released).is_err() {
                pickup.again(&released);
                stalled.push(released.subscription);
            }
        }
    }
}

/// Pick up `released`: its Journey moved from its Subscription's queue to
/// the queue of where it leads, in one hand-on, and handed to the send step
/// where this node sends it. One the Ledger holds no Journey to send for is
/// audited and passed over, still held, for an operator.
///
/// # Errors
///
/// In words, where Xmip Storage did not answer a read or take the move, or
/// the Journey's claim is another's: the node reads it again
/// ([`Pickup::again`]).
pub fn pick_up(runtime: &Runtime<'_>, pickup: &Pickup, released: &Released) -> Result<(), String> {
    let (step, storage) = (runtime.send, runtime.storage);
    let id = released.held.hold.journey;
    let token = runtime.ids.next_u128();
    let claim = storage
        .claim(id, pickup.node(), token, step.lease())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("the Journey {id} is claimed by another"))?;
    let body = &released.held.hold.body;
    let (work, facts) = match read(runtime, id, body) {
        Ok(send_step::Found::Waiting(found)) => *found,
        Ok(send_step::Found::Failed(_) | send_step::Found::Finished) => {
            let _ = storage.release(&claim);
            pickup.unreadable(released, "its Journey has ended");
            return Ok(());
        }
        Ok(send_step::Found::Unreadable(why)) => {
            let _ = storage.release(&claim);
            pickup.unreadable(released, &why);
            return Ok(());
        }
        Err(why) => {
            let _ = storage.release(&claim);
            return Err(why);
        }
    };
    let to = released.destination.clone();
    let queue = step.queue(&to);
    let sent_here = runtime.sends.serves(&to) && !send_step::sequential(runtime.sends, &to);
    let moved = HandOn {
        claim: claim.clone(),
        result: send_step::record(&work.journey),
        messages: Vec::new(),
        next: Vec::new(),
        leaves: vec![released.held.hold.queue],
        queued: vec![Hold {
            queue,
            journey: id,
            body: body.clone(),
        }],
        kept_for_nanos: sent_here
            .then(|| u64::try_from(step.lease().as_nanos()).unwrap_or(u64::MAX)),
    };
    match storage.hand_on(&moved) {
        Ok(true) => {}
        Ok(false) => return Err(format!("the claim on the Journey {id} lapsed")),
        Err(error) => {
            // Given back, so reading it again claims it again at once.
            let _ = storage.release(&claim);
            return Err(error.to_string());
        }
    }
    pickup.moved(released);
    if sent_here {
        step.hand(Departure {
            work,
            facts,
            to,
            queue,
            claim,
            progress: Progress::default(),
            sequence: None,
        });
    } else {
        step.ask(queue);
    }
    Ok(())
}
