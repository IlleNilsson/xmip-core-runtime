//! A Journey a paused Subscription held, picked up once it is resumed
//! (ADR-0013, amendment 2026-09-30; `runtime-model.md` section 9).
//!
//! **Everything is read back from the Ledger.** The Journey, its Message
//! and the Message's Stream were written by the receive; what the hold kept
//! beside the Journey is the identity arrival concluded, in its one binary
//! form (`context::facts_record`). So a Journey held before a restart, or
//! on another node, departs as it would have then. Departure authorizes
//! again, now, as it always does: what arrival concluded is a record of
//! then and never a licence to act now. A mechanism is never built from a
//! record (`xcore::Mechanism`): the one a held identity names is the one
//! this node's authenticators declare under that name, and a held Journey
//! whose mechanism the node no longer carries does not depart, in words.
//!
//! **Only a delivered Journey is released.** Every departure sent: the
//! Journey is written Completed and let go of from its queue in one write.
//! Anything else: it is written Failed and stays held, its Message with it
//! (`runtime-model.md` section 12). A read or a write Xmip Storage did not
//! answer leaves it, and everything after it in its queue, to be read
//! again from its place, so nothing is passed over that was not read. A
//! Journey sent whose release was not written is sent again when it is
//! read again: at least once, never lost (`runtime-model.md` section 15).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use context::IdentityFacts;
use journey::{Journey, JourneyEntry, JourneyState};
use message::Message;
use stream::Content;
use xcore::{ExecutionId, Mechanism, mechanism};

use crate::departure::{Departed, depart_to};
use crate::generation::ReceivedWork;
use crate::ledger::Chunks;
use crate::message_path::Runtime;
use crate::outcome::Tally;
use crate::pickup::{Pickup, Released};

/// How long the node waits for something to pick up before it looks
/// whether it is stopping: a resume or a hold wakes it at once.
const WAIT: Duration = Duration::from_millis(50);

/// The most held Journeys taken at once.
const MOST: usize = 64;

/// What the node picks up, as it is let go of, until it stops. A
/// Subscription whose held Journey is to be read again has the rest of
/// what it let go of this time read again too, so its order holds.
pub(crate) fn pick_up_released(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    stopping: &AtomicBool,
    tally: &Tally,
) {
    while !stopping.load(Ordering::Acquire) {
        let mut stalled: Vec<String> = Vec::new();
        for released in pickup.released(WAIT, MOST) {
            if stalled.contains(&released.subscription) {
                pickup.again(&released);
                continue;
            }
            match pick_up(runtime, pickup, &released) {
                Ok(departed) => tally.departed(&departed),
                Err(_) => {
                    pickup.again(&released);
                    stalled.push(released.subscription);
                }
            }
        }
    }
}

/// Pick up `released`: its Journey, its Message and the identity it
/// arrived with read back from the Ledger, a departure to where its
/// Subscription leads, and the Journey written as it ended — released
/// where it was delivered, kept Failed where not. A Failed Journey is
/// passed over unless a resume tries it again. The departures, none where
/// it was passed over.
///
/// # Errors
///
/// In words, where Xmip Storage did not answer a read or take a write: the
/// node reads it again ([`Pickup::again`]).
pub fn pick_up(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    released: &Released,
) -> Result<Vec<Departed>, String> {
    let storage = runtime.storage;
    let id = released.held.hold.journey;
    let Some(record) = storage.read_journey(id).map_err(|e| e.to_string())? else {
        pickup.unreadable(released, "its Journey is not in the Ledger");
        return Ok(Vec::new());
    };
    let journey = match Journey::from_record(&record.body) {
        Ok(journey) => journey,
        Err(why) => {
            pickup.unreadable(released, &why.to_string());
            return Ok(Vec::new());
        }
    };
    if journey.state == JourneyState::Failed && !released.retry {
        pickup.passed(released);
        return Ok(Vec::new());
    }
    let Some(held) = journey.messages().last().copied() else {
        pickup.unreadable(released, "its Journey holds no Message");
        return Ok(Vec::new());
    };
    let Some(kept) = storage
        .read_message(held.message_id)
        .map_err(|e| e.to_string())?
    else {
        pickup.unreadable(released, "its Message is not in the Ledger");
        return Ok(Vec::new());
    };
    let message = match Message::from_record(&kept.body, |stream| {
        Ok(Arc::new(Chunks::of(Arc::clone(storage), stream)) as Arc<dyn Content>)
    }) {
        Ok(message) => message,
        Err(why) => {
            pickup.unreadable(released, &why.to_string());
            return Ok(Vec::new());
        }
    };
    let to = &released.destination;
    let departed =
        match IdentityFacts::from_record(&released.held.hold.body, |name| carried(runtime, name)) {
            Ok(facts) => {
                let work = ReceivedWork {
                    journey: journey.clone(),
                    message,
                };
                depart_to(runtime, &work, &facts, to)
            }
            Err(why) => vec![Departed::Failed {
                to: to.clone(),
                retryable: false,
                detail: why.to_string(),
            }],
        };
    let delivered = !departed.is_empty() && departed.iter().all(Departed::sent);
    let ended = journey.append(
        JourneyEntry {
            execution_id: ExecutionId::new(runtime.ids.next_u128()),
            message_id: held.message_id,
            action: "send".to_string(),
            outcome: said(&departed),
            timestamp_unix_nanos: runtime.clock.unix_timestamp_nanos(),
        },
        if delivered {
            JourneyState::Completed
        } else {
            JourneyState::Failed
        },
    );
    if delivered {
        pickup.delivered(released, &ended)?;
    } else {
        pickup.kept(released, &ended)?;
    }
    Ok(departed)
}

/// What the departures came to, in words, as the Journey records it.
fn said(departed: &[Departed]) -> String {
    if departed.is_empty() {
        return "nowhere to go".to_string();
    }
    departed
        .iter()
        .map(|one| match one {
            Departed::Sent { to, .. } => format!("sent to {to}"),
            Departed::NoSuchDestination { to } => format!("no Send Location for {to}"),
            Departed::ProcessNotRun { to } => format!("{to} is run by no runtime yet"),
            Departed::NotPermitted { to, decision } => format!("not permitted to {to}: {decision}"),
            Departed::Failed { to, detail, .. } => format!("not sent to {to}: {detail}"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The mechanism of that name this node carries: one its authenticators
/// declare, or the circumstance every node infers (ADR-0019 clause 7).
fn carried(runtime: &Runtime<'_>, name: &str) -> Option<Mechanism> {
    runtime
        .authenticators
        .iter()
        .map(|authenticator| authenticator.mechanism())
        .chain([mechanism::circumstance()])
        .find(|mechanism| mechanism.name() == name)
}
