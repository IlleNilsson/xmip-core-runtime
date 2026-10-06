//! One pass of a Journey's send and its hand-on, and a Journey read back
//! from the Ledger to be sent: what the Send pool's threads run, and what a
//! scan finds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use configure::OnFailure;
use context::IdentityFacts;
use journey::{Journey, JourneyEntry, JourneyState};
use message::Message;
use persist::storage::{HandOn, JourneyRecord};
use route::Subscriber;
use stream::Content;
use xcore::{ExecutionId, JourneyId, Mechanism, mechanism};

use super::Departure;
use crate::departure::{Departed, depart_to, said};
use crate::generation::ReceivedWork;
use crate::ledger::Chunks;
use crate::message_path::Runtime;
use crate::sending::Destination;

/// How one pass of a send ended, once its hand-on was written.
#[derive(Debug)]
pub enum Ended {
    /// Sent to every Port: written Completed, and out of its queue.
    Completed(Vec<Departed>),
    /// A Location is tried again after `after`: written Recovering, its
    /// claim kept until then and a lease past it.
    Waiting {
        after: Duration,
        departed: Vec<Departed>,
    },
    /// Every Location failed its tries: written Failed with `reason`, its
    /// Message with it, kept in its queue for an operator's Retry or
    /// Dismiss; a Sequential Send Port whose `on_failure` is `block` holds
    /// its sequence behind it.
    Failed {
        reason: String,
        departed: Vec<Departed>,
    },
    /// The claim was no longer this node's — it lapsed, and another took
    /// the Journey up, or a renewal found it another's — so nothing was
    /// written, and nothing more tried from here.
    Lost(Vec<Departed>),
    /// Xmip Storage did not take the hand-on, in words: the claim lapses,
    /// and the Journey is sent again — at least once, never lost.
    Unwritten(String),
}

/// One pass of `departure`'s send — its Send Port, unless sent already,
/// tried once on its active Send Location, failing over as its policy says,
/// each try only while its claim is surely this node's — and its hand-on,
/// one write: the outcome on the Journey, with what was tried in words and
/// its tries, its place let go of where it was sent, and the claim released
/// or kept to its due time. A claim a renewal found another's writes
/// nothing: the Journey is the other holder's.
pub fn send(runtime: &Runtime<'_>, departure: &mut Departure) -> Ended {
    let step = runtime.send;
    let Departure {
        work,
        facts,
        to,
        progress,
        ..
    } = departure;
    let id = work.journey.journey_id();
    let owned = || step.holds(id);
    let departed = depart_to(runtime, work, facts, to, (progress, &owned));
    if step.is_lost(id) {
        return Ended::Lost(departed);
    }
    let (state, kept) = if progress.sent {
        (JourneyState::Completed, None)
    } else if progress.waiting() {
        let after = backoff(runtime, &departure.to);
        (JourneyState::Recovering, Some(after))
    } else {
        (JourneyState::Failed, None)
    };
    let mut outcome = said(&departed);
    if let Some(after) = kept {
        outcome = format!("{outcome}; tried again in {after:?}");
    }
    match written(runtime, departure, state, outcome, kept) {
        Ok(true) => {}
        Ok(false) => return Ended::Lost(departed),
        Err(why) => return Ended::Unwritten(why),
    }
    match (state, kept) {
        (JourneyState::Completed, _) => Ended::Completed(departed),
        (_, Some(after)) => Ended::Waiting { after, departed },
        _ => Ended::Failed {
            reason: format!(
                "{}: {}",
                departure.to.name(),
                departure.progress.given_up.as_deref().unwrap_or_default()
            ),
            departed,
        },
    }
}

/// `departure`, whose send thread panicked before its hand-on, written
/// Failed with `why` — kept in its queue for an operator, as every Journey
/// that failed is — and its claim ended; released where Xmip Storage did
/// not take the write, so it is not held to its lapse.
pub(super) fn abandoned(runtime: &Runtime<'_>, departure: &mut Departure, why: &str) -> Ended {
    match written(
        runtime,
        departure,
        JourneyState::Failed,
        why.to_string(),
        None,
    ) {
        Ok(true) => Ended::Failed {
            reason: format!("{}: {why}", departure.to.name()),
            departed: Vec::new(),
        },
        Ok(false) => Ended::Lost(Vec::new()),
        Err(unwritten) => {
            let _ = runtime.storage.release(&departure.claim);
            Ended::Unwritten(unwritten)
        }
    }
}

/// `departure`'s hand-on, one write: its Journey in `state` with what was
/// tried, `outcome`, and its tries; its place let go of where it completed;
/// its claim ended, or kept to `kept` and a lease past it. `true` where it
/// was written, and the Journey kept on `departure` — and, kept, its claim
/// surely held to `kept` and a lease from when the write was asked; `false`
/// where the claim was no longer this node's; in words where Xmip Storage
/// did not take it.
fn written(
    runtime: &Runtime<'_>,
    departure: &mut Departure,
    state: JourneyState,
    outcome: String,
    kept: Option<Duration>,
) -> Result<bool, String> {
    let mut journey = departure.work.journey.clone().append(
        JourneyEntry {
            execution_id: ExecutionId::new(runtime.ids.next_u128()),
            message_id: departure.work.message.message_id(),
            action: "send".to_string(),
            outcome,
            timestamp_unix_nanos: runtime.clock.unix_timestamp_nanos(),
        },
        state,
    );
    journey.attempts = departure.progress.attempts();
    let lease = runtime.send.lease();
    let hand_on = HandOn {
        claim: departure.claim.clone(),
        result: record(&journey),
        messages: Vec::new(),
        next: Vec::new(),
        leaves: if state == JourneyState::Completed {
            vec![departure.queue]
        } else {
            Vec::new()
        },
        queued: Vec::new(),
        requeued: Vec::new(),
        kept_for_nanos: kept.map(|after| nanos(after + lease)),
    };
    let asked = Instant::now();
    match runtime.storage.hand_on(&hand_on) {
        Ok(true) => {
            departure.work.journey = journey;
            if let Some(after) = kept {
                departure.until = asked + after + lease;
            }
            Ok(true)
        }
        Ok(false) => Ok(false),
        Err(error) => Err(format!(
            "Xmip Storage did not take the send of the Journey {}: {error}",
            journey.journey_id()
        )),
    }
}

/// How long the Send Port `to` waits before its active Location is tried
/// again.
fn backoff(runtime: &Runtime<'_>, to: &Subscriber) -> Duration {
    match to {
        Subscriber::SendPort(port) => runtime.sends.port(port).backoff(),
        Subscriber::SendGroup(_) | Subscriber::WorkProcess(_) => Duration::ZERO,
    }
}

/// Whether a Journey bound for `to` that failed blocks its sequence:
/// `on_failure = "block"` on a Sequential Send Port.
pub(super) fn blocks(runtime: &Runtime<'_>, to: &Subscriber) -> bool {
    match runtime.sends.to(to) {
        Destination::Ports(ports) => ports
            .iter()
            .any(|port| matches!(port.sequence(), Some((_, OnFailure::Block)))),
        Destination::Process | Destination::Nowhere => false,
    }
}

/// What the Ledger holds of a Journey in a queue.
#[derive(Debug)]
pub enum Found {
    /// Still to be sent: its Journey and Message, and the identity it
    /// arrived with.
    Waiting(Box<(ReceivedWork, IdentityFacts)>),
    /// Failed, kept in its queue: its sequence blocks behind it.
    Failed(Box<ReceivedWork>),
    /// Completed or dismissed already.
    Finished,
    /// Not readable as a Journey to send, in words: passed over, for an
    /// operator.
    Unreadable(String),
}

/// The Journey `journey` read back from the Ledger, its Message and its
/// Message's Stream with it, and the identity it arrived with from `body`,
/// what its queue keeps beside it (`context::facts_record`). A mechanism is
/// never built from a record (`xcore::Mechanism`): the one a kept identity
/// names is the one this node's authenticators declare under that name.
///
/// # Errors
///
/// In words, where Xmip Storage did not answer: read again later.
pub fn read(runtime: &Runtime<'_>, journey: JourneyId, body: &[u8]) -> Result<Found, String> {
    let storage = runtime.storage;
    let Some(record) = storage.read_journey(journey).map_err(|e| e.to_string())? else {
        return Ok(Found::Unreadable(
            "its Journey is not in the Ledger".to_string(),
        ));
    };
    let journey = match Journey::from_record(&record.body) {
        Ok(journey) => journey,
        Err(why) => return Ok(Found::Unreadable(why.to_string())),
    };
    if matches!(
        journey.state,
        JourneyState::Completed | JourneyState::Dismissed
    ) {
        return Ok(Found::Finished);
    }
    let Some(held) = journey.messages().last().copied() else {
        return Ok(Found::Unreadable(
            "its Journey holds no Message".to_string(),
        ));
    };
    let Some(kept) = storage
        .read_message(held.message_id)
        .map_err(|e| e.to_string())?
    else {
        return Ok(Found::Unreadable(
            "its Message is not in the Ledger".to_string(),
        ));
    };
    let message = match Message::from_record(&kept.body, |stream| {
        Ok(Arc::new(Chunks::of(Arc::clone(storage), stream)) as Arc<dyn Content>)
    }) {
        Ok(message) => message,
        Err(why) => return Ok(Found::Unreadable(why.to_string())),
    };
    let work = ReceivedWork { journey, message };
    if work.journey.state == JourneyState::Failed {
        return Ok(Found::Failed(Box::new(work)));
    }
    match IdentityFacts::from_record(body, |name| carried(runtime, name)) {
        Ok(facts) => Ok(Found::Waiting(Box::new((work, facts)))),
        Err(why) => Ok(Found::Unreadable(why.to_string())),
    }
}

/// The value of `key` in `message`'s context — what a Sequential Send
/// Port's sequences are told apart by — or empty, where it carries none or
/// the Port names none: one sequence for all of them.
#[must_use]
pub fn sequence(message: &Message, key: Option<&str>) -> String {
    key.and_then(|key| message.context().get(key))
        .and_then(xcore::ScalarValue::text)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
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

/// A Journey as Xmip Storage keeps it.
pub(crate) fn record(journey: &Journey) -> JourneyRecord {
    JourneyRecord {
        journey: journey.journey_id(),
        body: journey.record(),
    }
}

/// A duration in nanoseconds, the most a `u64` holds at most.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
