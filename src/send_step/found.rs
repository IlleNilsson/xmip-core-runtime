//! A Message read back from the Ledger to be sent (`super`): what a scan
//! finds under its claim, and what an operator's act and a Work Process's
//! turn read of a Journey.

use std::time::Instant;

use context::IdentityFacts;
use journey::{Journey, JourneyState};
use message::Message;
use persist::storage::Claimed;
use xcore::{JourneyId, Mechanism, mechanism};

use super::steps::{Step, Steps};
use crate::generation::ReceivedWork;
use crate::ledger::Chunks;
use crate::message_path::Runtime;

/// What the Ledger holds of a Message in a queue.
#[derive(Debug)]
pub enum Found {
    /// Still to be sent: its Journey and Message, and the identity it
    /// arrived with.
    Waiting(Box<(ReceivedWork, IdentityFacts)>),
    /// Failed, kept in its queue: its sequence blocks behind it.
    Failed(Box<ReceivedWork>),
    /// Completed or dismissed already.
    Finished,
    /// Not readable as a Message to send, in words: passed over, for an
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
    let record = runtime
        .storage
        .read_journey(journey)
        .map_err(|e| e.to_string())?;
    let kept = Claimed {
        journey: record,
        ..Claimed::default()
    };
    found(runtime, kept, body, &mut Steps::default())
}

/// What `kept` holds of a Journey read back — its record, and its Message
/// and that Message's Stream's record where they were read with it under a
/// claim (`persist::storage::Claimed`) — as [`read`] says it, with `body`;
/// a Message or a Stream not read with it read now, its time added to
/// `steps`' read.
///
/// # Errors
///
/// As [`read`].
pub(super) fn found(
    runtime: &Runtime<'_>,
    kept: Claimed,
    body: &[u8],
    steps: &mut Steps,
) -> Result<Found, String> {
    let storage = runtime.storage;
    let Some(record) = kept.journey else {
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
    let began = Instant::now();
    let read_with = kept.message.filter(|read| read.message == held.message_id);
    let read_message = match read_with {
        Some(read) => Some(read),
        None => storage
            .read_message(held.message_id)
            .map_err(|e| e.to_string())?,
    };
    let Some(message) = read_message else {
        return Ok(Found::Unreadable(
            "its Message is not in the Ledger".to_string(),
        ));
    };
    let stream = kept.stream;
    let message = Message::from_record(&message.body, |id| match &stream {
        Some(record) if record.stream == id => Ok(Chunks::kept(storage, record)),
        _ => Chunks::referred(storage, id),
    });
    steps.add(Step::Read, began.elapsed());
    let message = match message {
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
