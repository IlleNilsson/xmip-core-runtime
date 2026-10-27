//! One pass of a Journey's send and its hand-on, and a Journey read back
//! from the Ledger to be sent: what the Send pool's threads run, and what a
//! scan finds.

use std::time::Duration;

use configure::OnFailure;
use context::IdentityFacts;
use journey::{Journey, JourneyEntry, JourneyState};
use message::Message;
use persist::storage::{Durable, Failure, HandOn, Wait};
use route::Subscriber;
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
    /// A Location is tried again after `after`: written Recovering, its due
    /// time kept at its place in its queue, its claim released.
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
    /// Nothing was tried: the claim was not surely this node's when the
    /// pass began — its last confirmation older than a lease — though no
    /// renewal found it another's. Nothing is written, so the pass leaves no
    /// entry and counts no try; the claim is given back and the queue read
    /// again, where a scan claims it afresh. Until 2026-10-16 such a pass was
    /// written Recovering, an entry and a backoff for a try never made.
    Untried,
    /// Its Stream does not head a sequence it holds a place in
    /// (`crate::sequence`): nothing is tried or written, its claim is
    /// given back, and it waits in its queue until the Stream ahead of it
    /// has ended and a scan takes it up.
    Behind,
    /// Xmip Storage did not take the hand-on, in words: the claim lapses,
    /// and the Journey is sent again — at least once, never lost.
    Unwritten(String),
}

/// One pass of `departure`'s send — its Send Port, unless sent already,
/// tried once on its active Send Location, failing over as its policy says,
/// each try only while its claim is surely this node's — and its hand-on,
/// one write: the outcome on the Journey, with what was tried in words and
/// its tries, its place let go of where it was sent or its due time kept
/// there where it waits, and the claim released. A claim a renewal found
/// another's writes nothing: the Journey is the other holder's; nor does a
/// pass that tried nothing ([`Ended::Untried`]).
pub fn send(runtime: &Runtime<'_>, departure: &mut Departure) -> Ended {
    let step = runtime.send;
    match placed(runtime, departure) {
        Ok(true) => {}
        Ok(false) => return Ended::Lost(Vec::new()),
        Err(why) => return Ended::Unwritten(why),
    }
    match heads(runtime, departure) {
        Ok(true) => {}
        Ok(false) => return Ended::Behind,
        Err(why) => return Ended::Unwritten(why),
    }
    let Departure {
        work,
        facts,
        to,
        progress,
        durable,
        claim,
        ..
    } = departure;
    // The far end is told the claim's fence beside the deduplication key.
    progress.fence = claim.fence;
    let id = work.journey.journey_id();
    let owned = || step.holds(id);
    let kept = || {
        durable
            .as_ref()
            .map_or(Ok(()), Durable::wait)
            .map_err(|why| format!("its Publication was not kept in the Ledger: {why}"))
    };
    let departed = depart_to(runtime, work, facts, to, (progress, &owned, &kept));
    if step.is_lost(id) {
        return Ended::Lost(departed);
    }
    if departed.is_empty() && progress.waiting() {
        return Ended::Untried;
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
/// tried, `outcome`, and its tries; its place let go of where it completed,
/// or, Failed, entered in its queue's index of failed Journeys with
/// `outcome` as why, or, waiting, its due time `kept` from now kept at its
/// place; its claim ended. `true` where it was written, and the Journey
/// kept on `departure`; `false` where the claim was no longer this node's;
/// in words where Xmip Storage did not take it.
fn written(
    runtime: &Runtime<'_>,
    departure: &mut Departure,
    state: JourneyState,
    outcome: String,
    kept: Option<Duration>,
) -> Result<bool, String> {
    // Failed, it waits in its queue for an operator, entered in the queue's
    // index of failed Journeys in this same write, with why.
    let failed = (state == JourneyState::Failed).then(|| Failure {
        queue: departure.queue,
        reason: outcome.clone(),
    });
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
    // Its places in its Send Port's and its Send Locations' sequences are
    // let go once it is sent, or once it failed, each where a failure lets
    // the rest pass.
    let leaves_point: Vec<u128> = departure
        .work
        .journey
        .sequences
        .iter()
        .filter(|sequenced| match state {
            JourneyState::Completed => true,
            JourneyState::Failed => sequenced.skips,
            _ => false,
        })
        .map(|sequenced| sequenced.queue)
        .collect();
    let hand_on = HandOn {
        claim: departure.claim.clone(),
        result: crate::ledger::journey_record(&journey),
        messages: Vec::new(),
        next: Vec::new(),
        leaves: if state == JourneyState::Completed {
            vec![departure.queue]
        } else {
            Vec::new()
        }
        .into_iter()
        .chain(leaves_point)
        .collect(),
        queued: Vec::new(),
        requeued: Vec::new(),
        failed,
        cleared: Vec::new(),
        waits: kept.map(|after| Wait {
            queue: departure.queue,
            after_nanos: nanos(after),
        }),
        kept_for_nanos: None,
    };
    match runtime.storage.hand_on(&hand_on) {
        Ok(true) => {
            departure.work.journey = journey;
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
/// a Send Port, or a Send Location it may leave by, naming a correlation
/// set whose `on_failure` is `block`.
pub(super) fn blocks(runtime: &Runtime<'_>, to: &Subscriber) -> bool {
    match runtime.sends.to(to) {
        Destination::Ports(ports) => ports.iter().any(|port| {
            port.points
                .iter()
                .any(|point| point.on_failure == OnFailure::Block)
        }),
        Destination::Process | Destination::Nowhere => false,
    }
}

/// Whether `departure` may be sent now: its Stream heads every sequence it
/// holds end to end, and it heads every sequence of its Send Port and of
/// the Send Locations it may leave by (`crate::sequence`), told it in the
/// write that brought it to the Port.
/// `departure`'s places at its Send Port and Send Locations, taken once its
/// Stream heads its own sequences (`crate::sequence::take_late`): `false`
/// where its claim was another's.
fn placed(runtime: &Runtime<'_>, departure: &mut Departure) -> Result<bool, String> {
    let journey = &departure.work.journey;
    if !crate::sequence::waits_for_places(runtime.sends, journey, &departure.to) {
        return Ok(true);
    }
    let placing = crate::sequence::heading(
        runtime.storage.as_ref(),
        (runtime.work.cluster(), runtime.sends, runtime.gathering),
        (
            &mut departure.work.journey,
            &departure.work.message,
            &departure.to,
        ),
        (&departure.claim, runtime.send.lease()),
    )?;
    // Behind another Stream, its places wait: `heads` says it is behind.
    Ok(placing != crate::sequence::Placing::Lost)
}

fn heads(runtime: &Runtime<'_>, departure: &Departure) -> Result<bool, String> {
    let storage = runtime.storage.as_ref();
    if !crate::sequence::stream_heads(storage, &departure.work.journey)? {
        return Ok(false);
    }
    let member = departure.work.journey.journey_id().value();
    for sequenced in &departure.work.journey.sequences {
        if !crate::sequence::heads(storage, sequenced.queue, member)? {
            return Ok(false);
        }
    }
    Ok(true)
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
    let message = match Message::from_record(&kept.body, |stream| Chunks::referred(storage, stream))
    {
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

/// A duration in nanoseconds, the most a `u64` holds at most.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
