//! One pass of a Message's send and its hand-on: what the Send pool's
//! threads run. A Message read back from the Ledger to be sent is
//! `super::found`'s.

use std::cell::Cell;
use std::time::{Duration, Instant};

use configure::OnFailure;
use journey::{Journey, JourneyEntry, JourneyState};
use persist::storage::{Durable, Failure, HandOn, Wait};
use route::Subscriber;
use xcore::ExecutionId;
use xcore::spent::Spent;

use super::Departure;
use super::steps::Step;
use crate::departure::{Departed, depart_to, said};
use crate::message_path::Runtime;
use crate::outcome::Measured;
use crate::sending::Destination;

/// How one pass of a send ended, once its hand-on was written.
#[derive(Debug)]
pub enum Ended {
    /// Sent to every Port: written Completed, and out of its queue.
    Completed(Vec<Departed>),
    /// A Location is tried again after `after`, the wait its Send Port's
    /// guards asked for: written Recovering, its due time kept at its place
    /// in its queue, its claim released.
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
    /// the Message up, or a renewal found it another's — so nothing was
    /// written, and nothing more tried from here.
    Lost(Vec<Departed>),
    /// Nothing was tried: the claim was not surely this node's when the
    /// pass began — its last confirmation older than a lease — though no
    /// renewal found it another's; or what it is sent under, its Publication
    /// or its claim, or the hand-on ahead of it in its sequence, was never
    /// made durable, and the send its far end would have seen was abandoned
    /// (ADR-0018, amendments 2026-11-12 and 2026-11-15). Nothing is
    /// written, so the pass leaves no
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
    /// and the Message is sent again — at least once, never lost.
    Unwritten(String),
}

/// One pass of `departure`'s send — its Send Port, unless sent already,
/// tried once on its active Send Location, failing over as its policy says,
/// each try only while its claim is surely this node's — and its hand-on,
/// one write: the outcome on the Journey, with what was tried in words and
/// its tries, its place let go of where it was sent or its due time kept
/// there where it waits, and the claim released. A claim a renewal found
/// another's writes nothing: the Message is the other holder's; nor does a
/// pass that tried nothing ([`Ended::Untried`]).
pub fn send(runtime: &Runtime<'_>, departure: &mut Departure) -> Ended {
    let step = runtime.send;
    // One still waiting for its places is passed: only the scan, reading its
    // queue in order, takes them (`scan::placed`), so they follow the
    // Ledger's order.
    if crate::sequence::waits_for_places(runtime.sends, &departure.work.journey, &departure.to) {
        return Ended::Behind;
    }
    // The send thread works for its Message from here to its hand-on's
    // answer, its send apart as the payload's I/O (`xcore::spent`): its
    // sequences read, its send, and its hand-on built and asked (ADR-0018,
    // amendment 2026-11-15).
    let entered = departure.spent.as_ref().map(Spent::entered);
    let began = Instant::now();
    let headed = crate::sequence::may_go(runtime.storage.as_ref(), &departure.work.journey);
    departure.steps.set(Step::Sequences, began.elapsed());
    // Heading them: its first byte waits until each write that let it head
    // — the hand-on ahead of it, wherever that was sent — is durable, where
    // it was not yet as read (the owner, 2026-11-15: *Wait for the disk*).
    let ahead = match headed {
        Ok(Some(ahead)) => ahead,
        Ok(None) => return Ended::Behind,
        Err(why) => return Ended::Unwritten(why),
    };
    step.heads_here(departure);
    let Departure {
        work,
        facts,
        to,
        progress,
        durable,
        claim,
        steps,
        ..
    } = departure;
    // The far end is told the claim's fence beside the deduplication key.
    progress.fence = claim.fence;
    let id = work.journey.journey_id();
    let owned = || step.holds(id);
    // The wait for its Publication, or its claim, and the hand-on ahead of
    // it to be durable timed apart from the send (ADR-0018, amendments
    // 2026-11-12 and 2026-11-15).
    let waited = Cell::new(None);
    let kept = || {
        let began = Instant::now();
        let kept = durable.as_ref().map(Durable::wait);
        let ahead_kept = ahead.iter().try_for_each(Durable::wait);
        if kept.is_some() || !ahead.is_empty() {
            waited.set(Some(began.elapsed()));
        }
        kept.unwrap_or(Ok(())).and(ahead_kept).map_err(|why| {
            format!(
                "its Publication or claim, or the hand-on ahead of it, was not kept in the \
                 Ledger: {why}"
            )
        })
    };
    let sending = Instant::now();
    let departed = depart_to(runtime, work, facts, to, (progress, &owned, &kept));
    let durable_took = waited.get();
    if let Some(took) = durable_took {
        steps.set(Step::Durable, took);
    }
    steps.set(
        Step::Send,
        sending
            .elapsed()
            .saturating_sub(durable_took.unwrap_or_default()),
    );
    let sent = departed.iter().any(Departed::sent);
    if step.is_lost(id) {
        return Ended::Lost(departed);
    }
    if departed.is_empty() && progress.waiting() {
        return Ended::Untried;
    }
    let (state, kept) = if progress.sent {
        (JourneyState::Completed, None)
    } else if progress.waiting() {
        // As long as its Port's guards asked of its last try; a pass that
        // stopped before they were asked waits for nothing.
        (
            JourneyState::Recovering,
            Some(progress.after.unwrap_or_default()),
        )
    } else {
        (JourneyState::Failed, None)
    };
    let mut outcome = said(&departed);
    if let Some(after) = kept {
        outcome = format!("{outcome}; tried again in {after:?}");
    }
    let handing = Instant::now();
    let handed = written(runtime, departure, state, outcome, kept);
    drop(entered);
    departure.steps.set(Step::HandOn, handing.elapsed());
    match handed {
        // Sent, its far end has it, and handed on: Xmip's own share of its
        // Message is read now (`Departure::measured`).
        Ok(Some(handed)) if sent => departure.measured(&handed),
        Ok(Some(_)) => {}
        Ok(None) => return Ended::Lost(departed),
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

impl Departure {
    /// Its Message's own share read, once its hand-on, `handed`, is written:
    /// what its account counted, with its shares of what the Storage node's
    /// writer worked on what it was sent under and on its hand-on; and the
    /// disk's time beside it, with their syncs' shares (ADR-0018, amendment
    /// 2026-11-15: until then its hand-on was in no one's share). Nothing
    /// where it has no account, read from the Ledger.
    fn measured(&mut self, handed: &Durable) {
        let Some(spent) = &self.spent else {
            return;
        };
        let under = self.durable.as_ref();
        let worked = under.map_or(Duration::ZERO, Durable::worked) + handed.worked();
        let synced = under.map_or(Duration::ZERO, Durable::synced) + handed.synced();
        self.measured = Some(Measured {
            own: spent.own(worked),
            disk_sync: spent.disk_sync(synced),
        });
    }
}

/// `departure`, whose send thread panicked before its hand-on, written
/// Failed with `why` — kept in its queue for an operator, as every Message
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
        Ok(Some(_)) => Ended::Failed {
            reason: format!("{}: {why}", departure.to.name()),
            departed: Vec::new(),
        },
        Ok(None) => Ended::Lost(Vec::new()),
        Err(unwritten) => {
            let _ = runtime.storage.release(&departure.claim);
            Ended::Unwritten(unwritten)
        }
    }
}

/// `departure`'s hand-on, one write: its Journey in `state` with what was
/// tried, `outcome`, and its tries; its place let go of where it completed,
/// or, Failed, entered in its queue's index of failed Messages with
/// `outcome` as why, or, waiting, its due time `kept` from now kept at its
/// place; its claim ended. Where it was written, its durability, what the
/// Storage node's batch worked for it (`Durable::worked`); nothing where the
/// claim was no longer this node's; in words where Xmip Storage did not
/// take it. The Journey is kept on `departure` as the pass left it, moved
/// out and back, never copied (2026-11-15): after a hand-on not taken only
/// its identifier is read, and its Message is read again from the Ledger.
fn written(
    runtime: &Runtime<'_>,
    departure: &mut Departure,
    state: JourneyState,
    outcome: String,
    kept: Option<Duration>,
) -> Result<Option<Durable>, String> {
    departure.settled();
    // Failed, it waits in its queue for an operator, entered in the queue's
    // index of failed Messages in this same write, with why.
    let failed = (state == JourneyState::Failed).then(|| Failure {
        queue: departure.queue,
        reason: outcome.clone(),
    });
    let id = departure.work.journey.journey_id();
    let mut journey = std::mem::replace(&mut departure.work.journey, Journey::new(id)).append(
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
    let leaves_point = crate::sequence::let_go(&journey);
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
    departure.work.journey = journey;
    match runtime.storage.hand_on(hand_on) {
        Ok((taken, handed)) => Ok(taken.then_some(handed)),
        Err(error) => Err(format!(
            "Xmip Storage did not take the send of the Message of the Journey {id}: {error}"
        )),
    }
}

/// Whether a Message bound for `to` that failed blocks its sequence:
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

/// A duration in nanoseconds, the most a `u64` holds at most.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
