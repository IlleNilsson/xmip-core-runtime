//! A Journey's places at its destination taken once its Stream heads its
//! end-to-end sequences, never before (the owner, 2026-10-22: *Default one
//! stream, message, journey at a time. Put it in the ledger if it is not
//! processed now*).
//!
//! A Stream behind the head of its Receive Location's sequence is not
//! being processed, so a Journey born of it takes no place at the Send
//! Port, Send Location or Work Process it is bound for: it waits in the
//! Ledger. Its places are taken in the write that first takes it up once
//! its Stream heads, so a destination's queue holds Streams' Journeys in
//! the order the Streams were let through, and a Stream's Journey a Work
//! Process publishes later never waits behind a Stream that waits for it.

use std::time::Duration;

use journey::Journey;
use message::Message;
use persist::storage::{Claim, HandOn, XmipStorage};
use route::{Gathering, Subscriber};

use super::points_of;
use crate::sending::Sends;

/// Where a Journey stands as a step takes it up: its Stream behind
/// another's, its places at its destination held, or its claim another's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placing {
    Behind,
    Placed,
    Lost,
}

/// `journey`'s Stream asked whether it heads its own sequences and, where
/// it does, its places at `to` taken ([`take_late`]).
///
/// # Errors
/// As [`take_late`], or Xmip Storage not answering.
pub fn heading(
    storage: &dyn XmipStorage,
    configured: (&str, &Sends, &Gathering),
    (journey, message, to): (&mut Journey, &Message, &Subscriber),
    claimed: (&Claim, Duration),
) -> Result<Placing, String> {
    if !super::stream_heads(storage, journey)? {
        return Ok(Placing::Behind);
    }
    if take_late(storage, configured, (journey, message, to), claimed)? {
        Ok(Placing::Placed)
    } else {
        Ok(Placing::Lost)
    }
}

/// Whether `journey`, bound for `to`, still waits for its places there:
/// its point names a set and it holds no place yet.
#[must_use]
pub fn waits_for_places(sends: &Sends, journey: &Journey, to: &Subscriber) -> bool {
    journey.sequences.is_empty() && !points_of(sends, to).is_empty()
}

/// `journey`'s places at `to`, taken now under `claim` in one write — the
/// Journey told them, the claim kept a `lease` on — where it still waits
/// for them ([`waits_for_places`]) and its Stream heads its end-to-end
/// sequences, as the caller has asked. `false` where the claim was not its
/// holder's any more: nothing written.
///
/// # Errors
/// A key part its Message lacks, or Xmip Storage not answering, in words.
pub fn take_late(
    storage: &dyn XmipStorage,
    (cluster, sends, gathering): (&str, &Sends, &Gathering),
    (journey, message, to): (&mut Journey, &Message, &Subscriber),
    (claim, lease): (&Claim, Duration),
) -> Result<bool, String> {
    if !waits_for_places(sends, journey, to) {
        return Ok(true);
    }
    let promoted = gathering.promote(message).map_err(|why| why.to_string())?;
    let mut placed = journey.clone();
    let queued = super::placed(cluster, &points_of(sends, to), &mut placed, &promoted)?;
    let hand_on = HandOn {
        claim: claim.clone(),
        result: crate::ledger::journey_record(&placed),
        messages: Vec::new(),
        next: Vec::new(),
        leaves: Vec::new(),
        queued,
        requeued: Vec::new(),
        failed: None,
        cleared: Vec::new(),
        waits: None,
        kept_for_nanos: Some(u64::try_from(lease.as_nanos()).unwrap_or(u64::MAX)),
    };
    let taken = storage.hand_on(&hand_on).map_err(|why| {
        format!(
            "Xmip Storage did not take the places of the Journey {}: {why}",
            journey.journey_id()
        )
    })?;
    if taken {
        *journey = placed;
    }
    Ok(taken)
}
