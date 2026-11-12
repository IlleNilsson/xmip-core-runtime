//! What a Message lets go of as its Journey ends at a point: its places in
//! the sequences there (ADR-0024 and ADR-0066, amendments 2026-10-22;
//! ADR-0066, third amendment 2026-11-12).
//!
//! The owner chose, 2026-10-22: block by default, skip as the option — a
//! Message that failed, waiting for an operator, keeps its place until Retry
//! or Dismiss, and a set's `on_failure = "skip"` lets the rest pass
//! (`runtime-model.md` section 3, *A claim is not ordering*). One rule,
//! whichever step ends the Journey and however it failed: the send step's
//! hand-on, a Work Process's turn — its flow's error no scope caught, a turn
//! refused, a turn that panicked — and an operator's Dismiss; and Xmip
//! Storage counts a Stream's, or a Send Port Group delivery's, open
//! Journeys by it (`crate::ledger::journey_record`).

use journey::{Journey, JourneyState};

/// Whether a Journey in `state` lets go of a place it holds in a sequence
/// whose point `skips` a failure: once it completed or was dismissed, and
/// once it failed where its point skips; never while it is under way,
/// waits or is retried.
#[must_use]
pub const fn lets_go(state: JourneyState, skips: bool) -> bool {
    match state {
        JourneyState::Completed | JourneyState::Dismissed => true,
        JourneyState::Failed => skips,
        _ => false,
    }
}

/// The places `journey`'s Message holds at the point it is at — its Work
/// Process's, or its Send Port's and those of the Send Locations it may
/// leave by — that it lets go of in the state it is in ([`lets_go`]), by
/// their queues.
#[must_use]
pub fn let_go(journey: &Journey) -> Vec<u128> {
    journey
        .sequences
        .iter()
        .filter(|sequenced| lets_go(journey.state, sequenced.skips))
        .map(|sequenced| sequenced.queue)
        .collect()
}
