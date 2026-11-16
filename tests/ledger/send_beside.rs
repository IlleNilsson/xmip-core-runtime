//! The send side keeps up (ADR-0018, amendment 2026-11-15): the Streams of
//! one Receive Location, one sequence end to end, reach the far end in the
//! order received, and the next of the sequence behind a send under way on
//! the node waits beside it under its claim, never given back and claimed
//! again from its queue (`send_step::beside`); one further behind is given
//! back and taken up from its queue as the one ahead of it heads, never at
//! every read of the queue (`send_step::behind`). Until 2026-11-15 every
//! read of the queue claimed again whatever waited behind and gave it back.
//!
//! The far end holds each send until the test lets it go, so each Stream is
//! received while the one ahead of it is in its send; the reads of every
//! queue are an hour apart, so only the sends and the wakes take anything
//! up. Every claim and every claim given back is counted by Xmip Storage
//! (`fixture::Failing`): a Publication's own claims are its write's, not a
//! claim.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use transport::TransportError;
use xcore::JourneyId;
use xmip_core_runtime::fixture::{FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{Runtime, carry};
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::ReceiveGate;

use super::receive_cycle::{node, on_working_node};
use super::sending::{PATIENCE, Told, dispatching, interleaving, onward, order, out, sender, took};

/// A far end holding each send until the test lets it go: how many reached
/// it, and how many it let go.
#[derive(Default)]
struct Holding {
    counts: Mutex<(u32, u32)>,
    moved: Condvar,
}

impl Holding {
    /// One send reached it: held until the test lets it go, at most the
    /// tests' patience.
    fn hold(&self) -> transport::Result<()> {
        let deadline = Instant::now() + PATIENCE;
        let mut counts = self.counts.locked();
        counts.0 += 1;
        let this = counts.0;
        self.moved.notify_all();
        while counts.1 < this {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TransportError {
                    message: "never let go".to_string(),
                    retryable: false,
                });
            }
            counts = self
                .moved
                .wait_timeout(counts, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Ok(())
    }

    /// Wait, bounded, until `sends` reached it.
    fn reached(&self, sends: u32) {
        let deadline = Instant::now() + PATIENCE;
        let mut counts = self.counts.locked();
        while counts.0 < sends {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "never reached: {sends}");
            counts = self
                .moved
                .wait_timeout(counts, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// The next send held let go.
    fn let_go(&self) {
        self.counts.locked().1 += 1;
        self.moved.notify_all();
    }
}

/// `streams` Streams of the Location's one sequence carried through a node
/// sending `Out` to a far end that holds each send: the first carried, then
/// `behind` more each while the one ahead is held, and each after them
/// carried once the one ahead reached the far end — each let go in turn.
/// What the far end took, and how often a claim was asked and given back.
fn carried_one_sequence(streams: u32, behind: u32) -> (Vec<String>, u64, u64) {
    let (failing, storage) = interleaving();
    let holding = Arc::new(Holding::default());
    let held = Arc::clone(&holding);
    let (far, taken) = FarEnd::answering(Box::new(move |_| held.hold()));
    let mut sending = sender(node(), far, out(|_| {}));
    sending.tuning.send_scan = Duration::from_secs(3600);
    // A claim that lapsed under a loaded machine is given back untried: a
    // lease that outlasts the test.
    sending.tuning.send_lease = Duration::from_secs(30);
    on_working_node(
        &storage,
        (CHUNK, &onward()),
        (sending, Vec::new()),
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                carry_held(runtime, (pickup, gate), (&holding, told), (streams, behind));
            });
        },
    );
    (
        took(&taken),
        failing.asked_times(Operation::Claim),
        failing.asked_times(Operation::Release),
    )
}

/// [`carried_one_sequence`]'s carrying, each Stream sent and completed.
fn carry_held(
    runtime: &Runtime<'_>,
    (pickup, gate): (&Pickup, &ReceiveGate),
    (holding, told): (&Holding, &Told),
    (streams, behind): (u32, u32),
) {
    let carried = |number| carry(runtime, pickup, gate, order(number)).journeys[0].journey_id();
    let mut ids: Vec<JourneyId> = vec![carried(0)];
    holding.reached(1);
    for number in 1..=behind {
        ids.push(carried(number));
    }
    for number in (behind + 1)..streams {
        // The one ahead let go once the next is carried behind its send.
        let ahead = u32::try_from(ids.len()).expect("a count");
        holding.reached(ahead - behind);
        ids.push(carried(number));
        holding.let_go();
    }
    for _ in 0..=behind {
        holding.let_go();
    }
    for id in &ids {
        told.wait_for(*id, "completed");
    }
}

/// The Streams `0..streams`, as the far end takes them.
fn in_order(streams: u32) -> Vec<String> {
    (0..streams)
        .map(|number| format!("order {number}"))
        .collect()
}

#[test]
fn the_next_of_a_sequence_waits_beside_the_send_ahead_of_it_and_is_never_claimed_again() {
    const STREAMS: u32 = 16;
    let (taken, claims, released) = carried_one_sequence(STREAMS, 0);
    assert_eq!(taken, in_order(STREAMS), "in the order received");
    assert_eq!(released, 0, "none given back");
    assert!(
        claims <= u64::from(STREAMS),
        "at most a claim a Message beyond its Publication's: {claims}"
    );
}

#[test]
fn messages_further_behind_are_taken_up_as_the_one_ahead_heads_not_at_every_read() {
    const STREAMS: u32 = 12;
    const BEHIND: u32 = 5;
    let (taken, claims, released) = carried_one_sequence(STREAMS, BEHIND);
    assert_eq!(taken, in_order(STREAMS), "in the order received");
    // The first behind the one held waits beside it; each further behind
    // was given back as its Publication's pass found it, and is claimed
    // once more as the one ahead of it heads — on a loaded machine one
    // taken up as the one before it is still being claimed is given back
    // once more — never at every read of the queue, which claimed each of
    // them again after every send: fifty given back here until 2026-11-15.
    let twice_each = 2 * u64::from(STREAMS);
    assert!(
        released <= twice_each,
        "given back at most twice each: {released}"
    );
    assert!(
        claims <= twice_each,
        "taken up at most twice each: {claims}"
    );
}
