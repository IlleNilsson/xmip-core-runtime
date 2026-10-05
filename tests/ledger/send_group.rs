//! A Send Port Group, and the key a send carries (`runtime-model.md`
//! section 10: *A Send Port Group is only a named set: routing already made
//! one Journey per Send Port in it*; section 15: *the key Xmip hands it is
//! the Journey id*):
//!
//! - a Subscription to a Group opens one Journey per Port of the Group in
//!   the Publication's one write, each led to its Port and waiting in its
//!   Port's queue, and each Port is sent, or fails, alone;
//! - every send of a Journey carries its identifier as its deduplication
//!   key, the same on every try of it and another for every other Journey.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, PoisonError};

use configure::{Retry, SendPortGroup};
use journey::JourneyState;
use path::expression::Expression;
use route::{Subscriber, Subscription};
use transport::TransportError;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};

use super::receive_cycle::{node, on_node};
use super::sending::{
    dispatching, journey, memory, onward, order, out, port, refusing, sender, senders, taking,
    took, waiting_in,
};

/// The Subscription `both`, matching everything to the Group `Both`.
fn to_both() -> [Subscription; 1] {
    [Subscription::new(
        "both",
        Subscriber::SendGroup("Both".to_string()),
        Expression::parse("xmip.transport.mechanism = 'circumstance'").expect("compiles"),
    )]
}

#[test]
fn a_send_port_group_opens_one_journey_per_port_each_sent_alone() {
    let storage = memory();
    let (out_end, out_took) = FarEnd::answering(taking());
    let (archive_end, archive_took) = FarEnd::answering(refusing("the archive is full", false));
    let group = SendPortGroup {
        name: "Both".to_string(),
        send_ports: vec!["Out".to_string(), "Archive".to_string()],
    };
    let sending = senders(
        node(),
        vec![
            (out_end, out(|_| {})),
            (archive_end, port("Archive", |_| {})),
        ],
        vec![group],
    );
    on_node(
        &storage,
        (CHUNK, &to_both()),
        sending,
        |runtime, pickup, gate| {
            // Before the send step runs: the Publication's one write.
            let carried = carry(runtime, pickup, gate, order(1));
            assert_eq!(carried.cycle(), ReceiveCycle::Completed);
            let ports: Vec<Option<&str>> = carried
                .journeys
                .iter()
                .map(|journey| journey.send_port.as_deref())
                .collect();
            assert_eq!(ports, [Some("Out"), Some("Archive")], "one per Port");
            let (to_out, to_archive) = (
                carried.journeys[0].journey_id(),
                carried.journeys[1].journey_id(),
            );
            assert_eq!(waiting_in(runtime, "Out"), [to_out], "in its Port's queue");
            assert_eq!(waiting_in(runtime, "Archive"), [to_archive]);
            assert!(waiting_in(runtime, "Both").is_empty(), "the Group has none");

            dispatching(runtime, |told| {
                told.wait_for(to_out, "completed");
                told.wait_for(to_archive, "failed");
            });
            assert_eq!(
                journey(storage.as_ref(), to_out).state,
                JourneyState::Completed
            );
            let failed = journey(storage.as_ref(), to_archive);
            assert_eq!(failed.state, JourneyState::Failed, "alone");
            assert_eq!(took(&out_took), ["order 1"]);
            assert!(took(&archive_took).is_empty());
            let figures = runtime.send.figures();
            assert_eq!((figures["Out"].sent, figures["Archive"].failed), (1, 1));
        },
    );
}

#[test]
fn every_send_carries_its_journey_as_its_key_the_same_on_every_try() {
    let storage = memory();
    let tries = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&tries);
    let (far, _) = FarEnd::answering(Box::new(move |_| {
        if counted.fetch_add(1, Ordering::Relaxed) == 0 {
            return Err(TransportError {
                message: "not yet".to_string(),
                retryable: true,
            });
        }
        Ok(())
    }));
    let keys = far.keys();
    let retrying = out(|port| {
        port.retry = Some(Retry {
            attempts: 1,
            backoff: "10ms".to_string(),
        });
    });
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, retrying),
        |runtime, pickup, gate| {
            dispatching(runtime, |told| {
                let first = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
                told.wait_for(first, "completed");
                let second = carry(runtime, pickup, gate, order(2)).journeys[0].journey_id();
                told.wait_for(second, "completed");
                let keys = keys.lock().unwrap_or_else(PoisonError::into_inner).clone();
                let (first, second) = (first.to_string(), second.to_string());
                assert_eq!(
                    keys,
                    [first.clone(), first, second],
                    "a retry is the same delivery"
                );
            });
        },
    );
}
