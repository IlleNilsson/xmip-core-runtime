//! What a receive's Publication is found by (proposed 2026-10-09): its
//! Journey by its Send Port and its state and by the Message it holds, its
//! Message by when it was written, and its audit record by when it
//! happened once the keeper kept it — each through `XmipStorage::query`,
//! as an operator's search would ask it.

use std::io::Cursor;

use journey::JourneyState;
use persist::storage::{Ask, Query, Span};
use receive::ReceivedStream;
use xmip_core_runtime::message_path::carry;
use xmip_core_runtime::outcome::Arrived;

use super::receive_cycle::on_runtime;
use super::sending::memory;

fn query(ask: Ask) -> Query {
    Query {
        ask,
        most: 10,
        newest_first: false,
    }
}

#[test]
fn a_published_journey_is_found_by_its_send_port_and_its_message_by_when() {
    let storage = memory();
    let carried = on_runtime(&storage, 64, |runtime, pickup, gate| {
        let order = Cursor::new(b"order 1".to_vec());
        carry(
            runtime,
            pickup,
            gate,
            ReceivedStream::new(order, "tcp://127.0.0.1:1"),
        )
    });
    let Arrived::Routed { work, .. } = &carried.arrived else {
        panic!("routed: {:?}", carried.arrived);
    };
    let message = work.message.message_id().value();
    let journey = carried.journeys[0].journey_id().value();

    let bound = Ask::JourneysAtSendPort {
        send_port: "Out".to_string(),
        state: JourneyState::Active.word().to_string(),
    };
    assert_eq!(storage.query(&query(bound)).expect("asked"), [journey]);
    let holding = Ask::JourneysHolding { message };
    assert_eq!(storage.query(&query(holding)).expect("asked"), [journey]);
    let created = Ask::MessagesCreated { created: Span::ALL };
    assert_eq!(storage.query(&query(created)).expect("asked"), [message]);

    let kept = storage.keep_audit(10).expect("kept");
    assert_eq!(kept, 1, "the Publication's audit record");
    let occurred = Ask::AuditOccurred {
        occurred: Span::ALL,
    };
    assert_eq!(storage.query(&query(occurred)).expect("asked").len(), 1);
}
