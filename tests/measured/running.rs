//! A running node (`xmip_core_runtime::running`), measured: Messages
//! carried from its Receive Location to the far end, Xmip's own share of
//! each held under a millisecond. Eight senders carried side by side are
//! `side_by_side.rs`'s.

use std::time::Instant;

use net::fixture::unheld;
use tcp::TcpTransport;
use transport::Transport;
use xcore::latency::{PlainWake, spread, worked_beside_a_plain_wake};
use xmip_core_runtime::fixture::started;

use super::node::{count_anew, deliver, given, linked, node, path_text, written};

#[test]
fn a_node_carries_every_message_from_its_receive_location_to_the_far_end() {
    const MESSAGES: u32 = 200;
    let far = TcpTransport::loopback();
    let (listener, far_address) = far.bind().expect("the far end binds");
    let receive = unheld().to_string();
    let path = written("carries", &node(&receive, &far_address));

    count_anew();
    let running = started(path_text(&path), || linked(&path)).expect("the node starts");

    // One module per technology, however many Locations use it; one
    // transport instance per Location.
    let registered: Vec<&str> = running
        .capabilities()
        .capabilities()
        .map(|c| c.capability.as_str())
        .collect();
    assert_eq!(
        registered,
        [
            "authenticate:circumstance",
            "authorize:open",
            "transport:xmip-core-transport-tcp"
        ]
    );
    assert_eq!(given().len(), 2, "one transport per Location");
    assert!(
        xmip_core_runtime::catalogue::declarations().contains_key("tcp"),
        "loading carries the declaration"
    );

    deliver(&TcpTransport::loopback(), &receive, b"order 0");
    let first = far
        .accept_one(&listener)
        .expect("the first arrives")
        .taken()
        .expect("read whole");
    assert_eq!(first.bytes, b"order 0");

    // The node counts the processor time its threads work for each
    // Message and reports Xmip's own share, the fastest of five
    // (`Outcomes::own_share`); each Message's time end to end is printed
    // beside it, for information, and a plain wake measured beside each.
    let (plain, mut times, mut idle) = (PlainWake::start(), Vec::new(), Vec::new());
    for message in 1..=MESSAGES {
        let payload = format!("order {message}");
        let started = Instant::now();
        TcpTransport::loopback()
            .send(&receive, payload.as_bytes())
            .expect("the node takes it");
        let arrived = far
            .accept_one(&listener)
            .expect("it reaches the far end")
            .taken()
            .expect("read whole");
        times.push(started.elapsed());
        assert_eq!(arrived.bytes, payload.as_bytes());
        idle.push(plain.round().1);
    }
    let _ = spread("a Message end to end, for information", times);

    let outcomes = running.stop();
    let carried = u64::from(MESSAGES) + 1;
    assert_eq!(outcomes.received, carried);
    assert_eq!(outcomes.routed, carried, "{outcomes:?}");
    assert_eq!(outcomes.sent, carried, "{outcomes:?}");
    assert_eq!(
        outcomes.refused + outcomes.failed + outcomes.unroutable + outcomes.not_sent,
        0
    );
    // The millisecond rule, with the load counted as load (the owner,
    // 2026-10-03: *Go for A*; 2026-11-01: *the processor time its threads
    // spent working for the Message*): what the node's threads ran for a
    // Message outside its I/O — its Stream read off the connection, the
    // Ledger's append and sync, its send to the far end, its hand-on and
    // its share of the Storage node's batches — is Xmip's own share, and it
    // is held under a millisecond (its hand-on counted since 2026-11-15). A
    // thread waiting for a wake runs nothing, so no wake is counted. It is
    // measured by the node, so it is held by the rule's processor-time
    // half: within a millisecond of this process's processor time across a
    // plain wake measured in the same rounds
    // (`xcore::latency::worked_beside_a_plain_wake`); until 2026-11-15
    // under a millisecond flat.
    let own = outcomes.own_share.expect("the node measured its own share");
    // The Ledger's sync, the disk's time, printed beside it and held to
    // nothing (ADR-0018, amendment 2026-11-09).
    let disk = outcomes.disk_sync.expect("and the disk's time beside it");
    eprintln!(
        "Xmip's own share per Message {own:?}, the disk's sync beside it {disk:?}, the fastest \
         of five"
    );
    worked_beside_a_plain_wake("Xmip's own share per Message", own, idle);
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}
