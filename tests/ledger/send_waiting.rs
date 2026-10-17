//! A retry waiting for its due time, as the owner decided it on 2026-10-16
//! (open problem 43; `runtime-model.md` section 10):
//!
//! - it holds no claim and no place in the Send pool: its due time is kept
//!   at its place in its queue, so a far end that fails every send cannot
//!   fill the places every Port shares, and a healthy Port sends all it has
//!   while the failing one's Journeys wait;
//! - a restart keeps every due time, and no node takes one up before it;
//! - a pass that tried nothing, because its claim was not surely this
//!   node's, writes nothing: no entry, no try counted, no backoff.

use std::time::{Duration, Instant};

use configure::{Retry, SendPortGroup};
use path::expression::Expression;
use persist::storage::XmipStorage;
use route::{Subscriber, Subscription};
use xcore::JourneyId;
use xmip_core_runtime::departure::Progress;
use xmip_core_runtime::fixture::{FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::carry;
use xmip_core_runtime::pool::hardware_threads;
use xmip_core_runtime::send_step::{Departure, Found, read};

use super::receive_cycle::{node, on_node, on_runtime};
use super::sending::{
    dispatching, interleaving, journey, memory, onward, order, out, port, refusing, sender,
    senders, taking, took, until,
};

/// The Subscription `both`, matching everything to the Group of `Bad` and
/// `Out`.
fn to_both() -> [Subscription; 1] {
    [Subscription::new(
        "both",
        Subscriber::SendGroup("Both".to_string()),
        Expression::parse("xmip.transport.mechanism = 'circumstance'").expect("compiles"),
    )]
}

/// `Bad`, whose far end `bad` refuses every send in a way that may mend and
/// is retried after an hour, and `Out`, whose far end `out_end` takes all.
fn bad_and_out(bad: FarEnd, out_end: FarEnd) -> super::receive_cycle::Sender {
    let group = SendPortGroup {
        name: "Both".to_string(),
        send_ports: vec!["Bad".to_string(), "Out".to_string()],
    };
    let retried = port("Bad", |port| {
        port.retry = Some(Retry {
            attempts: 3,
            backoff: "1h".to_string(),
        });
    });
    let mut sending = senders(
        node(),
        vec![(bad, retried), (out_end, out(|_| {}))],
        vec![group],
    );
    sending.tuning.send_threads_per_hardware_thread = 1;
    sending
}

/// Whether another node could take a claim on `id` now — given back at
/// once where it could.
fn free(storage: &dyn XmipStorage, id: JourneyId) -> bool {
    let other = configure::fixture::test_cluster().node_scope(1);
    let taken = storage
        .claim(id, &other, id.value() ^ 0x0bad, Duration::from_secs(30))
        .expect("asked");
    taken.is_some_and(|claim| storage.release(&claim).expect("asked"))
}

#[test]
fn a_far_end_that_always_fails_holds_no_place_a_healthy_port_needs() {
    let storage = memory();
    // Three times as many as the pool has places, so waiting Journeys that
    // kept their places would leave `Out` none.
    let count = u32::try_from(hardware_threads() * 3).expect("a count");
    let (bad, _) = FarEnd::answering(refusing("the far end is down", true));
    let (out_end, out_took) = FarEnd::answering(taking());
    let (waiting, sent) = on_node(
        &storage,
        (CHUNK, &to_both()),
        bad_and_out(bad, out_end),
        |runtime, pickup, gate| {
            let (ids, _) = dispatching(runtime, |told| {
                let carried: Vec<_> = (1..=count)
                    .map(|n| carry(runtime, pickup, gate, order(n)).journeys)
                    .collect();
                let to = |port: &str| -> Vec<JourneyId> {
                    let led = |j: &&journey::Journey| j.send_port.as_deref() == Some(port);
                    carried
                        .iter()
                        .flat_map(|journeys| journeys.iter().filter(led))
                        .map(journey::Journey::journey_id)
                        .collect()
                };
                let (waiting, sent) = (to("Bad"), to("Out"));
                for id in &sent {
                    told.wait_for(*id, "completed");
                }
                for id in &waiting {
                    told.wait_for(*id, "waiting");
                }
                let figures = || runtime.send.figures()["Bad"].waiting;
                until(
                    || figures() == u64::from(count),
                    "every one waiting, read so",
                );
                for id in &waiting {
                    assert!(free(storage.as_ref(), *id), "no claim held while it waits");
                }
                (waiting, sent)
            });
            ids
        },
    );
    assert_eq!(
        took(&out_took).len(),
        sent.len(),
        "the healthy Port sent all"
    );
    // The node restarted, the far end mended: nothing is due for an hour.
    let (bad, bad_took) = FarEnd::answering(taking());
    let (out_end, _) = FarEnd::answering(taking());
    on_node(
        &storage,
        (CHUNK, &to_both()),
        bad_and_out(bad, out_end),
        |runtime, _, _| {
            dispatching(runtime, |_| {
                let figures = || runtime.send.figures().get("Bad").map(|f| f.waiting);
                until(|| figures() == Some(u64::from(count)), "read waiting again");
                let queue = runtime.send.queue(&Subscriber::SendPort("Bad".to_string()));
                let held = storage.read_held(queue, 0, 1024).expect("read");
                for kept in &held.held {
                    let left = held.due_in(kept).expect("its due time kept");
                    assert!(left > Duration::from_secs(1800), "{left:?}");
                }
            });
        },
    );
    assert!(took(&bad_took).is_empty(), "none taken up before it is due");
    for id in &waiting {
        assert_eq!(
            journey(storage.as_ref(), *id).attempts.tries,
            1,
            "one try each"
        );
    }
}

#[test]
fn a_scan_that_read_its_queue_before_a_retry_was_handed_on_never_sends_it_again() {
    // A scan reads `Out`'s queue while the Journey's first pass is under
    // way, so the read shows no due time at its place; the pass's hand-on
    // lands — Recovering, its due time an hour off, its claim released — and
    // only then does the scan go on with what it read. Its claim is granted,
    // for none is held; what it read under that claim decides.
    let (interleaved, storage) = interleaving();
    let (far, _) = FarEnd::answering(refusing("the far end is down", true));
    let retried = out(|port| {
        port.retry = Some(Retry {
            attempts: 3,
            backoff: "1h".to_string(),
        });
    });
    let id = on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, retried),
        |runtime, pickup, gate| {
            let id = carry(runtime, pickup, gate, order(1)).journeys[0].journey_id();
            let (read, was_read) = std::sync::mpsc::channel::<()>();
            let (settled, was_settled) = std::sync::mpsc::channel::<()>();
            let patience = Duration::from_secs(30);
            let reading = std::sync::Arc::clone(&interleaved);
            // Before the first pass's hand-on lands, a scan reads the queue,
            // and holds what it read until that pass is settled.
            interleaved.before(
                Operation::HandOn,
                Box::new(move || {
                    reading.after(
                        Operation::ReadHeld,
                        Box::new(move || {
                            read.send(()).expect("told");
                            was_settled.recv_timeout(patience).expect("settled");
                        }),
                    );
                    was_read.recv_timeout(patience).expect("the queue read");
                }),
            );
            dispatching(runtime, |told| {
                told.wait_for(id, "waiting");
                settled.send(()).expect("told");
            });
            id
        },
    );
    let tried = journey(storage.as_ref(), id);
    let sends = tried
        .entries()
        .iter()
        .filter(|e| e.action == "send")
        .count();
    assert_eq!(sends, 1, "tried once, not again before it is due");
    assert_eq!(tried.attempts.tries, 1, "one try");
}

#[test]
fn a_pass_whose_claim_is_not_surely_held_writes_nothing_and_is_taken_up_again() {
    let (interleaved, storage) = interleaving();
    let id = on_runtime(&storage, CHUNK, |runtime, pickup, gate| {
        carry(runtime, pickup, gate, order(1)).journeys[0].journey_id()
    });
    let (far, taken) = FarEnd::answering(taking());
    on_node(
        &storage,
        (CHUNK, &onward()),
        sender(node(), far, out(|_| {})),
        |runtime, _, _| {
            // The Journey claimed here, its last confirmation now: by the
            // time its pass begins it is older than nothing, so the claim is
            // not surely this node's, and no renewal confirms it again.
            interleaved.fail(Operation::Renew, u32::MAX);
            let to = Subscriber::SendPort("Out".to_string());
            let queue = runtime.send.queue(&to);
            let held = storage.read_held(queue, 0, 1).expect("read").held;
            let lease = Duration::from_secs(30);
            let claim = storage.claim(id, runtime.send.node(), 77, lease);
            let claim = claim.expect("asked").expect("claimed");
            let Ok(Found::Waiting(found)) = read(runtime, id, &held[0].hold.body) else {
                panic!("a Journey to send");
            };
            let (work, facts) = *found;
            let departure = Departure {
                progress: Progress::of(work.journey.attempts),
                work,
                facts,
                to,
                queue,
                claim,
                sequence: None,
                until: Instant::now(),
            };
            dispatching(runtime, |told| {
                runtime.send.hand(departure);
                told.wait_for(id, "untried");
                interleaved.heal();
                told.wait_for(id, "completed");
            });
        },
    );
    let sent = journey(storage.as_ref(), id);
    let tried: Vec<&str> = sent.entries().iter().map(|e| e.action.as_str()).collect();
    assert_eq!(tried, ["send"], "the pass that tried nothing wrote nothing");
    assert_eq!(sent.attempts.tries, 1, "nor counted a try");
    assert_eq!(took(&taken), ["order 1"]);
}
