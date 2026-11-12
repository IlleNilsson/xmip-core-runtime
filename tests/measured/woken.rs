//! A Message another node published, sent by the node that sends its Send
//! Port, over the wire, against the millisecond rule (open problem 46;
//! ADR-0018 and ADR-0028, amendments 2026-11-12): one Storage node, its
//! runtime database `RocksDB` on disk, served over Xmip's mutual TLS on
//! loopback, and each node reaching it as a node without the Storage role
//! does (`persist::storage::StorageClient`). From a node's carry of a
//! Message to the far end taking it from the node that sends its Send Port,
//! woken by the wait on its queue — its scan an hour — beside the same
//! carried by the sending node itself, over the same wire, the two in turn;
//! each call either node made of Xmip Storage timed
//! (`fixture::Failing::taken`), the median of each said. Until 2026-11-12
//! the case ran in process, where the calls a delivery across nodes adds
//! cost next to nothing.
//!
//! What it holds: the delivery across nodes within a millisecond of the
//! delivery on one node, the medians. The calls the sending node makes only
//! because another node published it — what is due in its queue, the claim,
//! and the Message's place, its Journey and its Message read again under
//! the claim — mostly overlap the publishing node's sync, since the wait is
//! answered once the Publication is readable, before it is durable; each is
//! said beside the delivery.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use persist::storage::{StorageClient, StorageServer, XmipStorage, client};
use xcore::lock::Locked;
use xmip_core_runtime::fixture::{Authority, Failing, FarEnd, Operation};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{Runtime, carry};
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::ReceiveGate;

use super::node::test_storage;
use super::receive_cycle::{Sender, on_node, on_runtime};
use super::sending::{dispatching, onward, order, out, sender, until};

/// How many Messages each way.
const ROUNDS: usize = 201;

/// An hour: no scan comes while the test runs.
const HOUR: Duration = Duration::from_secs(3600);

/// The Storage calls the sending node makes only for what another node
/// published.
const ACROSS: [Operation; 5] = [
    Operation::ReadDue,
    Operation::Claim,
    Operation::ReadHeld,
    Operation::ReadJourney,
    Operation::ReadMessage,
];

/// The node sending `Out`, its scan an hour, to a far end noting when it
/// took each Message.
fn sending() -> (Sender, Arc<Mutex<Vec<Instant>>>) {
    let took = Arc::new(Mutex::new(Vec::new()));
    let noted = Arc::clone(&took);
    let (far, _) = FarEnd::answering(Box::new(move |_| {
        noted.locked().push(Instant::now());
        Ok(())
    }));
    let node = configure::fixture::test_cluster().node_scope(1);
    let mut sending = sender(node, far, out(|_| {}));
    sending.tuning.send_scan = HOUR;
    (sending, took)
}

/// One node's receive path: what a Message is carried on.
type Path<'a, 'r> = (&'a Runtime<'r>, &'a Pickup, &'a ReceiveGate);

/// [`ROUNDS`] Messages carried on `own`, the node that sends `Out`, and as
/// many on `other`, one after another in turn, each once the far end took
/// the one before, so whatever the machine does meanwhile falls on both
/// alike: the median from each carry to the far end taking it, on `own`
/// and on `other`.
fn carried(own: Path<'_, '_>, other: Path<'_, '_>, took: &Mutex<Vec<Instant>>) -> [Duration; 2] {
    let mut taken = [Vec::new(), Vec::new()];
    for number in 0..ROUNDS * 2 {
        let (runtime, pickup, gate) = if number % 2 == 0 { own } else { other };
        let began = Instant::now();
        carry(
            runtime,
            pickup,
            gate,
            order(u32::try_from(number).expect("a number")),
        );
        until(|| took.locked().len() > number, "taken");
        taken[number % 2].push(took.locked()[number] - began);
    }
    taken.map(|mut taken| median(&mut taken))
}

fn median(taken: &mut [Duration]) -> Duration {
    taken.sort();
    taken.get(taken.len() / 2).copied().unwrap_or_default()
}

/// The median of each `operation` `storage` answered since last asked.
fn medians(storage: &Failing, operations: &[Operation]) -> Vec<(Operation, Duration)> {
    operations
        .iter()
        .map(|&operation| (operation, median(&mut storage.taken(operation))))
        .collect()
}

/// A node's Xmip Storage: the Storage node served at `at`, reached over
/// the wire with `authority`'s certificate, each call timed.
fn reaching(at: &str, authority: &Authority) -> Arc<Failing> {
    let identity = authority.identity("node");
    let reached = StorageClient::new(
        &[at.to_string()],
        &identity,
        client::TIMEOUT,
        client::PASS_OVER,
    )
    .expect("a client");
    Failing::over(Arc::new(reached))
}

#[test]
fn a_message_another_node_published_is_sent_over_the_wire_within_a_millisecond_of_its_own() {
    let place = std::env::temp_dir().join(format!("xmip-measured-woken-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&place);
    let authority = Authority::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
    let behind: Arc<dyn XmipStorage> = Arc::new(test_storage(&place));
    let server =
        StorageServer::start(behind, listener, &authority.identity("storage")).expect("served");
    let at = server.address().to_string();
    let (sends, publishes) = (reaching(&at, &authority), reaching(&at, &authority));
    let (sends_storage, publishes_storage): (Arc<dyn XmipStorage>, Arc<dyn XmipStorage>) =
        (Arc::clone(&sends) as _, Arc::clone(&publishes) as _);

    let (sending, took) = sending();
    let [alone, across] = on_node(
        &sends_storage,
        (CHUNK, &onward()),
        sending,
        |node, pickup, gate| {
            dispatching(node, |_| {
                on_runtime(&publishes_storage, CHUNK, |publisher, by, at| {
                    carried((node, pickup, gate), (publisher, by, at), &took)
                })
            })
            .0
        },
    );
    let own = medians(
        &sends,
        &[Operation::Publish, Operation::ReadChunk, Operation::HandOn],
    );
    let added = medians(&sends, &ACROSS);
    let published = medians(&publishes, &[Operation::Publish]);
    eprintln!(
        "LATENCY from a carry to the far end taking it over the wire, the median: published by \
         the node that sends its Send Port {alone:?} ({own:?}), by another node {across:?} \
         ({published:?}); the sending node's Storage calls for it {added:?}"
    );
    let beyond = across.saturating_sub(alone);
    server.stop();
    let _ = std::fs::remove_dir_all(&place);
    assert!(
        beyond < Duration::from_millis(1),
        "another node's Publication sent {beyond:?} later"
    );
}
