//! A Work Process run from the Ledger (`runtime-model.md` section 22;
//! ADR-0066, amendment 2026-10-22): a BPMN 2.0 design compiled to its
//! program, opened as a flow, and Messages carried through a node's
//! receive path into it — correlated by a cluster's Correlation to one
//! Instance, collected in a Batch in the order they were received, the
//! batch published back through routing to a Send Port — its state in the
//! Ledger between turns, never in a thread:
//!
//! - one client's Messages make one Instance, its Batch holding them in the
//!   order received;
//! - two clients' Messages carried at once, from two threads, with the work
//!   step dispatching on its pool meanwhile, make two Instances, neither
//!   Message of a client overtaking another;
//! - a node killed mid-process, its Instance waiting for the rest of its
//!   Batch: the node started again over the same Ledger finishes it, from
//!   the Instance the Ledger keeps;
//! - what a turn costs, beside its Ledger writes.

use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, Instant};

use path::expression::Expression;
use persist::storage::XmipStorage;
use process::{Compiled, DesignFormat, NoResources};
use process_bpmn::Bpmn;
use receive::ReceivedStream;
use route::{Subscriber, Subscription};
use xcore::ScalarValue;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, Runtime, carry};
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::ReceiveGate;
use xmip_core_runtime::sequence::{OnFailure, Point, PointKind};
use xmip_core_runtime::work_step::{
    KeyWord, NoUnits, ResolvedSet, Running, Turned, dispatch, turn_due,
};

use super::child_process::ChildProcess;
use super::receive_cycle::{Sender, node, on_working_node};
use super::sending::memory;
use super::{STARTED, directory, say, test_node};

/// The design: a client's first Message starts its Instance, the next
/// three are collected in a Batch, marked and published, all correlated
/// by the cluster's set `PerClient`.
const BATCHES: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    xmlns:xmip="urn:xmip:process:1" id="D" targetNamespace="urn:example:orders">
  <bpmn:process id="Batches" isExecutable="true">
    <bpmn:startEvent id="First">
      <bpmn:extensionElements><xmip:correlate correlation="PerClient"/></bpmn:extensionElements>
    </bpmn:startEvent>
    <bpmn:receiveTask id="Collect">
      <bpmn:extensionElements>
        <xmip:correlate correlation="PerClient"/>
        <xmip:batch most="3"/>
      </bpmn:extensionElements>
    </bpmn:receiveTask>
    <bpmn:task id="Mark">
      <bpmn:dataOutputAssociation id="Marked">
        <bpmn:assignment><bpmn:from>'batched'</bpmn:from><bpmn:to>Status</bpmn:to></bpmn:assignment>
      </bpmn:dataOutputAssociation>
    </bpmn:task>
    <bpmn:sendTask id="Publish"/>
    <bpmn:endEvent id="Done"/>
    <bpmn:sequenceFlow id="F1" sourceRef="First" targetRef="Collect"/>
    <bpmn:sequenceFlow id="F2" sourceRef="Collect" targetRef="Mark"/>
    <bpmn:sequenceFlow id="F3" sourceRef="Mark" targetRef="Publish"/>
    <bpmn:sequenceFlow id="F4" sourceRef="Publish" targetRef="Done"/>
  </bpmn:process>
</bpmn:definitions>"#;

/// The header a client is told apart by.
pub(super) fn client() -> String {
    context::property::header("http", "x-client")
}

/// The cluster's Correlation keyed by the client.
fn per_client() -> ResolvedSet {
    ResolvedSet {
        name: "PerClient".to_string(),
        keys: vec![KeyWord::Context(client())],
    }
}

/// The Work Process `Batches`, compiled from its design.
fn batches() -> Running {
    let program = Bpmn
        .compile(BATCHES, &NoResources)
        .expect("the design compiles");
    let flow = Compiled::new(program).expect("the unit opens");
    let cluster = configure::fixture::test_cluster().scope();
    Running::new(
        (&cluster, "Batches"),
        Box::new(flow),
        &[per_client()],
        &[],
        Arc::new(NoUnits),
    )
    .expect("it runs")
}

/// What routes a client's Message into the Work Process, and its batch out
/// to the Send Port `Out`, which this node has no Location for.
fn routes() -> Vec<Subscription> {
    let client = client();
    vec![
        Subscription::new(
            "work",
            Subscriber::WorkProcess("Batches".to_string()),
            Expression::parse(&format!("exists {client} and not exists Status")).expect("compiles"),
        ),
        Subscription::new(
            "out",
            Subscriber::SendPort("Out".to_string()),
            Expression::parse("Status = 'batched'").expect("compiles"),
        ),
    ]
}

/// The Receive Location opened up by client: each client's Streams one at
/// a time, clients side by side.
fn opened(gate: &ReceiveGate) -> ReceiveGate {
    let mut gate = gate.clone();
    gate.points = vec![Point {
        kind: PointKind::ReceiveLocation,
        name: gate.location.clone(),
        set: per_client(),
        on_failure: OnFailure::Block,
    }];
    gate
}

/// `text` from the client `who`, as a Receive Location takes it.
pub(super) fn from_client(who: &str, text: &str) -> ReceivedStream {
    ReceivedStream::new(Cursor::new(text.as_bytes().to_vec()), "tcp://127.0.0.1:1").with_header(
        "http",
        "x-client",
        ScalarValue::Text(who.to_string()),
    )
}

fn order(who: &str, number: u32) -> ReceivedStream {
    from_client(who, &format!("{who} {number}"))
}

/// A node that sends nothing itself: `Out` has no Location here.
pub(super) fn sending_nothing() -> Sender {
    Sender {
        sends: xmip_core_runtime::sending::Sends::default(),
        tuning: xmip_core_runtime::tuning::Tuning::default(),
        node: node(),
        audit: None,
    }
}

/// On a working node over `storage`, `run`.
fn working<T>(
    storage: &Arc<dyn XmipStorage>,
    run: impl FnOnce(&Runtime<'_>, &Pickup, &ReceiveGate) -> T,
) -> T {
    on_working_node(
        storage,
        (CHUNK, &routes()),
        (sending_nothing(), vec![batches()]),
        |r, p, g| run(r, p, &opened(g)),
    )
}

/// Each batch published to `Out`.
fn published(storage: &Arc<dyn XmipStorage>) -> Vec<Vec<String>> {
    published_to(storage, "Out")
}

/// Each Message published to the Send Port `port`, in the order its queue
/// holds them: the text of each of its Sections, in order.
pub(super) fn published_to(storage: &Arc<dyn XmipStorage>, port: &str) -> Vec<Vec<String>> {
    let cluster = configure::fixture::test_cluster().scope();
    let out = xmip_core_runtime::sending::queue(&cluster, &Subscriber::SendPort(port.into()));
    let held = storage.read_held(out, 0, 100).expect("read").held;
    held.iter()
        .map(|held| {
            let journey = storage
                .read_journey(held.hold.journey)
                .expect("read")
                .expect("its Journey");
            let journey = journey::Journey::from_record(&journey.body).expect("a Journey");
            let message = journey.messages().last().expect("a Message").message_id;
            let message = xmip_core_runtime::ledger::read_message(storage, message)
                .expect("read")
                .expect("its Message");
            message
                .sections()
                .iter()
                .map(|section| {
                    let mut text = String::new();
                    std::io::Read::read_to_string(
                        &mut section.stream.reader().expect("its Stream"),
                        &mut text,
                    )
                    .expect("text");
                    text
                })
                .collect()
        })
        .collect()
}

fn carried(runtime: &Runtime<'_>, pickup: &Pickup, gate: &ReceiveGate, who: &str, n: u32) {
    let carried = carry(runtime, pickup, gate, order(who, n));
    assert_eq!(
        carried.cycle(),
        ReceiveCycle::Completed,
        "{:?}",
        carried.arrived
    );
}

#[test]
fn a_clients_messages_make_one_instance_and_its_batch_holds_them_in_the_order_received() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        for number in 0..4 {
            carried(runtime, pickup, gate, "A", number);
            let turned = turn_due(runtime, pickup);
            assert!(
                turned.iter().all(|turned| matches!(turned, Turned::Done)),
                "{turned:?}"
            );
        }
    });
    assert_eq!(published(&storage), vec![vec!["A 1", "A 2", "A 3"]]);
}

#[test]
fn two_clients_carried_at_once_never_see_one_of_their_messages_overtake_another() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        std::thread::scope(|scope| {
            scope.spawn(|| dispatch(scope, runtime, pickup));
            std::thread::scope(|carrying| {
                for who in ["A", "B"] {
                    carrying.spawn(move || {
                        for number in 0..4 {
                            carried(runtime, pickup, gate, who, number);
                        }
                    });
                }
            });
            let until = Instant::now() + Duration::from_secs(10);
            while published(&storage).len() < 2 && Instant::now() < until {
                runtime.work.ask_every();
                std::thread::yield_now();
            }
            runtime.work.close();
        });
    });
    let mut batches = published(&storage);
    batches.sort();
    assert_eq!(
        batches,
        vec![vec!["A 1", "A 2", "A 3"], vec!["B 1", "B 2", "B 3"]]
    );
}

/// The child that carries a client's first two Messages, takes their
/// turns, says so, and waits to be killed with its Instance mid-Batch.
pub fn work_until_killed(storage: &Arc<dyn XmipStorage>) {
    working(storage, |runtime, pickup, gate| {
        for number in 0..2 {
            carried(runtime, pickup, gate, "A", number);
            let turned = turn_due(runtime, pickup);
            assert!(
                turned.iter().all(|t| matches!(t, Turned::Done)),
                "{turned:?}"
            );
        }
        say("waiting");
        loop {
            std::thread::park();
        }
    });
}

#[test]
fn a_node_killed_mid_process_is_started_again_and_finishes_its_instance_from_the_ledger() {
    let place = directory("work-killed");
    let child = ChildProcess::start("working", &place);
    child.heard("waiting", STARTED);
    let _ = child.killed();
    let storage = test_node(&place);
    assert!(
        published(&storage).is_empty(),
        "nothing is published mid-Batch"
    );
    working(&storage, |runtime, pickup, gate| {
        for number in 2..4 {
            carried(runtime, pickup, gate, "A", number);
            let turned = turn_due(runtime, pickup);
            assert!(
                turned.iter().all(|t| matches!(t, Turned::Done)),
                "{turned:?}"
            );
        }
    });
    assert_eq!(published(&storage), vec![vec!["A 1", "A 2", "A 3"]]);
}

#[test]
fn a_turn_costs_far_under_a_millisecond_beside_its_ledger_writes() {
    let storage = memory();
    working(&storage, |runtime, pickup, gate| {
        let mut spent = Vec::new();
        for (number, who) in (0..200u32).map(|n| (n % 4, format!("C{}", n / 4))) {
            carried(runtime, pickup, gate, &who, number);
            let began = Instant::now();
            let turned = turn_due(runtime, pickup);
            spent.push(began.elapsed());
            assert!(
                turned.iter().all(|t| matches!(t, Turned::Done)),
                "{turned:?}"
            );
        }
        spent.sort();
        let median = spent[spent.len() / 2];
        say(&format!(
            "a turn, its Ledger reads and its write in memory: median {median:?}, \
             slowest {:?}",
            spent[spent.len() - 1]
        ));
        // The millisecond rule is a release build's: a debug build's turn is
        // said and not held to it, as the estate's other figures are.
        if !cfg!(debug_assertions) {
            assert!(median < Duration::from_millis(1), "a turn took {median:?}");
        }
    });
}
