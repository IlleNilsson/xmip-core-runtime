//! The Work Process its tests run (`work_process.rs`, `work_debatch.rs`)
//! and the module's timing program (`tests/measured`) measures: a BPMN 2.0
//! design compiled to its program, the node it runs on, and a client's
//! Messages carried into it and its batches read back from the Ledger.

use std::io::Cursor;
use std::sync::Arc;

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
use xmip_core_runtime::work_step::{KeyWord, NoUnits, ResolvedSet, Running};

use super::receive_cycle::{Sender, node, on_working_node};

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
pub(super) fn per_client() -> ResolvedSet {
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
pub(super) fn working<T>(
    storage: &Arc<dyn XmipStorage>,
    run: impl FnOnce(&Runtime<'_>, &Pickup, &ReceiveGate) -> T,
) -> T {
    routing(storage, (true, sending_nothing()), run)
}

/// On a node over `storage` routing as [`working`] does, sending as
/// `sender` says, and running the Work Process only where it `runs`: one
/// node routing a client's Messages to the Work Process another runs
/// (`woken.rs`).
pub(super) fn routing<T>(
    storage: &Arc<dyn XmipStorage>,
    (runs, sender): (bool, Sender),
    run: impl FnOnce(&Runtime<'_>, &Pickup, &ReceiveGate) -> T,
) -> T {
    let running = if runs { vec![batches()] } else { Vec::new() };
    on_working_node(storage, (CHUNK, &routes()), (sender, running), |r, p, g| {
        run(r, p, &opened(g))
    })
}

/// Each batch published to `Out`.
pub(super) fn published(storage: &Arc<dyn XmipStorage>) -> Vec<Vec<String>> {
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

pub(super) fn carried(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    gate: &ReceiveGate,
    who: &str,
    n: u32,
) {
    let carried = carry(runtime, pickup, gate, order(who, n));
    assert_eq!(
        carried.cycle(),
        ReceiveCycle::Completed,
        "{:?}",
        carried.arrived
    );
}
