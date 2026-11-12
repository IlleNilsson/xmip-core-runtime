//! The Work Processes its tests run (`work_process.rs`, `work_debatch.rs`,
//! `woken.rs`, `woken_behind.rs`, `work_panicked.rs`, `work_bounded.rs`)
//! and the module's timing program (`tests/measured`) measures: BPMN 2.0
//! designs compiled to their programs, the node they run on, how a client's
//! Messages are routed and carried into them, and their batches read back
//! from the Ledger. What those tests turn with is `work_turning.rs`.

use std::io::Cursor;
use std::sync::Arc;

use path::expression::Expression;
use persist::storage::XmipStorage;
use process::{Compiled, DesignFormat, Flow, NoResources};
use process_bpmn::Bpmn;
use receive::ReceivedStream;
use route::{Subscriber, Subscription};
use xcore::{JourneyId, ScalarValue};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, Runtime, carry};
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::ReceiveGate;
use xmip_core_runtime::sequence::{OnFailure, Point, PointKind};
use xmip_core_runtime::work_step::{KeyWord, NoUnits, ResolvedSet, Running, WorkUnits};

use super::receive_cycle::{Sender, node, on_working_node};

/// A Message taken in and ended there.
pub(super) const ABSORB: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    id="D" targetNamespace="urn:example:orders">
  <bpmn:process id="Absorb" isExecutable="true">
    <bpmn:startEvent id="Arrived"/>
    <bpmn:endEvent id="Done"/>
    <bpmn:sequenceFlow id="F1" sourceRef="Arrived" targetRef="Done"/>
  </bpmn:process>
</bpmn:definitions>"#;

/// A Message taken in, handed to the unit `Call` of `Units`, and ended.
pub(super) const CALLS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    xmlns:xmip="urn:xmip:process:1" id="D" targetNamespace="urn:example:orders">
  <bpmn:process id="Calls" isExecutable="true">
    <bpmn:startEvent id="Arrived"/>
    <bpmn:serviceTask id="Call">
      <bpmn:extensionElements><xmip:call module="Units" unit="Call"/></bpmn:extensionElements>
    </bpmn:serviceTask>
    <bpmn:endEvent id="Done"/>
    <bpmn:sequenceFlow id="F1" sourceRef="Arrived" targetRef="Call"/>
    <bpmn:sequenceFlow id="F2" sourceRef="Call" targetRef="Done"/>
  </bpmn:process>
</bpmn:definitions>"#;

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
    running("Batches", BATCHES)
}

/// `design` compiled to its program and opened as a flow.
pub(super) fn compiled(design: &str) -> Compiled {
    let program = Bpmn
        .compile(design, &NoResources)
        .expect("the design compiles");
    Compiled::new(program).expect("the unit opens")
}

/// The Work Process `name` of the design `design`, following the cluster's
/// Correlation by client, calling no unit.
pub(super) fn running(name: &str, design: &str) -> Running {
    running_as(name, Box::new(compiled(design)), Arc::new(NoUnits))
}

/// The Work Process `name`, run by `flow`, following the cluster's
/// Correlation by client, its work done by `units`.
pub(super) fn running_as(name: &str, flow: Box<dyn Flow>, units: Arc<dyn WorkUnits>) -> Running {
    let cluster = configure::fixture::test_cluster().scope();
    Running::new((&cluster, name), flow, &[per_client()], &[], units).expect("it runs")
}

/// The header a Stream names the Work Process it is for by.
pub(super) fn route_header() -> String {
    context::property::header("http", "x-route")
}

/// `text`, as a Receive Location takes it, its route header saying `route`.
pub(super) fn stream(text: &str, route: &str) -> ReceivedStream {
    ReceivedStream::new(Cursor::new(text.as_bytes().to_vec()), "tcp://127.0.0.1:1").with_header(
        "http",
        "x-route",
        ScalarValue::Text(route.to_string()),
    )
}

/// Into each Work Process of `names` where a client's Stream's route header
/// names it: the client promoted, so the Correlation by client keys it.
pub(super) fn routes_to(names: &[&str]) -> Vec<Subscription> {
    let (header, client) = (route_header(), client());
    names
        .iter()
        .map(|name| {
            let filter = format!("exists {client} and {header} = '{name}'");
            let to = Subscriber::WorkProcess((*name).to_string());
            Subscription::new(*name, to, Expression::parse(&filter).expect("compiles"))
        })
        .collect()
}

/// A Message from the client `who` carried into the Work Process `name`
/// through `gate`, its Streams side by side with every other's: its
/// Journey.
pub(super) fn carried_to(
    (runtime, pickup): (&Runtime<'_>, &Pickup),
    gate: &ReceiveGate,
    name: &str,
    who: &str,
) -> JourneyId {
    let mut open = gate.clone();
    open.points.clear();
    let text = format!("{who} for {name}");
    let received =
        from_client(who, &text).with_header("http", "x-route", ScalarValue::Text(name.to_string()));
    let carried = carry(runtime, pickup, &open, received);
    assert_eq!(
        carried.cycle(),
        ReceiveCycle::Completed,
        "{:?}",
        carried.arrived
    );
    carried.journeys[0].journey_id()
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
