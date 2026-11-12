//! A Journey behind another Stream of its sequence, taken up at once where
//! another node ends that Stream (open problem 46; ADR-0018 and ADR-0066,
//! amendments 2026-11-12): the node passing it over waits on the
//! sequence's head in Xmip Storage, and reads its queue the moment the
//! head moves, on whichever node — never at its next scan, here an hour:
//!
//! - a Message bound for a Send Port, behind a Stream of its Receive
//!   Location whose last travel another node's Work Process ends, is sent
//!   by the node sending the Port;
//! - a Message bound for a Work Process, behind a Stream of its Receive
//!   Location another node sends, is taken its turn by the node running
//!   the Work Process;
//! - and a turn its Instance did not take — waiting for a timer — names
//!   what it waits on: the Instance as it read it.
//!
//! Each holds that the waiting node waits on the head before the other
//! node moves it, and that no second scan came before it was taken up: so
//! only the wait can have taken it up.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use journey::JourneyState;
use path::expression::Expression;
use persist::storage::{Position, Watched, XmipStorage};
use process::{Compiled, DesignFormat, NoResources};
use process_bpmn::Bpmn;
use receive::ReceivedStream;
use route::{Subscriber, Subscription};
use xcore::ScalarValue;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{Carried, ReceiveCycle, carry};
use xmip_core_runtime::tuning::Tuning;
use xmip_core_runtime::work_step::{NoUnits, Running, Turned, WorkStep, dispatch, turn_due};

use super::receive_cycle::{Sender, on_working_node};
use super::sending::{dispatching, journey, memory_node, out, sender, taking, took, until};
use super::work_design::{from_client, per_client, sending_nothing};

/// An hour: no scan comes while a test runs.
const HOUR: Duration = Duration::from_secs(3600);

/// The test cluster's second node: the one waiting on what another moves.
fn other() -> String {
    configure::fixture::test_cluster().node_scope(1)
}

/// A Work Process `name` of the design `design`, following the cluster's
/// Correlation by client.
fn running(name: &str, design: &str) -> Running {
    let program = Bpmn.compile(design, &NoResources).expect("compiles");
    let flow = Compiled::new(program).expect("opens");
    let cluster = configure::fixture::test_cluster().scope();
    Running::new(
        (&cluster, name),
        Box::new(flow),
        &[per_client()],
        &[],
        Arc::new(NoUnits),
    )
    .expect("it runs")
}

/// A Message taken in and ended there.
const ABSORB: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    id="D" targetNamespace="urn:example:orders">
  <bpmn:process id="Absorb" isExecutable="true">
    <bpmn:startEvent id="Arrived"/>
    <bpmn:endEvent id="Done"/>
    <bpmn:sequenceFlow id="F1" sourceRef="Arrived" targetRef="Done"/>
  </bpmn:process>
</bpmn:definitions>"#;

/// A client's first Message starts its Instance, which waits an hour, then
/// for the client's next.
const LATER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    xmlns:xmip="urn:xmip:process:1" id="D" targetNamespace="urn:example:orders">
  <bpmn:process id="Later" isExecutable="true">
    <bpmn:startEvent id="First">
      <bpmn:extensionElements><xmip:correlate correlation="PerClient"/></bpmn:extensionElements>
    </bpmn:startEvent>
    <bpmn:intermediateCatchEvent id="Hour">
      <bpmn:timerEventDefinition><bpmn:timeDuration>PT1H</bpmn:timeDuration></bpmn:timerEventDefinition>
    </bpmn:intermediateCatchEvent>
    <bpmn:receiveTask id="Next">
      <bpmn:extensionElements><xmip:correlate correlation="PerClient"/></bpmn:extensionElements>
    </bpmn:receiveTask>
    <bpmn:endEvent id="Done"/>
    <bpmn:sequenceFlow id="F1" sourceRef="First" targetRef="Hour"/>
    <bpmn:sequenceFlow id="F2" sourceRef="Hour" targetRef="Next"/>
    <bpmn:sequenceFlow id="F3" sourceRef="Next" targetRef="Done"/>
  </bpmn:process>
</bpmn:definitions>"#;

fn route_header() -> String {
    context::property::header("http", "x-route")
}

/// Into `Absorb` where the Stream says `process`, to `Out` where it says
/// `direct`.
fn absorbed_or_direct() -> Vec<Subscription> {
    let header = route_header();
    let route = |name: &str, to: Subscriber, value: &str| {
        let filter = format!("{header} = '{value}'");
        Subscription::new(name, to, Expression::parse(&filter).expect("compiles"))
    };
    vec![
        route("work", Subscriber::WorkProcess("Absorb".into()), "process"),
        route("direct", Subscriber::SendPort("Out".into()), "direct"),
    ]
}

fn stream(text: &str, route: &str) -> ReceivedStream {
    ReceivedStream::new(Cursor::new(text.as_bytes().to_vec()), "tcp://127.0.0.1:1").with_header(
        "http",
        "x-route",
        ScalarValue::Text(route.to_string()),
    )
}

/// The sequence the Stream of what `carried` opened first holds a place in
/// end to end, and that Journey.
fn sequence_of(carried: &Carried) -> (u128, journey::Journey) {
    let opened = carried.journeys[0].clone();
    let received = opened.received().expect("received here");
    (received.sequences[0], opened)
}

#[test]
fn a_message_behind_a_stream_another_node_ends_is_sent_at_once_by_the_node_sending_its_port() {
    let node = memory_node();
    let storage: Arc<dyn XmipStorage> = Arc::clone(&node) as _;
    let routes = absorbed_or_direct();
    let (far, taken) = FarEnd::answering(taking());
    let mut sending = sender(other(), far, out(|_| {}));
    sending.tuning.send_scan = HOUR;
    let absorbing = Sender {
        tuning: Tuning {
            work_scan: HOUR,
            ..Tuning::default()
        },
        ..sending_nothing()
    };
    on_working_node(
        &storage,
        (CHUNK, &routes),
        (sending, Vec::new()),
        |sends, _, _| {
            dispatching(sends, |told| {
                until(|| sends.send.scans() == 1, "the first scan made");
                let runs = (absorbing, vec![running("Absorb", ABSORB)]);
                on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
                    assert!(!gate.points.is_empty(), "the Location's own sequence");
                    let first = carry(works, pickup, gate, stream("first stream", "process"));
                    let second = carry(works, pickup, gate, stream("second stream", "direct"));
                    for carried in [&first, &second] {
                        assert_eq!(carried.cycle(), ReceiveCycle::Completed);
                    }
                    let (sequence, direct) = sequence_of(&second);
                    // Passed over behind the first Stream, its head waited on.
                    until(
                        || node.waiting_on(Watched::Head(sequence)) == 1,
                        "the sequence's head waited on",
                    );
                    // The first Stream's last travel ends on this node.
                    let turned = turn_due(works, pickup);
                    assert!(
                        turned.iter().any(|t| matches!(t, Turned::Done)),
                        "{turned:?}"
                    );
                    told.wait_for(direct.journey_id(), "completed");
                    assert_eq!(sends.send.scans(), 1, "sent before any scan came");
                });
            });
        },
    );
    assert_eq!(took(&taken), ["second stream"]);
}

#[test]
fn a_message_behind_a_stream_another_node_sends_takes_its_turn_at_once_where_it_runs() {
    let node = memory_node();
    let storage: Arc<dyn XmipStorage> = Arc::clone(&node) as _;
    let routes = absorbed_or_direct();
    let runner = Sender {
        tuning: Tuning {
            work_scan: HOUR,
            ..Tuning::default()
        },
        node: other(),
        ..sending_nothing()
    };
    let runs = (runner, vec![running("Absorb", ABSORB)]);
    on_working_node(
        &storage,
        (CHUNK, &routes),
        runs,
        |works, works_pickup, _| {
            std::thread::scope(|scope| {
                scope.spawn(|| dispatch(scope, works, works_pickup));
                let _closing = Closing(works.work);
                until(|| works.work.scans() == 1, "the first scan made");
                let receives = (sending_nothing(), Vec::new());
                on_working_node(
                    &storage,
                    (CHUNK, &routes),
                    receives,
                    |routes_on, pickup, gate| {
                        let first =
                            carry(routes_on, pickup, gate, stream("first stream", "direct"));
                        let second =
                            carry(routes_on, pickup, gate, stream("second stream", "process"));
                        for carried in [&first, &second] {
                            assert_eq!(carried.cycle(), ReceiveCycle::Completed);
                        }
                        let (sequence, absorbed) = sequence_of(&second);
                        // Passed over behind the first Stream, its head waited on.
                        until(
                            || node.waiting_on(Watched::Head(sequence)) == 1,
                            "the sequence's head waited on",
                        );
                        // Another node sends the first Stream: its travel ends.
                        let third = configure::fixture::test_cluster().node_scope(2);
                        let (far, taken) = FarEnd::answering(taking());
                        let sends = (sender(third, far, out(|_| {})), Vec::new());
                        on_working_node(&storage, (CHUNK, &routes), sends, |sends_on, _, _| {
                            dispatching(sends_on, |told| {
                                told.wait_for(first.journeys[0].journey_id(), "completed");
                            });
                        });
                        assert_eq!(took(&taken), ["first stream"]);
                        until(
                            || {
                                let state = journey(storage.as_ref(), absorbed.journey_id()).state;
                                state == JourneyState::Completed
                            },
                            "its turn taken",
                        );
                        assert_eq!(works.work.scans(), 1, "turned before any scan came");
                    },
                );
            });
        },
    );
}

#[test]
fn a_turn_its_instance_does_not_take_waits_on_the_instance_as_it_read_it() {
    let storage: Arc<dyn XmipStorage> = memory_node();
    let routes = [Subscription::new(
        "later",
        Subscriber::WorkProcess("Later".into()),
        Expression::parse("xmip.transport.mechanism = 'circumstance'").expect("compiles"),
    )];
    let runs = (sending_nothing(), vec![running("Later", LATER)]);
    on_working_node(&storage, (CHUNK, &routes), runs, |works, pickup, gate| {
        // Streams side by side: no sequence holds the second behind.
        let mut open = gate.clone();
        open.points.clear();
        let first = carry(works, pickup, &open, from_client("A", "A 0"));
        let second = carry(works, pickup, &open, from_client("A", "A 1"));
        let instance = first.journeys[0].journey_id().value();
        assert_ne!(second.journeys[0].journey_id().value(), instance);
        let turned = turn_due(works, pickup);
        assert!(matches!(turned[0], Turned::Done), "{turned:?}");
        let Turned::Waits { on, .. } = &turned[1] else {
            panic!("{turned:?}");
        };
        let at_its_first_turn = Position {
            watched: Watched::Instance(instance),
            at: 1,
        };
        assert_eq!(on, &[at_its_first_turn], "the Instance, waiting an hour");
    });
}

/// A Work Process step closed when this is dropped, however the test got
/// there, so a failing test fails rather than waits.
struct Closing<'a>(&'a WorkStep);

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
}
