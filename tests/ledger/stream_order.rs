//! Streams of one Receive Location reach an in-order Send Port in the
//! order they were received, one through a Work Process and one straight
//! there, and nothing waits for ever (the owner, 2026-10-22: *Default one
//! stream, message, journey at a time. Put it in the ledger if it is not
//! processed now*).
//!
//! Stream S1 goes through a Work Process, which publishes its Journey to
//! `Out` later; S2, received behind S1, goes to `Out` directly. S2 is not
//! being processed while S1 heads the Location's sequence, so its Journey
//! takes no place at `Out` until S1 has ended: S1's Journey goes first, and
//! S2's follows (`xmip_core_runtime::sequence::take_late`).

use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, Instant};

use configure::OnFailure;
use path::expression::Expression;
use process::{Compiled, DesignFormat, NoResources};
use process_bpmn::Bpmn;
use receive::ReceivedStream;
use route::{Subscriber, Subscription};
use xcore::ScalarValue;
use xmip_core_runtime::fixture::FarEnd;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::work_step::{NoUnits, Running, turn_due};

use super::receive_cycle::{node, on_working_node};
use super::sending::{dispatching, in_order, memory, out, sender, taking, took};

/// The Work Process: a Message marked and published back.
const ENRICH: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    id="D" targetNamespace="urn:example:orders">
  <bpmn:process id="Enrich" isExecutable="true">
    <bpmn:startEvent id="Arrived"/>
    <bpmn:task id="Mark">
      <bpmn:dataOutputAssociation id="Marked">
        <bpmn:assignment><bpmn:from>'enriched'</bpmn:from><bpmn:to>Status</bpmn:to></bpmn:assignment>
      </bpmn:dataOutputAssociation>
    </bpmn:task>
    <bpmn:sendTask id="Publish"/>
    <bpmn:endEvent id="Done"/>
    <bpmn:sequenceFlow id="F1" sourceRef="Arrived" targetRef="Mark"/>
    <bpmn:sequenceFlow id="F2" sourceRef="Mark" targetRef="Publish"/>
    <bpmn:sequenceFlow id="F3" sourceRef="Publish" targetRef="Done"/>
  </bpmn:process>
</bpmn:definitions>"#;

fn route_header() -> String {
    context::property::header("http", "x-route")
}

fn enrich() -> Running {
    let program = Bpmn.compile(ENRICH, &NoResources).expect("compiles");
    let flow = Compiled::new(program).expect("opens");
    let cluster = configure::fixture::test_cluster().scope();
    Running::new(
        (&cluster, "Enrich"),
        Box::new(flow),
        &[],
        &[],
        Arc::new(NoUnits),
    )
    .expect("it runs")
}

fn routes() -> Vec<Subscription> {
    let header = route_header();
    let route = |name: &str, to: Subscriber, filter: String| {
        Subscription::new(name, to, Expression::parse(&filter).expect("compiles"))
    };
    vec![
        route(
            "work",
            Subscriber::WorkProcess("Enrich".into()),
            format!("{header} = 'process' and not exists Status"),
        ),
        route(
            "direct",
            Subscriber::SendPort("Out".into()),
            format!("{header} = 'direct'"),
        ),
        route(
            "enriched",
            Subscriber::SendPort("Out".into()),
            "Status = 'enriched'".to_string(),
        ),
    ]
}

fn stream(text: &str, route: &str) -> ReceivedStream {
    ReceivedStream::new(Cursor::new(text.as_bytes().to_vec()), "tcp://127.0.0.1:1").with_header(
        "http",
        "x-route",
        ScalarValue::Text(route.to_string()),
    )
}

#[test]
fn a_stream_behind_another_takes_its_send_place_only_once_the_first_has_ended() {
    let storage = memory();
    let (far, taken) = FarEnd::answering(taking());
    let sending = sender(node(), far, out(in_order(OnFailure::Block)));
    on_working_node(
        &storage,
        (CHUNK, &routes()),
        (sending, vec![enrich()]),
        |runtime, pickup, gate| {
            assert!(!gate.points.is_empty(), "the Location's own sequence");
            dispatching(runtime, |_| {
                for (text, route) in [("S1", "process"), ("S2", "direct")] {
                    let carried = carry(runtime, pickup, gate, stream(text, route));
                    assert_eq!(carried.cycle(), ReceiveCycle::Completed, "{text}");
                }
                let until = Instant::now() + Duration::from_secs(10);
                while took(&taken).len() < 2 && Instant::now() < until {
                    let _ = turn_due(runtime, pickup);
                    runtime.send.rescan();
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
        },
    );
    assert_eq!(
        took(&taken),
        ["S1", "S2"],
        "S1, through its Work Process, before S2, and neither waits for ever"
    );
}
