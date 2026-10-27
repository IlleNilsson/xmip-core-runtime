//! A Work Process's Debatch run from the Ledger through the one splitting
//! implementation the receive calls too (`xmip_core_runtime::split`;
//! ADR-0031, amendment 2026-10-22):
//!
//! - a Message carried in is split a record a line, each part published back
//!   through routing as a Message of its own, in the order of its records,
//!   carrying the context the Work Process gave it;
//! - a record the unit refuses throws `record-refused`, naming the record,
//!   which the design's error boundary catches.

use std::sync::Arc;

use path::expression::Expression;
use persist::storage::XmipStorage;
use process::{Compiled, DesignFormat, NoResources};
use process_bpmn::Bpmn;
use route::{Subscriber, Subscription};
use xmip_core_runtime::fixture::LinesUnits;
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, carry};
use xmip_core_runtime::work_step::{Running, Turned, turn_due};

use super::receive_cycle::on_working_node;
use super::sending::memory;
use super::work_process::{client, from_client, published_to, sending_nothing};

/// The design: a Message marked, split a record a line, each part
/// published; a refused record caught and the Message published to
/// `Refused` instead.
const SPLITS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    xmlns:xmip="urn:xmip:process:1" id="D" targetNamespace="urn:example:orders">
  <bpmn:error id="Refused" errorCode="record-refused"/>
  <bpmn:process id="Splits" isExecutable="true">
    <bpmn:startEvent id="Arrived"/>
    <bpmn:task id="Mark">
      <bpmn:dataOutputAssociation id="Marked">
        <bpmn:assignment><bpmn:from>'split'</bpmn:from><bpmn:to>Status</bpmn:to></bpmn:assignment>
      </bpmn:dataOutputAssociation>
    </bpmn:task>
    <bpmn:serviceTask id="Split">
      <bpmn:extensionElements><xmip:debatch module="Units" unit="Lines"/></bpmn:extensionElements>
    </bpmn:serviceTask>
    <bpmn:boundaryEvent id="Caught" attachedToRef="Split">
      <bpmn:errorEventDefinition errorRef="Refused"/>
    </bpmn:boundaryEvent>
    <bpmn:task id="Unsplit">
      <bpmn:dataOutputAssociation id="Unmarked">
        <bpmn:assignment><bpmn:from>'refused'</bpmn:from><bpmn:to>Status</bpmn:to></bpmn:assignment>
      </bpmn:dataOutputAssociation>
    </bpmn:task>
    <bpmn:sendTask id="Report"/>
    <bpmn:endEvent id="Done"/>
    <bpmn:endEvent id="Reported"/>
    <bpmn:sequenceFlow id="F1" sourceRef="Arrived" targetRef="Mark"/>
    <bpmn:sequenceFlow id="F2" sourceRef="Mark" targetRef="Split"/>
    <bpmn:sequenceFlow id="F3" sourceRef="Split" targetRef="Done"/>
    <bpmn:sequenceFlow id="F4" sourceRef="Caught" targetRef="Unsplit"/>
    <bpmn:sequenceFlow id="F5" sourceRef="Unsplit" targetRef="Report"/>
    <bpmn:sequenceFlow id="F6" sourceRef="Report" targetRef="Reported"/>
  </bpmn:process>
</bpmn:definitions>"#;

fn splits() -> Running {
    let program = Bpmn
        .compile(SPLITS, &NoResources)
        .expect("the design compiles");
    let flow = Compiled::new(program).expect("the unit opens");
    let cluster = configure::fixture::test_cluster().scope();
    Running::new(
        (&cluster, "Splits"),
        Box::new(flow),
        &[],
        &[],
        Arc::new(LinesUnits),
    )
    .expect("it runs")
}

fn routes() -> Vec<Subscription> {
    let route = |name: &str, to: Subscriber, filter: &str| {
        Subscription::new(name, to, Expression::parse(filter).expect("compiles"))
    };
    vec![
        route(
            "work",
            Subscriber::WorkProcess("Splits".into()),
            &format!("exists {} and not exists Status", client()),
        ),
        route(
            "lines",
            Subscriber::SendPort("Lines".into()),
            "Status = 'split'",
        ),
        route(
            "refused",
            Subscriber::SendPort("Refused".into()),
            "Status = 'refused'",
        ),
    ]
}

/// `text` carried in and its Work Process's turns taken.
fn carried_and_turned(storage: &Arc<dyn XmipStorage>, text: &str) {
    on_working_node(
        storage,
        (CHUNK, &routes()),
        (sending_nothing(), vec![splits()]),
        |runtime, pickup, gate| {
            let carried = carry(runtime, pickup, gate, from_client("A", text));
            assert_eq!(
                carried.cycle(),
                ReceiveCycle::Completed,
                "{:?}",
                carried.arrived
            );
            let turned = turn_due(runtime, pickup);
            assert!(
                turned.iter().all(|turned| matches!(turned, Turned::Done)),
                "{turned:?}"
            );
        },
    );
}

#[test]
fn a_message_is_split_a_record_a_message_each_published_in_the_order_of_its_records() {
    let storage = memory();
    carried_and_turned(&storage, "one\ntwo\nthree\n");
    assert_eq!(
        published_to(&storage, "Lines"),
        vec![vec!["one"], vec!["two"], vec!["three"]]
    );
    assert!(published_to(&storage, "Refused").is_empty());
}

#[test]
fn a_record_the_unit_refuses_throws_record_refused_which_the_design_catches() {
    let storage = memory();
    carried_and_turned(&storage, "one\nbad!\nthree\n");
    assert!(
        published_to(&storage, "Lines").is_empty(),
        "no part is published once a record is refused"
    );
    assert_eq!(
        published_to(&storage, "Refused"),
        vec![vec!["one\nbad!\nthree\n"]]
    );
}
