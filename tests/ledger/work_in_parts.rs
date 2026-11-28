//! The Work Process the Instance tests run (`work_instances.rs`): an order
//! delivered in parts, drawn in BPMN 2.0 with its own values — what was
//! ordered and delivered — a wait it loops back to, a unit that checks each
//! delivery and can be broken, and a deadline; the routes that carry an
//! order's Messages into it and its confirmation out, and the node it runs
//! on.

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use expression::Expression;
use message::Message;
use persist::storage::XmipStorage;
use process::program::Call;
use receive::ReceivedStream;
use route::{Subscriber, Subscription};
use xcore::{IdGenerator, JourneyId, MessageId, ScalarValue};
use xmip_core_runtime::ledger::CHUNK;
use xmip_core_runtime::message_path::{ReceiveCycle, Runtime, carry};
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::ReceiveGate;
use xmip_core_runtime::split::Split;
use xmip_core_runtime::work_step::{Running, Thrown, WorkUnits};

use super::receive_cycle::on_working_node;
use super::work_design::{client, compiled, per_client, sending_nothing};
/// The design: an order keeps its lines; each delivery the wait takes is
/// checked by the unit `Check` of `Units` and counted, and the subprocess
/// loops back to the wait until every line is delivered; then the order is
/// marked delivered and published. `deadline` after the order its boundary
/// timer raises it overdue.
fn in_parts(deadline: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    xmlns:xmip="urn:xmip:process:1" id="D" targetNamespace="urn:example:orders">
  <bpmn:error id="Late" errorCode="overdue"/>
  <bpmn:process id="InParts" isExecutable="true">
    <bpmn:dataObject id="OrderedData" name="Ordered"/>
    <bpmn:dataObject id="DeliveredData" name="Delivered"/>
    <bpmn:startEvent id="Ordered">
      <bpmn:extensionElements><xmip:correlate correlation="PerClient"/></bpmn:extensionElements>
    </bpmn:startEvent>
    <bpmn:task id="Note">
      <bpmn:dataOutputAssociation id="NoteOrdered"><bpmn:targetRef>OrderedData</bpmn:targetRef>
        <bpmn:assignment><bpmn:from>http.header.x-lines</bpmn:from><bpmn:to>Ordered</bpmn:to></bpmn:assignment>
      </bpmn:dataOutputAssociation>
      <bpmn:dataOutputAssociation id="NoteDelivered"><bpmn:targetRef>DeliveredData</bpmn:targetRef>
        <bpmn:assignment><bpmn:from>0</bpmn:from><bpmn:to>Delivered</bpmn:to></bpmn:assignment>
      </bpmn:dataOutputAssociation>
    </bpmn:task>
    <bpmn:subProcess id="Deliver">
      <bpmn:startEvent id="Begin"/>
      <bpmn:exclusiveGateway id="Again"/>
      <bpmn:receiveTask id="Wait">
        <bpmn:extensionElements><xmip:correlate correlation="PerClient"/></bpmn:extensionElements>
      </bpmn:receiveTask>
      <bpmn:serviceTask id="Check">
        <bpmn:extensionElements><xmip:call module="Units" unit="Check"/></bpmn:extensionElements>
      </bpmn:serviceTask>
      <bpmn:task id="Count">
        <bpmn:dataOutputAssociation id="Counted"><bpmn:targetRef>DeliveredData</bpmn:targetRef>
          <bpmn:assignment><bpmn:from>Delivered + http.header.x-lines</bpmn:from><bpmn:to>Delivered</bpmn:to></bpmn:assignment>
        </bpmn:dataOutputAssociation>
      </bpmn:task>
      <bpmn:exclusiveGateway id="Done" default="NotYet"/>
      <bpmn:endEvent id="All"/>
      <bpmn:sequenceFlow id="ToAgain" sourceRef="Begin" targetRef="Again"/>
      <bpmn:sequenceFlow id="ToWait" sourceRef="Again" targetRef="Wait"/>
      <bpmn:sequenceFlow id="ToCheck" sourceRef="Wait" targetRef="Check"/>
      <bpmn:sequenceFlow id="ToCount" sourceRef="Check" targetRef="Count"/>
      <bpmn:sequenceFlow id="ToDone" sourceRef="Count" targetRef="Done"/>
      <bpmn:sequenceFlow id="Delivered" sourceRef="Done" targetRef="All">
        <bpmn:conditionExpression>Delivered &gt;= Ordered</bpmn:conditionExpression>
      </bpmn:sequenceFlow>
      <bpmn:sequenceFlow id="NotYet" sourceRef="Done" targetRef="Again"/>
    </bpmn:subProcess>
    <bpmn:boundaryEvent id="Deadline" attachedToRef="Deliver">
      <bpmn:timerEventDefinition><bpmn:timeDuration>{deadline}</bpmn:timeDuration></bpmn:timerEventDefinition>
    </bpmn:boundaryEvent>
    <bpmn:endEvent id="Overdue"><bpmn:errorEventDefinition errorRef="Late"/></bpmn:endEvent>
    <bpmn:task id="Mark">
      <bpmn:dataOutputAssociation id="Marked">
        <bpmn:assignment><bpmn:from>'delivered'</bpmn:from><bpmn:to>Status</bpmn:to></bpmn:assignment>
      </bpmn:dataOutputAssociation>
    </bpmn:task>
    <bpmn:sendTask id="Confirm"/>
    <bpmn:endEvent id="Closed"/>
    <bpmn:sequenceFlow id="F1" sourceRef="Ordered" targetRef="Note"/>
    <bpmn:sequenceFlow id="F2" sourceRef="Note" targetRef="Deliver"/>
    <bpmn:sequenceFlow id="F3" sourceRef="Deliver" targetRef="Mark"/>
    <bpmn:sequenceFlow id="F4" sourceRef="Mark" targetRef="Confirm"/>
    <bpmn:sequenceFlow id="F5" sourceRef="Confirm" targetRef="Closed"/>
    <bpmn:sequenceFlow id="F6" sourceRef="Deadline" targetRef="Overdue"/>
  </bpmn:process>
</bpmn:definitions>"#
    )
}

/// The unit `Check`: a new generation of the delivery it is handed, or the
/// error `offline` while it is broken.
struct Checking {
    broken: Arc<AtomicBool>,
}

impl WorkUnits for Checking {
    fn call(
        &self,
        call: &Call,
        message: &Message,
        ids: &dyn IdGenerator,
    ) -> Result<Vec<Message>, Thrown> {
        if self.broken.load(Ordering::Acquire) {
            return Err(Thrown {
                code: "offline".to_string(),
                reason: format!("the unit '{}' cannot reach its stock", call.unit),
            });
        }
        let checked = message.assigned(MessageId::new(ids.next_u128()), message.context().clone());
        Ok(vec![checked])
    }

    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown> {
        Err(Thrown {
            code: "no-unit".to_string(),
            reason: format!("no splitting unit '{}' here", call.unit),
        })
    }
}

/// The Work Process `InParts`, its deadline `deadline`, its unit `Check`
/// broken while `broken` says.
pub(super) fn running(deadline: &str, broken: &Arc<AtomicBool>) -> Running {
    let cluster = configure::fixture::test_cluster().scope();
    let units = Arc::new(Checking {
        broken: Arc::clone(broken),
    });
    let flow = Box::new(compiled(&in_parts(deadline)));
    Running::new((&cluster, "InParts"), flow, &[per_client()], &[], units).expect("it runs")
}

/// An order's Messages into the Work Process, its confirmation out to the
/// Send Port `Out`, which this node has no Location for.
fn routes() -> Vec<Subscription> {
    let route = |name: &str, to: Subscriber, filter: &str| {
        Subscription::new(name, to, Expression::parse(filter).expect("compiles"))
    };
    vec![
        route(
            "work",
            Subscriber::WorkProcess("InParts".into()),
            &format!("exists {} and not exists Status", client()),
        ),
        route(
            "out",
            Subscriber::SendPort("Out".into()),
            "Status = 'delivered'",
        ),
    ]
}

/// A Message of the order `order` carrying `lines`, carried in: its
/// Journey.
pub(super) fn carried(
    on: (&Runtime<'_>, &Pickup, &ReceiveGate),
    order: &str,
    lines: u32,
) -> JourneyId {
    let (runtime, pickup, gate) = on;
    let text = format!("{order}: {lines} line(s)");
    let stream = ReceivedStream::new(Cursor::new(text.into_bytes()), "tcp://127.0.0.1:1")
        .with_header("http", "x-client", ScalarValue::Text(order.to_string()))
        .with_header("http", "x-lines", ScalarValue::Text(lines.to_string()));
    let carried = carry(runtime, pickup, gate, stream);
    assert_eq!(
        carried.cycle(),
        ReceiveCycle::Completed,
        "{:?}",
        carried.arrived
    );
    carried.journeys[0].journey_id()
}

/// On a working node over `storage` running `InParts`, `run`: its Streams
/// side by side at the Receive Location, so what holds a later delivery
/// back is its Instance, never the order's Stream ahead of it.
pub(super) fn working(
    storage: &Arc<dyn XmipStorage>,
    process: Running,
    run: impl FnOnce((&Runtime<'_>, &Pickup, &ReceiveGate)),
) {
    on_working_node(
        storage,
        (CHUNK, &routes()),
        (sending_nothing(), vec![process]),
        |r, p, g| {
            let mut open = g.clone();
            open.points.clear();
            run((r, p, &open));
        },
    );
}
