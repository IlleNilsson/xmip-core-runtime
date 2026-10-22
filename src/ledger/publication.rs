//! Publication's one write into the Ledger (`runtime-model.md` sections 5
//! and 9): the Message record, a Journey for every Subscription routing
//! matched — one for each Send Port of a Send Port Group (section 10) —
//! what a paused Subscription holds, the rest in the queue of where
//! each leads with this node's claims, or — where nothing matched — the
//! Dead Message Queue entry, and the audit record, all or nothing.

use std::collections::BTreeMap;

use journey::{ChainCause, Journey, JourneyMessageRef, Received};
use message::Message;
use persist::storage::{AuditEntry, Durable, Hold, Publication, XmipStorage};
use route::{Gathering, Routing, Subscriber};
use xaudit::audit_record::AuditRecord;
use xaudit::origin::Origin;
use xcore::{AuditId, Clock, ExecutionPhase, IdGenerator, JourneyId, Severity};

use crate::dead_message::{self, Unmatched};
use crate::pickup::{Holding, Pickup};
use crate::send_step::{LinedUp, SendStep};
use crate::sending::Sends;

/// What a Publication wrote: a Journey for every Subscription routing
/// matched and every Send Port it reaches, in the order they were asked,
/// which of them a paused Subscription holds, and where the rest wait to be
/// sent — those this node claimed among them — and when it is durable.
pub struct Published {
    pub journeys: Vec<Journey>,
    pub holding: Holding,
    pub lined: LinedUp,
    /// Waited on before the receive cycle ends and before a far end sees a
    /// Journey of it: the Publication is answered before its sync.
    pub durable: Durable,
}

/// What a Publication is written with: Xmip Storage, how its identifiers
/// are minted, the clock, who its audit record says it came from, the
/// node's send step and its Send Ports.
pub struct Publisher<'a> {
    pub storage: &'a dyn XmipStorage,
    pub ids: &'a dyn IdGenerator,
    pub clock: &'a dyn Clock,
    pub origin: &'a Origin,
    pub send: &'a SendStep,
    pub sends: &'a Sends,
    /// What a sequence's keys read of the Message, and the cluster its
    /// sequences are named in (`crate::sequence`).
    pub gathering: &'a Gathering,
    pub cluster: &'a str,
}

/// A Journey a Publication opens: the Subscription that matched and where
/// the Journey leads — a Send Port, a Work Process, or a Send Port Group
/// no Application of this node declares.
#[derive(Clone, Debug)]
pub struct Opened {
    pub journey: Journey,
    pub subscription: String,
    pub to: Subscriber,
}

/// A Journey for every Subscription `routing` matched and every Send Port
/// `pickup` says it reaches — one per Port of a Send Port Group, each led
/// to its Port (`runtime-model.md` section 10: *A Send Port Group is only a
/// named set: routing already made one Journey per Send Port in it*) — in
/// the order they were asked, holding `held`, caused by that Subscription,
/// at depth zero, its identifier minted by `ids`: what a Publication opens,
/// and a Replay from the Dead Message Queue.
pub(crate) fn opened(
    routing: &Routing,
    pickup: &Pickup,
    held: JourneyMessageRef,
    ids: &dyn IdGenerator,
) -> Vec<Opened> {
    let matched = routing.evaluations.iter().filter(|e| e.matched());
    matched
        .flat_map(|evaluation| {
            let name = &evaluation.subscription_id;
            let cause = match &evaluation.destination {
                Subscriber::WorkProcess(process) => ChainCause::process(name, process),
                Subscriber::SendPort(_) | Subscriber::SendGroup(_) => {
                    ChainCause::subscription(name)
                }
            };
            pickup
                .reaches(name, &evaluation.destination)
                .into_iter()
                .map(move |to| {
                    let mut journey =
                        Journey::matched(JourneyId::new(ids.next_u128()), cause.clone())
                            .holding(held);
                    if let Subscriber::SendPort(port) = &to {
                        journey.send_port = Some(port.clone());
                    }
                    Opened {
                        journey,
                        subscription: name.clone(),
                        to,
                    }
                })
        })
        .collect()
}

/// Publication's write, through `publisher`: `message`'s record, a Journey
/// for every Subscription `routing` matched and every Send Port it reaches
/// ([`opened`]), those of them
/// `pickup` says a Subscription holds, the rest each in the queue of where
/// it leads, to be sent — claimed by this node where it sends it
/// ([`SendStep::line_up`]) — each with what `body` says is kept beside it,
/// and the audit record of the Publication, as one write, all or nothing,
/// answered before its sync and durable once its [`Durable`] says
/// (`XmipStorage::publish`). Nothing is sent here: the receive cycle ends
/// once this write is durable, and the acknowledgement; once it is, the
/// caller tells `pickup` ([`Pickup::published`]). No Journey where nothing matched: the
/// Message is kept with its entry in the node's Dead Message Queue — its
/// receive context, `unmatched`, every Subscription's decline and `body` —
/// in the same write (`runtime-model.md` section 9).
///
/// # Errors
///
/// In words, where Xmip Storage did not take it: the receive cycle has
/// failed, nothing is held or kept, and the sender is not acknowledged.
pub fn publish(
    publisher: &Publisher<'_>,
    pickup: &Pickup,
    (location, received): (&str, (Received, Vec<Hold>)),
    message: &Message,
    routing: &Routing,
    unmatched: &Unmatched<'_>,
    body: impl FnOnce() -> Vec<u8>,
) -> Result<Published, String> {
    let held = JourneyMessageRef {
        message_id: message.message_id(),
        stream_id: message.sections()[0].stream.id(),
    };
    let (received, places) = received;
    let mut opened = opened(routing, pickup, held, publisher.ids);
    // Every Journey born from the Stream says where it came in and which
    // sequences its Stream holds a place in (`crate::sequence`).
    for one in &mut opened {
        one.journey = one.journey.clone().received_as(received.clone());
    }
    let promoted = publisher
        .gathering
        .promote(message)
        .map_err(|why| why.to_string())?;
    let send_places =
        crate::sequence::places(publisher.cluster, publisher.sends, &mut opened, &promoted)?;
    let journeys: Vec<Journey> = opened.iter().map(|o| o.journey.clone()).collect();
    let (holding, mut lined, dead) = if journeys.is_empty() {
        let now = publisher.clock.unix_timestamp_nanos();
        let at = (pickup.node(), location, now);
        let entry = dead_message::entry(at, held, routing, unmatched, body());
        (Holding::default(), LinedUp::default(), Some(entry))
    } else {
        let kept = body();
        let holding = pickup.holding(&opened, || kept.clone());
        let departing = holding.departing(&opened);
        let lined = (publisher.send).line_up(publisher.sends, &departing, &kept, publisher.ids);
        (holding, lined, None)
    };
    let held: Vec<Hold> = holding
        .holds()
        .iter()
        .chain(&lined.holds)
        .chain(if journeys.is_empty() {
            &[][..]
        } else {
            &places[..]
        })
        .chain(&send_places)
        .cloned()
        .collect();
    let record = super::message_record(message);
    let mut audit = audited(publisher, location, message, &journeys);
    // The Message spelled out in its audit record, and its Stream's bytes
    // kept beside it by the audit keeper (ADR-0070).
    audit.audited = Some(super::audited(message, &record.body));
    let publication = Publication {
        message: record,
        journeys: journeys.iter().map(super::journey_record).collect(),
        held,
        audit,
        dead,
        claims: lined.claims.clone(),
        lease_nanos: u64::try_from(publisher.send.lease().as_nanos()).unwrap_or(u64::MAX),
    };
    let (holds, durable) = publisher.storage.publish(&publication).map_err(|why| {
        // Nothing it claimed is claimed: the places admitted are free.
        publisher.send.withdrawn(&lined);
        format!(
            "Xmip Storage did not take the Publication of the Message {}: {why}",
            message.message_id()
        )
    })?;
    // Only what Xmip Storage says this node holds is sent from here: a
    // Publication asked again after a lost answer holds none another node
    // took up meanwhile.
    publisher.send.confirmed(&mut lined, &holds);
    Ok(Published {
        journeys,
        holding,
        lined,
        durable,
    })
}

/// The audit record of a Publication (`runtime-model.md` section 9: *every
/// Publication is audited*), in the audit capability's own form, written
/// to the runtime database where an audit record is first written
/// (ADR-0062, amendment 2026-10-01).
fn audited(
    publisher: &Publisher<'_>,
    location: &str,
    message: &Message,
    journeys: &[Journey],
) -> AuditEntry {
    let section = &message.sections()[0];
    let listed = |words: Vec<String>| words.join(",");
    let properties: BTreeMap<String, String> = [
        ("location", location.to_string()),
        ("message", message.message_id().to_string()),
        ("stream", section.stream.id().to_string()),
        ("length", section.stream.len().to_string()),
        (
            "disposition",
            if journeys.is_empty() {
                "dead-message-queue"
            } else {
                "routed"
            }
            .to_string(),
        ),
        (
            "journeys",
            listed(
                journeys
                    .iter()
                    .map(|j| j.journey_id().to_string())
                    .collect(),
            ),
        ),
        (
            "subscriptions",
            listed(
                journeys
                    .iter()
                    .filter_map(Journey::cause)
                    .map(|cause| cause.subscription_id.clone())
                    .collect(),
            ),
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value))
    .collect();
    let record = AuditRecord {
        audit_id: AuditId::new(publisher.ids.next_u128()),
        origin: publisher.origin.clone(),
        scope: None,
        action: "publish".to_string(),
        phase: ExecutionPhase::Finished,
        severity: Severity::Information,
        timestamp_unix_nanos: publisher.clock.unix_timestamp_nanos(),
        message: None,
        properties,
    };
    super::audit_entry(&record)
}
