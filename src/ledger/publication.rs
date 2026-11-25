//! Publication's one write into the Ledger (`runtime-model.md` sections 5
//! and 9): the Message record, a Journey for every Subscription routing
//! matched — one for each Send Port of a Send Port Group (section 10) —
//! what a paused Subscription holds, the rest in the queue of where
//! each leads with this node's claims, or — where nothing matched — the
//! Dead Message Queue entry, and the audit record, all or nothing.

use std::fmt::{self, Display};

use journey::{ChainCause, Journey, JourneyMessageRef, Received};
use message::Message;
use persist::storage::{AuditEntry, Durable, Hold, Publication, XmipStorage};
use route::{Promoted, Routing, Subscriber};
use xaudit::audit_record::{AuditRecord, Properties};
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
    /// Message of it: the Publication is answered before its sync.
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
    /// The cluster its sequences are named in (`crate::sequence`).
    pub cluster: &'a str,
}

/// A Journey a Publication opens: the Subscription that matched and where
/// the Message leads on it — a Send Port, a Work Process, or a Send Port Group
/// no Application of this node declares.
#[derive(Clone, Debug)]
pub struct Opened {
    pub journey: Journey,
    pub subscription: String,
    pub to: Subscriber,
    /// The Send Port Group it was opened through, where its Subscription
    /// routes to one (`crate::sequence::delivered`).
    pub group: Option<String>,
}

/// The Send Port Group a Journey of a Message routed to `destination` is
/// opened through, where it is one.
pub(crate) fn through(destination: &Subscriber) -> Option<String> {
    match destination {
        Subscriber::SendGroup(group) => Some(group.clone()),
        Subscriber::SendPort(_) | Subscriber::WorkProcess(_) => None,
    }
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
            let group = through(&evaluation.destination);
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
                        group: group.clone(),
                    }
                })
        })
        .collect()
}

/// Publication's write, through `publisher`: `message`'s record, a Journey
/// for every Subscription `routing` matched over `promoted`, what arrival
/// promoted of it — the places its Journeys take read from it too, so the
/// Message is promoted once — and every Send Port it reaches
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
    (message, promoted): (&Message, &Promoted),
    routing: &Routing,
    unmatched: &Unmatched<'_>,
    body: impl FnOnce() -> Vec<u8>,
) -> Result<Published, String> {
    let held = JourneyMessageRef {
        message_id: message.message_id(),
        stream_id: message.sections()[0].stream.id(),
    };
    let (received, places) = received;
    // Every Journey born from the Stream says where it came in and which
    // sequences its Stream holds a place in (`crate::sequence`).
    let mut opened: Vec<Opened> = opened(routing, pickup, held, publisher.ids)
        .into_iter()
        .map(|one| Opened {
            journey: one.journey.received_as(received.clone()),
            ..one
        })
        .collect();
    // The members of each delivery by a Send Port Group naming a
    // Correlation know their delivery (`crate::sequence::delivered`).
    crate::sequence::delivered(publisher.sends, &mut opened, publisher.ids);
    // A Stream holding sequences end to end has its Messages take no place
    // where they are bound yet: each takes its places once its Stream heads
    // its own, so destinations hold Streams in the order they are let
    // through (`crate::sequence::take_late`). One holding none takes them
    // now, in this write.
    let send_places = if received.sequences.is_empty() {
        crate::sequence::places(publisher.cluster, publisher.sends, &mut opened, promoted)?
    } else {
        Vec::new()
    };
    // What the write keeps at the end of each queue: what a Subscription
    // holds, each Message lined up with what is kept beside it, and the
    // Stream's places — moved in, never copied.
    let (holding, mut lined, mut waiting, dead) = if opened.is_empty() {
        let now = publisher.clock.unix_timestamp_nanos();
        let at = (pickup.node(), location, now);
        // A Replay opens its Journeys holding no place of the Stream's.
        let kept = crate::sequence::Kept::write(None, &body());
        let entry = dead_message::entry(at, held, routing, unmatched, kept);
        (
            Holding::default(),
            LinedUp::default(),
            Vec::new(),
            Some(entry),
        )
    } else {
        // Beside each, the Stream's places: what a step reads its queue by
        // (`crate::sequence::Kept`).
        let kept = crate::sequence::Kept::write(Some(&received), &body());
        let holding = pickup.holding(&opened, || kept.clone());
        let departing = holding.departing(&opened);
        let lined = (publisher.send).line_up(publisher.sends, &departing, publisher.ids);
        let mut waiting = holding.holds().to_vec();
        waiting.extend(lined.holds(kept));
        waiting.extend(places);
        (holding, lined, waiting, None)
    };
    waiting.extend(send_places);
    let record = super::message_record(message);
    let said = (publisher.ids, publisher.clock, publisher.origin);
    let mut audit = audited(said, location, message, &opened);
    // The Message spelled out in its audit record, and its Stream's bytes
    // kept beside it by the audit keeper (ADR-0070).
    audit.audited = Some(super::audited(message, &record.body));
    let publication = Publication {
        message: record,
        journeys: opened
            .iter()
            .map(|one| super::journey_record(&one.journey))
            .collect(),
        held: waiting,
        audit,
        dead,
        claims: lined.claims(),
        lease_nanos: u64::try_from(publisher.send.lease().as_nanos()).unwrap_or(u64::MAX),
    };
    let (holds, durable) = publisher.storage.publish(publication).map_err(|why| {
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
        journeys: opened.into_iter().map(|one| one.journey).collect(),
        holding,
        lined,
        durable,
    })
}

/// The audit record of a Publication (`runtime-model.md` section 9: *every
/// Publication is audited*), in the audit capability's own form, written
/// to the runtime database where an audit record is first written
/// (ADR-0062, amendment 2026-10-01): its identifier minted by `ids`, its
/// time `clock`'s, from `origin`, saying what the Publication of `message`
/// at `location` that `opened` its Journeys was ([`Said`]).
fn audited(
    (ids, clock, origin): (&dyn IdGenerator, &dyn Clock, &Origin),
    location: &str,
    message: &Message,
    opened: &[Opened],
) -> AuditEntry {
    let record = AuditRecord {
        audit_id: AuditId::new(ids.next_u128()),
        origin: origin.clone(),
        scope: None,
        action: "publish".to_string(),
        phase: ExecutionPhase::Finished,
        severity: Severity::Information,
        timestamp_unix_nanos: clock.unix_timestamp_nanos(),
        message: None,
        properties: Said {
            location,
            message,
            opened,
        },
    };
    super::audit_entry(record)
}

/// What a Publication's audit record says of it beside its own fields:
/// whether it was routed or kept in the Dead Message Queue, the Journeys
/// it opened, its first Stream's length, where it came in, its Message,
/// that Stream, and the Subscriptions its Journeys are for — typed, in
/// their names' order, each written where the record is, never made a
/// string first (`xaudit::audit_record::Properties`; 2026-11-14).
struct Said<'a> {
    location: &'a str,
    message: &'a Message,
    opened: &'a [Opened],
}

impl<'a> Properties for Said<'a> {
    fn each(&self, said: &mut dyn FnMut(&str, &dyn Display)) {
        let stream = &self.message.sections()[0].stream;
        let disposition = if self.opened.is_empty() {
            "dead-message-queue"
        } else {
            "routed"
        };
        said("disposition", &disposition);
        let journey = |one: &'a Opened| Some(one.journey.journey_id());
        said("journeys", &Listed(self.opened, journey));
        said("length", &stream.len());
        said("location", &self.location);
        said("message", &self.message.message_id());
        said("stream", &stream.id());
        let subscription = |one: &'a Opened| {
            let cause = one.journey.cause();
            cause.map(|cause| cause.subscription_id.as_str())
        };
        said("subscriptions", &Listed(self.opened, subscription));
    }
}

/// What its reading says of each Journey opened, where it says anything,
/// one after another, a comma between.
struct Listed<'a, F>(&'a [Opened], F);

impl<'a, T: Display, F: Fn(&'a Opened) -> Option<T>> Display for Listed<'a, F> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, value) in self.0.iter().filter_map(&self.1).enumerate() {
            if at > 0 {
                out.write_str(",")?;
            }
            write!(out, "{value}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::MessageContext;
    use message::{MessageSection, MessageTreatment};
    use stream::Stream;
    use xcore::{MessageId, SectionId, StreamId};

    struct At(i128);

    impl Clock for At {
        fn unix_timestamp_nanos(&self) -> i128 {
            self.0
        }
    }

    struct Minted(u128);

    impl IdGenerator for Minted {
        fn next_u128(&self) -> u128 {
            self.0
        }
    }

    /// A Journey opened by `cause`'s Subscription, to the Send Port
    /// `Billing`.
    fn opened(id: u128, cause: ChainCause) -> Opened {
        Opened {
            subscription: cause.subscription_id.clone(),
            journey: Journey::matched(JourneyId::new(id), cause),
            to: Subscriber::SendPort("Billing".to_string()),
            group: None,
        }
    }

    /// The test cluster's first node, where the Publication is made: a name
    /// is configuration (ADR-0056, amendment 2026-10-03).
    fn here() -> String {
        configure::fixture::test_cluster().node_scope(0)
    }

    /// The body of the audit record of a Publication of an eight-byte
    /// Message at `Orders` that opened `journeys`, made at [`here`].
    fn body(journeys: &[Opened]) -> String {
        let origin = Origin {
            program: "xmip-service".to_string(),
            host: "edge-01".to_string(),
            process: 42,
            location: Some(here()),
        };
        let section = MessageSection {
            section_id: SectionId::new(6),
            name: None,
            stream: Stream::new(StreamId::new(9), b"<Order/>".to_vec(), None),
            contract: None,
        };
        let message = Message::received(
            MessageId::new(5),
            vec![section],
            MessageContext::new(),
            MessageTreatment::default(),
        );
        let said = (
            &Minted(3) as &dyn IdGenerator,
            &At(1_790_000_000_123_456_789) as &dyn Clock,
            &origin,
        );
        let entry = audited(said, "Orders", &message, journeys);
        String::from_utf8(entry.body).expect("TOML")
    }

    /// The bytes a Publication's audit record is written in, held: its
    /// canonical form is what its audit chain digests (ADR-0070 clause 5),
    /// so every chain already written still verifies however the record is
    /// made.
    #[test]
    fn a_publication_s_audit_record_is_written_as_it_always_has_been() {
        let journeys = [
            opened(7, ChainCause::subscription("billing")),
            opened(8, ChainCause::process("audit", "Approval")),
        ];
        assert_eq!(body(&journeys), ROUTED.replace(HERE, &here()));
        assert_eq!(body(&[]), UNMATCHED.replace(HERE, &here()));
    }

    /// Where the held records say [`here`].
    const HERE: &str = "{here}";

    /// Captured from the record as it was built through a map of formatted
    /// properties until 2026-11-14, made at [`HERE`].
    const ROUTED: &str = r#"[[record]]
audit_id = "00000000-0000-0000-0000-000000000003"
at = "2026-09-21T14:13:20.123456789Z"
program = "xmip-service"
host = "edge-01"
process = "42"
location = "{here}"
action = "publish"
phase = "Finished"
severity = "Information"
[record.properties]
"disposition" = "routed"
"journeys" = "00000000-0000-0000-0000-000000000007,00000000-0000-0000-0000-000000000008"
"length" = "8"
"location" = "Orders"
"message" = "00000000-0000-0000-0000-000000000005"
"stream" = "00000000-0000-0000-0000-000000000009"
"subscriptions" = "billing,audit"

"#;

    /// As [`ROUTED`], of a Publication that opened none.
    const UNMATCHED: &str = r#"[[record]]
audit_id = "00000000-0000-0000-0000-000000000003"
at = "2026-09-21T14:13:20.123456789Z"
program = "xmip-service"
host = "edge-01"
process = "42"
location = "{here}"
action = "publish"
phase = "Finished"
severity = "Information"
[record.properties]
"disposition" = "dead-message-queue"
"journeys" = ""
"length" = "8"
"location" = "Orders"
"message" = "00000000-0000-0000-0000-000000000005"
"stream" = "00000000-0000-0000-0000-000000000009"
"subscriptions" = ""

"#;
}
