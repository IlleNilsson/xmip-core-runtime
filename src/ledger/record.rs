//! The Ledger's records of a Journey, a Message and an audit record, each
//! with every single value of it laid out beside its sealed body, in the
//! clear (`persist::storage::JourneyFacts` and its siblings; proposed
//! 2026-10-09): made here, once, from the object the body is the
//! serialization of, so every write of one carries the same values. A list
//! — a Journey's entries and Message references, a Message's Sections and
//! context, an audit record's properties — is in the body alone.

use context::property::PARTY;
use journey::Journey;
use message::Message;
use observe::Scope;
use persist::storage::{
    AuditEntry, AuditFacts, Audited, JourneyFacts, JourneyRecord, MessageFacts, MessageRecord,
};
use xaudit::audit_record::AuditRecord;
use xcore::StreamId;

/// A Journey as Xmip Storage keeps it: its form, and its state, the Journey
/// it came from and what caused it, its depth, the Work Process it is in,
/// its Send Port, the Send Location it is at and its tries there, and the
/// Message it holds last. Its times are Xmip Storage's.
pub(crate) fn journey_record(journey: &Journey) -> JourneyRecord {
    let cause = journey.cause();
    JourneyRecord {
        journey: journey.journey_id(),
        body: journey.record(),
        facts: JourneyFacts {
            state: journey.state.word().to_string(),
            previous_journey: journey.previous_journey_id().map(|id| id.value()),
            subscription: cause.map(|cause| cause.subscription_id.clone()),
            cause_work_process: cause.and_then(|cause| cause.work_process.clone()),
            depth: journey.depth(),
            work_process: journey.current_work_process.clone(),
            send_port: journey.send_port.clone(),
            send_location: journey.attempts.location,
            attempts: journey.attempts.tries,
            message: journey
                .messages()
                .last()
                .map(|held| held.message_id.value()),
            ..JourneyFacts::default()
        },
    }
}

/// A Message as Xmip Storage keeps it: its form, the Message it came from,
/// its generation, how it was made and its treatment, and — read from its
/// Sections and its context — its length, the Party its context says it
/// came from, and its first Section's contract and Stream.
pub(crate) fn message_record(message: &Message) -> MessageRecord {
    let first = message.sections().first();
    let party = message.context().get(PARTY).and_then(|value| value.text());
    let treatment = message.treatment();
    MessageRecord {
        message: message.message_id(),
        body: message.record(),
        facts: MessageFacts {
            previous_message: message.previous_message_id().map(|id| id.value()),
            generation: message.generation(),
            created_by: message.created_by().word().to_string(),
            priority: treatment.priority.word().to_string(),
            execution_profile: treatment.execution_profile.word().to_string(),
            durability: treatment.durability.word().to_string(),
            size_bytes: message
                .sections()
                .iter()
                .map(|section| section.stream.length())
                .sum(),
            party: party.map(|party| party.into_owned()),
            contract: first.and_then(|section| section.contract.clone()),
            stream: first.map(|section| section.stream.id().value()),
            ..MessageFacts::default()
        },
    }
}

/// What an audit record of an act on `message` carries of it (ADR-0070):
/// the Message in full, `body` — its one binary form, as the Ledger keeps
/// it — and every Stream its Sections are over, in their order, each once,
/// whose bytes the audit keeper keeps beside the audit record.
pub(crate) fn audited(message: &Message, body: &[u8]) -> Audited {
    let mut streams: Vec<StreamId> = Vec::new();
    for section in message.sections() {
        let stream = section.stream.id();
        if !streams.contains(&stream) {
            streams.push(stream);
        }
    }
    Audited {
        message: body.to_vec(),
        streams,
    }
}

/// An audit record as Xmip Storage keeps it: its form, and when it
/// happened, what, in which phase and how severe, whether it failed, what
/// it says, its origin — and the cluster and the node by name, as its
/// location says them, by the one rule (`observe::Scope`) the audit reader
/// reads them by — and the execution it belongs to: its Journey, its
/// Message and its artifact, spelled out.
pub(crate) fn audit_entry(record: &AuditRecord) -> AuditEntry {
    let scope = record.scope.as_ref();
    let artifact = scope.map(|scope| &scope.artifact);
    let origin = &record.origin;
    let location = origin.location.as_deref().map(Scope::new);
    AuditEntry {
        id: record.audit_id,
        body: record.toml().into_bytes(),
        audited: None,
        facts: AuditFacts {
            occurred_unix_nanos: u64::try_from(record.timestamp_unix_nanos.max(0))
                .unwrap_or(u64::MAX),
            action: record.action.clone(),
            phase: record.phase.word().to_string(),
            severity: record.severity.word().to_string(),
            failed: record.is_failure(),
            text: record.message.clone(),
            program: origin.program.clone(),
            host: origin.host.clone(),
            process: origin.process,
            location: origin.location.clone(),
            hidden: origin.hidden,
            execution: scope.map(|scope| scope.execution_id.value()),
            journey: scope.map(|scope| scope.journey_id.value()),
            message: scope.map(|scope| scope.message_id.value()),
            artifact_kind: artifact.map(|artifact| artifact.artifact_type.to_string()),
            artifact_name: artifact.map(|artifact| artifact.name.clone()),
            artifact_version: artifact.and_then(|artifact| artifact.version.clone()),
            node: location
                .as_ref()
                .and_then(|scope| scope.node())
                .map(str::to_string),
            cluster: location
                .as_ref()
                .and_then(|scope| scope.segments().next())
                .map(str::to_string),
            ..AuditFacts::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::MessageContext;
    use journey::{ChainCause, ChainLimit, JourneyMessageRef, JourneyState};
    use message::{MessageSection, MessageTreatment};
    use stream::Stream;
    use xaudit::origin::Origin;
    use xcore::{
        AuditId, ExecutionPhase, JourneyId, MessageId, ScalarValue, SectionId, Severity, StreamId,
    };

    #[test]
    fn a_journey_s_facts_are_its_own() {
        let first = Journey::new(JourneyId::new(1));
        let mut journey = Journey::following(
            JourneyId::new(2),
            &first,
            ChainCause::subscription("billing"),
            ChainLimit::DEFAULT,
        )
        .expect("within the limit")
        .holding(JourneyMessageRef {
            message_id: MessageId::new(7),
            stream_id: StreamId::new(9),
        });
        journey.state = JourneyState::Failed;
        journey.send_port = Some("Billing".to_string());
        journey.attempts.tries = 3;
        let facts = journey_record(&journey).facts;
        assert_eq!(facts.state, "Failed");
        assert_eq!((facts.attempts, facts.depth), (3, 1));
        assert_eq!(facts.send_port.as_deref(), Some("Billing"));
        assert_eq!((facts.previous_journey, facts.message), (Some(1), Some(7)));
        assert_eq!(facts.subscription.as_deref(), Some("billing"));
    }

    #[test]
    fn a_message_s_facts_are_its_own_and_its_party_its_context_s() {
        let section = MessageSection {
            section_id: SectionId::new(1),
            name: None,
            stream: Stream::new(StreamId::new(9), b"<Order/>".to_vec(), None),
            contract: Some("Order".to_string()),
        };
        let context =
            MessageContext::new().with_value(PARTY, ScalarValue::Text("Contoso".to_string()));
        let message = Message::received(
            MessageId::new(5),
            vec![section],
            context,
            MessageTreatment::default(),
        );
        let facts = message_record(&message).facts;
        assert_eq!(facts.party.as_deref(), Some("Contoso"));
        assert_eq!(facts.contract.as_deref(), Some("Order"));
        assert_eq!((facts.size_bytes, facts.stream), (8, Some(9)));
        assert_eq!(facts.created_by, "Receive");
    }

    #[test]
    fn an_audit_record_s_values_are_its_own_its_origin_s_among_them() {
        let cluster = configure::fixture::test_cluster();
        let mut origin = Origin::here("xmip-service");
        origin.location = Some(cluster.node_scope(0));
        let record = AuditRecord {
            audit_id: AuditId::new(3),
            origin,
            scope: None,
            action: "publish".to_string(),
            phase: ExecutionPhase::Failure,
            severity: Severity::Error,
            timestamp_unix_nanos: 42,
            message: Some("refused".to_string()),
            properties: std::collections::BTreeMap::new(),
        };
        let facts = audit_entry(&record).facts;
        assert!(facts.failed);
        assert_eq!(
            (facts.phase.as_str(), facts.occurred_unix_nanos),
            ("Failure", 42)
        );
        assert_eq!(facts.location, Some(cluster.node_scope(0)));
        assert_eq!(facts.text.as_deref(), Some("refused"));
        assert_eq!(facts.program, "xmip-service");
        let node = &cluster.nodes[0].name;
        assert_eq!(
            facts.node.as_ref(),
            Some(node),
            "by name, from its location"
        );
        assert_eq!(facts.cluster.as_deref(), Some(cluster.name.as_str()));
        assert_eq!(facts.journey, None, "a program's own act");
    }

    #[test]
    fn an_audit_of_a_message_of_two_sections_keeps_both_streams_each_verified() {
        use persist::storage::ChunkReader;
        use std::io::Read;
        let storage = crate::ledger::in_memory();
        let contents = [b"<Order/>".repeat(900), b"<Invoice/>".repeat(700)];
        let mut sections = Vec::new();
        for (at, content) in (0..).zip(&contents) {
            let id = StreamId::new(70 + at);
            let mut bytes = content.as_slice();
            let kept = crate::ledger::write_stream(storage.as_ref(), id, &mut bytes, 1024)
                .expect("written");
            sections.push(MessageSection {
                section_id: SectionId::new(at + 1),
                name: None,
                stream: kept.stream(storage, None),
                contract: None,
            });
        }
        // A third Section over the first Stream: it is copied once.
        let shared = sections[0].stream.clone();
        sections.push(MessageSection {
            section_id: SectionId::new(3),
            name: None,
            stream: shared,
            contract: None,
        });
        let message = Message::received(
            MessageId::new(71),
            sections,
            MessageContext::new(),
            MessageTreatment::default(),
        );
        let record = AuditRecord {
            audit_id: AuditId::new(72),
            origin: Origin::here("xmip-service"),
            scope: None,
            action: "publish".to_string(),
            phase: ExecutionPhase::Finished,
            severity: Severity::Information,
            timestamp_unix_nanos: 42,
            message: None,
            properties: std::collections::BTreeMap::new(),
        };
        let mut entry = audit_entry(&record);
        entry.audited = Some(audited(&message, &message.record()));
        storage.write_audit(&entry).expect("written");
        storage.keep_audit(10).expect("kept");
        let kept = storage
            .read_kept_audit(entry.id)
            .expect("read")
            .expect("kept");

        let carried = kept.audited.as_ref().expect("carried");
        assert_eq!(carried.message, message.record(), "the Message in full");
        assert_eq!(carried.streams, [StreamId::new(70), StreamId::new(71)]);
        let carrying = persist::storage::Query {
            ask: persist::storage::Ask::AuditOfStream { stream: 70 },
            most: 10,
            newest_first: false,
        };
        let found = storage.query(&carrying).expect("asked");
        assert_eq!(found, [72], "the shared Stream once, found by its row");
        for (at, content) in (0..).zip(&contents) {
            let mut read = Vec::new();
            ChunkReader::audited(storage.as_ref(), kept.id, StreamId::new(70 + at))
                .expect("read")
                .expect("it carries the Stream")
                .read_to_end(&mut read)
                .expect("verified");
            assert!(read == *content, "Stream {at}");
        }
    }
}
