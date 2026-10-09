//! The Ledger's records of a Journey, a Message and an audit record, each
//! with the facts Xmip Storage keeps searchable beside its sealed body
//! (`persist::storage::JourneyFacts` and its siblings; proposed
//! 2026-10-09): made here, once, from the object the body is the
//! serialization of, so every write of one carries the same facts.

use context::property::PARTY;
use journey::Journey;
use message::Message;
use observe::Scope;
use persist::storage::{
    AuditEntry, AuditFacts, JourneyFacts, JourneyRecord, MessageFacts, MessageRecord,
};
use xaudit::audit_record::{AuditRecord, phase_word, severity_word};

/// A Journey as Xmip Storage keeps it: its form, its state, its tries and
/// its depth, the Send Port and the Work Process it is at, the Journey it
/// came from and the Message it holds last. Its times are Xmip Storage's.
pub(crate) fn journey_record(journey: &Journey) -> JourneyRecord {
    JourneyRecord {
        journey: journey.journey_id(),
        body: journey.record(),
        facts: JourneyFacts {
            state: journey.state.number(),
            attempts: journey.attempts.tries,
            depth: journey.depth(),
            send_port: journey.send_port.clone(),
            work_process: journey.current_work_process.clone(),
            previous_journey: journey.previous_journey_id().map(|id| id.value()),
            message: journey
                .messages()
                .last()
                .map(|held| held.message_id.value()),
            ..JourneyFacts::default()
        },
    }
}

/// A Message as Xmip Storage keeps it: its form, its generation, how it was
/// made, its length, the Message it came from, the Party its context says
/// it came from, and its first Section's contract and Stream.
pub(crate) fn message_record(message: &Message) -> MessageRecord {
    let first = message.sections().first();
    let party = message.context().get(PARTY).and_then(|value| value.text());
    MessageRecord {
        message: message.message_id(),
        body: message.record(),
        facts: MessageFacts {
            generation: message.generation(),
            created_by: message.created_by().number(),
            size_bytes: message
                .sections()
                .iter()
                .map(|section| section.stream.length())
                .sum(),
            previous_message: message.previous_message_id().map(|id| id.value()),
            party: party.map(|party| party.into_owned()),
            contract: first.and_then(|section| section.contract.clone()),
            stream: first.map(|section| section.stream.id().value()),
            ..MessageFacts::default()
        },
    }
}

/// An audit record as Xmip Storage keeps it: its form, and when it
/// happened, what, in which phase and how severe, whether it failed, the
/// program that wrote it, the cluster and the node it was written on, and
/// the artifact, Journey, Message and execution it is about.
pub(crate) fn audit_entry(record: &AuditRecord) -> AuditEntry {
    let scope = record.scope.as_ref();
    let location = record.origin.location.as_deref().map(Scope::new);
    AuditEntry {
        id: record.audit_id,
        body: record.toml().into_bytes(),
        facts: AuditFacts {
            occurred_unix_nanos: u64::try_from(record.timestamp_unix_nanos.max(0))
                .unwrap_or(u64::MAX),
            action: record.action.clone(),
            phase: phase_word(record.phase).to_string(),
            severity: severity_word(record.severity).to_string(),
            failed: record.is_failure(),
            program: record.origin.program.clone(),
            artifact_kind: scope.map(|scope| scope.artifact.artifact_type.to_string()),
            cluster: location
                .as_ref()
                .and_then(|scope| scope.segments().next())
                .map(str::to_string),
            node: location
                .as_ref()
                .and_then(|scope| scope.node())
                .map(str::to_string),
            artifact: scope.map(|scope| scope.artifact.name.clone()),
            journey: scope.map(|scope| scope.journey_id.value()),
            message: scope.map(|scope| scope.message_id.value()),
            execution: scope.map(|scope| scope.execution_id.value()),
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
        assert_eq!(facts.state, JourneyState::Failed.number());
        assert_eq!((facts.attempts, facts.depth), (3, 1));
        assert_eq!(facts.send_port.as_deref(), Some("Billing"));
        assert_eq!((facts.previous_journey, facts.message), (Some(1), Some(7)));
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
        assert_eq!(facts.created_by, message.created_by().number());
    }

    #[test]
    fn an_audit_record_s_facts_are_its_own_and_its_node_its_location_s() {
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
            message: None,
            properties: std::collections::BTreeMap::new(),
        };
        let facts = audit_entry(&record).facts;
        assert!(facts.failed);
        assert_eq!(
            (facts.phase.as_str(), facts.occurred_unix_nanos),
            ("failure", 42)
        );
        let node = cluster.nodes[0].name.clone();
        assert_eq!(facts.node, Some(node));
        assert_eq!(facts.journey, None, "a program's own act");
    }
}
