//! What a Message generation is, and the three treatments an artifact declares.
//!
//! Arrived from the platform repository's `src/vertical_slice.rs` on
//! 2026-08-26. Its own arrival path went on 2026-08-27, superseded by
//! [`crate::arrival`], which consumes the real `ReceivedStream` from
//! `xmip-core-receive` rather than raw bytes.
//!
//! Assignment and Transformation are the two things that end a Message
//! generation. Assignment changes metadata and keeps the Stream; Transformation
//! produces a new Stream. Neither edits anything — ADR-0013.

use xmip_core::{IdGenerator, MessageId, SectionId, StreamId};
use xmip_journey::{Journey, JourneyMessageRef};
use xmip_message::{
    ExecutionProfile, Message, MessageCreationSource, MessageDurability, MessagePriority,
    MessageSection, MessageTreatment,
};
use xmip_stream::Stream;

/// One Message and the Journey opened over it.
#[derive(Clone, Debug, PartialEq)]
pub struct ReceivedWork {
    pub journey: Journey,
    pub message: Message,
}

/// Metadata changed. The Stream did not.
pub fn apply_assignment(
    ids: &dyn IdGenerator,
    work: ReceivedWork,
    context: xmip_context::MessageContext,
) -> ReceivedWork {
    let assigned = work
        .message
        .assigned(MessageId::new(ids.next_u128()), context);
    let stream_id = assigned.sections()[0].stream.id();

    ReceivedWork {
        journey: work.journey.holding(JourneyMessageRef {
            message_id: assigned.message_id(),
            stream_id,
        }),
        message: assigned,
    }
}

/// Content changed, so there is a new Stream and a new generation.
pub fn apply_transformation(
    ids: &dyn IdGenerator,
    work: ReceivedWork,
    bytes: impl Into<std::sync::Arc<[u8]>>,
    media_type: Option<String>,
) -> ReceivedWork {
    let stream_id = StreamId::new(ids.next_u128());
    let message_id = MessageId::new(ids.next_u128());

    let section = MessageSection {
        section_id: SectionId::new(ids.next_u128()),
        name: work.message.sections()[0].name.clone(),
        stream: Stream::new(stream_id, bytes, media_type),
        contract: None,
    };

    let transformed = work.message.transformed(
        message_id,
        vec![section],
        work.message.context().clone(),
        MessageCreationSource::Transformation,
    );

    ReceivedWork {
        journey: work.journey.holding(JourneyMessageRef {
            message_id,
            stream_id,
        }),
        message: transformed,
    }
}

/// A caller is waiting. Latency over history.
#[must_use]
pub const fn conversation() -> MessageTreatment {
    MessageTreatment {
        priority: MessagePriority::Immediate,
        execution_profile: ExecutionProfile::Conversation,
        durability: MessageDurability::Ephemeral,
    }
}

/// The default. Full history, full recovery.
#[must_use]
pub const fn business() -> MessageTreatment {
    MessageTreatment {
        priority: MessagePriority::Normal,
        execution_profile: ExecutionProfile::Business,
        durability: MessageDurability::Recoverable,
    }
}

/// Moved, not understood.
#[must_use]
pub const fn pass_through() -> MessageTreatment {
    MessageTreatment {
        priority: MessagePriority::Background,
        execution_profile: ExecutionProfile::PassThrough,
        durability: MessageDurability::Durable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use xmip_context::MessageContext;
    use xmip_core::JourneyId;

    /// Counts from one. Not UUIDv7, and deliberately so: a test that asserts on
    /// identifiers needs them to be the same on every run.
    ///
    /// `AtomicU64` rather than `AtomicU128`, which is not stable.
    #[derive(Default)]
    struct Counter(AtomicU64);

    impl IdGenerator for Counter {
        fn next_u128(&self) -> u128 {
            u128::from(self.0.fetch_add(1, Ordering::Relaxed) + 1)
        }
    }

    fn arrived(ids: &dyn IdGenerator, treatment: MessageTreatment) -> ReceivedWork {
        let stream_id = StreamId::new(ids.next_u128());
        let message_id = MessageId::new(ids.next_u128());

        let section = MessageSection {
            section_id: SectionId::new(ids.next_u128()),
            name: None,
            stream: Stream::new(
                stream_id,
                b"<order/>".to_vec(),
                Some("application/xml".to_string()),
            ),
            contract: None,
        };

        ReceivedWork {
            journey: Journey::new(JourneyId::new(ids.next_u128())).holding(JourneyMessageRef {
                message_id,
                stream_id,
            }),
            message: Message::received(message_id, vec![section], MessageContext::new(), treatment),
        }
    }

    #[test]
    fn assignment_keeps_the_stream_and_transformation_replaces_it() {
        let ids = Counter::default();
        let received = arrived(&ids, business());
        let original = received.message.sections()[0].stream.id();

        let assigned = apply_assignment(&ids, received, MessageContext::new());
        assert_eq!(assigned.message.sections()[0].stream.id(), original);

        let transformed = apply_transformation(&ids, assigned, b"<Order/>".to_vec(), None);
        assert_ne!(transformed.message.sections()[0].stream.id(), original);

        assert_eq!(transformed.message.generation(), 2);
        assert_eq!(transformed.journey.messages.len(), 3);
    }

    #[test]
    fn an_assignment_is_recorded_as_an_assignment() {
        let ids = Counter::default();
        let assigned = apply_assignment(&ids, arrived(&ids, business()), MessageContext::new());

        assert_eq!(
            assigned.message.created_by(),
            MessageCreationSource::Assignment
        );
    }

    #[test]
    fn treatment_is_a_declaration_not_a_measurement() {
        // A two-kilobyte order and a two-gigabyte export can both be Immediate.
        let ids = Counter::default();

        assert_eq!(
            arrived(&ids, conversation()).message.treatment().priority,
            MessagePriority::Immediate
        );
        assert_eq!(
            arrived(&ids, pass_through()).message.treatment().priority,
            MessagePriority::Background
        );
    }

    #[test]
    fn the_three_treatments_differ_in_what_survives_a_restart() {
        assert_eq!(conversation().durability, MessageDurability::Ephemeral);
        assert_eq!(business().durability, MessageDurability::Recoverable);
        assert_eq!(pass_through().durability, MessageDurability::Durable);
    }
}
