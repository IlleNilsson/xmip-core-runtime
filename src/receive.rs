//! Arrival: a Stream comes in, a Message is made, a Journey opens over it.
//!
//! Arrived from the platform repository's `src/vertical_slice.rs` on
//! 2026-08-26. That version made its own identifiers with `Uuid::now_v7()`
//! inline; this one takes an [`IdGenerator`], so a test can produce a run it can
//! assert on and the runtime still gets UUIDv7 by default.
//!
//! Assignment and Transformation are the two things that end a Message
//! generation. Assignment changes metadata and keeps the Stream; Transformation
//! produces a new Stream. Neither edits anything — ADR-0013.

use xmip_core::{IdGenerator, JourneyId, MessageId, SectionId, StreamId};
use xmip_journey::{Journey, JourneyMessageRef};
use xmip_message::{
    ExecutionProfile, Message, MessageCreationSource, MessageDurability, MessagePriority,
    MessageSection, MessageTreatment,
};
use xmip_stream::Stream;

/// Something arriving from outside Xmip.
///
/// The transport that produced it is not recorded here. Routing reads promoted
/// context, and by this point how the bytes arrived is a fact for the audit
/// trail rather than an input to any decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Arrival {
    File { media_type: Option<String> },
    HttpRequest { media_type: Option<String> },
}

impl Arrival {
    #[must_use]
    pub fn media_type(&self) -> Option<&str> {
        match self {
            Self::File { media_type } | Self::HttpRequest { media_type } => media_type.as_deref(),
        }
    }
}

/// One Message and the Journey opened over it.
#[derive(Clone, Debug, PartialEq)]
pub struct ReceivedWork {
    pub journey: Journey,
    pub message: Message,
}

/// Take arriving bytes and open a Journey over them.
pub fn receive(
    ids: &dyn IdGenerator,
    arrival: &Arrival,
    bytes: impl Into<std::sync::Arc<[u8]>>,
    treatment: MessageTreatment,
) -> ReceivedWork {
    let stream_id = StreamId::new(ids.next_u128());
    let message_id = MessageId::new(ids.next_u128());

    let section = MessageSection {
        section_id: SectionId::new(ids.next_u128()),
        name: None,
        stream: Stream::new(stream_id, bytes, arrival.media_type().map(str::to_string)),
        contract: None,
    };

    let message = Message::received(
        message_id,
        vec![section],
        xmip_context::MessageContext::new(),
        treatment,
    );

    let journey = Journey::new(JourneyId::new(ids.next_u128())).holding(JourneyMessageRef {
        message_id,
        stream_id,
    });

    ReceivedWork { journey, message }
}

/// Metadata changed. The Stream did not.
pub fn apply_assignment(
    ids: &dyn IdGenerator,
    work: ReceivedWork,
    context: xmip_context::MessageContext,
) -> ReceivedWork {
    let assigned = work.message.assigned(MessageId::new(ids.next_u128()), context);
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

    fn arrived() -> ReceivedWork {
        receive(
            &Counter::default(),
            &Arrival::File {
                media_type: Some("application/xml".to_string()),
            },
            b"<order/>".to_vec(),
            business(),
        )
    }

    #[test]
    fn arrival_produces_one_message_the_journey_is_holding() {
        let work = arrived();

        assert_eq!(work.journey.messages.len(), 1);
        assert_eq!(work.journey.messages[0].message_id, work.message.message_id());
        assert_eq!(work.message.generation(), 0);
        assert_eq!(work.message.created_by(), MessageCreationSource::Receive);
    }

    #[test]
    fn assignment_keeps_the_stream_and_transformation_replaces_it() {
        let ids = Counter::default();
        let received = receive(
            &ids,
            &Arrival::HttpRequest { media_type: None },
            b"<order/>".to_vec(),
            business(),
        );
        let original_stream = received.message.sections()[0].stream.id();

        let assigned = apply_assignment(&ids, received, xmip_context::MessageContext::new());
        assert_eq!(assigned.message.sections()[0].stream.id(), original_stream);

        let transformed =
            apply_transformation(&ids, assigned, b"<Order/>".to_vec(), None);
        assert_ne!(
            transformed.message.sections()[0].stream.id(),
            original_stream
        );

        assert_eq!(transformed.message.generation(), 2);
        assert_eq!(transformed.journey.messages.len(), 3);
    }

    #[test]
    fn the_journey_is_active_and_does_not_follow_anything() {
        let work = arrived();

        assert!(!work.journey.state.is_terminal());
        assert!(work.journey.previous_journey_id.is_none());
    }

    #[test]
    fn the_arriving_media_type_reaches_the_stream() {
        let work = arrived();

        assert_eq!(
            work.message.sections()[0].stream.media_type(),
            Some("application/xml")
        );
    }

    #[test]
    fn treatment_is_a_declaration_not_a_measurement() {
        let ids = Counter::default();
        let tiny = receive(
            &ids,
            &Arrival::File { media_type: None },
            b"ok".to_vec(),
            conversation(),
        );
        let large = receive(
            &ids,
            &Arrival::File { media_type: None },
            vec![0_u8; 4096],
            pass_through(),
        );

        assert_eq!(tiny.message.treatment().priority, MessagePriority::Immediate);
        assert_eq!(
            large.message.treatment().priority,
            MessagePriority::Background
        );
    }
}
