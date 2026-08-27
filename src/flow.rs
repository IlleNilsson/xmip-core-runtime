//! Arrival to dispatch. The first path through Xmip that calls the modules in
//! order rather than describing what order they would be called in.
//!
//! ```text
//! ReceivedStream          bytes, and whatever credential the transport saw
//!   -> authenticate       against the Receive Location's closed set
//!   -> IdentityFacts      both layers recorded, alignment evaluated
//!   -> Message + Journey  a Journey exists only now, not before
//!   -> Promoted           context read as text
//!   -> publish            every Subscription asked, declines kept
//!   -> Dispatch           routed, or unroutable and retained
//! ```
//!
//! Transformation and sending are not here yet. What is here is the spine:
//! nothing in it is a placeholder, and every step is the module that owns it.

use xmip_authenticate::{authenticate, Authenticator, PartyRegistry, Presented, Refusal};
use xmip_context::{IdentityFacts, MessageContext};
use xmip_core::{IdGenerator, JourneyId, MessageId, SectionId};
use xmip_journey::{Journey, JourneyMessageRef};
use xmip_message::{Message, MessageSection, MessageTreatment};
use xmip_party::mechanism;
use xmip_receive::{ReceiveLocation, ReceivedStream};
use xmip_route::{publish, Dispatch, Promoted, Routing, Subscription};

use crate::receive::ReceivedWork;

/// What became of one arrival.
#[derive(Clone, Debug)]
pub enum Arrived {
    /// Refused at the gate.
    ///
    /// **No Journey exists.** ADR-0013: a Journey exists only after Validation,
    /// so there is nothing to suspend, resume or dismiss. The refusal is the
    /// whole record.
    Refused { reason: Refusal },

    /// Authenticated, published, and at least one Subscription wanted it.
    Routed {
        work: ReceivedWork,
        facts: IdentityFacts,
        routing: Routing,
    },

    /// Authenticated, published, and nobody wanted it.
    ///
    /// A disposition rather than a failure: the Stream was valid, it passed its
    /// gates, and no Subscription matched. That is a statement about
    /// configuration, and `routing.declines()` says which Subscription passed
    /// and why. Kept under retention so the question can be answered later.
    Unroutable {
        work: ReceivedWork,
        facts: IdentityFacts,
        routing: Routing,
    },
}

impl Arrived {
    /// Whether Xmip must keep this because nothing took it.
    #[must_use]
    pub const fn retains(&self) -> bool {
        matches!(self, Self::Unroutable { .. })
    }

    #[must_use]
    pub const fn routing(&self) -> Option<&Routing> {
        match self {
            Self::Routed { routing, .. } | Self::Unroutable { routing, .. } => Some(routing),
            Self::Refused { .. } => None,
        }
    }
}

/// Everything the flow needs that is not the arrival itself.
pub struct Runtime<'a> {
    pub ids: &'a dyn IdGenerator,
    pub authenticators: &'a [&'a dyn Authenticator],
    pub parties: &'a dyn PartyRegistry,
    pub subscriptions: &'a [Subscription],
    pub treatment: MessageTreatment,
}

/// Drive one arrival from bytes to a dispatch.
pub fn arrive(runtime: &Runtime<'_>, location: &ReceiveLocation, received: ReceivedStream) -> Arrived {
    // ADR-0019 clause 7. A partner drop folder is not an absence of identity:
    // where the technology presents no credential, the circumstance *is* the
    // transport identity and is authenticated as that — weakly, and on the
    // record.
    let presented = received.presented.clone().unwrap_or_else(|| {
        Presented::new(mechanism::circumstance(), received.source_uri.clone())
            .with_evidence("source", received.source_uri.clone())
    });

    let transport = match authenticate(
        &location.accept,
        runtime.authenticators,
        runtime.parties,
        &presented,
    ) {
        Ok(identity) => identity,
        Err(reason) => return Arrived::Refused { reason },
    };

    // No message identity yet: reading one means parsing the payload, and that
    // is content handling rather than arrival. The degenerate case in ADR-0019
    // clause 7 applies — the transport identity is authoritative for both
    // questions and alignment is vacuously satisfied.
    let facts = IdentityFacts::evaluate(location.identity_policy.alignment, transport, None);

    let context = promote_identity(&facts);

    let message_id = MessageId::new(runtime.ids.next_u128());
    let stream_id = received.stream.id();

    let section = MessageSection {
        section_id: SectionId::new(runtime.ids.next_u128()),
        name: None,
        stream: received.stream,
        contract: None,
    };

    let message = Message::received(message_id, vec![section], context, runtime.treatment);

    // The Journey opens here and not before. Everything above could have
    // refused, and a refused arrival has no line of execution to record.
    let journey = Journey::new(JourneyId::new(runtime.ids.next_u128())).holding(JourneyMessageRef {
        message_id,
        stream_id,
    });

    let work = ReceivedWork { journey, message };
    let routing = publish(&Promoted::from_context(work.message.context()), runtime.subscriptions);

    match routing.dispatch() {
        Dispatch::Routed(_) => Arrived::Routed {
            work,
            facts,
            routing,
        },
        Dispatch::Unroutable => Arrived::Unroutable {
            work,
            facts,
            routing,
        },
    }
}

/// Put what the gates concluded where a Subscription can read it.
///
/// Routing reads the promoted set and nothing else, so an identity that stays
/// inside `IdentityFacts` cannot be routed on. These names are the contract
/// between the two, and they are prefixed so a Contract promoting `Party`
/// cannot collide with Xmip promoting one.
fn promote_identity(facts: &IdentityFacts) -> MessageContext {
    use xmip_context::ContextValue;

    let mut context = MessageContext::new()
        .with_value(
            "xmip.transport.mechanism",
            ContextValue::Text(facts.transport.mechanism.name().to_string()),
        )
        .with_value(
            "xmip.transport.identity",
            ContextValue::Text(facts.transport.value.clone()),
        )
        .with_value(
            "xmip.transport.class",
            ContextValue::Text(facts.transport.class().to_string()),
        )
        .with_value(
            "xmip.transport.proven",
            ContextValue::Bool(facts.transport.mechanism.authenticates()),
        );

    if let Some(party) = facts.accountable().party_id {
        context = context.with_value("xmip.party", ContextValue::Text(party.to_string()));
    }

    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use xmip_authenticate::{Acceptance, AuthenticateError};
    use xmip_context::Verified;
    use xmip_core::{PartyId, StreamId};
    use xmip_party::{Identity, Mechanism, Party, PartyKind, Purpose};
    use xmip_receive::ReceiveLocationType;
    use xmip_route::{Predicate, Subscriber, Value};
    use xmip_stream::Stream;

    #[derive(Default)]
    struct Counter(AtomicU64);

    impl IdGenerator for Counter {
        fn next_u128(&self) -> u128 {
            u128::from(self.0.fetch_add(1, Ordering::Relaxed) + 1)
        }
    }

    struct Always(Mechanism, Verified);

    impl Authenticator for Always {
        fn mechanism(&self) -> Mechanism {
            self.0.clone()
        }

        fn verify(&self, _presented: &Presented) -> Result<Verified, AuthenticateError> {
            Ok(self.1)
        }
    }

    struct Registry(Vec<Party>);

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, purpose: Purpose, value: &str) -> Option<Party> {
            self.0
                .iter()
                .find(|party| party.identity(mechanism, purpose) == Some(value))
                .cloned()
        }
    }

    fn partner() -> Registry {
        Registry(vec![Party::new(
            PartyId::new(7),
            PartyKind::Organization,
            "partner-x",
        )
        .with(Identity::receiving(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
        ))])
    }

    fn location() -> ReceiveLocation {
        ReceiveLocation::new(
            xmip_core::ArtifactId::new(1),
            "partner-x",
            "https://xmip.example/in/partner-x",
            "https",
            ReceiveLocationType::DataTransfer,
        )
        .accepting(Acceptance::closed().accepting(&mechanism::mutual_tls()))
    }

    fn arriving() -> ReceivedStream {
        ReceivedStream::new(
            Stream::new(StreamId::new(100), b"<order/>".to_vec(), None),
            "https://xmip.example/in/partner-x",
        )
        .presenting(Presented::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
        ))
    }

    fn subscribed_to_partner() -> Vec<Subscription> {
        vec![Subscription::new(
            "billing",
            Subscriber::SendPort("Billing".to_string()),
            Predicate::equals("xmip.party", Value::Text(PartyId::new(7).to_string())),
        )]
    }

    fn runtime<'a>(
        ids: &'a Counter,
        authenticators: &'a [&'a dyn Authenticator],
        parties: &'a Registry,
        subscriptions: &'a [Subscription],
    ) -> Runtime<'a> {
        Runtime {
            ids,
            authenticators,
            parties,
            subscriptions,
            treatment: MessageTreatment::default(),
        }
    }

    #[test]
    fn a_file_arrives_and_reaches_a_send_port() {
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = partner();
        let subscriptions = subscribed_to_partner();

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions),
            &location(),
            arriving(),
        );

        let Arrived::Routed { work, facts, routing } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        assert_eq!(facts.accountable().party_id, Some(PartyId::new(7)));
        assert_eq!(routing.dispatch(), Dispatch::Routed(1));
        assert_eq!(
            routing.destinations()[0].to_string(),
            "SendPort.Billing"
        );

        // One Message, one Journey, and the Journey is holding it.
        assert_eq!(work.message.generation(), 0);
        assert_eq!(work.journey.messages.len(), 1);
        assert_eq!(work.journey.messages[0].message_id, work.message.message_id());
    }

    #[test]
    fn a_refused_arrival_opens_no_journey() {
        // ADR-0013: a Journey exists only after Validation. There is nothing to
        // suspend, resume or dismiss, and the type says so.
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = partner();
        let subscriptions = subscribed_to_partner();

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions),
            &location(),
            ReceivedStream::new(
                Stream::new(StreamId::new(101), b"{}".to_vec(), None),
                "https://xmip.example/in/partner-x",
            )
            .presenting(Presented::new(mechanism::api_key(), "k-123")),
        );

        let Arrived::Refused { reason } = arrived else {
            panic!("expected a refusal, got {arrived:?}");
        };

        assert_eq!(
            reason,
            Refusal::MechanismNotDeclared {
                presented: "api-key".to_string()
            }
        );
    }

    #[test]
    fn nobody_wanting_it_keeps_it_and_says_why() {
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = partner();

        let subscriptions = vec![Subscription::new(
            "invoices",
            Subscriber::SendPort("Invoices".to_string()),
            Predicate::equals("xmip.party", Value::Text(PartyId::new(99).to_string())),
        )];

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions),
            &location(),
            arriving(),
        );

        assert!(arrived.retains());

        let declines = arrived.routing().expect("published").declines();

        assert_eq!(declines.len(), 1);
        assert_eq!(declines[0].0, "invoices");
        assert!(declines[0].1.contains("xmip.party is"), "got: {}", declines[0].1);
    }

    #[test]
    fn a_drop_folder_authenticates_on_its_circumstance() {
        // ADR-0019 clause 7. No transport credential is presented, and the
        // circumstance is the identity rather than the absence of one.
        let ids = Counter::default();
        let circumstance = Always(mechanism::circumstance(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&circumstance];
        let parties = Registry(Vec::new());
        let subscriptions = vec![Subscription::new(
            "archive",
            Subscriber::SendPort("Archive".to_string()),
            Predicate::everything(),
        )];

        let folder = ReceiveLocation::new(
            xmip_core::ArtifactId::new(2),
            "drop",
            "file:///in/partner-y",
            "file",
            ReceiveLocationType::BatchLoad,
        )
        .accepting(Acceptance::closed().accepting(&mechanism::circumstance()));

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions),
            &folder,
            ReceivedStream::new(
                Stream::new(StreamId::new(102), b"ISA*00*".to_vec(), None),
                "file:///in/partner-y/order-1.edi",
            ),
        );

        let Arrived::Routed { facts, .. } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        // Recognised by nothing, authenticated anyway, and routed. A Party is a
        // shortcut, not a permission.
        assert_eq!(facts.accountable().party_id, None);
        assert_eq!(facts.transport.mechanism.name(), "circumstance");
    }

    #[test]
    fn what_the_gate_concluded_is_routable() {
        // Routing reads the promoted set and nothing else, so an identity that
        // stayed inside IdentityFacts could not be routed on.
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = partner();

        let subscriptions = vec![Subscription::new(
            "high-assurance-only",
            Subscriber::Process("Approval".to_string()),
            Predicate::equals(
                "xmip.transport.class",
                Value::Text("highAssurance".to_string()),
            ),
        )];

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions),
            &location(),
            arriving(),
        );

        assert_eq!(
            arrived.routing().expect("published").dispatch(),
            Dispatch::Routed(1)
        );
    }
}
