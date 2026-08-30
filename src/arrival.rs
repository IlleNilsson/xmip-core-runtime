//! The arrival path: what a Host Service does with a Stream that turns up.
//!
//! **Not an entity.** A Xmip Service, a Host Service and a Xmip Process each
//! have identity, lifecycle and configuration. This has none of them — nobody
//! authors one, nothing has one, and there is never more than one of it. It is
//! behaviour, and it lives here because the Host Service is what executes it.
//!
//! A Stream gets in three ways — something pushes it, Xmip is watching and it
//! appears, or a timer fires and Xmip goes and fetches it. All three are
//! arrivals, and the same gates run over all three. Only the first has a caller
//! to answer to, which is why `Arriving` travels with the Stream: an identity
//! with nobody to have passed it had better be inferred.
//!
//! ```text
//! ReceivedStream          bytes, how it got here, and whatever was observed
//!   -> identify           the claim read off the connection
//!   -> authenticate       against the Receive Location's closed set
//!   -> authorize          may this proven identity post here
//!   -> Message            created only once the transport gates have passed
//!   -> identify           again, over the Message this time
//!   -> authenticate       the message layer, against the same closed set
//!   -> authorize          alignment settled here, never by preferring a layer
//!   -> IdentityFacts      both layers recorded
//!   -> Journey            a Journey exists only now, not before
//!   -> Promoted           context read as text
//!   -> publish            every Subscription asked, declines kept
//!   -> Dispatch           routed, or unroutable and retained
//! ```
//!
//! Departure is the mirror half and lives in [`crate::departure`]. What both
//! halves are wired up with is in [`crate::engine`].
//!
//! Transformation is not here yet. What is here is the spine, and nothing in
//! it is a placeholder: every step is the module that owns it.

use xmip_authenticate::authenticate;
use xmip_authorize::{authorize, Action, Attempt};
use xmip_context::{IdentityFacts, MessageContext};
use xmip_core::{mechanism, Arriving, JourneyId, Layer, MessageId, SectionId};
use xmip_identify::{
    identify_message, identify_transport, IdentifyError, Presented, StreamArrival,
};
use xmip_journey::{Journey, JourneyMessageRef};
use xmip_message::{Message, MessageSection};
use xmip_receive::{ReceiveLocation, ReceivedStream};
use xmip_route::{publish, Dispatch, Promoted};


use crate::engine::Runtime;
use crate::generation::ReceivedWork;
use crate::outcome::{Arrived, Refused};

/// Drive one arrival from bytes to a dispatch.
///
/// ADR-0013's lifecycle, in its order, with nothing folded together:
///
/// ```text
/// Incoming Stream
///     -> Transport identification
///     -> Transport authentication
///     -> Transport authorization
///     -> Message creation
///     -> Default promotion
///     -> Optional message identification
///     -> Optional message authentication
///     -> Optional message authorization
///     -> Journey creation
/// ```
///
/// The break in the middle is the guarantee. Transport security is mandatory
/// and finishes before Message creation, so **Xmip never parses content from an
/// unauthorized sender** — and the type system carries that rather than the
/// comment, because the transport gate is handed an [`Arrival`] and only the
/// message gate is handed a [`Message`].
pub fn arrive(
    runtime: &Runtime<'_>,
    location: &ReceiveLocation,
    received: ReceivedStream,
) -> Arrived {
    let now = runtime.clock.unix_timestamp_nanos();

    // -- Transport identification ------------------------------------------
    //
    // Reading a claim off the connection belongs to a module rather than to
    // whatever transport happened to accept it.
    let arrival = StreamArrival::new(
        &received.stream,
        received.arriving,
        &received.source_uri,
        &received.transport_properties,
    );

    let claims = match identify_transport(runtime.transport_identifiers, &arrival) {
        Ok(claims) => claims,
        Err(IdentifyError { message }) => {
            return Arrived::Refused {
                reason: Refused::Identification(message),
            }
        }
    };

    // ADR-0019 clause 7. A partner drop folder is not an absence of identity,
    // and neither is a schedule: where nothing identified anything, the
    // circumstance *is* the transport identity and is authenticated as that —
    // inferred, weakly, and on the record.
    let presented = claims
        .into_iter()
        .next()
        .or_else(|| received.presented.clone())
        .unwrap_or_else(|| {
            Presented::inferred(mechanism::circumstance(), received.source_uri.clone())
                .with_evidence("source", received.source_uri.clone())
        });

    // -- Transport authentication ------------------------------------------
    let transport = match authenticate(
        &location.accept,
        runtime.authenticators,
        runtime.parties,
        &presented,
    ) {
        // The time travels with the identity. Everything downstream reads a
        // record of what was concluded now, and needs to know when now was.
        Ok(identity) => identity.at(now),
        Err(refusal) => {
            return Arrived::Refused {
                reason: Refused::Authentication(refusal),
            }
        }
    };

    // -- Transport authorization -------------------------------------------
    //
    // A Stream that authenticated is not yet anything: it still has to be
    // permitted to post here, and an unconfigured Receive Location permits
    // nothing. Alignment is vacuous while there is one layer, and is evaluated
    // again below once there may be two.
    let transport_facts =
        IdentityFacts::evaluate(location.identity_policy.alignment, transport, None);

    let permitted = authorize(
        runtime.policies,
        &transport_facts,
        &Attempt::new(Action::Receive, &location.name).at(now),
        location.identity_policy.on_misalignment,
    );

    if !permitted.allowed() {
        return Arrived::Refused {
            reason: Refused::Authorization(permitted),
        };
    }

    // -- Message creation and default promotion ----------------------------
    let message_id = MessageId::new(runtime.ids.next_u128());
    let section_id = SectionId::new(runtime.ids.next_u128());
    let stream_id = received.stream.id();

    let section = MessageSection {
        section_id,
        name: None,
        stream: received.stream,
        contract: None,
    };

    let message = Message::received(
        message_id,
        vec![section],
        promote_identity(&transport_facts, received.arriving),
        runtime.treatment,
    );

    // -- Message identification, authentication, authorization -------------
    //
    // *Optional* in the lifecycle means configuration decides whether there is
    // anything to read, not that the gate is skipped. With no message
    // identifiers configured the answer is "nothing was claimed", which is a
    // fact rather than an omission — and the degenerate case in ADR-0019
    // clause 7 then makes the transport identity authoritative for both
    // questions.
    let (facts, message) = match settle_message_identity(
        runtime,
        location,
        transport_facts,
        message,
        message_id,
        section_id,
        received.arriving,
        now,
    ) {
        Ok(settled) => settled,
        Err(reason) => return Arrived::Refused { reason },
    };

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

/// The second pass of the three gates, over the Message this time.
///
/// Returns the facts both layers produced and the Message carrying them. The
/// Message is rebuilt rather than mutated when a claim was found, under the
/// same identifiers: nothing has observed it yet, and ADR-0013 puts these gates
/// *inside* Message creation, so this is not a second generation. `generation()`
/// would be wrong if it said otherwise — a partner reading it would see an
/// edit that never happened.
fn settle_message_identity(
    runtime: &Runtime<'_>,
    location: &ReceiveLocation,
    transport_facts: IdentityFacts,
    message: Message,
    message_id: MessageId,
    section_id: SectionId,
    arriving: Arriving,
    now: i128,
) -> Result<(IdentityFacts, Message), Refused> {
    let claims = identify_message(runtime.message_identifiers, &message)
        .map_err(|failure| Refused::Identification(failure.message))?;

    let Some(claimed) = claims
        .into_iter()
        .find(|claim| claim.layer() == Layer::Message)
    else {
        return Ok((transport_facts, message));
    };

    // Authenticated against the same closed set. A location that never declared
    // the mechanism refuses it here exactly as it would at the transport, and
    // for the same clause-1 reason.
    let identity = authenticate(
        &location.accept,
        runtime.authenticators,
        runtime.parties,
        &claimed,
    )
    .map(|identity| identity.at(now))
    .map_err(Refused::Authentication)?;

    // Alignment becomes a real question only now. ADR-0019 clause 7 settles a
    // disagreement between the layers here, at authorization, and never by
    // quietly preferring one — a relayed integration where the VAN opened the
    // connection and the partner produced the content is the ordinary case, not
    // the attack.
    let facts = IdentityFacts::evaluate(
        location.identity_policy.alignment,
        transport_facts.transport.clone(),
        Some(identity),
    );

    let permitted = authorize(
        runtime.policies,
        &facts,
        &Attempt::new(Action::Receive, &location.name).at(now),
        location.identity_policy.on_misalignment,
    );

    if !permitted.allowed() {
        return Err(Refused::Authorization(permitted));
    }

    let section = MessageSection {
        section_id,
        name: message.sections()[0].name.clone(),
        stream: message.sections()[0].stream.clone(),
        contract: None,
    };

    let context = promote_identity(&facts, arriving);

    Ok((
        facts,
        Message::received(message_id, vec![section], context, runtime.treatment),
    ))
}

/// Put what the gates concluded where a Subscription can read it.
///
/// Routing reads the promoted set and nothing else, so an identity that stays
/// inside `IdentityFacts` cannot be routed on. These names are the contract
/// between the two, and they are prefixed so a Contract promoting `Party`
/// cannot collide with Xmip promoting one.
fn promote_identity(facts: &IdentityFacts, arriving: Arriving) -> MessageContext {
    use xmip_context::ContextValue;

    let mut context = MessageContext::new()
        .with_value("xmip.arriving", ContextValue::Text(arriving.to_string()))
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
        )
        .with_value(
            "xmip.transport.established",
            ContextValue::Text(facts.transport.established.to_string()),
        );

    // Promoted under its own names rather than overwriting the transport's. The
    // two layers are separate facts and a Subscription may route on either;
    // collapsing them would make "who sent it" unanswerable for exactly the
    // relayed integrations where the question matters.
    if let Some(message) = &facts.message {
        context = context
            .with_value(
                "xmip.message.mechanism",
                ContextValue::Text(message.mechanism.name().to_string()),
            )
            .with_value(
                "xmip.message.identity",
                ContextValue::Text(message.value.clone()),
            )
            .with_value(
                "xmip.message.class",
                ContextValue::Text(message.class().to_string()),
            )
            .with_value(
                "xmip.message.proven",
                ContextValue::Bool(message.mechanism.authenticates()),
            )
            .with_value(
                "xmip.message.established",
                ContextValue::Text(message.established.to_string()),
            );
    }

    context = context.with_value(
        "xmip.identity.misaligned",
        ContextValue::Bool(facts.alignment.is_misaligned()),
    );

    if let Some(party) = facts.accountable().party_id {
        context = context.with_value("xmip.party", ContextValue::Text(party.to_string()));
    }

    context
}

#[cfg(test)]
mod tests {
    use super::*;

    // The spine end to end, so the departure half is exercised from here rather
    // than in isolation: what a Message departs with is decided by what it
    // arrived with, and a test that stubbed the join would not catch the case
    // that matters.
    use crate::departure::{depart, Departed};
    use crate::engine::{PartyDirectory, Runtime, SendRegistry};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use xmip_authenticate::{Acceptance, AuthenticateError, Authenticator, PartyRegistry, Refusal};
    use xmip_authorize::{Authorizer, Decision};
    use xmip_context::Verified;
    use xmip_core::{
        Clock, CredentialRef, Departing, Established, IdGenerator, Mechanism, PartyId, Purpose,
        StreamId,
    };
    use xmip_identify::{MessageIdentifier, TransportIdentifier};
    use xmip_message::MessageTreatment;
    use xmip_party::{Identity, Party, PartyKind};
    use xmip_receive::ReceiveLocationType;
    use xmip_route::{Predicate, Subscriber, Subscription, Value};
    use xmip_send::{
        SendChain, SendError, SendLevel, SendLocation as Location, SendRequest, SendResult,
        SendTransport,
    };
    use xmip_stream::Stream;

    /// A clock that does not move. A test asserting on freshness needs the
    /// gap between two moments to be the one it chose.
    struct Fixed(i128);

    impl Clock for Fixed {
        fn unix_timestamp_nanos(&self) -> i128 {
            self.0
        }
    }

    const SECOND: i128 = 1_000_000_000;
    const NOW: i128 = 1_700_000_000 * SECOND;

    /// Allows anything on the connection. The estate's real policies are
    /// modules; this is the smallest thing that is not "nothing configured".
    struct Open;

    impl Authorizer for Open {
        fn name(&self) -> &str {
            "open"
        }

        fn layer(&self) -> Layer {
            Layer::Transport
        }

        fn decide(&self, _identity: &IdentityFacts, _attempt: &Attempt) -> Option<Decision> {
            Some(Decision::Allowed)
        }
    }

    #[derive(Default)]
    struct Counter(AtomicU64);

    impl IdGenerator for Counter {
        fn next_u128(&self) -> u128 {
            u128::from(self.0.fetch_add(1, Ordering::Relaxed) + 1)
        }
    }

    /// Reads a named transport property. The real ones are modules; this is the
    /// smallest thing that is genuinely the first gate rather than a transport
    /// having already decided.
    struct ReadsProperty(Mechanism, &'static str);

    impl TransportIdentifier for ReadsProperty {
        fn mechanism(&self) -> Mechanism {
            self.0.clone()
        }

        fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
            Ok(arrival
                .property(self.1)
                .map(|value| Presented::passed(self.0.clone(), value)))
        }
    }

    /// Reads ISA06 out of an X12 interchange. Names a Party and proves nothing,
    /// which is the point of running it as a separate gate.
    struct ReadsInterchange;

    impl MessageIdentifier for ReadsInterchange {
        fn mechanism(&self) -> Mechanism {
            mechanism::edi_x12_interchange()
        }

        fn identify(&self, message: &Message) -> Result<Option<Presented>, IdentifyError> {
            let bytes = message.sections()[0].stream.bytes();
            let text = core::str::from_utf8(bytes).map_err(|_| IdentifyError {
                message: "the interchange envelope is not text".to_string(),
            })?;

            Ok(text.split('*').nth(6).map(|value| {
                Presented::detected(mechanism::edi_x12_interchange(), format!("ISA06={value}"))
            }))
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

    /// Both halves over one list. Two traits because the gates may only have
    /// the narrow one; one implementation because a deployment has one set of
    /// Parties.
    struct Registry(Vec<Party>);

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, purpose: Purpose, value: &str) -> Option<PartyId> {
            self.0
                .iter()
                .find(|party| party.identity(mechanism, purpose) == Some(value))
                .map(|party| party.party_id)
        }
    }

    impl PartyDirectory for Registry {
        fn party(&self, party_id: PartyId) -> Option<Party> {
            self.0
                .iter()
                .find(|party| party.party_id == party_id)
                .cloned()
        }
    }

    /// One Send Port, configured to present Xmip's own identity.
    struct Sends;

    impl SendRegistry for Sends {
        fn location(&self, subscriber: &Subscriber) -> Option<(Location, SendChain)> {
            if subscriber.name() != "Billing" {
                return None;
            }

            Some((
                Location {
                    artifact_id: xmip_core::ArtifactId::new(10),
                    name: "Billing".to_string(),
                    uri: "sftp://billing.example/in".to_string(),
                    transport: "ssh-key".to_string(),
                    departing: Departing::Pushed,
                    present_as: None,
                },
                SendChain {
                    port: Some(PartyId::new(8)),
                    ..SendChain::default()
                },
            ))
        }
    }

    /// Records what it was asked to present, so a test can assert on identity
    /// rather than only on success.
    struct Recording {
        technology: &'static str,
        fail: Option<(bool, &'static str)>,
        presented: Mutex<Vec<String>>,
    }

    impl Recording {
        fn ok(technology: &'static str) -> Self {
            Self { technology, fail: None, presented: Mutex::new(Vec::new()) }
        }

        fn failing(technology: &'static str, retryable: bool, why: &'static str) -> Self {
            Self { technology, fail: Some((retryable, why)), presented: Mutex::new(Vec::new()) }
        }
    }

    impl SendTransport for Recording {
        fn technology(&self) -> &'static str {
            self.technology
        }

        fn send(&self, request: SendRequest<'_>) -> Result<SendResult, SendError> {
            self.presented.lock().unwrap().push(
                request
                    .present
                    .map_or_else(|| "(none)".to_string(), |identity| identity.value.clone()),
            );

            if let Some((retryable, message)) = self.fail {
                return Err(SendError { retryable, message: message.to_string() });
            }

            Ok(SendResult {
                response: None,
                status: "accepted".to_string(),
                properties: Vec::new(),
            })
        }
    }

    fn xmip_itself() -> Party {
        Party::new(PartyId::new(8), PartyKind::Service, "xmip").with(Identity::sending(
            mechanism::ssh_key(),
            "SHA256:xmip-outbound",
            CredentialRef::new("ssh-agent", "xmip"),
        ))
    }

    fn partner() -> Party {
        Party::new(PartyId::new(7), PartyKind::Organization, "partner-x").with(
            Identity::receiving(mechanism::mutual_tls(), "CN=partner-x.example"),
        )
    }

    fn registry() -> Registry {
        Registry(vec![partner(), xmip_itself()])
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
        .presenting(Presented::passed(
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
        sends: &'a Sends,
        transports: &'a [&'a dyn SendTransport],
        policies: &'a [&'a dyn Authorizer],
        clock: &'a dyn Clock,
    ) -> Runtime<'a> {
        Runtime {
            ids,
            authenticators,
            parties,
            directory: parties,
            subscriptions,
            treatment: MessageTreatment::default(),
            sends,
            transports,
            transport_identifiers: &[],
            message_identifiers: &[],
            policies,
            clock,
        }
    }



    #[test]
    fn a_file_arrives_and_reaches_a_send_port() {
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let subscriptions = subscribed_to_partner();
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock),
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
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let subscriptions = subscribed_to_partner();
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock),
            &location(),
            ReceivedStream::new(
                Stream::new(StreamId::new(101), b"{}".to_vec(), None),
                "https://xmip.example/in/partner-x",
            )
            .presenting(Presented::passed(mechanism::api_key(), "k-123")),
        );

        let Arrived::Refused {
            reason: Refused::Authentication(refusal),
        } = arrived
        else {
            panic!("expected an authentication refusal, got {arrived:?}");
        };

        assert_eq!(
            refusal,
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
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];

        let subscriptions = vec![Subscription::new(
            "invoices",
            Subscriber::SendPort("Invoices".to_string()),
            Predicate::equals("xmip.party", Value::Text(PartyId::new(99).to_string())),
        )];

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock),
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
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];
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
            &runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock),
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
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];

        let subscriptions = vec![Subscription::new(
            "high-assurance-only",
            Subscriber::Process("Approval".to_string()),
            Predicate::equals(
                "xmip.transport.class",
                Value::Text("highAssurance".to_string()),
            ),
        )];

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock),
            &location(),
            arriving(),
        );

        assert_eq!(
            arrived.routing().expect("published").dispatch(),
            Dispatch::Routed(1)
        );
    }

    #[test]
    fn a_routed_message_leaves_presenting_xmips_own_identity() {
        // The whole spine. A partner's certificate gets it in; Xmip's own SSH
        // key gets it out. ADR-0006: the send identity is resolved
        // independently, because the target only cares which identity Xmip
        // presents.
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let subscriptions = subscribed_to_partner();
        let sftp = Recording::ok("ssh-key");
        let posting: [&dyn SendTransport; 1] = [&sftp];

        let arrived = arrive(
            &runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock),
            &location(),
            arriving(),
        );

        let Arrived::Routed { work, facts, routing } = &arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        let departed = depart(
            &runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock),
            work,
            facts,
            routing,
        );

        assert_eq!(departed.len(), 1);
        assert!(departed[0].sent(), "got {:?}", departed[0]);

        // The Send Port declared it, not the Location and not the Message.
        let Departed::Sent { presented_from, .. } = &departed[0] else {
            unreachable!()
        };
        assert_eq!(*presented_from, Some(SendLevel::Port));

        // And the transport was handed Xmip's key rather than the partner's
        // certificate.
        assert_eq!(sftp.presented.lock().unwrap().as_slice(), ["SHA256:xmip-outbound"]);
    }

    #[test]
    fn a_destination_configuration_does_not_have_is_named() {
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];

        // Routing sends it to a Send Port that Sends knows nothing about.
        let subscriptions = vec![Subscription::new(
            "elsewhere",
            Subscriber::SendPort("Nowhere".to_string()),
            Predicate::everything(),
        )];

        let engine = runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock);
        let arrived = arrive(&engine, &location(), arriving());

        let Arrived::Routed { work, facts, routing } = &arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        let departed = depart(&engine, work, facts, routing);

        assert!(matches!(departed[0], Departed::NoSuchDestination { .. }));
    }

    #[test]
    fn the_transport_decides_whether_a_failure_is_worth_retrying() {
        // Not the runtime. Only the transport knows whether a refused
        // connection is a restart away from working.
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let subscriptions = subscribed_to_partner();
        let refusing = Recording::failing("ssh-key", true, "connection refused");
        let posting: [&dyn SendTransport; 1] = [&refusing];

        let engine = runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock);
        let arrived = arrive(&engine, &location(), arriving());

        let Arrived::Routed { work, facts, routing } = &arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        let departed = depart(&engine, work, facts, routing);

        let Departed::Failed { retryable, detail, .. } = &departed[0] else {
            panic!("expected a failure, got {:?}", departed[0]);
        };

        assert!(retryable);
        assert_eq!(detail, "connection refused");
    }

    #[test]
    fn a_technology_nothing_loaded_speaks_is_named_rather_than_guessed() {
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let subscriptions = subscribed_to_partner();

        // The Send Port wants ssh-key and only an HTTP transport is loaded.
        let http = Recording::ok("http");
        let posting: [&dyn SendTransport; 1] = [&http];

        let engine = runtime(&ids, &authenticators, &parties, &subscriptions, &Sends, &posting, &open, &clock);
        let arrived = arrive(&engine, &location(), arriving());

        let Arrived::Routed { work, facts, routing } = &arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        let departed = depart(&engine, work, facts, routing);

        let Departed::NoTransport { technology, .. } = &departed[0] else {
            panic!("expected no transport, got {:?}", departed[0]);
        };

        assert_eq!(technology, "ssh-key");
    }

    #[test]
    fn the_first_gate_is_called_and_the_transport_does_not_decide() {
        // The claim comes from an identifier reading the connection, not from a
        // transport handing over a conclusion. `ReceivedStream::presented` is
        // left empty here on purpose: if identification were still folded into
        // the transport there would be nothing to authenticate.
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let subscriptions = subscribed_to_partner();
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];

        let reads = ReadsProperty(mechanism::mutual_tls(), "tls.client.subject");
        let identifiers: [&dyn TransportIdentifier; 1] = [&reads];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &Sends,
            &posting,
            &open,
            &clock,
        );
        engine.transport_identifiers = &identifiers;

        let arrived = arrive(
            &engine,
            &location(),
            ReceivedStream::new(
                Stream::new(StreamId::new(103), b"<order/>".to_vec(), None),
                "https://xmip.example/in/partner-x",
            )
            .with_property("tls.client.subject", "CN=partner-x.example"),
        );

        let Arrived::Routed { facts, .. } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        assert_eq!(facts.transport.value, "CN=partner-x.example");
        assert_eq!(facts.accountable().party_id, Some(PartyId::new(7)));
    }

    #[test]
    fn the_message_gate_runs_after_the_message_exists_and_records_both_layers() {
        // ADR-0013's lifecycle end to end. The connection is a VAN's
        // certificate; the content names the partner in ISA06. Neither
        // substitutes for the other and both are on the record.
        let ids = Counter::default();
        let tls = Always(mechanism::mutual_tls(), Verified::Proven);

        // Claimed, not Proven. X12 carries no cryptography and the record has
        // to say so — this is the classic B2B mistake, refused at the type.
        let isa = Always(mechanism::edi_x12_interchange(), Verified::Claimed);
        let authenticators: [&dyn Authenticator; 2] = [&tls, &isa];

        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];
        let subscriptions = vec![Subscription::new(
            "edi",
            Subscriber::SendPort("Billing".to_string()),
            Predicate::equals(
                "xmip.message.mechanism",
                Value::Text("edi-x12-interchange".to_string()),
            ),
        )];

        let envelope = ReadsInterchange;
        let identifiers: [&dyn MessageIdentifier; 1] = [&envelope];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &Sends,
            &posting,
            &open,
            &clock,
        );
        engine.message_identifiers = &identifiers;

        let van = ReceiveLocation::new(
            xmip_core::ArtifactId::new(3),
            "van",
            "https://xmip.example/in/van",
            "https",
            ReceiveLocationType::DataTransfer,
        )
        .accepting(
            Acceptance::closed()
                .accepting(&mechanism::mutual_tls())
                .accepting(&mechanism::edi_x12_interchange()),
        );

        let arrived = arrive(
            &engine,
            &van,
            ReceivedStream::new(
                Stream::new(
                    StreamId::new(104),
                    b"ISA*00*          *00*          *ZZ*PARTNERX".to_vec(),
                    None,
                ),
                "https://xmip.example/in/van",
            )
            .presenting(Presented::passed(mechanism::mutual_tls(), "CN=van.example")),
        );

        let Arrived::Routed { facts, work, .. } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        // Both layers, neither collapsed into the other.
        assert_eq!(facts.transport.value, "CN=van.example");

        let message = facts.message.as_ref().expect("the envelope named someone");
        assert_eq!(message.value, "ISA06=PARTNERX");
        assert_eq!(message.verified, Verified::Claimed);

        // Still one Message. These gates run inside Message creation, so
        // reading the envelope is not an edit and does not open a generation.
        assert_eq!(work.message.generation(), 0);
    }

    #[test]
    fn a_message_identity_the_location_never_declared_is_refused() {
        // Clause 1 applies at both layers. A location that takes mutual-tls and
        // says nothing about X12 does not quietly accept an ISA06 because it
        // happens to be readable.
        let ids = Counter::default();
        let tls = Always(mechanism::mutual_tls(), Verified::Proven);
        let isa = Always(mechanism::edi_x12_interchange(), Verified::Claimed);
        let authenticators: [&dyn Authenticator; 2] = [&tls, &isa];

        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];
        let subscriptions = subscribed_to_partner();

        let envelope = ReadsInterchange;
        let identifiers: [&dyn MessageIdentifier; 1] = [&envelope];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &Sends,
            &posting,
            &open,
            &clock,
        );
        engine.message_identifiers = &identifiers;

        let arrived = arrive(
            &engine,
            &location(),
            ReceivedStream::new(
                Stream::new(
                    StreamId::new(105),
                    b"ISA*00*          *00*          *ZZ*PARTNERX".to_vec(),
                    None,
                ),
                "https://xmip.example/in/partner-x",
            )
            .presenting(Presented::passed(
                mechanism::mutual_tls(),
                "CN=partner-x.example",
            )),
        );

        let Arrived::Refused {
            reason: Refused::Authentication(refusal),
        } = arrived
        else {
            panic!("expected an authentication refusal, got {arrived:?}");
        };

        assert_eq!(
            refusal,
            Refusal::MechanismNotDeclared {
                presented: "edi-x12-interchange".to_string()
            }
        );
    }

    #[test]
    fn a_scheduled_pickup_has_no_caller_and_its_identity_is_inferred() {
        // A timer fires, Xmip logs into the partner's SFTP with its own key and
        // brings back a file. Nobody presented anything — Xmip was the client —
        // so the only identity available is the one the configuration implies.
        //
        // The gates still run. ADR-0019 clause 7: this is not an absence of
        // identity, it is an inferred one, and the record says which.
        let ids = Counter::default();
        let circumstance = Always(mechanism::circumstance(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&circumstance];
        let parties = Registry(Vec::new());
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];
        let subscriptions = vec![Subscription::new(
            "nightly",
            Subscriber::SendPort("Archive".to_string()),
            Predicate::equals("xmip.arriving", Value::Text("scheduled".to_string())),
        )];

        let nightly = ReceiveLocation::new(
            xmip_core::ArtifactId::new(4),
            "partner-y-nightly",
            "sftp://partner-y.example/out",
            "sftp",
            ReceiveLocationType::BatchLoad,
        )
        .accepting(Acceptance::closed().accepting(&mechanism::circumstance()));

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &Sends,
                &posting,
                &open,
                &clock,
            ),
            &nightly,
            ReceivedStream::new(
                Stream::new(StreamId::new(106), b"<orders/>".to_vec(), None),
                "sftp://partner-y.example/out/orders-2026-08-27.xml",
            )
            .scheduled(),
        );

        let Arrived::Routed { facts, .. } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        // Inferred, not passed. Nothing was presented and nothing pretends
        // otherwise.
        assert_eq!(facts.transport.established, Established::Inferred);
        assert_eq!(facts.transport.mechanism.name(), "circumstance");

        // And how it got here is routable, because "the nightly pickup" and
        // "partner-y posted something" are different events that a Subscription
        // has to be able to tell apart.
        assert_eq!(
            facts.transport.value,
            "sftp://partner-y.example/out/orders-2026-08-27.xml"
        );
    }

    #[test]
    fn how_it_arrived_and_how_the_identity_was_established_are_separate_facts() {
        // A pushed Stream with a detected identity: the partner posts an X12
        // interchange and the only name anywhere is inside the envelope. If
        // these were one fact, this case would have to be misfiled as one or
        // the other.
        let ids = Counter::default();
        let tls = Always(mechanism::mutual_tls(), Verified::Proven);
        let isa = Always(mechanism::edi_x12_interchange(), Verified::Claimed);
        let authenticators: [&dyn Authenticator; 2] = [&tls, &isa];

        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let posting: [&dyn SendTransport; 1] = [&Recording::ok("ssh-key")];
        let subscriptions = vec![Subscription::new(
            "pushed-edi",
            Subscriber::SendPort("Billing".to_string()),
            Predicate::equals("xmip.message.established", Value::Text("detected".to_string())),
        )];

        let envelope = ReadsInterchange;
        let identifiers: [&dyn MessageIdentifier; 1] = [&envelope];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &Sends,
            &posting,
            &open,
            &clock,
        );
        engine.message_identifiers = &identifiers;

        let van = ReceiveLocation::new(
            xmip_core::ArtifactId::new(5),
            "van",
            "https://xmip.example/in/van",
            "https",
            ReceiveLocationType::DataTransfer,
        )
        .accepting(
            Acceptance::closed()
                .accepting(&mechanism::mutual_tls())
                .accepting(&mechanism::edi_x12_interchange()),
        );

        let arrived = arrive(
            &engine,
            &van,
            ReceivedStream::new(
                Stream::new(
                    StreamId::new(107),
                    b"ISA*00*          *00*          *ZZ*PARTNERX".to_vec(),
                    None,
                ),
                "https://xmip.example/in/van",
            )
            .presenting(Presented::passed(mechanism::mutual_tls(), "CN=van.example")),
        );

        let Arrived::Routed { facts, routing, .. } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        // Pushed connection, passed transport identity, detected message
        // identity. Three separate facts, none inferable from the others.
        assert_eq!(facts.transport.established, Established::Passed);
        assert_eq!(
            facts.message.as_ref().expect("the envelope named someone").established,
            Established::Detected
        );
        assert_eq!(routing.dispatch(), Dispatch::Routed(1));
    }
}
