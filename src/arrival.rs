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
//!   -> Ledger             the Stream written in chunks
//!   -> Message            created only once the transport gates have passed
//!   -> identify           again, over the Message this time
//!   -> authenticate       the message layer, against the same closed set
//!   -> authorize          alignment settled here, never by preferring a layer
//!   -> IdentityFacts      both layers recorded
//!   -> Promoted           the names the filters use, each compiled once
//!   -> Journey            a Journey exists only now, not before
//!   -> publish            every Subscription asked, declines kept
//!   -> Dispatch           routed, or unroutable: the Dead Message Queue
//! ```
//!
//! Departure is the mirror half and lives in [`crate::departure`]. What both
//! halves are wired up with is in [`crate::message_path`].
//!
//! Transformation is not here yet. What is here is the spine, and nothing in
//! it is a placeholder: every step is the module that owns it.

use authenticate::authenticate;
use authorize::{Action, Attempt, authorize};
use context::property::PARTY;
use context::{IdentityFacts, MessageContext};
use identify::{IdentifyError, Presented, StreamArrival, identify_message, identify_transport};
use journey::{Journey, JourneyMessageRef};
use message::{Message, MessageSection};
use receive::ReceivedStream;
use route::{Dispatch, Promoted, publish};
use xcore::{Arriving, JourneyId, Layer, MessageId, SectionId, StreamId, mechanism};

use crate::generation::ReceivedWork;
use crate::ledger::write_stream;
use crate::message_path::Runtime;
use crate::outcome::{Arrived, Refused};
use crate::receiving::ReceiveGate;

/// Drive one arrival from bytes to a dispatch.
///
/// ADR-0013's lifecycle, in its order, with nothing folded together:
///
/// ```text
/// Incoming Stream
///     -> Transport identification
///     -> Transport authentication
///     -> Transport authorization
///     -> The Stream into the Ledger, in chunks
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
pub fn arrive(runtime: &Runtime<'_>, gate: &ReceiveGate, mut received: ReceivedStream) -> Arrived {
    let now = runtime.clock.unix_timestamp_nanos();

    // -- Transport identification ------------------------------------------
    //
    // Reading a claim off the connection belongs to a module rather than to
    // whatever transport happened to accept it.
    let arrival = StreamArrival::new(
        received.arriving,
        &received.source_uri,
        &received.transport_properties,
    );

    let claims = match identify_transport(runtime.transport_identifiers, &arrival) {
        Ok(claims) => claims,
        Err(IdentifyError { message }) => {
            return Arrived::Refused {
                reason: Refused::Identification(message),
            };
        }
    };

    // ADR-0019 clause 7. A Party drop folder is not an absence of identity,
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
        &gate.accept,
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
            };
        }
    };

    // -- Transport authorization -------------------------------------------
    //
    // A Stream that authenticated is not yet anything: it still has to be
    // permitted to post here, and an unconfigured Receive Location permits
    // nothing. Alignment is vacuous while there is one layer, and is evaluated
    // again below once there may be two.
    let transport_facts = IdentityFacts::evaluate(gate.identity.alignment, transport, None);

    let permitted = authorize(
        runtime.policies,
        &transport_facts,
        &Attempt::new(Action::Receive, &gate.location).at(now),
        gate.identity.on_misalignment,
    );

    if !permitted.allowed() {
        return Arrived::Refused {
            reason: Refused::Authorization(permitted),
        };
    }

    // -- The Stream into the Ledger, in chunks -----------------------------
    //
    // Only now, as the far end streams it: a refusal above reads and keeps
    // nothing (`runtime-model.md` section 5). What follows holds it as kept.
    let stream_id = StreamId::new(runtime.ids.next_u128());
    let body = &mut received.body;
    let stream = match write_stream(runtime.storage.as_ref(), stream_id, body, runtime.chunk) {
        Ok(kept) => kept.stream(runtime.storage, None),
        Err(reason) => return Arrived::Failed { reason },
    };

    // -- Message creation and default promotion ----------------------------
    let message_id = MessageId::new(runtime.ids.next_u128());
    let section_id = SectionId::new(runtime.ids.next_u128());
    let section = MessageSection {
        section_id,
        name: None,
        stream,
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
        gate,
        transport_facts,
        message,
        received.arriving,
        now,
    ) {
        Ok(settled) => settled,
        Err(reason) => return Arrived::Refused { reason },
    };

    // Before the Journey, where ADR-0013 puts default promotion: a filter that
    // cannot be read refuses the Message rather than declining it.
    let promoted = match promoted(runtime, &message) {
        Ok(promoted) => promoted,
        Err(reason) => return Arrived::Refused { reason },
    };
    // A gate given nothing because the Ledger could not be read routes on nothing.
    if let Some(why) = message.sections()[0].stream.unread() {
        return Arrived::Failed {
            reason: why.to_string(),
        };
    }

    // The Journey opens here and not before. Everything above could have
    // refused, and a refused arrival has no line of execution to record.
    let journey =
        Journey::new(JourneyId::new(runtime.ids.next_u128())).holding(JourneyMessageRef {
            message_id,
            stream_id,
        });

    let work = ReceivedWork { journey, message };
    let routing = publish(&promoted, runtime.subscriptions);

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
            promoted,
        },
    }
}

/// What routing reads: every name the Subscriptions' filters use, compiled
/// once when the Runtime was built (`Runtime::gathering`) and read here
/// through the route technology its prefix names. A `Null` is absent and
/// bytes are refused, bare or prefixed (ADR-0046, amended 2026-09-24).
fn promoted(runtime: &Runtime<'_>, message: &Message) -> Result<Promoted, Refused> {
    runtime
        .gathering
        .promote(message)
        .map_err(Refused::Promotion)
}

/// The second pass of the three gates, over the Message this time.
///
/// Returns the facts both layers produced and the Message carrying them. The
/// Message is rebuilt rather than mutated when a claim was found, under the
/// same identifiers: nothing has observed it yet, and ADR-0013 puts these gates
/// *inside* Message creation, so this is not a second generation. `generation()`
/// would be wrong if it said otherwise — a Party reading it would see an
/// edit that never happened.
fn settle_message_identity(
    runtime: &Runtime<'_>,
    gate: &ReceiveGate,
    transport_facts: IdentityFacts,
    message: Message,
    arriving: Arriving,
    now: i128,
) -> Result<(IdentityFacts, Message), Refused> {
    // Rebuilt under the same identifiers, and those identifiers are on the
    // Message it was handed. Passing them separately was two chances for the
    // caller to hand over the wrong ones, and clippy counted eight arguments.
    let message_id = message.message_id();
    let section_id = message.sections()[0].section_id;

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
        &gate.accept,
        runtime.authenticators,
        runtime.parties,
        &claimed,
    )
    .map(|identity| identity.at(now))
    .map_err(Refused::Authentication)?;

    // Alignment becomes a real question only now. ADR-0019 clause 7 settles a
    // disagreement between the layers here, at authorization, and never by
    // quietly preferring one — a relayed integration where the VAN opened the
    // connection and the Party produced the content is the ordinary case, not
    // the attack.
    let facts = IdentityFacts::evaluate(
        gate.identity.alignment,
        transport_facts.transport.clone(),
        Some(identity),
    );

    let permitted = authorize(
        runtime.policies,
        &facts,
        &Attempt::new(Action::Receive, &gate.location).at(now),
        gate.identity.on_misalignment,
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
    use xcore::ScalarValue;

    let mut context = MessageContext::new()
        .with_value("xmip.arriving", ScalarValue::Text(arriving.to_string()))
        .with_value(
            "xmip.transport.mechanism",
            ScalarValue::Text(facts.transport.mechanism.name().to_string()),
        )
        .with_value(
            "xmip.transport.identity",
            ScalarValue::Text(facts.transport.value.clone()),
        )
        .with_value(
            "xmip.transport.class",
            ScalarValue::Text(facts.transport.class().to_string()),
        )
        .with_value(
            "xmip.transport.proven",
            ScalarValue::Bool(facts.transport.mechanism.authenticates()),
        )
        .with_value(
            "xmip.transport.established",
            ScalarValue::Text(facts.transport.established.to_string()),
        );

    // Promoted under its own names rather than overwriting the transport's. The
    // two layers are separate facts and a Subscription may route on either;
    // collapsing them would make "who sent it" unanswerable for exactly the
    // relayed integrations where the question matters.
    if let Some(message) = &facts.message {
        context = context
            .with_value(
                "xmip.message.mechanism",
                ScalarValue::Text(message.mechanism.name().to_string()),
            )
            .with_value(
                "xmip.message.identity",
                ScalarValue::Text(message.value.clone()),
            )
            .with_value(
                "xmip.message.class",
                ScalarValue::Text(message.class().to_string()),
            )
            .with_value(
                "xmip.message.proven",
                ScalarValue::Bool(message.mechanism.authenticates()),
            )
            .with_value(
                "xmip.message.established",
                ScalarValue::Text(message.established.to_string()),
            );
    }

    context = context.with_value(
        "xmip.identity.misaligned",
        ScalarValue::Bool(facts.alignment.is_misaligned()),
    );

    if let Some(party) = facts.accountable().party_id {
        context = context.with_value(PARTY, ScalarValue::Text(party.to_string()));
    }

    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Always, Open};

    // The spine end to end, so the departure half is exercised from here rather
    // than in isolation: what a Message departs with is decided by what it
    // arrived with, and a test that stubbed the join would not catch the case
    // that matters.
    use crate::departure::{Departed, depart};
    use crate::message_path::{Parties, Runtime};
    use crate::receiving::ReceiveGate;
    use crate::sending::{Sending, Sends};
    use authenticate::{Acceptance, Authenticator, Refusal};
    use authorize::Authorizer;
    use context::Verified;
    use identify::{MessageIdentifier, TransportIdentifier};
    use message::MessageTreatment;
    use party::{Identity, Party, PartyKind};
    use path::expression::Expression;
    use route::{Gathering, Subscriber, Subscription};
    use send::{SendChain, SendLevel};
    use std::sync::atomic::{AtomicU64, Ordering};
    use transport::{Arrived as Delivered, Directions, Transport, TransportError};
    use xcore::{Clock, CredentialRef, Established, IdGenerator, Mechanism, PartyId};

    fn filter(text: &str) -> Expression {
        Expression::parse(text).expect("compiles")
    }

    /// `name = 'text'`, the filter most of these tests route on.
    fn equals(name: &str, text: &str) -> Expression {
        filter(&format!("{name} = '{text}'"))
    }

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

        fn identify(
            &self,
            arrival: &StreamArrival<'_>,
        ) -> Result<Option<Presented>, IdentifyError> {
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

    /// A transport that sends, or fails as told: the smallest thing that is
    /// a Send Location's transport rather than the runtime deciding.
    struct Recording {
        fail: Option<(bool, &'static str)>,
    }

    impl Recording {
        const fn ok() -> Self {
            Self { fail: None }
        }

        const fn failing(retryable: bool, why: &'static str) -> Self {
            Self {
                fail: Some((retryable, why)),
            }
        }
    }

    impl Transport for Recording {
        fn name(&self) -> &'static str {
            "recording"
        }

        fn directions(&self) -> Directions {
            Directions::SEND
        }

        fn receive(&self) -> transport::Result<Vec<Delivered>> {
            Ok(Vec::new())
        }

        fn arrivals(&self) -> transport::Arrivals {
            transport::Arrivals::Unordered("it receives nothing")
        }

        fn send(&self, _target: &str, _bytes: &[u8]) -> transport::Result<()> {
            match self.fail {
                Some((retryable, message)) => Err(TransportError {
                    message: message.to_string(),
                    retryable,
                }),
                None => Ok(()),
            }
        }
    }

    /// One Send Port, Billing, whose Port declares Xmip's own identity.
    fn sends(transport: Recording) -> Sends {
        let configured = configure::ConfiguredLocation {
            name: "Billing".to_string(),
            start: true,
            transport: "recording".to_string(),
            address: "sftp://billing.example/in".to_string(),
            credentials: None,
            contract: None,
            settings: configure::LocationSettings::default(),
            contract_settings: configure::LocationSettings::default(),
            accept: configure::Accept::default(),
        };
        Sends {
            locations: vec![Sending {
                configured,
                chain: SendChain {
                    port: Some(PartyId::new(8)),
                    ..SendChain::default()
                },
                transport: Box::new(transport),
            }],
            groups: Vec::new(),
        }
    }

    fn xmip_itself() -> Party {
        Party::new(PartyId::new(8), PartyKind::Service, "xmip").with(Identity::sending(
            mechanism::ssh_key(),
            "SHA256:xmip-outbound",
            CredentialRef::new("ssh-agent", "xmip"),
        ))
    }

    fn party_x() -> Party {
        Party::new(PartyId::new(7), PartyKind::Organization, "party-x").with(Identity::receiving(
            mechanism::mutual_tls(),
            "CN=party-x.example",
        ))
    }

    fn arriving() -> ReceivedStream {
        ReceivedStream::new(&b"<order/>"[..], "https://xmip.example/in/party-x").presenting(
            Presented::passed(mechanism::mutual_tls(), "CN=party-x.example"),
        )
    }

    fn subscribed_to_party_x() -> Vec<Subscription> {
        vec![Subscription::new(
            "billing",
            Subscriber::SendPort("Billing".to_string()),
            equals("xmip.party", &PartyId::new(7).to_string()),
        )]
    }

    fn registry() -> Parties {
        Parties(vec![party_x(), xmip_itself()])
    }

    fn location() -> ReceiveGate {
        ReceiveGate::new(
            "party-x",
            Acceptance::closed().accepting(&mechanism::mutual_tls()),
        )
    }

    fn runtime<'a>(
        ids: &'a Counter,
        authenticators: &'a [&'a dyn Authenticator],
        parties: &'a Parties,
        subscriptions: &'a [Subscription],
        sends: &'a Sends,
        policies: &'a [&'a dyn Authorizer],
        clock: &'a dyn Clock,
    ) -> Runtime<'a> {
        Runtime {
            ids,
            authenticators,
            parties,
            directory: parties,
            subscriptions,
            // Leaked: a test's Runtime borrows it for the test's length.
            gathering: Box::leak(Box::new(Gathering::of(&[], subscriptions))),
            treatment: MessageTreatment::default(),
            sends,
            transport_identifiers: &[],
            message_identifiers: &[],
            policies,
            clock,
            storage: crate::ledger::in_memory(),
            chunk: crate::ledger::CHUNK,
            origin: Box::leak(Box::new(xaudit::origin::Origin::here("arrival"))),
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
        let subscriptions = subscribed_to_party_x();
        let sends = sends(Recording::ok());

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
            &location(),
            arriving(),
        );

        let Arrived::Routed {
            work,
            facts,
            routing,
        } = arrived
        else {
            panic!("expected a route, got {arrived:?}");
        };

        assert_eq!(facts.accountable().party_id, Some(PartyId::new(7)));
        assert_eq!(routing.dispatch(), Dispatch::Routed(1));
        assert_eq!(routing.destinations()[0].to_string(), "SendPort.Billing");

        // One Message, one Journey, and the Journey is holding it.
        assert_eq!(work.message.generation(), 0);
        assert_eq!(work.journey.messages().len(), 1);
        assert_eq!(
            work.journey.messages()[0].message_id,
            work.message.message_id()
        );
    }

    /// ADR-0064: the Subscription is drawn in an Xmip Application, the node
    /// binds the Application, and what the tree takes from the binding is
    /// what routing asks.
    #[test]
    fn a_bound_applications_subscription_routes_a_message() {
        let cluster = configure::fixture::test_cluster();
        let node = format!(
            r#"[service]
name = "xmip"
cluster_name = "{cluster}"
node_name = "{node}"

[[applications]]
name = "Orders"

[[xmip_applications]]
name = "Orders"

[[xmip_applications.receive_ports]]
name = "Orders"

[[xmip_applications.receive_locations]]
name = "party-x"
receive_port = "Orders"
interaction = "data-transfer"
depth = "context"

[[xmip_applications.send_ports]]
name = "Billing"

[[xmip_applications.subscriptions]]
id = "billing"
destination = {{ send-port = "Billing" }}
filter = "xmip.party = '{party}'"
"#,
            cluster = cluster.name,
            node = cluster.node(0).name,
            party = PartyId::new(7)
        );
        let document = configure::parse_toml(&node).expect("the node reads");
        let orders = configure::binding::section(&document, "Orders")
            .expect("held")
            .application()
            .expect("the Application reads");
        let (tree, _) = crate::execution_tree::build_execution_tree(
            document,
            &[orders],
            &configure::Declarations::new(),
        )
        .expect("the node binds it");

        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let sends = sends(Recording::ok());

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &tree.subscriptions,
                &sends,
                &open,
                &clock,
            ),
            &location(),
            arriving(),
        );

        let routing = arrived.routing().expect("published");
        assert_eq!(routing.dispatch(), Dispatch::Routed(1));
        assert_eq!(routing.destinations()[0].to_string(), "SendPort.Billing");
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
        let subscriptions = subscribed_to_party_x();
        let sends = sends(Recording::ok());

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
            &location(),
            ReceivedStream::new(&b"{}"[..], "https://xmip.example/in/party-x")
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
        let sends = sends(Recording::ok());

        let subscriptions = vec![Subscription::new(
            "invoices",
            Subscriber::SendPort("Invoices".to_string()),
            equals("xmip.party", &PartyId::new(99).to_string()),
        )];

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
            &location(),
            arriving(),
        );

        assert!(arrived.retains());

        let declines = arrived.routing().expect("published").declines();

        assert_eq!(declines.len(), 1);
        assert_eq!(declines[0].0, "invoices");
        assert!(
            declines[0].1.contains("xmip.party is"),
            "got: {}",
            declines[0].1
        );
    }

    #[test]
    fn a_drop_folder_authenticates_on_its_circumstance() {
        // ADR-0019 clause 7. No transport credential is presented, and the
        // circumstance is the identity rather than the absence of one.
        let ids = Counter::default();
        let circumstance = Always(mechanism::circumstance(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&circumstance];
        let parties = Parties::default();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let sends = sends(Recording::ok());
        let subscriptions = vec![Subscription::new(
            "archive",
            Subscriber::SendPort("Archive".to_string()),
            Expression::everything(),
        )];

        let folder = ReceiveGate::new(
            "drop",
            Acceptance::closed().accepting(&mechanism::circumstance()),
        );

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
            &folder,
            ReceivedStream::new(&b"ISA*00*"[..], "file:///in/party-y/order-1.edi"),
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
        let sends = sends(Recording::ok());

        let subscriptions = vec![Subscription::new(
            "high-assurance-only",
            Subscriber::Process("Approval".to_string()),
            equals("xmip.transport.class", "highAssurance"),
        )];

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
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
        // The whole spine. A Party's certificate gets it in; Xmip's own SSH
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
        let subscriptions = subscribed_to_party_x();
        let sends = sends(Recording::ok());

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
            &location(),
            arriving(),
        );

        let Arrived::Routed {
            work,
            facts,
            routing,
        } = &arrived
        else {
            panic!("expected a route, got {arrived:?}");
        };

        let departed = depart(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
            work,
            facts,
            routing,
        );

        assert_eq!(departed.len(), 1);
        assert!(departed[0].sent(), "got {:?}", departed[0]);

        // The Send Port declared it, not the Location and not the Message.
        let Departed::Sent {
            presented_from,
            presented,
            ..
        } = &departed[0]
        else {
            unreachable!()
        };
        assert_eq!(*presented_from, Some(SendLevel::Port));

        // And the chain resolved Xmip's key rather than the Party's
        // certificate.
        assert_eq!(presented.as_deref(), Some("SHA256:xmip-outbound"));
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
        let sends = sends(Recording::ok());

        // Routing sends it to a Send Port that Sends knows nothing about.
        let subscriptions = vec![Subscription::new(
            "elsewhere",
            Subscriber::SendPort("Nowhere".to_string()),
            Expression::everything(),
        )];

        let engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &sends,
            &open,
            &clock,
        );
        let arrived = arrive(&engine, &location(), arriving());

        let Arrived::Routed {
            work,
            facts,
            routing,
        } = &arrived
        else {
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
        let subscriptions = subscribed_to_party_x();
        let sends = sends(Recording::failing(true, "connection refused"));

        let engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &sends,
            &open,
            &clock,
        );
        let arrived = arrive(&engine, &location(), arriving());

        let Arrived::Routed {
            work,
            facts,
            routing,
        } = &arrived
        else {
            panic!("expected a route, got {arrived:?}");
        };

        let departed = depart(&engine, work, facts, routing);

        let Departed::Failed {
            retryable, detail, ..
        } = &departed[0]
        else {
            panic!("expected a failure, got {:?}", departed[0]);
        };

        assert!(retryable);
        assert_eq!(detail, "connection refused");
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
        let subscriptions = subscribed_to_party_x();
        let sends = sends(Recording::ok());

        let reads = ReadsProperty(mechanism::mutual_tls(), "tls.client.subject");
        let identifiers: [&dyn TransportIdentifier; 1] = [&reads];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &sends,
            &open,
            &clock,
        );
        engine.transport_identifiers = &identifiers;

        let arrived = arrive(
            &engine,
            &location(),
            ReceivedStream::new(&b"<order/>"[..], "https://xmip.example/in/party-x")
                .with_property("tls.client.subject", "CN=party-x.example"),
        );

        let Arrived::Routed { facts, .. } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };

        assert_eq!(facts.transport.value, "CN=party-x.example");
        assert_eq!(facts.accountable().party_id, Some(PartyId::new(7)));
    }

    #[test]
    fn the_message_gate_runs_after_the_message_exists_and_records_both_layers() {
        // ADR-0013's lifecycle end to end. The connection is a VAN's
        // certificate; the content names the Party in ISA06. Neither
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
        let sends = sends(Recording::ok());
        let subscriptions = vec![Subscription::new(
            "edi",
            Subscriber::SendPort("Billing".to_string()),
            equals("xmip.message.mechanism", "edi-x12-interchange"),
        )];

        let envelope = ReadsInterchange;
        let identifiers: [&dyn MessageIdentifier; 1] = [&envelope];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &sends,
            &open,
            &clock,
        );
        engine.message_identifiers = &identifiers;

        let van = ReceiveGate::new(
            "van",
            Acceptance::closed()
                .accepting(&mechanism::mutual_tls())
                .accepting(&mechanism::edi_x12_interchange()),
        );

        let arrived = arrive(
            &engine,
            &van,
            ReceivedStream::new(
                &b"ISA*00*          *00*          *ZZ*PARTYX"[..],
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
        assert_eq!(message.value, "ISA06=PARTYX");
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
        let sends = sends(Recording::ok());
        let subscriptions = subscribed_to_party_x();

        let envelope = ReadsInterchange;
        let identifiers: [&dyn MessageIdentifier; 1] = [&envelope];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &sends,
            &open,
            &clock,
        );
        engine.message_identifiers = &identifiers;

        let arrived = arrive(
            &engine,
            &location(),
            ReceivedStream::new(
                &b"ISA*00*          *00*          *ZZ*PARTYX"[..],
                "https://xmip.example/in/party-x",
            )
            .presenting(Presented::passed(
                mechanism::mutual_tls(),
                "CN=party-x.example",
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
        // A timer fires, Xmip logs into the Party's SFTP with its own key and
        // brings back a file. Nobody presented anything — Xmip was the client —
        // so the only identity available is the one the configuration implies.
        //
        // The gates still run. ADR-0019 clause 7: this is not an absence of
        // identity, it is an inferred one, and the record says which.
        let ids = Counter::default();
        let circumstance = Always(mechanism::circumstance(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&circumstance];
        let parties = Parties::default();
        let allow = Open;
        let open: [&dyn Authorizer; 1] = [&allow];
        let clock = Fixed(NOW);
        let sends = sends(Recording::ok());
        let subscriptions = vec![Subscription::new(
            "nightly",
            Subscriber::SendPort("Archive".to_string()),
            equals("xmip.arriving", "scheduled"),
        )];

        let nightly = ReceiveGate::new(
            "party-y-nightly",
            Acceptance::closed().accepting(&mechanism::circumstance()),
        );

        let arrived = arrive(
            &runtime(
                &ids,
                &authenticators,
                &parties,
                &subscriptions,
                &sends,
                &open,
                &clock,
            ),
            &nightly,
            ReceivedStream::new(
                &b"<orders/>"[..],
                "sftp://party-y.example/out/orders-2026-08-27.xml",
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
        // "party-y posted something" are different events that a Subscription
        // has to be able to tell apart.
        assert_eq!(
            facts.transport.value,
            "sftp://party-y.example/out/orders-2026-08-27.xml"
        );
    }

    #[test]
    fn how_it_arrived_and_how_the_identity_was_established_are_separate_facts() {
        // A pushed Stream with a detected identity: the Party posts an X12
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
        let sends = sends(Recording::ok());
        let subscriptions = vec![Subscription::new(
            "pushed-edi",
            Subscriber::SendPort("Billing".to_string()),
            equals("xmip.message.established", "detected"),
        )];

        let envelope = ReadsInterchange;
        let identifiers: [&dyn MessageIdentifier; 1] = [&envelope];

        let mut engine = runtime(
            &ids,
            &authenticators,
            &parties,
            &subscriptions,
            &sends,
            &open,
            &clock,
        );
        engine.message_identifiers = &identifiers;

        let van = ReceiveGate::new(
            "van",
            Acceptance::closed()
                .accepting(&mechanism::mutual_tls())
                .accepting(&mechanism::edi_x12_interchange()),
        );

        let arrived = arrive(
            &engine,
            &van,
            ReceivedStream::new(
                &b"ISA*00*          *00*          *ZZ*PARTYX"[..],
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
            facts
                .message
                .as_ref()
                .expect("the envelope named someone")
                .established,
            Established::Detected
        );
        assert_eq!(routing.dispatch(), Dispatch::Routed(1));
    }

    fn subscribed_on(filter: Expression) -> Vec<Subscription> {
        vec![Subscription::new(
            "billing",
            Subscriber::SendPort("Billing".to_string()),
            filter,
        )]
    }

    #[test]
    fn a_prefixed_property_is_read_at_arrival_through_the_loaded_technology() {
        let ids = Counter::default();
        let proves = Always(mechanism::mutual_tls(), Verified::Proven);
        let authenticators: [&dyn Authenticator; 1] = [&proves];
        let parties = registry();
        let open: [&dyn Authorizer; 1] = [&Open];
        let clock = Fixed(NOW);
        let subscriptions = subscribed_on(equals("party:sender", &PartyId::new(7).to_string()));
        let sends = sends(Recording::ok());
        let bare = runtime(&ids, &authenticators, &parties, &[], &sends, &open, &clock);
        let party: [&dyn route::Source; 1] = [&route_party::PartySource];
        let gathering = Gathering::of(&party, &subscriptions);
        let loaded = Runtime {
            subscriptions: &subscriptions,
            gathering: &gathering,
            ..bare
        };

        let arrived = arrive(&loaded, &location(), arriving());
        let Arrived::Routed { routing, .. } = arrived else {
            panic!("expected a route, got {arrived:?}");
        };
        assert_eq!(routing.dispatch(), Dispatch::Routed(1));

        // Nothing loaded reads `party:`: a filter that cannot be read is a
        // configuration mistake, refused, not a decline (ADR-0046).
        let unread = Gathering::of(&[], &subscriptions);
        let unloaded = Runtime {
            gathering: &unread,
            ..loaded
        };
        let arrived = arrive(&unloaded, &location(), arriving());
        let Arrived::Refused {
            reason: Refused::Promotion(error),
        } = arrived
        else {
            panic!("expected a refusal, got {arrived:?}");
        };
        assert_eq!(error.technology, "party");
        assert!(error.reason.contains("no route technology"));
    }

    #[test]
    fn a_bare_name_holding_bytes_is_refused_and_a_null_is_absent() {
        let ids = Counter::default();
        let parties = registry();
        let clock = Fixed(NOW);
        let context = context::MessageContext::new()
            .with_value("Blob", xcore::ScalarValue::Binary(vec![0, 1, 2]))
            .with_value("Note", xcore::ScalarValue::Null);
        let message = Message::received(
            MessageId::new(1),
            Vec::new(),
            context,
            MessageTreatment::default(),
        );

        let nowhere = Sends::default();
        let on_bytes = subscribed_on(filter("exists Blob"));
        let reading = runtime(&ids, &[], &parties, &on_bytes, &nowhere, &[], &clock);
        let Err(Refused::Promotion(error)) = promoted(&reading, &message) else {
            panic!("bytes under a bare name are refused");
        };
        assert_eq!(error.technology, "context");
        assert_eq!(error.property, "Blob");

        let on_null = subscribed_on(filter("exists Note"));
        let reading = runtime(&ids, &[], &parties, &on_null, &nowhere, &[], &clock);
        let set = promoted(&reading, &message).expect("a Null is readable");
        assert_eq!(set.get("Note"), None);
        assert_eq!(publish(&set, &on_null).dispatch(), Dispatch::Unroutable);
    }
}
