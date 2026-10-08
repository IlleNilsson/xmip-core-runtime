//! What the gates concluded, and what the transport handed over, written
//! into the Message Context where a Subscription can read it.

use context::property::PARTY;
use context::{IdentityFacts, MessageContext};
use receive::ReceivedStream;

/// Put what the gates concluded where a Subscription can read it.
///
/// Routing reads the promoted set and nothing else, so an identity that stays
/// inside `IdentityFacts` cannot be routed on. These names are the contract
/// between the two, and they are prefixed so a Contract promoting `Party`
/// cannot collide with Xmip promoting one.
///
/// The headers the transport handed over go in first, each under the name
/// it travels by, `<protocol>.header.<name>`: the runtime writes them into
/// the Message Context once, at arrival, and no transport writes into a
/// context (ADR-0046, amendment 2026-09-25, later).
pub(super) fn promote_identity(facts: &IdentityFacts, received: &ReceivedStream) -> MessageContext {
    use xcore::ScalarValue;

    let mut context = MessageContext::new();
    for (name, value) in &received.headers {
        context = context.with_value(name.as_str(), value.clone());
    }
    let mut context = context
        .with_value(
            "xmip.arriving",
            ScalarValue::Text(received.arriving.to_string()),
        )
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
