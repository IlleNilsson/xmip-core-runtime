//! A running node's Message held by a paused Subscription, and picked up
//! again once it is resumed (ADR-0013, amendment 2026-09-30).
//!
//! What is held is what departure needs and nothing it does not: the
//! Message's identifier and content, and the identity arrival concluded, in
//! its words — so a Message held before a restart is picked up after it.
//! Departure authorizes again, now, as it always does: what arrival
//! concluded is a record of then and never a licence to act now. A
//! mechanism is never built from a record (`xcore::Mechanism`): the one a
//! held identity names is the one this node's authenticators declare under
//! that name, and a held Message whose mechanism the node no longer carries
//! does not depart, in words.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use context::{AlignmentResult, AuthenticatedIdentity, IdentityFacts, MessageContext, Verified};
use journey::{Journey, JourneyMessageRef};
use message::{Message, MessageSection};
use persist::HeldMessage;
use stream::Stream;
use xcore::{Established, JourneyId, Mechanism, PartyId, SectionId, StreamId, mechanism};

use crate::departure::{Departed, depart_to};
use crate::generation::ReceivedWork;
use crate::message_path::Runtime;
use crate::outcome::Tally;
use crate::pickup::{Pickup, Released};

const ALIGNMENT: &str = "alignment";
const LAYERS: [&str; 2] = ["transport", "message"];

/// What a paused Subscription keeps of `work`, which arrival concluded
/// `facts` of.
#[must_use]
pub fn held(work: &ReceivedWork, facts: &IdentityFacts) -> HeldMessage {
    let mut said = vec![(ALIGNMENT.to_string(), facts.alignment.word().to_string())];
    for (layer, identity) in LAYERS
        .into_iter()
        .zip([Some(&facts.transport), facts.message.as_ref()])
    {
        let Some(identity) = identity else {
            continue;
        };
        let mut say = |what: &str, value: String| said.push((format!("{layer}.{what}"), value));
        say("mechanism", identity.mechanism.name().to_string());
        say("value", identity.value.clone());
        say("established", identity.established.word().to_string());
        say("verified", identity.verified.word().to_string());
        say("at", identity.authenticated_at.to_string());
        if let Some(party) = identity.party_id {
            say("party", party.to_string());
        }
    }
    HeldMessage {
        message_id: Some(work.message.message_id()),
        content: work.message.sections()[0].stream.bytes().to_vec(),
        said,
        ..HeldMessage::default()
    }
}

/// Pick up what a resume let go of: the Message rebuilt from what was held,
/// a Journey opened for it, and a departure to where its Subscription
/// leads.
pub fn depart_released(runtime: &Runtime<'_>, released: &Released) -> Vec<Departed> {
    let to = released.destination.clone();
    let facts = match facts(runtime, &released.held) {
        Ok(facts) => facts,
        Err(why) => {
            return vec![Departed::Failed {
                to,
                retryable: false,
                detail: why,
            }];
        }
    };
    let held = &released.held;
    let message_id = held
        .message_id
        .unwrap_or_else(|| xcore::MessageId::new(runtime.ids.next_u128()));
    let stream = Stream::new(
        StreamId::new(runtime.ids.next_u128()),
        held.content.clone(),
        None,
    );
    let stream_id = stream.id();
    let section = MessageSection {
        section_id: SectionId::new(runtime.ids.next_u128()),
        name: None,
        stream,
        contract: None,
    };
    // Departure reads the content and the identity; the context arrival
    // promoted was for routing, which has decided.
    let message = Message::received(
        message_id,
        vec![section],
        MessageContext::new(),
        runtime.treatment,
    );
    let journey =
        Journey::new(JourneyId::new(runtime.ids.next_u128())).holding(JourneyMessageRef {
            message_id,
            stream_id,
        });
    let work = ReceivedWork { journey, message };
    depart_to(runtime, &work, &facts, &to)
}

/// What a resume let go of, picked up as it is let go of until the node
/// stops: each held Message departs where its Subscription leads, and only
/// then is its record of the wait released. The wait wakes on a resume; its
/// bound is how soon a stop is seen.
pub(crate) fn pick_up_released(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    stopping: &AtomicBool,
    tally: &Tally,
) {
    while !stopping.load(Ordering::Acquire) {
        for released in pickup.released(Duration::from_millis(50), 64) {
            tally.departed(&depart_released(runtime, &released));
            pickup.picked_up(&released);
        }
    }
}

/// The identity arrival concluded, read back from what was held.
fn facts(runtime: &Runtime<'_>, held: &HeldMessage) -> Result<IdentityFacts, String> {
    let transport = identity(runtime, held, "transport")?
        .ok_or("the held Message kept no transport identity")?;
    let message = identity(runtime, held, "message")?;
    let alignment = held
        .said(ALIGNMENT)
        .and_then(AlignmentResult::named)
        .ok_or("the held Message kept no alignment")?;
    Ok(IdentityFacts {
        transport,
        message,
        alignment,
    })
}

fn identity(
    runtime: &Runtime<'_>,
    held: &HeldMessage,
    layer: &str,
) -> Result<Option<AuthenticatedIdentity>, String> {
    let said = |what: &str| held.said(&format!("{layer}.{what}"));
    let Some(name) = said("mechanism") else {
        return Ok(None);
    };
    let mechanism = carried(runtime, name).ok_or_else(|| {
        format!("the mechanism '{name}' the Message was held under is not carried by this node")
    })?;
    let unread = |what: &str| format!("the held Message's {layer} {what} does not read");
    let established = said("established")
        .and_then(Established::named)
        .ok_or_else(|| unread("establishment"))?;
    let verified = said("verified")
        .and_then(Verified::named)
        .ok_or_else(|| unread("verification"))?;
    let at = said("at").and_then(|at| at.parse().ok()).unwrap_or(0);
    let mut identity = AuthenticatedIdentity::new(
        mechanism,
        said("value").unwrap_or_default(),
        established,
        verified,
    )
    .at(at);
    if let Some(party) = said("party").and_then(|party| party.parse::<PartyId>().ok()) {
        identity = identity.resolving_to(party);
    }
    Ok(Some(identity))
}

/// The mechanism of that name this node carries: one its authenticators
/// declare, or the circumstance every node infers (ADR-0019 clause 7).
fn carried(runtime: &Runtime<'_>, name: &str) -> Option<Mechanism> {
    runtime
        .authenticators
        .iter()
        .map(|authenticator| authenticator.mechanism())
        .chain([mechanism::circumstance()])
        .find(|mechanism| mechanism.name() == name)
}
