//! What arrival asks of a Receive Location: the gate it holds, read from its
//! configuration once, as the node starts.

use authenticate::{Acceptance, Authenticator};
use configure::{ConfiguredLocation, PartyConfiguration};
use receive::IdentityPolicy;

use crate::sequence::Point;

/// What arrival asks of the Receive Location a Stream came in at: its name,
/// the closed set of mechanisms and Parties it accepts (ADR-0019 clause 1)
/// and what it does when the two identity layers disagree (clause 7). Read
/// from the Location's configuration once, as the node starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveGate {
    /// The Location's name, what an authorization attempt names.
    pub location: String,
    pub accept: Acceptance,
    pub identity: IdentityPolicy,
    /// Its Receive Port, where it has one.
    pub port: String,
    /// The sequences its Streams hold a place in end to end: its own by
    /// default, one Stream at a time (`crate::sequence`).
    pub points: Vec<Point>,
}

impl ReceiveGate {
    /// The gate `configured` declares, each accepted mechanism taken from the
    /// authenticator that verifies it, and each accepted Party by the
    /// identifier the node knows it by among `parties`.
    ///
    /// # Errors
    /// Every accepted mechanism no authenticator in `authenticators`
    /// verifies, and every accepted Party `parties` does not declare, one
    /// sentence each: a Location that accepts what nothing can verify, or
    /// whom nobody is, is refused as the node starts, not at its first
    /// Stream.
    pub fn of(
        configured: &ConfiguredLocation,
        authenticators: &[&dyn Authenticator],
        parties: &[PartyConfiguration],
    ) -> Result<Self, Vec<String>> {
        let mut accept = Acceptance::closed();
        let mut problems = configure::party::accepted_problems(parties, configured);
        for party in configured
            .accept
            .party
            .iter()
            .filter_map(|name| configure::party::named(parties, name))
        {
            accept = accept.from_party(party);
        }

        for name in &configured.accept.mechanism {
            match authenticators
                .iter()
                .map(|authenticator| authenticator.mechanism())
                .find(|mechanism| mechanism.name() == name)
            {
                Some(mechanism) => accept = accept.accepting(&mechanism),
                None => problems.push(format!(
                    "the Receive Location '{}' accepts '{name}', and no authenticator this \
                     node was built with verifies it",
                    configured.name
                )),
            }
        }

        if problems.is_empty() {
            Ok(Self {
                location: configured.name.clone(),
                accept,
                identity: IdentityPolicy {
                    minimum: configured.accept.minimum(),
                    ..IdentityPolicy::default()
                },
                port: String::new(),
                points: vec![Point::receive_location(&configured.name)],
            })
        } else {
            Err(problems)
        }
    }

    /// A gate named `location` accepting `accept`, with the default identity
    /// policy.
    #[must_use]
    pub fn new(location: &str, accept: Acceptance) -> Self {
        Self {
            location: location.to_string(),
            accept,
            identity: IdentityPolicy::default(),
            port: String::new(),
            points: vec![Point::receive_location(location)],
        }
    }

    /// The same gate, taking `minimum` on each layer.
    #[must_use]
    pub const fn taking(mut self, minimum: context::Minimum) -> Self {
        self.identity.minimum = minimum;
        self
    }
}
