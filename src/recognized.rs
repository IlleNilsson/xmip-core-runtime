//! The Parties a node's configuration recognizes, as the gates ask for
//! them.
//!
//! `[[parties]]` (ADR-0019 clause 4; ADR-0028, amendment 2026-10-13) names
//! each Party with the identities it is recognized by. The authentication
//! gate asks whose a verified value is, after it verified it and never
//! before; the answer is the Party holding that identity, by the identifier
//! the configuration gives it (`configure::party`).

use authenticate::PartyRegistry;
use configure::PartyConfiguration;
use xcore::{PartyId, Purpose};

/// The configuration's Parties, resolving a verified value to the one
/// holding it.
///
/// A configured identity is written as its mechanism writes it and names
/// neither the mechanism nor the direction (`configure::party`), so a
/// value resolves to the Party holding it whatever mechanism verified it
/// and whatever the purpose asked. The assistant's reading of 2026-10-19,
/// as the Playground resolves its Parties, for the owner to overrule:
/// ADR-0019 clause 4 keeps a Party's identities per direction and per
/// mechanism, and `[[parties]]` does not yet say either.
#[derive(Clone, Debug, Default)]
pub struct Recognized(pub Vec<PartyConfiguration>);

impl PartyRegistry for Recognized {
    fn resolve(&self, _mechanism: &str, _purpose: Purpose, value: &str) -> Option<PartyId> {
        configure::party::holding(&self.0, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verified_value_resolves_to_the_party_holding_it_and_a_stranger_to_none() {
        let parties = configure::party::parties(
            "[[parties]]\nname = \"first\"\nidentities = [\"CN=first.example\"]\n\n\
             [[parties]]\nname = \"second\"\nidentities = [\"CN=second.example\"]\n",
        )
        .expect("parses");
        let recognized = Recognized(parties);

        assert_eq!(
            recognized.resolve("mutual-tls", Purpose::Receive, "CN=second.example"),
            Some(configure::party::id(1))
        );
        assert_eq!(
            recognized.resolve("mutual-tls", Purpose::Receive, "CN=third.example"),
            None
        );
    }
}
