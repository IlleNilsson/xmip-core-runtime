//! The Parties a node's configuration recognizes, as the gates ask for
//! them.
//!
//! `[[parties]]` (ADR-0019 clause 4; ADR-0028, amendment 2026-10-13) names
//! each Party with its identifier and the identities it is recognized by,
//! each with the mechanism that verifies it and what it is for. The
//! authentication gate asks whose a verified value is, after it verified it
//! and never before; the answer is the Party holding that value under that
//! mechanism for that purpose, by the identifier written with it
//! (`configure::party`; the owner, 2026-10-19).

use authenticate::PartyRegistry;
use configure::PartyConfiguration;
use xcore::{PartyId, Purpose};

/// The configuration's Parties, resolving a verified value to the one
/// holding it under the mechanism that verified it, for the purpose asked.
#[derive(Clone, Debug, Default)]
pub struct Recognized(pub Vec<PartyConfiguration>);

impl PartyRegistry for Recognized {
    fn resolve(&self, mechanism: &str, purpose: Purpose, value: &str) -> Option<PartyId> {
        configure::party::holding(&self.0, mechanism, purpose, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use configure::PartyIdentity;

    #[test]
    fn a_verified_value_resolves_by_its_mechanism_and_purpose_and_a_stranger_to_none() {
        let party = |name: &str| {
            let subject = format!("CN={name}.example");
            PartyConfiguration::new(
                name,
                vec![PartyIdentity::new("mutual-tls", Purpose::Receive, subject)],
            )
        };
        let parties = vec![party("first"), party("second")];
        let second = parties[1].id;
        let recognized = Recognized(parties);

        assert_eq!(
            recognized.resolve("mutual-tls", Purpose::Receive, "CN=second.example"),
            second
        );
        assert_eq!(
            recognized.resolve("certificate", Purpose::Receive, "CN=second.example"),
            None
        );
        assert_eq!(
            recognized.resolve("mutual-tls", Purpose::Send, "CN=second.example"),
            None
        );
        assert_eq!(
            recognized.resolve("mutual-tls", Purpose::Receive, "CN=third.example"),
            None
        );
    }
}
