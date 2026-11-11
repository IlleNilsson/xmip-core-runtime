//! The Parties a node knows, built once as it starts from `[[parties]]`
//! (ADR-0019 clause 4; `configure::party`), and the one registry both sides
//! of the message path ask.
//!
//! `[[parties]]` names each identity's mechanism by a word, and a mechanism
//! is declared by the module that implements it, never built from
//! configuration (`xcore::mechanism`). So the word is looked up among the
//! declarations: first the mechanisms this node's authenticators declare,
//! which a third party's module may add to, then those Xmip declares itself
//! (`xcore::mechanism::named`). A word nothing declares is refused as the
//! node starts, in words.
//!
//! The gates ask whose a verified value is, after it was verified and never
//! before; the send side asks which identity a Party presents (ADR-0006).
//! One list answers both, because a deployment has one set of Parties.
//!
//! A node serving lends its Parties to its process while it serves
//! ([`Parties::serve`]): a program in that process — one that loaded the
//! runtime's library and subscribes to Events — is the account the
//! operating system names, resolved through them ([`Parties::serving`]),
//! and never a Party it names (ADR-0019, amendment 2026-11-11).

use std::sync::{Arc, Mutex, Weak};
use xcore::lock::Locked;

use authenticate::{Authenticator, PartyRegistry};
use configure::{PartyConfiguration, PartyIdentity};
use party::{Identity, Party};
use xcore::{Mechanism, PartyId, Purpose, SecretName};

/// The Parties of every node serving in this process, as each started.
static SERVING: Mutex<Vec<Weak<Parties>>> = Mutex::new(Vec::new());

/// A Party, by the identifier the gates handed back.
///
/// Separate from [`PartyRegistry`], which answers with a `PartyId` and nothing
/// more. `architecture.toml` gives the three gates no dependency on
/// `xmip-core-party`, so a gate cannot read a Party's identities even by
/// accident; the runtime can, because the send side genuinely needs to —
/// ADR-0006 resolves *which* Party's identity to present through the Send
/// Location chain, and something then has to produce it.
pub trait PartyDirectory: Send + Sync {
    fn party(&self, party_id: PartyId) -> Option<Party>;
}

/// The Parties a node knows, answering both the gates' question (whose is
/// this verified value) and the send side's (which identity does this Party
/// present).
#[derive(Clone, Debug, Default)]
pub struct Parties(pub Vec<Party>);

impl Parties {
    /// The Parties `configured` declares, each identity's mechanism the one
    /// declared under its word by `authenticators` or by Xmip.
    ///
    /// A Party without its identifier is left out: `configure::party`
    /// refuses it, in words, as the node's configuration is bound.
    ///
    /// # Errors
    /// Every identity whose mechanism nothing declares, and every one whose
    /// secret is not a secret's name, one sentence each.
    pub fn of(
        configured: &[PartyConfiguration],
        authenticators: &[&dyn Authenticator],
    ) -> Result<Self, Vec<String>> {
        let mut problems = Vec::new();
        let mut parties = Vec::new();
        for written in configured {
            let Some(id) = written.id else { continue };
            let mut party = Party::new(id, None, &written.name);
            for identity in &written.identities {
                match built(identity, authenticators) {
                    Ok(identity) => party = party.with(identity),
                    Err(why) => problems.push(format!("the Party '{}' {why}", written.name)),
                }
            }
            parties.push(party);
        }
        if problems.is_empty() {
            Ok(Self(parties))
        } else {
            Err(problems)
        }
    }

    /// `parties`, a node's, lent to this process for as long as the node
    /// holds them: what a caller in this process resolves through.
    pub fn serve(parties: &Arc<Self>) {
        let mut serving = SERVING.locked();
        serving.retain(|held| held.strong_count() > 0);
        serving.push(Arc::downgrade(parties));
    }

    /// The Parties of every node serving in this process, as one registry;
    /// empty where none serves here. Two nodes may each declare a Party
    /// holding one account: [`Parties::holding`] names them all, so a
    /// caller resolves the same whichever node lent first.
    #[must_use]
    pub fn serving() -> Self {
        Self(
            SERVING
                .locked()
                .iter()
                .filter_map(Weak::upgrade)
                .flat_map(|parties| parties.0.clone())
                .collect(),
        )
    }

    /// Every Party holding `value` under `mechanism` for `purpose`, each
    /// once, in the order declared: more than one is a choice nothing here
    /// makes.
    #[must_use]
    pub fn holding(&self, mechanism: &str, purpose: Purpose, value: &str) -> Vec<&Party> {
        let mut held: Vec<&Party> = Vec::new();
        for party in &self.0 {
            if party.holds(mechanism, purpose, value)
                && held.iter().all(|seen| seen.party_id != party.party_id)
            {
                held.push(party);
            }
        }
        held
    }
}

/// The mechanism declared under `word`: by one of `authenticators`, or by
/// Xmip itself.
fn declared(word: &str, authenticators: &[&dyn Authenticator]) -> Option<Mechanism> {
    authenticators
        .iter()
        .map(|authenticator| authenticator.mechanism())
        .find(|mechanism| mechanism.name() == word)
        .or_else(|| xcore::mechanism::named(word))
}

/// `written` as the Party holds it, or why not, completing a sentence
/// that starts with the Party.
fn built(
    written: &PartyIdentity,
    authenticators: &[&dyn Authenticator],
) -> Result<Identity, String> {
    let (word, value) = (written.mechanism.as_str(), written.value.as_str());
    let mechanism = declared(word, authenticators).ok_or_else(|| {
        format!(
            "has an identity under '{word}', a mechanism neither this node's \
             authenticators nor Xmip declare"
        )
    })?;
    let secret = || {
        let name = written.secret.clone().unwrap_or_default();
        SecretName::new(name).map_err(|why| {
            format!(
                "has the {word} identity '{value}' for {}, whose secret is not one: {why}",
                written.purpose
            )
        })
    };
    Ok(match written.purpose {
        Purpose::Receive => Identity::receiving(mechanism, value),
        Purpose::Operate => Identity::operating(mechanism, value),
        Purpose::Process => Identity::processing(mechanism, value, secret()?),
        Purpose::Send => Identity::sending(mechanism, value, secret()?),
    })
}

impl PartyRegistry for Parties {
    fn resolve(&self, mechanism: &str, purpose: Purpose, value: &str) -> Option<PartyId> {
        self.0
            .iter()
            .find(|party| party.holds(mechanism, purpose, value))
            .map(|party| party.party_id)
    }
}

impl PartyDirectory for Parties {
    fn party(&self, party_id: PartyId) -> Option<Party> {
        self.0
            .iter()
            .find(|party| party.party_id == party_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(name: &str, identities: Vec<PartyIdentity>) -> PartyConfiguration {
        PartyConfiguration::new(name, identities)
    }

    fn receiving(name: &str) -> PartyIdentity {
        PartyIdentity::new("mutual-tls", Purpose::Receive, format!("CN={name}.example"))
    }

    #[test]
    fn a_verified_value_resolves_by_its_mechanism_and_purpose_and_a_stranger_to_none() {
        let configured = vec![
            party("first", vec![receiving("first")]),
            party("second", vec![receiving("second")]),
        ];
        let second = configured[1].id;
        let parties = Parties::of(&configured, &[]).expect("declared mechanisms");

        let resolve = |mechanism, purpose, value| parties.resolve(mechanism, purpose, value);
        assert_eq!(
            resolve("mutual-tls", Purpose::Receive, "CN=second.example"),
            second
        );
        assert_eq!(
            resolve("certificate", Purpose::Receive, "CN=second.example"),
            None
        );
        assert_eq!(
            resolve("mutual-tls", Purpose::Send, "CN=second.example"),
            None
        );
        assert_eq!(
            resolve("mutual-tls", Purpose::Receive, "CN=third.example"),
            None
        );
    }

    #[test]
    fn the_send_side_reads_the_identity_a_party_presents_and_its_secret() {
        let sent = PartyIdentity::new("ssh-key", Purpose::Send, "xmip").presenting("party-sftp");
        let configured = vec![party("party-x", vec![receiving("party-x"), sent])];
        let id = configured[0].id.expect("minted");
        let parties = Parties::of(&configured, &[]).expect("declared mechanisms");

        let found = parties.party(id).expect("the directory holds it");
        let presented = found.configured_for(Purpose::Send).next().expect("one");
        assert_eq!(presented.mechanism, xcore::mechanism::ssh_key());
        assert_eq!(
            presented
                .secret
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("party-sftp")
        );
    }

    #[test]
    fn a_node_lends_its_parties_to_the_process_while_it_holds_them() {
        let configured = vec![party("lent", vec![receiving("lent")])];
        let id = configured[0].id.expect("minted");
        let held = Arc::new(Parties::of(&configured, &[]).expect("declared mechanisms"));
        let lent = || Parties::serving().party(id).is_some();

        assert!(!lent(), "not before it serves");
        Parties::serve(&held);
        assert!(lent());
        drop(held);
        assert!(!lent(), "not after the node let them go");
    }

    #[test]
    fn a_mechanism_nothing_declares_is_refused_in_words() {
        let unknown = PartyIdentity::new("carrier-pigeon", Purpose::Receive, "v");
        let refused = Parties::of(&[party("party-x", vec![unknown])], &[]).expect_err("unknown");
        assert_eq!(
            refused,
            [
                "the Party 'party-x' has an identity under 'carrier-pigeon', a mechanism \
                 neither this node's authenticators nor Xmip declare"
            ]
        );
    }

    #[test]
    fn a_send_identity_without_its_secret_is_refused_in_words() {
        let unnamed = PartyIdentity::new("ssh-key", Purpose::Send, "xmip");
        let refused = Parties::of(&[party("party-x", vec![unnamed])], &[]).expect_err("unnamed");
        assert!(
            refused[0].starts_with("the Party 'party-x' has the ssh-key identity 'xmip' for send"),
            "{refused:?}"
        );
    }
}
