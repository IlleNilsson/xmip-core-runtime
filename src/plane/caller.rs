//! Who a caller of the operate plane is, through the one gate (ADR-0019,
//! amendment 2026-10-30; ADR-0009, amendment 2026-11-01).
//!
//! The owner, 2026-10-29: *First you present your identity, then you get
//! identified. Then we look to authentication, does your identification hold
//! up. When authenticated we look for Authorization.* A caller of a node's
//! operate listener, or of a web host's secure surface (`xmip_operate.h`
//! section 21), presents what its connection proves — a client certificate
//! the handshake verified against the anchors, or on the node's local
//! endpoint the account the operating system names — and nothing else.
//! That claim is read here, once for every plane, and run through
//! `authenticate::authenticate` like any arrival's: the certificate's
//! subject as `mutual-tls`, verified by the capability's [`Handshake`], and
//! the account as `peer-credentials`, by [`PeerCredentials`]. Only what the
//! gate answers is a caller; `plane::role::admitted` takes it.
//!
//! Each plane's acceptance is closed to the one mechanism its connection
//! carries, so nothing else can be tried there, and an operator is no
//! Party: the registry is empty, and a caller resolves to none. A program
//! in a node's own process subscribing to Events is the one caller resolved
//! to a Party here ([`subscriber`]): the account the operating system
//! names, through the Parties it is handed, never a Party the program
//! names; an account no Party holds, or more than one, is refused and
//! audited (ADR-0019, amendment 2026-11-11).

use authenticate::x509::Name;
use authenticate::{Acceptance, Authenticator, Handshake, PeerCredentials};
use context::AuthenticatedIdentity;
use context::property::{TLS_HANDSHAKE_VERIFIED as VERIFIED, TLS_PEER_ISSUER};
use identify::Presented;
use identify::evidence::{MUTUAL_TLS_HANDSHAKE, PEER_CREDENTIALS_SYSTEM};
use xaudit::program_audit::ProgramAudit;
use xcore::{Mechanism, Purpose, mechanism};
use xevent::filter::Filter;
use xevent::subscriber::Subscriber;

use crate::parties::Parties;

/// The caller a certificate proves: `leaf`, DER, the certificate a
/// handshake this process terminated verified against its anchors, its
/// subject the claim and the handshake's word its proof.
///
/// # Errors
///
/// A certificate whose names cannot be read, or the gate's refusal, in
/// words.
pub fn certificate(leaf: &[u8]) -> Result<AuthenticatedIdentity, String> {
    let subject = Name::subject_of(leaf).map_err(|failed| failed.to_string())?;
    let mut claim = Presented::passed(mechanism::mutual_tls(), subject.to_string())
        .with_proof(MUTUAL_TLS_HANDSHAKE, VERIFIED);
    if let Ok(issuer) = Name::issuer_of(leaf) {
        claim = claim.with_evidence(TLS_PEER_ISSUER, issuer.to_string());
    }
    gate(
        mechanism::mutual_tls(),
        &Handshake,
        &claim,
        &Parties::default(),
    )
}

/// The caller the operating system names on the node's local endpoint:
/// `account`, the one the connecting process runs as, read from the
/// connection.
///
/// # Errors
///
/// The gate's refusal, in words.
pub fn local(account: &str) -> Result<AuthenticatedIdentity, String> {
    local_of(account, &Parties::default())
}

/// The caller the operating system names, as [`local`], resolved through
/// `parties`: the Party whose `peer-credentials` identity names `account`,
/// or none.
///
/// # Errors
///
/// The gate's refusal, in words.
pub fn local_of(account: &str, parties: &Parties) -> Result<AuthenticatedIdentity, String> {
    let claim = Presented::detected(mechanism::peer_credentials(), account)
        .with_proof(PEER_CREDENTIALS_SYSTEM, VERIFIED);
    gate(
        mechanism::peer_credentials(),
        &PeerCredentials,
        &claim,
        parties,
    )
}

/// The Event subscriber a program in this process is among `parties`: the
/// account the operating system says the process runs as, as
/// [`subscriber_as`] takes it. The one rule for every program subscribing
/// in a node's process — the C boundary's (`ffi::event`, through the
/// Parties of the nodes serving here) and the Essentials' nodes'.
///
/// # Errors
/// The operating system named no account, or as [`subscriber_as`]; each
/// refusal audited in `audit`.
pub fn subscriber(
    parties: &Parties,
    filter: &Filter,
    audit: &ProgramAudit,
) -> Result<Subscriber, String> {
    match crate::plane::local::running_as() {
        Ok(account) => subscriber_as(&account, parties, filter, audit),
        Err(said) => Err(refused(audit, None, filter, said)),
    }
}

/// The Event subscriber `account` proves to be among `parties`: proven by
/// the gate ([`local_of`]) and resolved to the one declared Party whose
/// `peer-credentials` identity names it — never a Party the program names
/// (the owner, 2026-11-10; ADR-0019, amendment 2026-11-11). A refusal is
/// audited in `audit` with who asked and for `filter`, as the hub audits
/// its own (`xevent::subscriber::refused`).
///
/// # Errors
/// The gate's refusal; no Party holds `account`; or more than one does,
/// each named, whichever node lent it first.
pub fn subscriber_as(
    account: &str,
    parties: &Parties,
    filter: &Filter,
    audit: &ProgramAudit,
) -> Result<Subscriber, String> {
    let caller = local_of(account, parties).map_err(|said| refused(audit, None, filter, said))?;
    let holders = parties.holding(caller.mechanism.name(), Purpose::Receive, account);
    let party = match holders.as_slice() {
        [one] => (*one).clone(),
        [] => {
            let said = format!(
                "REFUSED: {account}, the account this process runs as, is no Party of a node \
                 serving in this process; a subscriber is the Party its proven caller resolves \
                 to, never one it names"
            );
            return Err(refused(audit, Some(&caller), filter, said));
        }
        many => {
            let named: Vec<String> = many
                .iter()
                .map(|party| format!("'{}' ({})", party.name, party.party_id))
                .collect();
            let said = format!(
                "REFUSED: {account}, the account this process runs as, is held by {} Parties of \
                 the nodes serving in this process, {}; a subscriber is one Party",
                many.len(),
                named.join(" and ")
            );
            return Err(refused(audit, Some(&caller), filter, said));
        }
    };
    Subscriber::proven(caller.clone(), &party, audit.clone())
        .map_err(|why| refused(audit, Some(&caller), filter, why.to_string()))
}

/// `said`, audited in `audit` as a subscribe refused by `caller` asking for
/// `filter`, and handed back.
fn refused(
    audit: &ProgramAudit,
    caller: Option<&AuthenticatedIdentity>,
    filter: &Filter,
    said: String,
) -> String {
    xevent::subscriber::refused(audit, caller, filter, &said);
    said
}

/// `claim` through the authentication gate, the plane accepting `taken`
/// alone, verifying it by `by` and resolving it through `parties`.
fn gate(
    taken: Mechanism,
    by: &dyn Authenticator,
    claim: &Presented,
    parties: &Parties,
) -> Result<AuthenticatedIdentity, String> {
    let acceptance = Acceptance::closed().accepting(&taken);
    authenticate::authenticate(&acceptance, &[by], parties, claim)
        .map_err(|refused| refused.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Verified;

    #[test]
    fn the_account_the_system_names_is_a_proven_caller_and_no_account_none() {
        let caller = local(r"CORP\jane").expect("proven");
        assert_eq!(caller.verified, Verified::Proven);
        assert_eq!(caller.value, r"CORP\jane");
        assert_eq!(caller.mechanism.name(), "peer-credentials");
        assert_eq!(caller.party_id, None, "an operator is no Party");
        assert!(local(" ").is_err());
    }

    #[test]
    fn the_account_resolves_to_the_party_whose_identity_names_it_and_no_other() {
        let configured = vec![configure::PartyConfiguration::new(
            "operations",
            vec![configure::PartyIdentity::new(
                "peer-credentials",
                xcore::Purpose::Receive,
                r"CORP\jane",
            )],
        )];
        let parties = Parties::of(&configured, &[]).expect("declared");

        let jane = local_of(r"CORP\jane", &parties).expect("proven");
        assert_eq!(jane.party_id, configured[0].id);
        let john = local_of(r"CORP\john", &parties).expect("proven");
        assert_eq!(john.party_id, None, "proven, and no Party holds him");
    }

    #[test]
    fn an_account_two_parties_hold_subscribes_as_neither_whichever_node_lent_first() {
        let held = |name: &str| {
            configure::PartyConfiguration::new(
                name,
                vec![configure::PartyIdentity::new(
                    "peer-credentials",
                    Purpose::Receive,
                    r"CORP\shared",
                )],
            )
        };
        let (first, second) = (held("operations"), held("on-call"));
        let at = std::env::temp_dir().join(format!("xmip-runtime-caller-{}", std::process::id()));
        let audit = ProgramAudit::new("xmip-core-runtime tests", Some(&at));
        let filter = Filter::everything();

        for order in [[&first, &second], [&second, &first]] {
            let configured: Vec<_> = order.into_iter().cloned().collect();
            let parties = Parties::of(&configured, &[]).expect("declared");
            let refused = subscriber_as(r"CORP\shared", &parties, &filter, &audit)
                .expect_err("two Parties hold it");
            assert!(refused.contains("is held by 2 Parties"), "{refused}");
            assert!(refused.contains("'operations'"), "{refused}");
            assert!(refused.contains("'on-call'"), "{refused}");
        }

        let alone = Parties::of(std::slice::from_ref(&first), &[]).expect("declared");
        let subscriber = subscriber_as(r"CORP\shared", &alone, &filter, &audit).expect("one");
        assert_eq!(Some(subscriber.party()), first.id);
        let _ = std::fs::remove_dir_all(&at);
    }

    #[test]
    fn a_verified_certificate_is_its_subject_proven_and_no_certificate_none() {
        let issued = rcgen::generate_simple_self_signed(vec!["operator.example".to_string()])
            .expect("a certificate");
        let caller = certificate(issued.cert.der()).expect("proven");
        assert_eq!(caller.verified, Verified::Proven);
        assert_eq!(caller.mechanism.name(), "mutual-tls");
        assert!(caller.value.contains("CN="), "{}", caller.value);
        assert!(certificate(b"not a certificate").is_err());
    }
}
