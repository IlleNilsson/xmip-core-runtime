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
//! Party: the registry is empty, and a caller resolves to none.

use authenticate::x509::Name;
use authenticate::{Acceptance, Authenticator, Handshake, PeerCredentials};
use context::AuthenticatedIdentity;
use context::property::{TLS_HANDSHAKE_VERIFIED as VERIFIED, TLS_PEER_ISSUER};
use identify::Presented;
use identify::evidence::{MUTUAL_TLS_HANDSHAKE, PEER_CREDENTIALS_SYSTEM};
use xcore::{Mechanism, mechanism};

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
    gate(mechanism::mutual_tls(), &Handshake, &claim)
}

/// The caller the operating system names on the node's local endpoint:
/// `account`, the one the connecting process runs as, read from the
/// connection.
///
/// # Errors
///
/// The gate's refusal, in words.
pub fn local(account: &str) -> Result<AuthenticatedIdentity, String> {
    let claim = Presented::detected(mechanism::peer_credentials(), account)
        .with_proof(PEER_CREDENTIALS_SYSTEM, VERIFIED);
    gate(mechanism::peer_credentials(), &PeerCredentials, &claim)
}

/// `claim` through the authentication gate, the plane accepting `taken`
/// alone and verifying it by `by`.
fn gate(
    taken: Mechanism,
    by: &dyn Authenticator,
    claim: &Presented,
) -> Result<AuthenticatedIdentity, String> {
    let acceptance = Acceptance::closed().accepting(&taken);
    authenticate::authenticate(&acceptance, &[by], &Parties::default(), claim)
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
        assert!(local(" ").is_err());
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
