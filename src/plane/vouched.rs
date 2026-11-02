//! The callers a relay vouched for, held by the node (ADR-0009, amendment
//! 2026-11-01: the node decides, not the host).
//!
//! A web host takes a browser's TLS and proves its caller in its own
//! process (`plane::held`); a hostile host in that process could act as
//! its own account. So the node keeps the authority: an account
//! `[operate] relay` names hands the node the certificate its browser
//! presented (`Vouch`), the node verifies it against its own `[operate]
//! anchors` for client authentication and runs it through its own gate
//! (`plane::caller::certificate`), and only then issues a handle of its
//! own. On a call that names that handle (`call::CALLER_HEADER`) the act is
//! the browser caller's and admitted by the caller's own role — never the
//! relay's — and only where the handle was issued to the very account the
//! call comes through, before its certificate's `notAfter`, and not yet
//! let go (`Unvouch`). A handle presented by any other account is no one.
//! Relaying grants no act of its own: the relay's own calls are judged by
//! its own role as any caller's.
//!
//! The limit, until the node takes part in the browser's handshake: a
//! compromised host can act for anyone whose certificate it has held while
//! that certificate is valid, within that caller's role and visibly in the
//! node's audit (`through`); it cannot make up an identity.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use authenticate::x509::{Anchors, Chain, Usage, not_after_of, verify};
use context::AuthenticatedIdentity;
use serde_json::{Value, json};

use crate::plane::caller;
use crate::plane::handle::{drawn, now};

/// How many callers a node holds for its relays at once, at most.
pub const MOST: usize = 65_536;

/// Who may relay for a caller, and what the caller's certificate must
/// reach: `[operate] relay` and `[operate] anchors`.
pub struct Relaying {
    relay: Vec<String>,
    anchors: Anchors,
}

impl Relaying {
    /// The accounts and subjects `relay` names, relaying callers whose
    /// certificates reach `anchors` (PEM).
    ///
    /// # Errors
    ///
    /// Anchors that hold no certificate, in words.
    pub fn new(relay: Vec<String>, anchors: &str) -> Result<Self, String> {
        let anchors = Anchors::from_pem(anchors).map_err(|failed| failed.to_string())?;
        if anchors.is_empty() {
            return Err("[operate] relay needs anchors that hold a certificate".to_string());
        }
        Ok(Self { relay, anchors })
    }

    /// Whether `who` — the identity a connection proved — is one `relay`
    /// names, without regard to case.
    #[must_use]
    pub fn relays(&self, who: &str) -> bool {
        self.relay
            .iter()
            .any(|relay| relay.trim().eq_ignore_ascii_case(who))
    }
}

/// One caller a relay vouched for.
struct Vouched {
    identity: AuthenticatedIdentity,
    until: i64,
    through: String,
}

fn vouched() -> MutexGuard<'static, HashMap<u64, Vouched>> {
    static VOUCHED: OnceLock<Mutex<HashMap<u64, Vouched>>> = OnceLock::new();
    VOUCHED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The caller `leaf` (DER) proves, vouched for `through` a relay: verified
/// against the anchors `relaying` holds and run through the node's own
/// gate, and held until its certificate ends; the node's handle.
///
/// # Errors
///
/// The certificate, its verification, the gate or a full registry, in
/// words.
pub fn vouch(relaying: &Relaying, through: &str, leaf: &[u8]) -> Result<u64, String> {
    let at = now();
    let chain = Chain::from_der(&[leaf]).map_err(|failed| failed.to_string())?;
    verify(&chain, &relaying.anchors, Usage::ClientAuth, None, at)
        .map_err(|failed| format!("REFUSED. The caller's certificate: {failed}"))?;
    let identity = caller::certificate(leaf)?;
    if !identity.verified.is_proven() {
        return Err(format!("REFUSED. {} is not proven", identity.value));
    }
    let until = not_after_of(leaf).map_err(|failed| failed.to_string())?;
    let mut held = vouched();
    if held.len() >= MOST {
        held.retain(|_, caller| caller.until > at);
        if held.len() >= MOST {
            return Err(format!(
                "REFUSED. The node holds {MOST} relayed callers already"
            ));
        }
    }
    let handle = drawn(|taken| held.contains_key(&taken));
    held.insert(
        handle,
        Vouched {
            identity,
            until,
            through: through.to_string(),
        },
    );
    Ok(handle)
}

/// The caller the node's `handle` holds, where it was vouched for `through`
/// this very account and its certificate has not ended; `None` — no one —
/// otherwise.
#[must_use]
pub fn proven(handle: u64, through: &str) -> Option<AuthenticatedIdentity> {
    let mut held = vouched();
    let caller = held.get(&handle)?;
    if caller.until <= now() {
        held.remove(&handle);
        return None;
    }
    (caller.through == through).then(|| caller.identity.clone())
}

/// Let the node's `handle` go, where `through` is the account it was
/// vouched for: whether it was.
pub fn unvouch(handle: u64, through: &str) -> bool {
    let mut held = vouched();
    if held
        .get(&handle)
        .is_some_and(|caller| caller.through == through)
    {
        held.remove(&handle);
        return true;
    }
    false
}

/// The answer to a relay's `Vouch`: `{"caller": <handle>}`, or
/// `{"refused": <why>}`.
#[must_use]
pub fn vouched_for(relaying: &Relaying, through: &str, message: &Value) -> Value {
    let leaf = message["certificate"]
        .as_str()
        .ok_or_else(|| "REFUSED. A Vouch names a certificate".to_string())
        .and_then(|text| {
            codec::base64::decode(text).map_err(|failed| format!("REFUSED. {failed}"))
        });
    match leaf.and_then(|leaf| vouch(relaying, through, &leaf)) {
        Ok(handle) => json!({ "caller": handle }),
        Err(refused) => json!({ "refused": refused }),
    }
}

/// The answer to a relay's `Unvouch`: `{"released": <whether>}`.
#[must_use]
pub fn unvouched(through: &str, message: &Value) -> Value {
    let handle = message["caller"].as_u64().unwrap_or(0);
    json!({ "released": unvouch(handle, through) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Authority;

    #[test]
    fn a_caller_is_vouched_for_by_its_certificate_and_known_through_its_relay_alone() {
        let authority = Authority::new();
        let (person, _, anchors) = authority.pem("alice");
        let leaf = Chain::from_pem(&person).expect("a chain").leaf().to_vec();
        let relaying = Relaying::new(vec!["HOST\\gui".to_string()], &anchors).expect("anchors");
        assert!(relaying.relays("host\\GUI") && !relaying.relays("HOST\\other"));

        let handle = vouch(&relaying, "HOST\\gui", &leaf).expect("vouched");
        let caller = proven(handle, "HOST\\gui").expect("the caller");
        assert!(caller.value.contains("alice"), "{}", caller.value);
        assert!(
            proven(handle, "HOST\\other").is_none(),
            "another account's is no one"
        );
        assert!(
            proven(handle ^ 1, "HOST\\gui").is_none(),
            "a forged handle is no one"
        );
        assert!(!unvouch(handle, "HOST\\other"));
        assert!(unvouch(handle, "HOST\\gui"));
        assert!(proven(handle, "HOST\\gui").is_none(), "let go");

        let stranger = Authority::new();
        let (theirs, _, _) = stranger.pem("mallory");
        let leaf = Chain::from_pem(&theirs).expect("a chain").leaf().to_vec();
        let refused = vouch(&relaying, "HOST\\gui", &leaf).expect_err("not under the anchors");
        assert!(
            refused.starts_with("REFUSED. The caller's certificate"),
            "{refused}"
        );
        assert!(Relaying::new(Vec::new(), "").is_err());
    }
}
