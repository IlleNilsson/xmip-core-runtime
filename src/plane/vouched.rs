//! The callers a relay vouched for, held by the node (ADR-0009, amendment
//! 2026-11-01: the node decides, not the host).
//!
//! A web host takes a browser's TLS and proves its caller in its own
//! process (`plane::held`); a hostile host in that process could act as
//! its own account. So the node keeps the authority: an account
//! `[operate] relay` names hands the node the browser's handshake
//! (`Vouch`), which proves the browser held its key in a handshake bound to
//! the node's own fresh nonce, to the relay's own listener
//! (`plane::possessed`); the node verifies the browser's chain against its
//! own `[operate] anchors` for client authentication and runs it through
//! its own gate (`plane::caller::certificate`), and only then issues a
//! handle of its own. On a call that names that handle (`call::CALLER_HEADER`) the act is
//! the browser caller's and admitted by the caller's own role — never the
//! relay's — and only where the handle was issued to the very account the
//! call comes through, before its certificate's `notAfter`, and not yet
//! let go (`Unvouch`). A handle presented by any other account is no one.
//! Relaying grants no act of its own: the relay's own calls are judged by
//! its own role as any caller's.
//!
//! The limit: a compromised host can act only for a browser that made a
//! fresh handshake with it holding its key, and — since it keeps the handle
//! — for as long as it does not let it go, until the browser's certificate
//! ends or the node starts again; within that browser's role and visibly in
//! the node's audit (`through`). It can neither make up an identity nor
//! replay a certificate it once saw.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use authenticate::x509::{Anchors, Chain, Usage, not_after_of, verify};
use context::AuthenticatedIdentity;
use serde_json::{Value, json};

use crate::plane::caller;
use crate::plane::fresh::Fresh;
use crate::plane::handle::{drawn, now};

/// How many callers a node holds for its relays at once, at most.
pub const MOST: usize = 65_536;

/// How many browsers' verified chains a node keeps at once, at most.
pub const KNOWN: usize = 1024;

/// Who may relay for a caller, and what the caller's certificate must
/// reach — `[operate] relay` and `[operate] anchors` — with what one node
/// holds for its relays: the nonces it issued (`plane::fresh`) and the
/// callers it vouched for, its own and no other node's in the process.
pub struct Relaying {
    relay: Vec<String>,
    anchors: Anchors,
    /// The nonces issued the relays.
    pub fresh: Fresh,
    vouched: Mutex<HashMap<u64, Vouched>>,
    /// The browsers' chains already verified and run through the gate,
    /// until their leaves end: a browser opens several connections with one
    /// certificate, and each proves its possession again, not its chain.
    known: Mutex<HashMap<Vec<Vec<u8>>, Known>>,
}

/// A browser's verified caller and until when its leaf is valid.
type Known = (AuthenticatedIdentity, i64);

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
        Ok(Self {
            relay,
            anchors,
            fresh: Fresh::default(),
            vouched: Mutex::default(),
            known: Mutex::default(),
        })
    }

    /// Whether `who` — the identity a connection proved — is one `relay`
    /// names, without regard to case.
    #[must_use]
    pub fn relays(&self, who: &str) -> bool {
        self.relay
            .iter()
            .any(|relay| relay.trim().eq_ignore_ascii_case(who))
    }

    fn held(&self) -> MutexGuard<'_, HashMap<u64, Vouched>> {
        self.vouched.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A browser's `chain` verified for client authentication and run
    /// through the gate ([`verified`]), once while its leaf is valid; at most
    /// [`KNOWN`] chains are kept, and past that all are let go and verified
    /// again.
    fn verified_once(&self, chain: &[Vec<u8>]) -> Result<Known, String> {
        let at = now();
        let mut known = self.known.lock().unwrap_or_else(PoisonError::into_inner);
        known.retain(|_, (_, until)| *until > at);
        if let Some(kept) = known.get(chain) {
            return Ok(kept.clone());
        }
        drop(known);
        let verified = verified(self, chain, Usage::ClientAuth)?;
        let mut known = self.known.lock().unwrap_or_else(PoisonError::into_inner);
        if known.len() >= KNOWN {
            known.clear();
        }
        known.insert(chain.to_vec(), verified.clone());
        Ok(verified)
    }
}

/// One caller a relay vouched for.
struct Vouched {
    identity: AuthenticatedIdentity,
    until: i64,
    through: String,
}

/// The caller `chain` (DER, leaf first) proves — verified against the
/// anchors `relaying` holds for `usage` and run through the node's own gate
/// — and until when its leaf is valid.
///
/// # Errors
///
/// The chain, its verification or the gate, in words.
pub fn verified(relaying: &Relaying, chain: &[Vec<u8>], usage: Usage) -> Result<Known, String> {
    let der: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let leaf = der.first().copied().ok_or("REFUSED. The chain is empty")?;
    let read = Chain::from_der(&der).map_err(|failed| failed.to_string())?;
    verify(&read, &relaying.anchors, usage, None, now())
        .map_err(|failed| format!("REFUSED. The certificate: {failed}"))?;
    let identity = caller::certificate(leaf)?;
    if !identity.verified.is_proven() {
        return Err(format!("REFUSED. {} is not proven", identity.value));
    }
    let until = not_after_of(leaf).map_err(|failed| failed.to_string())?;
    Ok((identity, until))
}

/// The caller `chain` (DER, leaf first) proves ([`verified`]), whose
/// possession of its key a relay's handshake proved (`plane::possessed`),
/// vouched for `through` that relay and held until its certificate ends:
/// the node's handle.
///
/// # Errors
///
/// The chain, its verification, the gate or a full registry, in words.
pub fn vouch(relaying: &Relaying, through: &str, chain: &[Vec<u8>]) -> Result<u64, String> {
    let at = now();
    let (identity, until) = relaying.verified_once(chain)?;
    let mut held = relaying.held();
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
pub fn proven(relaying: &Relaying, handle: u64, through: &str) -> Option<AuthenticatedIdentity> {
    let mut held = relaying.held();
    let caller = held.get(&handle)?;
    if caller.until <= now() {
        held.remove(&handle);
        return None;
    }
    (caller.through == through).then(|| caller.identity.clone())
}

/// Let the node's `handle` go, where `through` is the account it was
/// vouched for: whether it was.
pub fn unvouch(relaying: &Relaying, handle: u64, through: &str) -> bool {
    let mut held = relaying.held();
    if held
        .get(&handle)
        .is_some_and(|caller| caller.through == through)
    {
        held.remove(&handle);
        return true;
    }
    false
}

/// The answer to a relay's `Nonces` — `{"count", "listener": <base64>}`,
/// the leaf certificate of the listener its browsers reach — once that
/// certificate is verified under the node's anchors, here and once rather
/// than at every browser's handshake (`plane::fresh`): `{"nonces": [hex...],
/// "within_ms"}`, or `{"refused": <why>}`.
#[must_use]
pub fn nonces(relaying: &Relaying, connection: &AuthenticatedIdentity, message: &Value) -> Value {
    let listener = message["listener"]
        .as_str()
        .and_then(|text| codec::base64::decode(text).ok())
        .filter(|leaf| !leaf.is_empty());
    let Some(listener) = listener else {
        return json!({ "refused": "REFUSED. Nonces name the listener they are for" });
    };
    if let Err(refused) = verified(relaying, std::slice::from_ref(&listener), Usage::Any) {
        return json!({ "refused": format!("{refused}: the relay's listener (ADR-0009)") });
    }
    let count = usize::try_from(message["count"].as_u64().unwrap_or(1)).unwrap_or(1);
    relaying.fresh.answered(connection, &listener, count)
}

/// The answer to a relay's `Vouch` — `{"transcript": <base64>, "nonces":
/// [hex...]}`, the browser's handshake and every nonce bound into it —
/// once the handshake proves the browser held its key
/// (`plane::possessed`): `{"caller": <handle>}`, or `{"refused": <why>}`.
#[must_use]
pub fn vouched_for(relaying: &Relaying, through: &str, message: &Value) -> Value {
    let transcript = message["transcript"]
        .as_str()
        .ok_or_else(|| "REFUSED. A Vouch hands the browser's handshake".to_string())
        .and_then(|text| {
            codec::base64::decode(text).map_err(|failed| format!("REFUSED. {failed}"))
        });
    let nonces: Vec<Vec<u8>> = message["nonces"]
        .as_array()
        .map(|listed| {
            listed
                .iter()
                .filter_map(|one| one.as_str().and_then(|hex| codec::hex::decode(hex).ok()))
                .collect()
        })
        .unwrap_or_default();
    let proved = transcript.and_then(|transcript| {
        crate::plane::possessed::possessed(relaying, through, &transcript, &nonces)
    });
    match proved.and_then(|chain| vouch(relaying, through, &chain)) {
        Ok(handle) => json!({ "caller": handle }),
        Err(refused) => json!({ "refused": refused }),
    }
}

/// The answer to a relay's `Unvouch`: `{"released": <whether>}`.
#[must_use]
pub fn unvouched(relaying: &Relaying, through: &str, message: &Value) -> Value {
    let handle = message["caller"].as_u64().unwrap_or(0);
    json!({ "released": unvouch(relaying, handle, through) })
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

        let handle = vouch(&relaying, "HOST\\gui", &[leaf]).expect("vouched");
        let caller = proven(&relaying, handle, "HOST\\gui").expect("the caller");
        assert!(caller.value.contains("alice"), "{}", caller.value);
        assert!(
            proven(&relaying, handle, "HOST\\other").is_none(),
            "another account's is no one"
        );
        assert!(
            proven(&relaying, handle ^ 1, "HOST\\gui").is_none(),
            "a forged handle is no one"
        );
        assert!(!unvouch(&relaying, handle, "HOST\\other"));
        assert!(unvouch(&relaying, handle, "HOST\\gui"));
        assert!(proven(&relaying, handle, "HOST\\gui").is_none(), "let go");

        let stranger = Authority::new();
        let (theirs, _, _) = stranger.pem("mallory");
        let leaf = Chain::from_pem(&theirs).expect("a chain").leaf().to_vec();
        let refused = vouch(&relaying, "HOST\\gui", &[leaf]).expect_err("not under the anchors");
        assert!(refused.starts_with("REFUSED. The certificate"), "{refused}");
        assert!(Relaying::new(Vec::new(), "").is_err());
    }
}
