//! The callers the runtime proved, held for a host behind opaque handles
//! (ADR-0009, amendment 2026-11-01; `xmip_operate.h` sections 18 and 21).
//!
//! A host acts as a caller only by a handle the runtime handed out: the
//! authentication gate answered the caller (`plane::caller`), the identity
//! it answered is kept here, and the host carries the handle — never a name
//! — back to the one check every act passes (`plane::role::act_admitted`).
//! A handle is a number drawn from the operating system's random source
//! (`plane::handle`), never 0, which is no one; one unknown, released,
//! revoked, expired or forged is no one too.
//!
//! **How long one lives.** A handle is its holder's until it is released;
//! each holder takes a handle of its own ([`again`]), so a browser's
//! circuit, which outlives the connection that proved it, holds its own and
//! releases it when it ends. It never outlives what proved it: no longer
//! than the certificate's validity window, and every handle a listener's
//! sessions proved is revoked when that listener stops ([`revoke`]). At
//! most [`MOST`] are held at once; past that, the expired are dropped and,
//! where none is, the next caller is no one rather than the process's
//! memory unbounded.
//!
//! **This is a cache of what the nodes said** (ADR-0009, amendment
//! 2026-11-01, the relay): every holder of one caller shares one
//! [`Proof`] — the identity, the certificate that proved it, and the handle
//! each node it was vouched to issued (`plane::remote::relayed`). When the
//! last holder lets it go, each node is told (`Unvouch`), so no node acts
//! for a caller no host holds.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use context::AuthenticatedIdentity;

use crate::plane::handle::{drawn, now};

/// How many callers are held at once, at most: far more than the browsers
/// one web host serves.
pub const MOST: usize = 65_536;

/// What proved a held caller, so stopping it revokes everything it proved:
/// one per listener.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Prover(u64);

impl Prover {
    /// A prover no other in this process is.
    #[must_use]
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// What a node said for a caller: the handle it issued, under the key of
/// the surface that asked it, and what tells it the caller is let go.
struct Vouch {
    at: u64,
    handle: u64,
    ended: Option<Box<dyn FnOnce(u64) + Send>>,
}

/// One caller every holder of it shares: who the gate answered, the leaf
/// certificate that proved it where one did, and what each node said.
pub struct Proof {
    identity: AuthenticatedIdentity,
    leaf: Option<Vec<u8>>,
    vouched: Mutex<Vec<Vouch>>,
    refusals: Mutex<Vec<(u64, String)>>,
}

impl Proof {
    /// Who the gate answered.
    #[must_use]
    pub const fn identity(&self) -> &AuthenticatedIdentity {
        &self.identity
    }

    /// The leaf certificate that proved it, DER; `None` for a caller the
    /// operating system proved, which no node is vouched for.
    #[must_use]
    pub fn leaf(&self) -> Option<&[u8]> {
        self.leaf.as_deref()
    }

    /// The handle the node at `at` issued for this caller, if it did.
    #[must_use]
    pub fn vouched_at(&self, at: u64) -> Option<u64> {
        self.vouches()
            .iter()
            .find(|vouch| vouch.at == at)
            .map(|vouch| vouch.handle)
    }

    /// The node at `at` issued `handle` for this caller; `ended` is told it
    /// when the last holder lets the caller go.
    pub fn vouched(&self, at: u64, handle: u64, ended: Box<dyn FnOnce(u64) + Send>) {
        let replaced = {
            let mut vouches = self.vouches();
            let replaced = vouches
                .iter()
                .position(|vouch| vouch.at == at)
                .map(|place| vouches.swap_remove(place));
            vouches.push(Vouch {
                at,
                handle,
                ended: Some(ended),
            });
            replaced
        };
        // Two acts vouched at once: the node is told of the one replaced.
        if let Some(Vouch {
            handle,
            ended: Some(ended),
            ..
        }) = replaced
        {
            ended(handle);
        }
    }

    /// The node at `at` refused to vouch for this caller, in `why`: what an
    /// act for the caller there is told.
    pub fn refused(&self, at: u64, why: String) {
        self.refusals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((at, why));
    }

    /// Why the node at `at` refused to vouch for this caller, if it did.
    #[must_use]
    pub fn refusal(&self, at: u64) -> Option<String> {
        self.refusals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(refused, _)| *refused == at)
            .map(|(_, why)| why.clone())
    }

    fn vouches(&self) -> MutexGuard<'_, Vec<Vouch>> {
        self.vouched.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for Proof {
    fn drop(&mut self) {
        let vouched = self
            .vouched
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        for vouch in vouched.iter_mut() {
            if let Some(ended) = vouch.ended.take() {
                ended(vouch.handle);
            }
        }
    }
}

/// One holder's handle: the caller it shares, until when, and what proved
/// it.
struct Held {
    proof: Arc<Proof>,
    until: Option<i64>,
    by: Option<Prover>,
}

impl Held {
    fn live(&self, now: i64) -> bool {
        self.until.is_none_or(|until| until > now)
    }
}

/// Every caller held, and the provers revoked: a prover once stopped proves
/// no one after, so a session it handed over before is held by no one.
#[derive(Default)]
struct Holding {
    callers: HashMap<u64, Held>,
    revoked: HashSet<Prover>,
}

fn held() -> MutexGuard<'static, Holding> {
    static HELD: OnceLock<Mutex<Holding>> = OnceLock::new();
    HELD.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Hold `identity` — what the authentication gate answered — until `until`
/// (seconds since the Unix epoch; `None`, as long as its holder keeps it),
/// proved by `by` and, where a certificate proved it, by the `leaf` (DER):
/// the handle its holder carries, or 0 — no one — for an identity the gate
/// did not call proven, or where [`MOST`] are held.
#[must_use]
pub fn hold(
    identity: AuthenticatedIdentity,
    until: Option<i64>,
    by: Option<Prover>,
    leaf: Option<Vec<u8>>,
) -> u64 {
    if !identity.verified.is_proven() {
        return 0;
    }
    let proof = Arc::new(Proof {
        identity,
        leaf,
        vouched: Mutex::default(),
        refusals: Mutex::default(),
    });
    held_again(proof, until, by)
}

/// `proof` held by one more holder, its handle; 0 where it may not be.
fn held_again(proof: Arc<Proof>, until: Option<i64>, by: Option<Prover>) -> u64 {
    let at = now();
    if until.is_some_and(|until| until <= at) {
        return 0;
    }
    let mut dropped = Vec::new();
    let handle = {
        let mut held = held();
        if by.is_some_and(|by| held.revoked.contains(&by)) {
            return 0;
        }
        if held.callers.len() >= MOST {
            held.callers.retain(|_, caller| {
                let live = caller.live(at);
                if !live {
                    dropped.push(Arc::clone(&caller.proof));
                }
                live
            });
            if held.callers.len() >= MOST {
                return 0;
            }
        }
        let handle = drawn(|taken| held.callers.contains_key(&taken));
        held.callers.insert(handle, Held { proof, until, by });
        handle
    };
    // Each node a caller let go was vouched to is told after the lock.
    drop(dropped);
    handle
}

/// The caller `handle` holds, shared by every holder of it, where it is
/// held and its time has not passed; `None` — no one — otherwise. An
/// expired handle is dropped here.
#[must_use]
pub fn proof(handle: u64) -> Option<Arc<Proof>> {
    if handle == 0 {
        return None;
    }
    let mut held = held();
    let caller = held.callers.get(&handle)?;
    if caller.live(now()) {
        return Some(Arc::clone(&caller.proof));
    }
    let expired = held.callers.remove(&handle);
    drop(held);
    drop(expired);
    None
}

/// Who the caller `handle` holds is, as [`proof`] finds it.
#[must_use]
pub fn proven(handle: u64) -> Option<AuthenticatedIdentity> {
    proof(handle).map(|proof| proof.identity.clone())
}

/// Another holder of the caller `handle` holds: a handle of its own, for as
/// long and revoked by the same; 0 where `handle` is no one.
#[must_use]
pub fn again(handle: u64) -> u64 {
    let found = {
        let held = held();
        held.callers
            .get(&handle)
            .filter(|caller| caller.live(now()))
            .map(|caller| (Arc::clone(&caller.proof), caller.until, caller.by))
    };
    found.map_or(0, |(proof, until, by)| held_again(proof, until, by))
}

/// Release `handle`: after this it is no one. Whether it was held.
pub fn release(handle: u64) -> bool {
    let released = held().callers.remove(&handle);
    released.is_some()
}

/// Revoke every caller `by` proved: each of their handles is no one after.
pub fn revoke(by: Prover) {
    let mut revoked = Vec::new();
    {
        let mut held = held();
        held.revoked.insert(by);
        held.callers.retain(|_, caller| {
            let kept = caller.by != Some(by);
            if !kept {
                revoked.push(Arc::clone(&caller.proof));
            }
            kept
        });
    }
    drop(revoked);
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Verified;
    use xcore::{Established, mechanism};

    fn caller(verified: Verified) -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=a",
            Established::Passed,
            verified,
        )
    }

    #[test]
    fn a_held_caller_is_its_identity_until_released_and_a_forged_handle_is_no_one() {
        let handle = hold(caller(Verified::Proven), None, None, None);
        assert_ne!(handle, 0);
        assert_eq!(proven(handle).expect("held").value, "CN=a");
        assert!(proven(handle ^ 1).is_none(), "a handle never handed out");
        assert!(proven(0).is_none());
        assert!(release(handle));
        assert!(proven(handle).is_none(), "released");
        assert!(!release(handle));
    }

    #[test]
    fn only_a_proven_identity_is_held_and_never_past_its_end() {
        for weaker in [Verified::Vouched, Verified::Claimed, Verified::Refused] {
            assert_eq!(hold(caller(weaker), None, None, None), 0);
        }
        assert_eq!(
            hold(caller(Verified::Proven), Some(now() - 1), None, None),
            0
        );
        let ending = hold(caller(Verified::Proven), Some(now() + 2), None, None);
        assert!(proven(ending).is_some());
        held().callers.get_mut(&ending).expect("held").until = Some(now() - 1);
        assert!(proven(ending).is_none(), "its certificate has ended");
        assert!(!release(ending), "dropped when it was asked after");
    }

    #[test]
    fn each_holder_has_its_own_handle_and_a_stop_revokes_what_it_proved() {
        let listener = Prover::next();
        let session = hold(caller(Verified::Proven), None, Some(listener), None);
        let circuit = again(session);
        assert!(circuit != 0 && circuit != session);
        assert!(release(session));
        assert!(
            proven(circuit).is_some(),
            "the circuit outlives the session"
        );
        assert_eq!(again(session), 0, "a released handle holds no one");
        let other = hold(caller(Verified::Proven), None, Some(Prover::next()), None);
        revoke(listener);
        assert!(proven(circuit).is_none(), "revoked with its listener");
        let late = hold(caller(Verified::Proven), None, Some(listener), None);
        assert_eq!(late, 0, "a stopped listener proves no one after");
        assert!(proven(other).is_some(), "another listener's stays");
        assert!(release(other));
    }

    #[test]
    fn every_node_a_caller_was_vouched_to_is_told_when_its_last_holder_lets_go() {
        let told = Arc::new(Mutex::new(Vec::new()));
        let session = hold(caller(Verified::Proven), None, None, Some(vec![1]));
        let shared = proof(session).expect("held");
        let heard = Arc::clone(&told);
        shared.vouched(
            7,
            42,
            Box::new(move |handle| heard.lock().expect("told").push(handle)),
        );
        assert_eq!(
            (shared.vouched_at(7), shared.vouched_at(8)),
            (Some(42), None)
        );
        drop(shared);
        let circuit = again(session);
        assert!(release(session));
        assert!(
            told.lock().expect("told").is_empty(),
            "the circuit holds it"
        );
        assert!(release(circuit));
        assert_eq!(*told.lock().expect("told"), [42]);
    }
}
