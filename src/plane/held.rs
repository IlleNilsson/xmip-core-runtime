//! The callers the runtime proved, held for a host behind opaque handles
//! (ADR-0009, amendment 2026-11-01; `xmip_operate.h` sections 18 and 21).
//!
//! A host acts as a caller only by a handle the runtime handed out: the
//! authentication gate answered the caller (`plane::caller`), the identity
//! it answered is kept here, and the host carries the handle — never a name
//! — back to the one check every act passes (`plane::role::act_admitted`).
//! A handle is a number drawn from the operating system's random source
//! (`codec::random`), never 0, which is no one; one unknown, released,
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

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use context::AuthenticatedIdentity;

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

/// One caller held: who the gate answered, until when, and what proved it.
struct Held {
    identity: AuthenticatedIdentity,
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

impl core::ops::Deref for Holding {
    type Target = HashMap<u64, Held>;

    fn deref(&self) -> &Self::Target {
        &self.callers
    }
}

impl core::ops::DerefMut for Holding {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.callers
    }
}

fn held() -> MutexGuard<'static, Holding> {
    static HELD: OnceLock<Mutex<Holding>> = OnceLock::new();
    HELD.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Now, in seconds since the Unix epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Hold `identity` — what the authentication gate answered — until `until`
/// (seconds since the Unix epoch; `None`, as long as its holder keeps it),
/// proved by `by`: the handle its holder carries, or 0 — no one — for an
/// identity the gate did not call proven, or where [`MOST`] are held.
#[must_use]
pub fn hold(identity: AuthenticatedIdentity, until: Option<i64>, by: Option<Prover>) -> u64 {
    let at = now();
    if !identity.verified.is_proven() || until.is_some_and(|until| until <= at) {
        return 0;
    }
    let mut held = held();
    if by.is_some_and(|by| held.revoked.contains(&by)) {
        return 0;
    }
    if held.len() >= MOST {
        held.retain(|_, caller| caller.live(at));
        if held.len() >= MOST {
            return 0;
        }
    }
    let handle = loop {
        let drawn = u64::from_ne_bytes(codec::random::array());
        if drawn != 0 && !held.contains_key(&drawn) {
            break drawn;
        }
    };
    held.insert(
        handle,
        Held {
            identity,
            until,
            by,
        },
    );
    handle
}

/// The caller `handle` holds, where it is held and its time has not
/// passed; `None` — no one — otherwise. An expired handle is dropped here.
#[must_use]
pub fn proven(handle: u64) -> Option<AuthenticatedIdentity> {
    if handle == 0 {
        return None;
    }
    let mut held = held();
    if !held.get(&handle)?.live(now()) {
        held.remove(&handle);
        return None;
    }
    held.get(&handle).map(|caller| caller.identity.clone())
}

/// Another holder of the caller `handle` holds: a handle of its own, for as
/// long and revoked by the same; 0 where `handle` is no one.
#[must_use]
pub fn again(handle: u64) -> u64 {
    let found = {
        let held = held();
        held.get(&handle)
            .filter(|caller| caller.live(now()))
            .map(|caller| (caller.identity.clone(), caller.until, caller.by))
    };
    found.map_or(0, |(identity, until, by)| hold(identity, until, by))
}

/// Release `handle`: after this it is no one. Whether it was held.
pub fn release(handle: u64) -> bool {
    held().remove(&handle).is_some()
}

/// Revoke every caller `by` proved: each of their handles is no one after.
pub fn revoke(by: Prover) {
    let mut held = held();
    held.revoked.insert(by);
    held.retain(|_, caller| caller.by != Some(by));
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
        let handle = hold(caller(Verified::Proven), None, None);
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
            assert_eq!(hold(caller(weaker), None, None), 0);
        }
        assert_eq!(hold(caller(Verified::Proven), Some(now() - 1), None), 0);
        let ending = hold(caller(Verified::Proven), Some(now() + 2), None);
        assert!(proven(ending).is_some());
        held().get_mut(&ending).expect("held").until = Some(now() - 1);
        assert!(proven(ending).is_none(), "its certificate has ended");
        assert!(!release(ending), "dropped when it was asked after");
    }

    #[test]
    fn each_holder_has_its_own_handle_and_a_stop_revokes_what_it_proved() {
        let listener = Prover::next();
        let session = hold(caller(Verified::Proven), None, Some(listener));
        let circuit = again(session);
        assert!(circuit != 0 && circuit != session);
        assert!(release(session));
        assert!(
            proven(circuit).is_some(),
            "the circuit outlives the session"
        );
        assert_eq!(again(session), 0, "a released handle holds no one");
        let other = hold(caller(Verified::Proven), None, Some(Prover::next()));
        revoke(listener);
        assert!(proven(circuit).is_none(), "revoked with its listener");
        let late = hold(caller(Verified::Proven), None, Some(listener));
        assert_eq!(late, 0, "a stopped listener proves no one after");
        assert!(proven(other).is_some(), "another listener's stays");
        assert!(release(other));
    }
}
