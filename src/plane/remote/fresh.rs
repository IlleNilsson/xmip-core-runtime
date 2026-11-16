//! The nonces a web host's runtime keeps of each node it relays to
//! (ADR-0009, amendment 2026-11-02), and the binding a browser's handshake
//! is made under: one nonce of every surface this process follows a node
//! through, taken as the handshake starts (`tls::possession::binding`), so
//! the handshake can be proven to each of those nodes after.
//!
//! Each surface keeps a few of its node's nonces (`Nonces`, `plane::fresh`
//! on the node), by the listener whose certificate the browsers see, and
//! asks for more on a thread of its own before they run out, so a
//! handshake takes one without a round trip. Only a node the follow knows
//! answers is asked while a browser waits; one lost, not yet reached, or
//! that relays for no one binds nothing meanwhile — no browser waits on a
//! node that does not answer. How long a nonce is kept, and a node that
//! refused left, are counted on the surface's Clock (`Shared::clock`;
//! ADR-0068, amendment 2026-11-15).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use xcore::clock::{between, nanos};
use xcore::lock::Locked;

use serde_json::json;
use tls::possession::{BINDING, binding};

use crate::plane::call::NONCES;
use crate::plane::shared::Shared;

/// How long a nonce is kept to bind with: well inside the node's own
/// freshness, so the handshake and the proof after it both fit.
const KEPT: Duration = Duration::from_secs(10);

/// How many are asked for at once.
const AT_ONCE: usize = 8;

/// How long a node that refused nonces is left before it is asked again.
const REFUSED_FOR: Duration = Duration::from_secs(60);

/// A surface's nonces of its node, by the listener each was issued for,
/// each with when it was kept, and until when its node is left for a
/// listener it gave none for: readings of the surface's clock.
#[derive(Default)]
pub(crate) struct Pool {
    nonces: HashMap<Vec<u8>, VecDeque<(Vec<u8>, i128)>>,
    refused_until: HashMap<Vec<u8>, i128>,
    refilling: bool,
}

impl Pool {
    /// Whether `listener`'s node is left at `now`: it gave none less than
    /// [`REFUSED_FOR`] before.
    fn left(&self, listener: &[u8], now: i128) -> bool {
        self.refused_until
            .get(listener)
            .is_some_and(|until| *until > now)
    }

    /// The first nonce kept for `listener` still fresh at `now`, each kept
    /// [`KEPT`] or longer let go, and whether few are left.
    fn fresh(&mut self, listener: &[u8], now: i128) -> (Option<Vec<u8>>, bool) {
        let kept = self.nonces.entry(listener.to_vec()).or_default();
        kept.retain(|(_, taken)| between(*taken, now) < KEPT);
        let nonce = kept.pop_front().map(|(nonce, _)| nonce);
        (nonce, kept.len() < AT_ONCE / 2)
    }

    /// `given` kept for `listener` from `now`; where none was given, its
    /// node left for [`REFUSED_FOR`].
    fn given(&mut self, listener: &[u8], given: Vec<Vec<u8>>, now: i128) {
        if given.is_empty() {
            let until = now.saturating_add(nanos(REFUSED_FOR));
            self.refused_until.insert(listener.to_vec(), until);
            return;
        }
        let kept = self.nonces.entry(listener.to_vec()).or_default();
        kept.extend(given.into_iter().map(|nonce| (nonce, now)));
    }
}

/// What a browser's handshake is bound to: the binding, the nonces bound,
/// in order, and the surfaces whose nodes they are.
pub(crate) struct Bound {
    pub(crate) binding: [u8; BINDING],
    pub(crate) nonces: Vec<Vec<u8>>,
    pub(crate) surfaces: Vec<Weak<Shared>>,
}

fn surfaces() -> std::sync::MutexGuard<'static, Vec<Weak<Shared>>> {
    static SURFACES: Mutex<Vec<Weak<Shared>>> = Mutex::new(Vec::new());
    SURFACES.locked()
}

/// A surface this process follows a node through, its node a relay's to
/// bind a handshake to.
pub(crate) fn surfaced(shared: &Arc<Shared>) {
    let mut known = surfaces();
    known.retain(|one| one.strong_count() > 0);
    known.push(Arc::downgrade(shared));
}

/// A nonce of every live surface's node for the listener whose leaf
/// certificate is `listener` (DER), and their binding.
pub(crate) fn bound(listener: &[u8]) -> Bound {
    let live: Vec<Arc<Shared>> = surfaces().iter().filter_map(Weak::upgrade).collect();
    let mut bound = Bound {
        binding: [0; BINDING],
        nonces: Vec::new(),
        surfaces: Vec::new(),
    };
    for shared in live.iter().filter(|shared| !shared.ending()) {
        if let Some(nonce) = taken(shared, listener) {
            bound.nonces.push(nonce);
            bound.surfaces.push(Arc::downgrade(shared));
        }
    }
    let listed: Vec<&[u8]> = bound.nonces.iter().map(Vec::as_slice).collect();
    bound.binding = binding(&listed);
    bound
}

/// One fresh nonce of `shared`'s node for `listener`: one kept, more asked
/// for behind it where few are left; asked for now only where the follow
/// knows the node answers, and in the background otherwise.
fn taken(shared: &Arc<Shared>, listener: &[u8]) -> Option<Vec<u8>> {
    let now = shared.clock.monotonic_nanos();
    let reached = shared.state.locked().reachable;
    let (nonce, low) = {
        let mut pool = shared.fresh.locked();
        if pool.left(listener, now) {
            return None;
        }
        pool.fresh(listener, now)
    };
    match nonce {
        Some(nonce) => {
            if low {
                refill_behind(shared, listener);
            }
            Some(nonce)
        }
        None if reached => {
            refill(shared, listener);
            let mut pool = shared.fresh.locked();
            let kept = pool.nonces.entry(listener.to_vec()).or_default();
            kept.pop_front().map(|(nonce, _)| nonce)
        }
        None => {
            refill_behind(shared, listener);
            None
        }
    }
}

/// Ask `shared`'s node for nonces on a thread of its own, one ask at a
/// time.
fn refill_behind(shared: &Arc<Shared>, listener: &[u8]) {
    {
        let mut pool = shared.fresh.locked();
        if pool.refilling {
            return;
        }
        pool.refilling = true;
    }
    let (weak, listener) = (Arc::downgrade(shared), listener.to_vec());
    let spawned = std::thread::Builder::new()
        .name("xmip-operate-nonces".to_string())
        .spawn(move || {
            if let Some(shared) = weak.upgrade() {
                refill(&shared, &listener);
            }
        });
    if spawned.is_err() {
        shared.fresh.locked().refilling = false;
    }
}

/// Ask `shared`'s node for nonces for `listener` and keep them; a node that
/// gives none is left for a while.
fn refill(shared: &Shared, listener: &[u8]) {
    let asked = json!({ "count": AT_ONCE, "listener": codec::base64::encode(listener) });
    let answer = shared.called(NONCES, &asked, None).ok();
    let given: Vec<Vec<u8>> = answer
        .as_ref()
        .and_then(|answer| answer["nonces"].as_array())
        .map(|nonces| {
            nonces
                .iter()
                .filter_map(|one| one.as_str().and_then(|hex| codec::hex::decode(hex).ok()))
                .collect()
        })
        .unwrap_or_default();
    let now = shared.clock.monotonic_nanos();
    let mut pool = shared.fresh.locked();
    pool.refilling = false;
    pool.given(listener, given, now);
}

#[cfg(test)]
mod tests {
    use xcore::Clock;
    use xcore::clock::Stepped;

    use super::*;

    #[test]
    fn a_nonce_kept_goes_stale_and_a_node_that_gave_none_is_asked_again_on_the_clock() {
        let clock = Stepped::default();
        let mut pool = Pool::default();
        let one = |pool: &mut Pool| pool.fresh(b"leaf", clock.monotonic_nanos()).0;
        let given = vec![b"one".to_vec(), b"two".to_vec()];
        pool.given(b"leaf", given, clock.monotonic_nanos());
        clock.pass(KEPT.checked_sub(Duration::from_nanos(1)).expect("seconds"));
        assert_eq!(one(&mut pool), Some(b"one".to_vec()), "fresh within");
        clock.pass(Duration::from_nanos(1));
        assert_eq!(one(&mut pool), None, "stale at its span, and let go");

        pool.given(b"leaf", Vec::new(), clock.monotonic_nanos());
        assert!(pool.left(b"leaf", clock.monotonic_nanos()));
        clock.pass(
            REFUSED_FOR
                .checked_sub(Duration::from_nanos(1))
                .expect("seconds"),
        );
        assert!(pool.left(b"leaf", clock.monotonic_nanos()), "left within");
        clock.pass(Duration::from_nanos(1));
        assert!(!pool.left(b"leaf", clock.monotonic_nanos()), "asked again");
    }
}
