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
//! node that does not answer.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
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
/// and until when its node is left for a listener it gave none for.
#[derive(Default)]
pub(crate) struct Pool {
    nonces: HashMap<Vec<u8>, VecDeque<(Vec<u8>, Instant)>>,
    refused_until: HashMap<Vec<u8>, Instant>,
    refilling: bool,
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
    let now = Instant::now();
    let reached = shared.state.locked().reachable;
    let (nonce, low) = {
        let mut pool = shared.fresh.locked();
        if pool
            .refused_until
            .get(listener)
            .is_some_and(|until| *until > now)
        {
            return None;
        }
        let kept = pool.nonces.entry(listener.to_vec()).or_default();
        kept.retain(|(_, taken)| now - *taken < KEPT);
        let nonce = kept.pop_front().map(|(nonce, _)| nonce);
        (nonce, kept.len() < AT_ONCE / 2)
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
    let now = Instant::now();
    let mut pool = shared.fresh.locked();
    pool.refilling = false;
    if given.is_empty() {
        pool.refused_until
            .insert(listener.to_vec(), now + REFUSED_FOR);
        return;
    }
    let kept = pool.nonces.entry(listener.to_vec()).or_default();
    kept.extend(given.into_iter().map(|nonce| (nonce, now)));
}
