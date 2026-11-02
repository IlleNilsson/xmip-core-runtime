//! A surface relaying for a caller its host's runtime holds (ADR-0009,
//! amendments 2026-11-01 and 2026-11-02: the node decides). A web host's
//! caller is held in this process (`plane::held`); as its browser's
//! handshake finishes, every node it was bound to (`remote::fresh`) is
//! handed that handshake (`Vouch`, [`vouched_everywhere`]) and, once it
//! proves the browser held its key, answers a handle of its own, which
//! every call for that caller names (`call::CALLER_HEADER`), kept on the
//! caller's shared proof, one per node. A node the handshake was not proven
//! to acts for that caller on nothing, and says why. When the last holder
//! lets the caller go, the node is told (`Unvouch`) on the surface's own
//! bounded line. A caller the operating system proved for this process —
//! a desktop's — is this side's own connection, and is asked as it.

use std::sync::Arc;
#[cfg(feature = "node")]
use std::sync::{LazyLock, Weak, mpsc};

use serde_json::{Value, json};

use crate::plane::call::SECRETS;
#[cfg(feature = "node")]
use crate::plane::call::UNVOUCH;
use crate::plane::held;
#[cfg(feature = "node")]
use crate::plane::held::Proof;
use crate::plane::remote::Remote;
use crate::plane::role::{Role, admitted};
use crate::plane::shared::Shared;
#[cfg(feature = "node")]
use crate::plane::workers::Workers;
#[cfg(feature = "node")]
use xcore::spent::Spent;

impl Remote {
    /// `method` with `message`, for the caller the handle `held` holds in
    /// this process: as this side's own connection for 0 or a caller the
    /// operating system proved, for the caller the node vouched for
    /// otherwise; and no one — refused in the method's own answer — for a
    /// handle that holds no one, or a caller this node was not proven.
    ///
    /// # Errors
    ///
    /// Why the node did not answer.
    pub(super) fn relayed(
        &self,
        held: u64,
        method: &str,
        message: &Value,
    ) -> Result<Value, String> {
        if held == 0 {
            return self.asked(method, message);
        }
        let Some(proof) = held::proof(held) else {
            return Ok(nobody(method, &no_one()));
        };
        if proof.leaf().is_none() {
            return self.asked(method, message);
        }
        let at = key(&self.shared);
        let Some(node) = proof.vouched_at(at) else {
            let why = proof.refusal(at).unwrap_or_else(|| {
                format!(
                    "REFUSED. This browser's session was not proven to {}: a session proves \
                     itself to the nodes its host follows as it connects, and does again as \
                     it reconnects (ADR-0009)",
                    self.shared.address
                )
            });
            return Ok(nobody(method, &why));
        };
        self.asked_for(method, message, Some(node))
    }
}

/// Hand every node in `surfaces` the browser's `transcript`, bound to
/// `nonces`, for the caller `proof` holds: each node's handle kept on it,
/// the node told when the caller is let go; each refusal kept to say. The
/// nodes are asked at once — the first on this thread, each other on a
/// thread kept for it (`plane::workers`, since starting one cost more than
/// a node's own check) — so a session's start waits one round trip and the
/// slowest node's check, however many nodes its host follows, and never
/// the sum of them. Each thread's processor time on it is `spent`'s, the
/// session's own share.
#[cfg(feature = "node")]
pub(crate) fn vouched_everywhere(
    proof: &Arc<Proof>,
    surfaces: &[Weak<Shared>],
    transcript: &[u8],
    nonces: &[Vec<u8>],
    spent: &Spent,
) {
    static VOUCHING: LazyLock<Arc<Workers>> =
        LazyLock::new(|| Arc::new(Workers::named("xmip-operate-vouch")));
    let message = Arc::new(json!({
        "transcript": codec::base64::encode(transcript),
        "nonces": nonces.iter().map(|nonce| codec::hex::encode(nonce)).collect::<Vec<_>>(),
    }));
    let mut live = surfaces.iter().filter_map(Weak::upgrade);
    let Some(first) = live.next() else {
        return;
    };
    let (done, finished) = mpsc::channel::<()>();
    let mut asked = 0;
    for shared in live {
        let (kept, handed) = (Arc::clone(&shared), Arc::clone(&message));
        let (proof_kept, done, spent) = (Arc::clone(proof), done.clone(), spent.clone());
        if VOUCHING.run(Box::new(move || {
            let own = spent.entered();
            vouched_by(&proof_kept, &kept, &handed);
            drop(own);
            let _ = done.send(());
        })) {
            asked += 1;
        } else {
            // No thread to be had: this one asks that node itself.
            vouched_by(proof, &shared, &message);
        }
    }
    drop(done);
    vouched_by(proof, &first, &message);
    for _ in 0..asked {
        // bounded: each node's call waits at most its surface's patience,
        // and a thread that ends without saying drops its sender
        if finished.recv().is_err() {
            break;
        }
    }
}

/// One node handed the browser's handshake, `message`, for the caller
/// `proof` holds: its handle kept, or its refusal.
#[cfg(feature = "node")]
fn vouched_by(proof: &Proof, shared: &Arc<Shared>, message: &Value) {
    let at = key(shared);
    match shared.called(crate::plane::call::VOUCH, message, None) {
        Ok(answer) => match answer["caller"].as_u64() {
            Some(node) => {
                let weak = Arc::downgrade(shared);
                proof.vouched(at, node, Box::new(move |node| unvouch(&weak, node)));
            }
            None => proof.refused(at, said(&answer).to_string()),
        },
        Err((_, why)) => proof.refused(at, why),
    }
}

/// Tell the node a caller it vouched for is let go, on a thread of its own
/// so the holder letting go waits for no node, through the surface's own
/// bounded line; nothing where the surface has ended.
#[cfg(feature = "node")]
fn unvouch(shared: &Weak<Shared>, node: u64) {
    let Some(shared) = shared.upgrade() else {
        return;
    };
    if shared.ending() {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("xmip-operate-unvouch".to_string())
        .spawn(move || {
            let _ = shared.called(UNVOUCH, &json!({ "caller": node }), None);
        });
}

/// The key a surface's vouches are kept under on a proof: what it shares,
/// by place, which the proof's own weak reference keeps from being reused.
fn key(shared: &Arc<Shared>) -> u64 {
    Arc::as_ptr(shared) as usize as u64
}

/// The sentence an answer says.
#[cfg(feature = "node")]
fn said(answer: &Value) -> &str {
    answer["said"]
        .as_str()
        .or_else(|| answer["refused"].as_str())
        .unwrap_or_default()
}

/// The one refusal of no one, in the gate's own words.
fn no_one() -> String {
    admitted(
        None,
        Role::Developer,
        crate::plane::call::ACT,
        ("act", "on the node"),
    )
    .err()
    .unwrap_or_default()
}

/// A refusal in the answer `method` gives: the secrets' listing says
/// `refused`, an act or a secret set `denied`.
fn nobody(method: &str, refused: &str) -> Value {
    if method == SECRETS {
        json!({ "refused": refused })
    } else {
        json!({ "outcome": "denied", "said": refused })
    }
}
