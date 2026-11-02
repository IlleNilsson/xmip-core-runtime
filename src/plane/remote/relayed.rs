//! A surface relaying for a caller its host's runtime holds (ADR-0009,
//! amendment 2026-11-01: the node decides). A web host's caller is held in
//! this process (`plane::held`); the node is handed the certificate that
//! proved it (`Vouch`) and answers a handle of its own, which every call
//! for that caller names (`call::CALLER_HEADER`) — kept on the caller's
//! shared proof, one per node, and asked once. When the last holder lets
//! the caller go, the node is told (`Unvouch`) on the surface's own
//! bounded line. A caller the operating system proved for this process —
//! a desktop's — is this side's own connection, and is asked as it.

use std::sync::{Arc, Weak};

use serde_json::{Value, json};

use crate::plane::call::{REFUSED_CALL, SECRETS, UNKNOWN_CALLER, UNVOUCH, VOUCH};
use crate::plane::held::{self, Proof};
use crate::plane::remote::Remote;
use crate::plane::role::{Role, admitted};
use crate::plane::shared::Shared;

impl Remote {
    /// `method` with `message`, for the caller the handle `held` holds in
    /// this process: as this side's own connection for 0 or a caller the
    /// operating system proved, for the caller the node vouched for
    /// otherwise, vouching first where it has not; and no one — refused in
    /// the method's own answer — for a handle that holds no one.
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
        let Some(leaf) = proof.leaf() else {
            return self.asked(method, message);
        };
        let at = key(&self.shared);
        for _ in 0..2 {
            let node = match proof.vouched_at(at) {
                Some(node) => node,
                None => match self.vouch(&proof, leaf, at)? {
                    Ok(node) => node,
                    Err(refused) => return Ok(nobody(method, &refused)),
                },
            };
            let answer = self.asked_for(method, message, Some(node))?;
            if said(&answer) != UNKNOWN_CALLER {
                return Ok(answer);
            }
            // The node holds the caller no longer — it started again —
            // so it is vouched for once more.
            proof.forget(at);
        }
        Ok(nobody(method, UNKNOWN_CALLER))
    }

    /// The node's handle for the caller `leaf` (DER) proved, asked of the
    /// node and kept on `proof` under `at`, the node told when the caller
    /// is let go; or the node's refusal.
    fn vouch(
        &self,
        proof: &Arc<Proof>,
        leaf: &[u8],
        at: u64,
    ) -> Result<Result<u64, String>, String> {
        let message = json!({ "certificate": codec::base64::encode(leaf) });
        let answer = match self.asked(VOUCH, &message) {
            Ok(answer) => answer,
            Err(why) if why.starts_with(REFUSED_CALL) => return Ok(Err(why)),
            Err(why) => return Err(why),
        };
        let Some(node) = answer["caller"].as_u64() else {
            return Ok(Err(said(&answer).to_string()));
        };
        let shared = Arc::downgrade(&self.shared);
        proof.vouched(at, node, Box::new(move |node| unvouch(&shared, node)));
        Ok(Ok(node))
    }
}

/// Tell the node a caller it vouched for is let go, on a thread of its own
/// so the holder letting go waits for no node, through the surface's own
/// bounded line; nothing where the surface has ended.
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
