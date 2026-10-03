//! `xmip_operate.h` section 11, who may subscribe: the program hosting this
//! library hands the process's hub its policy, as a Rust program hands
//! `xevent::hub::Hub::authorize_by` an `authorize::Authorizer` (ADR-0065,
//! amendment 2026-09-26: being in the process admits nobody, and who may
//! subscribe is a policy and nothing beside it).
//!
//! Across the language boundary the trait is a callback: asked for each
//! attempt with the accountable identity — the Party it resolved to, its
//! mechanism and value — and the attempt's artifact and Contract, it answers
//! allow, deny, or no opinion. The gate around it, the order of policies and
//! what no opinion means are `authorize::authorize`'s.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::Arc;

use abi::ffi::status;
use abi::operate::event::{Authorizer as Decide, decision};
use authorize::{Attempt, Authorizer, Decision};
use context::IdentityFacts;
use xcore::Layer;
use xevent::hub::Hub;

use crate::ffi::operate::borrow;

/// The name a denial by the hosting program's policy carries.
const NAME: &str = "hosting-program";

/// The hosting program's callback and its context, as an `Authorizer`.
struct Hosted {
    decide: Decide,
    context: Context,
}

/// The program's context, handed back to its callback.
struct Context(*mut c_void);

// SAFETY: the header makes the context the program's, read only by its own
// callback, which the program makes safe to call from any thread.
unsafe impl Send for Context {}
// SAFETY: as above; the runtime never reads or writes through it.
unsafe impl Sync for Context {}

impl Authorizer for Hosted {
    fn name(&self) -> &'static str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let accountable = identity.accountable();
        let party = accountable
            .party_id
            .map(|party| party.to_string())
            .unwrap_or_default();
        let contract = attempt.contract.as_deref().unwrap_or("");
        // SAFETY: every string borrows a local that outlives the call; the
        // callback and its context are the program's, per the header.
        let answer = unsafe {
            (self.decide)(
                self.context.0,
                borrow(&party),
                borrow(accountable.mechanism.name()),
                borrow(&accountable.value),
                borrow(&attempt.artifact),
                borrow(contract),
            )
        };
        match answer {
            decision::ALLOW => Some(Decision::Allowed),
            decision::DENY => Some(Decision::denied(
                NAME,
                format!("Party {party} may not subscribe to '{}'", attempt.artifact),
            )),
            _ => None,
        }
    }
}

/// `xevent::hub::Hub::authorize_by` on the process's hub, with the program's
/// callback as its one policy; a null callback hands it none.
///
/// # Safety
/// `decide` is null or callable with `context` from any thread until it is
/// replaced, and returns one of the header's decisions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_authorize_v1(
    decide: Option<Decide>,
    context: *mut c_void,
) -> i32 {
    let policies: Vec<Arc<dyn Authorizer>> = decide
        .map(|decide| {
            Arc::new(Hosted {
                decide,
                context: Context(context),
            }) as Arc<dyn Authorizer>
        })
        .into_iter()
        .collect();
    Hub::process().authorize_by(policies);
    status::OK
}

/// The test policy every test of section 11 hands the process's hub: the
/// two Parties those tests subscribe as.
#[cfg(test)]
pub(crate) mod allowed {
    use super::*;
    use crate::ffi::operate::scope_text;
    use abi::ffi::Str;

    /// The Parties allowed.
    pub(crate) const PARTIES: [&str; 2] = [
        "0198a3c4-0000-7000-8000-000000000042",
        "00000000-0000-0000-0000-000000000009",
    ];

    extern "C" fn decide(_: *mut c_void, party: Str, _: Str, _: Str, _: Str, _: Str) -> i32 {
        // SAFETY: the runtime hands a string it borrows for the call.
        let party = unsafe { scope_text(party) }.unwrap_or("");
        if PARTIES.contains(&party) {
            decision::ALLOW
        } else {
            decision::NONE
        }
    }

    /// Hand the process's hub the test policy.
    pub(crate) fn policy() {
        // SAFETY: a callback of the header's shape, needing no context.
        let code = unsafe { xmip_event_authorize_v1(Some(decide), core::ptr::null_mut()) };
        assert_eq!(code, status::OK);
    }
}
