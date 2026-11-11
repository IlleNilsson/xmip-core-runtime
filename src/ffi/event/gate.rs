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

use crate::ffi::text::borrow;

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
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        event_authorize(decide, context)
    })
}

/// [`xmip_event_authorize_v1`] within its guard.
unsafe fn event_authorize(decide: Option<Decide>, context: *mut c_void) -> i32 {
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

/// What every test of section 11 stands on: a node serving in this process
/// whose Party holds the account the tests run as, and the policy the tests
/// hand the process's hub, allowing that Party.
#[cfg(test)]
pub(crate) mod allowed {
    use std::sync::LazyLock;

    use super::*;
    use crate::ffi::text::scope_text;
    use crate::parties::Parties;
    use abi::ffi::Str;
    use party::{Identity, Party};
    use xcore::{PartyId, mechanism};

    /// The Party this process proves to be, and the one the policy allows.
    pub(crate) const PARTY: &str = "0198a3c4-0000-7000-8000-000000000042";

    /// Its name, as a node's `[[parties]]` declares it.
    pub(crate) const NAME: &str = "runtime-tests";

    extern "C" fn decide(_: *mut c_void, party: Str, _: Str, _: Str, _: Str, _: Str) -> i32 {
        // SAFETY: the runtime hands a string it borrows for the call.
        let party = unsafe { scope_text(party) }.unwrap_or("");
        if party == PARTY {
            decision::ALLOW
        } else {
            decision::NONE
        }
    }

    /// The Parties a node serving in this process lends it, for the
    /// process's life: [`PARTY`], its `peer-credentials` identity the
    /// account the operating system says the tests run as.
    pub(crate) fn serving() {
        static SERVING: LazyLock<Arc<Parties>> = LazyLock::new(|| {
            let account = crate::plane::local::running_as().expect("the system names it");
            let id: PartyId = PARTY.parse().expect("a UUID");
            let party = Party::new(id, None, NAME)
                .with(Identity::receiving(mechanism::peer_credentials(), account));
            let parties = Arc::new(Parties(vec![party]));
            Parties::serve(&parties);
            parties
        });
        LazyLock::force(&SERVING);
    }

    /// The node's Parties lent, and the test policy handed the hub.
    pub(crate) fn policy() {
        serving();
        // SAFETY: a callback of the header's shape, needing no context.
        let code = unsafe { xmip_event_authorize_v1(Some(decide), core::ptr::null_mut()) };
        assert_eq!(code, status::OK);
    }
}
