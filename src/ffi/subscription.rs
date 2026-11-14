//! `xmip_operate.h` section 14, a node's Subscriptions: every Subscription
//! the nodes of this process route by, and what a read publication carries
//! of them (ADR-0013, amendment 2026-09-30), forwarded.
//!
//! The standing and the hold are `crate::pickup`'s. This writes one list's
//! JSON, once, for this process's nodes and for a read publication alike. A
//! pause or a resume reaches a node through its operate listener's door and
//! Xmip Storage, never here (ADR-0014, amendment 2026-11-13).
#![allow(unsafe_code)]

#[cfg(feature = "node")]
use abi::ffi::Str;
use abi::ffi::status;
use abi::operate::publication::Publication as Handle;
#[cfg(feature = "node")]
use node::Scope;
use observe::{PauseState, Subscription};
use serde_json::{Value, json};

use crate::ffi::publication::held;
use crate::ffi::rule::refuse;
#[cfg(feature = "node")]
use crate::ffi::text::scope_text;
#[cfg(feature = "node")]
use crate::pickup::Pickup;

/// A list of Subscriptions as the header writes it.
fn listed<'a>(subscriptions: impl Iterator<Item = &'a Subscription>) -> String {
    let subscriptions: Vec<Value> = subscriptions
        .map(|subscription| {
            json!({
                "node": subscription.node,
                "name": subscription.name,
                "application": subscription.application,
                "filter": subscription.filter,
                "destination": subscription.destination,
                "send_ports": subscription.send_ports,
                "file": subscription.file,
                "configuration": subscription.configuration,
                "state": subscription.state.word(),
                "paused": subscription.state == PauseState::Paused,
                "by": subscription.by,
                "picked_up": subscription.picked_up,
                "held": subscription.held,
                "since_unix_nanos": subscription.since_unix_nanos,
            })
        })
        .collect();
    json!({ "subscriptions": subscriptions }).to_string()
}

/// Every Subscription of every node in this process at or beneath `node`
/// (empty: all), as `crate::pickup::Pickup::standing` says.
///
/// # Safety
/// `node` points at its stated length of readable bytes; `out` has room for
/// `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node")]
pub unsafe extern "C" fn xmip_subscriptions_v1(
    node: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        subscriptions(node, out, cap, out_len)
    })
}

/// [`xmip_subscriptions_v1`] within its guard.
#[cfg(feature = "node")]
unsafe fn subscriptions(node: Str, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    // SAFETY: the caller upholds the header's contract on `node`.
    let Some(node) = (unsafe { scope_text(node) }) else {
        return status::MALFORMED;
    };
    let within = Scope::new(node);
    let standing: Vec<Subscription> = Pickup::registered()
        .iter()
        .filter(|pickup| within.contains(Scope::new(pickup.node())))
        .flat_map(|pickup| pickup.standing())
        .collect();

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&listed(standing.iter()), out, cap, out_len) };
    status::OK
}

/// What a read publication carries of Subscriptions.
///
/// # Safety
/// `publication` is a live handle; `out` has room for `cap` bytes;
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_subscriptions_v1(
    publication: *const Handle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        publication_subscriptions(publication, out, cap, out_len)
    })
}

/// [`xmip_publication_subscriptions_v1`] within its guard.
unsafe fn publication_subscriptions(
    publication: *const Handle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(read) = (unsafe { held(publication) }) else {
        return status::INVALID;
    };
    let publication = &read.publication;
    let text = listed(publication.subscriptions.iter());

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

#[cfg(all(test, feature = "node"))]
mod tests {
    use std::sync::Arc;

    use observe::Act;

    use super::*;
    use crate::configured_subscription::ConfiguredSubscription;
    use crate::ffi::publication::{xmip_publication_free_v1, xmip_publication_read_v1};
    use crate::ffi::text::borrow;
    use crate::pickup::tests::{published, subscription};

    /// This test's node: the test cluster's first, named apart so no other
    /// test's pickup is listed with it.
    fn node() -> String {
        format!(
            "{}-ffi-subscriptions",
            configure::fixture::test_cluster().node_scope(0)
        )
    }

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::subscription::SubscriptionsFn = xmip_subscriptions_v1;
        let _: abi::operate::subscription::PublicationSubscriptionsFn =
            xmip_publication_subscriptions_v1;
    }

    fn listed_here() -> Value {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut length = 0usize;
        let node = node();
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_subscriptions_v1(
                borrow(&node),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        serde_json::from_slice(&buffer[..length]).expect("JSON")
    }

    #[test]
    fn a_nodes_subscriptions_are_listed_paused_and_resumed_and_never_removed() {
        let billing = subscription("billing");
        let storage = crate::ledger::in_memory();
        let pickup = Pickup::open(
            &node(),
            vec![ConfiguredSubscription::unfiled(billing.clone())],
            Arc::clone(storage),
            None,
        )
        .expect("opened");

        let entry = listed_here()["subscriptions"][0].clone();
        assert_eq!(entry["name"], "billing");
        assert_eq!(entry["state"], "active");
        assert_eq!(entry["destination"], "the Send Port 'Out'");
        assert_eq!(entry["send_ports"], json!(["Out"]), "where its work goes");

        pickup.act("billing", Act::Pause, "ilian").expect("paused");
        let held = published(&pickup, storage.as_ref(), &[billing], "held");
        assert_eq!(held, Ok(1), "held, not picked up");
        let entry = listed_here()["subscriptions"][0].clone();
        assert_eq!(
            (entry["state"].clone(), entry["held"].clone()),
            ("paused".into(), 1.into())
        );

        let refusal = pickup
            .act("billing", Act::Remove, "ilian")
            .expect_err("refused");
        assert!(refusal.contains("TOML configuration"), "{refusal}");
        let refusal = pickup
            .act("shipping", Act::Pause, "ilian")
            .expect_err("refused");
        assert!(refusal.starts_with("REFUSED"), "{refusal}");

        pickup
            .act("billing", Act::Resume, "ilian")
            .expect("resumed");
        let released = pickup.released(std::time::Duration::ZERO, 8);
        assert_eq!(released.len(), 1);
        pickup.moved(&released[0]);
        let entry = listed_here()["subscriptions"][0].clone();
        assert_eq!(
            (entry["held"].clone(), entry["picked_up"].clone()),
            (0.into(), 1.into())
        );
    }

    /// ADR-0018, amendment 2026-11-11: a node that routes by none — it
    /// starts no Receive Location and runs no Work Process — lists none in
    /// section 14, and an act on one is refused in words, as its
    /// publication publishes none (`Pickup::routing_none`).
    #[test]
    fn a_node_that_routes_by_none_lists_none_and_refuses_an_act_in_words() {
        let node = format!(
            "{}-ffi-routing-none",
            configure::fixture::test_cluster().node_scope(1)
        );
        let storage = crate::ledger::in_memory();
        let pickup = Pickup::routing_none(&node, Arc::clone(storage), None).expect("opened");

        let mut buffer = vec![0u8; 64 * 1024];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_subscriptions_v1(
                borrow(&node),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        let listed: Value = serde_json::from_slice(&buffer[..length]).expect("JSON");
        assert_eq!(listed["subscriptions"], json!([]), "{listed}");

        let said = pickup
            .act("onward", Act::Pause, "ilian")
            .expect_err("refused");
        assert!(said.contains("routes by no Subscription"), "{said}");
    }

    #[test]
    fn a_read_publications_subscriptions_are_listed() {
        let cluster = configure::fixture::test_cluster();
        let text = format!(
            "node = \"{}\"\n\
             [[subscriptions]]\nnode = \"{}\"\nname = \"structured\"\n\
             state = \"paused\"\nheld = 4\n",
            cluster.scope(),
            cluster.node_scope(1)
        );
        let mut handle = core::ptr::null_mut();
        let mut buffer = vec![0u8; 4096];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let read = unsafe {
            xmip_publication_read_v1(
                borrow(&text),
                &raw mut handle,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(read, status::OK);
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_publication_subscriptions_v1(
                handle,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        let list: Value = serde_json::from_slice(&buffer[..length]).expect("JSON");
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        unsafe { xmip_publication_free_v1(handle) };
        assert_eq!(
            list.get("orders"),
            None,
            "a snapshot is read, never acted on"
        );
        assert_eq!(list["subscriptions"][0]["name"], "structured");
        assert_eq!(list["subscriptions"][0]["held"], 4);
        assert_eq!(list["subscriptions"][0]["paused"], true);
    }
}
