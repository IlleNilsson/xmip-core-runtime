//! `xmip_operate.h` section 14, a node's Subscriptions: every Subscription
//! the nodes of this process route by, pause and resume on one of them, and
//! what a read publication carries of them (ADR-0013, amendment
//! 2026-09-30), forwarded.
//!
//! The standing, the hold, the acts and their audit are `crate::pickup`'s;
//! the acts' words are `observe`'s. This writes one list's JSON, once, for
//! this process's nodes and for a read publication alike. There is no
//! remove: a Subscription is added and removed in the TOML configuration.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::publication::Publication as Handle;
use observe::{Noun, PauseState, Scope, Subscription};
use serde_json::{Value, json};

use crate::ffi::operate::scope_text;
use crate::ffi::publication::held;
use crate::ffi::rule::refuse;
use crate::pickup::Pickup;

/// A list of Subscriptions as the header writes it.
fn listed<'a>(orders: &str, subscriptions: impl Iterator<Item = &'a Subscription>) -> String {
    let subscriptions: Vec<Value> = subscriptions
        .map(|subscription| {
            json!({
                "node": subscription.node,
                "name": subscription.name,
                "application": subscription.application,
                "filter": subscription.filter,
                "destination": subscription.destination,
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
    json!({ "orders": orders, "subscriptions": subscriptions }).to_string()
}

/// Every Subscription of every node in this process at or beneath `node`
/// (empty: all), as `crate::pickup::Pickup::standing` says.
///
/// # Safety
/// `node` points at its stated length of readable bytes; `out` has room for
/// `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_subscriptions_v1(
    node: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
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
    unsafe { refuse(&listed("", standing.iter()), out, cap, out_len) };
    status::OK
}

/// `crate::pickup::Pickup::act` on the node at `node` in this process,
/// forwarded: pause or resume the Subscription called `name`, by `who`.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `said` has room
/// for `said_cap` bytes; `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_subscription_act_v1(
    node: Str,
    name: Str,
    act: Str,
    who: Str,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe {
        (
            scope_text(node),
            scope_text(name),
            scope_text(act),
            scope_text(who),
        )
    };
    let (Some(node), Some(name), Some(act), Some(who)) = texts else {
        return status::MALFORMED;
    };
    let pickup = Pickup::registered()
        .into_iter()
        .find(|pickup| pickup.node() == node);
    let (code, sentence) = match (Noun::Subscription.act(act), pickup) {
        (Err(refused), _) => (status::INVALID, refused),
        (Ok(_), None) => (
            status::NOT_FOUND,
            format!("REFUSED: no node at {node} runs in this process"),
        ),
        (Ok(act), Some(pickup)) => match pickup.act(name, act, who) {
            Ok(done) => (status::OK, done),
            Err(refused) => (status::NOT_FOUND, refused),
        },
    };

    // SAFETY: `said` and `said_len` per the contract.
    unsafe { refuse(&sentence, said, said_cap, said_len) };
    code
}

/// What a read publication carries of Subscriptions, and where its
/// publisher takes orders.
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
    // SAFETY: per the contract above.
    let Some(read) = (unsafe { held(publication) }) else {
        return status::INVALID;
    };
    let publication = &read.publication;
    let text = listed(&publication.orders, publication.subscriptions.iter());

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use journey::Journey;

    use super::*;
    use crate::configured_subscription::ConfiguredSubscription;
    use crate::ffi::operate::borrow;
    use crate::ffi::publication::{xmip_publication_free_v1, xmip_publication_read_v1};
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
        let _: abi::operate::subscription::SubscriptionActFn = xmip_subscription_act_v1;
        let _: abi::operate::subscription::PublicationSubscriptionsFn =
            xmip_publication_subscriptions_v1;
    }

    fn act(name: &str, word: &str) -> (i32, String) {
        let mut buffer = vec![0u8; 1024];
        let mut length = 0usize;
        let node = node();
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_subscription_act_v1(
                borrow(&node),
                borrow(name),
                borrow(word),
                borrow("ilian"),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        (
            code,
            String::from_utf8_lossy(&buffer[..length]).into_owned(),
        )
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

        assert_eq!(act("billing", "pause").0, status::OK);
        let held = published(&pickup, storage.as_ref(), &[billing], "held");
        assert_eq!(held, Ok(1), "held, not picked up");
        let entry = listed_here()["subscriptions"][0].clone();
        assert_eq!(
            (entry["state"].clone(), entry["held"].clone()),
            ("paused".into(), 1.into())
        );

        let (code, refusal) = act("billing", "remove");
        assert_eq!(code, status::INVALID);
        assert!(refusal.contains("TOML configuration"), "{refusal}");
        let (code, refusal) = act("shipping", "pause");
        assert_eq!(code, status::NOT_FOUND);
        assert!(refusal.starts_with("REFUSED"), "{refusal}");

        assert_eq!(act("billing", "resume").0, status::OK);
        let released = pickup.released(std::time::Duration::ZERO, 8);
        assert_eq!(released.len(), 1);
        let journey = Journey::new(released[0].held.hold.journey);
        pickup.delivered(&released[0], &journey).expect("delivered");
        let entry = listed_here()["subscriptions"][0].clone();
        assert_eq!(
            (entry["held"].clone(), entry["picked_up"].clone()),
            (0.into(), 1.into())
        );
    }

    #[test]
    fn a_read_publications_subscriptions_are_listed_with_where_orders_go() {
        let cluster = configure::fixture::test_cluster();
        let text = format!(
            "node = \"{}\"\norders = 'shared/orders'\n\
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
        assert_eq!(list["orders"], "shared/orders");
        assert_eq!(list["subscriptions"][0]["name"], "structured");
        assert_eq!(list["subscriptions"][0]["held"], 4);
        assert_eq!(list["subscriptions"][0]["paused"], true);
    }
}
