//! `xmip_operate.h` section 11, what an operator lists and does: every
//! Event subscription a hub holds, and pause, resume and remove on one of
//! them (ADR-0065, amendment 2026-09-29), forwarded.
//!
//! The hub's standing, the acts, their audit are the event crate's, and the
//! acts' words and the order a surface leaves for a node it reads through a
//! publication are `observe`'s (`ffi/order.rs` leaves it); this writes one
//! list's JSON, once, for this process's hub and for a read publication
//! alike. It is not section 14, a node's Subscriptions.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::publication::Publication as Handle;
use observe::{EventSubscription, Noun, PauseState};
use serde_json::{Value, json};
use xevent::hub::Hub;

use crate::ffi::operate::scope_text;
use crate::ffi::publication::held;
use crate::ffi::rule::refuse;

/// A list of Event subscriptions as the header writes it.
fn listed<'a>(orders: &str, subscriptions: impl Iterator<Item = &'a EventSubscription>) -> String {
    let subscriptions: Vec<Value> = subscriptions
        .map(|subscription| {
            json!({
                "node": subscription.node,
                "id": subscription.id,
                "subscriber": subscription.subscriber,
                "party": subscription.party,
                "action": subscription.action,
                "scope": subscription.scope,
                "state": subscription.state.word(),
                "paused": subscription.state == PauseState::Paused,
                "queued": subscription.queued,
                "capacity": subscription.capacity,
                "delivered": subscription.delivered,
                "missed": subscription.missed,
                "since_unix_nanos": subscription.since_unix_nanos,
            })
        })
        .collect();
    json!({ "orders": orders, "event_subscriptions": subscriptions }).to_string()
}

/// `xevent::hub::Hub::standing` on the process's hub, forwarded.
///
/// # Safety
/// `node` points at its stated length of readable bytes; `out` has room for
/// `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_subscriptions_v1(
    node: Str,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `node`.
    let Some(node) = (unsafe { scope_text(node) }) else {
        return status::MALFORMED;
    };
    let standing = Hub::process().standing(node);

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&listed("", standing.iter()), out, cap, out_len) };
    status::OK
}

/// `xevent::hub::Hub::act` on the process's hub, forwarded.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `said` has room
/// for `said_cap` bytes; `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_subscription_act_v1(
    id: u64,
    act: Str,
    who: Str,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both.
    let (Some(act), Some(who)) = (unsafe { (scope_text(act), scope_text(who)) }) else {
        return status::MALFORMED;
    };
    let (code, sentence) = match Noun::EventSubscription.act(act) {
        Err(refused) => (status::INVALID, refused),
        Ok(act) => match Hub::process().act(id, act, who) {
            Ok(done) => (status::OK, done),
            Err(refused) => (status::NOT_FOUND, refused.to_string()),
        },
    };

    // SAFETY: `said` and `said_len` per the contract.
    unsafe { refuse(&sentence, said, said_cap, said_len) };
    code
}

/// What a read publication carries of Event subscriptions, and where its
/// publisher takes orders.
///
/// # Safety
/// `publication` is a live handle; `out` has room for `cap` bytes;
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_event_subscriptions_v1(
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
    let text = listed(&publication.orders, publication.event_subscriptions.iter());

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

#[cfg(test)]
mod tests {
    use xaudit::program_audit::ProgramAudit;
    use xcore::PartyId;
    use xevent::filter::Filter;
    use xevent::subscriber::Subscriber;

    use super::*;
    use crate::ffi::operate::borrow;
    use crate::ffi::publication::{xmip_publication_free_v1, xmip_publication_read_v1};

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::event::EventSubscriptionsFn = xmip_event_subscriptions_v1;
        let _: abi::operate::event::EventSubscriptionActFn = xmip_event_subscription_act_v1;
        let _: abi::operate::event::PublicationEventSubscriptionsFn =
            xmip_publication_event_subscriptions_v1;
    }

    fn said(code: i32, buffer: &[u8], length: usize) -> (i32, String) {
        (
            code,
            String::from_utf8_lossy(&buffer[..length.min(buffer.len())]).into_owned(),
        )
    }

    fn act(id: u64, word: &str) -> (i32, String) {
        let mut buffer = vec![0u8; 1024];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_event_subscription_act_v1(
                id,
                borrow(word),
                borrow("ilian"),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        said(code, &buffer, length)
    }

    fn listed_here(node: &str) -> Value {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_event_subscriptions_v1(
                borrow(node),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        serde_json::from_slice(&buffer[..length]).expect("JSON")
    }

    #[test]
    fn the_process_hub_is_listed_and_acted_on_and_a_stranger_act_is_refused() {
        let at = std::env::temp_dir().join("xmip-runtime-subscription-ffi");
        let subscriber = Subscriber::in_process(
            PartyId::new(9),
            ProgramAudit::new("xmip-runtime tests", Some(&at)),
        );
        let subscription = Hub::process()
            .subscribe(subscriber, Filter::everything().beneath("xmip:///CT"), 4)
            .expect("allowed");
        let id = subscription.id();
        let find = || {
            listed_here("xmip:///CT/node/alpha")["event_subscriptions"]
                .as_array()
                .expect("a list")
                .iter()
                .find(|entry| entry["id"] == id)
                .cloned()
        };

        let entry = find().expect("listed");
        assert_eq!(entry["node"], "xmip:///CT/node/alpha");
        assert_eq!(entry["state"], "active");
        assert_eq!(entry["scope"], "xmip:///CT");
        assert_eq!(entry["capacity"], 4);
        assert_eq!(entry["party"], PartyId::new(9).to_string().as_str());
        assert_eq!(
            entry["subscriber"], "",
            "declared with no name, and none is made up"
        );

        assert_eq!(act(id, "pause").0, status::OK);
        assert_eq!(find().expect("listed")["state"], "paused");
        assert_eq!(act(id, "resume").0, status::OK);
        let (code, refusal) = act(id, "sulk");
        assert_eq!(code, status::INVALID);
        assert!(refusal.contains("pause, resume, remove"), "{refusal}");
        assert_eq!(act(id, "remove").0, status::OK);
        assert!(find().is_none());
        let (code, refusal) = act(id, "pause");
        assert_eq!(code, status::NOT_FOUND);
        assert!(refusal.starts_with("REFUSED"), "{refusal}");
        drop(subscription);
    }

    #[test]
    fn a_read_publications_event_subscriptions_are_listed_with_where_orders_go() {
        let text = "node = \"xmip:///CT\"\norders = 'shared/orders'\n\
                    [[event_subscriptions]]\nnode = \"xmip:///CT/node/alpha\"\nid = 3\n\
                    subscriber = \"p\"\nstate = \"paused\"\n";
        let mut handle = core::ptr::null_mut();
        let mut buffer = vec![0u8; 4096];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let read = unsafe {
            xmip_publication_read_v1(
                borrow(text),
                &raw mut handle,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(read, status::OK);
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_publication_event_subscriptions_v1(
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
        assert_eq!(list["event_subscriptions"][0]["state"], "paused");
        assert_eq!(list["event_subscriptions"][0]["id"], 3);
    }
}
