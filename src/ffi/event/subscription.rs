//! `xmip_operate.h` section 11, what an operator lists and does: every
//! subscription a hub holds, and pause, resume and remove on one of them
//! (ADR-0065, amendment 2026-09-29), forwarded.
//!
//! The hub's standing, the acts, their audit and the order a surface leaves
//! for a node it reads through a publication are the event crate's; this
//! writes one list's JSON, once, for this process's hub and for a read
//! publication alike, and reads the act's word by `xevent::act::Act`.
#![allow(unsafe_code)]

use std::path::Path;

use abi::ffi::{Str, status};
use abi::operate::publication::Publication as Handle;
use observe::{Subscription, SubscriptionState};
use serde_json::{Value, json};
use xevent::act::Act;
use xevent::hub::Hub;
use xevent::order::Order;

use crate::ffi::operate::scope_text;
use crate::ffi::publication::held;
use crate::ffi::rule::refuse;

/// A list of subscriptions as the header writes it.
fn listed<'a>(orders: &str, subscriptions: impl Iterator<Item = &'a Subscription>) -> String {
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
                "paused": subscription.state == SubscriptionState::Paused,
                "queued": subscription.queued,
                "capacity": subscription.capacity,
                "delivered": subscription.delivered,
                "missed": subscription.missed,
                "since_unix_nanos": subscription.since_unix_nanos,
            })
        })
        .collect();
    json!({ "orders": orders, "subscriptions": subscriptions }).to_string()
}

/// The act a word names, or the refusal of it.
fn act_named(word: &str) -> Result<Act, String> {
    Act::named(word).ok_or_else(|| {
        let words: Vec<&str> = Act::ALL.iter().map(|act| act.word()).collect();
        format!(
            "REFUSED: '{word}' is no act on a subscription; the acts are {}",
            words.join(", ")
        )
    })
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
    let (code, sentence) = match act_named(act) {
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

/// `xevent::order::Order::leave`, forwarded.
///
/// # Safety
/// As for [`xmip_event_subscription_act_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_subscription_order_v1(
    orders: Str,
    node: Str,
    id: u64,
    act: Str,
    who: Str,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe {
        (
            scope_text(orders),
            scope_text(node),
            scope_text(act),
            scope_text(who),
        )
    };
    let (Some(orders), Some(node), Some(act), Some(who)) = texts else {
        return status::MALFORMED;
    };
    let (code, sentence) = if orders.is_empty() {
        (
            status::INVALID,
            "REFUSED: the publication says nowhere its publisher takes orders".to_string(),
        )
    } else {
        match act_named(act) {
            Err(refused) => (status::INVALID, refused),
            Ok(act) => {
                let order = Order {
                    node: node.to_string(),
                    id,
                    act,
                    who: who.to_string(),
                };
                match order.leave(Path::new(orders)) {
                    Ok(file) => (status::OK, file.display().to_string()),
                    Err(error) if error.to_string().starts_with("REFUSED") => {
                        (status::INVALID, error.to_string())
                    }
                    Err(error) => (status::IO, error.to_string()),
                }
            }
        }
    };

    // SAFETY: `said` and `said_len` per the contract.
    unsafe { refuse(&sentence, said, said_cap, said_len) };
    code
}

/// What a read publication carries, and where its publisher takes orders.
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
    use xaudit::program_audit::ProgramAudit;
    use xcore::PartyId;
    use xevent::filter::Filter;
    use xevent::subscriber::Subscriber;

    use super::*;
    use crate::ffi::operate::borrow;
    use crate::ffi::publication::{xmip_publication_free_v1, xmip_publication_read_v1};

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::event::SubscriptionsFn = xmip_event_subscriptions_v1;
        let _: abi::operate::event::SubscriptionActFn = xmip_event_subscription_act_v1;
        let _: abi::operate::event::SubscriptionOrderFn = xmip_event_subscription_order_v1;
        let _: abi::operate::event::PublicationSubscriptionsFn = xmip_publication_subscriptions_v1;
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
            listed_here("xmip:///CT/node/R1")["subscriptions"]
                .as_array()
                .expect("a list")
                .iter()
                .find(|entry| entry["id"] == id)
                .cloned()
        };

        let entry = find().expect("listed");
        assert_eq!(entry["node"], "xmip:///CT/node/R1");
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
    fn an_order_is_left_where_the_publication_says_and_its_list_read_back() {
        let orders = std::env::temp_dir().join("xmip-runtime-subscription-orders");
        let _ = std::fs::remove_dir_all(&orders);
        let place = orders.display().to_string();
        let text = format!(
            "node = \"xmip:///CT\"\norders = '{place}'\n[[subscriptions]]\n\
             node = \"xmip:///CT/node/R1\"\nid = 3\nsubscriber = \"p\"\nstate = \"paused\"\n"
        );
        let mut handle = core::ptr::null_mut();
        let mut buffer = vec![0u8; 4096];
        let mut length = 0usize;
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
        unsafe { xmip_publication_free_v1(handle) };
        assert_eq!(list["orders"], place.as_str());
        assert_eq!(list["subscriptions"][0]["state"], "paused");

        let code = unsafe {
            xmip_event_subscription_order_v1(
                borrow(&place),
                borrow("xmip:///CT/node/R1"),
                3,
                borrow("pause"),
                borrow("ilian"),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(said(code, &buffer, length).0, status::OK);
        let taken = Order::take(&orders, "xmip:///CT/node/R1");
        assert_eq!(taken.len(), 1);
        assert_eq!(
            taken[0].as_ref().map(|order| (order.id, order.act)),
            Ok((3, Act::Pause))
        );

        let code = unsafe {
            xmip_event_subscription_order_v1(
                borrow(""),
                borrow("xmip:///CT/node/R1"),
                3,
                borrow("pause"),
                borrow("ilian"),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::INVALID);
        let _ = std::fs::remove_dir_all(&orders);
    }
}
