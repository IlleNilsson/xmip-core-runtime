//! `xmip_operate.h` section 14, an operator's order: an act on an Event
//! subscription or a Subscription left where a publication says its
//! publisher takes orders, for the node to take at its next look
//! (ADR-0065, amendment 2026-09-29; ADR-0013, amendment 2026-09-30).
//!
//! One order for both: the file, its place, its shape and which acts each
//! noun takes are `observe::Order`'s and `observe::Noun`'s, forwarded.
#![allow(unsafe_code)]

use std::path::Path;

use abi::ffi::{Str, status};
use observe::{Noun, Order};

use crate::ffi::operate::scope_text;
use crate::ffi::rule::refuse;

/// `observe::Order::leave`, forwarded: `act` on the `noun` called `target`
/// of the node at `node`, left in `orders` by `who`.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `said` has room
/// for `said_cap` bytes; `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_order_v1(
    orders: Str,
    node: Str,
    noun: Str,
    target: Str,
    act: Str,
    who: Str,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe {
        [
            scope_text(orders),
            scope_text(node),
            scope_text(noun),
            scope_text(target),
            scope_text(act),
            scope_text(who),
        ]
    };
    let [
        Some(orders),
        Some(node),
        Some(noun),
        Some(target),
        Some(act),
        Some(who),
    ] = texts
    else {
        return status::MALFORMED;
    };
    let (code, sentence) = match left(orders, node, noun, target, act, who) {
        Ok(file) => (status::OK, file),
        Err(refused) if refused.starts_with("REFUSED") => (status::INVALID, refused),
        Err(failed) => (status::IO, failed),
    };

    // SAFETY: `said` and `said_len` per the contract.
    unsafe { refuse(&sentence, said, said_cap, said_len) };
    code
}

/// The order left, and the file written.
fn left(
    orders: &str,
    node: &str,
    noun: &str,
    target: &str,
    act: &str,
    who: &str,
) -> Result<String, String> {
    if orders.is_empty() {
        return Err("REFUSED: the publication says nowhere its publisher takes orders".into());
    }
    let noun = Noun::named(noun)
        .ok_or_else(|| format!("REFUSED: '{noun}' is nothing an operator acts on"))?;
    let order = Order {
        node: node.to_string(),
        noun,
        target: target.to_string(),
        act: noun.act(act)?,
        who: who.to_string(),
    };
    order
        .leave(Path::new(orders))
        .map(|file| file.display().to_string())
}

#[cfg(test)]
mod tests {
    use observe::Act;

    use super::*;
    use crate::ffi::operate::borrow;

    fn order(orders: &str, noun: &str, target: &str, act: &str) -> (i32, String) {
        let mut buffer = vec![0u8; 4096];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_order_v1(
                borrow(orders),
                borrow("xmip:///CT/node/beta"),
                borrow(noun),
                borrow(target),
                borrow(act),
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

    #[test]
    fn the_export_has_the_shape_the_binding_declares() {
        let _: abi::operate::subscription::OrderFn = xmip_order_v1;
    }

    #[test]
    fn an_order_on_either_noun_is_left_for_its_node_and_a_remove_of_a_subscription_is_not() {
        let orders = std::env::temp_dir().join("xmip-runtime-orders");
        let _ = std::fs::remove_dir_all(&orders);
        let place = orders.display().to_string();

        assert_eq!(
            order(&place, "subscription", "structured", "pause").0,
            status::OK
        );
        assert_eq!(
            order(&place, "event-subscription", "3", "remove").0,
            status::OK
        );
        let (code, refusal) = order(&place, "subscription", "structured", "remove");
        assert_eq!(code, status::INVALID);
        assert!(refusal.contains("TOML configuration"), "{refusal}");
        assert_eq!(order(&place, "sulk", "x", "pause").0, status::INVALID);
        assert_eq!(order("", "subscription", "x", "pause").0, status::INVALID);

        let taken: Vec<(Noun, String, Act)> = Order::take(&orders, "xmip:///CT/node/beta")
            .into_iter()
            .map(|order| order.map(|order| (order.noun, order.target, order.act)))
            .collect::<Result<_, _>>()
            .expect("orders");
        assert_eq!(
            taken,
            vec![
                (Noun::Subscription, "structured".to_string(), Act::Pause),
                (Noun::EventSubscription, "3".to_string(), Act::Remove),
            ]
        );
        let _ = std::fs::remove_dir_all(&orders);
    }
}
