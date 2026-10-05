//! `xmip_operate.h` section 16, the Journeys that failed: listed from Xmip
//! Storage a page at a time or as a read publication carries them, and an
//! operator's act on one, Retry or Dismiss, on the send step of a node in
//! this process, forwarded.
//!
//! The list, the act, its write and its audit are `crate::send_step`'s; the
//! act's word is `observe`'s. This writes one list's JSON, once, for this
//! process's nodes and for a read publication alike.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::publication::Publication as Handle;
use observe::{Act, FailedJourney, FailedJourneys, Scope};
use serde_json::{Value, json};

use crate::ffi::operate::scope_text;
use crate::ffi::publication::held;
use crate::ffi::rule::refuse;
use crate::send_step::{PUBLISHED_FAILED, SendStep};

/// A list of failed Journeys as the header writes it: each Port's, with the
/// place its next page reads from, where there is one.
fn listed<'a>(
    orders: &str,
    failed: impl Iterator<Item = (&'a FailedJourneys, Option<u64>)>,
) -> String {
    let failed: Vec<Value> = failed
        .map(|(port, next)| {
            let journeys: Vec<Value> = port
                .journeys
                .iter()
                .map(|failed| {
                    json!({
                        "journey": failed.journey,
                        "sequence": failed.sequence,
                        "reason": failed.reason,
                    })
                })
                .collect();
            json!({
                "node": port.node,
                "send_port": port.send_port,
                "count": port.count,
                "next": next,
                "journeys": journeys,
            })
        })
        .collect();
    json!({ "orders": orders, "failed_journeys": failed }).to_string()
}

/// The Journeys that failed at `port` (empty: every Port) of every node in
/// this process at or beneath `node` (empty: all), read from Xmip Storage
/// from `from` on, at most `most` (0: a hundred) of each Port, as
/// `crate::send_step::SendStep::failed_journeys` reads them.
///
/// # Safety
/// `node` and `port` point at their stated length of readable bytes; `out`
/// has room for `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_failed_journeys_v1(
    node: Str,
    port: Str,
    from: u64,
    most: u32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on both strings.
    let texts = unsafe { (scope_text(node), scope_text(port)) };
    let (Some(node), Some(port)) = texts else {
        return status::MALFORMED;
    };
    let most = if most == 0 {
        u32::try_from(PUBLISHED_FAILED).unwrap_or(u32::MAX)
    } else {
        most
    };
    let (code, text) = match failed(node, port, from, most) {
        Ok(failed) => (
            status::OK,
            listed("", failed.iter().map(|(port, next)| (port, *next))),
        ),
        Err(failed) => (status::IO, failed),
    };

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// Each Port's page of failed Journeys, as [`xmip_failed_journeys_v1`]
/// lists them.
fn failed(
    node: &str,
    port: &str,
    from: u64,
    most: u32,
) -> Result<Vec<(FailedJourneys, Option<u64>)>, String> {
    let within = Scope::new(node);
    let mut failed = Vec::new();
    for step in SendStep::registered() {
        if !within.contains(Scope::new(step.node())) {
            continue;
        }
        let ports = step.ports();
        for name in ports
            .into_iter()
            .filter(|name| port.is_empty() || name == port)
        {
            let page = step.failed_journeys(&name, from, most)?;
            let journeys = page
                .journeys
                .iter()
                .map(|failed| FailedJourney {
                    journey: failed.journey.to_string(),
                    sequence: failed.place,
                    reason: failed.reason.clone(),
                })
                .collect();
            let listed = FailedJourneys {
                node: step.node().to_string(),
                send_port: name,
                count: page.count,
                journeys,
            };
            failed.push((listed, page.next));
        }
    }
    Ok(failed)
}

/// What a read publication carries of failed Journeys, and where its
/// publisher takes orders.
///
/// # Safety
/// `publication` is a live handle; `out` has room for `cap` bytes;
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_failed_journeys_v1(
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
    let text = listed(
        &publication.orders,
        publication.failed_journeys.iter().map(|port| (port, None)),
    );

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

/// `crate::send_step::SendStep::act` on the node at `node` in this process,
/// forwarded: `act` on the Journey `journey`, by `who`.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `said` has room
/// for `said_cap` bytes; `said_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_journey_act_v1(
    node: Str,
    journey: Str,
    act: Str,
    who: Str,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on every string.
    let texts = unsafe {
        [
            scope_text(node),
            scope_text(journey),
            scope_text(act),
            scope_text(who),
        ]
    };
    let [Some(node), Some(journey), Some(act), Some(who)] = texts else {
        return status::MALFORMED;
    };
    let (code, sentence) = acted(node, journey, act, who);

    // SAFETY: `said` and `said_len` per the contract.
    unsafe { refuse(&sentence, said, said_cap, said_len) };
    code
}

/// What came of `act` on `journey` at `node`, and its status.
fn acted(node: &str, journey: &str, act: &str, who: &str) -> (i32, String) {
    let Some(act) = Act::named(act).filter(|act| matches!(act, Act::Retry | Act::Dismiss)) else {
        let refused = observe::Noun::Journey.act(act).err().unwrap_or_default();
        return (status::INVALID, refused);
    };
    let step = SendStep::registered()
        .into_iter()
        .find(|step| step.node() == node);
    match step {
        None => (
            status::NOT_FOUND,
            format!("REFUSED: no node at {node} runs in this process"),
        ),
        Some(step) => match step.act(journey, act, who) {
            Ok(done) => (status::OK, done),
            Err(failed) if failed.starts_with("FAILED") => (status::IO, failed),
            Err(refused) => (status::NOT_FOUND, refused),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::operate::borrow;

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::journey::JourneyActFn = xmip_journey_act_v1;
        let _: abi::operate::journey::FailedJourneysFn = xmip_failed_journeys_v1;
        let _: abi::operate::journey::PublicationFailedJourneysFn =
            xmip_publication_failed_journeys_v1;
    }

    #[test]
    fn no_node_here_lists_no_failed_journeys_and_a_list_has_the_headers_shape() {
        let node = format!(
            "{}-ffi-failed-journeys",
            configure::fixture::test_cluster().node_scope(0)
        );
        let mut buffer = vec![0u8; 1024];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_failed_journeys_v1(
                borrow(&node),
                borrow(""),
                0,
                0,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        let said: Value = serde_json::from_slice(&buffer[..length]).expect("JSON");
        assert_eq!(said["failed_journeys"], json!([]));
        assert_eq!(said["orders"], "");

        let port = FailedJourneys {
            node,
            send_port: "Out".to_string(),
            count: 3,
            journeys: vec![FailedJourney {
                journey: "j".to_string(),
                sequence: 2,
                reason: "refused".to_string(),
            }],
        };
        let read: Value =
            serde_json::from_str(&listed("orders", [(&port, Some(3))].into_iter())).expect("JSON");
        let first = &read["failed_journeys"][0];
        assert_eq!(first["send_port"], "Out");
        assert_eq!(first["count"], 3);
        assert_eq!(first["next"], 3);
        assert_eq!(first["journeys"][0]["reason"], "refused");
        assert_eq!(read["orders"], "orders");
    }

    fn act(node: &str, word: &str) -> (i32, String) {
        let mut buffer = vec![0u8; 1024];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_journey_act_v1(
                borrow(node),
                borrow("0199a000-0000-7000-8000-000000000001"),
                borrow(word),
                borrow("an operator"),
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
    fn an_act_on_a_node_not_here_or_no_act_on_a_journey_is_refused_in_words() {
        let node = format!(
            "{}-ffi-journey",
            configure::fixture::test_cluster().node_scope(0)
        );
        let (code, said) = act(&node, "retry");
        assert_eq!(code, status::NOT_FOUND);
        assert!(said.starts_with("REFUSED: no node at"), "{said}");
        let (code, said) = act(&node, "replay");
        assert_eq!(code, status::INVALID);
        assert!(said.contains("the acts are retry, dismiss"), "{said}");
    }
}
