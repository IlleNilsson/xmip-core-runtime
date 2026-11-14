//! `xmip_operate.h` section 16, the Messages that failed: listed from Xmip
//! Storage a page at a time or as a read publication carries them,
//! forwarded. A Retry or a Dismiss reaches a node through its operate
//! listener's door and Xmip Storage, never here (ADR-0014, amendment
//! 2026-11-13).
//!
//! The list is `crate::send_step`'s. This writes one list's JSON, once, for
//! this process's nodes and for a read publication alike.
#![allow(unsafe_code)]

#[cfg(feature = "node")]
use abi::ffi::Str;
use abi::ffi::status;
use abi::operate::publication::Publication as Handle;
#[cfg(feature = "node")]
use node::Scope;
use observe::FailedMessages;
use serde_json::{Value, json};

use crate::ffi::publication::held;
use crate::ffi::rule::refuse;
#[cfg(feature = "node")]
use crate::ffi::text::scope_text;
#[cfg(feature = "node")]
use crate::send_step::{FAILED_WINDOW, PortFigures, SendStep};

/// A list of failed Messages as the header writes it: each Port's, with the
/// place its next page reads from, where there is one.
fn listed<'a>(failed: impl Iterator<Item = (&'a FailedMessages, Option<u64>)>) -> String {
    let failed: Vec<Value> = failed
        .map(|(port, next)| {
            let messages: Vec<Value> = port
                .messages
                .iter()
                .map(|failed| {
                    json!({
                        "journey": failed.journey,
                        "sequence": failed.sequence,
                        "reason": failed.reason,
                    })
                })
                .collect();
            let last = port
                .last_failure
                .as_ref()
                .map(|last| json!({ "journey": last.journey, "reason": last.reason }));
            json!({
                "node": port.node,
                "send_port": port.send_port,
                "count": port.count,
                "blocked": port.blocked,
                "next": next,
                "messages": messages,
                "last_failure": last,
            })
        })
        .collect();
    json!({ "failed_messages": failed }).to_string()
}

/// The Messages that failed at `port` (empty: every Port) of every node in
/// this process at or beneath `node` (empty: all), read from Xmip Storage
/// from the place `from` on in each Port's index of failed Messages, at
/// most `most` (0: `send_step::FAILED_WINDOW`, a hundred) of each Port, as
/// `crate::send_step::SendStep::failed_messages` reads them.
///
/// # Safety
/// `node` and `port` point at their stated length of readable bytes; `out`
/// has room for `cap` bytes; `out_len` is writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node")]
pub unsafe extern "C" fn xmip_failed_messages_v1(
    node: Str,
    port: Str,
    from: u64,
    most: u32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        failed_listed(node, port, from, most, out, cap, out_len)
    })
}

/// [`xmip_failed_messages_v1`] within its guard.
#[cfg(feature = "node")]
unsafe fn failed_listed(
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
        u32::try_from(FAILED_WINDOW).unwrap_or(u32::MAX)
    } else {
        most
    };
    let (code, text) = match failed(node, port, from, most) {
        Ok(failed) => (
            status::OK,
            listed(failed.iter().map(|(port, next)| (port, *next))),
        ),
        Err(failed) => (status::IO, failed),
    };

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    code
}

/// Each Port's page of failed Messages, as [`xmip_failed_messages_v1`]
/// lists them.
#[cfg(feature = "node")]
fn failed(
    node: &str,
    port: &str,
    from: u64,
    most: u32,
) -> Result<Vec<(FailedMessages, Option<u64>)>, String> {
    let within = Scope::new(node);
    let mut failed = Vec::new();
    for step in SendStep::registered() {
        if !within.contains(Scope::new(step.node())) {
            continue;
        }
        let ports = step.ports();
        let figures = step.figures();
        for name in ports
            .into_iter()
            .filter(|name| port.is_empty() || name == port)
        {
            let page = step.failed_messages(&name, from, most)?;
            let messages = page.messages.iter().map(|one| one.published()).collect();
            let figures = figures.get(&name);
            let listed = FailedMessages {
                node: step.node().to_string(),
                count: page.count,
                blocked: figures.is_some_and(|figures| figures.blocked),
                messages,
                last_failure: figures.and_then(PortFigures::last),
                send_port: name,
            };
            failed.push((listed, page.next));
        }
    }
    Ok(failed)
}

/// What a read publication carries of failed Messages.
///
/// # Safety
/// `publication` is a live handle; `out` has room for `cap` bytes;
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_failed_messages_v1(
    publication: *const Handle,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        publication_failed_messages(publication, out, cap, out_len)
    })
}

/// [`xmip_publication_failed_messages_v1`] within its guard.
unsafe fn publication_failed_messages(
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
    let text = listed(publication.failed_messages.iter().map(|port| (port, None)));

    // SAFETY: `out` and `out_len` per the contract.
    unsafe { refuse(&text, out, cap, out_len) };
    status::OK
}

#[cfg(all(test, feature = "node"))]
mod tests {
    use super::*;
    use crate::ffi::text::borrow;

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::message::FailedMessagesFn = xmip_failed_messages_v1;
        let _: abi::operate::message::PublicationFailedMessagesFn =
            xmip_publication_failed_messages_v1;
    }

    #[test]
    fn no_node_here_lists_no_failed_messages_and_a_list_has_the_headers_shape() {
        let node = format!(
            "{}-ffi-failed-messages",
            configure::fixture::test_cluster().node_scope(0)
        );
        let mut buffer = vec![0u8; 1024];
        let mut length = 0usize;
        // SAFETY: every pointer is this test's own string or buffer, alive for the call.
        let code = unsafe {
            xmip_failed_messages_v1(
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
        assert_eq!(said["failed_messages"], json!([]));

        let port = FailedMessages {
            node,
            send_port: "Out".to_string(),
            count: 3,
            blocked: true,
            messages: vec![observe::FailedMessage {
                journey: "j".to_string(),
                sequence: 2,
                reason: "refused".to_string(),
            }],
            last_failure: Some(observe::LastFailure {
                journey: "k".to_string(),
                reason: "refused since".to_string(),
            }),
        };
        let none_now = FailedMessages {
            send_port: "Quiet".to_string(),
            ..FailedMessages::default()
        };
        let read: Value =
            serde_json::from_str(&listed([(&port, Some(3)), (&none_now, None)].into_iter()))
                .expect("JSON");
        let first = &read["failed_messages"][0];
        assert_eq!(first["send_port"], "Out");
        assert_eq!(first["count"], 3);
        assert_eq!(first["blocked"], true);
        assert_eq!(first["next"], 3);
        assert_eq!(first["messages"][0]["reason"], "refused");
        assert_eq!(first["last_failure"]["journey"], "k", "history, apart");
        let quiet = &read["failed_messages"][1];
        assert_eq!(
            (&quiet["count"], &quiet["blocked"]),
            (&json!(0), &json!(false))
        );
        assert_eq!(quiet["last_failure"], Value::Null);
        assert_eq!(
            read.get("orders"),
            None,
            "a snapshot is read, never acted on"
        );
    }
}
