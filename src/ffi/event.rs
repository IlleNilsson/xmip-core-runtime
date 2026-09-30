//! `xmip_operate.h` section 11: Events, subscribed, forwarded.
//!
//! A program in any language that loaded this library subscribes to the
//! process's hub, `xmip-core-event`'s `Hub::process`, and this file does
//! nothing else: the matching rule, the authorization gate, the queue and
//! the audit are the event crate's (ADR-0065, ADR-0052). The header's
//! action and outcome integers are read here, the one place that has both
//! them and the crates' enums, as `ffi/audit.rs` reads the audit phase.
//!
//! A drained batch owns what it hands out: the Events, the text of their
//! identifiers, and the header's structs borrowing from both; one call
//! frees it (section 8's pattern). A listening subscription calls back on
//! the event crate's listener thread with one Event borrowed for the call.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a program hands over where to write.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use abi::ffi::{Str, status};
use abi::operate::event::{
    Callback, Event as Wire, EventBatch, EventFilter, EventSubscription as Handle,
};
use xevent::Event;
use xevent::hub::{EventSubscription, Hub};
use xevent::listener::Listener;

use crate::ffi::rule::refuse;

mod crossing;
mod subscription;

use crossing::{Texts, asked, event_of, texts_of, view_of};

/// What a subscription handle holds: a queue the program drains, or a
/// listener calling it back, which is held only to be dropped.
struct Held {
    drained: Option<EventSubscription>,
    _listening: Option<Listener>,
}

/// A drained batch: the Events, their texts, and the header's structs
/// borrowing from both. Nothing here moves while the batch lives.
struct Batch {
    _events: Vec<Arc<Event>>,
    _texts: Vec<Texts>,
    views: Vec<Wire>,
}

/// The program's callback context, carried to the listener's thread.
struct Context(*mut c_void);

// SAFETY: the header makes the context the program's, used only by its own
// callback on the thread the runtime starts; the runtime never reads it.
unsafe impl Send for Context {}

impl Context {
    /// The pointer, taken through the whole wrapper so a closure moves
    /// the wrapper and not the bare pointer.
    const fn get(&self) -> *mut c_void {
        self.0
    }
}

/// `xevent::hub::Hub::subscribe` on the process's hub, forwarded.
///
/// # Safety
/// Every `Str` points at its stated length of readable bytes; `filter` is
/// null or a readable filter whose lists hold their stated lengths; `out`
/// and `said_len` are writable; `said` has room for `said_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_subscribe_v1(
    program: Str,
    directory: Str,
    subscriber: Str,
    filter: *const EventFilter,
    capacity: usize,
    out: *mut *mut Handle,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    // SAFETY: out and said_len are writable per the contract.
    unsafe {
        *out = core::ptr::null_mut();
        *said_len = 0;
    }
    // SAFETY: the caller upholds the header's contract on every argument.
    let asked = unsafe { asked(program, directory, subscriber, filter) };
    let (subscriber, filter) = match asked {
        Ok(asked) => asked,
        Err(code) => return code,
    };

    match Hub::process().subscribe(subscriber, filter, capacity) {
        Ok(subscription) => {
            // SAFETY: out is writable; the box is the handle's until freed.
            unsafe { *out = handle(Some(subscription), None) };
            status::OK
        }
        Err(refused) => {
            // SAFETY: said and said_len per the contract.
            unsafe { refuse(&refused.to_string(), said, said_cap, said_len) };
            status::AUTH
        }
    }
}

/// `xevent::hub::EventSubscription::listen`, forwarded: `callback` with
/// `context` for each Event, on the listener's thread.
///
/// # Safety
/// As [`xmip_event_subscribe_v1`]; `callback` may be called with `context`
/// from another thread until the handle is unsubscribed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_listen_v1(
    program: Str,
    directory: Str,
    subscriber: Str,
    filter: *const EventFilter,
    capacity: usize,
    callback: Callback,
    context: *mut c_void,
    out: *mut *mut Handle,
    said: *mut u8,
    said_cap: usize,
    said_len: *mut usize,
) -> i32 {
    let mut drained = core::ptr::null_mut();
    // SAFETY: the same contract, passed on whole.
    let code = unsafe {
        xmip_event_subscribe_v1(
            program,
            directory,
            subscriber,
            filter,
            capacity,
            &raw mut drained,
            said,
            said_cap,
            said_len,
        )
    };
    // SAFETY: out is writable per the contract.
    unsafe { *out = core::ptr::null_mut() };
    if code != status::OK {
        return code;
    }
    // SAFETY: `drained` is the handle just made, and nobody else has it.
    let held = unsafe { Box::from_raw(drained.cast::<Held>()) };
    let Some(subscription) = held.drained else {
        return status::INTERNAL;
    };
    let context = Context(context);

    let listening = subscription.listen(move |event| {
        let texts = texts_of(event);
        let view = view_of(event, &texts);
        // SAFETY: the view and everything it borrows live across the call.
        unsafe { callback(context.get(), &raw const view) };
    });
    match listening {
        Ok(listener) => {
            // SAFETY: out is writable; the box is the handle's until freed.
            unsafe { *out = handle(None, Some(listener)) };
            status::OK
        }
        Err(_) => status::CAPACITY,
    }
}

/// `xevent::hub::EventSubscription::next`, forwarded, as a batch.
///
/// # Safety
/// `subscription` is a handle subscribe returned and nobody unsubscribed;
/// every `out_` pointer is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_next_v1(
    subscription: *mut Handle,
    timeout_ms: u32,
    max: usize,
    out_batch: *mut *mut EventBatch,
    out_events: *mut *const Wire,
    out_len: *mut usize,
    out_refused: *mut u64,
) -> i32 {
    // SAFETY: every out pointer is writable per the contract.
    unsafe {
        *out_batch = core::ptr::null_mut();
        *out_events = core::ptr::null();
        *out_len = 0;
        *out_refused = 0;
    }
    // SAFETY: per the contract, a live handle or null.
    let Some(held) = (unsafe { subscription.cast::<Held>().as_ref() }) else {
        return status::INVALID;
    };
    let Some(subscription) = &held.drained else {
        return status::STATE;
    };

    let delivery = subscription.next(Duration::from_millis(u64::from(timeout_ms)), max);
    if delivery.events.is_empty() && delivery.refused == 0 {
        return status::TIMEOUT;
    }
    let texts: Vec<Texts> = delivery
        .events
        .iter()
        .map(|event| texts_of(event))
        .collect();
    let views = delivery
        .events
        .iter()
        .zip(&texts)
        .map(|(event, texts)| view_of(event, texts))
        .collect();
    let batch = Box::new(Batch {
        _events: delivery.events,
        _texts: texts,
        views,
    });

    // SAFETY: every out pointer is writable; the views live in the batch,
    // whose box is the program's until it frees it.
    unsafe {
        *out_events = batch.views.as_ptr();
        *out_len = batch.views.len();
        *out_refused = delivery.refused;
        *out_batch = Box::into_raw(batch).cast::<EventBatch>();
    }
    status::OK
}

/// Release a batch and everything borrowed from it.
///
/// # Safety
/// `batch` is null or a batch next returned and nobody freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_batch_free_v1(batch: *mut EventBatch) {
    if !batch.is_null() {
        // SAFETY: per the contract, the box next made.
        drop(unsafe { Box::from_raw(batch.cast::<Batch>()) });
    }
}

/// Unsubscribe either kind of handle.
///
/// # Safety
/// `subscription` is null or a handle subscribe or listen returned and
/// nobody unsubscribed; nothing borrowed from it is used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_unsubscribe_v1(subscription: *mut Handle) {
    if !subscription.is_null() {
        // SAFETY: per the contract, the box subscribe or listen made.
        drop(unsafe { Box::from_raw(subscription.cast::<Held>()) });
    }
}

/// `xevent::hub::Hub::publish` on the process's hub, forwarded.
///
/// # Safety
/// `event` points at a readable Event whose strings and diagnostics hold
/// their stated lengths; `out_delivered` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_event_publish_v1(
    event: *const Wire,
    out_delivered: *mut usize,
) -> i32 {
    // SAFETY: out_delivered is writable per the contract.
    unsafe { *out_delivered = 0 };
    // SAFETY: per the contract, a readable Event or null.
    let Some(wire) = (unsafe { event.as_ref() }) else {
        return status::INVALID;
    };
    // SAFETY: per the contract on its strings.
    match unsafe { event_of(wire) } {
        Ok(event) => {
            let delivered = Hub::process().publish(event);
            // SAFETY: writable per the contract.
            unsafe { *out_delivered = delivered };
            status::OK
        }
        Err(code) => code,
    }
}

/// A new handle's box.
fn handle(drained: Option<EventSubscription>, listening: Option<Listener>) -> *mut Handle {
    let held = Held {
        drained,
        _listening: listening,
    };
    Box::into_raw(Box::new(held)).cast::<Handle>()
}

#[cfg(test)]
mod tests {
    use super::crossing::slice;
    use super::*;
    use crate::ffi::operate::{borrow, scope_text};
    use abi::operate::event::{action, outcome};
    use std::sync::Mutex;
    use std::sync::mpsc::{self, Sender};

    #[test]
    fn the_exports_have_the_shapes_the_binding_declares() {
        let _: abi::operate::event::SubscribeFn = xmip_event_subscribe_v1;
        let _: abi::operate::event::ListenFn = xmip_event_listen_v1;
        let _: abi::operate::event::NextFn = xmip_event_next_v1;
        let _: abi::operate::event::BatchFreeFn = xmip_event_batch_free_v1;
        let _: abi::operate::event::UnsubscribeFn = xmip_event_unsubscribe_v1;
        let _: abi::operate::event::PublishFn = xmip_event_publish_v1;
    }

    /// A temporary audit directory of this test's own.
    fn directory(name: &str) -> String {
        let name = format!("xmip-runtime-event-{name}-{}", std::process::id());
        let at = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&at);
        at.to_string_lossy().into_owned()
    }

    const PARTY: &str = "0198a3c4-0000-7000-8000-000000000042";

    fn subscribe(directory: &str, filter: &EventFilter) -> *mut Handle {
        let mut out = core::ptr::null_mut();
        let mut said = [0u8; 256];
        let mut said_len = 0;
        // SAFETY: every pointer is to a live local of the stated size.
        let code = unsafe {
            xmip_event_subscribe_v1(
                borrow("xmip-core-runtime tests"),
                borrow(directory),
                borrow(PARTY),
                filter,
                0,
                &raw mut out,
                said.as_mut_ptr(),
                said.len(),
                &raw mut said_len,
            )
        };
        assert_eq!(code, status::OK);
        out
    }

    fn raised(scope: &str, diagnostics: &[Str]) -> Wire {
        Wire {
            id: Str::empty(),
            kind: borrow("se.xmip.receive.failure"),
            time_unix_nanos: 0,
            action: action::RECEIVE,
            outcome: outcome::FAILURE,
            scope: borrow(scope),
            journey: borrow("0198a3c4-0000-7000-8000-000000000001"),
            message: Str::empty(),
            stream: Str::empty(),
            endpoint: borrow("tcp://0.0.0.0:5000"),
            module: Str::empty(),
            artifact: borrow("orders"),
            party: Str::empty(),
            diagnostics: diagnostics.as_ptr(),
            diagnostics_len: diagnostics.len(),
        }
    }

    fn publish(event: &Wire) -> (i32, usize) {
        let mut delivered = 0;
        // SAFETY: the Event and its strings are live locals.
        let code = unsafe { xmip_event_publish_v1(event, &raw mut delivered) };
        (code, delivered)
    }

    /// A string the runtime handed back, as text.
    fn read(value: Str) -> String {
        // SAFETY: the batch the string borrows from is still held.
        unsafe { scope_text(value) }.expect("UTF-8").to_string()
    }

    /// Drain once: the status, the batch, the Events and the refusals.
    fn next(handle: *mut Handle, timeout_ms: u32) -> (i32, *mut EventBatch, &'static [Wire]) {
        let (mut batch, mut events, mut len, mut refused) =
            (core::ptr::null_mut(), core::ptr::null(), 0, 0);
        // SAFETY: the handle is live and every out pointer is a local; the
        // Events borrow from the batch, which the caller frees after use.
        unsafe {
            let code = xmip_event_next_v1(
                handle,
                timeout_ms,
                16,
                &raw mut batch,
                &raw mut events,
                &raw mut len,
                &raw mut refused,
            );
            (code, batch, slice(events, len))
        }
    }

    #[test]
    fn a_subscriber_drains_what_it_matches_and_frees_it() {
        let at = directory("drain");
        let scope = "xmip:///ffi-drain/node/n/receive/orders";
        let failures = [outcome::FAILURE];
        let filter = EventFilter {
            types: core::ptr::null(),
            types_len: 0,
            outcomes: failures.as_ptr(),
            outcomes_len: 1,
            scope: borrow("xmip:///ffi-drain"),
            party: Str::empty(),
        };
        let handle = subscribe(&at, &filter);
        let diagnostics = [borrow("status"), borrow("refused")];

        assert_eq!(publish(&raised(scope, &diagnostics)), (status::OK, 1));

        let (code, batch, events) = next(handle, 1000);
        assert_eq!((code, events.len()), (status::OK, 1));
        let event = &events[0];
        assert_eq!(read(event.kind), "se.xmip.receive.failure");
        assert_eq!(read(event.scope), scope);
        assert_eq!(read(event.artifact), "orders");
        assert_eq!(read(event.journey), "0198a3c4-0000-7000-8000-000000000001");
        assert_eq!(read(event.id).len(), 36, "minted");
        // SAFETY: two strings borrowed from the batch.
        let said = unsafe { slice(event.diagnostics, event.diagnostics_len) };
        assert_eq!(read(said[1]), "refused");
        // SAFETY: the batch is freed once, and nothing of it is read again.
        unsafe { xmip_event_batch_free_v1(batch) };

        let (code, batch, _) = next(handle, 1);
        assert_eq!(code, status::TIMEOUT);
        assert!(batch.is_null());
        // SAFETY: the handle is unsubscribed once.
        unsafe { xmip_event_unsubscribe_v1(handle) };
        let _ = std::fs::remove_dir_all(&at);
    }

    extern "C" fn told(context: *mut c_void, event: *const Wire) {
        // SAFETY: the context is the test's sender and the Event lives for
        // the call.
        unsafe {
            let tell = &*context.cast::<Mutex<Sender<String>>>();
            let kind = scope_text((*event).kind).expect("UTF-8").to_string();
            let _ = tell.lock().expect("tell").send(kind);
        }
    }

    #[test]
    fn a_listener_is_called_back_with_each_event() {
        let at = directory("listen");
        let (tell, heard) = mpsc::channel();
        let tell = Box::new(Mutex::new(tell));
        let filter = EventFilter {
            types: core::ptr::null(),
            types_len: 0,
            outcomes: core::ptr::null(),
            outcomes_len: 0,
            scope: borrow("xmip:///ffi-listen"),
            party: Str::empty(),
        };
        let (mut out, mut said, mut said_len) = (core::ptr::null_mut(), [0u8; 64], 0);
        let context: *const Mutex<Sender<String>> = &raw const *tell;
        // SAFETY: the context outlives the handle, which is unsubscribed
        // before it is dropped.
        let code = unsafe {
            xmip_event_listen_v1(
                borrow("xmip-core-runtime tests"),
                borrow(&at),
                borrow(PARTY),
                &raw const filter,
                0,
                told,
                context.cast_mut().cast(),
                &raw mut out,
                said.as_mut_ptr(),
                said.len(),
                &raw mut said_len,
            )
        };
        assert_eq!(code, status::OK);

        publish(&raised("xmip:///ffi-listen/node/n", &[]));

        let kind = heard
            .recv_timeout(Duration::from_secs(2))
            .expect("called back");
        assert_eq!(kind, "se.xmip.receive.failure");
        // SAFETY: the handle is live and unsubscribed once.
        unsafe { xmip_event_unsubscribe_v1(out) };
        drop(tell);
        let _ = std::fs::remove_dir_all(&at);
    }

    #[test]
    fn what_the_header_refuses_is_refused() {
        assert_eq!(publish(&raised("", &[])).0, status::INVALID, "a scope");
        let mut unknown = raised("xmip:///c", &[]);
        unknown.outcome = 8;
        assert_eq!(publish(&unknown).0, status::INVALID);
        let mut malformed = raised("xmip:///c", &[]);
        malformed.journey = borrow("not a uuid");
        assert_eq!(publish(&malformed).0, status::MALFORMED);

        let (mut out, mut said, mut said_len) = (core::ptr::null_mut(), [0u8; 64], 0);
        // SAFETY: every pointer is to a live local.
        let nobody = unsafe {
            xmip_event_subscribe_v1(
                borrow("t"),
                Str::empty(),
                Str::empty(),
                core::ptr::null(),
                0,
                &raw mut out,
                said.as_mut_ptr(),
                said.len(),
                &raw mut said_len,
            )
        };
        assert_eq!(nobody, status::INVALID, "a subscriber is a Party");
        assert!(out.is_null());
    }
}
