//! The runtime's side of `xmip_operate.h`: the table a surface calls.
//!
//! ADR-0027. `xmip-core-observe` publishes a [`Snapshot`]; this hands it to a
//! surface through the C table in `xmip-core-abi`. Every call reads that
//! snapshot and nothing else — no call here makes execution wait.
//!
//! One of two places in this crate that dereference a pointer, and it says so:
//! a surface hands over `out` and `out_len` and the header promises they are
//! written. The other is `start.rs`, for the same reason. Nothing else in the
//! runtime needs `unsafe`, so the crate denies it and these two files allow it.
#![allow(unsafe_code)]

use xmip_abi::ffi::{Str, status};
use xmip_abi::operate::{HealthEntry, Measurement, Operate, counted, health};
use xmip_observe::{Count, Counted, Health, HealthRecord, Snapshot};

use crate::start::unconfigured;

/// What sits behind `ctx`: the snapshot, and what the last call handed out.
///
/// Entries borrow from `held`, which is why the header says they are valid
/// until the next call on this table. Replacing `held` is what invalidates
/// them, and that is the whole lifetime rule.
pub struct Operator {
    source: Source,
    held_health: Vec<HealthRecord>,
    held_count: Option<Count>,
}

/// Where a table's snapshot comes from.
///
/// `Published` reads what the node has most recently published, on every
/// call — so a table handed out before a node started sees the node once it
/// has. The first build copied the snapshot at creation and the GUI read
/// "unconfigured" forever while the log said the node had started
/// (2026-09-05). `Fixed` is for tests and for a surface that wants one
/// consistent view.
enum Source {
    Fixed(Snapshot),
    Published,
}

impl Source {
    /// Change the snapshot this source reads: in place for `Fixed`, on the
    /// shared `PUBLISHED` for `Published`. Pause and resume go through here,
    /// so an operator pausing a live table changes what every table then reads.
    fn mutate<R>(&mut self, change: impl FnOnce(&mut Snapshot) -> R) -> R {
        match self {
            Source::Fixed(snapshot) => change(snapshot),
            Source::Published => {
                let mut guard = PUBLISHED
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let snapshot = guard.get_or_insert_with(unconfigured);
                change(snapshot)
            }
        }
    }
}

impl Operator {
    /// A table over one fixed snapshot.
    #[must_use]
    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            source: Source::Fixed(snapshot),
            held_health: Vec::new(),
            held_count: None,
        }
    }

    /// A table over whatever is published, read at each call.
    #[must_use]
    pub fn live() -> Self {
        Self {
            source: Source::Published,
            held_health: Vec::new(),
            held_count: None,
        }
    }

    fn snapshot(&self) -> Snapshot {
        match &self.source {
            Source::Fixed(snapshot) => snapshot.clone(),
            Source::Published => PUBLISHED
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
                .unwrap_or_else(unconfigured),
        }
    }

    /// The C table over this operator. The surface holds the table and calls
    /// `destroy` when it is done; until then `self` must not move.
    #[must_use]
    pub fn table(self: Box<Self>) -> Operate {
        Operate {
            abi_version: xmip_abi::operate::XMIP_OPERATE_VERSION,
            ctx: Box::into_raw(self).cast(),
            health: Some(health_entry),
            measure: Some(measure_entry),
            pause: Some(pause_entry),
            resume: Some(resume_entry),
            destroy: Some(destroy_entry),
        }
    }
}

fn borrow(text: &str) -> Str {
    Str {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

/// The header's `int` for an observe `Health`.
const fn wire_health(value: Health) -> i32 {
    match value {
        Health::Green => health::GREEN,
        Health::Yellow => health::YELLOW,
        Health::Red => health::RED,
    }
}

/// An observe `Counted` for the header's `int`, or `None`.
const fn from_wire_counted(value: i32) -> Option<Counted> {
    match value {
        counted::STREAMS => Some(Counted::Streams),
        counted::MESSAGES => Some(Counted::Messages),
        counted::JOURNEYS => Some(Counted::Journeys),
        counted::BYTES => Some(Counted::Bytes),
        _ => None,
    }
}

/// The scope a surface passed, as `&str`, or `None` if it is not UTF-8 —
/// which the header says to answer with `XMIP_E_MALFORMED`.
///
/// # Safety
/// `scope` must point at `scope.len` readable bytes, as the header requires.
pub(crate) unsafe fn scope_text<'a>(scope: Str) -> Option<&'a str> {
    if scope.ptr.is_null() {
        return Some("");
    }

    // SAFETY: the caller upholds the header's contract on `scope`.
    let bytes = unsafe { core::slice::from_raw_parts(scope.ptr, scope.len) };

    core::str::from_utf8(bytes).ok()
}

/// `health` in the table. Fill up to `cap`, report the true count.
///
/// # Safety
/// `ctx` came from [`Operator::table`]; `out` has room for `cap` entries;
/// `out_len` is writable.
unsafe extern "C" fn health_entry(
    ctx: *mut u8,
    scope: Str,
    out: *mut HealthEntry,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let operator = unsafe { &mut *ctx.cast::<Operator>() };
    let Some(text) = (unsafe { scope_text(scope) }) else {
        return status::MALFORMED;
    };

    operator.held_health = operator.snapshot().health(text);

    // SAFETY: `out_len` is writable per the contract.
    unsafe { *out_len = operator.held_health.len() };

    if operator.held_health.is_empty() {
        return status::NOT_FOUND;
    }

    for (index, record) in operator.held_health.iter().take(cap).enumerate() {
        let entry = HealthEntry {
            scope: borrow(&record.scope),
            health: wire_health(record.health),
            severity: record.severity,
            evidence: borrow(&record.evidence),
            observed_unix_nanos: record.observed_unix_nanos,
        };

        // SAFETY: `index < cap` and `out` has room for `cap` entries.
        unsafe { out.add(index).write(entry) };
    }

    status::OK
}

/// `measure` in the table. One entry: the sum over the scope.
///
/// # Safety
/// As for [`health_entry`].
unsafe extern "C" fn measure_entry(
    ctx: *mut u8,
    scope: Str,
    what: i32,
    out: *mut Measurement,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let operator = unsafe { &mut *ctx.cast::<Operator>() };
    let Some(text) = (unsafe { scope_text(scope) }) else {
        return status::MALFORMED;
    };
    let Some(kind) = from_wire_counted(what) else {
        return status::INVALID;
    };

    operator.held_count = operator.snapshot().measure(text, kind);

    let Some(count) = &operator.held_count else {
        // SAFETY: `out_len` is writable per the contract.
        unsafe { *out_len = 0 };

        return status::NOT_FOUND;
    };

    // SAFETY: `out_len` is writable per the contract.
    unsafe { *out_len = 1 };

    if cap == 0 {
        return status::OK;
    }

    let entry = Measurement {
        scope: borrow(&count.scope),
        counted: what,
        value: count.value,
        window_start_unix_nanos: count.window_start_unix_nanos,
        window_end_unix_nanos: count.window_end_unix_nanos,
        observed_unix_nanos: count.observed_unix_nanos,
    };

    // SAFETY: `cap >= 1`, so `out` has room for one entry.
    unsafe { out.write(entry) };

    status::OK
}

/// `pause` in the table. Pause everything at and beneath the scope, by `who`.
///
/// The first operation on this boundary that acts rather than reads. It
/// changes the published snapshot, so the next read — by this table or any
/// other — sees the pause. `XMIP_E_NOT_FOUND` when the scope names nothing.
///
/// # Safety
/// `ctx` came from [`Operator::table`]; `scope` and `who` each point at their
/// stated length of readable bytes.
unsafe extern "C" fn pause_entry(ctx: *mut u8, scope: Str, who: Str) -> i32 {
    // SAFETY: per the contract above.
    let operator = unsafe { &mut *ctx.cast::<Operator>() };
    let (Some(text), Some(who)) = (unsafe { scope_text(scope) }, unsafe { scope_text(who) }) else {
        return status::MALFORMED;
    };

    let now = crate::start::now_unix_nanos();
    let paused = operator
        .source
        .mutate(|snapshot| snapshot.pause(text, who, now));

    if paused == 0 {
        status::NOT_FOUND
    } else {
        status::OK
    }
}

/// `resume` in the table. Resume everything at and beneath the scope.
///
/// # Safety
/// As for [`pause_entry`], without `who`.
unsafe extern "C" fn resume_entry(ctx: *mut u8, scope: Str) -> i32 {
    // SAFETY: per the contract above.
    let operator = unsafe { &mut *ctx.cast::<Operator>() };
    let Some(text) = (unsafe { scope_text(scope) }) else {
        return status::MALFORMED;
    };

    let resumed = operator.source.mutate(|snapshot| snapshot.resume(text));

    if resumed == 0 {
        status::NOT_FOUND
    } else {
        status::OK
    }
}

/// `destroy` in the table. After this nothing borrowed from it is valid.
///
/// # Safety
/// `ctx` came from [`Operator::table`] and is not used again.
unsafe extern "C" fn destroy_entry(ctx: *mut u8) {
    // SAFETY: `ctx` was produced by `Box::into_raw` in `table`.
    drop(unsafe { Box::from_raw(ctx.cast::<Operator>()) });
}

/// What this process has published. The runtime writes it as the node runs; the
/// export below hands a copy to whichever surface asks. A copy, so a surface
/// reading a table never blocks the node writing the next one — ADR-0027
/// clause 6 in one line.
static PUBLISHED: std::sync::Mutex<Option<Snapshot>> = std::sync::Mutex::new(None);

/// Publish the node's current snapshot for surfaces to read.
pub fn publish(snapshot: Snapshot) {
    *PUBLISHED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(snapshot);
}

/// The one symbol a surface loads. `XMIP_OPERATE_ENTRYPOINT` in the header.
///
/// Fills `out` and returns `XMIP_OK`, or returns a status and leaves `out`
/// untouched. A version this build does not speak is `XMIP_E_UNSUPPORTED`
/// here rather than a failure on the first call. A runtime that has published
/// nothing yet still answers — with [`unconfigured`], which is the truth about
/// it — rather than with an empty tree a surface would have to guess at.
///
/// # Safety
/// `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operate_v1(version: u32, out: *mut Operate) -> i32 {
    if version != xmip_abi::operate::XMIP_OPERATE_VERSION {
        return status::UNSUPPORTED;
    }

    // SAFETY: `out` is writable per the contract.
    unsafe { out.write(Box::new(Operator::live()).table()) };

    status::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        let mut snapshot = Snapshot::new();

        snapshot.record_health(HealthRecord {
            scope: "xmip:///edge-01/transport/ftp".into(),
            health: Health::Green,
            severity: 0,
            evidence: String::new(),
            observed_unix_nanos: 10,
        });
        snapshot.record_health(HealthRecord {
            scope: "xmip:///edge-01/transport/sftp".into(),
            health: Health::Red,
            severity: 90,
            evidence: "refused by partner-x".into(),
            observed_unix_nanos: 11,
        });
        snapshot.record_count(Count {
            scope: "xmip:///edge-01/transport/ftp".into(),
            counted: Counted::Streams,
            value: 40,
            window_start_unix_nanos: 0,
            window_end_unix_nanos: 60,
            observed_unix_nanos: 60,
        });
        snapshot.record_count(Count {
            scope: "xmip:///edge-01/transport/sftp".into(),
            counted: Counted::Streams,
            value: 2,
            window_start_unix_nanos: 0,
            window_end_unix_nanos: 60,
            observed_unix_nanos: 60,
        });

        snapshot
    }

    /// Read a `Str` the table handed back, as a surface would.
    fn text(value: Str) -> String {
        if value.ptr.is_null() {
            return String::new();
        }

        // SAFETY: the table promises `len` readable bytes until the next call.
        let bytes = unsafe { core::slice::from_raw_parts(value.ptr, value.len) };

        String::from_utf8(bytes.to_vec()).expect("UTF-8")
    }

    #[test]
    fn a_surface_reads_health_worst_first_through_the_table() {
        let table = Box::new(Operator::new(snapshot())).table();
        let mut out = [HealthEntry {
            scope: Str::empty(),
            health: 0,
            severity: 0,
            evidence: Str::empty(),
            observed_unix_nanos: 0,
        }; 4];
        let mut len = 0usize;

        // SAFETY: the table came from `Operator::table`; `out` has 4 entries.
        let code = unsafe {
            (table.health.expect("health"))(
                table.ctx,
                borrow("xmip:///edge-01"),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        };

        assert_eq!(code, status::OK);
        assert_eq!(len, 2);
        assert_eq!(out[0].health, health::RED);
        assert_eq!(text(out[0].evidence), "refused by partner-x");

        // SAFETY: not used after this.
        unsafe { (table.destroy.expect("destroy"))(table.ctx) };
    }

    #[test]
    fn a_short_buffer_is_told_the_true_count_and_nothing_is_truncated_silently() {
        let table = Box::new(Operator::new(snapshot())).table();
        let mut len = 0usize;

        // SAFETY: `cap` is 0, so `out` is never written.
        let code = unsafe {
            (table.health.expect("health"))(
                table.ctx,
                borrow("xmip:///edge-01"),
                core::ptr::null_mut(),
                0,
                &mut len,
            )
        };

        assert_eq!(code, status::OK);
        assert_eq!(len, 2, "the surface asks again with a bigger buffer");

        // SAFETY: not used after this.
        unsafe { (table.destroy.expect("destroy"))(table.ctx) };
    }

    #[test]
    fn a_node_measurement_is_the_sum_and_a_scope_with_nothing_is_not_found() {
        let table = Box::new(Operator::new(snapshot())).table();
        let mut out = Measurement {
            scope: Str::empty(),
            counted: 0,
            value: 0,
            window_start_unix_nanos: 0,
            window_end_unix_nanos: 0,
            observed_unix_nanos: 0,
        };
        let mut len = 0usize;

        // SAFETY: per the table's contract; `out` has room for one.
        let code = unsafe {
            (table.measure.expect("measure"))(
                table.ctx,
                borrow("xmip:///edge-01"),
                counted::STREAMS,
                &mut out,
                1,
                &mut len,
            )
        };

        assert_eq!(code, status::OK);
        assert_eq!(out.value, 42);

        // SAFETY: as above.
        let missing = unsafe {
            (table.measure.expect("measure"))(
                table.ctx,
                borrow("xmip:///nowhere"),
                counted::STREAMS,
                &mut out,
                1,
                &mut len,
            )
        };

        assert_eq!(missing, status::NOT_FOUND);
        assert_eq!(len, 0);

        // SAFETY: not used after this.
        unsafe { (table.destroy.expect("destroy"))(table.ctx) };
    }

    #[test]
    fn the_export_refuses_a_version_it_does_not_speak_and_leaves_out_alone() {
        let mut out = std::mem::MaybeUninit::<Operate>::uninit();

        // SAFETY: `out` is writable; on refusal it is not written.
        let code = unsafe { xmip_operate_v1(99, out.as_mut_ptr()) };

        assert_eq!(code, status::UNSUPPORTED);
    }

    #[test]
    fn a_table_handed_out_before_a_node_started_sees_it_afterwards() {
        let mut out = std::mem::MaybeUninit::<Operate>::uninit();

        // SAFETY: `out` is writable.
        let code =
            unsafe { xmip_operate_v1(xmip_abi::operate::XMIP_OPERATE_VERSION, out.as_mut_ptr()) };
        assert_eq!(code, status::OK);

        // SAFETY: the export wrote a complete table.
        let table = unsafe { out.assume_init() };

        // Published *after* the surface took its table — the order the GUI
        // does it in: load the library, then start the node. The first build
        // copied the snapshot at creation and never saw the node.
        publish(snapshot());

        let mut len = 0usize;

        // SAFETY: `cap` is 0, so nothing is written but `len`.
        let found = unsafe {
            (table.health.expect("health"))(
                table.ctx,
                borrow("xmip:///edge-01"),
                core::ptr::null_mut(),
                0,
                &mut len,
            )
        };

        assert_eq!(found, status::OK);
        assert_eq!(len, 2);

        // SAFETY: not used after this.
        unsafe { (table.destroy.expect("destroy"))(table.ctx) };
    }

    #[test]
    fn a_kind_this_build_does_not_know_is_refused_as_invalid() {
        let table = Box::new(Operator::new(snapshot())).table();
        let mut len = 0usize;

        // SAFETY: `cap` is 0, so `out` is never written.
        let code = unsafe {
            (table.measure.expect("measure"))(
                table.ctx,
                borrow("xmip:///edge-01"),
                99,
                core::ptr::null_mut(),
                0,
                &mut len,
            )
        };

        assert_eq!(code, status::INVALID);

        // SAFETY: not used after this.
        unsafe { (table.destroy.expect("destroy"))(table.ctx) };
    }
}
