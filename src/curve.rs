//! `xmip_operate.h` section 8, a curve: a node's throughput over time, read
//! by `observe::Curve` and handed to a surface as the header's measurements.
//!
//! The history file a publisher writes beside its publication had its shape
//! written by the Playground and walked again by the estate's
//! `Get-XmipHistory` until 2026-09-24 (open problem 25). This parses the text
//! by [`Curve::read`] and lays each point out as an `XmipMeasurement`,
//! borrowing every string from the curve it holds; the cmdlet reads it
//! through `Xmip.Abi`'s `PublicationReader` and walks no TOML.
//!
//! One of the files in this crate that dereference a pointer, for the reason
//! `operate.rs` gives: a surface hands over where to write.
#![allow(unsafe_code)]

use abi::ffi::{Str, status};
use abi::operate::Measurement;
use abi::operate::publication::Curve as Handle;
use observe::Curve;

use crate::operate::{borrow, scope_text};
use crate::publication::fill_copied;
use crate::rule::refuse;
use crate::wire::wire_counted;

/// A read curve and its points laid out as the header's, each string borrowed
/// from `curve`, whose buffers do not move while it lives.
struct Read {
    // Held for what `points` borrows; never read again.
    _curve: Curve,
    points: Vec<Measurement>,
}

impl Read {
    fn of(curve: Curve) -> Self {
        let points = curve
            .points
            .iter()
            .map(|point| Measurement {
                scope: borrow(&point.scope),
                counted: wire_counted(point.counted),
                value: point.value,
                window_start_unix_nanos: point.window_start_unix_nanos,
                window_end_unix_nanos: point.window_end_unix_nanos,
                observed_unix_nanos: point.observed_unix_nanos,
            })
            .collect();
        Self {
            _curve: curve,
            points,
        }
    }
}

/// `observe::Curve::read`, into a handle, or the reader's refusal.
///
/// # Safety
/// `text` points at its stated length of readable bytes; `out` and
/// `out_len` are writable; `report` has room for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_curve_read_v1(
    text: Str,
    out: *mut *mut Handle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller upholds the header's contract on `text`.
    let Some(text) = (unsafe { scope_text(text) }) else {
        return status::MALFORMED;
    };

    match Curve::read(text) {
        Ok(curve) => {
            let read = Box::into_raw(Box::new(Read::of(curve)));
            // SAFETY: `out` and `out_len` are writable per the contract.
            unsafe {
                *out = read.cast::<Handle>();
                *out_len = 0;
            }
            status::OK
        }
        Err(said) => {
            // SAFETY: per the contract above.
            unsafe {
                *out = core::ptr::null_mut();
                refuse(&said, report, cap, out_len);
            }
            status::INVALID
        }
    }
}

/// The curve's points, in the fill shape.
///
/// # Safety
/// `curve` is a live handle; `out` has room for `cap` entries; `out_len` is
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_curve_points_v1(
    curve: *const Handle,
    out: *mut Measurement,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    match unsafe { curve.cast::<Read>().as_ref() } {
        // SAFETY: per the contract above.
        Some(read) => unsafe { fill_copied(&read.points, out, cap, out_len) },
        None => status::INVALID,
    }
}

/// Release a curve's handle and everything borrowed from it.
///
/// # Safety
/// `curve` is null or a handle `xmip_curve_read_v1` returned and nobody
/// freed; nothing borrowed from it is used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_curve_free_v1(curve: *mut Handle) {
    if !curve.is_null() {
        // SAFETY: per the contract above, the box this handle was made from.
        drop(unsafe { Box::from_raw(curve.cast::<Read>()) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::operate::{counted, publication};

    fn read(text: &str) -> (i32, *mut Handle) {
        let mut handle = core::ptr::null_mut();
        let mut report = [0u8; 256];
        let mut len = 0usize;
        // SAFETY: `text` is live; every out is writable.
        let code = unsafe {
            xmip_curve_read_v1(
                borrow(text),
                &raw mut handle,
                report.as_mut_ptr(),
                report.len(),
                &raw mut len,
            )
        };
        (code, handle)
    }

    #[test]
    fn every_export_has_the_shape_the_binding_declares() {
        let _: publication::CurveReadFn = xmip_curve_read_v1;
        let _: publication::CurvePointsFn = xmip_curve_points_v1;
        let _: publication::CurveFreeFn = xmip_curve_free_v1;
    }

    #[test]
    fn a_curve_crosses_as_observe_reads_it_and_a_stranger_is_refused() {
        let (code, handle) = read(
            "node = 'xmip:///n'\n[[points]]\ncounted = 'bytes'\nvalue = 9\n\
             observed_unix_nanos = 3\n[[points]]\ncounted = 'throughput'\n",
        );
        assert_eq!(code, status::OK);

        let mut points = [Measurement {
            scope: Str::empty(),
            counted: 0,
            value: 0,
            window_start_unix_nanos: 0,
            window_end_unix_nanos: 0,
            observed_unix_nanos: 0,
        }; 2];
        let mut len = 0usize;
        // SAFETY: a live handle; `points` has room for two.
        let code = unsafe { xmip_curve_points_v1(handle, points.as_mut_ptr(), 2, &raw mut len) };
        assert_eq!((code, len), (status::OK, 1), "an unknown kind is skipped");
        assert_eq!(
            (
                points[0].counted,
                points[0].value,
                points[0].observed_unix_nanos
            ),
            (counted::BYTES, 9, 3)
        );
        // SAFETY: freed once.
        unsafe { xmip_curve_free_v1(handle) };

        let (code, handle) = read("points = 3");
        assert_eq!(code, status::INVALID);
        assert!(handle.is_null());
    }
}
