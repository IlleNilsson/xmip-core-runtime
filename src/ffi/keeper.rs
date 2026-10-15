//! `xmip_operate.h` section 17, the remote open whose key its platform's
//! keeper holds (ADR-0034, amendment 2026-10-15): the surface hands the
//! certificate chain and a signing callback instead of the key's PEM, and
//! every signature the handshake needs is asked of the callback — the
//! Android Keystore, the Secure Enclave, Windows CNG behind it. The signer
//! is `tls::Sign`, once; this lays the callback out as one and decides
//! nothing.
#![allow(unsafe_code)]

use std::sync::Arc;

use abi::ffi::{Slice, Str, status};
use abi::operate::remote::{Remote as RemoteHandle, SignFn};

use crate::ffi::remote::handed;
use crate::ffi::text::scope_text;
use crate::plane::Remote;

/// Room for a signature, and for a keeper's sentence where it refuses: a
/// P-256 signature in DER is at most 72 bytes.
const ROOM: usize = 512;

/// The surface's callback and the context it is called with.
struct Keeper {
    sign: SignFn,
    context: usize,
}

impl tls::Sign for Keeper {
    fn sign(&self, message: &[u8]) -> tls::Result<Vec<u8>> {
        let mut room = [0u8; ROOM];
        let mut length = 0usize;
        let lent = Slice {
            ptr: message.as_ptr(),
            len: message.len(),
        };
        // SAFETY: the surface promised, opening the handle, that `sign`
        // may be called with `context` from any thread until the handle is
        // freed; `room` and `length` are live and writable.
        let code = unsafe {
            (self.sign)(
                self.context as *mut core::ffi::c_void,
                lent,
                room.as_mut_ptr(),
                room.len(),
                &raw mut length,
            )
        };
        let written = &room[..length.min(ROOM)];
        match code {
            status::OK if length <= ROOM => Ok(written.to_vec()),
            status::OK => Err(tls::TlsError::new(format!(
                "the keeper's signature is {length} bytes, more than the {ROOM} it is given"
            ))),
            _ => Err(tls::TlsError::new(String::from_utf8_lossy(written))),
        }
    }
}

/// `crate::plane::Remote::open` over the node at `address`, presenting
/// `certificate`, a PEM chain, whose key the surface's keeper holds: `sign`
/// is called with `context` for every signature, and the node is taken
/// only where its certificate reaches `anchors`, PEM.
///
/// # Safety
/// The strings point at their stated lengths; `sign` may be called with
/// `context` from any thread, at once from several, until the handle is
/// freed; `out` is writable; `report` has room for `cap` bytes and
/// `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_remote_open_kept_v1(
    address: Str,
    certificate: Str,
    anchors: Str,
    sign: SignFn,
    context: *mut core::ffi::c_void,
    out: *mut *mut RemoteHandle,
    report: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let texts = unsafe {
        (
            scope_text(address),
            scope_text(certificate),
            scope_text(anchors),
        )
    };
    let (Some(address), Some(certificate), Some(anchors)) = texts else {
        return status::MALFORMED;
    };
    let keeper = Arc::new(Keeper {
        sign,
        context: context as usize,
    });
    let opened = tls::Identity::from_signer(certificate.as_bytes(), keeper, anchors.as_bytes())
        .map_err(|failed| failed.message)
        .and_then(|identity| Remote::open(address, &identity));
    // SAFETY: per the contract above.
    unsafe { handed(opened, out, report, cap, out_len) }
}

#[cfg(all(test, feature = "node"))]
mod tests {
    use abi::operate::remote::Served;

    use super::*;
    use crate::ffi::remote::{xmip_remote_act_v1, xmip_remote_free_v1};
    use crate::ffi::served::{
        xmip_operate_serve_stop_v1, xmip_operate_serve_v1, xmip_operate_served_address_v1,
    };
    use crate::ffi::text::borrow;
    use crate::fixture::Authority;

    /// The keeper a test stands in: a key this side holds, or none.
    unsafe extern "C" fn keeper(
        context: *mut core::ffi::c_void,
        message: Slice,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> i32 {
        // SAFETY: the test lends a live key, or null, as the context.
        let key = unsafe { context.cast::<provision::KeyPair>().as_ref() };
        // SAFETY: the runtime lends the message for the call.
        let message = unsafe { core::slice::from_raw_parts(message.ptr, message.len) };
        let (code, bytes) = match key.map(|key| key.sign(message)) {
            Some(Ok(signature)) => (status::OK, signature),
            _ => (status::AUTH, b"the user said no".to_vec()),
        };
        // SAFETY: `out` has room for `cap` bytes and `out_len` is writable.
        unsafe { crate::ffi::rule::hand(&bytes, out, cap, out_len) };
        code
    }

    #[test]
    fn the_header_states_the_kept_open() {
        let _: abi::operate::remote::OpenKeptFn = xmip_remote_open_kept_v1;
    }

    #[test]
    fn a_key_its_keeper_holds_is_the_caller_the_listener_proves() {
        let authority = Authority::new();
        let (certificate, key, anchors) = authority.pem("node");
        let mut report = vec![0u8; 4096];
        let mut length = 0usize;
        let mut served: *mut Served = std::ptr::null_mut();
        // SAFETY: every pointer is to live storage of its stated size.
        let code = unsafe {
            xmip_operate_serve_v1(
                borrow("127.0.0.1:0"),
                borrow(&certificate),
                borrow(&key),
                borrow(&anchors),
                borrow(""),
                borrow("keeper-exports-test"),
                &raw mut served,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        let mut address = vec![0u8; 256];
        // SAFETY: as above.
        unsafe {
            xmip_operate_served_address_v1(
                served,
                address.as_mut_ptr(),
                address.len(),
                &raw mut length,
            );
        }
        let address = String::from_utf8_lossy(&address[..length]).to_string();

        let (chain, key, anchors) = authority.pem("phone");
        let kept = provision::KeyPair::from_pem(&key).expect("the keeper's key");
        let act = |context: *mut core::ffi::c_void| {
            let mut remote: *mut RemoteHandle = std::ptr::null_mut();
            let mut said = vec![0u8; 4096];
            let mut length = 0usize;
            // SAFETY: as above; the context outlives the handle.
            unsafe {
                let code = xmip_remote_open_kept_v1(
                    borrow(&address),
                    borrow(&chain),
                    borrow(&anchors),
                    keeper,
                    context,
                    &raw mut remote,
                    said.as_mut_ptr(),
                    said.len(),
                    &raw mut length,
                );
                assert_eq!(code, status::OK);
                let code = xmip_remote_act_v1(
                    remote,
                    borrow(&crate::fixture::absent_node()),
                    borrow("subscription"),
                    borrow("orders"),
                    borrow("pause"),
                    said.as_mut_ptr(),
                    said.len(),
                    &raw mut length,
                );
                xmip_remote_free_v1(remote);
                (code, String::from_utf8_lossy(&said[..length]).to_string())
            }
        };

        let (code, said) = act((&raw const kept).cast_mut().cast());
        assert_eq!(code, status::AUTH, "{said}");
        assert!(said.starts_with("REFUSED. CN=phone"), "{said}");
        let (code, said) = act(std::ptr::null_mut());
        assert_eq!(code, status::UNAVAILABLE, "{said}");

        // SAFETY: `served` is live, and freed once.
        unsafe { xmip_operate_serve_stop_v1(served) };
    }
}
