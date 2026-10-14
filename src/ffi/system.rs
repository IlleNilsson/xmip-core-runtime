//! The two calls into Windows the local operate endpoint makes that its
//! pipe library does not (`plane::local`; ADR-0014, amendment 2026-10-13):
//! ending a read waiting on a pipe from another thread, and the name of the
//! user a pipe's client runs as. Here because the runtime keeps every
//! unsafe call in this folder (ADR-0050).
#![allow(unsafe_code)]

/// Cancel every read and write in flight on the pipe whose handle `open`
/// holds, from any thread (`CancelIoEx`); nothing where it holds none. A
/// pipe's stream clears `open` under its lock before its handle closes, so
/// the handle cancelled is never one reused for something else.
pub(crate) fn cancel_io(open: &std::sync::Mutex<Option<usize>>) {
    use windows_sys::Win32::System::IO::CancelIoEx;
    let open = open
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(handle) = *open {
        // SAFETY: the handle is open — the lock it was read under is held,
        // and its stream clears it under that lock before the handle closes.
        unsafe {
            CancelIoEx(
                handle as windows_sys::Win32::Foundation::HANDLE,
                std::ptr::null(),
            )
        };
    }
}

/// The calling thread's user, as `DOMAIN\user` (`GetUserNameExW`); while a
/// pipe's client is impersonated, the client's.
///
/// # Errors
///
/// Where Windows does not say.
#[cfg(feature = "node")]
pub(crate) fn user_name() -> Result<String, String> {
    use windows_sys::Win32::Security::Authentication::Identity::{
        GetUserNameExW, NameSamCompatible,
    };
    let unknown = || {
        format!(
            "the caller is not known: {}",
            std::io::Error::last_os_error()
        )
    };
    let mut size = 0u32;
    // SAFETY: a null buffer of size 0 asks only for the size.
    unsafe { GetUserNameExW(NameSamCompatible, std::ptr::null_mut(), &raw mut size) };
    if size == 0 {
        return Err(unknown());
    }
    let mut name = vec![0u16; size as usize];
    // SAFETY: `name` has room for `size` characters, as `size` says.
    let named = unsafe { GetUserNameExW(NameSamCompatible, name.as_mut_ptr(), &raw mut size) };
    if !named {
        return Err(unknown());
    }
    name.truncate(size as usize);
    Ok(String::from_utf16_lossy(&name))
}
