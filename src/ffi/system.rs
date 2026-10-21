//! The calls into Windows the local operate endpoint makes that its pipe
//! library does not (`plane::local`; ADR-0014, amendment 2026-10-13; open
//! problem 35): opening a pipe as a client that lets the node identify it
//! and nothing more, ending a read waiting on a pipe from another thread,
//! the account a pipe's client runs as, and the security identifier of an
//! account the configuration admits. Here because the runtime keeps every
//! unsafe call in this folder (ADR-0050).
#![allow(unsafe_code)]

use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::time::Duration;

use widestring::U16CStr;

/// Open the named pipe at `path` as a client the server may identify and
/// never act as: `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so a
/// node — or whatever made a pipe of that name first — learns the caller's
/// account and cannot impersonate it beyond reading who it is. Read and
/// write the data only: a client asks for no right to make an instance of
/// the pipe. `None` where every instance is busy.
pub(crate) fn open_identifying(path: &U16CStr) -> Option<std::io::Result<OwnedHandle>> {
    use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
        OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    // SAFETY: `path` ends in NUL, as a `U16CStr` does; every other
    // argument is a constant or null.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        let busy = error.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok();
        return (!busy).then_some(Err(error));
    }
    // SAFETY: just opened, and owned by nothing else.
    Some(Ok(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

/// Wait at most `within` for an instance of the pipe at `path` to be free;
/// whether one is.
pub(crate) fn wait_free(path: &U16CStr, within: Duration) -> bool {
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
    let milliseconds = u32::try_from(within.as_millis()).unwrap_or(u32::MAX).max(1);
    // SAFETY: `path` ends in NUL, as a `U16CStr` does.
    unsafe { WaitNamedPipeW(path.as_ptr(), milliseconds) != 0 }
}

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

/// The calling thread's impersonation token, as a pipe's client lent it:
/// the security identifier of its user and the level it was lent at
/// (`SECURITY_IMPERSONATION_LEVEL`). Opened as the process, since a token
/// lent for identification alone cannot open itself.
///
/// # Errors
///
/// Where the thread impersonates nobody, or Windows does not say.
#[cfg(feature = "node")]
pub(crate) fn impersonated() -> Result<(Vec<u32>, i32), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the current thread's pseudo-handle, and a place for the token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        return Err(unknown("the thread holds no caller's token"));
    }
    let read = user_and_level(token);
    // SAFETY: opened above, closed once.
    unsafe { CloseHandle(token) };
    read
}

#[cfg(feature = "node")]
fn user_and_level(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(Vec<u32>, i32), String> {
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TOKEN_USER, TokenImpersonationLevel, TokenUser,
    };
    let mut size = 0u32;
    // SAFETY: a null buffer of size 0 asks only for the size.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut size) };
    let mut user = vec![0u64; (size as usize).div_ceil(8).max(1)];
    // SAFETY: `user` has room for `size` bytes, aligned for a TOKEN_USER.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            user.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    };
    if read == 0 {
        return Err(unknown("the caller's token names no user"));
    }
    // SAFETY: Windows wrote a TOKEN_USER at the start of `user`, and the
    // identifier it points at lies within it, `GetLengthSid` bytes long.
    let sid = unsafe {
        let sid = (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        let length = GetLengthSid(sid) as usize;
        let mut words = vec![0u32; length.div_ceil(4)];
        std::ptr::copy_nonoverlapping(sid.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), length);
        words
    };
    let mut level = 0i32;
    let mut written = 0u32;
    // SAFETY: `level` is the SECURITY_IMPERSONATION_LEVEL Windows writes.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenImpersonationLevel,
            (&raw mut level).cast(),
            4,
            &raw mut written,
        )
    };
    if read == 0 {
        return Err(unknown("the caller's token names no level"));
    }
    Ok((sid, level))
}

/// The level a client lends its token at to be identified and nothing
/// more (`SecurityIdentification`), which a test holds every surface to.
#[cfg(all(test, feature = "node"))]
pub(crate) const IDENTIFICATION: i32 = windows_sys::Win32::Security::SecurityIdentification;

/// The account `sid` names, `DOMAIN\user` as Windows writes it in a login.
///
/// # Errors
///
/// Where Windows knows no account by it.
#[cfg(feature = "node")]
pub(crate) fn account_name(sid: &[u32]) -> Result<String, String> {
    use windows_sys::Win32::Security::LookupAccountSidW;
    let pointer = sid.as_ptr().cast_mut().cast();
    let (mut name_size, mut domain_size, mut kind) = (0u32, 0u32, 0i32);
    // SAFETY: null buffers of size 0 ask only for the sizes.
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            pointer,
            std::ptr::null_mut(),
            &raw mut name_size,
            std::ptr::null_mut(),
            &raw mut domain_size,
            &raw mut kind,
        )
    };
    let mut name = vec![0u16; name_size.max(1) as usize];
    let mut domain = vec![0u16; domain_size.max(1) as usize];
    // SAFETY: each buffer has room for the characters its size says.
    let named = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            pointer,
            name.as_mut_ptr(),
            &raw mut name_size,
            domain.as_mut_ptr(),
            &raw mut domain_size,
            &raw mut kind,
        )
    };
    if named == 0 {
        return Err(unknown("no account has the caller's identifier"));
    }
    let name = String::from_utf16_lossy(&name[..name_size as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_size as usize]);
    Ok(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

/// The security identifier of the account or group called `name`, as SDDL
/// writes one: `S-1-5-32-545`.
///
/// # Errors
///
/// Where Windows knows no account or group by that name, in words.
#[cfg(feature = "node")]
pub(crate) fn account_sid(name: &str) -> Result<String, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::LookupAccountNameW;
    let wide = widestring::U16CString::from_str(name).map_err(|error| error.to_string())?;
    let (mut sid_size, mut domain_size, mut kind) = (0u32, 0u32, 0i32);
    // SAFETY: `wide` ends in NUL; null buffers of size 0 ask only for sizes.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wide.as_ptr(),
            std::ptr::null_mut(),
            &raw mut sid_size,
            std::ptr::null_mut(),
            &raw mut domain_size,
            &raw mut kind,
        )
    };
    let mut sid = vec![0u32; (sid_size as usize).div_ceil(4).max(1)];
    let mut domain = vec![0u16; domain_size.max(1) as usize];
    // SAFETY: each buffer has room for what its size says.
    let found = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wide.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_size,
            domain.as_mut_ptr(),
            &raw mut domain_size,
            &raw mut kind,
        )
    };
    if found == 0 {
        return Err(format!(
            "Windows knows no account or group called \"{name}\": {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` holds the identifier Windows wrote; `text` receives a
    // string Windows allocates, freed below.
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &raw mut text) } == 0 {
        return Err(unknown("the identifier has no text"));
    }
    // SAFETY: Windows wrote a NUL-terminated string at `text`.
    let written = unsafe { widestring::U16CStr::from_ptr_str(text) }.to_string_lossy();
    // SAFETY: allocated by ConvertSidToStringSidW, freed once.
    unsafe { LocalFree(text.cast()) };
    Ok(written)
}

/// Windows' last error, as a refusal saying `what`.
#[cfg(feature = "node")]
fn unknown(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}
