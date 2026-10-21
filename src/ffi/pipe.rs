//! The server end of the local operate endpoint's named pipe on Windows
//! (`plane::local`): each instance made, and a client waited for on it,
//! here rather than in the pipe library, as the pipe's reads and writes are
//! (`ffi::pipe_io`).
//!
//! The library's accept waits for a client by `ConnectNamedPipe` with no
//! `OVERLAPPED` on an instance opened overlapped, which Windows documents
//! as unsound (*may incorrectly report that the connect operation is
//! complete*), and clears an instance it judges empty with
//! `DisconnectNamedPipe`; and its stream, made from a handle, opens the
//! handle again (`ReOpenFile`) and closes the one it was given, which on a
//! pipe is a second connection and the first one's end. Together a caller
//! connected twice, the node held the connection the caller had let go,
//! and read nothing from a caller that was connected and waiting on the
//! other (2026-10-21, open problem 35). Here an instance is waited on with
//! an `OVERLAPPED` of its own and never disconnected, the handle a client
//! reached is the one read, and the next instance is made before the
//! connected one is handed out, so a client always finds one listening.
#![allow(unsafe_code)]

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use widestring::U16CStr;

/// Who may open a pipe, as Windows holds a security descriptor: read once
/// from SDDL and kept for every instance the pipe makes.
pub(crate) struct Descriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is read-only once made, and freed once, on drop.
unsafe impl Send for Descriptor {}
// SAFETY: as above.
unsafe impl Sync for Descriptor {}

impl Descriptor {
    /// The descriptor `sddl` writes.
    ///
    /// # Errors
    ///
    /// Where Windows does not read it.
    pub(crate) fn from_sddl(sddl: &U16CStr) -> std::io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `sddl` ends in NUL; `descriptor` receives what Windows
        // allocates, freed on drop.
        let read = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion, freed once.
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
    }
}

/// A new instance of the pipe at `path`, overlapped, byte mode, refusing
/// clients from another machine, each direction holding `buffer` bytes,
/// opened only by whom `descriptor` admits — the first of its name where
/// `first`, so a pipe another process made already is refused.
///
/// # Errors
///
/// Where Windows refuses the instance.
pub(crate) fn instance(
    path: &U16CStr,
    descriptor: &Descriptor,
    first: bool,
    buffer: u32,
) -> std::io::Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let first = if first {
        FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        0
    };
    let open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first;
    let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: `path` ends in NUL; `attributes` and its descriptor live
    // across the call.
    let handle = unsafe {
        CreateNamedPipeW(
            path.as_ptr(),
            open,
            mode,
            PIPE_UNLIMITED_INSTANCES,
            buffer,
            buffer,
            0,
            &raw const attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: just made, and owned by nothing else.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
/// Wait until a client has connected to the listening instance `pipe`,
/// with an `OVERLAPPED` of its own. A client connected already, or one
/// connected and gone — whose first read then says it is gone — returns at
/// once.
///
/// # Errors
///
/// Where Windows refuses the wait.
pub(crate) fn connected(pipe: &OwnedHandle) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, HANDLE,
    };
    use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
    use windows_sys::Win32::System::Threading::CreateEventW;
    let pipe = pipe.as_raw_handle() as HANDLE;
    // SAFETY: a manual-reset event, unnamed, with no attributes.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: all zero is an OVERLAPPED's initial state.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event;
    // SAFETY: `pipe` is open for the call, and `overlapped` outlives the
    // operation, which is waited for below before it drops.
    let waited = if unsafe { ConnectNamedPipe(pipe, &raw mut overlapped) } != 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        match error
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
        {
            Some(ERROR_PIPE_CONNECTED | ERROR_NO_DATA) => Ok(()),
            Some(ERROR_IO_PENDING) => {
                let mut moved = 0u32;
                // SAFETY: the operation started above on `pipe` with
                // `overlapped`; waiting for it to end (`bWait`).
                let ended =
                    unsafe { GetOverlappedResult(pipe, &raw const overlapped, &raw mut moved, 1) };
                if ended == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
            _ => Err(error),
        }
    };
    // SAFETY: made above, closed once, after the operation ended.
    unsafe { CloseHandle(event) };
    waited
}

/// `act` run while this thread stands in for the client of the connected
/// instance `pipe` — at the level the client lent, identification alone
/// from every surface — and back to itself after, acted or not.
///
/// # Errors
///
/// Where Windows lends nothing: a client that sent nothing yet.
pub(crate) fn impersonating<T>(pipe: &OwnedHandle, act: impl FnOnce() -> T) -> std::io::Result<T> {
    use windows_sys::Win32::Security::RevertToSelf;
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    // SAFETY: `pipe` is an open server instance.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let acted = act();
    // SAFETY: the thread impersonates the client since the call above.
    unsafe { RevertToSelf() };
    Ok(acted)
}
