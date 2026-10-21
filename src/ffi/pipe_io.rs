//! A named pipe's reads and writes, either end, on the handle it was
//! opened or connected with (`plane::local`): overlapped, each operation
//! waited for on an event of the connection's own, and cancellable from
//! another thread (`ffi::system::cancel_io`). Here rather than in the pipe
//! library, whose stream opens a handle it is given again and closes the
//! original — on a pipe a second connection, and the end of the first
//! (`ffi::pipe` says what that cost). A read finding its peer gone is the
//! end, `Ok(0)`.
#![allow(unsafe_code)]

use std::os::windows::io::{AsRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_NOT_CONNECTED, HANDLE,
};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows_sys::core::BOOL;

/// The event one connection's operations are waited for on, one at a time.
pub(crate) struct Event(HANDLE);

// SAFETY: an event handle may be waited on and closed from any thread.
unsafe impl Send for Event {}
// SAFETY: as above; the connection waits on it from one thread at a time.
unsafe impl Sync for Event {}

impl Event {
    /// A manual-reset event, which each read and write resets as it starts.
    ///
    /// # Errors
    ///
    /// Where Windows makes none.
    pub(crate) fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        // SAFETY: unnamed, with no attributes.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self(event))
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: made by `new`, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Read into `buffer` from `pipe`, waiting until something comes: how much
/// was read, `0` where the peer is gone.
///
/// # Errors
///
/// The read's failure, or its cancel.
pub(crate) fn read(pipe: &OwnedHandle, event: &Event, buffer: &mut [u8]) -> std::io::Result<usize> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    let handle = pipe.as_raw_handle() as HANDLE;
    let read = waited(pipe, event, |overlapped| {
        // SAFETY: `buffer` holds `length` bytes and outlives the operation,
        // which `waited` ends before it returns.
        unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                length,
                std::ptr::null_mut(),
                overlapped,
            )
        }
    });
    match read {
        Err(error) if gone(&error) => Ok(0),
        read => read,
    }
}

/// Write `bytes` to `pipe`: how many were written.
///
/// # Errors
///
/// The write's failure, its cancel, or a peer gone.
pub(crate) fn write(pipe: &OwnedHandle, event: &Event, bytes: &[u8]) -> std::io::Result<usize> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let handle = pipe.as_raw_handle() as HANDLE;
    waited(pipe, event, |overlapped| {
        // SAFETY: `bytes` holds `length` bytes and outlives the operation,
        // which `waited` ends before it returns.
        unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                length,
                std::ptr::null_mut(),
                overlapped,
            )
        }
    })
}

/// Whether `error` says the peer is gone.
fn gone(error: &std::io::Error) -> bool {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .is_some_and(|code| code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED)
}

/// One overlapped operation `start` begins on `pipe` with `event`, waited
/// for to its end: how many bytes it moved.
fn waited(
    pipe: &OwnedHandle,
    event: &Event,
    start: impl FnOnce(*mut OVERLAPPED) -> BOOL,
) -> std::io::Result<usize> {
    // SAFETY: all zero is an OVERLAPPED's initial state.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.0;
    if start(&raw mut overlapped) == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != i32::try_from(ERROR_IO_PENDING).ok() {
            return Err(error);
        }
    }
    let mut moved = 0u32;
    // SAFETY: the operation started on `pipe` with `overlapped`, which lives
    // until it has ended: this waits for that (`bWait`).
    let ended = unsafe {
        GetOverlappedResult(
            pipe.as_raw_handle() as HANDLE,
            &raw const overlapped,
            &raw mut moved,
            1,
        )
    };
    if ended == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(moved as usize)
}
