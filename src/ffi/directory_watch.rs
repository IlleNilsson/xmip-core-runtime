//! The calls into Windows a directory watch makes (`directory_watch`): a
//! change notification on the directory's file names, sizes and last
//! writes (`FindFirstChangeNotificationW`) and an event that ends the wait on it,
//! both waited on at once (`WaitForMultipleObjects`). Here because the
//! runtime keeps every unsafe call in this folder (ADR-0050).
#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
};

/// A directory's changes, and the event that ends the wait for them. The
/// handles are kept as numbers, as `net::pipe` keeps a pipe's, so the
/// watch is sent to the thread that waits; both are open from `new` until
/// `drop`, and only `drop` closes them.
pub(crate) struct Changes {
    change: usize,
    ended: usize,
}

impl Changes {
    /// Watch the files in `directory`: one created, renamed into it,
    /// removed, or written and closed is a change — the last so a file a
    /// producer wrote in place tells as it is finished.
    pub(crate) fn new(directory: &Path) -> std::io::Result<Self> {
        let wide: Vec<u16> = directory
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let filter =
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE;
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that lives across
        // the call; the handle returned is this watch's, closed in `drop`.
        let change = unsafe { FindFirstChangeNotificationW(wide.as_ptr(), 0, filter) };
        if change == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: no attributes and no name: an unnamed manual-reset event,
        // not set, this watch's own, closed in `drop`.
        let ended = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if ended.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: `change` was opened above and is closed once, here.
            unsafe { FindCloseChangeNotification(change) };
            return Err(error);
        }
        Ok(Self {
            change: change as usize,
            ended: ended as usize,
        })
    }

    /// Wait, using no processor, until the directory changes — `true`, the
    /// wait armed again for the next — or until [`Changes::end`] — `false`,
    /// as is a wait Windows refuses.
    pub(crate) fn next(&self) -> bool {
        let handles = [self.ended as HANDLE, self.change as HANDLE];
        // SAFETY: both handles are open until `drop`, which cannot run while
        // `&self` is borrowed; the array lives across the call. The end is
        // first, so a change and an end at once is the end.
        let woke = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
        // A change after the wake and before the wait is armed again is
        // kept by Windows and satisfies the next wait at once.
        // SAFETY: `change` is the open change notification.
        woke == WAIT_OBJECT_0 + 1
            && unsafe { FindNextChangeNotification(self.change as HANDLE) } != 0
    }

    /// End the wait, and every later one.
    pub(crate) fn end(&self) {
        // SAFETY: `ended` is the open event, until `drop`.
        unsafe { SetEvent(self.ended as HANDLE) };
    }
}

impl Drop for Changes {
    fn drop(&mut self) {
        // SAFETY: both were opened in `new`, nothing waits on them once the
        // last reference is dropped, and each is closed once, here.
        unsafe {
            FindCloseChangeNotification(self.change as HANDLE);
            CloseHandle(self.ended as HANDLE);
        }
    }
}
