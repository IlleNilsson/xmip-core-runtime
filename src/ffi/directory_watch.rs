//! The calls into Windows a directory watch makes (`directory_watch`): a
//! change notification on the directory's file names, sizes and last
//! writes (`FindFirstChangeNotificationW`) and an event that ends the wait on it,
//! both waited on at once (`WaitForMultipleObjects`), and a file's stamp
//! and identity. Here because the runtime keeps every unsafe call in this
//! folder (ADR-0050).
#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ID_128, FILE_ID_INFO, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
    GetFileAttributesExW, GetFileExInfoStandard, GetFileInformationByHandleEx,
    WIN32_FILE_ATTRIBUTE_DATA,
};

use crate::directory_watch::Stamp;
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
    /// producer wrote in place tells as it is finished — and so is a folder
    /// made in it or taken away, as inotify and kqueue tell one.
    pub(crate) fn new(directory: &Path) -> std::io::Result<Self> {
        let wide = codec::wide::terminated(directory.as_os_str().encode_wide())
            .map_err(std::io::Error::other)?;
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE;
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

/// `path`'s stamp from its attributes, the file left unopened
/// (`GetFileAttributesExW`); `None` where it is not there, is a folder, or
/// the path is no wide string.
pub(crate) fn stamp(path: &Path) -> Option<Stamp> {
    let wide = codec::wide::terminated(path.as_os_str().encode_wide()).ok()?;
    let mut data = WIN32_FILE_ATTRIBUTE_DATA {
        dwFileAttributes: 0,
        ftCreationTime: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ftLastAccessTime: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        ftLastWriteTime: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
    };
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that lives across the
    // call, and `data` is the structure GetFileExInfoStandard writes, owned
    // here and alive across it.
    let read = unsafe {
        GetFileAttributesExW(wide.as_ptr(), GetFileExInfoStandard, (&raw mut data).cast())
    };
    let time = |at: FILETIME| u64::from(at.dwHighDateTime) << 32 | u64::from(at.dwLowDateTime);

    (read != 0 && data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0).then(|| Stamp {
        written: time(data.ftLastWriteTime),
        made: time(data.ftCreationTime),
        length: u64::from(data.nFileSizeHigh) << 32 | u64::from(data.nFileSizeLow),
    })
}

/// `path`'s file ID on its volume (`GetFileInformationByHandleEx`,
/// `FileIdInfo`): the file opened for its attributes only, every sharing
/// allowed, so a publisher renaming over it is not held up; `None` where it
/// is not there, is a folder, or will not open this moment.
pub(crate) fn identity(path: &Path) -> Option<u128> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .ok()?;
    let mut info = FILE_ID_INFO {
        VolumeSerialNumber: 0,
        FileId: FILE_ID_128 {
            Identifier: [0; 16],
        },
    };
    let size = u32::try_from(size_of::<FILE_ID_INFO>()).ok()?;
    // SAFETY: the handle is `file`'s, open across the call, and `info` is
    // the structure `FileIdInfo` writes, owned here, alive across the call
    // and of the size given.
    let read = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            size,
        )
    };
    (read != 0).then(|| u128::from_le_bytes(info.FileId.Identifier))
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
