//! A directory the operating system watches, and a thread told each time
//! it changes: how a program running a node is woken by a file another
//! process leaves for it — `xmip-service`'s orders (ADR-0018, amendment
//! 2026-09-30), a file Receive Location's drop directory (ADR-0024,
//! amendment 2026-10-20) — rather than looking again and again. A surface
//! is told, never asks (ADR-0052, amendment 2026-09-15), and a node is told
//! as a surface is.
//!
//! The thread waits in the kernel, using no processor, until a file is
//! created in the directory, renamed into it, closed after it was written
//! or, on Windows, removed from it or grown, and calls what it was given;
//! a change during the call is kept and
//! tells it again at once, so none is lost. Dropping the watch ends the
//! wait and joins the thread. Each operating system's own notification:
//! Windows a change notification (`ffi/directory_watch.rs`, where the
//! runtime keeps its unsafe calls), Linux and Android inotify, macOS and
//! the BSDs kqueue, the last two through `nix`'s safe calls.

use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

cfg_select! {
    windows => {
        use crate::ffi::directory_watch as os;
    }
    any(target_os = "linux", target_os = "android") => {
        mod inotify;
        use inotify as os;
    }
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ) => {
        mod kqueue;
        use kqueue as os;
    }
    _ => {
        compile_error!(
            "a directory is watched on Windows, Linux, Android, macOS, iOS and the BSDs only"
        );
    }
}

/// What says whether a watched file changed: when it was last written,
/// when it was made and its length; equal while the file is left alone.
/// Each is the operating system's own count, compared and never read as a
/// time. On Linux "made" is the file's inode, so a file renamed over it is
/// told apart; on Windows it is the creation time, which Windows gives back
/// to a file renamed over one within seconds (tunneling), so a copy that
/// kept the write time and length is told apart only by [`identity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub written: u64,
    pub made: u64,
    pub length: u64,
}

/// `path`'s stamp, or `None` where no file is there: asked of the operating
/// system without opening the file, so a surface asks it of a publication
/// on every question nothing told it of (`operate::surface::snapshot`) for
/// a few microseconds.
#[must_use]
pub fn stamp(path: &Path) -> Option<Stamp> {
    #[cfg(windows)]
    {
        crate::ffi::directory_watch::stamp(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file = std::fs::metadata(path)
            .ok()
            .filter(std::fs::Metadata::is_file)?;
        let written = u64::try_from(file.mtime()).unwrap_or(0) * 1_000_000_000
            + u64::try_from(file.mtime_nsec()).unwrap_or(0);
        Some(Stamp {
            written,
            made: file.ino(),
            length: file.size(),
        })
    }
}

/// Which file is at `path`: the number its volume gives it, which no file
/// renamed over it shares, however alike their stamps; `None` where no file
/// is there or it will not open this moment, as when a publisher renames
/// over it. Windows opens the file to ask, its attributes only and every
/// sharing allowed, for some microseconds, so a follow asks it once per
/// notice and a question never (`operate::surface::snapshot`); Unix answers
/// the inode without opening it.
#[must_use]
pub fn identity(path: &Path) -> Option<u128> {
    #[cfg(windows)]
    {
        crate::ffi::directory_watch::identity(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file = std::fs::metadata(path)
            .ok()
            .filter(std::fs::Metadata::is_file)?;
        Some(u128::from(file.dev()) << 64 | u128::from(file.ino()))
    }
}

/// A directory watched, and the thread told of its changes.
pub struct DirectoryWatch {
    changes: Arc<os::Changes>,
    thread: Option<JoinHandle<()>>,
}

impl DirectoryWatch {
    /// Watch `directory`, which exists, and call `changed` on a thread of
    /// its own each time it changes, until the watch is dropped.
    ///
    /// # Errors
    ///
    /// Where the operating system will not watch it, or start the thread.
    pub fn spawn(
        directory: &Path,
        mut changed: impl FnMut() + Send + 'static,
    ) -> std::io::Result<Self> {
        let changes = Arc::new(os::Changes::new(directory)?);
        let watching = Arc::clone(&changes);
        let thread = std::thread::Builder::new()
            .name("xmip-directory-watch".to_string())
            .spawn(move || {
                while watching.next() {
                    changed();
                }
            })?;
        Ok(Self {
            changes,
            thread: Some(thread),
        })
    }
}

impl Drop for DirectoryWatch {
    fn drop(&mut self) {
        self.changes.end();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use file::temporary::Folder;

    use super::*;

    fn directory(name: &str) -> Folder {
        Folder::new(&format!("runtime-directory-watch-{name}"))
    }

    #[test]
    fn a_file_renamed_into_the_directory_tells_the_watch() {
        let directory = directory("renamed");
        let (told, tells) = mpsc::channel();
        let watch = DirectoryWatch::spawn(&directory, move || {
            let _ = told.send(Instant::now());
        })
        .expect("watched");

        let part = directory.join("order.xmip.part");
        std::fs::write(&part, "an order").expect("written");
        let left = Instant::now();
        std::fs::rename(&part, directory.join("order.xmip")).expect("renamed");
        // Every change up to the rename tells; the last is the rename's.
        let mut last = tells.recv_timeout(Duration::from_secs(5)).expect("told");
        while let Ok(later) = tells.recv_timeout(Duration::from_millis(50)) {
            last = later;
        }
        assert!(last >= left, "told of the rename");

        drop(watch);
    }

    #[test]
    fn a_stamp_stays_while_the_file_is_left_alone_and_moves_when_it_is_replaced() {
        let directory = directory("stamp");
        let file = directory.join("C1-snapshot.xmip");
        assert_eq!(stamp(&file), None, "no file, no stamp");
        assert_eq!(stamp(&directory), None, "a directory is no file");

        std::fs::write(&file, "a publication").expect("written");
        let first = stamp(&file).expect("stamped");
        assert_eq!(first.length, 13);
        assert_eq!(stamp(&file), Some(first), "left alone");

        let part = directory.join("C1-snapshot.xmip.part");
        std::fs::write(&part, "another publication").expect("written");
        std::fs::rename(&part, &file).expect("renamed over");
        let second = stamp(&file).expect("stamped");
        assert_ne!(second, first, "replaced");
    }

    #[test]
    fn a_copy_renamed_over_a_file_is_another_file_however_alike_their_stamps() {
        let directory = directory("identity");
        let source = directory.join("prepared.xmip");
        let file = directory.join("C1-snapshot.xmip");
        assert_eq!(identity(&file), None, "no file, no identity");
        assert_eq!(identity(&directory), None, "a directory is no file");

        std::fs::write(&source, "a publication").expect("written");
        std::fs::copy(&source, &file).expect("copied");
        let first = identity(&file).expect("identified");
        assert_eq!(identity(&file), Some(first), "left alone");

        // The copy keeps the write time and length, and Windows gives the
        // name's creation time back to the file renamed over it.
        let part = directory.join("C1-snapshot.xmip.part");
        std::fs::copy(&source, &part).expect("copied");
        std::fs::rename(&part, &file).expect("renamed over");
        assert_ne!(identity(&file), Some(first), "replaced");
    }

    #[test]
    fn a_directory_that_is_not_there_is_refused() {
        let folder = directory("missing");
        let missing = folder.join("not-there");
        assert!(DirectoryWatch::spawn(&missing, || {}).is_err());
    }
}
