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

#[cfg(windows)]
use crate::ffi::directory_watch as os;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod inotify;
#[cfg(any(target_os = "linux", target_os = "android"))]
use inotify as os;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod kqueue;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use kqueue as os;
#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
compile_error!("a directory is watched on Windows, Linux, Android, macOS, iOS and the BSDs only");

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

    use super::*;

    fn directory(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "xmip-directory-watch-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a directory");
        directory
    }

    #[test]
    fn a_file_renamed_into_the_directory_tells_the_watch() {
        let directory = directory("renamed");
        let (told, tells) = mpsc::channel();
        let watch = DirectoryWatch::spawn(&directory, move || {
            let _ = told.send(Instant::now());
        })
        .expect("watched");

        let part = directory.join("order.toml.part");
        std::fs::write(&part, "an order").expect("written");
        let left = Instant::now();
        std::fs::rename(&part, directory.join("order.toml")).expect("renamed");
        // Every change up to the rename tells; the last is the rename's.
        let mut last = tells.recv_timeout(Duration::from_secs(5)).expect("told");
        while let Ok(later) = tells.recv_timeout(Duration::from_millis(50)) {
            last = later;
        }
        assert!(last >= left, "told of the rename");

        drop(watch);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_dropped_watch_ends_its_thread_at_once() {
        // Held as the fastest of five beside the machine's own wake, round
        // by round (`xcore::latency`): a drop wakes the watching thread and
        // then this one as it joins, two wakes, under about a millisecond.
        // Each watch is dropped once its thread is watching, as a watch is
        // when a Location stops: told of a change first, so what is
        // measured is the drop, never the thread's start on a machine with
        // no processor free for it.
        use xcore::latency::{FIVE, PlainWake, spread};
        let directory = directory("dropped");
        let plain = PlainWake::start();
        let (mut ended, mut woke) = (Vec::new(), Vec::new());
        for round in 0..4 * FIVE {
            let (told, tells) = mpsc::channel();
            let watch = DirectoryWatch::spawn(&directory, move || {
                let _ = told.send(());
            })
            .expect("watched");
            std::fs::write(directory.join(format!("round-{round}")), "").expect("written");
            tells
                .recv_timeout(Duration::from_secs(5))
                .expect("its thread watches");
            let asked = Instant::now();
            drop(watch);
            ended.push(asked.elapsed());
            woke.push(plain.round().0);
        }
        let ended = spread("a watch dropped to its thread joined", ended);
        let usual = spread("a plain channel beside it", woke).fastest_of_five;
        assert!(
            ended.fastest_of_five < Duration::from_millis(1) + usual * 2,
            "the fastest of five {:?}, the machine's own wake {usual:?}",
            ended.fastest_of_five
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_directory_that_is_not_there_is_refused() {
        let missing = directory("missing").join("not-there");
        assert!(DirectoryWatch::spawn(&missing, || {}).is_err());
    }
}
