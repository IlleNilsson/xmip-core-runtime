//! A directory watch on Linux and Android: inotify for a file closed after
//! writing or renamed into the directory, and a pipe whose write ends the
//! wait, both polled at once.

use std::io::Write;
use std::os::fd::AsFd;
use std::path::Path;

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};

/// A directory's changes, and the pipe that ends the wait for them.
pub(crate) struct Changes {
    inotify: Inotify,
    ending: std::io::PipeReader,
    end: std::io::PipeWriter,
}

impl Changes {
    pub(crate) fn new(directory: &Path) -> std::io::Result<Self> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        inotify.add_watch(
            directory,
            AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_CLOSE_WRITE,
        )?;
        let (ending, end) = std::io::pipe()?;
        Ok(Self {
            inotify,
            ending,
            end,
        })
    }

    /// Wait until the directory changes, `true`, or until [`Changes::end`],
    /// `false`, as is a wait the kernel refuses.
    pub(crate) fn next(&self) -> bool {
        let mut fds = [
            PollFd::new(self.ending.as_fd(), PollFlags::POLLIN),
            PollFd::new(self.inotify.as_fd(), PollFlags::POLLIN),
        ];
        loop {
            match poll(&mut fds, PollTimeout::NONE) {
                Ok(_) => break,
                Err(Errno::EINTR) => {}
                Err(_) => return false,
            }
        }
        if fds[0].any().unwrap_or(true) {
            return false;
        }
        // Read every event waiting, so the next poll waits for a new one.
        while self
            .inotify
            .read_events()
            .is_ok_and(|events| !events.is_empty())
        {}
        true
    }

    pub(crate) fn end(&self) {
        let _ = (&self.end).write_all(&[1]);
    }
}
