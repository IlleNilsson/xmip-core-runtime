//! A directory watch on Linux and Android: inotify for a file closed after
//! writing, anything renamed into the directory and a folder made in it,
//! and a pipe whose write ends the wait, both polled at once.

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
            AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_CREATE,
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
        loop {
            let mut fds = [
                PollFd::new(self.ending.as_fd(), PollFlags::POLLIN),
                PollFd::new(self.inotify.as_fd(), PollFlags::POLLIN),
            ];
            match poll(&mut fds, PollTimeout::NONE) {
                Ok(_) => {}
                Err(Errno::EINTR) => continue,
                Err(_) => return false,
            }
            if fds[0].any().unwrap_or(true) {
                return false;
            }
            // Read every event waiting, so the next poll waits for a new one.
            let mut told = false;
            while let Ok(events) = self.inotify.read_events()
                && !events.is_empty()
            {
                told |= events.iter().any(|event| tells(event.mask));
            }
            if told {
                return true;
            }
        }
    }

    pub(crate) fn end(&self) {
        let _ = (&self.end).write_all(&[1]);
    }
}

// Whether an event is a change the watch tells: every one but a file only
// made, which tells once it is written and closed, so a producer's file
// tells as it is finished, never as it is begun.
fn tells(mask: AddWatchFlags) -> bool {
    !mask.contains(AddWatchFlags::IN_CREATE) || mask.contains(AddWatchFlags::IN_ISDIR)
}
