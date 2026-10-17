//! A directory watch on macOS and the BSDs: kqueue for a write to the
//! directory — an entry added or removed — and for a pipe whose write ends
//! the wait, both in one queue.

use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use nix::errno::Errno;
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

/// A directory's changes, and the pipe that ends the wait for them.
pub(crate) struct Changes {
    queue: Kqueue,
    // Held open: the queue watches it.
    _directory: OwnedFd,
    ending: std::io::PipeReader,
    end: std::io::PipeWriter,
}

impl Changes {
    pub(crate) fn new(directory: &Path) -> std::io::Result<Self> {
        let opened = OwnedFd::from(std::fs::File::open(directory)?);
        let (ending, end) = std::io::pipe()?;
        let queue = Kqueue::new()?;
        let flags = EvFlags::EV_ADD | EvFlags::EV_CLEAR;
        let watched = [
            KEvent::new(
                opened.as_raw_fd() as usize,
                EventFilter::EVFILT_VNODE,
                flags,
                FilterFlag::NOTE_WRITE,
                0,
                0,
            ),
            KEvent::new(
                ending.as_raw_fd() as usize,
                EventFilter::EVFILT_READ,
                flags,
                FilterFlag::empty(),
                0,
                0,
            ),
        ];
        queue.kevent(&watched, &mut [], None)?;
        Ok(Self {
            queue,
            _directory: opened,
            ending,
            end,
        })
    }

    /// Wait until the directory changes, `true`, or until [`Changes::end`],
    /// `false`, as is a wait the kernel refuses.
    pub(crate) fn next(&self) -> bool {
        let empty = KEvent::new(
            0,
            EventFilter::EVFILT_READ,
            EvFlags::empty(),
            FilterFlag::empty(),
            0,
            0,
        );
        let mut heard = [empty, empty];
        let count = loop {
            match self.queue.kevent(&[], &mut heard, None) {
                Ok(count) => break count,
                Err(Errno::EINTR) => {}
                Err(_) => return false,
            }
        };
        let ending = self.ending.as_raw_fd() as usize;
        !heard[..count].iter().any(|event| event.ident() == ending)
    }

    pub(crate) fn end(&self) {
        let _ = (&self.end).write_all(&[1]);
    }
}
