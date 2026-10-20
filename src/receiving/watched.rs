//! A polled Receive Location's far end watched, where it tells of a change
//! (`transport::Notice`): its rest after a receive that found nothing ends
//! the moment the word comes, and lasts its sweep where none does
//! (`[tuning] receive_sweep`), so a file dropped is listed as it lands
//! rather than at the next poll (ADR-0024, amendment 2026-10-20). A drop
//! directory not there yet is watched from the first rest that finds it;
//! until then the Location polls.

use transport::{Notice, Transport};

use super::pace::Asking;
use crate::directory_watch::DirectoryWatch;
use crate::stopping::{Nudge, Stopping};

/// What tells one Location's rest of a change.
pub(super) struct Watched {
    notice: Option<Notice>,
    watch: Option<DirectoryWatch>,
    nudge: Nudge,
}

impl Watched {
    /// What `transport` says tells of a change, where it is polled; its
    /// word wakes a rest on `stopping`.
    pub(super) fn new(transport: &dyn Transport, stopping: &Stopping) -> Self {
        Self {
            notice: transport
                .waiting()
                .polled()
                .then(|| transport.notice())
                .flatten(),
            watch: None,
            nudge: stopping.nudge(),
        }
    }

    /// How the transport is asked again: told where its far end is
    /// watched — the watch begun here, where it was not yet and can be —
    /// polled where not, and at once where its receive waits by itself.
    pub(super) fn asking(&mut self, polled: bool) -> Asking {
        if !polled {
            return Asking::Waits;
        }
        if self.watch.is_none()
            && let Some(Notice::Directory(directory)) = &self.notice
        {
            let nudge = self.nudge.clone();
            self.watch = DirectoryWatch::spawn(directory, move || nudge.tell()).ok();
        }
        if self.watch.is_some() {
            Asking::Told
        } else {
            Asking::Polled
        }
    }

    /// The word that ends a rest, while the far end is watched.
    pub(super) fn nudge(&self) -> Option<&Nudge> {
        self.watch.as_ref().map(|_| &self.nudge)
    }
}
