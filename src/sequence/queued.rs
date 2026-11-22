//! A Message of a queue as a step keeps it behind its sequences' heads
//! (`super::Heads`): identifiers only, never what is kept beside it, so what
//! a step keeps of a backlog is a few words a Message (ADR-0066, amendment
//! 2026-11-22).

use persist::storage::Held;
use xcore::JourneyId;

use super::kept::Kept;

/// A Message of a queue as a step keeps it: its Journey, where its queue's
/// index of what is due keeps it, and the places its Stream holds, each with
/// who holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queued {
    pub journey: JourneyId,
    /// Its due time as the index keeps it, and its place in its queue.
    pub at: (u64, u64),
    pub places: Vec<(u128, u128)>,
}

impl Queued {
    /// `held`, as read from its queue.
    ///
    /// # Errors
    /// What its queue keeps beside it is no [`Kept`], in words.
    pub fn of(held: &Held) -> Result<Self, String> {
        Ok(Self {
            journey: held.hold.journey,
            at: (held.due_at(), held.sequence),
            places: Kept::read(&held.hold.body)?.places,
        })
    }

    /// Its place in its queue.
    #[must_use]
    pub const fn place(&self) -> u64 {
        self.at.1
    }
}
