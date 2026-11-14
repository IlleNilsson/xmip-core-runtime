//! A node's membership of its cluster, through Xmip Storage (the design of
//! 2026-11-12 the owner approved, section 3.2; the membership the cluster
//! consolidation agreed on 2026-11-07: *each node registers at start in the
//! administration database … runtime implements cluster::Membership over
//! it; a differing save is flagged*).
//!
//! **Written by the node.** A node activated writes its row of the
//! `membership` table (`persist::storage::MemberRecord`) once it reaches
//! Xmip Storage — tried again, each `[tuning] storage_pass_over` apart,
//! until it does — and again as it stops in order, before its own Storage
//! node stops ([`Joined::stop`]). Its row says the node, the roles it
//! declares and its capability's evidence, where its operate listener
//! answers on the network, where its sync listener answers (none starts
//! one yet, ADR-0065), its place among the Storage nodes where it is one,
//! found by the process it answers as, the signed save it runs and its
//! process, drawn new at each start. A Storage node of several writes
//! through the Xmip Storage it already holds for its own work: its own
//! databases while the primary, the primary over the wire while not.
//!
//! **Followed, never asked again and again.** Once written, the node waits
//! on the table (`persist::storage::Watched::Membership`) and reads the
//! members each time a write moves it, so what it holds of them is the
//! latest ([`Followed`]): what `xcluster::Membership` answers, the one seam
//! every follower of the members takes, and what the node's record of its
//! membership is said from.
//!
//! **A save not its peers' is flagged** (ADR-0031, amendment 2026-11-06,
//! point 3): `<node>/membership` is Stressed where the save the node runs is
//! not the one most of the running members run, alone at the most
//! ([`peers_save`]).

mod followed;
mod member;
mod said;

pub use followed::{Followed, Place};
pub use said::{MEMBERSHIP, peers_save};

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use persist::storage::{MemberRecord, XmipStorage};

/// A node's membership while it runs: its row written and the members
/// followed, on a thread of its own, until [`Joined::stop`].
pub struct Joined {
    followed: Arc<Followed>,
    thread: Option<JoinHandle<()>>,
}

impl Joined {
    /// `row` written to `storage` once it is reached, its place among the
    /// Storage nodes as `place` finds it, and the members followed there,
    /// each wait for at most `bound` — the node's `[tuning] storage_wait` —
    /// and each try that fails `rest` apart, its `storage_pass_over`.
    ///
    /// # Errors
    ///
    /// Where its thread does not start, in words.
    pub fn start(
        storage: Arc<dyn XmipStorage>,
        (row, place): (MemberRecord, Place),
        (bound, rest): (Duration, Duration),
    ) -> Result<Self, String> {
        let followed = Arc::new(Followed::new(storage, (row, place), (bound, rest)));
        let running = Arc::clone(&followed);
        let thread = std::thread::Builder::new()
            .name("xmip-membership".to_string())
            .spawn(move || running.run())
            .map_err(|error| format!("the membership's thread did not start: {error}"))?;
        Ok(Self {
            followed,
            thread: Some(thread),
        })
    }

    /// The members as the node follows them.
    #[must_use]
    pub const fn followed(&self) -> &Arc<Followed> {
        &self.followed
    }

    /// Stop in order, as `reached` — what its Xmip Storage's client already
    /// knows (`storage::Reached::answers`) — says: the following ends at
    /// once; where Storage answers, its thread is joined and, where its row
    /// was written, the row is written again saying it stopped, Xmip
    /// Storage setting when, one round trip; where Storage does not, nothing
    /// is written and the thread is let go to end on its own, so a stop
    /// never waits out a Storage node's timeout (the millisecond rule). Once
    /// is enough; again does nothing more.
    ///
    /// Where its row is left saying it runs, why, in one sentence: what the
    /// node's stop record says, since the cluster then says it did not
    /// answer.
    pub fn stop(&mut self, reached: Result<(), &'static str>) -> Option<&'static str> {
        let thread = self.thread.take()?;
        self.followed.end();
        if let Err(why) = reached {
            // Let go, not joined: it may be in a call no Storage node ends.
            drop(thread);
            return self.followed.written().then_some(why);
        }
        if thread.join().is_err() {
            return Some(PANICKED);
        }
        self.followed.stopped().err().map(|_| UNWRITTEN)
    }
}

impl Drop for Joined {
    /// Let go without a stop in order: the following ends and nothing is
    /// written; [`Joined::stop`] is the stop in order.
    fn drop(&mut self) {
        if self.thread.take().is_some() {
            self.followed.end();
        }
    }
}

/// Its own Storage node of several found no primary as it stopped.
pub const FINDING: &str =
    "its membership row still says it runs: its own Storage node found no primary as it stopped";

/// No Storage node it lists answered when last asked, as it stopped.
pub const UNANSWERED: &str = "its membership row still says it runs: no Storage node it lists \
                              answered when last asked, as it stopped";

/// Storage answered, and did not take its stop.
const UNWRITTEN: &str = "its membership row still says it runs: Xmip Storage did not take its stop";

/// Its thread panicked.
const PANICKED: &str = "its membership row still says it runs: its membership's thread panicked";

/// A random 128-bit number, never zero, drawn from the operating system's
/// random source: the process a node's row is keyed by, new each start.
#[must_use]
pub fn process() -> u128 {
    loop {
        let drawn = u128::from_be_bytes(codec::random::array());
        if drawn != 0 {
            return drawn;
        }
    }
}

#[cfg(test)]
mod tests;
