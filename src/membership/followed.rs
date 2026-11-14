//! The members as a node follows them in Xmip Storage (`super`): its own
//! row written once Storage is reached, then the table waited on and read
//! each time a write moves it, on the membership's own thread.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use persist::storage::{MemberRecord, Position, Waiter, Watched, XmipStorage};
use xcore::lock::Locked;
use xcore::wake::Revision;

/// Its place among the Storage nodes listed, as its own Storage node finds
/// it: none for a node that is none of them, or until it is found.
pub type Place = Box<dyn Fn() -> Option<usize> + Send + Sync>;

/// What the node holds of the members, and what it has to say of them.
pub struct Followed {
    storage: Arc<dyn XmipStorage>,
    row: Mutex<MemberRecord>,
    place: Place,
    waiter: Arc<Waiter>,
    known: Mutex<Known>,
    /// Raised each time the members are read anew.
    read: Revision,
    /// What bounds each wait, and how long a try that failed rests.
    bound: Duration,
    rest: Duration,
}

/// What was read of the members last, and why the last try failed.
#[derive(Default)]
struct Known {
    written: bool,
    members: Arc<Vec<MemberRecord>>,
    problem: Option<String>,
}

impl Followed {
    pub(super) fn new(
        storage: Arc<dyn XmipStorage>,
        (row, place): (MemberRecord, Place),
        (bound, rest): (Duration, Duration),
    ) -> Self {
        Self {
            storage,
            row: Mutex::new(row),
            place,
            waiter: Arc::new(Waiter::new()),
            known: Mutex::default(),
            read: Revision::new(),
            bound,
            rest,
        }
    }

    /// The node's own row, as it writes it: Xmip Storage's own values unset.
    #[must_use]
    pub fn row(&self) -> MemberRecord {
        self.row.locked().clone()
    }

    /// Its row with its place among the Storage nodes, where its own
    /// Storage node has found it since: as each try writes it.
    fn placed(&self) -> MemberRecord {
        let mut row = self.row.locked();
        if row.storage_place.is_none() {
            row.storage_place = (self.place)().and_then(|place| u32::try_from(place).ok());
        }
        row.clone()
    }

    /// Whether its row has reached Xmip Storage.
    #[must_use]
    pub fn written(&self) -> bool {
        self.known.locked().written
    }

    /// The members as last read: each node's latest row, running or
    /// stopped in order; none before the node's row was written.
    #[must_use]
    pub fn rows(&self) -> Arc<Vec<MemberRecord>> {
        Arc::clone(&self.known.locked().members)
    }

    /// Why its last try at Xmip Storage failed, where it did and nothing
    /// has succeeded since.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        self.known.locked().problem.clone()
    }

    /// Raised each time the members are read anew: what a follower of them
    /// waits past, told rather than asking again.
    #[must_use]
    pub const fn revision(&self) -> &Revision {
        &self.read
    }

    /// The row written, then the table followed, until [`Followed::end`].
    pub(super) fn run(&self) {
        while !self.waiter.is_stopped() {
            match self.storage.write_member(&self.placed()) {
                Ok(()) => {
                    let mut known = self.known.locked();
                    known.written = true;
                    known.problem = None;
                    break;
                }
                Err(problem) => self.failed(&problem.to_string()),
            }
        }
        // Where the table stood when last read: nowhere yet, so the first
        // wait answers at once with where it stands, read next.
        let mut seen = 0;
        while !self.waiter.is_stopped() {
            let asked = Instant::now();
            let waited = [Position {
                watched: Watched::Membership,
                at: seen,
            }];
            match self
                .storage
                .wait_queues(&waited, (self.bound, 0), &self.waiter)
            {
                Ok(moved) => match moved.first() {
                    Some(moved) => match self.storage.read_members() {
                        Ok(members) => {
                            seen = moved.position.at;
                            self.took(members);
                        }
                        Err(problem) => self.failed(&problem.to_string()),
                    },
                    // Held to its bound, or less by a Storage node that
                    // holds none so long: the rest of it rested.
                    None => self.waiter.rest(self.bound.saturating_sub(asked.elapsed())),
                },
                Err(problem) => self.failed(&problem.to_string()),
            }
        }
    }

    /// The following ended, at once, the wait under way among it.
    pub(super) fn end(&self) {
        self.waiter.stop();
        self.read.wake();
    }

    /// Its row written again saying it stopped, where it was written once.
    pub(super) fn stopped(&self) -> Result<(), persist::PersistError> {
        if !self.written() {
            return Ok(());
        }
        let stopped = MemberRecord {
            stopped_unix_nanos: Some(0),
            ..self.row()
        };
        self.storage.write_member(&stopped)
    }

    fn took(&self, members: Vec<MemberRecord>) {
        {
            let mut known = self.known.locked();
            known.members = Arc::new(members);
            known.problem = None;
        }
        self.read.raise();
    }

    /// `problem` kept to be said, and a rest before the next try.
    fn failed(&self, problem: &str) {
        self.known.locked().problem = Some(problem.to_string());
        self.waiter.rest(self.rest);
    }
}
