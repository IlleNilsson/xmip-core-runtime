//! The members as a node follows them in Xmip Storage (`super`): its own
//! row written once Storage is reached, then the table waited on and read
//! each time a write moves it, on the membership's own thread; or, where
//! Xmip Storage refuses its start as superseded, nothing more tried.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use persist::PersistError;
use persist::storage::{MemberRecord, Position, Waiter, Watched, XmipStorage};
use xcore::lock::Locked;
use xcore::wake::Revision;

/// Its place among the Storage nodes listed, as its own Storage node finds
/// it: none for a node that is none of them, or until it is found.
pub type Place = Box<dyn Fn() -> Option<usize> + Send + Sync>;

/// Its node's start file raised to a later start's number, where Xmip
/// Storage refused its start below it (`super::numbering::floored`).
pub type Floor = Box<dyn Fn(u64) -> Result<(), String> + Send + Sync>;

/// What the node holds of the members, and what it has to say of them.
pub struct Followed {
    storage: Arc<dyn XmipStorage>,
    row: Mutex<MemberRecord>,
    place: Place,
    floor: Floor,
    waiter: Arc<Waiter>,
    known: Mutex<Known>,
    /// Raised each time the members are read anew, and as its start is
    /// refused as superseded.
    read: Revision,
    /// What bounds each wait, and how long a try that failed rests.
    bound: Duration,
    rest: Duration,
}

/// What was read of the members last, why the last try failed, and why its
/// start was refused, where Xmip Storage refused it.
#[derive(Default)]
struct Known {
    written: bool,
    members: Arc<Vec<MemberRecord>>,
    problem: Option<String>,
    refused: Option<String>,
}

impl Followed {
    pub(super) fn new(
        storage: Arc<dyn XmipStorage>,
        (row, place, floor): (MemberRecord, Place, Floor),
        (bound, rest): (Duration, Duration),
    ) -> Self {
        Self {
            storage,
            row: Mutex::new(row),
            place,
            floor,
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

    /// Why Xmip Storage refused its start as superseded, and what became of
    /// its node's start file, where it did: the start is then no member,
    /// and tries nothing more (ADR-0056, amendment 2026-11-20).
    #[must_use]
    pub fn refused(&self) -> Option<String> {
        self.known.locked().refused.clone()
    }

    /// Raised each time the members are read anew: what a follower of them
    /// waits past, told rather than asking again.
    #[must_use]
    pub const fn revision(&self) -> &Revision {
        &self.read
    }

    /// The row written, then the table followed, until [`Followed::end`];
    /// a start refused as superseded follows nothing.
    pub(super) fn run(&self) {
        while !self.waiter.is_stopped() {
            match self.storage.write_member(&self.placed()) {
                Ok(()) => {
                    let mut known = self.known.locked();
                    known.written = true;
                    known.problem = None;
                    break;
                }
                Err(PersistError::Superseded { latest, reason }) => {
                    self.superseded(latest, &reason);
                    return;
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

    /// Its row written again saying it stopped, where it was written once:
    /// its own row alone, whether it is its node's latest as Xmip Storage
    /// keeps it, so a successor started meanwhile stays the member
    /// (`XmipStorage::write_member`).
    pub(super) fn stopped(&self) -> Result<(), PersistError> {
        if !self.written() {
            return Ok(());
        }
        let stopped = MemberRecord {
            stopped_unix_nanos: Some(0),
            ..self.row()
        };
        self.storage.write_member(&stopped)
    }

    /// Its start refused, `latest` the later start of its node that is its
    /// member: its node's start file floored there, so the node's next
    /// start registers whatever its clock says, and why kept to be said.
    /// Never tried again: asked again, it would be the late write Xmip
    /// Storage refuses.
    fn superseded(&self, latest: u64, reason: &str) {
        let floored = match (self.floor)(latest) {
            Ok(()) => format!("its node's next start is numbered above start {latest}"),
            Err(why) => format!("its node's start file is not raised to start {latest}: {why}"),
        };
        {
            let mut known = self.known.locked();
            known.refused = Some(format!("{reason}; {floored}"));
            known.problem = None;
        }
        self.read.raise();
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
