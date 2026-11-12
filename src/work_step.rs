//! The Work Process step: every Message bound for a Work Process this node
//! runs, read from the Ledger and taken a turn of its Instance on the
//! node's Work pool (`runtime-model.md` section 22; ADR-0066, amendment
//! 2026-10-22).
//!
//! ```text
//! Publication   the Message waits in its Work Process's queue in the Ledger
//! -> admit      a page a round from where its pass stands, oldest first,
//!               each Work Process a share of the Work pool's threads, the
//!               rest left in the Ledger (`admission`, `reading`); one whose
//!               key is behind an earlier one of the same key waits, so a
//!               key's Messages never overtake
//! -> claim      through Xmip Storage
//! -> turn       its Instance read from the Ledger, found by its key in a
//!               Correlation, or a new one; the unit advanced, its acts
//!               carried out — work on a Message, a Message published
//!               back through routing — until it waits or ends
//! -> hand on    one write (`XmipStorage::turn`): the Journey, the
//!               Instance, its correlation keys, what it published, and the
//!               Message kept at its place with a due time where a timer
//!               waits; written only over the turn it read
//! ```
//!
//! **Nothing waits on a thread.** An Instance waiting for a Message or a
//! time is a record in the Ledger. A Message of its key waits in the
//! queue, taken up by whichever node reads it first — at once where
//! another node put it there, the step waiting on its queues in Xmip
//! Storage (`crate::queue_watch`; open problem 46, built 2026-11-12) — and
//! a timer is the due time of the Message whose turn started it, taken up
//! when due. A turn its Instance did not take, or that waits behind
//! another of its sequence, waits on what holds it — the Instance as it
//! read it, each key it correlates by that no Instance holds, the
//! sequence's head — and is taken up the moment any node moves one
//! ([`Turned::Waits`]; 2026-11-12).
//!
//! **A turn that panics ends Failed with what it said** (2026-11-12): caught
//! under its claim and written as a flow's uncaught error is, and its place
//! and its ownership on this node given back however it ends
//! (`admission::Owning`), so no panic strands its Journey or ends the
//! dispatching.
//!
//! **The engine never knows the design.** A unit is opened as
//! `process::Flow`, linked or loaded through the C ABI
//! (`crate::ffi::loaded_work_process`), and nothing here reads a design.

mod acts;
mod admission;
mod dispatch;
mod keys;
#[cfg(feature = "dynamic-loading")]
mod opened;
mod reading;
mod running;
mod turning;

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use persist::storage::XmipStorage;
use xaudit::program_audit::ProgramAudit;
use xcore::JourneyId;
use xcore::wake::Wake;

use crate::pool::Limits;
use crate::queue_watch::{QueueWatch, Woken};
use reading::Reading;

pub use dispatch::{dispatch, turn_due};
pub use keys::{KeyWord, ResolvedSet};
#[cfg(feature = "dynamic-loading")]
pub use opened::opened;
pub use running::{NO_UNIT, NoUnits, Running, Thrown, WorkUnits};
pub use turning::Turned;

/// How long a claim on a Message bound for a Work Process holds before it
/// lapses: a turn is short, and one longer than this is still never
/// written twice, its Instance written only over the turn it read.
pub const WORK_LEASE: Duration = Duration::from_secs(30);

/// The Work pool's threads for each of the machine's hardware threads,
/// where the node's `[tuning] work_threads_per_hardware_thread` does not
/// say: two, as the Send pool's, since a turn waits on the Ledger and on
/// the units it calls. Its most bounds the turns the step holds too
/// (`admission`).
pub const WORK_THREADS_PER_HARDWARE_THREAD: usize = 2;

/// How often the queues of the Work Processes this node runs are read for
/// what no live claim holds, and for a timer due, where `[tuning]
/// work_scan` does not say: every second, the bound on one wait on them.
pub const WORK_SCAN: Duration = Duration::from_secs(1);

/// The node's Work Process step.
pub struct WorkStep {
    cluster: String,
    node: String,
    storage: Arc<dyn XmipStorage>,
    lease: Duration,
    scan: Duration,
    limits: Limits,
    audit: Option<ProgramAudit>,
    running: Vec<Running>,
    state: Mutex<State>,
    wake: Wake,
    /// Its watch on its queues, and on what a turn it gave back waits on,
    /// stopped as it closes (`crate::queue_watch`).
    watch: QueueWatch,
}

#[derive(Default)]
struct State {
    /// The Messages, by Journey, admitted for a turn on this node: queued in
    /// the Work pool or running (`admission`).
    owned: HashSet<JourneyId>,
    /// How the read of each Work Process's queue stands, by its place in
    /// `WorkStep::running`.
    readings: Vec<Reading>,
    /// The Work Process that goes first in the next round: each in turn.
    first: usize,
    /// When each queue next has a timer due, as its last read showed.
    due: Vec<(u128, Instant)>,
    /// How many turns this node wrote: what tells a turn that waited
    /// whether another was written while it was held.
    written: u64,
    /// How many scans of every queue it began.
    scans: u64,
    /// How many turns unwound past their own catch.
    unwound: u64,
    closed: bool,
}

impl WorkStep {
    /// The step of the node at `node` in the cluster at `cluster`, over
    /// `storage`, running `running` on a pool bounded by `limits`, its
    /// queues read every `scan` as well as when another node writes to one.
    #[must_use]
    pub fn new(
        (cluster, node): (&str, &str),
        storage: Arc<dyn XmipStorage>,
        (limits, scan): (Limits, Duration),
        audit: Option<ProgramAudit>,
        running: Vec<Running>,
    ) -> Self {
        let state = State {
            readings: running.iter().map(|_| Reading::default()).collect(),
            ..State::default()
        };
        Self {
            cluster: cluster.to_string(),
            node: node.to_string(),
            storage,
            lease: WORK_LEASE,
            scan,
            limits,
            audit,
            running,
            state: Mutex::new(state),
            wake: Wake::new(),
            watch: QueueWatch::of(node),
        }
    }

    /// The Work Processes it runs.
    #[must_use]
    pub fn running(&self) -> &[Running] {
        &self.running
    }

    /// Whether it runs the Work Process `name`.
    #[must_use]
    pub fn runs(&self, name: &str) -> bool {
        self.running.iter().any(|running| running.name == name)
    }

    /// Read `queue` now, where it is one of a Work Process this node runs.
    pub fn ask(&self, queue: u128) {
        self.asked(queue, None);
    }

    /// Read `queue` now from what `woken` brought of it: a write on any
    /// node put a Message in it, or moved what a turn it gave back waits on
    /// (`crate::queue_watch`).
    pub(crate) fn woken(&self, queue: u128, woken: Woken) {
        self.asked(queue, woken.due);
    }

    /// `queue`'s reading asked, from `first` where a wake brought it.
    fn asked(&self, queue: u128, first: Option<persist::storage::DueQueue>) {
        let mut state = self.lock();
        let at = self
            .running
            .iter()
            .position(|running| running.queue == queue);
        let Some(reading) = at.and_then(|at| state.readings.get_mut(at)) else {
            return;
        };
        reading.asked(first);
        drop(state);
        self.wake.notify_all();
    }

    /// Read every queue it runs now: a Stream ahead in a sequence has ended.
    pub fn ask_every(&self) {
        let mut state = self.lock();
        for reading in &mut state.readings {
            reading.asked(None);
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Stop taking work; what is in a turn finishes it.
    pub fn close(&self) {
        self.lock().closed = true;
        self.watch.stop();
        self.wake.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.locked()
    }

    fn failed(&self, problem: &str) {
        if let Some(audit) = &self.audit {
            let _ = audit.failed("process", &format!("{}: {problem}", self.node));
        }
    }

    /// The cluster it runs in: `xmip:///<cluster>`.
    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }
}

#[cfg(any(test, feature = "test-support"))]
impl WorkStep {
    /// How many scans of every queue it made: what a test waits for before
    /// another node publishes, so only a wake can take up what it publishes.
    #[must_use]
    pub fn scans(&self) -> u64 {
        self.lock().scans
    }

    /// How many turns it holds now, queued in the Work pool or running.
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().owned.len()
    }

    /// How many turns unwound past their own catch, let go of and left to
    /// their claims' lapse.
    #[must_use]
    pub fn unwound(&self) -> u64 {
        self.lock().unwound
    }
}
