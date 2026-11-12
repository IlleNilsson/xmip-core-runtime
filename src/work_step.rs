//! The Work Process step: every Message bound for a Work Process this node
//! runs, read from the Ledger and taken a turn of its Instance on the
//! node's Work pool (`runtime-model.md` section 22; ADR-0066, amendment
//! 2026-10-22).
//!
//! ```text
//! Publication   the Message waits in its Work Process's queue in the Ledger
//! -> scan       oldest first; one whose key is behind an earlier one of the
//!               same key waits, so a key's Messages never overtake
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
//! when due.
//!
//! **The engine never knows the design.** A unit is opened as
//! `process::Flow`, linked or loaded through the C ABI
//! (`crate::ffi::loaded_work_process`), and nothing here reads a design.

mod acts;
mod dispatch;
mod keys;
#[cfg(feature = "dynamic-loading")]
mod opened;
mod running;
mod turning;

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use persist::storage::{Waiter, XmipStorage};
use xaudit::program_audit::ProgramAudit;
use xcore::JourneyId;
use xcore::wake::Wake;

use crate::pool::Limits;

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
    /// What its watch on its queues waits as, stopped as it closes
    /// (`crate::queue_watch`).
    waiter: Arc<Waiter>,
}

#[derive(Default)]
struct State {
    /// The Messages, by Journey, claimed and in a turn on this node.
    owned: HashSet<JourneyId>,
    /// Queues to read now.
    asked: Vec<u128>,
    /// When each queue next has a timer due, as its last read showed.
    due: Vec<(u128, Instant)>,
    /// How many turns this node wrote: what tells a turn that waited
    /// whether another was written while it was held.
    written: u64,
    /// How many scans of every queue it made.
    scans: u64,
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
        Self {
            cluster: cluster.to_string(),
            node: node.to_string(),
            storage,
            lease: WORK_LEASE,
            scan,
            limits,
            audit,
            running,
            state: Mutex::new(State::default()),
            wake: Wake::new(),
            waiter: Arc::new(Waiter::of(node)),
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
        if !self.running.iter().any(|running| running.queue == queue) {
            return;
        }
        let mut state = self.lock();
        if !state.asked.contains(&queue) {
            state.asked.push(queue);
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Read every queue it runs now: a Stream ahead in a sequence has ended.
    pub fn ask_every(&self) {
        let mut state = self.lock();
        for running in &self.running {
            if !state.asked.contains(&running.queue) {
                state.asked.push(running.queue);
            }
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Stop taking work; what is in a turn finishes it.
    pub fn close(&self) {
        self.lock().closed = true;
        self.waiter.stop();
        self.wake.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.locked()
    }

    /// `journey` taken for a turn on this node, and how many turns it had
    /// written as it was; `None` where it holds it in one already.
    fn own(&self, journey: JourneyId) -> Option<u64> {
        let mut state = self.lock();
        state.owned.insert(journey).then_some(state.written)
    }

    /// `journey` let go of after its turn, `done` where it was written,
    /// owned since this node had written `since` turns.
    fn disown(&self, journey: JourneyId, queue: u128, (done, since): (bool, u64)) {
        let mut state = self.lock();
        state.owned.remove(&journey);
        if done {
            state.written += 1;
        }
        // After a written turn the next of its queue may go on now. One
        // that waits is read again only where another turn was written
        // while it was held — what it waited for may have moved on, and the
        // read that turn asked passed over it while held here (found
        // 2026-11-12, once a scan no longer came every second); else the
        // next written turn's read finds it: never a loop of reads.
        if (done || state.written != since) && !state.asked.contains(&queue) {
            state.asked.push(queue);
        }
        drop(state);
        self.wake.notify_all();
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
}
