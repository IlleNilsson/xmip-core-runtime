//! The operator a surface's table stands for: which snapshot it answers from,
//! what it last handed out, and what this process has published.
//!
//! The logic behind `xmip_operate.h`'s table, kept outside `ffi/`, which
//! holds only the boundary itself (ADR-0050, refined 2026-09-25): the table,
//! its entries and the exports are `ffi/operate.rs`.

use observe::{Count, HealthRecord, Snapshot};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use crate::start::unconfigured;

/// What sits behind `ctx`: the snapshot, and what the last call handed out.
///
/// Entries borrow from `held`, which is why the header says they are valid
/// until the next call on this table. Replacing `held` is what invalidates
/// them, and that is the whole lifetime rule.
pub struct Operator {
    pub(crate) source: Source,
    pub(crate) held_health: Vec<HealthRecord>,
    pub(crate) held_count: Option<Count>,
}

/// Where a table's snapshot comes from.
///
/// `Published` reads what the node has most recently published, on every
/// call — so a table handed out before a node started sees the node once it
/// has. The first build copied the snapshot at creation and the GUI read
/// "unconfigured" forever while the log said the node had started
/// (2026-09-05). `Fixed` is for tests and for a surface that wants one
/// consistent view.
pub(crate) enum Source {
    Fixed(Arc<Snapshot>),
    Published,
}

impl Source {
    /// Change the snapshot this source reads: in place for `Fixed`, on the
    /// shared `PUBLISHED` for `Published`. Pause and resume go through here,
    /// so an operator pausing a live table changes what every table then reads.
    pub(crate) fn mutate<R>(&mut self, change: impl FnOnce(&mut Snapshot) -> R) -> R {
        match self {
            Source::Fixed(snapshot) => change(Arc::make_mut(snapshot)),
            Source::Published => {
                let mut guard = PUBLISHED
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let snapshot = guard.get_or_insert_with(|| Arc::new(unconfigured()));
                change(Arc::make_mut(snapshot))
            }
        }
    }
}

impl Operator {
    /// A table over one fixed snapshot.
    #[must_use]
    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            source: Source::Fixed(Arc::new(snapshot)),
            held_health: Vec::new(),
            held_count: None,
        }
    }

    /// A table over whatever is published, read at each call.
    #[must_use]
    pub fn live() -> Self {
        Self {
            source: Source::Published,
            held_health: Vec::new(),
            held_count: None,
        }
    }

    /// The snapshot to answer from: a shared handle, never a copy. Every
    /// surface call used to clone the whole publication under the lock the
    /// publisher needs — eight copies of eleven thousand records per board
    /// render (2026-09-15). A publication is immutable once published, so
    /// the handle is enough.
    pub(crate) fn snapshot(&self) -> Arc<Snapshot> {
        match &self.source {
            Source::Fixed(snapshot) => Arc::clone(snapshot),
            Source::Published => PUBLISHED
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
                .unwrap_or_else(|| Arc::new(unconfigured())),
        }
    }
}

/// What this process has published. The runtime writes it as the node runs; the
/// table in `ffi/operate.rs` hands a copy to whichever surface asks. A copy, so a surface
/// reading a table never blocks the node writing the next one — ADR-0027
/// clause 6 in one line.
static PUBLISHED: Mutex<Option<Arc<Snapshot>>> = Mutex::new(None);

/// The monotonic publication revision and the wake-up primitive shared by all
/// operator surfaces in this process. It is separate from PUBLISHED so a
/// sleeping observer never holds the snapshot lock a publisher needs.
static CHANGE: OnceLock<(Mutex<u64>, Condvar)> = OnceLock::new();

pub(crate) fn change_clock() -> &'static (Mutex<u64>, Condvar) {
    CHANGE.get_or_init(|| (Mutex::new(0), Condvar::new()))
}

pub(crate) fn announce_change() {
    let (revision, changed) = change_clock();
    let mut revision = revision
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *revision = revision.wrapping_add(1).max(1);
    changed.notify_all();
}

/// Publish the node's current snapshot for surfaces to read.
pub fn publish(snapshot: Snapshot) {
    *PUBLISHED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(snapshot));
    announce_change();
}
