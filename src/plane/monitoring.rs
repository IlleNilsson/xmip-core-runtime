//! What a node declaring the monitoring role does (ADR-0027 decision 8,
//! ADR-0056 and ADR-0067, amendments 2026-11-13; the design of 2026-11-12
//! the owner approved, section 3.3): it gathers its cluster's view and
//! answers it on its operate listener, `Cluster` and `ClusterWait`, beside
//! its own publication.
//!
//! **Followed, never asked again and again.** The members are what its
//! membership says ([`Members`]: membership through Xmip Storage on a node);
//! each time the membership is read anew it is told, and where the members
//! it lists differ from those gathered, a fresh [`Gatherer`] follows them
//! and replaces the one before. Each view a gatherer assembles is posted,
//! once, as the text a publication file holds, to the cluster's [`Board`]
//! the listener answers from: so answering `Cluster` reads a text already
//! written, and a stop wakes a wait on it as it wakes one on the node's own
//! (`plane::served::read`).
//!
//! **Its scope is the cluster's**, and its source the gatherer's one source
//! rule, *CL1, gathered by OP1: 9 of 9 nodes reached*; a node never
//! composes a second.
//!
//! **A start never waits on it.** A gatherer starts once every member was
//! heard, each within its own surface's patience; that runs on the
//! membership's thread here, never on the node's start.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use observe::Publication;
use xcluster::{Member, Membership};
use xcore::lock::Locked;
use xcore::wake::Revision;

use crate::plane::board::{Board, Published};
use crate::plane::gather::{Gathered, Gatherer, Reach};

/// How long a stop waits for the membership's thread, which may be in a
/// gatherer's start, before it is left to end alone.
const ENDS: Duration = Duration::from_secs(1);

/// Who a cluster's members are, and told each time they are read anew: the
/// seam a monitoring node follows them through.
pub trait Members: Membership {
    /// Raised each time the members are read anew.
    fn moved(&self) -> &Revision;
}

/// How this node reaches each member: in process for itself, over the
/// member's operate listener for every other (`plane::gather::Reach`).
pub type Reaching = Box<dyn Fn(&Member) -> Reach + Send + Sync>;

/// A monitoring node's gathering: the cluster's publication it answers,
/// and the threads gathering it once begun.
#[derive(Default)]
pub struct Monitoring {
    shared: Arc<Shared>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

/// What the gathering's threads share.
#[derive(Default)]
struct Shared {
    /// The cluster's publication as the listener answers it: revision 0 and
    /// no text until the first view.
    board: Arc<Board>,
    /// The gatherer following the members now, none before the first.
    current: Mutex<Option<Arc<Gatherer>>>,
    /// Raised as each gatherer replaces the one before.
    replaced: Revision,
    /// The members followed, once begun.
    members: OnceLock<Arc<dyn Members>>,
    stopping: AtomicBool,
}

impl Shared {
    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}

impl Monitoring {
    /// The cluster's publication, which a listener answers `Cluster` and
    /// `ClusterWait` from (`Listener::gathers`).
    #[must_use]
    pub fn published(&self) -> Arc<dyn Published> {
        Arc::clone(&self.shared.board) as Arc<dyn Published>
    }

    /// Begin gathering the cluster at `root`, `by` the node of that scope,
    /// of the members `members` says, each reached as `reach` says, until
    /// [`Monitoring::stop`]. Once; again does nothing.
    ///
    /// # Errors
    ///
    /// A thread that does not start, in words.
    pub fn begin(
        &self,
        (root, by): (String, String),
        members: Arc<dyn Members>,
        reach: Reaching,
    ) -> Result<(), String> {
        let mut threads = self.threads.locked();
        if self.shared.stopping() || self.shared.members.set(Arc::clone(&members)).is_err() {
            return Ok(());
        }
        let shared = Arc::clone(&self.shared);
        let following = std::thread::Builder::new()
            .name("xmip-monitoring-members".to_string())
            .spawn(move || followed(&shared, (&root, &by), &*members, &*reach))
            .map_err(|error| format!("the monitoring node's gathering did not start: {error}"))?;
        threads.push(following);
        let shared = Arc::clone(&self.shared);
        let posting = std::thread::Builder::new()
            .name("xmip-monitoring-post".to_string())
            .spawn(move || posted(&shared))
            .map_err(|error| format!("the monitoring node's gathering did not start: {error}"))?;
        threads.push(posting);
        Ok(())
    }

    /// Stop gathering: every wait woken, the gatherer let go, each thread
    /// waited for at most [`ENDS`] and one in a gatherer's start left to
    /// end alone. Once is enough.
    pub fn stop(&self) {
        let shared = &self.shared;
        shared.stopping.store(true, Ordering::SeqCst);
        shared.replaced.wake();
        if let Some(members) = shared.members.get() {
            members.moved().wake();
        }
        if let Some(current) = shared.current.locked().take() {
            current.wake();
        }
        let until = Instant::now() + ENDS;
        for thread in std::mem::take(&mut *self.threads.locked()) {
            while !thread.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_micros(200));
            }
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for Monitoring {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Follow the members until the gathering stops: each time they are read
/// anew and differ from those gathered, a fresh gatherer of them replaces
/// the one before. One that does not start leaves the one before gathering,
/// and is tried again when the members are next read.
fn followed(
    shared: &Shared,
    (root, by): (&str, &str),
    members: &dyn Members,
    reach: &(dyn Fn(&Member) -> Reach + Send + Sync),
) {
    let mut gathered: Option<Vec<Member>> = None;
    while !shared.stopping() {
        let seen = members.moved().now();
        if let Ok(listed) = members.members()
            && gathered.as_ref() != Some(&listed)
            && let Ok(gatherer) = Gatherer::start(root, Some(by), members, reach)
        {
            // A stop while it started takes no gatherer from here on: one
            // started meanwhile is let go, never kept.
            let mut current = shared.current.locked();
            if shared.stopping() {
                return;
            }
            let before = current.replace(Arc::new(gatherer));
            drop(current);
            shared.replaced.raise();
            if let Some(before) = before {
                before.wake();
            }
            gathered = Some(listed);
        }
        members
            .moved()
            .wait_unless(seen, Duration::MAX, || shared.stopping());
    }
}

/// Post each view the gatherer now assembles, once, until the gathering
/// stops: woken as it assembles, as another replaces it, and as it stops.
fn posted(shared: &Shared) {
    let mut last = (0, 0);
    while !shared.stopping() {
        let replaced = shared.replaced.now();
        let current = shared.current.locked().clone();
        let Some(gatherer) = current else {
            shared
                .replaced
                .wait_unless(replaced, Duration::MAX, || shared.stopping());
            continue;
        };
        let view = gatherer.gathered();
        if (replaced, view.revision) != last {
            shared.board.post(written(&view));
            last = (replaced, view.revision);
        }
        let moved = || shared.stopping() || shared.replaced.now() != replaced;
        let _ = gatherer.wait_unless(view.revision, Duration::MAX, &moved);
    }
}

/// `view` as the text a publication file holds: at the cluster's scope,
/// its source the gatherer's.
#[must_use]
pub fn written(view: &Gathered) -> String {
    Publication::whole(&view.topology.source, &view.root, &view.snapshot)
        .with_topology(Some(view.topology.clone()))
        .to_toml()
}
