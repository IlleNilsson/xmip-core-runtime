//! A node's act watch, and the door every operator's act goes through
//! (ADR-0014, amendment 2026-11-13; the owner, 2026-10-13: *Acts go to
//! Xmip Storage. Nodes are consumable: pause, resume, retry, dismiss and
//! replay are written to Storage with who and when, and every node honors
//! them*).
//!
//! **The door** ([`Door`]) is the node an operator's surface reaches. Its
//! operate listener admits the operator first, by the operator's own role
//! (`plane::role::admitted`), and only then hands the act to the door,
//! which writes it to Xmip Storage asked of the node that owns what it acts
//! on (`persist::storage::ActRecord`): where that node runs in this
//! process, through that node's Storage; where it does not, only where this
//! node declares the operational role (`node::Capability::carries_acts`),
//! and every other node refuses in words, naming the role. It then holds
//! the surface's call while the owning node takes it, at most `[tuning]
//! operate_act`, and answers what that node decided — or `asked`, where
//! the bound passed first.
//!
//! **The act watch** ([`ActWatch`]) is every running node's, beside its
//! queue watch: it holds a wait on Xmip Storage on the acts asked of its
//! node and is told at once of each written, on whichever node it was
//! asked ([`Watched::Acts`]). It is the one taker of its node's acts: each
//! is judged again by name against the node's own `[operate]` lists,
//! applied by the one apply (`applied::apply`), decided once, and audited
//! at the node (`taken`). An act asked while the node was not running
//! stays asked, never expiring (the owner, 2026-11-12), and is taken as
//! the node's act watch starts. Whatever process asked it, an act has one
//! taker, so it is never applied twice by two.

use std::sync::{Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use persist::storage::{ActRecord, Position, Waiter, Watched, XmipStorage};
use xaudit::program_audit::ProgramAudit;
use xcore::lock::Locked;

use crate::plane::{Grants, Published};

mod door;
mod taken;

pub use door::{Asker, Door, OPERATE_ACT};

/// How many acts one read of a node's acts takes.
const PAGE: u32 = 64;

/// The most a wait no Storage node answered rests before it is asked
/// again: an act asked meanwhile is found as soon as one answers.
const RETRY: Duration = Duration::from_secs(1);

/// What takes the acts asked of one node.
pub struct ActWatch {
    /// The node's scope: `xmip:///<cluster>/node/<name>`.
    node: String,
    storage: Arc<dyn XmipStorage>,
    /// Who holds which role on the node, by name (`plane::grant`).
    grants: Grants,
    audit: ProgramAudit,
    /// What the node publishes, told of each act taken so it publishes at
    /// once.
    published: Option<Arc<dyn Published>>,
    waiter: Arc<Waiter>,
}

/// An act watch on its thread, stopped as it is dropped.
pub struct ActWatching {
    watch: Arc<ActWatch>,
    thread: Option<JoinHandle<()>>,
}

/// Every act watch running in this process: what a door finds the owning
/// node's by.
static RUNNING: Mutex<Vec<Weak<ActWatch>>> = Mutex::new(Vec::new());

impl ActWatch {
    /// The act watch of the node at `node`, over its Xmip Storage, judging
    /// by `grants` and auditing in `audit`; nothing waits yet.
    #[must_use]
    pub fn new(
        node: &str,
        storage: Arc<dyn XmipStorage>,
        grants: Grants,
        audit: &ProgramAudit,
    ) -> Self {
        Self {
            node: node.to_string(),
            storage,
            grants,
            audit: audit.clone(),
            published: None,
            waiter: Arc::new(Waiter::of(node)),
        }
    }

    /// The same, telling `published` of each act it takes.
    #[must_use]
    pub fn telling(mut self, published: Arc<dyn Published>) -> Self {
        self.published = Some(published);
        self
    }

    /// Watched on a thread of its own, each wait for at most `bound`, until
    /// what this returns is dropped; the door of every listener in this
    /// process finds it from now on.
    ///
    /// # Errors
    ///
    /// No thread.
    pub fn start(self, bound: Duration) -> Result<ActWatching, String> {
        let watch = Arc::new(self);
        {
            let mut running = RUNNING.locked();
            running.retain(|held| held.strong_count() > 0);
            running.push(Arc::downgrade(&watch));
        }
        let watched = Arc::clone(&watch);
        let thread = std::thread::Builder::new()
            .name("xmip-act-watch".to_string())
            .spawn(move || watched.run(bound))
            .map_err(|error| format!("the act watch has no thread: {error}"))?;
        Ok(ActWatching {
            watch,
            thread: Some(thread),
        })
    }

    /// The act watch of the node at `node` running in this process.
    #[must_use]
    pub fn running(node: &str) -> Option<Arc<Self>> {
        RUNNING
            .locked()
            .iter()
            .filter_map(Weak::upgrade)
            .find(|watch| watch.node == node && !watch.waiter.is_stopped())
    }

    /// The Xmip Storage its node's acts are asked in.
    #[must_use]
    pub fn storage(&self) -> &Arc<dyn XmipStorage> {
        &self.storage
    }

    /// Until stopped: told of each act asked of the node, each taken in
    /// order. The first answer says where the node's acts stand, and every
    /// act still asked is taken then, the ones asked while the node was not
    /// running among them; from then on, each asked after the last seen.
    fn run(&self, bound: Duration) {
        let node = ActRecord::of_node(&self.node);
        let mut seen: Option<u64> = None;
        while !self.waiter.is_stopped() {
            self.waiter.asking();
            let at = seen.unwrap_or(0);
            let watched = [Position {
                watched: Watched::Acts(node),
                at,
            }];
            match self.storage.wait_queues(&watched, (bound, 0), &self.waiter) {
                // Nothing moved within the wait: asked again at once, since
                // a Storage node may hold a wait shorter than `bound`.
                Ok(moved) => {
                    let now = moved
                        .iter()
                        .find(|one| one.position.watched == Watched::Acts(node))
                        .map(|one| one.position.at);
                    let read = match (seen, now) {
                        (None, Some(now)) => self.take_still_asked().then_some(now),
                        (Some(seen), Some(now)) => Some(self.take_after(seen, now)),
                        (seen, None) => seen,
                    };
                    // An act it could not read is read again after a rest,
                    // never asked for without pause.
                    if now.is_some_and(|now| read.is_none_or(|read| read < now)) {
                        self.waiter.rest(RETRY.min(bound));
                    }
                    seen = read.or(seen);
                }
                Err(_) => self.waiter.rest(RETRY.min(bound)),
            }
        }
    }

    /// Every act still asked of the node, oldest first: whether each was
    /// read.
    fn take_still_asked(&self) -> bool {
        let mut after = 0;
        loop {
            let Ok(acts) = self.storage.read_acts(&self.node, (after, PAGE), true) else {
                return false;
            };
            for act in &acts {
                self.take(act);
            }
            match acts.last() {
                Some(last) if acts.len() >= usize::try_from(PAGE).unwrap_or(usize::MAX) => {
                    after = last.place;
                }
                _ => return true,
            }
        }
    }

    /// Each act asked of the node after the place `seen`, up to `now`: the
    /// place of the last read.
    fn take_after(&self, mut seen: u64, now: u64) -> u64 {
        while seen < now {
            let Ok(acts) = self.storage.read_acts(&self.node, (seen, PAGE), false) else {
                return seen;
            };
            for act in &acts {
                self.take(act);
            }
            match acts.last() {
                Some(last) => seen = last.place,
                None => return now,
            }
        }
        seen
    }

    /// Stopped: its wait ends now, and no other is asked.
    fn stop(&self) {
        self.waiter.stop();
    }
}

impl Drop for ActWatching {
    fn drop(&mut self) {
        self.watch.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        RUNNING.locked().retain(|held| {
            held.upgrade()
                .is_some_and(|w| !Arc::ptr_eq(&w, &self.watch))
        });
    }
}

#[cfg(test)]
mod tests;
