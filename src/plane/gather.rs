//! The cluster's view gathered from its members, each followed over its
//! operate listener as a surface follows a node (ADR-0027 decision 8; the
//! design of 2026-11-12 the owner approved, section 3.3; ADR-0052,
//! amendment 2026-11-13). Who the members are is the cluster's seam,
//! `xcluster::Membership`: the run's roster on the Essentials' roll, which
//! reads every node it does not simulate through this; membership through
//! Xmip Storage on a node, the design's next piece. How this process reaches
//! each — the surface, the identity it presents, and where it says it
//! reached it — is its caller's, a [`Reach`] for each member. Not tied to
//! the `node` feature: a program that runs no node gathers too.
//!
//! **Followed, never asked again and again.** Each member is followed
//! through a [`Follow`] — a `Remote` over its operate listener, or the
//! gathering node's own publication in process — told as its publication
//! advances, and read once each time it is told, so what was heard of it is
//! its latest; one this process cannot reach is said not to answer, and
//! why. A [`Gatherer`] starts by hearing every member once, each within its
//! own surface's patience, so its first view is whole.
//!
//! **One assembler.** On each member heard, one thread takes the latest of
//! every member and assembles the cluster's view ([`Gathered::assembled`]);
//! what is heard meanwhile is assembled together, next. A caller with a view
//! of its own merges what was heard into it instead ([`Gathered::merged`]),
//! stating each member's `<node>/reached` ([`reached`]) at its own time.

mod assembler;
mod follow;
mod follower;
mod gathered;
mod reached;

pub use follow::Follow;
#[cfg(feature = "node")]
pub use follow::own;
pub use gathered::{Gathered, Heard, Said};
pub use reached::reached;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use node::Scope;
use observe::now_unix_nanos;
use observe::topology::relate;
use observe::topology::window::Window;
use xcluster::{ClusterError, Member, Membership};
use xcore::lock::Locked;
use xcore::wake::Revision;

/// How this process reaches one member: where, as its `<node>/reached`
/// opens — the roll's `real, at <address>` — and what it is followed
/// through, a surface shared with whatever else the caller asks of the
/// member or the node's own publication; or why this process cannot reach
/// it.
pub struct Reach {
    pub at: String,
    pub through: Result<Arc<dyn Follow>, String>,
}

/// A cluster's members followed, and the view assembled from what each
/// published.
pub struct Gatherer {
    gathering: Arc<Gathering>,
    assembler: Option<JoinHandle<()>>,
    followers: Vec<JoinHandle<()>>,
}

/// One member as this gatherer follows it: or, stopped in order at a time,
/// follows not at all.
struct Followed {
    at: String,
    through: Result<Arc<dyn Follow>, String>,
    stopped: Option<u64>,
}

/// What the followers, the assembler and the gatherer share.
struct Gathering {
    root: String,
    /// The scope of the node gathering, where a node gathers.
    by: Option<String>,
    members: Vec<Followed>,
    /// The members as they are drawn, in the same order: each by its name,
    /// an opaque id, the roles it declares and its place in `[storage]
    /// nodes`.
    drawn: Vec<relate::Member>,
    /// The latest heard of each member, none before it was first heard.
    latest: Mutex<Vec<Option<Arc<Heard>>>>,
    /// Raised as each member is heard.
    heard: Revision,
    /// The view last assembled.
    view: Mutex<Arc<Gathered>>,
    /// Raised as each view is assembled.
    assembled: Revision,
    ending: AtomicBool,
}

impl Gatherer {
    /// The members `membership` says, of the cluster at `root`, gathered
    /// `by` the node of that scope where a node gathers, each followed as
    /// `reach` says this process reaches it, from now: returned once every
    /// member was heard once and the first view assembled.
    ///
    /// # Errors
    ///
    /// The membership could not be read, as it says: nothing is followed.
    pub fn start(
        root: &str,
        by: Option<&str>,
        membership: &dyn Membership,
        reach: &dyn Fn(&Member) -> Reach,
    ) -> Result<Self, ClusterError> {
        let listed = membership.members()?;
        let members: Vec<Followed> = listed
            .iter()
            .map(|member| {
                let Reach { at, through } = reach(member);
                let stopped = member.stopped;
                Followed {
                    at,
                    through,
                    stopped,
                }
            })
            .collect();
        let gathering = Arc::new(Gathering {
            root: root.to_string(),
            by: by.map(str::to_string),
            drawn: listed.iter().map(drawn).collect(),
            latest: Mutex::new(vec![None; members.len()]),
            members,
            heard: Revision::new(),
            view: Mutex::default(),
            assembled: Revision::new(),
            ending: AtomicBool::new(false),
        });
        let followers = follower::started(&gathering);
        let built = gathering.first_heard();
        let mut window = Window::new();
        gathering.assemble(&mut window);
        let assembler = (!followers.is_empty())
            .then(|| assembler::started(&gathering, built, window))
            .flatten();
        Ok(Self {
            gathering,
            assembler,
            followers,
        })
    }

    /// The view last assembled.
    #[must_use]
    pub fn gathered(&self) -> Arc<Gathered> {
        Arc::clone(&self.gathering.view.locked())
    }

    /// The view once one later than revision `after` is assembled, or the
    /// last after `within`.
    #[must_use]
    pub fn wait(&self, after: u64, within: Duration) -> Arc<Gathered> {
        self.wait_unless(after, within, &|| false)
    }

    /// The same, or the last view as soon as `stopped` says the one waiting
    /// stops, woken by [`Gatherer::wake`]: what a publisher of the view
    /// waits in, which ends when another gatherer takes this one's place or
    /// its node stops — never by looking again.
    #[must_use]
    pub fn wait_unless(
        &self,
        after: u64,
        within: Duration,
        stopped: &dyn Fn() -> bool,
    ) -> Arc<Gathered> {
        let gathering = &self.gathering;
        gathering
            .assembled
            .wait_unless(after, within, || gathering.ending() || stopped());
        self.gathered()
    }

    /// Wake every wait on its views, so each looks at what stops it.
    pub fn wake(&self) {
        self.gathering.assembled.wake();
    }
}

impl Gathering {
    fn ending(&self) -> bool {
        self.ending.load(Ordering::SeqCst)
    }

    /// The member at `at` heard to have said `said`, and the assembler told.
    fn heard(&self, at: usize, said: Said) {
        let heard = Arc::new(Heard {
            node: self.drawn[at].node.clone(),
            at: self.members[at].at.clone(),
            said,
        });
        self.latest.locked()[at] = Some(heard);
        self.heard.raise();
    }

    /// The revision every member had been heard by, waited for.
    fn first_heard(&self) -> u64 {
        loop {
            let revision = self.heard.now();
            if self.latest.locked().iter().all(Option::is_some) {
                return revision;
            }
            self.heard.wait(revision, Duration::MAX);
        }
    }

    /// The view assembled from the latest of every member, now.
    fn assemble(&self, window: &mut Window) {
        let heard: Vec<Arc<Heard>> = self.latest.locked().iter().flatten().cloned().collect();
        let revision = self.assembled.now() + 1;
        let members = (
            self.root.as_str(),
            self.by.as_deref(),
            self.drawn.as_slice(),
        );
        let gathered = Gathered::assembled(members, heard, revision, (now_unix_nanos(), window));
        *self.view.locked() = Arc::new(gathered);
        self.assembled.raise();
    }
}

/// `member` as a cluster's drawing relates and stands it: by its name — the
/// `<name>` of its scope, `xmip:///<cluster>/node/<name>` — the roles it
/// declares and its place in `[storage] nodes`.
fn drawn(member: &Member) -> relate::Member {
    let name = Scope::new(&member.node).node().unwrap_or(&member.node);
    let place = member
        .storage_place
        .and_then(|place| u32::try_from(place).ok());
    relate::Member::new(name, member.capability.roles(), place)
}

impl Drop for Gatherer {
    /// Every thread woken to end: the assembler waited for, which is woken
    /// from a wait or ends its assembly, and each follower let go, which
    /// ends as soon as what it asks its member is answered.
    fn drop(&mut self) {
        let gathering = &self.gathering;
        gathering.ending.store(true, Ordering::SeqCst);
        gathering.heard.wake();
        gathering.assembled.wake();
        for through in gathering
            .members
            .iter()
            .filter_map(|one| one.through.as_ref().ok())
        {
            through.wake();
        }
        if let Some(assembler) = self.assembler.take() {
            let _ = assembler.join();
        }
        for follower in self.followers.drain(..) {
            if follower.is_finished() {
                let _ = follower.join();
            }
        }
    }
}

#[cfg(test)]
mod tests;
