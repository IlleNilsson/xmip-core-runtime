//! The send step: every Journey bound for a Send Port read from the Ledger
//! and sent on the node's Send pool (`runtime-model.md` section 10, *How a
//! send runs*; ADR-0018, amendments 2026-10-01 and 2026-10-03).
//!
//! ```text
//! Publication     each Journey waits in its Send Port's queue in the
//!                 Ledger; one this node sends is claimed in the same write
//! -> claim        through Xmip Storage: the Publication's, or a scan's
//! -> send         the Port's Send Locations in order, retry and failover
//! -> hand on      one write: the outcome on the Journey — Completed and
//!                 out of its queue, or Failed with its reason and kept
//!                 there — its tries, the claim released; or Recovering,
//!                 its tries and the claim kept to its due time
//! ```
//!
//! **One Journey per Send Port.** A Send Port Group's Journeys are opened
//! one per Port at the Publication, each in its own Port's queue
//! (`runtime-model.md` section 10), so each Port of a Group is sent, retried,
//! failed and acted on alone.
//!
//! **The receive cycle sends nothing.** It ends at the Publication's durable
//! write and the acknowledgement; departure is this step's. A Journey whose
//! Send Port this node sends is claimed in the Publication's own write and
//! handed to the Send pool in memory, so the send starts without a sync of
//! its own, where the pool has room for it; any other waits in its queue
//! for a node that sends it, or for room.
//!
//! **The pool's threads bound what the node holds.** Every Journey it
//! claims — at a Publication, a resumed Subscription's move, a scan — is
//! admitted to a place in the Send pool first ([`admission`]); what has
//! none stays durable and unclaimed in its queue, read again the moment a
//! place frees.
//!
//! **A retry waiting for its backoff holds no thread.** Its due time is in
//! the Ledger — its claim kept until then, written in the hand-on — and the
//! node keeps when it is due only to start it again; a node that dies lets
//! the claim lapse, and another takes it up.
//!
//! **Recovery is a scan.** As the node starts, and every `[tuning]
//! send_scan` after, each queue this node sends is read oldest first, and
//! every Journey in it no live claim holds is claimed and sent: one a node
//! left when it died, one whose send was cut short, one no node sending its
//! Port held. Claims of work in flight are renewed while it runs; a stop
//! gives back the claims of what waits ([`SendStep::close`]).
//!
//! **A claim found lost is not sent on** ([`renewal`]). A renewal that
//! finds the claim another's stops every further attempt from this node;
//! one Xmip Storage does not answer leaves the claim unconfirmed — its Send
//! Port Done, a flat-out error — and attempts go on only while a lease from the last
//! confirmation lasts, after which the claim is presumed lost, audited, and
//! no Location is tried again from here. A send already under way keeps the
//! Journey's identifier as its deduplication key.
//!
//! **A Sequential Send Port keeps its order** by its order key: a sequence
//! has one Journey in flight at a time, the oldest in its queue first, and
//! one that failed blocks it, or is set aside, as its `on_failure` says
//! (`runtime-model.md` section 3, *A claim is not ordering*).
//!
//! **A Journey that failed waits for an operator** in its queue: Retry
//! sends it again, Dismiss ends it Dismissed, each an act through the
//! node's orders, audited ([`SendStep::act`], `runtime-model.md` section
//! 13). A retry's count is the Journey's `attempts`, kept with its every
//! hand-on, so it survives a restart and another node taking it up.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use context::IdentityFacts;
use journey::Journey;
use persist::storage::{Claim, Hold, XmipStorage};
use route::Subscriber;
use xaudit::program_audit::ProgramAudit;
use xcore::{IdGenerator, JourneyId};

use crate::departure::Progress;
use crate::generation::ReceivedWork;
use crate::pool::Limits;
use crate::sending::{Destination, Sends, queue};
use crate::tuning::Tuning;

mod admission;
mod dispatch;
mod failed;
mod figures;
mod journey_act;
mod pass;
mod registered;
mod renewal;
mod scan;

use admission::Owned;
pub use dispatch::dispatch;
pub use failed::FailedPage;
pub use figures::{FailedJourney, PUBLISHED_FAILED, PortFigures};
pub(crate) use pass::record;
pub use pass::{Ended, Found, read, send, sequence};

/// The Send pool's threads for each of the machine's hardware threads,
/// where the node's `[tuning] send_threads_per_hardware_thread` does not
/// say: two, since a send waits on its far end and on the Ledger.
pub const SEND_THREADS_PER_HARDWARE_THREAD: usize = 2;

/// How long a send thread with nothing to do waits before it ends, where
/// `[tuning] send_idle` does not say: a minute, as a receive thread's.
pub const SEND_IDLE: Duration = Duration::from_secs(60);

/// How long a claim on a Journey holds before it lapses, unless renewed,
/// where `[tuning] send_lease` does not say: thirty seconds — how long a
/// node's death leaves its sends before another node takes them up.
pub const SEND_LEASE: Duration = Duration::from_secs(30);

/// How often the queues this node sends are read for what no live claim
/// holds, where `[tuning] send_scan` does not say: every second.
pub const SEND_SCAN: Duration = Duration::from_secs(1);

/// What is told how each pass of a send ended, once its hand-on is written:
/// the node's count of what it sent and what failed.
pub type Settled<'a> = &'a (dyn Fn(&Departure, &Ended) + Sync);

/// One Journey being sent: its Journey and Message, the identity it arrived
/// with, where it leads, the queue it waits in, the claim it is sent under,
/// where its send stands and, on a Sequential Send Port, its sequence.
#[derive(Clone, Debug)]
pub struct Departure {
    pub work: ReceivedWork,
    pub facts: IdentityFacts,
    pub to: Subscriber,
    pub queue: u128,
    pub claim: Claim,
    pub progress: Progress,
    /// Its order key's value, on a Sequential Send Port.
    pub sequence: Option<String>,
    /// The latest this node is sure its claim holds, on its own clock: a
    /// lease — waiting for a retry, its due time and a lease — from when
    /// the request that last confirmed the claim was asked, so no two
    /// clocks are ever compared.
    pub until: Instant,
}

/// What a Publication writes for the Journeys that go on to be sent: each
/// in its destination's queue, and the claims this node takes on those it
/// sends itself.
#[derive(Debug, Default)]
pub struct LinedUp {
    pub holds: Vec<Hold>,
    pub claims: Vec<Claim>,
    /// The claimed ones, by Journey: where each leads and its queue.
    claimed: Vec<(JourneyId, Subscriber, u128, Claim)>,
    /// The places in the Send pool admitted for them.
    admitted: usize,
    /// When it was lined up, before its Publication was asked: what its
    /// claims are surely held a lease from.
    asked: Option<Instant>,
}

/// A node's send step: what it sends, what it holds claimed, what waits for
/// its due time, and its figures per Send Port.
pub struct SendStep {
    cluster: String,
    node: String,
    storage: Arc<dyn XmipStorage>,
    lease: Duration,
    scan: Duration,
    limits: Limits,
    audit: Option<ProgramAudit>,
    state: Mutex<State>,
    wake: Condvar,
}

#[derive(Default)]
struct State {
    /// Claimed and ready to send.
    handed: VecDeque<Departure>,
    /// Waiting for their due time, retries.
    due: Vec<(Instant, Departure)>,
    owned: HashMap<JourneyId, Owned>,
    /// Places in the Send pool admitted for Journeys not yet owned.
    admitted: usize,
    /// Found unclaimed by a scan, each under a place admitted, being
    /// claimed on a send thread.
    taking: HashSet<JourneyId>,
    /// Queues holding Journeys the pool had no room for, read again once a
    /// place frees.
    starved: Vec<u128>,
    /// Read at their place in a queue and found not to be sent —
    /// unreadable, failed and set aside, or finished though still in a
    /// queue — passed over by every scan after. A Retry moves a Journey to
    /// a new place, where it is read again. By queue, so a whole read of
    /// one forgets what has left it.
    passed: HashMap<u128, HashSet<(JourneyId, u64)>>,
    /// The Send Ports this node sends, each with whether a Journey of it
    /// that failed blocks its sequence: what an operator's act on one of
    /// its Journeys is decided by.
    ports: BTreeMap<String, bool>,
    /// Queues to read now, beside the scan of them all.
    asked: Vec<u128>,
    figures: BTreeMap<String, PortFigures>,
    /// Every Journey that failed waiting in a queue this node sends, by
    /// its Send Port and its place: what a scan of the Ledger read Failed,
    /// so the evidence outlives a restart and covers what another node
    /// failed.
    failing: BTreeMap<String, figures::Failing>,
    closed: bool,
}

impl SendStep {
    /// The send step of the node at `node` (`xmip:///<cluster>/node/<name>`)
    /// in the cluster at `cluster` (`xmip:///<cluster>`), over `storage`,
    /// run as `tuning` says. `audit` records every Journey that failed.
    #[must_use]
    pub fn new(
        (cluster, node): (&str, &str),
        storage: Arc<dyn XmipStorage>,
        tuning: &Tuning,
        audit: Option<ProgramAudit>,
    ) -> Self {
        Self {
            cluster: cluster.to_string(),
            node: node.to_string(),
            storage,
            lease: tuning.send_lease,
            scan: tuning.send_scan,
            limits: tuning.send(),
            audit,
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        }
    }

    /// The queue in the Ledger the Journeys bound for `to` wait in.
    #[must_use]
    pub fn queue(&self, to: &Subscriber) -> u128 {
        queue(&self.cluster, to)
    }

    /// How long a claim this node takes holds before it lapses.
    #[must_use]
    pub const fn lease(&self) -> Duration {
        self.lease
    }

    /// The Journeys a Publication opens that go on to be sent — each with
    /// where it leads — lined up: each kept at the end of its destination's
    /// queue, beside it `body`, the identity it arrived with in its one
    /// form; and those this node sends, on a Send Port that is not
    /// Sequential, claimed by it in the same write, minted by `ids` — as
    /// many as the Send pool admits; the rest wait unclaimed for room.
    #[must_use]
    pub fn line_up(
        &self,
        sends: &Sends,
        departing: &[(&Journey, &Subscriber)],
        body: &[u8],
        ids: &dyn IdGenerator,
    ) -> LinedUp {
        let sent_here = |to: &Subscriber| sends.serves(to) && !sequential(sends, to);
        let wanted = departing.iter().filter(|(_, to)| sent_here(to)).count();
        let mut lined = LinedUp {
            admitted: self.admit(wanted),
            asked: Some(Instant::now()),
            ..LinedUp::default()
        };
        let mut places = lined.admitted;
        for (journey, to) in departing {
            let queue = self.queue(to);
            let journey = journey.journey_id();
            lined.holds.push(Hold {
                queue,
                journey,
                body: body.to_vec(),
            });
            if places > 0 && sent_here(to) {
                places -= 1;
                let claim = Claim {
                    journey,
                    holder: self.node.clone(),
                    token: ids.next_u128(),
                    until_unix_nanos: 0,
                };
                lined.claims.push(claim.clone());
                lined.claimed.push((journey, (*to).clone(), queue, claim));
            }
        }
        lined
    }

    /// What `lined` claimed, durable now in its Publication, handed to the
    /// Send pool: each of `journeys` it claimed, with `work`'s Message and
    /// the identity it arrived with, `facts`, each in the place admitted
    /// for it. A queue holding a Journey this node sends and did not claim
    /// is read at once, or once a place frees.
    pub fn handed(
        &self,
        lined: LinedUp,
        journeys: &[Journey],
        work: &ReceivedWork,
        facts: &IdentityFacts,
    ) {
        let until = lined.asked.unwrap_or_else(Instant::now) + self.lease;
        let mut state = self.lock();
        state.admitted = state.admitted.saturating_sub(lined.admitted);
        for (id, to, queue, claim) in lined.claimed {
            let Some(journey) = journeys.iter().find(|j| j.journey_id() == id) else {
                continue;
            };
            let departure = Departure {
                work: ReceivedWork {
                    journey: journey.clone(),
                    message: work.message.clone(),
                },
                facts: facts.clone(),
                to,
                queue,
                claim,
                progress: Progress::of(journey.attempts),
                sequence: None,
                until,
            };
            state.owned.insert(id, Owned::of(&departure));
            state.handed.push_back(departure);
        }
        for hold in &lined.holds {
            let claimed = state.owned.contains_key(&hold.journey);
            if !claimed && !state.asked.contains(&hold.queue) {
                state.asked.push(hold.queue);
            }
        }
        drop(state);
        self.wake.notify_all();
    }

    /// `departure`, claimed by this node under a place the Send pool
    /// admitted for it ([`SendStep::admit`]), handed to the pool.
    pub fn hand(&self, departure: Departure) {
        self.own(departure.work.journey.journey_id(), Owned::of(&departure));
        self.lock().handed.push_back(departure);
        self.wake.notify_all();
    }

    /// Read `queue` now, for what waits in it unclaimed.
    pub fn ask(&self, queue: u128) {
        let mut state = self.lock();
        if !state.asked.contains(&queue) {
            state.asked.push(queue);
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Stop taking work: what is handed is sent, and the claims of what
    /// waits for its due time are given back (ADR-0018 clause 12), once the
    /// step's dispatching ends.
    pub fn close(&self) {
        self.lock().closed = true;
        self.wake.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The Send Ports it sends, by name.
    #[must_use]
    pub fn ports(&self) -> Vec<String> {
        self.lock().ports.keys().cloned().collect()
    }

    /// The node it sends for: `xmip:///<cluster>/node/<name>`.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }
}

/// Whether what is bound for `to` is sent in sequence: a Sequential Send
/// Port, or a Group with one among its Ports.
pub(crate) fn sequential(sends: &Sends, to: &Subscriber) -> bool {
    match sends.to(to) {
        Destination::Ports(ports) => ports.iter().any(|port| port.sequence().is_some()),
        Destination::Process | Destination::Nowhere => false,
    }
}
