//! The send step: every Journey bound for a Send Port read from the Ledger
//! and sent on the node's Send pool (`runtime-model.md` section 10, *How a
//! send runs*; ADR-0018, amendments 2026-10-01 and 2026-10-03).
//!
//! ```text
//! Publication     each Journey waits in its Send Port's queue in the
//!                 Ledger; one this node sends is claimed in the same write
//! -> claim        through Xmip Storage: the Publication's, or a scan's
//! -> send         the Port's Send Locations in order, retry and failover
//! -> hand on      one write: the outcome on the Journey — Completed, or
//!                 Failed with its reason — its place let go of, the claim
//!                 released; or Recovering, the claim kept to its due time
//! ```
//!
//! **The receive cycle sends nothing.** It ends at the Publication's durable
//! write and the acknowledgement; departure is this step's. A Journey whose
//! Send Port this node sends is claimed in the Publication's own write and
//! handed to the Send pool in memory, so the send starts without a sync of
//! its own; any other waits in its queue for a node that sends it.
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
//! **A Sequential Send Port keeps its order** by its order key: a sequence
//! has one Journey in flight at a time, the oldest in its queue first, and
//! one that failed blocks it, kept in the queue, or is set aside, as its
//! `on_failure` says (`runtime-model.md` section 3, *A claim is not
//! ordering*).

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

mod dispatch;
mod figures;
mod pass;
mod scan;

pub use dispatch::dispatch;
pub use figures::PortFigures;
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

/// A Journey this node holds claimed: in flight on the Send pool, or
/// waiting for its due time.
#[derive(Clone, Debug)]
struct Owned {
    claim: Claim,
    queue: u128,
    sequence: Option<String>,
}

#[derive(Default)]
struct State {
    /// Claimed and ready to send.
    handed: VecDeque<Departure>,
    /// Waiting for their due time, retries.
    due: Vec<(Instant, Departure)>,
    owned: HashMap<JourneyId, Owned>,
    /// Read and found not to be sent — unreadable, or finished though still
    /// in a queue — audited once and passed over by every scan after.
    passed: HashSet<JourneyId>,
    /// Queues to read now, beside the scan of them all.
    asked: Vec<u128>,
    figures: BTreeMap<String, PortFigures>,
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
    /// Sequential, claimed by it in the same write, minted by `ids`.
    #[must_use]
    pub fn line_up(
        &self,
        sends: &Sends,
        departing: &[(&Journey, &Subscriber)],
        body: &[u8],
        ids: &dyn IdGenerator,
    ) -> LinedUp {
        let mut lined = LinedUp::default();
        for (journey, to) in departing {
            let queue = self.queue(to);
            let journey = journey.journey_id();
            lined.holds.push(Hold {
                queue,
                journey,
                body: body.to_vec(),
            });
            if sends.serves(to) && !sequential(sends, to) {
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
    /// the identity it arrived with, `facts`. A queue holding a Journey
    /// this node sends and did not claim is read at once.
    pub fn handed(
        &self,
        lined: LinedUp,
        journeys: &[Journey],
        work: &ReceivedWork,
        facts: &IdentityFacts,
    ) {
        let mut state = self.lock();
        for (id, to, queue, claim) in lined.claimed {
            let Some(journey) = journeys.iter().find(|j| j.journey_id() == id) else {
                continue;
            };
            state.owned.insert(
                id,
                Owned {
                    claim: claim.clone(),
                    queue,
                    sequence: None,
                },
            );
            state.handed.push_back(Departure {
                work: ReceivedWork {
                    journey: journey.clone(),
                    message: work.message.clone(),
                },
                facts: facts.clone(),
                to,
                queue,
                claim,
                progress: Progress::default(),
                sequence: None,
            });
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

    /// `departure`, claimed by this node, handed to the Send pool.
    pub fn hand(&self, departure: Departure) {
        let mut state = self.lock();
        state.owned.insert(
            departure.work.journey.journey_id(),
            Owned {
                claim: departure.claim.clone(),
                queue: departure.queue,
                sequence: departure.sequence.clone(),
            },
        );
        state.handed.push_back(departure);
        drop(state);
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

    /// The figures of every Send Port this node has sent through.
    #[must_use]
    pub fn figures(&self) -> BTreeMap<String, PortFigures> {
        let state = self.lock();
        let mut figures = state.figures.clone();
        for (_, waiting) in &state.due {
            for port in waiting.progress.ports.keys() {
                figures.entry(port.clone()).or_default().waiting += 1;
            }
        }
        figures
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
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
