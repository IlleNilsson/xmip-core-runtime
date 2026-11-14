//! The send step: every Message bound for a Send Port read from the Ledger
//! and sent on the node's Send pool (`runtime-model.md` section 10, *How a
//! send runs*; ADR-0018, amendments 2026-10-01 and 2026-10-03).
//!
//! ```text
//! Publication     each Message waits in its Send Port's queue in the
//!                 Ledger; one this node sends is claimed in the same write
//! -> claim        through Xmip Storage: the Publication's, or a scan's
//! -> send         the Port's Send Locations in order, retry and failover
//! -> hand on      one write: the outcome on the Journey — Completed and
//!                 out of its queue, or Failed with its reason and kept
//!                 there — its tries, the claim released; or Recovering,
//!                 its tries, its due time kept at its place, the claim
//!                 released
//! ```
//!
//! **One Journey per Send Port.** A Send Port Group's Journeys are opened
//! one per Port at the Publication, the Message in each Port's own queue
//! (`runtime-model.md` section 10), so each Port of a Group is sent, retried,
//! failed and acted on alone.
//!
//! **The receive cycle sends nothing.** It ends at the Publication's durable
//! write and the acknowledgement; departure is this step's. A Message whose
//! Send Port this node sends is claimed in the Publication's own write and
//! handed to the Send pool in memory, so the send starts without a sync of
//! its own, where the pool has room for it; any other waits in its queue
//! for a node that sends it, or for room.
//!
//! **The pool's threads bound what the node holds.** Every Message it
//! claims — at a Publication, a resumed Subscription's move, a scan — is
//! admitted to a place in the Send pool first ([`admission`]); what has
//! none stays durable and unclaimed in its queue, read again the moment a
//! place frees.
//!
//! **A retry waiting for its backoff holds nothing** (the owner,
//! 2026-10-16; open problem 43). Its hand-on keeps its due time at its
//! place in its queue, on Xmip Storage's clock, and releases its claim and
//! its place in the Send pool; a scan passes over it until it is due and
//! then takes it up like any other, on whichever node. The node keeps only
//! the earliest due time each queue's last read showed, and each hand-on
//! since that read began noted, and wakes for it at that time, so one far
//! end that fails cannot fill the pool every Port shares.
//!
//! **Another node's Publication wakes it** (open problem 46, built
//! 2026-11-12): the step waits on the queues it sends in Xmip Storage, and
//! reads each one the moment a Publication, a hand-on, a turn or a Replay
//! on any node puts a Message in it, what is due there coming with the
//! wake, so it claims without a read of its own first; and a Message it
//! passed over behind another Stream of its sequence is read again the
//! moment any node moves that sequence's head (`crate::queue_watch`).
//!
//! **A claim taken from a queue is sent under once readable** (ADR-0018,
//! amendment 2026-11-12). Xmip Storage answers it before its sync, with
//! when it is durable (`XmipStorage::claim_ahead`), so the Message's read,
//! its sequences and its send are prepared while the claim syncs; a
//! technology that holds its delivery back lets its far end see it only
//! once the claim is durable and still this node's, and every other sends
//! its first byte only then. A claim whose sync failed, or whose word never
//! came, abandons what was prepared: no far end saw it, no try is counted,
//! and the claim is given back where Xmip Storage still answers.
//!
//! **Each send is timed step by step** ([`Steps`]), and each Send Port's
//! snapshot says the median of each step over its latest sends, handed in
//! memory and taken from its queue apart (2026-11-12).
//!
//! **Recovery is a scan.** As the node starts, and every `[tuning]
//! send_scan` after, each queue this node sends is read oldest first, and
//! every Message in it no live claim holds, and due, is claimed and sent:
//! one a node left when it died, one whose send was cut short, one whose
//! retry is due, one no node sending its Port held. What a scan read may be
//! older than its claim, so every claim it takes reads the Message's place
//! again, its due time with it, and sends only what is still there, due
//! and to be sent (2026-10-17). Claims of work in flight are renewed while
//! it runs.
//!
//! **A claim found lost is not sent on** ([`renewal`]). A renewal that
//! finds the claim another's stops every further attempt from this node;
//! one Xmip Storage does not answer leaves the claim unconfirmed — its Send
//! Port Done, a flat-out error — and attempts go on only while a lease from the last
//! confirmation lasts, after which the claim is presumed lost, audited, and
//! no Location is tried again from here. A send already under way keeps the
//! Journey's identifier as its deduplication key.
//!
//! **A Send Port naming a Correlation keeps its order** per key, and a
//! Message of a Stream that holds its Receive Location's sequence waits for
//! it: a Message that does not head its sequences is passed, its claim given
//! back, and taken up once it does; one that failed blocks its sequence, or
//! is set aside, as its set's `on_failure` says (`crate::sequence`;
//! `runtime-model.md` section 3, *A claim is not ordering*).
//!
//! **A Message that failed waits for an operator** in its queue: Retry
//! sends it again, Dismiss ends it Dismissed, each an act asked at a node's
//! door and taken by its act watch, audited ([`SendStep::act`],
//! `crate::act_watch`, `runtime-model.md` section 13). A retry's count is the Journey's `attempts`, kept with its every
//! hand-on, so it survives a restart and another node taking it up. The
//! hand-on that fails it enters it in its queue's index of failed Messages
//! in the Ledger and the act takes it out, so how many wait is Xmip
//! Storage's count, and the node keeps a bounded window of the oldest
//! ([`figures`]).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use xcore::lock::Locked;

use context::IdentityFacts;
use journey::Journey;
use persist::storage::{Claim, Durable, Hold, XmipStorage};
use route::Subscriber;
use xaudit::program_audit::ProgramAudit;
use xcore::spent::Spent;
use xcore::wake::Wake;
use xcore::{IdGenerator, JourneyId};

use crate::departure::Progress;
use crate::generation::ReceivedWork;
use crate::outcome::Measured;
use crate::pool::Limits;
use crate::queue_watch::{QueueWatch, Woken};
use crate::sending::{Destination, Sends, queue};
use crate::stream_share::StreamShare;
use crate::tuning::Tuning;

mod admission;
mod dispatch;
mod due;
mod failed;
mod figures;
#[cfg(test)]
mod fixture;
mod found;
mod message_act;
mod pass;
mod reading;
mod registered;
mod renewal;
mod scan;
mod steps;
mod under_claim;

use admission::Owned;
pub use dispatch::dispatch;
pub use failed::FailedPage;
pub use figures::{FAILED_WINDOW, FailedMessage, PortFigures};
pub use found::{Found, read};
pub use pass::{Ended, send};
pub use steps::{STEPS_KEPT, Step, Steps};

/// The Send pool's threads for each of the machine's hardware threads,
/// where the node's `[tuning] send_threads_per_hardware_thread` does not
/// say: two, since a send waits on its far end and on the Ledger.
pub const SEND_THREADS_PER_HARDWARE_THREAD: usize = 2;

/// How long a send thread with nothing to do waits before it ends, where
/// `[tuning] send_idle` does not say: a minute, as a receive thread's.
pub const SEND_IDLE: Duration = Duration::from_secs(60);

/// How long a claim on a Message holds before it lapses, unless renewed,
/// where `[tuning] send_lease` does not say: thirty seconds — how long a
/// node's death leaves its sends before another node takes them up.
pub const SEND_LEASE: Duration = Duration::from_secs(30);

/// How often the queues this node sends are read for what no live claim
/// holds, where `[tuning] send_scan` does not say: every second.
pub const SEND_SCAN: Duration = Duration::from_secs(1);

/// What is told how each pass of a send ended, once its hand-on is written:
/// the node's count of what it sent and what failed.
pub type Settled<'a> = &'a (dyn Fn(&Departure, &Ended) + Sync);

/// One Message being sent: its Journey and Message, the identity it arrived
/// with, where it leads, the queue it waits in, the claim it is sent under,
/// and where its send stands.
#[derive(Clone, Debug)]
pub struct Departure {
    pub work: ReceivedWork,
    pub facts: IdentityFacts,
    pub to: Subscriber,
    pub queue: u128,
    pub claim: Claim,
    pub progress: Progress,
    /// The latest this node is sure its claim holds, on its own clock: a
    /// lease from when the request that last confirmed the claim was asked,
    /// so no two clocks are ever compared.
    pub until: Instant,
    /// When what it is sent under is durable: its Publication, where its
    /// receive cycle handed it on before the Ledger synced it, or its claim,
    /// where a scan took it ahead of its sync (ADR-0018, amendment
    /// 2026-11-12). The far end sees it only then, and nothing of it where it
    /// never is. `None` where nothing it is sent under waits for a sync.
    pub durable: Option<Durable>,
    /// Handed in memory by its node's own Publication, which claimed it in
    /// the same write; else taken from its queue: how its steps are kept.
    pub handed: bool,
    /// Its Message's account, the processor time worked for it since its
    /// transport handed it over, where its receive cycle handed it on
    /// (`xcore::spent`); `None` where it was read from the Ledger.
    pub spent: Option<Spent>,
    /// Xmip's own share of its Message, once sent: the processor time its
    /// threads worked for it outside its I/O, from its transport handing it
    /// over to its far end having it ([`Spent::own`]); and the disk's time
    /// beside it, its waits for a storage device to sync
    /// ([`Spent::disk_sync`]).
    pub measured: Option<Measured>,
    /// What its send took on this node so far, step by step.
    pub steps: Steps,
}

impl Departure {
    /// What it is sent under waited on until durable, or until its sync
    /// failed, before a write that ends its claim: that write says what came
    /// of it, and a claim's word read over the wire frees its connection for
    /// the next request, never left for its drop to close (ADR-0018,
    /// amendment 2026-11-12). At once where it was waited on already.
    pub(crate) fn settled(&self) {
        if let Some(durable) = &self.durable {
            let _ = durable.wait();
        }
    }
}

/// What a Publication writes for the Messages that go on to be sent: each
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

/// A node's send step: what it sends, what it holds claimed, when each of
/// its queues next has a retry due, and its figures per Send Port.
pub struct SendStep {
    cluster: String,
    node: String,
    storage: Arc<dyn XmipStorage>,
    lease: Duration,
    scan: Duration,
    /// The oldest failed Messages of each Send Port it keeps and publishes:
    /// `[tuning] failed_window`.
    window: usize,
    limits: Limits,
    audit: Option<ProgramAudit>,
    state: Mutex<State>,
    wake: Wake,
    /// The Streams its departures read now, each chunk read once for every
    /// departure of a Stream keeping up.
    share: StreamShare,
    /// Its watch on its queues, and on what a Message it passed over waits
    /// on, stopped as it closes (`crate::queue_watch`).
    watch: QueueWatch,
}

#[derive(Default)]
struct State {
    /// Claimed and ready to send.
    handed: VecDeque<Departure>,
    /// By queue, when its earliest retry is due and how many wait for one,
    /// as its last read of the Ledger showed: one entry per queue, however
    /// many wait, as `xmip-core-schedule` decides ([`schedule::due::Due`]).
    due: HashMap<u128, schedule::due::Due>,
    owned: HashMap<JourneyId, Owned>,
    /// Places in the Send pool admitted for Messages not yet owned.
    admitted: usize,
    /// Found unclaimed by a scan, each under a place admitted, being
    /// claimed on a send thread.
    taking: HashSet<JourneyId>,
    /// Queues holding Messages the pool had no room for, read again once a
    /// place frees.
    starved: Vec<u128>,
    /// Read at their place in a queue and found not to be sent —
    /// unreadable, or finished though still in a queue — passed over by
    /// every scan after; one that failed is passed over by its place's mark
    /// in the Ledger instead (`persist::storage::Held::failed`). A Retry
    /// moves a Message to a new place, where it is read again. By queue, so
    /// a whole read of one forgets what has left it.
    passed: HashMap<u128, HashSet<(JourneyId, u64)>>,
    /// The Send Ports this node sends, each with whether a Message of it
    /// that failed blocks its sequence: what an operator's act on one of
    /// its Messages is decided by.
    ports: BTreeMap<String, bool>,
    /// Queues to read now, beside the scan of them all.
    asked: Vec<u128>,
    /// Queues another node's write moved, to read now: what is due in each,
    /// as the wake brought it where it did, never its failed Messages,
    /// which no such write moves (`crate::queue_watch`).
    woken: Vec<(u128, Woken)>,
    /// By Send Port, what its latest sends took, step by step.
    timed: BTreeMap<String, steps::Kept>,
    /// How many scans of every queue it made.
    scans: u64,
    figures: BTreeMap<String, PortFigures>,
    /// By Send Port, how many failed Messages wait in its queue and the
    /// oldest of them, at most its `window`: read from the queue's
    /// index of them in the Ledger, so the evidence outlives a restart,
    /// covers what another node failed, and is bounded however many fail.
    failing: BTreeMap<String, figures::Window>,
    /// Every queue to read now: a Stream ahead in a sequence has ended, so
    /// what waited behind it may go on (`crate::sequence`).
    rescan: bool,
    /// The queues it sends from, read again on a rescan.
    served: Vec<u128>,
    closed: bool,
}

impl SendStep {
    /// The send step of the node at `node` (`xmip:///<cluster>/node/<name>`)
    /// in the cluster at `cluster` (`xmip:///<cluster>`), over `storage`,
    /// run as `tuning` says. `audit` records every Message that failed.
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
            share: StreamShare::new(Arc::clone(&storage), tuning.stream_stall),
            storage,
            lease: tuning.send_lease,
            scan: tuning.send_scan,
            window: tuning.failed_window,
            limits: tuning.send(),
            audit,
            state: Mutex::new(State::default()),
            wake: Wake::new(),
            // Its own: a Publication this node claims every Message of in
            // the same write does not wake it (`persist::storage::Waiter`).
            watch: QueueWatch::of(node),
        }
    }

    /// The queue in the Ledger the Messages bound for `to` wait in.
    #[must_use]
    pub fn queue(&self, to: &Subscriber) -> u128 {
        queue(&self.cluster, to)
    }

    /// How long a claim this node takes holds before it lapses.
    #[must_use]
    pub const fn lease(&self) -> Duration {
        self.lease
    }

    /// The Messages of the Journeys a Publication opens that go on to be
    /// sent — each with
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
                    fence: 0,
                };
                lined.claims.push(claim.clone());
                lined.claimed.push((journey, (*to).clone(), queue, claim));
            }
        }
        lined
    }

    /// What `lined` claimed in its Publication, handed to the Send pool:
    /// each of `journeys` it claimed, with `work`'s Message and the
    /// identity it arrived with, `facts`, each in the place admitted for
    /// it, and let out to its far end once `durable` says the Publication
    /// is; the Message's time goes with each, the account the calling
    /// thread works for (`xcore::spent::current`). A queue holding a Message this node sends and did not claim is
    /// read at once, or once a place frees.
    pub fn handed(
        &self,
        lined: LinedUp,
        journeys: &[Journey],
        work: &ReceivedWork,
        facts: &IdentityFacts,
        durable: &Durable,
    ) {
        let until = lined.asked.unwrap_or_else(Instant::now) + self.lease;
        // The Message's account, which the carrying thread works for.
        let spent = xcore::spent::current();
        let mut state = self.lock();
        state.admitted = state.admitted.saturating_sub(lined.admitted);
        for (id, to, queue, claim) in lined.claimed {
            let Some(journey) = journeys.iter().find(|j| j.journey_id() == id) else {
                continue;
            };
            let mut departure = Departure {
                work: ReceivedWork {
                    journey: journey.clone(),
                    message: work.message.clone(),
                },
                facts: facts.clone(),
                to,
                queue,
                claim,
                progress: Progress::of(journey.attempts),
                until,
                durable: Some(durable.clone()),
                handed: true,
                spent: spent.clone(),
                measured: None,
                steps: Steps::default(),
            };
            departure.steps.ready();
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
    pub fn hand(&self, mut departure: Departure) {
        self.own(departure.work.journey.journey_id(), Owned::of(&departure));
        departure.steps.ready();
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

    /// Read what is due in `queue` now, starting from what `woken` brought
    /// of it: a write, on any node, put a Message in it, or moved what a
    /// Message it passed over waits on (`crate::queue_watch`). Woken again
    /// before it is read, what the latest wake brought is read, since the
    /// earliest wake.
    pub(crate) fn woken(&self, queue: u128, woken: Woken) {
        let mut state = self.lock();
        match state.woken.iter_mut().find(|(kept, _)| *kept == queue) {
            Some((_, kept)) => kept.due = woken.due,
            None => state.woken.push((queue, woken)),
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Read every queue now: a Stream ahead in a sequence has ended.
    pub fn rescan(&self) {
        self.lock().rescan = true;
        self.wake.notify_all();
    }

    /// Stop taking work: what is handed is sent, once the step's
    /// dispatching ends. What waits for a retry holds no claim to give back
    /// (ADR-0018 clause 12): it waits in its queue, its due time there.
    pub fn close(&self) {
        self.lock().closed = true;
        self.watch.stop();
        self.wake.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.locked()
    }

    /// The Send Ports it sends, by name.
    #[must_use]
    pub fn ports(&self) -> Vec<String> {
        self.lock().ports.keys().cloned().collect()
    }

    /// The Streams its departures read now, each read once for every
    /// departure of it keeping up (`crate::stream_share`).
    #[must_use]
    pub const fn share(&self) -> &StreamShare {
        &self.share
    }

    /// The node it sends for: `xmip:///<cluster>/node/<name>`.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }
}

/// Whether what is bound for `to` passes its Send Port in a sequence: a
/// Send Port naming a Correlation, or a Group with one among its Ports.
pub(crate) fn sequential(sends: &Sends, to: &Subscriber) -> bool {
    match sends.to(to) {
        Destination::Ports(ports) => ports.iter().any(|port| !port.points.is_empty()),
        Destination::Process | Destination::Nowhere => false,
    }
}
