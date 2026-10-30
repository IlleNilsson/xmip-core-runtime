//! What a node's send step counts per Send Port, the last Message that
//! failed there with its reason, and the Messages that failed waiting in
//! its queue for an operator: what its snapshot publishes at the Port's
//! scope (`crate::running::publication`), so every surface shows it.
//!
//! **Now, and what was.** `failing`, `oldest_failing` and `blocked` are the
//! queue as it stands, as Xmip Storage keeps it: the count and the oldest
//! of the queue's index of failed Messages in the Ledger, written with each
//! failure and each act on one, whichever node failed it
//! (`persist::storage::FailedQueue`); `sent`, `failed` and `last_failure`
//! are history since the node started. Until 2026-10-06 `last_failure` was
//! filled from the queue where the node had seen none fail, so history and
//! now were one figure.
//!
//! **The node keeps a window, not the backlog.** Of each Port's index it
//! keeps how many wait and the oldest `[tuning] failed_window` of them, read
//! again only where the index's places moved since the last read; the rest
//! are read from Xmip Storage a page at a time ([`SendStep::failed_messages`]).
//! Until 2026-10-16 the node kept every one a scan had read Failed, so its
//! memory grew with the failures (open problem 34).

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use observe::{FailedMessages, LastFailure};
use persist::storage::Failed;
use xcore::{Clock, JourneyId, SystemClock};

use super::SendStep;

/// The oldest failed Messages of one Send Port the node keeps and its
/// publication carries, where `[tuning] failed_window` does not say: a
/// hundred; the rest are read from Xmip Storage a page at a time
/// ([`super::SendStep::failed_messages`]).
pub const FAILED_WINDOW: usize = 100;

/// One Send Port's figures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortFigures {
    /// Messages sent since the node started: written Completed.
    pub sent: u64,
    /// Messages whose every Send Location failed its tries since the node
    /// started: written Failed.
    pub failed: u64,
    /// Messages waiting now for a retry's due time, as the last read of its
    /// queue found them in the Ledger, whichever node they wait for.
    pub waiting: u64,
    /// The last that failed here since the node started: its Journey and
    /// why, in words. History: it may since have been retried or dismissed.
    pub last_failure: Option<(String, String)>,
    /// How many Messages that failed wait in its queue for an operator now,
    /// as Xmip Storage counts them — those that failed before a restart, or
    /// on another node, among them.
    pub failing: u64,
    /// Whether one of them blocks its sequence now: a Sequential Send Port
    /// whose `on_failure` is `block`.
    pub blocked: bool,
    /// The oldest of them, at most `[tuning] failed_window`.
    pub oldest_failing: Vec<FailedMessage>,
    /// Claims of its Journeys this node holds whose renewal Xmip Storage
    /// has not answered, now: the Port is Done while any is.
    pub unconfirmed: u64,
    /// When the oldest of those renewals was asked, in nanoseconds since
    /// the Unix epoch: since when Xmip Storage has not answered.
    pub unanswered_since: Option<i128>,
    /// Journeys whose claim this node found another's, or presumed lapsed,
    /// since it started, and let go of without sending them further.
    pub lost: u64,
    /// Since when, in nanoseconds since the Unix epoch, Xmip Storage has
    /// not answered a read of its queue, and its last answer, in words: the
    /// Port is Done while it has not, since what waits in its queue cannot
    /// be found. Gone at the first read answered.
    pub unread: Option<(i128, String)>,
}

/// A Message that failed, waiting in its Send Port's queue for an
/// operator's Retry or Dismiss.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedMessage {
    pub journey: JourneyId,
    /// Its place in its Send Port's queue: oldest lowest.
    pub place: u64,
    /// Why it failed, as its last entry says.
    pub reason: String,
}

impl PortFigures {
    /// The Port's state in one line, as its snapshot says it.
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut said = format!(
            "sent {}, failed {}, waiting {}, failed in its queue {}",
            self.sent, self.failed, self.waiting, self.failing
        );
        if self.blocked {
            said.push_str(", its sequence blocked behind them");
        }
        if self.unconfirmed > 0 {
            said.push_str(&format!(
                ", Xmip Storage has not answered the renewal of its claims {}",
                self.unconfirmed
            ));
            if let Some(since) = self.unanswered_since {
                said.push_str(&format!(" since {}", codec::civil::rfc3339_nanos(since)));
            }
        }
        if let Some((since, why)) = &self.unread {
            said.push_str(&format!(
                ", Xmip Storage has not answered a read of its queue since {} ({why})",
                codec::civil::rfc3339_nanos(*since)
            ));
        }
        if self.lost > 0 {
            said.push_str(&format!(", claims lost to another holder {}", self.lost));
        }
        if let Some((journey, why)) = &self.last_failure {
            said.push_str(&format!(
                "; the Message of the Journey {journey} failed: {why}"
            ));
        }
        said
    }

    /// The last Message that failed here since the node started, as every
    /// publication of it says it: history, apart from what fails now.
    #[must_use]
    pub fn last(&self) -> Option<LastFailure> {
        self.last_failure
            .as_ref()
            .map(|(journey, reason)| LastFailure {
                journey: journey.clone(),
                reason: reason.clone(),
            })
    }

    /// The Messages that failed at the Send Port `port` of the node at
    /// `node`, as its snapshot publishes them: how many wait in its queue
    /// now — zero where none, so a surface says *none now* from the record
    /// rather than from its absence — whether they block its sequence, the
    /// oldest with why, and apart from them the last that failed there since
    /// the node started, as history. Until 2026-10-06 only a Port with some
    /// waiting was published.
    #[must_use]
    pub fn published(&self, node: &str, port: &str) -> FailedMessages {
        FailedMessages {
            node: node.to_string(),
            send_port: port.to_string(),
            count: self.failing,
            blocked: self.blocked,
            messages: self
                .oldest_failing
                .iter()
                .map(FailedMessage::published)
                .collect(),
            last_failure: self.last(),
        }
    }
}

impl FailedMessage {
    /// The Message as its queue's index of failed Messages keeps it.
    #[must_use]
    pub fn of(failed: &Failed) -> Self {
        Self {
            journey: failed.journey,
            place: failed.place,
            reason: failed.reason.clone(),
        }
    }

    /// The Message as a publication, and every list of failed Messages,
    /// says it.
    #[must_use]
    pub fn published(&self) -> observe::FailedMessage {
        observe::FailedMessage {
            journey: self.journey.to_string(),
            sequence: self.place,
            reason: self.reason.clone(),
        }
    }
}

impl SendStep {
    /// The figures of every Send Port this node sends or has sent through.
    #[must_use]
    pub fn figures(&self) -> BTreeMap<String, PortFigures> {
        let state = self.lock();
        let mut figures = state.figures.clone();
        for port in state.ports.keys() {
            figures.entry(port.clone()).or_default();
        }
        for due in state.due.values() {
            figures.entry(due.port.clone()).or_default().waiting += due.waiting;
        }
        let (now, wall) = (Instant::now(), SystemClock.unix_timestamp_nanos());
        for owned in state.owned.values() {
            if let Some(asked) = owned.standing.unanswered_since() {
                let ago = i128::try_from(now.saturating_duration_since(asked).as_nanos());
                let since = wall - ago.unwrap_or(0);
                let figures = figures.entry(owned.port.clone()).or_default();
                figures.unconfirmed += 1;
                figures.unanswered_since =
                    Some(figures.unanswered_since.map_or(since, |was| was.min(since)));
            }
        }
        for (port, window) in &state.failing {
            let figures = figures.entry(port.clone()).or_default();
            figures.failing = window.count;
            figures.oldest_failing.clone_from(&window.oldest);
            figures.blocked = window.count > 0 && state.ports.get(port) == Some(&true);
        }
        figures
    }

    /// `port`'s window on its queue's index of failed Messages, `queue`,
    /// read again from Xmip Storage where the index moved since the last
    /// read — one read of its places where it did not — or, with `afresh`,
    /// whatever it last read. Where Xmip Storage does not answer, the last
    /// read stands: the read of the queue itself says it is unanswered.
    pub(crate) fn read_failed(&self, (port, queue): (&str, u128), afresh: bool) {
        let Ok(places) = self.storage.read_failed(queue, 0, 0) else {
            return;
        };
        let at = (places.next, places.count);
        let unchanged = |state: &super::State| {
            state
                .failing
                .get(port)
                .is_some_and(|w| w.read_at == Some(at))
        };
        if !afresh && unchanged(&self.lock()) {
            return;
        }
        let most = u32::try_from(self.window).unwrap_or(u32::MAX);
        let Ok(read) = self.storage.read_failed(queue, 0, most) else {
            return;
        };
        let window = Window {
            count: read.count,
            read_at: Some((read.next, read.count)),
            oldest: read.failed.iter().map(FailedMessage::of).collect(),
        };
        self.lock().failing.insert(port.to_string(), window);
    }

    /// A whole read of `queue` found only `present`, by Journey and place:
    /// every place passed over that is gone from it forgotten.
    pub(crate) fn read_whole(&self, queue: u128, present: &Present) {
        if let Some(passed) = self.lock().passed.get_mut(&queue) {
            passed.retain(|place| present.contains(place));
        }
    }

    /// `port`'s queue read, or, with why in words, not answered: kept as
    /// since when Xmip Storage has not answered, and audited the first time.
    pub(crate) fn queue_read(&self, port: &str, unanswered: Option<String>) {
        let mut state = self.lock();
        let figures = state.figures.entry(port.to_string()).or_default();
        let began = figures.unread.is_none();
        let since = figures.unread.as_ref().map(|(since, _)| *since);
        figures.unread = unanswered.map(|why| {
            let since = since.unwrap_or_else(|| SystemClock.unix_timestamp_nanos());
            (since, why)
        });
        let said = figures.unread.clone().filter(|_| began);
        drop(state);
        if let Some((_, why)) = said {
            self.failed(&format!(
                "Xmip Storage did not answer a read of the queue of {port}, so what waits \
                 in it is not found: {why}"
            ));
        }
    }
}

/// Journeys by their place in a queue.
pub(super) type Present = HashSet<(JourneyId, u64)>;

/// What the node keeps of one Send Port's queue's index of failed Messages:
/// how many wait and the oldest, at most its window, as Xmip Storage last
/// answered — however many failed, never more.
#[derive(Debug, Default)]
pub(super) struct Window {
    count: u64,
    /// The index's next place and count as that answer had them: while they
    /// stand, nothing failed there or left it since.
    read_at: Option<(u64, u64)>,
    oldest: Vec<FailedMessage>,
}
