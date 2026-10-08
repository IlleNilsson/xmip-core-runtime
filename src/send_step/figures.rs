//! What a node's send step counts per Send Port, the last Journey that
//! failed there with its reason, and every Journey that failed waiting in
//! its queue for an operator: what its snapshot publishes at the Port's
//! scope (`crate::running::publication`), so every surface shows it.
//!
//! **Now, and what was.** `failing`, `oldest_failing` and `blocked` are the
//! queue as it stands, from the Journeys a scan of the Ledger read Failed
//! in it; `sent`, `failed` and `last_failure` are history since the node
//! started. Until 2026-10-06 `last_failure` was filled from the queue where
//! the node had seen none fail, so history and now were one figure.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use observe::{FailedJourneys, LastFailure};
use xcore::{Clock, JourneyId, SystemClock};

use super::SendStep;

/// The most failed Journeys of one Send Port a publication carries, the
/// oldest first; the rest are read from Xmip Storage a page at a time
/// ([`super::SendStep::failed_journeys`]).
pub const PUBLISHED_FAILED: usize = 100;

/// One Send Port's figures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortFigures {
    /// Journeys sent since the node started: written Completed.
    pub sent: u64,
    /// Journeys whose every Send Location failed its tries since the node
    /// started: written Failed.
    pub failed: u64,
    /// Journeys waiting now for a retry's due time.
    pub waiting: u64,
    /// The last that failed here since the node started: its Journey and
    /// why, in words. History: it may since have been retried or dismissed.
    pub last_failure: Option<(String, String)>,
    /// How many Journeys that failed wait in its queue for an operator now,
    /// as the node's scans of the Ledger found them — those that failed
    /// before a restart, or on another node, among them.
    pub failing: u64,
    /// Whether one of them blocks its sequence now: a Sequential Send Port
    /// whose `on_failure` is `block`.
    pub blocked: bool,
    /// The oldest of them, at most [`PUBLISHED_FAILED`].
    pub oldest_failing: Vec<FailedJourney>,
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

/// A Journey that failed, waiting in its Send Port's queue for an
/// operator's Retry or Dismiss.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedJourney {
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
            said.push_str(&format!("; the Journey {journey} failed: {why}"));
        }
        said
    }

    /// The last Journey that failed here since the node started, as every
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

    /// The Journeys that failed at the Send Port `port` of the node at
    /// `node`, as its snapshot publishes them: how many wait in its queue
    /// now — zero where none, so a surface says *none now* from the record
    /// rather than from its absence — whether they block its sequence, the
    /// oldest with why, and apart from them the last that failed there since
    /// the node started, as history. Until 2026-10-06 only a Port with some
    /// waiting was published.
    #[must_use]
    pub fn published(&self, node: &str, port: &str) -> FailedJourneys {
        FailedJourneys {
            node: node.to_string(),
            send_port: port.to_string(),
            count: self.failing,
            blocked: self.blocked,
            journeys: self
                .oldest_failing
                .iter()
                .map(FailedJourney::published)
                .collect(),
            last_failure: self.last(),
        }
    }
}

impl FailedJourney {
    /// The Journey as a publication, and every list of failed Journeys,
    /// says it.
    #[must_use]
    pub fn published(&self) -> observe::FailedJourney {
        observe::FailedJourney {
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
        for (_, waiting) in &state.due {
            let port = waiting.to.name().to_string();
            figures.entry(port).or_default().waiting += 1;
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
        for (port, failing) in &state.failing {
            let figures = figures.entry(port.clone()).or_default();
            figures.failing = failing.len() as u64;
            figures.oldest_failing = failing
                .by_place
                .values()
                .take(PUBLISHED_FAILED)
                .cloned()
                .collect();
            figures.blocked = failing.len() > 0 && state.ports.get(port) == Some(&true);
        }
        figures
    }

    /// The Journey at `place` in `port`'s queue, read Failed with `reason`.
    pub(crate) fn found_failing(&self, port: &str, place: u64, journey: JourneyId, reason: String) {
        let mut state = self.lock();
        let failing = state.failing.entry(port.to_string()).or_default();
        failing.forget(journey);
        failing.place_of.insert(journey, place);
        failing.by_place.insert(
            place,
            FailedJourney {
                journey,
                place,
                reason,
            },
        );
    }

    /// The Journey `journey` of `port`'s queue, read and found not Failed:
    /// sent again, finished, or not readable.
    pub(crate) fn not_failing(&self, port: &str, journey: JourneyId) {
        if let Some(failing) = self.lock().failing.get_mut(port) {
            failing.forget(journey);
        }
    }

    /// A whole read of `port`'s queue, `queue`, found only `present`, by
    /// Journey and place: what failed there and is gone — dismissed, or sent
    /// again, by another node — forgotten, and every place passed over that
    /// is gone with it.
    pub(crate) fn read_whole(&self, (port, queue): (&str, u128), present: &Present) {
        let mut state = self.lock();
        if let Some(failing) = state.failing.get_mut(port) {
            failing
                .by_place
                .retain(|place, failed| present.contains(&(failed.journey, *place)));
            failing
                .place_of
                .retain(|journey, place| present.contains(&(*journey, *place)));
        }
        if let Some(passed) = state.passed.get_mut(&queue) {
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

/// Every Journey that failed waiting in one Send Port's queue: by its place,
/// oldest first, and the place of each by its Journey, so a Journey read
/// again is found at once however long the backlog.
#[derive(Debug, Default)]
pub(super) struct Failing {
    by_place: BTreeMap<u64, FailedJourney>,
    place_of: HashMap<JourneyId, u64>,
}

impl Failing {
    /// How many wait.
    pub(super) fn len(&self) -> usize {
        self.by_place.len()
    }

    fn forget(&mut self, journey: JourneyId) {
        if let Some(place) = self.place_of.remove(&journey) {
            self.by_place.remove(&place);
        }
    }
}
