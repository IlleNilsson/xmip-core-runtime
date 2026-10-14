//! A Receive Location's drain once its node's stop is raised (ADR-0018
//! clause 12; `runtime-model.md` section 5, *How a receive runs*).
//!
//! A far end that keeps what it hands over until it is told — a file left
//! in its directory, a message leased, a caller waiting for its answer —
//! loses nothing when the Location stops taking: it is sent again. One
//! that let go of it already loses it. Raw TCP's sender is done once its
//! kernel took the bytes (`xmip-core-transport-tcp`'s `AT_MOST_ONCE`), and
//! a connection the operating system completed and queued in the
//! listener's backlog before the stop is a Stream the sender was told went
//! through; so is a datagram in a socket's buffer. Until 2026-10-15 a
//! Location took nothing more once the stop was raised, the listener was
//! closed with its backlog in it, and those Streams were lost.
//!
//! So a Location whose receive waits for what arrives
//! (`transport::Waiting::Waits`), and whose far end has let go of what it
//! handed over (`transport::Acknowledgement::at_most_once`), goes on
//! receiving after the stop until a receive finds nothing — which its own
//! wait bounds, as it bounds every receive — and never past `[tuning]
//! receive_drain` from the stop, so senders that never pause cannot hold
//! the stop. A polled Location's far end keeps what it holds, and a
//! Location whose far end is told is stopped as before: it loses nothing.

use std::time::{Duration, Instant};

use crate::stopping::Stopping;

use super::pace::Ended;

/// How long a stopping Receive Location goes on taking what its far end
/// already let go of, where the node's `[tuning] receive_drain` does not
/// say: a second — the assistant's drafting, 2026-10-15, for the owner to
/// overrule. It bounds senders that never pause; a backlog is taken in
/// milliseconds.
pub const RECEIVE_DRAIN: Duration = Duration::from_secs(1);

/// One Location's drain: whether it is one that drains, and once the stop
/// is raised, until when and whether a receive has found nothing.
pub(super) struct Drain {
    /// The receive waits for what arrives: a polled far end keeps it.
    waits: bool,
    /// The far end of an arrival handed over let go of it.
    let_go: bool,
    /// `[tuning] receive_drain`.
    bound: Duration,
    /// When the drain ends at the latest, from the first receive asked
    /// after the stop.
    until: Option<Instant>,
    /// A receive asked after the stop found nothing, or failed.
    quiet: bool,
}

impl Drain {
    /// The drain of a Location whose receive `waits`, bounded by `bound`.
    pub(super) const fn new(waits: bool, bound: Duration) -> Self {
        Self {
            waits,
            let_go: false,
            bound,
            until: None,
            quiet: false,
        }
    }

    /// Whether the Location asks its transport again: always until the
    /// stop is raised; after it, while it drains.
    pub(super) fn asks(&mut self, stopping: &Stopping) -> bool {
        if !stopping.raised() {
            return true;
        }
        if !self.waits || !self.let_go || self.quiet {
            return false;
        }
        let until = *self
            .until
            .get_or_insert_with(|| Instant::now() + self.bound);
        Instant::now() < until
    }

    /// A receive handed over `arrivals`, `let_go` where any's far end let
    /// go of it.
    pub(super) const fn handed(&mut self, let_go: bool) {
        self.let_go |= let_go;
    }

    /// A receive ended as `ended`: one asked after the stop that found
    /// nothing, or failed, ends the drain.
    pub(super) fn received(&mut self, ended: Ended) {
        if self.until.is_some() && ended != Ended::Found {
            self.quiet = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stopped() -> Stopping {
        let stopping = Stopping::default();
        stopping.raise();
        stopping
    }

    #[test]
    fn until_the_stop_every_location_asks() {
        let mut drain = Drain::new(false, RECEIVE_DRAIN);
        assert!(drain.asks(&Stopping::default()));
    }

    #[test]
    fn after_the_stop_only_a_waiting_location_whose_far_end_let_go_drains() {
        let stopping = stopped();
        assert!(!Drain::new(false, RECEIVE_DRAIN).asks(&stopping), "polled");
        assert!(!Drain::new(true, RECEIVE_DRAIN).asks(&stopping), "told");
        let mut polled = Drain::new(false, RECEIVE_DRAIN);
        polled.handed(true);
        assert!(!polled.asks(&stopping));
        let mut drain = Drain::new(true, RECEIVE_DRAIN);
        drain.handed(false);
        assert!(!drain.asks(&stopping), "a far end that is told keeps it");
        drain.handed(true);
        assert!(drain.asks(&stopping));
    }

    #[test]
    fn a_drain_ends_at_the_first_receive_that_finds_nothing() {
        let stopping = stopped();
        for ended in [Ended::Nothing, Ended::Mendable] {
            let mut drain = Drain::new(true, RECEIVE_DRAIN);
            drain.handed(true);
            assert!(drain.asks(&stopping));
            drain.received(Ended::Found);
            assert!(drain.asks(&stopping));
            drain.received(ended);
            assert!(!drain.asks(&stopping), "{ended:?}");
        }
    }

    #[test]
    fn what_a_receive_under_way_at_the_stop_found_does_not_end_the_drain() {
        let mut drain = Drain::new(true, RECEIVE_DRAIN);
        drain.handed(true);
        drain.received(Ended::Nothing);
        assert!(drain.asks(&stopped()), "the backlog may have filled since");
    }

    #[test]
    fn a_drain_ends_at_its_bound_whatever_keeps_arriving() {
        let stopping = stopped();
        let mut drain = Drain::new(true, Duration::from_millis(1));
        drain.handed(true);
        assert!(drain.asks(&stopping));
        let began = Instant::now();
        while drain.asks(&stopping) {
            drain.received(Ended::Found);
        }
        assert!(began.elapsed() < Duration::from_secs(1));
    }
}
