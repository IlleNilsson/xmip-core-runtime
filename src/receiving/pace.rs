//! How long a Receive Location rests before it asks its transport again:
//! not at all after a receive that handed something over, or one whose own
//! wait paces it; its poll interval after a polled receive that found
//! nothing — its sweep, where its far end tells it of a change and the rest
//! ends at that word (`transport::Notice`); its backoff after a polled
//! receive that failed in a way asking again may mend (`runtime-model.md`
//! section 5, *How a receive runs*).
//! Both are measured from when the receive began, so a receive that took
//! its time is not made to wait it twice. The rest is waited on the node's
//! stop ([`crate::stopping::Stopping::wait`]), which a stop ends at once.

use std::time::Duration;

use super::drain::RECEIVE_DRAIN;

/// How long a polled Receive Location rests after a receive that found
/// nothing, where the node's `[tuning] receive_poll` does not say: a second
/// — the assistant's drafting, 2026-10-12, for the owner to overrule.
pub const RECEIVE_POLL: Duration = Duration::from_secs(1);

/// How long a polled Receive Location whose far end tells it of a change
/// rests after a receive that found nothing, where no word comes and the
/// node's `[tuning] receive_sweep` does not say: a second — a recovery
/// sweep, for what lay there before the watch began or a word missed; the
/// assistant's drafting, 2026-10-20, for the owner to overrule.
pub const RECEIVE_SWEEP: Duration = Duration::from_secs(1);

/// How long a polled Receive Location rests after a receive that failed in
/// a way asking again may mend, where the node's `[tuning] receive_backoff`
/// does not say: five seconds, as a Send Port's retry is written in
/// `runtime-model.md` section 20 — the assistant's drafting, 2026-10-12,
/// for the owner to overrule.
pub const RECEIVE_BACKOFF: Duration = Duration::from_secs(5);

/// A Receive Location's rests, and how long it drains once its node stops,
/// from the node's `[tuning]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pace {
    /// After a polled receive that found nothing.
    pub poll: Duration,
    /// After a polled receive that found nothing, where the far end tells
    /// of a change: ended at once by that word.
    pub sweep: Duration,
    /// After a polled receive that failed in a way asking again may mend.
    pub backoff: Duration,
    /// How long, from the stop, a Location goes on taking what its far end
    /// already let go of (`drain.rs`).
    pub drain: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            poll: RECEIVE_POLL,
            sweep: RECEIVE_SWEEP,
            backoff: RECEIVE_BACKOFF,
            drain: RECEIVE_DRAIN,
        }
    }
}

/// How a Location's transport is asked again: its receive waits by itself,
/// it is polled, or it is polled and its far end tells of a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asking {
    Waits,
    Polled,
    Told,
}

/// How one receive ended, as its rest reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It handed over at least one arrival.
    Found,
    /// It found nothing.
    Nothing,
    /// It failed in a way asking again may mend.
    Mendable,
}

impl Pace {
    /// The rest before the next receive, after one that `ended` so and
    /// `took` that long, on a transport asked as `asking` says
    /// (`transport::Waiting`, `transport::Notice`).
    ///
    /// A waiting receive is asked again at once whichever way it ended: its
    /// own wait paces it, and its wait running out is told as a failure
    /// asking again may mend, which a rest would only make an arrival wait
    /// behind.
    #[must_use]
    pub fn rest(self, asking: Asking, ended: Ended, took: Duration) -> Duration {
        let interval = match (ended, asking) {
            (Ended::Found, _) | (_, Asking::Waits) => return Duration::ZERO,
            (Ended::Nothing, Asking::Polled) => self.poll,
            (Ended::Nothing, Asking::Told) => self.sweep,
            (Ended::Mendable, _) => self.backoff,
        };
        interval.saturating_sub(took)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACE: Pace = Pace {
        poll: Duration::from_millis(200),
        sweep: Duration::from_secs(2),
        backoff: Duration::from_secs(3),
        drain: Duration::from_millis(500),
    };

    #[test]
    fn a_polled_receive_that_found_nothing_rests_its_poll_less_what_it_took() {
        assert_eq!(
            PACE.rest(Asking::Polled, Ended::Nothing, Duration::ZERO),
            PACE.poll
        );
        assert_eq!(
            PACE.rest(Asking::Polled, Ended::Nothing, Duration::from_millis(50)),
            Duration::from_millis(150)
        );
        assert_eq!(
            PACE.rest(Asking::Polled, Ended::Nothing, Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    #[test]
    fn a_polled_receive_that_failed_and_may_mend_backs_off() {
        assert_eq!(
            PACE.rest(Asking::Polled, Ended::Mendable, Duration::ZERO),
            PACE.backoff
        );
        assert_eq!(
            PACE.rest(Asking::Polled, Ended::Mendable, Duration::from_secs(1)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn what_found_something_or_waits_by_itself_is_asked_again_at_once() {
        for ended in [Ended::Found, Ended::Nothing, Ended::Mendable] {
            assert_eq!(
                PACE.rest(Asking::Waits, ended, Duration::ZERO),
                Duration::ZERO
            );
        }
        assert_eq!(
            PACE.rest(Asking::Polled, Ended::Found, Duration::ZERO),
            Duration::ZERO
        );
    }

    #[test]
    fn a_told_receive_that_found_nothing_rests_its_sweep() {
        assert_eq!(
            PACE.rest(Asking::Told, Ended::Nothing, Duration::from_millis(500)),
            Duration::from_millis(1500)
        );
        assert_eq!(
            PACE.rest(Asking::Told, Ended::Mendable, Duration::ZERO),
            PACE.backoff
        );
        assert_eq!(
            PACE.rest(Asking::Told, Ended::Found, Duration::ZERO),
            Duration::ZERO
        );
    }

    #[test]
    fn the_defaults_are_the_constants() {
        assert_eq!(
            Pace::default(),
            Pace {
                poll: RECEIVE_POLL,
                sweep: RECEIVE_SWEEP,
                backoff: RECEIVE_BACKOFF,
                drain: RECEIVE_DRAIN,
            }
        );
    }
}
