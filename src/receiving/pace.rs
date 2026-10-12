//! How long a Receive Location rests before it asks its transport again:
//! not at all after a receive that handed something over, or one whose own
//! wait paces it; its poll interval after a polled receive that found
//! nothing; its backoff after a polled receive that failed in a way asking
//! again may mend (`runtime-model.md` section 5, *How a receive runs*).
//! Both are measured from when the receive began, so a receive that took
//! its time is not made to wait it twice. The rest is waited on the node's
//! stop ([`crate::stopping::Stopping::wait`]), which a stop ends at once.

use std::time::Duration;

/// How long a polled Receive Location rests after a receive that found
/// nothing, where the node's `[tuning] receive_poll` does not say: a second
/// — the assistant's drafting, 2026-10-12, for the owner to overrule.
pub const RECEIVE_POLL: Duration = Duration::from_secs(1);

/// How long a polled Receive Location rests after a receive that failed in
/// a way asking again may mend, where the node's `[tuning] receive_backoff`
/// does not say: five seconds, as a Send Port's retry is written in
/// `runtime-model.md` section 20 — the assistant's drafting, 2026-10-12,
/// for the owner to overrule.
pub const RECEIVE_BACKOFF: Duration = Duration::from_secs(5);

/// A Receive Location's rests, from the node's `[tuning]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pace {
    /// After a polled receive that found nothing.
    pub poll: Duration,
    /// After a polled receive that failed in a way asking again may mend.
    pub backoff: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            poll: RECEIVE_POLL,
            backoff: RECEIVE_BACKOFF,
        }
    }
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
    /// `took` that long, on a transport whose receive is `polled` or waits
    /// (`transport::Waiting`).
    ///
    /// A waiting receive is asked again at once whichever way it ended: its
    /// own wait paces it, and its wait running out is told as a failure
    /// asking again may mend, which a rest would only make an arrival wait
    /// behind.
    #[must_use]
    pub fn rest(self, polled: bool, ended: Ended, took: Duration) -> Duration {
        let interval = match ended {
            Ended::Found => return Duration::ZERO,
            _ if !polled => return Duration::ZERO,
            Ended::Nothing => self.poll,
            Ended::Mendable => self.backoff,
        };
        interval.saturating_sub(took)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACE: Pace = Pace {
        poll: Duration::from_millis(200),
        backoff: Duration::from_secs(3),
    };

    #[test]
    fn a_polled_receive_that_found_nothing_rests_its_poll_less_what_it_took() {
        assert_eq!(PACE.rest(true, Ended::Nothing, Duration::ZERO), PACE.poll);
        assert_eq!(
            PACE.rest(true, Ended::Nothing, Duration::from_millis(50)),
            Duration::from_millis(150)
        );
        assert_eq!(
            PACE.rest(true, Ended::Nothing, Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    #[test]
    fn a_polled_receive_that_failed_and_may_mend_backs_off() {
        assert_eq!(
            PACE.rest(true, Ended::Mendable, Duration::ZERO),
            PACE.backoff
        );
        assert_eq!(
            PACE.rest(true, Ended::Mendable, Duration::from_secs(1)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn what_found_something_or_waits_by_itself_is_asked_again_at_once() {
        for ended in [Ended::Found, Ended::Nothing, Ended::Mendable] {
            assert_eq!(PACE.rest(false, ended, Duration::ZERO), Duration::ZERO);
        }
        assert_eq!(
            PACE.rest(true, Ended::Found, Duration::ZERO),
            Duration::ZERO
        );
    }

    #[test]
    fn the_defaults_are_the_constants() {
        assert_eq!(
            Pace::default(),
            Pace {
                poll: RECEIVE_POLL,
                backoff: RECEIVE_BACKOFF
            }
        );
    }
}
