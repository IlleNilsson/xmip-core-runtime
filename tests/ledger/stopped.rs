//! A Receive Location a test serves, its stop raised however the test ends,
//! so a wait that never came fails as a panic rather than waits for good on
//! a Location that serves on (found 2026-11-15: a test whose wait panicked
//! past its patience on a loaded machine then waited on Locations it never
//! stopped, and the test that started it waited on it, two and a half
//! hours).

use xmip_core_runtime::message_path::{Carried, Runtime};
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::receiving::Receiving;
use xmip_core_runtime::stopping::Stopping;

use super::sending::until;

/// A Location's stop, raised when this is dropped, however the test got
/// there; dropped by a panic, it says first what `left` says was left.
pub(super) struct Stop<'a> {
    stopping: &'a Stopping,
    left: Option<&'a dyn Fn() -> String>,
}

impl<'a> Stop<'a> {
    /// `stopping`, raised once this is dropped.
    pub(super) const fn of(stopping: &'a Stopping) -> Self {
        Self {
            stopping,
            left: None,
        }
    }

    /// `stopping`, raised once this is dropped, saying what `left` says
    /// where a panic dropped it.
    pub(super) const fn saying(stopping: &'a Stopping, left: &'a dyn Fn() -> String) -> Self {
        Self {
            stopping,
            left: Some(left),
        }
    }
}

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(left) = self.left
        {
            eprintln!("never done: {}", left());
        }
        self.stopping.raise();
    }
}

/// `location` served on `runtime` until its stop is raised — by what it
/// carried, each told to `each`, or by its far end — or its serve ends by
/// itself, waited for within the test's patience, the stop raised however
/// that wait ended: how its serve ended.
pub(super) fn until_stopped(
    location: &Receiving,
    (runtime, pickup): (&Runtime<'_>, &Pickup),
    stopping: &Stopping,
    each: impl FnMut(&Carried) + Send,
) -> Result<(), String> {
    std::thread::scope(|scope| {
        let serving = scope.spawn(|| {
            std::thread::scope(|pool| location.serve(pool, runtime, pickup, stopping, each))
        });
        let stop = Stop::of(stopping);
        until(
            || stopping.raised() || serving.is_finished(),
            "the Location's stop",
        );
        drop(stop);
        serving.join().expect("the Location serves")
    })
}
