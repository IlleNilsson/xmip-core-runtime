//! A surface's waits on its node: told when the follow has told more, never
//! asking again and again, and — for a gatherer following the surface beside
//! its other callers (`plane::gather`) — ended by what stops the one
//! waiting, woken without ending the surface.

use std::time::Duration;

use xcore::lock::Locked;

use super::{Remote, State};

impl Remote {
    /// The state once a follower has been told more than `seen` times, or
    /// after `within`: the follow starts with the first wait and runs while
    /// this lives.
    #[must_use]
    pub fn wait(&self, seen: u64, within: Duration) -> State {
        self.wait_unless(seen, within, &|| false)
    }

    /// The same, or as soon as `stopped` says the one waiting stops, woken
    /// by [`Remote::wake`].
    pub(crate) fn wait_unless(
        &self,
        seen: u64,
        within: Duration,
        stopped: &dyn Fn() -> bool,
    ) -> State {
        self.followed();
        let state = self.shared.state.locked();
        self.shared
            .told
            .wait_timeout_while(&self.shared.state, state, within, |state| {
                state.told <= seen && !self.shared.ending() && !stopped()
            })
            .0
            .clone()
    }

    /// Wake every wait, so it looks at what stops it, with nothing told and
    /// the surface not ended.
    pub(crate) fn wake(&self) {
        let _state = self.shared.state.locked();
        self.shared.told.notify_all();
    }
}
