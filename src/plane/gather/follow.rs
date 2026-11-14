//! What a gatherer follows one member's publication through, a seam: a
//! surface over the member's operate listener ([`Remote`]), or, for the
//! gathering node itself, its own publication in process ([`own`], over its
//! `Published`), since a node's service account holds no role on its own
//! listener. Either tells as the publication changes and is read then,
//! never asked again and again.

use std::time::Duration;

#[cfg(feature = "node")]
use std::sync::Arc;

#[cfg(feature = "node")]
use crate::plane::board::Published;
use crate::plane::remote::Remote;

/// One member's publication, as a gatherer follows it.
pub trait Follow: Send + Sync {
    /// The publication now, the text its file holds, or why it did not
    /// answer.
    ///
    /// # Errors
    ///
    /// Why the member did not answer, in its surface's words.
    fn publication(&self) -> Result<String, String>;

    /// How many changes it has told of so far.
    fn told(&self) -> u64;

    /// The count once it is past `seen`, or as soon as `stopped` says the
    /// follower stops, woken by [`Follow::wake`]: never by asking again.
    fn told_after(&self, seen: u64, stopped: &dyn Fn() -> bool) -> u64;

    /// Wake every wait, so each looks at what stops it.
    fn wake(&self);
}

/// A member on another machine or in another process, followed over its
/// operate listener: its follow tells each revision and each change of its
/// reach.
impl Follow for Remote {
    fn publication(&self) -> Result<String, String> {
        Remote::publication(self).map(|(_, text)| text)
    }

    fn told(&self) -> u64 {
        self.state().told
    }

    fn told_after(&self, seen: u64, stopped: &dyn Fn() -> bool) -> u64 {
        self.wait_unless(seen, Duration::MAX, stopped).told
    }

    fn wake(&self) {
        Remote::wake(self);
    }
}

/// The gathering node's own publication, `published`, followed in process
/// by its revision.
#[cfg(feature = "node")]
#[must_use]
pub fn own(published: Arc<dyn Published>) -> Arc<dyn Follow> {
    Arc::new(Own(published))
}

/// A node's own publication, as a gatherer follows it.
#[cfg(feature = "node")]
struct Own(Arc<dyn Published>);

#[cfg(feature = "node")]
impl Follow for Own {
    fn publication(&self) -> Result<String, String> {
        Ok(self.0.read().1)
    }

    fn told(&self) -> u64 {
        self.0.read().0
    }

    fn told_after(&self, seen: u64, stopped: &dyn Fn() -> bool) -> u64 {
        self.0.wait(seen, Duration::MAX, stopped)
    }

    fn wake(&self) {
        self.0.wake();
    }
}
