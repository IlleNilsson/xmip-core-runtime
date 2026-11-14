//! What a surface over a node's operate listener shares between the
//! calls made on it and its follow: how it reaches the node and how long a
//! call waits on it, what the follow has told, whether it is ending, and
//! what ends a read either of its lines waits in.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use xcore::lock::Locked;

use xcore::wake::Wake;

use crate::plane::deadline::Deadline;
use crate::plane::line::{Ending, Line, Reach};
use crate::plane::local::Cancel;
use crate::plane::remote::{Follows, State};

pub(crate) struct Shared {
    /// What the node is called in what a surface says: its operate
    /// address, or its local endpoint's path.
    pub(crate) address: String,
    pub(crate) reach: Reach,
    /// How long a connect, a handshake or an answer to a call waits.
    pub(crate) patience: Duration,
    /// The deadline of a call on a line that keeps no time itself.
    pub(crate) deadline: Deadline,
    /// The deadline of the follow's try — its connect, its handshake and
    /// the node's first answer — on a line that keeps no time itself: the
    /// same wait every call on the surface has.
    pub(crate) trying: Deadline,
    pub(crate) retry: Vec<Duration>,
    pub(crate) state: Mutex<State>,
    pub(crate) told: Wake,
    pub(crate) ending: Arc<AtomicBool>,
    /// In a connect, which nothing cuts short.
    pub(crate) connecting: AtomicBool,
    /// What ends a read the follow's line, or the asking line, waits in,
    /// where the line has no timeout to look between.
    pub(crate) following: Mutex<Option<Cancel>>,
    /// Which publication the follow asks the node for, named by the first
    /// wait that names one (`remote::cluster`); the node's own until then.
    pub(crate) follows: std::sync::OnceLock<Follows>,
    pub(crate) asking: Mutex<Option<Cancel>>,
    /// The asking line itself, held between calls: on what is shared, so
    /// a caller a host lets go is told to the node on it (`remote::relayed`)
    /// without the surface.
    pub(crate) line: Mutex<Option<Line>>,
    /// The node's nonces kept to bind a browser's handshake to
    /// (`remote::fresh`).
    #[cfg(feature = "node")]
    pub(crate) fresh: Mutex<crate::plane::remote::fresh::Pool>,
}

impl Shared {
    /// Tell every follower `change`.
    pub(crate) fn tell(&self, change: impl FnOnce(&mut State)) {
        let mut state = self.state.locked();
        change(&mut state);
        state.told += 1;
        self.told.notify_all();
    }

    pub(crate) fn ending(&self) -> bool {
        self.ending.load(Ordering::SeqCst)
    }

    /// Which publication the follow asks for now.
    pub(crate) fn follows(&self) -> Follows {
        self.follows.get().copied().unwrap_or_default()
    }

    /// What a line of this surface asks whether it ends by.
    pub(crate) fn ended(&self) -> Ending {
        let ending = Arc::clone(&self.ending);
        Box::new(move || ending.load(Ordering::SeqCst))
    }

    /// Cancel a read the asking line waits in.
    pub(crate) fn cancel_asking(&self) {
        if let Some(cancel) = &*self.asking.locked() {
            cancel.cancel();
        }
    }

    /// Cancel a read the follow's line waits in.
    pub(crate) fn cancel_following(&self) {
        if let Some(cancel) = &*self.following.locked() {
            cancel.cancel();
        }
    }

    /// Cancel a read either line waits in.
    pub(crate) fn cancel(&self) {
        for slot in [&self.following, &self.asking] {
            if let Some(cancel) = &*slot.locked() {
                cancel.cancel();
            }
        }
    }
}
