//! What a surface over a node's operate listener shares between the
//! calls made on it and its follow: how it reaches the node and how long a
//! call waits on it, what the follow has told, whether it is ending, and
//! what ends a read either of its lines waits in.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use xcore::wake::Wake;

use crate::plane::deadline::Deadline;
use crate::plane::line::{Ending, Reach};
use crate::plane::local::Cancel;
use crate::plane::remote::State;

pub(crate) struct Shared {
    /// What the node is called in what a surface says: its operate
    /// address, or its local endpoint's path.
    pub(crate) address: String,
    pub(crate) reach: Reach,
    /// How long a connect, a handshake or an answer to a call waits.
    pub(crate) patience: Duration,
    /// The deadline of a call on a line that keeps no time itself.
    pub(crate) deadline: Deadline,
    pub(crate) retry: Vec<Duration>,
    pub(crate) state: Mutex<State>,
    pub(crate) told: Wake,
    pub(crate) ending: Arc<AtomicBool>,
    /// In a connect, which nothing cuts short.
    pub(crate) connecting: AtomicBool,
    /// What ends a read the follow's line, or the asking line, waits in,
    /// where the line has no timeout to look between.
    pub(crate) following: Mutex<Option<Cancel>>,
    pub(crate) asking: Mutex<Option<Cancel>>,
}

impl Shared {
    /// Tell every follower `change`.
    pub(crate) fn tell(&self, change: impl FnOnce(&mut State)) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        change(&mut state);
        state.told += 1;
        self.told.notify_all();
    }

    pub(crate) fn ending(&self) -> bool {
        self.ending.load(Ordering::SeqCst)
    }

    /// What a line of this surface asks whether it ends by.
    pub(crate) fn ended(&self) -> Ending {
        let ending = Arc::clone(&self.ending);
        Box::new(move || ending.load(Ordering::SeqCst))
    }

    /// Cancel a read the asking line waits in.
    pub(crate) fn cancel_asking(&self) {
        if let Some(cancel) = &*self.asking.lock().unwrap_or_else(PoisonError::into_inner) {
            cancel.cancel();
        }
    }

    /// Cancel a read either line waits in.
    pub(crate) fn cancel(&self) {
        for slot in [&self.following, &self.asking] {
            if let Some(cancel) = &*slot.lock().unwrap_or_else(PoisonError::into_inner) {
                cancel.cancel();
            }
        }
    }
}
