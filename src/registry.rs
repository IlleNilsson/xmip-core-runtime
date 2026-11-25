//! What this process holds of each node it runs — its pickup, its send
//! step, its Work Process step — registered, so the runtime's library and
//! an operator's act find each by its node (`crate::applied`;
//! `xmip_operate.h` sections 14 to 16 and 29). One registry, placed once:
//! each kind keeps a static of its own.

use std::sync::{Arc, Mutex, Weak};

use xcore::lock::Locked;

/// The registered of one kind, held weakly: one dropped is gone from it.
pub(crate) struct Registry<T> {
    held: Mutex<Vec<Weak<T>>>,
}

impl<T> Registry<T> {
    /// None registered yet.
    pub(crate) const fn new() -> Self {
        Self {
            held: Mutex::new(Vec::new()),
        }
    }

    /// `one` registered, those dropped since let go of.
    pub(crate) fn register(&self, one: &Arc<T>) {
        let mut held = self.held.locked();
        held.retain(|kept| kept.strong_count() > 0);
        held.push(Arc::downgrade(one));
    }

    /// Every one registered and still held.
    pub(crate) fn all(&self) -> Vec<Arc<T>> {
        self.held
            .locked()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
}
