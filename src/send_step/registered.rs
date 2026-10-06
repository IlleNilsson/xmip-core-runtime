//! Every node's send step this process holds, registered, so the runtime's
//! library finds one by its node and acts on its Journeys (`xmip_operate.h`
//! section 16).

use std::sync::{Arc, Mutex, PoisonError, Weak};

use super::SendStep;

/// Every node's send step in this process, registered.
static REGISTERED: Mutex<Vec<Weak<SendStep>>> = Mutex::new(Vec::new());

impl SendStep {
    /// `step` registered, so the runtime's library finds it by its node
    /// and acts on its Journeys (`xmip_operate.h` section 16).
    pub fn register(step: &Arc<Self>) {
        let mut registered = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
        registered.retain(|held| held.strong_count() > 0);
        registered.push(Arc::downgrade(step));
    }

    /// Every node's send step this process holds.
    #[must_use]
    pub fn registered() -> Vec<Arc<Self>> {
        REGISTERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
}
