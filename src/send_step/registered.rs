//! Every node's send step this process holds, registered, so the runtime's
//! library finds one by its node and acts on its Messages (`xmip_operate.h`
//! section 16).

use std::sync::Arc;

use super::SendStep;
use crate::registry::Registry;

/// Every node's send step in this process, registered.
static REGISTERED: Registry<SendStep> = Registry::new();

impl SendStep {
    /// `step` registered, so the operate library finds it by its node
    /// and acts on its Messages (`xmip_operate.h` section 16).
    pub fn register(step: &Arc<Self>) {
        REGISTERED.register(step);
    }

    /// Every node's send step this process holds.
    #[must_use]
    pub fn registered() -> Vec<Arc<Self>> {
        REGISTERED.all()
    }
}
