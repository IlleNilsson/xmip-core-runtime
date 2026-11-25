//! Every node's Work Process step this process holds, registered, so the
//! runtime's library lists its Instances and an operator's act on a
//! Message that failed at one of its Work Processes finds it by its node
//! (`xmip_operate.h` section 29; `crate::applied`).

use std::sync::Arc;

use super::WorkStep;
use crate::registry::Registry;

/// Every node's Work Process step in this process, registered.
static REGISTERED: Registry<WorkStep> = Registry::new();

impl WorkStep {
    /// `step` registered, so the operate library finds it by its node.
    pub fn register(step: &Arc<Self>) {
        REGISTERED.register(step);
    }

    /// Every node's Work Process step this process holds.
    #[must_use]
    pub fn registered() -> Vec<Arc<Self>> {
        REGISTERED.all()
    }

    /// The node it runs on: `xmip:///<cluster>/node/<name>`.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }
}
