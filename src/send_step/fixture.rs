//! The send step its unit tests take: over an embedded Xmip Storage in
//! memory, sealed under a key held in memory, for the test cluster's first
//! node at the default `[tuning]`.

use std::sync::Arc;

use persist::fixture::Memory;
use persist::storage::{Embedded, XmipStorage};
use secret::{Held, KekName};

use super::SendStep;
use crate::tuning::Tuning;

/// A send step nothing dispatches, over an empty Xmip Storage in memory.
pub(super) fn step() -> SendStep {
    let keys = Held::new(secret::fixture::Memory::default());
    let kek = KekName::new("storage").expect("a name");
    let storage: Arc<dyn XmipStorage> = Arc::new(
        Embedded::open(
            Memory::default(),
            Memory::default(),
            Memory::default(),
            &keys,
            &kek,
        )
        .expect("opened"),
    );
    let cluster = configure::fixture::test_cluster();
    let node = cluster.node_scope(0);
    SendStep::new((&cluster.scope(), &node), storage, &Tuning::default(), None)
}
