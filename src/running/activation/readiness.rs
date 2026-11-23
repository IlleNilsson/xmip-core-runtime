//! Whether a node is ready, as its last publication says (the owner,
//! 2026-11-23: *That has to be sorted, nothing can be left*; ADR-0056,
//! amendment 2026-11-23): it runs the slice it holds (`<node>/configuration`,
//! the activation rule) and its Xmip Storage stands Fine (`<node>/storage`)
//! — reached, and where the node is one Storage node of several, the
//! primary or a standby ready and following, never one finding its primary,
//! copying or catching up (`storage::reached`). What a deployment asks
//! after it restarts a node, before it restarts the next
//! (`xmip-service --readiness`): a Storage node restarted comes back a
//! standby, and the next stopped before it is ready leaves its primary no
//! standby to hand over to. A stopped node's publication says its Storage
//! Done, so a node that has not published since it started again is never
//! ready by what it said before.

use observe::Health;

use super::published::published;
use super::standing::activated;
use crate::storage::DATABASES;

/// Whether the node configured at `path` is ready, in its own words: what
/// it runs, and its Xmip Storage.
///
/// # Errors
/// It is not, or it cannot be told; in the node's own words where it
/// published any.
pub fn readiness(path: &str) -> Result<String, String> {
    let published = published(path)?;
    let runs = activated(path, &published)?;
    let not = |why: &str| format!("{path}: the node is not ready: {why}");
    let last = published.last.as_ref().map_err(|why| not(why))?;
    let storage = last.record(DATABASES).map_err(|why| not(&why))?;
    if storage.health == Health::Fine {
        Ok(format!("{runs}; {}", storage.evidence))
    } else {
        Err(not(&storage.evidence))
    }
}
