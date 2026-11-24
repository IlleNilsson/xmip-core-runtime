//! Whether a node is ready, as its last publication since its start now
//! says (the owner, 2026-11-23: *That has to be sorted, nothing can be
//! left*; ADR-0056, amendments 2026-11-23 and 2026-11-24): it runs the slice
//! it holds (`<node>/configuration`, the activation rule) and its Xmip
//! Storage stands Fine (`<node>/storage`) — reached, and where the node is
//! one Storage node of several, the primary or a standby ready and
//! following, never one finding its primary, copying or catching up
//! (`storage::reached`). What a deployment asks after it restarts a node,
//! before it restarts the next (`xmip-service --readiness`): a Storage node
//! restarted comes back a standby, and the next stopped before it is ready
//! leaves its primary no standby to hand over to.
//!
//! **Only a publication of its start now** (open problem 137). A node
//! numbers each start as its first act, before anything can refuse it
//! (`membership::numbering`: the node's Clock in nanoseconds, above the one
//! its start file kept), so a publication whose records were observed
//! before that number is an earlier process's: one killed, crashed or
//! stopped past its service manager's bound leaves its last one saying its
//! Storage stands Fine, and is never ready by it. Until 2026-11-24 only a
//! stop in order said otherwise, its last publication saying its Storage
//! Done.
//!
//! **Told, never asked again and again** (open problem 140). [`awaited`]
//! reads the node's file, its trust and where it publishes once, then reads
//! its publication again each time the operating system says the folder it
//! publishes in changed (`directory_watch`), and the node publishes at once
//! as its Storage's standing changes. Until 2026-11-24 the wait slept a
//! publication's round between looks, and each look admitted the whole
//! configuration again.

use std::sync::mpsc::sync_channel;
use std::time::Duration;

use observe::Health;
use xcore::Clock;
use xcore::clock::between;

use super::published::{Node, published};
use super::standing::activated;
use crate::directory_watch::DirectoryWatch;
use crate::storage::DATABASES;

/// How often a wait looks again where the operating system will not watch
/// the folder the node publishes in.
const UNWATCHED: Duration = Duration::from_millis(250);

/// Whether the node configured at `path` is ready, in its own words: what
/// it runs, and its Xmip Storage.
///
/// # Errors
/// It is not, or it cannot be told; in the node's own words where it
/// published any.
pub fn readiness(path: &str) -> Result<String, String> {
    ready(path, &Node::read(path)?)
}

/// [`readiness`], waited for within `within` on `clock`: asked again each
/// time the folder the node publishes in changes, until it is ready or
/// `within` has passed.
///
/// # Errors
/// It is not ready by then, in the node's own words where it published any,
/// or it cannot be told.
pub fn awaited(path: &str, within: Duration, clock: &dyn Clock) -> Result<String, String> {
    let began = clock.monotonic_nanos();
    let node = Node::read(path)?;
    let (told, tells) = sync_channel::<()>(1);
    let watching = told.clone();
    let watch = node.directory().and_then(|directory| {
        DirectoryWatch::spawn(directory, move || {
            let _ = watching.try_send(());
        })
        .ok()
    });
    loop {
        let refused = match ready(path, &node) {
            Ok(said) => return Ok(said),
            Err(refused) => refused,
        };
        let left = within.saturating_sub(between(began, clock.monotonic_nanos()));
        if left.is_zero() {
            return Err(refused);
        }
        // Where the operating system will not watch the folder — none made
        // yet, as before the node first started — it is looked at again.
        let waited = if watch.is_some() {
            left
        } else {
            left.min(UNWATCHED)
        };
        // `told` lives to the end, so the wait times out where nothing
        // tells it, never ends at once for a sender gone.
        let _ = tells.recv_timeout(waited);
    }
}

/// Whether `node`, configured at `path`, is ready by its publication now.
fn ready(path: &str, node: &Node) -> Result<String, String> {
    let published = published(node);
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
