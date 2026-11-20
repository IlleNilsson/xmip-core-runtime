//! Which start of its node a start is (ADR-0056, amendment 2026-11-20): a
//! number the node takes itself as its process is drawn, above the one it
//! kept last and never below its Clock (`xcore::clock::serial`, as a
//! slice's serial is taken), and keeps (`configure::start`) before its row
//! is first tried. Only the node's own machine sees its starts in the order
//! they happened, so the order is drawn here, and Xmip Storage registers a
//! start only above its node's latest, never by the order writes arrive.
//!
//! **Across a crash** the number kept survives, so the next start is above
//! it even where the clock was set back since; a start that crashed before
//! keeping its number sent nothing under it. **A store lost or restored
//! from a backup** keeps an older number or none, and the Clock puts the
//! next start above every start before it while the clock is right. Where
//! the clock is behind too, Xmip Storage refuses the start, saying the
//! latest's number, and the start floors its file there ([`floored`]), so
//! the node's next start registers whatever its clock says: that start
//! comes after the refusal, which came after the start it is above. A start
//! refused never registers itself again, since asked again it would be the
//! late write this prevents.

use std::path::Path;

use configure::start::{Start, start_at};
use xcore::Clock;

use crate::kept::{held, kept};

/// What a node calls its start file in words.
const WHAT: &str = "start";

/// The number of the node configured at `configuration`'s start now: above
/// the one its start file keeps and never below `clock`, kept there before
/// it is returned. A file that does not read is one lost: the clock alone
/// numbers the start.
///
/// # Errors
/// Where the start file cannot be read or kept, in words: the start then
/// has no number, and writes no row.
pub fn numbered(configuration: &Path, clock: &dyn Clock) -> Result<u64, String> {
    let at = start_at(configuration);
    let last = last_at(&at)?.unwrap_or(0);
    let start = xcore::clock::serial(last, clock.unix_timestamp_nanos());
    kept(&at, Start { start }.written().as_bytes(), WHAT)?;
    Ok(start)
}

/// The start file of the node configured at `configuration` raised to
/// `latest`, where it keeps less: the number a later start of the node
/// registered under, which Xmip Storage refused this start below, so the
/// node's next start is numbered above it.
///
/// # Errors
/// Where the start file cannot be read or kept, in words.
pub fn floored(configuration: &Path, latest: u64) -> Result<(), String> {
    let at = start_at(configuration);
    if last_at(&at)?.is_some_and(|last| last >= latest) {
        return Ok(());
    }
    kept(&at, Start { start: latest }.written().as_bytes(), WHAT)
}

/// The number the start file at `at` keeps: none where it is absent or does
/// not read.
fn last_at(at: &Path) -> Result<Option<u64>, String> {
    Ok(held(at, WHAT)?.and_then(|text| Start::read(&text).ok().map(|kept| kept.start)))
}

#[cfg(test)]
mod tests;
