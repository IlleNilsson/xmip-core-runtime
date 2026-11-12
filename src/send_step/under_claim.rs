//! A Message a scan claimed, read again under its claim with its place in
//! its queue (`runtime-model.md` section 10, *A read is acted on only under
//! its claim*, corrected 2026-10-17): the page the scan read may be older
//! than the claim, read before another pass's hand-on landed. Its place,
//! its Journey, its Message and its Stream's record are one request
//! (`XmipStorage::read_claimed`; open problem 46, 2026-11-12: until then
//! four, one after another, 0.9 ms in the Essentials).

use std::time::Instant;

use context::IdentityFacts;
use xcore::JourneyId;

use super::found::{Found, found};
use super::steps::{Step, Steps};
use crate::generation::ReceivedWork;
use crate::message_path::Runtime;

/// What a Message a scan claimed is, read again under its claim.
pub(super) enum Under {
    /// At its place, due, and still to be sent.
    Waiting(Box<(ReceivedWork, IdentityFacts)>),
    /// At its place, its retry due at this time on this node's clock: a
    /// hand-on since the scan's read kept its due time there and released
    /// its claim.
    NotDue(Instant),
    /// No longer at its place: sent, dismissed or moved since.
    Moved,
    /// At its place and due, and not to be sent: failed, finished or not
    /// readable as a Message to send.
    Not(Found),
    /// Xmip Storage did not answer.
    Unanswered,
}

/// The Message at `place` in `queue`, read under this node's claim with
/// its Journey and its Message in one request, its place checked first —
/// still there, still this Message's, and due — then read as `body`, what
/// its queue keeps beside it, says; the read timed in `steps`.
pub(super) fn under_claim(
    runtime: &Runtime<'_>,
    queue: u128,
    (id, at): (JourneyId, u64),
    (body, steps): (&[u8], &mut Steps),
) -> Under {
    let asked = Instant::now();
    let claimed = runtime.send.storage.read_claimed(queue, at, id);
    steps.set(Step::Read, asked.elapsed());
    let Ok(claimed) = claimed else {
        return Under::Unanswered;
    };
    let page = &claimed.place;
    let Some(held) = page
        .held
        .first()
        .filter(|held| held.sequence == at && held.hold.journey == id)
    else {
        return Under::Moved;
    };
    if let Some(left) = page.due_in(held) {
        return Under::NotDue(asked + left);
    }
    match found(runtime, claimed, body, steps) {
        Ok(Found::Waiting(found)) => Under::Waiting(found),
        Ok(found) => Under::Not(found),
        Err(_) => Under::Unanswered,
    }
}
