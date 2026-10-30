//! A Message a scan claimed, read again under its claim with its place in
//! its queue (`runtime-model.md` section 10, *A read is acted on only under
//! its claim*, corrected 2026-10-17): the page the scan read may be older
//! than the claim, read before another pass's hand-on landed.

use std::time::Instant;

use context::IdentityFacts;
use xcore::JourneyId;

use super::pass::{Found, read};
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

/// The Message at `place` in `queue`, read under this node's claim: its
/// place first — still there, still this Message's, and due — then its
/// Journey and the Message, with `body`, what its queue keeps beside it.
pub(super) fn under_claim(
    runtime: &Runtime<'_>,
    queue: u128,
    (id, at): (JourneyId, u64),
    body: &[u8],
) -> Under {
    let asked = Instant::now();
    let Ok(page) = runtime.send.storage.read_held(queue, at, 1) else {
        return Under::Unanswered;
    };
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
    match read(runtime, id, body) {
        Ok(Found::Waiting(found)) => Under::Waiting(found),
        Ok(found) => Under::Not(found),
        Err(_) => Under::Unanswered,
    }
}
