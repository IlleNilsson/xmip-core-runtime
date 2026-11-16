//! A Message on a thread of the Send pool: claimed there where a scan found
//! it, sent, its pass settled however it ends — a panic too — and the next
//! of its sequence that waited beside it passed on the same thread as soon
//! as its hand-on is answered (`super::beside`).

use xcore::JourneyId;

use super::beside::Beside;
use super::pass::{Ended, abandoned, send};
use super::scan::{self, Unclaimed};
use super::{Departure, Settled};
use crate::message_path::Runtime;
use crate::pool::Pool;

/// `departure` sent on `pool`, and its pass settled — also where its send
/// panics ([`Sending`]).
pub(super) fn run<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    departure: Departure,
) {
    pool.run(Box::new(move || sent(runtime, settled, departure)));
}

/// `unclaimed` claimed and read on a thread of `pool`, under the place
/// admitted for it, and sent there: a backlog's claims are taken side by
/// side, sharing their commits, never one by one on the dispatching, which
/// cost a commit's sync each until 2026-10-06. Where it is not this node's
/// to send after all, or its claim panics, its place is given back
/// ([`Taking`]).
pub(super) fn take<'env>(
    pool: &Pool<'_, 'env>,
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    unclaimed: Unclaimed,
) {
    pool.run(Box::new(move || {
        let mut taking = Taking {
            runtime,
            journey: Some(unclaimed.journey()),
        };
        if let Some(departure) = scan::take(runtime, &unclaimed) {
            taking.journey = None;
            sent(runtime, settled, departure);
        }
    }));
}

/// `departure` sent, and its pass settled — also where its send panics —
/// and then the next of its sequence that waited beside it, on this same
/// thread, as soon as its hand-on is answered (`super::beside`).
pub(super) fn sent<'env>(
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    departure: Departure,
) {
    let mut next = Some(departure);
    while let Some(departure) = next.take() {
        next = passed(runtime, settled, departure);
    }
}

/// One pass of `departure`'s send, settled — or, behind, kept beside the
/// one ahead of it: what waited beside it, to be passed on now.
fn passed<'env>(
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    departure: Departure,
) -> Option<Departure> {
    let mut sending = Sending {
        runtime,
        settled,
        departure: Some(departure),
    };
    let departure = sending.departure.as_mut()?;
    departure.steps.taken_up();
    let mut ended = send(runtime, departure);
    if matches!(ended, Ended::Behind) {
        ended = beside_or_behind(runtime, &mut sending)?;
    }
    let departure = sending.departure.as_mut()?;
    let sequenced = departure
        .work
        .journey
        .received()
        .is_some_and(|received| !received.sequences.is_empty())
        || departure.work.journey.group.is_some()
        || !crate::sequence::points_of(runtime.sends, &departure.to).is_empty();
    let closed = sequenced && matches!(ended, Ended::Completed(_) | Ended::Failed { .. });
    let next = sending
        .departure
        .take()
        .and_then(|departure| runtime.send.settle(settled, departure, ended));
    // A Message of a Stream that holds a sequence has ended its Journey: what waits
    // behind it in either step may go on now (`crate::sequence`).
    if closed {
        runtime.send.rescan();
        runtime.work.ask_every();
    }
    next
}

/// A pass `sending` holds that ended behind: kept beside the one ahead of
/// it where that one is in its send here (`super::beside`), and then
/// nothing; passed again at once where it heads its sequences by now and
/// none ahead of it is in a send here, its claim kept; else behind, as it
/// was. One that waits for its places is the scan's, in its queue's order.
fn beside_or_behind(runtime: &Runtime<'_>, sending: &mut Sending<'_>) -> Option<Ended> {
    let departure = sending.departure.as_ref()?;
    let journey = &departure.work.journey;
    if crate::sequence::waits_for_places(runtime.sends, journey, &departure.to) {
        return Some(Ended::Behind);
    }
    let Ok(waits) = crate::sequence::behind(runtime.storage.as_ref(), journey) else {
        return Some(Ended::Behind);
    };
    let waiting = sending.departure.take()?;
    match runtime.send.wait_beside(waiting, &waits) {
        Beside::Waits => None,
        Beside::Goes(going) => Some(send(runtime, sending.departure.insert(going))),
        Beside::Behind(behind) => {
            sending.departure = Some(behind);
            Some(Ended::Behind)
        }
    }
}

/// A Message a scan found, being claimed on a send thread: its place given
/// back unless it was claimed and owned, however the claim ended.
struct Taking<'env> {
    runtime: &'env Runtime<'env>,
    journey: Option<JourneyId>,
}

impl Drop for Taking<'_> {
    fn drop(&mut self) {
        if let Some(journey) = self.journey.take() {
            self.runtime.send.untake(journey);
        }
    }
}

/// One Message on a send thread, settled however its send ends. Sent to
/// its end, it is settled by what the send wrote. A send that panicked is
/// settled on the way out: written Failed with why — kept in its queue for
/// an operator — its claim ended, audited, and let go of, so it is never
/// left owned with its claim renewed and passed over by every scan, as it
/// was until 2026-10-05.
struct Sending<'env> {
    runtime: &'env Runtime<'env>,
    settled: Settled<'env>,
    departure: Option<Departure>,
}

impl Drop for Sending<'_> {
    fn drop(&mut self) {
        let Some(mut departure) = self.departure.take() else {
            return;
        };
        let why = "its send thread panicked before its hand-on was written";
        let ended = abandoned(self.runtime, &mut departure, why);
        if let Some(next) = self.runtime.send.settle(self.settled, departure, ended) {
            self.runtime.send.hand_back(next);
        }
    }
}
