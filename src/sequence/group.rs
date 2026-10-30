//! A Send Port Group's sequence: one place for each delivery, held until
//! every member Send Port has succeeded or failed (ADR-0024 and ADR-0066,
//! amendments 2026-10-27).
//!
//! The owner, 2026-10-27: *a send port group does not have to send in
//! order, it is a spread solution. Success should be audited as each send
//! port does, failures should be audited as they should*; and *The result
//! is a set of ports that succeeded or failed … one has to accumulate the
//! results. Report the results as a set.* So a Group naming a Correlation
//! holds its key for a delivery — the member Journeys one Publication
//! opens through it — until the set is complete. Its members go side by
//! side; the next delivery of the same key waits until the set before it
//! is complete, and where that set holds a failure, its key follows
//! `on_failure`: blocked until an operator retries or dismisses the
//! failed member, or let go (`skip`). Xmip Storage counts the members
//! still open and lets the place go with the last
//! (`persist::storage`'s origin, `JourneyFacts::group_delivery`).

use journey::{GroupDelivery, Journey};
use persist::storage::{Hold, XmipStorage};
use route::{Promoted, Subscriber};
use xcore::IdGenerator;

use super::{OnFailure, Point, PointKind, heads};
use crate::ledger::Opened;
use crate::sending::Sends;

/// The Send Port Group `name`'s sequence, where it names a Correlation.
fn point<'a>(sends: &'a Sends, name: &str) -> Option<&'a Point> {
    sends
        .points
        .iter()
        .find(|point| point.kind == PointKind::SendPortGroup && point.name == name)
}

/// Each delivery among `opened` by a Send Port Group naming a Correlation
/// told to its members: one delivery for the Journeys one Subscription
/// opened through the Group, its identifier minted by `ids`, every member
/// knowing every other.
pub fn delivered(sends: &Sends, opened: &mut [Opened], ids: &dyn IdGenerator) {
    let mut at = 0;
    while at < opened.len() {
        let one = &opened[at];
        let end = opened[at..]
            .iter()
            .position(|other| other.subscription != one.subscription || other.group != one.group)
            .map_or(opened.len(), |length| at + length);
        if let Some(point) = one.group.as_deref().and_then(|name| point(sends, name)) {
            let delivery = GroupDelivery {
                name: point.name.clone(),
                delivery: ids.next_u128(),
                queue: None,
                skips: point.on_failure == OnFailure::Skip,
                members: opened[at..end]
                    .iter()
                    .map(|member| member.journey.journey_id().value())
                    .collect(),
            };
            for member in &mut opened[at..end] {
                member.journey.group = Some(delivery.clone());
            }
        }
        at = end;
    }
}

/// The place `journey`'s delivery takes in its Group's sequence for its
/// key, read from `promoted`, the Journey told it: nothing where it is no
/// Group's member or has its place.
///
/// # Errors
/// A key part its Message lacks, in words.
pub fn group_placed(
    cluster: &str,
    sends: &Sends,
    journey: &mut Journey,
    promoted: &Promoted,
) -> Result<Option<Hold>, String> {
    let Some(group) = journey.group.as_ref().filter(|group| group.queue.is_none()) else {
        return Ok(None);
    };
    let Some(point) = point(sends, &group.name) else {
        return Ok(None);
    };
    let place = point.place(cluster, group.delivery, (journey, promoted))?;
    if let Some(group) = journey.group.as_mut() {
        group.queue = Some(place.queue);
    }
    Ok(Some(place))
}

/// Whether `journey`'s delivery heads its Group's sequence, where it is a
/// member of one: the set before it of the same key is complete.
///
/// # Errors
/// Xmip Storage did not answer.
pub fn group_heads(storage: &dyn XmipStorage, journey: &Journey) -> Result<bool, String> {
    match journey
        .group
        .as_ref()
        .and_then(|group| Some((group.queue?, group.delivery)))
    {
        Some((queue, delivery)) => heads(storage, queue, delivery),
        None => Ok(true),
    }
}

/// Whether a Message bound for `to` may be a member of a delivery by a
/// Send Port Group naming a Correlation: a Send Port of such a Group.
#[must_use]
pub fn grouped(sends: &Sends, to: &Subscriber) -> bool {
    let Subscriber::SendPort(port) = to else {
        return false;
    };
    sends
        .groups
        .iter()
        .any(|group| group.send_ports.contains(port) && point(sends, &group.name).is_some())
}

/// Whether `journey` is a member of a delivery by a Send Port Group naming
/// a Correlation that has not taken its place in the Group's sequence yet.
#[must_use]
pub fn waits_for_group(sends: &Sends, journey: &Journey) -> bool {
    journey
        .group
        .as_ref()
        .is_some_and(|group| group.queue.is_none() && point(sends, &group.name).is_some())
}
