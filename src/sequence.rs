//! The one Sequence: what lets work through a point one at a time per key,
//! in the order the Ledger wrote it (ADR-0024 and ADR-0066, amendments
//! 2026-10-22).
//!
//! The owner, 2026-10-22: *A default correlation set is its receive
//! location name. There might be more streams, files, pushing at that
//! receive location. Default one stream, message, journey at a time. Put it
//! in the ledger if it is not processed now. If I want to open up for
//! parallelism I can use context values like Receive Port, Work Process,
//! Send Port, Message and Journey context values. I can widen and strangle
//! parallelism at any configurable point*; and *Equal values in a
//! correlation set (aka hashtable) go in the same queue, different values
//! go parallel depending on the value in the correlation set.*
//!
//! - **A sequence is a queue in the Ledger**, one per point and key: the
//!   point — a Receive Location, a Receive Port, a Work Process, a Send
//!   Port Group, a Send Port, a Send Location — the Correlation named
//!   there, and the key's values written out in full ([`Point::queue`]).
//!   Equal keys share it; different keys are different queues and run in
//!   parallel.
//! - **A place is held from the write that brings work to the point**, in
//!   that write, and work there goes on only while it holds the first
//!   place ([`heads`]). Nothing waits on a thread: what does not head its
//!   sequence waits in the Ledger, and a scan takes it up once it does.
//! - **A Receive Location's and a Receive Port's sequence is end to end**:
//!   the place is the Stream's, held by its origin — the Message it was
//!   received as — until the last Journey born from it ends, which Xmip
//!   Storage counts (`persist::storage`'s origin). A Work Process's and a
//!   Send Port's is the Message's, held while it is at that point, and let
//!   go of as it fails where the point's `on_failure` is `skip`, however
//!   it failed ([`let_go`]).
//! - **A Send Port Group's is its delivery's** (`group`): held for the
//!   Messages of the member Journeys one Publication opens through the
//!   Group until every member has succeeded or failed, which Xmip Storage counts too.
//! - **A Receive Location heads its own by default**: one Stream at a time,
//!   keyed by its own name, until it names a set that spreads the work.

mod configured;
mod group;
mod head;
mod late;
mod let_go;

pub use configure::OnFailure;
pub use configured::{destinations, names, point, received_at};
pub use group::{delivered, group_heads, group_placed, grouped, waits_for_group};
pub use head::{Stands, behind, heads, held_by, may_go, stands, stream_heads, waits_on};
use journey::{Journey, Received, Sequenced};
pub use late::{Placing, heading, take_late, waits_for_places};
pub use let_go::{let_go, lets_go};

use crate::ledger::Opened;
use message::Message;
use persist::storage::{Hold, named};
use route::Promoted;
use xcore::JourneyId;

use crate::sending::{Destination, Sends};
use crate::work_step::{KeyWord, ResolvedSet};
use route::Subscriber;

/// What kind of point a sequence is at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointKind {
    ReceiveLocation,
    ReceivePort,
    WorkProcess,
    SendPortGroup,
    SendPort,
    SendLocation,
}

impl PointKind {
    /// Its word, in a sequence's name.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::ReceiveLocation => "receive-location",
            Self::ReceivePort => "receive-port",
            Self::WorkProcess => "work-process",
            Self::SendPortGroup => "send-port-group",
            Self::SendPort => "send-port",
            Self::SendLocation => "send-location",
        }
    }

    /// Whether its sequence holds the Stream end to end.
    #[must_use]
    pub const fn end_to_end(self) -> bool {
        matches!(self, Self::ReceiveLocation | Self::ReceivePort)
    }
}

/// One point a Correlation governs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub kind: PointKind,
    /// The artifact's name.
    pub name: String,
    pub set: ResolvedSet,
    pub on_failure: OnFailure,
}

impl Point {
    /// A Receive Location's own sequence where it names no set: keyed by
    /// its name, one Stream at a time.
    #[must_use]
    pub fn receive_location(name: &str) -> Self {
        Self {
            kind: PointKind::ReceiveLocation,
            name: name.to_string(),
            set: ResolvedSet {
                name: name.to_string(),
                keys: vec![KeyWord::ReceiveLocation],
            },
            on_failure: OnFailure::Block,
        }
    }

    /// The sequence `key`, the full text of a key's values, has at this
    /// point in the cluster at `cluster`: its queue, and the name it is
    /// kept by beside every place, so two keys are told apart by their
    /// values and never by a hash alone.
    #[must_use]
    pub fn queue(&self, cluster: &str, key: &str) -> (u128, String) {
        let text = format!(
            "{cluster}/sequence/{}/{}/{}/{key}",
            self.kind.word(),
            self.name,
            self.set.name
        );
        (named(&text), text)
    }

    /// The place `member` — an origin, or a Message by its Journey — takes
    /// in its key's sequence, `journey` and `promoted` read for the key.
    ///
    /// # Errors
    /// A key part it lacks, in words.
    pub fn place(
        &self,
        cluster: &str,
        member: u128,
        (journey, promoted): (&Journey, &Promoted),
    ) -> Result<Hold, String> {
        let at = self.at(journey);
        let key = self.set.text(journey, promoted, &at)?;
        let (queue, text) = self.queue(cluster, &key);
        Ok(Hold {
            queue,
            journey: JourneyId::new(member),
            body: text.into_bytes(),
        })
    }

    fn at(&self, journey: &Journey) -> String {
        match self.kind {
            PointKind::WorkProcess => self.name.clone(),
            _ => journey.current_work_process.clone().unwrap_or_default(),
        }
    }
}

/// Where a Stream received at `location` of `port` as `message` came in,
/// and every place its origin takes in the end-to-end sequences `points`,
/// in the cluster at `cluster`, the keys read from `promoted`, what arrival
/// promoted of it: the Message is promoted once.
///
/// # Errors
/// A key part the Message lacks, in words.
pub fn received(
    cluster: &str,
    (location, port, points): (&str, &str, &[Point]),
    (message, promoted): (&Message, &Promoted),
) -> Result<(Received, Vec<Hold>), String> {
    let origin = message.message_id().value();
    let mut received = Received {
        location: location.to_string(),
        port: port.to_string(),
        origin,
        sequences: Vec::new(),
        skips: points
            .iter()
            .any(|point| point.on_failure == OnFailure::Skip),
    };
    let probe = Journey::new(JourneyId::new(0)).received_as(received.clone());
    let mut places = Vec::with_capacity(points.len());
    for point in points {
        let place = point.place(cluster, origin, (&probe, promoted))?;
        received.sequences.push(place.queue);
        places.push(place);
    }
    Ok((received, places))
}

/// The places the Messages of the Journeys `opened` take in the sequences
/// of the points they are bound for — a Send Port Group's for their
/// delivery, a Send Port, the Send Locations it may leave by, or a Work
/// Process, each naming a Correlation — their keys read from `promoted`,
/// each Journey told its places: taken in the write that opens them, so the
/// order is the Ledger's.
///
/// # Errors
/// A key part a Message lacks, in words.
pub fn places(
    cluster: &str,
    sends: &Sends,
    opened: &mut [Opened],
    promoted: &Promoted,
) -> Result<Vec<Hold>, String> {
    let mut places = Vec::new();
    for one in opened {
        places.extend(group_placed(cluster, sends, &mut one.journey, promoted)?);
        places.extend(placed(
            cluster,
            &points_of(sends, &one.to),
            &mut one.journey,
            promoted,
        )?);
    }
    Ok(places)
}

/// The places the Message of `journey` takes in the sequences of `points`,
/// its key read from `promoted`, the Journey told each.
///
/// # Errors
/// A key part its Message lacks, in words.
pub fn placed(
    cluster: &str,
    points: &[&Point],
    journey: &mut Journey,
    promoted: &Promoted,
) -> Result<Vec<Hold>, String> {
    let mut places = Vec::with_capacity(points.len());
    for point in points {
        let member = journey.journey_id().value();
        let place = point.place(cluster, member, (journey, promoted))?;
        journey.sequences.push(Sequenced {
            queue: place.queue,
            skips: point.on_failure == OnFailure::Skip,
        });
        places.push(place);
    }
    Ok(places)
}

/// The sequences what is bound for `to` passes its point in: its Work
/// Process's, or its Send Port's and those of the Send Locations the Port
/// may leave by, each where it names a Correlation.
#[must_use]
pub fn points_of<'a>(sends: &'a Sends, to: &'a Subscriber) -> Vec<&'a Point> {
    match to {
        Subscriber::WorkProcess(name) => sends
            .points
            .iter()
            .filter(|point| point.kind == PointKind::WorkProcess && point.name == *name)
            .collect(),
        _ => match sends.to(to) {
            Destination::Ports(ports) => ports.into_iter().flat_map(|port| port.points).collect(),
            Destination::Process | Destination::Nowhere => Vec::new(),
        },
    }
}
