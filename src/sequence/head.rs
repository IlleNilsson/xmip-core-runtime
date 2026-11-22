//! Where a place stands in its sequence, read from the Ledger: heading it,
//! so work there may go on, or behind, with where the head stands — what
//! it waits on (`persist::storage::Watched::Head`). A place let go of is
//! readable before its sync, so a read that finds a place heading says
//! when the write that let it head — the hand-on of the one before it,
//! wherever that was asked — is durable, where it is not yet
//! (`XmipStorage::read_head`): a send's first byte waits for it, so the
//! order survives any crash (the owner, 2026-11-15: *Wait for the disk*;
//! ADR-0018, amendment 2026-11-15). Where no write under way moved the
//! head, as is common, the read is the one it was and nothing more is read
//! or waited for.

use journey::Journey;
use persist::storage::{Durable, Position, Watched, XmipStorage};
use xcore::lock::Locked;

/// Where a place stands in its sequence, as the Ledger reads it.
#[derive(Clone, Debug)]
pub enum Stands {
    /// It heads it, the write that let it head durable once this says,
    /// where it is not yet.
    Heads(Option<Durable>),
    /// It does not: where the head stands, what it waits on.
    Behind(Position),
}

/// Each sequence the Message of `journey` holds a place in, and who holds
/// the place: its Stream's end to end, by its origin; its Send Port Group
/// delivery's, by the delivery; and its own at the point it is at, by its
/// Journey — in the order work there goes on in.
pub fn held_by(journey: &Journey) -> impl Iterator<Item = (u128, u128)> + '_ {
    let member = journey.journey_id().value();
    let stream = super::kept::streamed(journey.received());
    let group = journey
        .group
        .as_ref()
        .and_then(|group| Some((group.queue?, group.delivery)));
    let own = journey
        .sequences
        .iter()
        .map(move |sequenced| (sequenced.queue, member));
    stream.chain(group).chain(own)
}

/// Whether the Message of `journey` may go on: it heads every sequence it
/// holds a place in ([`held_by`]) — and, where it does, each write that let
/// it head that is not yet durable, what its far end waits for; none where
/// each was durable as read, as is common. `None` where it does not head
/// one.
///
/// # Errors
/// Xmip Storage did not answer, in words.
pub fn may_go(
    storage: &dyn XmipStorage,
    journey: &Journey,
) -> Result<Option<Vec<Durable>>, String> {
    let mut moving = Vec::new();
    for (queue, holder) in held_by(journey) {
        match stands(storage, queue, holder)? {
            Stands::Heads(unsynced) => moving.extend(unsynced),
            Stands::Behind(_) => return Ok(None),
        }
    }
    Ok(Some(moving))
}

/// Whether `member` holds the first place in the sequence `queue`.
///
/// # Errors
/// Xmip Storage did not answer, in words.
pub fn heads(storage: &dyn XmipStorage, queue: u128, member: u128) -> Result<bool, String> {
    Ok(matches!(stands(storage, queue, member)?, Stands::Heads(_)))
}

/// Where the head of the sequence `queue` stands, where `member` does not
/// hold its first place — what it waits on (`persist::storage::Watched::
/// Head`): how many places were ever let go of there, which only one let
/// go of moves — or none where it heads it.
///
/// # Errors
/// Xmip Storage did not answer, in words.
pub fn waits_on(
    storage: &dyn XmipStorage,
    queue: u128,
    member: u128,
) -> Result<Option<Position>, String> {
    Ok(match stands(storage, queue, member)? {
        Stands::Heads(_) => None,
        Stands::Behind(head) => Some(head),
    })
}

/// Where `member` stands in the sequence `queue`, read from the Ledger, or
/// as this process remembers it heading.
///
/// # Errors
/// Xmip Storage did not answer, in words.
pub fn stands(storage: &dyn XmipStorage, queue: u128, member: u128) -> Result<Stands, String> {
    if headed().contains(&(queue, member)) {
        return Ok(Stands::Heads(None));
    }
    Ok(read_head(storage, queue)?.stands(queue, member))
}

/// The head of a sequence as read: who holds its first place, whether it
/// holds any, where its head stands, and when the write that moved it is
/// durable, where it is not yet.
#[derive(Clone, Debug)]
pub struct HeadRead {
    first: Option<u128>,
    holds: bool,
    at: Position,
    moving: Option<Durable>,
}

/// The head of the sequence `queue`, read from the Ledger.
///
/// # Errors
/// Xmip Storage did not answer, in words.
pub fn read_head(storage: &dyn XmipStorage, queue: u128) -> Result<HeadRead, String> {
    let read = storage.read_head(queue, 1).map_err(|why| why.to_string())?;
    let page = &read.held;
    Ok(HeadRead {
        first: page.held.first().map(|first| first.hold.journey.value()),
        holds: page.count != 0,
        at: Position {
            watched: Watched::Head(queue),
            at: page.next.saturating_sub(page.count),
        },
        moving: read.moving,
    })
}

impl HeadRead {
    /// Where its head stood as read: how many places were ever let go of
    /// there, which only one let go of moves.
    #[must_use]
    pub const fn at(&self) -> u64 {
        self.at.at
    }

    /// Where `member` stands in the sequence `queue`, as this read found
    /// its head.
    ///
    /// A page that reads nothing while the queue still holds places is no
    /// head: only an empty queue is (corrected 2026-10-27; an empty page read
    /// mid-write let a Message overtake under load). Only a place seen at
    /// the head is remembered, and only once the write that let it head is
    /// durable: an empty queue says nothing of a place taken later, and a
    /// head a crash could still move back is no head this process knows
    /// (2026-11-15).
    #[must_use]
    pub fn stands(&self, queue: u128, member: u128) -> Stands {
        match self.first {
            Some(first) if first == member => {
                if self.moving.is_none() {
                    headed().remember((queue, member));
                }
                Stands::Heads(self.moving.clone())
            }
            Some(_) => Stands::Behind(self.at),
            None if self.holds => Stands::Behind(self.at),
            None => Stands::Heads(self.moving.clone()),
        }
    }
}

/// Each sequence the Message of `journey` holds a place in and does not
/// head ([`held_by`]), with where its head stands as read now: what it
/// waits on, taken up the moment any node moves one (open problem 46,
/// 2026-11-12). None where it heads them all.
///
/// # Errors
/// Xmip Storage did not answer, in words.
pub fn behind(storage: &dyn XmipStorage, journey: &Journey) -> Result<Vec<Position>, String> {
    let mut behind = Vec::new();
    for (queue, holder) in held_by(journey) {
        behind.extend(waits_on(storage, queue, holder)?);
    }
    Ok(behind)
}

/// Whether the Stream the Message of `journey` was born from heads every
/// sequence it holds a place in end to end: work on it may go on.
///
/// # Errors
/// Xmip Storage did not answer.
pub fn stream_heads(storage: &dyn XmipStorage, journey: &Journey) -> Result<bool, String> {
    let Some(received) = journey.received() else {
        return Ok(true);
    };
    for queue in &received.sequences {
        if !heads(storage, *queue, received.origin)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// What this process has seen head its sequence, the write that let it
/// head durable. A place that heads a sequence heads it until it is let
/// go, and nothing asks of a place once it is let go — its Stream or its
/// Journey has ended — so what is remembered here is never wrong, and a
/// Stream's later steps on this node ask the Ledger nothing (the owner,
/// 2026-10-22: a Receive Location's own sequence costs as little as the
/// Location can make it, never the cluster-wide promise).
struct Headed(std::sync::Mutex<std::collections::HashSet<(u128, u128)>>);

/// The most places remembered at once; the oldest are forgotten together.
const REMEMBERED: usize = 65_536;

impl Headed {
    fn contains(&self, place: &(u128, u128)) -> bool {
        self.lock().contains(place)
    }

    fn remember(&self, place: (u128, u128)) {
        let mut known = self.lock();
        if known.len() >= REMEMBERED {
            known.clear();
        }
        known.insert(place);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<(u128, u128)>> {
        self.0.locked()
    }
}

fn headed() -> &'static Headed {
    static HEADED: std::sync::LazyLock<Headed> = std::sync::LazyLock::new(|| {
        Headed(std::sync::Mutex::new(std::collections::HashSet::new()))
    });
    &HEADED
}
