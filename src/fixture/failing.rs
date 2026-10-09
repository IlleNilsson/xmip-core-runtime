//! Xmip Storage that fails on demand, lets another writer in first, or
//! loses a Publication's answer: what the runtime's tests race and break
//! Storage with, by the test's order rather than its luck.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use persist::PersistError;
use persist::storage::{
    AdministrationKind, AdministrationRecord, AuditEntry, Claim, DeadEntry, DeadQueue, HandOn,
    HeldQueue, JourneyRecord, MessageRecord, Publication, Query, Replay, Replayed, StreamChunk,
    StreamRecord, XmipStorage,
};
use xcore::{AuditId, JourneyId, MessageId, StreamId};

/// An operation of Xmip Storage a [`Failing`] can be told to fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    Publish,
    ReadHeld,
    HandOn,
    Claim,
    Renew,
    ReadJourney,
    WriteJourney,
    ReadMessage,
    WriteAdministration,
    ReadDead,
    Replay,
}

/// What a [`Failing`] runs once, the next time an operation is asked,
/// before it answers: another writer's step, landed between two of the
/// caller's.
pub type Interleaved = Box<dyn FnOnce() + Send>;

/// Xmip Storage that fails on demand, as a Storage node that does not
/// answer: each operation told to fail does so the number of times it was
/// told, as `PersistError::Unreachable`, and every other call passes
/// through to the Storage beneath. An operation can also be told to let
/// another writer in first, once ([`Failing::before`]), so a race is a
/// test's order rather than its luck; and a Publication's answer can be
/// lost, once ([`Failing::lose_answer`]).
pub struct Failing {
    beneath: Arc<dyn XmipStorage>,
    failing: Mutex<BTreeMap<Operation, u32>>,
    before: Mutex<BTreeMap<Operation, Interleaved>>,
    lost: Mutex<Option<Interleaved>>,
}

impl Failing {
    /// Failing nothing yet, over `beneath`.
    #[must_use]
    pub fn over(beneath: Arc<dyn XmipStorage>) -> Arc<Self> {
        Arc::new(Self {
            beneath,
            failing: Mutex::new(BTreeMap::new()),
            before: Mutex::new(BTreeMap::new()),
            lost: Mutex::new(None),
        })
    }

    /// The next Publication written beneath and its answer lost: `meanwhile`
    /// runs — another node's work landing before the answer would have
    /// come — and the Publication is asked again, as a Storage client asks
    /// the next Storage node when one does not answer, and that answer is
    /// the one given.
    pub fn lose_answer(&self, meanwhile: Interleaved) {
        *self.lost.lock().unwrap_or_else(PoisonError::into_inner) = Some(meanwhile);
    }

    /// Run `first` once, the next time `operation` is asked, before it is
    /// answered.
    pub fn before(&self, operation: Operation, first: Interleaved) {
        self.before
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(operation, first);
    }

    /// Fail `operation` the next `times` it is asked; `u32::MAX` until
    /// [`Failing::heal`].
    pub fn fail(&self, operation: Operation, times: u32) {
        self.lock().insert(operation, times);
    }

    /// Fail nothing any more.
    pub fn heal(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Operation, u32>> {
        self.failing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn asked(&self, operation: Operation) -> Result<(), PersistError> {
        let first = self
            .before
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&operation);
        if let Some(first) = first {
            first();
        }
        let mut failing = self.lock();
        let Some(left) = failing.get_mut(&operation) else {
            return Ok(());
        };
        if *left == 0 {
            return Ok(());
        }
        if *left != u32::MAX {
            *left -= 1;
        }
        Err(PersistError::Unreachable {
            reason: format!("{operation:?} told to fail"),
        })
    }
}

impl XmipStorage for Failing {
    fn write_chunk(&self, chunk: &StreamChunk) -> Result<(), PersistError> {
        self.beneath.write_chunk(chunk)
    }

    fn read_chunk(
        &self,
        stream: StreamId,
        index: u32,
    ) -> Result<Option<StreamChunk>, PersistError> {
        self.beneath.read_chunk(stream, index)
    }

    fn write_stream(&self, last: &StreamChunk, stream: &StreamRecord) -> Result<(), PersistError> {
        self.beneath.write_stream(last, stream)
    }

    fn read_stream(&self, stream: StreamId) -> Result<Option<StreamRecord>, PersistError> {
        self.beneath.read_stream(stream)
    }

    fn write_message(&self, message: &MessageRecord) -> Result<(), PersistError> {
        self.beneath.write_message(message)
    }

    fn read_message(&self, message: MessageId) -> Result<Option<MessageRecord>, PersistError> {
        self.asked(Operation::ReadMessage)?;
        self.beneath.read_message(message)
    }

    fn write_journey(&self, journey: &JourneyRecord) -> Result<(), PersistError> {
        self.asked(Operation::WriteJourney)?;
        self.beneath.write_journey(journey)
    }

    fn read_journey(&self, journey: JourneyId) -> Result<Option<JourneyRecord>, PersistError> {
        self.asked(Operation::ReadJourney)?;
        self.beneath.read_journey(journey)
    }

    fn publish(&self, publication: &Publication) -> Result<Vec<Claim>, PersistError> {
        self.asked(Operation::Publish)?;
        let lost = self
            .lost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(meanwhile) = lost {
            self.beneath.publish(publication)?;
            meanwhile();
        }
        self.beneath.publish(publication)
    }

    fn read_held(&self, queue: u128, from: u64, most: u32) -> Result<HeldQueue, PersistError> {
        self.asked(Operation::ReadHeld)?;
        self.beneath.read_held(queue, from, most)
    }

    fn read_dead(&self, queue: u128, from: u64, most: u32) -> Result<DeadQueue, PersistError> {
        self.asked(Operation::ReadDead)?;
        self.beneath.read_dead(queue, from, most)
    }

    fn read_dead_message(
        &self,
        queue: u128,
        message: MessageId,
    ) -> Result<DeadEntry, PersistError> {
        self.asked(Operation::ReadDead)?;
        self.beneath.read_dead_message(queue, message)
    }

    fn replay(&self, replay: &Replay) -> Result<Replayed, PersistError> {
        self.asked(Operation::Replay)?;
        self.beneath.replay(replay)
    }

    fn claim(
        &self,
        journey: JourneyId,
        holder: &str,
        token: u128,
        lease: Duration,
    ) -> Result<Option<Claim>, PersistError> {
        self.asked(Operation::Claim)?;
        self.beneath.claim(journey, holder, token, lease)
    }

    fn renew(&self, claims: &[Claim], lease: Duration) -> Result<Vec<Claim>, PersistError> {
        self.asked(Operation::Renew)?;
        self.beneath.renew(claims, lease)
    }

    fn release(&self, claim: &Claim) -> Result<bool, PersistError> {
        self.beneath.release(claim)
    }

    fn hand_on(&self, hand_on: &HandOn) -> Result<bool, PersistError> {
        self.asked(Operation::HandOn)?;
        self.beneath.hand_on(hand_on)
    }

    fn write_audit(&self, entry: &AuditEntry) -> Result<(), PersistError> {
        self.beneath.write_audit(entry)
    }

    fn keep_audit(&self, most: u32) -> Result<u32, PersistError> {
        self.beneath.keep_audit(most)
    }

    fn read_kept_audit(&self, id: AuditId) -> Result<Option<AuditEntry>, PersistError> {
        self.beneath.read_kept_audit(id)
    }

    fn write_administration(&self, record: &AdministrationRecord) -> Result<(), PersistError> {
        self.asked(Operation::WriteAdministration)?;
        self.beneath.write_administration(record)
    }

    fn read_administration(
        &self,
        kind: AdministrationKind,
        id: u128,
    ) -> Result<Option<AdministrationRecord>, PersistError> {
        self.beneath.read_administration(kind, id)
    }

    fn remove_administration(
        &self,
        kind: AdministrationKind,
        id: u128,
    ) -> Result<(), PersistError> {
        self.beneath.remove_administration(kind, id)
    }

    fn query(&self, query: &Query) -> Result<Vec<u128>, PersistError> {
        self.beneath.query(query)
    }
}
