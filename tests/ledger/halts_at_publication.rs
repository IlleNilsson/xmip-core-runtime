//! Xmip Storage that stops a receive at its Publication, so a kill lands
//! after the Stream's chunks and before anything of the Publication.

use std::sync::Arc;
use std::time::Duration;

use persist::PersistError;
use persist::storage::{
    AdministrationKind, AdministrationRecord, AuditEntry, Claim, DeadEntry, DeadQueue, HandOn,
    HeldQueue, JourneyRecord, MessageRecord, Publication, Query, Replay, Replayed, StreamChunk,
    XmipStorage,
};
use xcore::{AuditId, JourneyId, MessageId, StreamId};

use super::say;

/// Xmip Storage that lets every Stream chunk through and halts the receive
/// at its Publication, before anything of it is written, until the process
/// is killed.
struct HaltsAtPublication(Arc<dyn XmipStorage>);

/// `storage` halting every receive at its Publication.
pub fn halting(storage: Arc<dyn XmipStorage>) -> Arc<dyn XmipStorage> {
    Arc::new(HaltsAtPublication(storage))
}

impl XmipStorage for HaltsAtPublication {
    fn write_chunk(&self, chunk: &StreamChunk) -> Result<(), PersistError> {
        self.0.write_chunk(chunk)?;
        say(&format!("chunk {} {}", chunk.stream.value(), chunk.index));
        Ok(())
    }

    fn read_chunk(
        &self,
        stream: StreamId,
        index: u32,
    ) -> Result<Option<StreamChunk>, PersistError> {
        self.0.read_chunk(stream, index)
    }

    fn write_message(&self, message: &MessageRecord) -> Result<(), PersistError> {
        self.0.write_message(message)
    }

    fn publish(&self, publication: &Publication) -> Result<Vec<Claim>, PersistError> {
        say(&format!("halting {}", publication.message.message.value()));
        loop {
            std::thread::park();
        }
    }

    fn read_held(&self, queue: u128, from: u64, most: u32) -> Result<HeldQueue, PersistError> {
        self.0.read_held(queue, from, most)
    }

    fn read_dead(&self, queue: u128, from: u64, most: u32) -> Result<DeadQueue, PersistError> {
        self.0.read_dead(queue, from, most)
    }

    fn read_dead_message(
        &self,
        queue: u128,
        message: MessageId,
    ) -> Result<DeadEntry, PersistError> {
        self.0.read_dead_message(queue, message)
    }

    fn replay(&self, replay: &Replay) -> Result<Replayed, PersistError> {
        self.0.replay(replay)
    }

    fn read_message(&self, message: MessageId) -> Result<Option<MessageRecord>, PersistError> {
        self.0.read_message(message)
    }

    fn write_journey(&self, journey: &JourneyRecord) -> Result<(), PersistError> {
        self.0.write_journey(journey)
    }

    fn read_journey(&self, journey: JourneyId) -> Result<Option<JourneyRecord>, PersistError> {
        self.0.read_journey(journey)
    }

    fn claim(
        &self,
        journey: JourneyId,
        holder: &str,
        token: u128,
        lease: Duration,
    ) -> Result<Option<Claim>, PersistError> {
        self.0.claim(journey, holder, token, lease)
    }

    fn renew(&self, claims: &[Claim], lease: Duration) -> Result<Vec<Claim>, PersistError> {
        self.0.renew(claims, lease)
    }

    fn release(&self, claim: &Claim) -> Result<bool, PersistError> {
        self.0.release(claim)
    }

    fn hand_on(&self, hand_on: &HandOn) -> Result<bool, PersistError> {
        self.0.hand_on(hand_on)
    }

    fn write_audit(&self, entry: &AuditEntry) -> Result<(), PersistError> {
        self.0.write_audit(entry)
    }

    fn keep_audit(&self, most: u32) -> Result<u32, PersistError> {
        self.0.keep_audit(most)
    }

    fn read_kept_audit(&self, id: AuditId) -> Result<Option<AuditEntry>, PersistError> {
        self.0.read_kept_audit(id)
    }

    fn write_administration(&self, record: &AdministrationRecord) -> Result<(), PersistError> {
        self.0.write_administration(record)
    }

    fn read_administration(
        &self,
        kind: AdministrationKind,
        id: u128,
    ) -> Result<Option<AdministrationRecord>, PersistError> {
        self.0.read_administration(kind, id)
    }

    fn remove_administration(
        &self,
        kind: AdministrationKind,
        id: u128,
    ) -> Result<(), PersistError> {
        self.0.remove_administration(kind, id)
    }

    fn query(&self, query: &Query) -> Result<Vec<u128>, PersistError> {
        self.0.query(query)
    }
}
