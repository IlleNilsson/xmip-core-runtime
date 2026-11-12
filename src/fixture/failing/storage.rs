//! Xmip Storage's operations through a [`Failing`]: each it can be told to
//! fail asked, counted and timed (`super`), every other passed through.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use persist::PersistError;
use persist::storage::{
    AdministrationKind, AdministrationRecord, AuditEntry, Claim, Claimed, DeadEntry, DeadQueue,
    DuePart, DueQueue, Durable, FailedQueue, HandOn, HeldQueue, JourneyRecord, KeptAudit,
    MessageRecord, Moved, Position, Publication, Query, Replay, Replayed, StreamChunk,
    StreamRecord, Waiter, XmipStorage,
};
use xcore::lock::Locked;
use xcore::{AuditId, JourneyId, MessageId, StreamId};

use super::{Failing, Operation};

impl XmipStorage for Failing {
    fn write_chunk(&self, chunk: &StreamChunk) -> Result<(), PersistError> {
        self.beneath.write_chunk(chunk)
    }

    fn read_chunk(
        &self,
        stream: StreamId,
        index: u32,
    ) -> Result<Option<StreamChunk>, PersistError> {
        let asked = self.asked(Operation::ReadChunk)?;
        let answer = self.beneath.read_chunk(stream, index);
        self.answered(Operation::ReadChunk, asked, answer)
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
        let asked = self.asked(Operation::ReadMessage)?;
        let answer = self.beneath.read_message(message);
        self.answered(Operation::ReadMessage, asked, answer)
    }

    fn write_journey(&self, journey: &JourneyRecord) -> Result<(), PersistError> {
        let asked = self.asked(Operation::WriteJourney)?;
        let answer = self.beneath.write_journey(journey);
        self.answered(Operation::WriteJourney, asked, answer)
    }

    fn read_journey(&self, journey: JourneyId) -> Result<Option<JourneyRecord>, PersistError> {
        let asked = self.asked(Operation::ReadJourney)?;
        let answer = self.beneath.read_journey(journey);
        self.answered(Operation::ReadJourney, asked, answer)
    }

    fn publish(&self, publication: Publication) -> Result<(Vec<Claim>, Durable), PersistError> {
        let asked = self.asked(Operation::Publish)?;
        let lost = self.lost.locked().take();
        if let Some(meanwhile) = lost {
            self.beneath.publish(publication.clone())?.1.wait()?;
            meanwhile();
        }
        let answer = self.beneath.publish(publication);
        self.answered(Operation::Publish, asked, answer)
    }

    fn read_held(&self, queue: u128, from: u64, most: u32) -> Result<HeldQueue, PersistError> {
        let asked = self.asked(Operation::ReadHeld)?;
        let answer = self.beneath.read_held(queue, from, most);
        self.answered(Operation::ReadHeld, asked, answer)
    }

    /// Asked as each read it stands for, failing as any of them is told to,
    /// and answered as one, as the Storage beneath answers it.
    fn read_claimed(
        &self,
        queue: u128,
        at: u64,
        journey: JourneyId,
    ) -> Result<Claimed, PersistError> {
        for read in [
            Operation::ReadHeld,
            Operation::ReadJourney,
            Operation::ReadMessage,
        ] {
            self.asked(read)?;
        }
        let asked = self.asked(Operation::ReadClaimed)?;
        let answer = self.beneath.read_claimed(queue, at, journey);
        self.answered(Operation::ReadClaimed, asked, answer)
    }

    fn read_failed(&self, queue: u128, from: u64, most: u32) -> Result<FailedQueue, PersistError> {
        let asked = self.asked(Operation::ReadFailed)?;
        let answer = self.beneath.read_failed(queue, from, most);
        self.answered(Operation::ReadFailed, asked, answer)
    }

    fn read_due(
        &self,
        q: u128,
        p: DuePart,
        f: (u64, u64),
        m: u32,
    ) -> Result<DueQueue, PersistError> {
        let asked = self.asked(Operation::ReadDue)?;
        let answer = self.beneath.read_due(q, p, f, m);
        self.answered(Operation::ReadDue, asked, answer)
    }

    fn wait_queues(
        &self,
        seen: &[Position],
        wait: (Duration, u32),
        waiter: &Arc<Waiter>,
    ) -> Result<Vec<Moved>, PersistError> {
        let asked = self.asked(Operation::WaitQueues)?;
        if self.at_once.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }
        let answer = self.beneath.wait_queues(seen, wait, waiter);
        self.answered(Operation::WaitQueues, asked, answer)
    }

    fn read_dead(&self, queue: u128, from: u64, most: u32) -> Result<DeadQueue, PersistError> {
        let asked = self.asked(Operation::ReadDead)?;
        let answer = self.beneath.read_dead(queue, from, most);
        self.answered(Operation::ReadDead, asked, answer)
    }

    fn read_dead_message(
        &self,
        queue: u128,
        message: MessageId,
    ) -> Result<DeadEntry, PersistError> {
        let asked = self.asked(Operation::ReadDead)?;
        let answer = self.beneath.read_dead_message(queue, message);
        self.answered(Operation::ReadDead, asked, answer)
    }

    fn replay(&self, replay: &Replay) -> Result<Replayed, PersistError> {
        let asked = self.asked(Operation::Replay)?;
        let answer = self.beneath.replay(replay);
        self.answered(Operation::Replay, asked, answer)
    }

    fn claim(
        &self,
        journey: JourneyId,
        holder: &str,
        token: u128,
        lease: Duration,
    ) -> Result<Option<Claim>, PersistError> {
        let asked = self.asked(Operation::Claim)?;
        let answer = self.beneath.claim(journey, holder, token, lease);
        self.answered(Operation::Claim, asked, answer)
    }

    /// Asked, counted and timed as a claim: its answer, never its sync.
    fn claim_ahead(
        &self,
        journey: JourneyId,
        holder: &str,
        token: u128,
        lease: Duration,
    ) -> Result<(Option<Claim>, Durable), PersistError> {
        let asked = self.asked(Operation::Claim)?;
        let answer = self.beneath.claim_ahead(journey, holder, token, lease);
        self.answered(Operation::Claim, asked, answer)
    }

    fn renew(&self, claims: &[Claim], lease: Duration) -> Result<Vec<Claim>, PersistError> {
        let asked = self.asked(Operation::Renew)?;
        let answer = self.beneath.renew(claims, lease);
        self.answered(Operation::Renew, asked, answer)
    }

    fn release(&self, claim: &Claim) -> Result<bool, PersistError> {
        self.beneath.release(claim)
    }

    fn turn(&self, turn: &persist::storage::Turn) -> Result<bool, PersistError> {
        self.beneath.turn(turn)
    }

    fn read_instance(
        &self,
        instance: u128,
    ) -> Result<Option<persist::storage::InstanceRecord>, PersistError> {
        self.beneath.read_instance(instance)
    }

    fn read_instance_key(&self, correlation: u128) -> Result<Option<u128>, PersistError> {
        self.beneath.read_instance_key(correlation)
    }

    fn hand_on(&self, hand_on: &HandOn) -> Result<bool, PersistError> {
        let asked = self.asked(Operation::HandOn)?;
        let answer = self.beneath.hand_on(hand_on);
        self.answered(Operation::HandOn, asked, answer)
    }

    fn write_audit(&self, entry: &AuditEntry) -> Result<(), PersistError> {
        self.beneath.write_audit(entry)
    }

    fn keep_audit(&self, most: u32, chunk: usize) -> Result<u32, PersistError> {
        self.beneath.keep_audit(most, chunk)
    }

    fn read_kept_audit(&self, id: AuditId) -> Result<Option<KeptAudit>, PersistError> {
        self.beneath.read_kept_audit(id)
    }

    fn read_kept_audit_stream(
        &self,
        id: AuditId,
        stream: StreamId,
    ) -> Result<Option<StreamRecord>, PersistError> {
        self.beneath.read_kept_audit_stream(id, stream)
    }

    fn read_kept_audit_chunk(
        &self,
        id: AuditId,
        stream: Option<StreamId>,
        index: u32,
    ) -> Result<Option<Vec<u8>>, PersistError> {
        self.beneath.read_kept_audit_chunk(id, stream, index)
    }

    fn write_administration(&self, record: &AdministrationRecord) -> Result<(), PersistError> {
        let asked = self.asked(Operation::WriteAdministration)?;
        let answer = self.beneath.write_administration(record);
        self.answered(Operation::WriteAdministration, asked, answer)
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

    fn write_secret(&self, secret: &persist::storage::SecretRecord) -> Result<(), PersistError> {
        self.beneath.write_secret(secret)
    }

    fn read_secret(
        &self,
        name: &xcore::SecretName,
    ) -> Result<Option<persist::storage::SecretRecord>, PersistError> {
        self.beneath.read_secret(name)
    }

    fn list_secrets(&self) -> Result<Vec<persist::storage::SecretEntry>, PersistError> {
        self.beneath.list_secrets()
    }

    fn query(&self, query: &Query) -> Result<Vec<u128>, PersistError> {
        self.beneath.query(query)
    }
}
