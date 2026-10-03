//! The gates' stand-ins the runtime's tests run a node with, and Xmip
//! Storage that fails on demand ([`Failing`]), once: its unit tests and its
//! integration tests (`tests/ledger`) both take them from here. Behind the `test-support` feature, which only a dev-dependency
//! enables, so they are never in a production build.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use authenticate::{AuthenticateError, Authenticator};
use authorize::{Attempt, Authorizer, Decision};
use context::{IdentityFacts, Verified};
use identify::Presented;
use persist::PersistError;
use persist::storage::{
    AdministrationKind, AdministrationRecord, AuditEntry, Claim, DeadEntry, DeadQueue, HandOn,
    HeldQueue, JourneyRecord, MessageRecord, Publication, Replay, Replayed, StreamChunk,
    XmipStorage,
};
use xcore::{AuditId, JourneyId, Layer, Mechanism, MessageId, StreamId, mechanism};

/// Verifies every claim of its mechanism with the verdict it was given.
pub struct Always(pub Mechanism, pub Verified);

impl Always {
    /// ADR-0019 clause 7: where nothing was presented, the circumstance is
    /// the transport identity, and is authenticated as that — claimed,
    /// since nothing cryptographic stands behind a loopback connection.
    #[must_use]
    pub fn circumstance() -> Self {
        Self(mechanism::circumstance(), Verified::Claimed)
    }
}

impl Authenticator for Always {
    fn mechanism(&self) -> Mechanism {
        self.0.clone()
    }

    fn verify(&self, _presented: &Presented) -> Result<Verified, AuthenticateError> {
        Ok(self.1)
    }
}

/// Allows what the gates authenticated. The estate's real policies are
/// technologies; this is the smallest thing that is not "nothing
/// configured", which permits nothing.
pub struct Open;

impl Authorizer for Open {
    fn name(&self) -> &str {
        "open"
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, _identity: &IdentityFacts, _attempt: &Attempt) -> Option<Decision> {
        Some(Decision::Allowed)
    }
}

/// An operation of Xmip Storage a [`Failing`] can be told to fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    Publish,
    ReadHeld,
    ReleaseHeld,
    ReadJourney,
    WriteJourney,
    ReadMessage,
    WriteAdministration,
    ReadDead,
    Replay,
}

/// Xmip Storage that fails on demand, as a Storage node that does not
/// answer: each operation told to fail does so the number of times it was
/// told, as `PersistError::Unreachable`, and every other call passes
/// through to the Storage beneath.
pub struct Failing {
    beneath: Arc<dyn XmipStorage>,
    failing: Mutex<BTreeMap<Operation, u32>>,
}

impl Failing {
    /// Failing nothing yet, over `beneath`.
    #[must_use]
    pub fn over(beneath: Arc<dyn XmipStorage>) -> Arc<Self> {
        Arc::new(Self {
            beneath,
            failing: Mutex::new(BTreeMap::new()),
        })
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

    fn publish(&self, publication: &Publication) -> Result<(), PersistError> {
        self.asked(Operation::Publish)?;
        self.beneath.publish(publication)
    }

    fn read_held(&self, queue: u128, from: u64, most: u32) -> Result<HeldQueue, PersistError> {
        self.asked(Operation::ReadHeld)?;
        self.beneath.read_held(queue, from, most)
    }

    fn release_held(
        &self,
        queue: u128,
        sequence: u64,
        journey: &JourneyRecord,
    ) -> Result<(), PersistError> {
        self.asked(Operation::ReleaseHeld)?;
        self.beneath.release_held(queue, sequence, journey)
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
        self.beneath.claim(journey, holder, token, lease)
    }

    fn renew(&self, claim: &Claim, lease: Duration) -> Result<Option<Claim>, PersistError> {
        self.beneath.renew(claim, lease)
    }

    fn release(&self, claim: &Claim) -> Result<bool, PersistError> {
        self.beneath.release(claim)
    }

    fn hand_on(&self, hand_on: &HandOn) -> Result<bool, PersistError> {
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
}
