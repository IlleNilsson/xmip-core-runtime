//! The node's Dead Message Queue as an operator sees it, and Replay, the
//! Operator's act on one of its Messages once a Subscription is added or
//! fixed (ADR-0013, amendment 2026-10-01; ADR-0052, amendment 2026-10-01).
//!
//! **A Replay routes the Message again**, its promoted properties as they
//! were kept against the node's Subscriptions of now, and opens a Journey
//! for each that matches, as its Publication would have. Every one is held
//! at the end of its Subscription's queue, since no receive cycle is left
//! to depart from: the node picks each up from there as a resume does, and
//! a paused Subscription keeps it until it is resumed. The Journeys, the
//! holds and the audit record of the write go to Xmip Storage with the
//! entry taken out, as one write (`persist::storage::Replay`); a Replay
//! asked again after a lost answer writes nothing twice. A Message that
//! still matches nothing stays where it is, and the refusal says why.

use std::collections::BTreeMap;
use std::str::FromStr;

use journey::{Journey, JourneyMessageRef};
use observe::{Act, Noun};
use persist::storage::{AuditEntry, DeadEntry, Replay, Replayed, dead_message_queue};
use route::{Promoted, publish};
use xaudit::audit_record::AuditRecord;
use xcore::{
    AuditId, Clock, ExecutionPhase, IdGenerator, MessageId, Severity, SystemClock, UuidV7Generator,
};

use super::Pickup;
use crate::dead_message;

/// The most of its Dead Message Queue a node publishes: the oldest.
pub const PUBLISHED: u32 = 100;

/// The refusal of a Replay of what the queue of `node` never kept.
fn never(node: &str, id: MessageId) -> String {
    format!("REFUSED: the Dead Message Queue of {node} never kept a Message {id}")
}

impl Pickup {
    /// How many Messages this node's Dead Message Queue keeps, and up to
    /// `most` of them, oldest first, as the node publishes them.
    ///
    /// # Errors
    /// In words, where Xmip Storage did not answer.
    pub fn dead_messages(&self, most: u32) -> Result<(u64, Vec<observe::DeadMessage>), String> {
        let queue = dead_message_queue(&self.node);
        let read = self
            .storage
            .read_dead(queue, 0, most)
            .map_err(|error| format!("the Dead Message Queue of {}: {error}", self.node))?;
        Ok((
            read.count,
            read.dead.iter().map(dead_message::published).collect(),
        ))
    }

    /// Replay the Message `message` (its identifier) from this node's Dead
    /// Message Queue, by `who`, and say what came of it. Audited.
    ///
    /// # Errors
    /// REFUSED, in words, for what names no Message, a Message the queue
    /// does not keep, and one that still matches no Subscription; FAILED
    /// where Xmip Storage did not answer or take the write, and nothing
    /// changed.
    pub fn replay(&self, message: &str, who: &str) -> Result<String, String> {
        let node = &self.node;
        let id = MessageId::from_str(message)
            .map_err(|_| format!("REFUSED: '{message}' names no Message"))?;
        let queue = dead_message_queue(node);
        let entry = match self.storage.read_dead_message(queue, id) {
            Ok(DeadEntry::Kept(dead)) => dead.message,
            Ok(DeadEntry::Replayed) => return Ok(format!("Message {id} was replayed already")),
            Ok(DeadEntry::Never) => return Err(never(node, id)),
            Err(error) => return Err(self.not_replayed(id, &error.to_string())),
        };
        let promoted = entry
            .promoted
            .iter()
            .fold(Promoted::new(), |promoted, one| {
                promoted.set(&one.name, &one.value)
            });
        let subscriptions: Vec<route::Subscription> = self
            .lock()
            .entries
            .iter()
            .map(|entry| entry.configured.subscription.clone())
            .collect();
        let routing = publish(&promoted, &subscriptions);
        let ids = UuidV7Generator;
        let held = JourneyMessageRef {
            message_id: id,
            stream_id: entry.stream,
        };
        let opened = crate::ledger::opened(&routing, self, held, &ids);
        let journeys: Vec<Journey> = opened.iter().map(|o| o.journey.clone()).collect();
        if journeys.is_empty() {
            let why: Vec<String> = routing
                .declines()
                .iter()
                .map(|(name, why)| format!("'{name}': {why}"))
                .collect();
            return Err(format!(
                "REFUSED: the Message {id} still matches no Subscription on {node}, and stays \
                 in its Dead Message Queue; {}",
                if why.is_empty() {
                    "no Subscription is configured".to_string()
                } else {
                    why.join("; ")
                }
            ));
        }
        let holding = self.held(&opened, || entry.body.clone(), true);
        let replay = Replay {
            queue,
            message: id,
            journeys: journeys.iter().map(crate::ledger::journey_record).collect(),
            held: holding.holds().to_vec(),
            audit: self.replayed_record(id, &journeys, who, &ids),
        };
        match self.storage.replay(&replay) {
            Ok(Replayed::Now) => {
                self.published(&holding);
                let said = format!(
                    "Message {id} replayed by {who}: {} Journey(s) opened, picked up from \
                     their Subscriptions' queues oldest first",
                    journeys.len()
                );
                self.audited_replay(id, who, journeys.len(), &said);
                Ok(said)
            }
            Ok(Replayed::Before) => Ok(format!("Message {id} was replayed already")),
            Ok(Replayed::Absent) => Err(never(node, id)),
            Err(error) => Err(self.not_replayed(id, &error.to_string())),
        }
    }

    /// The audit record the Replay's write keeps (ADR-0062, amendment
    /// 2026-10-01), in the audit capability's own form.
    fn replayed_record(
        &self,
        id: MessageId,
        journeys: &[Journey],
        who: &str,
        ids: &dyn IdGenerator,
    ) -> AuditEntry {
        let opened: Vec<String> = journeys
            .iter()
            .map(|j| j.journey_id().to_string())
            .collect();
        let properties = BTreeMap::from([
            ("node".to_string(), self.node.clone()),
            ("message".to_string(), id.to_string()),
            ("by".to_string(), who.to_string()),
            ("journeys".to_string(), opened.join(",")),
        ]);
        let record = AuditRecord {
            audit_id: AuditId::new(ids.next_u128()),
            origin: crate::running::origin(self.audit.as_ref(), &self.node),
            scope: None,
            action: Noun::DeadMessage.action(Act::Replay),
            phase: ExecutionPhase::Finished,
            severity: Severity::Information,
            timestamp_unix_nanos: SystemClock.unix_timestamp_nanos(),
            message: None,
            properties,
        };
        crate::ledger::audit_entry(&record)
    }

    fn audited_replay(&self, id: MessageId, who: &str, opened: usize, said: &str) {
        let Some(audit) = &self.audit else {
            return;
        };
        let properties = BTreeMap::from([
            ("node".to_string(), self.node.clone()),
            ("message".to_string(), id.to_string()),
            ("by".to_string(), who.to_string()),
            ("journeys".to_string(), opened.to_string()),
        ]);
        let action = Noun::DeadMessage.action(Act::Replay);
        let phase = ExecutionPhase::Execute;
        let _ = audit.record(
            &action,
            phase,
            Severity::Information,
            Some(said),
            properties,
        );
    }

    /// FAILED, said and audited: nothing of the Replay was written.
    fn not_replayed(&self, id: MessageId, problem: &str) -> String {
        self.failed("dead-message.replay", problem);
        format!("FAILED: the Message {id} is not replayed: Xmip Storage did not answer: {problem}")
    }
}
