//! An operator's acts on a Journey that failed: Retry and Dismiss
//! (`runtime-model.md` section 13: *Retry resumes from the failed audited
//! stage of the same Journey … an authorized operator may retry after
//! automatic retries are exhausted and the underlying fault is fixed*;
//! *Dismiss intentionally terminates a Journey without deleting its
//! history*; ADR-0013, amendment 2026-08-26, `Dismissed`).
//!
//! **Each is one hand-on under a claim**, through Xmip Storage, so it is the
//! one writer of its Journey while it acts and a repeat after a lost answer
//! writes nothing twice:
//!
//! - **Retry** writes the Journey Active again, its tries begun anew, and
//!   moves it to the end of its Send Port's queue, from where the Send pool
//!   takes it up as it takes up every Journey; where it blocks a Sequential
//!   Send Port (`on_failure = "block"`) it keeps its place, so its sequence
//!   goes on in order from it.
//! - **Dismiss** writes it Dismissed — terminal, its history, its Message
//!   and its Stream kept — and lets go of its place, so on a Sequential
//!   Send Port the next of its order key goes.
//!
//! An act is taken by a node that sends the Journey's Send Port, the one
//! whose figures showed it failed: that node knows whether the Port blocks.
//! Who may act is the surface's to decide by role; the node applies what
//! reaches it and audits it with who acted.

use std::collections::BTreeMap;
use std::str::FromStr;

use journey::{Attempts, Journey, JourneyEntry, JourneyState};
use observe::{Act, Noun};
use persist::storage::HandOn;
use route::Subscriber;
use xcore::{
    Clock, ExecutionId, ExecutionPhase, IdGenerator, JourneyId, MessageId, Severity, SystemClock,
    UuidV7Generator,
};

use super::SendStep;
use super::pass::record;

impl SendStep {
    /// Retry or dismiss the Journey `journey` (its identifier), by `who`,
    /// and say what came of it once it is written. Audited.
    ///
    /// # Errors
    /// REFUSED, in words, for an act a Journey does not take, what names no
    /// Journey, one that has not failed, and one this node does not send;
    /// FAILED where Xmip Storage did not answer or take it, and nothing
    /// changed.
    pub fn act(&self, journey: &str, act: Act, who: &str) -> Result<String, String> {
        let act = Noun::Journey.act(act.word())?;
        let id = JourneyId::from_str(journey)
            .map_err(|_| format!("REFUSED: '{journey}' names no Journey"))?;
        let not_done = |problem: &str| self.not_done(act, id, problem);
        let kept = match self.storage.read_journey(id) {
            Ok(Some(record)) => Journey::from_record(&record.body)
                .map_err(|why| format!("REFUSED: the Journey {id} cannot be read: {why}"))?,
            Ok(None) => return Err(format!("REFUSED: no Journey {id} is in the Ledger")),
            Err(error) => return Err(not_done(&error.to_string())),
        };
        if act == Act::Dismiss && kept.state == JourneyState::Dismissed {
            return Ok(format!("Journey {id} was dismissed already"));
        }
        if kept.state != JourneyState::Failed {
            return Err(format!(
                "REFUSED: the Journey {id} is {:?}, not Failed; only a Journey that failed \
                 is retried or dismissed",
                kept.state
            ));
        }
        let Some(port) = kept.send_port.clone() else {
            return Err(format!("REFUSED: the Journey {id} leads to no Send Port"));
        };
        let Some(blocks) = self.lock().ports.get(&port).copied() else {
            return Err(format!(
                "REFUSED: {} sends no Send Port {port}; act on the node that sends it",
                self.node
            ));
        };
        let queue = self.queue(&Subscriber::SendPort(port.clone()));
        let token = UuidV7Generator.next_u128();
        let claim = match self.storage.claim(id, &self.node, token, self.lease) {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                return Err(format!(
                    "REFUSED: the Journey {id} is claimed by another; act again once it is free"
                ));
            }
            Err(error) => return Err(not_done(&error.to_string())),
        };
        let said = match act {
            Act::Retry => format!("Journey {id} retried by {who}; sent again from {port}'s queue"),
            _ => format!("Journey {id} dismissed by {who}; its history is kept"),
        };
        let acted = acted(kept, act, &said);
        let retry = act == Act::Retry;
        let hand_on = HandOn {
            claim: claim.clone(),
            result: record(&acted),
            messages: Vec::new(),
            next: Vec::new(),
            leaves: if retry { Vec::new() } else { vec![queue] },
            queued: Vec::new(),
            requeued: if retry && !blocks {
                vec![queue]
            } else {
                Vec::new()
            },
            kept_for_nanos: None,
        };
        match self.storage.hand_on(&hand_on) {
            Ok(true) => {}
            Ok(false) => return Err(not_done("its claim lapsed before it was written")),
            Err(error) => {
                let _ = self.storage.release(&claim);
                return Err(not_done(&error.to_string()));
            }
        }
        self.lock().passed.retain(|(passed, _)| *passed != id);
        self.ask(queue);
        self.audited(act, id, (who, &port), &said);
        Ok(said)
    }

    fn audited(&self, act: Act, id: JourneyId, (who, port): (&str, &str), said: &str) {
        let Some(audit) = &self.audit else {
            return;
        };
        let properties = BTreeMap::from([
            ("node".to_string(), self.node.clone()),
            ("journey".to_string(), id.to_string()),
            ("send_port".to_string(), port.to_string()),
            ("by".to_string(), who.to_string()),
        ]);
        let action = Noun::Journey.action(act);
        let phase = ExecutionPhase::Execute;
        let _ = audit.record(
            &action,
            phase,
            Severity::Information,
            Some(said),
            properties,
        );
    }

    /// FAILED, said and audited: nothing of the act was written.
    fn not_done(&self, act: Act, id: JourneyId, problem: &str) -> String {
        let said = format!(
            "FAILED: the Journey {id} is not {}: Xmip Storage did not take it: {problem}",
            if act == Act::Retry {
                "retried"
            } else {
                "dismissed"
            }
        );
        if let Some(audit) = &self.audit {
            let _ = audit.failed(
                &Noun::Journey.action(act),
                &format!("{}: {said}", self.node),
            );
        }
        said
    }
}

/// `kept` as `act` leaves it: Active again with its tries begun anew, or
/// Dismissed, the act appended to its history in words.
fn acted(kept: Journey, act: Act, said: &str) -> Journey {
    let message_id = kept
        .messages()
        .last()
        .map(|held| held.message_id)
        .unwrap_or(MessageId::new(0));
    let state = if act == Act::Retry {
        JourneyState::Active
    } else {
        JourneyState::Dismissed
    };
    let mut acted = kept.append(
        JourneyEntry {
            execution_id: ExecutionId::new(UuidV7Generator.next_u128()),
            message_id,
            action: act.word().to_string(),
            outcome: said.to_string(),
            timestamp_unix_nanos: SystemClock.unix_timestamp_nanos(),
        },
        state,
    );
    if act == Act::Retry {
        acted.attempts = Attempts::default();
    }
    acted
}
