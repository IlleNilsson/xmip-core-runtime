//! An operator's acts on a Message that failed at a Work Process: Retry
//! and Dismiss (`runtime-model.md` sections 13 and 22: *kept in its Work
//! Process's queue for an operator's Retry or Dismiss*; ADR-0066, amendment
//! 2026-11-25; open problem 193). The acts a failed Message takes at a Send
//! Port, through the same rules (`crate::journey_act`), noun `message`, its
//! Journey's identifier, asked at any node's door and applied by the node
//! that runs the Work Process (`crate::applied`).
//!
//! **Each is one write under a claim** on the Message, so it is the one
//! writer of its Journey while it acts:
//!
//! - **Retry** writes the Journey Active, its tries begun anew, and moves
//!   it to the end of its Work Process's queue, from where the step takes
//!   its turn again; one whose failed turn was its timer's is written
//!   Waiting instead, due now, at its place. Where its turn failed its
//!   Instance, that turn alone takes the Instance on again, from where it
//!   stood before it (`super::turning`): every other Message of its key
//!   waits until then.
//! - **Dismiss** writes it Dismissed — terminal, its history, Message and
//!   Stream kept — and lets go of its queue and its places; where its turn
//!   failed its Instance, the Instance ends in the same write, its keys let
//!   go, its history saying who dismissed it.
//!
//! Either takes it out of its queue's index of failed Messages.

use std::str::FromStr;

use journey::{Journey, JourneyState};
use observe::{Act, Noun};
use persist::storage::{Claim, InstanceKey, InstanceRecord, InstanceWrite, Turn, Wait};
use process::{Handling, Instance, form};
use xcore::{IdGenerator, JourneyId, UuidV7Generator};

use super::WorkStep;
use super::acts::Made;
use super::running::Running;
use super::turning::written::{entry, hand_on};
use crate::journey_act::{self, Acting, acted, claimed_by_another, dismissed};

/// The Instance a Journey's turn failed: its identifier, its record and its
/// state.
type Failed = (u128, InstanceRecord, Instance);

impl WorkStep {
    /// Whether the Journey `journey` is at a Work Process this node runs:
    /// the one its acts are applied by.
    #[must_use]
    pub fn holds(&self, journey: &str) -> bool {
        let Ok(id) = JourneyId::from_str(journey) else {
            return false;
        };
        let Ok(Some(record)) = self.storage.read_journey(id) else {
            return false;
        };
        Journey::from_record(&record.body).is_ok_and(|kept| {
            kept.send_port.is_none()
                && kept
                    .current_work_process
                    .as_deref()
                    .is_some_and(|name| self.runs(name))
        })
    }

    /// Retry or dismiss the Message whose Journey is `journey`, failed at a
    /// Work Process this node runs, by `who`, and say what came of it once
    /// it is written. Audited.
    ///
    /// # Errors
    /// REFUSED, in words, for an act a failed Message does not take, what
    /// names no Journey, one whose Message has not failed, and one this node
    /// does not run the Work Process of; FAILED where Xmip Storage did not
    /// answer or take it, and nothing changed.
    pub fn act(&self, journey: &str, act: Act, who: &str) -> Result<String, String> {
        let act = Noun::Message.act(act.word())?;
        let id = JourneyId::from_str(journey)
            .map_err(|_| format!("REFUSED: '{journey}' names no Journey"))?;
        let acting = self.acting();
        let (seen, kept) = acting.kept(act, id)?;
        if act == Act::Dismiss && kept.state == JourneyState::Dismissed {
            return Ok(format!(
                "The Message of the Journey {id} was dismissed already"
            ));
        }
        let running = self.failed_here(id, &kept)?;
        let token = UuidV7Generator.next_u128();
        let claim = match self.storage.claim(id, &self.node, token, self.lease) {
            Ok(Some(claim)) => claim,
            Ok(None) => return Err(claimed_by_another(id)),
            Err(error) => return Err(acting.not_done(act, id, &error.to_string())),
        };
        let released = |said: String| {
            let _ = self.storage.release(&claim);
            Err(said)
        };
        if let Err(refused) = acting.unchanged(act, id, &seen) {
            return released(refused);
        }
        let failed = match self.failed_by(running, &kept) {
            Ok(failed) => failed,
            Err(problem) => return released(acting.not_done(act, id, &problem)),
        };
        let said = said(act, (id, who), running, failed.is_some());
        match self.written(running, act, (&claim, kept), failed, &said) {
            Ok(true) => {}
            Ok(false) => {
                return Err(acting.not_done(act, id, "its claim lapsed before it was written"));
            }
            Err(problem) => return released(acting.not_done(act, id, &problem)),
        }
        self.acted_on(running);
        acting.audited((act, id), (who, ("work_process", &running.name)), &said);
        Ok(said)
    }

    /// This step's [`Acting`].
    fn acting(&self) -> Acting<'_> {
        Acting {
            node: &self.node,
            storage: self.storage.as_ref(),
            audit: self.audit.as_ref(),
        }
    }

    /// The Work Process this node runs that `kept`, the Journey `id`, failed
    /// at: refused, in words, where it has not failed or this node runs no
    /// such Work Process.
    fn failed_here(&self, id: JourneyId, kept: &Journey) -> Result<&Running, String> {
        journey_act::failed(id, kept)?;
        let Some(name) = kept.current_work_process.as_deref() else {
            return Err(format!(
                "REFUSED: the Message of the Journey {id} failed at no Work Process"
            ));
        };
        self.running
            .iter()
            .find(|running| running.name == name)
            .ok_or_else(|| {
                format!(
                    "REFUSED: {} runs no Work Process {name}; act on a node that runs it",
                    self.node
                )
            })
    }

    /// The Instance the turn of `kept` failed, where it failed one: found by
    /// its Message's keys as its turn found it, and failed by this Journey.
    fn failed_by(&self, running: &Running, kept: &Journey) -> Result<Option<Failed>, String> {
        let id = kept.journey_id().value();
        let Some(held) = kept.messages().last() else {
            return Ok(None);
        };
        let message = crate::ledger::read_message(&self.storage, held.message_id)?
            .ok_or_else(|| format!("the Ledger holds no Message {}", held.message_id))?;
        let keys = running.keys(kept, &message)?;
        let (instance, record) = running.instance(self.storage.as_ref(), id, &keys)?;
        let Some(record) = record.filter(|record| !record.ended) else {
            return Ok(None);
        };
        let state: Instance = form::read(&record.body).map_err(|why| why.to_string())?;
        Ok((state.failed_by() == Some(id)).then_some((instance, record, state)))
    }

    /// `act` on `kept` under `claim`, written as one: the Journey as the act
    /// leaves it, and the Instance it failed ended where it is dismissed.
    /// Whether the claim was still its holder's.
    fn written(
        &self,
        running: &Running,
        act: Act,
        (claim, kept): (&Claim, Journey),
        failed: Option<Failed>,
        said: &str,
    ) -> Result<bool, String> {
        let queue = running.queue;
        let retry = act == Act::Retry;
        let due = failed
            .as_ref()
            .is_some_and(|(_, _, state)| failed_when_due(state, kept.journey_id().value()));
        let mut after = acted(kept, act, said);
        if retry && due {
            after.state = JourneyState::Waiting;
        }
        let mut hand_on = hand_on(claim, &after, Made::default());
        hand_on.cleared = vec![queue];
        if retry {
            if due {
                hand_on.waits = Some(Wait {
                    queue,
                    after_nanos: 0,
                });
            } else {
                hand_on.requeued = vec![queue];
            }
        } else {
            hand_on.leaves = std::iter::once(queue)
                .chain(crate::sequence::let_go(&after))
                .collect();
        }
        let Some((instance, record, mut state)) = failed.filter(|_| !retry) else {
            let written = self.storage.hand_on(hand_on).map_err(|e| e.to_string())?;
            return Ok(written.0);
        };
        // Dismissed, the Instance its turn failed ends with it.
        let now = self.clock.unix_timestamp_nanos();
        let journey = after.journey_id().value();
        let message = after
            .messages()
            .last()
            .map_or(0, |held| held.message_id.value());
        state.handled(entry(now, Handling::Dismissed, message, journey));
        let unkeyed = state
            .keys
            .iter()
            .map(|key| InstanceKey {
                key: running.correlation(key),
                instance,
            })
            .collect();
        let turn = Turn {
            hand_on,
            instances: vec![InstanceWrite {
                record: InstanceRecord {
                    turns: record.turns + 1,
                    ended: true,
                    body: form::instance(&state),
                    ..record.clone()
                },
                over: record.turns,
            }],
            keys: Vec::new(),
            unkeyed,
        };
        self.storage.turn(&turn).map_err(|e| e.to_string())
    }

    /// An act on a Message of `running` written: its queue read again, and
    /// what this node publishes of its failed Messages read again with it.
    fn acted_on(&self, running: &Running) {
        self.window_moved(running);
        self.ask(running.queue);
    }
}

/// Whether the turn of the Journey `journey` that failed `state` was its
/// timer's: the event its history says that turn took.
fn failed_when_due(state: &Instance, journey: u128) -> bool {
    state
        .history
        .iter()
        .rev()
        .filter(|entry| entry.journey == journey)
        .skip_while(|entry| entry.what != Handling::Failed)
        .find(|entry| {
            matches!(
                entry.what,
                Handling::Due | Handling::Arrived | Handling::Started
            )
        })
        .is_some_and(|entry| entry.what == Handling::Due)
}

/// What an act says once written.
fn said(act: Act, (id, who): (JourneyId, &str), running: &Running, instance: bool) -> String {
    match (act, instance) {
        (Act::Retry, true) => format!(
            "The Message of the Journey {id} retried by {who}; its turn of the Instance it \
             failed is taken again from {}'s queue",
            running.name
        ),
        (Act::Retry, false) => format!(
            "The Message of the Journey {id} retried by {who}; turned again from {}'s queue",
            running.name
        ),
        (_, true) => format!("{}, and the Instance it failed ended", dismissed(id, who)),
        (_, false) => dismissed(id, who),
    }
}
