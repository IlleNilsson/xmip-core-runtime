//! A turn written (`super`): the Journey, what the turn made, the Instance
//! and its correlation keys, in one hand-on — or the Message written Failed,
//! kept in its queue for an operator.

use journey::{Journey, JourneyState};
use persist::storage::{Failure, HandOn, InstanceKey, InstanceRecord, InstanceWrite, Turn, Wait};
use process::{Instance, Outcome, form};

use super::super::acts::Made;
use super::{Taking, Turned};
use crate::generation::ReceivedWork;
use crate::ledger::{journey_record, message_record};

impl Taking<'_> {
    /// The turn as one write: the Journey, what was made, the Instance and
    /// its correlations, and the Message kept with a due time where a timer
    /// waits.
    pub(super) fn written(
        &mut self,
        work: ReceivedWork,
        (instance_id, over): (u128, u64),
        instance: Instance,
        ended: Option<Outcome>,
        now: i128,
    ) -> Turn {
        let queue = self.running.queue;
        let mut journey: Journey = work.journey;
        journey.current_work_process = Some(self.running.name.clone());
        let mut hand_on = self.hand_on(&journey);
        let due = instance.next_due().filter(|_| ended.is_none());
        match (&ended, due) {
            (Some(Outcome::Failed { code, reason }), _) => {
                journey.state = JourneyState::Failed;
                hand_on.failed = Some(Failure {
                    queue,
                    reason: format!("{} threw {code}: {reason}", self.running.name),
                });
            }
            (_, Some(due)) => {
                journey.state = JourneyState::Waiting;
                let after = u64::try_from(due.saturating_sub(now)).unwrap_or(0);
                hand_on.waits = Some(Wait {
                    queue,
                    after_nanos: after,
                });
            }
            _ => {
                journey.state = JourneyState::Completed;
                hand_on.leaves.push(queue);
            }
        }
        if let Some((point, skips)) = self.point {
            let done = journey.state == JourneyState::Completed;
            if done || (journey.state == JourneyState::Failed && skips) {
                hand_on.leaves.push(point);
            }
        }
        hand_on.result = journey_record(&journey);
        let correlations: Vec<u128> = instance
            .keys
            .iter()
            .map(|key| self.correlation(key))
            .collect();
        let finished = ended.is_some();
        let owned: Vec<InstanceKey> = correlations
            .iter()
            .map(|key| InstanceKey {
                key: *key,
                instance: instance_id,
            })
            .collect();
        Turn {
            hand_on,
            instances: vec![InstanceWrite {
                record: InstanceRecord {
                    instance: instance_id,
                    work_process: self.running.name.clone(),
                    turns: instance.turns.max(over + 1),
                    ended: finished,
                    body: form::instance(&instance),
                },
                over,
            }],
            keys: if finished { Vec::new() } else { owned.clone() },
            unkeyed: if finished { owned } else { Vec::new() },
        }
    }

    /// The hand-on of `journey`, with what the turn made.
    fn hand_on(&mut self, journey: &Journey) -> HandOn {
        let made = std::mem::take(&mut self.made);
        HandOn {
            claim: self.claim.clone(),
            result: journey_record(journey),
            messages: made
                .new
                .iter()
                .filter_map(|id| made.messages.get(id))
                .map(message_record)
                .collect(),
            next: made.opened.iter().map(journey_record).collect(),
            leaves: Vec::new(),
            queued: made.holds,
            requeued: Vec::new(),
            failed: None,
            cleared: Vec::new(),
            waits: None,
            kept_for_nanos: None,
        }
    }

    /// `work` written Failed with `why`, kept in its queue for an operator.
    pub(super) fn fail(&mut self, work: Box<ReceivedWork>, why: &str) -> Turned {
        self.made = Made::default();
        let mut journey = work.journey;
        journey.state = JourneyState::Failed;
        journey.current_work_process = Some(self.running.name.clone());
        let mut hand_on = self.hand_on(&journey);
        hand_on.failed = Some(Failure {
            queue: self.running.queue,
            reason: why.to_string(),
        });
        match self.runtime.storage.hand_on(&hand_on) {
            Ok(true) => Turned::Failed(why.to_string()),
            Ok(false) => Turned::Waits {
                why: "its claim was another's".to_string(),
                on: Vec::new(),
            },
            Err(failed) => Turned::Unwritten(failed.to_string()),
        }
    }
}
