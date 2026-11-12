//! A turn written (`super`): the Journey, what the turn made, the Instance
//! and its correlation keys, in one hand-on — or the Message written Failed,
//! kept in its queue for an operator, by the one failure writer
//! ([`failed`]): a flow's uncaught error, a turn that could not be taken,
//! and a turn that panicked ([`panicked`]; ADR-0066, amendment 2026-11-12).

use journey::{Journey, JourneyState};
use persist::storage::{
    Claim, Failure, HandOn, Held, InstanceKey, InstanceRecord, InstanceWrite, Turn, Wait,
};
use process::{Instance, Outcome, form};

use super::super::acts::Made;
use super::super::running::Running;
use super::{Taking, Turned};
use crate::generation::ReceivedWork;
use crate::ledger::{journey_record, message_record};
use crate::message_path::Runtime;

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
        let mut hand_on = hand_on(&self.claim, &journey, std::mem::take(&mut self.made));
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

    /// `work` written Failed with `why`, kept in its queue for an operator,
    /// nothing the turn made with it.
    pub(super) fn fail(&mut self, work: Box<ReceivedWork>, why: &str) -> Turned {
        self.made = Made::default();
        failed((self.runtime, self.running), &self.claim, work.journey, why)
    }
}

/// The hand-on of `journey` under `claim`, with what the turn `made`.
fn hand_on(claim: &Claim, journey: &Journey, made: Made) -> HandOn {
    HandOn {
        claim: claim.clone(),
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

/// `journey`, of `running`'s queue, written Failed with `why` under
/// `claim`, kept in its queue for an operator: `Failed` where written,
/// waiting where its claim was another's — a turn whose write landed ended
/// its claim, so nothing written is overwritten — and unwritten where Xmip
/// Storage did not take it.
fn failed(
    (runtime, running): (&Runtime<'_>, &Running),
    claim: &Claim,
    mut journey: Journey,
    why: &str,
) -> Turned {
    journey.state = JourneyState::Failed;
    journey.current_work_process = Some(running.name.clone());
    let mut hand_on = hand_on(claim, &journey, Made::default());
    hand_on.failed = Some(Failure {
        queue: running.queue,
        reason: why.to_string(),
    });
    match runtime.storage.hand_on(&hand_on) {
        Ok(true) => Turned::Failed(why.to_string()),
        Ok(false) => Turned::Waits {
            why: "its claim was another's".to_string(),
            on: Vec::new(),
        },
        Err(failed) => Turned::Unwritten(failed.to_string()),
    }
}

/// The turn of the Message `held` names, which panicked under `claim`
/// having `said` what it said, written Failed with it, the Journey read
/// again under the claim and no Message touched — one may be what
/// panicked. Where the Journey cannot be read, or Xmip Storage does not
/// take the write, its claim is given back and it is unwritten, taken up
/// again at once (as the send step abandons a send).
pub(super) fn panicked(
    runtime: &Runtime<'_>,
    running: &Running,
    (held, claim): (&Held, &Claim),
    said: &str,
) -> Turned {
    let why = format!("its turn panicked: {said}");
    let read = runtime.storage.read_journey(held.hold.journey);
    let journey = match read {
        Ok(Some(record)) => Journey::from_record(&record.body).map_err(|e| e.to_string()),
        Ok(None) => Err("the Ledger holds no such Journey".to_string()),
        Err(not) => Err(not.to_string()),
    };
    let unread = match journey {
        Ok(journey) => match failed((runtime, running), claim, journey, &why) {
            Turned::Unwritten(not) => not,
            turned => return turned,
        },
        Err(not) => not,
    };
    let _ = runtime.storage.release(claim);
    Turned::Unwritten(format!(
        "{}: the Journey {}: {why}, and it was not written Failed ({unread}); \
         its claim given back",
        running.name, held.hold.journey
    ))
}
