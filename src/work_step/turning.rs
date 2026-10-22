//! One turn of one Instance: the Journey claimed, its Instance read from
//! the Ledger, the unit advanced and its acts carried out until it waits
//! or ends, and all of it handed on in one write (`XmipStorage::turn`).

use journey::{Journey, JourneyState};
use persist::storage::{
    Claim, Correlation, Failure, HandOn, Held, InstanceRecord, InstanceWrite, Turn, Wait, named,
};
use process::{Act, Event, Instance, Outcome, Refused, form};

use super::acts::{self, Made};
use super::keys::promoted;
use super::running::Running;
use crate::generation::ReceivedWork;
use crate::ledger::{journey_record, message_record};
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use crate::send_step::{Found, read};
use crate::sequence::{heads, stream_heads};

/// The most acts one turn carries out: a flow that keeps asking for work
/// without waiting is stopped, never run forever.
const MOST_ACTS: usize = 10_000;

/// How a turn ended.
#[derive(Debug)]
pub enum Turned {
    /// Written: the Instance moved on.
    Done,
    /// Not now, its claim given back: another holds it, its Stream does not
    /// head its sequence, no step of its Instance waits for it, or its
    /// Instance moved on since it was read.
    Waits(String),
    /// Written Failed with why, kept in its queue for an operator.
    Failed(String),
    /// Xmip Storage did not take it, in words.
    Unwritten(String),
}

/// The Journey `held` names, of `running`'s queue, taken a turn of.
pub(super) fn turn(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    running: &Running,
    held: &Held,
) -> Turned {
    let step = runtime.work;
    let id = held.hold.journey;
    let token = runtime.ids.next_u128();
    let claim = match step.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => claim,
        Ok(None) => return Turned::Waits("another holds it".to_string()),
        Err(why) => return Turned::Unwritten(why.to_string()),
    };
    let release = |why: String| {
        let _ = step.storage.release(&claim);
        Turned::Waits(why)
    };
    let work = match read(runtime, id, &held.hold.body) {
        Ok(Found::Waiting(found)) => found.0,
        Ok(_) => return release("it is not one to take a turn of".to_string()),
        Err(why) => return release(why),
    };
    match stream_heads(step.storage.as_ref(), &work.journey) {
        Ok(true) => {}
        Ok(false) => return release("its Stream waits behind another".to_string()),
        Err(why) => return release(why),
    }
    let point = work
        .journey
        .sequence
        .map(|sequenced| (sequenced.queue, sequenced.skips));
    if let Some((queue, _)) = point {
        match heads(step.storage.as_ref(), queue, id.value()) {
            Ok(true) => {}
            Ok(false) => return release("it waits behind another at its Work Process".to_string()),
            Err(why) => return release(why),
        }
    }
    let mut taking = Taking {
        runtime,
        pickup,
        running,
        claim: claim.clone(),
        body: &held.hold.body,
        made: Made::default(),
        point,
    };
    match taking.take(work) {
        Ok(Some(turn)) => match step.storage.turn(&turn) {
            Ok(true) => Turned::Done,
            Ok(false) => release("its Instance moved on since it was read".to_string()),
            Err(why) => Turned::Unwritten(why.to_string()),
        },
        Ok(None) => release("no step of its Instance waits for it".to_string()),
        Err((work, why)) => taking.fail(work, &why),
    }
}

/// A turn under way.
struct Taking<'a> {
    runtime: &'a Runtime<'a>,
    pickup: &'a Pickup,
    running: &'a Running,
    claim: Claim,
    body: &'a [u8],
    made: Made,
    /// Its place in its Work Process's sequence, where the Work Process names
    /// a correlation set, and whether a failure lets it go.
    point: Option<(u128, bool)>,
}

type Taken = Result<Option<Turn>, (Box<ReceivedWork>, String)>;

impl Taking<'_> {
    /// The turn `work` takes, ready to write; `None` where its Instance
    /// does not take it now.
    fn take(&mut self, work: ReceivedWork) -> Taken {
        let fail = |work: &ReceivedWork, why: String| Err((Box::new(work.clone()), why));
        let keys = match self.keys(&work) {
            Ok(keys) => keys,
            Err(why) => return fail(&work, why),
        };
        let (instance_id, record) = match self.instance(&work, &keys) {
            Ok(found) => found,
            Err(why) => return fail(&work, why),
        };
        let over = record.as_ref().map_or(0, |record| record.turns);
        let mut instance = match &record {
            Some(record) if !record.ended => match form::read::<Instance>(&record.body) {
                Ok(instance) => instance,
                Err(why) => return fail(&work, why.to_string()),
            },
            _ => Instance::new(),
        };
        let message = work.message.message_id().value();
        self.made.messages.insert(message, work.message.clone());
        let event = if work.journey.state == JourneyState::Waiting {
            Event::Due
        } else {
            let mut arrival = match acts::arrival(self.running, message, &self.made) {
                Ok(arrival) => arrival,
                Err(why) => return fail(&work, why),
            };
            arrival.keys = keys;
            Event::Arrived(arrival)
        };
        let now = self.runtime.clock.unix_timestamp_nanos();
        let ended = match self.advance(&work, &mut instance, event, now) {
            Ok(Some(ended)) => Some(ended),
            Ok(None) => None,
            Err(Refused::NotWaiting) => return Ok(None),
            Err(Refused::Ended) => Some(Outcome::Completed),
            Err(Refused::Unfit(why)) => return fail(&work, why),
        };
        Ok(Some(self.written(
            work,
            (instance_id, over),
            instance,
            ended,
            now,
        )))
    }

    /// `work`'s key in each set the Work Process follows that it has every
    /// key part of.
    fn keys(&self, work: &ReceivedWork) -> Result<Vec<(u32, String)>, String> {
        let promoted = promoted(&self.running.gathering, &work.message)?;
        let mut keys = Vec::new();
        for (number, set) in self.running.sets.iter().enumerate() {
            if let Ok(key) = set.text(&work.journey, &promoted, &self.running.name) {
                keys.push((u32::try_from(number).unwrap_or(u32::MAX), key));
            }
        }
        Ok(keys)
    }

    /// The correlation key `key` of the set numbered `set`: its identifier,
    /// named from the Work Process, the set and the key's full values.
    fn correlation(&self, (set, key): &(u32, String)) -> u128 {
        let name = self
            .running
            .sets
            .get(*set as usize)
            .map_or("", |set| set.name.as_str());
        named(&format!(
            "{}/work-process/{}/correlation/{name}/{key}",
            self.runtime.work.cluster, self.running.name
        ))
    }

    /// The Instance `work` belongs to: the one a key of its correlates to,
    /// else the one it started, by its Journey.
    fn instance(
        &self,
        work: &ReceivedWork,
        keys: &[(u32, String)],
    ) -> Result<(u128, Option<InstanceRecord>), String> {
        let storage = &self.runtime.work.storage;
        for key in keys {
            if let Some(instance) = storage
                .read_correlation(self.correlation(key))
                .map_err(|why| why.to_string())?
            {
                let record = storage
                    .read_instance(instance)
                    .map_err(|why| why.to_string())?;
                return Ok((instance, record));
            }
        }
        let instance = work.journey.journey_id().value();
        let record = storage
            .read_instance(instance)
            .map_err(|why| why.to_string())?;
        Ok((instance, record))
    }

    /// `instance` advanced on `event` and every act carried out, until no
    /// work is asked for: how it ended, where it did.
    fn advance(
        &mut self,
        work: &ReceivedWork,
        instance: &mut Instance,
        event: Event,
        now: i128,
    ) -> Result<Option<Outcome>, Refused> {
        let mut events = vec![event];
        let mut ended = None;
        let mut carried = 0;
        while let Some(event) = events.pop() {
            let acts = self.running.flow.advance(instance, &event, now)?;
            for act in acts {
                carried += 1;
                if carried > MOST_ACTS {
                    return Err(Refused::Unfit(format!(
                        "it asked for more than {MOST_ACTS} acts"
                    )));
                }
                let next = match act {
                    Act::Work {
                        node,
                        work: asked,
                        message,
                    } => acts::work(
                        self.runtime,
                        self.running,
                        &mut self.made,
                        (node, &asked, message),
                    ),
                    Act::Combine { node, messages } => acts::combine(
                        self.runtime,
                        self.running,
                        &mut self.made,
                        (node, &messages),
                    ),
                    Act::Publish { message } => {
                        let from = (&work.journey, self.body);
                        acts::publish(self.runtime, self.pickup, &mut self.made, from, message)
                            .map_err(Refused::Unfit)?;
                        continue;
                    }
                    Act::Ended(outcome) => {
                        ended = Some(outcome);
                        continue;
                    }
                };
                events.insert(0, next.map_err(Refused::Unfit)?);
            }
        }
        Ok(ended)
    }

    /// The turn as one write: the Journey, what was made, the Instance and
    /// its correlations, and the Journey kept with a due time where a timer
    /// waits.
    fn written(
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
            correlations: if finished {
                Vec::new()
            } else {
                correlations
                    .iter()
                    .map(|correlation| Correlation {
                        correlation: *correlation,
                        instance: instance_id,
                    })
                    .collect()
            },
            uncorrelated: if finished { correlations } else { Vec::new() },
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
    fn fail(&mut self, work: Box<ReceivedWork>, why: &str) -> Turned {
        self.made = Made::default();
        let mut journey = work.journey;
        journey.state = JourneyState::Failed;
        journey.current_work_process = Some(self.running.name.clone());
        let mut hand_on = self.hand_on(&journey);
        hand_on.failed = Some(Failure {
            queue: self.running.queue,
            reason: why.to_string(),
        });
        match self.runtime.work.storage.hand_on(&hand_on) {
            Ok(true) => Turned::Failed(why.to_string()),
            Ok(false) => Turned::Waits("its claim was another's".to_string()),
            Err(failed) => Turned::Unwritten(failed.to_string()),
        }
    }
}
