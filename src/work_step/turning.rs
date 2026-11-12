//! One turn of one Instance: the Message claimed, its Instance read from
//! the Ledger, the unit advanced and its acts carried out until it waits
//! or ends, and all of it handed on in one write (`XmipStorage::turn`).
//!
//! **A turn that panics ends Failed** (ADR-0066, amendment 2026-11-12):
//! everything after its claim is caught at the turn's boundary — the flow,
//! a unit's call or split, the runtime's own acts and the turn's write —
//! and the Journey written Failed with what the panic said, through the
//! write a flow's uncaught error takes (`written::panicked`), or its claim
//! given back where that cannot be written. The write is made after the
//! catch, never while unwinding.

use std::panic::{self, AssertUnwindSafe};

use journey::JourneyState;
use persist::storage::{Claim, Held, InstanceRecord, Position, Turn, Watched, named};
use process::{Act, Event, Instance, Outcome, Refused, form};

use super::acts::{self, Made};
use super::keys::promoted;
use super::running::Running;
use crate::generation::ReceivedWork;
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use crate::send_step::{Found, read};
use crate::sequence::{Placing, behind, waits_on};

mod written;

/// The most acts one turn carries out: a flow that keeps asking for work
/// without waiting is stopped, never run forever.
const MOST_ACTS: usize = 10_000;

/// How a turn ended.
#[derive(Debug)]
pub enum Turned {
    /// Written: the Instance moved on.
    Done,
    /// Not now, its claim given back, `why`: another holds it, its Stream does not head its
    /// sequence, no step of its Instance waits for it, its Instance moved on since it was read,
    /// or another Instance took a key it starts by — taken again, it joins that one. And `on`,
    /// what it waits on: a sequence's head, the Instance as it read it, each key it correlates
    /// by that no Instance holds — taken up the moment any node moves one, at once where one
    /// moved already (open problem 46, 2026-11-12); none where another holds it, or it is no
    /// Message to take a turn of.
    Waits { why: String, on: Vec<Position> },
    /// Written Failed with why, kept in its queue for an operator.
    Failed(String),
    /// Xmip Storage did not take it, in words.
    Unwritten(String),
}

/// The Message `held` names by its Journey, of `running`'s queue, taken a turn of on one
/// Storage node: its claim, its reads, the Streams it splits and its write (`Runtime::over`).
pub(super) fn turn(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    running: &Running,
    held: &Held,
) -> Turned {
    let step = runtime.work;
    let statement = persist::storage::statement(&step.storage);
    let runtime = &runtime.over(&statement);
    let (id, token) = (held.hold.journey, runtime.ids.next_u128());
    let claim = match runtime.storage.claim(id, &step.node, token, step.lease) {
        Ok(Some(claim)) => claim,
        Ok(None) => {
            return Turned::Waits {
                why: "another holds it".to_string(),
                on: Vec::new(),
            };
        }
        Err(why) => return Turned::Unwritten(why.to_string()),
    };
    let turned = || claimed((runtime, pickup), running, held, &claim);
    match panic::catch_unwind(AssertUnwindSafe(turned)) {
        Ok(turned) => turned,
        Err(thrown) => {
            let said = crate::pool::said(thrown.as_ref());
            written::panicked(runtime, running, (held, &claim), &said)
        }
    }
}

/// The turn of the Message `held` names, under `claim`: its Instance found
/// and advanced, its acts carried out and all of it written, or its claim
/// given back where it waits.
fn claimed(
    (runtime, pickup): (&Runtime<'_>, &Pickup),
    running: &Running,
    held: &Held,
    claim: &Claim,
) -> Turned {
    let step = runtime.work;
    let id = held.hold.journey;
    let waits = |why: &str| Turned::Waits {
        why: why.to_string(),
        on: Vec::new(),
    };
    let release = |why: String, on: Vec<Position>| {
        let _ = runtime.storage.release(claim);
        Turned::Waits { why, on }
    };
    let mut work = match read(runtime, id, &held.hold.body) {
        Ok(Found::Waiting(found)) => found.0,
        Ok(_) => return release("it is not one to take a turn of".to_string(), Vec::new()),
        Err(why) => return release(why, Vec::new()),
    };
    // Its place at the Work Process, taken once its Stream heads its own.
    let to = route::Subscriber::WorkProcess(running.name.clone());
    let configured = (step.cluster(), runtime.sends, runtime.gathering);
    let at = (&mut work.journey, &work.message, &to);
    let lease = (claim, step.lease);
    match crate::sequence::heading(runtime.storage.as_ref(), configured, at, lease) {
        Ok(Placing::Placed) => {}
        Ok(Placing::Behind) => {
            let on = behind(runtime.storage.as_ref(), &work.journey).unwrap_or_default();
            return release("its Stream waits behind another".to_string(), on);
        }
        Ok(Placing::Lost) => return waits("its claim was another's"),
        Err(why) => return release(why, Vec::new()),
    }
    // A Message bound for a Work Process holds one place at it: the Work
    // Process's own sequence, where it names a set.
    let point = work
        .journey
        .sequences
        .first()
        .map(|sequenced| (sequenced.queue, sequenced.skips));
    if let Some((queue, _)) = point {
        match waits_on(runtime.storage.as_ref(), queue, id.value()) {
            Ok(None) => {}
            Ok(Some(head)) => {
                let why = "it waits behind another at its Work Process".to_string();
                return release(why, vec![head]);
            }
            Err(why) => return release(why, Vec::new()),
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
        on: Vec::new(),
    };
    match taking.take(work) {
        Ok(Some(turn)) => match runtime.storage.turn(&turn) {
            Ok(true) => Turned::Done,
            Ok(false) => release(
                "its Instance moved on since it was read, or another took its key".to_string(),
                taking.on,
            ),
            Err(why) => Turned::Unwritten(why.to_string()),
        },
        Ok(None) => release(
            "no step of its Instance waits for it".to_string(),
            taking.on,
        ),
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
    /// a Correlation, and whether a failure lets it go.
    point: Option<(u128, bool)>,
    /// What it waits on where its Instance does not take it, or its write
    /// finds the Instance moved: the Instance as it read it, and — where no
    /// key named one — each key it correlates by, held by no Instance.
    on: Vec<Position>,
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
        self.on = self.waits_for((instance_id, over), &work, &keys);
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

    /// What a turn of `work` over the Instance `instance`, read at the turn
    /// `over`, waits on where that Instance does not take it, or moved since:
    /// the Instance, and where it is the one `work` started — no key of
    /// `keys` naming one — each key, held by none.
    fn waits_for(
        &self,
        (instance, over): (u128, u64),
        work: &ReceivedWork,
        keys: &[(u32, String)],
    ) -> Vec<Position> {
        let mut on = vec![Position {
            watched: Watched::Instance(instance),
            at: over,
        }];
        if instance == work.journey.journey_id().value() {
            on.extend(keys.iter().map(|key| Position {
                watched: Watched::Key(self.correlation(key)),
                at: 0,
            }));
        }
        on
    }

    /// The Instance `work` belongs to: the one a key of its correlates to,
    /// else the one it started, by its Journey.
    fn instance(
        &self,
        work: &ReceivedWork,
        keys: &[(u32, String)],
    ) -> Result<(u128, Option<InstanceRecord>), String> {
        let storage = self.runtime.storage;
        for key in keys {
            if let Some(instance) = storage
                .read_instance_key(self.correlation(key))
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
}
