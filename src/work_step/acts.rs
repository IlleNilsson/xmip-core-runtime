//! What a turn's acts make: the work done on a Message — an Assignment, a
//! unit's call, a split — the Messages of a Batch made one, and a Message
//! published back through routing, each a new Message generation and
//! nothing edited (`doc/terminology.md`, *Message and Section*).
//!
//! The owner, 2026-10-22: *Transformation and Assignment where ever they
//! occur, creates a new message from a previous or created message.*

use std::collections::HashMap;

use journey::{ChainCause, ChainLimit, Journey, JourneyMessageRef};
use message::{Message, MessageCreationSource, MessageSection};
use process::program::{Call, Work};
use process::{Arrival, Event};
use route::Subscriber;
use xcore::{JourneyId, MessageId};

use super::keys::promoted;
use super::running::{Running, Thrown};
use crate::ledger::Opened;
use crate::message_path::Runtime;
use crate::pickup::Pickup;
use persist::storage::Hold;

/// What a turn has made so far: the Messages, by identifier, and which of
/// them are new; the Journeys it opened and the places they take.
#[derive(Default)]
pub(super) struct Made {
    pub(super) messages: HashMap<u128, Message>,
    pub(super) new: Vec<u128>,
    pub(super) opened: Vec<Journey>,
    pub(super) holds: Vec<Hold>,
}

impl Made {
    fn add(&mut self, message: Message) -> u128 {
        let id = message.message_id().value();
        self.new.push(id);
        self.messages.insert(id, message);
        id
    }

    /// The Message `id`, made in this turn or read from the Ledger.
    pub(super) fn message(&mut self, runtime: &Runtime<'_>, id: u128) -> Result<Message, String> {
        if let Some(message) = self.messages.get(&id) {
            return Ok(message.clone());
        }
        let message = crate::ledger::read_message(runtime.storage, MessageId::new(id))?
            .ok_or_else(|| format!("the Ledger holds no Message {id}"))?;
        self.messages.insert(id, message.clone());
        Ok(message)
    }
}

/// `work` done at `node` on the Message `on`: the event the flow takes next.
pub(super) fn work(
    runtime: &Runtime<'_>,
    running: &Running,
    made: &mut Made,
    (node, work, on): (u32, &Work, u128),
) -> Result<Event, String> {
    let message = made.message(runtime, on)?;
    let outcome = match work {
        Work::Assign(assignments) => {
            let context = assign::apply(message.context().clone(), assignments);
            Ok(vec![message.assigned(
                MessageId::new(runtime.ids.next_u128()),
                context,
            )])
        }
        Work::Unit(call) => running.units.call(call, &message, runtime.ids),
        Work::Debatch(call) => debatch(runtime, running, call, &message)?,
    };
    match outcome {
        Ok(messages) => {
            let made_now = messages
                .into_iter()
                .map(|message| arrival(running, made.add(message), made))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Event::Done {
                node,
                made: made_now,
            })
        }
        Err(thrown) => Ok(Event::Threw {
            node,
            code: thrown.code,
            reason: thrown.reason,
        }),
    }
}

/// `message` split by the unit `call` names, through the one splitting
/// implementation (`crate::split`): its parts, or — where the unit refused
/// any record, all or nothing — `split::REFUSED`, its reason the report:
/// a summary line, then each failed record's block, for the flow's scopes.
///
/// # Errors
/// A Section that could not be read, or a part Xmip Storage did not take.
fn debatch(
    runtime: &Runtime<'_>,
    running: &Running,
    call: &Call,
    message: &Message,
) -> Result<Result<Vec<Message>, Thrown>, String> {
    let mut split = match running.units.splitter(call) {
        Ok(split) => split,
        Err(thrown) => return Ok(Err(thrown)),
    };
    let unit = format!("unit '{}' of '{}'", call.unit, call.module);
    let parts = crate::split::whole(
        (runtime.storage, runtime.ids, runtime.chunk),
        message,
        (split.as_mut(), Some(unit)),
    )?;
    Ok(parts.map_err(|failures| Thrown {
        code: crate::split::REFUSED.to_string(),
        reason: failures.to_string(),
    }))
}

/// The Messages `messages` made one at `node`: their Sections in order,
/// the first one's context.
pub(super) fn combine(
    runtime: &Runtime<'_>,
    running: &Running,
    made: &mut Made,
    (node, messages): (u32, &[u128]),
) -> Result<Event, String> {
    let mut members = Vec::with_capacity(messages.len());
    for id in messages {
        members.push(made.message(runtime, *id)?);
    }
    let Some(first) = members.first() else {
        return Ok(Event::Done {
            node,
            made: Vec::new(),
        });
    };
    let sections: Vec<MessageSection> = members
        .iter()
        .flat_map(|member| member.sections().iter().cloned())
        .collect();
    let batch = first.transformed(
        MessageId::new(runtime.ids.next_u128()),
        sections,
        first.context().clone(),
        MessageCreationSource::Batch,
    );
    let id = made.add(batch);
    Ok(Event::Done {
        node,
        made: vec![arrival(running, id, made)?],
    })
}

/// The Message `id` as a turn sees it: the values the flow reads of it.
pub(super) fn arrival(running: &Running, id: u128, made: &Made) -> Result<Arrival, String> {
    let message = made
        .messages
        .get(&id)
        .ok_or("a Message the turn did not make")?;
    let promoted = promoted(&running.gathering, message)?;
    let values = running
        .flow
        .declared()
        .reads
        .iter()
        .filter_map(|name| {
            promoted
                .get(name)
                .map(|value| (name.clone(), value.to_string()))
        })
        .collect();
    Ok(Arrival {
        message: id,
        values,
        keys: Vec::new(),
    })
}

/// `message` published back through routing from `from`: a Journey for
/// every Subscription it matches, each following `from` in the chain and
/// held in its destination's queue, or held where its Subscription holds
/// it; refused where it matches none.
pub(super) fn publish(
    runtime: &Runtime<'_>,
    pickup: &Pickup,
    made: &mut Made,
    (from, body): (&Journey, &[u8]),
    message: u128,
) -> Result<(), String> {
    let published = made.message(runtime, message)?;
    let promoted = promoted(runtime.gathering, &published)?;
    let routing = route::publish(&promoted, runtime.subscriptions);
    let held = JourneyMessageRef {
        message_id: published.message_id(),
        stream_id: published.sections()[0].stream.id(),
    };
    let mut opened = Vec::new();
    for evaluation in routing.evaluations.iter().filter(|e| e.matched()) {
        let name = &evaluation.subscription_id;
        let cause = match &evaluation.destination {
            Subscriber::WorkProcess(process) => ChainCause::process(name, process),
            _ => ChainCause::subscription(name),
        };
        for to in pickup.reaches(name, &evaluation.destination) {
            let id = JourneyId::new(runtime.ids.next_u128());
            let mut journey = Journey::following(id, from, cause.clone(), ChainLimit::DEFAULT)
                .map_err(|refused| refused.to_string())?
                .holding(held);
            if let Subscriber::SendPort(port) = &to {
                journey.send_port = Some(port.clone());
            }
            opened.push(Opened {
                journey,
                subscription: name.clone(),
                to,
            });
        }
    }
    if opened.is_empty() {
        return Err(format!(
            "the Message {} it published matched no Subscription",
            published.message_id()
        ));
    }
    if !made.new.contains(&message) {
        made.new.push(message);
    }
    let cluster = runtime.work.cluster();
    let places = crate::sequence::places(cluster, runtime.sends, &mut opened, &promoted)?;
    made.holds.extend(places);
    let holding = pickup.holding(&opened, || body.to_vec());
    made.holds.extend(holding.holds().iter().cloned());
    for (journey, to) in holding.departing(&opened) {
        made.holds.push(Hold {
            queue: runtime.send.queue(to),
            journey: journey.journey_id(),
            body: body.to_vec(),
        });
    }
    made.opened
        .extend(opened.into_iter().map(|one| one.journey));
    Ok(())
}
