//! An operator's act on a node running in this process, applied once,
//! whichever way it came: an order the node took from its `orders`
//! directory (`xmip-service`), or an act that reached the node's operate
//! listener over the network (ADR-0014, amendment 2026-10-12).
//!
//! The node is found by its scope among the nodes this process runs —
//! their pickups and send steps as registered — and the act is that
//! node's: a pause or resume of a Subscription and a Replay from its Dead
//! Message Queue are its pickup's, a Retry or Dismiss of a Journey its
//! send step's; each records itself in the node's audit with who acted.
//! A node of this process keeps no Event subscription hub, so an act on
//! an Event subscription is refused in words.

use observe::{Act, Noun, Order};

use crate::pickup::Pickup;
use crate::send_step::SendStep;

/// What came of an act, with the sentence that says so.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Applied {
    /// Taken.
    Taken(String),
    /// Refused, opening REFUSED: no such node here, nothing of that name,
    /// or an act the thing does not take now.
    Refused(String),
    /// Not tried, opening FAILED: Xmip Storage did not answer and nothing
    /// changed.
    Failed(String),
}

impl Applied {
    /// The sentence, whatever came of it.
    #[must_use]
    pub fn said(&self) -> &str {
        match self {
            Self::Taken(said) | Self::Refused(said) | Self::Failed(said) => said,
        }
    }

    /// Taken as `Ok`, anything else as `Err`, each with its sentence.
    ///
    /// # Errors
    ///
    /// The sentence of a refusal or a failure.
    pub fn into_result(self) -> Result<String, String> {
        match self {
            Self::Taken(said) => Ok(said),
            Self::Refused(said) | Self::Failed(said) => Err(said),
        }
    }

    /// What an act's own answer says: FAILED for a failure, a refusal
    /// otherwise.
    fn of(answer: Result<String, String>) -> Self {
        match answer {
            Ok(said) => Self::Taken(said),
            Err(said) if said.starts_with("FAILED") => Self::Failed(said),
            Err(said) => Self::Refused(said),
        }
    }
}

/// Apply `order` to the node of this process it names, by its `who`.
#[must_use]
pub fn apply(order: &Order) -> Applied {
    let node = order.node.as_str();
    let absent = || Applied::Refused(format!("REFUSED: no node at {node} runs in this process"));
    match order.noun {
        Noun::Subscription | Noun::DeadMessage => {
            let Some(pickup) = Pickup::registered()
                .into_iter()
                .find(|pickup| pickup.node() == node)
            else {
                return absent();
            };
            Applied::of(if order.act == Act::Replay {
                pickup.replay(&order.target, &order.who)
            } else {
                pickup.act(&order.target, order.act, &order.who)
            })
        }
        Noun::Journey => SendStep::registered()
            .into_iter()
            .find(|step| step.node() == node)
            .map_or_else(absent, |step| {
                Applied::of(step.act(&order.target, order.act, &order.who))
            }),
        Noun::EventSubscription => Applied::Refused(format!(
            "REFUSED: {node} keeps no Event subscription hub; the Event subscription '{}' is \
             another process's",
            order.target
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(noun: Noun, act: Act) -> Order {
        Order {
            node: crate::fixture::absent_node(),
            noun,
            target: "t".to_string(),
            act,
            who: "CN=tester".to_string(),
        }
    }

    #[test]
    fn a_node_not_in_this_process_is_refused_in_words() {
        for (noun, act) in [
            (Noun::Subscription, Act::Pause),
            (Noun::DeadMessage, Act::Replay),
            (Noun::Journey, Act::Retry),
        ] {
            let applied = apply(&order(noun, act));
            let node = crate::fixture::absent_node();
            assert_eq!(
                applied,
                Applied::Refused(format!("REFUSED: no node at {node} runs in this process"))
            );
        }
    }

    #[test]
    fn an_event_subscription_is_another_processes() {
        let applied = apply(&order(Noun::EventSubscription, Act::Pause));
        assert!(applied.said().contains("keeps no Event subscription hub"));
    }
}
