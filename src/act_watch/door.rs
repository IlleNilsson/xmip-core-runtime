//! A node's door for operator acts (`super`): what its operate listener
//! hands an act it admitted, by the caller's own role, to be written to
//! Xmip Storage asked of the node that owns what it acts on, and answered
//! with what that node decided (ADR-0014 and ADR-0056, amendments
//! 2026-11-13).
//!
//! **Who carries it.** Where the owning node runs in this process — its act
//! watch is here — the act is written through that node's Xmip Storage,
//! whatever this node declares: a node without the operational role still
//! takes acts on itself (the owner, 2026-11-12). Where it does not, only a
//! node declaring the operational role writes it
//! (`node::Capability::carries_acts`, read from its roles and never from a
//! name); every other refuses in words, naming the role.
//!
//! **What the asker is told.** The door waits on the act's decision
//! ([`Watched::Act`]) for at most `[tuning] operate_act`, [`OPERATE_ACT`]
//! where it says nothing, and answers the owning node's own decision and
//! sentence — or `asked`, where the bound passed first: the act stays asked
//! in Xmip Storage, never expiring, and its node takes it as soon as it
//! runs.

use std::sync::Arc;
use std::time::Duration;

use node::Scope;
use observe::Order;
use persist::storage::{ActOutcome, ActRecord, Position, Waiter, Watched, XmipStorage};
use xcore::{IdGenerator, UuidV7Generator};

use super::ActWatch;
use crate::plane::Role;
use crate::plane::grant::Presented;

/// How long a door holds the asker's call while the owning node takes the
/// act, where `[tuning] operate_act` says nothing.
pub const OPERATE_ACT: Duration = Duration::from_secs(1);

/// Who asks a call of a node's operate listener, and so an act at its
/// door: the caller its gate proved — or, where a relay called for one,
/// that caller as the node holds it — how it proved them, the role granted
/// that very caller, none where none is, and the relay it came through.
#[derive(Clone, Copy, Debug)]
pub struct Asker<'a> {
    pub who: &'a str,
    /// The mechanism that proved them: `mutual-tls` or `peer-credentials`.
    pub proven: &'a str,
    /// What they presented, which their role is read from by the one rule
    /// (`plane::grant::Grants::of`).
    pub presented: &'a Presented,
    pub role: Option<Role>,
    pub through: Option<&'a str>,
}

/// One node's door.
pub struct Door {
    /// The node it is; none for a listener a program hosts through the C
    /// ABI, which is no node's.
    node: Option<String>,
    /// Whether it declares the operational role.
    carries: bool,
    /// Its own Xmip Storage, what it writes an act for another node
    /// through.
    storage: Option<Arc<dyn XmipStorage>>,
    within: Duration,
}

impl Door {
    /// The door of no node: an act is written only where the node it is
    /// asked of runs in this process.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            node: None,
            carries: false,
            storage: None,
            within: OPERATE_ACT,
        }
    }

    /// The door of the node at `node` declaring `capability`, writing an
    /// act for another node through `storage`, holding an asker's call at
    /// most `within`.
    #[must_use]
    pub fn of(
        node: &str,
        capability: &node::Capability,
        storage: Arc<dyn XmipStorage>,
        within: Duration,
    ) -> Self {
        Self {
            node: Some(node.to_string()),
            carries: capability.carries_acts(),
            storage: Some(storage),
            within,
        }
    }

    /// `order`, admitted by `asker`'s role already, written asked of the
    /// node it names and answered: that node's decision and sentence, or
    /// `asked` where it did not decide within this door's bound; refused in
    /// words where this door carries no act to it, failed where Xmip
    /// Storage did not take it.
    #[must_use]
    pub fn ask(&self, order: &Order, asker: Asker<'_>) -> (ActOutcome, String) {
        let node = order.node.as_str();
        let owner = ActWatch::running(node);
        let storage = match (&owner, self.carries, &self.storage) {
            (Some(owner), _, _) => Arc::clone(owner.storage()),
            (None, true, Some(storage)) => Arc::clone(storage),
            _ => return (ActOutcome::Refused, carried_by_none(node)),
        };
        let act = ActRecord {
            act: UuidV7Generator.next_u128(),
            node: node.to_string(),
            noun: order.noun.word().to_string(),
            target: order.target.clone(),
            word: order.act.word().to_string(),
            who: asker.who.to_string(),
            proven: asker.proven.to_string(),
            certificate: asker.presented.certificate().map(<[u8]>::to_vec),
            role: asker.role.map_or("none", Role::word).to_string(),
            through: asker.through.map(str::to_string),
            door: self.node.clone().unwrap_or_else(|| node.to_string()),
            ..ActRecord::default()
        };
        match storage.ask_act(&act) {
            Ok(asked) => self.answered(storage.as_ref(), &asked),
            Err(failed) => (
                ActOutcome::Failed,
                format!(
                    "FAILED: the act was not asked of {node}; Xmip Storage did not take it: \
                     {failed}"
                ),
            ),
        }
    }

    /// What became of `asked` within this door's bound: told by the wait
    /// on its decision, read once that moved or the bound passed.
    fn answered(&self, storage: &dyn XmipStorage, asked: &ActRecord) -> (ActOutcome, String) {
        let watched = [Position {
            watched: Watched::Act(asked.act),
            at: 0,
        }];
        let waiter = Arc::new(Waiter::new());
        // An answer with nothing moved, or none, is read as it stands.
        let _ = storage.wait_queues(&watched, (self.within, 0), &waiter);
        let page = (asked.place.saturating_sub(1), 1);
        let decided = storage
            .read_acts(&asked.node, page, false)
            .ok()
            .and_then(|acts| acts.into_iter().find(|act| act.act == asked.act))
            .filter(|act| !act.is_asked());
        match decided {
            Some(act) => (act.outcome, act.said),
            None => (ActOutcome::Asked, still_asked(&asked.node)),
        }
    }
}

/// What the asker is told of an act its node did not decide within the
/// door's bound.
fn still_asked(node: &str) -> String {
    let name = named(node);
    format!("asked of {name}; not taken yet; {name} takes it as soon as it runs")
}

/// The refusal of an act for a node that does not run in this process, at
/// a door that declares no operational role.
fn carried_by_none(node: &str) -> String {
    format!(
        "REFUSED: no node at {node} runs in this process, and this node declares no \
         operational role, so it carries no act to another node; ask {} itself, or a node \
         declaring the operational role (ADR-0056)",
        named(node)
    )
}

/// The node's name, the last of its scope, or the scope where it names
/// none.
fn named(node: &str) -> String {
    Scope::new(node)
        .node()
        .filter(|name| !name.is_empty())
        .map_or_else(|| node.to_string(), str::to_string)
}
