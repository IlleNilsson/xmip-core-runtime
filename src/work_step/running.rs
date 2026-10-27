//! One Work Process this node runs: its unit opened as a flow, the
//! correlation sets it follows read from the cluster's, the names its
//! decisions and its keys read compiled once, and its queue.

use std::sync::Arc;

use message::Message;
use process::Flow;
use process::program::Call;
use route::{Gathering, Source, Subscriber};
use xcore::IdGenerator;

use super::keys::ResolvedSet;
use crate::split::Split;

/// What a Work Process's work on a Message calls: the units a step names
/// by module and unit (ADR-0066, amendment 2026-10-22), handed in, never
/// looked up by name here.
pub trait WorkUnits: Send + Sync {
    /// `call` done on `message`: the Messages it made, the one the flow
    /// goes on with first.
    ///
    /// # Errors
    /// What it threw: its code and why, caught by the flow's scopes.
    fn call(
        &self,
        call: &Call,
        message: &Message,
        ids: &dyn IdGenerator,
    ) -> Result<Vec<Message>, Thrown>;

    /// The splitting unit `call` names, ready for one Message: a Debatch
    /// feeds it through [`crate::split`], the implementation the receive
    /// calls too.
    ///
    /// # Errors
    /// What it threw: its code and why, caught by the flow's scopes.
    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown>;
}

/// An error a unit threw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thrown {
    pub code: String,
    pub reason: String,
}

/// The code a call throws where the node carries no unit of that name.
pub const NO_UNIT: &str = "no-unit";

/// No unit at all: every call throws [`NO_UNIT`].
pub struct NoUnits;

impl NoUnits {
    fn none(call: &Call) -> Thrown {
        Thrown {
            code: NO_UNIT.to_string(),
            reason: format!(
                "this node carries no unit '{}' of '{}'",
                call.unit, call.module
            ),
        }
    }
}

impl WorkUnits for NoUnits {
    fn call(&self, call: &Call, _: &Message, _: &dyn IdGenerator) -> Result<Vec<Message>, Thrown> {
        Err(Self::none(call))
    }

    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown> {
        Err(Self::none(call))
    }
}

/// One Work Process this node runs.
pub struct Running {
    pub name: String,
    pub flow: Box<dyn Flow>,
    /// The sets its steps follow, in the order its program numbers them.
    pub sets: Vec<ResolvedSet>,
    /// What its decisions and its keys read of a Message.
    pub gathering: Gathering,
    /// Its queue in the Ledger.
    pub queue: u128,
    pub units: Arc<dyn WorkUnits>,
}

impl Running {
    /// The Work Process `name` of the cluster at `cluster`, run by `flow`,
    /// the sets it follows found among the cluster's `sets`, its names read
    /// through `sources`, its work done by `units`.
    ///
    /// # Errors
    /// A set it follows the cluster does not declare, or a name no source
    /// reads — each in words naming the Work Process.
    pub fn new(
        (cluster, name): (&str, &str),
        flow: Box<dyn Flow>,
        sets: &[ResolvedSet],
        sources: &[&dyn Source],
        units: Arc<dyn WorkUnits>,
    ) -> Result<Self, String> {
        let declared = flow.declared().clone();
        let followed = declared
            .sets
            .iter()
            .map(|set| {
                sets.iter()
                    .find(|known| known.name == *set)
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "the Work Process '{name}' follows the correlation set '{set}', \
                         which the cluster does not declare"
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut names: Vec<&str> = declared.reads.iter().map(String::as_str).collect();
        for set in &followed {
            names.extend(set.names());
        }
        let gathering = Gathering::new(sources, &names);
        if let Some(refused) = gathering.refusals().next() {
            return Err(format!("the Work Process '{name}': {refused}"));
        }
        Ok(Self {
            name: name.to_string(),
            flow,
            sets: followed,
            gathering,
            queue: crate::sending::queue(cluster, &Subscriber::WorkProcess(name.to_string())),
            units,
        })
    }
}
