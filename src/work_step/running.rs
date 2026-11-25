//! One Work Process this node runs: its unit opened as a flow, the
//! Correlations it follows read from the cluster's, the names its
//! decisions and its keys read compiled once, and its queue.

use std::sync::Arc;

use journey::Journey;
use message::Message;
use persist::storage::{InstanceRecord, XmipStorage, named};
use process::Flow;
use process::program::Call;
use route::{Gathering, Source, Subscriber};
use xcore::IdGenerator;

use super::keys::{ResolvedSet, promoted};
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
    /// The cluster it runs in: `xmip:///<cluster>`.
    pub cluster: String,
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
                            "the Work Process '{name}' follows the Correlation '{set}', \
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
            cluster: cluster.to_string(),
            name: name.to_string(),
            flow,
            sets: followed,
            gathering,
            queue: crate::sending::queue(cluster, &Subscriber::WorkProcess(name.to_string())),
            units,
        })
    }

    /// The name of the Correlation it numbers `set`.
    #[must_use]
    pub fn set_name(&self, set: u32) -> &str {
        self.sets
            .get(usize::try_from(set).unwrap_or(usize::MAX))
            .map_or("", |set| set.name.as_str())
    }

    /// The key `journey` and its `message` carry in each Correlation it
    /// follows that they carry every key part of, by the set's number.
    ///
    /// # Errors
    /// A route technology refused the Message, in words.
    pub(crate) fn keys(
        &self,
        journey: &Journey,
        message: &Message,
    ) -> Result<Vec<(u32, String)>, String> {
        let promoted = promoted(&self.gathering, message)?;
        let mut keys = Vec::new();
        for (number, set) in self.sets.iter().enumerate() {
            if let Ok(key) = set.text(journey, &promoted, &self.name) {
                keys.push((u32::try_from(number).unwrap_or(u32::MAX), key));
            }
        }
        Ok(keys)
    }

    /// The correlation key `key` of the set numbered `set`: its identifier,
    /// named from the cluster, the Work Process, the set and the key's full
    /// values.
    #[must_use]
    pub(crate) fn correlation(&self, (set, key): &(u32, String)) -> u128 {
        let name = self.set_name(*set);
        named(&format!(
            "{}/work-process/{}/correlation/{name}/{key}",
            self.cluster, self.name
        ))
    }

    /// The Instance a Message of `keys` on the Journey `journey` belongs
    /// to, as `storage` keeps it: the one a key of its correlates to, else
    /// the one it started, by its Journey.
    ///
    /// # Errors
    /// Xmip Storage did not answer, in words.
    pub(crate) fn instance(
        &self,
        storage: &dyn XmipStorage,
        journey: u128,
        keys: &[(u32, String)],
    ) -> Result<(u128, Option<InstanceRecord>), String> {
        for key in keys {
            let found = storage
                .read_instance_key(self.correlation(key))
                .map_err(|why| why.to_string())?;
            if let Some(instance) = found {
                let record = storage
                    .read_instance(instance)
                    .map_err(|why| why.to_string())?;
                return Ok((instance, record));
            }
        }
        let record = storage
            .read_instance(journey)
            .map_err(|why| why.to_string())?;
        Ok((journey, record))
    }
}
