//! A node running: ADR-0018's nine startup phases over its configuration and
//! the technologies its program linked, the message path on every Receive
//! Location it starts, and a stop that drains.
//!
//! ```text
//! 1 read-configuration     the node's document and the Applications it binds
//! 2 build-execution-tree   what this node starts, bound
//! 3 validate-startup       every Location held to its technology's declaration;
//!                          every technology, accepted mechanism and filter name
//!                          one this node was built with — refused here, not at
//!                          the first Message
//! 4 plan-host-services     the Host Services the started Modules need
//! 5 start-host-services    this process is the in-process one
//! 6 load-modules           each technology used loaded once, its declaration
//!                          carried into the catalogue; each library opened once
//! 7 register-capabilities  each capability once, by the Module serving it
//! 8 verify-extensions      the execution tree's, verified and not loaded
//! 9 accept-work            each Location's transport built once; Xmip Storage
//!                          reached; the Runtime built once; every Receive
//!                          Location serving; the send step dispatching, its
//!                          queues read first for what the Ledger left
//! ```
//!
//! Phase 3 also holds how the node reaches Xmip Storage to what its program
//! linked, and phase 9 reaches it (`crate::storage`): every Stream a
//! Receive Location takes in is written to the Ledger through it.
//!
//! [`Running::start`] runs the phases over one slice and serves nothing;
//! [`Running::activate`] begins serving. Which slices a node tries, and in
//! what order, is [`activation`]'s (ADR-0031, amendment 2026-11-12).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use configure::{ConfiguredLocation, LocationSettings};
use xaudit::origin::Origin;
use xaudit::program_audit::ProgramAudit;

use crate::capability_registry::CapabilityRegistry;
use crate::host::HostService;
use crate::outcome::{Outcomes, Tally};
use crate::pickup::Pickup;
use crate::send_step::SendStep;
use crate::service::StartupPhase;
use crate::stopping::Stopping;
use crate::storage::Reached;

pub mod activation;
mod certificate_standing;
mod operate;
pub mod publication;
pub mod revocation_list;
mod serving;
mod starting;

/// Why a node did not start: the phase that refused it, and every problem it
/// found there, one sentence each (ADR-0055: refused at the door, in words).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub phase: StartupPhase,
    pub problems: Vec<String>,
}

impl Refusal {
    /// Refused at `phase`, for `problems`: the runtime's phases, and the
    /// program's own steps before the node accepts work (`activation`).
    #[must_use]
    pub const fn at(phase: StartupPhase, problems: Vec<String>) -> Self {
        Self { phase, problems }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refused at {}: {}", self.phase, self.problems.join("; "))
    }
}

/// A node, started, serving once activated, until [`Running::stop`], or
/// until it is dropped.
pub struct Running {
    cluster: String,
    node: String,
    /// Whether its configuration says it may reach the internet (ADR-0045).
    online: bool,
    capabilities: CapabilityRegistry,
    host_services: Vec<HostService>,
    /// Each Location it started: its stage, where it is published beneath
    /// that stage (`ExecutionTree::beneath`), and its configuration.
    locations: Vec<(node::Stage, String, ConfiguredLocation)>,
    /// Each Location it knows and did not start, by stage and name.
    not_started: Vec<(&'static str, String)>,
    stopping: Arc<Stopping>,
    /// What the serving thread owns, held from the start to the activation.
    served: Option<serving::Served>,
    serving: Option<JoinHandle<()>>,
    tally: Arc<Tally>,
    /// Whether it routes, and so processes: a Receive Location starts or a
    /// Work Process runs (`starting::routes`).
    routes: bool,
    /// The nodes the cluster's bindings place a Location on: the only ones
    /// its Storage node draws traffic from and to (`starting::bound_nodes`).
    bound: Vec<String>,
    /// The roles its configuration declares, `[nodes.<name>] roles`: what
    /// its drawing says it is related, stands and is for by (ADR-0052 and
    /// ADR-0056, amendments 2026-11-13).
    roles: Vec<node::NodeRole>,
    pickup: Arc<Pickup>,
    send: Arc<SendStep>,
    data: PathBuf,
    /// The slice it runs and how it came to, and, once activated, what its
    /// record at `<node>/configuration` says (`activation`).
    attempt: activation::Attempt,
    standing: Option<activation::Standing>,
    /// `[provision]`, as the slice it runs says it: what its program serves
    /// the cluster's authority from ([`Running::provision`]).
    provision: BTreeMap<String, LocationSettings>,
    storage: Reached,
    /// `[operate]`, and the file it was read from ([`Running::operate`]).
    operate: Option<configure::OperateConfiguration>,
    /// When each certificate it presents is due for renewal (ADR-0034,
    /// amendment 2026-10-22).
    certificates: certificate_standing::CertificateStanding,
    /// `[tuning]`: how long a surface's local call waits, what bounds the
    /// operate listeners.
    tuning: crate::tuning::Tuning,
    configuration: PathBuf,
    #[cfg(feature = "dynamic-loading")]
    libraries: Option<crate::library::Libraries>,
}

impl Running {
    /// The cluster the node belongs to, `service.cluster_name`.
    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// The node's name, `service.node_name`.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Every capability loaded, once each, by the Module serving it.
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilityRegistry {
        &self.capabilities
    }

    /// The Host Services the node's Modules needed, as started.
    #[must_use]
    pub fn host_services(&self) -> &[HostService] {
        &self.host_services
    }

    /// The node's Subscriptions, their standing and what they hold, which
    /// an operator pauses and resumes (ADR-0013, amendment 2026-09-30).
    #[must_use]
    pub fn pickup(&self) -> &Pickup {
        &self.pickup
    }

    /// The node's send step: what it sends from the Ledger, and its figures
    /// per Send Port.
    #[must_use]
    pub fn send(&self) -> &SendStep {
        &self.send
    }

    /// Its data directory (`configure::ServiceConfiguration::data`):
    /// where the orders an operator leaves for it and its last snapshot
    /// are kept.
    #[must_use]
    pub fn data(&self) -> &Path {
        &self.data
    }

    /// `[provision]`, as the slice the node runs says it, never as the file
    /// beside it says now: the purposes its certificates are issued for,
    /// and the cluster's authority its program serves (ADR-0034).
    #[must_use]
    pub const fn provision(&self) -> &BTreeMap<String, LocationSettings> {
        &self.provision
    }

    /// How the node reaches Xmip Storage, which its receives write the
    /// Ledger through.
    #[must_use]
    pub const fn storage(&self) -> &Reached {
        &self.storage
    }

    /// What became of every Stream so far.
    #[must_use]
    pub fn outcomes(&self) -> Outcomes {
        self.tally.outcomes()
    }

    /// Stop: every Receive Location takes nothing more once its current
    /// receive returns — one whose far end already let go of what it
    /// handed over first drains what is queued for it (ADR-0018, amendment
    /// 2026-10-15) — what it took is carried whole, and then the
    /// transports and the loaded Modules are let go (ADR-0018 clause 12).
    /// Returns what became of every Stream.
    pub fn stop(mut self) -> Outcomes {
        self.halt();
        self.tally.outcomes()
    }

    fn halt(&mut self) {
        self.stopping.raise();
        if let Some(serving) = self.serving.take()
            && serving.join().is_err()
        {
            self.tally
                .fail(&self.node, "the node's serving thread panicked".to_string());
        }
        for service in &mut self.host_services {
            service.stop();
        }
        // The node's own work stopped, what it serves the others stops: a
        // primary Storage node hands its standbys what it wrote first.
        self.storage.stop();
        #[cfg(feature = "dynamic-loading")]
        drop(self.libraries.take());
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Who a running node's audit records say they came from: the program's
/// origin where it audits, this process as the runtime otherwise, and the
/// node's location on each (ADR-0062, amendment 2026-09-29).
#[must_use]
pub fn origin(program: Option<&ProgramAudit>, node: &str) -> Origin {
    Origin {
        location: Some(node.to_string()),
        ..program.map_or_else(
            || Origin::here(env!("CARGO_PKG_NAME")),
            |audit| audit.origin(),
        )
    }
}

#[cfg(test)]
mod accepted;
