pub mod arrival;
pub mod capability_registry;
pub mod compatibility;
pub mod departure;
pub mod engine;
pub mod execution_tree;
pub mod generation;
pub mod host;
/// The contract trait of a loaded module (ADR-0057 clause 8 step 2).
#[cfg(feature = "dynamic-loading")]
pub mod loaded_contract;
/// Opening a module for real. Behind the feature that has always named it.
#[cfg(feature = "dynamic-loading")]
pub mod loaded_module;
pub mod operate;
pub mod outcome;
pub mod registration;
pub mod rule;
pub mod service;
pub mod start;
mod wire;

use std::collections::BTreeSet;

use abi::{ExecutionHostKind, ExtensionManifest, HandlerInvocation, HandlerResult, ModuleManifest};
use node::NodeRole;
use serde::{Deserialize, Serialize};

/// The runtime's plan for one node: which Host Services it spawns, under which
/// roles.
///
/// The roles are `xmip-core-node`'s; this crate carried its own copy of the
/// four until 2026-09-14 (ADR-0044). The node is still named, not typed as
/// `node::Node`: configuration names a cluster and a node (`[service]` in
/// `start.rs`), and `Node` carries an identifier, a capability set and a trust
/// flag the plan does not know at planning time. Wrapping the names in a
/// `Node` would mean inventing those.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeNode {
    pub cluster_name: String,
    pub node_name: String,
    pub roles: BTreeSet<NodeRole>,
    pub host_services: Vec<HostServicePlan>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostServicePlan {
    pub host_type: String,
    pub trusted: bool,
    pub bitness: HostBitness,
    pub modules: Vec<ModuleManifest>,
    pub verified_extensions: Vec<ExtensionManifest>,
}

/// Execution width of the Host Service.
///
/// Classical variants are the address width of the process. `Qubit` carries a
/// count, because quantum hardware is described by how many qubits it offers
/// rather than by a single width — a 127-qubit processor is not the same
/// target as a 20-qubit one, and a Host Service that needs 100 cannot run on
/// the smaller.
///
/// Quantum execution is reachable today through providers such as Azure
/// Quantum, on real hardware or on a simulator. Xmip carries the shape now so
/// that a Host Service can declare the requirement, whether or not this node
/// can satisfy it.
///
/// A width this node cannot provide is a configuration error. It is caught at
/// validate-startup and returned, not discovered at spawn time — a Host Service
/// asking for a card that is not in the machine, or for more qubits than the
/// machine has, should fail before anything starts.
///
/// The count is u64 rather than u128 because TOML integers are 64-bit signed,
/// so a wider type could hold a value the manifest cannot express. u64 tops
/// out around 9.2e18 qubits, which is not a limit anyone will meet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostBitness {
    Bit32,
    Bit64,
    Bit128,
    Qubit(u64),
    Native,
}

#[derive(Clone, Debug, Default)]
pub struct ModuleRegistry {
    manifests: Vec<ModuleManifest>,
}

impl ModuleRegistry {
    pub fn register(&mut self, manifest: ModuleManifest) {
        self.manifests.push(manifest);
    }

    pub fn manifests(&self) -> &[ModuleManifest] {
        &self.manifests
    }

    pub fn plan_host_services(&self, cluster_name: &str, node_name: &str) -> RuntimeNode {
        RuntimeNode {
            cluster_name: cluster_name.to_string(),
            node_name: node_name.to_string(),
            roles: [NodeRole::Operational, NodeRole::Executing]
                .into_iter()
                .collect(),
            host_services: self
                .manifests
                .iter()
                .cloned()
                .map(|module| HostServicePlan {
                    host_type: host_type_for(&module),
                    trusted: module.capabilities.iter().any(|c| c.trusted_required),
                    bitness: HostBitness::Native,
                    modules: vec![module],
                    verified_extensions: Vec::new(),
                })
                .collect(),
        }
    }
}

pub trait RuntimeDispatcher {
    fn dispatch(&self, invocation: HandlerInvocation) -> HandlerResult;
}

/// Which Host Service a Module needs.
///
/// This used to read the Module's `kind`. ADR-0012 clause 5 removed that field,
/// and reading it here was wrong before it was removed: a Module's kind said
/// what it *does*, and what decides the host process is what it is *written
/// in*. A .NET transport and a .NET content handler share a host; a .NET
/// transport and a Rust transport do not.
///
/// A Module whose capabilities disagree about their execution host cannot be
/// placed in one Host Service. That is a manifest defect, and naming it here
/// makes it visible at planning time rather than at spawn time.
fn host_type_for(module: &ModuleManifest) -> String {
    let mut hosts = module
        .capabilities
        .iter()
        .map(|capability| execution_host_name(&capability.execution_host))
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();

    match hosts.as_slice() {
        [] => "native-rust-host".to_string(),
        [only] => format!("{only}-host"),
        many => format!("mixed-host({})", many.join("+")),
    }
}

const fn execution_host_name(host: &ExecutionHostKind) -> &'static str {
    match host {
        ExecutionHostKind::NativeRust => "native-rust",
        ExecutionHostKind::DotNet => "dotnet",
        ExecutionHostKind::Java => "java",
        ExecutionHostKind::Python => "python",
        ExecutionHostKind::CAbi => "c-abi",
        ExecutionHostKind::Go => "go",
        ExecutionHostKind::PowerShell => "powershell",
        ExecutionHostKind::Bash => "bash",
    }
}
