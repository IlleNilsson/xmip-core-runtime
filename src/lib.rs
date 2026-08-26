pub mod capability_registry;
pub mod execution_tree;

use serde::{Deserialize, Serialize};
use xmip_core::{ExtensionManifest, HandlerInvocation, HandlerResult, ModuleKind, ModuleManifest};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeNode {
    pub cluster_name: String,
    pub node_name: String,
    pub roles: Vec<NodeRole>,
    pub host_services: Vec<HostServicePlan>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Operational,
    Monitoring,
    Executing,
    Development,
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
            roles: vec![NodeRole::Operational, NodeRole::Executing],
            host_services: self
                .manifests
                .iter()
                .cloned()
                .map(|module| HostServicePlan {
                    host_type: format!("{}-host", module.identity.kind.kind_name()),
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

trait ModuleKindName {
    fn kind_name(&self) -> &'static str;
}

impl ModuleKindName for ModuleKind {
    fn kind_name(&self) -> &'static str {
        match self {
            ModuleKind::TransportHandler => "transport",
            ModuleKind::ContentHandler => "content",
            ModuleKind::LogicHandler => "logic",
            ModuleKind::StoreProvider => "store",
            ModuleKind::ManagementModule => "management",
        }
    }
}
