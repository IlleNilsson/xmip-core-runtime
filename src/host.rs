//! The Xmip Host Services a node's Modules run in, planned at startup phase 4
//! and started at phase 5 (ADR-0018).
//!
//! A Host Service is a process. Which Host Service a Module needs is decided
//! by one rule, [`host_type`]: what the Module is *written in*, never what it
//! does or what it is called.

use std::collections::BTreeMap;

use abi::{ExecutionHostKind, ExtensionManifest, ModuleManifest};
use serde::{Deserialize, Serialize};

/// The runtime's plan for one Host Service: its type, whether it holds
/// trusted work, its width, and the Modules and Extensions it hosts.
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

/// The registered, supervised thing. ADR-0018.
#[derive(Clone, Debug)]
pub struct HostService {
    pub plan: HostServicePlan,
    pub state: HostServiceState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostServiceState {
    Planned,
    Starting,
    Running,
    Stopped,
    Failed(String),
}

/// The Host Service the node's own process is: the one that loads a Module
/// in process, through the C ABI, whether it was written in Rust or in
/// anything else that exports the header's table (ADR-0012).
pub const IN_PROCESS: [&str; 2] = ["native-rust-host", "c-abi-host"];

impl HostService {
    /// Planned, not started.
    #[must_use]
    pub const fn planned(plan: HostServicePlan) -> Self {
        Self {
            plan,
            state: HostServiceState::Planned,
        }
    }

    /// Whether this Host Service is the node's own process, which startup
    /// phase 5 starts by running on.
    #[must_use]
    pub fn in_process(&self) -> bool {
        IN_PROCESS.contains(&self.plan.host_type.as_str())
    }

    pub fn start(&mut self) {
        self.state = HostServiceState::Starting;
        self.state = HostServiceState::Running;
    }

    pub fn stop(&mut self) {
        self.state = HostServiceState::Stopped;
    }
}

/// Startup phase 4: the Host Services `modules` need, one per host type,
/// each holding the Modules of that type in the order they were given.
#[must_use]
pub fn plan(modules: &[ModuleManifest]) -> Vec<HostService> {
    let mut by_type: BTreeMap<String, HostServicePlan> = BTreeMap::new();

    for module in modules {
        let host_type = host_type(module);
        let planned = by_type
            .entry(host_type.clone())
            .or_insert_with(|| HostServicePlan {
                host_type,
                trusted: false,
                bitness: HostBitness::Native,
                modules: Vec::new(),
                verified_extensions: Vec::new(),
            });
        planned.trusted |= module.capabilities.iter().any(|c| c.trusted_required);
        planned.modules.push(module.clone());
    }

    by_type.into_values().map(HostService::planned).collect()
}

/// Which Host Service a Module needs.
///
/// What decides the Host Service is what a Module is *written in*, never what
/// it does (ADR-0012 clause 5 removed the Module's `kind`): a .NET transport
/// and a .NET content handler share a host; a .NET transport and a Rust
/// transport do not.
///
/// A Module whose capabilities disagree about their execution host cannot be
/// placed in one Host Service. That is a manifest defect, and naming it here
/// makes it visible at planning time rather than at spawn time.
#[must_use]
pub fn host_type(module: &ModuleManifest) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{ModuleCapability, ModuleEntrypoint, ModuleIdentity};

    fn module(name: &str, hosts: &[ExecutionHostKind]) -> ModuleManifest {
        ModuleManifest {
            identity: ModuleIdentity {
                name: name.to_string(),
                version: "0.1.0".to_string(),
            },
            capabilities: hosts
                .iter()
                .map(|host| ModuleCapability {
                    capability: "contract".to_string(),
                    execution_host: host.clone(),
                    trusted_required: false,
                })
                .collect(),
            entrypoint: ModuleEntrypoint {
                library_path: None,
                executable_path: None,
                symbol: None,
            },
        }
    }

    #[test]
    fn what_a_module_is_written_in_decides_its_host_and_not_its_name() {
        use ExecutionHostKind::{CAbi, DotNet, NativeRust};

        assert_eq!(
            host_type(&module("dotnet-thing", &[NativeRust])),
            "native-rust-host"
        );
        assert_eq!(host_type(&module("a", &[DotNet, DotNet])), "dotnet-host");
        assert_eq!(host_type(&module("a", &[])), "native-rust-host");
        assert_eq!(
            host_type(&module("a", &[NativeRust, CAbi])),
            "mixed-host(c-abi+native-rust)"
        );
    }

    #[test]
    fn modules_of_one_host_type_share_one_host_service() {
        use ExecutionHostKind::{CAbi, DotNet, NativeRust};

        let planned = plan(&[
            module("a", &[NativeRust]),
            module("b", &[DotNet]),
            module("c", &[NativeRust]),
            module("d", &[CAbi]),
        ]);

        let types: Vec<&str> = planned.iter().map(|h| h.plan.host_type.as_str()).collect();
        assert_eq!(types, ["c-abi-host", "dotnet-host", "native-rust-host"]);
        assert_eq!(planned[2].plan.modules.len(), 2);
        assert!(planned[0].in_process() && planned[2].in_process());
        assert!(
            !planned[1].in_process(),
            "a .NET module needs a Host Service of its own"
        );
        assert!(planned.iter().all(|h| h.state == HostServiceState::Planned));
    }
}
