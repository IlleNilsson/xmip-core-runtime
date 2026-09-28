//! The capabilities a node's Modules registered, startup phase 7 (ADR-0018):
//! one entry per capability, naming the Module that serves it and how that
//! Module came to be in the process.
//!
//! A capability is registered once. A second Module claiming what one already
//! serves is refused, and so is the same Module registered twice — which is
//! what holds a Module to being loaded once however many Locations use it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use abi::ModuleManifest;

/// How a Module came to be in the process (ADR-0025, ADR-0057).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Load {
    /// Compiled into the program that started the node, by build feature
    /// (ADR-0018, amendment 2026-09-26).
    Linked,
    /// Opened from its library through the C ABI (ADR-0057).
    Library(PathBuf),
}

/// One capability, and the Module serving it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredCapability {
    /// The capability as claimed: `transport:xmip-core-transport-tcp`,
    /// `route:party`, a manifest's own `capability`.
    pub capability: String,
    /// The Module serving it, by the name it declares.
    pub module: String,
    pub load: Load,
}

#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    capabilities: BTreeMap<String, RegisteredCapability>,
}

impl CapabilityRegistry {
    /// Register that `module` serves `capability`.
    ///
    /// # Errors
    /// The capability is already registered, naming the Module that holds it.
    pub fn register(&mut self, capability: &str, module: &str, load: Load) -> Result<(), String> {
        if let Some(held) = self.capabilities.get(capability) {
            return Err(format!(
                "capability '{capability}' is already registered, by '{}'",
                held.module
            ));
        }

        self.capabilities.insert(
            capability.to_string(),
            RegisteredCapability {
                capability: capability.to_string(),
                module: module.to_string(),
                load,
            },
        );

        Ok(())
    }

    /// Register every capability a Module's manifest claims.
    ///
    /// # Errors
    /// The first capability already registered.
    pub fn register_module(
        &mut self,
        manifest: &ModuleManifest,
        load: &Load,
    ) -> Result<(), String> {
        for capability in &manifest.capabilities {
            self.register(
                &capability.capability,
                &manifest.identity.name,
                load.clone(),
            )?;
        }

        Ok(())
    }

    #[must_use]
    pub fn get(&self, capability: &str) -> Option<&RegisteredCapability> {
        self.capabilities.get(capability)
    }

    pub fn capabilities(&self) -> impl Iterator<Item = &RegisteredCapability> {
        self.capabilities.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capability_is_served_once_and_a_second_claim_names_the_first() {
        let mut registry = CapabilityRegistry::default();
        registry
            .register(
                "transport:xmip-core-transport-tcp",
                "xmip-core-transport-tcp",
                Load::Linked,
            )
            .expect("first");

        let refused = registry
            .register("transport:xmip-core-transport-tcp", "another", Load::Linked)
            .expect_err("once");

        assert!(refused.contains("already registered, by 'xmip-core-transport-tcp'"));
        assert_eq!(registry.capabilities().count(), 1);
        assert_eq!(
            registry
                .get("transport:xmip-core-transport-tcp")
                .map(|c| &c.load),
            Some(&Load::Linked)
        );
    }
}
