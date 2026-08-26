use std::collections::BTreeMap;
use xmip_core::{ModuleCapability, ModuleIdentity, ModuleManifest};

#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    capabilities: BTreeMap<String, RegisteredCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredCapability {
    pub capability: ModuleCapability,
    pub module_identity: ModuleIdentity,
}

impl CapabilityRegistry {
    pub fn register_module(&mut self, manifest: &ModuleManifest) -> Result<(), String> {
        for capability in &manifest.capabilities {
            if self.capabilities.contains_key(&capability.capability) {
                return Err(format!(
                    "capability '{}' is already registered",
                    capability.capability
                ));
            }

            self.capabilities.insert(
                capability.capability.clone(),
                RegisteredCapability {
                    capability: capability.clone(),
                    module_identity: manifest.identity.clone(),
                },
            );
        }

        Ok(())
    }

    pub fn get(&self, capability: &str) -> Option<&RegisteredCapability> {
        self.capabilities.get(capability)
    }

    pub fn capabilities(&self) -> impl Iterator<Item = &RegisteredCapability> {
        self.capabilities.values()
    }
}
