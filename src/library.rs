//! The Modules a node opens from their library, startup phase 6 (ADR-0018,
//! ADR-0025): every `[[modules]]` entry the configuration starts, opened once
//! through the C ABI and held until the node stops (ADR-0057).
//!
//! The loader is `ffi/loaded_module.rs`, and whether the host takes what it
//! opened is `abi::accepts`, beside the descriptor's own rule. What is here is
//! the order: which trait a Module is asked for, what the host drives of it,
//! and the lifecycle the header gives every table — `configure` once, `start`,
//! and `stop` before the library is let go (header section 8).

use configure::ModuleConfiguration;

/// What a Module's manifest claims it serves, as the trait `descriptor.module`
/// must name: `contract` of `contract`, `transport` of `transport:file`.
#[cfg(feature = "dynamic-loading")]
fn claimed_trait(capability: &str) -> &str {
    capability
        .split_once(':')
        .map_or(capability, |(capability, _)| capability)
}

/// Every Module `modules` starts, opened from its library and started.
#[cfg(feature = "dynamic-loading")]
pub struct Libraries {
    opened: Vec<crate::ffi::loaded_module::LoadedModule>,
    /// The Work Process units opened, each by its module and its unit.
    flows: Vec<(
        String,
        String,
        std::sync::Arc<crate::ffi::loaded_work_process::UnitModule>,
    )>,
}

#[cfg(feature = "dynamic-loading")]
impl Libraries {
    /// Open each Module, once, and start what the host drives of it.
    ///
    /// # Errors
    /// One sentence per Module that could not be opened, was refused by
    /// `abi::accepts`, claims a trait this host drives no table of, or
    /// refused its own lifecycle. A Module opened before the failure is
    /// stopped and let go.
    pub fn open(modules: &[ModuleConfiguration]) -> Result<Self, Vec<String>> {
        use crate::ffi::loaded_contract::{CONTRACT, LoadedContract, expectation};
        use crate::ffi::loaded_module::LoadedModule;
        use crate::ffi::loaded_work_process::{self, WORK_PROCESS};

        let mut opened = Vec::new();
        let mut flows = Vec::new();
        let mut problems = Vec::new();

        for module in modules {
            let path = match library(module) {
                Ok(path) => path,
                Err(problem) => {
                    problems.push(problem);
                    continue;
                }
            };
            let traits: Vec<&str> = module
                .manifest
                .capabilities
                .iter()
                .map(|claim| claimed_trait(&claim.capability))
                .collect();
            if traits == [WORK_PROCESS] {
                // A Work Process unit: opened once, its flow taken by every
                // Work Process naming one of its units (`crate::work_step`).
                match LoadedModule::open(
                    std::path::Path::new(path),
                    &loaded_work_process::expectation(),
                ) {
                    Ok(loaded) => {
                        // A unit's library holds one unit, its descriptor's
                        // standard naming it (`process::export`), and the
                        // manifest declares it (`abi::ModuleUnit`).
                        let unit = loaded.descriptor().standard.clone();
                        let declared = module.manifest.units.iter().any(|declared| {
                            declared.name == unit
                                && declared.capability == abi::UnitCapability::WorkProcess
                        });
                        if !declared {
                            problems.push(format!(
                                "the module '{}' holds the unit '{unit}', which its manifest \
                                 does not declare as a {WORK_PROCESS} unit",
                                module.name
                            ));
                            continue;
                        }
                        let loaded = loaded_work_process::UnitModule::shared(loaded);
                        flows.push((module.name.clone(), unit, loaded));
                    }
                    Err(why) => problems.push(format!("the module '{}': {why}", module.name)),
                }
                continue;
            }
            if traits != [CONTRACT] {
                problems.push(format!(
                    "the module '{}' claims {traits:?}; this runtime drives the \
                     '{CONTRACT}' and '{WORK_PROCESS}' tables of a loaded module and no \
                     other yet",
                    module.name
                ));
                continue;
            }
            let loaded =
                LoadedModule::open(std::path::Path::new(path), &expectation()).and_then(|loaded| {
                    {
                        let contract = LoadedContract::of(&loaded)?;
                        contract.configure("")?;
                        contract.start()?;
                    }
                    Ok(loaded)
                });
            match loaded {
                Ok(loaded) => opened.push(loaded),
                Err(why) => problems.push(format!("the module '{}': {why}", module.name)),
            }
        }

        let libraries = Self { opened, flows };
        if problems.is_empty() {
            Ok(libraries)
        } else {
            drop(libraries);
            Err(problems)
        }
    }

    /// The Modules opened, each with the file it came from.
    pub fn modules(&self) -> impl Iterator<Item = &crate::ffi::loaded_module::LoadedModule> {
        let units = self.flows.iter().map(|(_, _, unit)| unit.module());
        self.opened.iter().chain(units)
    }

    /// The flow of the unit `unit` of the module `module`, where it was
    /// opened.
    ///
    /// # Errors
    /// None of that name was opened, or its table does not drive.
    pub fn flow(&self, module: &str, unit: &str) -> Result<Box<dyn process::Flow>, String> {
        let (_, _, loaded) = self
            .flows
            .iter()
            .find(|(of, name, _)| of == module && name == unit)
            .ok_or_else(|| format!("no module '{module}' opened holds the unit '{unit}'"))?;
        crate::ffi::loaded_work_process::LoadedFlow::of(loaded.clone())
            .map(|flow| Box::new(flow) as Box<dyn process::Flow>)
    }
}

/// Stopped before it is let go: the header's lifecycle ends with `stop`, and
/// `LoadedModule`'s own drop then destroys the instance and unloads the
/// library, in that order.
#[cfg(feature = "dynamic-loading")]
impl Drop for Libraries {
    fn drop(&mut self) {
        for loaded in &self.opened {
            if let Ok(contract) = crate::ffi::loaded_contract::LoadedContract::of(loaded) {
                // A module that refuses to stop is let go all the same: the
                // node is stopping, and nothing is left to call it.
                drop(contract.stop());
            }
        }
    }
}

/// Where a started Module's library is.
///
/// # Errors
/// The Module names no library — it runs as its own executable, or names
/// nothing to load — or names an entrypoint other than the header's one.
pub fn library(module: &ModuleConfiguration) -> Result<&str, String> {
    let entrypoint = &module.manifest.entrypoint;
    if let Some(symbol) = &entrypoint.symbol
        && symbol != abi::XMIP_ENTRYPOINT
    {
        return Err(format!(
            "the module '{}' names the entrypoint '{symbol}'; a conforming module exports \
             exactly {} (header section 7)",
            module.name,
            abi::XMIP_ENTRYPOINT
        ));
    }
    match (&entrypoint.library_path, &entrypoint.executable_path) {
        (Some(path), _) if !path.trim().is_empty() => Ok(path),
        (_, Some(_)) => Err(format!(
            "the module '{}' runs as its own executable, and this runtime starts no \
             Module out of process yet",
            module.name
        )),
        _ => Err(format!(
            "the module '{}' names no library to load",
            module.name
        )),
    }
}

/// Without the `dynamic-loading` feature a node opens no library: every
/// Module the configuration starts is refused, naming the feature.
///
/// # Errors
/// One sentence per started Module.
#[cfg(not(feature = "dynamic-loading"))]
pub fn refuse(modules: &[ModuleConfiguration]) -> Result<(), Vec<String>> {
    let problems: Vec<String> = modules
        .iter()
        .map(|module| match library(module) {
            Ok(path) => format!(
                "the module '{}' is a library ({path}), and this runtime was built without \
                 the dynamic-loading feature that opens one",
                module.name
            ),
            Err(problem) => problem,
        })
        .collect();

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}
