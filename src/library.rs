//! The Modules a node opens from their library, startup phase 6 (ADR-0018,
//! ADR-0025): every `[[modules]]` entry the configuration starts, opened once
//! through the C ABI and held until the node stops (ADR-0057) — a module
//! holding only Work Process units only where a Work Process the node starts
//! names it ([`to_open`]) — each from its `library_path` read against the
//! folder the node's configuration is in ([`located`]).
//!
//! The loader is `ffi/loaded_module.rs`, and whether the host takes what it
//! opened is `abi::accepts`, beside the descriptor's own rule. What is here is
//! the order: which trait a Module is asked for, what the host drives of it,
//! and the lifecycle the header gives every table — `configure` once, `start`,
//! and `stop` before the library is let go (header section 8).

use std::path::{Path, PathBuf};

use configure::{ModuleConfiguration, WorkProcessConfiguration};

/// What a Module's manifest claims it serves, as the trait `descriptor.module`
/// must name: `contract` of `contract`, `transport` of `transport:file`.
fn claimed_trait(capability: &str) -> &str {
    capability
        .split_once(':')
        .map_or(capability, |(capability, _)| capability)
}

/// Whether `module` holds Work Process units and nothing else: every trait
/// its manifest claims is the work process trait (`xmip_module.h` section
/// 13).
#[must_use]
pub fn holds_only_work_processes(module: &ModuleConfiguration) -> bool {
    let claims = &module.manifest.capabilities;
    let word = abi::UnitCapability::WorkProcess.word();
    !claims.is_empty()
        && claims
            .iter()
            .all(|claim| claimed_trait(&claim.capability) == word)
}

/// The Modules of `modules` a node opens: each that starts, and of those a
/// module holding only Work Process units only where one of `processes`,
/// the Work Processes the node starts, names it — a unit's library given to
/// the whole cluster is opened by the nodes that run its flow, and no other
/// (ADR-0056, amendment 2026-11-13).
#[must_use]
pub fn to_open(
    modules: Vec<ModuleConfiguration>,
    processes: &[WorkProcessConfiguration],
) -> Vec<ModuleConfiguration> {
    modules
        .into_iter()
        .filter(|module| module.start)
        .filter(|module| {
            !holds_only_work_processes(module)
                || processes
                    .iter()
                    .any(|process| process.module.as_deref() == Some(module.name.as_str()))
        })
        .collect()
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
    /// Open each Module, once, from its library read against `base`, the
    /// folder the node's configuration is in ([`located`]), and start what
    /// the host drives of it.
    ///
    /// # Errors
    /// One sentence per Module that could not be opened, was refused by
    /// `abi::accepts`, claims a trait this host drives no table of, or
    /// refused its own lifecycle. A Module opened before the failure is
    /// stopped and let go.
    pub fn open(modules: &[ModuleConfiguration], base: &Path) -> Result<Self, Vec<String>> {
        use crate::ffi::loaded_contract::{CONTRACT, LoadedContract, expectation};
        use crate::ffi::loaded_module::LoadedModule;
        use crate::ffi::loaded_work_process::{self, WORK_PROCESS};

        let mut opened = Vec::new();
        let mut flows = Vec::new();
        let mut problems = Vec::new();

        for module in modules {
            let path = match located(module, base) {
                Ok(path) => path,
                Err(problem) => {
                    problems.push(problem);
                    continue;
                }
            };
            if holds_only_work_processes(module) {
                // A Work Process unit: opened once, its flow taken by every
                // Work Process naming one of its units (`crate::work_step`).
                match LoadedModule::open(&path, &loaded_work_process::expectation()) {
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
            let traits: Vec<&str> = module
                .manifest
                .capabilities
                .iter()
                .map(|claim| claimed_trait(&claim.capability))
                .collect();
            if traits != [CONTRACT] {
                problems.push(format!(
                    "the module '{}' claims {traits:?}; this runtime drives the \
                     '{CONTRACT}' and '{WORK_PROCESS}' tables of a loaded module and no \
                     other yet",
                    module.name
                ));
                continue;
            }
            let loaded = LoadedModule::open(&path, &expectation()).and_then(|loaded| {
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

/// Where a started Module's library is on this machine: its `library_path`
/// read against `base`, the folder the node's configuration is in, as every
/// other path a node's configuration names is — never against the working
/// directory the service happens to run in; a path written absolute as
/// written.
///
/// # Errors
/// As [`library`].
pub fn located(module: &ModuleConfiguration, base: &Path) -> Result<PathBuf, String> {
    library(module).map(|path| base.join(path))
}

/// The library a started Module's manifest names, as written.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The design the runtime's example Work Process unit is generated
    /// from, beside it.
    const DESIGN: &str = include_str!("../examples/approval_unit.bpmn");

    /// Where the example unit is, and what it is called.
    const ORIGIN: process::generate::Origin<'static> = process::generate::Origin {
        design: "approval_unit.bpmn",
        format: process_bpmn::FORMAT,
        module: "approval-unit",
        version: (0, 1, 0),
    };

    /// The unit [`DESIGN`] compiles into now: its crate's library source and
    /// its `[[modules]]` entry.
    fn generated() -> process::generate::Generated {
        use process::DesignFormat;
        let program = process_bpmn::Bpmn
            .compile(DESIGN, &process::NoResources)
            .expect("the design compiles");
        process::generate::unit(&program, &ORIGIN)
    }

    /// A node's configuration holding the module entry `module`, read.
    fn modules(module: &str) -> Vec<ModuleConfiguration> {
        let cluster = configure::fixture::test_cluster();
        let text = format!(
            "[service]\nname = \"xmip\"\ncluster_name = \"{}\"\nnode_name = \"{}\"\n\n{module}",
            cluster.name,
            cluster.node(0).name
        );
        configure::parse_toml(&text).expect("reads").modules
    }

    #[test]
    fn a_library_is_read_against_the_configurations_folder_an_absolute_one_as_written() {
        let [module] =
            <[ModuleConfiguration; 1]>::try_from(modules(&generated().module)).expect("one module");
        let file = process::generate::library_file(ORIGIN.module);
        let base = Path::new("configuration");
        assert_eq!(located(&module, base), Ok(base.join(&file)));
        let absolute = std::env::temp_dir().join(&file);
        let mut elsewhere = module.clone();
        elsewhere.manifest.entrypoint.library_path = Some(absolute.display().to_string());
        assert_eq!(located(&elsewhere, base), Ok(absolute));
    }

    #[test]
    fn a_module_of_work_process_units_opens_only_where_a_started_work_process_names_it() {
        let units = modules(&generated().module);
        assert!(holds_only_work_processes(&units[0]));
        let process = WorkProcessConfiguration {
            name: "Approval".to_string(),
            start: true,
            required_modules: Vec::new(),
            extensions: Vec::new(),
            module: Some(ORIGIN.module.to_string()),
            unit: Some("Approval".to_string()),
            settings: configure::LocationSettings::default(),
        };
        assert_eq!(to_open(units.clone(), &[process]), units);
        assert_eq!(to_open(units, &[]), [] as [ModuleConfiguration; 0]);
    }

    /// `source` with its layout taken out — every blank, and a comma before
    /// a closing bracket — so a file `cargo fmt` laid out compares equal to
    /// the text it was written as.
    fn unlaid(source: &str) -> String {
        source
            .split_whitespace()
            .collect::<String>()
            .replace(",]", "]")
            .replace(",)", ")")
    }

    /// The example unit is what its design generates now, laid out as
    /// `cargo fmt` lays it, so it cannot drift from the design or from
    /// `process::generate`.
    #[test]
    fn the_example_unit_is_what_its_design_generates_now() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/approval_unit.rs");
        let held = std::fs::read_to_string(&path).unwrap_or_default();
        let now = generated().library;
        assert!(
            unlaid(&held) == unlaid(&now),
            "{} is not what its design generates now; generated:\n{now}",
            path.display()
        );
    }

    /// The unit generated from a design, built as a library (the example
    /// `approval_unit`), opened from beside a node's configuration through
    /// the C ABI, and turned: the first test of `xmip_module.h` section 13
    /// over a library a node opens (ADR-0056, amendment 2026-11-13).
    #[cfg(feature = "dynamic-loading")]
    #[test]
    fn a_unit_generated_from_a_design_opens_from_beside_its_configuration_and_turns() {
        use process::{Act, Arrival, Event, Instance, Outcome};

        let file = process::generate::library_file(ORIGIN.module);
        let built = std::env::current_exe()
            .ok()
            .and_then(|test| Some(test.parent()?.parent()?.join("examples").join(&file)))
            .expect("the test program's folder");
        assert!(
            built.is_file(),
            "no unit library at {}: build the example first, cargo build --example \
             approval_unit (cargo test builds it)",
            built.display()
        );
        let configuration =
            std::env::temp_dir().join(format!("xmip-runtime-library-{}", std::process::id()));
        let folder = configuration.join("work-process");
        std::fs::create_dir_all(&folder).expect("the configuration's folder");
        std::fs::copy(&built, folder.join(&file)).expect("the library beside it");
        let entry = generated().module.replace(
            &format!("library_path = \"{file}\""),
            &format!("library_path = \"work-process/{file}\""),
        );
        let modules = modules(&entry);

        let elsewhere = Libraries::open(&modules, Path::new("elsewhere"))
            .err()
            .expect("not against the working directory");
        assert!(elsewhere[0].contains("would not open"), "{elsewhere:?}");
        let libraries = Libraries::open(&modules, &configuration).expect("opens");
        let flow = libraries
            .flow(ORIGIN.module, "Approval")
            .expect("its unit's flow");
        assert_eq!(flow.declared().name, "Approval");
        let arrived = |message| {
            Event::Arrived(Arrival {
                message,
                values: Vec::new(),
                keys: Vec::new(),
            })
        };
        let mut instance = Instance::new();
        let first = flow.advance(&mut instance, &arrived(1), 0).expect("starts");
        assert!(first.is_empty(), "{first:?}");
        assert!(instance.waits_for_a_message());
        let acts = flow
            .advance(&mut instance, &arrived(2), 0)
            .expect("goes on");
        assert_eq!(
            acts,
            vec![Act::Publish { message: 2 }, Act::Ended(Outcome::Completed)]
        );
        drop(flow);
        drop(libraries);
        // A library still mapped may not be removed on every system; the
        // folder is the test's own either way.
        drop(std::fs::remove_dir_all(&configuration));
    }
}
