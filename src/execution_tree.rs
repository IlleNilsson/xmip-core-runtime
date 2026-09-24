//! Startup phases 2 and 3 (ADR-0018): build the execution tree from the
//! node's configuration document and validate it.
//!
//! The tree is derived from `configure::XmipConfigurationDocument` and holds
//! the document's own types — what starts, in the document's words — plus
//! the one thing only the runtime knows, which extensions it verified. Until
//! 2026-09-24 it read a second model of the configuration and restated a
//! subset of it in startup node types of its own (open problem 25, row b).

use abi::ExtensionManifest;
use configure::{
    ConfiguredLocation, ModuleConfiguration, ServiceConfiguration, XmipConfigurationDocument,
    XmipProcessConfiguration,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// What a node starts, taken from its configuration document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTree {
    pub service: ServiceConfiguration,
    pub modules_to_start: Vec<ModuleConfiguration>,
    pub xmip_processes_to_start: Vec<XmipProcessConfiguration>,
    pub receive_locations_to_start: Vec<ConfiguredLocation>,
    pub send_locations_to_start: Vec<ConfiguredLocation>,
    pub verified_extensions: Vec<VerifiedExtensionNode>,
}

/// An extension the runtime checked at startup, and whether it loaded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedExtensionNode {
    pub name: String,
    pub version: String,
    pub loaded_during_startup: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl StartupValidationReport {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate the document and take from it what starts.
///
/// # Errors
/// The validation report, when it holds an error.
pub fn build_execution_tree(
    document: XmipConfigurationDocument,
) -> Result<(ExecutionTree, StartupValidationReport), StartupValidationReport> {
    let report = validate_startup_configuration(&document);
    if !report.is_valid() {
        return Err(report);
    }

    let modules_to_start = document
        .modules
        .into_iter()
        .filter(|module| module.start)
        .collect();

    let xmip_processes_to_start = document
        .xmip_processes
        .into_iter()
        .filter(|xmip_process| xmip_process.start)
        .collect::<Vec<_>>();

    let verified_extensions = xmip_processes_to_start
        .iter()
        .flat_map(|xmip_process| {
            xmip_process.extensions.iter().chain(
                xmip_process
                    .xmip_subprocesses
                    .iter()
                    .flat_map(|xmip_subprocess| xmip_subprocess.extensions.iter()),
            )
        })
        .map(verified_extension)
        .collect();

    let starting = |locations: Vec<ConfiguredLocation>| {
        locations
            .into_iter()
            .filter(|location| location.start)
            .collect()
    };

    Ok((
        ExecutionTree {
            service: document.service,
            modules_to_start,
            xmip_processes_to_start,
            receive_locations_to_start: starting(document.receive_locations),
            send_locations_to_start: starting(document.send_locations),
            verified_extensions,
        },
        report,
    ))
}

/// Everything in the document that would stop the node starting, as errors,
/// and what would start it degraded, as warnings.
#[must_use]
pub fn validate_startup_configuration(
    document: &XmipConfigurationDocument,
) -> StartupValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let configured_modules = document
        .modules
        .iter()
        .map(|module| module.name.as_str())
        .collect::<BTreeSet<_>>();

    let started_modules = document
        .modules
        .iter()
        .filter(|module| module.start)
        .map(|module| module.name.as_str())
        .collect::<BTreeSet<_>>();

    for module in &document.modules {
        if module.name.trim().is_empty() {
            errors.push("configured module requires a name".to_string());
        }

        if module.manifest.capabilities.is_empty() {
            warnings.push(format!("module '{}' declares no capabilities", module.name));
        }
    }

    for xmip_process in &document.xmip_processes {
        if xmip_process.name.trim().is_empty() {
            errors.push("configured Xmip Process requires a name".to_string());
        }

        let owner = format!("Xmip Process '{}'", xmip_process.name);
        for required_module in &xmip_process.required_modules {
            validate_required_module(
                required_module,
                &configured_modules,
                &started_modules,
                &mut errors,
                &mut warnings,
                &owner,
            );
        }

        for extension in &xmip_process.extensions {
            verify_extension_manifest(extension, &mut errors, &owner);
        }

        for xmip_subprocess in &xmip_process.xmip_subprocesses {
            if xmip_subprocess.name.trim().is_empty() {
                errors.push(format!(
                    "Xmip Process '{}' has an Xmip Subprocess without a name",
                    xmip_process.name
                ));
            }

            let owner = format!(
                "Xmip Subprocess '{}' of Xmip Process '{}'",
                xmip_subprocess.name, xmip_process.name
            );
            for required_module in &xmip_subprocess.required_modules {
                validate_required_module(
                    required_module,
                    &configured_modules,
                    &started_modules,
                    &mut errors,
                    &mut warnings,
                    &owner,
                );
            }

            for extension in &xmip_subprocess.extensions {
                verify_extension_manifest(extension, &mut errors, &owner);
            }
        }
    }

    for (stage, locations) in [
        ("Receive Location", &document.receive_locations),
        ("Send Location", &document.send_locations),
    ] {
        for location in locations {
            validate_location(stage, location, &mut errors);
        }
    }

    StartupValidationReport { errors, warnings }
}

/// A location the document names but leaves empty. The document already
/// refuses one without a `transport` key; this refuses one whose value says
/// nothing, which is what an editor writes when nobody chose.
fn validate_location(stage: &str, location: &ConfiguredLocation, errors: &mut Vec<String>) {
    if location.name.trim().is_empty() {
        errors.push(format!("configured {stage} requires a name"));
    }

    if location.transport.trim().is_empty() {
        errors.push(format!("{stage} '{}' requires a transport", location.name));
    }
}

fn validate_required_module(
    required_module: &str,
    configured_modules: &BTreeSet<&str>,
    started_modules: &BTreeSet<&str>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    owner: &str,
) {
    if !configured_modules.contains(required_module) {
        errors.push(format!(
            "{owner} requires missing module '{required_module}'"
        ));
        return;
    }

    if !started_modules.contains(required_module) {
        warnings.push(format!(
            "{owner} requires module '{required_module}', but it is configured not to start"
        ));
    }
}

fn verify_extension_manifest(extension: &ExtensionManifest, errors: &mut Vec<String>, owner: &str) {
    if extension.name.trim().is_empty() {
        errors.push(format!("{owner} references an extension without a name"));
    }

    if extension.version.trim().is_empty() {
        errors.push(format!("extension '{}' requires a version", extension.name));
    }

    if extension.entrypoint.path.trim().is_empty() {
        errors.push(format!(
            "extension '{}' requires an entrypoint path",
            extension.name
        ));
    }
}

fn verified_extension(extension: &ExtensionManifest) -> VerifiedExtensionNode {
    VerifiedExtensionNode {
        name: extension.name.clone(),
        version: extension.version.clone(),
        loaded_during_startup: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = r#"
[service]
name = "xmip"
cluster_name = "home"
node_name = "node-a"

[[modules]]
name = "file"
start = true
[modules.manifest.identity]
name = "file"
version = "0.1.0"
[[modules.manifest.capabilities]]
capability = "transport:file"
execution_host = "native-rust"
trusted_required = true
[modules.manifest.entrypoint]
library_path = "xmip_handler_file"
symbol = "xmip_create_module"

[[xmip_processes]]
name = "inbound"
start = true
required_modules = ["file"]
extensions = []

[[xmip_processes.xmip_subprocesses]]
name = "normalize"
required_modules = ["file"]
[[xmip_processes.xmip_subprocesses.extensions]]
name = "normalize-text"
version = "0.1.0"
execution_host = "native-rust"
required_capabilities = []
[xmip_processes.xmip_subprocesses.extensions.entrypoint]
path = "extensions/normalize_text"
symbol_or_command = "run"

[[receive_locations]]
name = "orders-in"
start = true
transport = "file"
address = "C:/in"

[[send_locations]]
name = "billing-out"
start = false
transport = "file"
address = "C:/out"
"#;

    #[test]
    fn the_tree_is_what_the_document_starts_and_extensions_are_verified_not_loaded() {
        let document = configure::parse_toml(NODE).expect("parses");
        let (tree, report) = build_execution_tree(document.clone()).expect("valid tree");

        assert!(report.is_valid());
        assert_eq!(tree.service, document.service);
        assert_eq!(tree.modules_to_start, document.modules);
        assert_eq!(tree.xmip_processes_to_start, document.xmip_processes);
        assert_eq!(tree.receive_locations_to_start, document.receive_locations);
        assert!(tree.send_locations_to_start.is_empty(), "start = false");
        assert_eq!(tree.verified_extensions.len(), 1);
        assert!(!tree.verified_extensions[0].loaded_during_startup);
    }

    #[test]
    fn a_location_with_an_empty_transport_is_refused() {
        let source = NODE.replace(
            "transport = \"file\"\naddress = \"C:/in\"",
            "transport = \"\"\naddress = \"C:/in\"",
        );
        let document = configure::parse_toml(&source).expect("parses");
        let report = build_execution_tree(document).expect_err("refused");

        assert_eq!(
            report.errors,
            ["Receive Location 'orders-in' requires a transport"]
        );
    }
}
