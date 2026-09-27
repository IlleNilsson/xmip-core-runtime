//! Startup phases 2 and 3 (ADR-0018): build the execution tree from the
//! node's configuration document and validate it.
//!
//! The tree is derived from `configure::XmipConfigurationDocument` and holds
//! the document's own types — what starts, in the document's words — plus
//! the one thing only the runtime knows, which extensions it verified. Until
//! 2026-09-24 it read a second model of the configuration and restated a
//! subset of it in startup node types of its own (open problem 25, row b).
//!
//! A node that binds Xmip Applications (ADR-0064) is given them: the tree
//! takes the Locations its bindings give this node and every Subscription
//! of every bound Application, through `configure::bind`, which is the one
//! reading of a binding.

use abi::ExtensionManifest;
use configure::{
    ConfiguredLocation, ModuleConfiguration, ServiceConfiguration, XmipApplicationDocument,
    XmipConfigurationDocument, XmipProcessConfiguration,
};
use route::Subscription;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use xcore::settings::Applies;

/// What a node starts, taken from its configuration document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTree {
    pub service: ServiceConfiguration,
    pub modules_to_start: Vec<ModuleConfiguration>,
    pub xmip_processes_to_start: Vec<XmipProcessConfiguration>,
    pub receive_locations_to_start: Vec<ConfiguredLocation>,
    pub send_locations_to_start: Vec<ConfiguredLocation>,
    pub verified_extensions: Vec<VerifiedExtensionNode>,
    /// What routing asks of every published Message on this node: every
    /// Subscription of every Xmip Application the node binds.
    pub subscriptions: Vec<Subscription>,
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

/// Validate the document, bind the Xmip Applications it names from
/// `applications`, and take from both what starts.
///
/// # Errors
/// The validation report, when it holds an error — a binding that does not
/// join its Application among them.
pub fn build_execution_tree(
    document: XmipConfigurationDocument,
    applications: &[XmipApplicationDocument],
) -> Result<(ExecutionTree, StartupValidationReport), StartupValidationReport> {
    let mut report = validate_startup_configuration(&document);
    if !report.is_valid() {
        return Err(report);
    }

    let bound = match configure::bind(&document, applications) {
        Ok(bound) => bound,
        Err(problems) => {
            report.errors.extend(problems);
            return Err(report);
        }
    };

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

    Ok((
        ExecutionTree {
            service: document.service,
            modules_to_start,
            xmip_processes_to_start,
            receive_locations_to_start: starting(
                document
                    .receive_locations
                    .into_iter()
                    .chain(bound.receive_locations),
            ),
            send_locations_to_start: starting(
                document
                    .send_locations
                    .into_iter()
                    .chain(bound.send_locations),
            ),
            verified_extensions,
            subscriptions: bound.subscriptions,
        },
        report,
    ))
}

/// The locations that start, the node's own and those its bindings give it.
fn starting(locations: impl Iterator<Item = ConfiguredLocation>) -> Vec<ConfiguredLocation> {
    locations.filter(|location| location.start).collect()
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

    // Each Location's settings, held to the declaration its technology makes
    // of them, for every technology this runtime carries (ADR-0064,
    // amendment 2026-09-26): a node's own and every bound one.
    let declared = crate::catalogue::declarations();
    for (stage, side, locations) in [
        (
            "Receive Location",
            Applies::Receive,
            &document.receive_locations,
        ),
        ("Send Location", Applies::Send, &document.send_locations),
    ] {
        for location in locations {
            validate_location(stage, location, &mut errors);
            errors.extend(configure::location_problems(location, side, &declared));
        }
    }
    for binding in &document.applications {
        for (side, locations) in [
            (Applies::Receive, &binding.receive_locations),
            (Applies::Send, &binding.send_ports),
        ] {
            for bound in locations {
                errors.extend(configure::location_problems(
                    &bound.location,
                    side,
                    &declared,
                ));
            }
        }
    }

    errors.extend(configure::binding_problems(document));

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
        let (tree, report) = build_execution_tree(document.clone(), &[]).expect("valid tree");

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
        let report = build_execution_tree(document, &[]).expect_err("refused");

        assert_eq!(
            report.errors,
            ["Receive Location 'orders-in' requires a transport"]
        );
    }

    #[test]
    fn a_location_is_held_to_the_declaration_of_a_technology_carried() {
        use xcore::settings::{Kind, Presence, Setting, Settings};
        const DROP: &Settings = &Settings {
            technology: "xmip-core-transport-drop",
            settings: &[Setting {
                name: "pattern",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "Which file names a Receive Location takes.",
                applies: Applies::Receive,
            }],
        };
        crate::catalogue::carry(crate::catalogue::Capability::Transport, DROP);

        let source = NODE.replace(
            "transport = \"file\"\naddress = \"C:/in\"",
            "transport = \"xmip-core-transport-drop\"\naddress = \"C:/in\"\n\
             [receive_locations.settings]\ncolour = \"lime\"",
        );
        let document = configure::parse_toml(&source).expect("parses");
        let report = build_execution_tree(document, &[]).expect_err("refused");
        assert_eq!(report.errors.len(), 2, "{:?}", report.errors);
        assert!(report.errors.iter().any(|e| e.contains("\"colour\"")));
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("requires \"pattern\""))
        );
        assert!(
            report
                .errors
                .iter()
                .all(|e| e.contains("xmip-core-transport-drop"))
        );
    }

    /// The Application of `doc/application.md`, cut to one route.
    pub(crate) const ORDERS: &str = r#"[application]
name = "Orders"

[[receive_locations]]
name = "OrdersIn"

[[send_ports]]
name = "Billing"

[[subscriptions]]
id = "billing"
destination = { send-port = "Billing" }
filter = "MessageType = 'Order'"
"#;

    /// Node alpha binding it: alpha takes the Receive Location, beta the Send Port.
    pub(crate) const ALPHA: &str = r#"[service]
name = "xmip-alpha"
cluster_name = "orders"
node_name = "alpha"

[[applications]]
name = "Orders"
document = "orders.application.toml"

[[applications.receive_locations]]
name = "OrdersIn"
node = "alpha"
start = true
transport = "xmip-core-transport-file"
address = "/var/xmip/in/orders"

[[applications.send_ports]]
name = "Billing"
node = "beta"
start = true
transport = "xmip-core-transport-http"
address = "https://billing.example/orders"
"#;

    #[test]
    fn a_bound_application_gives_the_tree_its_locations_and_subscriptions() {
        let document = configure::parse_toml(ALPHA).expect("parses");
        let orders = configure::parse_application(ORDERS).expect("parses");
        let (tree, _) = build_execution_tree(document, &[orders]).expect("binds");

        assert_eq!(tree.receive_locations_to_start.len(), 1);
        assert_eq!(tree.receive_locations_to_start[0].name, "OrdersIn");
        assert!(tree.send_locations_to_start.is_empty(), "beta takes it");
        assert_eq!(tree.subscriptions.len(), 1);
        assert_eq!(tree.subscriptions[0].id, "billing");
    }

    #[test]
    fn a_binding_of_an_application_not_given_is_refused() {
        let document = configure::parse_toml(ALPHA).expect("parses");
        let report = build_execution_tree(document, &[]).expect_err("refused");

        assert_eq!(
            report.errors,
            ["the node binds the Xmip Application 'Orders', which it was not given"]
        );
    }
}
