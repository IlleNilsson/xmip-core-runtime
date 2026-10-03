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
    BoundReceivePort, ConfiguredLocation, Declarations, DesignedSendPort, ModuleConfiguration,
    SendPortGroup, ServiceConfiguration, XmipApplication, XmipConfigurationDocument,
    XmipProcessConfiguration,
};
use route::Subscription;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use xcore::settings::Applies;

use crate::tuning::Tuning;

/// What a node starts, taken from its configuration document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTree {
    pub service: ServiceConfiguration,
    pub modules_to_start: Vec<ModuleConfiguration>,
    pub xmip_processes_to_start: Vec<XmipProcessConfiguration>,
    pub receive_locations_to_start: Vec<ConfiguredLocation>,
    /// The Receive Ports of the Applications the node binds that its bound
    /// Receive Locations are at, each Location with the interaction and
    /// depth it states (ADR-0031, amendment 2026-10-01).
    pub receive_ports: Vec<BoundReceivePort>,
    pub send_locations_to_start: Vec<ConfiguredLocation>,
    /// The Send Ports the node takes of the Applications it binds, with
    /// their policy: Send Locations in order, retry, failover, execution
    /// style, order key and failure policy (the same amendment).
    pub send_ports: Vec<DesignedSendPort>,
    pub verified_extensions: Vec<VerifiedExtensionNode>,
    /// What routing asks of every published Message on this node: every
    /// Subscription of every Xmip Application the node binds.
    pub subscriptions: Vec<Subscription>,
    /// The Send Port Groups of the Applications the node binds, which a
    /// Subscription routed to a group reaches.
    pub send_port_groups: Vec<SendPortGroup>,
    /// What the node runs by, `[tuning]` read with its defaults
    /// (ADR-0031, amendment 2026-10-03).
    pub tuning: Tuning,
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

/// Validate the document, each Location's settings against the technology
/// declarations in `declared`, bind the Xmip Applications it names from
/// `applications`, and take from both what starts.
///
/// # Errors
/// The validation report, when it holds an error — a binding that does not
/// join its Application among them.
pub fn build_execution_tree(
    document: XmipConfigurationDocument,
    applications: &[XmipApplication],
    declared: &Declarations,
) -> Result<(ExecutionTree, StartupValidationReport), StartupValidationReport> {
    let mut report = validate_startup_configuration(&document, declared);
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

    let tuning = Tuning::read(&document.tuning).map_err(|problems| StartupValidationReport {
        errors: problems,
        warnings: Vec::new(),
    })?;

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
            receive_ports: bound.receive_ports,
            send_locations_to_start: starting(
                document
                    .send_locations
                    .into_iter()
                    .chain(bound.send_locations),
            ),
            send_ports: bound.send_ports,
            verified_extensions,
            subscriptions: bound.subscriptions,
            send_port_groups: bound.send_port_groups,
            tuning,
        },
        report,
    ))
}

/// The locations that start, the node's own and those its bindings give it.
fn starting(locations: impl Iterator<Item = ConfiguredLocation>) -> Vec<ConfiguredLocation> {
    locations.filter(|location| location.start).collect()
}

/// Everything in the document that would stop the node starting, as errors,
/// and what would start it degraded, as warnings. Each Location is held to
/// the declaration its technology makes in `declared`; a technology `declared`
/// does not hold is the caller's to judge.
#[must_use]
pub fn validate_startup_configuration(
    document: &XmipConfigurationDocument,
    declared: &Declarations,
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
    // of them (ADR-0064, amendment 2026-09-26): a node's own and every bound
    // one.
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
            errors.extend(configure::location_problems(location, side, declared));
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
                    declared,
                ));
            }
        }
    }

    errors.extend(configure::binding_problems(document));
    // Every outward and hardware assumption, held to the runtime's own
    // declaration of them (ADR-0031, amendment 2026-10-03).
    if let Err(problems) = Tuning::read(&document.tuning) {
        errors.extend(problems);
    }
    // The Storage nodes it reaches, and the database server a Storage node
    // is in front of, read by Xmip Storage (`deployment-model.md` section 7).
    errors.extend(document.storage.problems());
    if let Some(database) = &document.storage.database {
        errors.extend(persist::storage::database::problems(
            &database.runtime,
            &database.administration,
            &database.password,
        ));
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

    /// A node's configuration, the test cluster's first node named in it.
    fn node() -> String {
        let cluster = configure::fixture::test_cluster();
        NODE.replace("<cluster>", &cluster.name)
            .replace("<node>", &cluster.node(0).name)
    }

    const NODE: &str = r#"
[service]
name = "xmip"
cluster_name = "<cluster>"
node_name = "<node>"

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
        let document = configure::parse_toml(&node()).expect("parses");
        let (tree, report) =
            build_execution_tree(document.clone(), &[], &Declarations::new()).expect("valid tree");

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
        let source = node().replace(
            "transport = \"file\"\naddress = \"C:/in\"",
            "transport = \"\"\naddress = \"C:/in\"",
        );
        let document = configure::parse_toml(&source).expect("parses");
        let report =
            build_execution_tree(document, &[], &Declarations::new()).expect_err("refused");

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
        let declared = Declarations::from([(DROP.technology, DROP)]);

        let source = node().replace(
            "transport = \"file\"\naddress = \"C:/in\"",
            "transport = \"xmip-core-transport-drop\"\naddress = \"C:/in\"\n\
             [receive_locations.settings]\ncolour = \"lime\"",
        );
        let document = configure::parse_toml(&source).expect("parses");
        let report = build_execution_tree(document, &[], &declared).expect_err("refused");
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

    /// A node of the test cluster at `place` binding the Orders Application
    /// it holds as a section: the first node takes the Receive Location,
    /// the second the Send Port.
    pub(crate) fn orders(place: usize) -> XmipConfigurationDocument {
        configure::parse_toml(&orders_text(place)).expect("parses")
    }

    /// The text [`orders`] reads.
    pub(crate) fn orders_text(place: usize) -> String {
        let cluster = configure::fixture::test_cluster();
        let (first, second) = (&cluster.node(0).name, &cluster.node(1).name);
        format!(
            r#"[service]
name = "xmip"
cluster_name = "{name}"
node_name = "{node}"

[[applications]]
name = "Orders"

[[applications.receive_locations]]
name = "OrdersIn"
node = "{first}"
start = true
transport = "xmip-core-transport-file"
address = "/var/xmip/in/orders"

[[applications.send_ports]]
name = "Billing"
node = "{second}"
start = true
transport = "xmip-core-transport-http"
address = "https://billing.example/orders"

[[xmip_applications]]
name = "Orders"

[[xmip_applications.receive_ports]]
name = "Orders"

[[xmip_applications.receive_locations]]
name = "OrdersIn"
receive_port = "Orders"
interaction = "data-transfer"
depth = "light"

[[xmip_applications.send_ports]]
name = "Billing"
execution_style = "sequential"
on_failure = "block"

[[xmip_applications.subscriptions]]
id = "billing"
destination = {{ send-port = "Billing" }}
filter = "MessageType = 'Order'"
"#,
            name = cluster.name,
            node = cluster.node(place).name,
        )
    }

    fn application(document: &XmipConfigurationDocument) -> XmipApplication {
        configure::binding::section(document, "Orders")
            .expect("held")
            .application()
            .expect("reads")
    }

    #[test]
    fn a_bound_application_gives_the_tree_its_locations_ports_and_subscriptions() {
        let document = orders(0);
        let design = application(&document);
        let (tree, _) =
            build_execution_tree(document, &[design], &Declarations::new()).expect("binds");

        assert_eq!(tree.receive_locations_to_start.len(), 1);
        assert_eq!(tree.receive_locations_to_start[0].name, "OrdersIn");
        assert_eq!(tree.receive_ports[0].name, "Orders");
        let location = &tree.receive_ports[0].receive_locations[0];
        assert_eq!(
            location.interaction,
            Some(configure::Interaction::DataTransfer)
        );
        assert_eq!(location.depth, Some(configure::Depth::Light));
        assert!(
            tree.send_locations_to_start.is_empty(),
            "the second takes it"
        );
        assert!(tree.send_ports.is_empty());
        assert_eq!(tree.subscriptions.len(), 1);
        assert_eq!(tree.subscriptions[0].id, "billing");

        let document = orders(1);
        let design = application(&document);
        let (tree, _) =
            build_execution_tree(document, &[design], &Declarations::new()).expect("binds");
        assert_eq!(
            tree.send_ports[0].on_failure,
            Some(configure::OnFailure::Block)
        );
        assert!(tree.receive_ports.is_empty());
    }

    #[test]
    fn a_binding_of_an_application_not_given_is_refused() {
        let report =
            build_execution_tree(orders(0), &[], &Declarations::new()).expect_err("refused");

        assert_eq!(
            report.errors,
            ["the node binds the Xmip Application 'Orders', which it was not given"]
        );
    }

    /// Startup phase 3 refuses a Receive Location without its Receive Port
    /// and a Sequential Send Port without its failure policy.
    #[test]
    fn a_location_without_its_port_and_a_sequential_port_without_on_failure_are_refused() {
        let text = orders_text(0)
            .replace("receive_port = \"Orders\"\n", "")
            .replace("on_failure = \"block\"\n", "");
        let document = configure::parse_toml(&text).expect("parses");

        let report = validate_startup_configuration(&document, &Declarations::new());
        assert_eq!(report.errors.len(), 2, "{:?}", report.errors);
        assert!(
            report.errors[0].contains("names no receive_port"),
            "{:?}",
            report.errors
        );
        assert!(
            report.errors[1].contains("states no on_failure"),
            "{:?}",
            report.errors
        );
    }
}
