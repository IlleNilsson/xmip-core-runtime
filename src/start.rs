//! A node's configuration read, planned and validated for a surface: the
//! first three of ADR-0018's startup phases, and nothing that runs.
//!
//! `xmip_start_v1` hands a surface this, and publishes what it planned
//! through `operator.rs`. Running a node — the other six phases, its Modules
//! loaded and its Receive Locations accepting work — is
//! [`crate::running::Running::start`], called by the program that links the
//! technologies the node needs (ADR-0018, amendment 2026-09-26); a surface's
//! process links none, and whether it may run a node at all is open problem
//! 20. Both read a configuration through [`read`], one reading.
//!
//! Its two exports, `xmip_start_v1` and `xmip_validate_v1`, are the
//! boundary and live in `ffi/start.rs` (ADR-0050, refined 2026-09-25); what
//! they do is here.

use std::path::Path;

use configure::{
    DocumentKind, XmipApplicationDocument, XmipConfigurationDocument, application_problems,
    document_kind, parse_application,
};
use observe::{Health, HealthRecord, Snapshot, now_unix_nanos};

use crate::catalogue;
use crate::execution_tree::{build_execution_tree, validate_startup_configuration};
use crate::operator::publish;
use crate::service::read_node;

/// What a runtime says about itself before any node has published: it is
/// here, and it has nothing to run. `Stressed`, not `Done` — nothing is failing
/// — and not `Fine`, because an operator who sees `Fine` over an unconfigured
/// runtime has been told something false. The one line of evidence is the one
/// they need.
pub(crate) fn unconfigured() -> Snapshot {
    let now = now_unix_nanos();

    let mut snapshot = Snapshot::new();

    snapshot.record_health(HealthRecord {
        scope: "xmip:///".into(),
        health: Health::Stressed,
        severity: 50,
        evidence: "runtime loaded, no node started — give xmip_start_v1 a node TOML".into(),
        observed_unix_nanos: now,
    });

    snapshot
}

/// A configuration that could not be read: why, and the scope that says so —
/// the node's, once the document named one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unread {
    pub scope: String,
    pub reason: String,
}

/// What startup phase 1 reads: the node's configuration, the Xmip
/// Applications it binds, and the file each was read from.
pub type Read = (
    XmipConfigurationDocument,
    Vec<XmipApplicationDocument>,
    Vec<ApplicationFile>,
);

/// A bound Xmip Application's file as it was read: what an operator is
/// shown a Subscription's configuration from (ADR-0013, amendment
/// 2026-09-30), so nothing reads the file a second time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationFile {
    /// The Application's name, as its binding names it.
    pub name: String,
    /// Where it was read from.
    pub file: String,
    /// What the file said.
    pub text: String,
}

/// Startup phase 1: the node configuration at `path`, and every Xmip
/// Application it binds, each read from the file its binding names, relative
/// to the configuration (ADR-0064).
///
/// # Errors
/// The file cannot be read or does not parse, or a bound Application cannot
/// be read or does not parse.
pub fn read(path: &str) -> Result<Read, Unread> {
    let root = |reason: String| Unread {
        scope: "xmip:///".to_string(),
        reason,
    };
    let source = std::fs::read_to_string(path)
        .map_err(|error| root(format!("cannot read {path}: {error}")))?;
    let document = read_node(&source).map_err(|report| {
        root(format!(
            "{path} does not parse: {}",
            report.errors.join("; ")
        ))
    })?;
    let (applications, files) = bound_applications(path, &document).map_err(|reason| Unread {
        scope: format!("xmip:///{}", document.service.node_name),
        reason: format!("configuration refused: {reason}"),
    })?;

    Ok((document, applications, files))
}

/// Plan a node from its configuration file, as a surface asks: read it, build
/// the execution tree, validate it against the technologies this runtime
/// carries, and say what it would start. Nothing is loaded and nothing runs,
/// and every record says so — an operator reading `Fine` over a node that
/// has not loaded a module has been told something false.
///
/// Red when the file cannot be read or does not validate, with the errors as
/// evidence. A refusal that names the fault is the point of validating first.
#[must_use]
pub fn start(path: &str) -> Snapshot {
    let now = now_unix_nanos();
    let mut snapshot = Snapshot::new();
    let refuse = |snapshot: &mut Snapshot, scope: String, evidence: String| {
        snapshot.record_health(HealthRecord {
            scope,
            health: Health::Done,
            severity: 90,
            evidence,
            observed_unix_nanos: now,
        });
    };

    let (document, applications, _) = match read(path) {
        Ok(read) => read,
        Err(Unread { scope, reason }) => {
            refuse(&mut snapshot, scope, reason);
            return snapshot;
        }
    };

    let node = format!("xmip:///{}", document.service.node_name);

    let tree = match build_execution_tree(document, &applications, &catalogue::declarations()) {
        Ok((tree, _)) => tree,
        Err(report) => {
            let evidence = format!("configuration refused: {}", report.errors.join("; "));
            refuse(&mut snapshot, node, evidence);
            return snapshot;
        }
    };

    snapshot.record_health(HealthRecord {
        scope: node.clone(),
        health: Health::Stressed,
        severity: 50,
        evidence: format!(
            "{} module(s), {} process(es), {} Subscription(s) validated and planned; not \
             running \u{2014} a node runs in the program that links its technologies",
            tree.modules_to_start.len(),
            tree.xmip_processes_to_start.len(),
            tree.subscriptions.len()
        ),
        observed_unix_nanos: now,
    });

    for module in &tree.modules_to_start {
        snapshot.record_health(HealthRecord {
            scope: format!("{node}/module/{}", module.name),
            health: Health::Stressed,
            severity: 50,
            evidence: format!("planned, not loaded ({})", module.manifest.identity.version),
            observed_unix_nanos: now,
        });
    }

    for process in &tree.xmip_processes_to_start {
        snapshot.record_health(HealthRecord {
            scope: format!("{node}/process/{}", process.name),
            health: Health::Stressed,
            severity: 50,
            evidence: format!(
                "planned, not started; needs {}",
                process.required_modules.join(", ")
            ),
            observed_unix_nanos: now,
        });
    }

    // The other two stages of the message path. xmip:///<node>/<stage>/<name>
    // is what the GUI groups by, and Receive and Send are what an operator
    // runs — a node with only Process on the page is two thirds empty.
    for (stage, locations) in [
        ("receive", &tree.receive_locations_to_start),
        ("send", &tree.send_locations_to_start),
    ] {
        for location in locations {
            snapshot.record_health(HealthRecord {
                scope: format!("{node}/{stage}/{}", location.name),
                health: Health::Stressed,
                severity: 50,
                evidence: format!(
                    "planned, not started; {} at {}",
                    location.transport, location.address
                ),
                observed_unix_nanos: now,
            });
        }
    }

    snapshot
}

/// The Xmip Applications `document` binds, each read from the file its
/// binding names, relative to the configuration at `path` (ADR-0064).
fn bound_applications(
    path: &str,
    document: &XmipConfigurationDocument,
) -> Result<(Vec<XmipApplicationDocument>, Vec<ApplicationFile>), String> {
    let base = Path::new(path).parent().unwrap_or_else(|| Path::new(""));

    document
        .applications
        .iter()
        .map(|binding| {
            let file = base.join(&binding.document);
            let source = std::fs::read_to_string(&file).map_err(|error| {
                format!(
                    "cannot read the Xmip Application {}: {error}",
                    file.display()
                )
            })?;
            let application = parse_application(&source)
                .map_err(|error| format!("{} does not parse: {error}", file.display()))?;
            let read = ApplicationFile {
                name: binding.name.clone(),
                file: file.display().to_string(),
                text: source,
            };
            Ok((application, read))
        })
        .collect::<Result<Vec<_>, String>>()
        .map(|read| read.into_iter().unzip())
}

/// [`start`], then publish what it found: true when the node validated.
/// Validation asks whether any leaf is Done, not what the root rolls up to: a
/// Done no longer propagates (ADR-0041), so the root would read Holding, but
/// one Done leaf still means the configuration is invalid.
pub(crate) fn start_published(path: &str) -> bool {
    let snapshot = start(path);
    let valid = !snapshot
        .health("xmip:///")
        .iter()
        .any(|record| record.health == Health::Done);

    publish(snapshot);
    valid
}

/// Validate a document without starting anything, and return the problems.
/// Publishes nothing — the running estate is untouched. ADR-0027 clause 9,
/// the editor's Validate.
///
/// Either document `configure` reads, which it tells apart: an Xmip
/// Application is checked as a design (ADR-0064), and a node configuration
/// as startup would check it before building the tree, its bindings as far
/// as they say on their own — the Applications they join are files beside
/// it, which a text does not have, and [`start`] reads them. Each Location
/// is held to the declaration of every technology this runtime carries.
///
/// Empty when the document is good. Each string is one problem, in the
/// words `xmip-core-configure` and the execution-tree validator use.
#[must_use]
pub fn validate(source: &str) -> Vec<String> {
    match document_kind(source) {
        DocumentKind::Application => application_problems(source),
        DocumentKind::Node => match read_node(source) {
            Ok(document) => {
                validate_startup_configuration(&document, &catalogue::declarations()).errors
            }
            Err(report) => report.errors,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_from_a_missing_file_is_done_and_says_which_file() {
        let snapshot = start("Z:/no/such/node.toml");

        assert_eq!(snapshot.worst("xmip:///"), Some(Health::Done));
        assert!(
            snapshot.health("xmip:///")[0]
                .evidence
                .contains("no/such/node.toml")
        );
    }

    #[test]
    fn starting_from_a_valid_file_plans_the_node_and_says_it_is_not_running() {
        let path = std::env::temp_dir().join("xmip-operate-start-test.toml");
        std::fs::write(
            &path,
            r#"
[service]
name = "xmip-edge-01"
cluster_name = "lab"
node_name = "edge-01"

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
library_path = "xmip_core_transport_file"
symbol = "xmip_create_module_v1"

[[xmip_processes]]
name = "approval"
start = true
required_modules = ["file"]
xmip_subprocesses = []
extensions = []

[[receive_locations]]
name = "orders-in"
start = true
transport = "file"
address = "C:/in"

[[send_locations]]
name = "billing-out"
start = true
transport = "file"
address = "C:/out"
"#,
        )
        .expect("write fixture");

        let snapshot = start(path.to_str().expect("utf-8 path"));

        let records = snapshot.health("xmip:///edge-01");
        assert_eq!(records.len(), 5, "node, module, process, receive, send");
        assert!(
            records
                .iter()
                .any(|r| r.scope == "xmip:///edge-01/receive/orders-in")
        );
        assert!(
            records
                .iter()
                .any(|r| r.scope == "xmip:///edge-01/send/billing-out")
        );
        assert!(
            records.iter().all(|r| r.health == Health::Stressed),
            "planned, not running"
        );
        assert!(
            records
                .iter()
                .any(|r| r.scope == "xmip:///edge-01/module/file")
        );
        assert!(
            records
                .iter()
                .any(|r| r.scope == "xmip:///edge-01/process/approval")
        );
        assert!(records[0].evidence.contains("not running"));
    }

    #[test]
    fn a_good_configuration_validates_with_no_problems() {
        let source = r#"
[service]
name = "xmip-edge-01"
cluster_name = "lab"
node_name = "edge-01"

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
library_path = "xmip_core_transport_file"
symbol = "xmip_create_module_v1"
"#;

        assert!(
            validate(source).is_empty(),
            "a well-formed node has no problems"
        );
    }

    #[test]
    fn a_minimal_process_validates() {
        // ADR-0031, amendment 2026-09-24: a Process that needs no module and
        // has no Subprocess or Extension need not say so.
        let source = "[service]\nname = \"n\"\ncluster_name = \"c\"\nnode_name = \"d\"\n\
                      [[xmip_processes]]\nname = \"minimal\"\nstart = true\n";

        assert!(validate(source).is_empty(), "{:?}", validate(source));
    }

    #[test]
    fn a_location_missing_start_or_transport_is_refused_not_defaulted() {
        let head = "[service]\nname = \"n\"\ncluster_name = \"c\"\nnode_name = \"d\"\n";
        let no_start = format!(
            "{head}[[receive_locations]]\nname = \"in\"\ntransport = \"file\"\naddress = \"a\"\n"
        );
        let no_transport =
            format!("{head}[[send_locations]]\nname = \"out\"\nstart = true\naddress = \"a\"\n");

        for (source, key) in [(no_start, "start"), (no_transport, "transport")] {
            let problems = validate(&source);
            assert_eq!(problems.len(), 1, "{problems:?}");
            assert!(problems[0].contains(key), "names `{key}`: {}", problems[0]);
        }
    }

    #[test]
    fn a_broken_configuration_names_its_problems_and_publishes_nothing() {
        // Not TOML at all. validate returns the parse problem and, being
        // validate, changes nothing an observer would see.
        let problems = validate("this is not toml {{{");

        assert!(!problems.is_empty());
        assert!(
            problems[0].to_lowercase().contains("parse") || problems[0].contains("configuration")
        );
    }

    const ORDERS: &str = "[application]\nname = \"Orders\"\n\n[[receive_locations]]\n\
                          name = \"OrdersIn\"\n\n[[send_ports]]\nname = \"Billing\"\n\n\
                          [[subscriptions]]\nid = \"billing\"\n\
                          destination = { send-port = \"Billing\" }\nfilter = \"true\"\n";

    const ALPHA: &str = "[service]\nname = \"xmip-alpha\"\ncluster_name = \"orders\"\n\
                      node_name = \"alpha\"\n\n[[applications]]\nname = \"Orders\"\n\
                      document = \"orders.application.toml\"\n\n\
                      [[applications.receive_locations]]\nname = \"OrdersIn\"\nnode = \"alpha\"\n\
                      start = true\ntransport = \"xmip-core-transport-file\"\n\
                      address = \"/var/xmip/in/orders\"\n";

    #[test]
    fn an_application_validates_as_a_design() {
        assert!(validate(ORDERS).is_empty(), "{:?}", validate(ORDERS));

        let astray = ORDERS.replace("{ send-port = \"Billing\" }", "{ process = \"Approval\" }");
        assert_eq!(
            validate(&astray),
            [
                "Subscription 'billing' routes to the Xmip Process 'Approval', which the \
              Application does not declare"
            ]
        );
    }

    #[test]
    fn a_node_binding_an_application_validates_its_binding_as_far_as_it_says() {
        assert!(validate(ALPHA).is_empty(), "{:?}", validate(ALPHA));

        let nowhere = ALPHA.replace("node = \"alpha\"", "node = \"\"");
        assert_eq!(
            validate(&nowhere),
            ["the Receive Location 'OrdersIn' of 'Orders' requires the node that takes it"]
        );
    }

    #[test]
    fn starting_a_node_reads_the_applications_it_binds_beside_it() {
        let directory = std::env::temp_dir().join(format!("xmip-bind-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        std::fs::write(directory.join("orders.application.toml"), ORDERS).expect("writes");
        let node = directory.join("r1.toml");
        std::fs::write(&node, ALPHA).expect("writes");

        let snapshot = start(node.to_str().expect("utf-8 path"));
        let records = snapshot.health("xmip:///alpha");

        assert!(
            records
                .iter()
                .any(|r| r.scope == "xmip:///alpha/receive/OrdersIn"),
            "{records:?}"
        );
        assert!(
            records[0].evidence.contains("1 Subscription(s)"),
            "{}",
            records[0].evidence
        );

        std::fs::remove_file(directory.join("orders.application.toml")).expect("removes");
        let snapshot = start(node.to_str().expect("utf-8 path"));
        assert_eq!(snapshot.health("xmip:///alpha")[0].health, Health::Done);
        assert!(
            snapshot.health("xmip:///alpha")[0]
                .evidence
                .contains("cannot read the Xmip Application"),
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// ADR-0066 clause 1: a filter is compiled as the node starts, and one
    /// that does not compile refuses the node then, not at the first Message.
    #[test]
    fn a_filter_that_does_not_compile_refuses_the_node_at_start() {
        let directory = std::env::temp_dir().join(format!("xmip-filter-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let broken = ORDERS.replace(
            "filter = \"true\"",
            "filter = \"MessageType = 'Order' + 1\"",
        );
        assert_ne!(broken, ORDERS);
        std::fs::write(directory.join("orders.application.toml"), broken).expect("writes");
        let node = directory.join("r1.toml");
        std::fs::write(&node, ALPHA).expect("writes");

        let snapshot = start(node.to_str().expect("utf-8 path"));
        let refused = &snapshot.health("xmip:///alpha")[0];

        assert_eq!(refused.health, Health::Done);
        assert!(
            refused.evidence.contains("does not parse"),
            "{}",
            refused.evidence
        );
        assert!(
            refused.evidence.contains("arithmetic"),
            "{}",
            refused.evidence
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}
