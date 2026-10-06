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

use configure::{DocumentKind, XmipApplication, XmipConfigurationDocument, document_kind};
use observe::{Health, HealthRecord, Snapshot, now_unix_nanos};

use crate::catalogue;
use crate::execution_tree::{build_execution_tree, validate_startup_configuration};
use crate::operator::publish;
use crate::running::publication::location;
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
    Vec<XmipApplication>,
    Vec<ApplicationFile>,
);

/// The file a bound Xmip Application was read from, as it was read: what an
/// operator is shown a Subscription's configuration from (ADR-0013,
/// amendment 2026-09-30), so nothing reads the file a second time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationFile {
    /// The Application's name, as its binding names it.
    pub name: String,
    /// The node's configuration it is a section of.
    pub file: String,
    /// What the file said.
    pub text: String,
}

/// Startup phase 1: the node configuration at `path`, and every Xmip
/// Application it binds, each its section of the configuration
/// (`configure::section`, ADR-0064 amendment 2026-10-03).
///
/// # Errors
/// The file cannot be read or does not parse, or a bound Application is not
/// held or does not read.
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
    let (applications, files) =
        bound_applications(path, &source, &document).map_err(|reason| Unread {
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
            tree.work_processes_to_start.len(),
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

    for process in &tree.work_processes_to_start {
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

/// The Xmip Applications `document` binds, each its section of the
/// configuration `source` read from `path`.
fn bound_applications(
    path: &str,
    source: &str,
    document: &XmipConfigurationDocument,
) -> Result<(Vec<XmipApplication>, Vec<ApplicationFile>), String> {
    document
        .applications
        .iter()
        .map(|binding| {
            let held = configure::binding::section(document, &binding.name).ok_or_else(|| {
                format!(
                    "{path} binds the Xmip Application '{}' and holds no section of it",
                    binding.name
                )
            })?;
            let read = ApplicationFile {
                name: binding.name.clone(),
                file: path.to_string(),
                text: source.to_string(),
            };
            Ok((held.application()?, read))
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
/// Both documents `configure` reads, which it tells apart: a node
/// configuration is checked as startup would check it before building the
/// tree, its bindings with the Xmip Application sections they bind
/// (ADR-0064, amendment 2026-10-03). Each Location
/// is held to the declaration of every technology this runtime carries, and
/// `[tuning]` to the runtime's own. A cluster's `xmip.toml` is checked node
/// by node, each as the slice `configure::slice` writes it, every problem
/// opening with its node's location, `xmip:///<cluster>/node/<name>`
/// (ADR-0027 clause 4; ADR-0031, amendment 2026-10-03).
///
/// Empty when the document is good. Each string is one problem, in the
/// words `xmip-core-configure` and the execution-tree validator use.
#[must_use]
pub fn validate(source: &str) -> Vec<String> {
    match document_kind(source) {
        DocumentKind::Node => validate_node(source),
        DocumentKind::Cluster => match configure::slices(source) {
            Ok(slices) => slices
                .iter()
                .flat_map(|(node, slice)| {
                    let cluster = configure::parse_toml(slice)
                        .map(|document| document.service.cluster_name)
                        .unwrap_or_default();
                    let located = location(&cluster, node);
                    validate_node(slice)
                        .into_iter()
                        .map(move |problem| format!("{located}: {problem}"))
                })
                .collect(),
            Err(problem) => vec![problem],
        },
    }
}

fn validate_node(source: &str) -> Vec<String> {
    match read_node(source) {
        Ok(document) => {
            validate_startup_configuration(&document, &catalogue::declarations()).errors
        }
        Err(report) => report.errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `[service]` section of the test cluster's first node, and its
    /// name.
    fn service() -> (String, String) {
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node(0).name.clone();
        let head = format!(
            "[service]\nname = \"xmip-{node}\"\ncluster_name = \"{}\"\nnode_name = \"{node}\"\n",
            cluster.name
        );
        (head, node)
    }

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
        let (head, node) = service();
        std::fs::write(
            &path,
            format!(
                r#"
{head}
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

[[work_processes]]
name = "approval"
start = true
required_modules = ["file"]
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
"#
            ),
        )
        .expect("write fixture");

        let snapshot = start(path.to_str().expect("utf-8 path"));

        let at = format!("xmip:///{node}");
        let records = snapshot.health(&at);
        assert_eq!(records.len(), 5, "node, module, process, receive, send");
        for leaf in [
            "receive/orders-in",
            "send/billing-out",
            "module/file",
            "process/approval",
        ] {
            let scope = format!("{at}/{leaf}");
            assert!(records.iter().any(|r| r.scope == scope), "{scope}");
        }
        assert!(
            records.iter().all(|r| r.health == Health::Stressed),
            "planned, not running"
        );
        assert!(records[0].evidence.contains("not running"));
    }

    #[test]
    fn a_good_configuration_validates_with_no_problems() {
        let (head, _) = service();
        let source = format!(
            r#"
{head}
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
"#
        );

        assert!(
            validate(&source).is_empty(),
            "a well-formed node has no problems"
        );
    }

    #[test]
    fn a_minimal_process_validates() {
        // ADR-0031, amendment 2026-09-24: a Work Process that needs no
        // module and no Extension need not say so.
        let (head, _) = service();
        let source = format!("{head}[[work_processes]]\nname = \"minimal\"\nstart = true\n");

        assert!(validate(&source).is_empty(), "{:?}", validate(&source));
    }

    #[test]
    fn a_location_missing_start_or_transport_is_refused_not_defaulted() {
        let (head, _) = service();
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

    /// A node of the test cluster binding the Orders Application it holds
    /// as a section, taking its Receive Location.
    fn orders() -> (String, String) {
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node(0).name.clone();
        let text = format!(
            r#"[service]
name = "xmip"
cluster_name = "{name}"
node_name = "{node}"

[[applications]]
name = "Orders"

[[applications.receive_locations]]
name = "OrdersIn"
node = "{node}"
start = true
transport = "xmip-core-transport-file"
address = "/var/xmip/in/orders"

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

[[xmip_applications.subscriptions]]
id = "billing"
destination = {{ send-port = "Billing" }}
filter = "true"
"#,
            name = cluster.name
        );
        (text, node)
    }

    /// `text` written as a node's configuration in a directory of its own.
    fn written(text: &str, what: &str) -> (std::path::PathBuf, String) {
        let directory = std::env::temp_dir().join(format!("xmip-{what}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let node = directory.join("node.toml");
        std::fs::write(&node, text).expect("writes");
        let path = node.to_str().expect("utf-8 path").to_string();
        (directory, path)
    }

    #[test]
    fn a_node_binding_an_application_validates_its_binding_and_its_section() {
        let (text, node) = orders();
        assert!(validate(&text).is_empty(), "{:?}", validate(&text));

        let nowhere = text.replace(&format!("node = \"{node}\""), "node = \"\"");
        assert_eq!(
            validate(&nowhere),
            ["the Receive Location 'OrdersIn' of 'Orders' requires the node that takes it"]
        );

        let astray = text.replace(
            "{ send-port = \"Billing\" }",
            "{ work-process = \"Approval\" }",
        );
        assert_eq!(
            validate(&astray),
            [
                "Xmip Application 'Orders': Subscription 'billing' routes to the Work Process \
                 'Approval', which the Application does not declare"
            ]
        );
    }

    #[test]
    fn starting_a_node_reads_the_applications_it_holds_as_sections() {
        let (text, node) = orders();
        let (directory, path) = written(&text, "section");

        let snapshot = start(&path);
        let records = snapshot.health(&format!("xmip:///{node}"));
        assert!(
            records
                .iter()
                .any(|r| r.scope == format!("xmip:///{node}/receive/OrdersIn")),
            "{records:?}"
        );
        assert!(
            records[0].evidence.contains("1 Subscription(s)"),
            "{}",
            records[0].evidence
        );
        let read = read(&path).expect("reads");
        assert_eq!(read.1[0].subscriptions[0].id, "billing");
        assert_eq!(read.2[0].file, path);
        assert_eq!(read.2[0].text, text);

        let unheld = text[..text.find("[[xmip_applications]]").expect("held")].to_string();
        std::fs::write(&path, unheld).expect("writes");
        let refused = &start(&path).health(&format!("xmip:///{node}"))[0];
        assert_eq!(refused.health, Health::Done);
        assert!(
            refused.evidence.contains("holds no section"),
            "{}",
            refused.evidence
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// ADR-0066 clause 1: a filter is compiled as the node starts, and one
    /// that does not compile refuses the node then, not at the first Message.
    #[test]
    fn a_filter_that_does_not_compile_refuses_the_node_at_start() {
        let (text, node) = orders();
        let broken = text.replace(
            "filter = \"true\"",
            "filter = \"MessageType = 'Order' + 1\"",
        );
        assert_ne!(broken, text);
        let (directory, path) = written(&broken, "filter");

        let snapshot = start(&path);
        let refused = &snapshot.health(&format!("xmip:///{node}"))[0];

        assert_eq!(refused.health, Health::Done);
        assert!(
            refused.evidence.contains("arithmetic"),
            "{}",
            refused.evidence
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_clusters_file_validates_node_by_node_and_its_tuning_is_held_to_bounds() {
        let test = configure::fixture::test_cluster();
        let (name, first, second) = (&test.name, &test.node(0).name, &test.node(1).name);
        let cluster = format!(
            "[service]\nname = \"n\"\ncluster_name = \"{name}\"\n[tuning]\nsegments = 44\n\
             [nodes.{first}]\n[nodes.{second}.tuning]\nsegments = 0\n"
        );
        let problems = validate(&cluster);
        assert_eq!(problems.len(), 1, "{problems:?}");
        let located = format!("{}: ", location(name, second));
        assert!(
            problems[0].starts_with(&located) && problems[0].contains("segments"),
            "{problems:?}"
        );
        let good = cluster.replace("segments = 0", "segments = 8");
        assert!(validate(&good).is_empty(), "{:?}", validate(&good));
    }
}
