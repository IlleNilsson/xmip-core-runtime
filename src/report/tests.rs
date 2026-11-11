use std::path::{Path, PathBuf};

use report::{AtRest, Data, Installation, Report, Reports, answer};
use serde_json::{Value, json};
use xaudit::audit_query::AuditQuery;
use xaudit::audit_store;

use super::{Composed, PROBED, Unanswered, act, carry, configuration};

/// A folder of the test's own under the system's temporary directory.
fn folder(name: &str) -> PathBuf {
    let folder = std::env::temp_dir().join(format!("xmip-report-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).expect("a folder");
    folder
}

/// The test cluster's first node, keeping Xmip Storage itself, with a
/// Receive and a Send Location and `tables` after them.
fn node_text(tables: &str) -> String {
    let cluster = configure::fixture::test_cluster();
    let node = &cluster.node(0).name;
    format!(
        "roles = \"storage\"\n[service]\nname = \"xmip-{node}\"\ncluster_name = \"{}\"\n\
         node_name = \"{node}\"\n\
         [[receive_locations]]\nname = \"in\"\naddress = \"https://h/in\"\n\
         [[send_locations]]\nname = \"out\"\naddress = \"sftp://h/out\"\n{tables}",
        cluster.name
    )
}

fn written(folder: &Path, text: &str) -> String {
    let path = folder.join("node.xmip");
    std::fs::write(&path, text).expect("written");
    path.display().to_string()
}

fn opened(arguments: &Value) -> Result<Value, Unanswered> {
    act("open", &arguments.to_string(), usize::MAX)
        .map(|answer| serde_json::from_str(&answer).expect("JSON"))
}

fn listing(arguments: &Value) -> Result<Value, Unanswered> {
    act("list", &arguments.to_string(), usize::MAX)
        .map(|answer| serde_json::from_str(&answer).expect("JSON"))
}

fn names(list: &Value) -> Vec<&str> {
    list["reports"]
        .as_array()
        .expect("reports")
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect()
}

#[test]
fn a_nodes_own_configuration_is_probed_every_location_undeclared_and_so_a_gap() {
    let folder = folder("node");
    let configuration = written(&folder, &node_text(""));
    let answer = opened(&json!({
        "report": "Regulation", "parameter": "GDPR", "row": "Encryption in transit",
        "configuration": configuration, "program": "xmip",
        "directory": folder.display().to_string(),
    }))
    .expect("opened");
    let cluster = configure::fixture::test_cluster();
    assert_eq!(answer["node"], json!(cluster.node(0).name));
    let requirement = &answer["requirement"];
    assert_eq!(requirement["state"], "gap");
    assert_eq!(requirement["behind"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        requirement["actions"]
            .as_array()
            .expect("actions")
            .iter()
            .map(|action| action["kind"].clone())
            .collect::<Vec<_>>(),
        [json!("not-yet-available")],
        "no Location is plain, both are undeclared"
    );
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn a_clusters_file_is_sliced_for_the_node_named_and_refused_without_one() {
    let cluster = configure::fixture::test_cluster();
    let storing = &cluster.with_role("storage").name;
    let sliced = configuration(&cluster.text, Some(storing)).expect("sliced");
    assert_eq!(&sliced.service.node_name, storing);

    let refused = configuration(&cluster.text, None).expect_err("no node named");
    for node in &cluster.nodes {
        assert!(refused.contains(&node.name), "{refused}");
    }
    let own = configure::parse_toml(&node_text("")).expect("parses");
    let other = &cluster.node(1).name;
    let refused = configuration(&node_text(""), Some(other)).expect_err("another node");
    assert!(
        refused.contains(&own.service.node_name) && refused.contains(other),
        "{refused}"
    );

    let folder = folder("cluster");
    let answer = opened(&json!({
        "report": "Regulation", "parameter": "GDPR", "row": "Encryption at rest",
        "configuration": cluster.path.display().to_string(), "node": storing,
        "program": "xmip", "directory": folder.display().to_string(),
    }))
    .expect("opened");
    assert_eq!(answer["node"], json!(storing));
    assert_eq!(
        answer["requirement"]["state"], "evidence",
        "sealed on its own"
    );
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn each_data_domain_is_kept_as_the_one_storage_decision_says() {
    let server = node_text("[runtime]\nstorage = \"postgresql\"\nconnection = \"host=db-1\"\n");
    let composed = Composed::of(configure::parse_toml(&server).expect("parses")).expect("kept");
    assert_eq!(composed.at_rest("runtime"), AtRest::Server("postgresql"));
    assert_eq!(composed.at_rest("audit"), AtRest::Sealed);

    let listing = node_text("[storage]\nnodes = [\"storage.example:7443\"]\n")
        .replace("roles = \"storage\"", "roles = \"receiving\"");
    let composed = Composed::of(configure::parse_toml(&listing).expect("parses")).expect("kept");
    assert_eq!(composed.at_rest("administration"), AtRest::StorageNodes);

    let neither = node_text("").replace("roles = \"storage\"\n", "");
    let refused = Composed::of(configure::parse_toml(&neither).expect("parses"))
        .err()
        .expect("kept nowhere");
    assert!(refused.contains("[storage] nodes"), "{refused}");
}

#[test]
fn one_probe_is_one_audit_record_and_the_list_expects_what_it_took() {
    let folder = folder("probed");
    let directory = folder.display().to_string();
    let configuration = written(&folder, &node_text(""));
    let answer = opened(&json!({
        "report": "Regulation", "parameter": "GDPR", "configuration": configuration,
        "program": "xmip", "directory": directory,
    }))
    .expect("opened");

    let file = audit_store::stated(Some(&folder)).expect("a file");
    let query = AuditQuery::from_pairs([("action", PROBED)]).expect("a query");
    let page = audit_store::ask(&file, &query).expect("read");
    assert_eq!(page.matched, 1);
    let record = &page.records[0];
    assert_eq!(record.properties["report"], "Regulation");
    assert_eq!(record.properties["parameter"], "GDPR");
    assert_eq!(record.properties["took_ms"], answer["took_ms"].to_string());
    assert_eq!(
        record.message.as_deref(),
        Some(
            format!(
                "The Regulation Report's Quest probed node {} for GDPR in {} ms and changed \
                 nothing.",
                answer["node"].as_str().expect("a node"),
                answer["took_ms"]
            )
            .as_str()
        ),
        "the Quest probes, the Report presents"
    );

    let list = listing(&json!({ "directory": directory })).expect("listed");
    let regulation = list["reports"]
        .as_array()
        .expect("reports")
        .iter()
        .find(|entry| entry["name"] == "Regulation")
        .expect("listed");
    assert_eq!(regulation["took_ms"], answer["took_ms"]);
    assert_eq!(regulation["probed_at"], json!(record.at));
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn a_report_that_cannot_be_opened_is_refused_before_its_configuration_is_read() {
    let folder = folder("before");
    let directory = folder.display().to_string();
    let missing = folder.join("nowhere.xmip").display().to_string();
    let cluster = configure::fixture::test_cluster()
        .path
        .display()
        .to_string();
    for (report, configuration, said) in [
        ("Audit", &missing, "xmip_audit_read_v1"),
        (
            "Parties",
            &missing,
            "the Parties Report is not yet available",
        ),
        (
            "Firewall",
            &cluster,
            "the Firewall Report is not yet available",
        ),
        ("Nowhere", &missing, "no Report is named 'Nowhere'"),
    ] {
        let Err(Unanswered::Refused(refused)) = opened(&json!({
            "report": report, "configuration": configuration, "program": "xmip",
            "directory": directory,
        })) else {
            panic!("{report} is refused, never a file failing or a node asked for");
        };
        assert!(
            refused.starts_with("REFUSED: ") && refused.contains(said),
            "{refused}"
        );
    }
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn a_table_naming_no_technology_is_refused_and_never_probed_as_evidence() {
    let folder = folder("misnamed");
    let configuration = written(
        &folder,
        &node_text("[runtime]\nstorage = \"postgres\"\nconnection = \"host=db-1 dbname=x\"\n"),
    );
    let Err(Unanswered::Refused(refused)) = opened(&json!({
        "report": "Regulation", "parameter": "GDPR", "row": "Encryption at rest",
        "configuration": configuration, "program": "xmip",
        "directory": folder.display().to_string(),
    })) else {
        panic!("a misnamed storage is refused");
    };
    assert!(
        refused.contains("[runtime] storage: 'postgres' is none Xmip Storage keeps"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn an_audit_that_cannot_be_read_leaves_every_report_listed_and_says_why() {
    let folder = folder("unreadable");
    let file = audit_store::stated(Some(&folder)).expect("a file");
    // A folder where the audit file is: there, and not readable as one.
    std::fs::create_dir_all(&file).expect("a folder in its place");
    let list = listing(&json!({ "directory": folder.display().to_string() })).expect("listed");
    let _ = std::fs::remove_dir_all(&folder);
    let standard = Reports::standard();
    let every: Vec<&str> = standard.iter().map(Report::name).collect();
    // Xmip's own, in order; a test carrying one of its own may add it after.
    assert_eq!(names(&list)[..every.len()], every[..]);
    let unread = list["unread"].as_str().expect("said why");
    assert!(unread.starts_with("FAILED: "), "{unread}");
    let at = every.iter().position(|name| *name == "Regulation");
    let regulation = &list["reports"][at.expect("listed")];
    assert_eq!(regulation["expect"], answer::UNREAD);
    assert!(regulation.get("took_ms").is_none());
}

#[test]
fn one_report_is_listed_by_name_and_a_name_that_is_none_refused() {
    let folder = folder("one");
    let directory = folder.display().to_string();
    let one = listing(&json!({ "report": "Regulation", "directory": directory })).expect("one");
    assert_eq!(names(&one), ["Regulation"]);
    let Err(Unanswered::Refused(refused)) =
        listing(&json!({ "report": "Nowhere", "directory": directory }))
    else {
        panic!("a name that is none is refused");
    };
    assert!(
        refused.starts_with("REFUSED: no Report is named 'Nowhere'; there are: Audit"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn what_cannot_be_opened_is_refused_and_nothing_is_audited() {
    let folder = folder("refused");
    let directory = folder.display().to_string();
    let configuration = written(&folder, &node_text(""));
    for (arguments, said) in [
        (
            json!({ "report": "Audit", "configuration": configuration, "program": "xmip",
                 "directory": directory }),
            "xmip_audit_read_v1",
        ),
        (
            json!({ "report": "Regulation", "parameter": "GDPR", "configuration": configuration,
                 "program": "", "directory": directory }),
            "no program",
        ),
        (
            json!({ "report": "Regulation", "configuration": configuration }),
            "do not read",
        ),
    ] {
        let Err(Unanswered::Refused(refused)) = opened(&arguments) else {
            panic!("{arguments} is refused");
        };
        assert!(
            refused.starts_with("REFUSED: ") && refused.contains(said),
            "{refused}"
        );
    }
    assert!(audit_store::stated(Some(&folder)).is_none_or(|file| !file.exists()));
    let _ = std::fs::remove_dir_all(&folder);
}

/// A Report a module carries.
struct Carried;

impl Report for Carried {
    fn name(&self) -> &'static str {
        "Carried by a module"
    }

    fn covers(&self) -> &'static str {
        "What a module reports."
    }

    fn data(&self) -> Data<'_> {
        Data::Quest(None)
    }
}

#[test]
fn a_carried_report_is_listed_after_xmips_and_a_second_of_its_name_refused() {
    carry(Box::new(Carried)).expect("carried");
    let folder = folder("carried");
    let list = listing(&json!({ "directory": folder.display().to_string() })).expect("listed");
    let _ = std::fs::remove_dir_all(&folder);
    let names = names(&list);
    let standard = Reports::standard();
    let own: Vec<&str> = standard.iter().map(Report::name).collect();
    assert_eq!(names.last(), Some(&"Carried by a module"), "{names:?}");
    assert_eq!(
        names[..names.len() - 1],
        own[..],
        "Xmip's own first, in order"
    );
    let refused = carry(Box::new(Carried)).expect_err("held already");
    assert!(refused.contains("'Carried by a module'"), "{refused}");
}
