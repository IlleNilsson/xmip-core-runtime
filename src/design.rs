//! `xmip_operate.h` section 10: the cluster's `xmip.toml` read, edited and
//! sliced for the designer and the Operation Desktop (ADR-0064, amendment
//! 2026-10-03; ADR-0031, amendment 2026-10-05), what the exports do.
//! The exports are `ffi/design.rs`'s; each reads its text, calls this, and
//! writes back what it answers.
//!
//! Nothing here is a rule. The file's views, an Xmip Application's routes,
//! a filter's text and structure, every edit and the slicing are
//! `xmip-core-configure`'s; this reads the JSON a surface hands over into
//! configure's types and writes configure's answers as JSON, which is how
//! they cross — in memory, never to disk (ADR-0031 clause 2).

use configure::filter::{self, FilterPart};
use configure::view_edit::{ClusterEdit, apply};
use configure::views::Views;
use configure::{DocumentKind, document_kind};
use serde::Serialize;

/// Why a node's own document is not sliced: it is the slice.
pub const NOT_A_CLUSTER: &str = "this is a node's configuration document, not a cluster's \
                                 xmip.toml: it declares no [nodes]; only the cluster's file is \
                                 edited, and each node's is sliced from it";

/// The cluster's file as one view per artifact kind, [`Views::of`], with
/// `document`: `cluster` where the text declares its nodes and `node` where
/// it is a node's own document, [`document_kind`] — so a surface offers no
/// node's file for editing without a rule of its own (ADR-0031, amendment
/// 2026-10-05).
///
/// # Errors
/// The reader's words when the text is not TOML.
pub fn views(cluster: &str) -> Result<String, String> {
    let mut answer =
        serde_json::to_value(Views::of(cluster)?).map_err(|error| error.to_string())?;
    answer["document"] = match document_kind(cluster) {
        DocumentKind::Cluster => "cluster",
        DocumentKind::Node => "node",
    }
    .into();
    json(&answer)
}

/// Each node's configuration document sliced from the cluster's file by
/// the one slicing, [`configure::slices`] — or the one node `node` names,
/// [`configure::slice`] — as `{"slices":[{"node","text"}]}`: what a surface
/// writes and ships to each node when the cluster's file is saved (ADR-0031,
/// amendment 2026-10-05).
///
/// # Errors
/// A node's own document, which is never sliced; or the slicing's words:
/// the text is not TOML, declares no such node, or a node does not slice.
pub fn slices(cluster: &str, node: &str) -> Result<String, String> {
    if document_kind(cluster) == DocumentKind::Node {
        return Err(NOT_A_CLUSTER.to_string());
    }
    let sliced = if node.is_empty() {
        configure::slices(cluster)?
    } else {
        vec![(node.to_string(), configure::slice(cluster, node)?)]
    };
    let slices: Vec<serde_json::Value> = sliced
        .into_iter()
        .map(|(node, text)| serde_json::json!({ "node": node, "text": text }))
        .collect();
    json(&serde_json::json!({ "slices": slices }))
}

/// A filter's text as rows and groups, [`filter::structure`].
///
/// # Errors
/// The expression language's words when the text does not compile.
pub fn filter_structure(text: &str) -> Result<String, String> {
    json(&filter::structure(text)?)
}

/// Rows and groups as the filter's canonical text, [`filter::text`].
///
/// # Errors
/// When the JSON is not a filter's structure, or a row does not read.
pub fn filter_text(structure: &str) -> Result<String, String> {
    let part: FilterPart = serde_json::from_str(structure)
        .map_err(|error| format!("not a filter's rows and groups: {error}"))?;
    filter::text(&part)
}

/// The cluster's file with an edit made to it, [`apply`].
///
/// # Errors
/// When the JSON is not an edit, or configure refuses it.
pub fn edit(cluster: &str, edit: &str) -> Result<String, String> {
    let edit: ClusterEdit =
        serde_json::from_str(edit).map_err(|error| format!("not an edit: {error}"))?;
    apply(cluster, &edit)
}

fn json(answer: &impl Serialize) -> Result<String, String> {
    serde_json::to_string(answer).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cluster holding one Xmip Application as a section; no node is
    /// named, so no name is written here.
    const CLUSTER: &str = "[service]\nname = \"xmip\"\n\n[[xmip_applications]]\n\
                           name = \"Orders\"\n\n[[xmip_applications.send_ports]]\n\
                           name = \"Billing\"\n\n[[xmip_applications.subscriptions]]\n\
                           id = \"billing\"\ndestination = { send-port = \"Billing\" }\n\
                           filter = \"true\"\n";

    #[test]
    fn the_views_cross_as_configure_answers_them() {
        let answer: serde_json::Value =
            serde_json::from_str(&views(CLUSTER).expect("views")).expect("JSON");

        assert_eq!(answer["views"][0]["kind"], "cluster");
        assert_eq!(answer["document"], "node");
        let route = &answer["views"][10];
        assert_eq!(route["kind"], "route");
        assert_eq!(route["entries"][0]["routes"]["application"], "Orders");
        assert_eq!(
            route["entries"][0]["routes"]["edges"][0]["to"],
            "send-port:Billing"
        );
        assert!(views("not = [toml").is_err());
    }

    #[test]
    fn a_filter_crosses_to_its_structure_and_back_to_the_same_text() {
        let text = "exists Urgent or not Amount < 10";
        let structure = filter_structure(text).expect("structure");

        assert_eq!(filter_text(&structure).expect("text"), text);
        assert!(filter_text("{}").is_err());
        assert!(filter_structure("Amount == 1").is_err());
    }

    #[test]
    fn an_edit_crosses_as_json_and_comes_back_as_the_text() {
        let edited = edit(
            CLUSTER,
            &serde_json::json!({ "application": {
                "application": "Orders", "edit": { "add-send-port": { "name": "Ledger" } } } })
            .to_string(),
        )
        .expect("edits");

        assert!(edited.contains("name = \"Ledger\""), "{edited}");
        assert!(edit(CLUSTER, r#"{"remove-everything":{}}"#).is_err());
    }

    #[test]
    fn the_slices_cross_as_the_one_slicing_writes_them() {
        let test = configure::fixture::test_cluster();
        let [one, two] = [0, 1].map(|place| test.node(place).name.clone());
        let cluster = format!("{CLUSTER}\n[nodes.{one}]\n\n[nodes.{two}]\n");
        let every: serde_json::Value =
            serde_json::from_str(&slices(&cluster, "").expect("slices")).expect("JSON");

        assert_eq!(every["slices"].as_array().map(Vec::len), Some(2));
        assert_eq!(every["slices"][0]["node"], one.as_str());
        assert_eq!(
            every["slices"][0]["text"],
            configure::slice(&cluster, &one).expect("slice")
        );

        let only: serde_json::Value =
            serde_json::from_str(&slices(&cluster, &two).expect("slice")).expect("JSON");
        assert_eq!(only["slices"][0]["node"], two.as_str());
        assert!(slices(&cluster, &format!("{one}{two}")).is_err());
        assert_eq!(
            slices(&format!("[service]\nnode_name = \"{one}\"\n"), ""),
            Err(NOT_A_CLUSTER.to_string())
        );
    }
}
