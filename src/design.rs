//! `xmip_operate.h` section 10: the cluster's `xmip.toml` read and edited
//! for the designer (ADR-0064, amendment 2026-10-03), what the exports do.
//! The exports are `ffi/design.rs`'s; each reads its text, calls this, and
//! writes back what it answers.
//!
//! Nothing here is a rule. The file's views, an Xmip Application's routes,
//! a filter's text and structure and every edit are
//! `xmip-core-configure`'s; this reads the JSON a surface hands over into
//! configure's types and writes configure's answers as JSON, which is how
//! they cross — in memory, never to disk (ADR-0031 clause 2).

use configure::filter::{self, FilterPart};
use configure::view_edit::{ClusterEdit, apply};
use configure::views::Views;
use serde::Serialize;

/// The cluster's file as one view per artifact kind, [`Views::of`].
///
/// # Errors
/// The reader's words when the text is not TOML.
pub fn views(cluster: &str) -> Result<String, String> {
    json(&Views::of(cluster)?)
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
}
