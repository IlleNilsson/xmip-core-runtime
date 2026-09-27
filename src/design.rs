//! `xmip_operate.h` section 10: an Xmip Application read and edited for a
//! designer (ADR-0064), what the exports do. The exports are
//! `ffi/design.rs`'s; each reads its text, calls this, and writes back what
//! it answers.
//!
//! Nothing here is a rule. The Application, its routes, a filter's text and
//! structure and every edit are `xmip-core-configure`'s; this reads the JSON
//! a surface hands over into configure's types and writes configure's
//! answers as JSON, which is how they cross — in memory, never to disk
//! (ADR-0031 clause 2).

use configure::edit::{ApplicationEdit, apply};
use configure::filter::{self, FilterPart};
use configure::routes::Routes;
use configure::{PARSE_FAILED, parse_application};
use serde::Serialize;

/// An Application's routes as a graph, [`Routes::of`].
///
/// # Errors
/// The reader's words when the text is not an Xmip Application.
pub fn routes(application: &str) -> Result<String, String> {
    let document =
        parse_application(application).map_err(|error| format!("{PARSE_FAILED}: {error}"))?;
    json(&Routes::of(&document))
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

/// The Application with an edit made to it, [`apply`].
///
/// # Errors
/// When the JSON is not an edit, or configure refuses it.
pub fn edit(application: &str, edit: &str) -> Result<String, String> {
    let edit: ApplicationEdit =
        serde_json::from_str(edit).map_err(|error| format!("not an edit: {error}"))?;
    apply(application, &edit)
}

fn json(answer: &impl Serialize) -> Result<String, String> {
    serde_json::to_string(answer).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDERS: &str = "[application]\nname = \"Orders\"\n\n[[send_ports]]\n\
                          name = \"Billing\"\n\n[[subscriptions]]\nid = \"billing\"\n\
                          destination = { send-port = \"Billing\" }\nfilter = \"true\"\n";

    #[test]
    fn the_routes_cross_as_the_graph_configure_draws() {
        let answer: serde_json::Value =
            serde_json::from_str(&routes(ORDERS).expect("routes")).expect("JSON");

        assert_eq!(answer["application"], "Orders");
        assert_eq!(answer["nodes"][0]["id"], "subscription:billing");
        assert_eq!(answer["edges"][0]["to"], "send-port:Billing");
        assert!(
            routes("[service]\n")
                .expect_err("not one")
                .starts_with(PARSE_FAILED)
        );
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
        let edited = edit(ORDERS, r#"{"add-send-port":{"name":"Ledger"}}"#).expect("edits");

        assert!(edited.contains("name = \"Ledger\""), "{edited}");
        assert!(edit(ORDERS, r#"{"remove-everything":{}}"#).is_err());
    }
}
