//! What a node presents to the Parties that reach it, and the anchors a
//! Party's certificate must reach: `[provision.receive]` (ADR-0034; ADR-0033,
//! amendment 2026-10-13), read as the node starts and handed to every
//! transport it builds as the guard its receives terminate TLS with
//! (`transport::Guard`; ADR-0033, amendment 2026-10-19).
//!
//! With `anchors`, the guard requests a client certificate and refuses one
//! that does not reach them, so a Location's `mutual-tls` has a verified
//! peer to record; without, it presents the node's certificate alone. The
//! operator's own files are the one source a node reads: a table naming a
//! `source` — ACME, the cluster's authority, self-signed — is refused as
//! the node starts, since no node runs a provisioner yet (open problem 27).

use std::path::Path;
use std::sync::Arc;

use configure::XmipConfigurationDocument;
use provision::{Order, Purpose, Source};
use transport::Guard;

/// The purpose's table, `[provision.receive]`.
const RECEIVE: &str = "receive";

/// The guard `document`, the node configuration at `configuration`, gives
/// its receives; `None` where it names no `[provision.receive]`.
///
/// # Errors
///
/// The table is refused — a `source` this node does not link, an unknown
/// key, a file left out — or its files do not read or do not pair; one
/// sentence each, naming the table.
pub fn guard(
    document: &XmipConfigurationDocument,
    configuration: &Path,
) -> Result<Option<Guard>, Vec<String>> {
    let Some(table) = document.provision.get(RECEIVE) else {
        return Ok(None);
    };
    let said = |why: String| vec![format!("[provision.{RECEIVE}]: {why}")];
    let read = provision::read(RECEIVE, &table.given(), &[])
        .map_err(|refused| said(refused.to_string()))?;
    let base = configuration.parent().unwrap_or_else(|| Path::new("."));
    let order = Order {
        purpose: Purpose::Receive,
        names: &[],
        keep: base,
    };
    let held = provision::Files::configured(&read.settings, base)
        .obtain(&order)
        .map_err(|failed| said(failed.message))?;
    let (chain, key) = (held.chain.as_bytes(), held.key.as_bytes());
    let config = match &held.anchors {
        Some(anchors) => {
            tls::Identity::from_pem(chain, key, anchors.as_bytes()).and_then(|it| it.server())
        }
        None => tls::server_config(chain, key),
    }
    .map_err(|failed| said(failed.message))?;
    Ok(Some(Guard::new(Arc::new(config))))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::fixture::Authority;

    /// A node's configuration in a folder of its own, with `provision`
    /// after its `[service]`.
    fn configured(authority: &Authority, provision: &str) -> (XmipConfigurationDocument, PathBuf) {
        let place = authority.directory.join("node.toml");
        let text = format!(
            "[service]\nname = \"n\"\ncluster_name = \"c\"\nnode_name = \"d\"\n\n{provision}"
        );
        std::fs::write(&place, &text).expect("written");
        (configure::parse_toml(&text).expect("parses"), place)
    }

    #[test]
    fn the_operators_files_with_anchors_guard_the_receives_and_none_leaves_them_bare() {
        let authority = Authority::new();
        let (certificate, key, anchors) = authority.pem("localhost");
        for (name, text) in [
            ("receive.pem", &certificate),
            ("receive.key", &key),
            ("parties.pem", &anchors),
        ] {
            std::fs::write(authority.directory.join(name), text).expect("written");
        }
        let (document, place) = configured(
            &authority,
            "[provision.receive]\ncertificate = \"receive.pem\"\nkey = \"receive.key\"\n\
             anchors = \"parties.pem\"\n",
        );
        assert!(guard(&document, &place).expect("read").is_some());

        let (bare, place) = configured(&authority, "");
        assert!(guard(&bare, &place).expect("read").is_none());
    }

    #[test]
    fn a_source_no_node_runs_and_a_missing_file_are_refused_naming_the_table() {
        let authority = Authority::new();
        let (document, place) = configured(
            &authority,
            "[provision.receive]\nsource = \"xmip-core-provision-self-signed\"\n\
             names = \"localhost\"\nlifetime = \"1h\"\n",
        );
        let refused = guard(&document, &place).expect_err("no source runs");
        assert!(refused[0].starts_with("[provision.receive]"), "{refused:?}");

        let (document, place) = configured(
            &authority,
            "[provision.receive]\ncertificate = \"absent.pem\"\nkey = \"absent.key\"\n",
        );
        let refused = guard(&document, &place).expect_err("no file");
        assert!(refused[0].contains("absent.pem"), "{refused:?}");
    }
}
