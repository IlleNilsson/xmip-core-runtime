//! A secret set on a node, and the secrets it keeps listed (ADR-0019,
//! amendment 2026-10-29): what a surface's `Set-XmipSecret` reaches
//! through the node's operate listener, applied here once.
//!
//! The node is found among those this process runs, and the secret written
//! through its Xmip Storage into the Administration Database's `secret`
//! table, sealed at rest there (`persist::storage::secret`). Its value
//! crosses only the operate listener — Xmip's mutual TLS, or the local
//! endpoint the operating system guards — and is never said back: a
//! listing carries each secret's name, kind, and when and by whom it was
//! set. A Location naming it reads it as it next connects, without a
//! restart.

use std::sync::Arc;

use persist::storage::{SecretEntry, SecretRecord, XmipStorage};
use serde_json::{Value, json};
use xcore::{IdGenerator, Secret, SecretKind, SecretName, UuidV7Generator};

use crate::applied::Applied;
use crate::pickup::Pickup;

/// The Xmip Storage of the node at `node` in this process; with `node`
/// empty, of the one node it runs, as `xmip-service` runs one.
fn storage_of(node: &str) -> Result<Arc<dyn XmipStorage>, String> {
    let registered = Pickup::registered();
    let found = if node.is_empty() && registered.len() == 1 {
        registered.first()
    } else {
        registered.iter().find(|pickup| pickup.node() == node)
    };
    found
        .map(|pickup| Arc::clone(pickup.storage()))
        .ok_or_else(|| match node {
            "" => {
                "REFUSED: name the node; this process runs more than one node, or none".to_string()
            }
            node => format!("REFUSED: no node at {node} runs in this process"),
        })
}

/// The secret `name` of the kind `kind` names set to `value` through the
/// node at `node`, by `who`.
#[must_use]
pub fn set(node: &str, (name, kind, value): (&str, &str, &str), who: &str) -> Applied {
    let made = SecretName::new(name).and_then(|name| {
        let kind = SecretKind::named(kind).ok_or_else(|| {
            let words: Vec<&str> = SecretKind::ALL.iter().map(|kind| kind.word()).collect();
            format!("'{kind}' is no kind of secret: {}", words.join(", "))
        })?;
        Secret::new(name, kind, value.as_bytes().to_vec())
    });
    let secret = match made {
        Ok(secret) => secret,
        Err(why) => return Applied::Refused(format!("REFUSED: {why}")),
    };
    let storage = match storage_of(node) {
        Ok(storage) => storage,
        Err(refused) => return Applied::Refused(refused),
    };
    let record = SecretRecord {
        id: UuidV7Generator.next_u128(),
        secret,
        set_unix_nanos: 0,
        set_by: who.to_string(),
    };
    match storage.write_secret(&record) {
        Ok(()) => Applied::Taken(format!(
            "the secret '{name}', a {}, is set; a Location naming it presents it as it next \
             connects",
            record.secret.kind()
        )),
        Err(failed) => Applied::Failed(format!(
            "FAILED: the secret '{name}' is not set, Xmip Storage did not take it: {failed}"
        )),
    }
}

/// The secrets the node at `node` keeps, as a listing says them:
/// `{"secrets":[{"name","kind","set_unix_nanos","set_by"}]}`.
///
/// # Errors
///
/// No such node here, opening REFUSED; Xmip Storage did not answer,
/// opening FAILED.
pub fn listed(node: &str) -> Result<Value, String> {
    let entries = storage_of(node)?
        .list_secrets()
        .map_err(|failed| format!("FAILED: the secrets could not be read: {failed}"))?;
    Ok(said(&entries))
}

/// `entries` as a listing says them.
#[must_use]
pub fn said(entries: &[SecretEntry]) -> Value {
    let secrets: Vec<Value> = entries
        .iter()
        .map(|entry| {
            json!({
                "name": entry.name.as_str(),
                "kind": entry.kind.word(),
                "set_unix_nanos": entry.set_unix_nanos,
                "set_by": entry.set_by,
            })
        })
        .collect();
    json!({ "secrets": secrets })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_for_a_node_not_here_or_not_of_its_kind_is_refused_in_words() {
        let node = crate::fixture::absent_node();
        let absent = set(&node, ("partner-x", "password", "drawn"), "CN=tester");
        assert_eq!(
            absent,
            Applied::Refused(format!("REFUSED: no node at {node} runs in this process"))
        );
        let kind = set(&node, ("partner-x", "token", "drawn"), "CN=tester");
        assert!(
            kind.said()
                .contains("'token' is no kind of secret: password, key, certificate")
        );
        let named = set(&node, ("partner x", "password", "drawn"), "CN=tester");
        assert!(
            named.said().contains("is no secret name"),
            "{}",
            named.said()
        );
        assert!(listed(&node).expect_err("absent").starts_with("REFUSED"));
    }
}

#[cfg(test)]
mod set {
    use super::*;
    use persist::storage::StoredSecrets;
    use xcore::Secrets as _;

    #[test]
    fn a_secret_set_through_a_node_is_read_by_its_locations_and_listed_without_its_value() {
        let node = format!(
            "{}-secret-test",
            configure::fixture::test_cluster().node_scope(0)
        );
        let storage = crate::ledger::in_memory();
        let _pickup = Pickup::open(&node, Vec::new(), Arc::clone(storage), None).expect("open");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        let drawn = format!("drawn-{:x}", now.map(|t| t.as_nanos()).unwrap_or_default());

        let applied = set(&node, ("partner-x.set", "password", &drawn), "CN=tester");
        assert!(matches!(applied, Applied::Taken(_)), "{applied:?}");
        let name = SecretName::new("partner-x.set").expect("a name");
        let read = StoredSecrets(Arc::clone(storage))
            .secret(&name)
            .expect("read");
        assert_eq!(read.expect("set").text(), drawn);

        let listed = listed(&node).expect("listed").to_string();
        assert!(listed.contains("\"name\":\"partner-x.set\""), "{listed}");
        assert!(listed.contains("\"set_by\":\"CN=tester\""), "{listed}");
        assert!(!listed.contains(&drawn), "a listing never says a value");
    }
}
