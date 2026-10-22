//! When each certificate a node presents is due for renewal, said in its
//! health (ADR-0034, amendment 2026-10-22): a node no network route reaches
//! its authority from renews by hand — a request carried out, a chain
//! carried back — so it says when to begin. At
//! `<node>/certificate/<use>`, for each certificate its configuration names
//! — `operate`, `receive`, `storage` — `Fine` while current, `Stressed`
//! saying renewal due from two thirds of its life, `Done` once it has
//! ended; what a certificate is, and when it is renewed, is the
//! capability's (`provision::renewal::Standing`).
//!
//! A file is read as the node starts and again only when it changed, so a
//! publication round reads no certificate: a chain imported while the node
//! runs is said at the next round.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use configure::XmipConfigurationDocument;
use observe::Health;
use provision::Parsed;
use provision::renewal::Standing;

/// What a certificate file said when it was read: its validity and serial,
/// or why it did not read.
type Read = Result<(i64, i64, String), String>;

/// One certificate a node presents.
struct Held {
    /// What the node presents it for.
    word: &'static str,
    path: PathBuf,
    /// When the file was read last, and what it said.
    read: Mutex<Option<(Option<SystemTime>, Read)>>,
}

/// Every certificate a node's configuration names.
pub(crate) struct CertificateStanding {
    held: Vec<Held>,
}

impl CertificateStanding {
    /// The certificates `document`, the configuration whose folder is
    /// `base`, names: `[operate]`'s, `[provision.receive]`'s and
    /// `[storage]`'s, each relative to `base`.
    pub(crate) fn configured(document: &XmipConfigurationDocument, base: &Path) -> Self {
        let receive = document.provision.get("receive").and_then(|table| {
            table
                .given()
                .into_iter()
                .find_map(|(key, value)| match value {
                    xcore::settings::Given::Text(path) if key == "certificate" => Some(path),
                    _ => None,
                })
        });
        let named = [
            (
                "operate",
                document
                    .operate
                    .as_ref()
                    .and_then(|it| it.certificate.clone()),
            ),
            ("receive", receive),
            ("storage", document.storage.certificate.clone()),
        ];
        Self {
            held: named
                .into_iter()
                .filter_map(|(word, path)| {
                    path.map(|path| Held {
                        word,
                        path: base.join(path),
                        read: Mutex::new(None),
                    })
                })
                .collect(),
        }
    }

    /// Each certificate's standing at `now_nanos`, nanoseconds since the
    /// epoch as a publication is stamped, as a record beneath `node`.
    pub(crate) fn publish(
        &self,
        node: &str,
        now_nanos: i64,
        record: &mut impl FnMut(String, Health, String),
    ) {
        let now = now_nanos / 1_000_000_000;
        for held in &self.held {
            let scope = format!("{node}/certificate/{}", held.word);
            let (health, evidence) = match held.current() {
                Ok((not_before, not_after, serial)) => {
                    said(&held.path, (not_before, not_after), &serial, now)
                }
                Err(unread) => (Health::Done, unread),
            };
            record(scope, health, evidence);
        }
    }
}

impl Held {
    /// The certificate's validity and serial, read again where the file
    /// changed since it was read last.
    fn current(&self) -> Read {
        let modified = std::fs::metadata(&self.path)
            .and_then(|metadata| metadata.modified())
            .ok();
        let mut read = self
            .read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((when, what)) = read.as_ref()
            && *when == modified
            && modified.is_some()
        {
            return what.clone();
        }
        let what = std::fs::read_to_string(&self.path)
            .map_err(|failure| format!("{}: {failure}", self.path.display()))
            .and_then(|text| Parsed::first(&text).map_err(|failure| failure.message))
            .map(|leaf| (leaf.not_before, leaf.not_after, leaf.serial_hex()));
        *read = Some((modified, what.clone()));
        what
    }
}

/// The health and the words for a certificate valid from `not_before` to
/// `not_after`, at `now`.
fn said(
    path: &Path,
    (not_before, not_after): (i64, i64),
    serial: &str,
    now: i64,
) -> (Health, String) {
    let standing = Standing::between(not_before, not_after, now);
    let health = if standing.expired {
        Health::Done
    } else if standing.due {
        Health::Stressed
    } else {
        Health::Fine
    };
    (
        health,
        format!(
            "{}: {serial} at {}, valid until {}, renewal due from {}",
            standing.word(),
            path.display(),
            moment(not_after),
            moment(standing.renew_at)
        ),
    )
}

/// `unix` as RFC 3339 writes it, in UTC (`codec::civil`).
fn moment(unix: i64) -> String {
    codec::civil::rfc3339_nanos(i128::from(unix) * 1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test cluster's first node, configured with an operate
    /// certificate in `tls`, and its scope.
    fn configured() -> (XmipConfigurationDocument, String, String) {
        let cluster = configure::fixture::test_cluster();
        let node = cluster.node(0).name.clone();
        let text = format!(
            "[service]\nname = \"xmip\"\ncluster_name = \"{}\"\nnode_name = \"{node}\"\n\n\
             [operate]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls/node.pem\"\n\
             key = \"tls/node.key\"\nanchors = \"tls/anchors.pem\"\n",
            cluster.name
        );
        let scope = format!("{}/node/{node}", cluster.scope());
        (configure::parse_toml(&text).expect("parses"), node, scope)
    }

    #[test]
    fn each_certificate_a_node_presents_says_when_its_renewal_is_due() {
        let base = std::env::temp_dir().join(format!("xmip-standing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (document, node, scope) = configured();
        let now = provision::now();
        let authority = base.join("authority");
        provision::node::issue_into(
            &authority,
            "test authority",
            &node,
            &[],
            &base.join("tls"),
            now,
        )
        .expect("issued");
        let standing = CertificateStanding::configured(&document, &base);
        let said = |at: i64| {
            let mut records = Vec::new();
            standing.publish(
                &scope,
                at * 1_000_000_000,
                &mut |scope, health, evidence| {
                    records.push((scope, health, evidence));
                },
            );
            records
        };
        let current = said(now);
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].0, format!("{scope}/certificate/operate"));
        assert_eq!(current[0].1, Health::Fine, "{}", current[0].2);
        let due = said(now + 61 * 86_400);
        assert_eq!(due[0].1, Health::Stressed);
        assert!(due[0].2.starts_with("renewal due"), "{}", due[0].2);
        assert_eq!(said(now + 91 * 86_400)[0].1, Health::Done);
        std::fs::remove_dir_all(&base).expect("removes what it wrote");
    }
}
