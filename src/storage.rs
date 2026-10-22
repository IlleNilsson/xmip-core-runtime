//! How a node reaches Xmip Storage, the doorway to the Ledger, decided as
//! it starts (`runtime-model.md` section 3, *The Ledger*; ADR-0056,
//! amendment 2026-10-01, the Storage role): one `Arc<dyn XmipStorage>` the
//! message path writes through, whichever is behind it.
//!
//! - **The program's own.** A program that opened Xmip Storage itself — a
//!   test's Storage node — hands it over in [`Linked::storage`], and that
//!   one is the node's.
//! - **The node's own Storage node.** Only a node with the Storage role
//!   stores (the owner, 2026-10-20; ADR-0056, amendment 2026-10-20). One
//!   whose `[storage]` lists no Storage node is the only one, embedded
//!   (`deployment-model.md` section 3: *A one-node deployment is its own
//!   Storage node*). One that lists them — every Storage node of the
//!   cluster, itself among them — is one of several: the primary or a
//!   standby copying it, as they settle it among themselves
//!   (`persist::storage::standby`; ADR-0056, amendment 2026-10-22). Each
//!   data domain's database is where its table, `[runtime]`,
//!   `[administration]` or `[audit]`, says — its `storage` and its
//!   `connection`, a path relative to the configuration file — and, where
//!   the table is left out, under the data directory: `RocksDB` at
//!   `<data>/storage/runtime`, `SQLite` at
//!   `<data>/storage/administration.sqlite` and at
//!   `<data>/storage/audit.sqlite` ([`FILES`]); all three sealed under the
//!   key store `[store]` names, with the key [`KEK`]. Where `[storage]
//!   listen` names an address, the node serves Xmip Storage there to the
//!   nodes reaching it, over Xmip's mutual TLS with what `[storage]`
//!   presents. Phase 3 refuses a table Xmip Storage does not read, a
//!   database server, whose backend is not built yet, a program that was
//!   not built with both engines — what `deploy/profile/role/storage.toml`
//!   builds — and one of several that names nowhere to serve them; phase 9
//!   one whose databases do not open or whose listener does not bind.
//! - **The Storage nodes `[storage]` lists**, reached over Xmip's mutual
//!   TLS with the certificate, key and anchors `[storage]` names, the
//!   primary asked and the standbys passed over
//!   (`persist::storage::client`). One listing them and naming nothing to
//!   present is refused at phase 3.
//!
//! A node declaring neither the Storage role nor `[storage] nodes` is
//! refused at phase 3, in words naming both.

mod opened;
mod reached;

pub use reached::Reached;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use configure::XmipConfigurationDocument;
use node::NodeRole;
use persist::storage::XmipStorage;
use persist::storage::database::{self, Domain, Technology};
use persist::storage::schema::Database;

use crate::linked::Linked;
use crate::running::Refusal;
use crate::service::StartupPhase;

/// The key-encryption key a Storage node's data keys are wrapped under.
pub const KEK: &str = "storage";

/// Where a Storage node keeps its databases, under the node's data
/// directory.
pub const PLACE: &str = "storage";

/// The leaf beneath a node what it reaches Xmip Storage through is
/// published at, and one record to each data domain it keeps beneath it
/// ([`Reached::published`]).
pub const DATABASES: &str = "storage";

/// Where each data domain's database is in [`PLACE`] where its table is
/// left out: the runtime, the administration and the audit database.
pub const FILES: [&str; 3] = ["runtime", "administration.sqlite", "audit.sqlite"];

/// The administration and audit databases' engine on a Storage node that
/// keeps them itself, by module name (`deployment-model.md` section 7).
pub const ADMINISTRATION: &str = "xmip-core-persist-sqlite";

/// What a node will reach Xmip Storage through, once phase 3 has held it
/// to what the program linked.
pub enum Planned {
    /// The program's own.
    Given(Arc<dyn XmipStorage>),
    /// The node's own Storage node, each data domain's database at its
    /// place — runtime, administration, audit — sealed by the key store
    /// named `key_store` keeping its keys in `keys`, and served where
    /// `serving` says.
    Kept {
        places: [PathBuf; 3],
        key_store: String,
        keys: PathBuf,
        serving: Option<Serving>,
    },
    /// The Storage nodes listed, reached presenting `identity`.
    Reaching {
        listed: Vec<String>,
        identity: tls::Identity,
    },
}

/// Where a Storage node serves Xmip Storage, what it presents, and every
/// Storage node of the cluster, itself among them — none where it is the
/// only one.
pub struct Serving {
    pub listen: String,
    pub identity: tls::Identity,
    pub listed: Vec<String>,
}

/// The data domains' tables `document` holds, each with its database.
#[must_use]
pub fn domains(document: &XmipConfigurationDocument) -> Vec<Domain<'_>> {
    Database::ALL
        .into_iter()
        .zip(document.domains())
        .filter_map(|(database, (_, table))| {
            table.map(|table| Domain {
                database,
                storage: &table.storage,
                connection: &table.connection,
            })
        })
        .collect()
}

/// How the node configured at `path` reaches Xmip Storage, held to what
/// `linked` carries.
///
/// # Errors
///
/// Refused at phase 3 where its roles are not role words; where it
/// declares no Storage role and lists no Storage node; where it lists
/// Storage nodes and names nothing to present to them; or where it keeps
/// Xmip Storage itself and a data domain's table is not one Xmip Storage
/// reads, names a database server, its program was not built with both
/// engines, or it is one of several and names nowhere to serve them.
pub fn plan(
    document: &XmipConfigurationDocument,
    path: &str,
    linked: &Linked,
) -> Result<Planned, Refusal> {
    if let Some(given) = &linked.storage {
        return Ok(Planned::Given(Arc::clone(given)));
    }
    let refused = |problem: String| Refusal::at(StartupPhase::ValidateStartup, vec![problem]);
    let roles = NodeRole::declared(document.roles.as_deref().unwrap_or("")).map_err(refused)?;
    let listed: Vec<String> = document
        .storage
        .nodes
        .iter()
        .map(|node| node.as_str().to_string())
        .collect();
    let file = Path::new(path);
    let presented = || -> Result<tls::Identity, Vec<String>> {
        let named = document
            .storage
            .presented()
            .map_err(|problem| vec![problem])?;
        let presented = named.ok_or_else(|| {
            vec![
                "[storage] names no certificate, key and anchors: what this node presents to \
                 the Storage nodes and trusts of them over Xmip's mutual TLS"
                    .to_string(),
            ]
        })?;
        let files = [presented.certificate, presented.key, presented.anchors];
        crate::presented::identity(file, "storage", files).map_err(|problem| vec![problem])
    };
    let refused_all = |problems| Refusal::at(StartupPhase::ValidateStartup, problems);
    if !roles.contains(&NodeRole::Storage) {
        if listed.is_empty() {
            return Err(refused(
                "this node does not declare the storage role and [storage] nodes lists no \
                 Storage node: only a node with the storage role keeps Xmip Storage, and any \
                 other reaches it through [storage] nodes"
                    .to_string(),
            ));
        }
        let identity = presented().map_err(refused_all)?;
        return Ok(Planned::Reaching { listed, identity });
    }
    let serving = match (&document.storage.listen, listed.is_empty()) {
        (None, true) => None,
        (None, false) => {
            return Err(refused(
                "this node declares the storage role and [storage] nodes lists the cluster's \
                 Storage nodes, and [storage] names no listen to serve the others on"
                    .to_string(),
            ));
        }
        (Some(listen), _) => Some(Serving {
            listen: listen.clone(),
            identity: presented().map_err(refused_all)?,
            listed,
        }),
    };
    kept(document, file, linked, serving)
}

/// The node's own Storage node, held to what `linked` carries.
fn kept(
    document: &XmipConfigurationDocument,
    file: &Path,
    linked: &Linked,
    serving: Option<Serving>,
) -> Result<Planned, Refusal> {
    let data = document.service.data_directory(file);
    let base = file.parent().unwrap_or_else(|| Path::new(""));
    let store = document.store.resolve(&data, base);
    let named = domains(document);
    let password = document
        .storage
        .database
        .as_ref()
        .map(|d| d.password.as_str());
    let mut problems = database::problems(&named, password);
    for domain in &named {
        if let Some(Technology::Server(server)) = Technology::named(domain.storage) {
            problems.push(format!(
                "[{}] storage names {}, and Xmip Storage has no {} backend built yet; it \
                 follows as its own technology of xmip-core-persist",
                domain.database.word(),
                server.word(),
                server.word()
            ));
        }
    }
    for (engine, technology, database) in [
        (&linked.engine, configure::store::ENGINE, "runtime"),
        (
            &linked.administration,
            ADMINISTRATION,
            "administration and audit",
        ),
    ] {
        if engine.is_none() {
            problems.push(format!(
                "this node keeps Xmip Storage itself (the storage role), and was not built \
                 with {technology}, its {database} databases' engine"
            ));
        }
    }
    if linked.key_store(&store.key_store).is_none() {
        problems.push(format!(
            "[store] names the key store '{}', which this node was not built with",
            store.key_store
        ));
    }
    if !problems.is_empty() {
        return Err(Refusal::at(StartupPhase::ValidateStartup, problems));
    }
    let place = data.join(PLACE);
    let tables = document.domains();
    let places = [0, 1, 2].map(|at| {
        tables[at].1.map_or_else(
            || place.join(FILES[at]),
            |table| base.join(&table.connection),
        )
    });
    Ok(Planned::Kept {
        places,
        key_store: store.key_store,
        keys: store.keys,
        serving,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::CHUNK;
    use crate::linked::{LinkedEngine, LinkedKeyStore};
    use crate::tuning::Tuning;
    use observe::Health;
    use persist::Engine;
    use persist::PersistError;
    use persist::storage::Embedded;
    use secret::KekName;
    use secret::KeyStore;

    /// The test cluster's first node declaring [`STORAGE`], and its
    /// `[service]` section, and the file name it is read from.
    fn service() -> (String, String) {
        let cluster = configure::fixture::test_cluster();
        let node = &cluster.node(0).name;
        let head = format!(
            "{STORAGE}[service]\nname = \"xmip-{node}\"\ncluster_name = \"{}\"\n\
             node_name = \"{node}\"\n",
            cluster.name
        );
        (head, format!("{node}.toml"))
    }

    /// What a node keeping Xmip Storage itself declares.
    const STORAGE: &str = "roles = \"executing, storage\"\n";

    fn memory(_: &Path) -> Result<Box<dyn Engine>, PersistError> {
        Ok(Box::new(persist::fixture::Memory::default()))
    }

    fn keys(_: &Path) -> Box<dyn KeyStore> {
        Box::new(secret::Held::new(secret::fixture::Memory::default()))
    }

    fn linked() -> Linked {
        Linked {
            engine: Some(LinkedEngine::new("xmip-core-persist-memory", memory)),
            administration: Some(LinkedEngine::new("xmip-core-persist-memory", memory)),
            key_stores: vec![LinkedKeyStore::new("xmip-core-secret-memory", keys)],
            ..Linked::default()
        }
    }

    fn document(text: &str) -> XmipConfigurationDocument {
        configure::parse_toml(text).expect("parses")
    }

    /// Each store [`recorded`] opened, by where, so a test reads what was
    /// kept in each.
    static OPENED: std::sync::Mutex<Vec<(PathBuf, &'static persist::fixture::Memory)>> =
        std::sync::Mutex::new(Vec::new());

    fn recorded(place: &Path) -> Result<Box<dyn Engine>, PersistError> {
        let store: &'static persist::fixture::Memory = Box::leak(Box::default());
        let mut opened = OPENED.lock().expect("opened");
        opened.push((place.to_path_buf(), store));
        Ok(Box::new(store))
    }

    fn opened_at(place: &Path) -> &'static persist::fixture::Memory {
        let opened = OPENED.lock().expect("opened");
        let found = opened.iter().find(|(at, _)| at == place);
        found.map(|(_, store)| *store).expect("opened there")
    }

    #[test]
    fn an_audit_database_named_elsewhere_keeps_the_audit_there_and_none_in_administration() {
        let directory =
            std::env::temp_dir().join(format!("xmip-storage-audit-{}", std::process::id()));
        let (head, file) = service();
        let text = format!(
            "{head}data = \"state\"\n[store]\nkey_store = \"xmip-core-secret-memory\"\n\
             [audit]\nstorage = \"sqlite\"\nconnection = \"elsewhere/audit.sqlite\"\n"
        );
        let linked = Linked {
            engine: Some(LinkedEngine::new("xmip-core-persist-memory", recorded)),
            administration: Some(LinkedEngine::new("xmip-core-persist-memory", recorded)),
            ..linked()
        };
        let path = directory.join(file);
        let reached = plan(&document(&text), path.to_str().expect("UTF-8"), &linked)
            .expect("planned")
            .open(&linked, &Tuning::default())
            .expect("opened");

        assert!(directory.join("elsewhere").is_dir(), "{}", reached.said());
        assert!(reached.said().contains("elsewhere"), "{}", reached.said());
        let place = directory.join("state").join(PLACE);
        let administration = opened_at(&place.join(FILES[1]));
        let audit = opened_at(&directory.join("elsewhere/audit.sqlite"));
        let before = (administration.everything(), audit.everything());
        let entry = persist::storage::AuditEntry {
            id: xcore::AuditId::new(1),
            body: b"kept".to_vec(),
            audited: None,
            facts: persist::storage::AuditFacts::default(),
        };
        reached.storage().write_audit(&entry).expect("written");
        assert_eq!(reached.storage().keep_audit(10, CHUNK).expect("kept"), 1);
        let kept = reached.storage().read_kept_audit(entry.id).expect("read");
        assert!(kept.is_some(), "kept");
        assert_eq!(administration.everything(), before.0, "nothing audit there");
        assert_ne!(audit.everything(), before.1, "kept in the audit database");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_node_listing_no_storage_node_is_its_own() {
        let directory = std::env::temp_dir().join(format!("xmip-storage-{}", std::process::id()));
        let (head, file) = service();
        let text =
            format!("{head}data = \"state\"\n[store]\nkey_store = \"xmip-core-secret-memory\"\n");
        let path = directory.join(file);
        let reached = plan(&document(&text), path.to_str().expect("UTF-8"), &linked())
            .expect("planned")
            .open(&linked(), &Tuning::default())
            .expect("opened");

        let said = reached.said();
        assert!(
            said.starts_with("its own Storage node, runtime at "),
            "{said}"
        );
        assert!(directory.join("state").join(PLACE).is_dir());
        for file in FILES {
            let beside = directory.join("state").join(PLACE).join(file);
            assert!(said.contains(&beside.display().to_string()), "{said}");
        }
        assert_eq!(reached.chunk(), CHUNK);
        let version = persist::storage::schema::VERSION;
        let held = format!("runtime schema version {version} on memory");
        assert!(said.contains(&held), "{said}");
        let node = &configure::fixture::test_cluster().node_scope(0);
        let published = reached.published(node);
        let at = |word: &str| format!("{node}/storage/{word}");
        assert_eq!(
            published[0],
            (format!("{node}/storage"), Health::Fine, reached.said())
        );
        assert_eq!(
            published[1..],
            ["runtime", "administration", "audit"].map(|word| (
                at(word),
                Health::Fine,
                format!("schema version {version} on memory")
            ))
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn only_a_node_with_the_storage_role_stores() {
        let (head, file) = service();
        for roles in ["", "roles = \"executing, monitoring\"\n"] {
            let text = format!("{head}[store]\nkey_store = \"xmip-core-secret-memory\"\n")
                .replace(STORAGE, roles);
            let refused = plan(&document(&text), &file, &linked())
                .err()
                .expect("neither the role nor a Storage node");
            assert_eq!(refused.phase, StartupPhase::ValidateStartup);
            assert!(
                refused.problems[0].contains("storage role")
                    && refused.problems[0].contains("[storage] nodes"),
                "{refused}"
            );
        }
        let unknown = head.replace(STORAGE, "roles = \"stores\"\n");
        let refused = plan(&document(&unknown), &file, &linked())
            .err()
            .expect("no role is called stores");
        assert!(refused.problems[0].contains("stores"), "{refused}");
    }

    #[test]
    fn what_the_node_cannot_reach_storage_with_is_refused_at_phase_three() {
        let unbuilt = Linked {
            key_stores: vec![LinkedKeyStore::new("xmip-core-secret-memory", keys)],
            ..Linked::default()
        };
        let (head, file) = service();
        let named = format!("{head}[store]\nkey_store = \"xmip-core-secret-memory\"\n");
        let refused = plan(&document(&named), &file, &unbuilt)
            .err()
            .expect("neither engine is linked");
        assert_eq!(refused.phase, StartupPhase::ValidateStartup);
        assert_eq!(refused.problems.len(), 2, "{refused}");
        assert!(refused.problems[1].contains(ADMINISTRATION), "{refused}");

        let server = format!(
            "{head}[store]\nkey_store = \"xmip-core-secret-memory\"\n\
             [runtime]\nstorage = \"postgresql\"\nconnection = \"host=db-1 dbname=xmip_runtime\"\n\
             [administration]\nstorage = \"rocksdb\"\nconnection = \"administration\"\n\
             [storage.database]\npassword = \"xmip-storage-database\"\n"
        );
        let refused = plan(&document(&server), &file, &linked())
            .err()
            .expect("a server and the wrong engine");
        assert_eq!(refused.problems.len(), 2, "{refused}");
        assert!(refused.problems[0].starts_with("[administration] storage"));
        assert!(refused.problems[1].contains("no postgresql backend built"));

        let listed = format!("{head}[storage]\nnodes = [\"storage.example:7443\"]\n");
        let refused = plan(&document(&listed), &file, &linked())
            .err()
            .expect("no client was handed over");
        assert!(refused.problems[0].contains("[storage] nodes"), "{refused}");

        let given = Linked {
            storage: Some(Arc::new(
                Embedded::open(
                    persist::fixture::Memory::default(),
                    persist::fixture::Memory::default(),
                    persist::fixture::Memory::default(),
                    &secret::Held::new(secret::fixture::Memory::default()),
                    &KekName::new(KEK).expect("a name"),
                )
                .expect("opened"),
            )),
            ..Linked::default()
        };
        let reached = plan(&document(&listed), &file, &given)
            .expect("the program's own")
            .open(&given, &Tuning::default())
            .expect("reached");
        assert!(
            reached
                .said()
                .starts_with("the Xmip Storage its program opened")
        );
    }

    /// A node of the test cluster at `place` in `directory`, declaring
    /// `roles`, reaching the Storage nodes `listed`, serving at `listen`
    /// where it names one, presenting what `directory`'s `tls` holds.
    fn reaching_node(
        directory: &Path,
        (place, roles): (usize, &str),
        listed: &[String],
        listen: Option<&str>,
    ) -> (XmipConfigurationDocument, String) {
        let cluster = configure::fixture::test_cluster();
        let node = &cluster.node(place).name;
        let nodes: Vec<String> = listed.iter().map(|at| format!("\"{at}\"")).collect();
        let listen = listen
            .map(|at| format!("listen = \"{at}\"\n"))
            .unwrap_or_default();
        let text = format!(
            "roles = \"{roles}\"\n[service]\nname = \"xmip-{node}\"\ncluster_name = \"{}\"\n\
             node_name = \"{node}\"\ndata = \"state-{place}\"\n\
             [store]\nkey_store = \"xmip-core-secret-memory\"\n\
             [tuning]\nstorage_silence = \"300ms\"\nstorage_beat = \"20ms\"\n\
             [storage]\nnodes = [{}]\n{listen}certificate = \"tls/node.pem\"\n\
             key = \"tls/node.key\"\nanchors = \"tls/anchors.pem\"\n",
            cluster.name,
            nodes.join(", ")
        );
        let path = directory.join(format!("{node}.toml"));
        (document(&text), path.display().to_string())
    }

    fn opened(document: &XmipConfigurationDocument, path: &str) -> Reached {
        let tuning = Tuning::read(&document.tuning).expect("tuning");
        plan(document, path, &linked())
            .expect("planned")
            .open(&linked(), &tuning)
            .expect("opened")
    }

    #[test]
    fn a_node_reaches_the_storage_nodes_listed_and_carries_on_once_the_primary_stops() {
        let authority = crate::fixture::Authority::new();
        let directory = authority.directory.clone();
        let (certificate, key, anchors) = authority.pem("node");
        std::fs::create_dir_all(directory.join("tls")).expect("a folder");
        for (file, pem) in [
            ("node.pem", certificate),
            ("node.key", key),
            ("anchors.pem", anchors),
        ] {
            std::fs::write(directory.join("tls").join(file), pem).expect("written");
        }
        let listed = [net::fixture::unheld(), net::fixture::unheld()].map(|a| a.to_string());
        let storage = |place: usize| {
            let (document, path) = reaching_node(
                &directory,
                (place, "storage"),
                &listed,
                Some(&listed[place]),
            );
            opened(&document, &path)
        };
        let (first, second) = (storage(0), storage(1));
        let (document, path) = reaching_node(&directory, (2, "receiving"), &listed, None);
        let reaching = opened(&document, &path);
        assert!(
            first.said().contains("the primary Storage node"),
            "{}",
            first.said()
        );
        assert!(second.said().contains("a standby"), "{}", second.said());

        let journey = persist::storage::JourneyRecord {
            journey: xcore::JourneyId::new(7),
            body: b"over the wire".to_vec(),
            facts: persist::storage::JourneyFacts::default(),
        };
        reaching.storage().write_journey(&journey).expect("written");
        let node = configure::fixture::test_cluster().node_scope(2);
        let said = &reaching.published(&node)[0];
        assert_eq!(said.1, Health::Fine, "{}", said.2);
        assert!(
            said.2.contains(&format!("{} answered", listed[0])),
            "{}",
            said.2
        );

        first.stop();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !second.said().contains("the primary Storage node")
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let read = reaching
            .storage()
            .read_journey(journey.journey)
            .expect("read");
        assert_eq!(read.map(|r| r.body), Some(b"over the wire".to_vec()));
        second.stop();
        let gone = reaching.storage().read_journey(journey.journey);
        assert!(gone.is_err(), "no Storage node answers");
        let said = &reaching.published(&node)[0];
        assert_eq!(said.1, Health::Done, "{}", said.2);
    }

    #[test]
    fn a_node_listing_storage_nodes_with_nothing_to_present_is_refused_in_words() {
        let (head, file) = service();
        let text = head.replace(STORAGE, "roles = \"receiving\"\n")
            + "[storage]\nnodes = [\"storage.example:7443\"]\n";
        let refused = plan(&document(&text), &file, &linked())
            .err()
            .expect("nothing to present");
        assert!(
            refused.problems[0].contains("names no certificate, key and anchors"),
            "{refused}"
        );
    }
}
