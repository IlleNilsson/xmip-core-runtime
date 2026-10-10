//! How a node reaches Xmip Storage, the doorway to the Ledger, decided as
//! it starts (`runtime-model.md` section 3, *The Ledger*; ADR-0056,
//! amendment 2026-10-01, the Storage role): one `Arc<dyn XmipStorage>` the
//! message path writes through, whichever is behind it.
//!
//! - **The program's own.** A program that opened Xmip Storage itself — a
//!   test's Storage node, or a [`persist::storage::StorageClient`] it
//!   built with the identity it presents — hands it over in
//!   [`Linked::storage`], and that one is the node's.
//! - **The node's own embedded Storage node.** A node whose `[storage]`
//!   lists no Storage node is its own (`deployment-model.md` section 3: *A
//!   one-node deployment is its own Storage node*). Each data domain's
//!   database is where its table, `[runtime]`, `[administration]` or
//!   `[audit]`, says — its `storage` and its `connection`, a path relative
//!   to the configuration file (the owner, 2026-10-10: *i would do it like
//!   runtime, storage, connection string*) — and, where the table is left
//!   out, under the data directory: `RocksDB` at `<data>/storage/runtime`,
//!   `SQLite` at `<data>/storage/administration.sqlite` and at
//!   `<data>/storage/audit.sqlite` ([`FILES`]); all three sealed under the
//!   key store `[store]` names, with the key [`KEK`]. Phase 3 refuses a
//!   table Xmip Storage does not read, a database server, whose backend is
//!   not built yet, and a program that was not built with both engines —
//!   what `deploy/profile/role/storage.toml` builds — and phase 9 one
//!   whose databases do not open.
//! - **The Storage nodes `[storage]` lists**, round robin over Xmip's
//!   mutual TLS. The identity a node presents to them is not in its
//!   configuration yet, so a node listing them is refused at phase 3 unless
//!   its program handed it the client.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use configure::XmipConfigurationDocument;
use persist::Engine;
use persist::storage::database::{self, Domain, Technology};
use persist::storage::schema::Database;
use persist::storage::{Embedded, XmipStorage};
use secret::KekName;

use crate::linked::Linked;
use crate::running::Refusal;
use crate::service::StartupPhase;

/// The key-encryption key an embedded Storage node's data keys are
/// wrapped under.
pub const KEK: &str = "storage";

/// Where an embedded Storage node keeps its databases, under the node's
/// data directory.
pub const PLACE: &str = "storage";

/// Where each data domain's database is in [`PLACE`] where its table is
/// left out: the runtime, the administration and the audit database.
pub const FILES: [&str; 3] = ["runtime", "administration.sqlite", "audit.sqlite"];

/// What a node will reach Xmip Storage through, once phase 3 has held it
/// to what the program linked.
pub enum Planned {
    /// The program's own.
    Given(Arc<dyn XmipStorage>),
    /// The node's own embedded Storage node, each data domain's database
    /// at its place — runtime, administration, audit — sealed by the key
    /// store named `key_store` keeping its keys in `keys`.
    Embedded {
        places: [PathBuf; 3],
        key_store: String,
        keys: PathBuf,
    },
}

/// Xmip Storage as the node reached it, and the chunk a Stream is written
/// in.
pub struct Reached {
    storage: Arc<dyn XmipStorage>,
    chunk: usize,
    said: String,
}

impl Reached {
    /// Xmip Storage.
    #[must_use]
    pub fn storage(&self) -> &Arc<dyn XmipStorage> {
        &self.storage
    }

    /// The size a Stream is written to the Ledger in.
    #[must_use]
    pub const fn chunk(&self) -> usize {
        self.chunk
    }

    /// What it is and where, in words, and the chunk.
    #[must_use]
    pub fn said(&self) -> &str {
        &self.said
    }
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
/// Refused at phase 3 where the node lists Storage nodes and its program
/// gave it no way to reach them, or where it is its own Storage node and a
/// data domain's table is not one Xmip Storage reads, names a database
/// server, or its program was not built with both embedded engines.
pub fn plan(
    document: &XmipConfigurationDocument,
    path: &str,
    linked: &Linked,
) -> Result<Planned, Refusal> {
    if let Some(given) = &linked.storage {
        return Ok(Planned::Given(Arc::clone(given)));
    }
    let refused = |problem: String| Refusal::at(StartupPhase::ValidateStartup, vec![problem]);
    if !document.storage.nodes.is_empty() {
        return Err(refused(
            "[storage] nodes lists the Storage nodes this node reaches, and the identity it \
             presents to them over Xmip's TLS is not configurable yet; its program has to \
             hand it the client"
                .to_string(),
        ));
    }
    let file = Path::new(path);
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
                "this node is its own Storage node ([storage] lists none), and was not built \
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
    Ok(Planned::Embedded {
        places,
        key_store: store.key_store,
        keys: store.keys,
    })
}

/// The administration and audit databases' engine on an embedded Storage
/// node, by module name (`deployment-model.md` section 7).
pub const ADMINISTRATION: &str = "xmip-core-persist-sqlite";

impl Planned {
    /// Reach it: the program's own as it is, the embedded Storage node
    /// opened, writing Streams in chunks of `chunk` bytes (the node's
    /// `[tuning]`, `crate::tuning::Tuning::chunk`).
    ///
    /// # Errors
    ///
    /// Refused at phase 9 where the embedded Storage node's databases do
    /// not open: their directory cannot be made, an engine refuses —
    /// another process holding it among the reasons — or a key does not
    /// unwrap.
    pub fn open(self, linked: &Linked, chunk: usize) -> Result<Reached, Refusal> {
        let (storage, said) = match self {
            Self::Given(storage) => (storage, "the Xmip Storage its program opened".to_string()),
            Self::Embedded {
                places,
                key_store,
                keys,
            } => {
                let [runtime, administration, audit] = places.each_ref().map(|p| p.display());
                let at = format!(
                    "runtime at {runtime}, administration at {administration}, audit at {audit}"
                );
                let opened = embedded(linked, &places, &key_store, &keys).map_err(|problem| {
                    Refusal::at(
                        StartupPhase::AcceptWork,
                        vec![format!(
                            "its own Storage node, {at}, did not open: {problem}"
                        )],
                    )
                })?;
                let said = format!("its own Storage node, {at}, sealed under {key_store}");
                (opened, said)
            }
        };
        let said = format!("{said}, Streams in chunks of {} KiB", chunk / 1024);
        Ok(Reached {
            storage,
            chunk,
            said,
        })
    }
}

fn embedded(
    linked: &Linked,
    [runtime_at, administration_at, audit_at]: &[PathBuf; 3],
    key_store: &str,
    keys: &Path,
) -> Result<Arc<dyn XmipStorage>, String> {
    let (Some(runtime), Some(administration), Some(key_store)) = (
        linked.engine.as_ref(),
        linked.administration.as_ref(),
        linked.key_store(key_store),
    ) else {
        return Err("its engines or its key store are not linked".to_string());
    };
    for directory in [runtime_at, administration_at, audit_at] {
        let parent = directory.parent().unwrap_or(directory);
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let keys = key_store.open(keys);
    let kek = KekName::new(KEK).map_err(|error| error.to_string())?;
    let opened = |engine: &crate::linked::LinkedEngine, at: &Path| {
        engine.open(at).map_err(|error| error.to_string())
    };
    let runtime: Box<dyn Engine> = opened(runtime, runtime_at)?;
    let administration_store: Box<dyn Engine> = opened(administration, administration_at)?;
    let audit: Box<dyn Engine> = opened(administration, audit_at)?;
    let node = Embedded::open(runtime, administration_store, audit, keys.as_ref(), &kek)
        .map_err(|error| error.to_string())?;
    Ok(Arc::new(node))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::CHUNK;
    use crate::linked::{LinkedEngine, LinkedKeyStore};
    use persist::PersistError;
    use secret::KeyStore;

    /// The `[service]` section of the test cluster's first node, and the
    /// file name it is read from.
    fn service() -> (String, String) {
        let cluster = configure::fixture::test_cluster();
        let node = &cluster.node(0).name;
        let head = format!(
            "[service]\nname = \"xmip-{node}\"\ncluster_name = \"{}\"\nnode_name = \"{node}\"\n",
            cluster.name
        );
        (head, format!("{node}.toml"))
    }

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
            .open(&linked, CHUNK)
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
            .open(&linked(), CHUNK)
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
        let _ = std::fs::remove_dir_all(&directory);
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
            .open(&given, CHUNK)
            .expect("reached");
        assert!(
            reached
                .said()
                .starts_with("the Xmip Storage its program opened")
        );
    }
}
