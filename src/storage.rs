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
//!   one-node deployment is its own Storage node*): `RocksDB` for the
//!   runtime database at `<data>/storage/runtime` and `SQLite` for the
//!   administration database at `<data>/storage/administration.sqlite`,
//!   both sealed under the key store `[store]` names, with the key
//!   [`KEK`]. Phase 3 refuses a program that was not built with both
//!   engines — what `deploy/profile/role/storage.toml` builds — and phase 9
//!   one whose databases do not open.
//! - **The Storage nodes `[storage]` lists**, round robin over Xmip's
//!   mutual TLS. The identity a node presents to them is not in its
//!   configuration yet, so a node listing them is refused at phase 3 unless
//!   its program handed it the client.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use configure::XmipConfigurationDocument;
use persist::Engine;
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

/// What a node will reach Xmip Storage through, once phase 3 has held it
/// to what the program linked.
pub enum Planned {
    /// The program's own.
    Given(Arc<dyn XmipStorage>),
    /// The node's own embedded Storage node, in `place`, sealed by the key
    /// store named `key_store` keeping its keys in `keys`.
    Embedded {
        place: PathBuf,
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

/// How the node configured at `path` reaches Xmip Storage, held to what
/// `linked` carries.
///
/// # Errors
///
/// Refused at phase 3 where the node lists Storage nodes and its program
/// gave it no way to reach them, or where it is its own Storage node and
/// its program was not built with both embedded engines.
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
    let mut problems = Vec::new();
    for (engine, technology, database) in [
        (&linked.engine, configure::store::ENGINE, "runtime"),
        (&linked.administration, ADMINISTRATION, "administration"),
    ] {
        if engine.is_none() {
            problems.push(format!(
                "this node is its own Storage node ([storage] lists none), and was not built \
                 with {technology}, its {database} database's engine"
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
    Ok(Planned::Embedded {
        place: data.join(PLACE),
        key_store: store.key_store,
        keys: store.keys,
    })
}

/// The administration database's engine on an embedded Storage node, by
/// module name (`deployment-model.md` section 7).
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
                place,
                key_store,
                keys,
            } => {
                let opened = embedded(linked, &place, &key_store, &keys).map_err(|problem| {
                    Refusal::at(
                        StartupPhase::AcceptWork,
                        vec![format!(
                            "its own Storage node at {} did not open: {problem}",
                            place.display()
                        )],
                    )
                })?;
                (
                    opened,
                    format!(
                        "its own Storage node at {}, sealed under {key_store}",
                        place.display()
                    ),
                )
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
    place: &Path,
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
    std::fs::create_dir_all(place).map_err(|error| error.to_string())?;
    let keys = key_store.open(keys);
    let kek = KekName::new(KEK).map_err(|error| error.to_string())?;
    let runtime: Box<dyn Engine> = runtime
        .open(&place.join("runtime"))
        .map_err(|error| error.to_string())?;
    let administration: Box<dyn Engine> = administration
        .open(&place.join("administration.sqlite"))
        .map_err(|error| error.to_string())?;
    let node = Embedded::open(runtime, administration, keys.as_ref(), &kek)
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

        assert!(
            reached.said().starts_with("its own Storage node at "),
            "{}",
            reached.said()
        );
        assert!(directory.join("state").join(PLACE).is_dir());
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
