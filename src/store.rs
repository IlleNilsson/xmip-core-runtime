//! A node's runtime store, opened as the node starts from what its
//! configuration says and what its program linked (ADR-0018, amendment
//! 2026-09-30).
//!
//! The configuration names the engine and the key store by module name, and
//! where each keeps its bytes (`configure::store`, every default there);
//! the program links the engines and key stores it was built with
//! ([`crate::linked::LinkedEngine`], [`crate::linked::LinkedKeyStore`]), as
//! it links transports. Phase 3 refuses a store naming either one the
//! program was not built with; phase 9 opens it — persist's
//! `EncryptedStore` over the engine, its data key wrapped under the
//! key-encryption key [`KEK`] of the key store — and refuses a store that
//! does not open, before anything serves. What the node keeps there is what
//! a paused Subscription leaves (ADR-0013, amendment 2026-09-30).
//!
//! A program that linked no engine, starting a node whose configuration
//! names no store, holds in memory for the node's life. A program that
//! opened a store itself hands it over in [`Linked::store`], and that one is
//! the node's.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use configure::XmipConfigurationDocument;
use configure::store::Store as Configured;
use persist::EncryptedStore;
use secret::KekName;

use crate::linked::Linked;
use crate::pickup::Store;
use crate::running::Refusal;
use crate::service::StartupPhase;

/// The key-encryption key the runtime store's data key is wrapped under.
pub const KEK: &str = "runtime";

/// The store a node will open, once phase 3 has held it to what the
/// program linked.
pub struct Planned {
    data: PathBuf,
    store: Option<Configured>,
}

/// The store a node opened, and what it says of it.
pub struct Opened {
    data: PathBuf,
    store: Option<Store>,
    said: String,
}

impl Opened {
    /// The node's data directory (`configure::ServiceConfiguration::data`).
    #[must_use]
    pub fn data(&self) -> &Path {
        &self.data
    }

    /// The store, or none where the node holds in memory.
    #[must_use]
    pub fn held(&self) -> Option<Store> {
        self.store.clone()
    }

    /// What the store is and where, in words: the engine and its place,
    /// the key store and its.
    #[must_use]
    pub fn said(&self) -> &str {
        &self.said
    }
}

/// The store the node configured at `path` names, held to what `linked`
/// carries.
///
/// # Errors
/// Refused at phase 3 where the configuration names an engine or a key
/// store the program was not built with, or an engine without its place.
pub fn plan(
    document: &XmipConfigurationDocument,
    path: &str,
    linked: &Linked,
) -> Result<Planned, Refusal> {
    let file = Path::new(path);
    let data = document.service.data_directory(file);
    let in_memory = linked.engines.is_empty() && document.store.is_default();
    if linked.store.is_some() || in_memory {
        return Ok(Planned { data, store: None });
    }
    let refused = |problem: String| Refusal::at(StartupPhase::ValidateStartup, vec![problem]);
    let base = file.parent().unwrap_or_else(|| Path::new(""));
    let store = document.store.resolve(&data, base).map_err(refused)?;
    let mut problems = Vec::new();
    if linked.engine(&store.engine).is_none() {
        problems.push(format!(
            "[store] names the engine '{}', which this node was not built with",
            store.engine
        ));
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
    Ok(Planned {
        data,
        store: Some(store),
    })
}

impl Planned {
    /// Open it.
    ///
    /// # Errors
    /// Refused at phase 9 where the store does not open: its directory
    /// cannot be made, the engine refuses it — another process holding it
    /// among the reasons — or its key does not unwrap.
    pub fn open(self, linked: &Linked) -> Result<Opened, Refusal> {
        let Some(configured) = self.store else {
            let (store, said) = match &linked.store {
                Some(store) => (Some(Arc::clone(store)), "the store its program opened"),
                None => (None, "in memory, for the node's life"),
            };
            return Ok(Opened {
                data: self.data,
                store,
                said: said.to_string(),
            });
        };
        let (store, said) = opened(&configured, linked).map_err(|problem| {
            Refusal::at(
                StartupPhase::AcceptWork,
                vec![format!(
                    "the runtime store {} at {} did not open: {problem}",
                    configured.engine,
                    configured.place.display()
                )],
            )
        })?;
        Ok(Opened {
            data: self.data,
            store: Some(store),
            said,
        })
    }
}

fn opened(configured: &Configured, linked: &Linked) -> Result<(Store, String), String> {
    let (Some(engine), Some(key_store)) = (
        linked.engine(&configured.engine),
        linked.key_store(&configured.key_store),
    ) else {
        return Err("its engine or key store is not linked".to_string());
    };
    if let Some(parent) = configured.place.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let keys = key_store.open(&configured.keys);
    let kek = KekName::new(KEK).map_err(|error| error.to_string())?;
    let engine = engine
        .open(&configured.place)
        .map_err(|error| error.to_string())?;
    let store = EncryptedStore::open(engine, keys.as_ref(), &kek).map_err(|e| e.to_string())?;
    let said = format!(
        "{} at {}, sealed under {} ({})",
        configured.engine,
        configured.place.display(),
        configured.key_store,
        keys.store()
    );
    Ok((Arc::new(store), said))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linked::{LinkedEngine, LinkedKeyStore};
    use persist::{Engine, PersistError};
    use secret::KeyStore;

    const NODE: &str = "[service]\nname = \"xmip-R1\"\ncluster_name = \"C1\"\nnode_name = \"R1\"\n";

    fn memory(_: &Path) -> Result<Box<dyn Engine>, PersistError> {
        Ok(Box::new(persist::fixture::Memory::default()))
    }

    fn keys(_: &Path) -> Box<dyn KeyStore> {
        Box::new(secret::Held::new(secret::fixture::Memory::default()))
    }

    fn linked() -> Linked {
        Linked {
            engines: vec![LinkedEngine::new("xmip-core-persist-memory", memory)],
            key_stores: vec![LinkedKeyStore::new("xmip-core-secret-memory", keys)],
            ..Linked::default()
        }
    }

    fn document(text: &str) -> XmipConfigurationDocument {
        configure::parse_toml(text).expect("parses")
    }

    #[test]
    fn a_store_the_program_links_is_opened_where_the_configuration_says() {
        let directory = std::env::temp_dir().join(format!("xmip-store-{}", std::process::id()));
        let text = format!(
            "{NODE}data = \"state\"\n[store]\nengine = \"xmip-core-persist-memory\"\n\
             place = \"state/store\"\nkey_store = \"xmip-core-secret-memory\"\n"
        );
        let path = directory.join("R1.toml");
        let opened = plan(&document(&text), path.to_str().expect("UTF-8"), &linked())
            .expect("planned")
            .open(&linked())
            .expect("opened");

        assert!(opened.held().is_some());
        assert_eq!(opened.data(), directory.join("state"));
        assert!(
            opened.said().starts_with("xmip-core-persist-memory at "),
            "{}",
            opened.said()
        );
        assert!(directory.join("state").is_dir(), "its directory is made");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn what_the_program_was_not_built_with_is_refused_at_phase_three() {
        let refused = plan(&document(NODE), "R1.toml", &linked())
            .err()
            .expect("the default engine is not linked here");
        assert_eq!(refused.phase, StartupPhase::ValidateStartup);
        assert!(
            refused.problems[0].contains("'xmip-core-persist-rocksdb'"),
            "{refused}"
        );
        assert!(refused.problems[1].contains("key store"), "{refused}");
    }

    #[test]
    fn a_program_that_linked_no_engine_holds_in_memory_unless_a_store_is_named() {
        let unlinked = Linked::default();
        let opened = plan(&document(NODE), "R1.toml", &unlinked)
            .expect("planned")
            .open(&unlinked)
            .expect("opened");
        assert!(opened.held().is_none());
        assert_eq!(opened.said(), "in memory, for the node's life");

        let named = format!("{NODE}[store]\nkeys = \"k\"\n");
        let refused = plan(&document(&named), "R1.toml", &unlinked)
            .err()
            .expect("a named store needs an engine");
        assert!(refused.problems[0].contains("engine"), "{refused}");
    }
}
