//! A node's Xmip Storage reached as it starts, at phase 9: the program's
//! own as it is, its own Storage node opened and served, or the Storage
//! nodes listed reached (`super`).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use persist::Engine;
use persist::storage::schema::DatabaseVersion;
use persist::storage::{Embedded, StorageClient, StorageNode, StorageServer, XmipStorage};
use secret::{KekName, KeyStore};

use super::reached::Behind;
use super::{KEK, Planned, Reached};
use crate::linked::Linked;
use crate::running::Refusal;
use crate::service::StartupPhase;
use crate::tuning::Tuning;

impl Planned {
    /// Reach it: the program's own as it is, the node's own Storage node
    /// opened — the only one, or one of several settling with the others
    /// which is the primary — and served where `[storage] listen` says, or
    /// the Storage nodes listed reached; every Stream written in chunks of
    /// `tuning`'s chunk, every dealing with a Storage node bounded by its
    /// `[tuning]`.
    ///
    /// # Errors
    ///
    /// Refused at phase 9 where the node's own databases do not open —
    /// their directory cannot be made, an engine refuses, another process
    /// holding it among the reasons, or a key does not unwrap — or where
    /// it cannot listen where it serves.
    pub fn open(self, linked: &Linked, tuning: &Tuning) -> Result<Reached, Refusal> {
        let refused = |problem: String| Refusal::at(StartupPhase::AcceptWork, vec![problem]);
        let timings = tuning.storage();
        let (storage, behind, serving) = match self {
            Self::Given(storage) => (storage, Behind::Given, None),
            Self::Reaching { listed, identity } => {
                let client =
                    StorageClient::new(&listed, &identity, timings.timeout, timings.pass_over)
                        .map_err(|problem| refused(problem.to_string()))?;
                let client = Arc::new(client);
                (
                    Arc::clone(&client) as Arc<dyn XmipStorage>,
                    Behind::Reaching(client),
                    None,
                )
            }
            Self::Kept {
                places,
                key_store,
                keys,
                serving,
            } => {
                let [runtime, administration, audit] = places.each_ref().map(|p| p.display());
                let at = format!(
                    "runtime at {runtime}, administration at {administration}, audit at {audit}"
                );
                let did_not_open = |problem: String| {
                    refused(format!(
                        "its own Storage node, {at}, did not open: {problem}"
                    ))
                };
                let (engines, keys) =
                    engines(linked, &places, &key_store, &keys).map_err(did_not_open)?;
                let kek = KekName::new(KEK).map_err(|e| did_not_open(e.to_string()))?;
                let bound = serving
                    .as_ref()
                    .map(|serving| {
                        TcpListener::bind(&serving.listen).map_err(|error| {
                            refused(format!(
                                "[storage] listen = \"{}\": {error}",
                                serving.listen
                            ))
                        })
                    })
                    .transpose()?;
                match (serving, bound) {
                    (Some(serving), Some(bound)) if !serving.listed.is_empty() => {
                        let node = StorageNode::new(
                            engines,
                            (keys, kek),
                            &serving.listed,
                            &serving.identity,
                            timings,
                        )
                        .map_err(|problem| did_not_open(problem.to_string()))?;
                        let server = StorageServer::several(&node, bound, &serving.identity)
                            .map_err(|problem| refused(problem.to_string()))?;
                        node.start(timings.silence + timings.timeout)
                            .map_err(|problem| refused(problem.to_string()))?;
                        (node.reaching(), Behind::Several(node), Some(server))
                    }
                    (serving, bound) => {
                        let [runtime, administration, audit] = engines;
                        let opened =
                            Embedded::open(runtime, administration, audit, keys.as_ref(), &kek)
                                .map_err(|problem| did_not_open(problem.to_string()))?;
                        let versions = *opened.versions();
                        let opened: Arc<dyn XmipStorage> = Arc::new(opened);
                        let server = match (serving, bound) {
                            (Some(serving), Some(bound)) => Some(
                                StorageServer::start(Arc::clone(&opened), bound, &serving.identity)
                                    .map_err(|problem| refused(problem.to_string()))?,
                            ),
                            _ => None,
                        };
                        let said = alone(&at, &key_store, &versions);
                        (opened, Behind::Alone(said, versions), server)
                    }
                }
            }
        };
        Ok(Reached {
            storage,
            chunk: tuning.chunk(),
            behind,
            serving: Mutex::new(serving),
        })
    }
}

/// What the only Storage node says of itself.
fn alone(at: &str, key_store: &str, versions: &[DatabaseVersion; 3]) -> String {
    let held: Vec<String> = versions
        .iter()
        .map(|held| format!("{} {}", held.database.word(), held.evidence()))
        .collect();
    format!(
        "its own Storage node, {at}, sealed under {key_store}: {}",
        held.join(", ")
    )
}

/// A Storage node's three engines — runtime, administration, audit — and
/// the key store their data keys are sealed in.
type Kept = ([Arc<dyn Engine>; 3], Arc<dyn KeyStore>);

/// The three engines a Storage node keeps its databases in, opened at
/// their places, and the key store their data keys are sealed in.
fn engines(
    linked: &Linked,
    [runtime_at, administration_at, audit_at]: &[PathBuf; 3],
    key_store: &str,
    keys: &Path,
) -> Result<Kept, String> {
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
    let keys: Arc<dyn KeyStore> = Arc::from(key_store.open(keys));
    let opened = |engine: &crate::linked::LinkedEngine, at: &Path| {
        engine
            .open(at)
            .map(Arc::from)
            .map_err(|error| error.to_string())
    };
    let engines: [Arc<dyn Engine>; 3] = [
        opened(runtime, runtime_at)?,
        opened(administration, administration_at)?,
        opened(administration, audit_at)?,
    ];
    Ok((engines, keys))
}
