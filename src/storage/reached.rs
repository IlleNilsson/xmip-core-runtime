//! Xmip Storage as a node reached it, and what the node publishes of it:
//! which Storage it uses and whether it is reached (`<node>/storage`), and
//! the schema version of each database it keeps (`<node>/storage/<domain>`).

use std::sync::{Arc, Mutex, PoisonError};

use observe::Health;
use persist::storage::schema::DatabaseVersion;
use persist::storage::{StorageClient, StorageNode, StorageServer, XmipStorage};

use super::DATABASES;

/// What is behind the Xmip Storage a node reached.
pub(super) enum Behind {
    /// What its program opened.
    Given,
    /// Its own embedded Storage node, the only one: what it said as it
    /// opened, and the version each database holds.
    Alone(String, [DatabaseVersion; 3]),
    /// Its own Storage node, one of several.
    Several(Arc<StorageNode>),
    /// The Storage nodes listed, over the wire.
    Reaching(Arc<StorageClient>),
}

/// Xmip Storage as the node reached it, the chunk a Stream is written in,
/// and what serves it to the others where the node does.
pub struct Reached {
    pub(super) storage: Arc<dyn XmipStorage>,
    pub(super) chunk: usize,
    pub(super) behind: Behind,
    pub(super) serving: Mutex<Option<StorageServer>>,
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

    /// Where it serves Xmip Storage to the others, where it does.
    #[must_use]
    pub fn serving(&self) -> Option<std::net::SocketAddr> {
        let serving = self.serving.lock().unwrap_or_else(PoisonError::into_inner);
        serving.as_ref().map(StorageServer::address)
    }

    /// What it reaches and how it stands, in words, and the chunk: what
    /// the node says as it starts and publishes at `<node>/storage`.
    #[must_use]
    pub fn said(&self) -> String {
        let (_, what) = self.standing();
        let serving = self
            .serving()
            .map(|at| format!(", serving the others at {at}"))
            .unwrap_or_default();
        format!(
            "{what}{serving}, Streams in chunks of {} KiB",
            self.chunk / 1024
        )
    }

    /// Whether what it reaches answers, and what it is, in words.
    fn standing(&self) -> (Health, String) {
        match &self.behind {
            Behind::Given => (
                Health::Fine,
                "the Xmip Storage its program opened".to_string(),
            ),
            Behind::Alone(said, _) => (Health::Fine, said.clone()),
            Behind::Several(node) => {
                let health = if node.is_finding() {
                    Health::Done
                } else {
                    Health::Fine
                };
                (health, format!("its own Storage node, {}", node.said()))
            }
            Behind::Reaching(client) => reached(client),
        }
    }

    /// The schema version each database the node keeps itself holds; none
    /// where it reaches the program's own or other Storage nodes, which say
    /// their own, or is a standby, whose databases its primary's are.
    #[must_use]
    pub fn versions(&self) -> Vec<DatabaseVersion> {
        match &self.behind {
            Behind::Alone(_, versions) => versions.to_vec(),
            Behind::Several(node) => node.versions().map(|v| v.to_vec()).unwrap_or_default(),
            Behind::Given | Behind::Reaching(_) => Vec::new(),
        }
    }

    /// What the node beneath `node` publishes of it: at `<node>/storage`,
    /// which Storage it uses and whether it is reached — every surface
    /// shows it — and at `<node>/storage/<domain>`, the schema version each
    /// database it keeps holds and what it is kept on (open problem 41).
    #[must_use]
    pub fn published(&self, node: &str) -> Vec<(String, Health, String)> {
        let (health, _) = self.standing();
        let mut published = vec![(format!("{node}/{DATABASES}"), health, self.said())];
        published.extend(self.versions().iter().map(|held| {
            let scope = format!("{node}/{DATABASES}/{}", held.database.word());
            (scope, Health::Fine, held.evidence())
        }));
        published
    }

    /// Each record [`Reached::published`] says, handed to `record`.
    pub fn publish(&self, node: &str, mut record: impl FnMut(String, Health, String)) {
        for (scope, health, evidence) in self.published(node) {
            record(scope, health, evidence);
        }
    }

    /// Serve no other node any more, and, one Storage node of several, hand
    /// its standbys what it wrote first: after the node's own work has
    /// stopped.
    pub fn stop(&self) {
        if let Behind::Several(node) = &self.behind {
            node.stop();
        }
        let serving = self
            .serving
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(serving) = serving {
            serving.stop();
        }
    }
}

/// What the client last came to with each Storage node it lists: Fine
/// where one answered as the primary on its last ask, Done where every one
/// asked failed — *Storage is not here is a flat-out error* (the owner,
/// 2026-10-06).
fn reached(client: &StorageClient) -> (Health, String) {
    let each = client.reached();
    let answered = each
        .iter()
        .any(|(_, last)| last.as_ref().is_some_and(|last| last.answered));
    let asked = each.iter().any(|(_, last)| last.is_some());
    let said: Vec<String> = each
        .iter()
        .map(|(address, last)| match last {
            None => format!("{address} not asked yet"),
            Some(last) if last.answered => format!("{address} answered"),
            Some(last) => format!("{address} {}", last.said),
        })
        .collect();
    let health = if answered || !asked {
        Health::Fine
    } else {
        Health::Done
    };
    let what = format!(
        "the Storage nodes {} over Xmip's mutual TLS: {}",
        each.iter()
            .map(|(address, _)| address.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        said.join("; ")
    );
    (health, what)
}
