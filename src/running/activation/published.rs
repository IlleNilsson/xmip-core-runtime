//! What a node configured at a path last published, as a deployment reads
//! it after restarting the node (`xmip-service --activation` and
//! `--readiness`): which slice its file holds, and its last publication
//! where it wrote one. Read once here for both, so each reads the same
//! records the same way.

use std::path::{Path, PathBuf};

use observe::{HealthRecord, Publication};

use super::super::publication::{SNAPSHOT, location};
use crate::signed::Which;

/// The node configured at a path: which slice its file holds, and its last
/// publication, or why it cannot be read.
pub(crate) struct Published {
    pub(crate) which: Which,
    pub(crate) last: Result<Last, String>,
}

/// A node's last publication, and where it publishes.
pub(crate) struct Last {
    /// The node's location, the scope it publishes beneath.
    location: String,
    /// The file it published in.
    snapshot: PathBuf,
    publication: Publication,
}

impl Last {
    /// Its record at `<node>/<leaf>`.
    ///
    /// # Errors
    /// It published none there, in words.
    pub(crate) fn record(&self, leaf: &str) -> Result<&HealthRecord, String> {
        let scope = format!("{}/{leaf}", self.location);
        self.publication
            .records
            .iter()
            .find(|record| record.scope == scope)
            .ok_or_else(|| format!("{} says nothing at {scope}", self.snapshot.display()))
    }
}

/// What the node configured at `path` holds and last published.
///
/// # Errors
/// Its file cannot be read, or holds no signed slice: what is said of the
/// node then is nothing.
pub(crate) fn published(path: &str) -> Result<Published, String> {
    let file =
        std::fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let signature = configure::signed::split(&file)
        .map_err(|why| format!("{path}: {why}"))?
        .1
        .ok_or_else(|| format!("{path} is not signed, and a node runs only a signed slice"))?;
    let which = Which {
        serial: signature.serial,
        save: signature.cluster,
    };
    Ok(Published {
        which,
        last: last(path),
    })
}

/// The last publication of the node configured at `path`, read where its
/// configuration says it publishes.
fn last(path: &str) -> Result<Last, String> {
    let (document, _, _) = crate::start::read(path).map_err(|unread| unread.reason)?;
    let service = &document.service;
    let snapshot = service.data_directory(Path::new(path)).join(SNAPSHOT);
    let text = std::fs::read_to_string(&snapshot).map_err(|error| {
        format!(
            "it has published nothing at {}: {error}",
            snapshot.display()
        )
    })?;
    let publication = Publication::read(&text)
        .map_err(|why| format!("{} does not read: {why}", snapshot.display()))?;
    Ok(Last {
        location: location(&service.cluster_name, &service.node_name),
        snapshot,
        publication,
    })
}
