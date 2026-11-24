//! What a node configured at a path last published since its start now, as
//! a deployment reads it after restarting the node (`xmip-service
//! --activation` and `--readiness`): which slice its file holds, and its
//! last publication where it wrote one since that start. Read once here for
//! both, so each reads the same records the same way; the file, its trust
//! and where the node publishes read once for a wait that asks again
//! (`readiness::awaited`).

use std::path::{Path, PathBuf};

use observe::{HealthRecord, Publication};

use super::super::publication::{SNAPSHOT, location};
use crate::membership::numbering;
use crate::signed::Which;

/// The node configured at a path, read once: which slice its file holds,
/// and where it publishes and keeps its start, or why that cannot be read.
pub(crate) struct Node {
    which: Which,
    place: Result<Place, String>,
}

/// Where a node publishes, beneath which location, and where it keeps the
/// number of its latest start.
struct Place {
    location: String,
    snapshot: PathBuf,
    configuration: PathBuf,
}

impl Node {
    /// The node configured at `path`.
    ///
    /// # Errors
    /// Its file cannot be read, or holds no signed slice: what is said of the
    /// node then is nothing.
    pub(crate) fn read(path: &str) -> Result<Self, String> {
        let file = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read {path}: {error}"))?;
        let signature = configure::signed::split(&file)
            .map_err(|why| format!("{path}: {why}"))?
            .1
            .ok_or_else(|| format!("{path} is not signed, and a node runs only a signed slice"))?;
        let which = Which {
            serial: signature.serial,
            save: signature.cluster,
        };
        Ok(Self {
            which,
            place: place(path),
        })
    }

    /// The folder it publishes in, where it can be told.
    pub(crate) fn directory(&self) -> Option<&Path> {
        self.place.as_ref().ok()?.snapshot.parent()
    }
}

/// Where the node configured at `path` publishes, read by its trust.
fn place(path: &str) -> Result<Place, String> {
    let (document, _, _) = crate::start::read(path).map_err(|unread| unread.reason)?;
    let service = &document.service;
    Ok(Place {
        location: location(&service.cluster_name, &service.node_name),
        snapshot: service.data_directory(Path::new(path)).join(SNAPSHOT),
        configuration: PathBuf::from(path),
    })
}

/// The node configured at a path: which slice its file holds, and its last
/// publication since its start now, or why there is none.
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

/// What `node`, configured at `path`, holds and last published since its
/// start now.
pub(crate) fn published(node: &Node) -> Published {
    Published {
        which: node.which.clone(),
        last: node.place.as_ref().map_err(Clone::clone).and_then(last),
    }
}

/// The last publication of the node at `place`, read where it publishes,
/// where it published it since its start now: one observed before the
/// number its latest start took is an earlier process's — one killed,
/// crashed or stopped past its service manager's bound — and says nothing
/// of the node now (open problem 137).
fn last(place: &Place) -> Result<Last, String> {
    let snapshot = &place.snapshot;
    let text = std::fs::read_to_string(snapshot).map_err(|error| {
        format!(
            "it has published nothing at {}: {error}",
            snapshot.display()
        )
    })?;
    let publication = Publication::read(&text)
        .map_err(|why| format!("{} does not read: {why}", snapshot.display()))?;
    let start = numbering::latest(&place.configuration)?;
    let observed = publication
        .records
        .iter()
        .map(|record| i128::from(record.observed_unix_nanos))
        .max();
    if let (Some(start), Some(observed)) = (start, observed)
        && observed < i128::from(start)
    {
        return Err(format!(
            "{} was published before its start now, numbered {start}: by an earlier process, \
             and it has published nothing since",
            snapshot.display()
        ));
    }
    Ok(Last {
        location: place.location.clone(),
        snapshot: snapshot.clone(),
        publication,
    })
}
