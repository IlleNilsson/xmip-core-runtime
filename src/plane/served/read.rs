//! A publication answered on the operate listener: the node's own
//! (`Publication`, `Wait`) and the cluster's a monitoring node gathered
//! (`Cluster`, `ClusterWait`; ADR-0027 decision 8, amendment 2026-11-13),
//! read and waited on one way, from what the listener was handed
//! (`plane::Published`); and what a listener handed no cluster's
//! publication answers the cluster's with — the one refusal, whether a node
//! declares no monitoring role or a program hosting a listener has posted
//! none it gathered: an answer of its own kind (`call::gathers_none`),
//! which a surface decides by, carrying words for a person, which nothing
//! decides by.

use std::time::Duration;

use net::http::Response;
use serde_json::{Value, json};

use crate::plane::board::Published;
use crate::plane::call::{self, CLUSTER, CLUSTER_WAIT, LONGEST_WAIT, WAIT};
use crate::plane::listener::Serve;

/// The words a listener handed no cluster's publication says, for a
/// person, in its answer to `Cluster` and `ClusterWait`
/// (`call::gathers_none`).
pub const GATHERS_NO_CLUSTER: &str = "REFUSED. This node declares no monitoring role, so it \
     gathers no cluster's publication: ask a node declaring the monitoring role, or follow this \
     node's own publication (ADR-0056; ADR-0027 decision 8)";

/// `method` — a read of the node's publication or the cluster's, or a wait
/// on either — its caller admitted already, answered from what the
/// listener holds: the revision and the text, or the revision once it is
/// past `after` in `message`, waiting at most its `within_ms` and never
/// past [`LONGEST_WAIT`], and at once as the listener stops.
pub(super) fn read(serve: &Serve, method: &str, message: &Value) -> Response {
    let published: &dyn Published = match method {
        CLUSTER | CLUSTER_WAIT => match serve.gathered.get() {
            Some(gathered) => gathered.as_ref(),
            None => return call::gathers_none(GATHERS_NO_CLUSTER),
        },
        _ => serve.published.as_ref(),
    };
    if matches!(method, WAIT | CLUSTER_WAIT) {
        let after = message["after"].as_u64().unwrap_or(0);
        let within = message["within_ms"]
            .as_u64()
            .map_or(LONGEST_WAIT, Duration::from_millis)
            .min(LONGEST_WAIT);
        let revision = published.wait(after, within, &|| serve.stopped());
        return call::answer(&json!({ "revision": revision }));
    }
    let (revision, text) = published.read();
    call::answer(&json!({ "revision": revision, "publication": text }))
}
