//! The members as the cluster's one seam says them, `xcluster::Membership`,
//! over the `membership` table as the node follows it (`super`): what every
//! follower of the members takes — the gatherer, the cluster's Events.

use node::Capability;
use persist::storage::MemberRecord;
use xcluster::{ClusterError, Member, Membership};

use super::Followed;

impl Membership for Followed {
    /// Each node's latest row as last read, running or stopped in order: a
    /// node stopped in order is a member until its environment removes it.
    ///
    /// # Errors
    ///
    /// Where the node's row has not reached Xmip Storage yet, saying why,
    /// or a row's evidence declares a word that is no role.
    fn members(&self) -> Result<Vec<Member>, ClusterError> {
        if !self.written() {
            let why = self
                .problem()
                .unwrap_or_else(|| "not tried yet".to_string());
            return Err(ClusterError::new(format!(
                "the members are not read yet: this node's row is not in Xmip Storage: {why}"
            )));
        }
        self.rows().iter().map(member).collect()
    }
}

/// `row` as a member: its node, where its sync and operate listeners
/// answer, what it declares — read back from its evidence by the one
/// reading, roles and online capability both — its place among the Storage
/// nodes, and when it stopped in order.
fn member(row: &MemberRecord) -> Result<Member, ClusterError> {
    let capability = Capability::from_evidence(&row.evidence)
        .map_err(|refused| ClusterError::new(format!("the member {}: {refused}", row.node)))?;
    Ok(Member {
        node: row.node.clone(),
        address: row.sync.clone(),
        capability,
        operate: row.operate.clone(),
        storage_place: row
            .storage_place
            .and_then(|place| usize::try_from(place).ok()),
        stopped: row.stopped_unix_nanos,
    })
}
