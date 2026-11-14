//! A running node's gathering of its cluster, where its roles include
//! monitoring (`node::Capability::gathers`; ADR-0027 decision 8, ADR-0056
//! and ADR-0067, amendments 2026-11-13): the cluster's publication handed
//! to each operate listener as it starts, so `Cluster` answers from it at
//! once — revision 0 until the first view — and the gathering begun once
//! the node is activated and follows its membership through Xmip Storage
//! (`crate::membership`).
//!
//! **How it reaches each member.** Itself in process, through its own
//! publication, never over its own listener, where its service account
//! holds no role; every other member at the operate address its membership
//! row says, presenting the node's own `[operate]` certificate, as an
//! Observer there: every node lists each node declaring monitoring in its
//! `[operate] observers` (`configure::observers`, ADR-0009, amendment
//! 2026-11-13). A node that presents no `[operate]` certificate reaches no
//! other, and says why at each member's `<node>/reached`. Each member's
//! surface is kept while the members change, so a member already followed
//! is never reached anew.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use xcluster::Member;
use xcore::lock::Locked;
use xcore::wake::Revision;

use super::Running;
use super::publication::cluster_location;
use crate::membership::Followed;
use crate::plane::gather::{self, Follow, Reach};
use crate::plane::monitoring::{Members, Monitoring, Reaching};
use crate::plane::{Listener, Published, Remote};

impl Members for Followed {
    fn moved(&self) -> &Revision {
        self.revision()
    }
}

impl Running {
    /// Where its roles include monitoring, the cluster's publication handed
    /// to each of its operate `listeners`, and its own publication,
    /// `published`, kept to follow itself in process by.
    pub(super) fn monitored(&self, listeners: &[Listener], published: &Arc<dyn Published>) {
        if !node::Capability::of(&self.roles).gathers() {
            return;
        }
        let monitoring = self.monitoring.get_or_init(|| Gathering {
            monitoring: Monitoring::default(),
            own: Arc::clone(published),
        });
        for listener in listeners {
            listener.gathers(monitoring.monitoring.published());
        }
    }

    /// Its gathering begun, over the members as it follows them, where its
    /// roles include monitoring and it is a member: once activated. A
    /// gathering that does not start is said as the node's failure.
    pub(super) fn gather(&self) {
        let (Some(gathering), Some(members)) = (self.monitoring.get(), self.membership()) else {
            return;
        };
        let itself = self.location();
        let reach = self.reaching(&itself, &gathering.own);
        let cluster = (cluster_location(&self.cluster), itself);
        if let Err(problem) = gathering.monitoring.begin(cluster, members, reach) {
            self.tally.fail(&self.node, problem);
        }
    }

    /// Its gathering stopped, where it gathers.
    pub(super) fn stop_gathering(&self) {
        if let Some(gathering) = self.monitoring.get() {
            gathering.monitoring.stop();
        }
    }

    /// How it reaches each member: `itself`, the node of that scope, through
    /// `own`, its publication; every other over its operate address,
    /// presenting its own `[operate]` identity.
    fn reaching(&self, itself: &str, own: &Arc<dyn Published>) -> Reaching {
        let identity = self.operate.as_ref().map_or_else(
            || Err(NO_IDENTITY.to_string()),
            |operate| match operate.network() {
                Ok(Some(network)) => {
                    let files = [network.certificate, network.key, network.anchors];
                    crate::presented::identity(&self.configuration, "operate", files)
                }
                Ok(None) => Err(NO_IDENTITY.to_string()),
                Err(problem) => Err(problem),
            },
        );
        let (itself, own) = (itself.to_string(), gather::own(Arc::clone(own)));
        let kept: Mutex<BTreeMap<String, Arc<Remote>>> = Mutex::default();
        Box::new(move |member: &Member| {
            if member.node == itself {
                return Reach {
                    at: "in process".to_string(),
                    through: Ok(Arc::clone(&own)),
                };
            }
            let Some(address) = member.operate.as_deref() else {
                return Reach {
                    at: "no operate address".to_string(),
                    through: Err(NO_ADDRESS.to_string()),
                };
            };
            let through = identity
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|identity| {
                    let mut kept = kept.locked();
                    if let Some(remote) = kept.get(address) {
                        return Ok(Arc::clone(remote) as Arc<dyn Follow>);
                    }
                    let remote = Arc::new(Remote::open(address, identity)?);
                    kept.insert(address.to_string(), Arc::clone(&remote));
                    Ok(remote as Arc<dyn Follow>)
                });
            Reach {
                at: format!("at {address}"),
                through,
            }
        })
    }
}

/// A monitoring node's gathering, and its own publication it follows
/// itself through.
pub(super) struct Gathering {
    monitoring: Monitoring,
    own: Arc<dyn Published>,
}

/// Why a node reaches no other member.
const NO_IDENTITY: &str = "this node presents no [operate] certificate, so it reaches no other \
                           member over its operate listener";

/// Why a member is not reached where its row names no operate address.
const NO_ADDRESS: &str = "its membership names no operate address: it listens on no network";
