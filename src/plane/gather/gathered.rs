//! What a gatherer heard of every member, together, and the cluster's view
//! it assembles from it: every member's snapshot merged by observe's one
//! merge (`Snapshot::merge`), its `<node>/reached` ([`super::reached`]), the
//! rollup at `<cluster>/node` (`observe::rollup::nodes`), and the cluster
//! drawn — its members (`draw::members`), their relations by role
//! (`relate::relations`), what each drew of itself merged by its name
//! (`Topology::merge_each`), and what moved stated by the gatherer's one window
//! (`observe::topology::window`), so no rate is computed in a second place
//! (open problem 63).

use std::sync::Arc;

use observe::topology::window::Window;
use observe::topology::{draw, relate};
use observe::{Snapshot, Topology};

use super::reached::reached;

/// What a member said when it was last heard.
#[derive(Clone, Debug)]
pub enum Said {
    /// Its publication: its snapshot, and what it drew of itself.
    Published {
        snapshot: Box<Snapshot>,
        drawing: Option<Topology>,
    },
    /// Nothing: why it did not answer, in its surface's words.
    Nothing(String),
    /// It stopped in order, at this time in unix nanoseconds, as its
    /// membership says.
    Stopped(u64),
}

/// What a gatherer last heard of one member.
#[derive(Clone, Debug)]
pub struct Heard {
    /// Its name: an opaque id beneath `<cluster>/node`.
    pub node: String,
    /// Where it is reached, as its `<node>/reached` opens.
    pub at: String,
    /// What it said.
    pub said: Said,
}

/// The latest a gatherer heard of every member, and the cluster's view
/// assembled from it.
#[derive(Debug, Default)]
pub struct Gathered {
    /// The cluster's scope.
    pub root: String,
    /// How many views the gatherer has assembled, this one the last: 0
    /// before the first.
    pub revision: u64,
    /// The latest heard of each member, in the order the members were
    /// given.
    pub heard: Vec<Arc<Heard>>,
    /// The cluster's view: every member's snapshot merged, each member's
    /// `<node>/reached`, and the rollup at `<cluster>/node`.
    pub snapshot: Snapshot,
    /// The cluster drawn from it.
    pub topology: Topology,
}

impl Gathered {
    /// The cluster at `root` of `members`, gathered `by` the node of that
    /// scope where a node gathers, assembled at `now` from what was `heard`
    /// of each, its `revision`, and what moved stated by `window`, the
    /// gatherer's one. Its drawing's source says who gathered and how many
    /// answered: *`<cluster>`, gathered by `<node>`: 9 of 9 nodes reached*,
    /// or *`<cluster>`, gathered: …* where no node gathers.
    #[must_use]
    pub fn assembled(
        (root, by, members): (&str, Option<&str>, &[relate::Member]),
        heard: Vec<Arc<Heard>>,
        revision: u64,
        (now, window): (i64, &mut Window),
    ) -> Self {
        let mut snapshot = Snapshot::new();
        let drawings = stated(root, &heard, &mut snapshot, now);
        let rollup = observe::rollup::nodes(&snapshot, root, heard.len(), now);
        snapshot.record_health(rollup);
        let answered = heard
            .iter()
            .filter(|one| matches!(one.said, Said::Published { .. }))
            .count();
        let gathered = by.map_or_else(
            || "gathered".to_string(),
            |by| format!("gathered by {}", draw::label(by)),
        );
        let mut topology = Topology {
            source: format!(
                "{}, {gathered}: {answered} of {} nodes reached",
                draw::label(root),
                heard.len()
            ),
            observed_unix_nanos: now,
            nodes: draw::members(&snapshot, root, members),
            links: relate::relations(root, members, &snapshot),
        };
        topology.merge_each(drawings);
        window.state(&mut topology, &snapshot);
        Self {
            root: root.to_string(),
            revision,
            heard,
            snapshot,
            topology,
        }
    }

    /// What was heard of every member merged into `view` — a view of the
    /// caller's own — and each member's `<node>/reached` stated at `now`;
    /// and what each drew of itself, by its name, for the caller to merge
    /// into its drawing of the cluster (`Topology::merge`). What the
    /// Essentials' roll states each round (ADR-0028, amendment 2026-11-13).
    #[must_use]
    pub fn merged(&self, view: &mut Snapshot, now: i64) -> Vec<(String, Topology)> {
        stated(&self.root, &self.heard, view, now)
            .into_iter()
            .map(|(name, drawing)| (name.to_string(), drawing.clone()))
            .collect()
    }
}

/// Each of `heard` merged into `view` beneath `root`, its snapshot where it
/// published and its `<node>/reached` at `now` whatever it said, in order;
/// what each drew of itself, by its name.
fn stated<'a>(
    root: &str,
    heard: &'a [Arc<Heard>],
    view: &mut Snapshot,
    now: i64,
) -> Vec<(&'a str, &'a Topology)> {
    heard
        .iter()
        .filter_map(|one| {
            if let Said::Published { snapshot, .. } = &one.said {
                view.merge(snapshot);
            }
            view.record_health(reached(root, one, now));
            match &one.said {
                Said::Published {
                    drawing: Some(drawing),
                    ..
                } => Some((one.node.as_str(), drawing)),
                _ => None,
            }
        })
        .collect()
}
