//! The sequences a node's configuration names: each point that names a
//! correlation set, read once as the node starts, and the default every
//! Receive Location has (`super`).
//!
//! The owner, 2026-10-22: *Of course that is why the stages exist, Receive
//! Location, Receive Port. It is up to Xmip to work as specified. A Receive
//! Location can work on its own when the Correlation Set value is only
//! Receive Location. When there is a more complicated Correlation Set, Xmip
//! is the tool.*

use configure::{CorrelationSet, OnFailure};

use super::{Point, PointKind};
use crate::execution_tree::ExecutionTree;
use crate::work_step::ResolvedSet;

/// The point of `kind` called `name` that names the set `set` of `sets`.
///
/// # Errors
/// The set is not declared, or a key of it is no key word.
pub fn point(
    sets: &[CorrelationSet],
    (kind, name): (PointKind, &str),
    set: &str,
) -> Result<Point, String> {
    let declared = sets
        .iter()
        .find(|declared| declared.name == set)
        .ok_or_else(|| {
            format!(
                "the {} '{name}' names the correlation set '{set}', which the cluster does not \
                 declare",
                kind.word()
            )
        })?;
    Ok(Point {
        kind,
        name: name.to_string(),
        set: ResolvedSet::read(&declared.name, &declared.keys)?,
        on_failure: declared.on_failure.unwrap_or(OnFailure::Block),
    })
}

/// The sequences a Stream received at `location` holds end to end: the
/// Location's own — the set it names, or its name alone — and its Receive
/// Port's where the Port names a set; and the Port it is at.
///
/// # Errors
/// As [`point`].
pub fn received_at(tree: &ExecutionTree, location: &str) -> Result<(String, Vec<Point>), String> {
    let at = tree.receive_ports.iter().find_map(|port| {
        port.receive_locations
            .iter()
            .find(|designed| designed.name == location)
            .map(|designed| (port, designed))
    });
    let Some((port, designed)) = at else {
        return Ok((String::new(), vec![Point::receive_location(location)]));
    };
    let sets = &tree.correlation_sets;
    let own = match &designed.correlation_set {
        Some(set) => point(sets, (PointKind::ReceiveLocation, location), set)?,
        None => Point::receive_location(location),
    };
    let mut points = vec![own];
    if let Some(set) = &port.correlation_set {
        points.push(point(sets, (PointKind::ReceivePort, &port.name), set)?);
    }
    Ok((port.name.clone(), points))
}

/// The sequences of the node's Send Ports and Work Processes that name a
/// correlation set.
///
/// # Errors
/// Every point naming a set that is not declared, or broken, in words.
pub fn destinations(tree: &ExecutionTree) -> Result<Vec<Point>, Vec<String>> {
    let sets = &tree.correlation_sets;
    let named = tree
        .send_ports
        .iter()
        .filter_map(|port| {
            let set = port.correlation_set.as_deref()?;
            Some(point(sets, (PointKind::SendPort, &port.name), set))
        })
        .chain(
            tree.work_process_sets
                .iter()
                .map(|(name, set)| point(sets, (PointKind::WorkProcess, name), set)),
        );
    let (points, problems): (Vec<_>, Vec<_>) = named.partition(Result::is_ok);
    if problems.is_empty() {
        Ok(points.into_iter().filter_map(Result::ok).collect())
    } else {
        Err(problems.into_iter().filter_map(Result::err).collect())
    }
}

/// Every Message Context name the points of `points` read: what the
/// node's gathering reads beside its Subscriptions' names.
pub fn names(points: &[Point]) -> impl Iterator<Item = &str> {
    points.iter().flat_map(|point| point.set.names())
}
