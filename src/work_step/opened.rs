//! The Work Processes a node runs, opened as it starts: each that names a
//! compiled unit (`module` and `unit`) taken from the library its module
//! was opened from, the Correlations it follows read from the
//! cluster's, its names compiled through the route technologies the
//! program linked.

use std::sync::Arc;

use route::Source;

use super::keys::ResolvedSet;
use super::running::{NoUnits, Running};
use crate::execution_tree::ExecutionTree;
use crate::library::Libraries;
use crate::linked::Linked;

/// Every Work Process `tree` starts that names its unit, opened.
///
/// # Errors
/// One sentence per Work Process whose unit was not opened, or whose sets
/// or names do not read; a Work Process that names only one of `module`
/// and `unit`, too.
pub fn opened(
    tree: &ExecutionTree,
    cluster: &str,
    libraries: &Libraries,
    linked: &Linked,
) -> Result<Vec<Running>, Vec<String>> {
    let mut problems = Vec::new();
    let sets: Vec<ResolvedSet> = tree
        .correlations
        .iter()
        .filter_map(|set| match ResolvedSet::read(&set.name, &set.keys) {
            Ok(set) => Some(set),
            Err(why) => {
                problems.push(why);
                None
            }
        })
        .collect();
    let sources: Vec<&dyn Source> = linked.sources.iter().map(AsRef::as_ref).collect();
    let mut running = Vec::new();
    for process in &tree.work_processes_to_start {
        let (module, unit) = match (&process.module, &process.unit) {
            (Some(module), Some(unit)) => (module, unit),
            (None, None) => continue,
            _ => {
                problems.push(format!(
                    "the Work Process '{}' names its unit by module and unit, both",
                    process.name
                ));
                continue;
            }
        };
        let opened = libraries.flow(module, unit).and_then(|flow| {
            Running::new(
                (cluster, &process.name),
                flow,
                &sets,
                &sources,
                Arc::new(NoUnits),
            )
        });
        match opened {
            Ok(opened) => running.push(opened),
            Err(why) => problems.push(format!("the Work Process '{}': {why}", process.name)),
        }
    }
    if problems.is_empty() {
        Ok(running)
    } else {
        Err(problems)
    }
}
