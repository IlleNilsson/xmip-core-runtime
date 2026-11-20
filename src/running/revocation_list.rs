//! The cluster authority's revocation list kept current on the node that
//! keeps the authority (ADR-0034, amendment 2026-11-07): a list is valid a
//! week (`provision::register::LIST_LIFETIME`) and every mutual-TLS listener
//! that holds it refuses each client once it is past its nextUpdate
//! (`crate::presented`), so the node asks for it every [`EVERY`] and the
//! register remakes it by its one rule — once a day old
//! (`provision::register::Register::list`) — long before then, whether or
//! not anyone else asks for it. The hour is counted on the node's Clock
//! (ADR-0068, amendment 2026-11-15).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use provision::Issuer;
use xcore::Clock;
use xcore::clock::between;

use crate::running::Running;

/// How often a running node asks for its authority's list.
pub const EVERY: Duration = Duration::from_hours(1);

/// The list kept beside one node's configuration, and when it was last
/// asked for, on the node's clock.
pub struct RevocationList {
    configuration: PathBuf,
    asked: Option<i128>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for RevocationList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationList")
            .field("configuration", &self.configuration)
            .field("asked", &self.asked)
            .finish_non_exhaustive()
    }
}

impl Running {
    /// The revocation list the authority kept beside this node's
    /// configuration publishes, to keep current while the node runs.
    #[must_use]
    pub fn revocation_list(&self) -> RevocationList {
        RevocationList {
            configuration: self.configuration.clone(),
            asked: None,
            clock: Arc::clone(&self.clock),
        }
    }
}

impl RevocationList {
    /// Where [`EVERY`] has passed since it was last asked for, ask the
    /// authority for its list, which the register remakes where the one kept
    /// is a day old: whether a list is kept here to keep current. Nothing
    /// is made where the node keeps no authority or no list was made yet.
    ///
    /// # Errors
    ///
    /// The authority or its register cannot be read, or the list cannot be
    /// written; in words naming the file.
    pub fn keep(&mut self) -> Result<bool, String> {
        let now = self.clock.monotonic_nanos();
        if self.asked.is_some_and(|asked| between(asked, now) < EVERY) {
            return Ok(false);
        }
        self.asked = Some(now);
        current(&self.configuration, provision::now())
    }
}

/// The list kept beside the configuration at `configuration`, asked for at
/// `now`: whether one is kept there.
fn current(configuration: &Path, now: i64) -> Result<bool, String> {
    let list = crate::presented::list_at(configuration);
    let place = list.parent().unwrap_or_else(|| Path::new("."));
    if !list.exists() || !place.join(provision::issuer::KEY).exists() {
        return Ok(false);
    }
    let said = |why: String| format!("the revocation list {}: {why}", list.display());
    let authority = Issuer::kept(place).map_err(|error| said(error.to_string()))?;
    authority
        .revocation_list(now)
        .map_err(|error| said(error.to_string()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn a_list_a_day_old_is_made_again_and_a_node_keeping_none_makes_none() {
        let base = file::temporary::Folder::new("runtime-list-current");
        let configuration = base.join("node.xmip");
        let place = base.join(crate::signed::AUTHORITY);
        let now = provision::now();
        let authority =
            Issuer::kept_or_made(&place, "test authority", now, 30 * DAY).expect("an authority");
        assert!(!current(&configuration, now).expect("read"), "no list yet");
        let list = crate::presented::list_at(&configuration);
        assert!(!list.exists());

        let first = authority.revocation_list(now).expect("a list");
        assert!(current(&configuration, now + 3600).expect("kept"));
        assert_eq!(std::fs::read(&list).expect("read"), first, "fresh: kept");
        assert!(current(&configuration, now + DAY + 1).expect("kept"));
        assert_ne!(
            std::fs::read(&list).expect("read"),
            first,
            "a day old: made again"
        );

        let clock = Arc::new(xcore::clock::Stepped::default());
        let mut kept = RevocationList {
            configuration,
            asked: None,
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
        };
        assert!(kept.keep().expect("asked"));
        assert!(!kept.keep().expect("not yet"), "asked once an hour");
        clock.pass(EVERY.checked_sub(Duration::from_nanos(1)).expect("an hour"));
        assert!(!kept.keep().expect("not yet"), "a nanosecond short");
        clock.pass(Duration::from_nanos(1));
        assert!(
            kept.keep().expect("asked"),
            "asked again once the hour passed"
        );
    }
}
