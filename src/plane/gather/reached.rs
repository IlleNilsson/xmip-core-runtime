//! What `<node>/reached` says of a member of the cluster: reached at where
//! it is, did not answer and why, or stopped in order and when — the one
//! rule, which the gatherer states for every member of the view it
//! assembles and which a caller merging what was heard into a view of its
//! own states through it (`Gathered::merged`). A cluster's drawing reads it
//! for each relation's mood (`observe::topology::relate`). Until
//! 2026-11-13 the Essentials' roll held it (ADR-0028 and ADR-0052,
//! amendments 2026-11-13).

use std::time::{Duration, SystemTime};

use codec::civil::CivilTime;
use observe::snapshot::PAUSED_SEVERITY;
use observe::topology::draw::joined;
use observe::{Health, HealthRecord};

use super::gathered::{Heard, Said};

/// The leaf beneath a member's scope its reach is said at.
const REACHED: &str = "reached";

/// What `<root>/node/<member>/reached` says of `heard` at `now`: Fine at
/// where it is reached where it published; Exhausted, the same place and
/// why, where it did not answer; Paused, a deliberate stop, where it
/// stopped in order, and when, as RFC 3339.
#[must_use]
pub fn reached(root: &str, heard: &Heard, now: i64) -> HealthRecord {
    let (health, severity, evidence) = match &heard.said {
        Said::Published { .. } => (Health::Fine, 0, heard.at.clone()),
        Said::Nothing(why) => (
            Health::Exhausted,
            0,
            format!("{}, did not answer: {why}", heard.at),
        ),
        Said::Stopped(at) => (
            Health::Paused,
            PAUSED_SEVERITY,
            format!("{}, stopped in order at {}", heard.at, to_the_second(*at)),
        ),
    };
    HealthRecord {
        scope: joined(&[root, "/node/", &heard.node, "/", REACHED]),
        health,
        severity,
        evidence,
        observed_unix_nanos: now,
    }
}

/// `unix_nanos` as RFC 3339 in UTC to the whole second, as a person reads
/// when a member stopped: `2026-11-13T09:00:00Z`.
fn to_the_second(unix_nanos: u64) -> String {
    let after = Duration::from_nanos(unix_nanos);
    CivilTime::from_system_time(SystemTime::UNIX_EPOCH + after).rfc3339()
}
