//! What a node says of its membership, at `<node>/membership`, and the one
//! rule that flags a save not its peers' (ADR-0031, amendment 2026-11-06,
//! point 3: *the Monitor flags one whose save is not its peers'*). Every
//! surface reads the record from the snapshot, so none keeps words of its
//! own.

use std::collections::BTreeMap;

use codec::civil::CivilTime;
use observe::Health;
use persist::storage::MemberRecord;

use super::Followed;

/// Where beneath its node a node says its membership.
pub const MEMBERSHIP: &str = "membership";

/// The save the running members run, where one is theirs: the one most of
/// them run, alone at the most. None where none runs, or two saves are run
/// by as many members each — no save is then the peers'.
#[must_use]
pub fn peers_save(members: &[MemberRecord]) -> Option<&str> {
    let mut runs: BTreeMap<&str, usize> = BTreeMap::new();
    for member in members.iter().filter(|member| member.runs()) {
        *runs.entry(member.save.as_str()).or_default() += 1;
    }
    let most = runs.values().copied().max()?;
    let mut at_most = runs.iter().filter(|(_, count)| **count == most);
    let (save, _) = at_most.next()?;
    at_most.next().is_none().then_some(*save)
}

impl Followed {
    /// The node's membership as `<node>/membership` says it, handed to
    /// `record`: Working until its row reaches Xmip Storage; Stressed where
    /// the save it runs is not its peers' ([`peers_save`]); Fine otherwise.
    pub fn publish(&self, node: &str, mut record: impl FnMut(String, Health, String)) {
        let scope = format!("{node}/{MEMBERSHIP}");
        let (health, evidence) = self.said();
        record(scope, health, evidence);
    }

    fn said(&self) -> (Health, String) {
        let row = self.row();
        if !self.written() {
            let why = self.problem().unwrap_or_else(|| "writing it".to_string());
            return (
                Health::Working,
                format!("not a member yet: its row is not in Xmip Storage: {why}"),
            );
        }
        let members = self.rows();
        let own = members
            .iter()
            .find(|member| member.process == row.process)
            .unwrap_or(&row);
        let mut said = format!(
            "a member since {}, as process {:032x}: {}; runs serial {} of save {}",
            to_the_second(own.started_unix_nanos),
            row.process,
            listening(&row),
            row.serial,
            row.save
        );
        let running: Vec<&MemberRecord> = members.iter().filter(|m| m.runs()).collect();
        let peers = peers_save(&members);
        let others = running.len().saturating_sub(1);
        if others == 0 || peers == Some(row.save.as_str()) {
            said.push_str(&format!("; {} member(s) run, on this save", running.len()));
            return (Health::Fine, said);
        }
        let elsewhere: Vec<String> = running
            .iter()
            .filter(|member| member.save != row.save)
            .map(|member| format!("{} on {}", member.node, member.save))
            .collect();
        said.push_str(&format!(
            "; this save is not its peers': {}",
            elsewhere.join(", ")
        ));
        (Health::Stressed, said)
    }
}

/// Where the node answers, in words: its operate listener on the network,
/// its sync listener and its place among the Storage nodes.
fn listening(row: &MemberRecord) -> String {
    let operate = row.operate.as_ref().map_or_else(
        || "no operate listener on the network".to_string(),
        |at| format!("operated at {at}"),
    );
    let sync = row.sync.as_ref().map_or_else(
        || "no sync listener".to_string(),
        |at| format!("synced at {at}"),
    );
    let place = row
        .storage_place
        .map(|place| format!(", Storage node {} of those listed", place + 1))
        .unwrap_or_default();
    format!("{operate}, {sync}{place}")
}

/// `unix_nanos` as RFC 3339 in UTC to the whole second, as a person reads
/// when a member started: `2026-11-13T09:00:00Z`.
fn to_the_second(unix_nanos: u64) -> String {
    let after = std::time::Duration::from_nanos(unix_nanos);
    CivilTime::from_system_time(std::time::SystemTime::UNIX_EPOCH + after).rfc3339()
}
