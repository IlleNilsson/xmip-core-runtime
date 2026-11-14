//! An act asked of a node, taken by that node once (`super`): judged again
//! against the node's own `[operate]` lists by the one rule its door
//! admitted the caller by, from the certificate or the account the caller
//! presented (`plane::grant::Grants::of`), so a door can grant nothing the
//! owning node's configuration does not and the node refuses nothing the
//! same lists granted (ADR-0009, amendment 2026-11-13); applied by the one
//! apply (`applied::apply`); decided once
//! in Xmip Storage; and audited at the node, saying who asked it, at which
//! door and through which relay, and what came of it.

use std::collections::BTreeMap;

use observe::{Noun, Order};
use persist::storage::{ActOutcome, ActRecord};
use xcore::{ExecutionPhase, Severity};

use super::ActWatch;
use crate::applied::{Applied, apply};
use crate::plane::Role;
use crate::plane::grant::Presented;

/// The audit action an act taken at its node records: the one the door's
/// gate records its admission under (`plane::served::AUDIT_ACTION`).
const AUDIT_ACTION: &str = "act";

impl ActWatch {
    /// `act`, asked of this node, taken where it is still asked: decided
    /// once, its decision audited, and what the node publishes told where
    /// it was taken.
    pub(super) fn take(&self, act: &ActRecord) {
        if !act.is_asked() {
            return;
        }
        let (outcome, said) = self.decided(act);
        match self.storage.decide_act(act.act, (outcome, &said)) {
            Ok(decided) => self.audited(&decided),
            Err(failed) => self.unrecorded(act, outcome, &failed.to_string()),
        }
        if outcome == ActOutcome::Taken
            && let Some(published) = &self.published
        {
            published.acted();
        }
    }

    /// What this node makes of `act`: refused where it names no noun or no
    /// act the noun takes, or where its caller is not listed here as an
    /// Operator or above; otherwise what the one apply answers.
    fn decided(&self, act: &ActRecord) -> (ActOutcome, String) {
        let Some(noun) = Noun::named(&act.noun) else {
            let said = format!("REFUSED: '{}' is no noun", act.noun);
            return (ActOutcome::Refused, said);
        };
        let word = match noun.act(&act.word) {
            Ok(word) => word,
            Err(refused) => return (ActOutcome::Refused, refused),
        };
        // What the caller presented, as the door wrote it: read by the one
        // rule the door admitted it by.
        let presented = act.certificate.clone().map_or_else(
            || Presented::Account(act.who.clone()),
            Presented::Certificate,
        );
        let role = self.grants.of(&presented);
        if !role.is_some_and(Role::may_operate) {
            let held = role.map_or("no role", Role::word);
            let said = format!(
                "REFUSED. {} holds {held} at {}: its [operate] operators and developers do not \
                 name them, so it takes no act asked at {} (ADR-0009)",
                act.who, act.node, act.door
            );
            return (ActOutcome::Refused, said);
        }
        let order = Order {
            node: act.node.clone(),
            noun,
            target: act.target.clone(),
            act: word,
            who: act.who.clone(),
        };
        match apply(&order) {
            Applied::Taken(said) => (ActOutcome::Taken, said),
            Applied::Refused(said) => (ActOutcome::Refused, said),
            Applied::Failed(said) => (ActOutcome::Failed, said),
        }
    }

    /// The node's own record of `act` decided: who asked it, at which door,
    /// through which relay, and what came of it.
    fn audited(&self, act: &ActRecord) {
        let failed = act.outcome != ActOutcome::Taken;
        let (phase, severity) = if failed {
            (ExecutionPhase::Failure, Severity::Warning)
        } else {
            (ExecutionPhase::Finished, Severity::Information)
        };
        let message = format!("{}: {}", asked(act), act.outcome.word());
        self.record((phase, severity), &message, act);
    }

    /// `act` decided `outcome` here, its decision not written: said in the
    /// audit, and asked of the node still, taken again as it next starts.
    fn unrecorded(&self, act: &ActRecord, outcome: ActOutcome, failed: &str) {
        let message = format!(
            "{}: {}, but Xmip Storage did not take the decision, so it stays asked: {failed}",
            asked(act),
            outcome.word()
        );
        self.record((ExecutionPhase::Failure, Severity::Warning), &message, act);
    }

    fn record(
        &self,
        (phase, severity): (ExecutionPhase, Severity),
        message: &str,
        act: &ActRecord,
    ) {
        let mut properties = BTreeMap::from([
            ("act".to_string(), act.word.clone()),
            (
                "target".to_string(),
                format!("{} '{}'", act.noun, act.target),
            ),
            ("who".to_string(), act.who.clone()),
            ("role".to_string(), act.role.clone()),
            ("door".to_string(), act.door.clone()),
            ("outcome".to_string(), act.outcome.word().to_string()),
            ("said".to_string(), act.said.clone()),
        ]);
        if let Some(through) = &act.through {
            properties.insert("through".to_string(), through.clone());
        }
        let _ = self
            .audit
            .record(AUDIT_ACTION, phase, severity, Some(message), properties);
    }
}

/// Who asked `act`, where, and what it asks: *CN=alice asked at* the door's
/// scope *through CN=web to pause subscription 'Orders' at* the node's
/// scope.
fn asked(act: &ActRecord) -> String {
    let through = act
        .through
        .as_ref()
        .map(|through| format!(" through {through}"))
        .unwrap_or_default();
    format!(
        "{} asked at {}{through} to {} {} '{}' at {}",
        act.who, act.door, act.word, act.noun, act.target, act.node
    )
}
