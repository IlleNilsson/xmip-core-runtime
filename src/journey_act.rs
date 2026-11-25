//! An operator's act on a Message that failed, as every step that keeps
//! failed Messages takes it (`runtime-model.md` section 13): the Journey
//! read and read again under the act's claim, what the act leaves of it,
//! and its audit with who acted, or the failure said and audited. Placed
//! once: the send step acts for its Send Ports (`send_step::message_act`)
//! and the Work Process step for its Work Processes
//! (`work_step::message_act`; ADR-0066, amendment 2026-11-25).

use std::collections::BTreeMap;

use journey::{Attempts, Journey, JourneyEntry, JourneyState};
use observe::{Act, Noun};
use persist::storage::XmipStorage;
use xaudit::program_audit::ProgramAudit;
use xcore::{
    Clock, ExecutionId, ExecutionPhase, IdGenerator, JourneyId, MessageId, Severity, SystemClock,
    UuidV7Generator,
};

/// The step an act is taken through: its node, its Xmip Storage and its
/// audit.
pub(crate) struct Acting<'a> {
    pub(crate) node: &'a str,
    pub(crate) storage: &'a dyn XmipStorage,
    pub(crate) audit: Option<&'a ProgramAudit>,
}

impl Acting<'_> {
    /// The Journey `id` as the Ledger keeps it: its record's bytes, and it
    /// read.
    ///
    /// # Errors
    /// REFUSED where no such Journey is kept or it cannot be read; FAILED
    /// where Xmip Storage did not answer.
    pub(crate) fn kept(&self, act: Act, id: JourneyId) -> Result<(Vec<u8>, Journey), String> {
        match self.storage.read_journey(id) {
            Ok(Some(record)) => {
                let journey = Journey::from_record(&record.body)
                    .map_err(|why| format!("REFUSED: the Journey {id} cannot be read: {why}"))?;
                Ok((record.body, journey))
            }
            Ok(None) => Err(format!("REFUSED: no Journey {id} is in the Ledger")),
            Err(error) => Err(self.not_done(act, id, &error.to_string())),
        }
    }

    /// Whether the Journey `id`, read again under the act's claim, is still
    /// what was `seen` before it: refused in words where another writer —
    /// another operator's act, a node that sent or turned it — moved it
    /// meanwhile, so an act never writes back a state the Journey has left.
    ///
    /// # Errors
    /// As [`Acting::kept`], and REFUSED where it changed.
    pub(crate) fn unchanged(&self, act: Act, id: JourneyId, seen: &[u8]) -> Result<(), String> {
        let (now, journey) = self.kept(act, id)?;
        if now == seen {
            return Ok(());
        }
        Err(format!(
            "REFUSED: the Journey {id} changed while it was acted on and is {:?} now; \
             nothing was written, look again",
            journey.state
        ))
    }

    /// `act` on `id`, by `who`, at `at` — a Send Port or a Work Process, by
    /// its key and its name — audited with what it `said`.
    pub(crate) fn audited(
        &self,
        (act, id): (Act, JourneyId),
        (who, at): (&str, (&str, &str)),
        said: &str,
    ) {
        let Some(audit) = self.audit else {
            return;
        };
        let properties = BTreeMap::from([
            ("node".to_string(), self.node.to_string()),
            ("journey".to_string(), id.to_string()),
            (at.0.to_string(), at.1.to_string()),
            ("by".to_string(), who.to_string()),
        ]);
        let action = Noun::Message.action(act);
        let phase = ExecutionPhase::Execute;
        let _ = audit.record(
            &action,
            phase,
            Severity::Information,
            Some(said),
            properties,
        );
    }

    /// FAILED, said and audited: nothing of the act was written.
    pub(crate) fn not_done(&self, act: Act, id: JourneyId, problem: &str) -> String {
        let said = format!(
            "FAILED: the Message of the Journey {id} is not {}: Xmip Storage did not take it: \
             {problem}",
            if act == Act::Retry {
                "retried"
            } else {
                "dismissed"
            }
        );
        if let Some(audit) = self.audit {
            let _ = audit.failed(
                &Noun::Message.action(act),
                &format!("{}: {said}", self.node),
            );
        }
        said
    }
}

/// `kept` as `act` leaves it: Active again with its tries begun anew, or
/// Dismissed, the act appended to its history in words.
pub(crate) fn acted(kept: Journey, act: Act, said: &str) -> Journey {
    let message_id = kept
        .messages()
        .last()
        .map(|held| held.message_id)
        .unwrap_or(MessageId::new(0));
    let state = if act == Act::Retry {
        JourneyState::Active
    } else {
        JourneyState::Dismissed
    };
    let mut acted = kept.append(
        JourneyEntry {
            execution_id: ExecutionId::new(UuidV7Generator.next_u128()),
            message_id,
            action: act.word().to_string(),
            outcome: said.to_string(),
            timestamp_unix_nanos: SystemClock.unix_timestamp_nanos(),
        },
        state,
    );
    if act == Act::Retry {
        acted.attempts = Attempts::default();
    }
    acted
}
