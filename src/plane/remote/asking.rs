//! One call on a surface's asking line, bounded by the surface's patience:
//! the held connection first, a fresh one where it was lost meanwhile, and
//! a node that took longer said so in one sentence
//! (`deadline::not_answered`). The line is held on what the surface shares
//! (`Shared::line`), so a call made without the surface — a caller let go,
//! told to the node (`remote::relayed`) — is bounded alike.
use std::time::Instant;
use xcore::lock::Locked;

use crate::plane::call::REFUSED_CALL;
use crate::plane::deadline;
use crate::plane::line::Line;
use crate::plane::shared::Shared;

impl Shared {
    /// The call itself, for the caller the node's handle `caller` names
    /// where this side relays for one, waiting at most the surface's
    /// patience: its answer, or whether the node was lost and why — a node
    /// that took longer said so in one sentence (`deadline::not_answered`).
    pub(crate) fn called(
        &self,
        method: &str,
        message: &serde_json::Value,
        caller: Option<u64>,
    ) -> Result<serde_json::Value, (bool, String)> {
        let began = Instant::now();
        let patience = self.patience;
        self.deadline.arm(patience);
        let called = self.calling(method, message, caller, began);
        let fired = self.deadline.disarm();
        called.map_err(|(lost, why)| {
            if lost && (fired || began.elapsed() >= patience) {
                (true, deadline::not_answered(patience))
            } else {
                (lost, why)
            }
        })
    }

    fn calling(
        &self,
        method: &str,
        message: &serde_json::Value,
        caller: Option<u64>,
        began: Instant,
    ) -> Result<serde_json::Value, (bool, String)> {
        let patience = self.patience;
        let mut asking = self.line.locked();
        if let Some(line) = asking.as_mut() {
            match line.call(method, message, caller) {
                Ok(answer) => return Ok(answer),
                Err(why) if why.starts_with(REFUSED_CALL) => return Err((false, why)),
                // Silent for as long as a call waits: not tried again.
                Err(why) if began.elapsed() >= patience || self.deadline.passed() => {
                    *asking = None;
                    return Err((true, why));
                }
                // Lost since it last answered: a fresh connection is tried.
                Err(_) => *asking = None,
            }
        }
        let mut line = Line::open(&self.reach, patience, patience, self.ended(), &self.asking)
            .map_err(|why| (true, why))?;
        match line.call(method, message, caller) {
            Ok(answer) => {
                *asking = Some(line);
                Ok(answer)
            }
            Err(why) if why.starts_with(REFUSED_CALL) => {
                *asking = Some(line);
                Err((false, why))
            }
            Err(why) => Err((true, why)),
        }
    }
}
