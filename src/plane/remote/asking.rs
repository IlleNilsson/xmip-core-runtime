//! One call on a surface's asking line, bounded by the surface's patience:
//! the held connection first, a fresh one where it was lost meanwhile, and
//! a node that took longer said so in one sentence
//! (`deadline::not_answered`).

use std::sync::PoisonError;
use std::time::Instant;

use crate::plane::call::REFUSED_CALL;
use crate::plane::deadline;
use crate::plane::line::Line;
use crate::plane::remote::Remote;

impl Remote {
    /// The call itself, waiting at most the surface's patience: its
    /// answer, or whether the node was lost and why — a node that took
    /// longer said so in one sentence (`deadline::not_answered`).
    pub(super) fn called(
        &self,
        method: &str,
        message: &serde_json::Value,
    ) -> Result<serde_json::Value, (bool, String)> {
        let began = Instant::now();
        let patience = self.shared.patience;
        self.shared.deadline.arm(patience);
        let called = self.calling(method, message, began);
        let fired = self.shared.deadline.disarm();
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
        began: Instant,
    ) -> Result<serde_json::Value, (bool, String)> {
        let patience = self.shared.patience;
        let mut asking = self.asking.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(line) = asking.as_mut() {
            match line.call(method, message) {
                Ok(answer) => return Ok(answer),
                Err(why) if why.starts_with(REFUSED_CALL) => return Err((false, why)),
                // Silent for as long as a call waits: not tried again.
                Err(why) if began.elapsed() >= patience || self.shared.deadline.passed() => {
                    *asking = None;
                    return Err((true, why));
                }
                // Lost since it last answered: a fresh connection is tried.
                Err(_) => *asking = None,
            }
        }
        let mut line = Line::open(
            &self.shared.reach,
            patience,
            patience,
            self.shared.ended(),
            &self.shared.asking,
        )
        .map_err(|why| (true, why))?;
        match line.call(method, message) {
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
