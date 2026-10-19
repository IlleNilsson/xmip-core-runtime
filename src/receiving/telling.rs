//! One arrival's far end and its Location's settling, told once however
//! its carry ends.

use std::sync::mpsc;

use transport::{Acknowledgement, Verdict};

use super::refusal::verdict;
use super::turn::Ticket;
use crate::message_path::Carried;
use crate::outcome::Arrived;

/// One arrival's far end and the Location's settling, told once however
/// its carry ends. Carried to its end, it tells the cycle's verdict. A
/// carry that panicked tells it on the way out: the far end hears
/// [`Verdict::Failed`] and keeps the Stream to send again, and the
/// Location settles the arrival as failed — never left waiting for a
/// telling that will not come, which held its receives and its node's
/// stop for good until 2026-10-03.
pub(super) struct Telling {
    pub(super) tell: Option<mpsc::Sender<(Carried, transport::Result<()>)>>,
    pub(super) ticket: Option<Ticket>,
    pub(super) acknowledgement: Option<Acknowledgement>,
}

impl Telling {
    /// The cycle `carried` ended, its far end told and its settling sent.
    pub(super) fn told(mut self, carried: Carried) {
        let told = self.acknowledge(verdict(&carried));
        if let Some(tell) = self.tell.take() {
            let _ = tell.send((carried, told));
        }
    }

    /// The far end told `verdict` in its turn, once: the acknowledgement is
    /// taken before it is given, so one that panics is not given again.
    fn acknowledge(&mut self, verdict: Verdict) -> transport::Result<()> {
        let Some(acknowledgement) = self.acknowledgement.take() else {
            return Ok(());
        };
        match self.ticket.take() {
            Some(ticket) => ticket.in_turn(|| acknowledgement.acknowledge(verdict)),
            None => acknowledgement.acknowledge(verdict),
        }
    }
}

impl Drop for Telling {
    fn drop(&mut self) {
        let Some(tell) = self.tell.take() else {
            return;
        };
        let told = self.acknowledge(Verdict::Failed);
        let reason = "its carrying thread panicked before the receive cycle ended";
        let carried = Carried {
            arrived: Arrived::Failed {
                reason: reason.to_string(),
            },
            held: 0,
            journeys: Vec::new(),
        };
        let _ = tell.send((carried, told));
    }
}
