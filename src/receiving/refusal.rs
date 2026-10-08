//! A refused arrival: what its far end is told, and the transport event its
//! attempt is audited as.
//!
//! ADR-0013 clause 1: a Stream refused at transport identification,
//! authentication or authorization keeps nothing, and *the attempt is audited
//! as a transport event*. What the record says of the sender is the claim
//! the gate was handed — its mechanism, value, layer and how it was
//! established (ADR-0019 clauses 5 and 8) — and never its proof.

use std::collections::BTreeMap;

use identify::Presented;
use transport::{Refusal, Verdict};
use xcore::{ExecutionPhase, Layer, Severity};

use super::Receiving;
use crate::message_path::{Carried, ReceiveCycle};
use crate::outcome::{Arrived, Refused};

/// What the far end is told of a receive cycle, one to one: a completed
/// cycle is accepted; a refused one is refused for good, with why — an
/// unknown sender, one not permitted, content refused — for a protocol
/// whose rejection differs by cause; a failed one failed, so the far end
/// sends it again.
pub(super) const fn verdict(carried: &Carried) -> Verdict {
    match carried.cycle() {
        ReceiveCycle::Completed => Verdict::Accepted,
        ReceiveCycle::Refused => Verdict::Refused(refusal(&carried.arrived)),
        ReceiveCycle::Failed => Verdict::Failed,
    }
}

/// Why a refused arrival was refused, as its far end is told.
const fn refusal(arrived: &Arrived) -> Refusal {
    match arrived {
        Arrived::Refused {
            reason: Refused::Identification(_) | Refused::Authentication(..),
        } => Refusal::Unidentified,
        Arrived::Refused {
            reason: Refused::Authorization(_),
        } => Refusal::Forbidden,
        _ => Refusal::Unacceptable,
    }
}

/// The audit's names for a claim on `layer`, the same words the Message
/// Context promotes an identity under (`crate::arrival`): `xmip.transport`
/// or `xmip.message`.
pub(crate) const fn layer_prefix(layer: Layer) -> &'static str {
    match layer {
        Layer::Transport => "xmip.transport",
        Layer::Message => "xmip.message",
    }
}

/// The properties a refused claim is audited with.
fn claimed(presented: &Presented) -> BTreeMap<String, String> {
    let prefix = layer_prefix(presented.layer());
    BTreeMap::from([
        (
            format!("{prefix}.mechanism"),
            presented.mechanism.name().to_string(),
        ),
        (format!("{prefix}.identity"), presented.value.clone()),
        (
            format!("{prefix}.established"),
            presented.established.to_string(),
        ),
    ])
}

impl Receiving {
    /// Audit `carried` where a gate refused it with a claim in hand: the
    /// Location, the reason and the claim (ADR-0013 clause 1).
    pub(super) fn audit_refused(&self, carried: &Carried) {
        let (Some(audit), Arrived::Refused { reason }) = (&self.audit, &carried.arrived) else {
            return;
        };
        let Refused::Authentication(_, presented) = reason else {
            return;
        };
        let mut properties = claimed(presented);
        properties.insert("location".to_string(), self.configured.name.clone());
        let _ = audit.record(
            "receive",
            ExecutionPhase::Finished,
            Severity::Warning,
            Some(&format!(
                "the Receive Location '{}' refused a Stream at authentication: {reason}",
                self.configured.name
            )),
            properties,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::mechanism;

    #[test]
    fn a_refused_claim_is_audited_under_its_layer_and_provenance() {
        let transport = claimed(&Presented::passed(mechanism::ip(), "127.0.0.1"));
        assert_eq!(
            transport
                .get("xmip.transport.mechanism")
                .map(String::as_str),
            Some("ip")
        );
        assert_eq!(
            transport
                .get("xmip.transport.established")
                .map(String::as_str),
            Some("passed")
        );
        let message = claimed(
            &Presented::detected(mechanism::edi_x12_interchange(), "ISA06=PARTYX")
                .with_proof("never", "kept"),
        );
        assert_eq!(
            message.get("xmip.message.identity").map(String::as_str),
            Some("ISA06=PARTYX")
        );
        assert!(message.values().all(|value| value != "kept"));
    }
}
