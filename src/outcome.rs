//! What became of one arrival: refused at a gate, routed, or wanted by nobody;
//! and a running node's count of them ([`Outcomes`]).
//!
//! Separate from [`crate::arrival`], which is the lifecycle that produces one
//! of these. The outcome is read by callers that never run the lifecycle —
//! reporting, the Ledger, anything asking what happened — and they have no
//! business compiling the gates to find out.
//!
//! **A refusal is the whole record.** ADR-0013 puts a Journey's beginning after
//! Validation, so before that there is nothing to suspend, resume or dismiss.
//!
//! This is a definition and not a lifecycle, so ADR-0058's test would send it
//! to Foundation — and it stays here deliberately. `Arrived` quotes three
//! Capabilities' verdicts at once (`authenticate::Refusal`,
//! `authorize::Decision`, `route::Routing`), and a Foundation crate depends
//! only on Foundation. `xmip-core-context` cannot hold it without a cycle,
//! since all three already depend on context; `xmip-core-journey` could, and
//! only by inverting the estate's direction. So it lives in the crate that
//! already composes the three, which is ADR-0044's rule read upward.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::generation::ReceivedWork;
use crate::message_path::Carried;
use authenticate::Refusal;
use authorize::Decision;
use context::IdentityFacts;
use identify::Presented;
use route::{Promoted, Routing, SourceError};

/// Why a Stream never became a Journey.
#[derive(Clone, Debug)]
pub enum Refused {
    /// The arrival carried something this mechanism recognises and could not
    /// read — a malformed certificate, a truncated envelope.
    ///
    /// Distinct from carrying nothing, which is ordinary and reaches the
    /// circumstance instead.
    Identification(String),
    /// The credential was not accepted, or not accepted here: why, and the
    /// claim the gate was handed, with its layer and how it was established
    /// (ADR-0019 clauses 5 and 8), so the refused attempt is audited as the
    /// transport event ADR-0013 clause 1 makes it. Its proof never leaves
    /// the gate: what is kept of it is its mechanism, value and provenance.
    Authentication(Refusal, Box<Presented>),
    /// Verified, and not permitted to post here.
    Authorization(Decision),
    /// Verified and permitted, and a property a Subscription's filter names
    /// cannot be read: bytes where text is compared, or a prefix no loaded
    /// route technology provides (ADR-0046, amended 2026-09-24).
    Promotion(SourceError),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identification(detail) => write!(f, "{detail}"),
            Self::Authentication(refusal, _) => write!(f, "{refusal}"),
            Self::Authorization(decision) => write!(f, "{decision}"),
            Self::Promotion(error) => write!(f, "{error}"),
        }
    }
}

/// What became of one arrival.
#[derive(Clone, Debug)]
pub enum Arrived {
    /// Refused at a gate.
    ///
    /// **No Journey exists.** A Journey does not start until the Stream has
    /// been identified, authenticated *and* authorized — ADR-0013 puts its
    /// beginning after Validation, so before that there is nothing to suspend,
    /// resume or dismiss. The refusal is the whole record.
    Refused { reason: Refused },

    /// Authenticated, published, and at least one Subscription wanted it.
    Routed {
        work: ReceivedWork,
        facts: IdentityFacts,
        routing: Routing,
    },

    /// Authenticated, published, and nobody wanted it.
    ///
    /// A disposition rather than a failure: the Stream was valid, it passed its
    /// gates, and no Subscription matched. That is a statement about
    /// configuration, and `routing.declines()` says which Subscription passed
    /// and why. Kept in the node's Dead Message Queue with `promoted`, what
    /// routing read, so the question can be answered later and the Message
    /// replayed once a Subscription is added or fixed.
    Unroutable {
        work: ReceivedWork,
        facts: IdentityFacts,
        routing: Routing,
        promoted: Promoted,
    },

    /// Permitted, and not kept: Xmip Storage did not take the Stream, the
    /// Message or its Journeys, or the Stream could not be read. The
    /// receive cycle did not finish, so the sender is not acknowledged and
    /// may send again; what was written before the failure is a Stream no
    /// Message refers to (`runtime-model.md` section 5).
    Failed { reason: String },
}

impl Arrived {
    /// Whether Xmip must keep this because nothing took it.
    #[must_use]
    pub const fn retains(&self) -> bool {
        matches!(self, Self::Unroutable { .. })
    }

    #[must_use]
    pub const fn routing(&self) -> Option<&Routing> {
        match self {
            Self::Routed { routing, .. } | Self::Unroutable { routing, .. } => Some(routing),
            Self::Refused { .. } | Self::Failed { .. } => None,
        }
    }
}

/// What became of every Stream a running node took, counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcomes {
    /// Streams taken off a Receive Location.
    pub received: u64,
    /// Published, and at least one Subscription wanted it.
    pub routed: u64,
    /// Published, and nobody wanted it.
    pub unroutable: u64,
    /// Matches a paused Subscription held rather than picked up.
    pub held: u64,
    /// Refused at a gate before a Journey opened.
    pub refused: u64,
    /// Permitted, and not kept: Xmip Storage did not take it, so it was
    /// not acknowledged.
    pub failed: u64,
    /// Journeys the send step sent: written Completed.
    pub sent: u64,
    /// Journeys whose every Send Location failed its tries, not permitted
    /// or with nowhere to go: written Failed with why.
    pub not_sent: u64,
}

/// The counts a running node keeps as each Stream is carried, and why any
/// Receive Location stopped.
#[derive(Default)]
pub(crate) struct Tally {
    received: AtomicU64,
    routed: AtomicU64,
    unroutable: AtomicU64,
    held: AtomicU64,
    refused: AtomicU64,
    failed: AtomicU64,
    sent: AtomicU64,
    not_sent: AtomicU64,
    failures: Mutex<Vec<(String, String)>>,
}

impl Tally {
    /// Count what became of one Stream.
    pub(crate) fn record(&self, carried: &Carried) {
        let count = |counter: &AtomicU64| {
            counter.fetch_add(1, Ordering::Relaxed);
        };
        count(&self.received);
        count(match carried.arrived {
            Arrived::Routed { .. } => &self.routed,
            Arrived::Unroutable { .. } => &self.unroutable,
            Arrived::Refused { .. } => &self.refused,
            Arrived::Failed { .. } => &self.failed,
        });
        self.held.fetch_add(carried.held as u64, Ordering::Relaxed);
    }

    /// Count a Journey the send step wrote Completed.
    pub(crate) fn sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a Journey the send step wrote Failed.
    pub(crate) fn not_sent(&self) {
        self.not_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// `location` stopped serving, and why.
    pub(crate) fn fail(&self, location: &str, why: String) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((location.to_string(), why));
    }

    /// Every Location that stopped, with its reason.
    pub(crate) fn failures(&self) -> Vec<(String, String)> {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn outcomes(&self) -> Outcomes {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Outcomes {
            received: read(&self.received),
            routed: read(&self.routed),
            unroutable: read(&self.unroutable),
            held: read(&self.held),
            refused: read(&self.refused),
            failed: read(&self.failed),
            sent: read(&self.sent),
            not_sent: read(&self.not_sent),
        }
    }
}
