//! What became of one arrival: refused at a gate, routed, or wanted by nobody.
//!
//! Separate from [`crate::arrival`], which is the lifecycle that produces one
//! of these. The outcome is read by callers that never run the lifecycle —
//! reporting, the ToDo, anything asking what happened — and they have no
//! business compiling the gates to find out.
//!
//! **A refusal is the whole record.** ADR-0013 puts a Journey's beginning after
//! Validation, so before that there is nothing to suspend, resume or dismiss.

use std::fmt;

use authenticate::Refusal;
use authorize::Decision;
use context::IdentityFacts;
use route::Routing;

use crate::generation::ReceivedWork;

/// Why a Stream never became a Journey.
#[derive(Clone, Debug)]
pub enum Refused {
    /// The arrival carried something this mechanism recognises and could not
    /// read — a malformed certificate, a truncated envelope.
    ///
    /// Distinct from carrying nothing, which is ordinary and reaches the
    /// circumstance instead.
    Identification(String),
    /// The credential was not accepted, or not accepted here.
    Authentication(Refusal),
    /// Verified, and not permitted to post here.
    Authorization(Decision),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identification(detail) => write!(f, "{detail}"),
            Self::Authentication(refusal) => write!(f, "{refusal}"),
            Self::Authorization(decision) => write!(f, "{decision}"),
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
    /// and why. Kept under retention so the question can be answered later.
    Unroutable {
        work: ReceivedWork,
        facts: IdentityFacts,
        routing: Routing,
    },
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
            Self::Refused { .. } => None,
        }
    }
}
