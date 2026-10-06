//! The departure path: what a Host Service does with a Message that is going
//! somewhere.
//!
//! The mirror of [`crate::arrival`], and the same shape. A Stream arrives at a
//! Receive Location; a Message departs from a Send Location. Both are gated,
//! both are recorded, and the vocabulary is deliberately symmetric because an
//! operator watching an estate is reading one board.
//!
//! ```text
//! a Journey's destination   its Send Port: a Group's Journeys one per Port
//!   -> resolve   its Send Locations on this node, in configured order
//!   -> authorize may this identity still send, now
//!   -> identity  whose identity Xmip presents, per ADR-0006
//!   -> depart    through the Location's transport, built once
//! ```
//!
//! Authorization runs again here rather than being inherited from arrival.
//! Time has passed — a Process may have waited days for a human — and what was
//! true then is never a licence to act now.
//!
//! **One pass, never a wait.** [`depart_to`] tries the Port once on its
//! active Send Location and fails over at once where the Port says so; a
//! Location that may be tried again after its backoff is left waiting in
//! the [`Progress`] the send step keeps — the Journey's `attempts` in the
//! Ledger, so its count survives a restart — never slept on here
//! (`runtime-model.md` section 10: *A retry waiting for its backoff holds no
//! thread*). The Journey's identifier goes with every send, the key an
//! endpoint that deduplicates delivers it once by (section 15).
//!
//! **No attempt without the claim.** Before each Location is tried, the
//! send step is asked whether the Journey's claim is still surely this
//! node's; where it is not — found another's, or unconfirmed for longer
//! than its lease — the pass stops, and no Location is tried again from
//! here (section 10, *Corrected 2026-10-06*). A send already under way
//! goes on: its Journey's identifier lets the far end deduplicate it.

use authorize::{Action, Attempt, Decision, authorize};
use context::IdentityFacts;
use journey::Attempts;
use route::Subscriber;
use send::SendLevel;
use xcore::Purpose;

use crate::generation::ReceivedWork;
use crate::message_path::Runtime;
use crate::sending::{Destination, Port, Sending};

/// What became of one Message on its way out to one destination.
#[derive(Clone, Debug)]
pub enum Departed {
    Sent {
        to: Subscriber,
        /// Which artifact decided the identity presented, or `None` where
        /// nothing in the chain declared one.
        presented_from: Option<SendLevel>,
        /// The value of the identity the chain resolved to, as its Party
        /// holds it for sending (ADR-0006). The transport's `send` takes no
        /// identity, so a Location presents what its own settings give it;
        /// this records what the chain decided.
        presented: Option<String>,
    },
    /// Routing named a destination this node has no Send Location for.
    ///
    /// A Send Port bound to another node, or one no configuration gives a
    /// Location: the same class of mistake `never_satisfiable` catches on the
    /// receive side, found here at run time.
    NoSuchDestination { to: Subscriber },
    /// Routing matched a Work Process, and this runtime runs none yet: a
    /// Process is compiled at design time into a module a node loads
    /// (ADR-0066 clause 4).
    ProcessNotRun { to: Subscriber },
    /// Authorized to arrive, and not authorized to leave this way.
    ///
    /// The two are different questions and time may have passed between them.
    NotPermitted { to: Subscriber, decision: Decision },
    /// The transport tried and failed. `retryable` is the transport's answer,
    /// not the runtime's: only it knows whether a refused connection is a
    /// restart away from working.
    Failed {
        to: Subscriber,
        retryable: bool,
        detail: String,
    },
}

impl Departed {
    #[must_use]
    pub const fn sent(&self) -> bool {
        matches!(self, Self::Sent { .. })
    }
}

/// Where a Journey's send stands at its Send Port, across passes: what
/// the send step keeps between them, so a retry tries again where the last
/// pass left off. Its active Location and tries are the Journey's
/// `attempts`, written with every hand-on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// Sent: not tried again.
    pub sent: bool,
    /// The active Send Location, by its place in the Port's order.
    pub location: usize,
    /// How often the active Location has been tried.
    pub tries: u32,
    /// Every Location failed its tries: why, in words. Not tried again.
    pub given_up: Option<String>,
}

impl Progress {
    /// Where a Journey's `attempts` in the Ledger left its send.
    #[must_use]
    pub fn of(attempts: Attempts) -> Self {
        Self {
            location: attempts.location as usize,
            tries: attempts.tries,
            ..Self::default()
        }
    }

    /// The Journey's `attempts`, as this leaves them.
    #[must_use]
    pub fn attempts(&self) -> Attempts {
        Attempts {
            location: u32::try_from(self.location).unwrap_or(u32::MAX),
            tries: self.tries,
        }
    }

    /// Still to be tried, after its backoff.
    #[must_use]
    pub const fn waiting(&self) -> bool {
        !self.sent && self.given_up.is_none()
    }
}

/// One pass of a Message to `to`, its Send Port, unless it was sent or
/// given up already: tried once on its active Send Location, failing over
/// at once to the next where the Port's policy says `failover = "next"`,
/// `progress` keeping where it stands. The departures of this pass, one per
/// Location tried, each carrying the Journey's identifier as its
/// deduplication key. A Location that may be tried again is left waiting,
/// its backoff the send step's to keep. A Send Port Group is sent as one
/// Journey per Port, opened at its Publication, so one that reaches here is
/// declared by no Application of this node. `owned` says, before each
/// Location is tried, whether the Journey is still this node's to send; the
/// pass stops where it is not, nothing more tried.
pub fn depart_to(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    to: &Subscriber,
    (progress, owned): (&mut Progress, &dyn Fn() -> bool),
) -> Vec<Departed> {
    if !progress.waiting() {
        return Vec::new();
    }
    match (to, runtime.sends.to(to)) {
        (Subscriber::SendPort(_), Destination::Ports(ports)) => ports
            .first()
            .map(|port| depart_port(runtime, (work, facts), port, (progress, owned)))
            .unwrap_or_default(),
        (_, Destination::Process) => vec![Departed::ProcessNotRun { to: to.clone() }],
        _ => {
            progress.given_up = Some(format!(
                "no Send Port Group {} is declared on this node",
                to.name()
            ));
            vec![Departed::NoSuchDestination { to: to.clone() }]
        }
    }
}

/// One Port's part of a pass: its active Location tried, and the next
/// after it where it fails over — each only while `owned` says the Journey
/// is still this node's.
fn depart_port(
    runtime: &Runtime<'_>,
    (work, facts): (&ReceivedWork, &IdentityFacts),
    port: &Port<'_>,
    (standing, owned): (&mut Progress, &dyn Fn() -> bool),
) -> Vec<Departed> {
    let to = Subscriber::SendPort(port.name.to_string());
    let mut departed = Vec::new();
    loop {
        if !owned() {
            return departed;
        }
        let Some(sending) = port.locations.get(standing.location) else {
            standing.given_up = Some(format!("no Send Location for {to} on this node"));
            departed.push(Departed::NoSuchDestination { to });
            return departed;
        };
        let one = depart_one(runtime, work, facts, to.clone(), sending);
        standing.tries += 1;
        let again = match &one {
            Departed::Sent { .. } => {
                standing.sent = true;
                departed.push(one);
                return departed;
            }
            Departed::Failed { retryable, .. } => *retryable,
            _ => false,
        };
        let said = said(std::slice::from_ref(&one));
        departed.push(one);
        if again && standing.tries < port.tries() {
            return departed;
        }
        if port.fails_over() && standing.location + 1 < port.locations.len() {
            standing.location += 1;
            standing.tries = 0;
            continue;
        }
        standing.given_up = Some(said);
        return departed;
    }
}

fn depart_one(
    runtime: &Runtime<'_>,
    work: &ReceivedWork,
    facts: &IdentityFacts,
    to: Subscriber,
    sending: &Sending,
) -> Departed {
    let location = &sending.configured;

    // Authorized again, now, against the clock. What receive concluded may be
    // days old by the time a Process finished waiting for a human.
    let permitted = authorize(
        runtime.policies,
        facts,
        &Attempt::new(Action::Send, &location.name).at(runtime.clock.unix_timestamp_nanos()),
        context::OnMisalignment::Accept,
    );

    if !permitted.allowed() {
        return Departed::NotPermitted {
            to,
            decision: permitted,
        };
    }

    // ADR-0006. The first identity found walking Location, Port, Group,
    // Sending Process is the one presented — resolved independently of
    // whatever identity the Message arrived under, because the target only
    // cares which identity Xmip presents.
    let resolved = sending.chain.resolve();
    let party = resolved.and_then(|(party_id, _)| runtime.directory.party(party_id));
    let presented = party.as_ref().and_then(|party| {
        party
            .configured_for(Purpose::Send)
            .next()
            .map(|identity| identity.value.clone())
    });

    // Read whole from the Ledger here, where a transport's send takes it
    // whole; a send that streams reads it a chunk at a time
    // (`runtime-model.md` section 10).
    let bytes = match work.message.sections()[0].stream.load() {
        Ok(bytes) => bytes,
        Err(unread) => {
            return Departed::Failed {
                to,
                retryable: true,
                detail: unread.to_string(),
            };
        }
    };

    let key = work.journey.journey_id().to_string();
    match sending.transport.send_keyed(&location.address, bytes, &key) {
        Ok(()) => Departed::Sent {
            to,
            presented_from: resolved.map(|(_, level)| level),
            presented,
        },
        Err(failure) => Departed::Failed {
            to,
            retryable: failure.retryable,
            detail: failure.message,
        },
    }
}

/// What departures came to, in words, as a Journey records it.
#[must_use]
pub fn said(departed: &[Departed]) -> String {
    if departed.is_empty() {
        return "nowhere to go".to_string();
    }
    departed
        .iter()
        .map(|one| match one {
            Departed::Sent { to, .. } => format!("sent to {to}"),
            Departed::NoSuchDestination { to } => format!("no Send Location for {to}"),
            Departed::ProcessNotRun { to } => format!("{to} is run by no runtime yet"),
            Departed::NotPermitted { to, decision } => format!("not permitted to {to}: {decision}"),
            Departed::Failed { to, detail, .. } => format!("not sent to {to}: {detail}"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}
