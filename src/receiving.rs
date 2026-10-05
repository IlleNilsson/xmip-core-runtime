//! A Receive Location as a node runs it: its configuration, the gate it
//! holds and the transport built for it once, and the loop that takes what
//! arrives there and carries it, on the Location's pool of threads, through
//! the whole message path until the node stops.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::Scope;

use authenticate::{Acceptance, Authenticator};
use configure::ConfiguredLocation;
use receive::{IdentityPolicy, ReceivedStream};
use transport::{Acknowledgement, Refusal, Transport, Verdict};
use xaudit::program_audit::ProgramAudit;

use crate::message_path::{Carried, ReceiveCycle, Runtime, carry};

mod turn;

use crate::outcome::{Arrived, Refused};
use crate::pickup::Pickup;
use crate::pool::{Limits, Pool};
use turn::{Ticket, Turn};

/// What arrival asks of the Receive Location a Stream came in at: its name,
/// the closed set of mechanisms it accepts (ADR-0019 clause 1) and what it
/// does when the two identity layers disagree (clause 7). Read from the
/// Location's configuration once, as the node starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveGate {
    /// The Location's name, what an authorization attempt names.
    pub location: String,
    pub accept: Acceptance,
    pub identity: IdentityPolicy,
}

impl ReceiveGate {
    /// The gate `configured` declares, each accepted mechanism taken from the
    /// authenticator that verifies it.
    ///
    /// # Errors
    /// Every accepted mechanism no authenticator in `authenticators`
    /// verifies, one sentence each: a Location that accepts what nothing can
    /// verify is refused as the node starts, not at its first Stream.
    pub fn of(
        configured: &ConfiguredLocation,
        authenticators: &[&dyn Authenticator],
    ) -> Result<Self, Vec<String>> {
        let mut accept = Acceptance::closed();
        let mut problems = Vec::new();

        for name in &configured.accept.mechanism {
            match authenticators
                .iter()
                .map(|authenticator| authenticator.mechanism())
                .find(|mechanism| mechanism.name() == name)
            {
                Some(mechanism) => accept = accept.accepting(&mechanism),
                None => problems.push(format!(
                    "the Receive Location '{}' accepts '{name}', and no authenticator this \
                     node was built with verifies it",
                    configured.name
                )),
            }
        }

        if problems.is_empty() {
            Ok(Self {
                location: configured.name.clone(),
                accept,
                identity: IdentityPolicy::default(),
            })
        } else {
            Err(problems)
        }
    }

    /// A gate named `location` accepting `accept`, with the default identity
    /// policy.
    #[must_use]
    pub fn new(location: &str, accept: Acceptance) -> Self {
        Self {
            location: location.to_string(),
            accept,
            identity: IdentityPolicy::default(),
        }
    }
}

/// A Receive Location running: its configuration, its gate, and the
/// transport built for it once, which keeps its listener or session between
/// receives (`transport::kept`, `transport::serving`, `transport::pool`).
pub struct Receiving {
    pub configured: ConfiguredLocation,
    pub gate: ReceiveGate,
    pub transport: Box<dyn Transport + Send + Sync>,
    /// Its pool's bounds, from the node's `[tuning]`
    /// (`crate::tuning::Tuning::receive`).
    pub limits: Limits,
    /// Where it audits what its far end could not be told
    /// ([`Receiving::serve`]).
    pub audit: Option<ProgramAudit>,
}

impl Receiving {
    /// Take what arrives, and carry each Stream through the message path,
    /// until `stopping` is raised. `each` is told what became of every one.
    ///
    /// The loop asks the transport again after a receive that found nothing
    /// or failed in a way saying again may mend (a technology's wait running
    /// out is one), and looks at `stopping` between receives: a node stops
    /// once each Location's current receive returns, which the technology's
    /// own wait bounds. What arrived before that is carried whole.
    ///
    /// **Each arrival is carried on a thread of the Location's pool**
    /// (`runtime-model.md` section 3, *Threads, pools and chunks*; section
    /// 5, *How a receive runs*): one thread carries one arrival through the
    /// whole receive cycle and gives its far end the verdict, one to one
    /// with how the cycle ended ([`verdict`]) — accepted, refused for good,
    /// or failed so the far end sends it again. The pool is the Location's,
    /// within its [`Receiving::limits`], and its threads are in `scope`.
    ///
    /// **What the transport declares decides the order**
    /// (`transport::Arrivals`). Ordered arrivals — a cursor, a queue
    /// settled in order, a poll that reads again what is not yet told —
    /// are told in the order they came, every one before the transport is
    /// asked again. Unordered ones — each connection, request or datagram
    /// its own — are not waited on: the transport is asked again at once,
    /// and they are carried side by side up to the pool's most, so two
    /// senders never wait on each other and their Ledger writes share a
    /// disk sync. What is still being carried when the node stops is
    /// carried to its end and told.
    ///
    /// **A telling that failed in a way asking again may mend** — the far
    /// end not told now, what it sent kept for it to send again — does not
    /// stop the Location, and is audited, once for each reason, with the
    /// Location and why, so it is never dropped unseen.
    ///
    /// # Errors
    /// The transport failed in a way asking again will not mend — in a
    /// receive, or in telling the far end a verdict: the Location stops,
    /// and says why.
    pub fn serve<'scope, 'env>(
        &'env self,
        scope: &'scope Scope<'scope, 'env>,
        runtime: &'env Runtime<'env>,
        pickup: &'env Pickup,
        stopping: &AtomicBool,
        mut each: impl FnMut(&Carried),
    ) -> Result<(), String> {
        let limits = self.limits;
        let pool = Pool::new(scope, limits);
        // Ordered: nothing may be carrying when the transport is asked
        // again. Unordered: up to one less than the pool's most, so the
        // next receive's arrival has a thread.
        let room = if self.transport.arrivals().ordered() {
            0
        } else {
            limits.most.max(1) - 1
        };
        let (tell, told) = mpsc::channel();
        let mut carrying = Carrying {
            node: runtime.send.node(),
            count: 0,
            heard: BTreeSet::new(),
        };
        let mut ended = Ok(());
        while ended.is_ok() && !stopping.load(Ordering::Acquire) {
            // What is told already is settled now, so what became of an
            // arrival is counted as it ends, not once the pool is full.
            while ended.is_ok() && carrying.count > 0 {
                match told.try_recv() {
                    Ok(one) => ended = self.settled(&mut each, one, &mut carrying),
                    Err(_) => break,
                }
            }
            while ended.is_ok() && carrying.count > room {
                ended = self.settle(&mut each, &told, &mut carrying);
            }
            if ended.is_err() {
                break;
            }
            match self.transport.receive() {
                Ok(arrivals) => {
                    carrying.count += arrivals.len();
                    self.carry_all(&pool, runtime, pickup, arrivals, room == 0, &tell);
                }
                Err(failure) if failure.retryable => {}
                Err(failure) => ended = Err(self.stopped(&failure.message)),
            }
        }
        while carrying.count > 0 {
            let settled = self.settle(&mut each, &told, &mut carrying);
            if ended.is_ok() {
                ended = settled;
            }
        }
        ended
    }

    /// Wait for one arrival to be carried and told, hand it to `each`, and
    /// say whether the Location goes on: a telling that failed in a way
    /// saying again will not mend stops it; one that may mend leaves the
    /// far end to deliver it again — at-least-once, never a loss.
    fn settle(
        &self,
        each: &mut impl FnMut(&Carried),
        told: &mpsc::Receiver<(Carried, transport::Result<()>)>,
        carrying: &mut Carrying<'_>,
    ) -> Result<(), String> {
        let Ok(one) = told.recv() else {
            carrying.count = 0;
            return Err(self.stopped("a carrying thread ended without telling"));
        };
        self.settled(each, one, carrying)
    }

    /// One arrival carried and told, `one`, handed to `each`; whether the
    /// Location goes on, as [`Receiving::settle`] says.
    fn settled(
        &self,
        each: &mut impl FnMut(&Carried),
        (carried, telling): (Carried, transport::Result<()>),
        carrying: &mut Carrying<'_>,
    ) -> Result<(), String> {
        carrying.count -= 1;
        each(&carried);
        match telling {
            Err(failure) if !failure.retryable => Err(self.stopped(&failure.message)),
            Err(failure) => {
                self.not_told(carrying, &failure.message);
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    /// A telling that may mend, audited the first time its reason is heard
    /// on this Location's serve.
    fn not_told(&self, carrying: &mut Carrying<'_>, why: &str) {
        if !carrying.heard.insert(why.to_string()) {
            return;
        }
        if let Some(audit) = &self.audit {
            let _ = audit.failed(
                "receive",
                &format!(
                    "{}: the Receive Location '{}' could not tell its far end, which sends it \
                     again: {why}",
                    carrying.node, self.configured.name
                ),
            );
        }
    }

    /// Every one of `arrivals` carried on `pool` and its far end told —
    /// in the order they came where `in_order` says so — each reported on
    /// `tell` once told.
    fn carry_all<'env>(
        &'env self,
        pool: &Pool<'_, 'env>,
        runtime: &'env Runtime<'env>,
        pickup: &'env Pickup,
        arrivals: Vec<transport::Arrived>,
        in_order: bool,
        tell: &mpsc::Sender<(Carried, transport::Result<()>)>,
    ) {
        let turn = Arc::new(Turn::default());
        for (place, arrived) in arrivals.into_iter().enumerate() {
            let ticket = in_order.then(|| Ticket {
                turn: Arc::clone(&turn),
                place,
                passed: false,
            });
            let tell = tell.clone();
            pool.run(Box::new(move || {
                let (origin_uri, body, acknowledgement) = arrived.into_parts();
                let telling = Telling {
                    tell: Some(tell),
                    ticket,
                    acknowledgement: Some(acknowledgement),
                };
                let received = ReceivedStream::new(body, origin_uri);
                telling.told(carry(runtime, pickup, &self.gate, received));
            }));
        }
    }

    fn stopped(&self, why: &str) -> String {
        format!(
            "the Receive Location '{}' stopped: {why}",
            self.configured.name
        )
    }
}

/// What a Location's serve has carrying: its node, how many arrivals are
/// not yet told, and every reason a telling that may mend was heard for —
/// each audited once.
struct Carrying<'a> {
    node: &'a str,
    count: usize,
    heard: BTreeSet<String>,
}

/// One arrival's far end and the Location's settling, told once however
/// its carry ends. Carried to its end, it tells the cycle's verdict. A
/// carry that panicked tells it on the way out: the far end hears
/// [`Verdict::Failed`] and keeps the Stream to send again, and the
/// Location settles the arrival as failed — never left waiting for a
/// telling that will not come, which held its receives and its node's
/// stop for good until 2026-10-03.
struct Telling {
    tell: Option<mpsc::Sender<(Carried, transport::Result<()>)>>,
    ticket: Option<Ticket>,
    acknowledgement: Option<Acknowledgement>,
}

impl Telling {
    /// The cycle `carried` ended, its far end told and its settling sent.
    fn told(mut self, carried: Carried) {
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

/// What the far end is told of a receive cycle, one to one: a completed
/// cycle is accepted; a refused one is refused for good, with why — an
/// unknown sender, one not permitted, content refused — for a protocol
/// whose rejection differs by cause; a failed one failed, so the far end
/// sends it again.
const fn verdict(carried: &Carried) -> Verdict {
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
            reason: Refused::Identification(_) | Refused::Authentication(_),
        } => Refusal::Unidentified,
        Arrived::Refused {
            reason: Refused::Authorization(_),
        } => Refusal::Forbidden,
        _ => Refusal::Unacceptable,
    }
}
