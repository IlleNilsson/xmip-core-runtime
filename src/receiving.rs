//! A Receive Location as a node runs it: its configuration, the gate it
//! holds and the transport built for it once, and the loop that takes what
//! arrives there and carries it, on the Location's pool of threads, through
//! the whole message path until the node stops.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::Scope;
use std::time::Instant;

use authenticate::{Acceptance, Authenticator};
use configure::{ConfiguredLocation, PartyConfiguration};
use receive::IdentityPolicy;
use transport::Transport;
use xaudit::program_audit::ProgramAudit;

use crate::message_path::{Carried, Runtime, carry};

mod drain;
mod pace;
mod received;
mod refusal;
mod telling;
mod turn;

pub use drain::RECEIVE_DRAIN;
pub use pace::{Pace, RECEIVE_BACKOFF, RECEIVE_POLL};

use crate::budget::Held;
use crate::pickup::Pickup;
use crate::pool::{Limits, Pool};
use crate::stopping::Stopping;
use drain::Drain;
use pace::Ended;
use telling::Telling;
use turn::{Ticket, Turn};

/// What arrival asks of the Receive Location a Stream came in at: its name,
/// the closed set of mechanisms and Parties it accepts (ADR-0019 clause 1)
/// and what it does when the two identity layers disagree (clause 7). Read
/// from the Location's configuration once, as the node starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveGate {
    /// The Location's name, what an authorization attempt names.
    pub location: String,
    pub accept: Acceptance,
    pub identity: IdentityPolicy,
}

impl ReceiveGate {
    /// The gate `configured` declares, each accepted mechanism taken from the
    /// authenticator that verifies it, and each accepted Party by the
    /// identifier the node knows it by among `parties`.
    ///
    /// # Errors
    /// Every accepted mechanism no authenticator in `authenticators`
    /// verifies, and every accepted Party `parties` does not declare, one
    /// sentence each: a Location that accepts what nothing can verify, or
    /// whom nobody is, is refused as the node starts, not at its first
    /// Stream.
    pub fn of(
        configured: &ConfiguredLocation,
        authenticators: &[&dyn Authenticator],
        parties: &[PartyConfiguration],
    ) -> Result<Self, Vec<String>> {
        let mut accept = Acceptance::closed();
        let mut problems = configure::party::accepted_problems(parties, configured);
        for party in configured
            .accept
            .party
            .iter()
            .filter_map(|name| configure::party::named(parties, name))
        {
            accept = accept.from_party(party);
        }

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
    /// How long it rests before it asks a polled transport again, from the
    /// node's `[tuning]` (`crate::tuning::Tuning::pace`).
    pub pace: Pace,
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
    /// own wait bounds. What arrived before that is carried whole. A
    /// Location whose receive waits and whose far end let go of what it
    /// handed over — raw TCP, a datagram — drains first: it goes on
    /// receiving until a receive finds nothing, never past its pace's
    /// `drain` from the stop, so a connection queued in its listener's
    /// backlog before the stop is taken, not closed away (`drain.rs`).
    ///
    /// **What the transport declares decides how soon it is asked again**
    /// (`transport::Waiting`, [`Pace`]). One whose receive waits for what
    /// arrives is asked again at once, so an arrival is taken the moment it
    /// lands. One whose receive looks and returns at once — a directory
    /// listed, a query run — rests its poll interval after a receive that
    /// found nothing, and its backoff after one that failed in a way asking
    /// again may mend, each measured from when that receive began, so an
    /// idle Location never spins. The rest is waited on `stopping`, which
    /// ends it the moment the node stops.
    ///
    /// **Each arrival is carried on a thread of the Location's pool**
    /// (`runtime-model.md` section 3, *Threads, pools and chunks*; section
    /// 5, *How a receive runs*): one thread carries one arrival through the
    /// whole receive cycle and gives its far end the verdict, one to one
    /// with how the cycle ended (`refusal::verdict`) — accepted, refused for good,
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
    /// **No more is taken than there is room for** (open problem 38,
    /// 2026-10-19). A receive asks its transport for at most as many
    /// arrivals as the Location's pool has threads free and the node's carry
    /// budget has places (`crate::budget`), waiting for a place where the
    /// node has none; what it does not take stays at its far end — a file
    /// unclaimed in its directory, a message on its broker. Each carry holds
    /// its place until it is told, and the bytes a carry holds from the
    /// node's byte budget while it carries. Until then a receive took every
    /// arrival the transport handed over, and queued what the pool had no
    /// thread for.
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
        stopping: &Stopping,
        mut each: impl FnMut(&Carried),
    ) -> Result<(), String> {
        let limits = self.limits;
        let pool = Pool::new(scope, limits);
        // Ordered: nothing may be carrying when the transport is asked
        // again. Unordered: up to one less than the pool's most, so the
        // next receive's arrival has a thread.
        let ordered = self.transport.arrivals().ordered();
        let busy = if ordered { 0 } else { limits.most.max(1) - 1 };
        let polled = self.transport.waiting().polled();
        let (tell, told) = mpsc::channel();
        let mut carrying = Carrying {
            node: runtime.send.node(),
            count: 0,
            heard: BTreeSet::new(),
        };
        let mut ended = Ok(());
        let mut drain = Drain::new(!polled, self.pace.drain);
        while ended.is_ok() && drain.asks(stopping) {
            // What is told already is settled now, so what became of an
            // arrival is counted as it ends, not once the pool is full.
            while ended.is_ok() && carrying.count > 0 {
                match told.try_recv() {
                    Ok(one) => ended = self.settled(&mut each, one, &mut carrying),
                    Err(_) => break,
                }
            }
            while ended.is_ok() && carrying.count > busy {
                ended = self.settle(&mut each, &told, &mut carrying);
            }
            if ended.is_err() {
                break;
            }
            // No more arrivals are taken than this Location's pool and the
            // node's carry budget both have room for; the rest stay at the
            // far end. With none at the node, this waits for a carry to end.
            let room = limits.most.max(1) - carrying.count;
            let places = runtime.budget.carries.hold_up_to(room as u64);
            let began = Instant::now();
            let most = usize::try_from(places.charge()).unwrap_or(1);
            let outcome = match self.transport.receive_up_to(most) {
                Ok(arrivals) if arrivals.is_empty() => Ended::Nothing,
                Ok(arrivals) => {
                    drain.handed(arrivals.iter().any(|arrived| !arrived.defers()));
                    carrying.count += arrivals.len();
                    let carried = (arrivals, places, ordered);
                    self.carry_all(&pool, runtime, pickup, carried, &tell);
                    Ended::Found
                }
                Err(failure) if failure.retryable => Ended::Mendable,
                Err(failure) => {
                    ended = Err(self.stopped(&failure.message));
                    break;
                }
            };
            drain.received(outcome);
            let _ = stopping.wait(self.pace.rest(polled, outcome, began.elapsed()));
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
    /// `tell` once told. Each holds one of the node's carry places, from
    /// `places`, until it is told, and the bytes a carry holds from the
    /// node's byte budget while it carries — let go of before its turn to
    /// tell, so an arrival waiting to tell never holds back one carrying.
    fn carry_all<'env>(
        &'env self,
        pool: &Pool<'_, 'env>,
        runtime: &'env Runtime<'env>,
        pickup: &'env Pickup,
        (arrivals, mut places, in_order): (Vec<transport::Arrived>, Held<'env>, bool),
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
            let held = places.split(1);
            pool.run(Box::new(move || {
                let (received, acknowledgement) = received::received(arrived);
                let telling = Telling {
                    tell: Some(tell),
                    ticket,
                    acknowledgement: Some(acknowledgement),
                };
                let bytes = runtime.budget.received.hold(runtime.budget.carry());
                let carried = carry(runtime, pickup, &self.gate, received);
                drop(bytes);
                self.audit_refused(&carried);
                telling.told(carried);
                drop(held);
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
