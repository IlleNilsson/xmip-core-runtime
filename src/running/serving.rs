//! Startup phase 9's second half: what the serving thread owns for the
//! node's life, the Runtime built once from it, every Receive Location
//! serving, the pickup, and the send step dispatching until they stop.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

use authenticate::Authenticator;
use authorize::Authorizer;
use identify::{MessageIdentifier, TransportIdentifier};
use message::MessageTreatment;
use route::Gathering;
use xaudit::origin::Origin;
use xcore::{SystemClock, UuidV7Generator};

use crate::held_work::pick_up_released;
use crate::linked::Linked;
use crate::message_path::{Parties, Runtime};
use crate::outcome::Tally;
use crate::pickup::Pickup;
use crate::receiving::Receiving;
use crate::send_step::{self, SendStep};
use crate::sending::Sends;

/// What the serving thread owns for the node's life.
pub(super) struct Served {
    pub(super) storage: Arc<dyn persist::storage::XmipStorage>,
    pub(super) chunk: usize,
    pub(super) origin: Origin,
    pub(super) linked: Linked,
    pub(super) gathering: Gathering,
    pub(super) subscriptions: Vec<route::Subscription>,
    pub(super) pickup: Arc<Pickup>,
    pub(super) send: Arc<SendStep>,
    pub(super) sends: Sends,
    pub(super) receiving: Vec<Receiving>,
}

/// Startup phase 9's second half: the Runtime built once, and every Receive
/// Location serving on a thread of its own until `stopping` is raised. What
/// the thread owns is let go when the last Location has stopped — listeners
/// closed, sessions ended.
pub(super) fn serve(
    served: Served,
    stopping: Arc<AtomicBool>,
    tally: Arc<Tally>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let Served {
            storage,
            chunk,
            origin,
            linked,
            gathering,
            subscriptions,
            pickup,
            sends,
            send,
            receiving,
        } = served;
        let authenticators: Vec<&dyn Authenticator> =
            linked.authenticators.iter().map(AsRef::as_ref).collect();
        let policies: Vec<&dyn Authorizer> = linked.policies.iter().map(AsRef::as_ref).collect();
        let transport_identifiers: Vec<&dyn TransportIdentifier> = linked
            .transport_identifiers
            .iter()
            .map(AsRef::as_ref)
            .collect();
        let message_identifiers: Vec<&dyn MessageIdentifier> = linked
            .message_identifiers
            .iter()
            .map(AsRef::as_ref)
            .collect();
        let parties = Parties::default();

        let runtime = Runtime {
            ids: &UuidV7Generator,
            authenticators: &authenticators,
            parties: &parties,
            directory: &parties,
            subscriptions: &subscriptions,
            gathering: &gathering,
            treatment: MessageTreatment::default(),
            sends: &sends,
            send: &send,
            transport_identifiers: &transport_identifiers,
            message_identifiers: &message_identifiers,
            policies: &policies,
            clock: &SystemClock,
            storage: &storage,
            chunk,
            origin: &origin,
        };

        // The send step dispatches until every Receive Location and the
        // pickup have stopped, so nothing they hand it is left unsent; then
        // it is closed, and what it has in flight is sent before the scope
        // ends.
        let counted = |_: &send_step::Departure, ended: &send_step::Ended| match ended {
            send_step::Ended::Completed(_) => tally.sent(),
            send_step::Ended::Failed { .. } => tally.not_sent(),
            _ => {}
        };
        std::thread::scope(|scope| {
            let (runtime, tally, counted) = (&runtime, &*tally, &counted);
            scope.spawn(move || send_step::dispatch(scope, runtime, counted));
            std::thread::scope(|serving| {
                for location in &receiving {
                    let (pickup, stopping) = (&*pickup, &*stopping);
                    serving.spawn(move || {
                        let served =
                            location.serve(serving, runtime, pickup, stopping, |carried| {
                                tally.record(carried);
                            });
                        if let Err(why) = served {
                            tally.fail(&location.configured.name, why);
                        }
                    });
                }
                let (pickup, stopping) = (&*pickup, &*stopping);
                serving.spawn(move || pick_up_released(runtime, pickup, stopping));
            });
            runtime.send.close();
        });
    })
}
