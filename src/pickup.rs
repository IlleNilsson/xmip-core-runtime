//! A running node's Subscriptions as an operator sees and pauses them, and
//! what a paused one holds (ADR-0013, amendment 2026-09-30;
//! `runtime-model.md` section 9).
//!
//! **What a pause holds is in the Ledger.** Every Journey a Publication
//! opens for a paused Subscription is held: the Publication's one write
//! keeps it at the end of the Subscription's queue ([`Holding`],
//! `persist::storage::Hold`), so a receive whose hold was not written is not
//! acknowledged, and nothing is held in memory. Its Message and its Stream
//! are in the Ledger from the receive. Nothing is lost and nothing is
//! deleted (ADR-0040).
//!
//! **A resume** lets the node pick up what is held, oldest first, in the
//! order Xmip Storage numbered it ([`Pickup::released`]): each is moved on,
//! in one hand-on, to the queue of the Send Port its Subscription leads to,
//! and sent from there by the send step as every Journey is
//! (`crate::held_work`, [`Pickup::moved`]). A queue that cannot be read is
//! read again from where it was, never past what was not read
//! ([`Pickup::again`]). While a Subscription's queue holds anything, what
//! it matches joins the end of it, so it is picked up in the order it
//! matched.
//!
//! **The pause is operator state** in the administration database — what is
//! paused, by whom, since when (`deployment-model.md` section 7) — written
//! by every act before the act is said to be done, and read back as the
//! node takes its Subscriptions up: one paused before a restart is paused
//! after it, holding what it held.
//!
//! **A Subscription is not removed here.** It is configuration: added and
//! removed in the TOML of the Xmip Application that draws it. Pause and
//! resume are the acts ([`observe::Noun::Subscription`]); a remove is
//! refused in words, and so is an act on a Subscription not configured.
//!
//! **The Dead Message Queue** of the node is read and replayed here too
//! (`replay`): a Replay routes a Message nothing matched against these
//! Subscriptions and holds what it opens in their queues.
//!
//! The one [`Pickup`] of each node in this process is registered, so the
//! runtime's library lists and acts on it (`xmip_operate.h` section 14).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use observe::{Act, Noun, Subscription as Published, now_unix_nanos};
use persist::storage::{AdministrationKind, AdministrationRecord, XmipStorage, named};
use xaudit::program_audit::ProgramAudit;
use xcore::{ExecutionPhase, Severity};

use crate::configured_subscription::ConfiguredSubscription;

mod holding;
mod released;
mod replay;
mod state;

pub use holding::Holding;
pub use released::Released;
pub use replay::PUBLISHED;
use state::{Entry, Standing, State};

/// How long a queue that could not be read waits before it is read again.
const AGAIN: Duration = Duration::from_millis(50);

/// A node's Subscriptions, their standing, and where it is in what they
/// hold.
pub struct Pickup {
    node: String,
    storage: Arc<dyn XmipStorage>,
    audit: Option<ProgramAudit>,
    state: Mutex<State>,
    wake: Condvar,
}

/// Every node's pickup in this process.
static REGISTERED: Mutex<Vec<Weak<Pickup>>> = Mutex::new(Vec::new());

/// The URI naming the Subscription `name` on the node at `node`, whose
/// name-based identifier its queue and its operator record are found by.
fn uri(node: &str, name: &str) -> String {
    format!("{node}/subscription/{name}")
}

impl Pickup {
    /// The Subscriptions of the node at `node` (`xmip:///<cluster>/node/<name>`),
    /// each with its standing and what it holds read back from `storage`,
    /// registered for the runtime's library. `audit` records every act.
    ///
    /// # Errors
    /// Xmip Storage could not be read: a standing that cannot be read back
    /// is a pause that could be lost, so the node does not start.
    pub fn open(
        node: &str,
        configured: Vec<ConfiguredSubscription>,
        storage: Arc<dyn XmipStorage>,
        audit: Option<ProgramAudit>,
    ) -> Result<Arc<Self>, String> {
        let now = now_unix_nanos();
        let mut entries = Vec::new();
        for configured in configured {
            let name = configured.name().to_string();
            let unread =
                |error: &dyn std::fmt::Display| format!("the Subscription '{name}': {error}");
            let queue = named(&uri(node, &name));
            let standing = match storage
                .read_administration(AdministrationKind::Operator, queue)
                .map_err(|error| unread(&error))?
            {
                Some(record) => Standing::from_record(&record.body).map_err(|e| unread(&e))?,
                None => Standing {
                    since_unix_nanos: now,
                    ..Standing::default()
                },
            };
            let held = storage
                .read_held(queue, 0, 0)
                .map_err(|error| unread(&error))?
                .count;
            entries.push(Entry {
                configured,
                queue,
                pending: held > 0,
                standing,
                held,
                picked_up: 0,
                cursor: 0,
                taken: BTreeSet::new(),
                not_before: None,
            });
        }
        let pickup = Arc::new(Self {
            node: node.to_string(),
            storage,
            audit,
            state: Mutex::new(State { entries }),
            wake: Condvar::new(),
        });
        let mut registered = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
        registered.retain(|held| held.strong_count() > 0);
        registered.push(Arc::downgrade(&pickup));
        Ok(pickup)
    }

    /// Every node's pickup this process holds.
    #[must_use]
    pub fn registered() -> Vec<Arc<Self>> {
        REGISTERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    /// The node whose Subscriptions these are.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Pause or resume the Subscription called `name`, by `who`, and say
    /// what came of it once its standing is written. Audited.
    ///
    /// # Errors
    /// REFUSED, in words, for an act a Subscription does not take — remove
    /// among them: a Subscription is removed in the TOML configuration — and
    /// for a Subscription this node is not configured with; FAILED where
    /// Xmip Storage did not take its standing, and nothing changed.
    pub fn act(&self, name: &str, act: Act, who: &str) -> Result<String, String> {
        let act = Noun::Subscription.act(act.word())?;
        let mut state = self.lock();
        let Some(index) = state.index(name) else {
            return Err(format!(
                "REFUSED: no Subscription '{name}' is configured on {}; a Subscription is \
                 added and removed in the TOML configuration of the Xmip Application that \
                 draws it",
                self.node
            ));
        };
        let entry = &state.entries[index];
        let held = entry.held;
        let pause = match act {
            Act::Pause if entry.standing.paused => {
                return Ok(format!("Subscription '{name}' was already paused"));
            }
            Act::Resume if !entry.standing.paused => {
                return Ok(format!("Subscription '{name}' was not paused"));
            }
            Act::Pause => true,
            _ => false,
        };
        let standing = Standing {
            paused: pause,
            by: if pause {
                who.to_string()
            } else {
                String::new()
            },
            since_unix_nanos: now_unix_nanos(),
        };
        let record = AdministrationRecord {
            kind: AdministrationKind::Operator,
            id: entry.queue,
            body: standing.record(),
        };
        if let Err(error) = self.storage.write_administration(&record) {
            self.failed("subscription.standing", &error.to_string());
            return Err(format!(
                "FAILED: Subscription '{name}' is not {}: Xmip Storage did not take its \
                 standing: {error}",
                if pause { "paused" } else { "resumed" }
            ));
        }
        let entry = &mut state.entries[index];
        entry.standing = standing;
        let said = if pause {
            format!(
                "Subscription '{name}' paused by {who}; what it matches is held, not picked \
                 up, until it is resumed"
            )
        } else {
            (entry.cursor, entry.pending) = (0, true);
            self.wake.notify_all();
            format!(
                "Subscription '{name}' resumed by {who}; the {held} it held are picked up, \
                 oldest first"
            )
        };
        drop(state);
        self.audited(&Noun::Subscription.action(act), name, who, held, &said);
        Ok(said)
    }

    /// Every Subscription as this node publishes it, in the order routing
    /// asks them.
    #[must_use]
    pub fn standing(&self) -> Vec<Published> {
        self.lock().standing(&self.node)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn audited(&self, action: &str, name: &str, who: &str, held: u64, said: &str) {
        let Some(audit) = &self.audit else {
            return;
        };
        let properties = BTreeMap::from([
            ("node".to_string(), self.node.clone()),
            ("subscription".to_string(), name.to_string()),
            ("by".to_string(), who.to_string()),
            ("held".to_string(), held.to_string()),
        ]);
        let phase = ExecutionPhase::Execute;
        let _ = audit.record(action, phase, Severity::Information, Some(said), properties);
    }

    fn failed(&self, action: &str, problem: &str) {
        if let Some(audit) = &self.audit {
            let _ = audit.failed(action, &format!("{}: {problem}", self.node));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use journey::{ChainCause, Journey, JourneyMessageRef};
    use path::expression::Expression;
    use persist::storage::{AuditEntry, JourneyRecord, MessageRecord, Publication};
    use route::{Promoted, Subscriber, publish};
    use xcore::{AuditId, IdGenerator, JourneyId, MessageId, StreamId, UuidV7Generator};

    use super::*;
    use crate::fixture::{Failing, Operation};

    /// This module's node: the test cluster's first, named apart so no other
    /// test's pickup is listed with it.
    fn node() -> String {
        format!(
            "{}-pickup-test",
            configure::fixture::test_cluster().node_scope(0)
        )
    }

    pub(crate) fn subscription(name: &str) -> route::Subscription {
        route::Subscription::new(
            name,
            Subscriber::SendPort("Out".to_string()),
            Expression::parse("true").expect("compiles"),
        )
    }

    fn opened(storage: &Arc<dyn XmipStorage>) -> Arc<Pickup> {
        let configured = vec![ConfiguredSubscription::unfiled(subscription("orders"))];
        Pickup::open(&node(), configured, Arc::clone(storage), None).expect("opened")
    }

    /// One Message matched to every one of `subscriptions`, published
    /// through `pickup` into `storage` as the receive path publishes it,
    /// `body` kept beside what is held: how many were held, or why the
    /// Publication was not taken.
    pub(crate) fn published(
        pickup: &Pickup,
        storage: &dyn XmipStorage,
        subscriptions: &[route::Subscription],
        body: &str,
    ) -> Result<usize, String> {
        let ids = UuidV7Generator;
        let routing = publish(&Promoted::new(), subscriptions);
        let message = MessageId::new(ids.next_u128());
        let journeys: Vec<Journey> = routing
            .evaluations
            .iter()
            .filter(|evaluation| evaluation.matched())
            .map(|evaluation| {
                Journey::matched(
                    JourneyId::new(ids.next_u128()),
                    ChainCause::subscription(&evaluation.subscription_id),
                )
                .holding(JourneyMessageRef {
                    message_id: message,
                    stream_id: StreamId::new(ids.next_u128()),
                })
            })
            .collect();
        let holding = pickup.holding(&routing, &journeys, || body.as_bytes().to_vec());
        let publication = Publication {
            message: MessageRecord {
                message,
                body: Vec::new(),
            },
            journeys: journeys
                .iter()
                .map(|journey| JourneyRecord {
                    journey: journey.journey_id(),
                    body: journey.record(),
                })
                .collect(),
            held: holding.holds().to_vec(),
            dead: None,
            audit: AuditEntry {
                id: AuditId::new(ids.next_u128()),
                body: Vec::new(),
            },
            claims: Vec::new(),
            lease_nanos: 0,
        };
        storage.publish(&publication).map_err(|e| e.to_string())?;
        pickup.published(&holding);
        Ok(holding.holds().len())
    }

    fn route(pickup: &Pickup, storage: &Arc<dyn XmipStorage>, body: &str) -> usize {
        published(pickup, storage.as_ref(), &[subscription("orders")], body).expect("taken")
    }

    fn bodies(released: &[Released]) -> Vec<String> {
        released
            .iter()
            .map(|one| String::from_utf8_lossy(&one.held.hold.body).into_owned())
            .collect()
    }

    fn deliver(pickup: &Pickup, released: &Released) {
        let journey = Journey::new(released.held.hold.journey);
        pickup.delivered(released, &journey).expect("delivered");
    }

    #[test]
    fn a_paused_subscription_holds_what_it_matches_and_a_resume_picks_it_up_in_order() {
        let storage = crate::ledger::in_memory();
        let pickup = opened(storage);
        assert_eq!(route(&pickup, storage, "zero"), 0, "active: picked up");
        pickup.act("orders", Act::Pause, "ilian").expect("paused");
        for body in ["one", "two", "three"] {
            assert_eq!(route(&pickup, storage, body), 1, "paused: held");
        }
        let standing = &pickup.standing()[0];
        assert_eq!((standing.held, standing.picked_up), (3, 1));
        assert_eq!(standing.state, observe::PauseState::Paused);
        assert!(
            pickup.released(Duration::ZERO, 8).is_empty(),
            "nothing let go"
        );

        let said = pickup.act("orders", Act::Resume, "ilian").expect("resumed");
        assert!(said.contains("the 3 it held"), "{said}");
        assert_eq!(
            route(&pickup, storage, "four"),
            1,
            "joins the end of what it held"
        );
        let released = pickup.released(Duration::ZERO, 8);
        assert_eq!(bodies(&released), ["one", "two", "three", "four"]);
        let places: Vec<u64> = released.iter().map(|one| one.held.sequence).collect();
        assert_eq!(places, [0, 1, 2, 3], "the Ledger's order");
        for one in &released {
            deliver(&pickup, one);
        }
        let standing = &pickup.standing()[0];
        assert_eq!((standing.held, standing.picked_up), (0, 5), "nothing lost");
        let queue = named(&uri(&node(), "orders"));
        assert_eq!(storage.read_held(queue, 0, 8).expect("read").count, 0);
        assert_eq!(
            route(&pickup, storage, "five"),
            0,
            "drained: picked up again"
        );
    }

    #[test]
    fn a_pause_and_what_it_holds_survive_a_restart_of_the_node() {
        let storage = crate::ledger::in_memory();
        let before = opened(storage);
        before.act("orders", Act::Pause, "ilian").expect("paused");
        route(&before, storage, "one");
        route(&before, storage, "two");
        drop(before);

        let after = opened(storage);
        let standing = &after.standing()[0];
        assert_eq!(standing.state, observe::PauseState::Paused, "still paused");
        assert_eq!((standing.held, standing.by.as_str()), (2, "ilian"));
        after.act("orders", Act::Resume, "ilian").expect("resumed");
        let released = after.released(Duration::ZERO, 8);
        assert_eq!(bodies(&released), ["one", "two"]);
        deliver(&after, &released[0]);
        drop(after);

        let again = opened(storage);
        let released = again.released(Duration::ZERO, 8);
        assert_eq!(
            bodies(&released),
            ["two"],
            "resumed, not all picked up before the stop: picked up at the start"
        );
    }

    #[test]
    fn a_standing_xmip_storage_did_not_take_is_no_pause() {
        let failing = Failing::over(Arc::clone(crate::ledger::in_memory()));
        let storage: Arc<dyn XmipStorage> = failing.clone();
        let pickup = opened(&storage);
        failing.fail(Operation::WriteAdministration, 1);
        let refused = pickup
            .act("orders", Act::Pause, "ilian")
            .expect_err("not taken");
        assert!(refused.starts_with("FAILED"), "{refused}");
        assert_eq!(pickup.standing()[0].state, observe::PauseState::Active);
        assert_eq!(route(&pickup, &storage, "one"), 0, "not held: not paused");
    }

    #[test]
    fn a_remove_or_a_subscription_not_configured_is_refused_and_every_act_is_audited() {
        let at = std::env::temp_dir().join(format!("xmip-pickup-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&at);
        let audit = ProgramAudit::new("xmip-runtime pickup tests", Some(&at));
        let configured = vec![ConfiguredSubscription::unfiled(subscription("orders"))];
        let storage = Arc::clone(crate::ledger::in_memory());
        let pickup = Pickup::open(&node(), configured, storage, Some(audit)).expect("opened");

        let removed = pickup
            .act("orders", Act::Remove, "ilian")
            .expect_err("refused");
        assert!(removed.contains("TOML configuration"), "{removed}");
        let stranger = pickup
            .act("shipping", Act::Pause, "ilian")
            .expect_err("refused");
        assert!(
            stranger.starts_with("REFUSED: no Subscription 'shipping'"),
            "{stranger}"
        );
        pickup.act("orders", Act::Pause, "ilian").expect("paused");
        pickup.act("orders", Act::Resume, "ilian").expect("resumed");

        xaudit::keeper::settle();
        let text = std::fs::read_to_string(at.join(xaudit::file_sink::FILE_NAME)).expect("kept");
        assert!(text.contains("action = \"subscription.pause\""), "{text}");
        assert!(text.contains("action = \"subscription.resume\""), "{text}");
        assert!(text.contains("\"by\" = \"ilian\""), "{text}");
        let _ = std::fs::remove_dir_all(&at);
    }
}
