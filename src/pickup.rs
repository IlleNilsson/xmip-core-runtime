//! A running node's Subscriptions as an operator sees and pauses them
//! (ADR-0013, amendment 2026-09-30).
//!
//! **What a pause holds.** Every Message routing matches to a paused
//! Subscription is held: kept in the node's runtime store as persist's
//! [`HeldMessage`], numbered in the order it was held and counted, and not
//! picked up — no Journey opens for that Subscription and nothing departs.
//! Nothing is lost and nothing is deleted (ADR-0040). **A resume** lets go
//! of what was held, oldest first: the node picks each up as if routing had
//! just matched it, and only then is its record of the wait released. While
//! a resumed Subscription still has held Messages to pick up, what it
//! matches joins the end of them, so it picks up in the order it matched.
//!
//! **A restart.** The Subscription's [`SubscriptionHold`] — paused or not,
//! by whom, since when, the range of what it holds — is written on every act
//! and every hold, through the one [`RuntimeStore`] the node was given, and
//! read back when the node takes its Subscriptions up: one paused before a
//! restart is paused after it, holding what it held, and one resumed whose
//! held Messages were not all picked up when the node stopped picks them up
//! as it starts. A node given no store holds in memory, for its own life.
//!
//! **A Subscription is not removed here.** It is configuration: added and
//! removed in the TOML of the Xmip Application that draws it. Pause and
//! resume are the acts ([`observe::Noun::Subscription`]); a remove is
//! refused in words, and so is an act on a Subscription not configured.
//!
//! The one [`Pickup`] of each node in this process is registered, so the
//! runtime's library lists and acts on it (`xmip_operate.h` section 14).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use observe::{Act, Noun, Subscription as Published, now_unix_nanos};
use persist::{HeldMessage, RuntimeStore, SubscriptionHold};
use route::{Routing, Subscriber};
use xaudit::program_audit::ProgramAudit;
use xcore::{ExecutionPhase, Severity};

use crate::configured_subscription::ConfiguredSubscription;

mod state;

use state::{Entry, State};

/// The runtime store a node keeps what a pause leaves in: persist's, over
/// whichever engine the program linked.
pub type Store = Arc<dyn RuntimeStore + Send + Sync>;

/// A node's Subscriptions, their standing, and what they hold.
pub struct Pickup {
    node: String,
    store: Option<Store>,
    audit: Option<ProgramAudit>,
    state: Mutex<State>,
    released: Condvar,
}

/// A held Message a resume let go of, for the node to pick up.
#[derive(Clone, Debug)]
pub struct Released {
    /// The Subscription that held it.
    pub subscription: String,
    /// Where it leads.
    pub destination: Subscriber,
    pub held: HeldMessage,
}

/// Every node's pickup in this process.
static REGISTERED: Mutex<Vec<Weak<Pickup>>> = Mutex::new(Vec::new());

impl Pickup {
    /// The Subscriptions of the node at `node` (`xmip:///<cluster>/node/<name>`),
    /// each with its standing read back from `store`, registered for the
    /// runtime's library. `audit` records every act.
    ///
    /// # Errors
    /// The store could not be read: a standing that cannot be read back is
    /// a pause that could be lost, so the node does not start.
    pub fn open(
        node: &str,
        configured: Vec<ConfiguredSubscription>,
        store: Option<Store>,
        audit: Option<ProgramAudit>,
    ) -> Result<Arc<Self>, String> {
        let now = now_unix_nanos();
        let mut state = State {
            entries: Vec::new(),
            released: VecDeque::new(),
            memory: BTreeMap::new(),
        };
        for configured in configured {
            let name = configured.name().to_string();
            let kept = match &store {
                Some(store) => store
                    .load_subscription_hold(node, &name)
                    .map_err(|error| format!("the Subscription '{name}': {error}"))?,
                None => None,
            };
            let hold = kept.unwrap_or_else(|| SubscriptionHold {
                node: node.to_string(),
                subscription: name,
                since_unix_nanos: now,
                ..SubscriptionHold::default()
            });
            let index = state.entries.len();
            if !hold.paused {
                state
                    .released
                    .extend((hold.first_held..hold.next_held).map(|n| (index, n)));
            }
            state.entries.push(Entry {
                configured,
                hold,
                picked_up: 0,
                taken: BTreeSet::new(),
                done: BTreeSet::new(),
            });
        }
        let pickup = Arc::new(Self {
            node: node.to_string(),
            store,
            audit,
            state: Mutex::new(state),
            released: Condvar::new(),
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

    /// `routing` without what a paused Subscription holds: each Message it
    /// matched to one is held — `hold` says what the node needs to pick it
    /// up again — and each it matched to an active one counts as picked up.
    pub fn route(&self, routing: &Routing, hold: &dyn Fn() -> HeldMessage) -> Routing {
        let mut state = self.lock();
        let mut kept = Vec::new();
        for evaluation in &routing.evaluations {
            let index = evaluation
                .matched()
                .then(|| state.index(&evaluation.subscription_id))
                .flatten();
            let Some(index) = index else {
                kept.push(evaluation.clone());
                continue;
            };
            let entry = &mut state.entries[index];
            if !entry.hold.paused && entry.hold.held() == 0 {
                entry.picked_up += 1;
                kept.push(evaluation.clone());
                continue;
            }
            let mut held = hold();
            held.node.clone_from(&self.node);
            held.subscription.clone_from(&entry.hold.subscription);
            held.sequence = entry.hold.next_held;
            held.held_unix_nanos = now_unix_nanos();
            entry.hold.next_held += 1;
            let paused = entry.hold.paused;
            self.keep(&mut state, index, held);
            if !paused {
                let sequence = state.entries[index].hold.next_held - 1;
                state.released.push_back((index, sequence));
                self.released.notify_all();
            }
        }
        Routing { evaluations: kept }
    }

    /// Pause or resume the Subscription called `name`, by `who`, and say
    /// what came of it. Audited.
    ///
    /// # Errors
    /// REFUSED, in words, for an act a Subscription does not take — remove
    /// among them: a Subscription is removed in the TOML configuration — and
    /// for a Subscription this node is not configured with.
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
        let held = state.entries[index].hold.held();
        let said = match act {
            Act::Pause if state.entries[index].hold.paused => {
                format!("Subscription '{name}' was already paused")
            }
            Act::Pause => {
                state.released.retain(|(at, _)| *at != index);
                state.set(index, true, who);
                format!(
                    "Subscription '{name}' paused by {who}; what it matches is held, not \
                     picked up, until it is resumed"
                )
            }
            Act::Resume if !state.entries[index].hold.paused => {
                format!("Subscription '{name}' was not paused")
            }
            _ => {
                state.set(index, false, who);
                let entry = &state.entries[index];
                let waiting: Vec<u64> = (entry.hold.first_held..entry.hold.next_held)
                    .filter(|n| !entry.taken.contains(n) && !entry.done.contains(n))
                    .collect();
                state
                    .released
                    .extend(waiting.into_iter().map(|n| (index, n)));
                self.released.notify_all();
                format!(
                    "Subscription '{name}' resumed by {who}; the {held} it held are picked \
                     up, oldest first"
                )
            }
        };
        self.write(&state.entries[index].hold);
        drop(state);
        self.audited(&Noun::Subscription.action(act), name, who, held, &said);
        Ok(said)
    }

    /// Up to `max` held Messages a resume let go of, oldest first, waiting
    /// up to `timeout` for the first. Each is the node's to pick up and then
    /// to say so ([`Pickup::picked_up`]).
    pub fn released(&self, timeout: Duration, max: usize) -> Vec<Released> {
        let mut state = self.lock();
        if state.released.is_empty() && !timeout.is_zero() {
            state = self
                .released
                .wait_timeout_while(state, timeout, |state| state.released.is_empty())
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let mut taken = Vec::new();
        while taken.len() < max.max(1) {
            let Some((index, sequence)) = state.released.pop_front() else {
                break;
            };
            let Some(held) = self.load(&state, index, sequence) else {
                // Nothing kept under that number: nothing to pick up, and the
                // range it holds moves past it.
                state.entries[index].settle(sequence);
                continue;
            };
            let entry = &mut state.entries[index];
            entry.taken.insert(sequence);
            taken.push(Released {
                subscription: entry.hold.subscription.clone(),
                destination: entry.configured.subscription.destination.clone(),
                held,
            });
        }
        taken
    }

    /// The node picked `released` up: count it, and release its record of
    /// the wait.
    pub fn picked_up(&self, released: &Released) {
        let mut state = self.lock();
        let Some(index) = state.index(&released.subscription) else {
            return;
        };
        let sequence = released.held.sequence;
        let entry = &mut state.entries[index];
        if !entry.taken.remove(&sequence) {
            return;
        }
        entry.picked_up += 1;
        entry.settle(sequence);
        let hold = entry.hold.clone();
        state.memory.remove(&(index, sequence));
        if let Some(store) = &self.store
            && let Err(error) =
                store.release_held_message(&self.node, &released.subscription, sequence)
        {
            self.failed("subscription.pickup", &error.to_string());
        }
        self.write(&hold);
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

    /// Keep `held` and the standing that now counts it; in memory where the
    /// store is not given or would not take it, and said.
    fn keep(&self, state: &mut State, index: usize, held: HeldMessage) {
        let kept = self.store.as_ref().map(|store| store.hold_message(&held));
        if let Some(Err(error)) = &kept {
            self.failed("subscription.hold", &error.to_string());
        }
        if !matches!(kept, Some(Ok(()))) {
            state.memory.insert((index, held.sequence), held);
        }
        self.write(&state.entries[index].hold);
    }

    fn load(&self, state: &State, index: usize, sequence: u64) -> Option<HeldMessage> {
        if let Some(held) = state.memory.get(&(index, sequence)) {
            return Some(held.clone());
        }
        let name = &state.entries[index].hold.subscription;
        let store = self.store.as_ref()?;
        store
            .load_held_message(&self.node, name, sequence)
            .map_err(|error| self.failed("subscription.pickup", &error.to_string()))
            .ok()
            .flatten()
    }

    fn write(&self, hold: &SubscriptionHold) {
        if let Some(store) = &self.store
            && let Err(error) = store.persist_subscription_hold(hold)
        {
            self.failed("subscription.hold", &error.to_string());
        }
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
mod tests {
    use path::expression::Expression;
    use persist::EncryptedStore;
    use persist::fixture::Memory;
    use route::{Promoted, publish};
    use secret::{Held, KekName};

    use super::*;

    const NODE: &str = "xmip:///CT/node/pickup-test";

    fn configured(name: &str) -> ConfiguredSubscription {
        ConfiguredSubscription::unfiled(route::Subscription::new(
            name,
            Subscriber::SendPort("Out".to_string()),
            Expression::parse("true").expect("compiles"),
        ))
    }

    /// A store over `engine`, sealed under `keys`: reopened over the same
    /// two, it is the same node's store after a restart.
    fn store(engine: &'static Memory, keys: &Held<secret::fixture::Memory>) -> Store {
        let kek = KekName::new("runtime").expect("name");
        Arc::new(EncryptedStore::open(engine, keys, &kek).expect("open"))
    }

    fn opened(store: Option<Store>) -> Arc<Pickup> {
        Pickup::open(NODE, vec![configured("orders")], store, None).expect("opened")
    }

    /// Route one Message carrying `content` through the Subscription.
    fn route(pickup: &Pickup, content: &str) -> usize {
        let orders = [configured("orders").subscription];
        let routing = publish(&Promoted::new(), &orders);
        let held = || HeldMessage {
            content: content.as_bytes().to_vec(),
            ..HeldMessage::default()
        };
        pickup.route(&routing, &held).destinations().len()
    }

    fn contents(released: &[Released]) -> Vec<String> {
        released
            .iter()
            .map(|one| String::from_utf8_lossy(&one.held.content).into_owned())
            .collect()
    }

    #[test]
    fn a_paused_subscription_holds_what_it_matches_and_a_resume_picks_it_up_in_order() {
        let pickup = opened(None);
        assert_eq!(route(&pickup, "zero"), 1, "active: picked up");
        pickup.act("orders", Act::Pause, "ilian").expect("paused");
        for content in ["one", "two", "three"] {
            assert_eq!(route(&pickup, content), 0, "paused: held, not picked up");
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
        assert_eq!(route(&pickup, "four"), 0, "joins the end of what it held");
        let released = pickup.released(Duration::ZERO, 8);
        assert_eq!(contents(&released), ["one", "two", "three", "four"]);
        for one in &released {
            pickup.picked_up(one);
        }
        let standing = &pickup.standing()[0];
        assert_eq!((standing.held, standing.picked_up), (0, 5), "nothing lost");
        assert_eq!(route(&pickup, "five"), 1, "drained: picked up again");
    }

    #[test]
    fn a_pause_and_what_it_holds_survive_a_restart_of_the_node() {
        let engine: &'static Memory = Box::leak(Box::default());
        let keys = Held::new(secret::fixture::Memory::default());
        let before = opened(Some(store(engine, &keys)));
        before.act("orders", Act::Pause, "ilian").expect("paused");
        route(&before, "one");
        route(&before, "two");
        drop(before);

        let after = opened(Some(store(engine, &keys)));
        let standing = &after.standing()[0];
        assert_eq!(standing.state, observe::PauseState::Paused, "still paused");
        assert_eq!((standing.held, standing.by.as_str()), (2, "ilian"));
        after.act("orders", Act::Resume, "ilian").expect("resumed");
        let released = after.released(Duration::ZERO, 8);
        assert_eq!(contents(&released), ["one", "two"]);
        after.picked_up(&released[0]);
        drop(after);

        let again = opened(Some(store(engine, &keys)));
        let released = again.released(Duration::ZERO, 8);
        assert_eq!(
            contents(&released),
            ["two"],
            "resumed, not all picked up before the stop: picked up at the start"
        );
    }

    #[test]
    fn a_remove_or_a_subscription_not_configured_is_refused_and_every_act_is_audited() {
        let at = std::env::temp_dir().join(format!("xmip-pickup-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&at);
        let audit = ProgramAudit::new("xmip-runtime pickup tests", Some(&at));
        let pickup =
            Pickup::open(NODE, vec![configured("orders")], None, Some(audit)).expect("opened");

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
