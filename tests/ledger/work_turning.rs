//! What the Work Process tests turn with (`woken.rs`, `woken_behind.rs`,
//! `work_panicked.rs`, `work_bounded.rs`, `work_sequenced.rs`): a flow that
//! records, refuses or panics before each advance, units that hold their
//! calls at a gate, panic, or throw once, the node whose Work pool a test
//! counts — its turns on the dispatching thread where a Work Process names
//! a Correlation — and the Work Process step dispatching while a test runs,
//! closed after.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use message::Message;
use process::program::Call;
use process::{Act, Compiled, Declared, Event, Flow, Instance, Refused};
use xcore::{IdGenerator, MessageId};
use xmip_core_runtime::message_path::Runtime;
use xmip_core_runtime::pickup::Pickup;
use xmip_core_runtime::sequence::{OnFailure, Point, PointKind};
use xmip_core_runtime::split::Split;
use xmip_core_runtime::tuning::Tuning;
use xmip_core_runtime::work_step::{NoUnits, Thrown, WorkStep, WorkUnits, dispatch};

use super::receive_cycle::Sender;
use super::sending::Gate;
use super::work_design::{compiled, per_client, sending_nothing};

/// An hour: no scan comes while a test runs.
pub(super) const HOUR: Duration = Duration::from_secs(3600);

/// What a [`Hooked`] flow runs before each advance: a test's record of it,
/// a refusal of the advance, or a panic.
pub(super) type Before = Box<dyn Fn() -> Result<(), Refused> + Send + Sync>;

/// A compiled flow that runs its `before` ahead of each advance.
pub(super) struct Hooked {
    flow: Compiled,
    before: Before,
}

impl Hooked {
    /// `design`, compiled, running `before` ahead of each advance.
    pub(super) fn of(design: &str, before: Before) -> Box<dyn Flow> {
        Box::new(Self {
            flow: compiled(design),
            before,
        })
    }
}

impl Flow for Hooked {
    fn declared(&self) -> &Declared {
        self.flow.declared()
    }

    fn advance(
        &self,
        instance: &mut Instance,
        event: &Event,
        now: i128,
    ) -> Result<Vec<Act>, Refused> {
        (self.before)()?;
        self.flow.advance(instance, event, now)
    }
}

/// Units whose every call is counted, then held at `gate` until it opens,
/// and answers its Message assigned to a new one.
pub(super) struct Gated {
    pub(super) gate: Arc<Gate>,
    pub(super) entered: Arc<AtomicUsize>,
}

impl WorkUnits for Gated {
    fn call(
        &self,
        _: &Call,
        message: &Message,
        ids: &dyn IdGenerator,
    ) -> Result<Vec<Message>, Thrown> {
        self.entered.fetch_add(1, Ordering::AcqRel);
        self.gate.wait();
        let id = MessageId::new(ids.next_u128());
        Ok(vec![message.assigned(id, message.context().clone())])
    }

    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown> {
        NoUnits.splitter(call)
    }
}

/// Units whose every call panics.
pub(super) struct Panicking;

impl WorkUnits for Panicking {
    fn call(&self, _: &Call, _: &Message, _: &dyn IdGenerator) -> Result<Vec<Message>, Thrown> {
        panic!("a unit that panics")
    }

    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown> {
        NoUnits.splitter(call)
    }
}

/// Units whose first call throws an error, and whose every later call
/// answers its Message assigned to a new one.
#[derive(Default)]
pub(super) struct ThrowingOnce {
    thrown: AtomicBool,
}

impl WorkUnits for ThrowingOnce {
    fn call(
        &self,
        _: &Call,
        message: &Message,
        ids: &dyn IdGenerator,
    ) -> Result<Vec<Message>, Thrown> {
        if !self.thrown.swap(true, Ordering::AcqRel) {
            return Err(Thrown {
                code: "refused".to_string(),
                reason: "a unit that throws".to_string(),
            });
        }
        let id = MessageId::new(ids.next_u128());
        Ok(vec![message.assigned(id, message.context().clone())])
    }

    fn splitter(&self, call: &Call) -> Result<Box<dyn Split>, Thrown> {
        NoUnits.splitter(call)
    }
}

/// A node that sends nothing, its Work pool one thread a hardware thread
/// and its scan an hour: what holds its turns is what a test counts.
pub(super) fn counted_node() -> Sender {
    Sender {
        tuning: Tuning {
            work_threads_per_hardware_thread: 1,
            work_scan: HOUR,
            ..Tuning::default()
        },
        ..sending_nothing()
    }
}

/// `sender` with the Work Process `name` naming the cluster's Correlation
/// by client, a failure blocking its sequence or letting it go on as
/// `on_failure` says: its turns are taken on the dispatching thread, in its
/// queue's order.
pub(super) fn sequenced(mut sender: Sender, name: &str, on_failure: OnFailure) -> Sender {
    sender.sends.points.push(Point {
        kind: PointKind::WorkProcess,
        name: name.to_string(),
        set: per_client(),
        on_failure,
    });
    sender
}

/// The Work Process step of `runtime` dispatching while `run` runs, closed
/// after, however `run` ends.
pub(super) fn turning<T>(runtime: &Runtime<'_>, pickup: &Pickup, run: impl FnOnce() -> T) -> T {
    std::thread::scope(|scope| {
        scope.spawn(|| dispatch(scope, runtime, pickup));
        let _closing = Closing(runtime.work);
        run()
    })
}

/// A Work Process step closed when this is dropped, however the test got
/// there, so a failing test fails rather than waits.
pub(super) struct Closing<'a>(pub(super) &'a WorkStep);

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
}
