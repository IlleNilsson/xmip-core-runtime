//! The work process trait of a loaded module, driven through its table
//! (`include/xmip_module.h` section 13; ADR-0066, amendment 2026-10-22).
//!
//! A Work Process compiled from a design ships apart from Xmip, as a
//! library a node loads, so a change to a process never rebuilds the node.
//! This is the host side of its table: what the unit declares, copied out
//! once as it opens, and a turn — the Instance, the event and the time in
//! `xmip-core-process`'s turn form — handed to `advance` and its answer
//! read back. The unit keeps nothing between turns, so any thread asks it
//! at any time.
//!
//! The third of the files in this crate that cross the boundary inward;
//! every `unsafe` block names the invariant that makes it sound.
#![allow(unsafe_code)]

use std::sync::Arc;

use abi::Expectation;
use abi::ffi::{Slice, WorkProcessVtable, status};
use process::form::{self, read_acts, write_turn};
use process::{Act, Declared, Event, Flow, Instance, Refused};

use crate::ffi::loaded_module::LoadedModule;

/// The trait this file drives, as `descriptor.module` spells it.
pub const WORK_PROCESS: &str = "work-process";

/// What this host requires of a module offering the work process trait.
#[must_use]
pub fn expectation() -> Expectation {
    Expectation::new(WORK_PROCESS, 1, 0)
}

/// The room a turn's answer is first given; a unit asking for more is
/// asked again with what it said it needs.
const FIRST_ROOM: usize = 4096;

/// A loaded Work Process unit's module, shared by every flow that asks it.
pub struct UnitModule(LoadedModule);

// SAFETY: header section 13 - a work process module keeps nothing between
// turns, and `advance` may be called from any thread, many at once; the
// table and the state live until `destroy`, which runs once, when the last
// holder lets it go.
unsafe impl Send for UnitModule {}
// SAFETY: as above; nothing of it is changed after it opens.
unsafe impl Sync for UnitModule {}

impl UnitModule {
    /// `module`, shared.
    #[must_use]
    pub fn shared(module: LoadedModule) -> Arc<Self> {
        Arc::new(Self(module))
    }

    /// The module it is.
    #[must_use]
    pub const fn module(&self) -> &LoadedModule {
        &self.0
    }
}

/// A loaded unit's flow: its module held while any turn may still ask it.
pub struct LoadedFlow {
    module: Arc<UnitModule>,
    table: *const WorkProcessVtable,
    declared: Declared,
}

// SAFETY: header section 13 — the module keeps nothing between turns and
// `advance` may be called from any thread, many at once; the table and the
// state live until `destroy`, which runs only once the last `Arc` of the
// module is let go.
unsafe impl Send for LoadedFlow {}
// SAFETY: as above; nothing of the flow is mutated after it opens.
unsafe impl Sync for LoadedFlow {}

impl LoadedFlow {
    /// The flow of `module`, its table selected by its descriptor and what
    /// it declares copied out.
    ///
    /// # Errors
    /// A module of another trait, one with no table, or one whose declared
    /// form does not read.
    pub fn of(unit: Arc<UnitModule>) -> Result<Self, String> {
        let module = unit.module();
        let descriptor = module.descriptor().clone();
        if descriptor.module != WORK_PROCESS {
            return Err(format!(
                "{descriptor} does not answer the '{WORK_PROCESS}' trait"
            ));
        }
        if module.vtable().is_null() {
            return Err(format!(
                "{descriptor} names '{WORK_PROCESS}' and carries no table"
            ));
        }
        let table = module.vtable().cast::<WorkProcessVtable>();
        // SAFETY: the table is the one `descriptor.module` names, checked
        // above, and lives in the library `module` holds.
        let Some(declared) = (unsafe { (*table).declared }) else {
            return Err(format!("{descriptor} carries no 'declared'"));
        };
        let mut out = Slice {
            ptr: std::ptr::null(),
            len: 0,
        };
        // SAFETY: `state` is the module's own; `out` is ours for the call.
        let answer = unsafe { declared(module.state(), &raw mut out) };
        if answer != status::OK || out.ptr.is_null() {
            return Err(format!(
                "{descriptor} did not say what it declares: {answer}"
            ));
        }
        // SAFETY: header section 13 — borrowed until destroy; copied now.
        let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
        let declared =
            form::read::<Declared>(&bytes).map_err(|why| format!("{descriptor}: {why}"))?;
        Ok(Self {
            module: unit,
            table,
            declared,
        })
    }

    fn turn(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        // SAFETY: the table lives as long as `self.module`.
        let Some(advance) = (unsafe { (*self.table).advance }) else {
            return Err("the unit carries no 'advance'".to_string());
        };
        let turn = Slice {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        };
        let mut room = vec![0u8; FIRST_ROOM];
        loop {
            let mut written = 0usize;
            // SAFETY: `state` is the module's; `turn` and `room` are ours and
            // valid for the call; the module writes at most `room.len()`.
            let answer = unsafe {
                advance(
                    self.module.module().state(),
                    turn,
                    room.as_mut_ptr(),
                    room.len(),
                    &raw mut written,
                )
            };
            match answer {
                status::OK => {
                    room.truncate(written);
                    return Ok(room);
                }
                status::CAPACITY if written > room.len() => room.resize(written, 0),
                other => {
                    return Err(format!(
                        "the unit '{}' answered {other}: {}",
                        self.declared.name,
                        self.module.module().last_error()
                    ));
                }
            }
        }
    }
}

impl Flow for LoadedFlow {
    fn declared(&self) -> &Declared {
        &self.declared
    }

    fn advance(
        &self,
        instance: &mut Instance,
        event: &Event,
        now_unix_nanos: i128,
    ) -> Result<Vec<Act>, Refused> {
        let answer = self
            .turn(&write_turn(instance, event, now_unix_nanos))
            .map_err(Refused::Unfit)?;
        let (after, acts) =
            read_acts(&answer).map_err(|why| Refused::Unfit(format!("its answer: {why}")))??;
        *instance = after;
        Ok(acts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::ffi::CreateModuleFn;
    use process::{Arrival, DesignFormat, NoResources, Outcome};
    use process_bpmn::Bpmn;

    /// A design that waits for a second Message and publishes it.
    const DESIGN: &str = r#"<bpmn:definitions
        xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL" id="D"
        targetNamespace="urn:example">
      <bpmn:process id="Approval" isExecutable="true">
        <bpmn:startEvent id="S"/>
        <bpmn:receiveTask id="Wait"/>
        <bpmn:sendTask id="Send"/>
        <bpmn:endEvent id="E"/>
        <bpmn:sequenceFlow id="F1" sourceRef="S" targetRef="Wait"/>
        <bpmn:sequenceFlow id="F2" sourceRef="Wait" targetRef="Send"/>
        <bpmn:sequenceFlow id="F3" sourceRef="Send" targetRef="E"/>
      </bpmn:process>
    </bpmn:definitions>"#;

    fn program() -> Vec<u8> {
        form::program(&Bpmn.compile(DESIGN, &NoResources).expect("compiles"))
    }

    // The unit, exported as a generated unit is, linked into this test.
    process::export_work_process!(&program(), unit = "Approval", version = (0, 1, 0));

    fn arrived(message: u128) -> Event {
        Event::Arrived(Arrival {
            message,
            values: Vec::new(),
            keys: Vec::new(),
        })
    }

    #[test]
    fn a_unit_crosses_the_boundary_a_turn_at_a_time_and_says_why_it_refuses() {
        // SAFETY: the exported entrypoint has the header's signature; the
        // macro spells its pointers as `c_void` where the binding names them.
        let create: CreateModuleFn = unsafe {
            std::mem::transmute::<
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void) -> i32,
                CreateModuleFn,
            >(xmip_create_module_v1)
        };
        let module = LoadedModule::linked(create, &expectation()).expect("created");
        let flow = LoadedFlow::of(UnitModule::shared(module)).expect("its table drives");
        assert_eq!(flow.declared().name, "Approval");
        let mut instance = Instance::new();
        assert!(
            flow.advance(&mut instance, &arrived(1), 0)
                .expect("starts")
                .is_empty()
        );
        assert!(instance.waits_for_a_message(), "the Instance crossed back");
        let acts = flow
            .advance(&mut instance, &arrived(2), 0)
            .expect("goes on");
        assert_eq!(
            acts,
            vec![Act::Publish { message: 2 }, Act::Ended(Outcome::Completed)]
        );
        assert_eq!(
            flow.advance(&mut instance, &Event::Due, 0),
            Err(Refused::Ended)
        );
    }
}
