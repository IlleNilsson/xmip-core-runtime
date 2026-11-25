//! A Work Process's Instances as a surface lists them (`runtime-model.md`
//! section 22; ADR-0066, amendment 2026-11-25; open problem 192;
//! `xmip_operate.h` section 29): which Instances each Work Process has,
//! each running, waiting — for a Message of its key in each Correlation it
//! holds, until its earliest deadline — failed with its code and why, or
//! completed; its own values; its history of Messages; and, beside them,
//! the Messages that failed in its queue, each by the Journey an operator's
//! Retry or Dismiss names.
//!
//! **Read from the Ledger** ([`WorkStep::instances`]): the Process Instance
//! table searched by the Work Process, newest written first — one search
//! and a read of each — and a page of its queue's index of failed Messages.
//!
//! **Published from what the node knows** ([`WorkStep::published`]): the
//! newest [`INSTANCE_WINDOW`] of each Work Process it runs, read from the
//! Ledger the first time it publishes, then as its own turns write them, so
//! a publication every quarter second costs no read of the Ledger; the
//! failed Messages read again once a scan, or at once after a turn here
//! failed or an operator acted. An Instance another node turned is in that
//! node's publication, and a cluster's merges them.

use std::collections::BTreeMap;

use observe::{InstanceHandled, WorkProcessInstance, WorkProcessInstances};
use persist::storage::{Ask, InstanceRecord, InstanceWrite, Query};
use process::{Instance, State, form};
use xcore::clock::nanos;
use xcore::lock::Locked;
use xcore::{JourneyId, MessageId};

use super::WorkStep;
use super::keys::shown;
use super::running::Running;
use crate::send_step::{FAILED_WINDOW, FailedMessage};

/// How many of a Work Process's newest Instances its node publishes.
pub const INSTANCE_WINDOW: usize = 20;

/// How many Instances a list reads from the Ledger where it asks for none.
pub const INSTANCE_PAGE: u32 = 100;

/// What an Instance is said to be once an operator dismissed the Message
/// that failed it: ended, failed.
pub const DISMISSED: &str = "dismissed";

/// What a node publishes of one Work Process it runs, kept between
/// publications.
#[derive(Default)]
pub(super) struct Window {
    /// Whether its Instances were read from the Ledger yet.
    read: bool,
    /// Its newest Instances, by identifier.
    seen: BTreeMap<String, WorkProcessInstance>,
    /// The Messages that failed in its queue, as last read, and when, on
    /// the step's clock; none where they are to be read again.
    failed: Option<(i128, u64, Vec<observe::FailedMessage>)>,
}

impl WorkStep {
    /// The Instances of the Work Process `name`, newest written first, at
    /// most `most` (0: [`INSTANCE_PAGE`]), read from the Ledger, and the
    /// oldest `most` of the Messages that failed in its queue.
    ///
    /// # Errors
    /// REFUSED where this node runs no such Work Process; FAILED where Xmip
    /// Storage did not answer.
    pub fn instances(&self, name: &str, most: u32) -> Result<WorkProcessInstances, String> {
        let running = self
            .running
            .iter()
            .find(|running| running.name == name)
            .ok_or_else(|| format!("REFUSED: {} runs no Work Process {name}", self.node))?;
        let most = if most == 0 { INSTANCE_PAGE } else { most };
        let instances = self.read_instances(running, most)?;
        let (count, failed) = self.read_failed(running, most)?;
        Ok(WorkProcessInstances {
            node: self.node.clone(),
            work_process: running.name.clone(),
            instances,
            failed_count: count,
            failed,
        })
    }

    /// What this node publishes of every Work Process it runs: the newest
    /// Instances it knows and the Messages that failed in its queue. One a
    /// read of the Ledger did not answer for is published as it was.
    #[must_use]
    pub fn published(&self) -> Vec<WorkProcessInstances> {
        let now = self.clock.monotonic_nanos();
        let mut published = Vec::with_capacity(self.running.len());
        for (at, running) in self.running.iter().enumerate() {
            let (read, stale) = {
                let windows = self.windows.locked();
                let window = &windows[at];
                let stale = window
                    .failed
                    .as_ref()
                    .is_none_or(|(when, _, _)| now - when >= nanos(self.scan));
                (window.read, stale)
            };
            let window = INSTANCE_WINDOW.try_into().unwrap_or(u32::MAX);
            let instances = (!read)
                .then(|| self.read_instances(running, window).ok())
                .flatten();
            let most = u32::try_from(FAILED_WINDOW).unwrap_or(u32::MAX);
            let failed = stale
                .then(|| self.read_failed(running, most).ok())
                .flatten();
            let mut windows = self.windows.locked();
            let kept = &mut windows[at];
            if let Some(instances) = instances {
                kept.read = true;
                for instance in instances {
                    kept.seen
                        .entry(instance.instance.clone())
                        .or_insert(instance);
                }
            }
            if let Some((count, failed)) = failed {
                kept.failed = Some((now, count, failed));
            }
            let mut instances: Vec<WorkProcessInstance> = kept.seen.values().cloned().collect();
            instances.sort_by_key(|one| std::cmp::Reverse(one.updated_unix_nanos));
            let (failed_count, failed) = kept
                .failed
                .as_ref()
                .map(|(_, count, failed)| (*count, failed.clone()))
                .unwrap_or_default();
            published.push(WorkProcessInstances {
                node: self.node.clone(),
                work_process: running.name.clone(),
                instances,
                failed_count,
                failed,
            });
        }
        published
    }

    /// The Instances `writes` wrote in a turn of `running` on this node,
    /// kept as the node publishes them, the oldest let go of past
    /// [`INSTANCE_WINDOW`]; one that failed reads its queue's failed
    /// Messages again.
    pub(super) fn seen(&self, running: &Running, writes: &[InstanceWrite]) {
        let Some(at) = self.place_of(running) else {
            return;
        };
        let now = i64::try_from(self.clock.unix_timestamp_nanos()).unwrap_or(i64::MAX);
        let mut windows = self.windows.locked();
        let window = &mut windows[at];
        for write in writes {
            let Some(mut described) = described(running, &write.record) else {
                continue;
            };
            if described.updated_unix_nanos == 0 {
                described.updated_unix_nanos = now;
            }
            if described.state == "failed" {
                window.failed = None;
            }
            window.seen.insert(described.instance.clone(), described);
        }
        while window.seen.len() > INSTANCE_WINDOW {
            let oldest = window
                .seen
                .values()
                .min_by_key(|one| one.updated_unix_nanos)
                .map(|one| one.instance.clone());
            let Some(oldest) = oldest else {
                break;
            };
            window.seen.remove(&oldest);
        }
    }

    /// What this node publishes of `running`'s failed Messages read again
    /// at its next publication: an operator acted on one, or a turn failed.
    pub(super) fn window_moved(&self, running: &Running) {
        if let Some(at) = self.place_of(running) {
            self.windows.locked()[at].failed = None;
        }
    }

    fn place_of(&self, running: &Running) -> Option<usize> {
        self.running.iter().position(|one| one.name == running.name)
    }

    /// The newest `most` Instances of `running`, read from the Ledger.
    fn read_instances(
        &self,
        running: &Running,
        most: u32,
    ) -> Result<Vec<WorkProcessInstance>, String> {
        let unanswered = |why: &dyn std::fmt::Display| {
            format!(
                "FAILED: Xmip Storage did not answer for {}'s Instances: {why}",
                running.name
            )
        };
        let query = Query {
            ask: Ask::InstancesOf {
                work_process: running.name.clone(),
            },
            most,
            newest_first: true,
        };
        let found = self.storage.query(&query).map_err(|why| unanswered(&why))?;
        let mut instances = Vec::with_capacity(found.len());
        for id in found {
            let record = self
                .storage
                .read_instance(id)
                .map_err(|why| unanswered(&why))?;
            if let Some(described) = record.and_then(|record| described(running, &record)) {
                instances.push(described);
            }
        }
        Ok(instances)
    }

    /// How many Messages that failed wait in `running`'s queue, and the
    /// oldest `most` of them.
    fn read_failed(
        &self,
        running: &Running,
        most: u32,
    ) -> Result<(u64, Vec<observe::FailedMessage>), String> {
        let read = self
            .storage
            .read_failed(running.queue, 0, most.max(1))
            .map_err(|why| {
                format!(
                    "FAILED: Xmip Storage did not answer for {}'s queue: {why}",
                    running.name
                )
            })?;
        let failed = read
            .failed
            .iter()
            .map(|one| FailedMessage::of(one).published())
            .collect();
        Ok((read.count, failed))
    }
}

/// `record`, an Instance of `running`, as a surface says it; none where its
/// state does not read as an Instance.
#[must_use]
pub fn described(running: &Running, record: &InstanceRecord) -> Option<WorkProcessInstance> {
    let instance: Instance = form::read(&record.body).ok()?;
    let state = instance.state();
    let (waits_for, until) = match &state {
        State::Waiting { message, until } => {
            let waits = match (*message, until.is_some()) {
                (true, true) => "message or time",
                (true, false) => "message",
                (false, true) => "time",
                (false, false) => "",
            };
            (waits, until.map(saturated))
        }
        _ => ("", None),
    };
    let (code, reason) = match &state {
        State::Failed { code, reason } => (code.clone(), reason.clone()),
        _ => (String::new(), String::new()),
    };
    let failed_by = instance
        .failed_by()
        .map(|journey| JourneyId::new(journey).to_string())
        .unwrap_or_default();
    // Failed and ended: an operator dismissed the Message that failed it.
    let word = match &state {
        State::Failed { .. } if record.ended => DISMISSED,
        _ => state.word(),
    };
    Some(WorkProcessInstance {
        instance: JourneyId::new(record.instance).to_string(),
        state: word.to_string(),
        waits_for: waits_for.to_string(),
        until_unix_nanos: until,
        correlations: instance
            .keys
            .iter()
            .map(|(set, key)| [running.set_name(*set).to_string(), shown(key)])
            .collect(),
        code,
        reason,
        failed_by,
        values: instance
            .values
            .iter()
            .map(|(name, value)| [name.clone(), value.clone()])
            .collect(),
        history: instance
            .history
            .iter()
            .map(|entry| InstanceHandled {
                at_unix_nanos: saturated(entry.at_unix_nanos),
                what: entry.what.word().to_string(),
                message: MessageId::new(entry.message).to_string(),
                journey: JourneyId::new(entry.journey).to_string(),
            })
            .collect(),
        earlier: instance.earlier,
        turns: record.turns,
        updated_unix_nanos: i64::try_from(record.updated_unix_nanos).unwrap_or(i64::MAX),
    })
}

/// A time in nanoseconds as a published record carries it.
fn saturated(nanos: i128) -> i64 {
    i64::try_from(nanos).unwrap_or(if nanos < 0 { i64::MIN } else { i64::MAX })
}
