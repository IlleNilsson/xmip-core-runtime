//! What a node's pickup keeps under its one lock: each Subscription, its
//! standing as the administration database keeps it, how many its queue in
//! the Ledger holds, and how far the node has read that queue (ADR-0013,
//! amendment 2026-09-30; `runtime-model.md` section 9).
//!
//! Nothing here is the only copy of anything: what is held is in the
//! Ledger and what is paused in the administration database, both through
//! Xmip Storage. A restart reads both back; what is in memory is where the
//! node is in reading them.

use std::collections::BTreeSet;
use std::time::Instant;

use codec::cursor::Cursor;
use codec::field::{read_text, text};
use codec::form::{Form, from_numbered, numbered};
use codec::writer::ByteWriter;
use observe::{PauseState, Subscription as Published};

use crate::configured_subscription::ConfiguredSubscription;

/// A Subscription's standing: operator state, what is paused, by whom and
/// when (`deployment-model.md` section 7), in its one binary form as the
/// body of an operator record in the administration database.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Standing {
    pub(super) paused: bool,
    /// Who paused it; empty while it is active.
    pub(super) by: String,
    /// When its state began, in unix nanoseconds.
    pub(super) since_unix_nanos: i64,
}

/// The form's number, the first byte of every standing written.
const FORM: u8 = 1;

impl Standing {
    /// The standing in its one binary form, after the form's number.
    pub(super) fn record(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.by.len());
        numbered(&mut out, FORM, self);
        out
    }

    /// The standing `bytes` hold, and nothing after it, or why not.
    pub(super) fn from_record(bytes: &[u8]) -> Result<Self, String> {
        from_numbered(bytes, FORM, "a standing").map_err(|error| error.to_string())
    }
}

/// The standing's fields, `codec::form::Form`, without the form's number
/// [`Standing::record`] writes before them.
impl Form for Standing {
    fn write(&self, out: &mut Vec<u8>) {
        out.byte(u8::from(self.paused));
        text(out, &self.by);
        out.i64_be(self.since_unix_nanos);
    }

    fn read(cursor: &mut Cursor<'_>) -> codec::Result<Self> {
        Ok(Self {
            paused: cursor.byte()? != 0,
            by: read_text(cursor)?,
            since_unix_nanos: cursor.i64_be()?,
        })
    }
}

pub(super) struct State {
    pub(super) entries: Vec<Entry>,
}

pub(super) struct Entry {
    pub(super) configured: ConfiguredSubscription,
    /// Its queue in the Ledger, and its operator record's identifier.
    pub(super) queue: u128,
    pub(super) standing: Standing,
    /// How many its queue holds, kept in step with each write.
    pub(super) held: u64,
    pub(super) picked_up: u64,
    /// The place the next read of its queue starts from.
    pub(super) cursor: u64,
    /// Let go of to the node and not yet done with.
    pub(super) taken: BTreeSet<u64>,
    /// Whether its queue may hold what the node has not read.
    pub(super) pending: bool,
    /// Not read again before this, after a read that failed.
    pub(super) not_before: Option<Instant>,
}

impl Entry {
    /// Whether the node has its queue to read now.
    pub(super) fn ready(&self, now: Instant) -> bool {
        self.pending && !self.standing.paused && self.not_before.is_none_or(|at| at <= now)
    }
}

impl State {
    pub(super) fn index(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.configured.name() == name)
    }

    pub(super) fn ready(&self) -> bool {
        let now = Instant::now();
        self.entries.iter().any(|entry| entry.ready(now))
    }

    /// Every Subscription as the node at `node` publishes it, in the order
    /// routing asks them.
    pub(super) fn standing(&self, node: &str) -> Vec<Published> {
        self.entries
            .iter()
            .map(|entry| Published {
                node: node.to_string(),
                name: entry.configured.name().to_string(),
                application: entry.configured.application.clone(),
                filter: entry.configured.subscription.filter.text().to_string(),
                destination: entry.configured.destination(),
                send_ports: entry.configured.ports.clone(),
                file: entry.configured.file.clone(),
                configuration: entry.configured.entry.clone(),
                state: if entry.standing.paused {
                    PauseState::Paused
                } else {
                    PauseState::Active
                },
                by: entry.standing.by.clone(),
                picked_up: entry.picked_up,
                held: entry.held,
                since_unix_nanos: entry.standing.since_unix_nanos,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes a paused standing is written as, taken from the encoder
    /// that wrote them before the form was a `Form` (2026-11-13): the form
    /// may not change.
    const PAUSED: &str = "010116616e206f70657261746f7220e2809420c3a5c3a4c3b6fffffffffffffffd";

    #[test]
    fn a_standing_is_written_byte_for_byte_as_its_form_was() {
        let standing = Standing {
            paused: true,
            by: "an operator — åäö".to_string(),
            since_unix_nanos: -3,
        };
        assert_eq!(codec::hex::encode(&standing.record()), PAUSED);
        let bytes = codec::hex::decode(PAUSED).expect("hex");
        assert_eq!(Standing::from_record(&bytes), Ok(standing));
    }

    #[test]
    fn a_standing_comes_back_from_its_record_as_it_was() {
        let standing = Standing {
            paused: true,
            by: "an operator — åäö".to_string(),
            since_unix_nanos: -3,
        };
        let record = standing.record();
        assert_eq!(Standing::from_record(&record), Ok(standing));
        assert!(Standing::from_record(&record[..record.len() - 1]).is_err());
        assert!(Standing::from_record(&[record.as_slice(), &[0]].concat()).is_err());
    }
}
