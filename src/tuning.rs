//! `[tuning]`: every outward and hardware assumption a node runs by,
//! configured per cluster and per node in the cluster's `xmip.toml`
//! (ADR-0031, amendment 2026-10-03: *All these outwards, hardware
//! assumptions and calculations should be configurable per cluster and
//! node*), read into the execution tree as the node starts.
//!
//! The keys are declared once, here, in `xmip-core`'s settings shape
//! ([`TUNING`]), and the table is read through that declaration as a
//! technology reads a Location's settings: an unknown key, a value of the
//! wrong kind or outside its bounds is refused at startup phase 3 in words.
//! Every key may be left out; its default is the constant the code beside
//! it keeps, so a constant is a default and never the only value:
//!
//! ```toml
//! [tuning]
//! tcp_segment = 1460                          # transport::TCP_SEGMENT
//! segments = 44                               # ledger::SEGMENTS
//! receive_threads_per_hardware_thread = 2     # pool::RECEIVE_THREADS_PER_HARDWARE_THREAD
//! receive_idle = "1m"                         # pool::RECEIVE_IDLE
//! storage_timeout = "5s"                      # persist's client::TIMEOUT
//! storage_pass_over = "5s"                    # persist's client::PASS_OVER
//! ```

use std::time::Duration;

use configure::LocationSettings;
use persist::storage::client;
use serde::{Deserialize, Serialize};
use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

use crate::ledger::SEGMENTS;
use crate::pool::{Limits, RECEIVE_IDLE, RECEIVE_THREADS_PER_HARDWARE_THREAD};

/// The longest any `[tuning]` duration may be: an hour.
pub const LONGEST: Duration = Duration::from_secs(3600);

/// What `[tuning]` may say, each key's kind, bounds and default.
pub const TUNING: &Settings = &Settings {
    technology: "[tuning]",
    settings: &[
        Setting {
            name: "tcp_segment",
            kind: Kind::Integer {
                minimum: 536,
                maximum: 9000,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(transport::TCP_SEGMENT))),
            meaning: "The bytes one TCP segment carries on this node's network, a chunk's unit.",
            applies: Applies::Both,
        },
        Setting {
            name: "segments",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 1024,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(SEGMENTS))),
            meaning: "The TCP segments one chunk of a Stream written to the Ledger holds.",
            applies: Applies::Both,
        },
        Setting {
            name: "receive_threads_per_hardware_thread",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 64,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(
                RECEIVE_THREADS_PER_HARDWARE_THREAD,
            ))),
            meaning: "The most threads a Receive Location's pool runs per hardware thread.",
            applies: Applies::Both,
        },
        Setting {
            name: "receive_idle",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(RECEIVE_IDLE)),
            meaning: "How long a receive thread with nothing to do waits before it ends.",
            applies: Applies::Both,
        },
        Setting {
            name: "storage_timeout",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(client::TIMEOUT)),
            meaning: "What bounds each connect to and each read from a Storage node.",
            applies: Applies::Both,
        },
        Setting {
            name: "storage_pass_over",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(client::PASS_OVER)),
            meaning: "How long a Storage node that did not answer is asked only after the rest.",
            applies: Applies::Both,
        },
    ],
};

/// A count as the declaration writes its default.
#[allow(clippy::cast_possible_wrap)]
const fn as_integer(count: usize) -> i64 {
    count as i64
}

/// `[tuning]` read: every value the node runs by, defaults taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tuning {
    pub tcp_segment: usize,
    pub segments: usize,
    pub receive_threads_per_hardware_thread: usize,
    pub receive_idle: Duration,
    pub storage_timeout: Duration,
    pub storage_pass_over: Duration,
}

impl Default for Tuning {
    /// Every default: what a node whose configuration says nothing of its
    /// tuning runs by.
    fn default() -> Self {
        Self::read(&LocationSettings::default()).unwrap_or_else(|problems| {
            unreachable!("the declaration's own defaults are refused: {problems:?}")
        })
    }
}

impl Tuning {
    /// `table` read through [`TUNING`].
    ///
    /// # Errors
    /// Every key the declaration refuses, and every duration not above
    /// nothing or above [`LONGEST`], one sentence each.
    pub fn read(table: &LocationSettings) -> Result<Self, Vec<String>> {
        let read = TUNING
            .read(Applies::Both, &table.given())
            .map_err(|refused| {
                refused
                    .0
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })?;
        let count = |name| usize::try_from(read.integer(name)).unwrap_or(1);
        let mut problems = Vec::new();
        let mut duration = |name| {
            let duration = read.duration(name);
            if duration.is_zero() || duration > LONGEST {
                problems.push(format!(
                    "[tuning] reads \"{name}\" as a duration above nothing and at most an hour"
                ));
            }
            duration
        };
        let tuning = Self {
            tcp_segment: count("tcp_segment"),
            segments: count("segments"),
            receive_threads_per_hardware_thread: count("receive_threads_per_hardware_thread"),
            receive_idle: duration("receive_idle"),
            storage_timeout: duration("storage_timeout"),
            storage_pass_over: duration("storage_pass_over"),
        };
        if problems.is_empty() {
            Ok(tuning)
        } else {
            Err(problems)
        }
    }

    /// The size a Stream is written to the Ledger in: [`Self::segments`]
    /// TCP segments of [`Self::tcp_segment`] bytes.
    #[must_use]
    pub const fn chunk(&self) -> usize {
        self.segments * self.tcp_segment
    }

    /// A Receive Location's pool on this machine.
    #[must_use]
    pub fn receive(&self) -> Limits {
        Limits::receive(self.receive_threads_per_hardware_thread, self.receive_idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Result<Tuning, Vec<String>> {
        Tuning::read(&LocationSettings(text.parse().expect("TOML")))
    }

    #[test]
    fn the_declaration_is_sound_and_its_defaults_are_the_constants() {
        assert!(TUNING.problems().is_empty(), "{:?}", TUNING.problems());
        let tuning = Tuning::default();
        assert_eq!(tuning.chunk(), crate::ledger::CHUNK);
        assert_eq!(tuning.receive_idle, RECEIVE_IDLE);
        assert_eq!(tuning.storage_timeout, client::TIMEOUT);
        assert_eq!(tuning.storage_pass_over, client::PASS_OVER);
        assert_eq!(
            tuning.receive().most,
            RECEIVE_THREADS_PER_HARDWARE_THREAD * crate::pool::hardware_threads()
        );
    }

    #[test]
    fn what_a_node_says_is_what_it_runs_by() {
        let tuning = read(
            "tcp_segment = 1440\nsegments = 8\nreceive_threads_per_hardware_thread = 4\n\
             receive_idle = \"30s\"\nstorage_timeout = \"250ms\"\nstorage_pass_over = \"2s\"\n",
        )
        .expect("reads");
        assert_eq!(tuning.chunk(), 8 * 1440);
        assert_eq!(tuning.receive_idle, Duration::from_secs(30));
        assert_eq!(tuning.storage_timeout, Duration::from_millis(250));
        assert_eq!(tuning.storage_pass_over, Duration::from_secs(2));
        assert_eq!(tuning.receive().most, 4 * crate::pool::hardware_threads());
    }

    #[test]
    fn an_unknown_key_a_wrong_kind_and_a_value_out_of_bounds_are_refused_in_words() {
        let refused = read(
            "segments = 0\ntcp_segment = \"1460\"\ncolour = \"lime\"\nreceive_idle = \"0s\"\n\
             storage_timeout = \"2h\"\n",
        )
        .expect_err("refused");
        let said = refused.join("\n");
        for word in ["segments", "tcp_segment", "colour", "[tuning]"] {
            assert!(said.contains(word), "names {word}: {said}");
        }
        let durations = read("receive_idle = \"0s\"\nstorage_timeout = \"2h\"\n")
            .expect_err("refused")
            .join("\n");
        assert!(durations.contains("receive_idle") && durations.contains("storage_timeout"));
    }
}
