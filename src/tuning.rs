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
//! receive_poll = "1s"                         # receiving::RECEIVE_POLL
//! receive_sweep = "1s"                        # receiving::RECEIVE_SWEEP
//! receive_backoff = "5s"                      # receiving::RECEIVE_BACKOFF
//! receive_drain = "1s"                        # receiving::RECEIVE_DRAIN
//! receive_handshake = "5s"                    # transport::guard::HANDSHAKE
//! node_receive_threads_per_hardware_thread = 4  # budget::NODE_RECEIVE_THREADS_PER_HARDWARE_THREAD
//! receive_chunks_per_thread = 8               # budget::RECEIVE_CHUNKS_PER_THREAD
//! send_threads_per_hardware_thread = 2        # send_step::SEND_THREADS_PER_HARDWARE_THREAD
//! send_idle = "1m"                            # send_step::SEND_IDLE
//! send_lease = "30s"                          # send_step::SEND_LEASE
//! send_scan = "1s"                            # send_step::SEND_SCAN
//! failed_window = 100                         # send_step::FAILED_WINDOW
//! send_chunks_per_thread = 16                 # budget::SEND_CHUNKS_PER_THREAD
//! storage_timeout = "5s"                      # persist's client::TIMEOUT
//! storage_pass_over = "5s"                    # persist's client::PASS_OVER
//! storage_beat = "100ms"                      # persist's standby::BEAT
//! storage_silence = "1s"                      # persist's standby::SILENCE
//! storage_kept = 67108864                     # persist's standby::KEPT
//! local_timeout = "2s"                        # plane::remote::LOCAL_TIMEOUT
//! ```

use std::time::Duration;

use configure::LocationSettings;
use persist::storage::standby::Timings;
use serde::{Deserialize, Serialize};
use xcore::settings::Applies;

use crate::pool::Limits;
use crate::receiving::Pace;

mod declared;

pub use declared::TUNING;

/// The longest any `[tuning]` duration may be: an hour.
pub const LONGEST: Duration = Duration::from_secs(3600);

/// `[tuning]` read: every value the node runs by, defaults taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tuning {
    pub tcp_segment: usize,
    pub segments: usize,
    pub receive_threads_per_hardware_thread: usize,
    pub receive_idle: Duration,
    pub receive_poll: Duration,
    pub receive_sweep: Duration,
    pub receive_backoff: Duration,
    pub receive_drain: Duration,
    pub receive_handshake: Duration,
    pub node_receive_threads_per_hardware_thread: usize,
    pub receive_chunks_per_thread: usize,
    pub send_threads_per_hardware_thread: usize,
    pub send_idle: Duration,
    pub send_lease: Duration,
    pub send_scan: Duration,
    pub failed_window: usize,
    pub send_chunks_per_thread: usize,
    pub storage_timeout: Duration,
    pub storage_pass_over: Duration,
    pub storage_beat: Duration,
    pub storage_silence: Duration,
    pub storage_kept: usize,
    pub local_timeout: Duration,
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
            receive_poll: duration("receive_poll"),
            receive_sweep: duration("receive_sweep"),
            receive_backoff: duration("receive_backoff"),
            receive_drain: duration("receive_drain"),
            receive_handshake: duration("receive_handshake"),
            node_receive_threads_per_hardware_thread: count(
                "node_receive_threads_per_hardware_thread",
            ),
            receive_chunks_per_thread: count("receive_chunks_per_thread"),
            send_threads_per_hardware_thread: count("send_threads_per_hardware_thread"),
            send_idle: duration("send_idle"),
            send_lease: duration("send_lease"),
            send_scan: duration("send_scan"),
            failed_window: count("failed_window"),
            send_chunks_per_thread: count("send_chunks_per_thread"),
            storage_timeout: duration("storage_timeout"),
            storage_pass_over: duration("storage_pass_over"),
            storage_beat: duration("storage_beat"),
            storage_silence: duration("storage_silence"),
            storage_kept: count("storage_kept"),
            local_timeout: duration("local_timeout"),
        };
        if problems.is_empty() {
            Ok(tuning)
        } else {
            Err(problems)
        }
    }

    /// What bounds a node's dealings with Storage nodes, and a Storage
    /// node's with the others (`persist::storage::standby`).
    #[must_use]
    pub const fn storage(&self) -> Timings {
        Timings {
            beat: self.storage_beat,
            silence: self.storage_silence,
            timeout: self.storage_timeout,
            pass_over: self.storage_pass_over,
            kept: self.storage_kept,
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
        Limits::per_hardware_thread(self.receive_threads_per_hardware_thread, self.receive_idle)
    }

    /// The arrivals the node carries at once across all its Receive
    /// Locations, beside each Location's own pool: its most is the node's
    /// carry budget (`crate::budget::NodeBudget`).
    #[must_use]
    pub fn node_receive(&self) -> Limits {
        Limits::per_hardware_thread(
            self.node_receive_threads_per_hardware_thread,
            self.receive_idle,
        )
    }

    /// How a Receive Location rests before it asks a polled transport
    /// again.
    #[must_use]
    pub const fn pace(&self) -> Pace {
        Pace {
            poll: self.receive_poll,
            sweep: self.receive_sweep,
            backoff: self.receive_backoff,
            drain: self.receive_drain,
        }
    }

    /// The node's Send pool on this machine.
    #[must_use]
    pub fn send(&self) -> Limits {
        Limits::per_hardware_thread(self.send_threads_per_hardware_thread, self.send_idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{
        NODE_RECEIVE_THREADS_PER_HARDWARE_THREAD, RECEIVE_CHUNKS_PER_THREAD, SEND_CHUNKS_PER_THREAD,
    };
    use crate::plane::remote::LOCAL_TIMEOUT;
    use crate::pool::{RECEIVE_IDLE, RECEIVE_THREADS_PER_HARDWARE_THREAD};
    use crate::send_step::{
        FAILED_WINDOW, SEND_IDLE, SEND_LEASE, SEND_SCAN, SEND_THREADS_PER_HARDWARE_THREAD,
    };
    use persist::storage::{client, standby};

    fn read(text: &str) -> Result<Tuning, Vec<String>> {
        Tuning::read(&LocationSettings(text.parse().expect("TOML")))
    }

    #[test]
    fn the_declaration_is_sound_and_its_defaults_are_the_constants() {
        assert!(TUNING.problems().is_empty(), "{:?}", TUNING.problems());
        let tuning = Tuning::default();
        assert_eq!(tuning.chunk(), crate::ledger::CHUNK);
        assert_eq!(tuning.receive_idle, RECEIVE_IDLE);
        assert_eq!(tuning.pace(), Pace::default());
        assert_eq!(tuning.storage_timeout, client::TIMEOUT);
        assert_eq!(tuning.storage_pass_over, client::PASS_OVER);
        assert_eq!(
            (
                tuning.storage_beat,
                tuning.storage_silence,
                tuning.storage_kept
            ),
            (standby::BEAT, standby::SILENCE, standby::KEPT)
        );
        assert_eq!(tuning.local_timeout, LOCAL_TIMEOUT);
        assert_eq!(tuning.receive_handshake, transport::guard::HANDSHAKE);
        assert_eq!(
            tuning.receive().most,
            RECEIVE_THREADS_PER_HARDWARE_THREAD * crate::pool::hardware_threads()
        );
        assert_eq!(
            tuning.send().most,
            SEND_THREADS_PER_HARDWARE_THREAD * crate::pool::hardware_threads()
        );
        assert_eq!(
            (tuning.send_idle, tuning.send_lease, tuning.send_scan),
            (SEND_IDLE, SEND_LEASE, SEND_SCAN)
        );
        assert_eq!(tuning.failed_window, FAILED_WINDOW);
        assert_eq!(
            tuning.node_receive().most,
            NODE_RECEIVE_THREADS_PER_HARDWARE_THREAD * crate::pool::hardware_threads()
        );
        assert_eq!(
            (
                tuning.receive_chunks_per_thread,
                tuning.send_chunks_per_thread
            ),
            (RECEIVE_CHUNKS_PER_THREAD, SEND_CHUNKS_PER_THREAD)
        );
    }

    #[test]
    fn what_a_node_says_is_what_it_runs_by() {
        let tuning = read(
            "tcp_segment = 1440\nsegments = 8\nreceive_threads_per_hardware_thread = 4\n\
             receive_idle = \"30s\"\nstorage_timeout = \"250ms\"\nstorage_pass_over = \"2s\"\n\
             send_threads_per_hardware_thread = 3\nsend_idle = \"20s\"\nsend_lease = \"5s\"\n\
             send_scan = \"200ms\"\nreceive_poll = \"100ms\"\nreceive_backoff = \"2s\"\n\
             receive_sweep = \"3s\"\n\
             receive_drain = \"250ms\"\nlocal_timeout = \"500ms\"\nfailed_window = 12\n\
             node_receive_threads_per_hardware_thread = 5\nreceive_chunks_per_thread = 3\n\
             send_chunks_per_thread = 9\n",
        )
        .expect("reads");
        assert_eq!(tuning.failed_window, 12);
        assert_eq!(
            tuning.node_receive().most,
            5 * crate::pool::hardware_threads()
        );
        assert_eq!(
            (
                tuning.receive_chunks_per_thread,
                tuning.send_chunks_per_thread
            ),
            (3, 9)
        );
        assert_eq!(tuning.local_timeout, Duration::from_millis(500));
        assert_eq!(tuning.send().most, 3 * crate::pool::hardware_threads());
        assert_eq!(tuning.send_lease, Duration::from_secs(5));
        assert_eq!(tuning.send_scan, Duration::from_millis(200));
        assert_eq!(
            tuning.pace(),
            Pace {
                poll: Duration::from_millis(100),
                sweep: Duration::from_secs(3),
                backoff: Duration::from_secs(2),
                drain: Duration::from_millis(250),
            }
        );
        assert_eq!(tuning.chunk(), 8 * 1440);
        assert_eq!(tuning.receive_idle, Duration::from_secs(30));
        assert_eq!(tuning.storage_timeout, Duration::from_millis(250));
        assert_eq!(tuning.storage_pass_over, Duration::from_secs(2));
        assert_eq!(tuning.receive().most, 4 * crate::pool::hardware_threads());
    }

    #[test]
    fn an_unknown_key_a_wrong_kind_and_a_value_out_of_bounds_are_refused_in_words() {
        let refused = read(
            "segments = 0\ntcp_segment = \"1460\"\ncolor = \"lime\"\nreceive_idle = \"0s\"\n\
             storage_timeout = \"2h\"\n",
        )
        .expect_err("refused");
        let said = refused.join("\n");
        for word in ["segments", "tcp_segment", "color", "[tuning]"] {
            assert!(said.contains(word), "names {word}: {said}");
        }
        let durations = read("receive_idle = \"0s\"\nstorage_timeout = \"2h\"\n")
            .expect_err("refused")
            .join("\n");
        assert!(durations.contains("receive_idle") && durations.contains("storage_timeout"));
    }
}
