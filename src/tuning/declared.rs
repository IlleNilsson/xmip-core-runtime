//! What `[tuning]` may say: each key, its kind, its bounds and its default,
//! declared once (`super`).

use persist::storage::{client, standby};
use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

use crate::budget::{
    NODE_RECEIVE_THREADS_PER_HARDWARE_THREAD, RECEIVE_CHUNKS_PER_THREAD, SEND_CHUNKS_PER_THREAD,
};
use crate::ledger::SEGMENTS;
use crate::plane::remote::LOCAL_TIMEOUT;
use crate::pool::{RECEIVE_IDLE, RECEIVE_THREADS_PER_HARDWARE_THREAD};
use crate::receiving::{RECEIVE_BACKOFF, RECEIVE_DRAIN, RECEIVE_POLL, RECEIVE_SWEEP};
use crate::send_step::{
    FAILED_WINDOW, SEND_IDLE, SEND_LEASE, SEND_SCAN, SEND_THREADS_PER_HARDWARE_THREAD,
};
use crate::stream_share::STREAM_STALL;

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
            name: "receive_poll",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(RECEIVE_POLL)),
            meaning: "How long a polled Receive Location that found nothing rests.",
            applies: Applies::Both,
        },
        Setting {
            name: "receive_sweep",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(RECEIVE_SWEEP)),
            meaning: "How long a Receive Location whose far end tells it of a change rests \
                      when no word comes: its recovery sweep.",
            applies: Applies::Both,
        },
        Setting {
            name: "receive_backoff",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(RECEIVE_BACKOFF)),
            meaning: "How long a polled Receive Location rests after a failure that may mend.",
            applies: Applies::Both,
        },
        Setting {
            name: "receive_drain",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(RECEIVE_DRAIN)),
            meaning: "How long a stopping Receive Location goes on taking what its far end \
                      already let go of.",
            applies: Applies::Both,
        },
        Setting {
            name: "receive_handshake",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(transport::guard::HANDSHAKE)),
            meaning: "The most each read of a TLS handshake a Receive Location terminates \
                      waits on the client, apart from the Location's own wait.",
            applies: Applies::Both,
        },
        Setting {
            name: "node_receive_threads_per_hardware_thread",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 256,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(
                NODE_RECEIVE_THREADS_PER_HARDWARE_THREAD,
            ))),
            meaning: "The most arrivals the node carries at once across all its Receive \
                      Locations, per hardware thread.",
            applies: Applies::Both,
        },
        Setting {
            name: "receive_chunks_per_thread",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 4096,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(RECEIVE_CHUNKS_PER_THREAD))),
            meaning: "The chunks of Streams the node's carries hold at once, per arrival the \
                      node carries at once.",
            applies: Applies::Both,
        },
        Setting {
            name: "send_threads_per_hardware_thread",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 64,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(
                SEND_THREADS_PER_HARDWARE_THREAD,
            ))),
            meaning: "The most threads the Send pool runs per hardware thread.",
            applies: Applies::Both,
        },
        Setting {
            name: "send_idle",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(SEND_IDLE)),
            meaning: "How long a send thread with nothing to do waits before it ends.",
            applies: Applies::Both,
        },
        Setting {
            name: "send_lease",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(SEND_LEASE)),
            meaning: "How long a claim on a Journey holds before it lapses, unless renewed.",
            applies: Applies::Both,
        },
        Setting {
            name: "send_scan",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(SEND_SCAN)),
            meaning: "How often the queues this node sends are read for unclaimed Journeys.",
            applies: Applies::Both,
        },
        Setting {
            name: "failed_window",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 10_000,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(FAILED_WINDOW))),
            meaning: "The oldest failed Messages of each Send Port the node keeps and publishes.",
            applies: Applies::Both,
        },
        Setting {
            name: "send_chunks_per_thread",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 65_536,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(SEND_CHUNKS_PER_THREAD))),
            meaning: "The chunks of Messages the node's sends hold at once, per thread of the \
                      Send pool.",
            applies: Applies::Both,
        },
        Setting {
            name: "stream_stall",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(STREAM_STALL)),
            meaning: "How long a send taking no chunk of a Stream holds the sends of it ahead \
                      back before they leave it behind to read from Storage.",
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
        Setting {
            name: "storage_beat",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(standby::BEAT)),
            meaning: "How often a primary Storage node says it is there to an idle standby.",
            applies: Applies::Both,
        },
        Setting {
            name: "storage_silence",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(standby::SILENCE)),
            meaning: "How long a standby Storage node hears no primary before it is promoted.",
            applies: Applies::Both,
        },
        Setting {
            name: "storage_kept",
            kind: Kind::Integer {
                minimum: 1_048_576,
                maximum: 68_719_476_736,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(standby::KEPT))),
            meaning: "The bytes of each database's writes a primary keeps for a standby behind it.",
            applies: Applies::Both,
        },
        Setting {
            name: "local_timeout",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(LOCAL_TIMEOUT)),
            meaning: "How long a surface's call to this node's local endpoint waits for it.",
            applies: Applies::Both,
        },
    ],
};

/// A count as the declaration writes its default.
#[allow(clippy::cast_possible_wrap)]
const fn as_integer(count: usize) -> i64 {
    count as i64
}
