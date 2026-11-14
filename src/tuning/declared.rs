//! What `[tuning]` may say: each key, its kind, its bounds and its default,
//! declared once (`super`).

use std::time::Duration;

use persist::storage::{client, standby};
use schedule::pace::{RECEIVE_BACKOFF, RECEIVE_DRAIN, RECEIVE_POLL, RECEIVE_SWEEP};
use xcluster::timing;
use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

use crate::act_watch::OPERATE_ACT;
use crate::budget::{
    NODE_RECEIVE_THREADS_PER_HARDWARE_THREAD, RECEIVE_CHUNKS_PER_THREAD, SEND_CHUNKS_PER_THREAD,
};
use crate::ledger::SEGMENTS;
use crate::plane::limits;
use crate::plane::remote::LOCAL_TIMEOUT;
use crate::pool::{RECEIVE_IDLE, RECEIVE_THREADS_PER_HARDWARE_THREAD};
use crate::secure_listener::HANDSHAKE_WITHIN;
use crate::send_step::{
    FAILED_WINDOW, SEND_IDLE, SEND_LEASE, SEND_SCAN, SEND_THREADS_PER_HARDWARE_THREAD,
};
use crate::stream_share::STREAM_STALL;
use crate::work_step::{WORK_SCAN, WORK_THREADS_PER_HARDWARE_THREAD};

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
            meaning: "How long a claim on a Message holds before it lapses, unless renewed.",
            applies: Applies::Both,
        },
        Setting {
            name: "send_scan",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(SEND_SCAN)),
            meaning: "How often the queues this node sends are read for unclaimed Messages, \
                      apart from as soon as another node puts one in: the bound on one wait.",
            applies: Applies::Both,
        },
        Setting {
            name: "work_threads_per_hardware_thread",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 64,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(
                WORK_THREADS_PER_HARDWARE_THREAD,
            ))),
            meaning: "The most threads the Work pool runs per hardware thread, and so the most \
                      turns the Work Process step holds at once.",
            applies: Applies::Both,
        },
        Setting {
            name: "work_scan",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(WORK_SCAN)),
            meaning: "How often the queues of the Work Processes this node runs are read, apart \
                      from as soon as another node puts a Message in one: the bound on one wait.",
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
            meaning: "How long a Storage node waits to hear from another, and how often a \
                      primary asks the others what they are.",
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
            name: "storage_wait",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(persist::storage::HOLD)),
            meaning: "The longest a Storage node holds one node's wait on its queues before it \
                      answers that nothing moved.",
            applies: Applies::Both,
        },
        Setting {
            name: "storage_unwaited",
            kind: Kind::Integer {
                minimum: 0,
                maximum: 4_194_304,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(persist::storage::UNWAITED))),
            meaning: "How many of what no node waits on now a Storage node keeps where its writer \
                      left it, so a wait on one again reads nothing; past it the longest unwaited \
                      is let go and read again when next waited on.",
            applies: Applies::Both,
        },
        Setting {
            name: "local_timeout",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(LOCAL_TIMEOUT)),
            meaning: "How long a surface's call to this node's local endpoint waits for it.",
            applies: Applies::Both,
        },
        Setting {
            name: "operate_connections",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 65_536,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(limits::CONNECTIONS))),
            meaning: "The connections each operate listener of this node answers at once; one \
                      past them is closed as it is accepted.",
            applies: Applies::Both,
        },
        Setting {
            name: "operate_handshakes",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 4096,
            },
            presence: Presence::Default(Fixed::Integer(as_integer(limits::HANDSHAKES))),
            meaning: "The connections to the operate listener that may be in their handshake \
                      at once; one past them is closed as it is accepted.",
            applies: Applies::Both,
        },
        Setting {
            name: "operate_handshake",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(HANDSHAKE_WITHIN)),
            meaning: "How long a handshake with the operate listener may take in all, however \
                      it is read.",
            applies: Applies::Both,
        },
        Setting {
            name: "operate_act",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(OPERATE_ACT)),
            meaning: "How long this node, as the door an operator's act is asked at, holds \
                      the asker's call while the node it is asked of takes it; past it the \
                      asker is told the act is asked, and its node takes it as soon as it runs.",
            applies: Applies::Both,
        },
        sync(
            "sync_beat",
            timing::BEAT,
            "How often an idle sync link says it is alive.",
        ),
        sync(
            "sync_silence",
            timing::SILENCE,
            "How long a sync link may say nothing before it is taken for broken.",
        ),
        sync(
            "sync_handshake",
            timing::HANDSHAKE,
            "The most a sync link's TLS handshake waits on the other node.",
        ),
        sync(
            "sync_watch",
            timing::WATCH,
            "How often a sync link waiting to read looks whether its side is ending.",
        ),
        sync(
            "sync_connect",
            timing::CONNECT,
            "The most a connect to another member's sync listener waits.",
        ),
        sync(
            "sync_write",
            timing::WRITE,
            "The most a sync link's write waits on a node that does not read.",
        ),
        sync(
            "sync_retry",
            timing::RETRY,
            "The first wait before a member that could not be reached is tried again, \
             doubled each time it is not.",
        ),
        sync(
            "sync_retry_most",
            timing::RETRY_MOST,
            "The longest wait before a member that could not be reached is tried again.",
        ),
        sync(
            "sync_follow",
            timing::FOLLOW,
            "How often the cluster's members are read again when nothing says they changed.",
        ),
    ],
};

/// A duration of the sync plane (`xcluster::sync`), its default the
/// constant beside the plane (`xcluster::timing`).
const fn sync(name: &'static str, default: Duration, meaning: &'static str) -> Setting {
    Setting {
        name,
        kind: Kind::Duration,
        presence: Presence::Default(Fixed::Duration(default)),
        meaning,
        applies: Applies::Both,
    }
}

/// A count as the declaration writes its default.
#[allow(clippy::cast_possible_wrap)]
const fn as_integer(count: usize) -> i64 {
    count as i64
}
