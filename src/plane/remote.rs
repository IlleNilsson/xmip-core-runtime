//! The surface over a node's operate listener: a node on another machine,
//! reached at its operate address over gRPC inside Xmip's mutual TLS
//! (ADR-0014, amendment 2026-10-12), or a node on this one, reached at its
//! local endpoint (ADR-0014, amendment 2026-10-13) — written once here
//! and exported through `xmip_operate.h` section 17, so the command line,
//! the PowerShell module and the GUIs follow a node the same way.
//!
//! It reads the node's publication — the text its file holds, which every
//! surface reads with the one reader (section 8) — acts on what the node
//! publishes as the identity its certificate proves, and follows the node:
//! told when the publication advances, never asking again and again
//! (ADR-0052, amendment 2026-09-15). The follow holds a connection of its
//! own and is the one place a surface asks rather than is told — when the
//! node cannot be reached, nothing can tell it the node is back — and
//! recovers on its own loop: [`RETRY`], the last repeated, for a connection
//! lost and a first one that failed alike; every follower is told at once
//! when the node is lost, with why, and again when it is back (ADR-0052,
//! note of 2026-10-05). While it is lost, a read says so rather than wait
//! on a second try.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::json;

use xcore::wake::Wake;

use crate::plane::call::{ACT, PUBLICATION};
use crate::plane::deadline::{self, Deadline};
use crate::plane::follow;
use crate::plane::line::{Line, Reach, host_of};
use crate::plane::local;
use crate::plane::shared::Shared;

mod asking;
mod secret;

/// How long a drop waits for the follow to end once its read is
/// cancelled.
const FOLLOW_ENDS: Duration = Duration::from_secs(1);

/// How long a connect, a handshake or an answer waits on a node on another
/// machine.
pub const PATIENCE: Duration = Duration::from_secs(5);

/// How long the same waits on a node on this machine, at its local
/// endpoint, where a configuration's `[tuning] local_timeout` says nothing
/// (`deadline`).
pub const LOCAL_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the follow waits before each try to reach a node it lost or
/// never reached, the last repeated for as long as it follows.
pub const RETRY: [Duration; 4] = [
    Duration::ZERO,
    Duration::from_secs(2),
    Duration::from_secs(10),
    Duration::from_secs(30),
];

/// Whether the node answers, why not where it does not, the revision of
/// its publication, and how many times a follower has been told.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    pub reachable: bool,
    pub reason: String,
    pub revision: u64,
    pub told: u64,
}

/// What an act came to on the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Taken.
    Taken,
    /// Refused by the caller's role (ADR-0009).
    Denied,
    /// Refused by the node: no such node, thing or act now.
    Refused,
    /// No act the noun takes.
    Invalid,
    /// Xmip Storage did not answer the node; nothing changed.
    Failed,
}

impl Outcome {
    /// The outcome the node's word names: `taken`, `denied`, `invalid`,
    /// `failed`, and refused for any other.
    #[must_use]
    pub fn of(word: &str) -> Self {
        match word {
            "taken" => Self::Taken,
            "denied" => Self::Denied,
            "invalid" => Self::Invalid,
            "failed" => Self::Failed,
            _ => Self::Refused,
        }
    }
}

/// A node reached at its operate listener.
pub struct Remote {
    shared: Arc<Shared>,
    asking: Mutex<Option<Line>>,
    follow: Mutex<Option<JoinHandle<()>>>,
}

impl Remote {
    /// A surface over the node at `address`, `host:port`, presenting
    /// `identity` and trusting the node only where its certificate reaches
    /// the identity's anchors. Nothing is connected yet.
    ///
    /// # Errors
    ///
    /// An address that is no operate address, or an identity that does not
    /// make a client.
    pub fn open(address: &str, identity: &tls::Identity) -> Result<Self, String> {
        Self::retrying(address, identity, RETRY.to_vec())
    }

    /// The same, trying a lost node again on `retry`'s schedule: what a
    /// test shortens.
    ///
    /// # Errors
    ///
    /// As [`Remote::open`].
    pub fn retrying(
        address: &str,
        identity: &tls::Identity,
        retry: Vec<Duration>,
    ) -> Result<Self, String> {
        host_of(address)?;
        let client = identity.client().map_err(|failed| failed.message)?;
        let config = Arc::new(tls::alpn::offering(client, &[b"h2"]));
        let reach = Reach::Network {
            address: address.to_string(),
            config,
        };
        Ok(Self::reaching(address.to_string(), reach, PATIENCE, retry))
    }

    /// A surface over the node on this machine whose local endpoint is
    /// called `endpoint` (`plane::local`): no TLS, the operating system
    /// proving to the node who this side runs as; each call waiting at most
    /// `within` — where it is zero, what the node declared from its
    /// `[tuning] local_timeout`, else [`LOCAL_TIMEOUT`]
    /// (`deadline::declared`). Nothing is connected yet.
    ///
    /// # Errors
    ///
    /// An endpoint that is no name in the endpoints' folder.
    pub fn local(endpoint: &str, within: Duration) -> Result<Self, String> {
        Self::local_retrying(endpoint, within, RETRY.to_vec())
    }

    /// The same, trying a lost node again on `retry`'s schedule.
    ///
    /// # Errors
    ///
    /// As [`Remote::local`].
    pub fn local_retrying(
        endpoint: &str,
        within: Duration,
        retry: Vec<Duration>,
    ) -> Result<Self, String> {
        let path = local::place(endpoint)?;
        let address = path.display().to_string();
        let within = if within.is_zero() {
            deadline::declared(&path)
        } else {
            within
        };
        let remote = Self::reaching(address, Reach::Local(path), within, retry);
        deadline::kept(&remote.shared);
        Ok(remote)
    }

    fn reaching(address: String, reach: Reach, patience: Duration, retry: Vec<Duration>) -> Self {
        let retry = if retry.is_empty() {
            RETRY.to_vec()
        } else {
            retry
        };
        Self {
            shared: Arc::new(Shared {
                address,
                reach,
                patience,
                deadline: Deadline::default(),
                retry,
                state: Mutex::new(State {
                    reason: "not connected yet".to_string(),
                    ..State::default()
                }),
                told: Wake::new(),
                ending: Arc::new(AtomicBool::new(false)),
                connecting: AtomicBool::new(false),
                following: Mutex::new(None),
                asking: Mutex::new(None),
            }),
            asking: Mutex::new(None),
            follow: Mutex::new(None),
        }
    }

    /// The node's operate address, or its local endpoint's path.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.shared.address
    }

    /// The node's publication and its revision, as its file holds it.
    ///
    /// # Errors
    ///
    /// Why the node did not answer: unreachable, said at once while the
    /// follow is recovering it.
    pub fn publication(&self) -> Result<(u64, String), String> {
        let answer = self.asked(PUBLICATION, &json!({}))?;
        let revision = answer["revision"].as_u64().unwrap_or(0);
        let text = answer["publication"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Ok((revision, text))
    }

    /// `act` on the `noun` called `target` of the node at `node`, as the
    /// identity this side's certificate proves: what came of it, and the
    /// node's sentence.
    ///
    /// # Errors
    ///
    /// Why the node did not answer.
    pub fn act(
        &self,
        node: &str,
        noun: &str,
        target: &str,
        act: &str,
    ) -> Result<(Outcome, String), String> {
        let message = json!({ "node": node, "noun": noun, "target": target, "act": act });
        let answer = self.asked(ACT, &message)?;
        let said = answer["said"].as_str().unwrap_or_default().to_string();
        Ok((
            Outcome::of(answer["outcome"].as_str().unwrap_or_default()),
            said,
        ))
    }

    /// The state once a follower has been told more than `seen` times, or
    /// after `within`: the follow starts with the first wait and runs while
    /// this lives.
    #[must_use]
    pub fn wait(&self, seen: u64, within: Duration) -> State {
        self.followed();
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.shared
            .told
            .wait_timeout_while(&self.shared.state, state, within, |state| {
                state.told <= seen && !self.shared.ending()
            })
            .0
            .clone()
    }

    /// The state now.
    #[must_use]
    pub fn state(&self) -> State {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn followed(&self) {
        let mut follow = self.follow.lock().unwrap_or_else(PoisonError::into_inner);
        if follow.is_none() {
            let shared = Arc::clone(&self.shared);
            *follow = std::thread::Builder::new()
                .name("xmip-operate-follow".to_string())
                .spawn(move || follow::run(&shared))
                .ok();
        }
    }

    /// One call on the asking connection, made again once on a fresh one
    /// where the connection held was lost meanwhile. A node that does not
    /// answer is told to every follower and from then on recovered by the
    /// follow's loop, which this starts: a read meanwhile says unreachable
    /// at once rather than try again (ADR-0052, note of 2026-10-05).
    fn asked(
        &self,
        method: &str,
        message: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let state = self.state();
        if !state.reachable && state.told > 0 {
            return Err(format!(
                "{} unreachable: {}",
                self.shared.address, state.reason
            ));
        }
        self.called(method, message).map_err(|(lost, why)| {
            if !lost {
                return why;
            }
            self.shared.tell(|state| {
                state.reachable = false;
                state.reason.clone_from(&why);
            });
            self.followed();
            format!("{} unreachable: {why}", self.shared.address)
        })
    }
}

impl Remote {
    /// End the follow and wake every wait, from any thread, while a call
    /// may still be in flight on another: what a binding asks before it
    /// frees the handle.
    pub fn end(&self) {
        // Every line reads through `net::watched`, which sees this within
        // a WATCH; every wait is woken now.
        self.shared.ending.store(true, Ordering::SeqCst);
        {
            let _state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.shared.told.notify_all();
        }
        // A line on a pipe has no timeout to look between: its read ends.
        self.shared.cancel();
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        self.end();
        let follow = self
            .follow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        // A follow in a connect is not waited for: it ends when the connect
        // does, holding nothing of this side's but what it shares.
        let Some(follow) = follow else {
            return;
        };
        let until = std::time::Instant::now() + FOLLOW_ENDS;
        while !follow.is_finished() && std::time::Instant::now() < until {
            if self.shared.connecting.load(Ordering::SeqCst) {
                return;
            }
            self.shared.cancel();
            std::thread::sleep(Duration::from_micros(200));
        }
        if follow.is_finished() {
            let _ = follow.join();
        }
    }
}
