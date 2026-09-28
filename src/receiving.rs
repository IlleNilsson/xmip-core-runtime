//! A Receive Location as a node runs it: its configuration, the gate it
//! holds and the transport built for it once, and the loop that takes what
//! arrives there through the whole message path until the node stops.

use std::sync::atomic::{AtomicBool, Ordering};

use authenticate::{Acceptance, Authenticator};
use configure::ConfiguredLocation;
use receive::{IdentityPolicy, ReceivedStream};
use stream::Stream;
use transport::Transport;
use xcore::StreamId;

use crate::message_path::{Carried, Runtime, carry};

/// What arrival asks of the Receive Location a Stream came in at: its name,
/// the closed set of mechanisms it accepts (ADR-0019 clause 1) and what it
/// does when the two identity layers disagree (clause 7). Read from the
/// Location's configuration once, as the node starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveGate {
    /// The Location's name, what an authorization attempt names.
    pub location: String,
    pub accept: Acceptance,
    pub identity: IdentityPolicy,
}

impl ReceiveGate {
    /// The gate `configured` declares, each accepted mechanism taken from the
    /// authenticator that verifies it.
    ///
    /// # Errors
    /// Every accepted mechanism no authenticator in `authenticators`
    /// verifies, one sentence each: a Location that accepts what nothing can
    /// verify is refused as the node starts, not at its first Stream.
    pub fn of(
        configured: &ConfiguredLocation,
        authenticators: &[&dyn Authenticator],
    ) -> Result<Self, Vec<String>> {
        let mut accept = Acceptance::closed();
        let mut problems = Vec::new();

        for name in &configured.accept.mechanism {
            match authenticators
                .iter()
                .map(|authenticator| authenticator.mechanism())
                .find(|mechanism| mechanism.name() == name)
            {
                Some(mechanism) => accept = accept.accepting(&mechanism),
                None => problems.push(format!(
                    "the Receive Location '{}' accepts '{name}', and no authenticator this \
                     node was built with verifies it",
                    configured.name
                )),
            }
        }

        if problems.is_empty() {
            Ok(Self {
                location: configured.name.clone(),
                accept,
                identity: IdentityPolicy::default(),
            })
        } else {
            Err(problems)
        }
    }

    /// A gate named `location` accepting `accept`, with the default identity
    /// policy.
    #[must_use]
    pub fn new(location: &str, accept: Acceptance) -> Self {
        Self {
            location: location.to_string(),
            accept,
            identity: IdentityPolicy::default(),
        }
    }
}

/// A Receive Location running: its configuration, its gate, and the
/// transport built for it once, which keeps its listener or session between
/// receives (`transport::kept`, `transport::serving`, `transport::pool`).
pub struct Receiving {
    pub configured: ConfiguredLocation,
    pub gate: ReceiveGate,
    pub transport: Box<dyn Transport + Send + Sync>,
}

impl Receiving {
    /// Take what arrives, and carry each Stream through the message path,
    /// until `stopping` is raised. `each` is told what became of every one.
    ///
    /// The loop asks the transport again after a receive that found nothing
    /// or failed in a way saying again may mend (a technology's wait running
    /// out is one), and looks at `stopping` between receives: a node stops
    /// once each Location's current receive returns, which the technology's
    /// own wait bounds. What arrived before that is carried whole.
    ///
    /// # Errors
    /// The transport failed in a way asking again will not mend: the
    /// Location stops, and says why.
    pub fn serve(
        &self,
        runtime: &Runtime<'_>,
        stopping: &AtomicBool,
        mut each: impl FnMut(&Carried),
    ) -> Result<(), String> {
        while !stopping.load(Ordering::Acquire) {
            match self.transport.receive() {
                Ok(arrivals) => {
                    for arrived in arrivals {
                        let stream = Stream::new(
                            StreamId::new(runtime.ids.next_u128()),
                            arrived.bytes,
                            None,
                        );
                        let received = ReceivedStream::new(stream, arrived.origin_uri);
                        each(&carry(runtime, &self.gate, received));
                    }
                }
                Err(failure) if failure.retryable => {}
                Err(failure) => {
                    return Err(format!(
                        "the Receive Location '{}' stopped: {}",
                        self.configured.name, failure.message
                    ));
                }
            }
        }

        Ok(())
    }
}
