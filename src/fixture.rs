//! The gates' stand-ins the runtime's tests run a node with, and Xmip
//! Storage that fails on demand ([`Failing`]), once: its unit tests and its
//! integration tests (`tests/ledger`) both take them from here. Behind the
//! `test-support` feature, which only a dev-dependency enables, so they are
//! never in a production build.

use std::sync::{Arc, Mutex, PoisonError};

use authenticate::{AuthenticateError, Authenticator};
use authorize::{Attempt, Authorizer, Decision};
use context::{IdentityFacts, Verified};
use identify::Presented;
use persist::storage::XmipStorage;
use xcore::{Layer, Mechanism, mechanism};

pub mod authority;
mod drain;
mod failing;

pub use authority::Authority;
pub use drain::Drain;
pub use failing::{Failing, Interleaved, Operation};

/// Verifies every claim of its mechanism with the verdict it was given.
pub struct Always(pub Mechanism, pub Verified);

impl Always {
    /// ADR-0019 clause 7: where nothing was presented, the circumstance is
    /// the transport identity, and is authenticated as that — claimed,
    /// since nothing cryptographic stands behind a loopback connection.
    #[must_use]
    pub fn circumstance() -> Self {
        Self(mechanism::circumstance(), Verified::Claimed)
    }
}

impl Authenticator for Always {
    fn mechanism(&self) -> Mechanism {
        self.0.clone()
    }

    fn verify(&self, _presented: &Presented) -> Result<Verified, AuthenticateError> {
        Ok(self.1)
    }
}

/// Allows what the gates authenticated. The estate's real policies are
/// technologies; this is the smallest thing that is not "nothing
/// configured", which permits nothing.
pub struct Open;

impl Authorizer for Open {
    fn name(&self) -> &str {
        "open"
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, _identity: &IdentityFacts, _attempt: &Attempt) -> Option<Decision> {
        Some(Decision::Allowed)
    }
}

/// What a test's far end answers a send of these bytes.
pub type Answer = Box<dyn Fn(&[u8]) -> transport::Result<()> + Send + Sync>;

/// A Send Location's far end in a test: every Stream it took, in the order
/// it took them, the deduplication key every send carried, and the answer
/// it gives each send.
pub struct FarEnd {
    taken: Arc<Mutex<Vec<Vec<u8>>>>,
    keys: Arc<Mutex<Vec<String>>>,
    answer: Answer,
}

impl FarEnd {
    /// A far end answering as `answer` says, and what it takes.
    #[must_use]
    pub fn answering(answer: Answer) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let taken = Arc::new(Mutex::new(Vec::new()));
        let far = Self {
            taken: Arc::clone(&taken),
            keys: Arc::default(),
            answer,
        };
        (far, taken)
    }

    /// The deduplication key of every send it was asked, taken or not, in
    /// the order asked.
    #[must_use]
    pub fn keys(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.keys)
    }

    /// The Send Location `name` sending to it.
    #[must_use]
    pub fn at(self, name: &str) -> crate::sending::Sending {
        crate::sending::Sending {
            configured: configure::ConfiguredLocation {
                name: name.to_string(),
                start: true,
                transport: "far-end".to_string(),
                address: "far-end".to_string(),
                credentials: None,
                contract: None,
                settings: configure::LocationSettings::default(),
                contract_settings: configure::LocationSettings::default(),
                accept: configure::Accept::default(),
                prepare: Vec::new(),
                transform: None,
                promote: None,
                demote: None,
            },
            chain: send::SendChain::default(),
            transport: Box::new(self),
        }
    }
}

impl transport::Transport for FarEnd {
    fn name(&self) -> &'static str {
        "far-end"
    }

    fn directions(&self) -> transport::Directions {
        transport::Directions::SEND
    }

    fn receive_up_to(&self, _most: usize) -> transport::Result<Vec<transport::Arrived>> {
        Ok(Vec::new())
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered("it receives nothing")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("it looks and finds nothing")
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered("a test's far end keeps every body it takes whole")
    }

    fn send_from(&self, _target: &str, outgoing: transport::Outgoing<'_>) -> transport::Result<()> {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(outgoing.key().unwrap_or_default().to_string());
        let bytes: &[u8] = &outgoing.gather()?;
        (self.answer)(bytes)?;
        self.taken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(bytes.to_vec());
        Ok(())
    }
}

/// The scope of a node the test cluster does not have
/// (`configure::fixture::TestCluster::absent`): what a test asks of a node
/// no process runs, by a name taken from the cluster and never invented.
#[must_use]
pub fn absent_node() -> String {
    let cluster = configure::fixture::test_cluster();
    format!("{}/node/{}", cluster.scope(), cluster.absent())
}

/// The node budget the default `[tuning]` gives, for a test's Runtime to
/// borrow for the test's length.
#[must_use]
pub fn node_budget() -> &'static crate::budget::NodeBudget {
    Box::leak(Box::new(crate::budget::NodeBudget::of(
        &crate::tuning::Tuning::default(),
    )))
}

/// A send step over `storage` of the test cluster's first node, run by the
/// default `[tuning]`, for a test's Runtime to borrow for the test's
/// length: one that dispatches only where the test runs it.
#[must_use]
pub fn send_step(storage: &Arc<dyn XmipStorage>) -> &'static crate::send_step::SendStep {
    send_step_of(
        storage,
        &configure::fixture::test_cluster().node_scope(0),
        &crate::tuning::Tuning::default(),
    )
}

/// A Work Process step over `storage` of the test cluster's first node,
/// running no Work Process.
#[must_use]
pub fn work_step(storage: &Arc<dyn XmipStorage>) -> &'static crate::work_step::WorkStep {
    let cluster = configure::fixture::test_cluster();
    Box::leak(Box::new(crate::work_step::WorkStep::new(
        (&cluster.scope(), &cluster.node_scope(0)),
        Arc::clone(storage),
        crate::pool::Limits::per_hardware_thread(1, std::time::Duration::from_secs(60)),
        None,
        Vec::new(),
    )))
}

/// A send step over `storage` of the test cluster's node at `node`
/// (`xmip:///<cluster>/node/<name>`), run as `tuning` says.
#[must_use]
pub fn send_step_of(
    storage: &Arc<dyn XmipStorage>,
    node: &str,
    tuning: &crate::tuning::Tuning,
) -> &'static crate::send_step::SendStep {
    let cluster = configure::fixture::test_cluster().scope();
    Box::leak(Box::new(crate::send_step::SendStep::new(
        (&cluster, node),
        Arc::clone(storage),
        tuning,
        None,
    )))
}
