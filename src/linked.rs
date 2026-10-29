//! The technologies a program was built with, handed to the node it starts.
//!
//! The runtime names no technology: `architecture.toml` lets a platform
//! service depend on no technology repository. The program that starts a node
//! does — `xmip-service` links the technologies a deployment needs by build
//! feature (ADR-0018, amendment 2026-09-26), a test links the ones it
//! exercises — and hands them over here. The node takes from them only what
//! its configuration names (ADR-0025): a Location's transport, a filter's
//! route technology, an accepted mechanism's authenticator.
//!
//! A module loaded from its library instead is named in the configuration's
//! `[[modules]]`, and the node opens it through the C ABI (ADR-0057); this is
//! the other way a Module is in a process.

use std::path::Path;
use std::sync::Arc;

use authenticate::Authenticator;
use authorize::Authorizer;
use configure::ConfiguredLocation;
use identify::{MessageIdentifier, TransportIdentifier};
use persist::storage::XmipStorage;
use persist::{Engine, PersistError};
use route::Source;
use secret::KeyStore;
use transport::{Configured, Guard, NodeLocation, Pinned, Secured, Transport};

use crate::receiving::ReceiveGate;
use xaudit::program_audit::ProgramAudit;
use xcore::settings::{Applies, Given, Settings};

/// A transport built for one Location: the one kept instance its receives or
/// sends go through.
pub type Opened = transport::Result<Box<dyn Transport + Send + Sync>>;

/// The node a Location's transport is built on: its location, the guard
/// its receives terminate TLS with, where its configuration gives one
/// (`crate::receive_certificate`), the keys its far ends are held to,
/// pinned on first contact under its data directory (`PINNED`), and the
/// secret the Location names, read from the node's Xmip Storage as it
/// connects (ADR-0019, amendment 2026-10-29).
pub type OnNode<'a> = (
    &'a NodeLocation,
    Option<&'a Guard>,
    &'a Arc<Pinned>,
    Option<Secured>,
);

/// The file under a node's data directory its far ends' pinned keys are
/// kept in (`transport::pinned`; ADR-0019, amendment 2026-10-28).
pub const PINNED: &str = "pinned-keys";

/// How a Location's transport is built: its address, the side it serves,
/// what its settings table gave, and the node it is built on.
pub type Open = fn(&str, Applies, &[(String, Given)], OnNode<'_>) -> Opened;

/// A transport technology linked into the program: its declaration, the
/// schemes a Location is entered with to choose it, and the one way a
/// Location builds it (`transport::Configured::open`).
pub struct LinkedTransport {
    settings: &'static Settings,
    schemes: &'static [&'static str],
    own_terms: fn(&str) -> &str,
    open: Open,
    waits: Waits,
}

/// Whether a Receive Location of a technology, at an address and with its
/// settings, waits for what is sent to it rather than going to look.
pub type Waits = fn(&str, &[(String, Given)]) -> bool;

impl LinkedTransport {
    /// The technology `T`, as its own declaration and constructor say.
    #[must_use]
    pub fn of<T: Configured + Send + Sync + 'static>() -> Self {
        Self {
            waits: waits::<T>,
            ..Self::opened_by::<T>(open::<T>)
        }
    }

    /// The technology `T`, as its own declaration says, built by `open`
    /// and said to wait for what is sent to it.
    #[must_use]
    pub fn opened_by<T: Configured>(open: Open) -> Self {
        Self {
            settings: T::SETTINGS,
            schemes: T::SCHEMES,
            own_terms: T::own_terms,
            open,
            waits: always,
        }
    }

    /// `location`'s address in this technology's own terms
    /// (`transport::Configured::own_terms`): what a send names as its
    /// target.
    #[must_use]
    pub fn target<'a>(&self, location: &'a ConfiguredLocation) -> &'a str {
        (self.own_terms)(&location.address)
    }

    /// The schemes a Location's address is entered with to choose it.
    #[must_use]
    pub const fn schemes(&self) -> &'static [&'static str] {
        self.schemes
    }

    /// Whether `location`'s address chooses this technology: the scheme it
    /// is entered with ([`ConfiguredLocation::scheme`]) is one it declares.
    #[must_use]
    pub fn chosen_by(&self, location: &ConfiguredLocation) -> bool {
        self.schemes.contains(&location.scheme().as_str())
    }

    /// Its module name.
    #[must_use]
    pub const fn technology(&self) -> &'static str {
        self.settings.technology
    }

    /// The settings it declares.
    #[must_use]
    pub const fn settings(&self) -> &'static Settings {
        self.settings
    }

    /// Build it for `location`, on `side`, on the node `on`.
    ///
    /// # Errors
    /// What the technology refuses of the Location's address or settings,
    /// of returning what the node held before it last stopped, or of the
    /// guard: a Location terminating TLS on a node with no `receive`
    /// certificate.
    pub fn open(&self, location: &ConfiguredLocation, side: Applies, on: OnNode<'_>) -> Opened {
        (self.open)(&location.address, side, &location.settings.given(), on)
    }

    /// Whether a Receive Location of it at `location` waits for what is
    /// sent to it — listens — rather than going to look, as the technology
    /// says of itself (`transport::Waiting`): what an environment opens its
    /// firewall for. One it refuses to build is said to, so nothing a
    /// configuration might listen on goes unsaid.
    #[must_use]
    pub fn waits(&self, location: &ConfiguredLocation) -> bool {
        (self.waits)(&location.address, &location.settings.given())
    }
}

/// Whether `T`, built for a Receive Location at `address`, waits.
fn waits<T: Configured + Send + Sync + 'static>(address: &str, given: &[(String, Given)]) -> bool {
    T::open(address, Applies::Receive, given).map_or(true, |built| {
        matches!(built.waiting(), transport::Waiting::Waits(_))
    })
}

/// Said to wait, where nothing else is known.
const fn always(_: &str, _: &[(String, Given)]) -> bool {
    true
}

/// `T` built from a Location and given its node, once, as it is built (the
/// owner, 2026-10-03; `transport::Configured::on_node`), the keys its far
/// ends are held to (`transport::Configured::pinned_by`), the guard its
/// receives terminate TLS with (`transport::Configured::guarded_by`), and
/// the secret its Location names (`transport::Configured::secured_by`).
pub(crate) fn open<T: Configured + Send + Sync + 'static>(
    address: &str,
    side: Applies,
    given: &[(String, Given)],
    (node, guard, pins, secured): OnNode<'_>,
) -> Opened {
    let built = T::open(address, side, given)?
        .on_node(node)?
        .pinned_by(pins)
        .guarded_by(guard)?;
    Ok(Box::new(match secured {
        Some(secured) => built.secured_by(secured)?,
        None => built,
    }))
}

/// How an engine opens its store at a place: a directory for `RocksDB`, a
/// file for `SQLite`.
pub type OpenEngine = fn(&Path) -> Result<Box<dyn Engine>, PersistError>;

/// An engine linked into the program, by its module name: the runtime
/// database's, `xmip-core-persist-rocksdb` (`configure::store::ENGINE`),
/// or the administration database's, `xmip-core-persist-sqlite`
/// (`crate::storage::ADMINISTRATION`) — the two engines of an embedded
/// Storage node (ADR-0015, amendment 2026-10-01).
pub struct LinkedEngine {
    technology: &'static str,
    open: OpenEngine,
}

impl LinkedEngine {
    /// The engine called `technology`, opened by `open`.
    #[must_use]
    pub const fn new(technology: &'static str, open: OpenEngine) -> Self {
        Self { technology, open }
    }

    /// Its module name.
    #[must_use]
    pub const fn technology(&self) -> &'static str {
        self.technology
    }

    /// Open it at `place`.
    ///
    /// # Errors
    /// The engine's refusal: the place cannot be opened, or another
    /// process holds it.
    pub fn open(&self, place: &Path) -> Result<Box<dyn Engine>, PersistError> {
        (self.open)(place)
    }
}

/// How a key store is built over the place it keeps its keys.
pub type OpenKeyStore = fn(&Path) -> Box<dyn KeyStore>;

/// A key store linked into the program (`xmip-core-secret`'s technologies),
/// by the module name a node's `[store]` names it by.
pub struct LinkedKeyStore {
    technology: &'static str,
    open: OpenKeyStore,
}

impl LinkedKeyStore {
    /// The key store called `technology`, built by `open`.
    #[must_use]
    pub const fn new(technology: &'static str, open: OpenKeyStore) -> Self {
        Self { technology, open }
    }

    /// Its module name.
    #[must_use]
    pub const fn technology(&self) -> &'static str {
        self.technology
    }

    /// Build it over `keys`.
    #[must_use]
    pub fn open(&self, keys: &Path) -> Box<dyn KeyStore> {
        (self.open)(keys)
    }
}

/// The Locations a node starts, as a policy set up from them reads them:
/// each Receive Location as its gate declares it
/// (`crate::receiving::ReceiveGate`), and each Send Location by its name.
#[derive(Clone, Copy, Debug)]
pub struct Started<'a> {
    pub receive: &'a [ReceiveGate],
    pub send: &'a [ConfiguredLocation],
}

/// How an authorization policy is set up from the Locations a node starts
/// ([`Started`]): what the `location` policy admits is what each Receive
/// Location declares it accepts, and each Send Location the node starts
/// (ADR-0050 section 5; the owner, 2026-10-19).
pub type LocationPolicy = fn(Started<'_>) -> Box<dyn Authorizer>;

/// Everything a program linked that a node may use.
///
/// Each list is what the program was built with, not what the node runs: the
/// node takes the transports its Locations name, the route technologies its
/// filters name and the authenticators its Receive Locations accept. The
/// policies and identifiers are each consulted at every gate, so every one
/// linked is taken — no configuration selects among them yet — and each of
/// [`Linked::location_policies`] is set up from the Locations the node
/// starts.
#[derive(Default)]
pub struct Linked {
    pub transports: Vec<LinkedTransport>,
    /// Route technologies, each the source a filter's prefix names
    /// (ADR-0046).
    pub sources: Vec<Box<dyn Source>>,
    pub authenticators: Vec<Box<dyn Authenticator>>,
    pub policies: Vec<Box<dyn Authorizer>>,
    /// Policies set up from the Locations the node starts, added to
    /// [`Linked::policies`] as it starts.
    pub location_policies: Vec<LocationPolicy>,
    pub transport_identifiers: Vec<Box<dyn TransportIdentifier>>,
    pub message_identifiers: Vec<Box<dyn MessageIdentifier>>,
    /// The runtime database's engine, where the program was built with
    /// it: with [`Linked::administration`], what a node that is its own
    /// Storage node opens Xmip Storage over (`crate::storage`, ADR-0018,
    /// amendments 2026-09-30 and 2026-10-01).
    pub engine: Option<LinkedEngine>,
    /// The administration database's engine, where the program was built
    /// with it, and the audit database's, a store of its own: with
    /// [`Linked::engine`], what a node that is its own Storage node opens
    /// Xmip Storage over (`crate::storage`).
    pub administration: Option<LinkedEngine>,
    /// The key stores the program was built with, one of which wraps an
    /// embedded Storage node's data keys.
    pub key_stores: Vec<LinkedKeyStore>,
    /// Xmip Storage the program opened itself — a test's Storage node, or a
    /// client of the Storage nodes the program reaches with the identity it
    /// presents — which the node writes the Ledger through instead of the
    /// one its configuration leads to (`crate::storage`).
    pub storage: Option<Arc<dyn XmipStorage>>,
    /// The program's own audit, where an operator's act on a Subscription
    /// is recorded (ADR-0062).
    pub audit: Option<ProgramAudit>,
}

impl Linked {
    /// The linked transport `location`'s address chooses, by the scheme it
    /// is entered with ([`ConfiguredLocation::scheme`]).
    #[must_use]
    pub fn transport(&self, location: &ConfiguredLocation) -> Option<&LinkedTransport> {
        self.transports
            .iter()
            .find(|linked| linked.chosen_by(location))
    }

    /// Every linked transport's declaration, by each scheme it is chosen
    /// with: what `configure` holds a Location's settings to.
    #[must_use]
    pub fn declarations(&self) -> configure::Declarations {
        self.transports
            .iter()
            .flat_map(|linked| {
                linked
                    .schemes
                    .iter()
                    .map(|scheme| (*scheme, linked.settings))
            })
            .collect()
    }

    /// One sentence for each scheme two linked transports both declare:
    /// an address entered with it could choose either.
    #[must_use]
    pub fn scheme_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for (at, first) in self.transports.iter().enumerate() {
            for second in &self.transports[at + 1..] {
                for scheme in first.schemes.iter().filter(|s| second.schemes.contains(s)) {
                    problems.push(format!(
                        "the scheme '{scheme}' is declared by both {} and {}",
                        first.technology(),
                        second.technology()
                    ));
                }
            }
        }
        problems
    }

    /// The linked key store a `[store]` names.
    #[must_use]
    pub fn key_store(&self, technology: &str) -> Option<&LinkedKeyStore> {
        self.key_stores
            .iter()
            .find(|linked| linked.technology() == technology)
    }
}
