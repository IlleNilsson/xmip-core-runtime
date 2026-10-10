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
use transport::{Configured, NodeLocation, Transport};
use xaudit::program_audit::ProgramAudit;
use xcore::settings::{Applies, Given, Settings};

/// A transport built for one Location: the one kept instance its receives or
/// sends go through.
pub type Opened = transport::Result<Box<dyn Transport + Send + Sync>>;

/// How a Location's transport is built: its address, the side it serves,
/// what its settings table gave, and the node it is built on.
pub type Open = fn(&str, Applies, &[(String, Given)], &NodeLocation) -> Opened;

/// A transport technology linked into the program: its declaration, and the
/// one way a Location builds it (`transport::Configured::open`).
pub struct LinkedTransport {
    settings: &'static Settings,
    open: Open,
}

impl LinkedTransport {
    /// The technology `T`, as its own declaration and constructor say.
    #[must_use]
    pub fn of<T: Configured + Send + Sync + 'static>() -> Self {
        Self::new(T::SETTINGS, open::<T>)
    }

    /// A technology declared by `settings` and built by `open`.
    #[must_use]
    pub const fn new(settings: &'static Settings, open: Open) -> Self {
        Self { settings, open }
    }

    /// Its module name, what a Location's `transport` names it by.
    #[must_use]
    pub const fn technology(&self) -> &'static str {
        self.settings.technology
    }

    /// The settings it declares.
    #[must_use]
    pub const fn settings(&self) -> &'static Settings {
        self.settings
    }

    /// Build it for `location`, on `side`, on the node at `node`.
    ///
    /// # Errors
    /// What the technology refuses of the Location's address or settings,
    /// or of returning what the node held before it last stopped.
    pub fn open(
        &self,
        location: &ConfiguredLocation,
        side: Applies,
        node: &NodeLocation,
    ) -> Opened {
        (self.open)(&location.address, side, &location.settings.given(), node)
    }
}

/// `T` built from a Location and given its node, once, as it is built (the
/// owner, 2026-10-03; `transport::Configured::on_node`).
fn open<T: Configured + Send + Sync + 'static>(
    address: &str,
    side: Applies,
    given: &[(String, Given)],
    node: &NodeLocation,
) -> Opened {
    Ok(Box::new(T::open(address, side, given)?.on_node(node)?))
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

/// Everything a program linked that a node may use.
///
/// Each list is what the program was built with, not what the node runs: the
/// node takes the transports its Locations name, the route technologies its
/// filters name and the authenticators its Receive Locations accept. The
/// policies and identifiers are each consulted at every gate, so every one
/// linked is taken — no configuration selects among them yet.
#[derive(Default)]
pub struct Linked {
    pub transports: Vec<LinkedTransport>,
    /// Route technologies, each the source a filter's prefix names
    /// (ADR-0046).
    pub sources: Vec<Box<dyn Source>>,
    pub authenticators: Vec<Box<dyn Authenticator>>,
    pub policies: Vec<Box<dyn Authorizer>>,
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
    /// The linked transport a Location names, by module name.
    #[must_use]
    pub fn transport(&self, technology: &str) -> Option<&LinkedTransport> {
        self.transports
            .iter()
            .find(|linked| linked.technology() == technology)
    }

    /// The linked key store a `[store]` names.
    #[must_use]
    pub fn key_store(&self, technology: &str) -> Option<&LinkedKeyStore> {
        self.key_stores
            .iter()
            .find(|linked| linked.technology() == technology)
    }
}
