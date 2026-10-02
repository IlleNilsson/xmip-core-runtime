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

use authenticate::Authenticator;
use authorize::Authorizer;
use configure::ConfiguredLocation;
use identify::{MessageIdentifier, TransportIdentifier};
use persist::{Engine, PersistError};
use route::Source;
use secret::KeyStore;
use transport::{Configured, Transport};
use xaudit::program_audit::ProgramAudit;
use xcore::settings::{Applies, Given, Settings};

use crate::pickup::Store;

/// A transport built for one Location: the one kept instance its receives or
/// sends go through.
pub type Opened = transport::Result<Box<dyn Transport + Send + Sync>>;

/// How a Location's transport is built: its address, the side it serves and
/// what its settings table gave.
pub type Open = fn(&str, Applies, &[(String, Given)]) -> Opened;

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

    /// Build it for `location`, on `side`.
    ///
    /// # Errors
    /// What the technology refuses of the Location's address or settings.
    pub fn open(&self, location: &ConfiguredLocation, side: Applies) -> Opened {
        (self.open)(&location.address, side, &location.settings.given())
    }
}

fn open<T: Configured + Send + Sync + 'static>(
    address: &str,
    side: Applies,
    given: &[(String, Given)],
) -> Opened {
    Ok(Box::new(T::open(address, side, given)?))
}

/// How an engine opens its store in a directory.
pub type OpenEngine = fn(&Path) -> Result<Box<dyn Engine>, PersistError>;

/// The runtime store's engine linked into the program, by its module name
/// (`xmip-core-persist-rocksdb`, `configure::store::ENGINE`): the one
/// engine of an embedded runtime database (ADR-0015, amendment 2026-10-01).
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
    /// The runtime store's engine, where the program was built with it;
    /// the node opens its store over it (`crate::store`, ADR-0018,
    /// amendments 2026-09-30 and 2026-10-01).
    pub engine: Option<LinkedEngine>,
    /// The key stores the program was built with, one of which wraps the
    /// runtime store's data key.
    pub key_stores: Vec<LinkedKeyStore>,
    /// A runtime store the program opened itself, which the node takes
    /// instead of opening the one its configuration names: where a paused
    /// Subscription's standing and what it holds are kept, so both survive
    /// a restart (ADR-0013, amendment 2026-09-30). None, with no engine
    /// linked and no `[store]` named, holds in memory for the node's life.
    pub store: Option<Store>,
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
