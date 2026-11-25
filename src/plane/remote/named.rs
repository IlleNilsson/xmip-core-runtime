//! A node reached at an address and trusted by its name: the surface
//! connects to the address it is given and checks the node's certificate
//! for the node's name, as a node on a machine whose name the machine
//! reaching it resolves to no address is reached (the System Tests on
//! virtual machines, at the addresses their deployment recorded).

use std::sync::Arc;
use std::time::Duration;
use xcore::Clock;

use crate::plane::line::Reach;
use crate::plane::remote::{PATIENCE, RETRY, Remote};

impl Remote {
    /// A surface over the node `name` at `address`, `host:port`: as
    /// [`Remote::open`], connected to `address` and trusting the node only
    /// where its certificate names `name` and reaches the identity's
    /// anchors. Nothing is connected yet.
    ///
    /// # Errors
    ///
    /// An address that is no operate address, or an identity that does not
    /// make a client.
    pub fn open_named(
        name: &str,
        address: &str,
        identity: &tls::Identity,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, String> {
        Self::retrying_named((name, address), identity, RETRY.to_vec(), clock)
    }

    /// The same, trying a lost node again on `retry`'s schedule: what a
    /// test shortens.
    ///
    /// # Errors
    ///
    /// As [`Remote::open_named`].
    pub fn retrying_named(
        (name, address): (&str, &str),
        identity: &tls::Identity,
        retry: Vec<Duration>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, String> {
        let client = identity.client().map_err(|failed| failed.message)?;
        let config = Arc::new(tls::alpn::offering(client, &[b"h2"]));
        let reach = Reach::named(address, name, config)?;
        Ok(Self::reaching(
            address.to_string(),
            reach,
            PATIENCE,
            retry,
            clock,
        ))
    }
}
