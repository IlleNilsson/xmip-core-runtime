//! A Send Location as a node runs it, and the node's Send Locations by the
//! name routing resolves.
//!
//! Routing decides *that* a Message goes to `SendPort.Billing`. Which
//! Location that is, and whose identity it presents, is configuration — and
//! it is resolved here rather than by routing, because ADR-0019 clause 3
//! keeps the two apart: routing never decides *how* something gets somewhere.
//! A bound Send Port is the Send Location its binding gives it, named as the
//! Port (ADR-0064), and a Send Port Group reaches its Ports together.

use configure::{ConfiguredLocation, SendPortGroup};
use route::Subscriber;
use send::SendChain;
use transport::Transport;

/// A Send Location running: its configuration, the chain that resolves the
/// identity it presents (ADR-0006), and the transport built for it once,
/// which keeps its connections and sessions between sends
/// (`transport::pool`).
pub struct Sending {
    pub configured: ConfiguredLocation,
    pub chain: SendChain,
    pub transport: Box<dyn Transport + Send + Sync>,
}

/// Where a destination routing matched is sent.
pub enum Destination<'a> {
    /// A Send Port, or every Port of a Send Port Group in the group's order,
    /// each with its Send Location on this node, or `None` where this node
    /// has none by that name.
    Ports(Vec<(&'a str, Option<&'a Sending>)>),
    /// An Xmip Process. Running one is not built: a Process is compiled at
    /// design time into a module a node loads (ADR-0066 clause 4), and none
    /// is yet.
    Process,
    /// A Send Port Group no bound Application declares.
    Nowhere,
}

/// The node's Send Locations, and the Send Port Groups of the Applications
/// it binds.
#[derive(Default)]
pub struct Sends {
    pub locations: Vec<Sending>,
    pub groups: Vec<SendPortGroup>,
}

impl Sends {
    /// Where `to` is sent on this node.
    #[must_use]
    pub fn to<'a>(&'a self, to: &'a Subscriber) -> Destination<'a> {
        match to {
            Subscriber::SendPort(port) => Destination::Ports(vec![(port, self.location(port))]),
            Subscriber::SendGroup(group) => self
                .groups
                .iter()
                .find(|declared| &declared.name == group)
                .map_or(Destination::Nowhere, |group| {
                    Destination::Ports(
                        group
                            .send_ports
                            .iter()
                            .map(|port| (port.as_str(), self.location(port)))
                            .collect(),
                    )
                }),
            Subscriber::Process(_) => Destination::Process,
        }
    }

    fn location(&self, name: &str) -> Option<&Sending> {
        self.locations
            .iter()
            .find(|sending| sending.configured.name == name)
    }
}
