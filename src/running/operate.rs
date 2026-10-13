//! A running node's operate listeners (ADR-0067), as its configuration's
//! `[operate]` says ([`configure::operate`]): the local endpoint every
//! surface on this machine reaches it at, which always starts (ADR-0014,
//! amendments 2026-10-13), and the network address a surface on another reaches it
//! at, with the certificate it presents and its key, the anchors a
//! surface's certificate must reach — and the role every proven caller
//! holds, on either.

use std::path::Path;
use std::sync::Arc;

use configure::operate::{Network, OperateConfiguration};
use xaudit::program_audit::ProgramAudit;

use crate::plane::{Listener, Published, Role};
use crate::registration::node_service_name;
use crate::running::Running;

impl Running {
    /// Serve the node's operate listeners over `published`, its acts
    /// recorded in `audit`: the local endpoint always — decided by the
    /// owner, 2026-10-13: *the local endpoint always starts, named
    /// `xmip-<node>` unless the configuration names it* — then the network
    /// listener where `[operate] listen` names it.
    ///
    /// # Errors
    ///
    /// A local name that would leave the endpoints' folder, a file that
    /// cannot be read, an identity that does not pair, or an address or
    /// endpoint that cannot be bound, each in words naming what.
    pub fn operate(
        &self,
        published: &Arc<dyn Published>,
        audit: &ProgramAudit,
    ) -> Result<Vec<Listener>, String> {
        let operate = self.operate.clone().unwrap_or_default();
        let stated = operate.role.as_deref().map(Role::named);
        let local = self.local_endpoint();
        let mut listeners = vec![
            Listener::local(&local, Arc::clone(published), stated, audit)
                .map_err(|why| format!("[operate] local = \"{local}\": {why}"))?,
        ];
        if let Some(network) = operate.network()? {
            listeners.push(listen(
                network,
                &self.configuration,
                Arc::clone(published),
                stated,
                audit,
            )?);
        }
        Ok(listeners)
    }

    /// The node's local endpoint's name: `[operate] local`, else the name
    /// its Xmip Service has, `xmip-<node>` (ADR-0053).
    #[must_use]
    pub fn local_endpoint(&self) -> String {
        self.operate
            .as_ref()
            .and_then(|operate| operate.local.clone())
            .unwrap_or_else(|| node_service_name(&self.node))
    }

    /// `[tuning] local_timeout`: how long a surface's call to the local
    /// endpoint waits, which the node declares beside the endpoint
    /// (`plane::deadline::DECLARED`).
    #[must_use]
    pub const fn local_timeout(&self) -> std::time::Duration {
        self.local_timeout
    }
}

fn listen(
    network: Network<'_>,
    configuration: &Path,
    published: Arc<dyn Published>,
    stated: Option<Role>,
    audit: &ProgramAudit,
) -> Result<Listener, String> {
    let read = |path: &str| {
        let file = OperateConfiguration::resolve(configuration, path);
        std::fs::read(&file).map_err(|error| format!("[operate] {}: {error}", file.display()))
    };
    let identity = tls::Identity::from_pem(
        &read(network.certificate)?,
        &read(network.key)?,
        &read(network.anchors)?,
    )
    .map_err(|failed| format!("[operate] {}", failed.message))?;
    let bound = std::net::TcpListener::bind(network.listen)
        .map_err(|error| format!("[operate] listen = \"{}\": {error}", network.listen))?;
    Listener::start(bound, &identity, published, stated, audit)
}
