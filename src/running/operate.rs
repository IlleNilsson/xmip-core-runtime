//! A running node's operate listeners (ADR-0067), as its configuration's
//! `[operate]` says ([`configure::operate`]): the local endpoint every
//! surface on this machine reaches it at (ADR-0014, amendment
//! 2026-10-13), and the network address a surface on another reaches it
//! at, with the certificate it presents and its key, the anchors a
//! surface's certificate must reach — and the role every proven caller
//! holds, on either.

use std::path::Path;
use std::sync::Arc;

use configure::operate::{Network, OperateConfiguration};
use xaudit::program_audit::ProgramAudit;

use crate::plane::{Listener, Published, Role};
use crate::running::Running;

impl Running {
    /// Serve the node's operate listeners over `published`, its acts
    /// recorded in `audit`: the local endpoint first, then the network
    /// listener, each where `[operate]` names it; none where the
    /// configuration has no `[operate]`.
    ///
    /// # Errors
    ///
    /// A table naming neither, a file that cannot be read, an identity
    /// that does not pair, or an address or endpoint that cannot be bound,
    /// each in words naming what.
    pub fn operate(
        &self,
        published: &Arc<dyn Published>,
        audit: &ProgramAudit,
    ) -> Result<Vec<Listener>, String> {
        let Some(operate) = &self.operate else {
            return Ok(Vec::new());
        };
        let stated = operate.role.as_deref().map(Role::named);
        let mut listeners = Vec::new();
        if let Some(local) = &operate.local {
            let listener = Listener::local(local, Arc::clone(published), stated, audit)
                .map_err(|why| format!("[operate] local = \"{local}\": {why}"))?;
            listeners.push(listener);
        }
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
