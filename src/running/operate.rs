//! A running node's operate listener (ADR-0067), as its configuration's
//! `[operate]` says ([`configure::operate`]): the address it binds, the
//! certificate it presents with its key, the anchors a surface's
//! certificate must reach and the role every proven caller holds.

use std::path::Path;
use std::sync::Arc;

use configure::operate::OperateConfiguration;
use xaudit::program_audit::ProgramAudit;

use crate::plane::{Listener, Published, Role};
use crate::running::Running;

impl Running {
    /// Serve the node's operate listener over `published`, its acts
    /// recorded in `audit`; `None` where the configuration has no
    /// `[operate]`.
    ///
    /// # Errors
    ///
    /// A file that cannot be read, an identity that does not pair, or an
    /// address that cannot be bound, each in words naming what.
    pub fn operate(
        &self,
        published: Arc<dyn Published>,
        audit: &ProgramAudit,
    ) -> Result<Option<Listener>, String> {
        let Some(operate) = &self.operate else {
            return Ok(None);
        };
        listen(operate, &self.configuration, published, audit).map(Some)
    }
}

fn listen(
    operate: &OperateConfiguration,
    configuration: &Path,
    published: Arc<dyn Published>,
    audit: &ProgramAudit,
) -> Result<Listener, String> {
    let read = |path: &str| {
        let file = OperateConfiguration::resolve(configuration, path);
        std::fs::read(&file).map_err(|error| format!("[operate] {}: {error}", file.display()))
    };
    let identity = tls::Identity::from_pem(
        &read(&operate.certificate)?,
        &read(&operate.key)?,
        &read(&operate.anchors)?,
    )
    .map_err(|failed| format!("[operate] {}", failed.message))?;
    let bound = std::net::TcpListener::bind(&operate.listen)
        .map_err(|error| format!("[operate] listen = \"{}\": {error}", operate.listen))?;
    let stated = operate.role.as_deref().map(Role::named);
    Listener::start(bound, &identity, published, stated, audit)
}
