//! A running node's operate listeners (ADR-0067), as its configuration's
//! `[operate]` says ([`configure::operate`]): the local endpoint every
//! surface on this machine reaches it at, which always starts (ADR-0014,
//! amendments 2026-10-13), and the network address a surface on another reaches it
//! at, with the certificate it presents and its key, the anchors a
//! surface's certificate must reach — and, on either, the role each proven
//! caller holds by its own name, `[operate] observers`, `operators` and
//! `developers` (`plane::grant`), none for a caller they do not name; who
//! may relay for a caller, `[operate] relay` (`plane::vouched`); and what
//! bounds each listener, `[tuning] operate_connections`,
//! `operate_handshakes` and `operate_handshake` (`plane::limits`). Every act
//! either listener admits is asked through the node's door, and every act
//! asked of the node through Xmip Storage is taken by its act watch, both
//! started here (`crate::act_watch`; `[tuning] operate_act`).

use std::path::Path;
use std::sync::Arc;

use configure::operate::Network;
use xaudit::program_audit::ProgramAudit;
use xcore::lock::Locked;

use crate::act_watch::{ActWatch, Door};
use crate::plane::local::Admitting;
use crate::plane::vouched::Relaying;
use crate::plane::{Grants, Listener, Published};
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
    /// A local name that would leave the endpoints' folder, a name listed
    /// under two roles, a file that cannot be read, an identity that does
    /// not pair, or an address or endpoint that cannot be bound, each in
    /// words naming what.
    pub fn operate(
        &self,
        published: &Arc<dyn Published>,
        audit: &ProgramAudit,
    ) -> Result<Vec<Listener>, String> {
        let operate = self.operate.clone().unwrap_or_default();
        let grants = Grants::listed(operate.grants()?);
        let acting = grants.clone();
        let local = self.local_endpoint();
        let admitting = Admitting {
            admit: &operate.admit,
            group: operate.group.as_deref(),
        };
        let mut listeners = vec![
            Listener::local(
                &local,
                admitting,
                Arc::clone(published),
                grants.clone(),
                audit,
            )
            .map_err(|why| format!("[operate] local = \"{local}\": {why}"))?,
        ];
        if let Some(network) = operate.network()? {
            let listener = listen(
                network,
                &self.configuration,
                Arc::clone(published),
                grants,
                audit,
            )?;
            // Where it answers, as bound: what its membership row says.
            let _ = self.operated.set(listener.address());
            listeners.push(listener);
        }
        for listener in &listeners {
            listener.limit(self.tuning.operate());
        }
        self.monitored(&listeners, published);
        if let Some((relay, anchors)) = operate.relaying()? {
            let anchors = crate::presented::file(&self.configuration, "operate", anchors)?;
            let anchors = String::from_utf8_lossy(&anchors);
            let relaying = Relaying::new(relay.to_vec(), &anchors)
                .map_err(|why| format!("[operate] relay: {why}"))?;
            let relaying = Arc::new(relaying);
            for listener in &listeners {
                listener.relay(Arc::clone(&relaying));
            }
        }
        self.acts_asked(published, (&listeners, acting), audit)?;
        Ok(listeners)
    }

    /// The node's door on each of `listeners`, and its act watch started
    /// over its Xmip Storage, judging every act asked of it by `grants`
    /// and telling `published` of each it takes (ADR-0014, amendment
    /// 2026-11-13).
    fn acts_asked(
        &self,
        published: &Arc<dyn Published>,
        (listeners, grants): (&[Listener], Grants),
        audit: &ProgramAudit,
    ) -> Result<(), String> {
        let (scope, storage) = (self.location(), self.storage.storage());
        let capability = node::Capability::of(&self.roles);
        let within = self.tuning.operate_act;
        let door = Arc::new(Door::of(&scope, &capability, Arc::clone(storage), within));
        for listener in listeners {
            listener.door(Arc::clone(&door));
        }
        let watch = ActWatch::new(&scope, Arc::clone(storage), grants, audit);
        let watching = watch
            .telling(Arc::clone(published))
            .start(self.tuning.storage_wait)?;
        *self.acts.locked() = Some(watching);
        Ok(())
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
        self.tuning.local_timeout
    }
}

fn listen(
    network: Network<'_>,
    configuration: &Path,
    published: Arc<dyn Published>,
    grants: Grants,
    audit: &ProgramAudit,
) -> Result<Listener, String> {
    let files = [network.certificate, network.key, network.anchors];
    let identity = crate::presented::identity(configuration, "operate", files)?;
    let bound = std::net::TcpListener::bind(network.listen)
        .map_err(|error| format!("[operate] listen = \"{}\": {error}", network.listen))?;
    Listener::start(bound, &identity, published, grants, audit)
}
