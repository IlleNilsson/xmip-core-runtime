//! `xmip_operate.h` section 11: Events, subscribed, forwarded.
//!
//! A program in any language that loaded this library subscribes to the
//! process's hub, `xmip-core-event`'s `Hub::process`, and these files do
//! nothing else: the matching rule, the authorization gate, the queue and
//! the audit are the event crate's (ADR-0065, ADR-0052). The header's
//! action and outcome integers cross in `crossing`, converted by
//! `crate::wire` with every other enum that crosses the header.
//!
//! The hub's exports (`hub`), what crosses (`crossing`) and the gate
//! (`gate`) are the node's. What a read publication carries of Event
//! subscriptions and who is not heard (`subscription`, `unheard`) a remote
//! build carries too.

#[cfg(feature = "node")]
mod crossing;
#[cfg(feature = "node")]
mod gate;
#[cfg(feature = "node")]
mod hub;
mod subscription;
mod unheard;
