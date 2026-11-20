//! A connection to an operate listener counts its HTTP/2 frames in a span
//! on the Clock the listener was handed, the node's (ADR-0068, amendment
//! 2026-11-16): a surface's two runs of `PING`s, each within what a span
//! allows, served where a span passed on that Clock between them, and the
//! connection calmed where none did.

use std::sync::Arc;

use audit_file::FileSink;
use context::{AuthenticatedIdentity, Verified};
use net::fixture::pinging::{Pinging, calmed};
use net::http2::Limits;
use xaudit::program_audit::ProgramAudit;
use xcore::Clock;
use xcore::clock::Stepped;

use super::calls;
use crate::plane::grant::Presented;
use crate::plane::listener::serving;
use crate::plane::{Board, Grants};

#[test]
fn a_connections_frames_in_a_span_are_counted_on_the_listeners_clock() {
    let pings = u64::from(Limits::DEFAULT.control_frames) * 3 / 5;
    let at = file::temporary::Folder::new("runtime-served");
    let audit = ProgramAudit::new("xmip-core-runtime tests", Some(FileSink::new(&*at)));
    let caller = AuthenticatedIdentity::new(
        xcore::mechanism::peer_credentials(),
        r"HOST\surface",
        xcore::Established::Detected,
        Verified::Proven,
    );
    let presented = Presented::Account(caller.value.clone());
    for passed in [true, false] {
        let clock = Arc::new(Stepped::default());
        let stepped = Arc::clone(&clock);
        let handed: Arc<dyn Clock> = clock;
        let serve = serving(
            None,
            Arc::new(Board::default()),
            Grants::default(),
            (&audit, handed),
        );
        let peer = Pinging::new(
            pings,
            Box::new(move || {
                if passed {
                    stepped.pass(Limits::DEFAULT.span);
                }
            }),
        );
        let written = peer.written();
        calls(Box::new(peer), (&caller, None, &presented), &serve);
        assert_eq!(calmed(&written), !passed, "{passed}");
    }
}
