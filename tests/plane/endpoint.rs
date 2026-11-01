//! A node's local endpoint — a named pipe on Windows, a Unix domain socket
//! elsewhere — and a surface on it, with no certificate: what the plane's
//! tests on this machine and the module's timing program
//! (`tests/measured`) both stand up.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use xaudit::program_audit::ProgramAudit;
use xmip_core_runtime::plane::{Board, Listener, Published, Remote, Role};

/// An endpoint no other test or run uses.
pub fn endpoint() -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let next = NEXT.fetch_add(1, Ordering::SeqCst);
    format!("xmip-operate-test-{}-{next}", std::process::id())
}

fn audit() -> ProgramAudit {
    let directory = std::env::temp_dir().join(endpoint());
    std::fs::create_dir_all(&directory).expect("an audit directory");
    ProgramAudit::new("plane-local-test", Some(&directory))
}

/// A node's local endpoint over `board`, holding `role`, its audit and the
/// endpoint's name.
pub fn node(board: &Arc<Board>, role: Option<Role>) -> (Listener, ProgramAudit, String) {
    let audit = audit();
    let called = endpoint();
    let published = Arc::clone(board) as Arc<dyn Published>;
    let admitting = xmip_core_runtime::plane::local::Admitting::default();
    let listener = Listener::local(&called, admitting, published, role, &audit).expect("it serves");
    (listener, audit, called)
}

/// A surface on the endpoint `called`, stating no wait of its own.
pub fn surface(called: &str) -> Remote {
    Remote::local_retrying(called, Duration::ZERO, vec![Duration::from_millis(50)])
        .expect("a surface")
}
