//! The one assembler of a gatherer: woken as any member is heard, it
//! assembles the cluster's view from the latest of every member, and what
//! is heard while it assembles is assembled together, next — never one
//! view per member heard.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use observe::topology::window::Window;

use super::Gathering;

/// The assembler's thread, from the members heard by revision `built`, the
/// first view's, stating what moved by `window`, the gatherer's one.
pub(super) fn started(
    gathering: &Arc<Gathering>,
    built: u64,
    window: Window,
) -> Option<JoinHandle<()>> {
    let shared = Arc::clone(gathering);
    std::thread::Builder::new()
        .name("xmip-gather-assemble".to_string())
        .spawn(move || assemble(&shared, built, window))
        .ok()
}

/// Assemble a view each time a member is heard after `built`, until the
/// gatherer ends.
fn assemble(gathering: &Gathering, mut built: u64, mut window: Window) {
    loop {
        let heard = gathering
            .heard
            .wait_unless(built, Duration::MAX, || gathering.ending());
        if gathering.ending() || heard <= built {
            return;
        }
        built = heard;
        gathering.assemble(&mut window);
    }
}
