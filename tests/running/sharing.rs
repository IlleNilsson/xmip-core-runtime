//! A node hands every Location it builds what its Locations share, one
//! `transport::Sharing` for the node (ADR-0064, amendment 2026-11-15): two
//! Locations naming one serial device go through its one port. The port is
//! a bench's, handed in through the serial line's `Opens` seam, so no device
//! and no sleep; it opens for one handle at a time, as the operating
//! system's does, so a Location with a sharing of its own was refused it.

use std::cell::RefCell;
use std::sync::Arc;

use net::fixture::unheld;
use serial::SerialTransport;
use serial::bench::Bench;
use transport::{Configured, Transport};
use xcore::settings::{Applies, Given};
use xmip_core_runtime::fixture::started;
use xmip_core_runtime::linked::{LinkedTransport, OnNode, Opened, built_on};

use super::node::{first, linked, node, path_text, written};

thread_local! {
    /// The device every serial Location this test's thread builds is on:
    /// startup runs on the thread that calls it.
    static BENCH: Bench = Bench::default();
    /// Each serial Location built, and the sharing its node handed it.
    static BUILT: RefCell<Vec<(SerialTransport, usize)>> = const { RefCell::new(Vec::new()) };
}

/// A serial Location built on the bench's port, given the rest by its node
/// as every Location is, and kept with the sharing it was handed.
fn benched(address: &str, side: Applies, given: &[(String, Given)], on: OnNode<'_>) -> Opened {
    let bench = BENCH.with(Bench::clone);
    let line = SerialTransport::open(address, side, given)?.opened_by(Arc::new(bench));
    let sharing = Arc::as_ptr(on.3).cast::<()>().addr();
    let line = built_on(line, on)?;
    BUILT.with(|built| built.borrow_mut().push((line.clone(), sharing)));
    Ok(Box::new(line))
}

/// The test node's Application with two Send Ports more, `Meter` and
/// `Display`, both on the serial device `COM9`.
fn on_one_device() -> String {
    let (node_name, _) = first();
    let ports = ["Meter", "Display"].map(|name| {
        format!(
            "[[applications.send_ports]]\nname = \"{name}\"\nnode = \"{node_name}\"\n\
             start = true\naddress = \"serial://COM9\"\n\
             [applications.send_ports.settings]\nbaud = 2400\nlength = 3\n\n"
        )
    });
    let declared = "[[xmip_applications.send_ports]]\nname = \"Meter\"\n\n\
                    [[xmip_applications.send_ports]]\nname = \"Display\"\n\n";
    node(&unheld().to_string(), &unheld().to_string())
        .replacen(
            "\n[[xmip_applications]]\n",
            &format!("\n{}[[xmip_applications]]\n", ports.concat()),
            1,
        )
        .replacen(
            "[[xmip_applications.send_ports]]\n",
            &format!("{declared}[[xmip_applications.send_ports]]\n"),
            1,
        )
}

/// Both serial Send Ports are handed the node's one sharing, so both go
/// through the device's one port, opened once: each writes what it is sent,
/// where a second port on the device would have been refused.
#[test]
fn two_locations_naming_one_device_on_a_node_share_its_one_port() {
    let path = written("one-port", &on_one_device());
    let running = started(path_text(&path), || {
        let mut linked = linked(&path);
        linked
            .transports
            .push(LinkedTransport::opened_by::<SerialTransport>(benched));
        linked
    })
    .expect("the node starts");
    let built = BUILT.with(RefCell::take);
    assert_eq!(built.len(), 2, "both serial Send Ports");
    assert_eq!(
        built[0].1, built[1].1,
        "the node's one sharing, handed to both"
    );
    for ((line, _), payload) in built.iter().zip([b"one", b"two"]) {
        line.send("COM9", payload)
            .expect("written through the one port");
    }
    let bench = BENCH.with(Bench::clone);
    assert_eq!(bench.written(), b"onetwo");
    assert_eq!(bench.opened(), 1, "one port for both");
    running.stop();
    let _ = std::fs::remove_dir_all(path.parent().expect("its directory"));
}
