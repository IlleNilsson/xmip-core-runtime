//! Telling systemd a service's state: a unit [`super::systemd_unit`] writes
//! is `Type=notify`, so systemd reports the service started only once the
//! program accepts work — a node's ADR-0018 ninth phase, a System Tests far
//! end's listening port — not at the process's first instruction. The
//! message is one datagram to the socket systemd names in `NOTIFY_SOCKET`,
//! as `sd_notify(3)` sends it. Anywhere else — another platform, a console,
//! a unit of another type — there is no socket and nothing is sent. The one
//! telling every program a unit runs calls: kept in `xmip-service` alone
//! until 2026-11-25, when a far end registered by the same unit never said
//! it was ready and systemd stopped it every 90 seconds.

/// The program accepts work.
pub fn ready() {
    notify("READY=1");
}

/// A stop arrived and the program drains.
pub fn stopping() {
    notify("STOPPING=1");
}

cfg_select! {
    target_os = "linux" => {
        fn notify(state: &str) {
            if let Some(socket) = std::env::var_os("NOTIFY_SOCKET")
                && let Err(error) = notify_at(&socket.to_string_lossy(), state)
            {
                eprintln!("could not tell systemd {state}: {error}");
            }
        }

        /// Send `state` to the socket `socket` names: `@name` is an abstract
        /// socket, anything else a path.
        fn notify_at(socket: &str, state: &str) -> std::io::Result<()> {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixDatagram};

            let address = match socket.strip_prefix('@') {
                Some(name) => SocketAddr::from_abstract_name(name.as_bytes())?,
                None => SocketAddr::from_pathname(socket)?,
            };
            UnixDatagram::unbound()?.send_to_addr(state.as_bytes(), &address)?;
            Ok(())
        }
    }
    _ => {
        fn notify(_state: &str) {}
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn systemd_hears_each_state_on_the_socket_it_named() {
        let directory = file::temporary::Folder::new("runtime-notify");
        let path = directory.join("notify");
        let systemd = UnixDatagram::bind(&path).expect("binds");

        for state in ["READY=1", "STOPPING=1"] {
            super::notify_at(path.to_str().expect("UTF-8"), state).expect("sent");
            let mut heard = [0u8; 32];
            let length = systemd.recv(&mut heard).expect("hears");
            assert_eq!(&heard[..length], state.as_bytes());
        }
    }
}
