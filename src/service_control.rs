//! Starting and stopping a node's installed Xmip Service through the
//! operating system's own service manager: the Windows service control
//! manager, systemd, launchd.
//!
//! One implementation for every platform and every surface. What a surface
//! asks is *start node alpha* or *stop node alpha*; which manager is asked,
//! and in which words, is decided here at compile time
//! ([`ServiceManager::for_target`]) and nowhere else. The service is found
//! by the name registration gave it ([`node_service_name`]), so a node that
//! was never installed as a service is refused in the manager's own words.
//!
//! The act returns when the manager has taken the request, not when the
//! node has finished starting or draining: a start runs ADR-0018's nine
//! phases and a stop drains what is in flight, and both are the node's to
//! report through its health. Nothing here restarts anything; the service
//! manager owns restarts, and nothing in Xmip starts itself.

use std::fmt;
use std::process::Command;

use crate::registration::{ServiceManager, node_service_name};

/// What an operator asks of a node's service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    Start,
    Stop,
}

impl Act {
    /// The word a surface and a record say it by.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }
}

impl fmt::Display for Act {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// The program and arguments that ask `manager` to `act` on `node`'s
/// service, or `None` where the platform has no service manager.
#[must_use]
pub fn asking(
    manager: ServiceManager,
    act: Act,
    node: &str,
) -> Option<(&'static str, Vec<String>)> {
    let name = node_service_name(node);
    let asked = match manager {
        ServiceManager::WindowsScm => ("sc.exe", vec![act.word().to_string(), name]),
        ServiceManager::Systemd => (
            "systemctl",
            vec![
                act.word().to_string(),
                "--no-block".to_string(),
                format!("{name}.service"),
            ],
        ),
        ServiceManager::Launchd => match act {
            Act::Start => (
                "launchctl",
                vec!["kickstart".into(), format!("system/{name}")],
            ),
            Act::Stop => (
                "launchctl",
                vec!["kill".into(), "SIGTERM".into(), format!("system/{name}")],
            ),
        },
        ServiceManager::None => return None,
    };
    Some(asked)
}

/// Ask this platform's service manager to `act` on `node`'s service.
///
/// # Errors
/// The sentence that says why not: no service manager here, the manager
/// could not be run, or it refused — in its own words, with the service's
/// name.
pub fn control(act: Act, node: &str) -> Result<String, String> {
    let manager = ServiceManager::for_target();
    let name = node_service_name(node);
    let Some((program, arguments)) = asking(manager, act, node) else {
        return Err(format!(
            "cannot {act} {name}: this platform has no service manager"
        ));
    };
    let ran = Command::new(program)
        .args(&arguments)
        .output()
        .map_err(|error| format!("cannot {act} {name}: {program} did not run: {error}"))?;
    let said = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim().to_string();
    let code = ran.status.code();

    if ran.status.success() {
        return Ok(format!("asked {program} to {act} {name}"));
    }
    if manager == ServiceManager::WindowsScm && already(act, code) {
        return Ok(format!("{name} was already {}", settled(act)));
    }
    let words = [said(&ran.stderr), said(&ran.stdout)]
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Err(format!(
        "{program} refused to {act} {name} (exit {}): {words}",
        code.map_or_else(|| "none".to_string(), |code| code.to_string())
    ))
}

/// The service control manager's own answer that nothing needed doing:
/// 1056, already running, to a start; 1062, not started, to a stop.
const fn already(act: Act, code: Option<i32>) -> bool {
    matches!(
        (act, code),
        (Act::Start, Some(1056)) | (Act::Stop, Some(1062))
    )
}

const fn settled(act: Act) -> &'static str {
    match act {
        Act::Start => "running",
        Act::Stop => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_manager_is_asked_in_its_own_words_by_the_registered_name() {
        let cases = [
            (
                ServiceManager::WindowsScm,
                Act::Start,
                "sc.exe",
                "start xmip-alpha",
            ),
            (
                ServiceManager::WindowsScm,
                Act::Stop,
                "sc.exe",
                "stop xmip-alpha",
            ),
            (
                ServiceManager::Systemd,
                Act::Start,
                "systemctl",
                "start --no-block xmip-alpha.service",
            ),
            (
                ServiceManager::Systemd,
                Act::Stop,
                "systemctl",
                "stop --no-block xmip-alpha.service",
            ),
            (
                ServiceManager::Launchd,
                Act::Start,
                "launchctl",
                "kickstart system/xmip-alpha",
            ),
            (
                ServiceManager::Launchd,
                Act::Stop,
                "launchctl",
                "kill SIGTERM system/xmip-alpha",
            ),
        ];
        for (manager, act, program, arguments) in cases {
            let (asked, with) = asking(manager, act, "alpha").expect("a manager");
            assert_eq!((asked, with.join(" ").as_str()), (program, arguments));
        }
        assert!(asking(ServiceManager::None, Act::Start, "alpha").is_none());
    }

    #[test]
    fn nothing_to_do_is_no_refusal_to_the_service_control_manager() {
        assert!(already(Act::Start, Some(1056)));
        assert!(already(Act::Stop, Some(1062)));
        assert!(!already(Act::Stop, Some(1056)));
        assert!(!already(Act::Start, Some(1060)));
    }

    /// A service nobody installed is refused by the manager, in its words
    /// and with the name asked for. The service control manager answers
    /// that without elevation.
    #[cfg(windows)]
    #[test]
    fn a_node_never_installed_is_refused_by_name() {
        let node = format!("never-installed-{}", std::process::id());

        let refused = control(Act::Stop, &node).expect_err("no such service");

        assert!(refused.contains(&node_service_name(&node)), "{refused}");
        assert!(refused.contains("exit 1060"), "{refused}");
    }
}
