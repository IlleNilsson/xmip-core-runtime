//! A definition applied: its service registered with this platform's
//! service manager and started, or stopped and removed. One
//! implementation for every program the estate runs as a service —
//! `xmip-service --install` and `--uninstall` (ADR-0015, amendment
//! 2026-10-13), and the System Tests' far ends — each asking it with its own
//! definition. Both need the elevation registering needs (ADR-0018, Open),
//! and a caller without it is refused in the service manager's words.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
use std::process::Command;

use super::ServiceDefinition;

/// Run `program` with `arguments`; an exit code but success and `fine` is
/// refused with what it said.
///
/// # Errors
///
/// The program could not run, or it refused, in its own words.
pub fn command(program: &str, arguments: &[String], fine: &[i32]) -> Result<(), String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    let code = output.status.code().unwrap_or(-1);
    if output.status.success() || fine.contains(&code) {
        return Ok(());
    }
    let words = String::from_utf8_lossy(&output.stdout).trim().to_string()
        + String::from_utf8_lossy(&output.stderr).trim();
    Err(format!(
        "{program} {} exited {code}: {words}",
        arguments.join(" ")
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|error| said(path, &error))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn said(path: &Path, error: &std::io::Error) -> String {
    format!("{}: {error}", path.display())
}

cfg_select! {
    windows => {
        /// Register `service`, named for `node`, with this platform's
        /// service manager, `give` its account what it reads and writes
        /// once that account is there, and start it.
        ///
        /// # Errors
        ///
        /// The manager's refusal, or `give`'s, in words.
        pub fn register(
            service: &ServiceDefinition,
            node: &str,
            give: &dyn Fn() -> Result<(), String>,
        ) -> Result<(), String> {
            use super::{windows_service_arguments, windows_service_settings};
            use crate::service_control::{Act, control};
            // 1073: the service exists already, as on a repair.
            command("sc.exe", &windows_service_arguments(service), &[1073])?;
            for (program, arguments) in windows_service_settings(service) {
                command(&program, &arguments, &[])?;
            }
            // A virtual account is there once its service is.
            give()?;
            control(Act::Start, node).map(|_| ())
        }
    }
    target_os = "linux" => {
        /// Register `service` with systemd, after `give` has given its
        /// account what it reads and writes, and start it.
        ///
        /// # Errors
        ///
        /// systemd's refusal, or `give`'s, in words.
        pub fn register(
            service: &ServiceDefinition,
            _: &str,
            give: &dyn Fn() -> Result<(), String>,
        ) -> Result<(), String> {
            give()?;
            let unit = format!("/etc/systemd/system/{}.service", service.name);
            write(Path::new(&unit), &super::systemd_unit(service)?)?;
            let unit_name = format!("{}.service", service.name);
            command("systemctl", &[String::from("daemon-reload")], &[])?;
            command("systemctl", &[String::from("enable"), unit_name.clone()], &[])?;
            // A restart starts a stopped unit and runs an upgraded program.
            command("systemctl", &[String::from("restart"), unit_name], &[])
        }
    }
    target_os = "macos" => {
        /// Register `service` with launchd, after `give` has given its
        /// account what it reads and writes, and so start it.
        ///
        /// # Errors
        ///
        /// launchd's refusal, or `give`'s, in words.
        pub fn register(
            service: &ServiceDefinition,
            _: &str,
            give: &dyn Fn() -> Result<(), String>,
        ) -> Result<(), String> {
            give()?;
            // The service's folder of its local endpoint first, made now and
            // at every boot.
            let run = format!("/Library/LaunchDaemons/{}.run.plist", service.name);
            write(Path::new(&run), &super::launchd_run_directory(service)?)?;
            let _ = command(
                "launchctl",
                &[String::from("bootout"), format!("system/{}.run", service.name)],
                &[],
            );
            command(
                "launchctl",
                &[String::from("bootstrap"), String::from("system"), run],
                &[],
            )?;
            let plist = format!("/Library/LaunchDaemons/{}.plist", service.name);
            write(Path::new(&plist), &super::launchd_plist(service))?;
            // An upgrade finds the daemon loaded; launchd loads it again only
            // after it is out, and a daemon that was never loaded is not,
            // which is fine.
            let _ = command(
                "launchctl",
                &[String::from("bootout"), format!("system/{}", service.name)],
                &[],
            );
            command(
                "launchctl",
                &[String::from("bootstrap"), String::from("system"), plist],
                &[],
            )
        }
    }
    _ => {
        /// No service manager to register with.
        ///
        /// # Errors
        ///
        /// Always: this platform has none.
        pub fn register(
            _: &ServiceDefinition,
            _: &str,
            _: &dyn Fn() -> Result<(), String>,
        ) -> Result<(), String> {
            Err("this platform has no service manager".to_string())
        }
    }
}

cfg_select! {
    windows => {
        /// Stop the service named `name`, `node`'s, waiting for its drain,
        /// and remove it.
        ///
        /// # Errors
        ///
        /// The manager's refusal, or a drain longer than a minute, in words.
        pub fn deregister(name: &str, node: &str) -> Result<String, String> {
            use std::time::{Duration, Instant};
            use windows_service::service::{ServiceAccess, ServiceState};
            use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
            use crate::service_control::{Act, control};

            /// The Service Control Manager's word for a service it does not have.
            const DOES_NOT_EXIST: i32 = 1060;
            /// How long a drain may take before the removal says so.
            const DRAIN: Duration = Duration::from_secs(60);

            let manager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                    .map_err(|error| format!("the Service Control Manager: {error}"))?;
            let access = ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE;
            let service = match manager.open_service(name, access) {
                Ok(service) => service,
                Err(windows_service::Error::Winapi(error))
                    if error.raw_os_error() == Some(DOES_NOT_EXIST) =>
                {
                    return Ok(format!("{name} is not registered; nothing to remove"));
                }
                Err(error) => return Err(format!("{name}: {error}")),
            };
            let state = |service: &windows_service::service::Service| {
                service
                    .query_status()
                    .map(|status| status.current_state)
                    .map_err(|error| format!("{name}: {error}"))
            };
            if state(&service)? != ServiceState::Stopped {
                control(Act::Stop, node)?;
                let began = Instant::now();
                while state(&service)? != ServiceState::Stopped {
                    if began.elapsed() > DRAIN {
                        return Err(format!("{name} did not stop within {} s", DRAIN.as_secs()));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            service
                .delete()
                .map_err(|error| format!("{name}: {error}"))?;
            Ok(format!(
                "{name} stopped and removed; its configuration and data are kept"
            ))
        }
    }
    target_os = "linux" => {
        /// Stop the unit named `name` and remove it.
        ///
        /// # Errors
        ///
        /// systemd's refusal, or the unit's file not removed, in words.
        pub fn deregister(name: &str, _: &str) -> Result<String, String> {
            let unit = format!("/etc/systemd/system/{name}.service");
            if !Path::new(&unit).exists() {
                return Ok(format!("{name} is not registered; nothing to remove"));
            }
            command(
                "systemctl",
                &[
                    String::from("disable"),
                    String::from("--now"),
                    format!("{name}.service"),
                ],
                &[],
            )?;
            std::fs::remove_file(&unit).map_err(|error| said(Path::new(&unit), &error))?;
            command("systemctl", &[String::from("daemon-reload")], &[])?;
            Ok(format!(
                "{name} stopped and removed; its configuration and data are kept"
            ))
        }
    }
    target_os = "macos" => {
        /// Stop the daemon named `name` and remove it.
        ///
        /// # Errors
        ///
        /// launchd's refusal, or its file not removed, in words.
        pub fn deregister(name: &str, _: &str) -> Result<String, String> {
            let plist = format!("/Library/LaunchDaemons/{name}.plist");
            if !Path::new(&plist).exists() {
                return Ok(format!("{name} is not registered; nothing to remove"));
            }
            command(
                "launchctl",
                &[String::from("bootout"), format!("system/{name}")],
                &[],
            )?;
            std::fs::remove_file(&plist).map_err(|error| said(Path::new(&plist), &error))?;
            // The folder's daemon goes with it; the folder stays for others.
            let run = format!("/Library/LaunchDaemons/{name}.run.plist");
            let _ = command(
                "launchctl",
                &[String::from("bootout"), format!("system/{name}.run")],
                &[],
            );
            let _ = std::fs::remove_file(&run);
            Ok(format!(
                "{name} stopped and removed; its configuration and data are kept"
            ))
        }
    }
    _ => {
        /// No service manager to remove from.
        ///
        /// # Errors
        ///
        /// Always: this platform has none.
        pub fn deregister(_: &str, _: &str) -> Result<String, String> {
            Err("this platform has no service manager".to_string())
        }
    }
}
