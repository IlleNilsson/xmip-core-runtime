//! Registering the Xmip Service and the Host Services with the platform.
//!
//! ADR-0018: the Xmip Service is the only thing the operating system starts,
//! and the Host Services it supervises are *registered services rather than
//! child processes* — which is what lets an operator stop one by name, and what
//! makes the service list a description of the node.
//!
//! **The name and description are generated, never authored.** ADR-0018 again:
//! an operator reading the service list can tell what each one does. A
//! hand-written display name is a description of what somebody meant at install
//! time, and it stops being true the first time configuration changes.
//!
//! ## What is here and what is not
//!
//! This module turns a [`ServiceDefinition`] into exactly what each platform's
//! service manager needs: a systemd unit, a launchd property list, or the
//! arguments for the Windows service control manager. That part is pure, and it
//! is where the mistakes are — a unit file with the wrong `Type=` restarts
//! forever, and nobody finds out until a node reboots at three in the morning.
//!
//! **Applying it is deliberately not here.** Registration needs elevation on
//! every platform that has it — administrator for the Windows SCM, root to
//! write a unit and reload — and ADR-0018 records that as an open question
//! rather than a settled one. Generating is safe, testable on any machine, and
//! reviewable; performing it is a privileged act that belongs with the
//! installer and its own decision.
//!
//! ## The device case is not here either
//!
//! `deployment-model.md` says the installer registers the Xmip Service *where
//! services exist*, and a microcontroller has no service manager to register
//! with — the runtime is the firmware entry point. That is open problem 22 and
//! this module does not pretend otherwise: [`ServiceManager::None`] names it.

use serde::{Deserialize, Serialize};

/// What the operating system is told about one service.
///
/// Everything an operator sees comes from here, and everything here comes from
/// configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDefinition {
    /// The name the service is registered, started and stopped by.
    pub name: String,

    /// What an operator sees in the service list.
    pub display_name: String,

    /// One line saying what this service does, generated from what it hosts.
    pub description: String,

    /// The Xmip binary this service runs.
    pub executable: String,

    /// Arguments that select which part of the node this service is.
    pub arguments: Vec<String>,

    /// The account it runs as. `None` means the platform default, which is
    /// LocalSystem on Windows and root under systemd — neither of which is what
    /// `deployment-model.md` section 5 wants for a production node.
    pub service_identity: Option<String>,

    /// The node's installation directory.
    pub working_directory: String,
}

impl ServiceDefinition {
    /// The Xmip Service for a node: the master, and the only thing the
    /// operating system starts.
    #[must_use]
    pub fn for_node(node: &str, executable: &str, working_directory: &str) -> Self {
        Self {
            name: format!("xmip-{node}"),
            display_name: format!("Xmip Service ({node})"),
            description: format!(
                "Reads the configuration for node {node}, builds and validates the \
                 execution tree, and supervises its Host Services. Not in the message path."
            ),
            executable: executable.into(),
            arguments: vec![String::from("service"), format!("--node={node}")],
            service_identity: None,
            working_directory: working_directory.into(),
        }
    }

    /// A Host Service, named for the work it holds.
    ///
    /// The description lists what it hosts, because that is the question an
    /// operator has when they find it in the service list and do not recognise
    /// the name.
    #[must_use]
    pub fn for_host(
        node: &str,
        host_type: &str,
        hosts: &[String],
        executable: &str,
        working_directory: &str,
    ) -> Self {
        let what = if hosts.is_empty() {
            String::from("nothing yet")
        } else {
            hosts.join(", ")
        };

        Self {
            name: format!("xmip-{node}-{host_type}"),
            display_name: format!("Xmip Host Service ({node}/{host_type})"),
            description: format!("Hosts {what} for node {node}."),
            executable: executable.into(),
            arguments: vec![
                String::from("host"),
                format!("--node={node}"),
                format!("--host={host_type}"),
            ],
            service_identity: None,
            working_directory: working_directory.into(),
        }
    }

    /// The same definition, running as a named account rather than the
    /// platform default.
    #[must_use]
    pub fn running_as(mut self, identity: &str) -> Self {
        self.service_identity = Some(identity.into());
        self
    }
}

/// What manages services on a platform.
///
/// `None` is a real answer, not a failure: an IoT device runs the runtime as
/// its firmware and has nothing to register with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceManager {
    WindowsScm,
    Systemd,
    Launchd,
    None,
}

impl ServiceManager {
    /// What this build's target platform uses.
    ///
    /// Resolved at compile time rather than probed, because a build for a
    /// bare-metal target has no service manager to probe for.
    #[must_use]
    pub const fn for_target() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::WindowsScm
        }
        #[cfg(target_os = "linux")]
        {
            Self::Systemd
        }
        #[cfg(target_os = "macos")]
        {
            Self::Launchd
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Self::None
        }
    }

    /// Whether registering means anything here.
    #[must_use]
    pub const fn registers(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// A systemd unit for this definition.
///
/// `Type=notify` is deliberate and is the one field worth arguing about.
/// ADR-0018 gives startup nine phases ending at `AcceptWork`, and `simple`
/// would report the service up the moment the process existed — before the
/// execution tree is built, let alone validated. A node that reports ready
/// before it can accept work is a node whose dependencies start against
/// nothing.
///
/// `Restart=on-failure` rather than `always`, because a validation failure is
/// not something restarting fixes: the configuration is wrong and will still be
/// wrong. Restarting it forever turns one legible refusal into a log nobody
/// reads.
#[must_use]
pub fn systemd_unit(definition: &ServiceDefinition) -> String {
    let arguments = definition.arguments.join(" ");
    let identity = match &definition.service_identity {
        Some(user) => format!("User={user}\n"),
        None => String::new(),
    };

    format!(
        "[Unit]\n\
         Description={description}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=notify\n\
         ExecStart={executable} {arguments}\n\
         WorkingDirectory={working}\n\
         {identity}\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        description = definition.description,
        executable = definition.executable,
        arguments = arguments,
        working = definition.working_directory,
        identity = identity,
    )
}

/// A launchd property list for this definition.
///
/// `RunAtLoad` with `KeepAlive` on `SuccessfulExit=false` is launchd's spelling
/// of `Restart=on-failure`, for the same reason.
#[must_use]
pub fn launchd_plist(definition: &ServiceDefinition) -> String {
    let mut arguments = String::new();

    arguments.push_str(&format!("\t\t<string>{}</string>\n", definition.executable));

    for argument in &definition.arguments {
        arguments.push_str(&format!("\t\t<string>{argument}</string>\n"));
    }

    let identity = match &definition.service_identity {
        Some(user) => format!("\t<key>UserName</key>\n\t<string>{user}</string>\n"),
        None => String::new(),
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{name}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n{arguments}\t</array>\n\
         \t<key>WorkingDirectory</key>\n\
         \t<string>{working}</string>\n\
         {identity}\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<dict>\n\
         \t\t<key>SuccessfulExit</key>\n\
         \t\t<false/>\n\
         \t</dict>\n\
         </dict>\n\
         </plist>\n",
        name = definition.name,
        arguments = arguments,
        working = definition.working_directory,
        identity = identity,
    )
}

/// The `sc.exe create` arguments for this definition.
///
/// Returned as arguments rather than as a command line, so a caller passes them
/// to the process API without quoting anything. `binPath=` is the one place
/// Windows requires the executable and its arguments to be one string, and the
/// space after each `=` is required by `sc.exe` — omitting it is the classic
/// way this fails with an unhelpful usage message.
#[must_use]
pub fn windows_service_arguments(definition: &ServiceDefinition) -> Vec<String> {
    let mut binary = definition.executable.clone();

    for argument in &definition.arguments {
        binary.push(' ');
        binary.push_str(argument);
    }

    let mut arguments = vec![
        String::from("create"),
        definition.name.clone(),
        format!("binPath= {binary}"),
        format!("DisplayName= {}", definition.display_name),
        String::from("start= auto"),
    ];

    if let Some(user) = &definition.service_identity {
        arguments.push(format!("obj= {user}"));
    }

    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_service() -> ServiceDefinition {
        ServiceDefinition::for_node("edge-01", "/opt/xmip/bin/xmip", "/opt/xmip")
    }

    #[test]
    fn a_node_service_is_named_and_described_from_the_node() {
        let definition = node_service();

        assert_eq!(definition.name, "xmip-edge-01");
        assert!(definition.display_name.contains("edge-01"));
        assert!(
            definition
                .description
                .contains("supervises its Host Services")
        );
    }

    #[test]
    fn a_host_service_says_what_it_hosts() {
        // The question an operator has when they find a name they do not
        // recognise in the service list.
        let hosts = vec![String::from("ftp receive"), String::from("sftp send")];
        let definition = ServiceDefinition::for_host(
            "edge-01",
            "transport",
            &hosts,
            "/opt/xmip/bin/xmip",
            "/opt/xmip",
        );

        assert_eq!(definition.name, "xmip-edge-01-transport");
        assert!(definition.description.contains("ftp receive, sftp send"));
    }

    #[test]
    fn a_host_service_with_nothing_in_it_says_so() {
        let definition = ServiceDefinition::for_host(
            "edge-01",
            "transport",
            &[],
            "/opt/xmip/bin/xmip",
            "/opt/xmip",
        );

        assert!(definition.description.contains("nothing yet"));
    }

    #[test]
    fn the_systemd_unit_waits_for_readiness_rather_than_for_a_process() {
        // Type=simple would report the node up before the execution tree is
        // built. ADR-0018 gives startup nine phases and only the last accepts
        // work.
        let unit = systemd_unit(&node_service());

        assert!(unit.contains("Type=notify"));
        assert!(!unit.contains("Type=simple"));
    }

    #[test]
    fn the_systemd_unit_does_not_restart_a_refusal_forever() {
        let unit = systemd_unit(&node_service());

        assert!(unit.contains("Restart=on-failure"));
        assert!(!unit.contains("Restart=always"));
    }

    #[test]
    fn the_systemd_unit_omits_the_user_when_there_is_none() {
        let unit = systemd_unit(&node_service());

        assert!(!unit.contains("User="));
    }

    #[test]
    fn the_systemd_unit_names_the_service_identity_when_there_is_one() {
        let unit = systemd_unit(&node_service().running_as("xmip"));

        assert!(unit.contains("User=xmip"));
    }

    #[test]
    fn the_launchd_plist_lists_the_executable_before_its_arguments() {
        let plist = launchd_plist(&node_service());
        let executable = plist.find("/opt/xmip/bin/xmip").expect("executable");
        let argument = plist.find("--node=edge-01").expect("argument");

        assert!(executable < argument, "argv[0] comes first");
    }

    #[test]
    fn the_launchd_plist_restarts_only_on_failure() {
        let plist = launchd_plist(&node_service());

        assert!(plist.contains("SuccessfulExit"));
        assert!(plist.contains("<false/>"));
    }

    #[test]
    fn the_windows_arguments_keep_the_space_sc_requires() {
        // `binPath=C:\...` fails with a usage message that says nothing about
        // the missing space. Every sc.exe argument is `key= value`.
        let arguments = windows_service_arguments(&node_service());

        for argument in &arguments {
            if let Some(equals) = argument.find('=') {
                let after = argument[equals + 1..].chars().next();

                assert_eq!(
                    after,
                    Some(' '),
                    "sc.exe needs a space after '=' in {argument}"
                );
            }
        }
    }

    #[test]
    fn the_windows_arguments_pass_the_executable_and_its_arguments_as_one() {
        let arguments = windows_service_arguments(&node_service());
        let bin = arguments
            .iter()
            .find(|a| a.starts_with("binPath="))
            .expect("binPath");

        assert!(bin.contains("/opt/xmip/bin/xmip"));
        assert!(bin.contains("--node=edge-01"));
    }

    #[test]
    fn a_platform_with_no_service_manager_says_so_rather_than_failing() {
        // The device case. deployment-model.md says the installer registers
        // "where services exist", and this is what that sentence means in a
        // type. Open problem 22.
        assert!(!ServiceManager::None.registers());
        assert!(ServiceManager::Systemd.registers());
    }

    #[test]
    fn the_target_decides_the_service_manager() {
        // Compile-time, not probed: a bare-metal build has nothing to probe.
        let manager = ServiceManager::for_target();

        #[cfg(target_os = "windows")]
        assert_eq!(manager, ServiceManager::WindowsScm);

        #[cfg(target_os = "linux")]
        assert_eq!(manager, ServiceManager::Systemd);

        #[cfg(target_os = "macos")]
        assert_eq!(manager, ServiceManager::Launchd);
    }
}
