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

use crate::plane::local::{LINUX_FOLDER, LINUX_SOCKET_PATH, own_folder};

mod launchd;
mod windows_scm;

pub use launchd::{launchd_plist, launchd_run_directory};
pub use windows_scm::{windows_service_arguments, windows_service_settings};

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

    /// What the service's environment holds beyond the platform's, each a
    /// name and its value: the audit directory an installer gave the node
    /// (ADR-0062), and nothing a person types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<(String, String)>,

    /// The name of the local endpoint the node binds ([`local_endpoint`]),
    /// whose folder the service manager makes for the node's account; none
    /// for a Host Service, which binds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
}

impl ServiceDefinition {
    /// The Xmip Service for a node: the master, and the only thing the
    /// operating system starts — `xmip-service --configuration <path>`, the
    /// estate root's executable (ADR-0018, amendment 2026-09-26).
    #[must_use]
    pub fn for_node(
        node: &str,
        executable: &str,
        configuration: &str,
        working_directory: &str,
    ) -> Self {
        Self {
            name: node_service_name(node),
            display_name: format!("Xmip Service ({node})"),
            description: format!(
                "Starts node {node} from its configuration, runs its in-process Host \
                 Service, and drains it when the service manager stops it."
            ),
            executable: executable.into(),
            arguments: vec![String::from("--configuration"), configuration.into()],
            service_identity: None,
            working_directory: working_directory.into(),
            environment: Vec::new(),
            local: Some(local_endpoint(node, None)),
        }
    }

    /// A Host Service, named for the work it holds.
    ///
    /// The description lists what it hosts, because that is the question an
    /// operator has when they find it in the service list and do not recognize
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
            environment: Vec::new(),
            local: None,
        }
    }

    /// The same definition, running as a named account rather than the
    /// platform default.
    #[must_use]
    pub fn running_as(mut self, identity: &str) -> Self {
        self.service_identity = Some(identity.into());
        self
    }

    /// The same definition, its environment holding `name` as `value`.
    #[must_use]
    pub fn with_variable(mut self, name: &str, value: &str) -> Self {
        self.environment.push((name.into(), value.into()));
        self
    }

    /// The same definition, the node binding the local endpoint called
    /// `endpoint`: what its configuration names ([`local_endpoint`]).
    #[must_use]
    pub fn serving_at(mut self, endpoint: &str) -> Self {
        self.local = Some(endpoint.into());
        self
    }
}

/// The name of node `node`'s local endpoint: `configured`, what its
/// `[operate] local` names, else the name its Xmip Service has,
/// `xmip-<node>` — decided by the owner, 2026-10-13: *the local endpoint
/// always starts, named `xmip-<node>` unless the configuration names it*.
#[must_use]
pub fn local_endpoint(node: &str, configured: Option<&str>) -> String {
    configured.map_or_else(|| node_service_name(node), str::to_string)
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
        cfg_select! {
            target_os = "windows" => Self::WindowsScm,
            target_os = "linux" => Self::Systemd,
            target_os = "macos" => Self::Launchd,
            _ => Self::None,
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
/// `Restart=on-failure` rather than `always`, and never after [`REFUSED`]:
/// a validation failure is not something restarting fixes — the
/// configuration is wrong and will still be wrong. Restarting it forever
/// turns one legible refusal into a log nobody reads. A stop exits 0, which
/// is no failure, so systemd restarts nothing Xmip stopped on purpose.
///
/// `RuntimeDirectory=xmip/<name>` makes the node's folder, named as the
/// local endpoint it binds is and placed by the one rule
/// (`plane::local::own_folder`), for the node's account, and `/run/xmip`
/// above it root's — decided by the owner, 2026-10-13: *created by systemd /
/// launchd for the node's account*, and 2026-11-15: a folder per node, so
/// two nodes under two accounts never take each other's socket — and keeps
/// it when the unit stops. systemd.exec: *the innermost specified
/// directories will be owned by the user and group specified in `User=` and
/// `Group=`*. A Host Service binds no endpoint and is given no folder.
///
/// # Errors
///
/// An endpoint's name the rule refuses, in its words.
pub fn systemd_unit(definition: &ServiceDefinition) -> Result<String, String> {
    let arguments = definition
        .arguments
        .iter()
        .map(|argument| quoted(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let identity = match &definition.service_identity {
        Some(user) => format!("User={user}\n"),
        None => String::new(),
    };
    let environment: String = definition
        .environment
        .iter()
        .map(|(name, value)| format!("Environment=\"{name}={value}\"\n"))
        .collect();
    let runtime = match &definition.local {
        // `/run/xmip/<name>` as systemd names a folder under `/run`.
        Some(endpoint) => format!(
            "RuntimeDirectory={}\nRuntimeDirectoryMode=0755\nRuntimeDirectoryPreserve=yes\n",
            own_folder(LINUX_FOLDER, LINUX_SOCKET_PATH, endpoint)?.trim_start_matches("/run/")
        ),
        None => String::new(),
    };

    Ok(format!(
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
         {environment}\
         {runtime}\
         Restart=on-failure\n\
         RestartPreventExitStatus={refused}\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        description = definition.description,
        executable = quoted(&definition.executable),
        arguments = arguments,
        working = definition.working_directory,
        identity = identity,
        environment = environment,
        refused = REFUSED,
        runtime = runtime,
    ))
}

/// The exit code of a node the Xmip Service refused to start: its
/// configuration does not read, or names what the program was not built
/// with. A service manager does not restart it; an operator fixes it.
pub const REFUSED: u8 = 2;

/// The registered name of a node's Xmip Service, `xmip-<node>` (ADR-0053
/// clause 1): what a service manager starts and stops it by.
#[must_use]
pub fn node_service_name(node: &str) -> String {
    format!("xmip-{node}")
}

/// `text` as one argument on a command line that systemd and the Windows
/// service control manager split at spaces: double-quoted where it has one.
fn quoted(text: &str) -> String {
    if text.contains(' ') {
        format!("\"{text}\"")
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node registered: the test cluster's first.
    fn node() -> String {
        configure::fixture::test_cluster().node(0).name.clone()
    }

    fn node_service() -> ServiceDefinition {
        ServiceDefinition::for_node(
            &node(),
            "/opt/xmip/bin/xmip-service",
            "/opt/xmip/config/node.xmip",
            "/opt/xmip",
        )
    }

    /// The systemd unit of `definition`, whose endpoint's name the rule
    /// takes.
    fn unit(definition: &ServiceDefinition) -> String {
        systemd_unit(definition).expect("a unit")
    }

    /// The launchd daemon making `definition`'s folder.
    fn run(definition: &ServiceDefinition) -> String {
        launchd_run_directory(definition).expect("a daemon")
    }

    #[test]
    fn a_node_service_is_named_and_described_from_the_node() {
        let definition = node_service();

        let node = node();
        assert_eq!(definition.name, format!("xmip-{node}"));
        assert!(definition.display_name.contains(&node));
        assert!(definition.description.contains(&format!("node {node}")));
        assert_eq!(
            definition.arguments,
            ["--configuration", "/opt/xmip/config/node.xmip"]
        );
    }

    #[test]
    fn a_host_service_says_what_it_hosts() {
        // The question an operator has when they find a name they do not
        // recognize in the service list.
        let hosts = vec![String::from("ftp receive"), String::from("sftp send")];
        let definition = ServiceDefinition::for_host(
            &node(),
            "transport",
            &hosts,
            "/opt/xmip/bin/xmip",
            "/opt/xmip",
        );

        assert_eq!(definition.name, format!("xmip-{}-transport", node()));
        assert!(definition.description.contains("ftp receive, sftp send"));
    }

    #[test]
    fn a_host_service_with_nothing_in_it_says_so() {
        let definition = ServiceDefinition::for_host(
            &node(),
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
        let unit = unit(&node_service());

        assert!(unit.contains("Type=notify"));
        assert!(!unit.contains("Type=simple"));
    }

    #[test]
    fn the_systemd_unit_does_not_restart_a_refusal_forever() {
        let unit = unit(&node_service());

        assert!(unit.contains("Restart=on-failure"));
        assert!(!unit.contains("Restart=always"));
    }

    /// Decided by the owner, 2026-10-13: the local endpoints' folder is
    /// *created by systemd / launchd for the node's account*; and
    /// 2026-11-15: a folder per node, beneath the root-owned one, named as
    /// the endpoint the node binds is.
    #[test]
    fn the_nodes_folder_is_made_for_the_nodes_account() {
        let name = node_service().name;
        let unit = unit(&node_service().running_as("xmip"));
        assert!(
            unit.contains(&format!("RuntimeDirectory=xmip/{name}\n")),
            "{unit}"
        );
        assert!(unit.contains("RuntimeDirectoryMode=0755\n"));
        assert!(unit.contains("RuntimeDirectoryPreserve=yes\n"));

        let made = run(&node_service().running_as("xmip"));
        let folder = format!("/var/run/xmip/{name}");
        let said = format!("mkdir -p -m 0755 {folder} &amp;&amp; chown xmip {folder}<");
        assert!(made.contains(&said), "{made}");
        assert!(made.contains(&format!("<string>{name}.run</string>")));
        assert!(!run(&node_service()).contains("chown"));
    }

    /// The folder is the endpoint's the configuration names, by the one
    /// rule the node binds by and every surface connects by
    /// (`plane::local::own_folder`), read for nothing: a custom
    /// `[operate] local` is its folder's name too, and a Host Service, which
    /// binds no endpoint, is given none.
    #[test]
    fn the_folder_is_the_endpoints_the_node_binds() {
        let named = node_service().serving_at("orders");
        assert!(unit(&named).contains("RuntimeDirectory=xmip/orders\n"));
        assert!(run(&named).contains("mkdir -p -m 0755 /var/run/xmip/orders<"));
        let node = node();
        assert_eq!(local_endpoint(&node, None), node_service_name(&node));
        assert_eq!(local_endpoint(&node, Some("orders")), "orders");

        let host = ServiceDefinition::for_host(&node, "transport", &[], "x", "/opt/xmip");
        assert!(!unit(&host).contains("RuntimeDirectory"));
        assert!(launchd_run_directory(&host).is_err());

        let long = node_service().serving_at(&"n".repeat(60));
        let refused = systemd_unit(&long).expect_err("no room");
        assert!(refused.contains("at most 107 bytes"), "{refused}");
        let refused = launchd_run_directory(&long).expect_err("no room");
        assert!(refused.contains("at most 103 bytes"), "{refused}");
    }

    /// The finding of 2026-11-14, decided by the owner on 2026-11-15: two
    /// nodes on one machine under two accounts are given two folders, each
    /// its own account's, so neither start takes the other's socket.
    #[test]
    fn two_nodes_under_two_accounts_are_given_two_folders() {
        let at = |node: &str, account: &str| {
            let definition =
                ServiceDefinition::for_node(node, "/opt/xmip/bin/xmip-service", "c", "/opt/xmip")
                    .running_as(account);
            (unit(&definition), run(&definition))
        };
        let (one, one_run) = at("n1", "alice");
        let (two, two_run) = at("n2", "bob");
        assert!(one.contains("User=alice\n") && one.contains("RuntimeDirectory=xmip/xmip-n1\n"));
        assert!(two.contains("User=bob\n") && two.contains("RuntimeDirectory=xmip/xmip-n2\n"));
        assert!(
            one_run.contains("chown alice /var/run/xmip/xmip-n1<"),
            "{one_run}"
        );
        assert!(
            two_run.contains("chown bob /var/run/xmip/xmip-n2<"),
            "{two_run}"
        );
    }

    #[test]
    fn the_systemd_unit_omits_the_user_when_there_is_none() {
        let unit = unit(&node_service());

        assert!(!unit.contains("User="));
    }

    #[test]
    fn the_systemd_unit_names_the_service_identity_when_there_is_one() {
        let unit = unit(&node_service().running_as("xmip"));

        assert!(unit.contains("User=xmip"));
    }

    #[test]
    fn the_launchd_plist_lists_the_executable_before_its_arguments() {
        let plist = launchd_plist(&node_service());
        let executable = plist
            .find("/opt/xmip/bin/xmip-service")
            .expect("executable");
        let argument = plist.find("--configuration").expect("argument");

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

        assert!(bin.contains("/opt/xmip/bin/xmip-service"));
        assert!(bin.contains("--configuration /opt/xmip/config/node.xmip"));
    }

    #[test]
    fn a_path_with_a_space_stays_one_argument() {
        let definition = ServiceDefinition::for_node(
            &node(),
            r"C:\Program Files\Xmip\bin\xmip-service.exe",
            r"C:\ProgramData\Xmip\config\node.xmip",
            r"C:\ProgramData\Xmip",
        );

        assert_eq!(
            windows_service_arguments(&definition)[2],
            r#"binPath= "C:\Program Files\Xmip\bin\xmip-service.exe" --configuration C:\ProgramData\Xmip\config\node.xmip"#
        );
        assert!(unit(&definition).contains(r#"ExecStart="C:\Program Files\"#));
    }

    #[test]
    fn every_manager_hands_the_service_its_environment() {
        let audit = "/var/opt/xmip/data/audit";
        let definition = node_service().with_variable("XMIP_AUDIT_DIRECTORY", audit);

        assert!(
            unit(&definition).contains(&format!("Environment=\"XMIP_AUDIT_DIRECTORY={audit}\"\n"))
        );
        let plist = launchd_plist(&definition);
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains(&format!("<string>{audit}</string>")));
        let settings = windows_service_settings(&definition);
        assert_eq!(settings[0].1[0], "description");
        assert_eq!(settings[1].0, "reg.exe");
        assert!(
            settings[1]
                .1
                .contains(&format!("XMIP_AUDIT_DIRECTORY={audit}"))
        );
    }

    #[test]
    fn a_service_with_no_environment_sets_none() {
        let definition = node_service();

        assert!(!unit(&definition).contains("Environment="));
        assert!(!launchd_plist(&definition).contains("EnvironmentVariables"));
        assert_eq!(windows_service_settings(&definition).len(), 1);
    }

    #[test]
    fn the_systemd_unit_does_not_restart_a_refused_node() {
        let unit = unit(&node_service());

        assert!(unit.contains(&format!("RestartPreventExitStatus={REFUSED}")));
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

        cfg_select! {
            target_os = "windows" => {
                assert_eq!(manager, ServiceManager::WindowsScm);
            }
            target_os = "linux" => {
                assert_eq!(manager, ServiceManager::Systemd);
            }
            target_os = "macos" => {
                assert_eq!(manager, ServiceManager::Launchd);
            }
            _ => {}
        }
    }
}
