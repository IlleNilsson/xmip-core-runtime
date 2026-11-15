//! What launchd is told about a definition: the daemon's property list, and
//! the daemon beside it that makes the node's folder of its local endpoint.
//! Pure, as the rest of `registration` is; applying it is the installer's
//! (`xmip-service --install`).

use super::ServiceDefinition;
use crate::plane::local::{MACOS_FOLDER, MACOS_SOCKET_PATH, own_folder};

/// The launchd daemon that makes the node's folder, named as the local
/// endpoint it binds is and placed by the one rule
/// (`plane::local::own_folder`), under `/var/run/xmip`, for this
/// definition's account at every boot, `/var/run/xmip` above it root's —
/// macOS empties `/var/run` as it starts, and launchd has no spelling of
/// systemd's `RuntimeDirectory` (decided by the owner, 2026-10-13: *created
/// by systemd / launchd for the node's account*, and 2026-11-15: a folder
/// per node). It runs as root, once at load, and is labeled `<name>.run`.
///
/// # Errors
///
/// A definition that binds no local endpoint, a Host Service's, or an
/// endpoint's name the rule refuses, in words.
pub fn launchd_run_directory(definition: &ServiceDefinition) -> Result<String, String> {
    let endpoint = definition.local.as_deref().ok_or_else(|| {
        format!(
            "{} binds no local endpoint, so it has no folder to make",
            definition.name
        )
    })?;
    let folder = own_folder(MACOS_FOLDER, MACOS_SOCKET_PATH, endpoint)?;
    let owner = definition
        .service_identity
        .as_deref()
        .map_or(String::new(), |user| {
            format!(" &amp;&amp; chown {user} {folder}")
        });
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{name}.run</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>/bin/sh</string>\n\
         \t\t<string>-c</string>\n\
         \t\t<string>mkdir -p -m 0755 {folder}{owner}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         </dict>\n\
         </plist>\n",
        name = definition.name,
    ))
}

/// A launchd property list for this definition.
///
/// `RunAtLoad` with `KeepAlive` on `SuccessfulExit=false` is launchd's spelling
/// of `Restart=on-failure`, for the same reason. launchd has no spelling of
/// `RestartPreventExitStatus`, so a refused node is started again after its
/// throttle interval, until an operator fixes its configuration.
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
    let environment = if definition.environment.is_empty() {
        String::new()
    } else {
        let pairs: String = definition
            .environment
            .iter()
            .map(|(name, value)| format!("\t\t<key>{name}</key>\n\t\t<string>{value}</string>\n"))
            .collect();
        format!("\t<key>EnvironmentVariables</key>\n\t<dict>\n{pairs}\t</dict>\n")
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
         {environment}\
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
        environment = environment,
    )
}
