//! What the Windows Service Control Manager is told about a definition: the
//! `sc.exe create` arguments, and the settings that finish the registration
//! after it. Pure, as the rest of `registration` is; applying it is the
//! installer's (`xmip-service --install`).

use super::{ServiceDefinition, quoted};

/// The `sc.exe create` arguments for this definition.
///
/// Returned as arguments rather than as a command line, so a caller passes them
/// to the process API without quoting anything. `binPath=` is the one place
/// Windows requires the executable and its arguments to be one string, and the
/// space after each `=` is required by `sc.exe` — omitting it is the classic
/// way this fails with an unhelpful usage message.
#[must_use]
pub fn windows_service_arguments(definition: &ServiceDefinition) -> Vec<String> {
    let mut binary = quoted(&definition.executable);

    for argument in &definition.arguments {
        binary.push(' ');
        binary.push_str(&quoted(argument));
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

/// What finishes a Windows registration after `sc.exe create`, each a
/// program and its arguments: the description, which `create` cannot set,
/// and the environment where the definition has one — the service's own
/// `Environment` value, which the Service Control Manager hands the process
/// and no other program sees.
#[must_use]
pub fn windows_service_settings(definition: &ServiceDefinition) -> Vec<(String, Vec<String>)> {
    let mut settings = vec![(
        String::from("sc.exe"),
        vec![
            String::from("description"),
            definition.name.clone(),
            definition.description.clone(),
        ],
    )];

    if !definition.environment.is_empty() {
        let variables = definition
            .environment
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("\\0");
        settings.push((
            String::from("reg.exe"),
            vec![
                String::from("add"),
                format!(
                    r"HKLM\SYSTEM\CurrentControlSet\Services\{}",
                    definition.name
                ),
                String::from("/v"),
                String::from("Environment"),
                String::from("/t"),
                String::from("REG_MULTI_SZ"),
                String::from("/d"),
                variables,
                String::from("/f"),
            ],
        ));
    }

    settings
}
