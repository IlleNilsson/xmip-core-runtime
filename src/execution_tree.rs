use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use xmip_core::{ExtensionManifest, ModuleManifest};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmipServiceConfiguration {
    pub service_name: String,
    pub cluster_name: String,
    pub node_name: String,
    pub modules: Vec<ConfiguredModule>,
    pub xmip_processes: Vec<ConfiguredXmipProcess>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredModule {
    pub name: String,
    pub manifest: ModuleManifest,
    pub start: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredXmipProcess {
    pub name: String,
    pub start: bool,
    pub required_modules: Vec<String>,
    pub xmip_subprocesses: Vec<ConfiguredXmipSubprocess>,
    pub extensions: Vec<ExtensionManifest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredXmipSubprocess {
    pub name: String,
    pub required_modules: Vec<String>,
    pub extensions: Vec<ExtensionManifest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTree {
    pub service_name: String,
    pub cluster_name: String,
    pub node_name: String,
    pub modules_to_start: Vec<ModuleStartupNode>,
    pub xmip_processes_to_start: Vec<XmipProcessStartupNode>,
    pub verified_extensions: Vec<VerifiedExtensionNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleStartupNode {
    pub name: String,
    pub manifest: ModuleManifest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmipProcessStartupNode {
    pub name: String,
    pub required_modules: Vec<String>,
    pub xmip_subprocesses: Vec<XmipSubprocessStartupNode>,
    pub extension_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmipSubprocessStartupNode {
    pub name: String,
    pub required_modules: Vec<String>,
    pub extension_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedExtensionNode {
    pub name: String,
    pub version: String,
    pub loaded_during_startup: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl StartupValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn build_execution_tree(
    configuration: XmipServiceConfiguration,
) -> Result<(ExecutionTree, StartupValidationReport), StartupValidationReport> {
    let report = validate_startup_configuration(&configuration);
    if !report.is_valid() {
        return Err(report);
    }

    let modules_to_start = configuration
        .modules
        .iter()
        .filter(|module| module.start)
        .map(|module| ModuleStartupNode {
            name: module.name.clone(),
            manifest: module.manifest.clone(),
        })
        .collect::<Vec<_>>();

    let mut verified_extensions = Vec::new();
    let xmip_processes_to_start = configuration
        .xmip_processes
        .iter()
        .filter(|xmip_process| xmip_process.start)
        .map(|xmip_process| {
            for extension in &xmip_process.extensions {
                verified_extensions.push(verified_extension(extension));
            }

            let xmip_subprocesses = xmip_process
                .xmip_subprocesses
                .iter()
                .map(|xmip_subprocess| {
                    for extension in &xmip_subprocess.extensions {
                        verified_extensions.push(verified_extension(extension));
                    }

                    XmipSubprocessStartupNode {
                        name: xmip_subprocess.name.clone(),
                        required_modules: xmip_subprocess.required_modules.clone(),
                        extension_names: xmip_subprocess
                            .extensions
                            .iter()
                            .map(|extension| extension.name.clone())
                            .collect(),
                    }
                })
                .collect();

            XmipProcessStartupNode {
                name: xmip_process.name.clone(),
                required_modules: xmip_process.required_modules.clone(),
                xmip_subprocesses,
                extension_names: xmip_process
                    .extensions
                    .iter()
                    .map(|extension| extension.name.clone())
                    .collect(),
            }
        })
        .collect();

    Ok((
        ExecutionTree {
            service_name: configuration.service_name,
            cluster_name: configuration.cluster_name,
            node_name: configuration.node_name,
            modules_to_start,
            xmip_processes_to_start,
            verified_extensions,
        },
        report,
    ))
}

pub fn validate_startup_configuration(
    configuration: &XmipServiceConfiguration,
) -> StartupValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let configured_modules = configuration
        .modules
        .iter()
        .map(|module| module.name.as_str())
        .collect::<BTreeSet<_>>();

    let started_modules = configuration
        .modules
        .iter()
        .filter(|module| module.start)
        .map(|module| module.name.as_str())
        .collect::<BTreeSet<_>>();

    for module in &configuration.modules {
        if module.name.trim().is_empty() {
            errors.push("configured module requires a name".to_string());
        }

        if module.manifest.capabilities.is_empty() {
            warnings.push(format!("module '{}' declares no capabilities", module.name));
        }
    }

    for xmip_process in &configuration.xmip_processes {
        if xmip_process.name.trim().is_empty() {
            errors.push("configured Xmip Process requires a name".to_string());
        }

        for required_module in &xmip_process.required_modules {
            validate_required_module(
                required_module,
                &configured_modules,
                &started_modules,
                &mut errors,
                &mut warnings,
                &format!("Xmip Process '{}'", xmip_process.name),
            );
        }

        for extension in &xmip_process.extensions {
            verify_extension_manifest(
                extension,
                &mut errors,
                &format!("Xmip Process '{}'", xmip_process.name),
            );
        }

        for xmip_subprocess in &xmip_process.xmip_subprocesses {
            if xmip_subprocess.name.trim().is_empty() {
                errors.push(format!(
                    "Xmip Process '{}' has an Xmip Subprocess without a name",
                    xmip_process.name
                ));
            }

            for required_module in &xmip_subprocess.required_modules {
                validate_required_module(
                    required_module,
                    &configured_modules,
                    &started_modules,
                    &mut errors,
                    &mut warnings,
                    &format!(
                        "Xmip Subprocess '{}' of Xmip Process '{}'",
                        xmip_subprocess.name, xmip_process.name
                    ),
                );
            }

            for extension in &xmip_subprocess.extensions {
                verify_extension_manifest(
                    extension,
                    &mut errors,
                    &format!(
                        "Xmip Subprocess '{}' of Xmip Process '{}'",
                        xmip_subprocess.name, xmip_process.name
                    ),
                );
            }
        }
    }

    StartupValidationReport { errors, warnings }
}

fn validate_required_module(
    required_module: &str,
    configured_modules: &BTreeSet<&str>,
    started_modules: &BTreeSet<&str>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    owner: &str,
) {
    if !configured_modules.contains(required_module) {
        errors.push(format!(
            "{owner} requires missing module '{required_module}'"
        ));
        return;
    }

    if !started_modules.contains(required_module) {
        warnings.push(format!(
            "{owner} requires module '{required_module}', but it is configured not to start"
        ));
    }
}

fn verify_extension_manifest(extension: &ExtensionManifest, errors: &mut Vec<String>, owner: &str) {
    if extension.name.trim().is_empty() {
        errors.push(format!("{owner} references an extension without a name"));
    }

    if extension.version.trim().is_empty() {
        errors.push(format!("extension '{}' requires a version", extension.name));
    }

    if extension.entrypoint.path.trim().is_empty() {
        errors.push(format!(
            "extension '{}' requires an entrypoint path",
            extension.name
        ));
    }
}

fn verified_extension(extension: &ExtensionManifest) -> VerifiedExtensionNode {
    VerifiedExtensionNode {
        name: extension.name.clone(),
        version: extension.version.clone(),
        loaded_during_startup: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmip_core::{
        ExecutionHostKind, ExtensionEntrypoint, ModuleCapability, ModuleEntrypoint, ModuleIdentity,
        ModuleKind,
    };

    #[test]
    fn verifies_extensions_without_loading_them() {
        let configuration = XmipServiceConfiguration {
            service_name: "xmip".to_string(),
            cluster_name: "home".to_string(),
            node_name: "node-a".to_string(),
            modules: vec![ConfiguredModule {
                name: "file".to_string(),
                start: true,
                manifest: ModuleManifest {
                    identity: ModuleIdentity {
                        name: "file".to_string(),
                        version: "0.1.0".to_string(),
                        kind: ModuleKind::TransportHandler,
                    },
                    capabilities: vec![ModuleCapability {
                        capability: "transport:file".to_string(),
                        execution_host: ExecutionHostKind::NativeRust,
                        trusted_required: true,
                    }],
                    entrypoint: ModuleEntrypoint {
                        library_path: Some("xmip_handler_file".to_string()),
                        executable_path: None,
                        symbol: Some("xmip_create_module".to_string()),
                    },
                },
            }],
            xmip_processes: vec![ConfiguredXmipProcess {
                name: "inbound".to_string(),
                start: true,
                required_modules: vec!["file".to_string()],
                xmip_subprocesses: vec![ConfiguredXmipSubprocess {
                    name: "normalize".to_string(),
                    required_modules: vec!["file".to_string()],
                    extensions: vec![ExtensionManifest {
                        name: "normalize-text".to_string(),
                        version: "0.1.0".to_string(),
                        execution_host: ExecutionHostKind::NativeRust,
                        entrypoint: ExtensionEntrypoint {
                            path: "extensions/normalize_text".to_string(),
                            symbol_or_command: Some("run".to_string()),
                        },
                        required_capabilities: Vec::new(),
                    }],
                }],
                extensions: Vec::new(),
            }],
        };

        let (tree, report) = build_execution_tree(configuration).expect("valid tree");

        assert!(report.is_valid());
        assert_eq!(tree.modules_to_start.len(), 1);
        assert_eq!(tree.xmip_processes_to_start.len(), 1);
        assert_eq!(tree.verified_extensions.len(), 1);
        assert!(!tree.verified_extensions[0].loaded_during_startup);
    }
}
