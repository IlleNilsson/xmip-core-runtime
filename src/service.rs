//! ADR-0018's nine startup phases, by the names the record gives them, and
//! the first one's reading of a node's configuration. The phases run in
//! `running.rs`; `start.rs` runs the first three for a surface.

use std::fmt;

use configure::{PARSE_FAILED, XmipConfigurationDocument, parse_toml};
use serde::{Deserialize, Serialize};

use crate::execution_tree::StartupValidationReport;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartupPhase {
    ReadConfiguration,
    BuildExecutionTree,
    ValidateStartup,
    PlanHostServices,
    StartHostServices,
    LoadModules,
    RegisterCapabilities,
    VerifyExtensions,
    AcceptWork,
}

impl StartupPhase {
    #[must_use]
    pub const fn id(&self) -> &'static str {
        match self {
            StartupPhase::ReadConfiguration => "read-configuration",
            StartupPhase::BuildExecutionTree => "build-execution-tree",
            StartupPhase::ValidateStartup => "validate-startup",
            StartupPhase::PlanHostServices => "plan-host-services",
            StartupPhase::StartHostServices => "start-host-services",
            StartupPhase::LoadModules => "load-modules",
            StartupPhase::RegisterCapabilities => "register-capabilities",
            StartupPhase::VerifyExtensions => "verify-extensions",
            StartupPhase::AcceptWork => "accept-work",
        }
    }
}

/// Startup phase 1: a node configuration's text read as `configure`'s one
/// document, or the reader's refusal as the report.
///
/// # Errors
/// The report, when the text does not parse.
pub fn read_node(source: &str) -> Result<XmipConfigurationDocument, StartupValidationReport> {
    parse_toml(source).map_err(|error| StartupValidationReport {
        errors: vec![format!("{PARSE_FAILED}: {error}")],
        warnings: Vec::new(),
    })
}

impl fmt::Display for StartupPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

#[must_use]
pub fn startup_phases() -> Vec<StartupPhase> {
    vec![
        StartupPhase::ReadConfiguration,
        StartupPhase::BuildExecutionTree,
        StartupPhase::ValidateStartup,
        StartupPhase::PlanHostServices,
        StartupPhase::StartHostServices,
        StartupPhase::LoadModules,
        StartupPhase::RegisterCapabilities,
        StartupPhase::VerifyExtensions,
        StartupPhase::AcceptWork,
    ]
}

#[must_use]
pub fn startup_sequence() -> Vec<&'static str> {
    startup_phases().iter().map(StartupPhase::id).collect()
}
