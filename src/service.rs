use crate::execution_tree::{ExecutionTree, StartupValidationReport, build_execution_tree};
use configure::parse_toml;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XmipServiceState {
    Created,
    ConfigurationRead,
    ExecutionTreeBuilt,
    StartupValidated,
    ReadyToStartHostServices,
    Running,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn id(&self) -> &'static str {
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

#[derive(Clone, Debug)]
pub struct XmipServiceStartupPlan {
    pub state: XmipServiceState,
    pub phases: Vec<StartupPhase>,
    pub execution_tree: ExecutionTree,
    pub validation_report: StartupValidationReport,
}

/// Startup phases 1 to 3 over a node configuration's text: read it as
/// `configure`'s one document, build the execution tree, validate it.
///
/// # Errors
/// The report, when the text does not parse or the document does not validate.
pub fn plan_startup_from_toml(
    source: &str,
) -> Result<XmipServiceStartupPlan, StartupValidationReport> {
    let document = parse_toml(source).map_err(|error| StartupValidationReport {
        errors: vec![format!("configuration parse failed: {error}")],
        warnings: Vec::new(),
    })?;

    let (execution_tree, validation_report) = build_execution_tree(document)?;

    Ok(XmipServiceStartupPlan {
        state: XmipServiceState::ReadyToStartHostServices,
        phases: startup_phases(),
        execution_tree,
        validation_report,
    })
}

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

pub fn startup_sequence() -> Vec<&'static str> {
    startup_phases().iter().map(StartupPhase::id).collect()
}
