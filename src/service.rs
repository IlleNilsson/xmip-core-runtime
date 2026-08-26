use serde::{Deserialize, Serialize};
use xmip_configuration::parse_service_configuration;
use xmip_runtime::execution_tree::{build_execution_tree, ExecutionTree, StartupValidationReport};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum XmipServiceState {
    Created,
    ConfigurationRead,
    ExecutionTreeBuilt,
    StartupValidated,
    ReadyToStartSystemProcesses,
    Running,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartupPhase {
    ReadConfiguration,
    BuildExecutionTree,
    ValidateStartup,
    PlanSystemProcesses,
    StartSystemProcesses,
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
            StartupPhase::PlanSystemProcesses => "plan-system-processes",
            StartupPhase::StartSystemProcesses => "start-system-processes",
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

pub fn plan_startup_from_toml(
    source: &str,
) -> Result<XmipServiceStartupPlan, StartupValidationReport> {
    let configuration =
        parse_service_configuration(source).map_err(|error| StartupValidationReport {
            errors: vec![format!("configuration parse failed: {error}")],
            warnings: Vec::new(),
        })?;

    let (execution_tree, validation_report) = build_execution_tree(configuration)?;

    Ok(XmipServiceStartupPlan {
        state: XmipServiceState::ReadyToStartSystemProcesses,
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
        StartupPhase::PlanSystemProcesses,
        StartupPhase::StartSystemProcesses,
        StartupPhase::LoadModules,
        StartupPhase::RegisterCapabilities,
        StartupPhase::VerifyExtensions,
        StartupPhase::AcceptWork,
    ]
}

pub fn startup_sequence() -> Vec<&'static str> {
    startup_phases().iter().map(StartupPhase::id).collect()
}
