//! A program under the Windows Service Control Manager: the dispatcher the
//! manager starts it through, the control handler its Stop and Shutdown
//! arrive on, and the states it reports — start pending while it starts,
//! running once it says so, stop pending while it drains, stopped with its
//! exit code. One implementation for every program the estate runs as a
//! service, `xmip-service` and the Essentials' far ends among them; each
//! gives it what it does when a stop arrives and what it runs, and the
//! service is registered under the name `registration` gives it.
//!
//! The handler only says a stop arrived, and who asked; the drain is the
//! program's, the same one a console's Ctrl+C and a Unix SIGTERM reach.

use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

/// What a program does when the manager asks it to stop: told who asked,
/// "the Service Control Manager" or "the system shutting down".
pub type Stopping = Box<dyn Fn(&'static str) + Send + Sync>;

/// What a program runs as the service, given the reporter it says it runs
/// and drains through: its exit code once it has stopped.
pub type Serving = Box<dyn FnOnce(&Reporter) -> u8 + Send>;

/// What a start hands the service's main, which the dispatcher calls with
/// nothing of it.
struct Given {
    name: String,
    stopping: Stopping,
    serving: Serving,
}

static GIVEN: OnceLock<Mutex<Option<Given>>> = OnceLock::new();
static ENDED: OnceLock<Result<u8, String>> = OnceLock::new();

/// How long the manager is told a start or a drain may take before it hears
/// again; the program's own waits bound both.
const WAIT: Duration = Duration::from_secs(30);

/// Hand the process to the Service Control Manager as the service `name`,
/// which calls `serving` and returns when it has stopped: its exit code.
/// A Stop or a Shutdown the manager sends is told to `stopping`.
///
/// # Errors
///
/// In words, where the manager did not start it — a program started from a
/// console is refused so — or its controls could not be taken.
pub fn run(name: &str, stopping: Stopping, serving: Serving) -> Result<u8, String> {
    let given = Given {
        name: name.to_string(),
        stopping,
        serving,
    };
    *GIVEN
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(given);
    service_dispatcher::start(name, service_main)
        .map_err(|error| format!("the Service Control Manager did not start it ({error})"))?;
    ENDED.get().cloned().unwrap_or(Ok(0))
}

/// The service's main, as the dispatcher calls it. The arguments a start
/// passes are not read: the program is what its own command line said.
extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
    let given = GIVEN
        .get()
        .and_then(|given| given.lock().unwrap_or_else(PoisonError::into_inner).take());
    if let Some(given) = given {
        let _ = ENDED.set(serve(given));
    }
}

/// What the service says to the manager while it runs.
pub struct Reporter {
    status: ServiceStatusHandle,
}

impl Reporter {
    /// It runs, and takes a Stop and a Shutdown.
    pub fn running(&self) {
        let taken = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN;
        self.report(ServiceState::Running, taken, 0);
    }

    /// It drains, and takes nothing more.
    pub fn stopping(&self) {
        self.report(ServiceState::StopPending, ServiceControlAccept::empty(), 0);
    }

    fn report(&self, state: ServiceState, accepted: ServiceControlAccept, code: u8) {
        let reported = self.status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code: if code == 0 {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(u32::from(code))
            },
            checkpoint: 0,
            wait_hint: WAIT,
            process_id: None,
        });
        if let Err(error) = reported {
            eprintln!("could not report {state:?} to the Service Control Manager: {error}");
        }
    }
}

/// `given` served: its controls taken, start pending reported, its program
/// run to its end and its exit code reported stopped.
fn serve(given: Given) -> Result<u8, String> {
    let (tell, asked) = mpsc::channel::<&'static str>();
    let registered =
        service_control_handler::register(&given.name, move |control| answer(control, &tell));
    let status = registered.map_err(|error| {
        format!(
            "{}: cannot take the manager's controls: {error}",
            given.name
        )
    })?;
    let stopping = given.stopping;
    // Each stop the handler hears is told to the program, on a thread of its
    // own, so the handler answers the manager at once.
    std::thread::spawn(move || {
        for by in asked {
            stopping(by);
        }
    });
    let reporter = Reporter { status };
    reporter.report(ServiceState::StartPending, ServiceControlAccept::empty(), 0);
    let code = (given.serving)(&reporter);
    reporter.report(ServiceState::Stopped, ServiceControlAccept::empty(), code);
    Ok(code)
}

/// The manager's control, answered: a Stop or a Shutdown is the drain,
/// asked, saying who asked; an Interrogate is answered by the last status;
/// nothing else is taken.
fn answer(control: ServiceControl, stop: &Sender<&'static str>) -> ServiceControlHandlerResult {
    let by = match control {
        ServiceControl::Stop => "the Service Control Manager",
        ServiceControl::Shutdown => "the system shutting down",
        ServiceControl::Interrogate => return ServiceControlHandlerResult::NoError,
        _ => return ServiceControlHandlerResult::NotImplemented,
    };
    // The receiver is gone only once the program has drained; a stop then
    // asks for nothing.
    let _ = stop.send(by);
    ServiceControlHandlerResult::NoError
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn a_stop_and_a_shutdown_each_ask_for_the_drain_once() {
        let (stop, stops) = mpsc::channel();

        for (control, by) in [
            (ServiceControl::Stop, "the Service Control Manager"),
            (ServiceControl::Shutdown, "the system shutting down"),
        ] {
            assert_matches!(answer(control, &stop), ServiceControlHandlerResult::NoError);
            assert_eq!(stops.try_recv(), Ok(by));
        }
        assert!(stops.try_recv().is_err(), "one stop per control");
    }

    #[test]
    fn nothing_else_the_manager_sends_stops_the_program() {
        let (stop, stops) = mpsc::channel();

        assert_matches!(
            answer(ServiceControl::Interrogate, &stop),
            ServiceControlHandlerResult::NoError
        );
        assert_matches!(
            answer(ServiceControl::Pause, &stop),
            ServiceControlHandlerResult::NotImplemented
        );
        assert!(stops.try_recv().is_err());
    }

    #[test]
    fn a_stop_after_the_drain_asks_for_nothing() {
        let (stop, stops) = mpsc::channel();
        drop(stops);

        assert_matches!(
            answer(ServiceControl::Stop, &stop),
            ServiceControlHandlerResult::NoError
        );
    }
}
