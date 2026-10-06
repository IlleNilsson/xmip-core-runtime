//! A Subscription as a node takes it up from its configuration: the route
//! it is, the Xmip Application that draws it, the file that Application was
//! read from and its entry there, as the file says it (ADR-0013, amendment
//! 2026-09-30).
//!
//! A Subscription is configuration. It is added and removed by editing its
//! Application's section of the cluster's `xmip.toml` and nowhere else, so
//! this is read from what startup phase 1 read and never written back.

use configure::XmipApplication;
use configure::application::destination_words;
use route::{Subscriber, Subscription};

use crate::start::ApplicationFile;

/// One Subscription a node routes by, and where it is configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredSubscription {
    pub subscription: Subscription,
    /// The Xmip Application that draws it.
    pub application: String,
    /// The file that Application was read from.
    pub file: String,
    /// Its `[[subscriptions]]` entry, as the file says it.
    pub entry: String,
    /// The Send Ports it reaches, each its own Journey: its Send Port, or
    /// every Port of its Send Port Group in the Group's order
    /// (`runtime-model.md` section 10: *A Send Port Group is only a named
    /// set: routing already made one Journey per Send Port in it*). None
    /// for a Work Process, or a Group no Application it is drawn in
    /// declares.
    pub ports: Vec<String>,
}

impl ConfiguredSubscription {
    /// Every Subscription of every bound Application, in the order the node
    /// binds them — the order routing asks them in — each with the file its
    /// Application was read from. `applications` and `files` are what
    /// startup phase 1 read, one file per Application.
    #[must_use]
    pub fn of(applications: &[XmipApplication], files: &[ApplicationFile]) -> Vec<Self> {
        applications
            .iter()
            .zip(files)
            .flat_map(|(application, file)| {
                application
                    .subscriptions
                    .iter()
                    .map(move |subscription| Self {
                        ports: reached(&subscription.destination, application),
                        subscription: subscription.clone(),
                        application: file.name.clone(),
                        file: file.file.clone(),
                        entry: configure::subscription_entry(
                            &file.text,
                            &file.name,
                            &subscription.id,
                        )
                        .unwrap_or_default(),
                    })
            })
            .collect()
    }

    /// A Subscription no file configures: one a program or a test hands a
    /// node itself.
    #[must_use]
    pub fn unfiled(subscription: Subscription) -> Self {
        Self {
            ports: match &subscription.destination {
                Subscriber::SendPort(port) => vec![port.clone()],
                Subscriber::SendGroup(_) | Subscriber::WorkProcess(_) => Vec::new(),
            },
            subscription,
            application: String::new(),
            file: String::new(),
            entry: String::new(),
        }
    }

    /// Its configured name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.subscription.id
    }

    /// Where it leads, in the words a problem names a destination by.
    #[must_use]
    pub fn destination(&self) -> String {
        destination_words(&self.subscription.destination)
    }
}

/// The Send Ports `destination` reaches in `application`: its Send Port, or
/// every Port of the Send Port Group it names there.
fn reached(destination: &Subscriber, application: &XmipApplication) -> Vec<String> {
    match destination {
        Subscriber::SendPort(port) => vec![port.clone()],
        Subscriber::SendGroup(group) => application
            .send_port_groups
            .iter()
            .find(|declared| &declared.name == group)
            .map(|declared| declared.send_ports.clone())
            .unwrap_or_default(),
        Subscriber::WorkProcess(_) => Vec::new(),
    }
}
