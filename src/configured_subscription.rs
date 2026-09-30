//! A Subscription as a node takes it up from its configuration: the route
//! it is, the Xmip Application that draws it, the file that Application was
//! read from and its entry there, as the file says it (ADR-0013, amendment
//! 2026-09-30).
//!
//! A Subscription is configuration. It is added and removed by editing the
//! Application's TOML and nowhere else, so this is read from what startup
//! phase 1 read and never written back.

use configure::XmipApplicationDocument;
use configure::application::destination_words;
use route::Subscription;

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
}

impl ConfiguredSubscription {
    /// Every Subscription of every bound Application, in the order the node
    /// binds them — the order routing asks them in — each with the file its
    /// Application was read from. `applications` and `files` are what
    /// startup phase 1 read, one file per Application.
    #[must_use]
    pub fn of(applications: &[XmipApplicationDocument], files: &[ApplicationFile]) -> Vec<Self> {
        applications
            .iter()
            .zip(files)
            .flat_map(|(application, file)| {
                application
                    .subscriptions
                    .iter()
                    .map(move |subscription| Self {
                        subscription: subscription.clone(),
                        application: file.name.clone(),
                        file: file.file.clone(),
                        entry: configure::subscription_entry(&file.text, &subscription.id)
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
