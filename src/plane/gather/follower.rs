//! The follow of one member: read once, then again each time its surface is
//! told the member's publication advanced or its reach changed — never
//! asked again and again (ADR-0052, amendment 2026-09-15). What is told
//! while a read is under way is read together, next.

use std::sync::Arc;
use std::thread::JoinHandle;

use observe::Publication;

use super::{Follow, Gathering, Said};

/// A thread following each member this process reaches; each that stopped
/// in order heard so at once, and each it cannot reach heard to say
/// nothing, and why.
pub(super) fn started(gathering: &Arc<Gathering>) -> Vec<JoinHandle<()>> {
    let mut followers = Vec::new();
    for (place, member) in gathering.members.iter().enumerate() {
        let through = match (member.stopped, &member.through) {
            (Some(when), _) => {
                gathering.heard(place, Said::Stopped(when));
                continue;
            }
            (None, Ok(through)) => Arc::clone(through),
            (None, Err(why)) => {
                gathering.heard(place, Said::Nothing(why.clone()));
                continue;
            }
        };
        let shared = Arc::clone(gathering);
        let spawned = std::thread::Builder::new()
            .name("xmip-gather-follow".to_string())
            .spawn(move || follow(&shared, place, through.as_ref()));
        match spawned {
            Ok(follower) => followers.push(follower),
            Err(error) => gathering.heard(place, Said::Nothing(format!("not followed: {error}"))),
        }
    }
    followers
}

/// Follow the member at `place` through `through` until the gatherer or
/// what it follows through ends.
fn follow(gathering: &Gathering, place: usize, through: &dyn Follow) {
    let _unheard = Unheard { gathering, place };
    let mut seen = through.told();
    loop {
        gathering.heard(place, read(through));
        let told = through.told_after(seen, &|| gathering.ending());
        if told <= seen {
            return;
        }
        seen = told;
    }
}

/// What the member publishes now, read whole, or why it did not answer.
fn read(through: &dyn Follow) -> Said {
    match through
        .publication()
        .and_then(|text| Publication::read(&text))
    {
        Ok(publication) => Said::Published {
            snapshot: Box::new(publication.snapshot()),
            drawing: publication.topology,
        },
        Err(why) => Said::Nothing(why),
    }
}

/// A follow that panicked, heard as saying nothing, so a gatherer starting
/// never waits on it.
struct Unheard<'a> {
    gathering: &'a Gathering,
    place: usize,
}

impl Drop for Unheard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let said = Said::Nothing("its follow ended".to_string());
            self.gathering.heard(self.place, said);
        }
    }
}
