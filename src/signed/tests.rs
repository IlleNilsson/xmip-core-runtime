//! The slice a node trusts, attacked: an edit, no signature, a stranger's
//! signature, a swapped anchor, an older serial, another file at the serial
//! seen and another node's slice; and trust kept apart from what runs
//! (ADR-0031, amendment 2026-11-12): admission pins and never activates.
//! And the candidate read by admission alone (amendment 2026-11-19): one
//! absent or unreadable is refused, and the active configuration runs.

use std::path::PathBuf;

use file::temporary::Folder;

use super::*;

/// The path of a node's configuration in a test's own folder, which goes
/// as the test ends, passing or failing.
struct Configured {
    path: PathBuf,
    _folder: Folder,
}

impl std::ops::Deref for Configured {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

/// A node's configuration at `config/node.xmip` in a folder of its own,
/// its cluster's authority beside it, and that authority.
fn folder(name: &str) -> (Configured, Issuer) {
    let base = Folder::new(&format!("runtime-signed-{name}"));
    let configuration = base.join("config");
    let issuer = Issuer::kept_or_made(&configuration.join(AUTHORITY), "xmip-cluster", 0, 3600)
        .expect("an authority");
    let path = configuration.join("node.xmip");
    (
        Configured {
            path,
            _folder: base,
        },
        issuer,
    )
}

/// `file` placed at `path` as the node's candidate.
fn placed<'a>(path: &'a Path, file: &str) -> &'a Path {
    std::fs::write(path, file).expect("the candidate placed");
    path
}

fn slice(node: &str) -> String {
    format!("[service]\nnode_name = \"{node}\"\ndata = \"data\"\n")
}

/// The authority's certificate beside `path` replaced by `issuer`'s.
fn swapped(path: &Path, issuer: &Issuer) {
    let at = path
        .parent()
        .expect("a folder")
        .join(AUTHORITY)
        .join(provision::issuer::CERTIFICATE);
    std::fs::write(at, issuer.certificate()).expect("swapped");
}

/// The pin the node at `path` holds.
fn pin(path: &Path) -> configure::signed::Pin {
    let text = std::fs::read_to_string(signed::pin_at(path)).expect("pinned");
    configure::signed::Pin::read(&text).expect("reads")
}

/// `file`'s serial.
fn serial_of(file: &str) -> u64 {
    signed::split(file)
        .expect("reads")
        .1
        .expect("signed")
        .serial
}

/// What the node at `path` admits of `file`, and activates where it is its
/// candidate: a node that ran it.
fn ran(path: &Path, file: &str) -> Admitted {
    let admitted = admitted(placed(path, file)).expect("admitted");
    if let Ok(Some(candidate)) = &admitted.candidate {
        activated(path, candidate).expect("activated");
    }
    admitted
}

#[test]
fn a_candidate_above_the_pin_is_pinned_as_seen_and_admission_activates_nothing() {
    let (path, issuer) = folder("seen");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    let admitted = admitted(placed(&path, &file)).expect("admitted");
    let candidate = admitted.candidate.expect("trusted").expect("a candidate");
    assert_eq!(candidate.text, slice("r1"));
    assert_eq!(admitted.active.expect_err("none"), NONE_TO_RUN);
    assert_eq!(pin(&path).serial, serial_of(&file), "pinned before it runs");
    assert_eq!(pin(&path).slice, candidate.digest());
    assert!(
        !signed::active_at(&path).exists(),
        "only activation writes it"
    );
}

#[test]
fn the_same_candidate_at_the_seen_serial_is_admitted_again_and_another_file_there_refused() {
    let (path, issuer) = folder("again");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    admitted(placed(&path, &file)).expect("admitted");
    let again = admitted(&path).expect("admitted again");
    assert!(matches!(again.candidate, Ok(Some(_))), "tried again");

    let at = (serial_of(&file), 0);
    let other = signed_as(
        &issuer,
        "cluster",
        &slice("r1").replace("data", "store"),
        at,
    );
    let refused = admitted(placed(&path, &other.expect("signed")))
        .expect("read")
        .candidate
        .expect_err("another file at the serial seen");
    assert!(
        refused.why.contains("is the one this node has seen"),
        "{refused}"
    );
}

#[test]
fn a_valid_slice_below_the_serial_seen_is_refused_though_above_the_active_one() {
    let (path, issuer) = folder("replay");
    let first = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    let between = sign(&issuer, "cluster", &slice("r1").replace("data", "between"));
    let seen = sign(&issuer, "cluster", &slice("r1").replace("data", "seen"));
    ran(&path, &first);
    admitted(placed(&path, &seen.expect("signed"))).expect("seen, never run");

    let admitted = admitted(placed(&path, &between.expect("signed"))).expect("read");
    let refused = admitted.candidate.expect_err("older than the serial seen");
    assert!(refused.why.contains("is not above"), "{refused}");
    assert!(refused.why.contains("older, or replayed"), "{refused}");
    assert_eq!(
        admitted.active.expect("runs").file,
        first,
        "the active one runs"
    );
}

#[test]
fn the_active_configuration_given_again_is_no_candidate() {
    let (path, issuer) = folder("active");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    ran(&path, &file);
    let again = admitted(&path).expect("admitted");
    assert_eq!(again.candidate, Ok(None));
    assert_eq!(again.active.expect("runs").file, file);
}

#[test]
fn an_edited_candidate_is_refused_and_the_active_configuration_runs() {
    let (path, issuer) = folder("edit");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    ran(&path, &file);
    let seen = pin(&path);

    let edited = file.replace("[service]\n", "[service]\nname = \"edited\"\n");
    let admitted = admitted(placed(&path, &edited)).expect("read");
    let refused = admitted.candidate.expect_err("edited");
    assert!(
        refused.why.contains("changed after it was signed"),
        "{refused}"
    );
    assert!(!refused.again, "what trust refuses it refuses again");
    assert_eq!(admitted.active.expect("runs").text, slice("r1"));
    assert_eq!(pin(&path), seen, "a refused candidate pins nothing");
}

/// The node at `path`, its candidate gone or unreadable, admits nothing of
/// it, tries it again at its next start, and runs `file`, its active
/// configuration, pinning nothing.
fn unread_and_the_active_one_runs(path: &Path, file: &str) {
    let seen = pin(path);
    let admitted = admitted(path).expect("read");
    let refused = admitted.candidate.expect_err("nothing to admit");
    let unread = format!("{} is refused: it cannot be read: ", path.display());
    assert!(refused.why.starts_with(&unread), "{refused}");
    assert!(refused.again, "tried again at the next start");
    assert_eq!(admitted.active.expect("runs").file, file);
    assert_eq!(pin(path), seen, "an unread candidate pins nothing");
    assert_eq!(checked(path).expect("what runs"), slice("r1"));
}

#[test]
fn a_missing_candidate_is_refused_by_admission_and_the_active_is_what_runs() {
    let (path, issuer) = folder("missing");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    ran(&path, &file);
    std::fs::remove_file(&*path).expect("the candidate taken away");
    unread_and_the_active_one_runs(&path, &file);
}

#[test]
fn an_unreadable_candidate_likewise() {
    let (path, issuer) = folder("unreadable");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    ran(&path, &file);
    std::fs::remove_file(&*path).expect("the candidate taken away");
    // A folder where the file goes: no platform reads it as a file, and an
    // administrator's account reads past a file's permissions.
    std::fs::create_dir(&*path).expect("a folder in its place");
    unread_and_the_active_one_runs(&path, &file);
}

#[test]
fn an_active_configuration_edited_in_the_data_directory_is_no_fallback() {
    let (path, issuer) = folder("edited-active");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    ran(&path, &file);
    let edited = file.replace("data", "elsewhere");
    std::fs::write(signed::active_at(&path), &edited).expect("edited");

    let next = sign(&issuer, "cluster", &slice("r1").replace("data", "next"));
    let admitted = admitted(placed(&path, &next.expect("signed"))).expect("read");
    let none = admitted.active.expect_err("no fallback");
    assert!(none.contains("active configuration at"), "{none}");
    assert!(none.contains("so it has none to run"), "{none}");
}

#[test]
fn the_pin_outlives_the_active_configuration_so_a_replay_is_still_refused() {
    let (path, issuer) = folder("apart");
    let older = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    let newer = sign(&issuer, "cluster", &slice("r1").replace("data", "store")).expect("signed");
    ran(&path, &newer);
    std::fs::remove_file(signed::active_at(&path)).expect("removed");

    let refused = checked(placed(&path, &older)).expect_err("replayed");
    assert!(refused.contains("is not above"), "{refused}");
    assert!(refused.contains(NONE_TO_RUN), "{refused}");
}

#[test]
fn a_check_writes_neither_file() {
    let (path, issuer) = folder("checked");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    assert_eq!(checked(placed(&path, &file)).expect("runs"), slice("r1"));
    assert!(
        !signed::pin_at(&path).exists(),
        "only the running node pins"
    );
    assert!(!signed::active_at(&path).exists());
}

#[test]
fn a_node_with_no_pin_pins_the_first_slice_it_admits() {
    let (path, issuer) = folder("unpinned");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    ran(&path, &file);
    std::fs::remove_file(signed::pin_at(&path)).expect("unpinned on purpose");
    admitted(&path).expect("the active one again");
    assert_eq!(pin(&path).serial, serial_of(&file), "the active one pins");
}

#[test]
fn both_files_are_kept_by_the_configurations_place_never_by_what_a_slice_says() {
    let (path, issuer) = folder("place");
    let elsewhere = slice("r1").replace("data = \"data\"", "data = \"../../elsewhere\"");
    ran(
        &path,
        &sign(&issuer, "cluster", &elsewhere).expect("signed"),
    );
    let data = configure::service::data_directory(None, &path);
    assert_eq!(signed::pin_at(&path), data.join("node.pin.toml"));
    assert!(signed::pin_at(&path).is_file());
    assert_eq!(signed::active_at(&path), data.join("node.active.xmip"));
    assert!(signed::active_at(&path).is_file());
}

#[test]
fn an_unsigned_slice_with_nothing_active_is_refused_in_words() {
    let (path, _) = folder("unsigned");
    let refused = checked(placed(&path, &slice("r1"))).expect_err("unsigned");
    assert!(
        refused.contains("it is not signed; and the node has no active configuration"),
        "{refused}"
    );
}

#[test]
fn a_slice_another_authority_signed_is_refused() {
    let (path, _) = folder("other");
    let (_, stranger) = folder("stranger");
    let file = sign(&stranger, "cluster", &slice("r1")).expect("signed");
    let refused = checked(placed(&path, &file)).expect_err("a stranger's");
    assert!(
        refused.contains("an authority other than this node's"),
        "{refused}"
    );
}

#[test]
fn a_swapped_anchor_with_a_slice_it_signed_is_refused() {
    let (path, issuer) = folder("swapped");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    ran(&path, &file);
    let seen = pin(&path);

    let (_, stranger) = folder("swapper");
    swapped(&path, &stranger);
    let forged = sign(&stranger, "cluster", &slice("r1")).expect("signed");
    let refused = admitted(placed(&path, &forged)).expect_err("the pin holds");
    assert!(
        refused.contains("not the one this node pinned"),
        "{refused}"
    );
    assert_eq!(pin(&path), seen, "the pin is not replaced");
    let active = std::fs::read_to_string(signed::active_at(&path)).expect("kept");
    assert_eq!(active, file, "nor the active configuration");
}

#[test]
fn another_nodes_slice_is_refused() {
    let (path, issuer) = folder("another");
    ran(
        &path,
        &sign(&issuer, "cluster", &slice("r1")).expect("signed"),
    );

    let theirs = sign(&issuer, "cluster", &slice("r2")).expect("signed");
    let admitted = admitted(placed(&path, &theirs)).expect("read");
    let refused = admitted.candidate.expect_err("another node's");
    assert!(
        refused
            .why
            .contains("the slice of the node r2, and this node is r1"),
        "{refused}"
    );
    assert_eq!(admitted.active.expect("its own runs").text, slice("r1"));
}

#[test]
fn a_slice_naming_no_node_is_not_signed() {
    let (_, issuer) = folder("nameless");
    let refused = sign(&issuer, "cluster", "[service]\n").expect_err("no node");
    assert!(refused.contains("names no node"), "{refused}");
}

#[test]
fn a_slice_signed_by_a_kept_authority_is_named_for_the_environments_cluster() {
    let (path, _) = folder("sliced");
    let base = path.parent().and_then(Path::parent).expect("its own");
    let file = base.join("cluster.xmip");
    let test = configure::fixture::test_cluster();
    let node = &test.node(0).name;
    let cluster = format!("[service]\nname = \"n\"\n\n[nodes.{node}]\n");
    let kept = path.parent().expect("a folder").join(AUTHORITY);
    let signed =
        sliced_signed(&cluster, &file, node, Some(&test.name), Some(&kept)).expect("signed");
    std::fs::write(&*path, signed).expect("placed");
    let text = checked(&path).expect("admitted");
    let named = format!("cluster_name = \"{}\"", test.name);
    assert!(text.contains(&named), "{text}");
    assert!(
        !base.join(AUTHORITY).exists(),
        "no authority made beside the file"
    );
}

#[test]
fn serials_rise_from_one_signing_to_the_next() {
    let (first, _) = serial();
    let (second, issued) = serial();
    assert!(second > first);
    assert!(issued > 0);
}

/// What a node with no active configuration says it lacks.
const NONE_TO_RUN: &str = "the node has no active configuration to run";
