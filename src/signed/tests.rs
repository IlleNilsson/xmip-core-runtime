//! The slice a node runs, attacked: an edit, no signature, a stranger's
//! signature, a swapped anchor, an older serial and another node's slice.

use super::*;

/// A node's configuration at `config/node.xmip` in a folder of its own,
/// its cluster's authority beside it, and that authority.
fn folder(name: &str) -> (PathBuf, Issuer) {
    let base = std::env::temp_dir().join(format!("xmip-signed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let configuration = base.join("config");
    let issuer = Issuer::kept_or_made(&configuration.join(AUTHORITY), "xmip-cluster", 0, 3600)
        .expect("an authority");
    (configuration.join("node.xmip"), issuer)
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

#[test]
fn a_signed_slice_runs_and_is_kept_and_an_edit_runs_the_kept_one_instead() {
    let (path, issuer) = folder("edit");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    assert_eq!(accepted(&path, &file).expect("runs"), (slice("r1"), None));
    assert_eq!(std::fs::read_to_string(kept_at(&path)).expect("kept"), file);
    assert_eq!(accepted(&path, &file).expect("again"), (slice("r1"), None));

    let edited = file.replace("[service]\n", "[service]\nname = \"edited\"\n");
    let (text, refused) = accepted(&path, &edited).expect("the kept one runs");
    assert_eq!(text, slice("r1"));
    let refused = refused.expect("said");
    assert!(refused.contains("changed after it was signed"), "{refused}");
}

#[test]
fn the_accepted_slice_is_kept_by_the_configurations_place_never_by_what_it_says() {
    let (path, issuer) = folder("place");
    let elsewhere = slice("r1").replace("data = \"data\"", "data = \"../../elsewhere\"");
    let file = sign(&issuer, "cluster", &elsewhere).expect("signed");
    accepted(&path, &file).expect("runs");
    let base = path.parent().and_then(Path::parent).expect("the folder");
    assert_eq!(kept_at(&path), base.join("data").join("node.accepted.xmip"));
    assert!(kept_at(&path).is_file());
}

#[test]
fn a_check_keeps_nothing() {
    let (path, issuer) = folder("checked");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    assert_eq!(checked(&path, &file).expect("runs"), (slice("r1"), None));
    assert!(!kept_at(&path).exists(), "only the running node keeps");
}

#[test]
fn an_unsigned_slice_with_nothing_accepted_is_refused_in_words() {
    let (path, _) = folder("unsigned");
    let refused = accepted(&path, &slice("r1")).expect_err("unsigned");
    assert!(
        refused.contains("it is not signed, and the node has no accepted slice"),
        "{refused}"
    );
}

#[test]
fn a_slice_another_authority_signed_is_refused() {
    let (path, _) = folder("other");
    let (_, stranger) = folder("stranger");
    let file = sign(&stranger, "cluster", &slice("r1")).expect("signed");
    let refused = accepted(&path, &file).expect_err("a stranger's");
    assert!(
        refused.contains("an authority other than this node's"),
        "{refused}"
    );
}

#[test]
fn a_swapped_anchor_with_a_slice_it_signed_is_refused() {
    let (path, issuer) = folder("swapped");
    let file = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    accepted(&path, &file).expect("pinned");

    let (_, stranger) = folder("swapper");
    swapped(&path, &stranger);
    let forged = sign(&stranger, "cluster", &slice("r1")).expect("signed");
    let refused = accepted(&path, &forged).expect_err("the pin holds");
    assert!(
        refused.contains("not the one this node pinned"),
        "{refused}"
    );
    assert_eq!(
        std::fs::read_to_string(kept_at(&path)).expect("kept"),
        file,
        "the accepted slice is not replaced"
    );
}

#[test]
fn an_older_serial_is_refused_and_the_newer_accepted_slice_runs() {
    let (path, issuer) = folder("older");
    let older = sign(&issuer, "cluster", &slice("r1")).expect("signed");
    let newer = sign(&issuer, "cluster", &slice("r1").replace("data", "store")).expect("signed");
    accepted(&path, &newer).expect("runs");

    let (text, refused) = accepted(&path, &older).expect("the newer one runs");
    assert_eq!(text, slice("r1").replace("data", "store"));
    let refused = refused.expect("said");
    assert!(refused.contains("is not above"), "{refused}");
}

#[test]
fn another_nodes_slice_is_refused() {
    let (path, issuer) = folder("another");
    accepted(
        &path,
        &sign(&issuer, "cluster", &slice("r1")).expect("signed"),
    )
    .expect("runs");

    let theirs = sign(&issuer, "cluster", &slice("r2")).expect("signed");
    let (text, refused) = accepted(&path, &theirs).expect("its own runs");
    assert_eq!(text, slice("r1"));
    let refused = refused.expect("said");
    assert!(
        refused.contains("the slice of the node r2, and this node is r1"),
        "{refused}"
    );
}

#[test]
fn a_slice_naming_no_node_is_not_signed() {
    let (_, issuer) = folder("nameless");
    let refused = sign(&issuer, "cluster", "[service]\n").expect_err("no node");
    assert!(refused.contains("names no node"), "{refused}");
}

#[test]
fn serials_rise_from_one_signing_to_the_next() {
    let (first, _) = serial();
    let (second, issued) = serial();
    assert!(second > first);
    assert!(issued > 0);
}
