//! `xmip_operate.h` section 17's `xmip_operate_post_cluster_v1`: a program
//! hosting a node through the C ABI that gathers its cluster posts the
//! cluster's publication as it posts its own (`xmip_operate_post_v1`), and
//! its listener answers `Cluster` and `ClusterWait` from what it posted
//! (ADR-0027 decision 8, amendment 2026-11-13). A program gathers by
//! posting one: the first post hands the listener the board, and until then
//! the listener refuses both in the words a node declaring no monitoring
//! role refuses them in (`plane::served::GATHERS_NO_CLUSTER`), one refusal.
#![allow(unsafe_code)]

use std::sync::Arc;

use abi::ffi::{Str, status};
use abi::operate::remote::Served as ServedHandle;

use super::Serving;
use crate::ffi::text::scope_text;
use crate::plane::{Board, Published};

/// Post `publication`, the text a publication file holds, as the cluster's
/// publication the program gathered: a new revision where it differs from
/// the last, and every surface following the cluster's told.
///
/// # Safety
/// `served` is a live handle; `publication` points at its stated length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_operate_post_cluster_v1(
    served: *const ServedHandle,
    publication: Str,
) -> i32 {
    abi::guarded(status::PANIC, || {
        // SAFETY: per the contract above.
        let Some(serving) = (unsafe { served.cast::<Serving>().as_ref() }) else {
            return status::INVALID;
        };
        // SAFETY: per the contract above.
        let Some(text) = (unsafe { scope_text(publication) }) else {
            return status::MALFORMED;
        };
        let board = serving.cluster.get_or_init(|| {
            let board = Arc::new(Board::default());
            serving
                .listener
                .gathers(Arc::clone(&board) as Arc<dyn Published>);
            board
        });
        board.post(text.to_string());
        status::OK
    })
}

#[cfg(test)]
mod tests {
    //! The cluster's publication across the C boundary, as a surface in
    //! another language reads and follows it: refused by a listener that
    //! gathers none, in the role's words and its own status; read and
    //! followed once the hosting program posted one; one publication
    //! followed by a handle; and a follow left to the node's answer
    //! following what the node answers, and saying which.

    use std::time::{Duration, Instant};

    use abi::operate::remote::{FOLLOWS_ANSWERED, FOLLOWS_CLUSTER, FOLLOWS_NODE, Remote, Served};

    use super::*;
    use crate::ffi::remote::{
        xmip_remote_cluster_v1, xmip_remote_end_v1, xmip_remote_free_v1, xmip_remote_open_v1,
        xmip_remote_wait_v1,
    };
    use crate::ffi::served::xmip_operate_serve_v2;
    use crate::ffi::served::xmip_operate_served_address_v1;
    use crate::ffi::served::{xmip_operate_post_v1, xmip_operate_serve_stop_v1};
    use crate::fixture::Authority;
    use crate::plane::served::GATHERS_NO_CLUSTER;

    fn text(value: &str) -> Str {
        Str {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }

    /// A listener this process serves, every surface the authority signs
    /// an Observer, and a surface opened on it.
    fn served_and_opened(authority: &Authority) -> (*mut Served, *mut Remote) {
        let (certificate, key, anchors) = authority.pem("node");
        let (mut report, mut length) = (vec![0u8; 4096], 0usize);
        let mut served: *mut Served = std::ptr::null_mut();
        // SAFETY: every pointer is to live storage of its stated size.
        let code = unsafe {
            xmip_operate_serve_v2(
                text("127.0.0.1:0"),
                text(&certificate),
                text(&key),
                text(&anchors),
                text("CN=surface\n"),
                text(""),
                text(""),
                text("plane-cluster-test"),
                &raw mut served,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        opened(authority, served)
    }

    /// `served` and a fresh surface opened on it.
    fn opened(authority: &Authority, served: *mut Served) -> (*mut Served, *mut Remote) {
        let (mut report, mut length) = (vec![0u8; 4096], 0usize);
        let mut address = vec![0u8; 256];
        // SAFETY: every pointer is to live storage of its stated size.
        let code = unsafe {
            xmip_operate_served_address_v1(
                served,
                address.as_mut_ptr(),
                address.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        let address = String::from_utf8_lossy(&address[..length]).to_string();
        let (certificate, key, anchors) = authority.pem("surface");
        let mut remote: *mut Remote = std::ptr::null_mut();
        // SAFETY: as above.
        let code = unsafe {
            xmip_remote_open_v1(
                text(&address),
                text(&certificate),
                text(&key),
                text(&anchors),
                &raw mut remote,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(code, status::OK);
        (served, remote)
    }

    /// `xmip_remote_cluster_v1`: its status, the text or the refusal, and
    /// the revision.
    fn cluster(remote: *const Remote) -> (i32, String, u64) {
        let (mut out, mut length, mut revision) = (vec![0u8; 4096], 0usize, 0u64);
        // SAFETY: every pointer is to live storage of its stated size.
        let code = unsafe {
            xmip_remote_cluster_v1(
                remote,
                out.as_mut_ptr(),
                out.len(),
                &raw mut length,
                &raw mut revision,
            )
        };
        let said = String::from_utf8_lossy(&out[..length.min(out.len())]).to_string();
        (code, said, revision)
    }

    /// What `xmip_remote_wait_v1` said.
    struct Said {
        code: i32,
        told: u64,
        revision: u64,
        reachable: u8,
        follows: u32,
        why: String,
    }

    /// `xmip_remote_wait_v1` following `follows` past `seen`.
    fn waited(remote: *const Remote, follows: u32, seen: u64) -> Said {
        let (mut told, mut revision, mut reachable, mut following) = (0u64, 0u64, 0u8, 9u32);
        let (mut reason, mut length) = (vec![0u8; 4096], 0usize);
        // SAFETY: every pointer is to live storage of its stated size.
        let code = unsafe {
            xmip_remote_wait_v1(
                remote,
                follows,
                seen,
                5000,
                &raw mut told,
                &raw mut revision,
                &raw mut reachable,
                &raw mut following,
                reason.as_mut_ptr(),
                reason.len(),
                &raw mut length,
            )
        };
        let why = String::from_utf8_lossy(&reason[..length.min(reason.len())]).to_string();
        Said {
            code,
            told,
            revision,
            reachable,
            follows: following,
            why,
        }
    }

    /// Each handle freed once, and the listener stopped.
    fn freed(remotes: &[*mut Remote], served: *mut Served) {
        for remote in remotes {
            // SAFETY: each handle is live and freed once.
            unsafe {
                xmip_remote_end_v1(*remote);
                xmip_remote_free_v1(*remote);
            }
        }
        // SAFETY: as above.
        unsafe { xmip_operate_serve_stop_v1(served) };
    }

    #[test]
    fn a_listener_gathering_none_refuses_the_cluster_in_the_roles_words() {
        let authority = Authority::new();
        let (served, remote) = served_and_opened(&authority);
        let (code, said, _) = cluster(remote);
        assert_eq!(code, status::UNSUPPORTED, "{said}");
        assert_eq!(said, GATHERS_NO_CLUSTER);
        assert!(said.contains("declares no monitoring role"), "{said}");
        // Following the cluster's there is told unreached, and why.
        let said = waited(remote, FOLLOWS_CLUSTER, 0);
        assert_eq!((said.code, said.reachable), (status::OK, 0), "{}", said.why);
        assert_eq!(said.follows, FOLLOWS_CLUSTER);
        assert!(
            said.told > 0 && said.why.contains("declares no monitoring role"),
            "{}",
            said.why
        );
        freed(&[remote], served);
    }

    #[test]
    fn a_cluster_posted_is_read_and_followed_and_a_handle_follows_one_publication() {
        let authority = Authority::new();
        let (served, remote) = served_and_opened(&authority);
        // SAFETY: `served` is live.
        let code = unsafe { xmip_operate_post_cluster_v1(served, text("source = \"one\"\n")) };
        assert_eq!(code, status::OK);
        assert_eq!(
            cluster(remote),
            (status::OK, "source = \"one\"\n".to_string(), 1)
        );
        let said = waited(remote, FOLLOWS_CLUSTER, 0);
        let reached = (said.code, said.revision, said.reachable, said.follows);
        assert_eq!(reached, (status::OK, 1, 1, FOLLOWS_CLUSTER), "{}", said.why);
        let posted = Instant::now();
        // SAFETY: as above.
        unsafe { xmip_operate_post_cluster_v1(served, text("source = \"two\"\n")) };
        assert_eq!(waited(remote, FOLLOWS_CLUSTER, said.told).revision, 2);
        assert!(posted.elapsed() < Duration::from_secs(1));
        // The node's own publication is another's to follow.
        let other = waited(remote, FOLLOWS_NODE, 0);
        assert_eq!(other.code, status::STATE, "{}", other.why);
        assert!(
            other.why.contains("follows the cluster's publication"),
            "{}",
            other.why
        );
        assert_eq!(waited(remote, 7, 0).code, status::INVALID);
        freed(&[remote], served);
    }

    #[test]
    fn a_follow_left_to_the_answer_follows_what_the_node_answers_and_says_which() {
        let authority = Authority::new();
        let (served, before) = served_and_opened(&authority);
        // SAFETY: `served` is live.
        unsafe { xmip_operate_post_v1(served, text("source = \"own\"\n")) };
        // Gathering none: its own, decided by the node's answer, at once.
        let own = waited(before, FOLLOWS_ANSWERED, 0);
        let decided = (own.code, own.reachable, own.follows, own.revision);
        assert_eq!(decided, (status::OK, 1, FOLLOWS_NODE, 1), "{}", own.why);
        let other = waited(before, FOLLOWS_CLUSTER, 0);
        assert_eq!(other.code, status::STATE, "{}", other.why);
        // Gathering: a handle opened then follows the cluster's.
        // SAFETY: as above.
        unsafe { xmip_operate_post_cluster_v1(served, text("source = \"gathered\"\n")) };
        let (_, after) = opened(&authority, served);
        let gathered = waited(after, FOLLOWS_ANSWERED, 0);
        let decided = (gathered.code, gathered.follows, gathered.revision);
        assert_eq!(
            decided,
            (status::OK, FOLLOWS_CLUSTER, 1),
            "{}",
            gathered.why
        );
        let (code, text, _) = cluster(after);
        assert_eq!(
            (code, text.as_str()),
            (status::OK, "source = \"gathered\"\n")
        );
        freed(&[before, after], served);
    }
}
