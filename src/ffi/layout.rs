//! `xmip_operate.h` section 8, the layout: where each thing a read
//! publication draws beneath a focus stands on the map, as
//! `observe::topology::layout` says it — the one rule, by role and the order
//! of `[storage] nodes`, never by traffic or a name — so the Web and the
//! Desktop stand every node alike (the owner, 2026-11-12: *We got to
//! straighten out the map. It has to focus on roles*; ADR-0052 and ADR-0056,
//! amendments 2026-11-13). The reader asks it, not the publisher: where
//! things stand depends on what the reader shows. Nothing here touches a
//! running node.
//!
//! In `ffi/`, the one folder of the runtime that may hold unsafe code
//! (ADR-0050, refined 2026-09-25): a surface hands over where to write.
#![allow(unsafe_code)]

use std::collections::{BTreeMap, HashMap};

use abi::ffi::{Str, status};
use abi::operate::publication::{Publication as Handle, TopologyPlace};
use observe::topology::layout::{Place, every_focus, layout};

use crate::ffi::publication::{Read, fill_copied, held};
use crate::ffi::text::scope_text;
use crate::wire::{wire_band, wire_column};

/// Where each thing beneath `focus` stands — or only the `shown_len` ids
/// `shown` names — in the fill shape, each id borrowed from the publication.
///
/// # Safety
/// `publication` is a live handle; `focus` points at its stated length of
/// readable bytes; `shown` has `shown_len` such strings; `out` has room for
/// `cap` entries; `out_len` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xmip_publication_layout_v1(
    publication: *const Handle,
    focus: Str,
    shown: *const Str,
    shown_len: usize,
    out: *mut TopologyPlace,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the caller's contract is this export's, passed on whole.
    abi::guarded(status::PANIC, || unsafe {
        publication_layout(publication, focus, (shown, shown_len), out, cap, out_len)
    })
}

/// [`xmip_publication_layout_v1`] within its guard.
unsafe fn publication_layout(
    publication: *const Handle,
    focus: Str,
    (shown, shown_len): (*const Str, usize),
    out: *mut TopologyPlace,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: per the contract above.
    let Some(read) = (unsafe { held(publication) }) else {
        return status::INVALID;
    };
    // SAFETY: the caller upholds the header's contract on `focus`.
    let Some(focus) = (unsafe { scope_text(focus) }) else {
        return status::MALFORMED;
    };
    let mut named = Vec::with_capacity(shown_len);
    for at in 0..shown_len {
        // SAFETY: `shown` has `shown_len` strings, each its stated length.
        let Some(id) = (unsafe { scope_text(shown.add(at).read()) }) else {
            return status::MALFORMED;
        };
        named.push(id);
    }
    let Some(topology) = read.publication.topology.as_ref() else {
        // SAFETY: `out_len` is writable; nothing is drawn.
        return unsafe { fill_copied::<TopologyPlace>(&[], out, cap, out_len) };
    };
    if named.is_empty() {
        // Every focus laid out once per publication, the first time any is
        // asked: a reader asks each as it reads.
        let laid = read.laid.get_or_init(|| {
            every_focus(topology)
                .into_iter()
                .map(|(focus, places)| (focus, crossing(read, places)))
                .collect()
        });
        let places = laid.get(focus).map_or(&[][..], Vec::as_slice);
        // SAFETY: `out` has room for `cap` entries; `out_len` is writable.
        return unsafe { fill_copied(places, out, cap, out_len) };
    }
    let places = crossing(read, layout(topology, focus, &named));
    // SAFETY: `out` has room for `cap` entries; `out_len` is writable.
    unsafe { fill_copied(&places, out, cap, out_len) }
}

/// Where everything stands beneath every focus of a read publication, as
/// the header lays it out, made once.
pub(crate) type Laid = BTreeMap<String, Vec<TopologyPlace>>;

/// `places` as the header lays them out, each id borrowed from the read
/// publication's own, found by an index made once.
fn crossing(read: &Read, places: Vec<Place>) -> Vec<TopologyPlace> {
    let drawn = read.drawn.get_or_init(|| {
        let topology = read.publication.topology.as_ref();
        let nodes = topology.map_or(&[][..], |topology| topology.nodes.as_slice());
        let mut drawn = HashMap::with_capacity(nodes.len());
        for (at, node) in nodes.iter().enumerate() {
            drawn.entry(node.id.clone()).or_insert(at);
        }
        drawn
    });
    places
        .into_iter()
        .filter_map(|place| {
            let node = read.nodes.get(*drawn.get(&place.id)?)?;
            Some(TopologyPlace {
                id: node.id,
                x: place.x,
                y: place.y,
                band: wire_band(place.band),
                column: wire_column(place.column),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::publication::{xmip_publication_free_v1, xmip_publication_read_v1};
    use crate::ffi::text::borrow;
    use abi::operate::publication::{LayoutFn, band, column};

    #[test]
    fn the_export_has_the_shape_the_binding_declares() {
        let _: LayoutFn = xmip_publication_layout_v1;
    }

    fn text(value: Str) -> String {
        // SAFETY: the export promises `len` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(value.ptr, value.len) };
        String::from_utf8(bytes.to_vec()).expect("UTF-8")
    }

    /// A Storage node and a receiving node read through the export stand as
    /// observe lays them out: the receiving one left of the Storage one, on
    /// the path row; and only what is shown is laid out.
    #[test]
    fn a_read_publication_stands_its_nodes_by_their_roles() {
        let cluster = configure::fixture::test_cluster();
        let (storing, receiving) = (
            cluster.with_role("storage").name.clone(),
            cluster.with_role("receiving").name.clone(),
        );
        let text_of = format!(
            "node = \"{root}\"\n[topology]\nsource = \"a roll\"\n\
             [[topology.nodes]]\nid = \"cluster\"\nkind = \"cluster\"\n\
             [[topology.nodes]]\nid = \"node/{storing}\"\nparent = \"cluster\"\n\
             kind = \"node\"\nroles = \"storage\"\nplace = 0\n\
             [[topology.nodes]]\nid = \"node/{receiving}\"\nparent = \"cluster\"\n\
             kind = \"node\"\nroles = \"receiving\"\n",
            root = cluster.scope(),
        );
        let mut handle = core::ptr::null_mut();
        let (mut report, mut length) = (vec![0u8; 1024], 0usize);
        // SAFETY: every pointer is this test's own, alive for the call.
        let read = unsafe {
            xmip_publication_read_v1(
                borrow(&text_of),
                &raw mut handle,
                report.as_mut_ptr(),
                report.len(),
                &raw mut length,
            )
        };
        assert_eq!(
            read,
            status::OK,
            "{}",
            String::from_utf8_lossy(&report[..length])
        );
        let blank = TopologyPlace {
            id: Str::empty(),
            x: -1.0,
            y: -1.0,
            band: -1,
            column: -1,
        };
        let mut places = [blank; 4];
        let mut count = 0usize;
        // SAFETY: a live handle; `places` has room for four.
        let code = unsafe {
            xmip_publication_layout_v1(
                handle,
                borrow("cluster"),
                core::ptr::null(),
                0,
                places.as_mut_ptr(),
                places.len(),
                &raw mut count,
            )
        };
        assert_eq!((code, count), (status::OK, 2));
        let at = |id: &str| {
            places[..count]
                .iter()
                .find(|place| text(place.id) == id)
                .copied()
                .unwrap_or(blank)
        };
        let (store, take) = (
            at(&format!("node/{storing}")),
            at(&format!("node/{receiving}")),
        );
        assert_eq!((store.band, store.column), (band::PATH, column::STORAGE));
        assert_eq!((take.band, take.column), (band::PATH, column::RECEIVING));
        assert!(
            take.x < store.x,
            "the receiving column is left of Storage's"
        );

        let shown = format!("node/{receiving}");
        let only = [borrow(&shown)];
        // SAFETY: as above, one id shown.
        let code = unsafe {
            xmip_publication_layout_v1(
                handle,
                borrow("cluster"),
                only.as_ptr(),
                only.len(),
                places.as_mut_ptr(),
                places.len(),
                &raw mut count,
            )
        };
        // SAFETY: the handle is this test's own, freed once.
        unsafe { xmip_publication_free_v1(handle) };
        assert_eq!((code, count), (status::OK, 1), "only what is shown");
    }
}
