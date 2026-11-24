#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::PathBuf;

use abi::XMIP_ABI_VERSION;
use abi::ffi::{
    Host, Module, PromoteVtable, PromotionSink, Reader, Slice, Str, VtableHeader, WireDescriptor,
    status, value_kind,
};
use node::Stage;
use xcore::ScalarValue;
use xcore::settings::Given;

use super::{LoadedPromotion, PROMOTE, expectation};
use crate::ffi::loaded_module::LoadedModule;

// ----------------------------------------------------------------------
// A Promote unit linked into this test: the content, whole, under the
// property its step's `property` names, and its length as `Length`.
// ----------------------------------------------------------------------

unsafe extern "C" fn configure(_: *mut c_void, _: Str) -> i32 {
    status::OK
}

unsafe extern "C" fn lifecycle(_: *mut c_void) -> i32 {
    status::OK
}

unsafe extern "C" fn last_error(_: *mut c_void) -> Str {
    Str::from_static("the step names no property")
}

unsafe extern "C" fn destroy(_: *mut c_void) {}

unsafe extern "C" fn open(
    _: *mut c_void,
    stage: Str,
    settings: Str,
    out_step: *mut *mut c_void,
) -> i32 {
    // SAFETY: both borrowed for this call, as the header lends them.
    let (stage, settings) = unsafe {
        (
            std::slice::from_raw_parts(stage.ptr, stage.len),
            std::slice::from_raw_parts(settings.ptr, settings.len),
        )
    };
    let read: serde_json::Value = serde_json::from_slice(settings).unwrap_or_default();
    let Some(property) = read.get("property").and_then(serde_json::Value::as_str) else {
        return status::CONTRACT;
    };
    if stage != b"receive" {
        return status::INVALID;
    }
    // SAFETY: `out_step` is the host's live local, written once.
    unsafe { *out_step = Box::into_raw(Box::new(property.to_string())).cast() };
    status::OK
}

unsafe extern "C" fn release(_: *mut c_void, step: *mut c_void) {
    // SAFETY: `step` came from `open` above and is released once.
    drop(unsafe { Box::from_raw(step.cast::<String>()) });
}

unsafe extern "C" fn promote(
    _: *mut c_void,
    step: *mut c_void,
    content: *const Reader,
    sink: *const PromotionSink,
) -> i32 {
    // SAFETY: the step is `open`'s; the reader and the sink are the host's,
    // lent for this call.
    let (property, content, sink) = unsafe { (&*step.cast::<String>(), &*content, &*sink) };
    let mut read = Vec::new();
    let mut buffer = [0u8; 3];
    loop {
        let Some(next) = content.read else {
            return status::INVALID;
        };
        // SAFETY: the host's reader, into our buffer, for its length.
        let got = unsafe { next(content.ctx, buffer.as_mut_ptr(), buffer.len()) };
        let Ok(got) = usize::try_from(got) else {
            return status::IO;
        };
        if got == 0 {
            break;
        }
        read.extend_from_slice(&buffer[..got]);
    }
    let length = read.len().to_string();
    let Some(promoted) = sink.promoted else {
        return status::INVALID;
    };
    let handed = [
        (property.as_str(), value_kind::STRING, read.as_slice()),
        ("Length", value_kind::NUMBER, length.as_bytes()),
    ];
    for (name, kind, value) in handed {
        let (name, value) = (
            Str {
                ptr: name.as_ptr(),
                len: name.len(),
            },
            Slice {
                ptr: value.as_ptr(),
                len: value.len(),
            },
        );
        // SAFETY: the host's sink; both borrows live across the call.
        let answer = unsafe { promoted(sink.ctx, name, kind, value) };
        if answer != status::OK {
            return answer;
        }
    }
    status::OK
}

static TABLE: PromoteVtable = PromoteVtable {
    header: VtableHeader {
        trait_major: 1,
        trait_minor: 0,
        configure: Some(configure),
        start: Some(lifecycle),
        stop: Some(lifecycle),
    },
    open: Some(open),
    release: Some(release),
    promote: Some(promote),
};

unsafe extern "C" fn create(host: *const Host, out: *mut Module) -> i32 {
    // SAFETY: the host's table and its live `*out`, for this call.
    unsafe {
        if (*host).abi_version != XMIP_ABI_VERSION {
            return status::UNSUPPORTED;
        }
        *out = Module {
            descriptor: WireDescriptor {
                abi_version: XMIP_ABI_VERSION,
                provider: Str::from_static("Whole"),
                module: Str::from_static(PROMOTE),
                standard: Str::from_static("Whole"),
                trait_major: 1,
                trait_minor: 0,
                module_major: 0,
                module_minor: 1,
                module_patch: 0,
            },
            state: std::ptr::null_mut(),
            vtable: (&raw const TABLE).cast(),
            last_error: Some(last_error),
            destroy: Some(destroy),
        };
    }
    status::OK
}

fn text(value: &str) -> Given {
    Given::Text(value.to_string())
}

#[test]
fn a_promote_unit_opens_a_step_and_promotes_through_its_table() {
    let module = LoadedModule::linked(create, &expectation()).expect("taken at trait 1.0");
    let promotion = LoadedPromotion::of(&module).expect("the promote table");
    promotion.lifecycle().configure("").expect("configures");
    promotion.lifecycle().start().expect("starts");

    let step = promotion
        .open(Stage::Receive, &[("property".to_string(), text("Order"))])
        .expect("a step opens");
    let promoted = step.promote(b"PO-4711").expect("promotes");
    assert_eq!(
        promoted,
        [
            ("Order".to_string(), ScalarValue::Text("PO-4711".into())),
            ("Length".to_string(), ScalarValue::Integer(7)),
        ]
    );
    let empty = step.promote(b"").expect("an empty Stream promotes");
    assert_eq!(empty[1], ("Length".to_string(), ScalarValue::Integer(0)));

    let refused = promotion.open(Stage::Receive, &[]).err().expect("refused");
    assert!(refused.contains("names no property"), "{refused}");
    drop(step);
    promotion.lifecycle().stop().expect("stops");
}

#[test]
fn a_value_is_read_as_its_kind_and_one_of_no_promoted_kind_is_refused() {
    use super::scalar;

    assert_eq!(
        scalar(value_kind::BOOL, b"true"),
        Ok(ScalarValue::Bool(true))
    );
    assert_eq!(
        scalar(value_kind::NUMBER, b"2.5"),
        Ok(ScalarValue::Decimal(2.5))
    );
    assert_eq!(
        scalar(value_kind::BINARY, b"\x01"),
        Ok(ScalarValue::Binary(vec![1]))
    );
    assert!(scalar(value_kind::MAP, b"").is_err());
    assert!(scalar(value_kind::NUMBER, b"many").is_err());
    let settings = super::transferred(&[
        ("member".to_string(), text("number")),
        ("lines".to_string(), Given::Integer(3)),
        ("strict".to_string(), Given::Boolean(true)),
        (
            "namespaces".to_string(),
            Given::Table(vec![("o".to_string(), text("urn:o"))]),
        ),
    ]);
    assert_eq!(
        settings,
        serde_json::json!({
            "member": "number", "lines": 3, "strict": true, "namespaces": { "o": "urn:o" }
        })
    );
}

/// The library `dotnet publish -p:PublishAot=true` makes of the module
/// `dotnet new xmip-module` gives (`Xmip.Templates`, ADR-0075), opened
/// through the C ABI as a node opens a Rust module's, and its Promote unit
/// `OrderNumber` called: the promoted value is the content's `number`.
/// Run on purpose, with the library named:
///
/// ```text
/// XMIP_PROMOTE_LIBRARY=<published library> cargo test -p xmip-core-runtime \
///   --features dynamic-loading loaded_promotion -- --ignored
/// ```
#[test]
#[ignore = "a .NET module's published library, named by XMIP_PROMOTE_LIBRARY; run on purpose"]
fn a_dotnet_module_from_the_template_promotes_through_the_c_abi() {
    let library = std::env::var("XMIP_PROMOTE_LIBRARY")
        .map(PathBuf::from)
        .expect("XMIP_PROMOTE_LIBRARY names the published library");
    let module = LoadedModule::open(&library, &expectation()).expect("the host takes it");
    assert_eq!(module.descriptor().standard, "OrderNumber");
    let promotion = LoadedPromotion::of(&module).expect("the promote table");
    promotion.lifecycle().configure("").expect("configures");
    promotion.lifecycle().start().expect("starts");

    // The entry the build wrote beside the library is what a node reads: it
    // names this library on this platform, declares the unit as a promote
    // unit, and its declaration fills in the step's default.
    let folder = library.parent().expect("the publish folder");
    let module_entry = std::fs::read_dir(folder)
        .expect("the publish folder")
        .filter_map(Result::ok)
        .map(|found| found.path())
        .find(|found| found.to_string_lossy().ends_with(".module.xmip"))
        .expect("the module's [[modules]] entry beside its library");
    let cluster = configure::fixture::test_cluster();
    let document = configure::parse_toml(&format!(
        "[service]\nname = \"xmip\"\ncluster_name = \"{}\"\nnode_name = \"{}\"\n\n{}",
        cluster.name,
        cluster.node(0).name,
        std::fs::read_to_string(&module_entry).expect("reads")
    ))
    .expect("a node reads the entry");
    let [declared] =
        <[configure::ModuleConfiguration; 1]>::try_from(document.modules).expect("one module");
    assert_eq!(declared.problems(), [] as [String; 0]);
    assert_eq!(
        crate::library::located(&declared, folder),
        Ok(library.clone())
    );
    let unit = declared.unit("OrderNumber").expect("the unit, declared");
    assert_eq!(unit.capability, abi::UnitCapability::Promote);
    let read = configure::modules::declared(&declared.name, unit)
        .expect("its settings' declaration")
        .read(xcore::settings::Applies::Both, &[])
        .expect("an empty step reads");
    assert_eq!(read.text("member"), "number");

    let step = promotion
        .open(Stage::Receive, &[("member".to_string(), text("number"))])
        .expect("a step");
    let unread = promotion
        .open(Stage::Receive, &[])
        .err()
        .expect("no member given");
    assert!(unread.contains("member"), "{unread}");
    let promoted = step
        .promote(br#"{"number":"PO-4711","lines":3}"#)
        .expect("promotes");
    assert_eq!(
        promoted,
        [(
            "OrderNumber".to_string(),
            ScalarValue::Text("PO-4711".into())
        )]
    );
    let named = promotion
        .open(Stage::Receive, &[("member".to_string(), text("reference"))])
        .expect("a step naming its member");
    let none = named
        .promote(br#"{"number":"PO-4711"}"#)
        .expect("promotes nothing");
    assert_eq!(none, []);
    let refused = promotion
        .open(Stage::Receive, &[("member".to_string(), text(""))])
        .err()
        .expect("an empty member is refused");
    assert!(refused.contains("member"), "{refused}");
    assert!(step.promote(b"not json").is_err());
    drop((step, named));
    promotion.lifecycle().stop().expect("stops");
}
