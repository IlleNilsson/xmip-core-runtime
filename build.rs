//! The runtime's library stays in the process once loaded (`xmip_operate.h`
//! section 1): it runs threads of its own that outlive every call, so
//! unloading it would unmap the code they run. On Windows the library pins
//! itself as it loads (`src/ffi/resident.rs`); on ELF systems the link marks
//! it `nodelete`, so `dlclose` releases a reference and never unmaps it. On
//! macOS dyld never unloads a library holding thread-local variables, which
//! the Rust standard library's threads do.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if family == "unix" && !matches!(os.as_str(), "macos" | "ios") {
        println!("cargo::rustc-cdylib-link-arg=-Wl,-z,nodelete");
    }
}
