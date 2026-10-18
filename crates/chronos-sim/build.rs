fn main() {
    println!("cargo:rustc-cfg=chronos_bundled");
    println!("cargo:rustc-check-cfg=cfg(chronos_bundled)");
    println!("cargo:rerun-if-changed=build.rs");
}
