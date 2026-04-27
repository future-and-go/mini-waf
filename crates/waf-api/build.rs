//! Build script for waf-api.
//!
//! `static_files.rs` uses `#[derive(RustEmbed)] #[folder = ".../dist/"]` to
//! embed the built admin-panel SPA into the binary. The proc-macro panics at
//! compile time if the folder is missing, which breaks `cargo build`,
//! `cargo clippy`, and `cargo check` on any environment that hasn't run
//! `npm run build` yet (CI, fresh clones, sandboxed builders, etc.).
//!
//! To keep the Rust crate compilable in isolation, this script creates an
//! empty placeholder `dist/` (with a stub `index.html`) when one isn't
//! already present. Real production builds still copy the real artifacts
//! into `dist/` before invoking `cargo`, so this only kicks in when the
//! admin-panel hasn't been built.

#![allow(clippy::expect_used, clippy::print_stdout)]

use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");
    let dist_dir = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("web")
        .join("admin-panel")
        .join("dist");

    println!("cargo:rerun-if-changed={}", dist_dir.display());

    let index_path = dist_dir.join("index.html");
    if index_path.exists() {
        return;
    }

    if let Err(e) = fs::create_dir_all(&dist_dir) {
        println!(
            "cargo:warning=waf-api: failed to create placeholder dist dir {}: {e}",
            dist_dir.display()
        );
        return;
    }

    let placeholder = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>WAF Admin (placeholder)</title></head>
<body>
<h1>WAF Admin UI not built</h1>
<p>Run <code>cd web/admin-panel &amp;&amp; npm install &amp;&amp; npm run build</code> and re-build the Rust binary to embed the real UI.</p>
</body>
</html>
"#;

    if let Err(e) = fs::write(&index_path, placeholder) {
        println!(
            "cargo:warning=waf-api: failed to write placeholder {}: {e}",
            index_path.display()
        );
    }
}
