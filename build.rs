//! Embeds the application icon and version information into the executable.
//!
//! This is what makes `deep-defense.exe` show its own icon in Explorer, on the
//! taskbar and in Alt-Tab, and what fills in the Details tab of its file
//! properties. Without it Windows falls back to the blank default icon.
//!
//! `windres` is driven directly rather than through the `winresource` crate.
//! That crate always passes `-I<manifest dir>`, and `windres` does not quote
//! include paths when it builds its preprocessor command line — so any project
//! whose path contains a space (this one does) fails with the unhelpful
//! "preprocessing failed". Writing the resource script ourselves also lets us
//! avoid `#include` entirely, which removes the need for an include path at
//! all.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/deep-defense.ico");
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if let Err(reason) = embed_resources() {
        // Art is not worth failing a build over: warn and produce a working,
        // if plain, executable.
        println!("cargo:warning=building without an embedded icon — {reason}");
    }
}

fn embed_resources() -> Result<(), String> {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").map_err(|_| "CARGO_MANIFEST_DIR is unset")?,
    );
    let out_dir =
        PathBuf::from(std::env::var("OUT_DIR").map_err(|_| "OUT_DIR is unset")?);

    let icon = manifest_dir.join("assets").join("deep-defense.ico");
    if !icon.is_file() {
        return Err(format!(
            "{} is missing; run `python tools/make_icon.py` to regenerate it",
            icon.display()
        ));
    }

    let script = out_dir.join("resource.rc");
    std::fs::write(&script, resource_script(&icon))
        .map_err(|e| format!("cannot write {}: {e}", script.display()))?;

    let object = out_dir.join("resource.o");
    run(
        "windres",
        &[
            // A BFD target keeps 32-bit hosts from guessing wrong.
            "--target".as_ref(),
            "pe-x86-64".as_ref(),
            script.as_os_str(),
            object.as_os_str(),
        ],
    )?;

    // Wrap the object in a static library: rustc links libraries, not bare
    // object files, and `+whole-archive` keeps the linker from discarding a
    // section nothing references from Rust code.
    let library = out_dir.join("libresource.a");
    let _ = std::fs::remove_file(&library);
    run(
        "ar",
        &["rcs".as_ref(), library.as_os_str(), object.as_os_str()],
    )?;

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static:+whole-archive=resource");
    Ok(())
}

fn run(program: &str, args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        format!(
            "cannot run {program} ({e}). Build with `.\\build.ps1`, which puts \
             MinGW's {program} on PATH."
        )
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// The resource script, written without `#include` so no header search path is
/// needed. All constants are spelled numerically for the same reason.
fn resource_script(icon: &Path) -> String {
    // Forward slashes: `windres` treats a backslash in a quoted string as an
    // escape, so `C:\Users\...` would silently mangle the path.
    let icon_path = icon.display().to_string().replace('\\', "/");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let mut parts = version.split('.').map(|p| p.parse::<u16>().unwrap_or(0));
    let (major, minor, patch) = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );

    format!(
        r#"1 ICON "{icon_path}"

1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEOS 0x40004L
FILETYPE 0x1L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "Deep Defense\0"
            VALUE "FileDescription", "Deep Defense password manager\0"
            VALUE "FileVersion", "{version}\0"
            VALUE "InternalName", "deep-defense\0"
            VALUE "LegalCopyright", "MIT licensed\0"
            VALUE "OriginalFilename", "deep-defense.exe\0"
            VALUE "ProductName", "Deep Defense\0"
            VALUE "ProductVersion", "{version}\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    )
}
