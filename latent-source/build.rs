//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! libewf detection and linking
//!

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(latent_ewf)");
    println!("cargo:rerun-if-env-changed=LATENT_EWF");
    println!("cargo:rerun-if-env-changed=LIBEWF_LIB_DIR");

    if std::env::var("LATENT_EWF").as_deref() == Ok("0") {
        return;
    }
    if std::env::var("CARGO_CFG_UNIX").is_err() {
        return;
    }
    match locate() {
        Some(dir) => link(&dir),
        None => println!("cargo:warning=libewf not found; building without E01/EWF support"),
    }
}

fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("LIBEWF_LIB_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    if let Ok(out) = std::process::Command::new("pkg-config")
        .args(["--libs-only-L", "libewf"])
        .output()
    {
        for tok in String::from_utf8_lossy(&out.stdout).split_whitespace() {
            if let Some(path) = tok.strip_prefix("-L") {
                dirs.push(PathBuf::from(path));
            }
        }
    }
    dirs.extend(
        [
            "/usr/lib",
            "/usr/local/lib",
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/opt/homebrew/lib",
            "/usr/local/opt/libewf/lib",
        ]
        .iter()
        .map(PathBuf::from),
    );
    dirs
}

fn locate() -> Option<PathBuf> {
    search_dirs()
        .into_iter()
        .find(|dir| library_in(dir).is_some())
}

fn library_in(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let hit = name == "libewf.so" || name.starts_with("libewf.so.") || name == "libewf.dylib";
        if hit {
            return Some(entry.path());
        }
    }
    None
}

fn link(dir: &Path) {
    let lib = library_in(dir).unwrap();
    println!("cargo:rustc-cfg=latent_ewf");

    let linkable = matches!(
        lib.file_name().and_then(|n| n.to_str()),
        Some("libewf.so" | "libewf.dylib")
    );
    if linkable {
        println!("cargo:rustc-link-search=native={}", dir.display());
    } else {
        let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let alias = out.join("libewf.so");
        let _ = std::fs::remove_file(&alias);
        symlink(&lib, &alias);
        println!("cargo:rustc-link-search=native={}", out.display());
    }
    println!("cargo:rustc-link-lib=dylib=ewf");
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("symlink libewf into OUT_DIR");
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _link: &Path) {
    unreachable!("EWF backend is Unix-only");
}
