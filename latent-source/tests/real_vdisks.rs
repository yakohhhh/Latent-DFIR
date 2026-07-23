//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Virtual disk round-trip tests
//!

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SIZE: usize = 256 * 1024;
const HOLE: std::ops::Range<usize> = 64 * 1024..128 * 1024;

fn has_qemu_img() -> bool {
    Command::new("qemu-img")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn flat() -> Vec<u8> {
    let mut v = vec![0u8; SIZE];
    for (i, b) in v.iter_mut().enumerate() {
        *b = if HOLE.contains(&i) {
            0
        } else {
            ((i * 31 + 7) % 251) as u8
        };
    }
    v
}

fn qemu_convert(dir: &Path, fmt: &str, opts: Option<&str>, out: &str) -> PathBuf {
    let raw = dir.join("flat.raw");
    std::fs::write(&raw, flat()).unwrap();
    let out = dir.join(out);

    let mut cmd = Command::new("qemu-img");
    cmd.args(["convert", "-f", "raw", "-O", fmt]);
    if let Some(o) = opts {
        cmd.args(["-o", o]);
    }
    cmd.arg(&raw).arg(&out);
    assert!(
        cmd.status().unwrap().success(),
        "qemu-img convert {fmt} failed"
    );
    out
}

fn assert_reads_like_flat(image: &Path) {
    let src = latent_source::open(image).unwrap();
    assert_eq!(src.size(), SIZE as u64, "wrong virtual size");

    let want = flat();
    let mut got = vec![0u8; SIZE];
    src.read_exact_at(0, &mut got).unwrap();
    assert_eq!(got, want, "full read differs");

    for &(off, len) in &[
        (0, 100),
        (60 * 1024, 16 * 1024),
        (127 * 1024, 4 * 1024),
        (SIZE - 10, 10),
    ] {
        let mut buf = vec![0u8; len];
        src.read_exact_at(off as u64, &mut buf).unwrap();
        assert_eq!(buf, &want[off..off + len], "window at {off} differs");
    }
}

#[test]
fn qcow2_round_trips() {
    if !has_qemu_img() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    assert_reads_like_flat(&qemu_convert(dir.path(), "qcow2", None, "disk.qcow2"));
}

#[test]
fn vmdk_monolithic_sparse_round_trips() {
    if !has_qemu_img() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    assert_reads_like_flat(&qemu_convert(
        dir.path(),
        "vmdk",
        Some("subformat=monolithicSparse"),
        "disk.vmdk",
    ));
}

#[test]
fn vhdx_dynamic_round_trips() {
    if !has_qemu_img() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    assert_reads_like_flat(&qemu_convert(
        dir.path(),
        "vhdx",
        Some("subformat=dynamic,block_size=1M"),
        "disk.vhdx",
    ));
}

#[test]
fn vhdx_fixed_round_trips() {
    if !has_qemu_img() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    assert_reads_like_flat(&qemu_convert(
        dir.path(),
        "vhdx",
        Some("subformat=fixed,block_size=1M"),
        "disk_fixed.vhdx",
    ));
}

#[test]
fn qcow2_with_a_backing_file_is_refused() {
    if !has_qemu_img() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let base = qemu_convert(dir.path(), "qcow2", None, "base.qcow2");
    let overlay = dir.path().join("overlay.qcow2");
    let ok = Command::new("qemu-img")
        .args(["create", "-f", "qcow2", "-b"])
        .arg(&base)
        .args(["-F", "qcow2"])
        .arg(&overlay)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "qemu-img create overlay failed");

    let opened = latent_source::open(&overlay);
    assert!(
        matches!(opened, Err(latent_source::SourceError::Unsupported { .. })),
        "expected a backing-file rejection"
    );
}
