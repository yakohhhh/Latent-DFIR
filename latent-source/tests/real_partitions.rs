//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Partition tests against sfdisk images
//!

#![cfg(target_os = "linux")]

use std::io::Write;
use std::process::{Command, Stdio};

use latent_source::partition::{self, Scheme};

fn has_sfdisk() -> bool {
    Command::new("sfdisk")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn build(script: &str) -> tempfile::NamedTempFile {
    let img = tempfile::NamedTempFile::new().unwrap();
    img.as_file().set_len(8 * 1024 * 1024).unwrap();

    let mut child = Command::new("sfdisk")
        .arg(img.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "sfdisk failed");
    img
}

#[test]
fn reads_a_real_gpt_disk() {
    if !has_sfdisk() {
        eprintln!("sfdisk not available, skipping");
        return;
    }
    let img = build("label: gpt\nstart=2048, size=2048, type=L\nstart=4096, size=2048, type=S\n");
    let src = latent_source::open(img.path()).unwrap();
    let table = partition::read(src.as_ref());

    assert_eq!(table.scheme, Scheme::Gpt);
    assert_eq!(table.len(), 2);
    assert_eq!(table.partitions[0].start, 2048 * 512);
    assert_eq!(table.partitions[0].length, 2048 * 512);
    assert_eq!(
        table.partitions[0].kind,
        "0fc63daf-8483-4772-8e79-3d69d8477de4"
    );
}

#[test]
fn reads_a_real_mbr_disk_with_a_logical() {
    if !has_sfdisk() {
        eprintln!("sfdisk not available, skipping");
        return;
    }
    let img = build(
        "label: dos\n\
         start=2048, size=2048, type=83\n\
         start=8192, size=4096, type=5\n\
         start=10240, size=1024, type=83\n",
    );
    let src = latent_source::open(img.path()).unwrap();
    let table = partition::read(src.as_ref());

    assert_eq!(table.scheme, Scheme::Mbr);
    assert_eq!(table.partitions.len(), 2);
    assert!(table.partitions.iter().any(|p| p.start == 2048 * 512));
    assert!(table.partitions.iter().any(|p| p.start == 10240 * 512));
}
