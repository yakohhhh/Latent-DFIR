//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Triage collection directories
//!

use std::path::{Path, PathBuf};

use crate::error::SourceError;
use crate::{Source, open};

pub struct Collection {
    root: PathBuf,
    files: Vec<PathBuf>,
    skipped: Vec<PathBuf>,
}

impl Collection {
    pub fn open(root: &Path) -> Result<Self, SourceError> {
        let meta = std::fs::metadata(root).map_err(|e| SourceError::io(root, e))?;
        if !meta.is_dir() {
            return Err(SourceError::Unrecognized {
                path: root.to_path_buf(),
            });
        }
        let mut c = Collection {
            root: root.to_path_buf(),
            files: Vec::new(),
            skipped: Vec::new(),
        };
        c.walk(root);
        Ok(c)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    pub fn skipped(&self) -> &[PathBuf] {
        &self.skipped
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn sources(&self) -> impl Iterator<Item = Result<Box<dyn Source>, SourceError>> + '_ {
        self.files.iter().map(|p| open(p))
    }

    fn walk(&mut self, dir: &Path) {
        let mut entries: Vec<_> = match std::fs::read_dir(dir) {
            Ok(rd) => rd.filter_map(Result::ok).collect(),
            Err(_) => {
                tracing::debug!(dir = %dir.display(), "cannot read directory, skipping");
                return;
            }
        };
        entries.sort_by_key(std::fs::DirEntry::file_name);

        for entry in entries {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => {
                    self.skip(path);
                    continue;
                }
            };

            if ft.is_dir() {
                self.walk(&path);
            } else if ft.is_file() {
                let empty = entry.metadata().map(|m| m.len() == 0).unwrap_or(true);
                if empty {
                    self.skip(path);
                } else {
                    self.files.push(path);
                }
            } else {
                self.skip(path);
            }
        }
    }

    fn skip(&mut self, path: PathBuf) {
        tracing::debug!(path = %path.display(), "skipping unrecognised entry");
        self.skipped.push(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        write(&r.join("b.img"), b"bb");
        write(&r.join("z.img"), b"zz");
        write(&r.join("a/d.bin"), b"dd");
        write(&r.join("a/c.bin"), b"cc");
        write(&r.join("empty.bin"), b"");
        dir
    }

    fn rel(c: &Collection) -> Vec<String> {
        c.files()
            .iter()
            .map(|p| {
                p.strip_prefix(c.root())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn walks_depth_first_with_sorted_siblings() {
        let dir = tree();
        let c = Collection::open(dir.path()).unwrap();
        assert_eq!(rel(&c), ["a/c.bin", "a/d.bin", "b.img", "z.img"]);
    }

    #[test]
    fn empty_files_are_skipped() {
        let dir = tree();
        let c = Collection::open(dir.path()).unwrap();
        assert!(c.skipped().iter().any(|p| p.ends_with("empty.bin")));
        assert!(!c.files().iter().any(|p| p.ends_with("empty.bin")));
    }

    #[test]
    fn order_is_stable_across_runs() {
        let dir = tree();
        assert_eq!(
            rel(&Collection::open(dir.path()).unwrap()),
            rel(&Collection::open(dir.path()).unwrap())
        );
    }

    #[test]
    fn recognised_files_open_and_read() {
        let dir = tree();
        let c = Collection::open(dir.path()).unwrap();
        let opened: Vec<_> = c.sources().map(|s| s.unwrap()).collect();
        assert_eq!(opened.len(), 4);
        let mut buf = [0u8; 2];
        opened[0].read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"cc");
    }

    #[test]
    fn a_file_is_not_a_collection() {
        let dir = tree();
        let f = dir.path().join("b.img");
        assert!(matches!(
            Collection::open(&f),
            Err(SourceError::Unrecognized { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("real.bin"), b"hi");
        std::os::unix::fs::symlink(dir.path().join("real.bin"), dir.path().join("link.bin"))
            .unwrap();
        let c = Collection::open(dir.path()).unwrap();
        assert_eq!(rel(&c), ["real.bin"]);
        assert!(c.skipped().iter().any(|p| p.ends_with("link.bin")));
    }
}
