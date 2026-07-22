//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Raw and dd images
//!

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::error::SourceError;
use crate::{Format, Identity, Source};

pub struct RawSource {
    backing: Backing,
    size: u64,
    identity: Identity,
}

enum Backing {
    Mapped(Mmap),
    Positioned(File),
    Empty,
}

impl RawSource {
    pub fn open(path: &Path) -> Result<Self, SourceError> {
        let (file, size) = open_file(path)?;
        let identity = Identity {
            path: path.to_path_buf(),
            format: Format::Raw,
        };

        if size == 0 {
            return Ok(RawSource {
                backing: Backing::Empty,
                size,
                identity,
            });
        }

        // SAFETY: read-only map of evidence; truncation under us would SIGBUS,
        // caught by the open/close hashing. Falls back to positioned reads.
        #[allow(unsafe_code)]
        let mapped = unsafe { Mmap::map(&file) };
        let backing = match mapped {
            Ok(m) => Backing::Mapped(m),
            Err(_) => Backing::Positioned(file),
        };
        Ok(RawSource {
            backing,
            size,
            identity,
        })
    }

    pub fn open_positioned(path: &Path) -> Result<Self, SourceError> {
        let (file, size) = open_file(path)?;
        let identity = Identity {
            path: path.to_path_buf(),
            format: Format::Raw,
        };
        let backing = if size == 0 {
            Backing::Empty
        } else {
            Backing::Positioned(file)
        };
        Ok(RawSource {
            backing,
            size,
            identity,
        })
    }
}

fn open_file(path: &Path) -> Result<(File, u64), SourceError> {
    let file = crate::readonly::open_readonly(path)?;
    let size = file.metadata().map_err(|e| SourceError::io(path, e))?.len();
    Ok((file, size))
}

impl Source for RawSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset > self.size {
            return Err(SourceError::OutOfRange {
                offset,
                size: self.size,
            });
        }
        let n = buf.len().min((self.size - offset) as usize);
        if n == 0 {
            return Ok(0);
        }
        match &self.backing {
            Backing::Mapped(m) => {
                let start = offset as usize;
                buf[..n].copy_from_slice(&m[start..start + n]);
                Ok(n)
            }
            Backing::Positioned(f) => {
                pread(f, &mut buf[..n], offset).map_err(|e| SourceError::io(&self.identity.path, e))
            }
            Backing::Empty => Ok(0),
        }
    }
}

#[cfg(unix)]
fn pread(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

#[cfg(windows)]
fn pread(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

#[cfg(not(any(unix, windows)))]
compile_error!("latent-source needs positioned reads, which means a Unix or Windows target");

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn file_with(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn mmap_and_positioned_read_the_same() {
        let data: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        let f = file_with(&data);
        let mapped = RawSource::open(f.path()).unwrap();
        let pos = RawSource::open_positioned(f.path()).unwrap();

        assert_eq!(mapped.size(), 5000);
        assert_eq!(pos.size(), 5000);

        for &(off, len) in &[(0u64, 16usize), (100, 500), (4990, 10), (0, 5000)] {
            let mut a = vec![0; len];
            let mut b = vec![0; len];
            mapped.read_exact_at(off, &mut a).unwrap();
            pos.read_exact_at(off, &mut b).unwrap();
            assert_eq!(a, b);
            assert_eq!(a, &data[off as usize..off as usize + len]);
        }
    }

    #[test]
    fn read_near_the_end_is_clamped() {
        let f = file_with(&[1, 2, 3, 4]);
        let s = RawSource::open(f.path()).unwrap();
        let mut buf = [0u8; 10];
        assert_eq!(s.read_at(2, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[3, 4]);
        assert_eq!(s.read_at(4, &mut buf).unwrap(), 0);
    }

    #[test]
    fn reading_past_the_end_errors() {
        let f = file_with(&[1, 2, 3, 4]);
        let s = RawSource::open(f.path()).unwrap();
        let mut buf = [0u8; 4];
        assert!(matches!(
            s.read_at(5, &mut buf),
            Err(SourceError::OutOfRange { .. })
        ));
        assert!(matches!(
            s.read_exact_at(2, &mut buf),
            Err(SourceError::ShortRead { got: 2, .. })
        ));
    }

    #[test]
    fn empty_file_is_a_zero_length_source() {
        let f = file_with(&[]);
        let s = RawSource::open(f.path()).unwrap();
        assert_eq!(s.size(), 0);
        assert_eq!(s.read_at(0, &mut [0u8; 8]).unwrap(), 0);
        assert!(matches!(
            s.read_at(1, &mut [0u8; 8]),
            Err(SourceError::OutOfRange { .. })
        ));
    }
}
