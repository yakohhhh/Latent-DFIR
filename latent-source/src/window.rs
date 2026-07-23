//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Offset and length sub-source
//!

use std::sync::Arc;

use crate::error::SourceError;
use crate::{Identity, Source};

pub struct Window {
    inner: Arc<dyn Source>,
    offset: u64,
    len: u64,
    identity: Identity,
}

impl Window {
    pub fn range(
        inner: Arc<dyn Source>,
        offset: u64,
        len: Option<u64>,
    ) -> Result<Self, SourceError> {
        let total = inner.size();
        if offset > total {
            return Err(SourceError::OutOfRange {
                offset,
                size: total,
            });
        }
        let available = total - offset;
        let len = len.unwrap_or(available).min(available);
        let identity = inner.identity().clone();
        Ok(Window {
            inner,
            offset,
            len,
            identity,
        })
    }
}

impl Source for Window {
    fn size(&self) -> u64 {
        self.len
    }

    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset > self.len {
            return Err(SourceError::OutOfRange {
                offset,
                size: self.len,
            });
        }
        let n = buf.len().min((self.len - offset) as usize);
        if n == 0 {
            return Ok(0);
        }
        self.inner.read_at(self.offset + offset, &mut buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawSource;
    use std::io::Write;

    fn source(bytes: &[u8]) -> Arc<dyn Source> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        let (_, path) = f.keep().unwrap();
        Arc::new(RawSource::open(&path).unwrap())
    }

    #[test]
    fn reads_are_translated_and_clamped() {
        let data: Vec<u8> = (0..100).collect();
        let w = Window::range(source(&data), 10, Some(20)).unwrap();
        assert_eq!(w.size(), 20);

        let mut buf = [0u8; 8];
        w.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(buf, [10, 11, 12, 13, 14, 15, 16, 17]);

        let mut big = [0u8; 50];
        assert_eq!(w.read_at(15, &mut big).unwrap(), 5);
        assert_eq!(&big[..5], &[25, 26, 27, 28, 29]);
    }

    #[test]
    fn length_is_clamped_to_the_parent() {
        let data = vec![0u8; 100];
        let w = Window::range(source(&data), 90, Some(1000)).unwrap();
        assert_eq!(w.size(), 10);
    }

    #[test]
    fn offset_past_the_end_is_rejected() {
        let data = vec![0u8; 100];
        assert!(matches!(
            Window::range(source(&data), 200, None),
            Err(SourceError::OutOfRange { .. })
        ));
    }

    #[test]
    fn default_length_runs_to_the_end() {
        let data = vec![0u8; 100];
        let w = Window::range(source(&data), 40, None).unwrap();
        assert_eq!(w.size(), 60);
    }
}
