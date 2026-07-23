//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! E01/EWF via libewf FFI
//!

use std::path::Path;

use crate::Source;
use crate::error::SourceError;

pub const MAGIC: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

#[cfg(latent_ewf)]
pub fn open(path: &Path) -> Result<Box<dyn Source>, SourceError> {
    Ok(Box::new(real::EwfSource::open(path)?))
}

#[cfg(not(latent_ewf))]
pub fn open(path: &Path) -> Result<Box<dyn Source>, SourceError> {
    Err(SourceError::Unsupported {
        path: path.to_path_buf(),
        format: "ewf",
        detail: "this build has no libewf; E01/EWF support is off".into(),
    })
}

#[cfg(latent_ewf)]
pub use real::EwfSource;

#[cfg(latent_ewf)]
#[allow(unsafe_code)]
mod real {
    use std::ffi::{CString, c_void};
    use std::os::raw::{c_char, c_int};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::Mutex;

    use crate::error::SourceError;
    use crate::{Format, Identity, Source};

    const OPEN_READ: c_int = 1;

    unsafe extern "C" {
        fn libewf_handle_initialize(handle: *mut *mut c_void, error: *mut *mut c_void) -> c_int;
        fn libewf_handle_free(handle: *mut *mut c_void, error: *mut *mut c_void) -> c_int;
        fn libewf_handle_open(
            handle: *mut c_void,
            filenames: *const *mut c_char,
            number: c_int,
            flags: c_int,
            error: *mut *mut c_void,
        ) -> c_int;
        fn libewf_handle_close(handle: *mut c_void, error: *mut *mut c_void) -> c_int;
        fn libewf_handle_get_media_size(
            handle: *mut c_void,
            size: *mut u64,
            error: *mut *mut c_void,
        ) -> c_int;
        fn libewf_handle_read_random(
            handle: *mut c_void,
            buffer: *mut c_void,
            size: usize,
            offset: i64,
            error: *mut *mut c_void,
        ) -> isize;
        fn libewf_handle_get_utf8_hash_value_size(
            handle: *mut c_void,
            id: *const u8,
            id_len: usize,
            size: *mut usize,
            error: *mut *mut c_void,
        ) -> c_int;
        fn libewf_handle_get_utf8_hash_value(
            handle: *mut c_void,
            id: *const u8,
            id_len: usize,
            value: *mut u8,
            value_size: usize,
            error: *mut *mut c_void,
        ) -> c_int;
        fn libewf_glob(
            filename: *const c_char,
            filename_len: usize,
            format: c_int,
            filenames: *mut *mut *mut c_char,
            number: *mut c_int,
            error: *mut *mut c_void,
        ) -> c_int;
        fn libewf_glob_free(
            filenames: *mut *mut c_char,
            number: c_int,
            error: *mut *mut c_void,
        ) -> c_int;
    }

    struct Handle(*mut c_void);
    // SAFETY: the handle is only used under its mutex, never concurrently.
    unsafe impl Send for Handle {}

    pub struct EwfSource {
        handle: Mutex<Handle>,
        identity: Identity,
        media_size: u64,
        md5: Option<String>,
        sha1: Option<String>,
    }

    impl EwfSource {
        pub fn open(path: &Path) -> Result<Self, SourceError> {
            let bad = |detail: &str| SourceError::Malformed {
                path: path.to_path_buf(),
                format: "ewf",
                detail: detail.to_string(),
            };
            let c_path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| bad("path contains a NUL byte"))?;

            // SAFETY: valid pointers, owned out-params, every early return frees
            // what was allocated so far.
            unsafe {
                let mut names: *mut *mut c_char = std::ptr::null_mut();
                let mut count: c_int = 0;
                if libewf_glob(
                    c_path.as_ptr(),
                    path.as_os_str().len(),
                    0,
                    &mut names,
                    &mut count,
                    std::ptr::null_mut(),
                ) != 1
                {
                    return Err(bad("could not enumerate EWF segments"));
                }

                let mut handle: *mut c_void = std::ptr::null_mut();
                if libewf_handle_initialize(&mut handle, std::ptr::null_mut()) != 1 {
                    libewf_glob_free(names, count, std::ptr::null_mut());
                    return Err(bad("libewf handle could not be created"));
                }

                let opened = libewf_handle_open(
                    handle,
                    names as *const *mut c_char,
                    count,
                    OPEN_READ,
                    std::ptr::null_mut(),
                );
                libewf_glob_free(names, count, std::ptr::null_mut());
                if opened != 1 {
                    libewf_handle_free(&mut handle, std::ptr::null_mut());
                    return Err(bad("not a readable EWF image"));
                }

                let mut media_size: u64 = 0;
                if libewf_handle_get_media_size(handle, &mut media_size, std::ptr::null_mut()) != 1
                {
                    libewf_handle_close(handle, std::ptr::null_mut());
                    libewf_handle_free(&mut handle, std::ptr::null_mut());
                    return Err(bad("could not read the media size"));
                }

                let md5 = hash_value(handle, b"MD5");
                let sha1 = hash_value(handle, b"SHA1");

                Ok(EwfSource {
                    handle: Mutex::new(Handle(handle)),
                    identity: Identity {
                        path: path.to_path_buf(),
                        format: Format::Ewf,
                    },
                    media_size,
                    md5,
                    sha1,
                })
            }
        }

        pub fn acquisition_md5(&self) -> Option<&str> {
            self.md5.as_deref()
        }

        pub fn acquisition_sha1(&self) -> Option<&str> {
            self.sha1.as_deref()
        }
    }

    unsafe fn hash_value(handle: *mut c_void, id: &[u8]) -> Option<String> {
        // SAFETY: buffer is sized from the size call before it is filled.
        unsafe {
            let mut size: usize = 0;
            if libewf_handle_get_utf8_hash_value_size(
                handle,
                id.as_ptr(),
                id.len(),
                &mut size,
                std::ptr::null_mut(),
            ) != 1
                || size <= 1
            {
                return None;
            }
            let mut buf = vec![0u8; size];
            if libewf_handle_get_utf8_hash_value(
                handle,
                id.as_ptr(),
                id.len(),
                buf.as_mut_ptr(),
                size,
                std::ptr::null_mut(),
            ) != 1
            {
                return None;
            }
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8(buf[..end].to_vec()).ok()
        }
    }

    impl Source for EwfSource {
        fn size(&self) -> u64 {
            self.media_size
        }

        fn identity(&self) -> &Identity {
            &self.identity
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
            if offset > self.media_size {
                return Err(SourceError::OutOfRange {
                    offset,
                    size: self.media_size,
                });
            }
            let n = buf.len().min((self.media_size - offset) as usize);
            if n == 0 {
                return Ok(0);
            }
            let guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: the mutex gives exclusive use of the handle; buf holds n bytes.
            let read = unsafe {
                libewf_handle_read_random(
                    guard.0,
                    buf.as_mut_ptr() as *mut c_void,
                    n,
                    offset as i64,
                    std::ptr::null_mut(),
                )
            };
            if read < 0 {
                return Err(SourceError::Malformed {
                    path: self.identity.path.clone(),
                    format: "ewf",
                    detail: "read failed".into(),
                });
            }
            Ok(read as usize)
        }
    }

    impl Drop for EwfSource {
        fn drop(&mut self) {
            let guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: last use of the handle; close then free, matching open.
            unsafe {
                let mut handle = guard.0;
                libewf_handle_close(handle, std::ptr::null_mut());
                libewf_handle_free(&mut handle, std::ptr::null_mut());
            }
        }
    }
}

#[cfg(all(test, latent_ewf))]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ewf")
            .join(name)
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect()
    }

    #[test]
    fn single_segment_reads_byte_for_byte() {
        let src = crate::open(&fixture("single.E01")).unwrap();
        assert_eq!(src.size(), 8192);
        let mut got = vec![0u8; 8192];
        src.read_exact_at(0, &mut got).unwrap();
        assert_eq!(got, pattern(8192));
    }

    #[test]
    fn multi_segment_reads_byte_for_byte() {
        let src = crate::open(&fixture("multi.E01")).unwrap();
        assert_eq!(src.size(), 65536);
        let want = pattern(65536);

        let mut whole = vec![0u8; 65536];
        src.read_exact_at(0, &mut whole).unwrap();
        assert_eq!(whole, want);

        let mut mid = [0u8; 4096];
        src.read_exact_at(30000, &mut mid).unwrap();
        assert_eq!(mid, want[30000..34096]);
    }

    #[test]
    fn acquisition_hash_extraction_is_clean() {
        let src = EwfSource::open(&fixture("single.E01")).unwrap();
        for hash in [src.acquisition_md5(), src.acquisition_sha1()]
            .into_iter()
            .flatten()
        {
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn a_garbage_ewf_errors_not_panics() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.E01");
        let mut bytes = MAGIC.to_vec();
        bytes.extend(std::iter::repeat_n(0xab, 4096));
        std::fs::write(&path, bytes).unwrap();
        assert!(crate::open(&path).is_err());
    }
}
