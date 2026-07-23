//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Read-only opening
//!

use std::fs::File;
use std::path::Path;

use crate::error::SourceError;

#[cfg(unix)]
pub(crate) fn open_readonly(path: &Path) -> Result<File, SourceError> {
    use rustix::fs::{Mode, OFlags, fcntl_getfl, open};

    let io = |e: rustix::io::Errno| SourceError::io(path, e.into());
    let base = OFlags::RDONLY | OFlags::CLOEXEC;

    let fd = {
        #[cfg(target_os = "linux")]
        {
            open(path, base | OFlags::NOATIME, Mode::empty())
                .or_else(|_| open(path, base, Mode::empty()))
                .map_err(io)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            open(path, base, Mode::empty()).map_err(io)?
        }
    };

    let flags = fcntl_getfl(&fd).map_err(io)?;
    if flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
        return Err(SourceError::NotReadOnly {
            path: path.to_path_buf(),
        });
    }
    Ok(File::from(fd))
}

#[cfg(windows)]
pub(crate) fn open_readonly(path: &Path) -> Result<File, SourceError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;

    // GENERIC_READ is the read-only guarantee; share everything so evidence held
    // open by another handle still opens.
    OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .map_err(|e| SourceError::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn handle_refuses_writes() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"evidence").unwrap();
        f.flush().unwrap();

        let mut ro = open_readonly(f.path()).unwrap();
        assert!(ro.write_all(b"x").is_err());

        use std::io::Read;
        let mut buf = String::new();
        ro.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "evidence");
    }
}
