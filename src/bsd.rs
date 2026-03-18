use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{stat, statfs};

use super::SmallBytes;

struct CacheEntry {
  mount_point: SmallBytes,
  device: SmallBytes,
}

thread_local! {
  static CACHE: RefCell<HashMap<u64, CacheEntry>> = RefCell::new(HashMap::new());
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Inner {
  mount_point: SmallBytes,
  device: SmallBytes,
  canonical: PathBuf,
  relative_offset: usize,
}

impl Inner {
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn mount_point(&self) -> &Path {
    self.mount_point.as_path()
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn device(&self) -> &OsStr {
    self.device.as_os_str()
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn relative_path(&self) -> &Path {
    let bytes = self.canonical.as_os_str().as_bytes();
    Path::new(OsStr::from_bytes(&bytes[self.relative_offset..]))
  }
}

#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn which_disk(path: &Path) -> std::io::Result<Inner> {
  let canonical = path.canonicalize()?;
  let st = stat(&canonical).map_err(std::io::Error::from)?;
  let dev = st.st_dev as u64;

  // Try thread-local cache first — avoids the statfs syscall on repeated lookups
  // for paths on the same device.
  let cached = CACHE.with(|c| {
    c.borrow()
      .get(&dev)
      .map(|e| (e.mount_point.clone(), e.device.clone()))
  });

  let (mount_point, device) = if let Some(hit) = cached {
    hit
  } else {
    let fs = statfs(&canonical).map_err(std::io::Error::from)?;
    let mp = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntonname));
    let dv = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntfromname));
    CACHE.with(|c| {
      c.borrow_mut().insert(
        dev,
        CacheEntry {
          mount_point: mp.clone(),
          device: dv.clone(),
        },
      );
    });
    (mp, dv)
  };

  let canonical_bytes = canonical.as_os_str().as_bytes();
  let mount_point_bytes = mount_point.as_bytes();

  let relative_offset = if canonical_bytes.starts_with(mount_point_bytes) {
    let off = mount_point_bytes.len();
    if off < canonical_bytes.len() && canonical_bytes[off] == b'/' {
      off + 1
    } else {
      off
    }
  } else {
    // Apple firmlink case: canonicalize() returns a path in the root namespace
    // (e.g. /Users/...) while statfs reports the real mount point
    // (e.g. /System/Volumes/Data). The relative part is the canonical path
    // without the leading '/'.
    #[cfg(any(
      target_os = "macos",
      target_os = "ios",
      target_os = "watchos",
      target_os = "tvos",
      target_os = "visionos",
    ))]
    {
      let firmlinked = Path::new(OsStr::from_bytes(mount_point_bytes))
        .join(canonical.strip_prefix("/").unwrap_or(&canonical));
      if firmlinked.exists() {
        // canonicalize() always returns absolute paths starting with '/',
        // so the relative part starts at byte 1.
        1
      } else {
        canonical_bytes.len()
      }
    }
    #[cfg(not(any(
      target_os = "macos",
      target_os = "ios",
      target_os = "watchos",
      target_os = "tvos",
      target_os = "visionos",
    )))]
    {
      canonical_bytes.len()
    }
  };

  Ok(Inner {
    mount_point,
    device,
    canonical,
    relative_offset,
  })
}

#[cfg_attr(not(tarpaulin), inline(always))]
fn c_chars_as_bytes(chars: &[core::ffi::c_char]) -> &[u8] {
  // SAFETY: c_char and u8 have the same size and alignment.
  let bytes: &[u8] =
    unsafe { &*(core::ptr::from_ref::<[core::ffi::c_char]>(chars) as *const [u8]) };
  let len = super::find_byte(0, bytes).unwrap_or(bytes.len());
  &bytes[..len]
}
