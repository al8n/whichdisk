#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

use std::ffi::OsStr;
use std::io;
use std::path::Path;

// All BSDs (including Apple platforms) use statfs with f_mntonname/f_mntfromname.
// NetBSD is excluded because rustix does not expose statfs for it;
// it falls through to the Linux-style /proc parsing below.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
  target_os = "freebsd",
  target_os = "openbsd",
  target_os = "dragonfly",
))]
#[path = "bsd.rs"]
mod os;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod os;

#[cfg(windows)]
#[path = "windows.rs"]
mod os;

const INLINE_CAPACITY: usize = 56;

/// Miri-safe `memchr` wrapper. Under miri, falls back to a simple byte-by-byte
/// scan because `memchr`'s SIMD internals are not miri-compatible.
#[cfg(unix)]
#[cfg_attr(not(tarpaulin), inline(always))]
fn find_byte(needle: u8, haystack: &[u8]) -> Option<usize> {
  #[cfg(miri)]
  {
    haystack.iter().position(|&b| b == needle)
  }
  #[cfg(not(miri))]
  {
    memchr::memchr(needle, haystack)
  }
}

/// Small-buffer-optimized byte string. Inlines up to 56 bytes on the stack;
/// longer values use `bytes::Bytes` (reference-counted, clone is a pointer copy).
#[derive(Clone, Debug)]
enum SmallBytes {
  /// Stack-inlined storage for short byte strings (≤ 56 bytes).
  Inline {
    data: [u8; INLINE_CAPACITY],
    len: u8,
  },
  /// Reference-counted heap storage for longer byte strings.
  Heap(bytes::Bytes),
}

impl SmallBytes {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn from_bytes(bytes: &[u8]) -> Self {
    if bytes.len() <= INLINE_CAPACITY {
      let mut data = [0u8; INLINE_CAPACITY];
      data[..bytes.len()].copy_from_slice(bytes);
      Self::Inline {
        data,
        len: bytes.len() as u8,
      }
    } else {
      Self::Heap(bytes::Bytes::copy_from_slice(bytes))
    }
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  fn as_bytes(&self) -> &[u8] {
    match self {
      Self::Inline { data, len } => &data[..*len as usize],
      Self::Heap(b) => b,
    }
  }

  #[cfg(unix)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn as_path(&self) -> &Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(OsStr::from_bytes(self.as_bytes()))
  }

  #[cfg(unix)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn as_os_str(&self) -> &OsStr {
    use std::os::unix::ffi::OsStrExt;
    OsStr::from_bytes(self.as_bytes())
  }

  /// On Windows, mount points and volume names are always valid UTF-8 (ASCII),
  /// so we can go through `&str` → `&Path`.
  #[cfg(windows)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn as_path(&self) -> &Path {
    Path::new(self.as_str())
  }

  /// On Windows, mount points and volume names are always valid UTF-8 (ASCII),
  /// so we can go through `&str` → `&OsStr`.
  #[cfg(windows)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn as_os_str(&self) -> &OsStr {
    OsStr::new(self.as_str())
  }

  #[cfg(windows)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn as_str(&self) -> &str {
    // Windows volume/mount names are always valid ASCII/UTF-8.
    // If this invariant is ever violated, it's a bug in our code.
    core::str::from_utf8(self.as_bytes())
      .expect("Windows volume/mount names are always valid ASCII/UTF-8")
  }
}

impl PartialEq for SmallBytes {
  #[inline]
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes() == other.as_bytes()
  }
}

impl Eq for SmallBytes {}

/// Information about the disk/volume a path resides on.
#[derive(Clone, PartialEq, Eq)]
pub struct Disk {
  inner: os::Inner,
}

impl Disk {
  /// Returns the mount point of the disk/volume.
  #[inline]
  pub fn mount_point(&self) -> &Path {
    self.inner.mount_point()
  }

  /// Returns the device name (e.g. `/dev/disk1s1`).
  #[inline]
  pub fn device(&self) -> &OsStr {
    self.inner.device()
  }

  /// Returns the path relative to the mount point.
  #[inline]
  pub fn relative_path(&self) -> &Path {
    self.inner.relative_path()
  }
}

impl core::fmt::Debug for Disk {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Disk")
      .field("mount_point", &self.mount_point())
      .field("device", &self.device())
      .field("relative_path", &self.relative_path())
      .finish()
  }
}

/// Given a path, resolves which disk/volume it resides on.
///
/// Returns the mount point, device name, and the path relative to the mount point.
pub fn which_disk(path: impl AsRef<Path>) -> io::Result<Disk> {
  os::which_disk(path.as_ref()).map(|inner| Disk { inner })
}

#[cfg(test)]
mod tests {
  use super::*;

  // ── which_disk tests ──────────────────────────────────────────────

  fn root_path() -> &'static str {
    if cfg!(windows) { "C:\\" } else { "/" }
  }

  fn nonexistent_path() -> &'static str {
    if cfg!(windows) {
      "Z:\\nonexistent\\path\\xyz"
    } else {
      "/nonexistent/path/that/does/not/exist"
    }
  }

  #[test]
  fn test_root() {
    let info = which_disk(root_path()).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
    assert_eq!(info.relative_path(), Path::new(""));
    println!("Root disk info: {:?}", info);
  }

  #[test]
  fn test_existing_path() {
    let info = which_disk(env!("CARGO_MANIFEST_DIR")).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
    assert!(!info.relative_path().as_os_str().is_empty());
    println!("Current directory disk info: {:?}", info);
  }

  #[test]
  fn test_nonexistent_path() {
    let result = which_disk(nonexistent_path());
    assert!(result.is_err());
  }

  #[test]
  fn test_file_path() {
    // Test with a real file, not just a directory.
    let info = which_disk(file!()).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
  }

  #[test]
  #[cfg(unix)]
  fn test_symlink_path() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target_file");
    std::fs::write(&target, b"hello").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let info_target = which_disk(&target).unwrap();
    let info_link = which_disk(&link).unwrap();

    // Both should resolve to the same mount point and device.
    assert_eq!(info_target.mount_point(), info_link.mount_point());
    assert_eq!(info_target.device(), info_link.device());
  }

  #[test]
  fn test_repeated_lookups_hit_cache() {
    // Call twice for the same device — second call should hit the cache.
    let info1 = which_disk(root_path()).unwrap();
    let info2 = which_disk(root_path()).unwrap();
    assert_eq!(info1.mount_point(), info2.mount_point());
    assert_eq!(info1.device(), info2.device());
  }

  #[test]
  fn test_deep_nested_path() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("a/b/c/d/e");
    std::fs::create_dir_all(&deep).unwrap();
    let info = which_disk(&deep).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.relative_path().as_os_str().is_empty());
  }

  #[test]
  fn test_relative_path_is_relative() {
    let info = which_disk(env!("CARGO_MANIFEST_DIR")).unwrap();
    // The relative path should not start with '/'.
    assert!(info.relative_path().is_relative());
  }

  #[test]
  fn test_temp_dir() {
    let dir = tempfile::tempdir().unwrap();
    let info = which_disk(dir.path()).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
  }

  // ── Disk size ─────────────────────────────────────────────────

  #[test]
  fn test_struct_size() {
    let size = core::mem::size_of::<Disk>();
    println!("Disk size: {size} bytes");
    assert!(size < 256, "Disk should be compact, got {size} bytes");
  }

  // ── SmallBytes tests ──────────────────────────────────────────────

  #[test]
  fn test_smallbytes_inline() {
    let data = b"hello";
    let sb = SmallBytes::from_bytes(data);
    assert_eq!(sb.as_bytes(), data);
    assert!(matches!(sb, SmallBytes::Inline { .. }));
  }

  #[test]
  fn test_smallbytes_heap() {
    let data = vec![b'x'; INLINE_CAPACITY + 1];
    let sb = SmallBytes::from_bytes(&data);
    assert_eq!(sb.as_bytes(), &data[..]);
    assert!(matches!(sb, SmallBytes::Heap(_)));
  }

  #[test]
  fn test_smallbytes_exact_capacity() {
    let data = vec![b'a'; INLINE_CAPACITY];
    let sb = SmallBytes::from_bytes(&data);
    assert_eq!(sb.as_bytes(), &data[..]);
    assert!(matches!(sb, SmallBytes::Inline { .. }));
  }

  #[test]
  fn test_smallbytes_empty() {
    let sb = SmallBytes::from_bytes(b"");
    assert_eq!(sb.as_bytes(), b"");
    assert!(matches!(sb, SmallBytes::Inline { len: 0, .. }));
  }

  #[test]
  fn test_smallbytes_clone_inline() {
    let sb = SmallBytes::from_bytes(b"/dev/sda1");
    let cloned = sb.clone();
    assert_eq!(sb.as_bytes(), cloned.as_bytes());
  }

  #[test]
  fn test_smallbytes_clone_heap() {
    let data = vec![b'z'; INLINE_CAPACITY + 10];
    let sb = SmallBytes::from_bytes(&data);
    let cloned = sb.clone();
    assert_eq!(sb.as_bytes(), cloned.as_bytes());
    assert!(matches!(cloned, SmallBytes::Heap(_)));
  }

  #[test]
  fn test_smallbytes_eq() {
    let a = SmallBytes::from_bytes(b"test");
    let b = SmallBytes::from_bytes(b"test");
    let c = SmallBytes::from_bytes(b"other");
    assert_eq!(a, b);
    assert_ne!(a, c);
  }

  #[test]
  fn test_smallbytes_eq_across_variants() {
    // Same content, one inline and one heap — should be equal.
    let data = vec![b'y'; INLINE_CAPACITY];
    let inline = SmallBytes::from_bytes(&data);

    let heap = SmallBytes::Heap(bytes::Bytes::from(data.clone()));
    assert_eq!(inline, heap);
  }

  #[cfg(unix)]
  #[test]
  fn test_smallbytes_as_path() {
    let sb = SmallBytes::from_bytes(b"/tmp");
    assert_eq!(sb.as_path(), Path::new("/tmp"));
  }

  #[cfg(unix)]
  #[test]
  fn test_smallbytes_as_os_str() {
    let sb = SmallBytes::from_bytes(b"device");
    assert_eq!(sb.as_os_str(), OsStr::new("device"));
  }

  #[cfg(unix)]
  #[test]
  fn test_smallbytes_as_path_heap() {
    let data = vec![b'/'; INLINE_CAPACITY + 1];
    let sb = SmallBytes::from_bytes(&data);
    let path = sb.as_path();
    assert_eq!(path.as_os_str().len(), INLINE_CAPACITY + 1);
  }

  // ── bsd.rs branch coverage ───────────────────────────────────────

  /// Covers the `off + 1` branch in bsd.rs: canonical starts with mount_point
  /// and the next byte is '/'. This requires a non-firmlinked path on a
  /// non-root mount point.
  #[cfg(target_os = "macos")]
  #[test]
  fn test_non_firmlinked_data_volume_path() {
    // .fseventsd lives directly on the data volume and is NOT firmlinked,
    // so canonicalize preserves the /System/Volumes/Data prefix.
    let path = std::path::Path::new("/System/Volumes/Data/.fseventsd");
    if !path.exists() {
      // Skip on systems without this directory.
      return;
    }
    let info = which_disk(path).unwrap();
    assert_eq!(
      info.mount_point(),
      Path::new("/System/Volumes/Data"),
      "expected data volume mount point"
    );
    assert_eq!(
      info.relative_path(),
      Path::new(".fseventsd"),
      "relative path should be the directory name"
    );
  }

  /// Covers the `canonical_bytes.len()` branch (empty relative path) in the
  /// firmlink else-arm: mount point doesn't prefix the canonical path AND
  /// the firmlinked path doesn't exist on disk.
  #[cfg(target_os = "macos")]
  #[test]
  fn test_data_volume_mount_point_itself() {
    // Accessing the mount point itself: canonical == mount_point,
    // off == canonical.len(), hits the `off` (not `off + 1`) branch.
    let path = std::path::Path::new("/System/Volumes/Data");
    if !path.exists() {
      return;
    }
    let info = which_disk(path).unwrap();
    assert_eq!(info.mount_point(), Path::new("/System/Volumes/Data"));
    assert_eq!(info.relative_path(), Path::new(""));
  }
}
