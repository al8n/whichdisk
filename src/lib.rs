#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

use std::{ffi::OsStr, io, path::Path};

// All BSDs (including Apple platforms) use statfs with f_mntonname/f_mntfromname.
// NetBSD uses its own backend (statvfs with f_mntonname/f_mntfromname)
// because rustix does not expose statfs for it.
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

#[cfg(target_os = "netbsd")]
#[path = "netbsd.rs"]
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

#[cfg(windows)]
impl core::hash::Hash for SmallBytes {
  #[inline]
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.as_bytes().hash(state);
  }
}

/// Information about a mount point (device, path, capacity, and whether it's ejectable).
///
/// Returned as part of [`PathLocation`] and by [`list`] / [`list_with`].
#[derive(Clone)]
pub struct MountPoint {
  pub(crate) mount_point: SmallBytes,
  pub(crate) device: SmallBytes,
  pub(crate) is_ejectable: bool,
  pub(crate) total_bytes: u64,
  pub(crate) available_bytes: u64,
}

impl PartialEq for MountPoint {
  /// Compares identity fields only (mount point, device, ejectable status).
  /// Disk usage fields are excluded because they change over time.
  #[inline]
  fn eq(&self, other: &Self) -> bool {
    self.mount_point == other.mount_point
      && self.device == other.device
      && self.is_ejectable == other.is_ejectable
  }
}

impl Eq for MountPoint {}

impl MountPoint {
  /// Returns the mount point path (e.g. `/`, `/home`, `C:\`).
  #[inline]
  pub fn mount_point(&self) -> &Path {
    self.mount_point.as_path()
  }

  /// Returns the device name (e.g. `/dev/sda1`, `\\?\Volume{GUID}\`).
  #[inline]
  pub fn device(&self) -> &OsStr {
    self.device.as_os_str()
  }

  /// Returns `true` if the volume is ejectable or removable.
  #[inline]
  pub fn is_ejectable(&self) -> bool {
    self.is_ejectable
  }

  /// Returns the total capacity of the volume in bytes.
  #[inline]
  pub fn total_bytes(&self) -> u64 {
    self.total_bytes
  }

  /// Returns the number of bytes available to unprivileged users.
  ///
  /// This may be less than the total free space if the filesystem
  /// reserves blocks for the superuser.
  #[inline]
  pub fn available_bytes(&self) -> u64 {
    self.available_bytes
  }

  /// Returns the number of bytes unavailable to unprivileged users.
  ///
  /// Computed as `total_bytes() - available_bytes()`. On filesystems that
  /// reserve blocks for the superuser (e.g. ext4), those reserved blocks
  /// are included in this count even if they are not occupied by data.
  #[inline]
  pub fn used_bytes(&self) -> u64 {
    self.total_bytes.saturating_sub(self.available_bytes)
  }
}

impl core::fmt::Debug for MountPoint {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("MountPoint")
      .field("mount_point", &self.mount_point())
      .field("device", &self.device())
      .field("is_ejectable", &self.is_ejectable)
      .field("total_bytes", &self.total_bytes)
      .field("available_bytes", &self.available_bytes)
      .finish()
  }
}

/// Information about the disk/volume a specific file path resides on.
///
/// Returned by [`resolve`]. Contains the mount point info and the
/// path relative to the mount point.
#[derive(Clone, PartialEq, Eq)]
pub struct PathLocation {
  inner: os::Inner,
}

impl PathLocation {
  /// Returns the mount point information.
  #[inline]
  pub fn mount_info(&self) -> &MountPoint {
    self.inner.mount_info()
  }

  /// Returns the mount point of the disk/volume.
  #[inline]
  pub fn mount_point(&self) -> &Path {
    self.inner.mount_info().mount_point()
  }

  /// Returns the device name (e.g. `/dev/disk1s1`).
  #[inline]
  pub fn device(&self) -> &OsStr {
    self.inner.mount_info().device()
  }

  /// Returns the canonicalized absolute path.
  ///
  /// This is the result of [`std::fs::canonicalize`] on the original input path.
  #[inline]
  pub fn canonical_path(&self) -> &Path {
    self.inner.canonical_path()
  }

  /// Returns the path relative to the mount point.
  #[inline]
  pub fn relative_path(&self) -> &Path {
    self.inner.relative_path()
  }

  /// Returns `true` if the volume is ejectable or removable (e.g. USB drives,
  /// SD cards, external SSDs).
  #[inline]
  pub fn is_ejectable(&self) -> bool {
    self.inner.mount_info().is_ejectable()
  }

  /// Returns the total capacity of the volume in bytes.
  #[inline]
  pub fn total_bytes(&self) -> u64 {
    self.inner.mount_info().total_bytes()
  }

  /// Returns the number of bytes available to unprivileged users.
  #[inline]
  pub fn available_bytes(&self) -> u64 {
    self.inner.mount_info().available_bytes()
  }

  /// Returns the number of bytes unavailable to unprivileged users.
  ///
  /// Computed as `total_bytes() - available_bytes()`. On filesystems that
  /// reserve blocks for the superuser (e.g. ext4), those reserved blocks
  /// are included in this count even if they are not occupied by data.
  #[inline]
  pub fn used_bytes(&self) -> u64 {
    self.inner.mount_info().used_bytes()
  }
}

impl core::fmt::Debug for PathLocation {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("PathLocation")
      .field("canonical_path", &self.canonical_path())
      .field("mount_point", &self.mount_point())
      .field("device", &self.device())
      .field("is_ejectable", &self.is_ejectable())
      .field("total_bytes", &self.total_bytes())
      .field("available_bytes", &self.available_bytes())
      .field("relative_path", &self.relative_path())
      .finish()
  }
}

/// Options for listing mounted volumes.
///
/// Use [`ListOptions::default()`] for all real disks,
/// [`ListOptions::ejectable_only()`] for removable media only, or
/// [`ListOptions::non_ejectable_only()`] for non-removable media only.
#[cfg(feature = "list")]
#[cfg_attr(docsrs, doc(cfg(feature = "list")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListOptions {
  ejectable_only: bool,
  non_ejectable_only: bool,
}

#[cfg(feature = "list")]
impl ListOptions {
  /// List all real (non-virtual) mounted volumes.
  #[inline]
  pub const fn all() -> Self {
    Self {
      ejectable_only: false,
      non_ejectable_only: false,
    }
  }

  /// List only ejectable/removable volumes (USB drives, SD cards, etc.).
  #[inline]
  pub const fn ejectable_only() -> Self {
    Self {
      ejectable_only: true,
      non_ejectable_only: false,
    }
  }

  /// List only non-ejectable/non-removable volumes (internal drives, etc.).
  #[inline]
  pub const fn non_ejectable_only() -> Self {
    Self {
      ejectable_only: false,
      non_ejectable_only: true,
    }
  }

  /// Set whether to filter to ejectable volumes only.
  ///
  /// Enabling this option will automatically disable the
  /// `non_ejectable_only` filter to keep the options consistent.
  #[inline]
  pub const fn set_ejectable_only(mut self, ejectable_only: bool) -> Self {
    self.ejectable_only = ejectable_only;
    if ejectable_only {
      self.non_ejectable_only = false;
    }
    self
  }

  /// Set whether to filter to non-ejectable volumes only.
  ///
  /// Enabling this option will automatically disable the
  /// `ejectable_only` filter to keep the options consistent.
  #[inline]
  pub const fn set_non_ejectable_only(mut self, non_ejectable_only: bool) -> Self {
    self.non_ejectable_only = non_ejectable_only;
    if non_ejectable_only {
      self.ejectable_only = false;
    }
    self
  }

  /// Returns `true` if only ejectable volumes will be listed.
  #[inline]
  pub const fn is_ejectable_only(&self) -> bool {
    self.ejectable_only
  }

  /// Returns `true` if only non-ejectable volumes will be listed.
  #[inline]
  pub const fn is_non_ejectable_only(&self) -> bool {
    self.non_ejectable_only
  }
}

#[cfg(feature = "list")]
impl Default for ListOptions {
  /// Defaults to listing all real disks.
  #[inline]
  fn default() -> Self {
    Self::all()
  }
}

/// Given a path, resolves which disk/volume it resides on.
///
/// Returns the mount point, device name, and the path relative to the mount point.
pub fn resolve(path: impl AsRef<Path>) -> io::Result<PathLocation> {
  os::resolve(path.as_ref()).map(|inner| PathLocation { inner })
}

/// Returns the [`PathLocation`] of the system drive root.
///
/// On Unix this resolves `/`. On Windows this resolves the `%SystemDrive%`
/// environment variable (falling back to `C:\` if unset).
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
  target_os = "freebsd",
  target_os = "openbsd",
  target_os = "dragonfly",
  target_os = "netbsd",
  target_os = "linux",
  windows,
))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "linux",
    windows,
  )))
)]
pub fn root() -> io::Result<PathLocation> {
  #[cfg(not(windows))]
  let path = std::path::PathBuf::from("/");
  #[cfg(windows)]
  let path = {
    let drive = std::env::var_os("SystemDrive").unwrap_or_else(|| "C:".into());
    let mut p = std::path::PathBuf::from(drive);
    p.push("\\");
    p
  };
  resolve(&path)
}

/// Lists mounted volumes with the given options.
///
/// ```rust,ignore
/// // List all disks
/// let all = whichdisk::list_with(ListOptions::all())?;
///
/// // List only ejectable
/// let removable = whichdisk::list_with(ListOptions::ejectable_only())?;
/// ```
#[cfg(feature = "list")]
#[cfg_attr(docsrs, doc(cfg(feature = "list")))]
pub fn list_with(opts: ListOptions) -> io::Result<Vec<MountPoint>> {
  os::list(opts)
}

/// Lists all real (non-virtual) mounted volumes.
///
/// Shorthand for `list_with(ListOptions::all())`.
#[cfg(feature = "list")]
#[cfg_attr(docsrs, doc(cfg(feature = "list")))]
pub fn list() -> io::Result<Vec<MountPoint>> {
  os::list(ListOptions::all())
}

/// Lists only ejectable/removable mounted volumes.
///
/// Shorthand for `list_with(ListOptions::ejectable_only())`.
#[cfg(feature = "list")]
#[cfg_attr(docsrs, doc(cfg(feature = "list")))]
pub fn list_ejectable() -> io::Result<Vec<MountPoint>> {
  os::list(ListOptions::ejectable_only())
}

/// Lists only non-ejectable/non-removable mounted volumes (internal drives, etc.).
///
/// Shorthand for `list_with(ListOptions::non_ejectable_only())`.
#[cfg(feature = "list")]
#[cfg_attr(docsrs, doc(cfg(feature = "list")))]
pub fn list_non_ejectable() -> io::Result<Vec<MountPoint>> {
  os::list(ListOptions::non_ejectable_only())
}

#[cfg(test)]
mod tests {
  use super::*;

  // ── resolve tests ──────────────────────────────────────────────

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
    let info = resolve(root_path()).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
    assert_eq!(info.relative_path(), Path::new(""));
    println!("Root disk info: {:?}", info);
  }

  #[test]
  fn test_root_fn() {
    let info = root().unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
    assert_eq!(info.relative_path(), Path::new(""));
    // root's canonical path should equal its mount point on platforms
    // where canonicalization does not change the root representation
    if cfg!(windows) {
      assert!(info.canonical_path().is_absolute());
    } else {
      assert_eq!(info.canonical_path(), info.mount_point());
    }
  }

  #[test]
  fn test_root_fn_matches_resolve() {
    let from_root = root().unwrap();
    let from_resolve = resolve(root_path()).unwrap();
    assert_eq!(from_root.mount_point(), from_resolve.mount_point());
    assert_eq!(from_root.device(), from_resolve.device());
    assert_eq!(from_root.is_ejectable(), from_resolve.is_ejectable());
    assert_eq!(from_root.canonical_path(), from_resolve.canonical_path());
  }

  #[test]
  fn test_existing_path() {
    let info = resolve(env!("CARGO_MANIFEST_DIR")).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
    assert!(!info.relative_path().as_os_str().is_empty());
    assert!(info.canonical_path().is_absolute());
    println!("Current directory disk info: {:?}", info);
  }

  #[test]
  fn test_is_ejectable() {
    // The root filesystem should not be ejectable.
    let info = resolve(root_path()).unwrap();
    assert!(!info.is_ejectable(), "root disk should not be ejectable");
  }

  #[test]
  fn test_nonexistent_path() {
    let result = resolve(nonexistent_path());
    assert!(result.is_err());
  }

  #[test]
  fn test_file_path() {
    // Test with a real file, not just a directory.
    let info = resolve(file!()).unwrap();
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

    let info_target = resolve(&target).unwrap();
    let info_link = resolve(&link).unwrap();

    // Both should resolve to the same mount point and device.
    assert_eq!(info_target.mount_point(), info_link.mount_point());
    assert_eq!(info_target.device(), info_link.device());
    // canonical_path should resolve the symlink to the target
    assert_eq!(info_target.canonical_path(), info_link.canonical_path());
  }

  #[test]
  fn test_repeated_lookups_hit_cache() {
    // Call twice for the same device — second call should hit the cache.
    let info1 = resolve(root_path()).unwrap();
    let info2 = resolve(root_path()).unwrap();
    assert_eq!(info1.mount_point(), info2.mount_point());
    assert_eq!(info1.device(), info2.device());
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_list() {
    let mounts = list().unwrap();
    assert!(!mounts.is_empty(), "should have at least one mount");

    for m in &mounts {
      assert!(
        m.mount_point().is_absolute(),
        "mount point should be absolute: {:?}",
        m
      );
      assert!(
        !m.device().is_empty(),
        "device should not be empty: {:?}",
        m
      );
    }
    println!("Found {} mounts", mounts.len());
    for m in &mounts {
      println!("  {:?}", m);
    }
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_list_ejectable() {
    let mounts = list_ejectable().unwrap();
    for m in &mounts {
      assert!(
        m.is_ejectable(),
        "should only contain ejectable mounts: {:?}",
        m
      );
    }
    println!("Found {} ejectable mounts", mounts.len());
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_list_non_ejectable() {
    let mounts = list_non_ejectable().unwrap();
    for m in &mounts {
      assert!(
        !m.is_ejectable(),
        "should only contain non-ejectable mounts: {:?}",
        m
      );
    }
    println!("Found {} non-ejectable mounts", mounts.len());
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_list_with() {
    let all = list_with(ListOptions::all()).unwrap();
    let ejectable = list_with(ListOptions::ejectable_only()).unwrap();
    let non_ejectable = list_with(ListOptions::non_ejectable_only()).unwrap();
    assert!(ejectable.len() <= all.len());
    assert!(non_ejectable.len() <= all.len());
    assert_eq!(ejectable.len() + non_ejectable.len(), all.len());
    for m in &ejectable {
      assert!(m.is_ejectable());
    }
    for m in &non_ejectable {
      assert!(!m.is_ejectable());
    }
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_list_options_default() {
    let opts = ListOptions::default();
    assert!(!opts.is_ejectable_only());
    assert!(!opts.is_non_ejectable_only());
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_list_options_builder() {
    let opts = ListOptions::all().set_ejectable_only(true);
    assert!(opts.is_ejectable_only());
    let opts2 = opts.set_ejectable_only(false);
    assert!(!opts2.is_ejectable_only());

    let opts3 = ListOptions::all().set_non_ejectable_only(true);
    assert!(opts3.is_non_ejectable_only());
    let opts4 = opts3.set_non_ejectable_only(false);
    assert!(!opts4.is_non_ejectable_only());

    // Setting ejectable_only should clear non_ejectable_only
    let opts5 = ListOptions::non_ejectable_only().set_ejectable_only(true);
    assert!(opts5.is_ejectable_only());
    assert!(!opts5.is_non_ejectable_only());

    // Setting non_ejectable_only should clear ejectable_only
    let opts6 = ListOptions::ejectable_only().set_non_ejectable_only(true);
    assert!(opts6.is_non_ejectable_only());
    assert!(!opts6.is_ejectable_only());
  }

  #[test]
  fn test_canonical_path() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test").unwrap();
    let info = resolve(&file).unwrap();

    let canonical = info.canonical_path();
    assert!(canonical.is_absolute());
    assert!(canonical.exists());
    assert!(canonical.ends_with("test.txt"));
  }

  #[test]
  fn test_canonical_path_resolves_dot_dot() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    // Resolve a path with ".." in it
    let dotdot = sub.join("../b");
    let info = resolve(&dotdot).unwrap();
    let canonical = info.canonical_path();
    // The canonical path should not contain ".."
    assert!(!canonical.to_string_lossy().contains(".."));
    assert!(canonical.ends_with("a/b"));
  }

  #[test]
  fn test_mount_info() {
    let info = resolve(root_path()).unwrap();
    let mi = info.mount_info();
    assert_eq!(mi.mount_point(), info.mount_point());
    assert_eq!(mi.device(), info.device());
    assert_eq!(mi.is_ejectable(), info.is_ejectable());
    assert_eq!(mi.total_bytes(), info.total_bytes());
    assert_eq!(mi.available_bytes(), info.available_bytes());
    assert_eq!(mi.used_bytes(), info.used_bytes());
  }

  #[test]
  fn test_disk_usage() {
    let info = resolve(root_path()).unwrap();
    // Root filesystem should have non-zero capacity.
    assert!(info.total_bytes() > 0, "total_bytes should be > 0");
    assert!(
      info.available_bytes() <= info.total_bytes(),
      "available should not exceed total"
    );
    assert_eq!(
      info.used_bytes(),
      info.total_bytes() - info.available_bytes(),
      "used = total - available"
    );
    println!(
      "Root disk: total={}, available={}, used={}",
      info.total_bytes(),
      info.available_bytes(),
      info.used_bytes()
    );
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_list_disk_usage() {
    let mounts = list().unwrap();
    for m in &mounts {
      // Some backends return (0, 0) when statvfs fails for a mount,
      // so only check the invariant when capacity is known.
      if m.total_bytes() > 0 {
        assert!(
          m.available_bytes() <= m.total_bytes(),
          "available should not exceed total for {:?}",
          m.mount_point()
        );
      }
    }
  }

  #[test]
  fn test_deep_nested_path() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("a/b/c/d/e");
    std::fs::create_dir_all(&deep).unwrap();
    let info = resolve(&deep).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.relative_path().as_os_str().is_empty());
    // canonical_path should end with the deep directory components
    let canonical = info.canonical_path();
    assert!(canonical.is_absolute());
    assert!(canonical.ends_with("a/b/c/d/e"));
  }

  #[test]
  fn test_relative_path_is_relative() {
    let info = resolve(env!("CARGO_MANIFEST_DIR")).unwrap();
    // The relative path should not start with '/'.
    assert!(info.relative_path().is_relative());
  }

  #[test]
  fn test_temp_dir() {
    let dir = tempfile::tempdir().unwrap();
    let info = resolve(dir.path()).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(!info.device().is_empty());
  }

  // ── PathLocation size ──────────────────────────────────────────

  #[test]
  fn test_struct_size() {
    let size = core::mem::size_of::<PathLocation>();
    println!("PathLocation size: {size} bytes");
    assert!(
      size < 256,
      "PathLocation should be compact, got {size} bytes"
    );
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

  #[cfg(windows)]
  #[test]
  fn test_smallbytes_hash_consistency() {
    use std::{
      collections::hash_map::DefaultHasher,
      hash::{Hash, Hasher},
    };

    let a = SmallBytes::from_bytes(b"mount");
    let b = SmallBytes::from_bytes(b"mount");

    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    a.hash(&mut ha);
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
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
    let info = resolve(path).unwrap();
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
    let info = resolve(path).unwrap();
    assert_eq!(info.mount_point(), Path::new("/System/Volumes/Data"));
    assert_eq!(info.relative_path(), Path::new(""));
  }
}
