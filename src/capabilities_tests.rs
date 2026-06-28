use super::*;

fn root_path() -> &'static str {
  if cfg!(windows) { "C:\\" } else { "/" }
}

#[test]
fn test_capabilities_accessor_matches_shorthands() {
  let info = resolve(root_path()).unwrap();
  let caps = info.capabilities();
  assert_eq!(caps.case_sensitive(), info.case_sensitive());
  assert_eq!(caps.case_preserving(), info.case_preserving());
  assert_eq!(caps.fs_type(), info.fs_type());
}

#[test]
fn test_mount_info_capabilities_match_path_location() {
  let info = resolve(root_path()).unwrap();
  let mi = info.mount_info();
  assert_eq!(mi.capabilities(), info.capabilities());
  assert_eq!(mi.case_sensitive(), info.case_sensitive());
  assert_eq!(mi.case_preserving(), info.case_preserving());
  assert_eq!(mi.fs_type(), info.fs_type());
}

#[test]
fn test_case_preserving_implies_consistency() {
  // A case-sensitive filesystem is necessarily case-preserving; if a platform
  // reports both flags, that combination must hold.
  let info = resolve(root_path()).unwrap();
  if info.case_sensitive() == Some(true) {
    // Platforms that can answer at all report case-preserving here too.
    if let Some(preserving) = info.case_preserving() {
      assert!(
        preserving,
        "case-sensitive volumes are always case-preserving"
      );
    }
  }
}

#[test]
fn test_capabilities_debug_contains_fields() {
  let info = resolve(root_path()).unwrap();
  let dbg = format!("{:?}", info.capabilities());
  assert!(dbg.contains("case_sensitive"));
  assert!(dbg.contains("case_preserving"));
  assert!(dbg.contains("fs_type"));
}

#[test]
fn test_path_location_debug_contains_capabilities() {
  let info = resolve(root_path()).unwrap();
  let dbg = format!("{info:?}");
  assert!(dbg.contains("capabilities"));
}

#[test]
fn test_capabilities_clone_and_eq() {
  let info = resolve(root_path()).unwrap();
  let caps = info.capabilities().clone();
  assert_eq!(&caps, info.capabilities());
}

#[test]
fn test_capabilities_cached_lookup_is_stable() {
  // Repeated lookups for the same volume must report identical capabilities,
  // whether served fresh or from the thread-local cache.
  let a = resolve(root_path()).unwrap();
  let b = resolve(root_path()).unwrap();
  assert_eq!(a.case_sensitive(), b.case_sensitive());
  assert_eq!(a.case_preserving(), b.case_preserving());
  assert_eq!(a.fs_type(), b.fs_type());
}

#[test]
fn test_from_fs_type_helper() {
  let caps = VolumeCapabilities::from_fs_type(b"ext4");
  assert_eq!(caps.case_sensitive(), None);
  assert_eq!(caps.case_preserving(), None);
  assert_eq!(caps.fs_type(), "ext4");

  let empty = VolumeCapabilities::from_fs_type(b"");
  assert_eq!(empty.fs_type(), "");
  assert_eq!(empty.case_sensitive(), None);
}

// ── fs-type → case-flag mapping ────────────────────────────────────

/// The shared mapping must report `Some(...)` only where the filesystem type
/// proves it, and `None` for configurable or unrecognized types — never a
/// guessed default. It is ASCII-case-insensitive so mixed-case names match too.
#[cfg(any(
  target_os = "freebsd",
  target_os = "openbsd",
  target_os = "dragonfly",
  target_os = "netbsd",
  target_os = "linux",
  windows,
))]
#[test]
fn test_case_flags_for_fs_type_mapping() {
  use super::case_flags_for_fs_type;

  // Case-insensitive and case-preserving.
  for fs in [
    b"vfat".as_slice(),
    b"exfat",
    b"ntfs",
    b"ntfs3",
    b"fuseblk",
    b"refs",
    b"msdosfs",
    b"NTFS",
    b"exFAT",
    b"FAT32",
  ] {
    assert_eq!(
      case_flags_for_fs_type(fs),
      (Some(false), Some(true)),
      "{fs:?}"
    );
  }

  // Case-insensitive, preservation unknown (DOS 8.3 short-name driver).
  assert_eq!(case_flags_for_fs_type(b"msdos"), (Some(false), None));

  // Case-sensitive, hence case-preserving.
  for fs in [
    b"ext2".as_slice(),
    b"ext3",
    b"ext4",
    b"ext2fs",
    b"xfs",
    b"btrfs",
    b"ufs",
    b"ffs",
    b"f2fs",
  ] {
    assert_eq!(
      case_flags_for_fs_type(fs),
      (Some(true), Some(true)),
      "{fs:?}"
    );
  }

  // Configurable per-dataset, or unmapped, or empty → unknown.
  for fs in [b"zfs".as_slice(), b"overlay", b"weirdfs", b""] {
    assert_eq!(case_flags_for_fs_type(fs), (None, None), "{fs:?}");
  }
}

#[cfg(feature = "list")]
#[test]
fn test_list_reports_capabilities() {
  for m in list().unwrap() {
    // fs_type should be populated for real (non-virtual) volumes.
    assert!(
      !m.fs_type().is_empty(),
      "expected a filesystem type for {:?}",
      m.mount_point()
    );
    // If a volume is case-sensitive, it must also be case-preserving.
    if m.case_sensitive() == Some(true) {
      if let Some(preserving) = m.case_preserving() {
        assert!(preserving);
      }
    }
  }
}

// ── Apple platforms ────────────────────────────────────────────────

/// Default APFS/HFS+ volumes are case-insensitive but case-preserving; getattrlist
/// reports both flags as valid, so neither is `None` and the fs type is known.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
#[test]
fn test_apple_reports_known_capabilities() {
  let info = resolve(root_path()).unwrap();
  assert!(
    info.case_sensitive().is_some(),
    "Apple volumes report case sensitivity"
  );
  assert!(
    info.case_preserving().is_some(),
    "Apple volumes report case preservation"
  );
  assert!(!info.fs_type().is_empty(), "Apple reports the fs type");
}

// ── Linux ──────────────────────────────────────────────────────────

/// Linux derives the case flags from the mountinfo filesystem type: `Some(...)`
/// for types it can map, `None` for types it cannot (e.g. overlayfs in a
/// container). The reported flags must match the shared mapping for whatever
/// type the root volume actually has.
#[cfg(target_os = "linux")]
#[test]
fn test_linux_case_flags_follow_fs_type() {
  let info = resolve(root_path()).unwrap();
  assert!(!info.fs_type().is_empty(), "fs type comes from mountinfo");
  let (sensitive, preserving) = super::case_flags_for_fs_type(info.fs_type().as_bytes());
  assert_eq!(info.case_sensitive(), sensitive);
  assert_eq!(info.case_preserving(), preserving);
}

// ── BSD / NetBSD ───────────────────────────────────────────────────

/// BSD/NetBSD derive the case flags from the `statfs`/`statvfs` filesystem type:
/// FFS/UFS are case-sensitive, but a ZFS root reports `None` (case sensitivity
/// is a per-dataset property). The reported flags must match the shared mapping.
#[cfg(any(
  target_os = "freebsd",
  target_os = "openbsd",
  target_os = "dragonfly",
  target_os = "netbsd",
))]
#[test]
fn test_bsd_case_flags_follow_fs_type() {
  let info = resolve(root_path()).unwrap();
  assert!(!info.fs_type().is_empty());
  let (sensitive, preserving) = super::case_flags_for_fs_type(info.fs_type().as_bytes());
  assert_eq!(info.case_sensitive(), sensitive);
  assert_eq!(info.case_preserving(), preserving);
}

// ── Windows ────────────────────────────────────────────────────────

/// Windows derives `case_sensitive` from the filesystem-type default (NTFS/ReFS/
/// FAT/exFAT look up names case-insensitively → `Some(false)`) and takes
/// `case_preserving` from the accurate `FILE_CASE_PRESERVED_NAMES` flag. The
/// `FILE_CASE_SENSITIVE_SEARCH` flag (volume *supports* case-sensitive names) is
/// deliberately not used as the lookup mode.
#[cfg(windows)]
#[test]
fn test_windows_reports_capabilities() {
  let info = resolve(root_path()).unwrap();
  assert_eq!(
    info.case_preserving(),
    Some(true),
    "NTFS preserves name case"
  );
  assert!(
    !info.fs_type().is_empty(),
    "GetVolumeInformationW reports fs type"
  );
  // The root volume is normally NTFS, whose default lookups are case-insensitive.
  let (sensitive, _) = super::case_flags_for_fs_type(info.fs_type().as_bytes());
  assert_eq!(info.case_sensitive(), sensitive);
  if info.fs_type().eq_ignore_ascii_case("ntfs") {
    assert_eq!(
      info.case_sensitive(),
      Some(false),
      "NTFS default lookups are case-insensitive"
    );
  }
}
