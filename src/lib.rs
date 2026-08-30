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

// Only the platforms that have to reproduce an Apple-derived volume UUID
// themselves need MD5; Apple platforms read the finished value from the kernel.
#[cfg(any(target_os = "linux", windows, test))]
mod md5;

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

/// Case-handling and filesystem-type capabilities of a volume.
///
/// Returned by [`MountPoint::capabilities`] and [`PathLocation::capabilities`].
///
/// The two case flags are [`Option<bool>`] because not every platform can
/// determine them: `None` means "unknown / could not query", which is distinct
/// from `Some(false)` ("known not to have this property"). The filesystem type
/// is an empty string when it could not be determined.
///
/// Case semantics, for a watcher that must compare path components:
/// - **case-sensitive** — `Foo` and `foo` name distinct entries (most Linux/BSD
///   filesystems, APFS volumes formatted case-sensitive).
/// - **case-preserving** — the filesystem stores the case a name was created
///   with but compares case-insensitively, so `Foo` and `foo` are the same
///   entry yet the on-disk name keeps its original casing (default APFS/HFS+,
///   NTFS, exFAT).
#[derive(Clone, PartialEq, Eq)]
pub struct VolumeCapabilities {
  pub(crate) case_sensitive: Option<bool>,
  pub(crate) case_preserving: Option<bool>,
  pub(crate) fs_type: SmallBytes,
}

/// Derives the case flags a filesystem type definitively determines, as
/// `(case_sensitive, case_preserving)`. Each component is `Some(...)` only when
/// the type proves it, and `None` otherwise — never a guessed default.
///
/// - The FAT family and NTFS/ReFS look up names case-**insensitively** →
///   `case_sensitive = Some(false)`. Windows (which always uses long names) and
///   the Linux long-name `vfat`/`exfat`/NTFS drivers preserve the created case;
///   the Linux/BSD `msdos` short-name (8.3) driver upper-cases names, so its
///   preservation is left `None` rather than over-asserted.
/// - The native Unix filesystems (`ext*`, `xfs`, `btrfs`, `ufs`, `ffs`, `f2fs`)
///   are case-**sensitive** by default, which necessarily implies
///   case-preserving → both `Some(true)`.
/// - Anything configurable per-volume/per-dataset (ZFS) or that we cannot map
///   yields `(None, None)`.
///
/// The match is ASCII-case-insensitive on the name so it works for both the
/// lowercase names Unix backends report (`ntfs`, `exfat`) and the mixed-case
/// names Windows reports (`NTFS`, `exFAT`).
#[cfg(any(
  target_os = "freebsd",
  target_os = "openbsd",
  target_os = "dragonfly",
  target_os = "netbsd",
  target_os = "linux",
  windows,
))]
pub(crate) fn case_flags_for_fs_type(fs_type: &[u8]) -> (Option<bool>, Option<bool>) {
  // Compare against lowercase needles so callers' mixed-case names still match.
  let mut lower = [0u8; INLINE_CAPACITY];
  let name: &[u8] = if fs_type.len() <= INLINE_CAPACITY {
    for (dst, &b) in lower.iter_mut().zip(fs_type) {
      *dst = b.to_ascii_lowercase();
    }
    &lower[..fs_type.len()]
  } else {
    // Real filesystem-type names are far shorter than this; an over-long name is
    // not one we map.
    return (None, None);
  };

  match name {
    // Case-insensitive and case-preserving. `fuseblk` is what Linux reports for
    // the ntfs-3g FUSE driver (and exfat-fuse) — both preserve case. The
    // `fat*` spellings are Windows-only (Linux/BSD use `vfat`/`msdos`); Windows
    // always uses long names and so preserves case.
    b"vfat" | b"exfat" | b"ntfs" | b"ntfs3" | b"fuseblk" | b"refs" | b"fat" | b"fat12"
    | b"fat16" | b"fat32" => (Some(false), Some(true)),
    // FreeBSD spells its FAT driver `msdosfs`; it uses long names and so
    // preserves case.
    b"msdosfs" => (Some(false), Some(true)),
    // Case-insensitive but NOT case-preserving: the Linux/BSD `msdos` short-name
    // (8.3) driver upper-cases names, so preservation stays unknown.
    b"msdos" => (Some(false), None),
    // Native Unix filesystems: case-sensitive, hence necessarily preserving.
    // `ext2fs` is OpenBSD's spelling; `hammer`/`hammer2` are DragonFly's.
    b"ext2" | b"ext3" | b"ext4" | b"ext2fs" | b"xfs" | b"btrfs" | b"ufs" | b"ffs" | b"f2fs"
    | b"hammer" | b"hammer2" => (Some(true), Some(true)),
    // Configurable (ZFS case sensitivity is a per-dataset property) or unmapped.
    _ => (None, None),
  }
}

impl VolumeCapabilities {
  /// Creates a value with both case flags unknown (`None`) and the given
  /// filesystem type (empty when it could not be determined). The Apple backend
  /// returns this when its per-volume `getattrlist` query is unavailable, before
  /// overwriting the flags it can prove.
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
    test,
  ))]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn from_fs_type(fs_type: &[u8]) -> Self {
    Self {
      case_sensitive: None,
      case_preserving: None,
      fs_type: SmallBytes::from_bytes(fs_type),
    }
  }

  /// Creates a value whose case flags are derived from the filesystem type via
  /// [`case_flags_for_fs_type`] — `Some(...)` only where the type proves it,
  /// `None` otherwise. Backends without a per-volume case query use this so they
  /// never assert an unproven default.
  #[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "linux",
    windows,
  ))]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn from_fs_type_defaults(fs_type: &[u8]) -> Self {
    let (case_sensitive, case_preserving) = case_flags_for_fs_type(fs_type);
    Self {
      case_sensitive,
      case_preserving,
      fs_type: SmallBytes::from_bytes(fs_type),
    }
  }

  /// Returns whether the volume is case-sensitive (`Foo` and `foo` are distinct
  /// entries), or `None` if the platform could not determine it.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn case_sensitive(&self) -> Option<bool> {
    self.case_sensitive
  }

  /// Returns whether the volume is case-preserving (an entry keeps the case it
  /// was created with, even when lookups are case-insensitive), or `None` if the
  /// platform could not determine it.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn case_preserving(&self) -> Option<bool> {
    self.case_preserving
  }

  /// Returns the filesystem type name (e.g. `apfs`, `ext4`, `NTFS`), or an empty
  /// string if it could not be determined.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn fs_type(&self) -> &str {
    // Filesystem type names reported by the OS are always ASCII; fall back to
    // an empty string rather than panicking if that ever fails to hold.
    core::str::from_utf8(self.fs_type.as_bytes()).unwrap_or("")
  }
}

impl core::fmt::Debug for VolumeCapabilities {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("VolumeCapabilities")
      .field("case_sensitive", &self.case_sensitive)
      .field("case_preserving", &self.case_preserving)
      .field("fs_type", &self.fs_type())
      .finish()
  }
}

/// A volume's durable identity, as the platform reports it.
///
/// Unlike a mount point or a device node — both of which are session-local and
/// change across remounts, reboots and machines — the value here is stored on
/// the volume itself, so it survives unmounting, re-plugging into another port,
/// and moving the disk to another computer.
///
/// The variants differ in strength, and a consumer that builds a registry key
/// from one should keep them apart (for example by prefixing the variant name)
/// rather than mixing their numeric spaces:
///
/// - [`FsUuid`] is a 128-bit filesystem UUID and is normally strong enough to
///   stand alone — with one caveat: on the FAT-class filesystems the platform
///   *derives* the UUID from a narrower serial (see below), so it is no
///   stronger than the value it was derived from, however wide it looks.
/// - [`Serial64`] is a 64-bit volume serial. Collisions are unlikely but it
///   carries no structure, so it is only as unique as the formatting tool made
///   it.
/// - [`Serial32`] is a 32-bit volume serial — the FAT class. It is weak: 32
///   bits is small, and some formatting tools derive it from the wall clock, so
///   two volumes formatted in the same second can collide. Consumers that need
///   a durable key should widen it with further invariants (volume size, label,
///   filesystem type).
///
/// [`volume_identity()`] returns [`None`] when the platform or the filesystem
/// genuinely reports no identity at all — a virtual filesystem, a network
/// mount, or a platform without a durable-identity query. `None` is an honest
/// "nothing to report", never a failure to look.
///
/// # The value comes with the assurance of the read
///
/// The identity is durable on the volume, but not every platform lets an
/// unprivileged caller read it *from* the volume: Apple and Windows ask the
/// mounted filesystem, while Linux recovers it from a name udev published about
/// the mount's source device, which can lag the media now behind that device.
/// So [`volume_identity()`] hands back an [`IdentityReading`] — this value and
/// the [`IdentityAssurance`] it was read at — rather than the value alone, and
/// a caller that must not act on a possibly-lagged name can require
/// [`Vouched`]. It is read afresh on every resolve, on every platform: no
/// backend keeps one.
///
/// [`IdentityReading`]: crate::IdentityReading
/// [`IdentityAssurance`]: crate::IdentityAssurance
/// [`Vouched`]: IdentityAssurance::Vouched
///
/// # The same volume answers the same on every platform
///
/// The form is fixed **per filesystem**, not per platform. Whatever a platform
/// can reach is reduced to the one value that filesystem's volumes are named
/// by, so a disk carried between macOS, Linux and Windows keeps a single key:
///
/// | Filesystem | Canonical identity | How each platform reaches it |
/// |---|---|---|
/// | APFS, ext2/3/4, XFS, f2fs | [`FsUuid`] — the UUID in the superblock | Apple: `getattrlist`. Linux: `/dev/disk/by-uuid` |
/// | btrfs | [`FsUuid`] — the filesystem's FSID, one value however many devices carry it | Linux: `/sys/fs/btrfs/<fsid>/devices/`, falling back to `/dev/disk/by-uuid` |
/// | HFS+ | [`FsUuid`] — a version-3 UUID derived from the volume's 64-bit Finder-info id | Apple derives it in the kernel; `blkid` derives the identical value and udev publishes it |
/// | exFAT, with no Volume GUID | [`FsUuid`] — a version-3 UUID derived from the 32-bit serial | Apple derives it in the kernel; Linux and Windows compute the same value from the serial they read |
/// | exFAT, carrying a Volume GUID | [`FsUuid`] — the GUID in the root directory (but see below) | Apple only |
/// | NTFS | [`Serial64`] — the full 64-bit boot-sector serial | Linux: `/dev/disk/by-uuid`. Windows: `FSCTL_GET_NTFS_VOLUME_DATA` |
/// | FAT12/16/32 | [`Serial32`] — the 32-bit boot-sector serial (but see below) | Linux: `/dev/disk/by-uuid`. Windows: `GetVolumeInformationW` |
///
/// Four cases cannot be made to agree. Each is a narrowing — a form poorer than
/// the volume's own identity, never a value invented in its place — and each is
/// recorded here rather than left as a difference a caller would have to
/// discover. In all four the failure is a *missed* match: two readings of one
/// volume can differ, and no two volumes are made to look alike.
///
/// ## FAT12/16/32 on Apple platforms
///
/// `msdosfs` never reports the serial. At mount time it derives a version-3
/// UUID from it and reports only that:
///
/// ```text
/// digest    = MD5( b3e20f39-f292-11d6-97a4-00306543ecac, as 16 raw bytes
///                ‖ the 4 serial bytes as they sit in the boot sector
///                ‖ the BPB total-sector count, as 4 little-endian bytes )
/// digest[6] = (digest[6] & 0x0f) | 0x30   // version 3
/// digest[8] = (digest[8] & 0x3f) | 0x80   // RFC 4122 variant
/// ```
///
/// (`msdosfs_generate_volume_uuid`; the sector count is the BPB's 16-bit
/// `bpbSectors`, or its 32-bit `bpbHugeSectors` when that field is zero.)
///
/// The sector count is the obstacle. Nothing unprivileged reports it off Apple:
/// `statfs` and `GetDiskFreeSpaceW` describe the *data area* in clusters, while
/// the BPB field also covers the reserved sectors, the FATs and the root
/// directory, so it cannot be recovered from them — and reading the boot sector
/// directly needs a raw volume handle, which needs elevation. Linux and Windows
/// therefore report the narrower [`Serial32`], which does not compare equal to
/// the UUID an Apple platform reports for the same stick. A consumer spanning
/// both should qualify the key with [`fs_type()`] and treat the two as separate
/// keyspaces. exFAT's derivation takes the serial alone, so it is unaffected by
/// the sector count — but see the Volume GUID below.
///
/// ## NTFS on Windows when the volume FSCTL is unavailable
///
/// `GetVolumeInformationW` reports only the low 32 bits of the 64-bit serial.
/// The full width comes from `FSCTL_GET_NTFS_VOLUME_DATA`, which needs a handle
/// on the volume device; where opening one fails, this crate falls back to
/// [`Serial32`] of the low half. That is a truncation of the [`Serial64`] Linux
/// reports for the same volume — the same bits, fewer of them — but the two do
/// not compare equal.
///
/// ## exFAT volumes carrying a native Volume GUID
///
/// The exFAT format permits an optional Volume GUID entry in the root
/// directory, and where one is present it, not the serial, is the volume's
/// identity: Apple reports that GUID through `getattrlist`, and `exfat.util -k`
/// documents the rule exactly — "if the root directory contains a Volume GUID
/// entry, that GUID is the value returned; otherwise, the 32-bit volume serial
/// number stored in the boot sector is converted to a UUID".
///
/// Nothing off Apple can read it. The entry lives in the root directory rather
/// than the boot sector, so reaching it means reading the volume's data through
/// a raw handle — which needs elevation — and neither `GetVolumeInformationW`
/// nor the `/dev/disk/by-uuid` name udev publishes carries it. Linux and Windows
/// therefore report the serial-derived UUID for such a volume, which is a
/// different value from the GUID Apple reports for it. A stamped volume read on
/// two platforms yields two identities; it is never mistaken for another volume.
///
/// Stamping is rare — no format tool writes one by default — but it is real:
/// `exfat.util -s` creates the entry, and one such volume is pinned as a test
/// fixture so this narrowing cannot quietly become untrue.
///
/// ## exFAT mounted through FUSE
///
/// The derivation belongs to the format, so applying it takes proof of the
/// format. Linux gives that proof for the in-kernel driver (`exfat`) and for a
/// FUSE mount that publishes its subtype (`fuse.exfat`), and this crate derives
/// the UUID for both. It gives no proof for `exfat-fuse` mounted as a
/// block-backed FUSE filesystem, which is reported as bare `fuseblk` — a name
/// shared with ntfs-3g and every other block-backed FUSE helper. There the
/// serial udev published is reported as [`Serial32`] rather than run through a
/// derivation that may not be the volume's. NTFS is unaffected either way: its
/// identity is the serial itself, whatever the mount publishes as its type.
///
/// ## Not verified: NTFS on an Apple platform
///
/// Apple ships a read-only NTFS driver, and its `ntfs.util` has a "Get UUID
/// Key" action — so an NTFS volume mounted there may well answer
/// `ATTR_VOL_UUID` with a UUID, which would be a fifth case of the same kind,
/// since Linux and Windows both name NTFS by its [`Serial64`]. No NTFS volume
/// was available to check it against on an Apple host, and an Apple platform is
/// not a place NTFS is usually read, so the row is left unclaimed rather than
/// guessed at in either direction.
///
/// # Zero is not an identity
///
/// A zero serial and the nil UUID are their formats' "nothing was ever
/// recorded" sentinels rather than values: every volume that was never given
/// one carries the same zeros, so accepting them would make all of them
/// collide. Every platform maps them to `None` here. Apple's kernel already
/// works this way — `msdosfs` derives no UUID at all from a zero serial.
///
/// [`FsUuid`]: VolumeIdentity::FsUuid
/// [`Serial32`]: VolumeIdentity::Serial32
/// [`Serial64`]: VolumeIdentity::Serial64
/// [`volume_identity()`]: MountPoint::volume_identity
/// [`fs_type()`]: VolumeCapabilities::fs_type
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum VolumeIdentity {
  /// A 128-bit filesystem UUID (APFS, ext2/3/4, XFS, btrfs, f2fs, …), or the
  /// version-3 UUID every platform derives for HFS+ and exFAT.
  ///
  /// The bytes are in the canonical order of the textual form: the first byte
  /// is the one rendered by the leading two hex digits of
  /// `8f19a253-d450-3090-abf6-e651943998d1`.
  FsUuid([u8; 16]),
  /// A 32-bit volume serial — the FAT12/16/32 class, where the on-disk format
  /// has no room for a UUID, and the fallback for an NTFS volume whose full
  /// serial could not be read. Rendered by most tools as two dash-separated
  /// 16-bit halves (`1a2b-3c4d`); the value here is the whole 32-bit number.
  Serial32(u32),
  /// A 64-bit volume serial, reported for volumes whose format carries a serial
  /// wider than 32 bits but no UUID — NTFS.
  Serial64(u64),
}

impl core::fmt::Debug for VolumeIdentity {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::FsUuid(uuid) => {
        f.write_str("FsUuid(")?;
        for (idx, byte) in uuid.iter().enumerate() {
          // Group as 8-4-4-4-12 hex digits, i.e. dashes after bytes 4/6/8/10.
          if matches!(idx, 4 | 6 | 8 | 10) {
            f.write_str("-")?;
          }
          write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
      }
      Self::Serial32(serial) => write!(f, "Serial32({serial:08x})"),
      Self::Serial64(serial) => write!(f, "Serial64({serial:016x})"),
    }
  }
}

/// How a [`VolumeIdentity`] was obtained, and so how far it can be trusted at
/// the instant it was read.
///
/// Every identity this crate reports is durable *on the volume*. What differs
/// per platform is whether an unprivileged caller can read it **from the
/// volume** or only from a **name the platform publishes about the device** —
/// and only the first of those cannot be stale. That is a fact about the
/// answer, so it travels with the answer instead of being left for a caller to
/// look up per platform.
///
/// A consumer that must not act on a name that might have lagged its volume
/// — one that erases, migrates or re-keys on what it reads — should require
/// [`Vouched`] and treat [`Published`] as "not now" rather than as "no". One
/// that is matching a volume it has seen before, and can tolerate a miss or a
/// late correction, can take either.
///
/// There is no promotion between the two. A [`Published`] name cannot be
/// checked for freshness without reading the volume's superblock, which needs a
/// raw device handle and so elevation; this crate takes none, and inventing a
/// check that did not read the volume would be the stale answer with a
/// stronger label on it.
///
/// [`Vouched`]: IdentityAssurance::Vouched
/// [`Published`]: IdentityAssurance::Published
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IdentityAssurance {
  /// Read from the mounted filesystem itself, on this call.
  ///
  /// The kernel was asked about the volume the path is on and answered for it:
  /// Apple's `getattrlist` with `ATTR_VOL_UUID`, and on Windows
  /// `GetVolumeInformationW` — plus `FSCTL_GET_NTFS_VOLUME_DATA` on NTFS —
  /// addressed to the volume's own `\\?\Volume{GUID}\` path. Nothing stands
  /// between the mount and the value, so media that replaced other media under
  /// the same mount point answers as itself.
  Vouched,
  /// Read from a name the platform publishes *about a device*, which can lag
  /// the filesystem now behind it.
  ///
  /// This is Linux. The kernel exposes no unprivileged per-path call for a
  /// filesystem UUID, so the value is recovered from what udev published for
  /// the mount's source device — `/dev/disk/by-uuid`, and
  /// `/sys/fs/btrfs/<fsid>/devices/` for btrfs.
  ///
  /// **The udev window is why this level exists.** udev re-points those
  /// symlinks from a uevent, so between new media appearing under a device node
  /// and udev running, the departed volume's name still resolves to that node,
  /// and a read landing inside that window names the volume that left. Nothing
  /// remembers the answer, so the window closes on the next call — but a
  /// consumer that already acted on the first answer is not un-acted by the
  /// second, which is precisely the decision this level exists to let a caller
  /// make for itself. Two unprivileged checks narrow the window without closing
  /// it: a published name of a width the mount's own filesystem cannot carry is
  /// refused, and where two names resolve to one device node, neither is
  /// reported.
  Published,
}

/// What one read of a volume's identity produced: the [identity] itself, and
/// the [assurance] of the read that produced it.
///
/// This is what [`volume_identity()`] returns, and the pairing is the point —
/// the value cannot be taken without the level it was read at being in hand.
/// The identity inside is the durable key: two readings of one volume on two
/// platforms carry the same [`VolumeIdentity`] and, usually, different
/// assurances, so it is [`identity()`] that goes into a registry and the
/// assurance that decides whether to write to it now.
///
/// [identity]: VolumeIdentity
/// [assurance]: IdentityAssurance
/// [`identity()`]: IdentityReading::identity
/// [`volume_identity()`]: MountPoint::volume_identity
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct IdentityReading {
  identity: VolumeIdentity,
  assurance: IdentityAssurance,
}

impl IdentityReading {
  /// Read from the mounted filesystem itself, on this call.
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
    windows,
    test
  ))]
  pub(crate) const fn vouched(identity: VolumeIdentity) -> Self {
    Self {
      identity,
      assurance: IdentityAssurance::Vouched,
    }
  }

  /// Read from a name the platform published about the mount's source device.
  #[cfg(any(target_os = "linux", test))]
  pub(crate) const fn published(identity: VolumeIdentity) -> Self {
    Self {
      identity,
      assurance: IdentityAssurance::Published,
    }
  }

  /// The identity the volume is named by — the durable key, whatever it was
  /// read from.
  #[inline]
  pub const fn identity(&self) -> VolumeIdentity {
    self.identity
  }

  /// How this identity was obtained.
  #[inline]
  pub const fn assurance(&self) -> IdentityAssurance {
    self.assurance
  }

  /// Whether the identity was read from the mounted filesystem itself on this
  /// call — shorthand for `assurance() == IdentityAssurance::Vouched`, so that
  /// requiring it is one call: `volume_identity().filter(IdentityReading::is_vouched)`.
  #[inline]
  pub const fn is_vouched(&self) -> bool {
    matches!(self.assurance, IdentityAssurance::Vouched)
  }
}

/// Decodes an even-length ASCII-hex string into `out`, which must be exactly
/// half as long. Returns `false` (leaving `out` partially written) if any byte
/// is not a hex digit.
#[cfg(any(target_os = "linux", test))]
fn hex_decode(src: &[u8], out: &mut [u8]) -> bool {
  debug_assert_eq!(src.len(), out.len() * 2);
  for (byte, pair) in out.iter_mut().zip(src.chunks_exact(2)) {
    match (hex_digit(pair[0]), hex_digit(pair[1])) {
      (Some(hi), Some(lo)) => *byte = (hi << 4) | lo,
      _ => return false,
    }
  }
  true
}

/// Parses an ASCII-hex string of at most 16 digits into a `u64`.
#[cfg(any(target_os = "linux", test))]
fn hex_u64(src: &[u8]) -> Option<u64> {
  debug_assert!(src.len() <= 16);
  let mut value: u64 = 0;
  for &byte in src {
    value = (value << 4) | u64::from(hex_digit(byte)?);
  }
  Some(value)
}

/// Maps one ASCII hex digit (either case) to its value.
#[cfg(any(target_os = "linux", test))]
const fn hex_digit(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

/// Wraps a 32-bit serial, rejecting the "no serial recorded" sentinel.
#[cfg(any(target_os = "linux", windows, test))]
const fn serial32(value: u32) -> Option<VolumeIdentity> {
  if value == 0 {
    None
  } else {
    Some(VolumeIdentity::Serial32(value))
  }
}

/// Wraps a 64-bit serial, rejecting the "no serial recorded" sentinel.
#[cfg(any(target_os = "linux", windows, test))]
const fn serial64(value: u64) -> Option<VolumeIdentity> {
  if value == 0 {
    None
  } else {
    Some(VolumeIdentity::Serial64(value))
  }
}

/// Wraps a filesystem UUID, rejecting the nil UUID.
#[cfg(any(
  target_os = "linux",
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
  windows,
  test
))]
pub(crate) const fn fs_uuid(uuid: [u8; 16]) -> Option<VolumeIdentity> {
  if u128::from_ne_bytes(uuid) == 0 {
    None
  } else {
    Some(VolumeIdentity::FsUuid(uuid))
  }
}

/// The namespace every Apple-derived volume UUID is hashed under —
/// `b3e20f39-f292-11d6-97a4-00306543ecac`. `msdosfs` calls it
/// `kFSUUIDNamespaceSHA1`, and `blkid` uses the same bytes to reproduce Apple's
/// HFS/HFS+ UUIDs.
#[cfg(any(target_os = "linux", windows, test))]
const APPLE_UUID_NAMESPACE: [u8; 16] = [
  0xb3, 0xe2, 0x0f, 0x39, 0xf2, 0x92, 0x11, 0xd6, 0x97, 0xa4, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac,
];

/// Derives the version-3 UUID an Apple platform reports for a volume whose
/// on-disk identity is `seed`, so that a platform holding the same `seed`
/// answers with the same UUID rather than with a value only it understands.
#[cfg(any(target_os = "linux", windows, test))]
fn apple_derived_uuid(seed: &[u8]) -> [u8; 16] {
  debug_assert!(seed.len() <= 8);

  let mut input = [0u8; 24];
  input[..16].copy_from_slice(&APPLE_UUID_NAMESPACE);
  input[16..16 + seed.len()].copy_from_slice(seed);

  let mut uuid = md5::digest(&input[..16 + seed.len()]);
  uuid[6] = (uuid[6] & 0x0f) | 0x30;
  uuid[8] = (uuid[8] & 0x3f) | 0x80;
  uuid
}

/// The filesystem-type names that *prove* a volume is exFAT.
///
/// The in-kernel drivers name it `exfat` (Linux since 5.7, and Apple's
/// `statfs`), and Windows spells it `exFAT`. A FUSE mount is named for its
/// helper instead, and only sometimes for the format it implements: libfuse
/// publishes a subtype, so `fuse.exfat` proves the format as surely as the
/// kernel driver does — but `exfat-fuse` mounted as a block-backed FUSE
/// filesystem is reported as bare `fuseblk`, which names the transport and not
/// the format, and proves nothing. See [`VolumeIdentity`]'s narrowings.
#[cfg(any(target_os = "linux", windows, test))]
const EXFAT_FS_TYPES: &[&[u8]] = &[b"exfat", b"fuse.exfat", b"fuse.exfat-fuse", b"exfat-fuse"];

/// Whether `fs_type` is one of `roster`, compared as the kernels spell these
/// names: ASCII, and not consistently in one case.
#[cfg(any(target_os = "linux", windows, test))]
fn names_one_of(fs_type: &[u8], roster: &[&[u8]]) -> bool {
  roster.iter().any(|name| fs_type.eq_ignore_ascii_case(name))
}

/// Whether `fs_type` names exFAT beyond doubt. A type that merely *might* be
/// exFAT is not one: deriving the exFAT UUID from something else's serial would
/// invent an identity no platform reports.
#[cfg(any(target_os = "linux", windows, test))]
pub(crate) fn is_exfat(fs_type: &[u8]) -> bool {
  names_one_of(fs_type, EXFAT_FS_TYPES)
}

/// Whether `fs_type` names btrfs — the one filesystem here that can span
/// several devices, and so the one whose identity cannot be recovered from a
/// single device's published name. There is no FUSE spelling to admit: btrfs is
/// an in-kernel driver and the kernel names it exactly this.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn is_btrfs(fs_type: &[u8]) -> bool {
  fs_type.eq_ignore_ascii_case(b"btrfs")
}

/// Reduces a volume whose only reachable value is a 32-bit serial to the
/// canonical identity for its filesystem.
///
/// An exFAT volume that carries no Volume GUID is named by the version-3 UUID
/// Apple derives from that serial, and the derivation takes nothing else, so
/// every platform that can read the serial produces the identical UUID —
/// computing it here is what keeps one exFAT stick to one identity across
/// macOS, Linux and Windows. A volume that *does* carry a Volume GUID is named
/// by that GUID instead, which no unprivileged call off Apple can read; the
/// derived value is then a documented narrowing rather than the volume's own
/// identity, and [`VolumeIdentity`] records it as one.
///
/// Everything else keeps the serial: FAT12/16/32 because Apple's derivation
/// also needs a sector count no other platform can reach, NTFS because this is
/// only the fallback for a volume whose full 64-bit serial could not be read,
/// and an unproven type — `fuseblk` — because the derivation belongs to a
/// format, not to a serial.
#[cfg(any(target_os = "linux", windows, test))]
pub(crate) fn identity_from_serial32(fs_type: &[u8], serial: u32) -> Option<VolumeIdentity> {
  if serial != 0 && is_exfat(fs_type) {
    return fs_uuid(apple_derived_uuid(&serial.to_le_bytes()));
  }
  serial32(serial)
}

/// Classifies what Windows can read about a volume into a [`VolumeIdentity`].
///
/// `ntfs_serial` is the full 64-bit serial from `FSCTL_GET_NTFS_VOLUME_DATA`
/// when that succeeded; `serial` is the 32-bit one `GetVolumeInformationW`
/// always reports, which for NTFS is the low half of the same number.
///
/// Both come from a call addressed to the volume's own GUID path and answered
/// by the filesystem mounted there, so the reading is [`Vouched`]. The narrowed
/// NTFS serial is vouched too: it is the volume's own number with fewer of its
/// bits, not a name that might belong to another volume.
///
/// [`Vouched`]: IdentityAssurance::Vouched
#[cfg(any(windows, test))]
pub(crate) fn windows_identity(
  fs_type: &[u8],
  serial: u32,
  ntfs_serial: Option<u64>,
) -> Option<IdentityReading> {
  ntfs_serial
    .and_then(serial64)
    .or_else(|| identity_from_serial32(fs_type, serial))
    .map(IdentityReading::vouched)
}

/// The filesystem types whose on-disk format records a 32-bit volume serial and
/// has no room for anything wider. `blkid` publishes it as `XXXX-XXXX`, so a
/// name of any other width on such a mount belongs to something else.
#[cfg(any(target_os = "linux", test))]
const FAT_CLASS_FS_TYPES: &[&[u8]] = &[b"vfat", b"msdos"];

/// The filesystem types that record a 64-bit volume serial, which `blkid`
/// publishes as sixteen bare hex digits. `fuseblk` is deliberately absent: it
/// names the transport and is shared with every other block-backed FUSE helper.
#[cfg(any(target_os = "linux", test))]
const NTFS_FS_TYPES: &[&[u8]] = &[b"ntfs", b"ntfs3", b"fuse.ntfs-3g"];

/// Whether the width udev published can be what a `fs_type` volume carries.
///
/// A `/dev/disk/by-uuid` name udev has not yet re-pointed still resolves to the
/// device node the media behind it left, and the scan cannot tell such a link
/// from a current one by looking at it. Where the mount's own filesystem type
/// *proves* what width the volume can carry, a name of a different width is
/// evidence the link belongs to something else — and the honest answer is then
/// no identity rather than another volume's.
///
/// The claim is made for exactly two families, because only their formats leave
/// no room for another width: the FAT family, exFAT included, records 32 bits,
/// and NTFS 64. Everything else makes no claim — a type this crate cannot pin
/// (`fuseblk`), and the UUID-carrying filesystems, which would need a roster
/// that the first filesystem left out of it would falsify. Nothing is rejected
/// on a guess.
#[cfg(any(target_os = "linux", test))]
fn width_fits_fs_type(fs_type: &[u8], published: VolumeIdentity) -> bool {
  if is_exfat(fs_type) || names_one_of(fs_type, FAT_CLASS_FS_TYPES) {
    return matches!(published, VolumeIdentity::Serial32(_));
  }
  if names_one_of(fs_type, NTFS_FS_TYPES) {
    return matches!(published, VolumeIdentity::Serial64(_));
  }
  true
}

/// Reduces what udev published for a Linux volume — classified from the width
/// of its `/dev/disk/by-uuid` name by [`parse_by_uuid_name`] — to the canonical
/// form for `fs_type`.
///
/// The name gives the width; only `fs_type` can say whether a 32-bit serial is
/// already the canonical identity or has to be reduced further (see
/// [`identity_from_serial32`]), and whether the width is one the volume could
/// carry at all (see [`width_fits_fs_type`]).
///
/// Whatever comes out is [`Published`], because what went in was a name udev
/// published about a device rather than an answer the mounted filesystem gave.
/// Reducing a published name to its canonical form does not make it a read of
/// the volume.
///
/// [`Published`]: IdentityAssurance::Published
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_identity(fs_type: &[u8], published: VolumeIdentity) -> Option<IdentityReading> {
  if !width_fits_fs_type(fs_type, published) {
    return None;
  }
  let identity = match published {
    VolumeIdentity::Serial32(serial) => identity_from_serial32(fs_type, serial)?,
    wider => wider,
  };
  Some(IdentityReading::published(identity))
}

/// Picks out of the whole `/dev/disk/by-uuid` directory the identity published
/// for one device node, and reduces it to the canonical form for `fs_type`.
///
/// This scan is what a Linux resolve pays, and it pays it every time: nothing
/// may remember the answer, because the only key a Unix mount cache has is
/// `st_dev` and that key vouches for nothing (see [`Witness`]). Two limits bound
/// what the scan can get wrong, and both are stated rather than left to be met:
///
/// - **A stale link is possible, and transient.** udev re-points these symlinks
///   from a uevent, so between new media appearing under a device node and udev
///   republishing, the old name still resolves to that node. A resolve inside
///   that window reports the identity of the volume that left. It is not
///   remembered anywhere, so the window cannot outlive the instant it happened
///   in: the next resolve reads the directory again and the answer corrects
///   itself as soon as udev has run. It is also not hidden: the reading says
///   [`Published`], which is the level's whole reason for existing, and a
///   caller that cannot act on a possibly-lagged name can refuse it.
/// - **Two names for one node are not an answer.** Republishing can leave both
///   the old name and the new one resolving to the same device node, and picking
///   whichever the directory happened to yield first would be a coin toss
///   presented as an identity. Where the names disagree, none is reported.
///
/// [`Published`]: IdentityAssurance::Published
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_identity_for_device<P>(
  entries: impl Iterator<Item = (P, VolumeIdentity)>,
  device: &Path,
  fs_type: &[u8],
) -> Option<IdentityReading>
where
  P: AsRef<Path>,
{
  let mut found: Option<VolumeIdentity> = None;
  for (target, published) in entries {
    if target.as_ref() != device {
      continue;
    }
    match found {
      None => found = Some(published),
      // The same identity under two spellings still names one volume.
      Some(seen) if seen == published => {}
      Some(_) => return None,
    }
  }
  linux_identity(fs_type, found?)
}

/// Classifies a `/dev/disk/by-uuid/` entry name into a [`VolumeIdentity`].
///
/// `blkid`/`udev` name these symlinks by what the filesystem actually stores,
/// so the shape of the name *is* the width of the identity:
///
/// - `8f19a253-d450-3090-abf6-e651943998d1` — a 128-bit UUID (ext*, XFS, btrfs,
///   f2fs, swap, LUKS …, and the UUID `blkid` derives for HFS/HFS+).
/// - `1a2b-3c4d` — the 32-bit FAT/exFAT volume serial.
/// - `1a2b3c4d5e6f7788` — a 64-bit serial (NTFS).
///
/// Anything else — an ISO9660 creation timestamp, a truncated name — is not an
/// identity we can classify, and yields [`None`] rather than a guess. So does a
/// name that is all zeros, which records the absence of a serial rather than
/// one whose value is zero.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_by_uuid_name(name: &[u8]) -> Option<VolumeIdentity> {
  match name.len() {
    // 8-4-4-4-12 hex digits.
    36 => {
      if [8, 13, 18, 23].iter().any(|&pos| name[pos] != b'-') {
        return None;
      }
      let mut uuid = [0u8; 16];
      // The five groups hold 4 + 2 + 2 + 2 + 6 = 16 bytes, in order.
      let (head, tail) = uuid.split_at_mut(4);
      let (group2, tail) = tail.split_at_mut(2);
      let (group3, tail) = tail.split_at_mut(2);
      let (group4, group5) = tail.split_at_mut(2);
      let groups = [
        (&name[0..8], head),
        (&name[9..13], group2),
        (&name[14..18], group3),
        (&name[19..23], group4),
        (&name[24..36], group5),
      ];
      for (src, out) in groups {
        if !hex_decode(src, out) {
          return None;
        }
      }
      fs_uuid(uuid)
    }
    // `XXXX-XXXX`: the FAT/exFAT serial, printed as two 16-bit halves.
    9 => {
      if name[4] != b'-' {
        return None;
      }
      // Four hex digits each, so both halves fit in 16 bits and the join is
      // exact.
      let high = hex_u64(&name[0..4])? as u32;
      let low = hex_u64(&name[5..9])? as u32;
      serial32((high << 16) | low)
    }
    // 16 bare hex digits.
    16 => serial64(hex_u64(name)?),
    _ => None,
  }
}

/// What a witness taken on this resolve says about a cache entry built with an
/// earlier one — and, through that, what a mount cache is allowed to serve.
///
/// The Unix backends cache per thread so that resolving many paths on one mount
/// costs one read of the mount table. What an entry is worth depends on what its
/// key can vouch for, and every key here names a **mount session**: `st_dev` is
/// a device number the kernel assigns and reuses, which neither survives a
/// remount nor distinguishes two volumes the kernel gives the same number (an
/// APFS container's volumes share one). Eject the stick behind a reused number
/// and put another in its place, and the key is unchanged while the volume
/// behind it is not.
///
/// Hence the two rules every backend here is held to:
///
/// > **No backend caches a volume's durable identity.** Every platform reads it
/// > on every resolve — Apple and Windows from the mounted filesystem, Linux
/// > from what udev published — because a key that names a place cannot say the
/// > volume there is still the one an entry describes, and a Windows volume GUID
/// > names *storage* whose filesystem serial an offline tool can rewrite under
/// > it.
/// >
/// > What a mount-session key may serve is the mount's own metadata, and only
/// > while a witness taken **on this resolve** still says the entry describes
/// > the mount now at that key. [`Unavailable`] is not a weaker [`Agrees`]: an
/// > entry nothing vouches for is a complete miss, field by field, and no part
/// > of it is reused.
///
/// The second rule is what keeps the first honest. On Linux the mount's
/// filesystem type is an *input* to the identity — it decides the canonical form
/// a published serial reduces to — so serving a remembered `fs_type` under a
/// reused `st_dev` would mint an identity for the new volume out of the departed
/// one's format. Re-reading the identity while reusing what was used to derive
/// it is not re-reading it.
///
/// A witness is a cheap value that names the *current* mount, taken every time
/// the cache is consulted. Linux takes it from `statx`'s unique mount id, which
/// the kernel mints per mount and never hands out again. A platform with none to
/// give — Apple, or a Linux kernel before 6.8 — vouches for nothing, and its
/// entries are worth nothing: the Apple backend keeps only what the recorded
/// `st_dev` conflation already governs, and the Linux one stores no entry at all
/// where the kernel had no id to give it. Windows keeps nothing: the one thing
/// its cache used to save is the same `GetVolumeInformationW` call the identity
/// is read from, so once that call is made on every resolve there is nothing
/// left for an entry to hold.
///
/// [`Agrees`]: Witness::Agrees
/// [`Unavailable`]: Witness::Unavailable
// Only Linux has a witness to take; the rule and its tests are shared, so both
// are always compiled.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Witness {
  /// Both witnesses exist and agree: the entry still describes its own mount.
  Agrees,
  /// Both exist and differ: the key has been reused, and the entry describes a
  /// mount that is gone.
  Disagrees,
  /// The platform has no witness to give, so nothing is vouched for.
  Unavailable,
}

#[allow(dead_code)]
impl Witness {
  /// Compares the witness an entry was built with against one taken now.
  pub(crate) const fn of(built_with: Option<u64>, now: Option<u64>) -> Self {
    match (built_with, now) {
      (Some(before), Some(now)) if before == now => Self::Agrees,
      (Some(_), Some(_)) => Self::Disagrees,
      _ => Self::Unavailable,
    }
  }

  /// Whether the entry may be served — whole, and only whole. Both other
  /// answers are complete misses; they differ in what they say about the world,
  /// not in what the cache may do with the entry.
  pub(crate) const fn holds(self) -> bool {
    matches!(self, Self::Agrees)
  }
}

/// Information about a mount point (device, path, capacity, capabilities, and
/// whether it's ejectable).
///
/// Returned as part of [`PathLocation`] and by [`list`] / [`list_with`].
#[derive(Clone)]
pub struct MountPoint {
  pub(crate) mount_point: SmallBytes,
  pub(crate) device: SmallBytes,
  pub(crate) is_ejectable: bool,
  pub(crate) capabilities: VolumeCapabilities,
  pub(crate) volume_identity: Option<IdentityReading>,
  #[cfg(feature = "disk-usage")]
  pub(crate) total_bytes: u64,
  #[cfg(feature = "disk-usage")]
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

  /// Returns the case-handling and filesystem-type [capabilities] of the volume.
  ///
  /// [capabilities]: VolumeCapabilities
  #[inline]
  pub const fn capabilities(&self) -> &VolumeCapabilities {
    &self.capabilities
  }

  /// Returns the volume's durable [identity] — the value stored on the volume
  /// itself, which survives remounting and moving the disk to another machine —
  /// together with the [assurance] of the read that produced it, or `None` if
  /// the platform or filesystem reports none.
  ///
  /// The identity is read afresh on every resolve, on every platform; nothing
  /// here is served from a cache.
  ///
  /// [identity]: VolumeIdentity
  /// [assurance]: IdentityAssurance
  #[inline]
  pub const fn volume_identity(&self) -> Option<IdentityReading> {
    self.volume_identity
  }

  /// Returns whether the volume is case-sensitive, or `None` if the platform
  /// could not determine it. Shorthand for `capabilities().case_sensitive()`.
  #[inline]
  pub const fn case_sensitive(&self) -> Option<bool> {
    self.capabilities.case_sensitive()
  }

  /// Returns whether the volume is case-preserving, or `None` if the platform
  /// could not determine it. Shorthand for `capabilities().case_preserving()`.
  #[inline]
  pub const fn case_preserving(&self) -> Option<bool> {
    self.capabilities.case_preserving()
  }

  /// Returns the filesystem type name (e.g. `apfs`, `ext4`, `NTFS`), or an empty
  /// string if it could not be determined. Shorthand for
  /// `capabilities().fs_type()`.
  #[inline]
  pub fn fs_type(&self) -> &str {
    self.capabilities.fs_type()
  }

  /// Returns the total capacity of the volume in bytes.
  #[cfg(feature = "disk-usage")]
  #[cfg_attr(docsrs, doc(cfg(feature = "disk-usage")))]
  #[inline]
  pub fn total_bytes(&self) -> u64 {
    self.total_bytes
  }

  /// Returns the number of bytes available to unprivileged users.
  ///
  /// This may be less than the total free space if the filesystem
  /// reserves blocks for the superuser.
  #[cfg(feature = "disk-usage")]
  #[cfg_attr(docsrs, doc(cfg(feature = "disk-usage")))]
  #[inline]
  pub fn available_bytes(&self) -> u64 {
    self.available_bytes
  }

  /// Returns the number of bytes unavailable to unprivileged users.
  ///
  /// Computed as `total_bytes() - available_bytes()`. On filesystems that
  /// reserve blocks for the superuser (e.g. ext4), those reserved blocks
  /// are included in this count even if they are not occupied by data.
  #[cfg(feature = "disk-usage")]
  #[cfg_attr(docsrs, doc(cfg(feature = "disk-usage")))]
  #[inline]
  pub fn used_bytes(&self) -> u64 {
    self.total_bytes.saturating_sub(self.available_bytes)
  }
}

impl core::fmt::Debug for MountPoint {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    let mut s = f.debug_struct("MountPoint");
    s.field("mount_point", &self.mount_point())
      .field("device", &self.device())
      .field("is_ejectable", &self.is_ejectable)
      .field("capabilities", &self.capabilities)
      .field("volume_identity", &self.volume_identity);
    #[cfg(feature = "disk-usage")]
    s.field("total_bytes", &self.total_bytes)
      .field("available_bytes", &self.available_bytes);
    s.finish()
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

  /// Returns the case-handling and filesystem-type [capabilities] of the volume.
  ///
  /// [capabilities]: VolumeCapabilities
  #[inline]
  pub fn capabilities(&self) -> &VolumeCapabilities {
    self.inner.mount_info().capabilities()
  }

  /// Returns the volume's durable [identity] and the [assurance] of the read
  /// that produced it, or `None` if the platform or filesystem reports none.
  /// Shorthand for `mount_info().volume_identity()`.
  ///
  /// [identity]: VolumeIdentity
  /// [assurance]: IdentityAssurance
  #[inline]
  pub fn volume_identity(&self) -> Option<IdentityReading> {
    self.inner.mount_info().volume_identity()
  }

  /// Returns whether the volume is case-sensitive, or `None` if the platform
  /// could not determine it. Shorthand for `capabilities().case_sensitive()`.
  #[inline]
  pub fn case_sensitive(&self) -> Option<bool> {
    self.inner.mount_info().case_sensitive()
  }

  /// Returns whether the volume is case-preserving, or `None` if the platform
  /// could not determine it. Shorthand for `capabilities().case_preserving()`.
  #[inline]
  pub fn case_preserving(&self) -> Option<bool> {
    self.inner.mount_info().case_preserving()
  }

  /// Returns the filesystem type name (e.g. `apfs`, `ext4`, `NTFS`), or an empty
  /// string if it could not be determined. Shorthand for
  /// `capabilities().fs_type()`.
  #[inline]
  pub fn fs_type(&self) -> &str {
    self.inner.mount_info().fs_type()
  }

  /// Returns the total capacity of the volume in bytes.
  #[cfg(feature = "disk-usage")]
  #[cfg_attr(docsrs, doc(cfg(feature = "disk-usage")))]
  #[inline]
  pub fn total_bytes(&self) -> u64 {
    self.inner.mount_info().total_bytes()
  }

  /// Returns the number of bytes available to unprivileged users.
  #[cfg(feature = "disk-usage")]
  #[cfg_attr(docsrs, doc(cfg(feature = "disk-usage")))]
  #[inline]
  pub fn available_bytes(&self) -> u64 {
    self.inner.mount_info().available_bytes()
  }

  /// Returns the number of bytes unavailable to unprivileged users.
  ///
  /// Computed as `total_bytes() - available_bytes()`. On filesystems that
  /// reserve blocks for the superuser (e.g. ext4), those reserved blocks
  /// are included in this count even if they are not occupied by data.
  #[cfg(feature = "disk-usage")]
  #[cfg_attr(docsrs, doc(cfg(feature = "disk-usage")))]
  #[inline]
  pub fn used_bytes(&self) -> u64 {
    self.inner.mount_info().used_bytes()
  }
}

impl core::fmt::Debug for PathLocation {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    let mut s = f.debug_struct("PathLocation");
    s.field("canonical_path", &self.canonical_path())
      .field("mount_point", &self.mount_point())
      .field("device", &self.device())
      .field("is_ejectable", &self.is_ejectable())
      .field("capabilities", self.capabilities())
      .field("volume_identity", &self.volume_identity());
    #[cfg(feature = "disk-usage")]
    s.field("total_bytes", &self.total_bytes())
      .field("available_bytes", &self.available_bytes());
    s.field("relative_path", &self.relative_path()).finish()
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
mod capabilities_tests;

#[cfg(test)]
mod identity_tests;

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
  #[cfg_attr(
    target_os = "netbsd",
    ignore = "NetBSD mount enumeration returns no entries in CI; needs a real host"
  )]
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
    #[cfg(feature = "disk-usage")]
    {
      assert_eq!(mi.total_bytes(), info.total_bytes());
      assert_eq!(mi.available_bytes(), info.available_bytes());
      assert_eq!(mi.used_bytes(), info.used_bytes());
    }
  }

  #[cfg(feature = "disk-usage")]
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

  #[cfg(all(feature = "list", feature = "disk-usage"))]
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
    // The bound leaves room for the inline `VolumeCapabilities` (its `fs_type`
    // reuses the 56-byte small-buffer-optimized `SmallBytes`) on top of the two
    // mount/device strings, plus the extra `PathBuf` the Windows backend carries.
    //
    // It rose by eight bytes when the identity began carrying its assurance:
    // `VolumeIdentity` is 24 bytes — a `[u8; 16]` beside a `u64`, so 8-aligned —
    // and one more byte of assurance rounds the pair to 32. That is the price of
    // a caller being unable to take the value without the level it was read at,
    // and it puts the largest layout (Windows, which carries the extra
    // `PathBuf`) at 320 exactly, so the bound now includes it.
    let size = core::mem::size_of::<PathLocation>();
    println!("PathLocation size: {size} bytes");
    assert!(
      size <= 320,
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
