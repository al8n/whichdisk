//! NetBSD: one `statvfs` is the whole resolve, and each listing row is one
//! entry of one census of the kernel's mount table, read with `getvfsstat(2)`
//! into a buffer this crate owns and taken only from an answer that left a
//! slot empty: see [`mount_table`]. This platform names no decline, so every
//! failed read here is the operation's error.
//!
//! **Every entry is decoded whole or the call fails.** The mount point, the
//! source and the filesystem type are fixed `char` arrays the kernel fills
//! with one NUL-terminated string each, and every mount has all three: see
//! [`Fields`]. An array with no terminator, or a mandatory field left empty,
//! is not an entry the kernel wrote, and it fails the resolve or the whole
//! listing with `InvalidData` — it is never passed over, which would leave a
//! census that reads as complete without it.

use std::{
  ffi::OsStr,
  io,
  os::unix::ffi::OsStrExt,
  path::{Path, PathBuf},
};

use super::{Ejectability, IdentityReading, NameReading, SmallBytes, VolumeCapabilities};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Inner {
  mount: super::MountPoint,
  canonical: PathBuf,
  relative_offset: usize,
}

impl Inner {
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn mount_info(&self) -> &super::MountPoint {
    &self.mount
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn canonical_path(&self) -> &Path {
    &self.canonical
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn relative_path(&self) -> &Path {
    let bytes = self.canonical.as_os_str().as_bytes();
    Path::new(OsStr::from_bytes(&bytes[self.relative_offset..]))
  }
}

/// NetBSD uses `libc::statvfs` (not `statfs`) which has `f_mntonname` and
/// `f_mntfromname`. We call `libc::statvfs` on the canonicalized path to get
/// mount info, similar to the BSD `statfs` approach.
///
/// **There is no mount cache here, and there must not be**, for the reason the
/// BSD backend's is gone: the key was `st_dev`, which names a mount session
/// rather than a volume and is handed to another mount once the first goes
/// away, so a hit had no witness standing behind it and could serve another
/// mount's mount point, device and capabilities — and the ejectability was then
/// asked of that mount point. See [`resolve`](super::os::resolve) on the BSD
/// side. The cost is one `statvfs` per resolve, which a `disk-usage` build made
/// on every call anyway.
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;

  let c_path = std::ffi::CString::new(canonical.as_os_str().as_bytes())
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
  // SAFETY: `libc::statvfs` is a C structure of integers and arrays of them,
  // for which all-zero bytes are a valid value.
  let mut vfs: libc::statvfs = unsafe { core::mem::zeroed() };
  // SAFETY: `c_path` is NUL-terminated and `vfs` a live structure this call
  // owns, both for the length of the call; the kernel writes one `statvfs`.
  if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } != 0 {
    return Err(io::Error::last_os_error());
  }

  let Fields {
    mount_point,
    source: device,
    fs_type,
  } = Fields::of(&vfs)?;
  let capabilities = volume_capabilities(fs_type.as_bytes());

  // The widths of these fields differ between NetBSD's ports.
  #[cfg(feature = "disk-usage")]
  #[allow(clippy::unnecessary_cast)]
  let (total_bytes, available_bytes) = {
    let frsize = if vfs.f_frsize != 0 {
      vfs.f_frsize as u64
    } else {
      vfs.f_bsize as u64
    };
    (
      (vfs.f_blocks as u64).saturating_mul(frsize),
      (vfs.f_bavail as u64).saturating_mul(frsize),
    )
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
    canonical_bytes.len()
  };

  // **One call, one row.** The ejectability used to make a `statvfs` of its own
  // just to read a device name this one already returned, which is two
  // observations of a path that a mount can move between; it reads
  // `f_mntfromname` straight off the call above now. The identity and the name
  // are `None` on this platform by design, so there is nothing else to combine
  // and no descriptor to pin: a single `statvfs` is a stronger guarantee than a
  // pinned one, and it costs nothing.
  let ejectability = ejectability_of_source(fs_type.as_bytes(), device.as_bytes());
  let identity = volume_identity(&canonical);
  let name = volume_name(&canonical);

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      ejectability,
      capabilities,
      volume_identity: identity,
      volume_name: name,
      #[cfg(feature = "disk-usage")]
      total_bytes,
      #[cfg(feature = "disk-usage")]
      available_bytes,
    },
    canonical,
    relative_offset,
  })
}

/// Virtual filesystem types to exclude on NetBSD.
#[cfg(feature = "list")]
const IGNORED_FS_TYPES: &[&[u8]] = &[
  b"autofs",
  b"devfs",
  b"linprocfs",
  b"procfs",
  b"fdescfs",
  b"tmpfs",
  b"linsysfs",
  b"kernfs",
  b"ptyfs",
];

/// Lists all real (non-virtual) mounted volumes: every entry of one census of
/// the kernel's mount table but the virtual filesystems. See [`mount_table`].
///
/// **Every entry of the census is decoded before any is filtered**, so an
/// entry the kernel could not have written fails the listing whatever its
/// type: see [`Fields`].
#[cfg(feature = "list")]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  let entries = mount_table()?
    .into_iter()
    .map(|entry| Fields::of(&entry).map(|fields| (entry, fields)))
    .collect::<io::Result<Vec<_>>>()?;
  let mut mounts = Vec::new();
  for (entry, fields) in &entries {
    let fs_type = fields.fs_type.as_bytes();
    // Skip virtual/pseudo filesystems.
    if IGNORED_FS_TYPES.contains(&fs_type) {
      continue;
    }
    let mp_bytes = fields.mount_point.as_bytes();
    // Skip EFI boot partition.
    if mp_bytes == b"/boot/efi" {
      continue;
    }

    let device_bytes = fields.source.as_bytes();
    // A source bound to the mount can say yes and can never say no: see
    // [`ejectability_of_source`].
    let ejectability = ejectability_of_source(fs_type, device_bytes);
    // Exact states: a volume of unknown ejectability is named by neither
    // only-filter, so it is excluded by either. See `ListOptions::excludes`.
    if opts.excludes(ejectability) {
      continue;
    }

    let mount_point = fields.mount_point.clone();
    let device = fields.source.clone();
    let capabilities = volume_capabilities(fs_type);
    let identity = volume_identity(mount_point.as_path());
    let name = volume_name(mount_point.as_path());
    #[cfg(not(feature = "disk-usage"))]
    let _ = entry;
    // The widths of these fields differ between NetBSD's ports.
    #[cfg(feature = "disk-usage")]
    #[allow(clippy::unnecessary_cast)]
    let (total_bytes, available_bytes) = {
      let frsize = if entry.f_frsize != 0 {
        entry.f_frsize as u64
      } else {
        entry.f_bsize as u64
      };
      (
        (entry.f_blocks as u64).saturating_mul(frsize),
        (entry.f_bavail as u64).saturating_mul(frsize),
      )
    };
    mounts.push(super::MountPoint {
      mount_point,
      device,
      ejectability,
      capabilities,
      volume_identity: identity,
      volume_name: name,
      #[cfg(feature = "disk-usage")]
      total_bytes,
      #[cfg(feature = "disk-usage")]
      available_bytes,
    });
  }
  Ok(mounts)
}

/// Every mount the kernel's mount table holds, read with `getvfsstat(2)` into
/// a buffer this crate owns: a census, complete or refused — see
/// [`Census::copied`](super::reading::Census::copied).
///
/// **A buffer sized to an earlier count is no proof.** `getvfsstat` fills as
/// many entries as the buffer holds and answers with that number when there
/// were more, so a mount added between counting the mounts and reading them
/// used to be cut off with nothing to say so. The census offers slots to spare
/// and is taken only from an answer that left one empty; an answer that fills
/// the buffer is asked again with more room.
///
/// **No count is asked first.** The `getvfsstat` the `libc` crate links is,
/// from NetBSD 10 on, the C library's compatibility wrapper for the entry
/// layout it declares (`__compat_getvfsstat`, `lib/libc/compat/sys`), and the
/// wrapper hands the kernel a buffer of its own even when it was given none —
/// so a count-only call reaches the kernel as a call with room for no entry,
/// which `do_sys_getvfsstat` answers 0, or fails where that buffer could not
/// be had. The census needs no count to be whole, so it starts from its own
/// room and grows it.
///
/// **`ST_NOWAIT`: the statistics the kernel keeps for each mount.** Asking
/// every filesystem to refresh them (`ST_WAIT`) is also asking the kernel to
/// leave out, silently, every mount whose refresh fails — `do_sys_getvfsstat`
/// skips such an entry and counts it nowhere — so a network filesystem whose
/// server is not answering would vanish from a census that reads as whole. A
/// row's capacity is therefore the one the kernel last recorded for its
/// mount. The census has no absence to report: every failure of it is the
/// listing's error.
#[cfg(feature = "list")]
fn mount_table() -> io::Result<super::reading::Census<libc::statvfs>> {
  // SAFETY: `libc::statvfs` is a C structure of integers and arrays of them,
  // for which all-zero bytes are a valid value.
  let empty: libc::statvfs = unsafe { core::mem::zeroed() };
  super::reading::Census::copied(empty, 0, getvfsstat, |_| false).required()
}

/// One `getvfsstat(2)` into `slots`: how many entries it wrote there, or the
/// error it failed with.
#[cfg(feature = "list")]
fn getvfsstat(slots: &mut [libc::statvfs]) -> io::Result<usize> {
  /// `ST_NOWAIT`: the statistics the kernel keeps, without a refresh.
  const ST_NOWAIT: core::ffi::c_int = 2;

  // SAFETY: the buffer is the start of `slots`, which is live and exactly
  // `size_of_val(slots)` bytes long for the call, and the kernel writes whole
  // entries of the layout `libc` declares, and no more bytes than it is told
  // there are.
  let written =
    unsafe { libc::getvfsstat(slots.as_mut_ptr(), core::mem::size_of_val(slots), ST_NOWAIT) };
  // The errno is read before anything else can overwrite it.
  usize::try_from(written).map_err(|_| io::Error::last_os_error())
}

/// What a NetBSD mount's source can say about removal: a yes where the
/// source is bound to the mount and names a class of drive that is only ever
/// removable media, and nothing otherwise.
///
/// **The source must be bound first.** puffs(3) makes `f_mntfromname` a
/// user-space server's own text, so a name is read only where the kernel's
/// own filesystem type proves the kernel opened the device it names: see
/// [`source_is_bound`](super::source_is_bound).
///
/// **A name never denies**, for the reason the other BSDs never do: `sd` is
/// NetBSD's SCSI disk driver and covers internal disks as well as USB mass
/// storage, and `ld` covers both RAID logical disks and SD/MMC cards, so
/// neither name is evidence either way. `cd` is, on this platform as on the
/// others, exclusively optical media — a disc that leaves the machine — and so
/// is `fd`. Everything else is [`Unknown`](super::Ejectability::Unknown).
fn ejectability_of_source(fs_type: &[u8], source: &[u8]) -> Ejectability {
  if names_optical_or_floppy(source) && super::source_is_bound(fs_type, source) {
    Ejectability::Ejectable
  } else {
    Ejectability::Unknown
  }
}

/// Whether a NetBSD device name is one of the classes that are exclusively
/// removable media. Spelled here as it is on the other BSDs, and held to a
/// driver letter and a unit number so that a volume name cannot answer for a
/// drive.
fn names_optical_or_floppy(device: &[u8]) -> bool {
  let Some(name) = device.strip_prefix(b"/dev/") else {
    return false;
  };
  // `cd0` and `cd0a` name the same drive, and NetBSD's own `mount(8)` uses the
  // second form: see [`names_unit_and_partition`](super::names_unit_and_partition).
  //
  // Nested rather than a let-chain, for the reason the BSD twin gives: a
  // let-chain is Rust 1.88 and this crate's `rust-version` is 1.85.
  for prefix in [&b"cd"[..], b"fd"] {
    if let Some(tail) = name.strip_prefix(prefix) {
      if super::names_unit_and_partition(tail) {
        return true;
      }
    }
  }
  false
}

/// NetBSD: derive case semantics from the filesystem type — `Some(...)` only for
/// types that determine it (FFS/UFS are case-sensitive, msdosfs is
/// case-insensitive) and `None` otherwise (ZFS case sensitivity is a per-dataset
/// property). There is no portable per-volume query. `fs_type` comes from
/// `statvfs` (`f_fstypename`).
fn volume_capabilities(fs_type: &[u8]) -> VolumeCapabilities {
  VolumeCapabilities::from_fs_type_defaults(fs_type)
}

/// NetBSD: no durable volume identity, because none is reachable honestly here.
///
/// `statvfs`'s `f_fsidx` is deliberately *not* used: like the other BSDs, NetBSD
/// hands it out at mount time (`vfs_getnewfsid()`) rather than reading it off
/// the volume, so it changes across reboots and differs between machines —
/// exactly the two things an identity must survive. There is no `libblkid`
/// equivalent and no per-volume UUID query in the `statvfs` interface, so the
/// honest answer is that this platform reports nothing.
fn volume_identity(_mount_point: &Path) -> Option<IdentityReading> {
  None
}

/// NetBSD: no label to publish either.
///
/// `statvfs` reports the mount point, the mount source and the filesystem type,
/// and nothing about a name written on the volume; a UFS label lives behind a
/// `dkctl`/`disklabel` road this crate does not take. The mount point's own last
/// component is what a caller sees instead — see
/// [`volume_name()`](super::MountPoint::volume_name).
fn volume_name(_mount_point: &Path) -> Option<NameReading> {
  None
}

/// The three strings every `statvfs` entry carries, each decoded strictly
/// out of its fixed array: the mount point, the source and the filesystem
/// type.
struct Fields {
  mount_point: SmallBytes,
  source: SmallBytes,
  fs_type: SmallBytes,
}

impl Fields {
  /// Every mandatory field of `vfs`, or `InvalidData`.
  ///
  /// Each is the bytes before its array's first NUL; an array the kernel
  /// wrote always holds one, so an array with none is not the kernel's
  /// writing. And every mount has all three — a mount point, which is an
  /// absolute path, a source and a type — so an entry missing one is not a
  /// mount the kernel is describing. Either way the entry is refused, and the
  /// call with it.
  fn of(vfs: &libc::statvfs) -> io::Result<Self> {
    let mount_point = c_string(&vfs.f_mntonname)?;
    let source = c_string(&vfs.f_mntfromname)?;
    let fs_type = c_string(&vfs.f_fstypename)?;
    if !mount_point.starts_with(b"/") || source.is_empty() || fs_type.is_empty() {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "a mount table entry without a mount point, a source or a filesystem type",
      ));
    }
    Ok(Self {
      mount_point: SmallBytes::from_bytes(mount_point),
      source: SmallBytes::from_bytes(source),
      fs_type: SmallBytes::from_bytes(fs_type),
    })
  }
}

/// The string the kernel wrote into a fixed `char` array: its bytes before
/// the terminating NUL, or `InvalidData` for an array that holds none.
fn c_string(chars: &[core::ffi::c_char]) -> io::Result<&[u8]> {
  // SAFETY: `c_char` and `u8` have the same size and alignment, every bit
  // pattern is valid for both, and the new slice borrows the same memory for
  // the same lifetime.
  let bytes: &[u8] =
    unsafe { &*(core::ptr::from_ref::<[core::ffi::c_char]>(chars) as *const [u8]) };
  match super::find_byte(0, bytes) {
    Some(len) => Ok(&bytes[..len]),
    None => Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "a mount table string with no terminator inside its array",
    )),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A `statvfs` entry spelling `mount_point`, `source` and `fs_type`, each
  /// followed by the NUL the kernel writes — or, for a string as long as its
  /// array, by none.
  fn entry(mount_point: &[u8], source: &[u8], fs_type: &[u8]) -> libc::statvfs {
    // SAFETY: `libc::statvfs` is a C structure of integers and arrays of them,
    // for which all-zero bytes are a valid value.
    let mut vfs: libc::statvfs = unsafe { core::mem::zeroed() };
    for (array, text) in [
      (&mut vfs.f_mntonname[..], mount_point),
      (&mut vfs.f_mntfromname[..], source),
      (&mut vfs.f_fstypename[..], fs_type),
    ] {
      for (slot, &byte) in array.iter_mut().zip(text) {
        *slot = byte as core::ffi::c_char;
      }
    }
    vfs
  }

  /// An entry is decoded whole or refused: a string with no terminator inside
  /// its array, and an entry without a mount point, a source or a type, fail
  /// with `InvalidData` rather than being passed over or read as far as the
  /// array goes.
  #[test]
  fn test_an_entry_is_whole_or_refused() {
    let fields = Fields::of(&entry(b"/mnt/usb", b"/dev/sd0e", b"msdos")).unwrap();
    assert_eq!(fields.mount_point.as_bytes(), b"/mnt/usb");
    assert_eq!(fields.source.as_bytes(), b"/dev/sd0e");
    assert_eq!(fields.fs_type.as_bytes(), b"msdos");

    let unterminated = vec![b'a'; 32];
    for vfs in [
      entry(b"", b"/dev/sd0e", b"ffs"),
      entry(b"mnt", b"/dev/sd0e", b"ffs"),
      entry(b"/mnt", b"", b"ffs"),
      entry(b"/mnt", b"/dev/sd0e", b""),
      entry(b"/mnt", b"/dev/sd0e", &unterminated),
    ] {
      assert_eq!(
        Fields::of(&vfs).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidData)
      );
    }
  }

  #[test]
  fn test_volume_identity_is_none() {
    // Documented gap: f_fsidx is a mount-session handle, not a volume identity.
    assert_eq!(volume_identity(Path::new("/")), None);
  }

  /// NetBSD's own `mount(8)` mounts a disc as `/dev/cd0a`, so the partition
  /// form has to be the one the matcher reads — it used to demand digits all
  /// the way to the end, and every disc this system actually mounts answered
  /// `Unknown`.
  #[test]
  fn test_a_disc_mounted_through_its_partition_still_names_a_drive() {
    for device in [
      "/dev/cd0",
      "/dev/cd0a",
      "/dev/cd1d",
      "/dev/fd0a",
      "/dev/fd0",
    ] {
      assert!(names_optical_or_floppy(device.as_bytes()), "{device}");
    }
  }

  /// And a name that is not a drive still says nothing — never a denial, which
  /// this platform has no way to make.
  #[test]
  fn test_a_name_that_is_not_a_drive_says_nothing() {
    for device in [
      "/dev/cdimages",
      "/dev/cd0extra",
      "/dev/cd",
      "/dev/sd0a",
      "/dev/ld0a",
      "cd0a",
    ] {
      assert!(!names_optical_or_floppy(device.as_bytes()), "{device}");
      assert_eq!(
        ejectability_of_source(b"cd9660", device.as_bytes()),
        Ejectability::Unknown,
        "{device}"
      );
    }
  }

  /// **A source text is not a binding**: puffs(3) lets a user-space server name
  /// `/dev/cd0a` as its source, and its type, which the kernel prefixes with
  /// `puffs|`, says so — so it says nothing about removal.
  #[test]
  fn test_a_source_binds_only_where_the_kernel_opened_it() {
    for fs_type in ["puffs|p2k|ffs", "puffs|perfuse|sshfs", "tmpfs", "nfs", ""] {
      assert_eq!(
        ejectability_of_source(fs_type.as_bytes(), b"/dev/cd0a"),
        Ejectability::Unknown,
        "{fs_type}"
      );
    }
    assert!(super::super::source_is_bound(b"ffs", b"/dev/null"));
    assert!(!super::super::source_is_bound(
      b"puffs|p2k|ffs",
      b"/dev/null"
    ));
  }
}
