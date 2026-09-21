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
  let mut vfs: libc::statvfs = unsafe { core::mem::zeroed() };
  if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } != 0 {
    return Err(io::Error::last_os_error());
  }

  let mount_point = SmallBytes::from_bytes(c_chars_as_bytes(&vfs.f_mntonname));
  let device = SmallBytes::from_bytes(c_chars_as_bytes(&vfs.f_mntfromname));
  let capabilities = volume_capabilities(c_chars_as_bytes(&vfs.f_fstypename));

  #[cfg(feature = "disk-usage")]
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
  let ejectability = ejectability_from_name(c_chars_as_bytes(&vfs.f_mntfromname));
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

/// Lists all real (non-virtual) mounted volumes via `getvfsstat` (the canonical
/// NetBSD enumeration syscall; `getmntinfo` wraps it). Virtual filesystems are
/// excluded by type, like the BSD path.
///
/// Census against the FreeBSD/OpenBSD/DragonFlyBSD `getmntinfo` non-reentrancy
/// hazard (see `bsd::list`'s doc comment and `bsd::GETMNTINFO_LOCK`): this
/// call goes straight to `getvfsstat(2)`, whose signature —
/// `buf: *mut statvfs, bufsize: size_t, flags: c_int` — takes a
/// caller-supplied buffer, unlike `getmntinfo(3)`'s `*mut *mut statfs`
/// out-parameter into a buffer the library owns. `buf` below is a `Vec` this
/// call allocates itself and no other call can reach, so there is no shared
/// static object for two threads to race on, and no lock is needed here.
///
/// Unverified on NetBSD: in testing both `getvfsstat` and `getmntinfo` return no
/// usable entries (empty `f_mntonname`) while per-path `statvfs` works — a
/// libc/ABI quirk that needs a real host to resolve. `test_list` is `ignore`d on
/// NetBSD; the canonical API is kept for real systems.
#[cfg(feature = "list")]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  // ST_WAIT (1) requests fresh statistics; a null buffer returns the count.
  const ST_WAIT: core::ffi::c_int = 1;
  let count = unsafe { libc::getvfsstat(core::ptr::null_mut(), 0, ST_WAIT) };
  if count < 0 {
    return Err(io::Error::last_os_error());
  }

  let mut buf: Vec<libc::statvfs> = Vec::with_capacity(count as usize);
  let bufsize =
    (count as usize).saturating_mul(core::mem::size_of::<libc::statvfs>()) as libc::size_t;
  let n = unsafe { libc::getvfsstat(buf.as_mut_ptr(), bufsize, ST_WAIT) };
  if n < 0 {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: getvfsstat wrote `n` (<= count = capacity) fully-initialized entries.
  unsafe { buf.set_len(n as usize) };

  let mut mounts = Vec::new();
  for entry in &buf {
    if entry.f_mntfromname[0] == 0 || entry.f_mntonname[0] == 0 {
      continue;
    }

    let fs_type = c_chars_as_bytes(&entry.f_fstypename);
    // Skip virtual/pseudo filesystems.
    if IGNORED_FS_TYPES.iter().any(|t| *t == fs_type) {
      continue;
    }
    let mp_bytes = c_chars_as_bytes(&entry.f_mntonname);
    // Skip EFI boot partition.
    if mp_bytes == b"/boot/efi" {
      continue;
    }

    let device_bytes = c_chars_as_bytes(&entry.f_mntfromname);
    // A device name can say yes and can never say no: see
    // [`ejectability_from_name`].
    let ejectability = ejectability_from_name(device_bytes);
    // Exact states: a volume of unknown ejectability is named by neither
    // only-filter, so it is excluded by either. See `ListOptions::excludes`.
    if opts.excludes(ejectability) {
      continue;
    }

    let mount_point = SmallBytes::from_bytes(mp_bytes);
    let device = SmallBytes::from_bytes(device_bytes);
    let capabilities = volume_capabilities(fs_type);
    let identity = volume_identity(mount_point.as_path());
    let name = volume_name(mount_point.as_path());
    #[cfg(feature = "disk-usage")]
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

/// Heuristic for removable media on NetBSD:
/// sd* = USB mass storage (SCSI disk), cd* = optical drives.
/// What a NetBSD device name can say about removal.
///
/// **A name never denies**, for the reason the other BSDs never do: `sd` is
/// NetBSD's SCSI disk driver and covers internal disks as well as USB mass
/// storage, and `ld` covers both RAID logical disks and SD/MMC cards, so
/// neither name is evidence either way. `cd` is, on this platform as on the
/// others, exclusively optical media — a disc that leaves the machine.
/// Everything else is [`Unknown`](super::Ejectability::Unknown).
fn ejectability_from_name(device: &[u8]) -> Ejectability {
  if names_optical_or_floppy(device) {
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

#[cfg_attr(not(tarpaulin), inline(always))]
fn c_chars_as_bytes(chars: &[core::ffi::c_char]) -> &[u8] {
  // SAFETY: c_char and u8 have the same size and alignment.
  let bytes: &[u8] =
    unsafe { &*(core::ptr::from_ref::<[core::ffi::c_char]>(chars) as *const [u8]) };
  let len = super::find_byte(0, bytes).unwrap_or(bytes.len());
  &bytes[..len]
}

#[cfg(test)]
mod tests {
  use super::*;

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
      assert_eq!(
        ejectability_from_name(device.as_bytes()),
        Ejectability::Ejectable,
        "{device}"
      );
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
      assert_eq!(
        ejectability_from_name(device.as_bytes()),
        Ejectability::Unknown,
        "{device}"
      );
    }
  }
}
