use std::{
  ffi::OsStr,
  io,
  os::unix::ffi::OsStrExt,
  path::{Path, PathBuf},
};

#[cfg(feature = "list")]
use std::collections::HashMap;

use bytes::{BufMut, BytesMut};

use rustix::{
  fd::OwnedFd,
  fs::{Dir, Mode, OFlags, ResolveFlags},
};

use super::{
  Ejectability, IdentityAssurance, IdentityReading, NameReading, SmallBytes, VolumeCapabilities,
  VolumeIdentity,
};

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

/// `STATX_MNT_ID`, added in Linux 5.8: the same id `/proc/self/mountinfo`
/// prints in its first field. It is reused after a mount goes away, and while
/// the mount is there it names exactly one line of that file — which is what
/// picking the right line needs, and all it is used for.
///
/// Requesting a mask bit the running kernel does not know is not an error; it
/// simply comes back unset in `stx_mask`, which is how this asks for the id
/// without demanding the kernel that has it.
///
/// `STATX_MNT_ID_UNIQUE` (Linux 6.8) used to be read beside it, to witness a
/// cache entry. That cache is gone and so is the read: the unique id names the
/// mount *object* rather than its attachment, and a move-mount reattaches the
/// object without minting a new one — see [`resolve`].
const STATX_MNT_ID: u32 = 0x0000_1000;

/// One `statx` field of an already-opened object.
///
/// Asked of a descriptor rather than of a path, because a path is re-resolved
/// on every call and a descriptor is not: see [`PinnedMount`].
fn statx_field(pinned: impl rustix::fd::AsFd, want: u32) -> Option<u64> {
  let stx = rustix::fs::statx(
    pinned,
    "",
    rustix::fs::AtFlags::EMPTY_PATH,
    rustix::fs::StatxFlags::from_bits_retain(want),
  )
  .ok()?;
  (stx.stx_mask & want != 0).then_some(stx.stx_mnt_id)
}

/// Everything one resolve knows about the mount it is resolving, taken from a
/// single pinned object.
///
/// **Facts about one mount must be sampled together or they are facts about
/// two.** The device number, the mount id and the mount table were each
/// sampled from the path independently, and a path is re-resolved every time:
/// an overmount landing between two of those samples produced a device number
/// from one mount and a mount id from another, so one mount's source and
/// filesystem type were reported under the other's numbers.
///
/// An `O_PATH` descriptor is what stops that. It names the object the caller
/// asked about and keeps naming it: a mount landing on top afterwards does not
/// move it, so the device number and the mount id both come off this one
/// descriptor and both describe the same mount. Nothing here opens the file
/// itself — `O_PATH` is a name, not an access.
///
/// **The descriptor is held for the whole resolve**, not just for the two
/// numbers. Two things turn on that:
///
/// - A descriptor on an object keeps a reference to the mount it is on, so the
///   kernel cannot free that mount while this lives — and a mount id is
///   returned to the allocator only when its mount is freed. The id therefore
///   cannot come to name a *different* mount between the `statx` that read it
///   and the `/proc` read that uses it. A `PinnedMount` that dropped its
///   descriptor left exactly that window open.
/// - Everything else this resolve asks about the mount is asked of this
///   descriptor rather than of the path again. Filesystem statistics are the
///   case that mattered: a `statvfs` by pathname re-resolves it, so a mount
///   landing on top in between answers with another volume's capacity under
///   this volume's name.
struct PinnedMount {
  /// The `O_PATH` descriptor every fact below was read from, and the one this
  /// resolve keeps asking.
  ///
  /// Held for its own sake as much as for its reads: a descriptor keeps a
  /// reference to the mount it is on, and that reference is what stops the
  /// kernel from freeing the mount and handing its id to another one while the
  /// resolve is still using it. A build without `disk-usage` asks it nothing
  /// and must hold it exactly the same, so the lint that would call it dead is
  /// answered rather than obeyed.
  #[cfg_attr(not(feature = "disk-usage"), allow(dead_code))]
  pinned: OwnedFd,
  /// The device number of the mount the pinned object is on.
  dev: u64,
  /// The id `/proc/self/mountinfo` spells for it, where the kernel has one.
  id: Option<u64>,
}

impl PinnedMount {
  /// Pins `canonical` and reads every fact about its mount off that one
  /// descriptor.
  fn of(canonical: &Path) -> io::Result<Self> {
    let pinned = rustix::fs::open(canonical, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
      .map_err(io::Error::from)?;
    let st = rustix::fs::fstat(&pinned).map_err(io::Error::from)?;
    Ok(Self {
      dev: st.st_dev,
      id: statx_field(&pinned, STATX_MNT_ID),
      pinned,
    })
  }

  /// Pins a listing row's mount point, and reads only the device number.
  ///
  /// A listing follows no mount id and reads no cache, so the two `statx` calls
  /// [`of`](Self::of) makes would be two syscalls a row for values nothing
  /// there looks at. What a row does need is the pin itself and the number to
  /// hold it to: the mount point the table named may already be another mount
  /// by the time it is opened, and a capacity read through this descriptor must
  /// be that row's or nothing at all.
  #[cfg(all(feature = "list", feature = "disk-usage"))]
  fn of_mount_point(mount_point: &Path) -> io::Result<Self> {
    let pinned = rustix::fs::open(mount_point, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
      .map_err(io::Error::from)?;
    let st = rustix::fs::fstat(&pinned).map_err(io::Error::from)?;
    Ok(Self {
      dev: st.st_dev,
      id: None,
      pinned,
    })
  }

  /// The filesystem statistics of the pinned object's mount.
  ///
  /// Asked of the descriptor, which is the same object the rest of the row
  /// describes. `fstatfs` — which is what `fstatvfs` is built on — is permitted
  /// on an `O_PATH` descriptor, so nothing needs to be opened for access to
  /// read a capacity.
  #[cfg(feature = "disk-usage")]
  fn statvfs(&self) -> io::Result<rustix::fs::StatVfs> {
    rustix::fs::fstatvfs(&self.pinned).map_err(io::Error::from)
  }
}

/// Whether `mount_point` is `path` itself or one of the directories it lies
/// under, compared on component boundaries so that `/media/usb2` is not read
/// as lying under `/media/usb`.
fn contains_path(mount_point: &[u8], path: &[u8]) -> bool {
  if mount_point == b"/" {
    return true;
  }
  let Some(rest) = path.strip_prefix(mount_point) else {
    return false;
  };
  rest.is_empty() || rest.starts_with(b"/")
}

/// Resolves one path, reading every fact it reports from the kernel on this
/// call.
///
/// **Nothing kernel-derived is remembered between calls, on this backend or on
/// any other.** A thread-local entry used to hold the mount point, the mount
/// source and the filesystem type, keyed by `st_dev` and served while
/// `statx`'s unique mount id still agreed. That id was the best witness this
/// platform has, and it is not enough: **it names the mount object, not where
/// that object is attached.** `do_move_mount` reattaches an existing mount
/// without minting a new one (`fs/namespace.c`), so a mount cached at `/old`
/// and then moved to `/new` kept an entry the witness still vouched for — and
/// a later resolve under `/new` was answered `/old`, with the wrong mount
/// point, the wrong relative path and, once the name fallback began deriving a
/// label from the mount point, the wrong name. If `/old` had since been reused,
/// that answer named an unrelated volume.
///
/// The entry is gone rather than re-witnessed. No value this crate can read
/// cheaply changes on every reattachment, and a cache whose witness cannot see
/// every topology change is the defect itself, not a cache with a gap. The cost
/// is one read of `/proc/<pid>/mountinfo` per resolve, through the authenticated
/// root it already opens — which is what every resolve that missed the cache
/// already paid, and what the listing road pays once for a whole enumeration.
#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;
  // One pinned observation of the mount, so that the device number and the
  // mount id cannot come from two different mounts: see [`PinnedMount`].
  let mount = PinnedMount::of(&canonical)?;
  // One authenticated root of each kind for the whole resolve: every kernel
  // table this call reads is read through one of them.
  let proc_root = proc_root();
  let dev_root = KernelDir::open("/dev", None);
  let sysfs_root = KernelDir::open("/sys", Some(SYSFS_MAGIC));

  let (mount_point, device, fs_type) = {
    let proc_root = proc_root.as_ref().ok_or_else(|| {
      io::Error::new(
        io::ErrorKind::NotFound,
        "procfs could not be opened and authenticated",
      )
    })?;
    lookup_mountinfo(proc_root, &canonical, &mount)?
  };

  // Read on every resolve, and deliberately never stored, exactly as the Apple
  // backend reads its own. `st_dev` names a mount session rather than a volume,
  // so no key here can vouch that a remembered identity still belongs to the
  // media behind it — and the two facts this derives it from, the mount source
  // and its filesystem type, are the same ones the witness above just vouched
  // for. The scan it costs is bounded: a mount source outside `/dev` skips it
  // outright, which is the hot "no identity" case.
  // One resolution of the mount source for every road that asks about it — the
  // identity, the label, and whether udev called it removable — and one level,
  // since all three are read through that same source.
  let source_device = dev_root
    .as_ref()
    .zip(device_relative(device.as_path()))
    .and_then(|(dev, relative)| dev.device_number(relative));

  // A kernel table that cannot be read from an authenticated root leaves every
  // read a claim.
  let source_assurance = proc_root
    .as_ref()
    .map(|proc_root| source_assurance(proc_root, fs_type.as_bytes()))
    .unwrap_or(IdentityAssurance::Declared);
  let volume_identity = dev_root
    .as_ref()
    .zip(source_device)
    .and_then(|(dev, source)| volume_identity(dev, source, fs_type.as_bytes(), source_assurance));

  let capabilities = volume_capabilities(fs_type.as_bytes());

  let canonical_bytes = canonical.as_os_str().as_bytes();
  let mp_bytes = mount_point.as_bytes();

  let relative_offset = if mp_bytes == b"/" {
    // Root mount: relative path is everything after the leading '/'
    1
  } else if canonical_bytes.starts_with(mp_bytes) {
    let off = mp_bytes.len();
    if off < canonical_bytes.len() && canonical_bytes[off] == b'/' {
      off + 1
    } else {
      off
    }
  } else {
    canonical_bytes.len() // empty relative path
  };

  // Asked of the kernel, per device, and kept no longer: see
  // [`device_ejectability`].
  let ejectability = device_ejectability(sysfs_root.as_ref(), source_device);
  // Read beside the identity, off the same udev directory tree, under the same
  // guard and at the level the same mount source earns: a source outside
  // `/dev` cannot be in that tree at all, and one its own mounter declared
  // makes the label as much of a claim as the identity. A label is not cached
  // with the mount's metadata above, because a person can rewrite a label while
  // the mount stays exactly as it is.
  let name = dev_root
    .as_ref()
    .zip(source_device)
    .and_then(|(dev, source)| volume_name(dev, source, fs_type.as_bytes(), source_assurance));

  // Asked of the pinned descriptor, not of the path again: a capacity is a
  // fact about the mount this row describes, and re-resolving the path for it
  // is how an overmount supplied another volume's numbers. See [`PinnedMount`].
  #[cfg(feature = "disk-usage")]
  let (total_bytes, available_bytes) = {
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    match mount.statvfs() {
      Ok(vfs) => {
        let frsize = if vfs.f_frsize != 0 {
          vfs.f_frsize as u64
        } else {
          vfs.f_bsize as u64
        };
        let total = (vfs.f_blocks as u64).saturating_mul(frsize);
        let avail = (vfs.f_bavail as u64).saturating_mul(frsize);
        (total, avail)
      }
      Err(_) => (0, 0),
    }
  };

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      ejectability,
      capabilities,
      volume_identity,
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

/// Virtual filesystem types to exclude from the disk list.
#[cfg(feature = "list")]
const IGNORED_FS_TYPES: &[&[u8]] = &[
  b"rootfs",
  b"sysfs",
  b"proc",
  b"devtmpfs",
  b"cgroup",
  b"cgroup2",
  b"pstore",
  b"squashfs",
  b"rpc_pipefs",
  b"iso9660",
  b"devpts",
  b"hugetlbfs",
  b"mqueue",
  b"tmpfs",
];

#[cfg(feature = "list")]
#[allow(clippy::unnecessary_cast)]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  // One authenticated `/dev` for the whole enumeration, as the kernel tables
  // below are read once for it.
  let dev_root = KernelDir::open("/dev", None);
  // One authenticated `/sys` for the whole enumeration, as the other roots
  // are opened once for it.
  let sysfs_root = KernelDir::open("/sys", Some(SYSFS_MAGIC));
  // One scan for the whole enumeration, rather than one per mount. Two names
  // resolving to one device node disagree about what is behind it, and the
  // enumeration answers that the same way a single resolve does — with no
  // identity, rather than with whichever the directory yielded last. See
  // [`linux_identity_for_device`](super::linux_identity_for_device).
  let mut by_uuid: HashMap<u64, Option<VolumeIdentity>> = HashMap::new();
  for (target, identity) in dev_root.as_ref().map(by_uuid_entries).unwrap_or_default() {
    by_uuid
      .entry(target)
      .and_modify(|seen| {
        if *seen != Some(identity) {
          *seen = None;
        }
      })
      .or_insert(Some(identity));
  }
  // The same one scan per enumeration for the labels, with the same answer
  // where two of them resolve to one device node: neither.
  let mut by_label: HashMap<u64, Option<SmallBytes>> = HashMap::new();
  for (target, label) in dev_root.as_ref().map(by_label_entries).unwrap_or_default() {
    let slot = by_label
      .entry(target)
      .or_insert_with(|| Some(label.clone()));
    if slot.as_ref() != Some(&label) {
      *slot = None;
    }
  }
  // One read of the kernel's own filesystem table for the whole enumeration,
  // as the two udev directories above are scanned once for it.
  let proc_root = proc_root().ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::NotFound,
      "procfs could not be opened and authenticated",
    )
  })?;
  let block_backed = block_backed_types(&proc_root);
  let mountinfo = mountinfo(&proc_root).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::NotFound,
      "mountinfo could not be read from the authenticated proc root",
    )
  })?;
  let mut mounts = Vec::new();
  let mut start = 0;

  while start < mountinfo.len() {
    let end = super::find_byte(b'\n', &mountinfo[start..])
      .map(|pos| start + pos)
      .unwrap_or(mountinfo.len());
    let line = &mountinfo[start..end];
    start = end + 1;

    if line.is_empty() {
      continue;
    }

    if let Some((_, row_major, row_minor, mp_raw, fs_type_raw, source_raw)) =
      parse_mountinfo_line(line)
    {
      // The device number the row itself names. Only the capacity road below
      // asks for it, and only that build has it to ask.
      #[cfg(not(feature = "disk-usage"))]
      let _ = (row_major, row_minor);
      // Skip virtual/pseudo filesystems.
      if IGNORED_FS_TYPES.contains(&fs_type_raw) {
        continue;
      }
      let mp = decode_octal_escapes(mp_raw);
      let mp_bytes = mp.as_bytes();
      // Skip /sys/*, /proc/*, /run/* (except /run/media/*).
      if mp_bytes.starts_with(b"/sys")
        || mp_bytes.starts_with(b"/proc")
        || (mp_bytes.starts_with(b"/run") && !mp_bytes.starts_with(b"/run/media"))
      {
        continue;
      }
      // Skip sunrpc device.
      if source_raw.starts_with(b"sunrpc") {
        continue;
      }

      let device = decode_octal_escapes(source_raw);
      // One resolution for every road below, taken the way a resolve takes it:
      // the decoded source — a source spelled with an escape names a different
      // path than its spelling does — reached beneath the `/dev` root, and
      // answered as the number the kernel names the device by.
      let resolved = dev_root
        .as_ref()
        .zip(device_relative(device.as_path()))
        .and_then(|(dev, relative)| dev.device_number(relative));
      let ejectability = device_ejectability(sysfs_root.as_ref(), resolved);
      // Exact states: a volume of unknown ejectability is named by neither
      // only-filter, so it is excluded by either. See `ListOptions::excludes`.
      if opts.excludes(ejectability) {
        continue;
      }
      let capabilities = volume_capabilities(fs_type_raw);
      let source_assurance = block_backed.assurance_of(fs_type_raw);
      let identity = resolved.and_then(|resolved| {
        let by_uuid_answer = || {
          by_uuid
            .get(&resolved)
            .copied()
            .flatten()
            .and_then(|published| super::linux_identity(fs_type_raw, published, source_assurance))
        };
        // Same order as a resolve: the kernel's own map first for btrfs, whose
        // members all carry one FSID and so cannot each have a by-uuid link.
        // A refusal is not a zero-match: see [`identity_after_btrfs`].
        if super::is_btrfs(fs_type_raw) {
          identity_after_btrfs(btrfs_identity(resolved, source_assurance), by_uuid_answer)
        } else {
          by_uuid_answer()
        }
      });
      // The same three roads a resolve takes, in the same order and for the
      // same reasons: btrfs from its own census, then the by-label directory,
      // then udev's runtime database for a label no directory of one name per
      // value can hold — that last one at `Declared`, never higher.
      let name = resolved.and_then(|resolved| {
        if super::is_btrfs(fs_type_raw) {
          return btrfs_sysfs()
            .and_then(|sysfs| btrfs_label(&sysfs, resolved))
            .map(|name| NameReading {
              name,
              assurance: source_assurance,
            });
        }
        if let Some(name) = by_label.get(&resolved).cloned().flatten() {
          return Some(NameReading {
            name,
            assurance: source_assurance,
          });
        }
        udev_database_label(resolved).map(|name| NameReading {
          name,
          assurance: IdentityAssurance::Declared,
        })
      });
      // A capacity is a fact about the mount this row describes, so it is read
      // from a descriptor pinned on that mount point — and only while that
      // descriptor is still on the mount the row named. A `statvfs` by pathname
      // re-resolves the mount point, so a mount arriving on top of it after the
      // table was read would answer with another volume's numbers under this
      // row's source, identity and name. See [`PinnedMount`]. A mount point
      // that cannot be pinned, or that has moved under the enumeration, reports
      // no capacity rather than someone else's.
      #[cfg(feature = "disk-usage")]
      let (total_bytes, available_bytes) = {
        #[allow(clippy::unnecessary_cast)]
        match PinnedMount::of_mount_point(mp.as_path()) {
          Ok(pinned) if pinned.dev == makedev(row_major, row_minor) => match pinned.statvfs() {
            Ok(vfs) => {
              let frsize = if vfs.f_frsize != 0 {
                vfs.f_frsize as u64
              } else {
                vfs.f_bsize as u64
              };
              (
                (vfs.f_blocks as u64).saturating_mul(frsize),
                (vfs.f_bavail as u64).saturating_mul(frsize),
              )
            }
            Err(_) => (0, 0),
          },
          _ => (0, 0),
        }
      };
      mounts.push(super::MountPoint {
        mount_point: mp,
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
  }
  Ok(mounts)
}

/// Linux: report the volume's case semantics from its filesystem type. The
/// per-directory ext4/f2fs **casefold** attribute (`chattr +F`) can make an
/// individual directory case-insensitive, but that is not a volume-level
/// property, so it is intentionally not reflected here; the result describes the
/// filesystem default and is `None` for types that do not determine it.
fn volume_capabilities(fs_type: &[u8]) -> VolumeCapabilities {
  VolumeCapabilities::from_fs_type_defaults(fs_type)
}

/// Linux: recover the volume's durable identity from `/dev/disk/by-uuid`.
///
/// The kernel does not expose a filesystem UUID through any unprivileged
/// per-path call, but udev already publishes what `blkid` read out of every
/// superblock, as a symlink named after the identity and pointing at the device
/// node. Reversing that link — resolving each symlink and matching it against
/// the mount source — recovers the identity without `libblkid`, without opening
/// the block device, and without root.
///
/// `None` when the device is not in the directory at all: a pseudo or network
/// filesystem whose source is not a block device, a filesystem `blkid` cannot
/// identify, or a system where udev is not running (a minimal container), which
/// is why this is a best-effort answer rather than an error.
///
/// `fs_type` decides the canonical form of a FAT-class serial, and can rule a
/// published name out as belonging to some other volume; both live in
/// [`linux_identity_for_device`](super::linux_identity_for_device), together
/// with the one window this leaves open and why it closes itself.
///
/// Whatever road the answer comes by it is
/// [`Published`](super::IdentityAssurance::Published): this platform has no
/// unprivileged call that asks the mounted filesystem for its own UUID, so
/// every value here is a name published about a device.
fn volume_identity(
  dev: &KernelDir,
  device: u64,
  fs_type: &[u8],
  assurance: IdentityAssurance,
) -> Option<IdentityReading> {
  // `device` is the number the kernel names the mount source by, resolved
  // beneath the `/dev` root by the caller — neither side of the comparison
  // below is ever a path.
  let by_uuid_answer =
    || super::linux_identity_for_device(by_uuid_entries(dev), device, fs_type, assurance);
  // Ask the kernel which filesystem the device belongs to before asking udev
  // what name it published for it: only the first can answer for a filesystem
  // whose members are several and whose mounted one is not the member udev's
  // single link happens to point at. See [`btrfs_fsid_for_device`]. A refusal
  // is not a zero-match: [`identity_after_btrfs`] consults `by_uuid_answer`
  // only where btrfs says the device is under no FSID of its at all.
  if super::is_btrfs(fs_type) {
    return identity_after_btrfs(btrfs_identity(device, assurance), by_uuid_answer);
  }
  by_uuid_answer()
}

/// Where the kernel publishes which filesystem each btrfs device belongs to.
const BTRFS_SYSFS_ROOT: &str = "fs/btrfs";

/// What a census of [`BTRFS_SYSFS_ROOT`] (or a fixture standing in for it, in
/// tests) found for one device number, for a mount `mountinfo` already named
/// as btrfs before this census was ever taken.
///
/// Two states, not three. Both callers — [`volume_identity`] and
/// [`list`](super::list) — reach this only after `mountinfo` has already
/// said the mount's filesystem type is btrfs, so "the device is not under
/// any btrfs filesystem" is not a fact this census can ever be reporting;
/// the caller already knows otherwise. What is left is only ever "sysfs
/// vouches for exactly one FSID" or "it does not," and the second of those
/// covers every shape the census can fail to settle in: zero claimants, more
/// than one, a temporary FSID, or a read that did not finish. Consulting
/// `/dev/disk/by-uuid` in place of [`Refused`](Self::Refused) would risk
/// reporting exactly the value this census just declined to vouch for — see
/// [`btrfs_fsid_for_device`] for why each shape of refusal happens, and
/// [`identity_after_btrfs`] for the one place both callers act on this.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BtrfsLookup {
  /// Exactly one filesystem claims the device, and nothing about the census
  /// or the FSID itself is in doubt.
  Matched(IdentityReading),
  /// Sysfs does not vouch for an FSID: no filesystem under the root claims
  /// the device, more than one does, the one that does carries a temporary
  /// FSID, or a read failed partway through. No identity is reported, and no
  /// other road is consulted in its place — never, not even where the
  /// census found nothing at all. A btrfs mount's identity is read from
  /// sysfs or not at all.
  Refused,
}

impl BtrfsLookup {
  /// The same answer, held to the level the mount source earned.
  ///
  /// The census answers one question — whether this device is a member of that
  /// filesystem — and it answers it out of sysfs, which is the kernel. What it
  /// does not answer is whether the device it was asked about is the device
  /// backing the mount: that came from the mount source, and a source its own
  /// mounter declared makes this answer a claim like any other read through it.
  /// So the level travels from the caller rather than from the census, exactly
  /// as it does on the udev road beside this one.
  fn at(self, assurance: IdentityAssurance) -> Self {
    match self {
      Self::Matched(reading) => Self::Matched(IdentityReading::at(reading.identity(), assurance)),
      Self::Refused => Self::Refused,
    }
  }
}

/// What one candidate filesystem directory's `temp_fsid` file said, read
/// directly rather than reduced to a `bool`.
///
/// A read failure is [`NotFound`](Self::NotFound) or
/// [`Unreadable`](Self::Unreadable), never one bit standing for both: a file
/// that plainly does not exist and a file this process was refused a look at
/// are different facts, even though [`btrfs_fsid_for_device`] now refuses on
/// both alike. Collapsing them the way a `bool` or an `Option` would still
/// throw away a distinction a caller diagnosing a refusal is entitled to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TempFsidMarker {
  /// Read cleanly as exactly `"0\n"`: this FSID is the volume's own.
  Permanent,
  /// Read cleanly as exactly `"1\n"`: this boot's mount chose the FSID fresh
  /// (see [`btrfs_fsid_for_device`]'s first narrowing).
  Temporary,
  /// The file was read, but its content is neither `"0\n"` nor `"1\n"`.
  Malformed,
  /// The file does not exist — [`io::ErrorKind::NotFound`] specifically.
  NotFound,
  /// The file could not be read for any other reason: permission, a masked
  /// `/sys`, or any other I/O failure.
  Unreadable,
}

/// btrfs: the FSID of the filesystem `device` is a member of, read from the
/// kernel's own map rather than from udev's links.
///
/// A btrfs filesystem is named by its FSID, and **every** member device carries
/// that same FSID — which is exactly why `/dev/disk/by-uuid` cannot answer for
/// a multi-device one. `blkid` reads one value off every member, so udev has
/// one name to publish and one link to publish it as, pointing at whichever
/// member it saw last. Mount the filesystem by any other member — `mount
/// /dev/sdc1 /mnt` is as valid as `/dev/sdb1`, and `mountinfo` records the one
/// that was used — and the reverse lookup finds no link for that source at all.
/// The filesystem then has no identity, though it is the same volume either
/// way.
///
/// The kernel publishes the mapping itself: `/sys/fs/btrfs/<fsid>/devices/`
/// holds one world-readable entry per member, each with a `dev` file naming the
/// block device's `major:minor`. Matching the mount source's own device number
/// against those names the filesystem whichever member carries the mount, needs
/// no privilege, and reads nothing off the volume.
fn btrfs_identity(device: u64, assurance: IdentityAssurance) -> BtrfsLookup {
  // A census that cannot be reached is a census failure like any other: see
  // [`btrfs_fsid_for_device`].
  let Some(sysfs) = btrfs_sysfs() else {
    return BtrfsLookup::Refused;
  };
  btrfs_fsid_for_device(&sysfs, device).at(assurance)
}

/// The authenticated `/sys` the btrfs census is read beneath.
///
/// `/sys` is held to `SYSFS_MAGIC` — unlike `/dev`, the kind is worth asking
/// here, since nothing but sysfs belongs at that path. The census addresses
/// everything by its path relative to **this** root rather than to
/// `fs/btrfs`, because a member entry under `devices/` is a symlink to the
/// block device's own directory elsewhere under `/sys`: from a root narrowed
/// to `fs/btrfs`, `RESOLVE_BENEATH` would refuse that climb and the census
/// would refuse every real filesystem.
fn btrfs_sysfs() -> Option<KernelDir> {
  KernelDir::open("/sys", Some(SYSFS_MAGIC))
}

/// Finds the btrfs filesystem under `sysfs_root` that counts the device
/// numbered `rdev` among its members, and answers with its FSID.
///
/// The reading is [`Published`](super::IdentityAssurance::Published) like every
/// other on this platform: sysfs is the kernel naming a device, not the
/// filesystem answering for itself.
///
/// # Zero claimants is refused, not evidence this isn't btrfs
///
/// Both callers of this function — [`volume_identity`] and
/// [`list`](super::list) — reach it only after `mountinfo` has already said
/// the mount's filesystem type is btrfs. So a census that names no claimant
/// for `rdev` at all is never read as "this device is not under btrfs" —
/// the caller already knows otherwise — and it is never treated as license
/// to fall back to `/dev/disk/by-uuid` either. A readable-but-empty sysfs
/// root, a bind mount that masks it, an FSID directory torn down between the
/// `mountinfo` snapshot and this read, and an outright unreadable root are
/// all indistinguishable from here, and every one of them is
/// [`Refused`](BtrfsLookup::Refused), the same as an outright ambiguous
/// match. Absence is never evidence; a btrfs mount's identity is read from
/// sysfs or not at all — see [`BtrfsLookup`] and [`identity_after_btrfs`],
/// the one place a refusal's ban on falling through is enforced.
///
/// # The census fails closed
///
/// Every read this performs — enumerating `sysfs_root` itself, a candidate's
/// `devices/` directory, and a member's `dev` file — can fail partway
/// through: a masked `/sys`, a container that hides part of the tree, a
/// directory removed mid-scan. A failure anywhere means this census cannot be
/// told apart from one that would have found a second claimant, or would have
/// found the very member holding `rdev`, had it been able to finish reading.
/// There is no safe default between those two, so none is guessed: any such
/// failure is [`Refused`](BtrfsLookup::Refused), the same answer as an
/// outright ambiguous match. This includes `sysfs_root` itself — a device
/// already known (from `mountinfo`) to be mounted as btrfs has the driver
/// loaded, and the driver registers this directory unconditionally at module
/// init, long before per-filesystem `temp_fsid` support existed, so an
/// unreadable root here is sysfs withholding the map, never "no btrfs on this
/// system."
///
/// # Two narrowings on top of a match, both refused rather than guessed
///
/// - **A temporary FSID is not an identity.** Linux 6.7+ mints one at mount
///   time for a single-device btrfs whose on-disk FSID collides with an
///   already-mounted filesystem's — a clone mounted beside its original, for
///   instance. The directory name is then chosen fresh by this boot's mount
///   rather than read off the volume, so it does not survive to the next
///   mount or the next machine, which is exactly what this face exists never
///   to report. Recovering the real, on-disk FSID would mean reading the
///   superblock, which needs elevation this crate does not take, so the mount
///   is left with no identity rather than a borrowed one.
/// - **A device claimed by more than one filesystem is ambiguous.** A btrfs
///   seed device is recognized read-only and can seed several sprouts at
///   once, so its device number is linked into every one of their `devices/`
///   directories at the same time — legitimately, not as a fault. Nothing
///   here can say which sprout the caller meant, so none is preferred over
///   the rest: this holds even where only one of the claimants carries a
///   temporary FSID, since the ambiguity is decided from device membership
///   alone, before any candidate's own marker is even consulted for it — the
///   walk does read every candidate's `temp_fsid` as it passes (see "Kernel
///   capability" below), but which one turns out permanent or temporary
///   never enters the ambiguity decision itself.
///
/// # A missing marker is refused, never guessed
///
/// Earlier rounds tried to tell a genuinely pre-6.7 kernel — one that never
/// installed the per-filesystem `temp_fsid` attribute at all — apart from a
/// current kernel whose sysfs view merely omits it, first from silence
/// alone, then from a kernel-wide feature file, then from a sibling
/// filesystem's own marker, and finally from the running kernel's own
/// `uname(2)` release compared against 6.7. Every one of those was an
/// inference from something *other* than the matched candidate's own marker,
/// and the last of them broke on the same shape the others had: the
/// `UNAME26` personality (`personality(2)`) makes a process's own `uname(2)`
/// report a 2.6.x release on an arbitrarily new kernel, and a vendor's
/// backport of `temp_fsid` into a distribution kernel numbered below 6.7
/// would decouple the release string from the capability just as
/// effectively in the other direction. No proxy for kernel capability reads
/// as trustworthy — only the file this census exists to read does.
///
/// So the matched candidate's own marker is now the only evidence
/// consulted, and it decides the answer alone: `Permanent` is `Matched`,
/// and everything else — `Temporary`, `Malformed`, `Unreadable`, and
/// critically `NotFound` — is `Refused`, regardless of a global marker, a
/// sibling's own reading, or any release guess. A pre-6.7 kernel (no
/// `temp_fsid` attribute to read at all) and a masked or namespaced sysfs
/// view on a current one are now indistinguishable from here, and both
/// report no btrfs identity — a missed match, never a false one.
///
/// `sysfs_root` is a parameter because what it names is what needs testing:
/// a multi-device btrfs filesystem is not something a unit test can conjure
/// — that takes root, loop devices, and `mkfs.btrfs`. A fixture tree
/// reproduces exactly what this reads, including both narrowings above and
/// the failure modes in [`BtrfsLookup::Refused`].
fn btrfs_fsid_for_device(sysfs: &KernelDir, rdev: u64) -> BtrfsLookup {
  match btrfs_census(sysfs, rdev) {
    // Membership says *which* filesystem the device belongs to; the marker
    // says whether that filesystem's FSID outlives this mount. An identity
    // needs both, so only a durable one is `Matched`.
    BtrfsCensus::Member {
      fsid,
      durable_fsid: true,
      ..
    } => BtrfsLookup::Matched(IdentityReading::published(fsid)),
    BtrfsCensus::Member { .. } | BtrfsCensus::Refused => BtrfsLookup::Refused,
  }
}

/// What the census found: an unambiguous membership, the directory that
/// filesystem occupies, and what its own marker says about its FSID.
///
/// **Membership and durability are two different facts, and only one of them is
/// about the label.** Whether exactly one filesystem claims this device, with
/// its whole `devices/` directory read, is what says *which* filesystem a value
/// published beside that FSID belongs to. Whether the FSID survives the mount
/// is what says whether the FSID is an *identity* — and a label is not an
/// identity. A filesystem mounted with a mount-time-only FSID, or one on a
/// kernel too old to have the attribute at all, still carries the label a
/// person wrote on it, and reporting no label for it was answering a question
/// about durability with an answer about naming.
///
/// The directory is kept because the identity is not the only thing the kernel
/// publishes beside an FSID. The filesystem's own label is there too, and it is
/// the only place a multi-device btrfs publishes one that every member can be
/// asked for. See [`btrfs_label`].
enum BtrfsCensus {
  /// One filesystem, and one only, holds the device, and its whole membership
  /// was read.
  Member {
    /// The FSID its sysfs directory is named by.
    fsid: VolumeIdentity,
    /// That directory, relative to `fs/btrfs`.
    dir: Vec<u8>,
    /// Whether the filesystem's own `temp_fsid` marker says the FSID above
    /// outlives this mount. Only the identity road turns on it; see
    /// [`TempFsidMarker`].
    durable_fsid: bool,
  },
  /// The census could not be completed, or the device has no single claimant.
  /// Nothing downstream is licensed by this — not an identity, and not a
  /// label.
  Refused,
}

/// The census itself. [`btrfs_fsid_for_device`] is its identity face, and the
/// laws below read it through that.
fn btrfs_census(sysfs: &KernelDir, rdev: u64) -> BtrfsCensus {
  let Some(entries) = sysfs.dir(Path::new(BTRFS_SYSFS_ROOT)) else {
    return BtrfsCensus::Refused;
  };

  // The one filesystem seen so far whose `devices/` holds `rdev`, kept
  // alongside its own sysfs directory rather than resolved to an answer
  // immediately: a second claimant found later must be able to void this one
  // unread, so its `temp_fsid` is never even opened for a device that turns
  // out ambiguous.
  let mut found: Option<(VolumeIdentity, Vec<u8>)> = None;

  for filesystem in entries {
    // A dirent whichdisk itself failed to read: the enumeration is only
    // partial, and what it would have shown is exactly what the rest of this
    // function exists to answer.
    let Ok(filesystem) = filesystem else {
      return BtrfsCensus::Refused;
    };
    // Only an FSID names a filesystem here. The directory also holds
    // `features`, and on newer kernels a flat `devices` list of every scanned
    // device, neither of which is a UUID.
    let name = filesystem.file_name().to_bytes().to_vec();
    let Some(fsid @ VolumeIdentity::FsUuid(_)) = super::parse_by_uuid_name(&name) else {
      continue;
    };
    let devices = KernelDir::at(&[BTRFS_SYSFS_ROOT.as_bytes(), &name, b"devices"]);
    let Some(members) = sysfs.dir(Path::new(OsStr::from_bytes(&devices))) else {
      // This candidate's own membership could not be read. It might have
      // been the (or another) claimant of `rdev`; a partial view of it is
      // exactly as untrustworthy as a partial view of the root.
      return BtrfsCensus::Refused;
    };
    let mut holds_rdev = false;
    for member in members {
      let Ok(member) = member else {
        return BtrfsCensus::Refused;
      };
      // A directory lists itself and its parent; neither is a member.
      let member = member.file_name().to_bytes().to_vec();
      if member == b"." || member == b".." {
        continue;
      }
      // The member is a link the kernel put there on purpose, so this one
      // read follows it — still beneath `/sys` and still across no mount.
      let dev = KernelDir::at(&[&devices, &member, b"dev"]);
      match sysfs_device_number(sysfs, Path::new(OsStr::from_bytes(&dev))) {
        Some(dev) if dev == rdev => holds_rdev = true,
        Some(_) => {}
        // Missing, unreadable, or malformed `dev` file for one member. That
        // file is exactly what would decide whether this member is `rdev`;
        // unable to read it, this member can be neither ruled in nor out.
        None => return BtrfsCensus::Refused,
      }
    }

    if !holds_rdev {
      continue;
    }
    if found.is_some() {
      // A second filesystem claims the same device — a shared seed device,
      // most likely. Neither claim is the answer, and neither candidate's
      // own marker is ever read to break the tie: the ambiguity is decided
      // from device membership alone.
      return BtrfsCensus::Refused;
    }
    found = Some((fsid, name));
  }

  let Some((fsid, name)) = found else {
    // A device `mountinfo` already named as btrfs, that this census names no
    // claimant for at all: never `NoMatch`. That answer would license
    // `by_uuid_answer`, which can hold exactly the value this refusal exists
    // to withhold — see the doc comment above, [`BtrfsLookup`], and
    // [`identity_after_btrfs`].
    return BtrfsCensus::Refused;
  };

  // Membership is settled: one claimant, whole directory read. The marker is
  // read now that ambiguity is already ruled out, and it decides one thing
  // only — whether this FSID is durable enough to be an identity. See the "A
  // missing marker is refused, never guessed" section above, which is about
  // the identity and about nothing else.
  let durable_fsid = match read_temp_fsid_marker(sysfs, &name) {
    // The census speaks for what sysfs said, which is a name the kernel
    // published about a device. What level the *caller* reports it at is the
    // mount source's to decide, and [`BtrfsLookup::at`] holds it there.
    TempFsidMarker::Permanent => true,
    // A mount-time-only FSID, chosen fresh by this boot's mount — never the
    // volume's own.
    TempFsidMarker::Temporary => false,
    // Read, but neither `"0\n"` nor `"1\n"` — not the well-formed marker an
    // identity requires.
    TempFsidMarker::Malformed => false,
    // The file exists but could not be read: never folded into "missing,"
    // and never permanent — see [`TempFsidMarker`].
    TempFsidMarker::Unreadable => false,
    // Missing outright. A pre-6.7 kernel that never installed the attribute
    // and a masked or namespaced view on a kernel that does are the same fact
    // from here, and neither is guessed past — no identity either way. The
    // filesystem is still the one this device belongs to, and still carries
    // whatever label its owner wrote on it.
    TempFsidMarker::NotFound => false,
  };

  BtrfsCensus::Member {
    fsid,
    dir: name,
    durable_fsid,
  }
}

/// The label the kernel publishes for the btrfs filesystem `device` belongs to.
///
/// `/dev/disk/by-label` holds one pathname per label, so a filesystem whose
/// label another volume also carries is missing from it, and so is every member
/// of a multi-device btrfs but the one udev happened to link. That is the same
/// one-link problem the identity road takes this census to escape, and the
/// kernel publishes the filesystem's own label beside its FSID — so the label
/// is read from the filesystem, exactly where the identity is, rather than from
/// a directory that can hold only one device per name.
///
/// A census that refuses refuses this too, and the by-label road is not
/// consulted in its place: a btrfs mount's identity is read from sysfs or not
/// at all, and its label is read the same way and for the same reason. See
/// [`identity_after_btrfs`].
///
/// **What it does *not* wait for is the `temp_fsid` marker.** That marker says
/// whether the FSID is durable, which is the identity's question; a label is
/// not an identity and does not become unreadable because the FSID is only
/// this mount's. Requiring a permanent marker here meant every btrfs volume on
/// a pre-6.7 kernel — which has no such attribute to read — and every
/// uniquely-claimed temporary-FSID mount silently lost its real label to the
/// mount-point substitute. Membership is what this needs, and membership is
/// what it asks for: one claimant, whole directory read.
fn btrfs_label(sysfs: &KernelDir, device: u64) -> Option<SmallBytes> {
  let BtrfsCensus::Member { dir, .. } = btrfs_census(sysfs, device) else {
    return None;
  };
  let path = KernelDir::at(&[BTRFS_SYSFS_ROOT.as_bytes(), &dir, b"label"]);
  let label = sysfs.read(Path::new(OsStr::from_bytes(&path))).ok()?;
  // `sysfs_emit` writes the label and a newline, so an unlabelled filesystem
  // writes the newline alone: no label rather than a label that is nothing.
  let label = label.strip_suffix(b"\n").unwrap_or(&label);
  (!label.is_empty()).then(|| SmallBytes::from_bytes(label))
}

/// Reads `<filesystem_dir>/temp_fsid` — the kernel's own marker for a
/// mount-time-only FSID — without collapsing a read failure to a `bool`:
/// "missing," "unreadable," and "malformed" are different facts about the
/// read even though [`btrfs_fsid_for_device`] refuses on all three alike.
///
/// `fs_devices->temp_fsid` is a `bool` (`fs/btrfs/volumes.h`), read out by
/// `btrfs_temp_fsid_show` and installed as `BTRFS_ATTR(, temp_fsid,
/// btrfs_temp_fsid_show)` in the same per-filesystem attribute array as
/// `label` and `metadata_uuid` (`fs/btrfs/sysfs.c`, present from v6.7 on,
/// absent in v6.6) — there is no `Documentation/ABI/testing/sysfs-fs-btrfs`
/// entry for it at all, unlike ext4, f2fs and xfs, so this is sourced from the
/// kernel itself rather than its ABI docs. `sysfs_emit(buf, "%d\n", ..)` on a
/// `bool` gives exactly `"0\n"` or `"1\n"`; anything else read from the file
/// is malformed rather than guessed at.
fn read_temp_fsid_marker(sysfs: &KernelDir, filesystem_dir: &[u8]) -> TempFsidMarker {
  let path = KernelDir::at(&[BTRFS_SYSFS_ROOT.as_bytes(), filesystem_dir, b"temp_fsid"]);
  match sysfs.read(Path::new(OsStr::from_bytes(&path))) {
    Ok(contents) if contents == b"0\n" => TempFsidMarker::Permanent,
    Ok(contents) if contents == b"1\n" => TempFsidMarker::Temporary,
    Ok(_) => TempFsidMarker::Malformed,
    Err(e) if e.kind() == io::ErrorKind::NotFound => TempFsidMarker::NotFound,
    Err(_) => TempFsidMarker::Unreadable,
  }
}

/// What [`volume_identity`] and [`list`](super::list) each fall back to when
/// btrfs did not answer: `/dev/disk/by-uuid`. Shared so both consult it under
/// the identical rule.
///
/// For a btrfs mount the outcome set is exactly
/// {[`Matched`](BtrfsLookup::Matched), [`Refused`](BtrfsLookup::Refused)} —
/// see [`BtrfsLookup`] — so `by_uuid_answer` is never invoked here: neither
/// arm below reaches for it. It stays a parameter anyway, for two reasons.
/// Every call site — the two production ones in [`volume_identity`] and
/// [`list`](super::list), and every test — keeps the one shape regardless of
/// whether a future narrowing changes what refuses, so a change that reopens
/// a branch here has to decide on purpose what to do with a by-uuid answer,
/// rather than silently gaining access to a road
/// [`btrfs_fsid_for_device`]'s own doc comment says a btrfs mount must never
/// be handed. And the panic-if-called fixtures — including ones for a
/// readable-empty and a truncated sysfs root — keep proving that promise at
/// this exact boundary, even though nothing here could call it today.
fn identity_after_btrfs(
  btrfs: BtrfsLookup,
  _by_uuid_answer: impl FnOnce() -> Option<IdentityReading>,
) -> Option<IdentityReading> {
  match btrfs {
    BtrfsLookup::Matched(reading) => Some(reading),
    BtrfsLookup::Refused => None,
  }
}

/// Reads a sysfs `dev` file — one line of `major:minor` — as a device number.
fn sysfs_device_number(sysfs: &KernelDir, path: &Path) -> Option<u64> {
  parse_device_number(&sysfs.read_linked(path).ok()?)
}

/// Yields every `/dev/disk/by-uuid` entry whose name names an identity we
/// understand, as `(device number, identity)`. Entries whose name is not a
/// recognizable identity, and entries that do not name a block device beneath
/// the `/dev` root, are skipped.
///
/// The identity here is classified from the name's width alone; the caller
/// still has to pass it through [`linux_identity`](super::linux_identity) with
/// the mount's filesystem type to reach the canonical form.
fn by_uuid_entries(dev: &KernelDir) -> Vec<(u64, VolumeIdentity)> {
  udev_entries(dev, "disk/by-uuid", super::parse_by_uuid_name)
}

/// A directory the kernel owns, opened once and read from without ever
/// crossing a mount.
///
/// **A path is not a name for a kernel table.** A process may run in a mount
/// namespace it does not own, and anything path-shaped in such a namespace can
/// be interposed: a file bound over `/proc/filesystems`, a directory bound over
/// `/dev/disk/by-label` holding a link of the mounter's choosing. Reading those
/// by pathname takes the answer from whoever wrote the mount table.
///
/// So each root is opened once and everything under it is reached from **that
/// descriptor** with `openat2` under `RESOLVE_BENEATH` and `RESOLVE_NO_XDEV`.
/// A mount interposed anywhere on the way is `EXDEV`, which is a refusal rather
/// than an answer, and a path that would climb out of the root is refused with
/// it.
///
/// ## What this does not do
///
/// It does not make a hostile namespace tell the truth, and nothing here should
/// be read as saying so. A namespace the process does not own can present its
/// own `/proc` and its own `/dev` **wholesale**, and `/proc/self/mountinfo` —
/// where the filesystem type that decides
/// [`Declared`](super::IdentityAssurance::Declared) comes from — is equally
/// theirs. What these roads refuse is a bind interposed *under* a genuine root.
/// That is worth refusing, and it is all that is claimed.
///
/// `openat2` is Linux 5.6 and later. Where it is missing every road through
/// here fails closed: no entries, no table, no identity — never a path open
/// standing in for one.
pub(super) struct KernelDir {
  root: OwnedFd,
}

impl KernelDir {
  /// Opens a kernel root and holds it to the filesystem it must be.
  ///
  /// The magic says what *kind* of filesystem a root is, never *whose*, so it
  /// is asked only where the kind is itself worth something. `/proc` and `/sys`
  /// are asked. `/dev` is not: what it carries is `tmpfs` or `ramfs`, which any
  /// user may mount, so the question would refuse nothing an attacker could not
  /// also present while risking a refusal on a legitimate host whose `/dev` is
  /// the other flavour. Under `/dev` it is `RESOLVE_NO_XDEV` that does the work.
  fn open(path: &str, magic: Option<rustix::fs::FsWord>) -> Option<Self> {
    let root = rustix::fs::open(
      path,
      OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
      Mode::empty(),
    )
    .ok()?;
    if let Some(magic) = magic {
      let matches = rustix::fs::fstatfs(&root)
        .map(|root| root.f_type == magic)
        .unwrap_or(false);
      if !matches {
        return None;
      }
    }
    Some(Self { root })
  }

  /// Stands a fixture directory in for a kernel root, for the laws that build
  /// one. It is opened as itself, with no magic to hold it to.
  #[cfg(test)]
  fn fixture(path: &Path) -> Option<Self> {
    rustix::fs::open(
      path,
      OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
      Mode::empty(),
    )
    .ok()
    .map(|root| Self { root })
  }

  /// Reaches `path` beneath this root, never across a mount and never out of
  /// the root.
  fn open_beneath(
    &self,
    path: &Path,
    oflags: OFlags,
    resolve: ResolveFlags,
  ) -> io::Result<OwnedFd> {
    rustix::fs::openat2(
      &self.root,
      path,
      oflags,
      Mode::empty(),
      ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | resolve,
    )
    .map_err(io::Error::from)
  }

  /// The device number of the block device `path` names beneath this root.
  ///
  /// `O_PATH` names the node without opening the device behind it: a block
  /// device need not be opened to be asked what number it is, and opening one
  /// can block, spin up hardware, or be refused outright.
  ///
  /// Symlinks are followed here, where the other roads forbid them, because a
  /// udev entry *is* a symlink and pointing at a device node is its whole job.
  /// `RESOLVE_BENEATH` keeps that resolution inside this root, which is why
  /// callers give the path relative to `/dev` rather than to the directory the
  /// link sits in: the links read `../../sda1`, and `BENEATH` would refuse the
  /// climb out of a deeper descriptor.
  fn device_number(&self, path: &Path) -> Option<u64> {
    let node = self
      .open_beneath(path, OFlags::PATH | OFlags::CLOEXEC, ResolveFlags::empty())
      .ok()?;
    let node = rustix::fs::fstat(&node).ok()?;
    // A number read off anything but a block device names nothing: `st_rdev`
    // is zero for a regular file, and a character device is not what any of
    // this is about.
    (rustix::fs::FileType::from_raw_mode(node.st_mode) == rustix::fs::FileType::BlockDevice)
      .then_some(node.st_rdev)
  }

  /// Lists a directory beneath this root.
  fn dir(&self, path: &Path) -> Option<Dir> {
    let dir = self
      .open_beneath(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        ResolveFlags::NO_SYMLINKS,
      )
      .ok()?;
    Dir::new(dir).ok()
  }

  /// Lists a directory beneath this root, reached across a symlink the kernel
  /// put there on purpose — the same seam [`read_linked`](Self::read_linked)
  /// opens for a file.
  ///
  /// `/sys/dev/block/<major>:<minor>` **is** a symlink: the number is an index
  /// into the device tree and the directory itself lives under `/sys/devices`.
  /// Every directory addressed through that index is therefore reached across
  /// one link, and refusing symlinks there refuses the kernel's own spelling of
  /// where a device sits — the `slaves/` walk below opened nothing at all until
  /// this existed. `RESOLVE_BENEATH` and `RESOLVE_NO_XDEV` still hold: the link
  /// may lead anywhere inside this root and across no mount, which is why such
  /// a directory is addressed from the root that contains both ends rather than
  /// from the directory the link sits in.
  fn dir_linked(&self, path: &Path) -> Option<Dir> {
    let dir = self
      .open_beneath(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        ResolveFlags::empty(),
      )
      .ok()?;
    Dir::new(dir).ok()
  }

  /// Reads a file beneath this root, keeping the difference between a file
  /// that is not there and one that could not be read — [`TempFsidMarker`]
  /// turns on it.
  fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read as _;

    let file = self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::CLOEXEC,
      ResolveFlags::NO_SYMLINKS,
    )?;
    let mut bytes = Vec::new();
    std::fs::File::from(file).read_to_end(&mut bytes)?;
    Ok(bytes)
  }

  /// Reads a file beneath this root, following a symlink the kernel put there
  /// on purpose.
  ///
  /// Structural reads refuse symlinks outright, because nothing in a kernel
  /// tree should need one to reach a file that is simply there. Some entries
  /// *are* links by design — a btrfs member under `devices/` is a link to the
  /// block device's own directory elsewhere under `/sys` — and refusing those
  /// refuses the fact itself. `RESOLVE_BENEATH` and `RESOLVE_NO_XDEV` still
  /// hold: the link may lead anywhere inside this root and across no mount,
  /// which is why such a read is addressed from the root that contains both
  /// ends rather than from the directory the link sits in.
  fn read_linked(&self, path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read as _;

    let file = self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::CLOEXEC,
      ResolveFlags::empty(),
    )?;
    let mut bytes = Vec::new();
    std::fs::File::from(file).read_to_end(&mut bytes)?;
    Ok(bytes)
  }

  /// Reads at most `limit` bytes of a file beneath this root.
  ///
  /// The unbounded read is for files the kernel writes, whose length the kernel
  /// decides. A file this crate cannot authenticate is not one of those.
  fn read_bounded(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read as _;

    let file = self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::CLOEXEC,
      ResolveFlags::NO_SYMLINKS,
    )?;
    let mut bytes = Vec::new();
    std::fs::File::from(file)
      .take(limit)
      .read_to_end(&mut bytes)?;
    Ok(bytes)
  }

  /// Where a symlink beneath this root points, read without following it.
  ///
  /// The target is the kernel's own spelling of where a device sits in its
  /// tree, which is the only thing that says which bus a device hangs off.
  /// Reading the link is not the same as walking it: nothing is opened, so
  /// nothing can be interposed along a path this never traverses.
  fn link_target(&self, path: &Path) -> Option<Vec<u8>> {
    let parent = path.parent()?;
    let name = path.file_name()?;
    let dir = self
      .open_beneath(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        ResolveFlags::NO_SYMLINKS,
      )
      .ok()?;
    rustix::fs::readlinkat(&dir, name, Vec::new())
      .ok()
      .map(|target| target.into_bytes())
  }

  /// A path beneath this root, built from a name the kernel wrote.
  fn at(parts: &[&[u8]]) -> Vec<u8> {
    let mut path = Vec::new();
    for part in parts {
      if !path.is_empty() {
        path.push(b'/');
      }
      path.extend_from_slice(part);
    }
    path
  }
}

/// `SYSFS_MAGIC`, which rustix does not name.
const SYSFS_MAGIC: rustix::fs::FsWord = 0x6265_6572;

/// The path of a mount source relative to `/dev`, or `None` where the source
/// names nothing under it.
///
/// A source that is not under `/dev/` cannot be in `/dev/disk` at all, and this
/// is the hot case: `tmpfs`, `proc`, `sysfs`, `overlay` and every other pseudo
/// filesystem names itself here. Skipping the scan for them is what makes
/// reading the identity on every resolve cheap enough to do.
///
/// It is a refusal as much as an optimization. A filesystem is free to call
/// itself whatever it likes — a FUSE mount may take `fsname=/tmp/link`, and a
/// relative name would otherwise be resolved against the working directory of
/// the process. What comes back is a path *relative to the `/dev` root*, which
/// is the only way any of it is opened: a source spelled `/dev/../tmp/link`
/// yields `../tmp/link`, and `RESOLVE_BENEATH` refuses to climb out for it.
fn device_relative(source: &Path) -> Option<&Path> {
  let bytes = source.as_os_str().as_bytes();
  let relative = bytes.strip_prefix(b"/dev/")?;
  (!relative.is_empty()).then(|| Path::new(OsStr::from_bytes(relative)))
}

/// The authenticated `/proc` both kernel reads go through, opened once per
/// operation.
fn proc_root() -> Option<KernelDir> {
  KernelDir::open("/proc", Some(rustix::fs::PROC_SUPER_MAGIC))
}

/// The number **this procfs** calls the calling process.
///
/// Not the number the process calls itself. A pid is meaningful only in a pid
/// namespace, and the numeric directories of a procfs are named in the
/// namespace that procfs was mounted in — which need not be the caller's. A
/// process in a child pid namespace that inherited an ancestor's procfs would
/// find its own id naming *another* process there, and read that process's
/// mount table: another mount namespace, so another source, another filesystem
/// type, and an identity or a label belonging to a volume the caller never
/// asked about. That needs no hostile mount at all, which is why the limit
/// stated on [`KernelDir`] does not cover it.
///
/// `self` is the translation the kernel provides, and reading the link is how
/// to ask for it without following it: `readlinkat` on the authenticated root
/// yields the number and resolves nothing. What comes back is then held to
/// what a pid may be — ASCII digits, nothing else, and a value that fits the
/// type a pid has — so that nothing else can be spelled into the path built
/// from it, and the read of `<pid>/mountinfo` stays symlink-free and guarded
/// like every other structural read here.
fn procfs_pid(proc_root: &KernelDir) -> Option<Vec<u8>> {
  let link = rustix::fs::readlinkat(&proc_root.root, "self", Vec::new()).ok()?;
  let pid = link.to_bytes();
  // A pid and nothing else: no separator, no dot, no sign, no emptiness, and
  // a number the type can hold. Anything else is not the answer to this
  // question, whatever it is.
  let plausible = !pid.is_empty()
    && pid.iter().all(u8::is_ascii_digit)
    && std::str::from_utf8(pid).ok()?.parse::<u32>().is_ok();
  plausible.then(|| pid.to_vec())
}

/// `/proc/self/mountinfo`, read from the authenticated root.
///
/// `None` is a mountinfo that could not be had *this way*, and every caller
/// fails closed on it rather than reaching for the pathname.
fn mountinfo(proc_root: &KernelDir) -> Option<Vec<u8>> {
  let path = KernelDir::at(&[&procfs_pid(proc_root)?, b"mountinfo"]);
  proc_root.read(Path::new(OsStr::from_bytes(&path))).ok()
}

/// The kernel's own table of filesystem types, read once per operation, from
/// the kernel and from nowhere else.
///
/// **A path is not a name for a kernel table.** A process may run in a mount
/// namespace it does not own, and anything path-shaped in such a namespace can
/// be interposed — a file bound over `/proc/filesystems`. Asking only what
/// filesystem the opened object sits on does not answer this, because the bind
/// may come from procfs itself: a task's own `comm` is writable, lives on
/// procfs, and can be made to hold a line of the grammar below.
///
/// So `/proc` is opened once and identified as procfs, and the entry is reached
/// from that descriptor under `RESOLVE_BENEATH`, `RESOLVE_NO_XDEV` and
/// `RESOLVE_NO_SYMLINKS`. A mount interposed anywhere on the way is `EXDEV`,
/// which is a refusal rather than an answer.
///
/// Two limits, stated rather than left to be found:
///
/// - `openat2` is Linux 5.6 and later. Where it is missing this road **fails
///   closed** — no table at all, so every read is
///   [`Declared`](super::IdentityAssurance::Declared) — rather than falling
///   back to a path open that vouches for nothing.
/// - The magic of a root says what *kind* of filesystem it is, never *whose*: a
///   user namespace may mount a procfs of its own, and this crate cannot tell
///   that one from the host's. What the magic refuses is the wrong kind of
///   object; what `RESOLVE_NO_XDEV` refuses is an interposition under the right
///   one. Neither is a claim that a namespace the process does not own can be
///   made to tell the truth.
fn block_backed_types(proc_root: &KernelDir) -> super::BlockBackedTypes {
  let Ok(table) = proc_root.read(Path::new("filesystems")) else {
    return super::BlockBackedTypes::none();
  };
  super::BlockBackedTypes::parse(&table).unwrap_or_else(super::BlockBackedTypes::none)
}

/// The level a read through one mount source is reported at, for a caller
/// asking about a single mount. An enumeration reads the table once with
/// [`block_backed_types`] instead of once per row.
fn source_assurance(proc_root: &KernelDir, fs_type: &[u8]) -> IdentityAssurance {
  block_backed_types(proc_root).assurance_of(fs_type)
}

/// Linux: recover the volume's published label from `/dev/disk/by-label`.
///
/// The road is the identity's own, one directory across: udev names a symlink
/// after what `blkid` read out of the superblock and points it at the device
/// node, so reversing the link recovers the label without `libblkid`, without
/// opening the block device, and without root. What comes back is a label, not
/// an identity — see [`volume_name()`](super::MountPoint::volume_name) for what
/// that does and does not promise.
///
/// The same two refusals the identity makes apply, for the same reasons. A
/// mount source outside `/dev` cannot be in the directory at all, and is the hot
/// case worth skipping the scan for. And where two labels resolve to one device
/// node — a departed volume's link that udev has not re-pointed yet, beside the
/// arriving one's — neither is reported: whichever the directory yields first is
/// a coin toss, and a name shown to a user is worth less than a wrong one costs.
///
/// `None` where udev published nothing for the device: an unlabeled volume, a
/// pseudo filesystem, or a system where udev is not running. The caller's
/// fallback then names the volume from its mount point.
///
/// The level the answer carries is the one its caller worked out for the mount
/// source, which is the level the identity beside it carries: see
/// [`BlockBackedTypes`](super::BlockBackedTypes).
fn volume_name(
  dev: &KernelDir,
  device: u64,
  fs_type: &[u8],
  assurance: IdentityAssurance,
) -> Option<NameReading> {
  // btrfs publishes its label where it publishes its FSID, and for the same
  // reason must be asked there: one label link cannot name every member of a
  // multi-device filesystem, nor two volumes that carry one label.
  if super::is_btrfs(fs_type) {
    let name = btrfs_label(&btrfs_sysfs()?, device)?;
    return Some(NameReading { name, assurance });
  }

  if let Some(name) = by_label_name(dev, device) {
    return Some(NameReading { name, assurance });
  }

  // The authenticated road had no answer. `/dev/disk/by-label` holds one
  // pathname per label, so the second volume to carry `NO NAME` is simply not
  // in it — and udev's own runtime database is keyed by the device number
  // instead, so it has an answer where the directory cannot. It is not a
  // source this crate can authenticate, and what it yields is reported at
  // `Declared` whatever the mount source itself earned: see
  // [`udev_database_label`].
  let name = udev_database_label(device)?;
  Some(NameReading {
    name,
    assurance: IdentityAssurance::Declared,
  })
}

/// The label `/dev/disk/by-label` publishes for one device, under the same two
/// refusals the identity road makes.
fn by_label_name(dev: &KernelDir, device: u64) -> Option<SmallBytes> {
  let mut found: Option<SmallBytes> = None;
  for (target, label) in by_label_entries(dev) {
    if target != device {
      continue;
    }
    // Compared through an owned answer rather than a live borrow of `found`,
    // so that the arm that fills it in is free to.
    match found.as_ref().map(|seen| *seen == label) {
      Some(true) => {}
      // Two labels, one node: neither names the volume.
      Some(false) => return None,
      None => found = Some(label),
    }
  }
  found
}

/// Yields every `/dev/disk/by-label` entry as `(device number, label)`.
/// Entries whose name decodes to nothing, and entries that do not name a block
/// device beneath the `/dev` root, are skipped.
fn by_label_entries(dev: &KernelDir) -> Vec<(u64, SmallBytes)> {
  udev_entries(dev, "disk/by-label", |name| {
    let label = decode_udev_escapes(name);
    (!label.as_bytes().is_empty()).then_some(label)
  })
}

/// Every entry of one `/dev/disk/by-*` directory, as the device number the
/// entry names and whatever its own name says.
///
/// Both the listing and each entry are taken beneath the authenticated `/dev`
/// root: the directory is opened from that descriptor with symlinks refused,
/// so a directory bound over it is `EXDEV` rather than a source of labels, and
/// each entry is then resolved by its path *relative to `/dev`* — `disk/by-uuid/NAME`
/// — because the link it points through reads `../../sda1` and
/// `RESOLVE_BENEATH` would refuse that climb from any deeper descriptor.
///
/// What comes back is a device number rather than a path, which is what the
/// callers compare. A number is what the kernel itself uses to name a device,
/// it cannot be spelled two ways, and reaching it this way retires the
/// `canonicalize` that used to follow these links wherever they led.
fn udev_entries<T>(
  dev: &KernelDir,
  directory: &str,
  read_name: impl Fn(&[u8]) -> Option<T>,
) -> Vec<(u64, T)> {
  let Some(entries) = dev.dir(Path::new(directory)) else {
    return Vec::new();
  };
  let mut found = Vec::new();
  for entry in entries {
    let Ok(entry) = entry else {
      continue;
    };
    let name = entry.file_name().to_bytes();
    if name == b"." || name == b".." {
      continue;
    }
    let Some(value) = read_name(name) else {
      continue;
    };
    let mut path = Vec::with_capacity(directory.len() + 1 + name.len());
    path.extend_from_slice(directory.as_bytes());
    path.push(b'/');
    path.extend_from_slice(name);
    let Some(number) = dev.device_number(Path::new(OsStr::from_bytes(&path))) else {
      continue;
    };
    found.push((number, value));
  }
  found
}

/// Decodes the `\x20`-style escapes udev writes into the names under
/// `/dev/disk/by-label`, which cannot carry a space, a slash or a non-printable
/// byte literally. A backslash that does not begin a well-formed escape is
/// itself: the label `a\b` is a label, not a malformed escape.
fn decode_udev_escapes(input: &[u8]) -> SmallBytes {
  // Fast path: no backslash means no escapes to decode.
  if super::find_byte(b'\\', input).is_none() {
    return SmallBytes::from_bytes(input);
  }

  // Decoding only shrinks (a 4-byte escape becomes one byte).
  let mut out = Vec::with_capacity(input.len());
  let mut i = 0;
  while i < input.len() {
    let escaped = match input[i..] {
      [b'\\', b'x', hi, lo, ..] => match (super::hex_digit(hi), super::hex_digit(lo)) {
        (Some(hi), Some(lo)) => Some((hi << 4) | lo),
        _ => None,
      },
      _ => None,
    };
    match escaped {
      Some(byte) => {
        out.push(byte);
        i += 4;
      }
      None => {
        out.push(input[i]);
        i += 1;
      }
    }
  }
  SmallBytes::from_bytes(&out)
}

/// The label udev recorded for one device in its runtime database, or `None`.
///
/// **This source cannot be authenticated, and what it yields is never reported
/// above [`Declared`](super::IdentityAssurance::Declared).** Every other root
/// here is held to a filesystem magic an unprivileged mounter cannot forge into
/// place — `PROC_SUPER_MAGIC`, `SYSFS_MAGIC` — and `/run` is tmpfs, which any
/// user may mount. So the sentence this road is read under is: a label read
/// from the udev runtime database is a claim by whoever controls `/run`, and on
/// a system with unprivileged user namespaces that is not necessarily the
/// system. It is reported, never vouched.
///
/// It is consulted only where the authenticated roads have no answer at all —
/// `/dev/disk/by-label` holds one pathname per label, so the second volume to
/// carry `NO NAME` has no link there — and never for btrfs, which has the sysfs
/// census and needs no claim.
///
/// The containment is the same as everywhere else even though the root is not:
/// opened beneath `/run` with `RESOLVE_BENEATH`, `RESOLVE_NO_XDEV` and
/// `RESOLVE_NO_SYMLINKS`, read to a bound, parsed strictly. `ID_FS_LABEL_ENC`
/// is the key, never `ID_FS_LABEL`: udev writes the latter with the characters
/// it considers unsafe replaced by `_`, which is not the label the volume
/// carries, while the former is the exact bytes in the same `\xNN` escaping
/// `/dev/disk/by-label` names use — the decoder this crate already has.
/// Anything malformed is no label, and the caller falls through to the mount
/// point as it always did.
fn udev_database_label(device: u64) -> Option<SmallBytes> {
  /// A udev database record for one device is a short list of short lines.
  /// Reading past this is reading something that is not one.
  const LIMIT: u64 = 64 * 1024;
  const KEY: &[u8] = b"E:ID_FS_LABEL_ENC=";

  let run = KernelDir::open("/run", None)?;
  let (major, minor) = unmakedev(device);
  let path = format!("udev/data/b{major}:{minor}");
  let record = run.read_bounded(Path::new(&path), LIMIT).ok()?;

  let value = record
    .split(|&byte| byte == b'\n')
    .find_map(|line| line.strip_prefix(KEY))?;
  let label = decode_udev_escapes(value);
  (!label.as_bytes().is_empty()).then_some(label)
}

/// The major and minor a device number is made of — the inverse of
/// [`makedev`], for the one road that must spell a device the way udev names
/// its own records.
fn unmakedev(dev: u64) -> (u64, u64) {
  let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff);
  let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff);
  (major, minor)
}

/// What the kernel says about whether a device's storage can leave the running
/// machine.
///
/// **Linux never answers [`NotEjectable`](super::Ejectability::NotEjectable).**
/// That is not an oversight, it is the honest end of three rounds of trying:
/// there is no unprivileged source on this platform that positively
/// establishes a drive as fixed in the machine.
///
/// - `removable` describes the **media**, not the drive. An external USB disk
///   reads `0` because nothing is taken out *of it*, and a card reader reads
///   `1` while being screwed to the board.
/// - Bus ancestry is an allowlist, and an allowlist can only ever say yes. A
///   drive on eSATA or Thunderbolt is absent from it and is no less removable
///   for that.
/// - A virtual block device — dm-crypt, LVM, MD, loop — has no bus of its own
///   at all, so its ancestry says nothing about the disks underneath it.
///
/// Each of those was, in an earlier round of this branch, turned into a denial
/// by reading "no evidence of removable" as "evidence of fixed". The rule now
/// is the one the enum documents: a denial needs a platform that positively
/// denies, and where none does, the answer is
/// [`Unknown`](super::Ejectability::Unknown).
///
/// **What does count as positive evidence of `Ejectable`,** asked of sysfs
/// beneath the authenticated `/sys` root and keyed by the device number:
///
/// - `removable` reading `1` — the kernel saying the media comes out.
/// - An ancestry through the USB or MMC subsystem — the kernel saying the
///   drive hangs off a bus whose devices leave while the machine runs.
/// - Either of those on any device a virtual device is **built from**. A
///   dm-crypt volume over a USB disk is as removable as the disk under it, so
///   `slaves/` is walked, to a bounded depth, before answering.
fn device_ejectability(sysfs: Option<&KernelDir>, device: Option<u64>) -> Ejectability {
  let (Some(sysfs), Some(device)) = (sysfs, device) else {
    return Ejectability::Unknown;
  };
  if says_removable(sysfs, device, 0) {
    Ejectability::Ejectable
  } else {
    // Nothing said it comes out. Nothing said it does not, either, and this
    // platform has no way to ask that question directly.
    Ejectability::Unknown
  }
}

/// How far down a stack of virtual devices the search for real storage goes.
///
/// dm over md over dm is already unusual; anything deeper is a loop or a
/// misreading, and a bounded walk cannot become one.
const SLAVE_DEPTH: u32 = 8;

/// Whether the kernel says this device, or anything it is built from, has
/// storage that leaves the running machine.
fn says_removable(sysfs: &KernelDir, device: u64, depth: u32) -> bool {
  let (major, minor) = unmakedev(device);
  let block = format!("dev/block/{major}:{minor}");

  // The kernel's own path for this device, read without walking it. A bus
  // whose devices are unplugged is a yes about every partition on the drive.
  if sysfs
    .link_target(Path::new(&block))
    .is_some_and(|ancestry| names_removable_bus(&ancestry))
  {
    return true;
  }

  // A partition's `removable` lives on the disk above it.
  let removable = sysfs
    .read_linked(Path::new(&format!("{block}/removable")))
    .or_else(|_| sysfs.read_linked(Path::new(&format!("{block}/../removable"))));
  if removable
    .as_deref()
    .is_ok_and(|value| value.trim_ascii() == b"1")
  {
    return true;
  }

  if depth >= SLAVE_DEPTH {
    return false;
  }
  // A virtual device is as removable as the storage it is built from: a
  // dm-crypt volume on a USB disk goes with the disk. `slaves/` is where the
  // kernel names those, and each name is a block device of its own.
  //
  // Reached with `dir_linked`, because `dev/block/<major>:<minor>` is itself a
  // symlink: a structural open refuses it before `slaves` is ever read, and
  // this walk then never ran on any real kernel.
  let Some(slaves) = sysfs.dir_linked(Path::new(&format!("{block}/slaves"))) else {
    return false;
  };
  for slave in slaves {
    let Ok(slave) = slave else {
      continue;
    };
    let name = slave.file_name().to_bytes();
    if name == b"." || name == b".." {
      continue;
    }
    let dev = KernelDir::at(&[block.as_bytes(), b"slaves", name, b"dev"]);
    let Some(number) = sysfs
      .read_linked(Path::new(OsStr::from_bytes(&dev)))
      .ok()
      .and_then(|text| parse_device_number(&text))
    else {
      continue;
    };
    if says_removable(sysfs, number, depth + 1) {
      return true;
    }
  }
  false
}

/// A sysfs `dev` file — one line of `major:minor` — as a device number.
fn parse_device_number(contents: &[u8]) -> Option<u64> {
  let line = contents.split(|&byte| byte == b'\n').next()?;
  let colon = super::find_byte(b':', line)?;
  Some(makedev(
    parse_u64(&line[..colon])?,
    parse_u64(&line[colon + 1..])?,
  ))
}

/// Whether a device's sysfs ancestry passes through a bus whose devices are
/// taken out while the machine runs.
///
/// The kernel spells the path of `/sys/dev/block/<major>:<minor>` through the
/// controllers the device hangs off, so a USB disk reads
/// `.../usb1/1-3/1-3:1.0/host6/.../block/sdb`, and an SD card reads
/// `.../mmc_host/mmc0/...`. Matching a whole path component rather than a
/// substring is what keeps a disk label or a vendor name spelling `usb` from
/// answering for the bus.
fn names_removable_bus(ancestry: &[u8]) -> bool {
  ancestry.split(|&byte| byte == b'/').any(|component| {
    component == b"mmc_host"
      || component == b"mmc"
      // `usb1`, `usb2`, … are the controllers; `usb` itself is the subsystem.
      || (component.starts_with(b"usb")
        && component[3..].iter().all(u8::is_ascii_digit))
  })
}

/// Finds the mount `canonical` is on, out of the mountinfo the authenticated
/// `/proc` gives.
///
/// The device number alone does not name a mount. Bind mounts share it, so a
/// filter on `st_dev` leaves several lines standing, and picking the longest
/// mount point among them picks whichever unrelated bind mount happens to have
/// the longest name — whose source, filesystem type and last path component
/// would then be reported for a path that is nowhere inside it.
///
/// Two answers, in order of what the kernel will say:
///
/// - The **mount id** `statx` reports for the path is the id mountinfo prints
///   in its first field. Where the kernel gives one (Linux 5.8 and later), it
///   names exactly one line, and that line must still contain the path before
///   it is taken; a row that does not is no answer about this path, and nothing
///   is returned rather than something.
/// - Otherwise the candidates are narrowed to the mounts whose mount point
///   *contains* the path — compared on component boundaries, so `/media/usb2`
///   is not read as containing `/media/usb/file` — and the deepest of those
///   wins, which is the one the kernel would have resolved through.
///
/// **Why containment rather than the device number** on the first road. A
/// recycled id naming another mount is what the check is for, and the pinned
/// descriptor already forecloses it: the kernel returns a mount id to its
/// allocator only when the mount is freed, and [`PinnedMount`] holds a
/// reference to that mount for the whole resolve. What is left to guard is a
/// row that simply does not describe this path, and containment says that
/// directly. The device number does not: btrfs gives every subvolume its own
/// anonymous number, so a path in a subvolume nested inside a mount carries a
/// number the mount's own row never prints, and requiring them to agree would
/// refuse to resolve ordinary paths on an ordinary btrfs root. The narrowing
/// road below still filters on it, because there it is a filter among many
/// candidates rather than the sole gate on the one the kernel named.
///
/// The row is required either way: a pinned mount with no row at all is a
/// refusal, never a guess.
fn lookup_mountinfo(
  proc_root: &KernelDir,
  canonical: &Path,
  mount: &PinnedMount,
) -> io::Result<(SmallBytes, SmallBytes, SmallBytes)> {
  let Some(mountinfo) = mountinfo(proc_root) else {
    // Mountinfo that cannot be had from the authenticated root is not had at
    // all: the pathname is exactly what must not be trusted here.
    return Err(io::Error::new(
      io::ErrorKind::NotFound,
      "mountinfo could not be read from the authenticated proc root",
    ));
  };
  // Both taken from the one pinned observation, so the line this picks and the
  // key it is cached under describe the same mount.
  let wanted = mount.id;
  let target_dev = mount.dev;
  let path = canonical.as_os_str().as_bytes();

  let mut best: Option<(SmallBytes, SmallBytes, SmallBytes)> = None;
  let mut best_len: usize = 0;
  let mut start = 0;

  while start < mountinfo.len() {
    let end = super::find_byte(b'\n', &mountinfo[start..])
      .map(|pos| start + pos)
      .unwrap_or(mountinfo.len());

    let line = &mountinfo[start..end];
    start = end + 1;

    if line.is_empty() {
      continue;
    }

    if let Some((line_id, dev_major, dev_minor, mp_raw, fs_type_raw, source_raw)) =
      parse_mountinfo_line(line)
    {
      // The kernel named the line outright.
      if let Some(wanted) = wanted {
        if line_id == wanted {
          // Named, and still held to describing the path that was pinned. A
          // mount the path is not inside answers for some other path entirely,
          // whether the line came from a recycled id or from a mount table
          // written to say so, and taking nothing is the honest end of either.
          let mp = decode_octal_escapes(mp_raw);
          if !contains_path(mp.as_bytes(), path) {
            return Err(io::Error::new(
              io::ErrorKind::NotFound,
              "the mountinfo row carrying this mount id does not contain the path",
            ));
          }
          return Ok((
            mp,
            decode_octal_escapes(source_raw),
            SmallBytes::from_bytes(fs_type_raw),
          ));
        }
        continue;
      }

      // Compare major:minor against stat's st_dev using Linux makedev encoding.
      if makedev(dev_major, dev_minor) != target_dev {
        continue;
      }
      // Of the mounts this path is actually inside, the deepest is the one it
      // is on. A mount point the path is not inside answers for some other
      // path entirely.
      let mp = decode_octal_escapes(mp_raw);
      if !contains_path(mp.as_bytes(), path) {
        continue;
      }
      if best.is_none() || mp.as_bytes().len() > best_len {
        best_len = mp.as_bytes().len();
        let device = decode_octal_escapes(source_raw);
        let fs_type = SmallBytes::from_bytes(fs_type_raw);
        best = Some((mp, device, fs_type));
      }
    }
  }

  best.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no mount point found for device"))
}

/// Parses a single line from `/proc/self/mountinfo`.
///
/// Format: `mount_id parent_id major:minor root mount_point options [optional]... - fs_type source super_options`
///
/// Returns `(mount_id, major, minor, mount_point_raw, fs_type_raw, source_raw)`.
#[allow(clippy::type_complexity)]
fn parse_mountinfo_line(line: &[u8]) -> Option<(u64, u64, u64, &[u8], &[u8], &[u8])> {
  let mut fields = line.split(|&b| b == b' ');

  let mount_id = parse_u64(fields.next()?)?;
  fields.next()?; // parent_id
  let dev_field = fields.next()?; // major:minor
  fields.next()?; // root
  let mount_point_raw = fields.next()?; // mount_point (octal-escaped)

  // Parse major:minor
  let colon = super::find_byte(b':', dev_field)?;
  let major = parse_u64(&dev_field[..colon])?;
  let minor = parse_u64(&dev_field[colon + 1..])?;

  // Skip options and optional tagged fields until the "-" separator.
  let mut found_sep = false;
  for field in fields.by_ref() {
    if field == b"-" {
      found_sep = true;
      break;
    }
  }
  if !found_sep {
    return None;
  }

  let fs_type_raw = fields.next()?; // fs_type
  let source_raw = fields.next()?; // mount source (device)

  Some((
    mount_id,
    major,
    minor,
    mount_point_raw,
    fs_type_raw,
    source_raw,
  ))
}

/// Reconstructs a `dev_t` from major and minor numbers using the Linux encoding.
#[cfg_attr(not(tarpaulin), inline(always))]
fn makedev(major: u64, minor: u64) -> u64 {
  ((major & 0xffff_f000) << 32)
    | ((major & 0x0000_0fff) << 8)
    | ((minor & 0xffff_ff00) << 12)
    | (minor & 0x0000_00ff)
}

/// Parses an ASCII decimal byte string into u64.
#[cfg_attr(not(tarpaulin), inline(always))]
fn parse_u64(bytes: &[u8]) -> Option<u64> {
  if bytes.is_empty() {
    return None;
  }
  let mut n: u64 = 0;
  for &b in bytes {
    let d = b.wrapping_sub(b'0');
    if d > 9 {
      return None;
    }
    n = n.checked_mul(10)?.checked_add(d as u64)?;
  }
  Some(n)
}

/// Decodes octal escape sequences (`\040`, `\011`, `\012`, `\134`) used
/// in `/proc/self/mountinfo` and `/proc/mounts`.
#[cfg_attr(not(tarpaulin), inline(always))]
fn decode_octal_escapes(input: &[u8]) -> SmallBytes {
  // Fast path: no backslash means no escapes to decode.
  if super::find_byte(b'\\', input).is_none() {
    return SmallBytes::from_bytes(input);
  }

  // Decoding only shrinks (4-byte escape → 1 byte), so if input fits in
  // INLINE_CAPACITY bytes the output is guaranteed to as well — decode into
  // a stack buffer.
  if input.len() <= super::INLINE_CAPACITY {
    let mut data = [0u8; super::INLINE_CAPACITY];
    let mut out = 0;
    let mut i = 0;
    while i < input.len() {
      if input[i] == b'\\' && i + 3 < input.len() {
        let a = input[i + 1].wrapping_sub(b'0');
        let b = input[i + 2].wrapping_sub(b'0');
        let c = input[i + 3].wrapping_sub(b'0');
        if a < 8 && b < 8 && c < 8 {
          data[out] = a * 64 + b * 8 + c;
          out += 1;
          i += 4;
          continue;
        }
      }
      data[out] = input[i];
      out += 1;
      i += 1;
    }
    SmallBytes::Inline {
      data,
      len: out as u8,
    }
  } else {
    let mut out = BytesMut::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
      if input[i] == b'\\' && i + 3 < input.len() {
        let a = input[i + 1].wrapping_sub(b'0');
        let b = input[i + 2].wrapping_sub(b'0');
        let c = input[i + 3].wrapping_sub(b'0');
        if a < 8 && b < 8 && c < 8 {
          out.put_u8(a * 64 + b * 8 + c);
          i += 4;
          continue;
        }
      }
      out.put_u8(input[i]);
      i += 1;
    }
    SmallBytes::Heap(out.freeze())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // ── parse_u64 ─────────────────────────────────────────────────────

  #[test]
  fn test_parse_u64_valid() {
    assert_eq!(parse_u64(b"0"), Some(0));
    assert_eq!(parse_u64(b"123"), Some(123));
    assert_eq!(parse_u64(b"259"), Some(259));
  }

  #[test]
  fn test_parse_u64_empty() {
    assert_eq!(parse_u64(b""), None);
  }

  #[test]
  fn test_parse_u64_non_digit() {
    assert_eq!(parse_u64(b"12a3"), None);
    assert_eq!(parse_u64(b"abc"), None);
  }

  #[test]
  fn test_parse_u64_overflow() {
    // u64::MAX = 18446744073709551615, adding one more digit should overflow
    assert_eq!(parse_u64(b"99999999999999999999"), None);
  }

  // ── makedev ───────────────────────────────────────────────────────

  #[test]
  fn test_makedev() {
    // major=8, minor=1 → /dev/sda1 on typical Linux
    let dev = makedev(8, 1);
    assert_eq!(dev, (8 << 8) | 1);
  }

  #[test]
  fn test_makedev_large() {
    // Verify extended device number encoding
    let dev = makedev(259, 0);
    let reconstructed_major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let reconstructed_minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    assert_eq!(reconstructed_major, 259);
    assert_eq!(reconstructed_minor, 0);
  }

  // ── parse_mountinfo_line ──────────────────────────────────────────

  #[test]
  fn test_parse_mountinfo_valid() {
    let line = b"36 35 98:0 / /mnt rw,noatime shared:1 - ext3 /dev/root rw,errors=continue";
    let (_, major, minor, mp, _fs_type, source) = parse_mountinfo_line(line).unwrap();
    assert_eq!(major, 98);
    assert_eq!(minor, 0);
    assert_eq!(mp, b"/mnt");
    assert_eq!(source, b"/dev/root");
  }

  #[test]
  fn test_parse_mountinfo_with_optional_fields() {
    // Multiple optional fields before the separator
    let line = b"100 50 8:1 / /boot rw master:1 shared:2 - ext4 /dev/sda1 rw";
    let (_, major, minor, mp, _fs_type, source) = parse_mountinfo_line(line).unwrap();
    assert_eq!(major, 8);
    assert_eq!(minor, 1);
    assert_eq!(mp, b"/boot");
    assert_eq!(source, b"/dev/sda1");
  }

  #[test]
  fn test_parse_mountinfo_no_separator() {
    // Malformed line without " - "
    let line = b"36 35 98:0 / /mnt rw,noatime shared:1";
    assert!(parse_mountinfo_line(line).is_none());
  }

  #[test]
  fn test_parse_mountinfo_too_few_fields() {
    let line = b"36 35";
    assert!(parse_mountinfo_line(line).is_none());
  }

  // ── the census answers membership, not the level ──────────────────

  /// A refused table leaves every read at `Declared`, and the btrfs road is no
  /// exception: its census speaks for what sysfs said, while the level it is
  /// reported at belongs to the mount source. Before this, a refused table left
  /// the label `Declared` and the identity `Published` on the same mount.
  #[test]
  fn test_the_btrfs_census_carries_the_level_of_its_mount_source() {
    let fsid = VolumeIdentity::FsUuid([0x33; 16]);
    let matched = BtrfsLookup::Matched(IdentityReading::published(fsid));

    let declared = matched.at(IdentityAssurance::Declared);
    let BtrfsLookup::Matched(reading) = declared else {
      panic!("a match held to a level is still a match");
    };
    assert_eq!(reading.identity(), fsid, "the level is not part of the key");
    assert!(reading.is_declared());

    let published = matched.at(IdentityAssurance::Published);
    let BtrfsLookup::Matched(reading) = published else {
      panic!("a match held to a level is still a match");
    };
    assert_eq!(reading.assurance(), IdentityAssurance::Published);
  }

  /// A refusal is a refusal at every level.
  #[test]
  fn test_a_refused_census_stays_refused() {
    assert!(matches!(
      BtrfsLookup::Refused.at(IdentityAssurance::Declared),
      BtrfsLookup::Refused
    ));
  }

  // ── the device number udev spells its records by ──────────────────

  /// The udev runtime database names a record `b<major>:<minor>`, so the one
  /// device number the roads already carry has to be taken apart again the way
  /// the kernel put it together.
  #[test]
  fn test_a_device_number_takes_apart_the_way_it_was_built() {
    for (major, minor) in [(8, 1), (8, 17), (259, 0), (253, 0), (0, 42), (4095, 255)] {
      assert_eq!(
        unmakedev(makedev(major, minor)),
        (major, minor),
        "{major}:{minor}"
      );
    }
  }

  // ── the number this procfs calls us ───────────────────────────────

  /// The pid comes from the authenticated root's own `self` link, so it is the
  /// number *that procfs* uses. Asking the process for its own id answers in
  /// the caller's pid namespace, which need not be the one the procfs was
  /// mounted in — and then the mount table read would be another process's.
  #[test]
  fn test_the_pid_is_the_one_this_procfs_uses() {
    let root = proc_fixture();
    let pid = procfs_pid(&root).expect("procfs publishes a self link");
    assert!(
      pid.iter().all(u8::is_ascii_digit) && !pid.is_empty(),
      "a pid is digits and nothing else: {:?}",
      String::from_utf8_lossy(&pid)
    );
    // On a host that shares its pid namespace with this process the two agree,
    // and where they would not, it is the procfs answer that names the right
    // mount table.
    assert_eq!(
      String::from_utf8_lossy(&pid).parse::<u32>().unwrap(),
      std::process::id(),
      "this test runs in the namespace its procfs was mounted in"
    );
  }

  /// A `self` link that is not a pid names nothing that may be built into a
  /// path, so the road refuses rather than reading whatever it points at.
  #[test]
  fn test_a_self_link_that_is_not_a_pid_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // An empty target is not in the list because the kernel refuses to make
    // such a link at all, so no procfs could present one.
    for target in ["1/../2", "12a", "-1", "  7", "1 2", "./3", "self", "1\n"] {
      let link = dir.path().join("self");
      let _ = std::fs::remove_file(&link);
      std::os::unix::fs::symlink(target, &link).unwrap();
      assert_eq!(
        procfs_pid(&fixture(dir.path())),
        None,
        "a self link reading {target:?} is not a pid"
      );
    }
  }

  // ── device_relative ───────────────────────────────────────────────

  #[test]
  fn test_device_relative_names_what_is_opened_beneath_dev() {
    assert_eq!(
      device_relative(Path::new("/dev/sda1")),
      Some(Path::new("sda1"))
    );
    assert_eq!(
      device_relative(Path::new("/dev/mapper/vg-root")),
      Some(Path::new("mapper/vg-root"))
    );
  }

  /// A filesystem that names itself, or names a path outside `/dev`, is not a
  /// device node however that path resolves: a FUSE mount whose `fsname` is a
  /// symlink into `/dev` must inherit neither the node's identity nor its
  /// label, and a relative name must never be canonicalized against the
  /// process's own directory.
  #[test]
  fn test_device_relative_refuses_everything_outside_dev() {
    assert_eq!(device_relative(Path::new("tmpfs")), None);
    assert_eq!(device_relative(Path::new("overlay")), None);
    assert_eq!(device_relative(Path::new("/tmp/disk-link")), None);
    assert_eq!(device_relative(Path::new("/home/alice/dev/sda1")), None);
    // The directory itself is not a node in it.
    assert_eq!(device_relative(Path::new("/dev")), None);
    assert_eq!(device_relative(Path::new("/dev/")), None);
  }

  /// A source that climbs back out is not refused here but by the open: what
  /// comes back is a path relative to the root, and `RESOLVE_BENEATH` will not
  /// follow it out.
  #[test]
  fn test_device_relative_hands_the_climb_to_the_open() {
    assert_eq!(
      device_relative(Path::new("/dev/../tmp/link")),
      Some(Path::new("../tmp/link"))
    );
  }

  // ── decode_octal_escapes ──────────────────────────────────────────

  #[test]
  fn test_decode_udev_escapes_plain_label() {
    assert_eq!(decode_udev_escapes(b"BACKUP").as_bytes(), b"BACKUP");
  }

  #[test]
  fn test_decode_udev_escapes_space() {
    assert_eq!(
      decode_udev_escapes(b"My\\x20Disk").as_bytes(),
      b"My Disk".as_slice()
    );
  }

  #[test]
  fn test_decode_udev_escapes_several() {
    assert_eq!(
      decode_udev_escapes(b"a\\x2fb\\x20c").as_bytes(),
      b"a/b c".as_slice()
    );
  }

  /// A backslash that begins no well-formed escape is a byte of the label.
  #[test]
  fn test_decode_udev_escapes_keeps_a_lone_backslash() {
    assert_eq!(decode_udev_escapes(b"a\\b").as_bytes(), b"a\\b".as_slice());
    assert_eq!(
      decode_udev_escapes(b"a\\x2").as_bytes(),
      b"a\\x2".as_slice()
    );
    assert_eq!(
      decode_udev_escapes(b"a\\xzz").as_bytes(),
      b"a\\xzz".as_slice()
    );
  }

  #[test]
  fn test_decode_no_escapes() {
    let result = decode_octal_escapes(b"/mnt/data");
    assert_eq!(result.as_bytes(), b"/mnt/data");
  }

  #[test]
  fn test_decode_space_escape_inline() {
    // \040 = space (0o40 = 32)
    let result = decode_octal_escapes(b"/mnt/my\\040drive");
    assert_eq!(result.as_bytes(), b"/mnt/my drive");
    assert!(matches!(result, SmallBytes::Inline { .. }));
  }

  #[test]
  fn test_decode_backslash_escape() {
    // \134 = backslash (0o134 = 92)
    let result = decode_octal_escapes(b"/mnt/back\\134slash");
    assert_eq!(result.as_bytes(), b"/mnt/back\\slash");
  }

  #[test]
  fn test_decode_multiple_escapes() {
    // \011 = tab (0o11 = 9), \012 = newline (0o12 = 10)
    let result = decode_octal_escapes(b"a\\011b\\012c");
    assert_eq!(result.as_bytes(), b"a\tb\nc");
  }

  #[test]
  fn test_decode_escape_at_end_truncated() {
    // Backslash near end without enough chars for a full octal — treated as literal
    let result = decode_octal_escapes(b"abc\\04");
    assert_eq!(result.as_bytes(), b"abc\\04");
  }

  #[test]
  fn test_decode_invalid_octal_digits() {
    // \089 — '8' and '9' are not valid octal digits, treated as literal
    let result = decode_octal_escapes(b"x\\089y");
    assert_eq!(result.as_bytes(), b"x\\089y");
  }

  #[test]
  fn test_decode_heap_path() {
    // Input longer than INLINE_CAPACITY with escapes
    let mut input = vec![b'a'; super::super::INLINE_CAPACITY + 10];
    // Insert \040 (space) near the start
    input[1] = b'\\';
    input[2] = b'0';
    input[3] = b'4';
    input[4] = b'0';
    let result = decode_octal_escapes(&input);
    assert!(matches!(result, SmallBytes::Heap(_)));
    // The result should have a space at position 1
    assert_eq!(result.as_bytes()[1], b' ');
  }

  #[test]
  fn test_decode_heap_literal_backslash() {
    // Heap path with a backslash that's not a valid octal escape
    let mut input = vec![b'x'; super::super::INLINE_CAPACITY + 5];
    input[0] = b'\\';
    input[1] = b'z'; // not octal
    let result = decode_octal_escapes(&input);
    assert!(matches!(result, SmallBytes::Heap(_)));
    assert_eq!(result.as_bytes()[0], b'\\');
    assert_eq!(result.as_bytes()[1], b'z');
  }

  // ── lookup_mountinfo ──────────────────────────────────────────────

  /// A path the kernel has no mount id for falls to the ancestor road, and a
  /// device number no line carries names no mount there either.
  ///
  /// The pair given here cannot arise from a resolve — `st_dev` and the mount
  /// id always describe one path — so the law asks about a path that does not
  /// exist, which is the only way to reach the ancestor road deliberately.
  #[test]
  fn test_lookup_mountinfo_nonexistent_dev() {
    // A pinned observation of the root, deliberately paired with a path that
    // is not on it — the only way to reach the ancestor road on purpose.
    let mount = PinnedMount::of(Path::new("/")).unwrap();
    let result = lookup_mountinfo(
      &proc_fixture(),
      Path::new("/whichdisk-no-such-path-at-all"),
      &PinnedMount {
        dev: 0xDEAD_BEEF,
        id: None,
        pinned: mount.pinned,
      },
    );
    assert!(result.is_err());
  }

  /// A row the kernel named by mount id is still held to describing the path
  /// that was pinned. The pinned descriptor is what stops the id from coming to
  /// name another mount at all — the kernel cannot free a mount a descriptor
  /// still references, and only a freed mount returns its id — so this is the
  /// second gate rather than the first: a mount table saying the named mount is
  /// somewhere the path is not is refused outright, and nothing is returned.
  #[test]
  fn test_a_named_row_that_does_not_contain_the_path_is_refused() {
    // `/proc` is its own mount on every Linux host, and its row's mount point
    // is `/proc` — which does not contain `/`. Pairing that mount's id with the
    // root path is the shape a recycled id would arrive in.
    let procfs = PinnedMount::of(Path::new("/proc")).unwrap();
    // Where the kernel has no mount id there is nothing to name a row with, and
    // the ancestor road answers instead; that road has a law of its own.
    if procfs.id.is_none() {
      return;
    }
    let result = lookup_mountinfo(&proc_fixture(), Path::new("/"), &procfs);
    assert!(
      result.is_err(),
      "a named row that does not contain the path is no answer about it"
    );

    // And the same id asked about a path that row does contain still answers.
    let (mp, _device, _fs_type) =
      lookup_mountinfo(&proc_fixture(), Path::new("/proc"), &procfs).unwrap();
    assert_eq!(mp.as_bytes(), b"/proc");
  }

  #[test]
  fn test_lookup_mountinfo_returns_fs_type() {
    // The root filesystem must resolve, and its mountinfo entry must carry a
    // non-empty fs type.
    let (mp, _device, fs_type) = lookup_mountinfo(
      &proc_fixture(),
      Path::new("/"),
      &PinnedMount::of(Path::new("/")).unwrap(),
    )
    .unwrap();
    assert_eq!(mp.as_bytes(), b"/");
    assert!(!fs_type.as_bytes().is_empty());
  }

  // ── volume_capabilities ───────────────────────────────────────────

  #[test]
  fn test_volume_capabilities_case_sensitive_fs() {
    // ext4 is case-sensitive and case-preserving by default.
    let caps = volume_capabilities(b"ext4");
    assert_eq!(caps.case_sensitive(), Some(true));
    assert_eq!(caps.case_preserving(), Some(true));
    assert_eq!(caps.fs_type(), "ext4");
  }

  #[test]
  fn test_volume_capabilities_case_insensitive_fs() {
    // vfat/exfat/ntfs look up names case-insensitively but preserve case.
    for fs in [b"vfat".as_slice(), b"exfat", b"ntfs", b"ntfs3", b"fuseblk"] {
      let caps = volume_capabilities(fs);
      assert_eq!(caps.case_sensitive(), Some(false), "{fs:?}");
      assert_eq!(caps.case_preserving(), Some(true), "{fs:?}");
    }
  }

  #[test]
  fn test_volume_capabilities_unknown_fs() {
    // ZFS case sensitivity is a per-dataset property; unmappable types are
    // reported as unknown rather than a guessed default.
    let caps = volume_capabilities(b"zfs");
    assert_eq!(caps.case_sensitive(), None);
    assert_eq!(caps.case_preserving(), None);
    assert_eq!(caps.fs_type(), "zfs");
  }

  // ── volume_identity ───────────────────────────────────────────────

  /// A source naming nothing that exists resolves to no device number, and a
  /// road with no number never asks udev anything.
  #[test]
  fn test_an_unknown_device_resolves_to_no_number() {
    let dev = dev_fixture();
    let relative = device_relative(Path::new("/dev/whichdisk-no-such-device")).unwrap();
    assert_eq!(dev.device_number(relative), None);
  }

  /// A pseudo filesystem names itself as its own mount source, so there is
  /// nothing under `/dev/disk` to look for and the scan must be skipped — this
  /// is what keeps re-probing an absent identity on every resolve affordable.
  #[test]
  fn test_volume_identity_skips_sources_outside_dev() {
    for source in [&b"tmpfs"[..], b"proc", b"overlay", b"/home/user/image.img"] {
      assert_eq!(
        device_relative(Path::new(OsStr::from_bytes(source))),
        None,
        "{source:?}"
      );
    }
  }

  /// Whatever this platform answers, it answers from a name published about a
  /// device — there is no unprivileged call here that asks the filesystem
  /// itself. A host with no udev (a minimal container) reports nothing, and
  /// then there is no level to pin.
  #[test]
  fn test_a_linux_reading_is_published() {
    let (_, device, fs_type) = lookup_mountinfo(
      &proc_fixture(),
      Path::new("/"),
      &PinnedMount::of(Path::new("/")).unwrap(),
    )
    .unwrap();
    let dev = dev_fixture();
    let Some(source) = device_relative(device.as_path()).and_then(|r| dev.device_number(r)) else {
      // A root whose source is not a block device under `/dev` — a container
      // on overlayfs — has no identity to pin a level to.
      return;
    };
    let Some(reading) = volume_identity(
      &dev,
      source,
      fs_type.as_bytes(),
      IdentityAssurance::Published,
    ) else {
      return;
    };
    assert_eq!(
      reading.assurance(),
      super::super::IdentityAssurance::Published
    );
    assert!(!reading.is_vouched());
  }

  // ── btrfs: one FSID, however many devices carry it ─────────────────

  const FSID_A: &str = "9f27c3b1-4d5e-4a70-8b21-6c0d5e4f3a2b";
  const FSID_B: &str = "1c4e8a90-77bb-4d21-9f30-2ea5b6c7d8e9";

  /// Builds a `/sys/fs/btrfs`-shaped tree: one directory per filesystem, each
  /// holding `devices/<name>/dev` with the member's `major:minor`.
  /// The real, authenticated `/proc`, which the mount laws below read through.
  fn proc_fixture() -> KernelDir {
    proc_root().expect("procfs opens and authenticates on a Linux host")
  }

  /// The real `/dev`, which the udev laws below read through. These laws
  /// assert what is *not* found rather than what is, so they hold on any host.
  fn dev_fixture() -> KernelDir {
    KernelDir::open("/dev", None).expect("/dev opens on a Linux host")
  }

  /// A fixture tree standing in for the kernel's own `/sys/fs/btrfs`. It is
  /// opened as itself, with no magic to hold it to, and every road through it
  /// is the road the kernel's own root takes.
  fn fixture(root: &Path) -> KernelDir {
    KernelDir::fixture(root).expect("the fixture root opens")
  }

  /// Builds the tree the kernel builds, in the shape it builds it: the census
  /// lives at `fs/btrfs` under a `/sys` stand-in, and each member under
  /// `devices/` is a **symlink** to the block device's own directory elsewhere
  /// in the tree, which is what sysfs actually publishes. A fixture that made
  /// them plain directories would pass a census that refuses every real
  /// filesystem — it did, until a review caught it.
  fn btrfs_sysfs_fixture(root: &Path, filesystems: &[(&str, &[(&str, &str)])]) {
    for (fsid, members) in filesystems {
      for (name, dev) in *members {
        // Where the kernel keeps the device itself, outside `fs/btrfs`.
        let device_dir = root.join("devices").join(name);
        std::fs::create_dir_all(&device_dir).unwrap();
        std::fs::write(device_dir.join("dev"), format!("{dev}\n")).unwrap();

        let devices = btrfs_dir(root, fsid).join("devices");
        std::fs::create_dir_all(&devices).unwrap();
        let link = devices.join(name);
        if !std::fs::symlink_metadata(&link).is_ok() {
          std::os::unix::fs::symlink(Path::new("../../../../devices").join(name), &link).unwrap();
        }
      }
    }
  }

  /// Where one filesystem's directory sits under a `/sys` stand-in.
  fn btrfs_dir(root: &Path, fsid: &str) -> PathBuf {
    root.join(BTRFS_SYSFS_ROOT).join(fsid)
  }

  /// Marks an already-built fixture filesystem as carrying a temporary FSID,
  /// the way Linux 6.7+ does: `<fsid>/temp_fsid` containing `"1"`. Called
  /// after [`btrfs_sysfs_fixture`], which is what creates the `<fsid>`
  /// directory this writes into.
  fn mark_temp_fsid(root: &Path, fsid: &str) {
    std::fs::write(btrfs_dir(root, fsid).join("temp_fsid"), "1\n").unwrap();
  }

  /// Marks an already-built fixture filesystem as carrying a permanent
  /// FSID — the well-formed marker [`BtrfsLookup::Matched`] now requires on
  /// the matched candidate: `<fsid>/temp_fsid` containing `"0"`. Called
  /// after [`btrfs_sysfs_fixture`], which is what creates the `<fsid>`
  /// directory this writes into.
  fn mark_permanent_fsid(root: &Path, fsid: &str) {
    std::fs::write(btrfs_dir(root, fsid).join("temp_fsid"), "0\n").unwrap();
  }

  /// Adds a member directory that carries no `dev` file at all — the exact
  /// shape `sysfs_device_number` cannot read, so the census cannot tell
  /// whether this member is the device being looked up.
  fn add_member_without_dev_file(root: &Path, fsid: &str, name: &str) {
    std::fs::create_dir_all(btrfs_dir(root, fsid).join("devices").join(name)).unwrap();
  }

  /// Makes an already-built fixture filesystem's own `temp_fsid` unreadable
  /// for a reason other than "the file does not exist": a directory in its
  /// place, which `std::fs::read` reports as an I/O error regardless of
  /// which user runs the test. A permission bit would do the same on an
  /// ordinary run, but a root-run test — the container gate, typically —
  /// bypasses permission checks entirely and would silently read the file
  /// instead of failing to, which is exactly the environment-dependence
  /// [`TempFsidMarker::Unreadable`] must not have.
  fn make_temp_fsid_unreadable(root: &Path, fsid: &str) {
    std::fs::create_dir_all(btrfs_dir(root, fsid).join("temp_fsid")).unwrap();
  }

  fn fsid(text: &str) -> Option<VolumeIdentity> {
    super::super::parse_by_uuid_name(text.as_bytes())
  }

  /// The [`BtrfsLookup::Matched`] a clean census produces for `text`, as an
  /// `IdentityReading` at [`Published`](super::super::IdentityAssurance::Published)
  /// — the same reading [`btrfs_fsid_for_device`] itself builds.
  fn matched(text: &str) -> BtrfsLookup {
    BtrfsLookup::Matched(IdentityReading::published(fsid(text).unwrap()))
  }

  /// The finding, in the shape it arrives in: a btrfs filesystem spanning two
  /// devices is one volume with one FSID, and the kernel's map answers with
  /// that FSID for **either** member — including the one udev could not
  /// publish a link for, because both members carry the same name and only one
  /// link of that name can exist.
  #[test]
  fn test_btrfs_names_the_filesystem_whichever_member_is_mounted() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17"), ("sdc1", "8:33")])],
    );
    mark_permanent_fsid(dir.path(), FSID_A);

    for member in [makedev(8, 17), makedev(8, 33)] {
      let BtrfsLookup::Matched(reading) = btrfs_fsid_for_device(&fixture(dir.path()), member)
      else {
        panic!("a member of this filesystem must match");
      };
      assert_eq!(Some(reading.identity()), fsid(FSID_A));
      assert_eq!(
        reading.assurance(),
        super::super::IdentityAssurance::Published,
        "sysfs is the kernel naming a device, not the filesystem answering"
      );
    }
  }

  /// The other half of the same test, and the reason the mapping is needed:
  /// udev publishes one `/dev/disk/by-uuid` link for the filesystem, pointing
  /// at one member. Where `mountinfo` names the other member, the reverse
  /// lookup has nothing to match and answers `None` — which is what the kernel
  /// map is asked before it.
  #[test]
  fn test_the_by_uuid_link_names_a_member_and_the_kernel_map_names_the_filesystem() {
    let published = fsid(FSID_A).unwrap();
    // The numbers the kernel names the two members by.
    let linked = 0x0811_u64;
    let mounted = 0x0821_u64;

    assert_eq!(
      super::super::linux_identity_for_device(
        [(linked, published)].into_iter(),
        mounted,
        b"btrfs",
        IdentityAssurance::Published
      ),
      None,
      "the link names the member udev saw, and the mount is on the other one"
    );

    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17"), ("sdc1", "8:33")])],
    );
    mark_permanent_fsid(dir.path(), FSID_A);
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 33)),
      matched(FSID_A),
      "and the filesystem is named all the same"
    );
  }

  #[test]
  fn test_btrfs_answers_only_for_a_device_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[
        (FSID_A, &[("sdb1", "8:17")]),
        (FSID_B, &[("sdd1", "8:49"), ("sde1", "8:65")]),
      ],
    );

    mark_permanent_fsid(dir.path(), FSID_B);

    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 65)),
      matched(FSID_B),
      "each filesystem answers for its own members"
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81)),
      BtrfsLookup::Refused,
      "a device no btrfs filesystem here holds is refused, not read as evidence \
       this device isn't btrfs — mountinfo already settled that question"
    );
  }

  /// An unreadable root cannot be told apart from a masked one: a device
  /// already known (from `mountinfo`) to be mounted as btrfs has the driver
  /// loaded, which registers this directory unconditionally, so a root that
  /// cannot be enumerated is sysfs withholding the map — the whole census is
  /// indeterminate, never "no btrfs here."
  #[test]
  fn test_an_unreadable_sysfs_root_is_refused_not_treated_as_no_match() {
    // A root that cannot be opened at all never becomes a `KernelDir`, and
    // `btrfs_identity` refuses on exactly that. A root that opens but cannot
    // be enumerated is the case below.
    assert!(
      KernelDir::fixture(Path::new("/whichdisk-no-such-sysfs")).is_none(),
      "a root that is not there cannot stand in for the census"
    );

    // An empty root reads as a census that names no claimant, which this road
    // refuses rather than reading as "no btrfs here".
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a root that holds no claimant might have held the answer"
    );
  }

  /// `/sys/fs/btrfs` also holds entries that are not filesystems — `features`,
  /// and on newer kernels a flat `devices` list of every scanned device. Only a
  /// UUID names a filesystem, so nothing else is read as one. Both entries here
  /// are fully readable, so the census completes without a single I/O error —
  /// and is still refused: a *clean* census that names no claimant is exactly
  /// as much "not evidence this isn't btrfs" as a torn one. See the
  /// [`BtrfsLookup`] doc comment.
  #[test]
  fn test_btrfs_reads_only_uuid_named_directories_as_filesystems() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[
        ("features", &[("sdb1", "8:17")]),
        ("devices", &[("sdc1", "8:33")]),
      ],
    );
    // Neither lookup ever finds a UUID-named claimant, so `found` stays empty.
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a clean census finding nothing is still refused, not a match for `features`"
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 33)),
      BtrfsLookup::Refused,
      "same for `devices` — neither non-UUID entry is ever read as a filesystem"
    );
  }

  // ── btrfs: temporary FSIDs and shared seed devices ──────────────────

  /// A temporary FSID is a name this boot's mount chose, not one read off
  /// the volume — it does not survive to the next mount or the next machine,
  /// so it is not reported as this volume's identity at all. A marker
  /// actually read as `"1\n"` on the matched candidate refuses outright —
  /// there is no other signal left that could override it.
  #[test]
  fn test_a_temporary_fsid_is_not_an_identity() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    mark_temp_fsid(dir.path(), FSID_A);

    // The match's own marker reads `Temporary` directly.
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a runtime-only FSID changes across mounts and machines"
    );
  }

  /// A shared seed device is recognized read-only and can seed several
  /// sprouts at once, so its device number is legitimately linked into more
  /// than one filesystem's `devices/` directory. Nothing here can say which
  /// sprout the caller meant, so neither FSID is guessed.
  #[test]
  fn test_a_device_shared_by_two_filesystems_is_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdz1", "8:81")]), (FSID_B, &[("sdz1", "8:81")])],
    );

    // Ambiguity short-circuits before either claimant's own marker is ever
    // read.
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81)),
      BtrfsLookup::Refused,
      "a device claimed by more than one filesystem names none of them"
    );
  }

  /// The pre-existing single-match (one filesystem, one or two members) and
  /// per-member cases are covered above by
  /// [`test_btrfs_names_the_filesystem_whichever_member_is_mounted`] and
  /// [`test_btrfs_answers_only_for_a_device_it_holds`] — this test is the
  /// third leg: two *different* devices, each held by exactly one
  /// filesystem, are answered independently and correctly alongside a
  /// temp-fsid fixture and an ambiguous one, so neither narrowing leaks into
  /// an unrelated device's answer. Both need their own readable `Permanent`
  /// marker to match.
  #[test]
  fn test_ordinary_matches_are_unaffected_by_the_narrowings() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[
        (FSID_A, &[("sdb1", "8:17")]),
        (FSID_B, &[("sdd1", "8:49"), ("sde1", "8:65")]),
      ],
    );
    mark_permanent_fsid(dir.path(), FSID_A);
    mark_permanent_fsid(dir.path(), FSID_B);

    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      matched(FSID_A)
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 65)),
      matched(FSID_B)
    );
  }

  /// The temporary-FSID and shared-seed narrowings together: one of two
  /// claimants on the same device carries a temporary FSID. The ambiguity is
  /// decided from device membership alone, before either claimant's own
  /// marker is ever opened — which one, if either, turns out to be temporary
  /// never enters the decision.
  #[test]
  fn test_ambiguity_wins_even_when_one_claimant_is_temporary() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdz1", "8:81")]), (FSID_B, &[("sdz1", "8:81")])],
    );
    mark_temp_fsid(dir.path(), FSID_A);

    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81)),
      BtrfsLookup::Refused,
      "two filesystems still claim the device; which one is temporary does not matter"
    );
  }

  // ── btrfs: the census fails closed ───────────────────────────────────

  /// A candidate whose `devices/` directory cannot even be opened might have
  /// been the (or another) claimant of `rdev` — the old scan's `else {
  /// continue }` treated that exactly like "this filesystem has no members,"
  /// silently dropping it from the count instead of refusing to answer.
  #[test]
  fn test_an_unreadable_devices_directory_refuses_rather_than_being_skipped() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    // FSID_B exists (a valid UUID directory) but was never given a `devices/`
    // subdirectory at all — the shape a masked or half-populated `/sys` would
    // produce for a filesystem this scan cannot fully see.
    std::fs::create_dir_all(dir.path().join(FSID_B)).unwrap();

    // FSID_B's unreadable `devices/` refuses before any marker — its own or
    // FSID_A's — is ever read.
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "FSID_B's membership is unknown, not empty — it might have held 8:17 too"
    );
  }

  /// A member whose `dev` file is missing cannot be ruled out as `rdev` —
  /// the old scan's `Some(rdev) == sysfs_device_number(..)` comparison folded
  /// "unreadable" into "not a match" via `None != Some(rdev)`, so a filesystem
  /// with one broken member still answered confidently using its other,
  /// readable members.
  #[test]
  fn test_a_missing_member_dev_file_refuses_even_with_no_other_claimant() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    add_member_without_dev_file(dir.path(), FSID_A, "sdb2");

    // The unreadable member refuses from within the membership scan itself,
    // before FSID_A's own marker is ever read.
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "sdb2's device number is unknown; FSID_A cannot be confidently matched around it"
    );
  }

  // ── btrfs: only a readable Permanent marker matches ───────────────────
  //
  // See "A missing marker is refused, never guessed" on
  // `btrfs_fsid_for_device` for why a kernel-wide flag, a sibling's own
  // marker, and the running kernel's `uname(2)` release are all
  // untrustworthy proxies for pre-6.7 detection. Only the matched
  // candidate's own marker is ever consulted; these fixtures guard that.

  /// A sibling's own readable marker never substitutes for the matched
  /// candidate's. FSID_A, the match, carries no marker at all; FSID_B, an
  /// unrelated filesystem, carries a well-formed `Permanent` one — refused
  /// regardless, since FSID_A's own marker is missing and FSID_B's is never
  /// even opened, only the matched candidate's. Guards against a
  /// sibling-reading fallback ever coming back.
  #[test]
  fn test_a_readable_sibling_marker_never_substitutes_for_the_matched_candidates_own() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17")]), (FSID_B, &[("sdd1", "8:49")])],
    );
    std::fs::write(btrfs_dir(dir.path(), FSID_B).join("temp_fsid"), "0\n").unwrap();

    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "FSID_A's own marker is missing; FSID_B's readable one is never consulted"
    );
  }

  /// A uniformly silent sysfs view — no marker on the matched candidate,
  /// none on an unrelated sibling either — refuses regardless of which
  /// kernel is actually running underneath: real, spoofed via `UNAME26`, or
  /// a vendor backport that ships the attribute under a pre-6.7 release
  /// number. `btrfs_fsid_for_device` takes no release parameter, so there is
  /// no signal here that could distinguish those cases.
  #[test]
  fn test_uniform_omission_refuses_with_no_release_channel_left_to_spoof() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17")]), (FSID_B, &[("sdd1", "8:49")])],
    );

    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a missing marker refuses outright now — old kernel or new, real or spoofed"
    );
  }

  /// The matched candidate's own `temp_fsid` exists and cannot be read for a
  /// reason other than "it is missing" — a permission denial on a real
  /// kernel, simulated here as a directory in the file's place (see
  /// [`make_temp_fsid_unreadable`] for why a directory and not a permission
  /// bit). `NotFound` and every other read failure are told apart in
  /// [`TempFsidMarker`], but they land on the same refusal here: read but
  /// wrong, or not read at all, is not the well-formed `"0\n"`
  /// [`Matched`](BtrfsLookup::Matched) requires.
  #[test]
  fn test_an_unreadable_marker_on_the_matched_candidate_refuses() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    make_temp_fsid_unreadable(dir.path(), FSID_A);

    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a marker that exists but cannot be read is not a missing one, and is never permanent"
    );
  }

  // ── resolve/list level: a btrfs refusal never falls through ───────────
  //
  // `volume_identity` and `list` must never treat `btrfs_fsid_for_device`'s
  // refusal as an ordinary zero-match and fall through to
  // `/dev/disk/by-uuid`, which can hold a link naming exactly the identity
  // btrfs just declined to vouch for. These fixtures drive
  // `identity_after_btrfs` — the function every caller shares — the same
  // way `volume_identity`/`list` do: a `BtrfsLookup` from a sysfs fixture,
  // and a by-uuid answer, combined under the one rule. Where the rule says
  // by-uuid must not be consulted, the fixture's own by-uuid closure panics
  // if it ever runs, rather than merely happening to return the same answer
  // either way.
  //
  // (f) and (g) cover a caller-known btrfs mount whose census sees zero
  // claimants: that refusal must fall through to by-uuid no more than the
  // temporary, ambiguous, or malformed shapes above do. (g) adds the "not
  // literally empty, but still zero claimants" shape beside it.

  /// (a) A temporary FSID is refused, and refused must not fall through —
  /// not even to a by-uuid link that would itself answer with the identity
  /// this face just declined to report (a clone mounted beside its original
  /// still carries the on-disk FSID `blkid` read off it before the kernel
  /// remapped this mount to a fresh one).
  #[test]
  fn test_a_temporary_fsid_refusal_does_not_fall_through_to_by_uuid() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    mark_temp_fsid(dir.path(), FSID_A);

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17));
    assert_eq!(btrfs, BtrfsLookup::Refused);
    assert_eq!(
      identity_after_btrfs(btrfs, || panic!(
        "a temporary FSID's refusal must never consult by-uuid, even where a link would answer"
      )),
      None
    );
  }

  /// (b) Two seed claimants are refused, and refused must not fall through —
  /// not even to a matching by-uuid link, which for a seed device points at
  /// whichever sprout udev happened to see last.
  #[test]
  fn test_an_ambiguous_seed_claim_does_not_fall_through_to_by_uuid() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdz1", "8:81")]), (FSID_B, &[("sdz1", "8:81")])],
    );

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81));
    assert_eq!(btrfs, BtrfsLookup::Refused);
    assert_eq!(
      identity_after_btrfs(btrfs, || panic!(
        "an ambiguous seed claim must never consult by-uuid, even where a link would answer"
      )),
      None
    );
  }

  /// (c) A second claimant whose `dev` file is absent refuses the whole
  /// census — the ambiguity cannot be ruled out, so this is `Refused`, not a
  /// confident match on the one claimant that could be read — and, as ever,
  /// a refusal does not fall through to by-uuid.
  #[test]
  fn test_a_second_claimants_missing_dev_file_refuses_and_does_not_fall_through() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    add_member_without_dev_file(dir.path(), FSID_B, "sdz1");

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17));
    assert_eq!(
      btrfs,
      BtrfsLookup::Refused,
      "FSID_B's unreadable member might have been 8:17 too"
    );
    assert_eq!(
      identity_after_btrfs(btrfs, || panic!(
        "an unreadable second claimant must never consult by-uuid"
      )),
      None
    );
  }

  /// (d) A malformed `temp_fsid` — neither `"0\n"` nor `"1\n"` — refuses
  /// rather than defaulting to permanent, for both an garbled value and an
  /// empty file, and neither falls through to by-uuid.
  #[test]
  fn test_a_malformed_temp_fsid_refuses_and_does_not_fall_through() {
    for malformed in ["x\n", ""] {
      let dir = tempfile::tempdir().unwrap();
      btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
      std::fs::write(btrfs_dir(dir.path(), FSID_A).join("temp_fsid"), malformed).unwrap();

      let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17));
      assert_eq!(
        btrfs,
        BtrfsLookup::Refused,
        "{malformed:?} is neither \"0\\n\" nor \"1\\n\""
      );
      assert_eq!(
        identity_after_btrfs(btrfs, || panic!(
          "a malformed temp_fsid must never consult by-uuid"
        )),
        None
      );
    }
  }

  /// (e) The matched candidate carries a readable `Permanent` marker, and
  /// by-uuid is never consulted for a btrfs mount that already has an
  /// answer. A match requires the marker itself — silence is never read as
  /// permanent — so the fixture writes one directly.
  #[test]
  fn test_a_permanent_marker_matches_and_skips_by_uuid() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17")]), (FSID_B, &[("sdd1", "8:49")])],
    );
    mark_permanent_fsid(dir.path(), FSID_A);

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17));
    let expected = IdentityReading::published(fsid(FSID_A).unwrap());
    assert_eq!(btrfs, BtrfsLookup::Matched(expected));
    assert_eq!(
      identity_after_btrfs(btrfs, || panic!(
        "a matched FSID must never consult by-uuid"
      )),
      Some(expected)
    );
  }

  /// (f) A caller-known btrfs mount whose sysfs census sees zero claimants —
  /// a readable, genuinely empty `/sys/fs/btrfs` — refuses, and refused must
  /// not fall through, not even to a by-uuid link that would itself answer.
  /// A bind mount masking the real root, an FSID directory torn down between
  /// the `mountinfo` snapshot and this read, and teardown racing that
  /// snapshot are all exactly this shape from here, and none of them may be
  /// answered from `/dev/disk/by-uuid` in their place. No arm of
  /// `identity_after_btrfs` calls the by-uuid closure for this outcome (see
  /// its doc comment), so the panic-if-called closure below guards that
  /// promise structurally rather than by reading the match arms.
  #[test]
  fn test_zero_claimants_refuses_and_does_not_fall_through_to_by_uuid() {
    let dir = tempfile::tempdir().unwrap();

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17));
    assert_eq!(
      btrfs,
      BtrfsLookup::Refused,
      "a readable, empty sysfs root is not evidence this isn't btrfs — mountinfo already settled that"
    );
    assert_eq!(
      identity_after_btrfs(btrfs, || panic!(
        "zero claimants must never consult by-uuid, even where a link would answer"
      )),
      None
    );
  }

  /// (g) The same zero-claimant refusal, but the root is not literally
  /// empty — it holds an unrelated filesystem that does not claim this
  /// device, the shape sysfs would show for an FSID directory torn down
  /// between the `mountinfo` snapshot and this read. "Has structure, just
  /// not the one asked about" refuses exactly like "has nothing at all."
  #[test]
  fn test_a_truncated_root_refuses_and_does_not_fall_through_to_by_uuid() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_B, &[("sdd1", "8:49")])]);

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17));
    assert_eq!(
      btrfs,
      BtrfsLookup::Refused,
      "FSID_B exists but does not claim 8:17; the root is not empty, only the answer is"
    );
    assert_eq!(
      identity_after_btrfs(btrfs, || panic!(
        "a truncated root must never consult by-uuid, even where a link would answer"
      )),
      None
    );
  }

  #[test]
  fn test_sysfs_device_number() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixture(dir.path());
    let path = dir.path().join("dev");
    let relative = Path::new("dev");

    std::fs::write(&path, "8:17\n").unwrap();
    assert_eq!(sysfs_device_number(&root, relative), Some(makedev(8, 17)));
    // Extended device numbers use the same encoding mountinfo is parsed with.
    std::fs::write(&path, "259:0\n").unwrap();
    assert_eq!(sysfs_device_number(&root, relative), Some(makedev(259, 0)));
    // A file that is not one, and one that is not there.
    std::fs::write(&path, "not-a-device\n").unwrap();
    assert_eq!(sysfs_device_number(&root, relative), None);
    assert_eq!(sysfs_device_number(&root, Path::new("absent")), None);
  }

  /// `/dev/disk/by-label` holds one pathname per label, so a multi-device
  /// btrfs has a link for whichever member udev saw last and none for the
  /// rest. Mounted through any other member, the filesystem's real label was
  /// missed and the mount point's last component silently stood in for it.
  /// The kernel publishes the label beside the FSID, where every member
  /// reaches it.
  #[test]
  fn test_a_btrfs_label_is_read_where_every_member_can_reach_it() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17"), ("sdc1", "8:33")])],
    );
    mark_permanent_fsid(dir.path(), FSID_A);
    std::fs::write(btrfs_dir(dir.path(), FSID_A).join("label"), "BACKUP\n").unwrap();

    // Either member reaches the one label, which is the whole point.
    for member in [makedev(8, 17), makedev(8, 33)] {
      assert_eq!(
        btrfs_label(&fixture(dir.path()), member)
          .as_ref()
          .map(SmallBytes::as_bytes),
        Some(&b"BACKUP"[..]),
        "every member carries the filesystem's label"
      );
    }
  }

  /// An unlabelled filesystem writes the newline alone, which is no label
  /// rather than a label that is nothing — and a census that refuses refuses
  /// the label with it, never falling through to the by-label road.
  #[test]
  fn test_an_unlabelled_or_refused_btrfs_reports_no_label() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    mark_permanent_fsid(dir.path(), FSID_A);
    std::fs::write(btrfs_dir(dir.path(), FSID_A).join("label"), "\n").unwrap();
    assert_eq!(btrfs_label(&fixture(dir.path()), makedev(8, 17)), None);

    // A device no filesystem claims is a refusal, and a refusal is not a
    // licence to look elsewhere.
    assert_eq!(btrfs_label(&fixture(dir.path()), makedev(8, 99)), None);
  }

  /// A label is not an identity, and the marker that decides whether an FSID
  /// is durable must not decide whether the filesystem has a name.
  ///
  /// A pre-6.7 kernel publishes no `temp_fsid` attribute at all, so requiring
  /// a permanent marker before reading the label lost the real label of
  /// **every** btrfs volume on such a kernel — and of every uniquely-claimed
  /// temporary-FSID mount on newer ones — to the mount-point substitute.
  /// Membership decides the label; the marker decides the identity; both laws
  /// are asserted here together so the two cannot be conflated again.
  #[test]
  fn test_a_btrfs_label_does_not_wait_on_the_temp_fsid_marker() {
    // Pre-6.7: no marker to read at all.
    let older = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(older.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    std::fs::write(btrfs_dir(older.path(), FSID_A).join("label"), "BACKUP\n").unwrap();
    assert!(
      !btrfs_dir(older.path(), FSID_A).join("temp_fsid").exists(),
      "the fixture must be a kernel that never had the attribute"
    );
    assert_eq!(
      btrfs_label(&fixture(older.path()), makedev(8, 17))
        .as_ref()
        .map(SmallBytes::as_bytes),
      Some(&b"BACKUP"[..]),
      "a kernel with no marker still publishes the filesystem's label"
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(older.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "and the identity rule is unchanged: no marker, no identity"
    );

    // A temporary FSID, uniquely claimed: the FSID is this mount's alone, but
    // the filesystem is still the one this device belongs to and still carries
    // the label its owner wrote.
    let temporary = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(temporary.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    mark_temp_fsid(temporary.path(), FSID_A);
    std::fs::write(btrfs_dir(temporary.path(), FSID_A).join("label"), "CLONE\n").unwrap();
    assert_eq!(
      btrfs_label(&fixture(temporary.path()), makedev(8, 17))
        .as_ref()
        .map(SmallBytes::as_bytes),
      Some(&b"CLONE"[..])
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(temporary.path()), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a mount-time FSID is still no identity"
    );

    // Ambiguous membership is the one thing that does refuse a label: two
    // filesystems claiming one device means neither of their labels is this
    // device's.
    let shared = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      shared.path(),
      &[(FSID_A, &[("sdb1", "8:17")]), (FSID_B, &[("sdb1", "8:17")])],
    );
    std::fs::write(btrfs_dir(shared.path(), FSID_A).join("label"), "ONE\n").unwrap();
    std::fs::write(btrfs_dir(shared.path(), FSID_B).join("label"), "TWO\n").unwrap();
    assert_eq!(btrfs_label(&fixture(shared.path()), makedev(8, 17)), None);
  }

  /// A member under `devices/` is a symlink to the block device's own
  /// directory elsewhere under `/sys` — that is what sysfs publishes — and the
  /// census must follow it. Refusing it refused every real btrfs filesystem,
  /// which a fixture of plain directories could not show.
  #[test]
  fn test_the_census_follows_the_member_symlink_sysfs_publishes() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sda1", "8:17")])]);
    mark_permanent_fsid(dir.path(), FSID_A);

    // The fixture really is a link, or this law proves nothing.
    let member = btrfs_dir(dir.path(), FSID_A).join("devices").join("sda1");
    assert!(
      std::fs::symlink_metadata(&member).unwrap().is_symlink(),
      "the fixture must publish what sysfs publishes"
    );

    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)),
      BtrfsLookup::Matched(IdentityReading::published(fsid(FSID_A).unwrap())),
      "a member the kernel links to is a member"
    );
  }

  /// Whatever udev published, every accepted entry named a block device
  /// beneath the `/dev` root — an entry that did not is dropped rather than
  /// carried, because a number that is not a device number matches nothing a
  /// mount source can be resolved to.
  #[test]
  fn test_by_uuid_entries_resolve_to_block_devices() {
    let dev = dev_fixture();
    for (target, _identity) in by_uuid_entries(&dev) {
      assert_ne!(target, 0, "a block device is never device number zero");
    }
  }

  /// The label road answers out of the same directory tree, under the same
  /// root, and drops an entry the same way.
  #[test]
  fn test_by_label_entries_resolve_to_block_devices() {
    let dev = dev_fixture();
    for (target, label) in by_label_entries(&dev) {
      assert_ne!(target, 0, "a block device is never device number zero");
      assert!(!label.as_bytes().is_empty(), "an empty label is no label");
    }
  }

  // ── resolve relative_offset branches ───────────────────────────

  #[test]
  fn test_resolve_root() {
    let info = resolve(Path::new("/")).unwrap();
    assert_eq!(info.mount_info().mount_point(), Path::new("/"));
    assert_eq!(info.relative_path(), Path::new(""));
  }

  #[test]
  fn test_resolve_deep_path() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("a/b/c");
    std::fs::create_dir_all(&deep).unwrap();
    let info = resolve(&deep).unwrap();
    assert!(info.mount_info().mount_point().is_absolute());
    assert!(info.relative_path().is_relative());
  }

  #[test]
  fn test_resolve_cache_hit() {
    let info1 = resolve(Path::new("/")).unwrap();
    let info2 = resolve(Path::new("/")).unwrap();
    assert_eq!(
      info1.mount_info().mount_point(),
      info2.mount_info().mount_point()
    );
    assert_eq!(info1.mount_info().device(), info2.mount_info().device());
  }

  #[test]
  fn test_resolve_nonexistent() {
    assert!(resolve(Path::new("/nonexistent/xyz")).is_err());
  }

  /// Nothing about a mount is remembered between resolves on this backend.
  ///
  /// There used to be a thread-local entry keyed by `st_dev` and served while
  /// `statx`'s unique mount id still agreed. That id names the mount *object*
  /// and not where it is attached: `do_move_mount` reattaches an existing
  /// mount without minting a new one, so an entry built at `/old` stayed
  /// vouched for after the mount moved to `/new`, and a later resolve under
  /// `/new` was answered `/old`. The law is that every field of a resolve is
  /// what the mount table says for that path at that moment.
  #[test]
  fn test_the_resolve_reads_the_mount_table_rather_than_remembering_it() {
    let truth = lookup_mountinfo(
      &proc_fixture(),
      Path::new("/"),
      &PinnedMount::of(Path::new("/")).unwrap(),
    )
    .unwrap();

    // Read after the table above, and still the same facts: there is no entry
    // an earlier call could have filled in on this one's behalf.
    let resolved = resolve(Path::new("/")).unwrap();
    let mount = resolved.mount_info();
    assert_eq!(mount.mount_point(), truth.0.as_path());
    assert_eq!(mount.device(), truth.1.as_os_str());
    let expected = volume_capabilities(truth.2.as_bytes());
    assert_eq!(mount.capabilities().fs_type(), expected.fs_type());
  }

  /// And the store itself is gone, not merely unused: a resolve keeps no
  /// kernel state anywhere that outlives the call.
  #[test]
  fn test_the_backend_holds_no_mount_state_between_calls() {
    let first = resolve(Path::new("/")).unwrap();
    let second = resolve(Path::new("/")).unwrap();
    // Two independent reads of an unchanging mount agree, which is all a
    // caller was ever promised — and each of them is a read.
    assert_eq!(
      first.mount_info().mount_point(),
      second.mount_info().mount_point()
    );
    assert_eq!(first.mount_info().device(), second.mount_info().device());
    assert_eq!(
      first.mount_info().volume_identity(),
      second.mount_info().volume_identity()
    );
  }

  /// Builds the shape sysfs really publishes for a virtual device stacked on a
  /// partition of a real disk, under a `/sys` stand-in:
  ///
  /// ```text
  /// dev/block/<stack>          -> ../../devices/virtual/block/<stacked>
  /// dev/block/<disk partition> -> ../../devices/bus/<disk>/<partition>
  /// devices/virtual/block/<stacked>/slaves/<partition> -> the partition's own directory
  /// devices/bus/<disk>/<partition>/dev                  -> "major:minor"
  /// ```
  ///
  /// The two links are the point. `/sys/dev/block/<major>:<minor>` is a
  /// symlink — the number is an index and the directory lives under
  /// `/sys/devices` — and so is each name under `slaves/`. A fixture that made
  /// them plain directories would pass a walk that reaches nothing on a real
  /// kernel, which is exactly what happened until a review caught it.
  ///
  /// Returns the stacked device's number.
  fn slave_stack_fixture(root: &Path, disk: &str, partition: &str, part_dev: (u64, u64)) -> u64 {
    let stacked = "dm-0";
    let stack_dev = makedev(253, 0);

    let disk_dir = root.join("devices").join("bus").join(disk);
    let part_dir = disk_dir.join(partition);
    std::fs::create_dir_all(&part_dir).unwrap();
    std::fs::write(
      part_dir.join("dev"),
      format!("{}:{}\n", part_dev.0, part_dev.1),
    )
    .unwrap();

    let slaves = root
      .join("devices")
      .join("virtual")
      .join("block")
      .join(stacked)
      .join("slaves");
    std::fs::create_dir_all(&slaves).unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../../../bus").join(disk).join(partition),
      slaves.join(partition),
    )
    .unwrap();

    let block = root.join("dev").join("block");
    std::fs::create_dir_all(&block).unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../devices/virtual/block").join(stacked),
      block.join("253:0"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../devices/bus").join(disk).join(partition),
      block.join(format!("{}:{}", part_dev.0, part_dev.1)),
    )
    .unwrap();

    stack_dev
  }

  /// Marks the disk a partition belongs to as holding media that comes out,
  /// where the kernel holds it: on the disk above the partition.
  fn mark_disk_removable(root: &Path, disk: &str) {
    std::fs::write(
      root
        .join("devices")
        .join("bus")
        .join(disk)
        .join("removable"),
      "1\n",
    )
    .unwrap();
  }

  /// The finding, as a law: a directory reached through
  /// `/sys/dev/block/<major>:<minor>` is reached across a symlink, so the
  /// structural opener refuses it before the directory is ever read. The
  /// `slaves/` walk went through that opener and therefore never ran at all —
  /// every dm-crypt, LVM or MD volume over removable storage answered
  /// `Unknown` no matter what was underneath it.
  #[test]
  fn test_a_structural_open_cannot_reach_through_the_device_symlink() {
    let dir = tempfile::tempdir().unwrap();
    slave_stack_fixture(dir.path(), "sdb", "sdb1", (8, 17));
    let sysfs = fixture(dir.path());
    let slaves = Path::new("dev/block/253:0/slaves");

    assert!(
      sysfs.dir(slaves).is_none(),
      "symlinks refused: the walk opened nothing"
    );
    assert!(
      sysfs.dir_linked(slaves).is_some(),
      "the kernel's own link followed: the walk reads the slaves"
    );
  }

  /// A virtual device is as removable as the storage it is built from, and the
  /// walk that establishes it has to pass through two kernel-owned symlinks to
  /// get there.
  #[test]
  fn test_the_slaves_walk_carries_a_removable_disk_up_the_stack() {
    let dir = tempfile::tempdir().unwrap();
    let stack = slave_stack_fixture(dir.path(), "sdb", "sdb1", (8, 17));
    mark_disk_removable(dir.path(), "sdb");

    assert_eq!(
      device_ejectability(Some(&fixture(dir.path())), Some(stack)),
      Ejectability::Ejectable,
      "the disk under the stack says its media comes out"
    );
  }

  /// And where nothing underneath says so, the answer is `Unknown` — never a
  /// denial. Linux has no source that positively establishes a fixed drive, so
  /// a walk that found no yes has found nothing, not a no.
  #[test]
  fn test_a_stack_over_silent_storage_is_unknown_and_never_denied() {
    let dir = tempfile::tempdir().unwrap();
    let stack = slave_stack_fixture(dir.path(), "sdb", "sdb1", (8, 17));

    assert_eq!(
      device_ejectability(Some(&fixture(dir.path())), Some(stack)),
      Ejectability::Unknown
    );
  }

  /// The walk is bounded, and a stack that points at itself must terminate
  /// rather than recur until the stack does.
  #[test]
  fn test_the_slaves_walk_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let block = dir.path().join("dev").join("block");
    let device = dir
      .path()
      .join("devices")
      .join("virtual")
      .join("block")
      .join("dm-0");
    std::fs::create_dir_all(device.join("slaves")).unwrap();
    std::fs::write(device.join("dev"), "253:0\n").unwrap();
    std::fs::create_dir_all(&block).unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../devices/virtual/block/dm-0"),
      block.join("253:0"),
    )
    .unwrap();
    // The device is its own slave.
    std::os::unix::fs::symlink(Path::new(".."), device.join("slaves").join("dm-0")).unwrap();

    assert_eq!(
      device_ejectability(Some(&fixture(dir.path())), Some(makedev(253, 0))),
      Ejectability::Unknown
    );
  }

  /// Exercises the non-root mount-point prefix branch of `relative_offset`:
  /// on many Linux systems, /boot, /home, or /tmp are separate mounts.
  #[test]
  fn test_resolve_non_root_mount() {
    for candidate in ["/boot", "/home", "/tmp", "/var", "/proc"] {
      let p = Path::new(candidate);
      if !p.exists() {
        continue;
      }
      let info = resolve(p).unwrap();
      let _ = info.relative_path();
    }
  }
}
