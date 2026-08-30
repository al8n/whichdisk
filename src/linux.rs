use std::{
  cell::RefCell,
  collections::HashMap,
  ffi::OsStr,
  io,
  os::unix::ffi::OsStrExt,
  path::{Path, PathBuf},
};

use bytes::{BufMut, BytesMut};

use rustix::fs::stat;
#[cfg(feature = "disk-usage")]
use rustix::fs::statvfs;

use super::{IdentityReading, SmallBytes, VolumeCapabilities, VolumeIdentity};

/// What one mount looked like when it was last read out of
/// `/proc/self/mountinfo`.
///
/// There is deliberately no identity here, and adding one would re-open the
/// defect this shape exists to close: the key is `st_dev`, which names a mount
/// session rather than a volume, and nothing durable may be remembered under it.
/// See [`Witness`](super::Witness).
struct CacheEntry {
  mount_point: SmallBytes,
  device: SmallBytes,
  fs_type: SmallBytes,
  /// The unique mount id of the mount this entry was built from. Not optional:
  /// an entry exists only where the kernel had an id to give, so there is no
  /// such thing here as an entry nothing witnesses. See [`mount_witness`].
  witness: u64,
}

struct ThreadCache {
  mounts: HashMap<u64, CacheEntry>,
  removable: Option<Vec<PathBuf>>,
}

thread_local! {
  static CACHE: RefCell<ThreadCache> = RefCell::new(ThreadCache {
    mounts: HashMap::new(),
    removable: None,
  });
}

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

/// `STATX_MNT_ID_UNIQUE`, added in Linux 6.8. Requesting a mask bit the running
/// kernel does not know is not an error — it simply comes back unset in
/// `stx_mask` — which is how this asks for the id without demanding the kernel
/// that has it.
const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;

/// The witness for a cache entry: the id of the mount `path` is on.
///
/// The cache is keyed by `st_dev`, which the kernel reuses — for a block
/// filesystem it is the device node's number, handed to whatever media next
/// takes that node, and for everything else an anonymous number from a pool
/// that recycles. A key like that cannot say whether the volume behind it is
/// still the one an entry describes. The *unique* mount id can: the kernel
/// mints it per mount and never hands it out again, so an entry is good for
/// exactly as long as the mount it was built from.
///
/// `None` where the kernel has no such id to give — before Linux 6.8, or where
/// `statx` itself is unavailable. Nothing is witnessed then, and the cache is
/// simply not used: every resolve reads `/proc/self/mountinfo`, which is the
/// honest cost of a key that vouches for nothing. See
/// [`Witness`](super::Witness).
fn mount_witness(path: &Path) -> Option<u64> {
  let stx = rustix::fs::statx(
    rustix::fs::CWD,
    path,
    rustix::fs::AtFlags::empty(),
    rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE),
  )
  .ok()?;
  (stx.stx_mask & STATX_MNT_ID_UNIQUE != 0).then_some(stx.stx_mnt_id)
}

#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;
  let st = stat(&canonical).map_err(io::Error::from)?;
  let dev = st.st_dev;

  // Taken on every resolve: it is what tells a cache hit apart from a key the
  // kernel has since handed to different media.
  let witness = mount_witness(&canonical);

  // Try the thread-local cache first — it saves re-reading
  // /proc/self/mountinfo for paths on the same mount. Only an agreeing witness
  // opens it, and it then serves the entry whole: a witness that disagrees says
  // the mount is gone, and no witness at all says nothing, and neither is a
  // licence to reuse a single field. See [`Witness`](super::Witness).
  let cached = CACHE.with(|c| {
    c.borrow().mounts.get(&dev).and_then(|e| {
      super::Witness::of(Some(e.witness), witness)
        .holds()
        .then(|| (e.mount_point.clone(), e.device.clone(), e.fs_type.clone()))
    })
  });

  let (mount_point, device, fs_type) = match cached {
    Some(hit) => hit,
    None => {
      let (mp, dv, fst) = lookup_mountinfo(dev)?;
      // Stored only where the kernel gave an id to store it under. Before
      // Linux 6.8 there is none, and then this cache is never populated at
      // all — an entry no witness stands behind could only ever be a miss.
      if let Some(witness) = witness {
        CACHE.with(|c| {
          c.borrow_mut().mounts.insert(
            dev,
            CacheEntry {
              mount_point: mp.clone(),
              device: dv.clone(),
              fs_type: fst.clone(),
              witness,
            },
          );
        });
      }
      (mp, dv, fst)
    }
  };

  // Read on every resolve, and deliberately never stored, exactly as the Apple
  // backend reads its own. `st_dev` names a mount session rather than a volume,
  // so no key here can vouch that a remembered identity still belongs to the
  // media behind it — and the two facts this derives it from, the mount source
  // and its filesystem type, are the same ones the witness above just vouched
  // for. The scan it costs is bounded: a mount source outside `/dev` skips it
  // outright, which is the hot "no identity" case.
  let volume_identity = volume_identity(device.as_path(), fs_type.as_bytes());

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

  let ejectable = is_ejectable(mount_point.as_path(), device.as_os_str());

  #[cfg(feature = "disk-usage")]
  let (total_bytes, available_bytes) = {
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    match statvfs(&canonical) {
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
      is_ejectable: ejectable,
      capabilities,
      volume_identity,
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
  let removable = CACHE.with(|c| {
    let mut cache = c.borrow_mut();
    cache
      .removable
      .get_or_insert_with(get_removable_devices)
      .clone()
  });
  // One scan for the whole enumeration, rather than one per mount. Two names
  // resolving to one device node disagree about what is behind it, and the
  // enumeration answers that the same way a single resolve does — with no
  // identity, rather than with whichever the directory yielded last. See
  // [`linux_identity_for_device`](super::linux_identity_for_device).
  let mut by_uuid: HashMap<PathBuf, Option<VolumeIdentity>> = HashMap::new();
  for (target, identity) in by_uuid_entries() {
    by_uuid
      .entry(target)
      .and_modify(|seen| {
        if *seen != Some(identity) {
          *seen = None;
        }
      })
      .or_insert(Some(identity));
  }
  let mountinfo = std::fs::read("/proc/self/mountinfo")?;
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

    if let Some((_, _, mp_raw, fs_type_raw, source_raw)) = parse_mountinfo_line(line) {
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

      let dev_path = Path::new(OsStr::from_bytes(source_raw));
      let is_ejectable = removable.iter().any(|r| r == dev_path);
      if opts.is_ejectable_only() && !is_ejectable {
        continue;
      }
      if opts.is_non_ejectable_only() && is_ejectable {
        continue;
      }
      let device = decode_octal_escapes(source_raw);
      let capabilities = volume_capabilities(fs_type_raw);
      let identity = dev_path.canonicalize().ok().and_then(|resolved| {
        let by_uuid_answer = || {
          by_uuid
            .get(&resolved)
            .copied()
            .flatten()
            .and_then(|published| super::linux_identity(fs_type_raw, published))
        };
        // Same order as a resolve: the kernel's own map first for btrfs, whose
        // members all carry one FSID and so cannot each have a by-uuid link.
        // A refusal is not a zero-match: see [`identity_after_btrfs`].
        if super::is_btrfs(fs_type_raw) {
          identity_after_btrfs(btrfs_identity(&resolved), by_uuid_answer)
        } else {
          by_uuid_answer()
        }
      });
      #[cfg(feature = "disk-usage")]
      let (total_bytes, available_bytes) = {
        let mp_path = mp.as_path();
        #[allow(clippy::unnecessary_cast)]
        match statvfs(mp_path) {
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
        }
      };
      mounts.push(super::MountPoint {
        mount_point: mp,
        device,
        is_ejectable,
        capabilities,
        volume_identity: identity,
        #[cfg(feature = "disk-usage")]
        total_bytes,
        #[cfg(feature = "disk-usage")]
        available_bytes,
      });
    }
  }
  Ok(mounts)
}

/// Checks if a device is removable by looking it up in `/dev/disk/by-id/`
/// for symlinks whose name starts with `usb-`.
/// The removable-device list is cached per-thread to avoid repeated scans.
pub(super) fn is_ejectable(_mount_point: &Path, device: &OsStr) -> bool {
  CACHE.with(|c| {
    let mut cache = c.borrow_mut();
    let removable = cache.removable.get_or_insert_with(get_removable_devices);
    removable.iter().any(|r| r.as_os_str() == device)
  })
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
fn volume_identity(device: &Path, fs_type: &[u8]) -> Option<IdentityReading> {
  // A mount source that is not a device node cannot be under `/dev/disk`, and
  // this is the hot case: `tmpfs`, `proc`, `sysfs`, `overlay` and every other
  // pseudo filesystem names itself here. Skipping the scan for them is what
  // makes reading the identity on every resolve cheap enough to do.
  if !device.as_os_str().as_bytes().starts_with(b"/dev/") {
    return None;
  }
  // The mount source can itself be a symlink (`/dev/mapper/...`), so resolve
  // both sides before comparing.
  let device = device.canonicalize().ok()?;
  let by_uuid_answer = || super::linux_identity_for_device(by_uuid_entries(), &device, fs_type);
  // Ask the kernel which filesystem the device belongs to before asking udev
  // what name it published for it: only the first can answer for a filesystem
  // whose members are several and whose mounted one is not the member udev's
  // single link happens to point at. See [`btrfs_fsid_for_device`]. A refusal
  // is not a zero-match: [`identity_after_btrfs`] consults `by_uuid_answer`
  // only where btrfs says the device is under no FSID of its at all.
  if super::is_btrfs(fs_type) {
    return identity_after_btrfs(btrfs_identity(&device), by_uuid_answer);
  }
  by_uuid_answer()
}

/// Where the kernel publishes which filesystem each btrfs device belongs to.
const BTRFS_SYSFS_ROOT: &str = "/sys/fs/btrfs";

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
fn btrfs_identity(device: &Path) -> BtrfsLookup {
  // `device` was canonicalized moments ago by the caller, so a `stat` failure
  // here is not "not btrfs" — it is this call losing the very device number
  // the census below is keyed on. Nothing that follows could be trusted
  // either way, so this is a census failure like any other: see
  // [`btrfs_fsid_for_device`].
  let Ok(st) = stat(device) else {
    return BtrfsLookup::Refused;
  };
  btrfs_fsid_for_device(Path::new(BTRFS_SYSFS_ROOT), st.st_rdev)
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
fn btrfs_fsid_for_device(sysfs_root: &Path, rdev: u64) -> BtrfsLookup {
  let Ok(entries) = std::fs::read_dir(sysfs_root) else {
    return BtrfsLookup::Refused;
  };

  // The one filesystem seen so far whose `devices/` holds `rdev`, kept
  // alongside its own sysfs directory rather than resolved to an answer
  // immediately: a second claimant found later must be able to void this one
  // unread, so its `temp_fsid` is never even opened for a device that turns
  // out ambiguous.
  let mut found: Option<(VolumeIdentity, PathBuf)> = None;

  for filesystem in entries {
    // A dirent whichdisk itself failed to read: the enumeration is only
    // partial, and what it would have shown is exactly what the rest of this
    // function exists to answer.
    let Ok(filesystem) = filesystem else {
      return BtrfsLookup::Refused;
    };
    // Only an FSID names a filesystem here. The directory also holds
    // `features`, and on newer kernels a flat `devices` list of every scanned
    // device, neither of which is a UUID.
    let name = filesystem.file_name();
    let Some(fsid @ VolumeIdentity::FsUuid(_)) = super::parse_by_uuid_name(name.as_bytes()) else {
      continue;
    };
    let path = filesystem.path();
    let Ok(members) = std::fs::read_dir(path.join("devices")) else {
      // This candidate's own membership could not be read. It might have
      // been the (or another) claimant of `rdev`; a partial view of it is
      // exactly as untrustworthy as a partial view of the root.
      return BtrfsLookup::Refused;
    };
    let mut holds_rdev = false;
    for member in members {
      let Ok(member) = member else {
        return BtrfsLookup::Refused;
      };
      match sysfs_device_number(&member.path().join("dev")) {
        Some(dev) if dev == rdev => holds_rdev = true,
        Some(_) => {}
        // Missing, unreadable, or malformed `dev` file for one member. That
        // file is exactly what would decide whether this member is `rdev`;
        // unable to read it, this member can be neither ruled in nor out.
        None => return BtrfsLookup::Refused,
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
      return BtrfsLookup::Refused;
    }
    found = Some((fsid, path));
  }

  let Some((fsid, path)) = found else {
    // A device `mountinfo` already named as btrfs, that this census names no
    // claimant for at all: never `NoMatch`. That answer would license
    // `by_uuid_answer`, which can hold exactly the value this refusal exists
    // to withhold — see the doc comment above, [`BtrfsLookup`], and
    // [`identity_after_btrfs`].
    return BtrfsLookup::Refused;
  };

  // The one road left to `Matched`: the sole, unambiguous claimant's own
  // marker, read now that ambiguity is already ruled out. See the "A missing
  // marker is refused, never guessed" section above.
  match read_temp_fsid_marker(&path) {
    TempFsidMarker::Permanent => BtrfsLookup::Matched(IdentityReading::published(fsid)),
    // A mount-time-only FSID, chosen fresh by this boot's mount — never the
    // volume's own.
    TempFsidMarker::Temporary => BtrfsLookup::Refused,
    // Read, but neither `"0\n"` nor `"1\n"` — not the well-formed marker a
    // match requires.
    TempFsidMarker::Malformed => BtrfsLookup::Refused,
    // The file exists but could not be read: never folded into "missing,"
    // and never permanent — see [`TempFsidMarker`].
    TempFsidMarker::Unreadable => BtrfsLookup::Refused,
    // Missing outright. A pre-6.7 kernel that never installed the attribute
    // and a masked or namespaced view on a kernel that does are the same
    // fact from here, and neither is guessed past — refused either way.
    TempFsidMarker::NotFound => BtrfsLookup::Refused,
  }
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
fn read_temp_fsid_marker(filesystem_dir: &Path) -> TempFsidMarker {
  match std::fs::read(filesystem_dir.join("temp_fsid")) {
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
fn sysfs_device_number(path: &Path) -> Option<u64> {
  let contents = std::fs::read(path).ok()?;
  let line = contents.split(|&b| b == b'\n').next()?;
  let colon = super::find_byte(b':', line)?;
  Some(makedev(
    parse_u64(&line[..colon])?,
    parse_u64(&line[colon + 1..])?,
  ))
}

/// Yields every `/dev/disk/by-uuid` entry whose name names an identity we
/// understand, as `(resolved device node, identity)`. Entries that do not
/// resolve, or whose name is not a recognizable identity, are skipped.
///
/// The identity here is classified from the name's width alone; the caller
/// still has to pass it through [`linux_identity`](super::linux_identity) with
/// the mount's filesystem type to reach the canonical form.
fn by_uuid_entries() -> impl Iterator<Item = (PathBuf, VolumeIdentity)> {
  std::fs::read_dir("/dev/disk/by-uuid")
    .into_iter()
    .flatten()
    .filter_map(|entry| {
      let entry = entry.ok()?;
      let name = entry.file_name();
      let identity = super::parse_by_uuid_name(name.as_bytes())?;
      Some((entry.path().canonicalize().ok()?, identity))
    })
}

/// Scans `/dev/disk/by-id/` for symlinks starting with `usb-` and
/// canonicalizes them to get the actual device paths (e.g. `/dev/sdb1`).
fn get_removable_devices() -> Vec<PathBuf> {
  match std::fs::read_dir("/dev/disk/by-id/") {
    Ok(entries) => entries
      .filter_map(|res| Some(res.ok()?.path()))
      .filter_map(|entry| {
        let name = entry.file_name()?;
        if name.to_str()?.starts_with("usb-") {
          entry.canonicalize().ok()
        } else {
          None
        }
      })
      .collect(),
    Err(_) => Vec::new(),
  }
}

/// Reads `/proc/self/mountinfo` and finds the entry matching `target_dev`.
/// Returns `(mount_point, device, fs_type)`.
fn lookup_mountinfo(target_dev: u64) -> io::Result<(SmallBytes, SmallBytes, SmallBytes)> {
  let mountinfo = std::fs::read("/proc/self/mountinfo")?;

  let mut best: Option<(SmallBytes, SmallBytes, SmallBytes)> = None;
  let mut best_len: usize = 0;
  let mut start = 0;

  // Use memchr to split lines instead of byte-by-byte closure.
  while start < mountinfo.len() {
    let end = super::find_byte(b'\n', &mountinfo[start..])
      .map(|pos| start + pos)
      .unwrap_or(mountinfo.len());

    let line = &mountinfo[start..end];
    start = end + 1;

    if line.is_empty() {
      continue;
    }

    if let Some((dev_major, dev_minor, mp_raw, fs_type_raw, source_raw)) =
      parse_mountinfo_line(line)
    {
      // Compare major:minor against stat's st_dev using Linux makedev encoding.
      let line_dev = makedev(dev_major, dev_minor);
      if line_dev != target_dev {
        continue;
      }

      // Among entries for the same device, pick the longest mount point
      // (handles bind mounts where multiple entries share a device).
      let mp = decode_octal_escapes(mp_raw);
      if mp.as_bytes().len() > best_len {
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
/// Returns `(major, minor, mount_point_raw, fs_type_raw, source_raw)`.
#[allow(clippy::type_complexity)]
fn parse_mountinfo_line(line: &[u8]) -> Option<(u64, u64, &[u8], &[u8], &[u8])> {
  let mut fields = line.split(|&b| b == b' ');

  fields.next()?; // mount_id
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

  Some((major, minor, mount_point_raw, fs_type_raw, source_raw))
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
    let (major, minor, mp, _fs_type, source) = parse_mountinfo_line(line).unwrap();
    assert_eq!(major, 98);
    assert_eq!(minor, 0);
    assert_eq!(mp, b"/mnt");
    assert_eq!(source, b"/dev/root");
  }

  #[test]
  fn test_parse_mountinfo_with_optional_fields() {
    // Multiple optional fields before the separator
    let line = b"100 50 8:1 / /boot rw master:1 shared:2 - ext4 /dev/sda1 rw";
    let (major, minor, mp, _fs_type, source) = parse_mountinfo_line(line).unwrap();
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

  // ── decode_octal_escapes ──────────────────────────────────────────

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

  #[test]
  fn test_lookup_mountinfo_nonexistent_dev() {
    // Device 0xDEADBEEF should not exist
    let result = lookup_mountinfo(0xDEAD_BEEF);
    assert!(result.is_err());
  }

  #[test]
  fn test_lookup_mountinfo_returns_fs_type() {
    // The root filesystem must resolve, and its mountinfo entry must carry a
    // non-empty fs type.
    let st = stat(Path::new("/")).unwrap();
    let (mp, _device, fs_type) = lookup_mountinfo(st.st_dev).unwrap();
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

  #[test]
  fn test_volume_identity_unknown_device_is_none() {
    assert_eq!(
      volume_identity(Path::new("/dev/whichdisk-no-such-device"), b"ext4"),
      None
    );
  }

  /// A pseudo filesystem names itself as its own mount source, so there is
  /// nothing under `/dev/disk` to look for and the scan must be skipped — this
  /// is what keeps re-probing an absent identity on every resolve affordable.
  #[test]
  fn test_volume_identity_skips_sources_outside_dev() {
    for source in [&b"tmpfs"[..], b"proc", b"overlay", b"/home/user/image.img"] {
      assert_eq!(
        volume_identity(Path::new(OsStr::from_bytes(source)), b"tmpfs"),
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
    let dev = stat(Path::new("/")).unwrap().st_dev;
    let (_, device, fs_type) = lookup_mountinfo(dev).unwrap();
    let Some(reading) = volume_identity(device.as_path(), fs_type.as_bytes()) else {
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
  fn btrfs_sysfs_fixture(root: &Path, filesystems: &[(&str, &[(&str, &str)])]) {
    for (fsid, members) in filesystems {
      for (name, dev) in *members {
        let member = root.join(fsid).join("devices").join(name);
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("dev"), format!("{dev}\n")).unwrap();
      }
    }
  }

  /// Marks an already-built fixture filesystem as carrying a temporary FSID,
  /// the way Linux 6.7+ does: `<fsid>/temp_fsid` containing `"1"`. Called
  /// after [`btrfs_sysfs_fixture`], which is what creates the `<fsid>`
  /// directory this writes into.
  fn mark_temp_fsid(root: &Path, fsid: &str) {
    std::fs::write(root.join(fsid).join("temp_fsid"), "1\n").unwrap();
  }

  /// Marks an already-built fixture filesystem as carrying a permanent
  /// FSID — the well-formed marker [`BtrfsLookup::Matched`] now requires on
  /// the matched candidate: `<fsid>/temp_fsid` containing `"0"`. Called
  /// after [`btrfs_sysfs_fixture`], which is what creates the `<fsid>`
  /// directory this writes into.
  fn mark_permanent_fsid(root: &Path, fsid: &str) {
    std::fs::write(root.join(fsid).join("temp_fsid"), "0\n").unwrap();
  }

  /// Adds a member directory that carries no `dev` file at all — the exact
  /// shape `sysfs_device_number` cannot read, so the census cannot tell
  /// whether this member is the device being looked up.
  fn add_member_without_dev_file(root: &Path, fsid: &str, name: &str) {
    std::fs::create_dir_all(root.join(fsid).join("devices").join(name)).unwrap();
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
    std::fs::create_dir_all(root.join(fsid).join("temp_fsid")).unwrap();
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
      let BtrfsLookup::Matched(reading) = btrfs_fsid_for_device(dir.path(), member) else {
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
    let linked = Path::new("/dev/sdb1");
    let mounted = Path::new("/dev/sdc1");

    assert_eq!(
      super::super::linux_identity_for_device([(linked, published)].into_iter(), mounted, b"btrfs"),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 33)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 65)),
      matched(FSID_B),
      "each filesystem answers for its own members"
    );
    assert_eq!(
      btrfs_fsid_for_device(dir.path(), makedev(8, 81)),
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
    assert_eq!(
      btrfs_fsid_for_device(Path::new("/whichdisk-no-such-sysfs"), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a root that cannot be enumerated might have held the answer"
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
      BtrfsLookup::Refused,
      "a clean census finding nothing is still refused, not a match for `features`"
    );
    assert_eq!(
      btrfs_fsid_for_device(dir.path(), makedev(8, 33)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 81)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
      matched(FSID_A)
    );
    assert_eq!(
      btrfs_fsid_for_device(dir.path(), makedev(8, 65)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 81)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
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
    std::fs::write(dir.path().join(FSID_B).join("temp_fsid"), "0\n").unwrap();

    assert_eq!(
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
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
      btrfs_fsid_for_device(dir.path(), makedev(8, 17)),
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

    let btrfs = btrfs_fsid_for_device(dir.path(), makedev(8, 17));
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

    let btrfs = btrfs_fsid_for_device(dir.path(), makedev(8, 81));
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

    let btrfs = btrfs_fsid_for_device(dir.path(), makedev(8, 17));
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
      std::fs::write(dir.path().join(FSID_A).join("temp_fsid"), malformed).unwrap();

      let btrfs = btrfs_fsid_for_device(dir.path(), makedev(8, 17));
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

    let btrfs = btrfs_fsid_for_device(dir.path(), makedev(8, 17));
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

    let btrfs = btrfs_fsid_for_device(dir.path(), makedev(8, 17));
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

    let btrfs = btrfs_fsid_for_device(dir.path(), makedev(8, 17));
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
    let path = dir.path().join("dev");

    std::fs::write(&path, "8:17\n").unwrap();
    assert_eq!(sysfs_device_number(&path), Some(makedev(8, 17)));
    // Extended device numbers use the same encoding mountinfo is parsed with.
    std::fs::write(&path, "259:0\n").unwrap();
    assert_eq!(sysfs_device_number(&path), Some(makedev(259, 0)));
    // A file that is not one, and one that is not there.
    std::fs::write(&path, "not-a-device\n").unwrap();
    assert_eq!(sysfs_device_number(&path), None);
    assert_eq!(sysfs_device_number(&dir.path().join("absent")), None);
  }

  #[test]
  fn test_by_uuid_entries_resolve_to_device_nodes() {
    // Whatever udev published, every accepted entry must resolve to a real node
    // under /dev — otherwise the match against a mount source is meaningless.
    for (target, _identity) in by_uuid_entries() {
      assert!(target.starts_with("/dev"), "{target:?}");
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

  #[test]
  fn test_mount_witness_names_the_mount_not_the_path() {
    let Some(root) = mount_witness(Path::new("/")) else {
      // Before Linux 6.8 there is no unique mount id to take, and then the
      // cache is never populated at all.
      return;
    };
    assert_eq!(Some(root), mount_witness(Path::new("/")));
    // Every path on one mount is on one mount.
    assert_eq!(Some(root), mount_witness(Path::new("/etc")));
  }

  /// An entry exists only where the kernel had a mount id to key it to. Before
  /// Linux 6.8 there is none, and then nothing is stored: there is no such
  /// thing here as an unwitnessed entry for a later resolve to half-believe.
  #[test]
  fn test_only_a_witnessed_mount_is_ever_stored() {
    CACHE.with(|c| c.borrow_mut().mounts.clear());
    let dev = stat(Path::new("/")).unwrap().st_dev;
    resolve(Path::new("/")).unwrap();

    let stored = CACHE.with(|c| c.borrow().mounts.get(&dev).map(|e| e.witness));
    assert_eq!(
      stored,
      mount_witness(Path::new("/")),
      "an entry is stored exactly when there is a witness to store it under"
    );
  }

  /// The entry describes a mount, and the witness is what says whether that
  /// mount is still there. Poison one under the root's `st_dev` as replaced
  /// media would, and no field of it may be served — the filesystem type least
  /// of all, since that is what decides the form the identity takes, so a stale
  /// `exfat` here would not merely mislabel the volume, it would mint a UUID
  /// for it out of the departed volume's format.
  ///
  /// The literal below is exhaustive, so an identity added back to the entry
  /// breaks this test rather than passing it.
  #[test]
  fn test_no_field_of_an_unvouched_entry_is_served() {
    let truth = resolve(Path::new("/")).unwrap();
    let dev = stat(Path::new("/")).unwrap().st_dev;

    CACHE.with(|c| {
      c.borrow_mut().mounts.insert(
        dev,
        CacheEntry {
          mount_point: SmallBytes::from_bytes(b"/nowhere"),
          device: SmallBytes::from_bytes(b"/dev/gone"),
          fs_type: SmallBytes::from_bytes(b"exfat"),
          // No mount ever carried this one.
          witness: u64::MAX,
        },
      );
    });

    let after = resolve(Path::new("/")).unwrap();
    assert_eq!(after.mount_info().mount_point(), Path::new("/"));
    assert_eq!(
      after.mount_info().device(),
      truth.mount_info().device(),
      "the replaced volume's device must not survive its mount"
    );
    assert_eq!(
      after.mount_info().capabilities().fs_type(),
      truth.mount_info().capabilities().fs_type(),
      "nor the filesystem type the identity's form is derived from"
    );
    assert_eq!(
      after.mount_info().volume_identity(),
      truth.mount_info().volume_identity(),
      "nor its identity"
    );
  }

  /// The other side of the same rule: an agreeing witness is what opens an
  /// entry, and it opens it whole. Skipped before Linux 6.8, where there is no
  /// witness to agree and so nothing is ever served from here.
  #[test]
  fn test_an_agreeing_witness_serves_the_entry() {
    let Some(witness) = mount_witness(Path::new("/")) else {
      return;
    };
    let dev = stat(Path::new("/")).unwrap().st_dev;
    let marker = SmallBytes::from_bytes(b"/whichdisk-served-from-the-cache");

    CACHE.with(|c| {
      c.borrow_mut().mounts.insert(
        dev,
        CacheEntry {
          mount_point: marker.clone(),
          device: SmallBytes::from_bytes(b"/dev/null"),
          fs_type: SmallBytes::from_bytes(b"ext4"),
          witness,
        },
      );
    });

    let hit = resolve(Path::new("/")).unwrap();
    assert_eq!(hit.mount_info().mount_point(), marker.as_path());
    assert_eq!(hit.mount_info().device(), Path::new("/dev/null"));
    // Leave nothing behind for the next resolve on this thread.
    CACHE.with(|c| c.borrow_mut().mounts.clear());
  }

  /// The identity is read on every resolve rather than remembered, so a hit
  /// reports what `/dev/disk/by-uuid` says now — from the mount source and
  /// filesystem type the witness just vouched for.
  #[test]
  fn test_the_identity_is_read_on_every_resolve() {
    let first = resolve(Path::new("/")).unwrap();
    let hit = resolve(Path::new("/")).unwrap();
    let dev = stat(Path::new("/")).unwrap().st_dev;
    let (_, device, fs_type) = lookup_mountinfo(dev).unwrap();

    assert_eq!(
      hit.mount_info().volume_identity(),
      volume_identity(device.as_path(), fs_type.as_bytes()),
      "a cache hit carries no identity of its own to serve"
    );
    assert_eq!(
      first.mount_info().volume_identity(),
      hit.mount_info().volume_identity()
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
