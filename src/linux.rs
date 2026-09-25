//! Linux: every value in a row is read from one observation of one mount.
//!
//! **An observation is formed once, from one native identity, and a row is
//! built from nothing else.** The identity is the mount id a pinned `O_PATH`
//! descriptor holds — `statx`'s `STATX_MNT_ID` where the kernel has it, the
//! `mnt_id:` line of the descriptor's own `fdinfo` where it does not, and a
//! named refusal where neither answers. The observation is the mount table
//! line that id names in a table read while the pin is held, and **every fact
//! of the row is read when the observation is formed, inside [`observed`], and
//! stored in it**: the capacity through the pin, and the identity, the label
//! and the removal answer out of the one resolution of that line's source,
//! beneath the `/proc`, `/dev` and `/sys` roots the observation's own
//! constructor opens. A btrfs mount's source is bound through the filesystem
//! itself: its FSID and its label, asked through a descriptor held to the
//! pinned mount, and the one census of the kernel's btrfs map that names that
//! FSID for the source. The row
//! is built by [`Observation::into_row`], whose only input is the observation
//! itself: no root, path, table or field can be handed to it. Pinning a
//! pathname, choosing a line and reading a fact are private to [`observed`],
//! so no row road can do any of them. A device number never identifies a
//! mount — `st_dev` is recycled, and a btrfs subvolume's never appears in the
//! table at all — and neither does path text.
//!
//! **A row's facts are read only after its binding is proven, on every
//! feature set.** A resolve pins the object the caller named; a listing pins
//! every row's mount point, and a row is the line its pin's held id names in
//! the table read again while the pin is held — wherever that mount is now —
//! or it is not reported: see [`resolve`] and [`list`]. The pin, every
//! pathname the row is read through and the mount table all belong to the
//! calling thread: the table is read beneath the thread's own procfs
//! directory, because a thread may have entered a mount namespace of its own.
//! What a row's facts are read out of — the filesystem roster, udev's
//! censuses — is read only after its binding, and never kept for a row bound
//! later; and **a fact is read only about the device that backs the mount**:
//! a source binds only where its node is the `major:minor` the kernel printed
//! for the mount, and a source that does not bind has nothing read about it.
//!
//! **Every platform read answers one of four outcomes** — a value, the
//! platform's own "there is none", a decline [`declined`] names, or a failure
//! — and no two are merged except where a caller names what each means: see
//! [`Reading`]. Every directory is read by [`listing`], to the end the kernel
//! proves; the mount table is read only whole, by [`MountTable::read`], and
//! every record of it strictly, by [`parse_record`]; and a census is read
//! whole or refused.

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
  fs::{Mode, OFlags, ResolveFlags},
};

use super::{
  Ejectability, IdentityAssurance, IdentityReading, SmallBytes, VolumeCapabilities, VolumeIdentity,
  reading::{Census, Reading},
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
/// without demanding the kernel that has it. A kernel without it answers the
/// same question through the descriptor's `fdinfo`: see [`observed`].
///
/// `STATX_MNT_ID_UNIQUE` (Linux 6.8) used to be read beside it, to witness a
/// cache entry. That cache is gone and so is the read: the unique id names the
/// mount *object* rather than its attachment, and a move-mount reattaches the
/// object without minting a new one — see [`resolve`].
const STATX_MNT_ID: u32 = 0x0000_1000;

/// The most a descriptor's `fdinfo` is read to. The kernel writes four short
/// lines for an `O_PATH` descriptor, and the mount id is the third.
const FDINFO_LIMIT: u64 = 4 * 1024;

/// Whether a failed read is this platform declining to answer, rather than the
/// read itself failing.
///
/// Every platform read on this backend is sorted by this set into the four
/// outcomes of a [`Reading`] — see [`reading`] — and every road that reports a
/// value with no "could not tell" of its own — the identity, the label, a
/// capacity — ends in its documented absence on these failures, and on nothing
/// else:
///
/// - **not there**, or not there as the thing asked for: `ENOENT`, `ENOTDIR`,
///   `EISDIR`, and `ENODEV` / `ENXIO` for a device that has gone;
/// - **may not look**: `EACCES`, `EPERM`;
/// - **refused by the containment**: `EXDEV` for a mount interposed on the
///   way, `ELOOP` for a symlink where a structural read forbids one — the
///   refusals [`KernelDir`] exists to make, beside the root that is not the
///   filesystem it must be, which [`KernelDir::open`] declines itself;
/// - **not implemented**: `ENOSYS` — a kernel without `openat2` or `statx` —
///   `EOPNOTSUPP`, and `ENOTTY`, a filesystem that does not serve an ioctl.
///
/// Anything else — a full descriptor table, no memory, an I/O error — is a
/// failure of this process or of the machine. It says nothing about the
/// volume, so it is returned as the error it is, never reported as a volume
/// with no identity, no label or no capacity.
fn declined(err: &io::Error) -> bool {
  use rustix::io::Errno;

  const DECLINES: [Errno; 12] = [
    Errno::NOENT,
    Errno::NOTDIR,
    Errno::ISDIR,
    Errno::NODEV,
    Errno::NXIO,
    Errno::ACCESS,
    Errno::PERM,
    Errno::XDEV,
    Errno::LOOP,
    Errno::NOSYS,
    Errno::OPNOTSUPP,
    Errno::NOTTY,
  ];
  Errno::from_io_error(err).is_some_and(|errno| DECLINES.contains(&errno))
}

/// Sorts what a platform call on this backend returned by the decline set
/// above, into the four outcomes every read here answers: see [`Reading`].
fn reading<T, E: Into<io::Error>>(read: Result<T, E>) -> Reading<T> {
  Reading::sort(read.map_err(Into::into), declined)
}

/// The one observation a Linux row is formed from, and the only place a row's
/// object is pinned, its mount table line chosen, or a fact of it read.
///
/// **Facts about one mount must be sampled together or they are facts about
/// two.** An `O_PATH` descriptor names the object the caller asked about and
/// keeps naming it: a mount landing on top afterwards does not move it. It is
/// held while the row is formed, and that is what makes the mount id it holds
/// an identity: a descriptor keeps a reference to its mount, a mount id returns
/// to the allocator only when its mount is freed, so while the pin lives its id
/// names this mount and no other. In a mount table read after the pin was
/// taken, that id's line is this mount's line — wherever it is attached now.
///
/// **The id comes from the descriptor, by one of two kernel doors, or not at
/// all.** `statx` names it where the kernel has `STATX_MNT_ID` (Linux 5.8);
/// before that, the descriptor's own `fdinfo` carries it as `mnt_id:` (Linux
/// 3.15), read beneath the authenticated `/proc` at the calling thread's own
/// descriptor table. A kernel that names it through neither is a named
/// refusal. What the id is never inferred from is a device number: `st_dev`
/// is handed to the next mount once the first goes away, bind mounts and
/// stacked mounts share one, and btrfs gives every subvolume an anonymous
/// number the table never prints — so a line chosen by it can be another
/// mount's, and a btrfs subvolume's path could never be resolved by it.
///
/// **Every fact of a row is read here, once, and stored in the observation.**
/// The roots the facts are read beneath are opened by the constructor itself
/// ([`Roots`](observed::Roots)); what the facts are read out of — the
/// filesystem roster and udev's censuses — is read only after the row is
/// bound, from a table read while its pin is held
/// ([`Facts`](observed::Facts), one per resolve and per batch of listed
/// pins); the line's source is resolved once, and binds only where its node is
/// the device the kernel printed for the mount itself — or, for btrfs, a
/// member of the filesystem the pinned mount answers for through a descriptor
/// held to it; and the removal answer, the identity, the label and the
/// capacity are all read from that one binding and that one pin. A btrfs
/// mount's FSID and label are the filesystem's own answer through one
/// descriptor, and its identity the one census of the kernel's btrfs map that
/// names that FSID, so a membership change between two reads cannot pair one
/// filesystem's FSID with another's label. The row is built by
/// [`Observation::into_row`], which takes the observation by value and is
/// given nothing beside it.
mod observed {
  use std::{cell::OnceCell, ffi::OsStr, io, os::unix::ffi::OsStrExt as _, path::Path};

  use rustix::{
    fd::{AsRawFd as _, OwnedFd},
    fs::{Mode, OFlags},
  };

  #[cfg(feature = "list")]
  use std::collections::HashMap;

  use super::{
    super::{
      BlockBackedTypes, Ejectability, IdentityAssurance, IdentityReading, MountPoint, NameReading,
      SmallBytes, VolumeIdentity, is_btrfs, linux_identity_for_device,
    },
    FDINFO_LIMIT, KernelDir, MountLine, MountTable, Reading, STATX_MNT_ID, UdevCensus, reading,
  };

  /// The object a row describes, pinned, and the mount id the pin holds.
  pub(super) struct Pinned {
    /// Held for its own sake as much as for its reads: the reference it keeps
    /// to its mount is what stops the kernel from freeing the mount and handing
    /// its id to another one while the row is formed. It is read for the
    /// capacity, and a btrfs mount's root pin is reopened through it: see
    /// [`BtrfsMount::of`].
    fd: OwnedFd,
    mount_id: u64,
  }

  impl Pinned {
    /// Pins `path` with one `O_PATH` descriptor and reads the mount id that
    /// descriptor holds.
    ///
    /// The open's own outcome where it does not open. Where it opens and the
    /// kernel names no mount id through either door, a decline that says so —
    /// never a guess at the mount by any other road.
    pub(super) fn of(path: &Path, proc_root: &KernelDir) -> Reading<Self> {
      reading(rustix::fs::open(
        path,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
      ))
      .and_then(|fd| match held_mount_id(&fd, proc_root) {
        Reading::Value(mount_id) => Reading::Value(Self { fd, mount_id }),
        Reading::Absent => Reading::Declined(io::Error::new(
          io::ErrorKind::Unsupported,
          "the kernel names no mount id for the pinned descriptor: statx answered \
           without STATX_MNT_ID and its fdinfo carries no mnt_id",
        )),
        Reading::Declined(err) => Reading::Declined(err),
        Reading::Failed(err) => Reading::Failed(err),
      })
    }

    /// The mount id this pin holds, for the laws.
    #[cfg(test)]
    pub(super) fn mount_id(&self) -> u64 {
      self.mount_id
    }

    /// The capacity of the mount this pin holds, as `(total, available)`
    /// bytes.
    ///
    /// `fstatfs` — which is what `fstatvfs` is built on — is permitted on an
    /// `O_PATH` descriptor, so nothing needs to be opened for access to read a
    /// capacity. A filesystem that keeps no statistics has none to report,
    /// which is zero; a statistics read that failed is the error it is.
    #[cfg(feature = "disk-usage")]
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    fn capacity(&self) -> io::Result<(u64, u64)> {
      Ok(match reading(rustix::fs::fstatvfs(&self.fd)).answered()? {
        Some(vfs) => {
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
        None => (0, 0),
      })
    }
  }

  /// The mount id the kernel names a descriptor's mount by: `statx` first,
  /// then the descriptor's own `fdinfo`.
  ///
  /// A `statx` that answered without the mask bit, or that the platform
  /// declined — a kernel without `statx`, a filter refusing it — hands the
  /// question to `fdinfo`; one that failed is the error it is. `Absent` where
  /// `fdinfo` carries no mount id either.
  fn held_mount_id(fd: &OwnedFd, proc_root: &KernelDir) -> Reading<u64> {
    match statx_mount_id(fd) {
      Reading::Value(id) => Reading::Value(id),
      Reading::Absent | Reading::Declined(_) => fdinfo_mount_id(fd, proc_root),
      Reading::Failed(err) => Reading::Failed(err),
    }
  }

  /// `statx` of the descriptor itself, for `STATX_MNT_ID`. `Absent` where the
  /// kernel answered without it.
  fn statx_mount_id(fd: &OwnedFd) -> Reading<u64> {
    reading(rustix::fs::statx(
      fd,
      "",
      rustix::fs::AtFlags::EMPTY_PATH,
      rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID),
    ))
    .and_then(|stx| {
      if stx.stx_mask & STATX_MNT_ID != 0 {
        Reading::Value(stx.stx_mnt_id)
      } else {
        Reading::Absent
      }
    })
  }

  /// The `mnt_id:` line of the descriptor's own `fdinfo` (Linux 3.15), read
  /// beneath the authenticated `/proc` at the calling thread's directory —
  /// the descriptor table this number was handed out in. `Absent` where the
  /// file carries no `mnt_id:` line (a kernel before 3.15); a file or a
  /// `thread-self` link the kernel could not have written is
  /// `Failed(InvalidData)`.
  fn fdinfo_mount_id(fd: &OwnedFd, proc_root: &KernelDir) -> Reading<u64> {
    super::procfs_thread(proc_root)
      .and_then(|thread| {
        let number = fd.as_raw_fd().to_string();
        let path = KernelDir::at(&[&thread, b"fdinfo", number.as_bytes()]);
        proc_root.read_bounded(Path::new(OsStr::from_bytes(&path)), FDINFO_LIMIT)
      })
      .and_then(|contents| match super::parse_fdinfo_mount_id(&contents) {
        Ok(Some(id)) => Reading::Value(id),
        Ok(None) => Reading::Absent,
        Err(err) => Reading::Failed(err),
      })
  }

  /// The roots every fact of an observation is read beneath: handles, and
  /// nothing read through them. Opened by an observation's constructor, and
  /// by nothing outside this module.
  pub(super) struct Roots {
    /// The authenticated `/proc`: the mount table, the mount id's second door
    /// and the kernel's filesystem table are read beneath it.
    proc: KernelDir,
    /// The authenticated `/dev` every source is resolved beneath, or `None`
    /// where the platform declined it — a road closed, not an error.
    dev: Option<KernelDir>,
    /// The `/sys` the removal question is asked beneath, opened the first time
    /// a bound device is in hand: see [`removal_root`](super::removal_root).
    removal: OnceCell<Option<KernelDir>>,
  }

  impl Roots {
    /// The authenticated `/proc`, which the mount table has no road but, so
    /// one that is not there or is not procfs ends the operation with the
    /// error that says so; and the authenticated `/dev`, where one that is not
    /// there is a road closed. Either failing to open is the error it is. See
    /// [`Reading`].
    fn open() -> io::Result<Self> {
      let proc = super::proc_root().required()?;
      let dev = KernelDir::open("/dev", None).answered()?;
      Ok(Self {
        proc,
        dev,
        removal: OnceCell::new(),
      })
    }

    /// The `/sys` the removal question is asked beneath, or `None` wherever it
    /// could not be had — which fails nothing: see
    /// [`removal_root`](super::removal_root).
    fn removal(&self) -> Option<&KernelDir> {
      self.removal.get_or_init(super::removal_root).as_ref()
    }

    /// The roots, opened as an observation opens them, for the laws.
    #[cfg(test)]
    pub(super) fn open_for_laws() -> io::Result<Self> {
      Self::open()
    }

    /// The removal question's `/sys`, for the laws.
    #[cfg(test)]
    pub(super) fn sysfs_for_laws(&self) -> Option<&KernelDir> {
      self.removal()
    }

    /// The authenticated `/dev`, for the laws.
    #[cfg(test)]
    pub(super) fn dev_for_laws(&self) -> Option<&KernelDir> {
      self.dev.as_ref()
    }

    /// What the facts of `line`'s row are read out of: the device that backs
    /// the mount the line is, where its source names it — and, for btrfs, the
    /// filesystem's own answer through the pinned mount.
    ///
    /// The source is resolved once beneath `/dev` to the number the kernel
    /// names its node by, and kept only where that number is proven to back
    /// the mount `pinned` holds:
    ///
    /// - **It is the device the kernel printed for the mount itself** —
    ///   `major:minor`, the device of the mount's superblock — in a table read
    ///   while the mount was pinned.
    /// - **Or, for btrfs, which prints an anonymous device for every mount, it
    ///   is a member of the very filesystem the pinned mount is**: the
    ///   kernel's btrfs map, read once, names exactly the FSID the filesystem
    ///   answered as the one filesystem the node is a member of.
    ///
    /// **A btrfs mount's identity and label need no source at all.** They are
    /// the filesystem answering for itself through a descriptor held to the
    /// pinned mount ([`BtrfsMount::of`]) — the FSID, where its own marker says
    /// it outlives the mount ([`btrfs_durable`](super::btrfs_durable)), and the
    /// label — so a container whose `/dev` carries no disk nodes still has
    /// them. The source binding decides only the facts about the source
    /// device: the removal answer.
    ///
    /// A source is a pathname, and a pathname is not the mount: a node or a
    /// link retargeted since the mount was made, and a device an unprivileged
    /// mounter named for a filesystem no device backs (tmpfs, FUSE), name a
    /// device the mount is not on, and **no fact is read about a device that
    /// did not bind** — no identity, no label, no removal answer.
    fn bind(&self, line: &MountLine, pinned: &Pinned) -> io::Result<Binding> {
      let node = match (&self.dev, super::device_relative(line.source.as_path())) {
        (Some(dev), Some(relative)) => dev.device_number(relative).answered()?,
        _ => None,
      };
      if let Some(node) = node.filter(|&node| node == line.device) {
        return Ok(Binding::Device(node));
      }
      if !is_btrfs(line.fs_type.as_bytes()) {
        return Ok(Binding::Unbound);
      }
      let Some(mount) = BtrfsMount::of(line, pinned, &self.proc)? else {
        return Ok(Binding::Unbound);
      };
      // The map the durability marker and the membership are both read from,
      // opened once; one that would not open leaves the FSID no identity and
      // the source no binding.
      let Some(sysfs) = super::btrfs_sysfs().answered()? else {
        return Ok(btrfs_binding(None, mount, false));
      };
      let durable = super::btrfs_durable(&sysfs, &mount.fsid)?;
      let census = match node {
        Some(node) => Some(super::btrfs_census(&sysfs, node)?),
        None => None,
      };
      let member = bound_member(node, census, mount.fsid);
      Ok(btrfs_binding(member, mount, durable))
    }
  }

  /// The source device a btrfs mount's binding carries: the source's node,
  /// where the one census of the kernel's map names exactly the FSID the
  /// filesystem answered as the node's one filesystem — and `None` where the
  /// source resolved to no node, to a node of no filesystem or of another, or
  /// to a seed several filesystems share.
  pub(super) fn bound_member(
    node: Option<u64>,
    census: Option<super::BtrfsCensus>,
    fsid: VolumeIdentity,
  ) -> Option<u64> {
    match (node, census) {
      (Some(node), Some(super::BtrfsCensus::Member { fsid: holder })) if holder == fsid => {
        Some(node)
      }
      _ => None,
    }
  }

  /// A btrfs mount's binding: the filesystem's own answer through the pinned
  /// mount, whether its FSID outlives the mount, and the source device where
  /// one is bound — see [`bound_member`]. The source decides the removal
  /// answer and nothing else.
  fn btrfs_binding(member: Option<u64>, mount: BtrfsMount, durable: bool) -> Binding {
    Binding::Btrfs {
      mount,
      durable,
      device: member,
    }
  }

  /// The identity and the label a btrfs mount reports, out of its
  /// filesystem's own answer through the pinned mount alone: the FSID, where
  /// its marker says it outlives the mount, and the label, whatever the
  /// marker says — each at the level the mount's own line earns. By-uuid is
  /// never consulted in the identity's place.
  pub(super) fn btrfs_facts(
    mount: BtrfsMount,
    durable: bool,
    assurance: IdentityAssurance,
  ) -> (Option<IdentityReading>, Option<NameReading>) {
    let lookup = if durable {
      super::BtrfsLookup::Matched(IdentityReading::published(mount.fsid))
    } else {
      super::BtrfsLookup::Refused
    };
    let identity = super::identity_after_btrfs(lookup.at(assurance), || Ok(None));
    let name = mount.label.map(|name| NameReading { name, assurance });
    (identity, name)
  }

  /// What a line's source is bound to: see [`Roots::bind`].
  pub(super) enum Binding {
    /// Nothing: no fact is read about the source.
    Unbound,
    /// The block device the kernel printed for the mount.
    Device(u64),
    /// A btrfs mount: the FSID and the label its filesystem answered through
    /// the pinned mount, whether that FSID outlives the mount, and the member
    /// device the source was bound to, if it was.
    Btrfs {
      mount: BtrfsMount,
      durable: bool,
      device: Option<u64>,
    },
  }

  impl Binding {
    /// The device the source is bound to, which the removal question is asked
    /// about.
    fn device(&self) -> Option<u64> {
      match self {
        Self::Unbound => None,
        Self::Device(device) => Some(*device),
        Self::Btrfs { device, .. } => *device,
      }
    }
  }

  /// What a btrfs filesystem says of itself through a descriptor bound to the
  /// pinned mount: its FSID and its label, one observation.
  pub(super) struct BtrfsMount {
    fsid: VolumeIdentity,
    label: Option<SmallBytes>,
  }

  impl BtrfsMount {
    /// What a filesystem answered, standing in for a live one's, for the laws.
    #[cfg(test)]
    pub(super) fn for_laws(fsid: VolumeIdentity, label: Option<&[u8]>) -> Self {
      Self {
        fsid,
        label: label.map(SmallBytes::from_bytes),
      }
    }

    /// Asks the btrfs filesystem the pinned mount is for its FSID and its
    /// label, through one descriptor proven to hold that mount — or `None`
    /// where no such descriptor could be had or the filesystem did not answer.
    ///
    /// 1. **The line's mount point is pinned again**, `O_PATH` — which
    ///    triggers no automount and opens nothing — and taken only where that
    ///    pin holds the same mount id as `pinned`: a mount point covered by
    ///    another mount, or a mount that moved, pins something else, and is
    ///    not asked. Held while the rest is read, the id names this mount and
    ///    no other.
    /// 2. **That pin is reopened for reading through its own descriptor**, the
    ///    one component of the calling thread's `fd/` directory beneath the
    ///    authenticated `/proc` that names it: the object the pin holds, with
    ///    no path walked again. `O_DIRECTORY`, so it is the mount's root
    ///    directory and nothing a read could disturb; a mount of a file, or a
    ///    root this process may not read, is declined.
    /// 3. **The reopened descriptor holds the same mount, on btrfs**: its own
    ///    mount id is the pin's, and its `fstatfs` is `BTRFS_SUPER_MAGIC`.
    /// 4. **Both questions are asked of it**: `BTRFS_IOC_FS_INFO` for the FSID
    ///    and `FS_IOC_GETFSLABEL` for the label — the filesystem answering for
    ///    itself, through the mount, needing no privilege.
    ///
    /// Every decline on the way is `None`; a read that failed is the error it
    /// is. An FSID that is all zeros is no FSID mkfs writes, and binds nothing.
    fn of(line: &MountLine, pinned: &Pinned, proc: &KernelDir) -> io::Result<Option<Self>> {
      let Some(fd) = mount_root(line, pinned, proc)? else {
        return Ok(None);
      };
      match reading(rustix::fs::fstatfs(&fd)).answered()? {
        Some(fs) if super::is_btrfs_magic(fs.f_type) => {}
        _ => return Ok(None),
      }
      let Some(fsid) = super::btrfs_fs_info(&fd).answered()? else {
        return Ok(None);
      };
      if fsid == [0; super::btrfs_fs_info::FSID_LEN] {
        return Ok(None);
      }
      let label = super::btrfs_fs_label(&fd).answered()?.flatten();
      Ok(Some(Self {
        fsid: VolumeIdentity::FsUuid(fsid),
        label,
      }))
    }
  }

  /// The root of the mount `pinned` holds, opened for reading through a pin
  /// held to that same mount — steps 1 to 3 of [`BtrfsMount::of`] — or `None`
  /// where no such descriptor could be had: a mount point covered by another
  /// mount, a mount that moved, a root this process may not read. A read that
  /// failed is the error it is.
  fn mount_root(
    line: &MountLine,
    pinned: &Pinned,
    proc: &KernelDir,
  ) -> io::Result<Option<OwnedFd>> {
    let root = match Pinned::of(line.mount_point.as_path(), proc) {
      Reading::Value(root) if root.mount_id == pinned.mount_id => root,
      Reading::Value(_) | Reading::Absent | Reading::Declined(_) => return Ok(None),
      Reading::Failed(err) => return Err(err),
    };
    let Some(fd) = reopened(&root, proc).answered()? else {
      return Ok(None);
    };
    if held_mount_id(&fd, proc).answered()? != Some(pinned.mount_id) {
      return Ok(None);
    }
    Ok(Some(fd))
  }

  /// The root's line, in a table read while the root is pinned, and the pin:
  /// for the laws.
  #[cfg(test)]
  pub(super) fn root_line_for_laws(roots: &Roots) -> Option<(MountLine, Pinned)> {
    let pinned = Pinned::of(Path::new("/"), &roots.proc).required().ok()?;
    let table = HeldTable::read(&roots.proc, &[&pinned]).ok()?;
    let line = table.0.line(pinned.mount_id)?.clone();
    Some((line, pinned))
  }

  /// [`mount_root`], every failure `None`, for the laws.
  #[cfg(test)]
  pub(super) fn mount_root_for_laws(
    line: &MountLine,
    pinned: &Pinned,
    roots: &Roots,
  ) -> Option<OwnedFd> {
    mount_root(line, pinned, &roots.proc).ok().flatten()
  }

  /// `pinned`'s own object, opened for reading through the magic link the
  /// calling thread's descriptor table has for it — `<tid>/fd/<n>` beneath
  /// the authenticated `/proc`, the directory reached structurally and the one
  /// component that names the descriptor followed. What it opens is the object
  /// the pin holds, whatever has happened to any path to it since.
  fn reopened(pinned: &Pinned, proc: &KernelDir) -> Reading<OwnedFd> {
    super::procfs_thread(proc)
      .and_then(|thread| {
        let fds = KernelDir::at(&[&thread, b"fd"]);
        reading(proc.open_beneath(
          Path::new(OsStr::from_bytes(&fds)),
          OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
          rustix::fs::ResolveFlags::NO_SYMLINKS,
        ))
      })
      .and_then(|fds| {
        let number = pinned.fd.as_raw_fd().to_string();
        reading(rustix::fs::openat(
          &fds,
          number.as_str(),
          OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOCTTY,
          Mode::empty(),
        ))
      })
  }

  /// A mount table read while the pin of every row formed from it was held:
  /// the only table a row's line is chosen from, and what a [`Facts`] is read
  /// after.
  pub(super) struct HeldTable(MountTable);

  impl HeldTable {
    /// The table, read now, while `pins` are held: the caller hands over the
    /// pins it holds, so no table read before them can be one of these.
    fn read(proc: &KernelDir, _pins: &[&Pinned]) -> io::Result<Self> {
      MountTable::read(proc).map(Self)
    }
  }

  /// Everything the facts of the rows one [`HeldTable`] binds are read out
  /// of: the kernel's filesystem roster and udev's two censuses.
  ///
  /// **Read only after the rows are bound, and never carried to other rows.**
  /// A `Facts` exists only once a table has been read while its rows' pins
  /// were held, so nothing in it can predate the binding of a row it serves;
  /// and it is dropped with those rows — a listing reads one per batch of
  /// pins — so a census read for one bound set of rows never answers for a
  /// row bound later, after a device number could have been reused or udev
  /// could have moved a link.
  pub(super) struct Facts<'r> {
    roots: &'r Roots,
    /// The kernel's own filesystem table: the level a read through a mount
    /// source earns. See [`BlockBackedTypes`].
    block_backed: BlockBackedTypes,
    /// One census of `/dev/disk/by-uuid`, read the first time a row of these
    /// needs it.
    by_uuid: OnceCell<UdevCensus<VolumeIdentity>>,
    /// One census of `/dev/disk/by-label`, the same way.
    by_label: OnceCell<UdevCensus<SmallBytes>>,
  }

  impl<'r> Facts<'r> {
    /// The facts of the rows `held` binds, read beneath `roots` from now on.
    fn after(roots: &'r Roots, _held: &HeldTable) -> io::Result<Self> {
      Ok(Self {
        roots,
        block_backed: super::block_backed_types(&roots.proc)?,
        by_uuid: OnceCell::new(),
        by_label: OnceCell::new(),
      })
    }

    /// The census of `/dev/disk/by-uuid`, read whole or refused; with no `/dev`
    /// to read it beneath, refused. See [`udev_entries`](super::udev_entries).
    fn by_uuid(&self) -> io::Result<&UdevCensus<VolumeIdentity>> {
      if let Some(census) = self.by_uuid.get() {
        return Ok(census);
      }
      let census = match &self.roots.dev {
        Some(dev) => super::by_uuid_entries(dev)?,
        None => UdevCensus::Refused,
      };
      Ok(self.by_uuid.get_or_init(|| census))
    }

    /// The census of `/dev/disk/by-label`, the same way.
    fn by_label(&self) -> io::Result<&UdevCensus<SmallBytes>> {
      if let Some(census) = self.by_label.get() {
        return Ok(census);
      }
      let census = match &self.roots.dev {
        Some(dev) => super::by_label_entries(dev)?,
        None => UdevCensus::Refused,
      };
      Ok(self.by_label.get_or_init(|| census))
    }
  }

  /// One mount, observed: its table line and every fact of its row, read when
  /// the observation was formed.
  pub(super) struct Observation {
    line: MountLine,
    ejectability: Ejectability,
    identity: Option<IdentityReading>,
    name: Option<NameReading>,
    #[cfg(feature = "disk-usage")]
    capacity: (u64, u64),
  }

  impl Observation {
    /// A resolve's observation, formed whole: the roots opened, `canonical`
    /// pinned, the mount table read while the pin is held, the line the pin's
    /// held id names in it — a table read before the pin could name a mount
    /// that is gone — and every fact of the row read from that line's source
    /// and that pin.
    pub(super) fn of_path(canonical: &Path) -> io::Result<Self> {
      let roots = Roots::open()?;
      let pinned = Pinned::of(canonical, &roots.proc).required()?;
      let table = HeldTable::read(&roots.proc, &[&pinned])?;
      let facts = Facts::after(&roots, &table)?;
      Self::resolved(&pinned, canonical, &table, &facts)
    }

    /// The line `pinned`'s held id names in `table`, which must still contain
    /// the path that was pinned, formed into its observation.
    ///
    /// No line carrying the id, and a line that does not contain the path,
    /// are both refusals: nothing is returned rather than something.
    fn resolved(
      pinned: &Pinned,
      canonical: &Path,
      table: &HeldTable,
      facts: &Facts<'_>,
    ) -> io::Result<Self> {
      let line = table.0.line(pinned.mount_id).ok_or_else(|| {
        io::Error::new(
          io::ErrorKind::NotFound,
          "no line of the mount table carries the pinned mount's id",
        )
      })?;
      // Named, and still held to describing the path that was pinned. A mount
      // the path is not inside answers for some other path entirely, whether
      // it moved away since the path was canonicalized or the table was
      // written to say so, and taking nothing is the honest end of either.
      if !super::contains_path(
        line.mount_point.as_bytes(),
        canonical.as_os_str().as_bytes(),
      ) {
        return Err(io::Error::new(
          io::ErrorKind::NotFound,
          "the mountinfo row carrying this mount id does not contain the path",
        ));
      }
      let (binding, ejectability, mounted) = Self::source_device(line, pinned, facts.roots)?;
      Self::formed(line.clone(), binding, ejectability, mounted, pinned, facts)
    }

    /// A listing row, formed into its observation where the options keep it:
    /// the source and the removal answer first, so that a row the options
    /// leave out has nothing else read about it.
    ///
    /// `line` is the line `pinned`'s held id names in a table read while the
    /// pin was held — the only line a listing forms anything from: see
    /// [`listing`].
    #[cfg(feature = "list")]
    fn listed(
      line: MountLine,
      pinned: &Pinned,
      facts: &Facts<'_>,
      opts: super::super::ListOptions,
    ) -> io::Result<Option<Self>> {
      let (binding, ejectability, mounted) = Self::source_device(&line, pinned, facts.roots)?;
      // Exact states: a volume of unknown ejectability is named by neither
      // only-filter, so it is excluded by either. See `ListOptions::excludes`.
      if opts.excludes(ejectability) {
        return Ok(None);
      }
      Self::formed(line, binding, ejectability, mounted, pinned, facts).map(Some)
    }

    /// The line's source, bound to the mount `pinned` holds — see
    /// [`Roots::bind`] — the identity the mounted filesystem names itself by
    /// through the mount, where it names one, and what the kernel says about
    /// the device's removal, bound to that identity and to one attach of the
    /// device: see [`bound_removal`](super::bound_removal). A mount whose
    /// source binds no device never opens `/sys` at all, and its removal
    /// answer is `Unknown`.
    fn source_device(
      line: &MountLine,
      pinned: &Pinned,
      roots: &Roots,
    ) -> io::Result<(Binding, Ejectability, Option<VolumeIdentity>)> {
      let binding = roots.bind(line, pinned)?;
      let Some(device) = binding.device() else {
        return Ok((binding, Ejectability::Unknown, None));
      };
      let mounted = Self::mounted_identity(line, pinned, roots, &binding);
      let removal = match (mounted, roots.removal(), roots.dev.as_ref()) {
        (Some(mounted), Some(sysfs), Some(dev)) => {
          let fs_type = line.fs_type.as_bytes();
          super::bound_removal(sysfs, device, mounted, |attach| {
            if super::published_at(dev, device, attach) {
              super::published_identity(dev, device, fs_type)
            } else {
              None
            }
          })
        }
        _ => Ejectability::Unknown,
      };
      Ok((binding, removal, mounted))
    }

    /// The identity the mounted filesystem names itself by through the mount
    /// `binding` holds — btrfs's FSID out of the binding, or asked through the
    /// mount's root reopened for the question
    /// ([`filesystem_identity`](super::filesystem_identity)) — in the form the
    /// line's filesystem type gives it. `None` wherever it names none, or the
    /// root could not be had: this binds the removal answer and the udev
    /// facts, and never fails the row.
    fn mounted_identity(
      line: &MountLine,
      pinned: &Pinned,
      roots: &Roots,
      binding: &Binding,
    ) -> Option<VolumeIdentity> {
      let fs_type = line.fs_type.as_bytes();
      let answered = match binding {
        Binding::Btrfs { mount, .. } => Some(mount.fsid),
        Binding::Device(_) | Binding::Unbound => mount_root(line, pinned, &roots.proc)
          .ok()
          .flatten()
          .and_then(|root| super::filesystem_identity(&root, fs_type)),
      }?;
      super::super::linux_identity(fs_type, answered, IdentityAssurance::Vouched)
        .map(|reading| reading.identity())
    }

    /// Every other fact of the row, read from the one binding of the line's
    /// source and the one pin, at the level the source earns.
    ///
    /// For btrfs, the binding carries everything: the one census of the
    /// kernel's btrfs map that bound the source answers the identity — see
    /// [`BtrfsCensus`](super::BtrfsCensus) — and the label is the one the
    /// filesystem answered through the pinned mount, whatever the census says
    /// about the FSID's durability; the udev roads are never consulted in
    /// their place. For everything else, the identity is `/dev/disk/by-uuid`'s,
    /// the label `/dev/disk/by-label`'s, and where that directory has none,
    /// udev's runtime database's, at `Declared` and never higher — **held to
    /// the mounted filesystem wherever it names itself through its mount**
    /// (`mounted`, see [`mounted_identity`](Self::mounted_identity)): udev's
    /// identity for the device must be that one, or nothing udev says of the
    /// device is reported, since it is some other filesystem's — a device
    /// number handed to another device, a link udev has not moved yet. Where
    /// the filesystem names none — exFAT, NTFS, ISO 9660, UDF, and XFS and
    /// ext4 on a kernel before 6.9 — udev's facts are bound by the device
    /// number alone, which the `Published` assurance says out loud. The
    /// capacity is `fstatvfs` through the pin.
    ///
    /// **Nothing is formed without a pin.** Both roads hand over the pin whose
    /// held id named `line`, so every fact below is read about a line the
    /// kernel bound to a mount this call holds, and a line nothing proved
    /// cannot reach this function at all.
    fn formed(
      line: MountLine,
      binding: Binding,
      ejectability: Ejectability,
      mounted: Option<VolumeIdentity>,
      pinned: &Pinned,
      facts: &Facts<'_>,
    ) -> io::Result<Self> {
      let fs_type = line.fs_type.as_bytes();
      let assurance = facts.block_backed.assurance_of(fs_type);
      let by_uuid_answer = |device: u64| -> io::Result<Option<IdentityReading>> {
        Ok(match facts.by_uuid()? {
          UdevCensus::Complete(entries) => linux_identity_for_device(
            entries.iter().map(|&(target, identity)| (target, identity)),
            device,
            fs_type,
            assurance,
          ),
          // A census that could not be read whole names nothing, for any
          // device.
          UdevCensus::Refused => None,
        })
      };
      let (identity, name) = match binding {
        Binding::Unbound => (None, None),
        Binding::Btrfs { mount, durable, .. } => btrfs_facts(mount, durable, assurance),
        Binding::Device(device) => 'udev: {
          let identity = by_uuid_answer(device)?;
          // A filesystem that names itself through its mount holds udev's
          // facts about the device to it: where udev names another identity,
          // or none, for the device, what udev says of it is some other
          // filesystem's, and none of it is reported.
          if mounted.is_some() && identity.map(|reading| reading.identity()) != mounted {
            break 'udev (None, None);
          }
          let name = match super::label_for_device(facts.by_label()?, device) {
            Some(name) => Some(NameReading { name, assurance }),
            None => super::udev_database_label(device)?.map(|name| NameReading {
              name,
              assurance: IdentityAssurance::Declared,
            }),
          };
          (identity, name)
        }
      };
      #[cfg(feature = "disk-usage")]
      let capacity = pinned.capacity()?;
      #[cfg(not(feature = "disk-usage"))]
      let _ = pinned;
      Ok(Self {
        line,
        ejectability,
        identity,
        name,
        #[cfg(feature = "disk-usage")]
        capacity,
      })
    }

    /// The mount point the line spells, where a resolve's path splits.
    pub(super) fn mount_point(&self) -> &SmallBytes {
      &self.line.mount_point
    }

    /// The row, and every value in it out of this one observation, which it
    /// takes by value and is given nothing beside.
    pub(super) fn into_row(self) -> MountPoint {
      let capabilities = super::volume_capabilities(self.line.fs_type.as_bytes());
      MountPoint {
        mount_point: self.line.mount_point,
        device: self.line.source,
        ejectability: self.ejectability,
        capabilities,
        volume_identity: self.identity,
        volume_name: self.name,
        #[cfg(feature = "disk-usage")]
        total_bytes: self.capacity.0,
        #[cfg(feature = "disk-usage")]
        available_bytes: self.capacity.1,
      }
    }

    /// The mount source the line spells, decoded, for the laws.
    #[cfg(test)]
    pub(super) fn source(&self) -> &SmallBytes {
      &self.line.source
    }

    /// The filesystem type the line spells, for the laws.
    #[cfg(test)]
    pub(super) fn fs_type(&self) -> &[u8] {
      self.line.fs_type.as_bytes()
    }

    /// A resolve's observation formed from a table a law hands in: see
    /// [`resolved`](Self::resolved).
    #[cfg(test)]
    pub(super) fn resolved_for_laws(
      pinned: &Pinned,
      canonical: &Path,
      table: &MountTable,
    ) -> io::Result<Self> {
      let roots = Roots::open()?;
      let table = HeldTable(table.clone());
      let facts = Facts::after(&roots, &table)?;
      Self::resolved(pinned, canonical, &table, &facts)
    }
  }

  /// Every row a listing reports, each formed into its one observation.
  ///
  /// **A row is proven before anything is read about it, whatever the
  /// features.** A table line is a claim the kernel made when the table was
  /// read; by the time a fact is read about it, the mount it named may have
  /// left and its mount point or its device node been reused. So every row's
  /// mount point is pinned, the table is read **again while the pins are
  /// held**, and a row whose pin holds the mount id it was listed under is the
  /// line that id names in the second table — **wherever that mount is now**,
  /// since a move keeps a mount and its id — with every fact of it read from
  /// that line and through that pin.
  ///
  /// **Every other row is omitted, and none refuses the listing.** A mount
  /// point that could not be pinned — gone, out of this caller's reach, or on
  /// a kernel that names no mount id — a pin holding another id — the mount
  /// covered by another, which no path reaches any more, or replaced — and an
  /// id that now names no line, or a line the listing leaves out, are each a
  /// mount this call could not bind to a line; a listing that failed on any
  /// of them would fail on every host where a mount comes or goes while it
  /// runs. What the listing never does is read a fact about a line nothing
  /// proved: there is no road from an unpinned line to
  /// [`Observation::formed`]. A pin that failed is the error it is.
  #[cfg(feature = "list")]
  pub(super) fn listing(opts: super::super::ListOptions) -> io::Result<Vec<Observation>> {
    let roots = Roots::open()?;
    let listed = MountTable::read(&roots.proc)?;
    let lines: Vec<&MountLine> = listed
      .lines()
      .filter(|line| super::is_listed(line))
      .collect();
    let mut observations = Vec::new();
    for batch in lines.chunks(super::PIN_BATCH) {
      // Every mount point of the batch pinned first, and every pin held while
      // the table is read again.
      let held = batch
        .iter()
        .map(
          |line| match Pinned::of(line.mount_point.as_path(), &roots.proc) {
            Reading::Value(pinned) => Ok(Some(pinned)),
            Reading::Absent | Reading::Declined(_) => Ok(None),
            Reading::Failed(err) => Err(err),
          },
        )
        .collect::<io::Result<Vec<_>>>()?;
      let table = HeldTable::read(&roots.proc, &held.iter().flatten().collect::<Vec<_>>())?;
      // Every fact of this batch's rows is read from here on, out of what is
      // read after its pins, and dropped with the batch.
      let facts = Facts::after(&roots, &table)?;
      let current = table.0.by_id();
      for (line, held) in batch.iter().zip(&held) {
        // The mount the row was listed under, held.
        let Some(pinned) = held.as_ref().filter(|pinned| pinned.mount_id == line.id) else {
          continue;
        };
        // As the second table says it is while the pin holds it — wherever
        // it is attached now — or gone.
        let Some(now) = held_line(pinned.mount_id, &current) else {
          continue;
        };
        observations.extend(Observation::listed(now.clone(), pinned, &facts, opts)?);
      }
    }
    Ok(observations)
  }

  /// The line a held mount id names in a table read while it was held, where
  /// the listing reports that line: **wherever that mount is now.** A move or
  /// an ancestor rename keeps a mount and its id, so the second table's line
  /// and every fact read through the same pin describe one mount at its
  /// current place. `None` where the id names no line now, or one the listing
  /// leaves out.
  #[cfg(feature = "list")]
  fn held_line<'t>(mount_id: u64, current: &HashMap<u64, &'t MountLine>) -> Option<&'t MountLine> {
    current
      .get(&mount_id)
      .copied()
      .filter(|line| super::is_listed(line))
  }

  #[cfg(test)]
  mod tests {
    use super::*;

    fn proc_root() -> KernelDir {
      super::super::proc_root()
        .required()
        .expect("procfs opens and authenticates on a Linux host")
    }

    /// Both kernel doors name the descriptor's mount by the same id, and the
    /// `fdinfo` door is what a kernel before 5.8 has.
    #[test]
    fn test_the_fdinfo_door_names_the_mount_statx_names() {
      let proc = proc_root();
      let pinned = Pinned::of(Path::new("/"), &proc)
        .required()
        .expect("the root pins");
      let Reading::Value(through_fdinfo) = fdinfo_mount_id(&pinned.fd, &proc) else {
        panic!("a Linux 3.15+ kernel names the mount id in fdinfo");
      };
      assert_eq!(through_fdinfo, pinned.mount_id());
      if let Reading::Value(through_statx) = statx_mount_id(&pinned.fd) {
        assert_eq!(
          through_statx, through_fdinfo,
          "one descriptor, one mount id"
        );
      }
    }

    /// A held id names its own line in the second table **wherever that
    /// mount is now**: a move keeps a mount and its id, so the row is the
    /// current line, not a skipped one. An id the table no longer carries,
    /// or one that now names a line the listing leaves out, names no row.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_moved_mount_is_its_held_ids_current_line() {
      // Listed at `/mnt/old` in the first table; moved to `/mnt/new` before
      // the second was read.
      let second = MountTable::parse(
        b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
          36 21 8:17 / /mnt/new rw - vfat /dev/sdb1 rw\n\
          37 21 0:40 / /tmp rw - tmpfs tmpfs rw\n",
      )
      .unwrap();
      let current = second.by_id();
      let moved =
        held_line(36, &current).expect("the held id still names a line the listing reports");
      assert_eq!(moved.mount_point.as_bytes(), b"/mnt/new");
      assert_eq!(moved.source.as_bytes(), b"/dev/sdb1");
      assert_eq!(moved.fs_type.as_bytes(), b"vfat");

      assert!(
        held_line(99, &current).is_none(),
        "an id the second table does not carry names a mount that is gone"
      );
      assert!(
        held_line(37, &current).is_none(),
        "an id whose line the listing leaves out names no row"
      );
    }

    /// A resolve takes only the line its pin's held id names, and that line
    /// must contain the pinned path: a pin paired with an id no line carries
    /// is refused, never answered by another line.
    #[test]
    fn test_a_resolve_takes_the_held_ids_line_or_nothing() {
      let proc = proc_root();
      let table = MountTable::read(&proc).unwrap();
      let pinned = Pinned::of(Path::new("/"), &proc).required().unwrap();
      let observation = Observation::resolved_for_laws(&pinned, Path::new("/"), &table).unwrap();
      assert_eq!(observation.mount_point().as_bytes(), b"/");
      assert!(!observation.fs_type().is_empty());

      let unheld = Pinned {
        fd: rustix::fs::open("/", OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap(),
        mount_id: u64::MAX,
      };
      assert!(
        Observation::resolved_for_laws(&unheld, Path::new("/"), &table).is_err(),
        "an id no line carries names no mount"
      );
    }

    /// A source binds only where its node is the device the kernel printed
    /// for the mount itself — or, for btrfs, a member of the filesystem the
    /// pinned mount is: the root's line binds its own device or nothing, and
    /// the same line naming another device binds nothing at all.
    #[test]
    fn test_a_source_binds_only_the_mounts_own_device() {
      let roots = Roots::open().unwrap();
      let pinned = Pinned::of(Path::new("/"), &roots.proc).required().unwrap();
      let table = HeldTable::read(&roots.proc, &[&pinned]).unwrap();
      let line = table
        .0
        .line(pinned.mount_id())
        .expect("the root's held id names a line")
        .clone();
      let btrfs = is_btrfs(line.fs_type.as_bytes());
      match roots.bind(&line, &pinned).unwrap() {
        Binding::Device(device) => {
          assert_eq!(device, line.device, "a bound device is the mount's own");
        }
        Binding::Btrfs { .. } => assert!(btrfs, "only btrfs binds through its FSID"),
        Binding::Unbound => {}
      }
      if !btrfs {
        let other = MountLine {
          device: line.device ^ 1,
          ..line
        };
        assert!(
          matches!(roots.bind(&other, &pinned).unwrap(), Binding::Unbound),
          "a source whose node is not the mount's device binds nothing"
        );
      }
    }

    /// Every row a listing reports is the line its own pin's held id named,
    /// with or without `disk-usage`: pinned again, each row's mount point
    /// still holds that id on a host whose mounts are not changing.
    #[cfg(feature = "list")]
    #[test]
    fn test_every_listed_row_is_the_line_its_pin_held() {
      let proc = proc_root();
      let observations = listing(super::super::super::ListOptions::all()).unwrap();
      assert!(
        observations
          .iter()
          .any(|observation| observation.line.mount_point.as_bytes() == b"/"),
        "the root is pinned and listed"
      );
      for observation in &observations {
        let pinned = Pinned::of(observation.line.mount_point.as_path(), &proc)
          .required()
          .unwrap();
        assert_eq!(
          pinned.mount_id(),
          observation.line.id,
          "{:?}",
          observation.line.mount_point.as_bytes()
        );
      }
    }
  }
}

use observed::Observation;

#[cfg(test)]
use observed::Pinned;

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
/// **One observation, formed once.** The object the caller named is pinned,
/// the mount table is read while the pin is held, and the row is the line the
/// pin's held mount id names, with every fact of it — the capacity through the
/// pin, and the identity, the label and the removal answer out of the one
/// resolution of that line's source — read when the observation is formed:
/// see [`observed`].
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
/// is one read of the calling thread's `mountinfo` per resolve, through the
/// authenticated root it already opens — which is what every resolve that
/// missed the cache already paid, and what the listing road pays once for a
/// whole enumeration and once more for each batch of its pins.
#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;
  let observation = Observation::of_path(&canonical)?;

  let canonical_bytes = canonical.as_os_str().as_bytes();
  let mp_bytes = observation.mount_point().as_bytes();
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

  Ok(Inner {
    mount: observation.into_row(),
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

/// How many listing rows are pinned at once, and held while the mount table is
/// read again for them.
///
/// Each pin is a descriptor held until its batch's table has been read, so a
/// bound keeps a host with thousands of mounts from holding thousands of
/// descriptors at once; each batch costs one more read of the table.
#[cfg(feature = "list")]
const PIN_BATCH: usize = 64;

/// One record of the mount table: the mount id it prints first, and what it
/// spells for the mount point, the filesystem type and the source, all three
/// decoded — a field spelled with an escape names something other than its
/// spelling does.
#[derive(Clone)]
struct MountLine {
  /// The id the table prints first, which a resolve and a listing choose a
  /// line by.
  id: u64,
  /// The device the kernel prints for the mount itself — `major:minor`, the
  /// device of its superblock — which is what binds a source to the mount: a
  /// source is the mount's device only where its node is this number. See
  /// `Roots::bound_device`.
  device: u64,
  mount_point: SmallBytes,
  fs_type: SmallBytes,
  source: SmallBytes,
}

/// One record of the mount table, parsed strictly, or `None` for a record the
/// kernel could not have written.
///
/// The grammar is `show_mountinfo`'s (`fs/proc_namespace.c`), fields separated
/// by single spaces, and **every field of it is held to that grammar**, not
/// only the ones a row keeps: the mount id and the parent's id in decimal;
/// `major:minor`; the root, non-empty; the mount point, an absolute path; the
/// per-mount options, `rw` or `ro` first; any number of optional fields, none
/// of them empty, up to a lone `-`; the filesystem type, non-empty; the
/// source, which may be empty — a mount made with an empty source name prints
/// it so; the per-superblock options, `rw` or `ro` first; and then the end of
/// the record, with nothing after it. The four paths and names the kernel
/// escapes must be spelled with its escapes and no others: see
/// [`decode_escapes`]. A record short of a field, or with one past its end,
/// is how a partial or overrun read would look, and is refused, not trimmed.
fn parse_record(record: &[u8]) -> Option<MountLine> {
  let mut fields = record.split(|&byte| byte == b' ');
  let id = parse_u64(fields.next()?)?;
  parse_u64(fields.next()?)?;
  let device = fields.next()?;
  let colon = super::find_byte(b':', device)?;
  let device = makedev(
    parse_u64(&device[..colon])?,
    parse_u64(&device[colon + 1..])?,
  );
  let root = fields.next()?;
  if root.is_empty() {
    return None;
  }
  decode_escapes(root)?;
  let mount_point = decode_escapes(fields.next()?)?;
  if !mount_point.as_bytes().starts_with(b"/") || !is_options(fields.next()?) {
    return None;
  }
  loop {
    match fields.next()? {
      b"-" => break,
      b"" => return None,
      _ => {}
    }
  }
  let fs_type = decode_escapes(fields.next()?)?;
  let source = decode_escapes(fields.next()?)?;
  if fs_type.as_bytes().is_empty() || !is_options(fields.next()?) || fields.next().is_some() {
    return None;
  }
  Some(MountLine {
    id,
    device,
    mount_point,
    fs_type,
    source,
  })
}

/// Whether a field is an options list as the kernel writes one: `rw` or `ro`
/// first, then the rest separated by commas, none of them empty.
fn is_options(field: &[u8]) -> bool {
  let mut options = field.split(|&byte| byte == b',');
  matches!(options.next(), Some(b"rw" | b"ro")) && options.all(|option| !option.is_empty())
}

/// Whether the listing reports a mount table line: not a virtual filesystem,
/// not a mount under `/sys`, `/proc` or `/run` other than `/run/media`, and not
/// the sunrpc pipe.
#[cfg(feature = "list")]
fn is_listed(line: &MountLine) -> bool {
  if IGNORED_FS_TYPES.contains(&line.fs_type.as_bytes()) {
    return false;
  }
  let mp = line.mount_point.as_bytes();
  if mp.starts_with(b"/sys")
    || mp.starts_with(b"/proc")
    || (mp.starts_with(b"/run") && !mp.starts_with(b"/run/media"))
  {
    return false;
  }
  !line.source.as_bytes().starts_with(b"sunrpc")
}

/// The mount table, read whole: every record of the calling thread's
/// `mountinfo`, parsed, out of one read no change to the table overlapped. The
/// census a resolve chooses its line from and a listing's rows are, and the
/// only way this backend has of reading the table.
#[cfg_attr(test, derive(Clone))]
struct MountTable(Vec<MountLine>);

impl MountTable {
  /// `/proc/<tgid>/task/<tid>/mountinfo` — the calling thread's own — read
  /// from the authenticated root as a census: see [`Census::snapshot`].
  ///
  /// **The table is the calling thread's, because the pin is.** A mount table
  /// is a view of one mount namespace, and a thread may have entered one of
  /// its own (`unshare(CLONE_FS)`, then `setns`) while the rest of its process
  /// stays where it was. Every pathname a row is read through — the path a
  /// resolve canonicalizes, the pin, every read beneath `/dev` — resolves in
  /// the calling thread's namespace, so the table read alongside them must be
  /// that thread's too; `self/mountinfo` would be the thread-group leader's,
  /// in which a pin's mount id names no line, or a listing another namespace
  /// entirely. The directory is the one [`procfs_thread`] reads off the
  /// authenticated root's `thread-self` link, the same one the mount id's
  /// `fdinfo` door is read beneath; a procfs that names no thread there
  /// fails the read.
  ///
  /// There is no pathname road behind it: a mount table that could not be had
  /// *this way* is not had at all, and the error that says why — a refusal of
  /// the containment, a kernel without `openat2`, a failed read — is what
  /// every caller returns.
  ///
  /// **A read that a change overlapped is read again.** The kernel hands the
  /// table over in pieces, one `read(2)` at a time, and keeps its place by
  /// position: before Linux 5.8 a mount added or removed between two pieces
  /// shifts every later line, so a line is skipped or given twice, and on any
  /// kernel the pieces can straddle a change. So the table is taken only from
  /// a read the kernel proves no mount event overlapped: `poll` on the open
  /// file answers `POLLPRI` once the namespace's mount table has changed since
  /// the file was opened (`mounts_poll`, `fs/proc_namespace.c`), and a read
  /// followed by no such answer is a table as it stood. **Every record must
  /// parse**, or the whole read is `InvalidData`: see [`parse`](Self::parse).
  fn read(proc: &KernelDir) -> io::Result<Self> {
    use std::io::Read as _;

    let thread = match procfs_thread(proc) {
      Reading::Value(thread) => thread,
      Reading::Absent => {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "the authenticated procfs's thread-self link names no thread",
        ));
      }
      Reading::Declined(err) | Reading::Failed(err) => return Err(err),
    };
    let path = KernelDir::at(&[&thread, b"mountinfo"]);
    let path = Path::new(OsStr::from_bytes(&path));
    Census::snapshot(
      || {
        let file = std::fs::File::from(proc.open_beneath(
          path,
          OFlags::RDONLY | OFlags::CLOEXEC,
          ResolveFlags::NO_SYMLINKS,
        )?);
        let mut table = Vec::new();
        (&file).read_to_end(&mut table)?;
        let unchanged = !mount_event_since_open(&file)?;
        Ok((Self::parse(&table)?.0, unchanged))
      },
      declined,
    )
    .required()
    .map(|census| Self(census.into_iter().collect()))
  }

  /// Every record of a mount table, parsed: all of them, or `InvalidData`.
  ///
  /// **A record is complete only at its newline.** The kernel ends every
  /// record with one, so bytes after the last newline are a record cut off —
  /// by a read that stopped short, or a table that was never finished — and an
  /// empty record is none the kernel writes. Either fails the table, and so
  /// does any record [`parse_record`] refuses: a record passed over is a mount
  /// left out of a table that reads as complete. No records at all is a table
  /// with nothing in it.
  fn parse(table: &[u8]) -> io::Result<Self> {
    let invalid = |what| io::Error::new(io::ErrorKind::InvalidData, what);
    let Some(records) = table.strip_suffix(b"\n") else {
      return if table.is_empty() {
        Ok(Self(Vec::new()))
      } else {
        Err(invalid("a mount table whose last record has no end"))
      };
    };
    records
      .split(|&byte| byte == b'\n')
      .map(|record| {
        parse_record(record)
          .ok_or_else(|| invalid("a mount table record the kernel could not have written"))
      })
      .collect::<io::Result<Vec<_>>>()
      .map(Self)
  }

  /// Every line, in the table's order.
  #[cfg(feature = "list")]
  fn lines(&self) -> impl Iterator<Item = &MountLine> {
    self.0.iter()
  }

  /// The line a mount id names.
  fn line(&self, id: u64) -> Option<&MountLine> {
    self.0.iter().find(|line| line.id == id)
  }

  /// Every line, keyed by the mount id it prints first, so that finding the
  /// line a held id names costs one lookup rather than a scan.
  #[cfg(feature = "list")]
  fn by_id(&self) -> HashMap<u64, &MountLine> {
    self.0.iter().map(|line| (line.id, line)).collect()
  }
}

/// Whether the mount table of this process's namespace has changed since
/// `file` — that table, opened — was opened: `poll` for `POLLPRI`, answered
/// at once.
fn mount_event_since_open(file: &std::fs::File) -> io::Result<bool> {
  use rustix::event::{PollFd, PollFlags, Timespec, poll};

  let mut fds = [PollFd::new(file, PollFlags::PRI)];
  let now = Timespec {
    tv_sec: 0,
    tv_nsec: 0,
  };
  loop {
    match poll(&mut fds, Some(&now)) {
      Ok(_) => return Ok(fds[0].revents().intersects(PollFlags::PRI | PollFlags::ERR)),
      Err(rustix::io::Errno::INTR) => {}
      Err(errno) => return Err(errno.into()),
    }
  }
}

/// Lists the mounted volumes: one row per line of the mount table the listing
/// reports, each row one observation, formed whole in [`observed`] — see
/// [`observed::listing`].
#[cfg(feature = "list")]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  Ok(
    observed::listing(opts)?
      .into_iter()
      .map(Observation::into_row)
      .collect(),
  )
}

/// Linux: report the volume's case semantics from its filesystem type. The
/// per-directory ext4/f2fs **casefold** attribute (`chattr +F`) can make an
/// individual directory case-insensitive, but that is not a volume-level
/// property, so it is intentionally not reflected here; the result describes the
/// filesystem default and is `None` for types that do not determine it.
fn volume_capabilities(fs_type: &[u8]) -> VolumeCapabilities {
  VolumeCapabilities::from_fs_type_defaults(fs_type)
}

/// Where the kernel publishes which filesystem each btrfs device belongs to.
const BTRFS_SYSFS_ROOT: &str = "fs/btrfs";

/// A btrfs mount's identity, or its refusal, for a mount `mountinfo` already
/// named as btrfs.
///
/// Two states, not three. The identity is the FSID the filesystem answered
/// for itself through the pinned mount (`BTRFS_IOC_FS_INFO`), and it is
/// [`Matched`](Self::Matched) only where the filesystem's own marker says it
/// outlives the mount ([`btrfs_durable`]); everything else — a temporary
/// FSID, a kernel or a sysfs view with no marker, a map that would not open —
/// is [`Refused`](Self::Refused). Consulting `/dev/disk/by-uuid` in place of a
/// refusal would risk reporting exactly the value the refusal declined to
/// vouch for: see [`identity_after_btrfs`], the one place an observation acts
/// on this.
///
/// **Reported `Published`, held to the source's level**, as every Linux
/// identity is. The FSID is the filesystem answering for itself through a
/// descriptor held to the pinned mount, which is what `Vouched` describes,
/// but its durability is sysfs's marker; the level stays where every
/// earlier btrfs reading stood until the owner rules otherwise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BtrfsLookup {
  /// The FSID the filesystem answered, whose marker says it outlives the
  /// mount.
  Matched(IdentityReading),
  /// No durable FSID: no identity is reported, and no other road is
  /// consulted in its place.
  Refused,
}

impl BtrfsLookup {
  /// The same answer, held to the level the mount source earned — the level
  /// every read on this platform travels at, from the mount's own line,
  /// exactly as it does on the udev road beside this one.
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
/// are different facts, even though [`btrfs_durable`] now refuses on
/// both alike. Collapsing them the way a `bool` or an `Option` would still
/// throw away a distinction a caller diagnosing a refusal is entitled to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TempFsidMarker {
  /// Read cleanly as exactly `"0\n"`: this FSID is the volume's own.
  Permanent,
  /// Read cleanly as exactly `"1\n"`: this boot's mount chose the FSID fresh
  /// (see [`btrfs_durable`]).
  Temporary,
  /// The file does not exist — [`io::ErrorKind::NotFound`] specifically.
  NotFound,
  /// The platform declined the read for any other reason: permission, a
  /// masked `/sys`, a path that is not the file it should be. A read that
  /// *failed* — no descriptors, an I/O error — is not a marker at all, and is
  /// returned as the error it is: see [`declined`].
  Unreadable,
}

/// btrfs: the census of the kernel's own map for the filesystem `device` is a
/// member of — read from sysfs rather than from udev's links — which binds a
/// btrfs mount's source device to the filesystem the pinned mount answered
/// for: see `observed::Roots::bind`.
///
/// A btrfs filesystem is named by its FSID, and **every** member device carries
/// that same FSID — which is exactly why `/dev/disk/by-uuid` cannot answer for
/// a multi-device one. `blkid` reads one value off every member, so udev has
/// one name to publish and one link to publish it as, pointing at whichever
/// member it saw last. The kernel publishes the mapping itself:
/// `/sys/fs/btrfs/<fsid>/devices/` holds one world-readable entry per member,
/// each with a `dev` file naming the block device's `major:minor`. Matching the
/// mount source's own device number against those names the filesystem
/// whichever member carries the mount, needs no privilege, and reads nothing
/// off the volume. See [`BtrfsCensus`] for what refuses.
/// The authenticated `/sys` the btrfs census is read beneath.
///
/// `/sys` is held to `SYSFS_MAGIC` — unlike `/dev`, the kind is worth asking
/// here, since nothing but sysfs belongs at that path. The census addresses
/// everything by its path relative to **this** root rather than to
/// `fs/btrfs`, because a member entry under `devices/` is a symlink to the
/// block device's own directory elsewhere under `/sys`: from a root narrowed
/// to `fs/btrfs`, `RESOLVE_BENEATH` would refuse that climb and the census
/// would refuse every real filesystem.
fn btrfs_sysfs() -> Reading<KernelDir> {
  KernelDir::open("/sys", Some(SYSFS_MAGIC))
}

/// The identity a fixture's map gives the one filesystem `rdev` is a member
/// of, where its marker says the FSID outlives the mount: membership by
/// [`btrfs_census`] and durability by [`btrfs_durable`], the two product roads
/// the laws hold together. A live mount's identity is the FSID the filesystem
/// answered through the pinned mount, held to the same durability.
#[cfg(test)]
fn btrfs_fsid_for_device(sysfs: &KernelDir, rdev: u64) -> io::Result<BtrfsLookup> {
  Ok(match btrfs_census(sysfs, rdev)? {
    BtrfsCensus::Member { fsid } if btrfs_durable(sysfs, &fsid)? => {
      BtrfsLookup::Matched(IdentityReading::published(fsid))
    }
    BtrfsCensus::Member { .. } | BtrfsCensus::Refused => BtrfsLookup::Refused,
  })
}

/// What the census found: the one filesystem that holds the device, whose
/// whole membership was read — or a refusal.
///
/// **It binds a btrfs mount's source device, and decides nothing else.** The
/// FSID and the label are the filesystem's own answer through the pinned
/// mount, and whether that FSID outlives the mount is its own marker's to say
/// ([`btrfs_durable`]); what the census adds is whether the mount's source is
/// a member of that filesystem, so that the removal answer is asked about a
/// device that backs the mount: see `observed::Roots::bind`.
///
/// # Zero claimants is refused, not evidence this isn't btrfs
///
/// An observation reaches this only after its mount table line has said the
/// mount's filesystem type is btrfs. So a census that names no claimant for
/// `rdev` at all is never read as "this device is not under btrfs" — the
/// caller already knows otherwise. A readable-but-empty sysfs root, a bind
/// mount that masks it, an FSID directory torn down between the `mountinfo`
/// snapshot and this read, and an outright unreadable root are all
/// indistinguishable from here, and every one of them is
/// [`Refused`](Self::Refused), the same as an ambiguous match. Absence is
/// never evidence.
///
/// # The census fails closed
///
/// Every read this performs — enumerating `sysfs_root` itself, a candidate's
/// `devices/` directory, and a member's `dev` file — can be declined partway
/// through: a masked `/sys`, a container that hides part of the tree, a
/// directory removed mid-scan. A decline anywhere means this census cannot be
/// told apart from one that would have found a second claimant, or would have
/// found the very member holding `rdev`, had it been able to finish reading.
/// There is no safe default between those two, so none is guessed: any such
/// decline is [`Refused`](Self::Refused). A read that *failed* rather than
/// being declined — no descriptors left, an I/O error — is not a census of
/// any kind, and is returned as the error it is: see [`declined`]. The driver
/// registers `fs/btrfs` unconditionally at module init, so an unreadable root
/// is sysfs withholding the map, never "no btrfs on this system".
///
/// # A device claimed by more than one filesystem is ambiguous
///
/// A btrfs seed device is recognized read-only and can seed several sprouts
/// at once, so its device number is linked into every one of their
/// `devices/` directories at the same time — legitimately, not as a fault.
/// Nothing here can say which sprout the mount is, so none is preferred over
/// the rest, and the source binds nothing.
///
/// The census takes its sysfs root as a parameter because what it names is
/// what needs testing: a multi-device btrfs filesystem is not something a
/// unit test can conjure. A fixture tree reproduces exactly what this reads.
enum BtrfsCensus {
  /// One filesystem, and one only, holds the device, and its whole membership
  /// was read.
  Member {
    /// The FSID its sysfs directory is named by.
    fsid: VolumeIdentity,
  },
  /// The census could not be completed, or the device has no single claimant.
  /// Nothing is bound by this.
  Refused,
}

/// The census itself: see [`BtrfsCensus`].
fn btrfs_census(sysfs: &KernelDir, rdev: u64) -> io::Result<BtrfsCensus> {
  let Some(entries) = sysfs.dir(Path::new(BTRFS_SYSFS_ROOT)).answered()? else {
    return Ok(BtrfsCensus::Refused);
  };

  // The one filesystem seen so far whose `devices/` holds `rdev`, kept rather
  // than answered at once: a second claimant found later voids it.
  let mut found: Option<VolumeIdentity> = None;

  // Read whole before one name of it is weighed — a refill sysfs declined
  // partway refuses the census above, since what it would have shown is
  // exactly what the rest of this function exists to answer. See [`listing`].
  for name in entries {
    // Only an FSID names a filesystem here. The directory also holds
    // `features`, and on newer kernels a flat `devices` list of every scanned
    // device, neither of which is a UUID.
    let Some(fsid @ VolumeIdentity::FsUuid(_)) = super::parse_by_uuid_name(&name) else {
      continue;
    };
    let devices = KernelDir::at(&[BTRFS_SYSFS_ROOT.as_bytes(), &name, b"devices"]);
    let Some(members) = sysfs
      .dir(Path::new(OsStr::from_bytes(&devices)))
      .answered()?
    else {
      // This candidate's own membership could not be read. It might have
      // been the (or another) claimant of `rdev`; a partial view of it is
      // exactly as untrustworthy as a partial view of the root.
      return Ok(BtrfsCensus::Refused);
    };
    let mut holds_rdev = false;
    for member in members {
      // The member is a link the kernel put there on purpose, so this one
      // read follows it — still beneath `/sys` and still across no mount.
      let dev = KernelDir::at(&[&devices, &member, b"dev"]);
      match sysfs_device_number(sysfs, Path::new(OsStr::from_bytes(&dev))).answered()? {
        Some(dev) if dev == rdev => holds_rdev = true,
        Some(_) => {}
        // Missing or unreadable `dev` file for one member. That file is
        // exactly what would decide whether this member is `rdev`; unable to
        // read it, this member can be neither ruled in nor out. A malformed
        // one is the error it is, above.
        None => return Ok(BtrfsCensus::Refused),
      }
    }

    if !holds_rdev {
      continue;
    }
    if found.is_some() {
      // A second filesystem claims the same device — a shared seed device,
      // most likely. Neither claim is the answer: the ambiguity is decided
      // from device membership alone.
      return Ok(BtrfsCensus::Refused);
    }
    found = Some(fsid);
  }

  // A device `mountinfo` already named as btrfs, that this census names no
  // claimant for at all, is a refusal, never "not btrfs": see [`BtrfsCensus`].
  Ok(found.map_or(BtrfsCensus::Refused, |fsid| BtrfsCensus::Member { fsid }))
}

/// Whether the kernel positively says a btrfs filesystem's FSID outlives this
/// mount: `/sys/fs/btrfs/<fsid>/temp_fsid` reading exactly `0` — the only
/// FSID this crate reports as an identity.
///
/// **A temporary FSID is not an identity.** Linux 6.7+ mints one at mount time
/// for a single-device btrfs whose on-disk FSID collides with an
/// already-mounted filesystem's — a clone mounted beside its original, for
/// instance. It is chosen fresh by this boot's mount rather than read off the
/// volume, so it does not survive to the next mount or the next machine.
/// Recovering the real, on-disk FSID would mean reading the superblock, which
/// needs elevation this crate does not take, so the mount is left with no
/// identity rather than a borrowed one; its label, a name and no identity, is
/// reported all the same.
///
/// **A missing marker is refused, never guessed.** Earlier rounds tried to
/// tell a genuinely pre-6.7 kernel — one that never installed the
/// per-filesystem attribute — apart from a current kernel whose sysfs view
/// merely omits it: from silence, from a kernel-wide feature file, from a
/// sibling filesystem's marker, and from the running kernel's own `uname(2)`
/// release. Every one of those was an inference from something other than the
/// filesystem's own marker, and each broke: the `UNAME26` personality makes a
/// process's `uname(2)` report a 2.6.x release on any kernel, and a vendor
/// backport decouples the release from the capability the other way. So the
/// marker alone decides: `Permanent` is durable, and `Temporary`,
/// `Unreadable` and `NotFound` are not. A pre-6.7 kernel and a masked or
/// namespaced sysfs view on a current one are indistinguishable from here,
/// and both report no btrfs identity — a missed match, never a false one. A
/// marker that is neither `0` nor `1` is `InvalidData`: see
/// [`read_temp_fsid_marker`].
fn btrfs_durable(sysfs: &KernelDir, fsid: &VolumeIdentity) -> io::Result<bool> {
  let name = fsid.to_string();
  Ok(matches!(
    read_temp_fsid_marker(sysfs, name.as_bytes())?,
    TempFsidMarker::Permanent
  ))
}

/// `BTRFS_SUPER_MAGIC`, the filesystem type `fstatfs` names btrfs by
/// (`include/uapi/linux/magic.h`). A 32-bit value whichever width the
/// platform's `f_type` has; a law holds it to the kernel's.
const BTRFS_SUPER_MAGIC: u32 = 0x9123_683E;

/// Whether an `fstatfs` filesystem type is btrfs's. The kernel's magic is 32
/// bits, written into an `f_type` of the platform's own width, so it is
/// compared in those 32 bits.
#[allow(clippy::unnecessary_cast)]
fn is_btrfs_magic(f_type: rustix::fs::FsWord) -> bool {
  f_type as u32 == BTRFS_SUPER_MAGIC
}

/// `BTRFS_IOCTL_MAGIC`, the ioctl type both btrfs questions are asked under.
const BTRFS_IOCTL_MAGIC: u8 = 0x94;

/// Where `struct btrfs_ioctl_fs_info_args` (`include/uapi/linux/btrfs.h`)
/// holds the FSID, how long the FSID is, and how long the whole structure is:
/// `max_id` and `num_devices`, two `__u64`, come first, and the structure is
/// padded to 1 KiB. A law holds all three to the kernel's structure.
mod btrfs_fs_info {
  pub(super) const FSID: usize = 16;
  pub(super) const FSID_LEN: usize = 16;
  pub(super) const LEN: usize = 1024;
}

/// `struct btrfs_ioctl_fs_info_args` as the bytes the kernel reads and writes:
/// nothing but bytes, so whatever the kernel writes is a value, aligned for
/// the 64-bit fields at its start, and handed over zeroed, so its one input —
/// `flags` — asks for nothing beyond the fixed answer.
#[repr(C, align(8))]
struct FsInfoArgs([u8; btrfs_fs_info::LEN]);

/// `BTRFS_IOC_FS_INFO`: `_IOR(BTRFS_IOCTL_MAGIC, 31, struct
/// btrfs_ioctl_fs_info_args)`, encoded for the platform the crate is built
/// for; a law holds it to the kernel's.
const BTRFS_IOC_FS_INFO: rustix::ioctl::Opcode =
  rustix::ioctl::opcode::read::<FsInfoArgs>(BTRFS_IOCTL_MAGIC, 31);

/// `FSLABEL_MAX`, which is also `BTRFS_LABEL_SIZE`: the room a label is
/// answered into.
const FSLABEL_MAX: usize = 256;

/// `FS_IOC_GETFSLABEL`: `_IOR(0x94, 49, char[FSLABEL_MAX])`, the number btrfs
/// has served its label under since before the generic name existed; a law
/// holds it to the kernel's.
const FS_IOC_GETFSLABEL: rustix::ioctl::Opcode =
  rustix::ioctl::opcode::read::<[u8; FSLABEL_MAX]>(BTRFS_IOCTL_MAGIC, 49);

/// `struct fsuuid2` (`include/uapi/linux/fs.h`): the length of the UUID the
/// kernel copies, and room for sixteen bytes of it. Bytes alone, so whatever
/// the kernel writes is a value; handed over zeroed. A law holds its size and
/// its fields' places to the kernel's.
#[repr(C)]
struct FsUuid2 {
  len: u8,
  uuid: [u8; 16],
}

/// `FS_IOC_GETFSUUID`: `_IOR(0x15, 0, struct fsuuid2)` (Linux 6.9), encoded
/// for the platform the crate is built for. The uapi header spells it as a
/// macro alone, so a law holds the structure it is encoded over to the
/// kernel's, and the encoding to the one `_IOR` gives.
const FS_IOC_GETFSUUID: rustix::ioctl::Opcode = rustix::ioctl::opcode::read::<FsUuid2>(0x15, 0);

/// `FAT_IOCTL_GET_VOLUME_ID`: `_IOR('r', 0x13, __u32)`; a law holds it to the
/// kernel's.
const FAT_IOCTL_GET_VOLUME_ID: rustix::ioctl::Opcode =
  rustix::ioctl::opcode::read::<u32>(b'r', 0x13);

/// The mounted filesystem's own identity, asked through `root` — the mount's
/// root, reopened for the question through a pin held to the mount — or
/// `None` where it names none:
///
/// - a FAT volume's 32-bit serial, `FAT_IOCTL_GET_VOLUME_ID`, for `vfat` and
///   `msdos`, which the FAT driver serves both under;
/// - every other filesystem's UUID, `FS_IOC_GETFSUUID` (Linux 6.9), which the
///   VFS answers out of the superblock for each filesystem that gives it one
///   — ext4, XFS, btrfs, f2fs among them — and refuses (`ENOTTY`) for the
///   rest, and every kernel before refuses too.
///
/// Neither needs a privilege. A zero serial and an all-zero UUID are no
/// identity, and a UUID of any length but sixteen is none this crate reads.
/// This is the removal road's, which never fails: every failure is `None`.
fn filesystem_identity(root: &OwnedFd, fs_type: &[u8]) -> Option<VolumeIdentity> {
  if matches!(fs_type, b"vfat" | b"msdos") {
    let mut serial: u32 = 0;
    // SAFETY: the opcode is `_IOR('r', 0x13, __u32)` — a law holds it to the
    // kernel's — so the kernel copies one `u32` into this one, live, zeroed
    // and exclusively borrowed for the call. `root` is open for the call.
    let asked = unsafe {
      rustix::ioctl::ioctl(
        root,
        rustix::ioctl::Updater::<{ FAT_IOCTL_GET_VOLUME_ID }, u32>::new(&mut serial),
      )
    };
    asked.ok()?;
    return (serial != 0).then_some(VolumeIdentity::Serial32(serial));
  }
  let mut answer = FsUuid2 {
    len: 0,
    uuid: [0; 16],
  };
  // SAFETY: the opcode is `_IOR(0x15, 0, struct fsuuid2)`, whose size is
  // `FsUuid2`'s seventeen bytes — a law holds the structure to the kernel's —
  // so the kernel copies no more than that into this buffer, which is live,
  // zeroed and exclusively borrowed for the call, and bytes alone, so
  // whatever the kernel writes is a value. `root` is open for the call.
  let asked = unsafe {
    rustix::ioctl::ioctl(
      root,
      rustix::ioctl::Updater::<{ FS_IOC_GETFSUUID }, FsUuid2>::new(&mut answer),
    )
  };
  asked.ok()?;
  (usize::from(answer.len) == answer.uuid.len() && answer.uuid != [0; 16])
    .then_some(VolumeIdentity::FsUuid(answer.uuid))
}

/// A btrfs filesystem's FSID, asked of it through `fd`:
/// `BTRFS_IOC_FS_INFO`, which needs no privilege.
///
/// `fd` must be a descriptor opened for reading on a btrfs filesystem —
/// `fstatfs` said so — and the answer is the filesystem's `fs_devices->fsid`,
/// the one its `/sys/fs/btrfs/<fsid>` directory is named by. The kernel copies
/// the whole structure out, or fails.
fn btrfs_fs_info(fd: &OwnedFd) -> Reading<[u8; btrfs_fs_info::FSID_LEN]> {
  let mut args = FsInfoArgs([0; btrfs_fs_info::LEN]);
  // SAFETY: the opcode is `_IOR(0x94, 31, struct btrfs_ioctl_fs_info_args)`,
  // whose size is `FsInfoArgs`'s 1024 bytes — a law holds both to the
  // kernel's — so the kernel reads its input `flags` from, and copies its
  // answer into, exactly this buffer, which is live, exclusively borrowed and
  // aligned for the call. It is bytes alone, so whatever the kernel writes is
  // a value; zeroed, it asks for no optional field. `fd` is open for the call,
  // and the caller has proven it is on btrfs, whose number this is.
  let asked = unsafe {
    rustix::ioctl::ioctl(
      fd,
      rustix::ioctl::Updater::<{ BTRFS_IOC_FS_INFO }, FsInfoArgs>::new(&mut args),
    )
  };
  reading(asked).map(|()| {
    let mut fsid = [0; btrfs_fs_info::FSID_LEN];
    fsid
      .copy_from_slice(&args.0[btrfs_fs_info::FSID..btrfs_fs_info::FSID + btrfs_fs_info::FSID_LEN]);
    fsid
  })
}

/// A btrfs filesystem's label, asked of it through `fd`: `FS_IOC_GETFSLABEL`,
/// which needs no privilege — see [`btrfs_label_in`] for how the answer is
/// read. `None` for a filesystem that carries none.
fn btrfs_fs_label(fd: &OwnedFd) -> Reading<Option<SmallBytes>> {
  let mut label = [0u8; FSLABEL_MAX];
  // SAFETY: the opcode is `_IOR(0x94, 49, char[FSLABEL_MAX])`, whose size is
  // the buffer's 256 bytes — a law holds it to the kernel's — and the kernel
  // copies no more than that into it; the buffer is live and exclusively
  // borrowed for the call, and bytes alone, so whatever the kernel writes is a
  // value. `fd` is open for the call, and on btrfs.
  let asked = unsafe {
    rustix::ioctl::ioctl(
      fd,
      rustix::ioctl::Updater::<{ FS_IOC_GETFSLABEL }, [u8; FSLABEL_MAX]>::new(&mut label),
    )
  };
  reading(asked).and_then(|()| match btrfs_label_in(&label) {
    Ok(label) => Reading::Value(label),
    Err(err) => Reading::Failed(err),
  })
}

/// The label btrfs answered `FS_IOC_GETFSLABEL` with, out of the zeroed buffer
/// it was handed.
///
/// **Where btrfs's answer ends.** `btrfs_ioctl_get_fslabel`
/// (`fs/btrfs/ioctl.c`) copies `strnlen(label, BTRFS_LABEL_SIZE)` bytes of the
/// label — one fewer where the label fills all 256, which it warns of — and
/// no terminator: none of the bytes it copies is zero, and it reports no
/// length. So in a buffer that was all zeros, the first zero is exactly where
/// its copy ended — the zero is this crate's, but where it stands is the
/// kernel's count — and the last byte is never one it wrote. A buffer with no
/// zero is no answer btrfs gives, and is `InvalidData`; no bytes before the
/// first zero is no label.
fn btrfs_label_in(buffer: &[u8; FSLABEL_MAX]) -> io::Result<Option<SmallBytes>> {
  let len = buffer.iter().position(|&byte| byte == 0).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidData,
      "a btrfs label that fills the whole buffer, which btrfs never copies",
    )
  })?;
  Ok((len > 0).then(|| SmallBytes::from_bytes(&buffer[..len])))
}

/// Reads `<filesystem_dir>/temp_fsid` — the kernel's own marker for a
/// mount-time-only FSID — without collapsing a read failure to a `bool`:
/// "missing," "unreadable," and "malformed" are different facts about the
/// read even though [`btrfs_durable`] refuses on all three alike.
///
/// `fs_devices->temp_fsid` is a `bool` (`fs/btrfs/volumes.h`), read out by
/// `btrfs_temp_fsid_show` and installed as `BTRFS_ATTR(, temp_fsid,
/// btrfs_temp_fsid_show)` in the same per-filesystem attribute array as
/// `label` and `metadata_uuid` (`fs/btrfs/sysfs.c`, present from v6.7 on,
/// absent in v6.6) — there is no `Documentation/ABI/testing/sysfs-fs-btrfs`
/// entry for it at all, unlike ext4, f2fs and xfs, so this is sourced from the
/// kernel itself rather than its ABI docs. `sysfs_emit(buf, "%d\n", ..)` on a
/// `bool` gives exactly `"0\n"` or `"1\n"`; anything else read from the file
/// is not the kernel's writing, and is `InvalidData` — the census fails,
/// rather than a row going on without its identity.
fn read_temp_fsid_marker(sysfs: &KernelDir, filesystem_dir: &[u8]) -> io::Result<TempFsidMarker> {
  let path = KernelDir::at(&[BTRFS_SYSFS_ROOT.as_bytes(), filesystem_dir, b"temp_fsid"]);
  match sysfs.read(Path::new(OsStr::from_bytes(&path))) {
    Reading::Value(contents) if contents == b"0\n" => Ok(TempFsidMarker::Permanent),
    Reading::Value(contents) if contents == b"1\n" => Ok(TempFsidMarker::Temporary),
    Reading::Value(_) => Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "a btrfs temp_fsid that is neither 0 nor 1",
    )),
    Reading::Declined(err) if err.kind() == io::ErrorKind::NotFound => Ok(TempFsidMarker::NotFound),
    Reading::Absent | Reading::Declined(_) => Ok(TempFsidMarker::Unreadable),
    Reading::Failed(err) => Err(err),
  }
}

/// What an observation falls back to when btrfs did not answer:
/// `/dev/disk/by-uuid` — the one rule every observation's identity goes
/// through.
///
/// For a btrfs mount the outcome set is exactly
/// {[`Matched`](BtrfsLookup::Matched), [`Refused`](BtrfsLookup::Refused)} —
/// see [`BtrfsLookup`] — so `by_uuid_answer` is never invoked here: neither
/// arm below reaches for it. It stays a parameter anyway, for two reasons.
/// Every call site — the one in an observation's constructor, and every test
/// — keeps the one shape regardless of
/// whether a future narrowing changes what refuses, so a change that reopens
/// a branch here has to decide on purpose what to do with a by-uuid answer,
/// rather than silently gaining access to a road
/// [`BtrfsLookup`]'s own doc comment says a btrfs mount must never
/// be handed. And the panic-if-called fixtures — including ones for a
/// readable-empty and a truncated sysfs root — keep proving that promise at
/// this exact boundary, even though nothing here could call it today.
fn identity_after_btrfs(
  btrfs: BtrfsLookup,
  _by_uuid_answer: impl FnOnce() -> io::Result<Option<IdentityReading>>,
) -> Option<IdentityReading> {
  match btrfs {
    BtrfsLookup::Matched(reading) => Some(reading),
    BtrfsLookup::Refused => None,
  }
}

/// Reads a sysfs `dev` file — one line of `major:minor` — as a device number.
///
/// A file that was read and is not exactly that line is not the kernel's
/// writing (`print_dev_t`), and is `Failed(InvalidData)` rather than a device
/// with no number; every other outcome is the read's own.
fn sysfs_device_number(sysfs: &KernelDir, path: &Path) -> Reading<u64> {
  sysfs
    .read_linked(path)
    .and_then(|contents| match parse_device_number(&contents) {
      Some(number) => Reading::Value(number),
      None => Reading::Failed(io::Error::new(
        io::ErrorKind::InvalidData,
        "a sysfs dev file that is not one line of major:minor",
      )),
    })
}

/// The census of `/dev/disk/by-uuid`: every entry that names a block device,
/// as `(device number, identity)`, the identity `None` where the entry's name
/// is not one this crate can classify — which still makes it a name for that
/// device. See [`udev_entries`].
///
/// The identity here is classified from the name's width alone; the caller
/// still has to pass it through [`linux_identity`](super::linux_identity) with
/// the mount's filesystem type to reach the canonical form.
fn by_uuid_entries(dev: &KernelDir) -> io::Result<UdevCensus<VolumeIdentity>> {
  udev_entries(dev, "disk/by-uuid", |name| {
    Ok(super::parse_by_uuid_name(name))
  })
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
/// own `/proc` and its own `/dev` **wholesale**, and the mount table read
/// beneath that `/proc` — where the filesystem type that decides
/// [`Declared`](super::IdentityAssurance::Declared) comes from — is equally
/// theirs. What these roads refuse is a bind interposed *under* a genuine root.
/// That is worth refusing, and it is all that is claimed.
///
/// `openat2` is Linux 5.6 and later. Where it is missing every road through
/// here fails closed: no entries, no table, no identity — never a path open
/// standing in for one. That is the platform declining; a read that failed
/// for any other reason is returned as the error it is. Every read here comes
/// back as a [`Reading`], and its callers say what each outcome means.
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
  ///
  /// A root that is not the filesystem it must be is declined, as the
  /// containment declines a path it refuses: the road is closed, and the error
  /// the decline carries says why. Every other outcome is the open's or the
  /// `fstatfs`'s own.
  fn open(path: &str, magic: Option<rustix::fs::FsWord>) -> Reading<Self> {
    reading(rustix::fs::open(
      path,
      OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
      Mode::empty(),
    ))
    .and_then(|root| {
      let Some(magic) = magic else {
        return Reading::Value(Self { root });
      };
      match reading(rustix::fs::fstatfs(&root)) {
        Reading::Value(fs) if fs.f_type == magic => Reading::Value(Self { root }),
        Reading::Value(_) => Reading::Declined(io::Error::new(
          io::ErrorKind::InvalidData,
          format!("{path} is not the filesystem it must be"),
        )),
        Reading::Absent => Reading::Absent,
        Reading::Declined(err) => Reading::Declined(err),
        Reading::Failed(err) => Reading::Failed(err),
      }
    })
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
  ///
  /// `Absent` where the path opened and names a node of another kind; the
  /// open's own decline where nothing is there or the containment refused a
  /// link; and a lookup that failed is `Failed`. The difference between the
  /// first two is the one a census turns on: see [`udev_entries`].
  fn device_number(&self, path: &Path) -> Reading<u64> {
    reading(self.open_beneath(path, OFlags::PATH | OFlags::CLOEXEC, ResolveFlags::empty()))
      .and_then(|node| reading(rustix::fs::fstat(&node)))
      .and_then(|node| {
        // A number read off anything but a block device names nothing:
        // `st_rdev` is zero for a regular file, and a character device is not
        // what any of this is about.
        if rustix::fs::FileType::from_raw_mode(node.st_mode) == rustix::fs::FileType::BlockDevice {
          Reading::Value(node.st_rdev)
        } else {
          Reading::Absent
        }
      })
  }

  /// Every name a directory beneath this root holds, with symlinks refused on
  /// the way, read to the end the kernel proves: see [`listing`].
  fn dir(&self, path: &Path) -> Reading<Census<Vec<u8>>> {
    reading(self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
      ResolveFlags::NO_SYMLINKS,
    ))
    .and_then(listing)
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
  /// from the directory the link sits in. Read to its proven end like any
  /// other: see [`listing`].
  fn dir_linked(&self, path: &Path) -> Reading<Census<Vec<u8>>> {
    reading(self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
      ResolveFlags::empty(),
    ))
    .and_then(listing)
  }

  /// Reads a file beneath this root, keeping the difference between a file
  /// that is not there and one that could not be read — [`TempFsidMarker`]
  /// turns on it.
  fn read(&self, path: &Path) -> Reading<Vec<u8>> {
    reading(self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::CLOEXEC,
      ResolveFlags::NO_SYMLINKS,
    ))
    .and_then(|file| read_whole(file, u64::MAX))
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
  fn read_linked(&self, path: &Path) -> Reading<Vec<u8>> {
    reading(self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::CLOEXEC,
      ResolveFlags::empty(),
    ))
    .and_then(|file| read_whole(file, u64::MAX))
  }

  /// Reads at most `limit` bytes of a file beneath this root.
  ///
  /// The unbounded read is for files the kernel writes, whose length the kernel
  /// decides. A file this crate cannot authenticate is not one of those.
  fn read_bounded(&self, path: &Path, limit: u64) -> Reading<Vec<u8>> {
    reading(self.open_beneath(
      path,
      OFlags::RDONLY | OFlags::CLOEXEC,
      ResolveFlags::NO_SYMLINKS,
    ))
    .and_then(|file| read_whole(file, limit))
  }

  /// Where a symlink beneath this root points, read without following it.
  ///
  /// The target is the kernel's own spelling of where a device sits in its
  /// tree, which is the only thing that says which bus a device hangs off.
  /// Reading the link is not the same as walking it: nothing is opened, so
  /// nothing can be interposed along a path this never traverses.
  fn link_target(&self, path: &Path) -> Reading<Vec<u8>> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
      return Reading::Absent;
    };
    reading(self.open_beneath(
      parent,
      OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
      ResolveFlags::NO_SYMLINKS,
    ))
    .and_then(|dir| reading(rustix::fs::readlinkat(&dir, name, Vec::new())))
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

/// Everything an opened kernel file holds, up to `limit` bytes.
///
/// A file longer than `limit` is `Failed(InvalidData)`: it is no file of the
/// kind the read expects, and a read that stopped at the limit would hand its
/// head over as though it were the whole.
fn read_whole(file: OwnedFd, limit: u64) -> Reading<Vec<u8>> {
  use std::io::Read as _;

  let mut bytes = Vec::new();
  reading(
    std::fs::File::from(file)
      .take(limit.saturating_add(1))
      .read_to_end(&mut bytes),
  )
  .and_then(|read| {
    if read as u64 > limit {
      Reading::Failed(io::Error::new(
        io::ErrorKind::InvalidData,
        "a kernel file longer than any of its kind",
      ))
    } else {
      Reading::Value(bytes)
    }
  })
}

/// How many bytes one `getdents64` refill is offered: room for dozens of
/// entries, and far more than the longest single one a kernel writes.
const LISTING_BUFFER: usize = 8 * 1024;

/// Every name an opened directory holds, read to the end the kernel proves.
///
/// **This is the one road a directory is read by, and it has no partial
/// answer.** `rustix::fs::Dir` reads a refill that fails with `ENOENT` — a
/// directory removed while it is being read — as the end of the directory, so
/// a census taken through it could stop after one bufferful and report that
/// prefix as the whole. [`RawDir`](rustix::fs::RawDir) returns every refill's
/// error, and [`Census::read`] ends in it: the directory is read up to the
/// `getdents64` that returns nothing, which is the kernel's own end of
/// directory, or the census is refused (a declined refill) or fails (any other
/// error). An interrupted refill is asked again. `.` and `..` are the directory
/// itself and its parent, not names it holds.
fn listing(dir: OwnedFd) -> Reading<Census<Vec<u8>>> {
  use core::mem::MaybeUninit;

  let mut buffer = vec![MaybeUninit::<u8>::uninit(); LISTING_BUFFER];
  let mut entries = rustix::fs::RawDir::new(&dir, &mut buffer);
  Census::read(
    || loop {
      match entries.next()? {
        Ok(entry) => {
          let name = entry.file_name().to_bytes();
          if name != b"." && name != b".." {
            return Some(Ok(name.to_vec()));
          }
        }
        Err(rustix::io::Errno::INTR) => {}
        Err(errno) => return Some(Err(errno.into())),
      }
    },
    declined,
  )
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
fn proc_root() -> Reading<KernelDir> {
  KernelDir::open("/proc", Some(rustix::fs::PROC_SUPER_MAGIC))
}

/// Whether `name` is a pid and nothing else: no separator, no dot, no sign, no
/// emptiness, and a number the type a pid has can hold. Anything else is not a
/// name that may be built into a path beneath `/proc`, whatever it is.
fn is_pid(name: &[u8]) -> bool {
  !name.is_empty()
    && name.iter().all(u8::is_ascii_digit)
    && std::str::from_utf8(name).is_ok_and(|pid| pid.parse::<u32>().is_ok())
}

/// The directory **this procfs** gives the calling thread, `<tgid>/task/<tid>`
/// — read off the authenticated root's own `thread-self` link and held to that
/// shape. Both the calling thread's mount table and its descriptors' `fdinfo`
/// are read beneath it.
///
/// **The thread's, not the process's.** A thread may have entered a mount
/// namespace of its own and unshared its descriptor table from the rest of its
/// process, so the mount table its pathnames resolve in and the table its
/// descriptor numbers were handed out in are both its own; `self` names the
/// thread-group leader's.
///
/// **This procfs's numbers, not the caller's.** A pid is meaningful only in a
/// pid namespace, and the numeric directories of a procfs are named in the
/// namespace that procfs was mounted in — which need not be the caller's. A
/// process in a child pid namespace that inherited an ancestor's procfs would
/// find its own ids naming *another* process there, and read that process's
/// mount table: another mount namespace, so another source, another filesystem
/// type, and an identity or a label belonging to a volume the caller never
/// asked about. That needs no hostile mount at all, which is why the limit
/// stated on [`KernelDir`] does not cover it. `thread-self` is the translation
/// the kernel provides, and reading the link is how to ask for it without
/// following it: `readlinkat` on the authenticated root yields the numbers and
/// resolves nothing. What comes back is then held to what a thread's directory
/// may be — two pids around `task`, nothing else — so that nothing else can be
/// spelled into a path built from it, and every read beneath it stays
/// symlink-free and guarded like every other structural read here.
///
/// A link spelled any other way is not the kernel's writing
/// (`proc_thread_self_get_link` writes exactly `<tgid>/task/<tid>`, and a
/// caller with no pid in this procfs's namespace gets `ENOENT`, not a link),
/// so it is `Failed(InvalidData)`: nothing may be built into a path from it.
fn procfs_thread(proc_root: &KernelDir) -> Reading<Vec<u8>> {
  reading(rustix::fs::readlinkat(
    &proc_root.root,
    "thread-self",
    Vec::new(),
  ))
  .and_then(|link| {
    let path = link.to_bytes();
    let mut parts = path.split(|&byte| byte == b'/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
      (Some(tgid), Some(task), Some(tid), None)
        if task == b"task" && is_pid(tgid) && is_pid(tid) =>
      {
        Reading::Value(path.to_vec())
      }
      _ => Reading::Failed(io::Error::new(
        io::ErrorKind::InvalidData,
        "a thread-self link that is not <tgid>/task/<tid>",
      )),
    }
  })
}

/// The mount id a descriptor's `fdinfo` carries on its `mnt_id:` line;
/// `None` only where it carries no such line — a kernel before 3.15, which
/// never writes one.
///
/// The file must be whole — see [`whole_lines`] — before any line of it is
/// read, and a `mnt_id:` line whose value is not a tab and a decimal number
/// (`seq_printf(m, "mnt_id:\t%i\n", ...)`) is not the kernel's writing: both
/// are `InvalidData`.
fn parse_fdinfo_mount_id(contents: &[u8]) -> io::Result<Option<u64>> {
  let Some(value) = whole_lines(contents)?.find_map(|line| line.strip_prefix(b"mnt_id:")) else {
    return Ok(None);
  };
  value
    .strip_prefix(b"\t")
    .and_then(parse_u64)
    .map(Some)
    .ok_or_else(|| {
      io::Error::new(
        io::ErrorKind::InvalidData,
        "an fdinfo mnt_id line that is not a tab and a decimal number",
      )
    })
}

/// Every line of a file written line by line — the kernel's `seq_file`
/// tables, udev's database — each without its newline, or `InvalidData`
/// where the file does not end in one: its writer ends every line, so bytes
/// after the last newline are a line it never finished, and a file cut short
/// is no file it wrote. An empty file has no lines.
fn whole_lines(contents: &[u8]) -> io::Result<impl Iterator<Item = &[u8]>> {
  let lines = match contents.strip_suffix(b"\n") {
    Some(lines) => Some(lines),
    None if contents.is_empty() => None,
    None => {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "a file whose last line has no newline",
      ));
    }
  };
  Ok(
    lines
      .into_iter()
      .flat_map(|lines| lines.split(|&byte| byte == b'\n')),
  )
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
fn block_backed_types(proc_root: &KernelDir) -> io::Result<super::BlockBackedTypes> {
  // A table the platform declined to hand over is no table, and leaves every
  // read `Declared`; a read that failed is the error it is.
  let Some(table) = proc_root.read(Path::new("filesystems")).answered()? else {
    return Ok(super::BlockBackedTypes::none());
  };
  // A table read whole that breaks the kernel's grammar is not the kernel's
  // table: an error, never a roster with nothing in it.
  super::BlockBackedTypes::parse(&table).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidData,
      "a /proc/filesystems that is not the kernel's grammar",
    )
  })
}

/// Linux: the label `/dev/disk/by-label` publishes for one device.
///
/// The road is the identity's own, one directory across: udev names a symlink
/// after what `blkid` read out of the superblock and points it at the device
/// node, so reversing the link recovers the label without `libblkid`, without
/// opening the block device, and without root. What comes back is a label, not
/// an identity — see [`volume_name()`](super::MountPoint::volume_name) for what
/// that does and does not promise.
///
/// The same refusals the identity makes apply, for the same reasons: a census
/// that could not be read whole names nothing, for any device, and where two
/// labels resolve to one device node — a departed volume's link that udev has
/// not re-pointed yet, beside the arriving one's — neither is reported:
/// whichever the directory yields first is a coin toss, and a name shown to a
/// user is worth less than a wrong one costs. So does a name nothing can show
/// agrees with the rest.
///
/// `None` where udev published nothing for the device: an unlabeled volume, a
/// pseudo filesystem, or a system where udev is not running. An observation
/// then asks udev's runtime database, at `Declared` — see
/// [`udev_database_label`] — and the caller's fallback names the volume from
/// its mount point where that has none either. btrfs is never asked here: its
/// label is read in its census, beside its FSID.
fn label_for_device(census: &UdevCensus<SmallBytes>, device: u64) -> Option<SmallBytes> {
  let UdevCensus::Complete(entries) = census else {
    return None;
  };
  let mut found: Option<&SmallBytes> = None;
  for (target, label) in entries {
    if *target != device {
      continue;
    }
    let Some(label) = label else {
      return None;
    };
    match found {
      None => found = Some(label),
      Some(seen) if seen == label => {}
      // Two labels, one node: neither names the volume.
      Some(_) => return None,
    }
  }
  found.cloned()
}

/// The census of `/dev/disk/by-label`: every entry that names a block device,
/// as `(device number, label)`, the label `None` where the name decodes to
/// nothing. A name udev could not have written — see [`decode_udev_escapes`]
/// — fails the census with `InvalidData`. See [`udev_entries`].
fn by_label_entries(dev: &KernelDir) -> io::Result<UdevCensus<SmallBytes>> {
  udev_entries(dev, "disk/by-label", |name| {
    let label = decode_udev_escapes(name)?;
    Ok((!label.as_bytes().is_empty()).then_some(label))
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
///
/// **The census is complete or refused.** Both callers refuse where two names
/// resolve to one device node, and that refusal is decided over the whole
/// directory: an entry passed over because it could not be read may be exactly
/// the second name. So the directory is read whole or not at all — a directory
/// the platform declined, a listing it stopped handing over partway, and an
/// entry whose link was declined while it was resolved (nothing there any
/// more, a link the containment refused) each refuse the census, and a read
/// that failed is the error it is. The listing itself is read to the end the
/// kernel proves, so a directory removed or replaced partway through refuses
/// the census rather than handing over the entries read before it: see
/// [`listing`]. The one entry left out is one that opened and is not a block
/// device, which names no volume at all. A name that is not a value this road
/// reads is kept, as `None`: it is still a name for the node it resolves to.
/// A name udev could not have written is no such name: `read_name` answers
/// `InvalidData` for it, and the census fails with that error.
fn udev_entries<T>(
  dev: &KernelDir,
  directory: &str,
  read_name: impl Fn(&[u8]) -> io::Result<Option<T>>,
) -> io::Result<UdevCensus<T>> {
  // The directory is read whole — to the end the kernel proves, see
  // [`listing`] — before one entry of it is resolved.
  let Some(entries) = dev.dir(Path::new(directory)).answered()? else {
    return Ok(UdevCensus::Refused);
  };
  let mut found = Vec::new();
  for name in entries {
    let mut path = Vec::with_capacity(directory.len() + 1 + name.len());
    path.extend_from_slice(directory.as_bytes());
    path.push(b'/');
    path.extend_from_slice(&name);
    match dev.device_number(Path::new(OsStr::from_bytes(&path))) {
      Reading::Value(number) => found.push((number, read_name(&name)?)),
      // Opened, and not a block device: it names no volume.
      Reading::Absent => {}
      // Declined while it was being resolved: what it would have named is
      // exactly what the refusal is decided over.
      Reading::Declined(_) => return Ok(UdevCensus::Refused),
      Reading::Failed(err) => return Err(err),
    }
  }
  Ok(UdevCensus::Complete(found))
}

/// One `/dev/disk/by-*` directory, read whole or not at all: see
/// [`udev_entries`].
enum UdevCensus<T> {
  /// Every entry was read. Each names the block device its link resolves to,
  /// and the value its own name spells — `None` where the name is not a value
  /// this road reads, which still makes it a name for that device.
  Complete(Vec<(u64, Option<T>)>),
  /// Something was declined partway, and what was not read could be the very
  /// name that settles an answer. A refused census names nothing, for any
  /// device.
  Refused,
}

/// Decodes the `\x20`-style escapes udev writes into the names under
/// `/dev/disk/by-label` and into `ID_FS_LABEL_ENC`, which cannot carry a
/// space, a slash or a non-printable byte literally.
///
/// **Whole, or `InvalidData`.** The encoder — `encode_devnode_name` in udev,
/// `blkid_encode_string` in libblkid — writes a backslash only as the start of
/// `\x` and two hex digits, and escapes a backslash of the label itself as
/// `\x5c`. So a backslash that begins anything else, or an escape cut short,
/// is no name the encoder wrote, and decoding it into a label would publish
/// bytes nobody wrote on the volume.
fn decode_udev_escapes(input: &[u8]) -> io::Result<SmallBytes> {
  // Fast path: no backslash means no escapes to decode.
  if super::find_byte(b'\\', input).is_none() {
    return Ok(SmallBytes::from_bytes(input));
  }

  // Decoding only shrinks (a 4-byte escape becomes one byte).
  let mut out = Vec::with_capacity(input.len());
  let mut rest = input;
  while let Some((&byte, tail)) = rest.split_first() {
    if byte != b'\\' {
      out.push(byte);
      rest = tail;
      continue;
    }
    let [b'x', hi, lo, after @ ..] = tail else {
      return Err(malformed_udev_escape());
    };
    let (Some(hi), Some(lo)) = (super::hex_digit(*hi), super::hex_digit(*lo)) else {
      return Err(malformed_udev_escape());
    };
    out.push((hi << 4) | lo);
    rest = after;
  }
  Ok(SmallBytes::from_bytes(&out))
}

/// The error a udev name or value that its encoder could not have written
/// ends in: see [`decode_udev_escapes`].
fn malformed_udev_escape() -> io::Error {
  io::Error::new(
    io::ErrorKind::InvalidData,
    "a udev name with a backslash that begins no \\xNN escape",
  )
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
/// A record that is not there is no label, and a read that failed is the error
/// it is. A record udev could not have written — see [`udev_label_in`] — is
/// `InvalidData`, never a missing label the mount point would stand in for.
fn udev_database_label(device: u64) -> io::Result<Option<SmallBytes>> {
  /// A udev database record for one device is a short list of short lines.
  /// Reading past this is reading something that is not one.
  const LIMIT: u64 = 64 * 1024;

  let Some(run) = KernelDir::open("/run", None).answered()? else {
    return Ok(None);
  };
  let (major, minor) = unmakedev(device);
  let path = format!("udev/data/b{major}:{minor}");
  let Some(record) = run.read_bounded(Path::new(&path), LIMIT).answered()? else {
    return Ok(None);
  };
  udev_label_in(&record)
}

/// The label one udev database record carries: `ID_FS_LABEL_ENC`, decoded, or
/// `None` where the record has no such key or its value decodes to nothing.
///
/// The record is held whole before any key of it is looked at — udev ends
/// every line it writes, so one cut short is no record it wrote — and the
/// value must decode strictly: see [`whole_lines`] and
/// [`decode_udev_escapes`]. Either failing is `InvalidData`.
fn udev_label_in(record: &[u8]) -> io::Result<Option<SmallBytes>> {
  const KEY: &[u8] = b"E:ID_FS_LABEL_ENC=";

  let Some(value) = whole_lines(record)?.find_map(|line| line.strip_prefix(KEY)) else {
    return Ok(None);
  };
  let label = decode_udev_escapes(value)?;
  Ok((!label.as_bytes().is_empty()).then_some(label))
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
/// **Linux denies only where the kernel writes `fixed`.** The device core
/// publishes one attribute that answers the removal question itself —
/// `removable`, reading `removable`, `fixed` or `unknown` — on the devices of
/// a bus that states it: USB writes it on every device from the port the
/// device is plugged into (`set_usb_port_removable`, `drivers/usb/core/hub.c`:
/// a port the firmware describes as hard-wired or not user-visible, or a
/// compound hub's non-removable port, is `fixed`), and PCI writes `removable`
/// below a port the firmware marks external (`pci_set_removable`,
/// `drivers/pci/probe.c`) and nothing otherwise. Nothing else in the kernel
/// writes `fixed`. So a disk is
/// [`NotEjectable`](super::Ejectability::NotEjectable) exactly where it hangs
/// off USB, **every** USB device between it and its host controller reads
/// `fixed` — a hard-wired hub inside a dock that is itself plugged in is not
/// fixed to the machine, and the dock's own port says so — no device on the
/// way reads `removable` or `unknown` (a USB root hub excepted: its `unknown`
/// only says it has no port), and the disk's own media flag reads `0`. Every
/// read that denial rests on must have answered; one that did not leaves the
/// answer to the roads below.
///
/// What is never a denial, and why earlier rounds of this branch were wrong to
/// make one of each:
///
/// - The media flag `removable` describes the **media**, not the drive. An
///   external USB disk reads `0` because nothing is taken out *of it*.
/// - Bus ancestry is an allowlist, and an allowlist can only ever say yes. A
///   drive on eSATA or Thunderbolt is absent from it and is no less removable
///   for that.
/// - A virtual block device — dm-crypt, LVM, MD, loop — has no bus of its own
///   at all, so its ancestry says nothing about the disks underneath it.
///
/// An internal SATA or NVMe disk therefore reads
/// [`Unknown`](super::Ejectability::Unknown): the kernel has no `fixed` to
/// write for it.
///
/// **What counts as `Ejectable`,** asked of sysfs beneath the authenticated
/// `/sys` root and keyed by the device number:
///
/// - the media flag reading `1` — the kernel saying the media comes out;
/// - an MMC card whose own `type` the kernel writes as `SD`. An MMC host
///   carries soldered eMMC as often as a card slot, and the MMC block driver
///   never sets the media flag, so the ancestry alone is no answer: an eMMC
///   reads `MMC`, and is [`Unknown`](super::Ejectability::Unknown);
/// - any device on the way reading `removable`;
/// - an ancestry through the USB subsystem that no `fixed` denied — the
///   kernel saying the drive hangs off a bus whose devices leave while the
///   machine runs;
/// - any of those on a device a virtual device is **built from**. A dm-crypt
///   volume over a USB disk is as removable as the disk under it, so `slaves/`
///   is walked, to a bounded depth. A virtual device is denied only where every
///   device it is built from is.
///
/// **Every fact is bound to the mount and to one attach of the device, and a
/// device number binds nothing on its own.** A mount holds its filesystem,
/// not the device a number names now: a disk that left while mounted, and a
/// device given its number since — or a device mapper table reloaded, an NBD
/// device reconnected — would answer for storage the mounted filesystem is
/// not on. So the answer is given only where three things hold:
///
/// 1. **The mounted filesystem names itself**, through a descriptor held to the
///    pinned mount — its UUID (`FS_IOC_GETFSUUID`, Linux 6.9), a FAT volume's
///    serial (`FAT_IOCTL_GET_VOLUME_ID`), or btrfs's FSID — and udev names the
///    same identity for the device now, published for **this attach** of it:
///    the attach's `diskseq` (Linux 5.15) has its own `/dev/disk/by-diskseq`
///    link to the device, which udev makes while it handles that attach (systemd
///    251), and the identity is read from `/dev/disk/by-uuid` after the attach
///    was taken — see [`device_sequence`] and [`published_at`].
/// 2. **Every device the answer is read from is taken at one attach**: the
///    `diskseq` of each — the disk, and each device a stack is built from — is
///    read before its attributes are, and again after the whole answer.
/// 3. **Nothing moved**: each is the same attach after as before.
///
/// Anything else — a filesystem that names no identity through its mount
/// (exFAT, NTFS, ISO 9660, UDF, XFS and ext4 before 6.9, a root this process
/// may not read), a kernel with no `diskseq`, a udev that publishes no
/// `by-diskseq` link, an identity udev does not name for the device, a
/// sequence that moved — is [`Unknown`](super::Ejectability::Unknown).
///
/// `sysfs` is the root [`removal_root`] opened for this question alone; like
/// every other failure on this road, one that could not be had is `Unknown`
/// rather than an error.
fn bound_removal(
  sysfs: &KernelDir,
  device: u64,
  mounted: VolumeIdentity,
  published: impl FnOnce(Sequence) -> Option<VolumeIdentity>,
) -> Ejectability {
  bound_removal_with(sysfs, device, mounted, published, || {})
}

/// [`bound_removal`], with `between` run after the answer was read and before
/// every attach is taken again — where a law moves one.
fn bound_removal_with(
  sysfs: &KernelDir,
  device: u64,
  mounted: VolumeIdentity,
  published: impl FnOnce(Sequence) -> Option<VolumeIdentity>,
  between: impl FnOnce(),
) -> Ejectability {
  let Some(attach) = device_sequence(sysfs, device) else {
    return Ejectability::Unknown;
  };
  if published(attach) != Some(mounted) {
    return Ejectability::Unknown;
  }
  let mut attaches = Vec::new();
  let answer = device_removal(
    sysfs,
    device,
    0,
    &mut |device| match device_sequence(sysfs, device) {
      Some(attach) => {
        attaches.push((device, attach));
        true
      }
      None => false,
    },
  );
  between();
  let held = device_sequence(sysfs, device) == Some(attach)
    && attaches
      .iter()
      .all(|&(device, attach)| device_sequence(sysfs, device) == Some(attach));
  if held { answer } else { Ejectability::Unknown }
}

/// The removal answer with no binding at all, for the laws that hold the
/// topology rules of [`bound_removal`] to fixture trees: every device is taken
/// as bound.
#[cfg(test)]
fn device_ejectability(sysfs: Option<&KernelDir>, device: Option<u64>) -> Ejectability {
  let (Some(sysfs), Some(device)) = (sysfs, device) else {
    return Ejectability::Unknown;
  };
  device_removal(sysfs, device, 0, &mut |_| true)
}

/// Which attach of a block device sysfs names now: its disk's `diskseq`,
/// which the kernel hands no other attach of any disk while it runs (Linux
/// 5.15, `block/genhd.c`: a sequence number that tells the uses of one device
/// name apart), and, for a partition, its number within the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sequence {
  disk: u64,
  partition: Option<u64>,
}

/// The attach of `device` sysfs names now — see [`Sequence`] — read beneath
/// `sysfs` by the device number, as every removal fact is; `None` where the
/// kernel publishes no sequence (before 5.15), or anything on the way is not
/// the kernel's writing — one decimal line.
fn device_sequence(sysfs: &KernelDir, device: u64) -> Option<Sequence> {
  let (major, minor) = unmakedev(device);
  let block = format!("dev/block/{major}:{minor}");
  // A partition's sequence is its disk's, and its number within the disk
  // tells it from the disk's other partitions.
  let (disk, partition) = match sysfs.read_linked(Path::new(&format!("{block}/partition"))) {
    Reading::Value(number) => (format!("{block}/.."), Some(decimal_line(&number)?)),
    Reading::Declined(err) if err.kind() == io::ErrorKind::NotFound => (block, None),
    _ => return None,
  };
  let sequence = sysfs
    .read_linked(Path::new(&format!("{disk}/diskseq")))
    .evidence()?;
  Some(Sequence {
    disk: decimal_line(&sequence)?,
    partition,
  })
}

/// One line of decimal digits, as sysfs writes a number.
fn decimal_line(contents: &[u8]) -> Option<u64> {
  parse_u64(contents.strip_suffix(b"\n")?)
}

/// Whether udev published `attach` of `device`: its `/dev/disk/by-diskseq`
/// link — `<diskseq>`, or `<diskseq>-part<n>` for a partition — resolves to
/// the device. udev makes it while it handles that attach, so the rest of
/// what udev publishes for the device is no older than the attach.
fn published_at(dev: &KernelDir, device: u64, attach: Sequence) -> bool {
  let link = match attach.partition {
    None => format!("disk/by-diskseq/{}", attach.disk),
    Some(number) => format!("disk/by-diskseq/{}-part{number}", attach.disk),
  };
  dev.device_number(Path::new(&link)).evidence() == Some(device)
}

/// The identity udev publishes for `device` under `/dev/disk/by-uuid` now —
/// one census read for this answer alone, after its attach was taken — in the
/// form `fs_type` gives it: see
/// [`linux_identity_for_device`](super::linux_identity_for_device). `None` where
/// the census is refused or names none for the device.
fn published_identity(dev: &KernelDir, device: u64, fs_type: &[u8]) -> Option<VolumeIdentity> {
  match by_uuid_entries(dev).ok()? {
    UdevCensus::Complete(entries) => super::linux_identity_for_device(
      entries.iter().map(|&(target, identity)| (target, identity)),
      device,
      fs_type,
      super::IdentityAssurance::Published,
    )
    .map(|reading| reading.identity()),
    UdevCensus::Refused => None,
  }
}

/// The `/sys` the removal question is asked beneath, opened for that question
/// alone and only once a device is in hand.
///
/// Every outcome but a root is `None`, a failure included: the removal
/// question answers [`Unknown`](super::Ejectability::Unknown) wherever it could
/// not be asked, and a `/sys` that would not open is exactly that — never a
/// reason to fail the resolve or the listing that asked. The btrfs census opens
/// its own, and keeps its stricter contract: see [`btrfs_sysfs`].
fn removal_root() -> Option<KernelDir> {
  KernelDir::open("/sys", Some(SYSFS_MAGIC)).evidence()
}

/// How far down a stack of virtual devices the search for real storage goes.
///
/// dm over md over dm is already unusual; anything deeper is a loop or a
/// misreading, and a bounded walk cannot become one.
const SLAVE_DEPTH: u32 = 8;

/// What the kernel says about one block device's storage, or about what it is
/// built from: see [`bound_removal`] for every road and its order. `bind` is
/// asked for each device before anything is read about it, and a device it
/// does not bind answers nothing.
///
/// Every read here can only lose an answer: a read that fails — declined or
/// not — is treated the same as one that found nothing, and a denial needs
/// every read it rests on to have answered. The answer left is
/// [`Unknown`](super::Ejectability::Unknown), which is the platform not having
/// been asked. That is the documented meaning of that state, and the one road
/// on this backend where a failure is not an error — which is why every read
/// here ends in [`Reading::evidence`], and no read anywhere else does.
fn device_removal(
  sysfs: &KernelDir,
  device: u64,
  depth: u32,
  bind: &mut dyn FnMut(u64) -> bool,
) -> Ejectability {
  if !bind(device) {
    return Ejectability::Unknown;
  }
  let (major, minor) = unmakedev(device);
  let block = format!("dev/block/{major}:{minor}");

  // A partition's media flag lives on the disk above it, and a partition's
  // directory sits inside the disk's.
  let partition = match sysfs.read_linked(Path::new(&format!("{block}/partition"))) {
    Reading::Value(_) => Some(true),
    Reading::Declined(err) if err.kind() == io::ErrorKind::NotFound => Some(false),
    _ => None,
  };
  let media = partition.and_then(|partition| {
    let flag = if partition {
      format!("{block}/../removable")
    } else {
      format!("{block}/removable")
    };
    match sysfs.read_linked(Path::new(&flag)).evidence()?.as_slice() {
      b"1\n" => Some(true),
      b"0\n" => Some(false),
      _ => None,
    }
  });
  if media == Some(true) {
    return Ejectability::Ejectable;
  }

  // The kernel's own path for this device, read without walking it.
  if let Some(ancestry) = sysfs.link_target(Path::new(&block)).evidence() {
    if names_mmc_host(&ancestry) && is_sd_card(sysfs, &block) {
      return Ejectability::Ejectable;
    }
    match partition.and_then(|partition| ports_say(sysfs, &ancestry, partition)) {
      Some(Ports::Removable) => return Ejectability::Ejectable,
      // The kernel says every link a user could break is fixed, which no bus
      // allowlist overrides: the answer is the denial where the media stays
      // too, and nothing where its flag could not be read.
      Some(Ports::Fixed) if media == Some(false) => return Ejectability::NotEjectable,
      Some(Ports::Fixed) => return Ejectability::Unknown,
      None => {}
    }
    if names_removable_bus(&ancestry) {
      return Ejectability::Ejectable;
    }
  }

  if depth >= SLAVE_DEPTH {
    return Ejectability::Unknown;
  }
  // A virtual device is as removable as the storage it is built from: a
  // dm-crypt volume on a USB disk goes with the disk. `slaves/` is where the
  // kernel names those, and each name is a block device of its own. A yes on
  // any of them is a yes; a denial needs one on every one, and at least one.
  //
  // Reached with `dir_linked`, because `dev/block/<major>:<minor>` is itself a
  // symlink: a structural open refuses it before `slaves` is ever read, and
  // this walk then never ran on any real kernel.
  let Some(slaves) = sysfs
    .dir_linked(Path::new(&format!("{block}/slaves")))
    .evidence()
  else {
    return Ejectability::Unknown;
  };
  let mut every_one_fixed = true;
  let mut any = false;
  for name in slaves {
    any = true;
    let dev = KernelDir::at(&[block.as_bytes(), b"slaves", &name, b"dev"]);
    let Some(number) = sysfs_device_number(sysfs, Path::new(OsStr::from_bytes(&dev))).evidence()
    else {
      every_one_fixed = false;
      continue;
    };
    match device_removal(sysfs, number, depth + 1, bind) {
      Ejectability::Ejectable => return Ejectability::Ejectable,
      Ejectability::NotEjectable => {}
      _ => every_one_fixed = false,
    }
  }
  if any && every_one_fixed {
    Ejectability::NotEjectable
  } else {
    Ejectability::Unknown
  }
}

/// What the device core's `removable` attributes say along a block device's
/// ancestry, where they settle anything: see [`bound_removal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ports {
  /// A device on the way reads `removable`.
  Removable,
  /// The device hangs off USB and every USB device on the way reads `fixed`,
  /// and nothing else on the way reads `removable` or `unknown`.
  Fixed,
}

/// What one device's `removable` attribute said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortWord {
  Removable,
  Fixed,
  Unknown,
  /// The device carries no such attribute: its bus states none.
  Absent,
  /// The attribute could not be read, or was not one of the kernel's words.
  Unread,
}

/// The device core's `removable` attribute, as the kernel writes it
/// (`removable_show`, `drivers/base/core.c`): one of three words and a
/// newline. Anything else is not the kernel's writing, and says nothing.
fn port_word(contents: &[u8]) -> PortWord {
  match contents {
    b"removable\n" => PortWord::Removable,
    b"fixed\n" => PortWord::Fixed,
    b"unknown\n" => PortWord::Unknown,
    _ => PortWord::Unread,
  }
}

/// What the `removable` attributes of every device between a block device and
/// the root of the device tree say — `None` where they settle nothing. See
/// [`bound_removal`] for the rule; the devices are read beneath `/sys`
/// by the kernel's own spelling of where the block device sits, `ancestry`.
fn ports_say(sysfs: &KernelDir, ancestry: &[u8], partition: bool) -> Option<Ports> {
  let mut usb_hops = 0usize;
  let mut every_hop_fixed = true;
  for (dir, name) in device_dirs(ancestry, partition)? {
    let word = match sysfs.read(Path::new(&format!("{dir}/removable"))) {
      Reading::Value(contents) => port_word(&contents),
      Reading::Declined(err) if err.kind() == io::ErrorKind::NotFound => PortWord::Absent,
      Reading::Absent | Reading::Declined(_) | Reading::Failed(_) => PortWord::Unread,
    };
    if word == PortWord::Removable {
      return Some(Ports::Removable);
    }
    if is_usb_device(&name) {
      usb_hops += 1;
      every_hop_fixed &= word == PortWord::Fixed;
    } else if is_usb_root_hub(&name) {
      // A root hub has no port: its `unknown` says only that.
      every_hop_fixed &= matches!(word, PortWord::Unknown | PortWord::Absent);
    } else {
      every_hop_fixed &= matches!(word, PortWord::Fixed | PortWord::Absent);
    }
  }
  (usb_hops > 0 && every_hop_fixed).then_some(Ports::Fixed)
}

/// The directories of the devices a block device hangs off, outermost first,
/// as paths beneath `/sys`, each with its own name — out of the kernel's
/// spelling of where the block device sits, the target of
/// `dev/block/<major>:<minor>`.
///
/// The block device's own directories — the disk's, and a partition's inside
/// it — and the `block` class directory most drivers put them in are no
/// device a port holds, and the disk's `removable` there is its media flag:
/// they are left out. `None` for a spelling that is not a path under
/// `devices/`, or has a component no path the kernel writes has.
fn device_dirs(ancestry: &[u8], partition: bool) -> Option<Vec<(String, Vec<u8>)>> {
  let parts: Vec<&[u8]> = ancestry
    .split(|&byte| byte == b'/')
    .skip_while(|part| *part == b"..")
    .collect();
  let (first, rest) = parts.split_first()?;
  if *first != b"devices" {
    return None;
  }
  let mut end = rest.len().checked_sub(if partition { 2 } else { 1 })?;
  if end > 0 && rest[end - 1] == b"block" {
    end -= 1;
  }
  let mut path = String::from("devices");
  let mut dirs = Vec::with_capacity(end);
  for part in &rest[..end] {
    if part.is_empty() || *part == b"." || *part == b".." {
      return None;
    }
    path.push('/');
    path.push_str(std::str::from_utf8(part).ok()?);
    dirs.push((path.clone(), part.to_vec()));
  }
  Some(dirs)
}

/// Whether a device directory's name is a USB device's: `<bus>-<port>`, then
/// `.<port>` for each hub below the root hub (`usb_new_device`'s
/// `dev_set_name`, `drivers/usb/core/usb.c`). An interface (`1-3:1.0`) and a
/// root hub (`usb1`) are not.
fn is_usb_device(name: &[u8]) -> bool {
  let mut halves = name.splitn(2, |&byte| byte == b'-');
  let (Some(bus), Some(ports)) = (halves.next(), halves.next()) else {
    return false;
  };
  let digits = |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
  digits(bus) && ports.split(|&byte| byte == b'.').all(digits)
}

/// Whether a device directory's name is a USB root hub's: `usb<bus>`.
fn is_usb_root_hub(name: &[u8]) -> bool {
  name
    .strip_prefix(b"usb")
    .is_some_and(|bus| !bus.is_empty() && bus.iter().all(u8::is_ascii_digit))
}

/// A sysfs `dev` file — one line of `major:minor` — as a device number.
fn parse_device_number(contents: &[u8]) -> Option<u64> {
  let line = contents.strip_suffix(b"\n")?;
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
/// `.../usb1/1-3/1-3:1.0/host6/.../block/sdb`. Matching a whole path component
/// rather than a substring is what keeps a disk label or a vendor name
/// spelling `usb` from answering for the bus.
fn names_removable_bus(ancestry: &[u8]) -> bool {
  ancestry.split(|&byte| byte == b'/').any(|component| {
    // `usb1`, `usb2`, … are the controllers; `usb` itself is the subsystem.
    component.starts_with(b"usb") && component[3..].iter().all(u8::is_ascii_digit)
  })
}

/// Whether a device hangs off an MMC host — `.../mmc_host/mmc0/mmc0:0001/...`
/// — which carries an SD card and soldered eMMC alike: see [`is_sd_card`].
fn names_mmc_host(ancestry: &[u8]) -> bool {
  ancestry
    .split(|&byte| byte == b'/')
    .any(|component| component == b"mmc_host")
}

/// Whether the MMC card a block device lives on is an SD card, by the card's
/// own `type` attribute, which the kernel writes as `MMC` for an MMC or eMMC
/// device and `SD` for an SD memory card (`type_show`,
/// `drivers/mmc/core/bus.c`). The card is the disk's `device`; a partition
/// reaches it through its disk. Anything but `SD` is no yes.
fn is_sd_card(sysfs: &KernelDir, block: &str) -> bool {
  sysfs
    .read_linked(Path::new(&format!("{block}/device/type")))
    .evidence()
    .or_else(|| {
      sysfs
        .read_linked(Path::new(&format!("{block}/../device/type")))
        .evidence()
    })
    .is_some_and(|card| card == b"SD\n")
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

/// A mount table field as the kernel's `mangle` spells it — every space, tab,
/// newline and backslash as a backslash and three octal digits — decoded, or
/// `None` for a spelling the kernel does not write.
///
/// **Strict.** The kernel escapes the backslash itself, so every backslash in
/// the table begins an escape: one followed by anything but three octal digits
/// naming a byte (`\000` to `\377`) is not the kernel's spelling of anything,
/// and the record it is in is refused rather than read as the characters it
/// happens to contain.
fn decode_escapes(input: &[u8]) -> Option<SmallBytes> {
  if super::find_byte(b'\\', input).is_none() {
    return Some(SmallBytes::from_bytes(input));
  }
  let mut out = BytesMut::with_capacity(input.len());
  let mut rest = input;
  while let Some(at) = super::find_byte(b'\\', rest) {
    out.put_slice(&rest[..at]);
    let digits = rest.get(at + 1..at + 4)?;
    let value = digits.iter().try_fold(0u16, |value, &digit| {
      (b'0'..=b'7')
        .contains(&digit)
        .then(|| value * 8 + u16::from(digit - b'0'))
    })?;
    out.put_u8(u8::try_from(value).ok()?);
    rest = &rest[at + 4..];
  }
  out.put_slice(rest);
  Some(SmallBytes::from_bytes(&out))
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

  // ── parse_record ──────────────────────────────────────────────────

  #[test]
  fn test_parse_mountinfo_valid() {
    let line = b"36 35 98:0 / /mnt rw,noatime shared:1 - ext3 /dev/root rw,errors=continue";
    let record = parse_record(line).unwrap();
    assert_eq!(record.id, 36);
    assert_eq!(record.mount_point.as_bytes(), b"/mnt");
    assert_eq!(record.fs_type.as_bytes(), b"ext3");
    assert_eq!(record.source.as_bytes(), b"/dev/root");
  }

  #[test]
  fn test_parse_mountinfo_with_optional_fields() {
    // Multiple optional fields before the separator
    let line = b"100 50 8:1 / /boot rw master:1 shared:2 - ext4 /dev/sda1 rw";
    let record = parse_record(line).unwrap();
    assert_eq!(record.id, 100);
    assert_eq!(record.mount_point.as_bytes(), b"/boot");
    assert_eq!(record.source.as_bytes(), b"/dev/sda1");
  }

  /// What the kernel writes and a strict reader must still take: a bind of an
  /// nsfs file, whose root is no path; a mount made with an empty source; and
  /// escaped spaces in the root, the mount point and the source.
  #[test]
  fn test_parse_mountinfo_takes_every_shape_the_kernel_writes() {
    let nsfs =
      parse_record(b"608 29 0:4 net:[4026532288] /run/netns/a rw shared:283 - nsfs nsfs rw")
        .unwrap();
    assert_eq!(nsfs.mount_point.as_bytes(), b"/run/netns/a");
    let empty_source =
      parse_record(b"40 21 0:50 / /mnt/t rw,relatime - tmpfs  rw,size=1k").unwrap();
    assert_eq!(empty_source.source.as_bytes(), b"");
    let escaped = parse_record(
      b"41 21 8:33 /a\\040b /media/my\\040disk rw - vfat /dev/disk\\040one rw,uid=1000",
    )
    .unwrap();
    assert_eq!(escaped.mount_point.as_bytes(), b"/media/my disk");
    assert_eq!(escaped.source.as_bytes(), b"/dev/disk one");
  }

  /// A record the kernel could not have written is refused whole: a field
  /// short, a field past the end, a field that breaks the grammar, or an
  /// escape the kernel does not spell.
  #[test]
  fn test_parse_mountinfo_refuses_what_the_kernel_would_not_write() {
    for line in [
      &b"36 35 98:0 / /mnt rw,noatime shared:1"[..],
      b"36 35",
      b"",
      // The example a truncated read leaves: no parent id, no super options.
      b"21 x 8:1 garbage / rw - ext4 /dev/sda1",
      b"21 1 8:1 / / rw - ext4 /dev/sda1",
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw extra",
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw ",
      b"21 1 8:1 / / rw - ext4 /dev/sda1 garbage",
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw,,noatime",
      b"21 1 81 / / rw - ext4 /dev/sda1 rw",
      b"21 1 8:1  / rw - ext4 /dev/sda1 rw",
      b"21 1 8:1 / relative rw - ext4 /dev/sda1 rw",
      b"21 1 8:1 / / noopts - ext4 /dev/sda1 rw",
      b"21 1 8:1 / / rw  - ext4 /dev/sda1 rw",
      b"21 1 8:1 / /  rw - ext4 /dev/sda1 rw",
      b"21 1 8:1 / /mnt\\04 rw - ext4 /dev/sda1 rw",
      b"21 1 8:1 / /mnt\\089 rw - ext4 /dev/sda1 rw",
      b"21 1 8:1 / /mnt\\777 rw - ext4 /dev/sda1 rw",
      b"21 1 8:1 / / rw -  /dev/sda1 rw",
    ] {
      assert!(
        parse_record(line).is_none(),
        "{:?}",
        String::from_utf8_lossy(line)
      );
    }
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

  // ── the calling thread's own table ─────────────────────────────────

  /// The mount table is the calling thread's, read beneath the directory the
  /// authenticated root's `thread-self` link names: where that link names no
  /// thread, there is no table at all, and neither the process's nor any
  /// other is read in its place.
  #[test]
  fn test_the_mount_table_is_the_calling_threads() {
    let dir = tempfile::tempdir().unwrap();
    // An empty target is not in the list because the kernel refuses to make
    // such a link at all, so no procfs could present one.
    for target in [
      "1/../2/task/3",
      "12a/task/1",
      "-1/task/2",
      "1 2/task/3",
      "./3/task/4",
      "self",
      "1",
    ] {
      let link = dir.path().join("thread-self");
      let _ = std::fs::remove_file(&link);
      std::os::unix::fs::symlink(target, &link).unwrap();
      let err = MountTable::read(&fixture(dir.path()))
        .err()
        .expect("no thread, no table");
      assert_eq!(
        err.kind(),
        io::ErrorKind::InvalidData,
        "a thread-self link reading {target:?} names no thread"
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
    assert_eq!(
      decode_udev_escapes(b"BACKUP").unwrap().as_bytes(),
      b"BACKUP"
    );
  }

  #[test]
  fn test_decode_udev_escapes_space() {
    assert_eq!(
      decode_udev_escapes(b"My\\x20Disk").unwrap().as_bytes(),
      b"My Disk".as_slice()
    );
  }

  #[test]
  fn test_decode_udev_escapes_several() {
    assert_eq!(
      decode_udev_escapes(b"a\\x2fb\\x20c\\x5C")
        .unwrap()
        .as_bytes(),
      b"a/b c\\".as_slice()
    );
  }

  /// The encoder writes a backslash only as the start of `\xNN`, so a
  /// backslash that begins anything else, or an escape cut short, is no name
  /// it wrote: `InvalidData`, never a byte of the label.
  #[test]
  fn test_decode_udev_escapes_refuses_what_the_encoder_never_wrote() {
    for input in [&b"a\\b"[..], b"a\\x2", b"a\\xzz", b"a\\", b"\\x", b"a\\X20"] {
      assert_eq!(
        decode_udev_escapes(input).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "{input:?}"
      );
    }
  }

  /// A udev database record is read whole before any key of it, and its
  /// label decoded strictly; a record without the key has no label.
  #[test]
  fn test_the_udev_database_label_is_read_whole() {
    assert_eq!(
      udev_label_in(b"S:disk/by-label/My\\x20Disk\nE:ID_FS_LABEL_ENC=My\\x20Disk\nG:systemd\n")
        .unwrap()
        .unwrap()
        .as_bytes(),
      b"My Disk"
    );
    for record in [&b"E:ID_FS_TYPE=ext4\n"[..], b"E:ID_FS_LABEL_ENC=\n", b""] {
      assert_eq!(udev_label_in(record).unwrap(), None, "{record:?}");
    }
    for record in [
      // A record cut short: the key's value, or the key itself, could be the
      // head of another.
      &b"E:ID_FS_LABEL_ENC=My\\x20Disk\nG:sys"[..],
      b"E:ID_FS_LABEL_ENC=My\\x20Di",
      b"E:ID_FS_LABEL_ENC=a\\b\n",
      b"E:ID_FS_LABEL_ENC=a\\x2\n",
    ] {
      assert_eq!(
        udev_label_in(record).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "{record:?}"
      );
    }
  }

  #[test]
  fn test_decode_no_escapes() {
    let result = decode_escapes(b"/mnt/data").unwrap();
    assert_eq!(result.as_bytes(), b"/mnt/data");
  }

  #[test]
  fn test_decode_space_escape_inline() {
    // \040 = space (0o40 = 32)
    let result = decode_escapes(b"/mnt/my\\040drive").unwrap();
    assert_eq!(result.as_bytes(), b"/mnt/my drive");
    assert!(matches!(result, SmallBytes::Inline { .. }));
  }

  #[test]
  fn test_decode_backslash_escape() {
    // \134 = backslash (0o134 = 92)
    let result = decode_escapes(b"/mnt/back\\134slash").unwrap();
    assert_eq!(result.as_bytes(), b"/mnt/back\\slash");
  }

  #[test]
  fn test_decode_multiple_escapes() {
    // \011 = tab (0o11 = 9), \012 = newline (0o12 = 10)
    let result = decode_escapes(b"a\\011b\\012c").unwrap();
    assert_eq!(result.as_bytes(), b"a\tb\nc");
  }

  /// The kernel escapes the backslash itself, so a backslash that begins no
  /// three-digit octal escape of one byte is no spelling the kernel writes,
  /// and nothing is decoded out of it.
  #[test]
  fn test_decode_refuses_what_the_kernel_does_not_spell() {
    for input in [
      &b"abc\\04"[..],
      b"abc\\",
      b"x\\089y",
      b"x\\400y",
      b"x\\777y",
      b"\\zzz",
      b"a\\b",
    ] {
      assert!(
        decode_escapes(input).is_none(),
        "{:?}",
        String::from_utf8_lossy(input)
      );
    }
    assert_eq!(decode_escapes(b"\\377").unwrap().as_bytes(), [0xff]);
    assert_eq!(decode_escapes(b"\\000").unwrap().as_bytes(), [0]);
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
    let result = decode_escapes(&input).unwrap();
    assert!(matches!(result, SmallBytes::Heap(_)));
    // The result should have a space at position 1
    assert_eq!(result.as_bytes()[1], b' ');
  }

  // ── the observation a resolve is formed from ──────────────────────

  /// The root's observation, as a resolve forms it.
  fn root_observation(pinned: &Pinned) -> Observation {
    let table = MountTable::read(&proc_fixture()).unwrap();
    Observation::resolved_for_laws(pinned, Path::new("/"), &table).unwrap()
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
    // is `/proc` — which does not contain `/`. Pairing that mount's pin with
    // the root path is the shape a moved or recycled mount would arrive in.
    let proc = proc_fixture();
    let procfs = Pinned::of(Path::new("/proc"), &proc).required().unwrap();
    let table = MountTable::read(&proc).unwrap();
    assert!(
      Observation::resolved_for_laws(&procfs, Path::new("/"), &table).is_err(),
      "a named row that does not contain the path is no answer about it"
    );

    // And the same pin asked about a path that row does contain still answers.
    let observation = Observation::resolved_for_laws(&procfs, Path::new("/proc"), &table).unwrap();
    assert_eq!(observation.mount_point().as_bytes(), b"/proc");
  }

  /// Every mount a pin can reach carries a mount id through one of the two
  /// kernel doors, and the root's line carries a filesystem type.
  #[test]
  fn test_a_resolve_observation_carries_its_lines_fs_type() {
    let pinned = Pinned::of(Path::new("/"), &proc_fixture())
      .required()
      .unwrap();
    let observation = root_observation(&pinned);
    assert_eq!(observation.mount_point().as_bytes(), b"/");
    assert!(!observation.fs_type().is_empty());
  }

  /// `fdinfo`'s `mnt_id:` line is the mount id; a file without one has none;
  /// and a file the kernel could not have written is `InvalidData`.
  #[test]
  fn test_the_fdinfo_mount_id_is_read_strictly() {
    assert_eq!(
      parse_fdinfo_mount_id(b"pos:\t0\nflags:\t012000000\nmnt_id:\t25\nino:\t2\n").unwrap(),
      Some(25)
    );
    assert_eq!(
      parse_fdinfo_mount_id(b"mnt_id:\t4096\n").unwrap(),
      Some(4096)
    );
    for contents in [&b"pos:\t0\nflags:\t012000000\n"[..], b""] {
      assert_eq!(
        parse_fdinfo_mount_id(contents).unwrap(),
        None,
        "{contents:?}"
      );
    }
    for contents in [
      &b"mnt_id:\t\n"[..],
      b"mnt_id:\t-1\n",
      b"mnt_id:\t2x\n",
      b"mnt_id: 25\n",
      // A line the kernel did not finish: its digits could be the head of
      // another number.
      b"mnt_id:\t4096",
      b"pos:\t0\nmnt_id:\t25",
      b"pos:\t0",
    ] {
      assert_eq!(
        parse_fdinfo_mount_id(contents).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "{contents:?}"
      );
    }
  }

  /// The thread's own procfs directory is `<tgid>/task/<tid>` and nothing
  /// else: a `thread-self` link spelled any other way is not the kernel's
  /// writing, and is `InvalidData`.
  #[test]
  fn test_the_thread_is_the_one_this_procfs_uses() {
    let live = procfs_thread(&proc_fixture());
    let Reading::Value(thread) = live else {
      panic!("procfs publishes a thread-self link");
    };
    let text = String::from_utf8(thread).unwrap();
    assert!(
      text.starts_with(&format!("{}/task/", std::process::id())),
      "this test runs in the namespace its procfs was mounted in: {text}"
    );

    let dir = tempfile::tempdir().unwrap();
    for target in [
      "1/task",
      "1/task/2/3",
      "1/tasks/2",
      "x/task/2",
      "1/task/../2",
      "1/task/",
    ] {
      let link = dir.path().join("thread-self");
      let _ = std::fs::remove_file(&link);
      std::os::unix::fs::symlink(target, &link).unwrap();
      assert!(
        matches!(
          procfs_thread(&fixture(dir.path())),
          Reading::Failed(ref err) if err.kind() == io::ErrorKind::InvalidData
        ),
        "a thread-self link reading {target:?} is not a thread"
      );
    }
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
  /// road with no number never asks udev anything. It is a decline — the node
  /// is not there — and not a node of another kind, which is the difference a
  /// census turns on.
  #[test]
  fn test_an_unknown_device_resolves_to_no_number() {
    let dev = dev_fixture();
    let relative = device_relative(Path::new("/dev/whichdisk-no-such-device")).unwrap();
    assert!(matches!(dev.device_number(relative), Reading::Declined(_)));
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
    let pinned = Pinned::of(Path::new("/"), &proc_fixture())
      .required()
      .unwrap();
    let Some(reading) = root_observation(&pinned).into_row().volume_identity() else {
      // A root whose source is not a block device under `/dev` — a container
      // on overlayfs — has no identity to pin a level to.
      return;
    };
    assert!(!reading.is_vouched(), "{reading:?}");
  }

  // ── the mount table, read whole ─────────────────────────────────────

  /// A mount table is every record of it or an error: a record that does not
  /// parse, an empty one, or one cut off before its newline is a mount a
  /// listing would leave out, or read in part, while reading as complete.
  #[test]
  fn test_a_mount_table_is_every_line_or_an_error() {
    let table = MountTable::parse(
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n36 21 8:17 / /mnt/usb rw - vfat /dev/sdb1 rw\n",
    )
    .unwrap();
    assert_eq!(
      table.line(36).map(|line| line.fs_type.as_bytes()),
      Some(&b"vfat"[..])
    );
    assert!(table.line(21).is_some());
    assert!(table.line(99).is_none());
    assert!(MountTable::parse(b"").unwrap().0.is_empty());

    for broken in [
      &b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\nnot a mountinfo line\n36 21 8:17 / /mnt/usb rw - vfat /dev/sdb1 rw\n"[..],
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n\n36 21 8:17 / /mnt/usb rw - vfat /dev/sdb1 rw\n",
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n36 21 8:17 / /mnt/usb rw - vfat /dev/sdb1 rw",
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n21 x 8:1 garbage / rw - ext4 /dev/sda1\n",
      b"\n",
    ] {
      assert_eq!(
        MountTable::parse(broken).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidData),
        "{:?}",
        String::from_utf8_lossy(broken)
      );
    }
  }

  /// The live table is read whole — no mount event overlapped the read it was
  /// taken from — and it names the root.
  #[test]
  fn test_the_live_mount_table_is_read_whole() {
    let proc = proc_fixture();
    let table = MountTable::read(&proc).unwrap();
    assert!(
      table
        .0
        .iter()
        .any(|line| line.mount_point.as_bytes() == b"/"),
      "every mount namespace has a root"
    );

    // A table opened and read with nothing mounted in between reports no
    // change; the kernel's own answer, asked the way the census asks it.
    let Reading::Value(thread) = procfs_thread(&proc) else {
      panic!("procfs names the calling thread");
    };
    let path = KernelDir::at(&[&thread, b"mountinfo"]);
    let file = std::fs::File::from(
      proc
        .open_beneath(
          Path::new(OsStr::from_bytes(&path)),
          OFlags::RDONLY | OFlags::CLOEXEC,
          ResolveFlags::NO_SYMLINKS,
        )
        .unwrap(),
    );
    let _ = mount_event_since_open(&file).unwrap();
  }

  // ── btrfs: one FSID, however many devices carry it ─────────────────

  const FSID_A: &str = "9f27c3b1-4d5e-4a70-8b21-6c0d5e4f3a2b";
  const FSID_B: &str = "1c4e8a90-77bb-4d21-9f30-2ea5b6c7d8e9";

  /// Builds a `/sys/fs/btrfs`-shaped tree: one directory per filesystem, each
  /// holding `devices/<name>/dev` with the member's `major:minor`.
  /// The real, authenticated `/proc`, which the mount laws below read through.
  fn proc_fixture() -> KernelDir {
    proc_root()
      .required()
      .expect("procfs opens and authenticates on a Linux host")
  }

  /// The real `/dev`, which the udev laws below read through. These laws
  /// assert what is *not* found rather than what is, so they hold on any host.
  fn dev_fixture() -> KernelDir {
    KernelDir::open("/dev", None)
      .required()
      .expect("/dev opens on a Linux host")
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
      let BtrfsLookup::Matched(reading) =
        btrfs_fsid_for_device(&fixture(dir.path()), member).unwrap()
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 33)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 65)).unwrap(),
      matched(FSID_B),
      "each filesystem answers for its own members"
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
      BtrfsLookup::Refused,
      "a clean census finding nothing is still refused, not a match for `features`"
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 33)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
      matched(FSID_A)
    );
    assert_eq!(
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 65)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap();
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

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 81)).unwrap();
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

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap();
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

  /// (d) A malformed `temp_fsid` — neither `"0\n"` nor `"1\n"` — is not the
  /// kernel's writing: the census fails with `InvalidData`, for a garbled
  /// value, a value with no newline and an empty file alike, rather than a
  /// row going on without its identity.
  #[test]
  fn test_a_malformed_temp_fsid_fails_the_census() {
    for malformed in ["x\n", "0", "1\n\n", ""] {
      let dir = tempfile::tempdir().unwrap();
      btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
      std::fs::write(btrfs_dir(dir.path(), FSID_A).join("temp_fsid"), malformed).unwrap();

      assert_eq!(
        btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17))
          .unwrap_err()
          .kind(),
        io::ErrorKind::InvalidData,
        "{malformed:?} is neither \"0\\n\" nor \"1\\n\""
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

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap();
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

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap();
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

    let btrfs = btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap();
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
    assert_eq!(
      sysfs_device_number(&root, relative).answered().unwrap(),
      Some(makedev(8, 17))
    );
    // Extended device numbers use the same encoding mountinfo is parsed with.
    std::fs::write(&path, "259:0\n").unwrap();
    assert_eq!(
      sysfs_device_number(&root, relative).answered().unwrap(),
      Some(makedev(259, 0))
    );
    // A file that was read and is not the kernel's one line, and one that is
    // not there: the first is a structure the kernel could not have written,
    // the second a decline.
    for contents in ["not-a-device\n", "8:17", "8:17\n9:1\n", "8:\n", ":17\n", ""] {
      std::fs::write(&path, contents).unwrap();
      assert!(
        matches!(
          sysfs_device_number(&root, relative),
          Reading::Failed(ref err) if err.kind() == io::ErrorKind::InvalidData
        ),
        "{contents:?}"
      );
    }
    assert!(matches!(
      sysfs_device_number(&root, Path::new("absent")),
      Reading::Declined(_)
    ));
  }

  /// The label btrfs answered is the bytes before the first zero of the
  /// zeroed buffer it copied into, since it copies no zero and no terminator;
  /// no bytes is no label, and a buffer with no zero left is no answer btrfs
  /// gives.
  #[test]
  fn test_a_btrfs_label_is_read_where_btrfs_ended_its_copy() {
    let answered = |label: &[u8]| {
      let mut buffer = [0u8; FSLABEL_MAX];
      buffer[..label.len()].copy_from_slice(label);
      btrfs_label_in(&buffer).map(|label| label.map(|label| label.as_bytes().to_vec()))
    };
    assert_eq!(answered(b"BACKUP").unwrap(), Some(b"BACKUP".to_vec()));
    assert_eq!(answered(b"").unwrap(), None);
    let longest = [b'x'; FSLABEL_MAX - 1];
    assert_eq!(answered(&longest).unwrap(), Some(longest.to_vec()));
    assert_eq!(
      btrfs_label_in(&[b'x'; FSLABEL_MAX])
        .err()
        .map(|err| err.kind()),
      Some(io::ErrorKind::InvalidData)
    );
  }

  /// The filesystem identity questions are the kernel's own: `struct
  /// fsuuid2`'s size and its fields' places, `FS_IOC_GETFSUUID`'s encoding
  /// over it — which the uapi header spells as a macro alone — and
  /// `FAT_IOCTL_GET_VOLUME_ID`, each against `linux-raw-sys`.
  #[test]
  fn test_the_filesystem_identity_questions_are_the_kernels() {
    use core::mem::{offset_of, size_of};

    use linux_raw_sys::{general, ioctl};

    assert_eq!(size_of::<FsUuid2>(), size_of::<general::fsuuid2>());
    assert_eq!(offset_of!(FsUuid2, len), offset_of!(general::fsuuid2, len));
    assert_eq!(
      offset_of!(FsUuid2, uuid),
      offset_of!(general::fsuuid2, uuid)
    );
    assert_eq!(
      FS_IOC_GETFSUUID,
      rustix::ioctl::opcode::read::<general::fsuuid2>(0x15, 0)
    );
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    assert_eq!(FS_IOC_GETFSUUID as u64, 0x8011_1500);
    assert_eq!(
      FAT_IOCTL_GET_VOLUME_ID as u64,
      u64::from(ioctl::FAT_IOCTL_GET_VOLUME_ID)
    );
  }

  /// Both btrfs questions, and the magic the descriptor is held to, are the
  /// kernel's own: the opcodes, the structure's size and its FSID's place, the
  /// label's room, and `BTRFS_SUPER_MAGIC`, each against `linux-raw-sys`.
  #[test]
  fn test_the_btrfs_questions_are_the_kernels() {
    use core::mem::{align_of, offset_of, size_of};

    use linux_raw_sys::{btrfs, general, ioctl};

    assert_eq!(
      BTRFS_IOC_FS_INFO as u64,
      u64::from(ioctl::BTRFS_IOC_FS_INFO)
    );
    assert_eq!(
      FS_IOC_GETFSLABEL as u64,
      u64::from(ioctl::FS_IOC_GETFSLABEL)
    );
    assert_eq!(u32::from(BTRFS_IOCTL_MAGIC), btrfs::BTRFS_IOCTL_MAGIC);
    assert_eq!(
      btrfs_fs_info::LEN,
      size_of::<btrfs::btrfs_ioctl_fs_info_args>()
    );
    assert_eq!(size_of::<FsInfoArgs>(), btrfs_fs_info::LEN);
    assert!(align_of::<FsInfoArgs>() >= align_of::<btrfs::btrfs_ioctl_fs_info_args>());
    assert_eq!(
      btrfs_fs_info::FSID,
      offset_of!(btrfs::btrfs_ioctl_fs_info_args, fsid)
    );
    assert_eq!(btrfs_fs_info::FSID_LEN, btrfs::BTRFS_FSID_SIZE as usize);
    assert_eq!(FSLABEL_MAX, general::FSLABEL_MAX as usize);
    assert_eq!(FSLABEL_MAX, btrfs::BTRFS_LABEL_SIZE as usize);
    assert_eq!(BTRFS_SUPER_MAGIC, general::BTRFS_SUPER_MAGIC);
    assert!(is_btrfs_magic(BTRFS_SUPER_MAGIC as rustix::fs::FsWord));
    assert!(!is_btrfs_magic(
      general::EXT4_SUPER_MAGIC as rustix::fs::FsWord
    ));
  }

  /// A bounded read hands over a whole file or fails: a file past its limit is
  /// no file of the kind the read expects, and its head is never handed over
  /// as though it were the whole.
  #[test]
  fn test_a_bounded_read_is_whole_or_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("fits"), vec![b'a'; 16]).unwrap();
    std::fs::write(dir.path().join("overruns"), vec![b'a'; 17]).unwrap();
    let root = fixture(dir.path());
    assert!(matches!(
      root.read_bounded(Path::new("fits"), 16),
      Reading::Value(ref bytes) if bytes.len() == 16
    ));
    assert!(matches!(
      root.read_bounded(Path::new("overruns"), 16),
      Reading::Failed(ref err) if err.kind() == io::ErrorKind::InvalidData
    ));
  }

  /// One census of the kernel's btrfs map names the one filesystem a device
  /// belongs to, and a device no filesystem claims is a refusal.
  #[test]
  fn test_one_census_names_the_one_filesystem_a_device_belongs_to() {
    let dir = tempfile::tempdir().unwrap();
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17")]), (FSID_B, &[("sdc1", "8:33")])],
    );
    for (member, id) in [(makedev(8, 17), FSID_A), (makedev(8, 33), FSID_B)] {
      match btrfs_census(&fixture(dir.path()), member).unwrap() {
        BtrfsCensus::Member { fsid: holder } => assert_eq!(Some(holder), fsid(id)),
        BtrfsCensus::Refused => panic!("{id} holds its member"),
      }
    }
    assert!(matches!(
      btrfs_census(&fixture(dir.path()), makedev(8, 99)).unwrap(),
      BtrfsCensus::Refused
    ));
  }

  /// **A btrfs source is bound only as a member of the filesystem the mount
  /// answered for**: the source's node binds where the census names exactly
  /// that FSID, and not where it names another, none, or two (a shared seed),
  /// nor where the source resolved to no node at all — a container whose
  /// `/dev` holds no disk nodes.
  #[test]
  fn test_a_btrfs_source_binds_only_as_a_member_of_the_answered_filesystem() {
    use observed::bound_member;

    let answered = fsid(FSID_A).unwrap();
    let node = makedev(8, 17);
    let census = |filesystems: &[(&str, &[(&str, &str)])]| {
      let dir = tempfile::tempdir().unwrap();
      btrfs_sysfs_fixture(dir.path(), filesystems);
      btrfs_census(&fixture(dir.path()), node).unwrap()
    };

    assert_eq!(
      bound_member(
        Some(node),
        Some(census(&[(FSID_A, &[("sdb1", "8:17")])])),
        answered
      ),
      Some(node)
    );
    assert_eq!(
      bound_member(
        Some(node),
        Some(census(&[(FSID_B, &[("sdb1", "8:17")])])),
        answered
      ),
      None,
      "a member of another filesystem"
    );
    assert_eq!(
      bound_member(
        Some(node),
        Some(census(&[
          (FSID_A, &[("sdb1", "8:17")]),
          (FSID_B, &[("sdb1", "8:17")])
        ])),
        answered
      ),
      None,
      "a seed two filesystems share"
    );
    assert_eq!(
      bound_member(
        Some(node),
        Some(census(&[(FSID_A, &[("sdc1", "8:33")])])),
        answered
      ),
      None,
      "a node no filesystem claims"
    );
    assert_eq!(bound_member(None, None, answered), None, "no node at all");
  }

  /// **A btrfs mount's identity and label stand on its filesystem's own
  /// answer through the pinned mount**, with or without a bound source: the
  /// FSID where its marker says it outlives the mount, the label whatever the
  /// marker says, each at the level the mount's line earns.
  #[test]
  fn test_a_btrfs_identity_and_label_stand_on_the_mount_alone() {
    use observed::{BtrfsMount, btrfs_facts};

    let answered = fsid(FSID_A).unwrap();
    let mount = || BtrfsMount::for_laws(answered, Some(b"BACKUP"));

    let (identity, name) = btrfs_facts(mount(), true, IdentityAssurance::Published);
    let identity = identity.expect("a durable FSID is an identity");
    assert_eq!(identity.identity(), answered);
    assert_eq!(identity.assurance(), IdentityAssurance::Published);
    let name = name.expect("the label is the filesystem's");
    assert_eq!(name.name.as_bytes(), b"BACKUP");
    assert_eq!(name.assurance, IdentityAssurance::Published);

    let (identity, name) = btrfs_facts(mount(), false, IdentityAssurance::Published);
    assert_eq!(identity, None, "a FSID that does not outlive the mount");
    assert_eq!(
      name.map(|name| name.name.as_bytes().to_vec()),
      Some(b"BACKUP".to_vec()),
      "the label does not wait on the marker"
    );

    let (identity, _) = btrfs_facts(mount(), true, IdentityAssurance::Declared);
    assert!(identity.unwrap().is_declared(), "held to the line's level");

    let (_, name) = btrfs_facts(
      BtrfsMount::for_laws(answered, None),
      true,
      IdentityAssurance::Published,
    );
    assert_eq!(name, None, "no label, no name");
  }

  /// Whether an FSID outlives its mount is its own marker's answer and
  /// nothing else's: `0` is durable; `1`, no marker and an unreadable one are
  /// not; anything else is `InvalidData`.
  #[test]
  fn test_a_btrfs_fsid_is_durable_only_where_its_marker_says_so() {
    let answered = fsid(FSID_A).unwrap();
    let durable = |marker: Option<&str>| {
      let dir = tempfile::tempdir().unwrap();
      btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
      if let Some(marker) = marker {
        std::fs::write(btrfs_dir(dir.path(), FSID_A).join("temp_fsid"), marker).unwrap();
      }
      btrfs_durable(&fixture(dir.path()), &answered)
    };
    assert!(durable(Some("0\n")).unwrap());
    assert!(!durable(Some("1\n")).unwrap());
    assert!(!durable(None).unwrap(), "no marker is no durability");
    assert_eq!(
      durable(Some("x\n")).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
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
      btrfs_fsid_for_device(&fixture(dir.path()), makedev(8, 17)).unwrap(),
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
    // A host whose directory could not be read whole has nothing to show.
    let UdevCensus::Complete(entries) = by_uuid_entries(&dev).unwrap() else {
      return;
    };
    for (target, _identity) in entries {
      assert_ne!(target, 0, "a block device is never device number zero");
    }
  }

  /// The label road answers out of the same directory tree, under the same
  /// root, and drops an entry the same way.
  #[test]
  fn test_by_label_entries_resolve_to_block_devices() {
    let dev = dev_fixture();
    let UdevCensus::Complete(entries) = by_label_entries(&dev).unwrap() else {
      return;
    };
    for (target, label) in entries {
      assert_ne!(target, 0, "a block device is never device number zero");
      let label = label.expect("every by-label name decodes to a label");
      assert!(!label.as_bytes().is_empty(), "an empty label is no label");
    }
  }

  /// A udev census is read whole or not at all.
  ///
  /// An entry that opens and is not a block device names no volume, and is
  /// passed over. An entry whose link is declined while it is resolved — a
  /// link to nothing, which is what a departing device leaves until udev
  /// catches up — could be exactly the second name for a device, the one the
  /// two-names-one-node refusal exists for, so it refuses the whole census:
  /// passing over it once let the name that remained be reported as though it
  /// were the only one.
  #[test]
  fn test_a_udev_census_is_complete_or_refused() {
    let dir = tempfile::tempdir().unwrap();
    let by_uuid = dir.path().join("disk").join("by-uuid");
    std::fs::create_dir_all(&by_uuid).unwrap();
    std::fs::write(dir.path().join("not-a-device"), b"").unwrap();
    std::os::unix::fs::symlink("../../not-a-device", by_uuid.join("1a2b-3c4d")).unwrap();

    let UdevCensus::Complete(entries) = by_uuid_entries(&fixture(dir.path())).unwrap() else {
      panic!("every entry was read, so the census is complete");
    };
    assert!(
      entries.is_empty(),
      "an entry that is no block device names no volume"
    );

    std::os::unix::fs::symlink("../../departed", by_uuid.join("5e6f-7a8b")).unwrap();
    assert!(
      matches!(
        by_uuid_entries(&fixture(dir.path())).unwrap(),
        UdevCensus::Refused
      ),
      "an entry declined while it was resolved refuses the census"
    );
  }

  /// The listing reports the lines a person would call volumes, and leaves the
  /// kernel's own plumbing out.
  /// A line as the listing weighs it: parsed, then kept where it reports it.
  #[cfg(feature = "list")]
  fn listed_line(line: &[u8]) -> Option<MountLine> {
    parse_record(line).filter(is_listed)
  }

  #[cfg(feature = "list")]
  #[test]
  fn test_a_listing_reads_the_lines_it_reports() {
    let usb = listed_line(b"36 21 8:17 / /run/media/al/USB rw - vfat /dev/sdb1 rw")
      .expect("a removable volume under /run/media is listed");
    assert_eq!(usb.id, 36);
    assert_eq!(usb.mount_point.as_bytes(), b"/run/media/al/USB");
    assert_eq!(usb.fs_type.as_bytes(), b"vfat");
    assert_eq!(usb.source.as_bytes(), b"/dev/sdb1");
    for line in [
      &b"22 1 0:21 / /proc rw - proc proc rw"[..],
      b"23 1 0:22 / /run/user/1000 rw - ext4 /dev/sda3 rw",
      b"24 1 0:23 / /tmp rw - tmpfs tmpfs rw",
      b"25 1 0:24 / /var/lib/nfs/rpc_pipefs rw - rpc_pipefs sunrpc rw",
      b"not a mountinfo line",
    ] {
      assert!(listed_line(line).is_none(), "{line:?}");
    }
  }

  /// A listing row is read through a pin, and the pin is held to the one line
  /// its own mount id names in a table read while it is held — not to a
  /// device number, which the kernel hands on to the next mount.
  #[cfg(feature = "list")]
  #[test]
  fn test_a_held_id_names_its_own_line_and_no_other() {
    let table = MountTable::parse(
      b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n36 21 8:17 / /mnt/usb rw - vfat /dev/sdb1 rw\n",
    )
    .unwrap();
    let lines = table.by_id();
    let row = lines
      .get(&36)
      .copied()
      .filter(|line| is_listed(line))
      .expect("the held id names a line, and a vfat mount is listed");
    assert_eq!(row.mount_point.as_bytes(), b"/mnt/usb");
    assert_eq!(row.source.as_bytes(), b"/dev/sdb1");
    assert_eq!(
      lines
        .get(&21)
        .copied()
        .filter(|line| is_listed(line))
        .map(|row| row.id),
      Some(21)
    );
    assert!(
      !lines.contains_key(&99),
      "an id no line carries names no mount"
    );
  }

  /// The removal question never fails the call that asks it: a `/sys` that
  /// could not be had leaves the answer `Unknown`, and so does a mount with no
  /// device to ask about, for which `/sys` is never opened at all.
  #[test]
  fn test_without_a_root_the_removal_question_is_unknown() {
    assert_eq!(
      device_ejectability(None, Some(makedev(8, 17))),
      Ejectability::Unknown
    );
    assert_eq!(device_ejectability(None, None), Ejectability::Unknown);
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
    let pinned = Pinned::of(Path::new("/"), &proc_fixture())
      .required()
      .unwrap();
    let truth = root_observation(&pinned);

    // Read after the table above, and still the same facts: there is no entry
    // an earlier call could have filled in on this one's behalf.
    let resolved = resolve(Path::new("/")).unwrap();
    let mount = resolved.mount_info();
    assert_eq!(mount.mount_point(), truth.mount_point().as_path());
    assert_eq!(mount.device(), truth.source().as_os_str());
    let expected = volume_capabilities(truth.fs_type());
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
    // A partition says it is one, with its number (`part_partition_show`).
    std::fs::write(part_dir.join("partition"), "1\n").unwrap();

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
      matches!(sysfs.dir(slaves), Reading::Declined(_)),
      "symlinks refused: the walk opened nothing"
    );
    assert!(
      matches!(sysfs.dir_linked(slaves), Reading::Value(_)),
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

  /// And where nothing underneath says anything, the answer is `Unknown` —
  /// never a denial: a walk that found no yes and no `fixed` has found
  /// nothing, not a no.
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

  /// **A live btrfs mount binds through its own filesystem.** Run by the CI
  /// job `test (btrfs)`, which makes a btrfs filesystem on a loop device,
  /// mounts it and a subvolume of it beside it, and names both here — no
  /// fixture can stand in for the kernel answering `BTRFS_IOC_FS_INFO` and
  /// `FS_IOC_GETFSLABEL`. Both mounts, and a file inside the first, resolve
  /// with the filesystem's FSID (where the kernel marks it permanent) and its
  /// label, as the mount itself answered them, and a loop device says nothing
  /// about removal; the listing carries both mounts the same way.
  #[test]
  #[ignore = "needs a live btrfs mount: the CI job test (btrfs) makes one and runs this"]
  fn test_a_live_btrfs_mount_binds_through_its_own_filesystem() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} names the mount"));
    let mount = PathBuf::from(var("WHICHDISK_BTRFS_MOUNT"));
    let subvolume = PathBuf::from(var("WHICHDISK_BTRFS_SUBVOLUME"));
    let label = var("WHICHDISK_BTRFS_LABEL");
    let fsid_text = var("WHICHDISK_BTRFS_FSID");
    let fsid = super::super::parse_by_uuid_name(fsid_text.as_bytes()).expect("an FSID");
    let durable =
      std::fs::read(format!("/sys/fs/btrfs/{fsid_text}/temp_fsid")).ok() == Some(b"0\n".to_vec());
    let file = mount.join("a-file");
    std::fs::write(&file, b"whichdisk").unwrap();

    for path in [&mount, &file, &subvolume] {
      let location = crate::resolve(path).unwrap();
      let row = location.mount_info();
      println!("{}: {row:?}", path.display());
      assert_eq!(
        row.volume_identity().map(|reading| reading.identity()),
        durable.then_some(fsid),
        "{}",
        path.display()
      );
      assert_eq!(
        row.volume_name(),
        Some(label.as_str()),
        "{}",
        path.display()
      );
      assert!(
        row.volume_name_assurance().is_some(),
        "the label is the filesystem's, not the mount point's"
      );
      assert_eq!(
        row.ejectability(),
        Ejectability::Unknown,
        "{}",
        path.display()
      );
    }

    #[cfg(feature = "list")]
    for listed in [&mount, &subvolume] {
      let rows = crate::list().unwrap();
      let row = rows
        .iter()
        .find(|row| row.mount_point() == listed.as_path())
        .unwrap_or_else(|| panic!("{} is listed", listed.display()));
      assert_eq!(
        row.volume_identity().map(|reading| reading.identity()),
        durable.then_some(fsid)
      );
      assert_eq!(row.volume_name(), Some(label.as_str()));
    }
  }

  /// A USB disk as the kernel lays it out: the disk `sdb` and its first
  /// partition, beneath the SCSI device of a mass-storage interface of the
  /// last of the USB devices `ports` — each a device directory of its own,
  /// outermost first, below root hub `usb1`, with its `removable` word, or
  /// none — the disk's media flag written as `media`, and `dev/block/8:16` and
  /// `dev/block/8:17` linked to them. Returns the partition's directory,
  /// relative to the root.
  fn usb_disk_fixture(root: &Path, ports: &[(&str, Option<&str>)], media: &str) -> PathBuf {
    let hub = PathBuf::from("devices/pci0000:00/0000:00:14.0/usb1");
    std::fs::create_dir_all(root.join(&hub)).unwrap();
    std::fs::write(root.join(&hub).join("removable"), "unknown\n").unwrap();
    let mut relative = hub;
    for (name, word) in ports {
      relative = relative.join(name);
      std::fs::create_dir_all(root.join(&relative)).unwrap();
      if let Some(word) = word {
        std::fs::write(root.join(&relative).join("removable"), format!("{word}\n")).unwrap();
      }
    }
    let interface = format!("{}:1.0", ports.last().unwrap().0);
    let disk = relative
      .join(interface)
      .join("host6/target6:0:0/6:0:0:0/block/sdb");
    let partition = disk.join("sdb1");
    std::fs::create_dir_all(root.join(&partition)).unwrap();
    std::fs::write(root.join(&disk).join("removable"), media).unwrap();
    std::fs::write(root.join(&disk).join("dev"), "8:16\n").unwrap();
    std::fs::write(root.join(&partition).join("dev"), "8:17\n").unwrap();
    std::fs::write(root.join(&partition).join("partition"), "1\n").unwrap();
    let block = root.join("dev/block");
    std::fs::create_dir_all(&block).unwrap();
    std::os::unix::fs::symlink(Path::new("../..").join(&disk), block.join("8:16")).unwrap();
    std::os::unix::fs::symlink(Path::new("../..").join(&partition), block.join("8:17")).unwrap();
    partition
  }

  /// **The one Linux denial: a USB disk the kernel calls fixed throughout.**
  /// Every USB device between the disk and its host controller reads `fixed`,
  /// the disk's media flag reads `0`, and nothing on the way reads `removable`
  /// — for the disk and its partition alike. A dock's hard-wired port behind a
  /// port that is not fixed, a port the kernel could not describe, and a
  /// kernel that writes no word at all are the bus's yes; media that comes
  /// out is a yes; and fixed ports over a media flag that could not be read
  /// are no answer, since the kernel's `fixed` outranks the bus allowlist.
  #[test]
  fn test_only_a_usb_disk_the_kernel_calls_fixed_throughout_is_denied() {
    type Ports<'a> = &'a [(&'a str, Option<&'a str>)];
    let cases: [(Ports<'_>, &str, Ejectability); 10] = [
      (&[("1-3", Some("fixed"))], "0\n", Ejectability::NotEjectable),
      (
        &[("1-3", Some("fixed")), ("1-3.2", Some("fixed"))],
        "0\n",
        Ejectability::NotEjectable,
      ),
      (&[("1-3", Some("fixed"))], "1\n", Ejectability::Ejectable),
      (
        &[("1-3", Some("removable")), ("1-3.2", Some("fixed"))],
        "0\n",
        Ejectability::Ejectable,
      ),
      (
        &[("1-3", Some("unknown")), ("1-3.2", Some("fixed"))],
        "0\n",
        Ejectability::Ejectable,
      ),
      (&[("1-3", None)], "0\n", Ejectability::Ejectable),
      (&[("1-3", Some("unknown"))], "0\n", Ejectability::Ejectable),
      (
        &[("1-3", Some("removable"))],
        "0\n",
        Ejectability::Ejectable,
      ),
      (&[("1-3", Some("Fixed"))], "0\n", Ejectability::Ejectable),
      (&[("1-3", Some("fixed"))], "0", Ejectability::Unknown),
    ];
    for (ports, media, expected) in cases {
      let dir = tempfile::tempdir().unwrap();
      usb_disk_fixture(dir.path(), ports, media);
      let sysfs = fixture(dir.path());
      for device in [makedev(8, 16), makedev(8, 17)] {
        assert_eq!(
          device_ejectability(Some(&sysfs), Some(device)),
          expected,
          "{ports:?} media {media:?} device {device:#x}"
        );
      }
    }
  }

  /// Writes `sequence` as the `diskseq` of the disk directory `disk`,
  /// relative to a fixture root, as the kernel writes it.
  fn write_diskseq(root: &Path, disk: &Path, sequence: u64) {
    std::fs::write(root.join(disk).join("diskseq"), format!("{sequence}\n")).unwrap();
  }

  /// **A removal answer is bound to the mounted filesystem and to one attach
  /// of the device, never to a device number alone.** Over a USB disk the
  /// kernel calls fixed throughout, its partition answers `NotEjectable` only
  /// where the filesystem the mount names is the one udev published for this
  /// attach, and the attach held while the answer was read. A device number
  /// given to another device carrying another filesystem, an attach udev has
  /// not published, a sequence that moved while the answer was read, and a
  /// kernel that publishes no sequence are each `Unknown`. The attach udev is
  /// asked about is the disk's sequence and, for a partition, its number.
  #[test]
  fn test_a_removal_answer_is_bound_to_the_mount_and_one_attach() {
    let ours = VolumeIdentity::FsUuid([0x11; 16]);
    let theirs = VolumeIdentity::FsUuid([0x22; 16]);
    let fixed = [("1-3", Some("fixed"))];

    let dir = tempfile::tempdir().unwrap();
    let partition = usb_disk_fixture(dir.path(), &fixed, "0\n");
    let disk = partition.parent().unwrap().to_path_buf();
    write_diskseq(dir.path(), &disk, 42);
    let sysfs = fixture(dir.path());
    let (whole, part) = (makedev(8, 16), makedev(8, 17));

    let mut asked = Vec::new();
    assert_eq!(
      bound_removal(&sysfs, part, ours, |attach| {
        asked.push(attach);
        Some(ours)
      }),
      Ejectability::NotEjectable,
      "the same filesystem, the same attach"
    );
    assert_eq!(
      bound_removal(&sysfs, whole, ours, |attach| {
        asked.push(attach);
        Some(ours)
      }),
      Ejectability::NotEjectable
    );
    assert_eq!(
      asked,
      [
        Sequence {
          disk: 42,
          partition: Some(1)
        },
        Sequence {
          disk: 42,
          partition: None
        }
      ]
    );

    assert_eq!(
      bound_removal(&sysfs, part, ours, |_| Some(theirs)),
      Ejectability::Unknown,
      "the number now names a device carrying another filesystem"
    );
    assert_eq!(
      bound_removal(&sysfs, part, ours, |_| None),
      Ejectability::Unknown,
      "udev has not published this attach, or names nothing for it"
    );
    assert_eq!(
      bound_removal_with(
        &sysfs,
        part,
        ours,
        |_| Some(ours),
        || write_diskseq(dir.path(), &disk, 43)
      ),
      Ejectability::Unknown,
      "the device was attached again while the answer was read"
    );
    assert_eq!(
      bound_removal(&sysfs, part, ours, |_| Some(ours)),
      Ejectability::NotEjectable,
      "the new attach, published with the same filesystem, answers again"
    );

    std::fs::remove_file(dir.path().join(&disk).join("diskseq")).unwrap();
    assert_eq!(
      bound_removal(&sysfs, part, ours, |_| Some(ours)),
      Ejectability::Unknown,
      "a kernel that publishes no sequence binds nothing"
    );
    for garbled in ["", "42", "42\n\n", "4 2\n", "-1\n"] {
      std::fs::write(dir.path().join(&disk).join("diskseq"), garbled).unwrap();
      assert_eq!(device_sequence(&sysfs, part), None, "{garbled:?}");
    }
  }

  /// **Every device a stack's answer is read from is held to one attach.** A
  /// device mapper volume over the fixed USB partition is denied while the
  /// disk under it keeps its sequence, and is `Unknown` where the disk is
  /// attached again while the answer is read; a slave that publishes no
  /// sequence answers nothing, and the stack with it.
  #[test]
  fn test_a_stack_is_held_to_one_attach_of_everything_under_it() {
    let ours = VolumeIdentity::FsUuid([0x33; 16]);
    let dir = tempfile::tempdir().unwrap();
    let partition = usb_disk_fixture(dir.path(), &[("1-3", Some("fixed"))], "0\n");
    let disk = partition.parent().unwrap().to_path_buf();
    write_diskseq(dir.path(), &disk, 7);
    let volume = dir.path().join("devices/virtual/block/dm-0");
    std::fs::create_dir_all(volume.join("slaves")).unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../../../..").join(&partition),
      volume.join("slaves/sdb1"),
    )
    .unwrap();
    std::fs::write(volume.join("diskseq"), "9\n").unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../devices/virtual/block/dm-0"),
      dir.path().join("dev/block/253:0"),
    )
    .unwrap();
    let sysfs = fixture(dir.path());
    let stack = makedev(253, 0);

    assert_eq!(
      bound_removal(&sysfs, stack, ours, |_| Some(ours)),
      Ejectability::NotEjectable
    );
    assert_eq!(
      bound_removal_with(
        &sysfs,
        stack,
        ours,
        |_| Some(ours),
        || write_diskseq(dir.path(), &disk, 8)
      ),
      Ejectability::Unknown,
      "the disk under the stack was attached again"
    );
    std::fs::remove_file(dir.path().join(&disk).join("diskseq")).unwrap();
    assert_eq!(
      bound_removal(&sysfs, stack, ours, |_| Some(ours)),
      Ejectability::Unknown,
      "a slave with no sequence answers nothing"
    );
  }

  /// **The live chain, on this machine**: the root's own filesystem names
  /// itself through its mount, udev published the attach of the device the
  /// root binds with a `by-diskseq` link, and udev's identity for that device
  /// is the filesystem's own — wherever each is on offer here. What is on
  /// offer is printed: a kernel before 6.9 names no UUID for most
  /// filesystems, and a container has no udev.
  #[test]
  fn test_the_root_binds_on_this_machine() {
    let roots = observed::Roots::open_for_laws().unwrap();
    let Some((line, pinned)) = observed::root_line_for_laws(&roots) else {
      println!("the root's line could not be had");
      return;
    };
    let fs_type = line.fs_type.as_bytes().to_vec();
    let mounted = observed::mount_root_for_laws(&line, &pinned, &roots)
      .and_then(|root| filesystem_identity(&root, &fs_type));
    let device = line.device;
    let sequence = roots
      .sysfs_for_laws()
      .and_then(|sysfs| device_sequence(sysfs, device));
    let published = match (roots.dev_for_laws(), sequence) {
      (Some(dev), Some(attach)) => Some(published_at(dev, device, attach)),
      _ => None,
    };
    let identity = roots
      .dev_for_laws()
      .and_then(|dev| published_identity(dev, device, &fs_type));
    println!(
      "root: {} on {:#x}; the filesystem names {mounted:?}; attach {sequence:?}, \
       published {published:?}; udev names {identity:?}",
      String::from_utf8_lossy(&fs_type),
      device
    );
    if let (Some(mounted), Some(true), Some(identity)) = (mounted, published, identity) {
      assert_eq!(
        crate::linux_identity(&fs_type, mounted, IdentityAssurance::Vouched)
          .map(|reading| reading.identity()),
        Some(identity),
        "udev's identity for the attach is the mounted filesystem's own"
      );
    }
  }

  /// A stack is denied only where every device it is built from is: over a
  /// fixed USB partition alone it is, and beside a disk that says nothing it
  /// is not.
  #[test]
  fn test_a_stack_is_denied_only_where_all_it_is_built_from_is() {
    let dir = tempfile::tempdir().unwrap();
    let partition = usb_disk_fixture(dir.path(), &[("1-3", Some("fixed"))], "0\n");
    let stacked = |name: &str, number: &str, slaves: &[(&str, &Path)]| {
      let device = dir.path().join("devices/virtual/block").join(name);
      std::fs::create_dir_all(device.join("slaves")).unwrap();
      for (slave, target) in slaves {
        std::os::unix::fs::symlink(
          Path::new("../../../../..").join(target),
          device.join("slaves").join(slave),
        )
        .unwrap();
      }
      std::os::unix::fs::symlink(
        Path::new("../../devices/virtual/block").join(name),
        dir.path().join("dev/block").join(number),
      )
      .unwrap();
    };
    stacked("dm-0", "253:0", &[("sdb1", &partition)]);
    let silent = PathBuf::from("devices/bus/sdc");
    std::fs::create_dir_all(dir.path().join(&silent)).unwrap();
    std::fs::write(dir.path().join(&silent).join("dev"), "8:32\n").unwrap();
    std::fs::write(dir.path().join(&silent).join("removable"), "0\n").unwrap();
    std::os::unix::fs::symlink(
      Path::new("../..").join(&silent),
      dir.path().join("dev/block/8:32"),
    )
    .unwrap();
    stacked("dm-1", "253:1", &[("sdb1", &partition), ("sdc", &silent)]);

    let sysfs = fixture(dir.path());
    assert_eq!(
      device_ejectability(Some(&sysfs), Some(makedev(253, 0))),
      Ejectability::NotEjectable
    );
    assert_eq!(
      device_ejectability(Some(&sysfs), Some(makedev(253, 1))),
      Ejectability::Unknown
    );
  }

  /// A disk its driver puts straight under its controller — NVMe, with no
  /// `block` directory on the way — is read the same way: a PCI port the
  /// firmware marks external says `removable`, and where nothing says
  /// anything, nothing is answered.
  #[test]
  fn test_a_pci_port_marked_external_is_a_yes_and_silence_is_no_answer() {
    for (external, expected) in [
      (true, Ejectability::Ejectable),
      (false, Ejectability::Unknown),
    ] {
      let dir = tempfile::tempdir().unwrap();
      let port = PathBuf::from("devices/pci0000:00/0000:00:1d.0/0000:3d:00.0");
      let disk = port.join("nvme/nvme0/nvme0n1");
      std::fs::create_dir_all(dir.path().join(&disk)).unwrap();
      std::fs::write(dir.path().join(&disk).join("removable"), "0\n").unwrap();
      if external {
        std::fs::write(dir.path().join(&port).join("removable"), "removable\n").unwrap();
      }
      std::fs::create_dir_all(dir.path().join("dev/block")).unwrap();
      std::os::unix::fs::symlink(
        Path::new("../..").join(&disk),
        dir.path().join("dev/block/259:0"),
      )
      .unwrap();
      assert_eq!(
        device_ejectability(Some(&fixture(dir.path())), Some(makedev(259, 0))),
        expected,
        "external {external}"
      );
    }
  }

  /// A `removable` word is one the kernel writes, and anything else says
  /// nothing.
  #[test]
  fn test_a_port_word_is_one_the_kernel_writes() {
    assert_eq!(port_word(b"removable\n"), PortWord::Removable);
    assert_eq!(port_word(b"fixed\n"), PortWord::Fixed);
    assert_eq!(port_word(b"unknown\n"), PortWord::Unknown);
    for other in [&b"fixed"[..], b"Fixed\n", b"fixed\n\n", b"", b"0\n", b"1\n"] {
      assert_eq!(port_word(other), PortWord::Unread, "{other:?}");
    }
  }

  /// USB devices and root hubs are named as the kernel names them, and an
  /// interface, a controller or a SCSI device is neither.
  #[test]
  fn test_usb_devices_and_root_hubs_are_named_as_the_kernel_names_them() {
    for name in ["1-3", "1-3.2", "12-1.4.3"] {
      assert!(is_usb_device(name.as_bytes()), "{name}");
      assert!(!is_usb_root_hub(name.as_bytes()), "{name}");
    }
    for name in [
      "usb1",
      "1-3:1.0",
      "1-",
      "-3",
      "1-3.",
      "1-3..2",
      "0000:00:14.0",
      "host6",
      "6:0:0:0",
      "1-3.x",
    ] {
      assert!(!is_usb_device(name.as_bytes()), "{name}");
    }
    for name in ["usb1", "usb12"] {
      assert!(is_usb_root_hub(name.as_bytes()), "{name}");
    }
    for name in ["usb", "usb1a", "1-3", "xusb1"] {
      assert!(!is_usb_root_hub(name.as_bytes()), "{name}");
    }
  }

  /// The devices on the way are every directory below `devices/` above the
  /// block layer's own: the disk's, a partition's, and the `block` directory
  /// most drivers put them in are left out.
  #[test]
  fn test_the_devices_on_the_way_leave_the_block_layer_out() {
    let names = |ancestry: &[u8], partition| {
      device_dirs(ancestry, partition).map(|dirs| {
        dirs
          .into_iter()
          .map(|(_, name)| String::from_utf8(name).unwrap())
          .collect::<Vec<_>>()
      })
    };
    let usb =
      b"../../devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0/host6/target6:0:0/6:0:0:0/block/sdb";
    let expected = [
      "pci0000:00",
      "0000:00:14.0",
      "usb1",
      "1-3",
      "1-3:1.0",
      "host6",
      "target6:0:0",
      "6:0:0:0",
    ];
    assert_eq!(names(usb, false).unwrap(), expected);
    assert_eq!(
      names(&[&usb[..], b"/sdb1"].concat(), true).unwrap(),
      expected
    );
    assert_eq!(
      names(
        b"../../devices/pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1",
        false
      )
      .unwrap(),
      [
        "pci0000:00",
        "0000:00:1d.0",
        "0000:3d:00.0",
        "nvme",
        "nvme0"
      ]
    );
    assert_eq!(
      names(b"../../devices/virtual/block/dm-0", false).unwrap(),
      ["virtual"]
    );
    let (_, first) = device_dirs(b"../../devices/virtual/block/dm-0", false).unwrap()[0].clone();
    assert_eq!(first, b"virtual");
    assert_eq!(
      device_dirs(b"../../devices/virtual/block/dm-0", false).unwrap()[0].0,
      "devices/virtual"
    );
    for bad in [
      &b"../../class/block/sdb"[..],
      b"../../devices/a/../b/block/sdb",
      b"../../devices",
      b"../../devices/a//b/sdb",
    ] {
      assert!(device_dirs(bad, false).is_none(), "{bad:?}");
    }
  }

  /// Measured on the machine the laws run on: every USB device's `removable`
  /// word is one the kernel writes, and every block device's removal answer
  /// prints beside its number.
  #[test]
  fn test_every_port_word_on_this_machine_is_the_kernels() {
    let Some(sysfs) = removal_root() else {
      return;
    };
    if let Some(devices) = sysfs.dir(Path::new("bus/usb/devices")).evidence() {
      for name in devices {
        let path = KernelDir::at(&[b"bus/usb/devices", &name, b"removable"]);
        if let Some(contents) = sysfs
          .read_linked(Path::new(OsStr::from_bytes(&path)))
          .evidence()
        {
          println!(
            "usb {}: {}",
            String::from_utf8_lossy(&name),
            String::from_utf8_lossy(&contents).trim_end()
          );
          assert_ne!(port_word(&contents), PortWord::Unread, "{name:?}");
        }
      }
    }
    if let Some(blocks) = sysfs.dir(Path::new("class/block")).evidence() {
      for name in blocks {
        let path = KernelDir::at(&[b"class/block", &name, b"dev"]);
        let Some(number) =
          sysfs_device_number(&sysfs, Path::new(OsStr::from_bytes(&path))).evidence()
        else {
          continue;
        };
        println!(
          "block {}: {:?}",
          String::from_utf8_lossy(&name),
          device_ejectability(Some(&sysfs), Some(number))
        );
      }
    }
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
