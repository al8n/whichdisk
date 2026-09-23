use std::{
  ffi::OsStr,
  os::unix::ffi::OsStrExt,
  path::{Path, PathBuf},
};

use rustix::fs::statfs;

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

/// Every value in one resolve comes from one observation of the object the
/// caller named.
///
/// **On Apple that takes a descriptor.** Five separate reads are needed there —
/// the mount metadata, the volume's capabilities, its identity, its label and
/// its ejectability — and each of them used to re-resolve the pathname, so an
/// overmount or a volume replacement between any two could return a vouched
/// identity from one volume, mount metadata from a second and a definitive
/// `NotEjectable` from a third, with nothing in the row admitting it. One
/// descriptor is opened on the canonical path and held for the whole call, and
/// every value is asked of *it*: `fstatfs` for the mount metadata, the capacity
/// and the kernel's own word on whether the storage leaves the machine, and
/// `fgetattrlist` for the capabilities, the identity and the label. Nothing in
/// the row is read by pathname, so nothing in it has to be tied back to the
/// rest. See [`pin_the_mount`] for a path that cannot be opened, and
/// [`ejectability_of_mount`] for the removal answer.
///
/// **On the other BSDs it takes one call and no descriptor.** There is nothing
/// to combine: the identity and the label are `None` by design, and the mount
/// point, the mount source, the filesystem type, the capacity *and* the
/// ejectability all come out of a single `statfs` — the ejectability from the
/// very `f_mntfromname` that call already returned, where it used to make a
/// second `statfs` of its own. One call is a stronger guarantee than a pinned
/// one, and it costs nothing; a descriptor would only cost these platforms the
/// paths their caller may traverse but not open.
///
/// **There is no mount cache here, and there must not be.** One existed, keyed
/// by `st_dev`, holding the mount point, the mount source and the volume's
/// capabilities for the life of the thread. That key is not a witness: a device
/// number names a mount session, it is handed to another mount once the first
/// goes away, and on Apple the sealed system volume and its data volume report
/// one between them, two live mounts under a single number. A hit
/// therefore had nothing standing behind it, and could serve another volume's
/// mount point and device — with the ejectability then asked of *that* mount
/// point, which on Apple is a platform that can answer `NotEjectable`. A
/// definitive denial about a volume the caller never named is the worst answer
/// this crate can give, so the entry that made it possible is gone rather than
/// refreshed. Nothing durable may be remembered under a key nothing can vouch
/// for, and this platform offers no per-mount witness to vouch with — nor, it
/// turned out, does any other: the Linux entry that had the best witness of the
/// three is gone too, because a unique mount id names the mount object and not
/// where it is attached.
///
/// The cost is one `statfs` per resolve, which is the call that would have been
/// made anyway on a `disk-usage` build — the cache re-queried it every time for
/// fresh capacities and kept only the three fields above. What a hit saved was
/// therefore the `volume_capabilities` `getattrlist`, one syscall on a path
/// already in hand.
#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> std::io::Result<Inner> {
  let canonical = path.canonicalize()?;

  // Apple: one descriptor, and every call that has a descriptor form asked of
  // it. Elsewhere: one `statfs`, which is every call there is.
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  let (pinned, fs) = pin_the_mount(&canonical)?;
  #[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  )))]
  let fs = statfs(&canonical).map_err(std::io::Error::from)?;

  let mount_point = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntonname));
  let device = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntfromname));

  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  let (volume_identity, capabilities) = match pinned.as_ref() {
    Some(fd) => {
      use rustix::fd::AsFd as _;
      (
        volume_identity_at(AttrTarget::Fd(fd.as_fd()))?,
        volume_capabilities_at(
          AttrTarget::Fd(fd.as_fd()),
          c_chars_as_bytes(&fs.f_fstypename),
        ),
      )
    }
    // The path could not be opened, so there is no descriptor to ask. Neither
    // is asked by pathname: an independently resolved pathname could answer
    // for another volume, and a `Vouched` identity from one is exactly the
    // value that must never be combined with another's metadata. What is
    // reported instead is derived from the one observation in hand — no
    // identity at all, and the capabilities the row's own filesystem type
    // implies. See [`pin_the_mount`].
    None => (
      None,
      VolumeCapabilities::from_fs_type(c_chars_as_bytes(&fs.f_fstypename)),
    ),
  };
  #[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  )))]
  let (volume_identity, capabilities) = (
    volume_identity(&canonical),
    volume_capabilities(&canonical, c_chars_as_bytes(&fs.f_fstypename)),
  );

  #[cfg(feature = "disk-usage")]
  #[allow(clippy::unnecessary_cast)]
  let (total_bytes, available_bytes) = {
    let bsize = fs.f_bsize as u64;
    (
      (fs.f_blocks as u64).saturating_mul(bsize),
      (fs.f_bavail as u64).saturating_mul(bsize),
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

  // Both come off the pinned descriptor, as everything above does: the label
  // with `fgetattrlist`, and the removal answer out of the very `fstatfs` the
  // mount metadata came from. Nothing ties them to the row after the fact,
  // because nothing needs to — they are the pinned volume answering. Neither
  // is remembered: a person can rewrite a label while the mount stays exactly
  // as it is.
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  let (ejectability, volume_name) = match pinned.as_ref() {
    Some(fd) => {
      use rustix::fd::AsFd as _;
      (
        ejectability_of_mount(&fs),
        volume_name_at(AttrTarget::Fd(fd.as_fd()))?,
      )
    }
    // No descriptor, so no label and nothing established about removal: see
    // [`pin_the_mount`].
    None => (Ejectability::Unknown, None),
  };
  // Everywhere else the device name is the one `f_mntfromname` the single
  // `statfs` above already returned, so there is no second call to bracket and
  // no label road at all.
  #[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  )))]
  let (ejectability, volume_name) = (
    ejectability_from_name(c_chars_as_bytes(&fs.f_mntfromname)),
    volume_name(&canonical),
  );

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      ejectability,
      capabilities,
      volume_identity,
      volume_name,
      #[cfg(feature = "disk-usage")]
      total_bytes,
      #[cfg(feature = "disk-usage")]
      available_bytes,
    },
    canonical,
    relative_offset,
  })
}

/// Apple platforms: enumerate volumes via NSFileManager, skip non-browsable
/// and non-local volumes, query ejectable/removable properties.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(super) fn list(opts: super::ListOptions) -> std::io::Result<Vec<super::MountPoint>> {
  use objc2_foundation::{
    NSArray, NSFileManager, NSURLResourceKey, NSURLVolumeIsBrowsableKey, NSURLVolumeIsEjectableKey,
    NSURLVolumeIsInternalKey, NSURLVolumeIsLocalKey, NSURLVolumeIsRemovableKey,
    NSVolumeEnumerationOptions,
  };

  let fm = NSFileManager::defaultManager();
  let keys: &[&NSURLResourceKey] = unsafe {
    &[
      NSURLVolumeIsBrowsableKey,
      NSURLVolumeIsLocalKey,
      NSURLVolumeIsEjectableKey,
      NSURLVolumeIsRemovableKey,
      NSURLVolumeIsInternalKey,
      objc2_foundation::NSURLVolumeNameKey,
      objc2_foundation::NSURLVolumeLocalizedNameKey,
    ]
  };
  let keys_array = NSArray::from_slice(keys);

  let urls = fm.mountedVolumeURLsIncludingResourceValuesForKeys_options(
    Some(&keys_array),
    NSVolumeEnumerationOptions::empty(),
  );
  let urls = urls.ok_or_else(|| std::io::Error::other("failed to enumerate volumes"))?;

  let mut mounts = Vec::new();
  for url in urls.iter() {
    // A volume that does not say it is browsable and local is skipped, and a
    // volume that does not answer at all is skipped with it: the enumeration
    // shows what it can vouch for.
    if get_bool_resource(&url, unsafe { NSURLVolumeIsBrowsableKey }) != Some(true) {
      continue;
    }
    if get_bool_resource(&url, unsafe { NSURLVolumeIsLocalKey }) != Some(true) {
      continue;
    }

    let ejectable = get_bool_resource(&url, unsafe { NSURLVolumeIsEjectableKey });
    let removable = get_bool_resource(&url, unsafe { NSURLVolumeIsRemovableKey });
    let internal = get_bool_resource(&url, unsafe { NSURLVolumeIsInternalKey });
    let ejectability = ejectability_of(ejectable, removable, internal);

    // Exact states: a volume of unknown ejectability is named by neither
    // only-filter, so it is excluded by either. See `ListOptions::excludes`.
    if opts.excludes(ejectability) {
      continue;
    }

    if let Some(path) = url.path() {
      let path_bytes = path.to_string().into_bytes();
      let mount_point = SmallBytes::from_bytes(&path_bytes);

      let mp_path = Path::new(OsStr::from_bytes(&path_bytes));
      let fs = match statfs(mp_path).map_err(std::io::Error::from) {
        Ok(fs) => fs,
        // The volume went away between the enumeration and this call, or its
        // mount point is out of this caller's reach: there is no row here to
        // describe. Any other failure is returned as the error it is, rather
        // than as a listing quietly short of a volume.
        Err(err) if declined(&err) => continue,
        Err(err) => return Err(err),
      };
      let device = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntfromname));
      let capabilities = volume_capabilities(mp_path, c_chars_as_bytes(&fs.f_fstypename));
      let identity = volume_identity(mp_path)?;
      // The enumeration already asked for the name keys above, so this reads a
      // value the URL is holding rather than making a call of its own.
      let name = volume_name_of(&url);
      #[cfg(feature = "disk-usage")]
      let (total_bytes, available_bytes) = {
        let bsize = fs.f_bsize as u64;
        (
          (fs.f_blocks as u64).saturating_mul(bsize),
          (fs.f_bavail as u64).saturating_mul(bsize),
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
  }
  Ok(mounts)
}

#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
/// A descriptor on the object the caller named, held for the whole resolve.
///
/// Opened `O_EVTONLY` — Apple's permission-minimal open, the one file-event
/// clients use — so a path the caller may traverse but has no right to *read*
/// still resolves, exactly as the pathname road did. `O_RDONLY` stands in
/// where that flag is refused. The file itself is never read: the descriptor
/// exists so that `fstatfs` and `fgetattrlist` ask about one object instead of
/// re-resolving a name five times.
fn pin(path: &Path) -> std::io::Result<rustix::fd::OwnedFd> {
  use rustix::{
    fs::{Mode, OFlags},
    io::Errno,
  };

  // `O_EVTONLY` is Apple-only and rustix does not name it, so it is spelled
  // from libc's own constant and carried in as a raw bit.
  let event_only = OFlags::from_bits_retain(libc::O_EVTONLY as u32);
  match rustix::fs::open(path, event_only | OFlags::CLOEXEC, Mode::empty()) {
    Ok(fd) => Ok(fd),
    // Only a refusal of this open itself — a right it lacks, or a filesystem
    // that does not take the flag — is a reason to try the other. A path that
    // went away, a full descriptor table or an I/O error would fail the second
    // open the same way, and trying it would only replace the error that says
    // so with one that may not.
    Err(Errno::ACCESS | Errno::PERM | Errno::INVAL | Errno::NOTSUP | Errno::OPNOTSUPP) => {
      rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(std::io::Error::from)
    }
    Err(errno) => Err(errno.into()),
  }
}

/// Pins the mount a resolve is about to describe, and hands back the one
/// `statfs` every other value in the row comes from.
///
/// Two outcomes:
///
/// 1. **The object opens.** Its `fstatfs` is the observation, and the
///    descriptor binds every descriptor-addressable read to it.
/// 2. **The object cannot be opened for want of permission** — `EACCES` or
///    `EPERM`, and nothing else. A `statfs` by pathname needs only search
///    permission on the directories above an object, so this crate has always
///    answered for paths a caller can reach but not open; a root-owned event
///    store on the Apple data volume is one. That one `statfs` is then the
///    whole row: the mount point, the source, the filesystem type and the
///    capacity, all out of a single call, and nothing else is asked — no
///    identity, no label, nothing established about removal, and the
///    capabilities the row's own filesystem type implies. See [`resolve`].
///
/// **No other descriptor stands in for the object's.** Opening the mount root
/// that `statfs` named, and reading the rest of the row off it, would need a
/// witness that the root and the path are on one *live* mount, and none is to
/// be had. A mount point and a mount source are names, reusable both. A volume
/// UUID names a volume rather than a mount: a clone carries its original's, and
/// a FAT or exFAT UUID is derived from a 32-bit serial, so two volumes can carry
/// one — and the one mounted there by the time the root is opened would answer
/// under the other's name. The mount-session handles do not close the gap
/// either. `st_dev`, `ATTR_CMN_DEVID` and `ATTR_CMN_FSID` are shared by the
/// sealed system volume and its data volume, two live mounts; `f_fsid` tells
/// those two apart, but it is a private field of `libc`'s `fsid_t`, and the
/// platform documents it as nothing more than "file system id". A held
/// descriptor does keep its own mount mounted — `unmount(2)` answers `EBUSY`
/// while a reference is held, and a forced unmount turns every later access
/// through it into an error — but pinning one mount does not make an
/// identifier that two mounts share name only one of them.
///
/// **Every other open error is returned as the error it is.** Descriptor
/// exhaustion, an I/O error and a path that went away are not facts about
/// permission, and none of them is a reason to describe the path some other
/// way.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
#[allow(clippy::type_complexity)]
fn pin_the_mount(
  canonical: &Path,
) -> std::io::Result<(Option<rustix::fd::OwnedFd>, rustix::fs::StatFs)> {
  match pin(canonical) {
    Ok(fd) => {
      let fs = rustix::fs::fstatfs(&fd).map_err(std::io::Error::from)?;
      Ok((Some(fd), fs))
    }
    // The one observation of a path that may be reached but not opened is the
    // row, and it is asked nothing more: see above.
    Err(err) if is_permission_denied(&err) => {
      let observed = statfs(canonical).map_err(std::io::Error::from)?;
      Ok((None, observed))
    }
    Err(err) => Err(err),
  }
}

/// Whether an open failed because this process may not open that object, as
/// opposed to failing for any of the reasons that are not a fact about
/// permission — a descriptor table that is full, an I/O error, a path that
/// went away.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn is_permission_denied(err: &std::io::Error) -> bool {
  // `EACCES` and `EPERM` both arrive as this kind, and they are the only two
  // failures that say "you may not open this", which is the only failure the
  // mount-root road answers.
  err.kind() == std::io::ErrorKind::PermissionDenied
}

/// What a `getattrlist` is addressed to: the descriptor a resolve holds, or
/// the pathname a listing row has.
///
/// One question, one body, two faces. The descriptor form is what makes an
/// Apple resolve one observation; the pathname form serves the listing alone,
/// whose rows come from an enumeration that hands over a path.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
enum AttrTarget<'a> {
  Fd(rustix::fd::BorrowedFd<'a>),
  /// A resolve never takes this face: a path it cannot open is described by
  /// its one `statfs` and asked nothing more. See [`pin_the_mount`].
  #[cfg(any(feature = "list", test))]
  Path(&'a std::ffi::CStr),
}

/// One `getattrlist`, addressed to whichever face the caller has.
///
/// `attrs` and `buf` are the caller's own live, `#[repr(C)]`, integer-only
/// buffers, and `size` is `buf`'s own declared size; the kernel writes no more
/// than that. Nothing in either object is read.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn getattrlist_at(
  target: AttrTarget<'_>,
  attrs: &mut libc::attrlist,
  buf: *mut core::ffi::c_void,
  size: usize,
) -> core::ffi::c_int {
  let attrs = core::ptr::from_mut(attrs).cast::<core::ffi::c_void>();
  match target {
    // SAFETY: the descriptor is valid for as long as the borrow lives, and
    // both buffers are live for the call and sized as declared.
    AttrTarget::Fd(fd) => {
      use rustix::fd::AsRawFd as _;
      unsafe { libc::fgetattrlist(fd.as_raw_fd(), attrs, buf, size, 0) }
    }
    // SAFETY: the same, with a NUL-terminated pathname that outlives the call.
    #[cfg(any(feature = "list", test))]
    AttrTarget::Path(path) => unsafe { libc::getattrlist(path.as_ptr(), attrs, buf, size, 0) },
  }
}

/// `MNT_REMOVABLE`, from `<sys/mount.h>`: "Denotes storage which can be
/// removed from the system by the user." `libc` does not name it.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const MNT_REMOVABLE: u32 = 0x0000_0200;

/// Apple platforms: whether the kernel says a resolve's storage leaves the
/// machine, read off the one `fstatfs` the row is built on.
///
/// **A resolve asks the kernel, not Foundation.** Foundation's removal keys
/// are asked by pathname and have no descriptor form, so their answer had to be
/// tied back to the pinned volume by something it carried, and the only such
/// thing was the volume's UUID. A UUID names a volume, not a mount: a clone
/// carries its original's, and a FAT or exFAT UUID is derived from a 32-bit
/// serial, so another volume mounted over the path for the length of the lookup
/// could answer under this one's name. `MNT_REMOVABLE` needs no such tie: the
/// kernel keeps it on the mount itself, and it arrives in the same `fstatfs`
/// the mount point, the source and the capacity come from.
///
/// The keys were half an answer besides — see [`ejectability_of`]: for a USB
/// disk both of them say no.
///
/// **It can only say yes.** A flag the kernel left clear is not the kernel
/// saying the storage stays; it only did not say that it leaves. So this road
/// answers [`Ejectable`](super::Ejectability::Ejectable) or
/// [`Unknown`](super::Ejectability::Unknown) and never a denial, which only a
/// listing can make, where Foundation answers for each volume's own URL.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn ejectability_of_mount(fs: &rustix::fs::StatFs) -> Ejectability {
  ejectability_from_flags(fs.f_flags)
}

/// The same answer, taken from the mount flags alone.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const fn ejectability_from_flags(flags: u32) -> Ejectability {
  if flags & MNT_REMOVABLE != 0 {
    Ejectability::Ejectable
  } else {
    Ejectability::Unknown
  }
}

/// What a volume's three keys together say, including when they say nothing —
/// the listing's road, where Foundation hands each volume's keys over with the
/// volume's own URL.
///
/// **The two removal keys are half the question.** `NSURLVolumeIsEjectableKey`
/// and `NSURLVolumeIsRemovableKey` are about the *media*: whether it comes out
/// of the drive. A USB or Thunderbolt disk's media never leaves its drive —
/// the drive leaves with it — and on a current macOS both keys answer `false`
/// for a USB disk. Reading those two noes as a denial reported external disks
/// [`NotEjectable`](super::Ejectability::NotEjectable). The other half is
/// `NSURLVolumeIsInternalKey`, whether the volume sits on an internal bus,
/// which is the platform answering whether the *drive* stays in the machine.
///
/// So a yes from either removal key is a yes, and so is a volume on an
/// external bus. A no needs **all three** answers: media that does not come
/// out, in a drive on an internal bus. Anything short of that, a key that said
/// nothing among them, is [`Unknown`](super::Ejectability::Unknown): a denial
/// on part of an answer is a negative derived from a silence.
#[cfg(any(feature = "list", test))]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const fn ejectability_of(
  ejectable: Option<bool>,
  removable: Option<bool>,
  internal: Option<bool>,
) -> Ejectability {
  match (ejectable, removable, internal) {
    (Some(true), _, _) | (_, Some(true), _) | (_, _, Some(false)) => Ejectability::Ejectable,
    (Some(false), Some(false), Some(true)) => Ejectability::NotEjectable,
    _ => Ejectability::Unknown,
  }
}

/// Whether a failed read is the platform declining to answer, rather than the
/// read itself failing.
///
/// Every road on this backend that reports a value with no "could not tell" of
/// its own — the identity, the label, a listing row — ends in its documented
/// absence on these failures, and on nothing else:
///
/// - **not there**, or not there as the thing asked for: `ENOENT`, `ENOTDIR`,
///   `EISDIR`, and `ENXIO` / `ENODEV` for a device that has gone;
/// - **may not look**: `EACCES`, `EPERM`;
/// - **not implemented**: `ENOTSUP`, `EOPNOTSUPP`, `ENOSYS`, and `EINVAL` —
///   what `getattrlist` answers for a volume attribute the filesystem does not
///   carry, as `devfs` and `autofs` do for the UUID and the name alike.
///
/// Anything else — a descriptor revoked by a forced unmount, a full descriptor
/// table, an I/O error — is a failure of the read, says nothing about the
/// volume, and is returned as the error it is.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn declined(err: &std::io::Error) -> bool {
  matches!(
    err.raw_os_error(),
    Some(
      libc::ENOENT
        | libc::ENOTDIR
        | libc::EISDIR
        | libc::ENXIO
        | libc::ENODEV
        | libc::EACCES
        | libc::EPERM
        | libc::ENOTSUP
        | libc::EOPNOTSUPP
        | libc::ENOSYS
        | libc::EINVAL
    )
  )
}

/// Apple platforms: the volume's published label, read from the volume itself.
///
/// **Read through the pinned descriptor**, with `ATTR_VOL_NAME` — the same
/// `getattrlist` road the identity and the capabilities take, and the same one
/// `diskutil info` prints as "Volume Name". That is what binds it: a value the
/// kernel answers *about the object this descriptor names* cannot be another
/// volume's, however the mount table changes around it. The NSURL road it
/// replaces could not say that — a volume resource key is asked by pathname,
/// and a pathname is re-resolved on every call.
///
/// The attribute is a length and an offset into the same buffer, so every
/// byte read out of it is bounds-checked against the buffer's own size before
/// it is touched. An empty name is no label rather than a label that is
/// nothing, and the caller's fallback then names the volume from its mount
/// point. `Vouched`, because the volume answered for itself, on this call.
///
/// A filesystem that carries no volume name answers `EINVAL`, and that is no
/// label too; a read that failed for any other reason is returned as the error
/// it is rather than as a volume with no name — see [`declined`].
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_name_at(target: AttrTarget<'_>) -> std::io::Result<Option<NameReading>> {
  // `getattrlist` writes a leading length, then the requested attributes in
  // bitmap order; `ATTR_VOL_NAME` is an `attrreference_t` whose payload
  // follows in the same buffer. 256 bytes is `NAME_MAX + 1`, which is the most
  // a volume name can be.
  #[repr(C)]
  struct NameBuf {
    length: u32,
    reference: libc::attrreference_t,
    name: [u8; 256],
  }

  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_NAME;

  let mut buf: NameBuf = unsafe { core::mem::zeroed() };
  let rc = getattrlist_at(
    target,
    &mut attrs,
    core::ptr::from_mut(&mut buf).cast::<core::ffi::c_void>(),
    core::mem::size_of::<NameBuf>(),
  );
  if rc != 0 {
    // Taken before anything else can overwrite it.
    let err = std::io::Error::last_os_error();
    return if declined(&err) { Ok(None) } else { Err(err) };
  }

  // Everything below reads the answer the kernel gave, and anything in it that
  // is not a name is no label.
  let label = || {
    // The offset the kernel writes is relative to the reference itself, and
    // may in principle be negative; the payload has to lie wholly inside the
    // buffer that was declared, or it is not a name this call was given.
    let base = core::mem::offset_of!(NameBuf, reference) as i64;
    let start = base.checked_add(i64::from(buf.reference.attr_dataoffset))?;
    let length = i64::from(buf.reference.attr_length);
    let end = start.checked_add(length)?;
    if start < 0 || length <= 0 || end > core::mem::size_of::<NameBuf>() as i64 {
      return None;
    }

    // SAFETY: `NameBuf` is `#[repr(C)]` and every field is an integer or an
    // array of them, so its bytes are a valid `[u8; N]` however the kernel
    // filled them.
    let bytes: &[u8; core::mem::size_of::<NameBuf>()] =
      unsafe { &*core::ptr::from_ref(&buf).cast() };
    let payload = &bytes[start as usize..end as usize];
    // The kernel counts the terminating NUL in `attr_length`.
    let name = match super::find_byte(0, payload) {
      Some(nul) => &payload[..nul],
      None => payload,
    };
    let name = core::str::from_utf8(name).ok()?;
    super::published_label(name, super::IdentityAssurance::Vouched)
  };
  Ok(label())
}

/// The label an NSURL already names, for a caller holding one — the enumeration
/// in [`list`](self::list), which asked for both keys up front.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_name_of(url: &objc2_foundation::NSURL) -> Option<NameReading> {
  use objc2_foundation::{NSURLVolumeLocalizedNameKey, NSURLVolumeNameKey};

  for key in unsafe { [NSURLVolumeNameKey, NSURLVolumeLocalizedNameKey] } {
    if let Some(name) = get_string_resource(url, key) {
      // Whether the volume published a label at all is the one question asked
      // here; what it published is reported as published. The volume answered
      // for itself, through the same road that vouches for its identity.
      if let Some(reading) = super::published_label(&name, super::IdentityAssurance::Vouched) {
        return Some(reading);
      }
    }
  }
  None
}

/// FreeBSD, OpenBSD, DragonFlyBSD: no label to publish.
///
/// A UFS or ZFS volume's label lives in a GEOM provider name or a dataset name
/// rather than in anything `statfs` reports, and reaching either means a
/// library or an ioctl this crate does not take. The mount point's own last
/// component is what a caller sees instead — see
/// [`volume_name()`](super::MountPoint::volume_name).
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
pub(super) fn volume_name(_path: &Path) -> Option<NameReading> {
  None
}

/// Helper: extract a string volume resource value from an NSURL.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn get_string_resource(
  url: &objc2_foundation::NSURL,
  key: &objc2_foundation::NSURLResourceKey,
) -> Option<String> {
  use objc2_foundation::NSString;

  let dict = url
    .resourceValuesForKeys_error(&objc2_foundation::NSArray::from_slice(&[key]))
    .ok()?;
  let obj = dict.objectForKey(key)?;
  let string: &NSString = unsafe { &*(&*obj as *const _ as *const NSString) };
  Some(string.to_string())
}

/// Helper: extract a boolean volume resource value from an NSURL.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn get_bool_resource(
  url: &objc2_foundation::NSURL,
  key: &objc2_foundation::NSURLResourceKey,
) -> Option<bool> {
  use objc2_foundation::NSNumber;

  // `None` is the volume not answering — the read failed, or it published no
  // value for this key — which is a different fact from its answering `false`.
  let dict = url
    .resourceValuesForKeys_error(&objc2_foundation::NSArray::from_slice(&[key]))
    .ok()?;
  let obj = dict.objectForKey(key)?;
  let num: &NSNumber = unsafe { &*(&*obj as *const _ as *const NSNumber) };
  Some(num.boolValue())
}

/// Serializes calls to `getmntinfo(3)`, whose buffer is process-wide; see the
/// non-reentrancy note on [`list`](self::list)'s doc comment.
#[cfg(feature = "list")]
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
static GETMNTINFO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// FreeBSD, OpenBSD, DragonFlyBSD: use getmntinfo, skip virtual filesystems.
///
/// `getmntinfo(3)` is not reentrant. Its own manual says so in BUGS: "The
/// getmntinfo() function writes the array of structures to an internal
/// static object and returns a pointer to that object. Subsequent calls to
/// getmntinfo() will modify the same object." (FreeBSD 15.1-RELEASE and
/// OpenBSD `getmntinfo(3)`; DragonFlyBSD's `getmntinfo` shares the same
/// `*mut *mut statfs` signature and BSD lineage.) Two threads calling it at
/// once therefore race on that one process-wide, realloc'd buffer: a caller
/// can be handed a stale pointer, or see `count <= 0` while another thread's
/// call is mid-refill — with no syscall having actually failed, so `errno`
/// (thread-local, only ever updated on failure) is left holding whatever it
/// last held on this thread, often 0. `GETMNTINFO_LOCK` serializes the call
/// and the copy-out of its entries below; the entries are copied into owned
/// storage before the lock is released, because releasing it hands the next
/// caller license to realloc — and thereby invalidate — the buffer this call
/// just read.
///
/// A `count <= 0` result paired with `raw_os_error() == Some(0)` is read as
/// "zero mounts," not a failure: nothing on this path sets errno to 0 to
/// report success, so an errno of exactly 0 carries no real error
/// information, and treating it as one would fabricate a failure out of an
/// ordinary empty answer. Any other errno still returns `Err`.
#[cfg(feature = "list")]
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
pub(super) fn list(opts: super::ListOptions) -> std::io::Result<Vec<super::MountPoint>> {
  const MNT_WAIT: core::ffi::c_int = 1;
  const MNT_NOWAIT: core::ffi::c_int = 2;

  // The call and the copy-out below run under one lock — see the doc comment
  // above — and the copy must finish before the lock is released.
  let raw_entries: Vec<libc::statfs> = {
    let _guard = GETMNTINFO_LOCK
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut mntbuf: *mut libc::statfs = core::ptr::null_mut();
    // MNT_NOWAIT returns cached statistics (fast), but on a cold process some
    // BSDs (notably OpenBSD) return 0 entries without setting errno; fall back to
    // MNT_WAIT, which forces a refresh and reliably populates the mount list.
    let mut count = unsafe { libc::getmntinfo(&mut mntbuf, MNT_NOWAIT) };
    if count <= 0 || mntbuf.is_null() {
      count = unsafe { libc::getmntinfo(&mut mntbuf, MNT_WAIT) };
    }
    if count <= 0 || mntbuf.is_null() {
      let err = std::io::Error::last_os_error();
      return if err.raw_os_error() == Some(0) {
        // errno was never set: an honest "no mounts", not a failure. See the
        // doc comment above.
        Ok(Vec::new())
      } else {
        Err(err)
      };
    }

    let entries = unsafe { core::slice::from_raw_parts(mntbuf, count as usize) };
    entries.to_vec()
  };

  let mut mounts = Vec::new();
  for entry in &raw_entries {
    let fs_type = c_chars_as_bytes(&entry.f_fstypename);
    if matches!(
      fs_type,
      b"autofs" | b"devfs" | b"linprocfs" | b"procfs" | b"fdescfs" | b"tmpfs" | b"linsysfs"
    ) {
      continue;
    }
    let mp_bytes = c_chars_as_bytes(&entry.f_mntonname);
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
    let capabilities = volume_capabilities(mount_point.as_path(), fs_type);
    let identity = volume_identity(mount_point.as_path());
    let name = volume_name(mount_point.as_path());
    #[cfg(feature = "disk-usage")]
    let (total_bytes, available_bytes) = {
      let bsize = entry.f_bsize as u64;
      (
        (entry.f_blocks as u64).saturating_mul(bsize),
        (entry.f_bavail as u64).saturating_mul(bsize),
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

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
/// What a FreeBSD, OpenBSD or DragonFly device name can say about removal.
///
/// **A name never denies.** These platforms are asked through the mount
/// table's device name, and a name is topology hearsay: FreeBSD's `da` is the
/// SCSI/SAS disk driver, which covers internal SAS and iSCSI as well as USB
/// mass storage, and OpenBSD attaches USB mass storage as `sd`, the same name
/// its internal SCSI disks carry. Reading either as evidence of a fixed drive
/// was inventing a denial out of a name, and reading `da` as evidence of a
/// *removable* one was inventing the opposite.
///
/// What survives is the one name class that is exclusively removable on all
/// three: `cd`, the optical drivers (`cd`, `acd`), where the medium is a disc
/// that leaves the machine and nothing internal is attached under that name.
/// `fd`, the floppy driver, is the same kind of fact. Every other name — `da`,
/// `sd`, `ada`, `nvd`, `vtbd` — says nothing either way, and says it as
/// [`Unknown`](super::Ejectability::Unknown).
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn ejectability_from_name(device: &[u8]) -> Ejectability {
  if names_optical_or_floppy(device) {
    Ejectability::Ejectable
  } else {
    Ejectability::Unknown
  }
}

/// Whether a BSD device name is one of the two classes that are exclusively
/// removable media on these platforms.
#[cfg(any(
  target_os = "freebsd",
  target_os = "openbsd",
  target_os = "dragonfly",
  target_os = "netbsd"
))]
fn names_optical_or_floppy(device: &[u8]) -> bool {
  let Some(name) = device.strip_prefix(b"/dev/") else {
    return false;
  };
  // `cd0`, `acd0`, `fd0` and their partition forms `cd0a`, `fd0a` — the driver
  // letters followed by a unit number, so that a volume named `cdimages`
  // cannot answer for an optical drive.
  //
  // Written as a nested `if` rather than a let-chain: let-chains are Rust 1.88
  // and this crate's `rust-version` is 1.85, so the shorter spelling would not
  // compile on the compiler the crate says it supports.
  for prefix in [&b"cd"[..], b"acd", b"fd"] {
    if let Some(tail) = name.strip_prefix(prefix) {
      if super::names_unit_and_partition(tail) {
        return true;
      }
    }
  }
  false
}

/// Apple platforms: query case-handling capabilities via `getattrlist` with
/// `ATTR_VOL_CAPABILITIES`. `fs_type` is taken from the caller's `statfs`
/// (`f_fstypename`). Case flags fall back to `None` when the volume does not
/// report the `VOL_CAP_FMT_CASE_SENSITIVE` / `VOL_CAP_FMT_CASE_PRESERVING` bits
/// as valid, or the syscall fails.
#[cfg(any(feature = "list", test))]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_capabilities(path: &Path, fs_type: &[u8]) -> VolumeCapabilities {
  let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
    return VolumeCapabilities::from_fs_type(fs_type);
  };
  volume_capabilities_at(AttrTarget::Path(&c_path), fs_type)
}

/// The same question, asked of whichever face the caller has.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_capabilities_at(target: AttrTarget<'_>, fs_type: &[u8]) -> VolumeCapabilities {
  // getattrlist writes a leading u32 length followed by the requested
  // attributes in bitmap order; for ATTR_VOL_CAPABILITIES that is a single
  // vol_capabilities_attr_t. #[repr(C)] guarantees the layout the kernel writes.
  #[repr(C)]
  struct CapabilitiesBuf {
    length: u32,
    caps: libc::vol_capabilities_attr_t,
  }

  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES;

  let mut buf: CapabilitiesBuf = unsafe { core::mem::zeroed() };
  let rc = getattrlist_at(
    target,
    &mut attrs,
    core::ptr::from_mut(&mut buf).cast::<core::ffi::c_void>(),
    core::mem::size_of::<CapabilitiesBuf>(),
  );
  if rc != 0 {
    return VolumeCapabilities::from_fs_type(fs_type);
  }

  // capabilities[VOL_CAPABILITIES_FORMAT] holds the format-capability bits;
  // a bit is only meaningful when the matching valid[...] bit is set.
  let format = buf.caps.capabilities[libc::VOL_CAPABILITIES_FORMAT];
  let format_valid = buf.caps.valid[libc::VOL_CAPABILITIES_FORMAT];

  let case_sensitive = if format_valid & libc::VOL_CAP_FMT_CASE_SENSITIVE != 0 {
    Some(format & libc::VOL_CAP_FMT_CASE_SENSITIVE != 0)
  } else {
    None
  };
  let case_preserving = if format_valid & libc::VOL_CAP_FMT_CASE_PRESERVING != 0 {
    Some(format & libc::VOL_CAP_FMT_CASE_PRESERVING != 0)
  } else {
    None
  };

  VolumeCapabilities {
    case_sensitive,
    case_preserving,
    fs_type: SmallBytes::from_bytes(fs_type),
  }
}

/// Apple platforms: read the volume's UUID via `getattrlist` with
/// `ATTR_VOL_UUID`. This is the same value `diskutil info` prints as
/// "Volume UUID", and it is stored on the volume, so it survives unmounting and
/// moving the disk to another machine.
///
/// The kernel answers for the volume the path is really on, on this call, so
/// the reading is [`Vouched`](super::IdentityAssurance::Vouched): no name
/// published about a device sits between the mount and the value.
///
/// `None` when the filesystem has no UUID to report: `getattrlist` answers
/// `EINVAL` on the pseudo-filesystems (`devfs`, `autofs`), and a filesystem that
/// answers but omits the attribute reports a short length rather than an error.
/// An all-zero UUID is the "no UUID" sentinel and is also reported as `None`,
/// and so is a path that is no longer there or is out of this caller's reach.
/// A read that failed for any other reason is returned as the error it is,
/// never as a volume with no identity — see [`declined`].
#[cfg(any(feature = "list", test))]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_identity(path: &Path) -> std::io::Result<Option<IdentityReading>> {
  // A path carrying an interior NUL is no path the kernel handed out, and
  // names no volume at all.
  let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
    return Ok(None);
  };
  volume_identity_at(AttrTarget::Path(&c_path))
}

/// The same question, asked of whichever face the caller has.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_identity_at(target: AttrTarget<'_>) -> std::io::Result<Option<IdentityReading>> {
  // getattrlist writes a leading u32 length followed by the requested
  // attributes in bitmap order; for ATTR_VOL_UUID that is a single uuid_t.
  // #[repr(C)] guarantees the layout the kernel writes.
  #[repr(C)]
  struct UuidBuf {
    length: u32,
    uuid: libc::uuid_t,
  }

  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID;

  let mut buf: UuidBuf = unsafe { core::mem::zeroed() };
  let rc = getattrlist_at(
    target,
    &mut attrs,
    core::ptr::from_mut(&mut buf).cast::<core::ffi::c_void>(),
    core::mem::size_of::<UuidBuf>(),
  );
  if rc != 0 {
    // Taken before anything else can overwrite it.
    let err = std::io::Error::last_os_error();
    return if declined(&err) { Ok(None) } else { Err(err) };
  }
  // `length` counts the bytes the kernel wrote, including itself; anything
  // shorter than the full buffer means the UUID was not among them.
  if (buf.length as usize) < core::mem::size_of::<UuidBuf>() {
    return Ok(None);
  }
  // An all-zero UUID records the absence of one; `fs_uuid` applies the same
  // rule every other backend uses.
  Ok(super::fs_uuid(buf.uuid).map(IdentityReading::vouched))
}

/// FreeBSD, OpenBSD, DragonFlyBSD: derive case semantics from the filesystem
/// type — `Some(...)` only for types that determine it (FFS/UFS are
/// case-sensitive, msdosfs/exFAT are case-insensitive) and `None` otherwise
/// (ZFS case sensitivity is a per-dataset property). There is no portable
/// per-volume query. `fs_type` comes from `statfs` (`f_fstypename`).
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn volume_capabilities(_path: &Path, fs_type: &[u8]) -> VolumeCapabilities {
  VolumeCapabilities::from_fs_type_defaults(fs_type)
}

/// FreeBSD, OpenBSD, DragonFlyBSD: no durable volume identity, because none is
/// reachable honestly here.
///
/// `statfs`'s `f_fsid` is deliberately *not* used: on these systems it is a
/// mount-session handle assigned by `vfs_getnewfsid()` when the filesystem is
/// mounted, not a property of the volume, so it changes across reboots and
/// differs between machines — exactly the two things an identity must survive.
/// Durable values do exist on disk (the UFS filesystem id, a GPT partition
/// UUID), but they are only reachable through the optional `geom_label` links
/// (`/dev/ufsid/`, `/dev/gptid/`), which are not enabled by default; wiring that
/// road up needs a real host to verify against.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn volume_identity(_path: &Path) -> Option<IdentityReading> {
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

#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_volume_identity_root_is_a_uuid() {
    let reading = volume_identity(Path::new("/"))
      .unwrap()
      .expect("the root volume reports a UUID");
    let super::super::VolumeIdentity::FsUuid(uuid) = reading.identity() else {
      panic!("Apple volumes report a UUID, got {reading:?}");
    };
    assert_ne!(uuid, [0u8; 16]);
  }

  /// The kernel read it off the volume the path is on, on this call. Apple has
  /// no published-name road and never takes one, so the level is fixed here.
  #[test]
  fn test_the_apple_reading_is_vouched() {
    let reading = volume_identity(Path::new("/"))
      .unwrap()
      .expect("the root volume reports a UUID");
    assert_eq!(
      reading.assurance(),
      super::super::IdentityAssurance::Vouched
    );
    assert!(reading.is_vouched());
  }

  #[test]
  fn test_volume_identity_is_stable_across_calls() {
    // The whole point of the value: two independent queries of the same volume
    // must agree, since it is read off the volume rather than the mount.
    assert_eq!(
      volume_identity(Path::new("/")).unwrap(),
      volume_identity(Path::new("/")).unwrap()
    );
  }

  #[test]
  fn test_volume_identity_pseudo_filesystem_is_none() {
    // devfs has no UUID and says so with `EINVAL`: the filesystem declining,
    // which is no identity — neither an invented value nor a failure.
    assert_eq!(volume_identity(Path::new("/dev")).unwrap(), None);
  }

  /// A failed read is not an answer about a volume, and only a declined one
  /// may stand for "none".
  ///
  /// An identity or a label reported absent because the descriptor table was
  /// full reads, to a caller, exactly like a volume that carries none — and a
  /// caller keying on the identity acts on that. So the absence is kept for
  /// the platform declining, and every other failure is the error it is.
  #[test]
  fn test_only_a_declined_read_is_an_absence() {
    use std::io::Error;

    for errno in [
      libc::ENOENT,
      libc::ENOTDIR,
      libc::EISDIR,
      libc::ENXIO,
      libc::ENODEV,
      libc::EACCES,
      libc::EPERM,
      libc::ENOTSUP,
      libc::EOPNOTSUPP,
      libc::ENOSYS,
      libc::EINVAL,
    ] {
      assert!(
        declined(&Error::from_raw_os_error(errno)),
        "errno {errno} is the platform declining to answer"
      );
    }
    for errno in [
      libc::EMFILE,
      libc::ENFILE,
      libc::EIO,
      libc::EBADF,
      libc::ENOMEM,
      libc::EINTR,
      libc::ENAMETOOLONG,
    ] {
      assert!(
        !declined(&Error::from_raw_os_error(errno)),
        "errno {errno} is a failed read, not an answer"
      );
    }
    assert!(!declined(&Error::other("not an errno at all")));
  }

  /// And the identity road keeps that rule on the live kernel: a path that is
  /// not there has no identity, while a name no filesystem call accepts is a
  /// failed read.
  #[test]
  fn test_a_failed_identity_read_is_an_error_and_a_declined_one_is_none() {
    assert_eq!(
      volume_identity(Path::new("/whichdisk-no-such-path")).unwrap(),
      None
    );
    let too_long = format!("/{}", "a".repeat(4096));
    let err = volume_identity(Path::new(&too_long)).expect_err("an over-long name is no answer");
    assert_eq!(err.raw_os_error(), Some(libc::ENAMETOOLONG));
  }

  /// Nothing about a mount is remembered between resolves.
  ///
  /// There used to be a thread-local entry keyed by `st_dev` holding the mount
  /// point, the mount source and the capabilities. That key is not a witness —
  /// a device number is handed to another mount once the first goes away, and
  /// on Apple the sealed system volume and its data volume report one between
  /// them — so a hit could serve another volume's mount point, which the
  /// ejectability was then asked of. The law is that every field of a resolve
  /// is what the kernel reports for that path at that moment, with no store in
  /// between that could answer for another volume.
  #[test]
  fn test_the_resolve_reads_the_mount_rather_than_remembering_it() {
    let truth = volume_identity(Path::new("/"))
      .unwrap()
      .expect("the root volume reports a UUID");
    let fs = statfs(Path::new("/")).expect("the root mount answers statfs");

    // Resolved after the reading above, and still the same facts: there is no
    // entry that an earlier call could have filled in on its behalf.
    let resolved = resolve(Path::new("/")).unwrap();
    let mount = resolved.mount_info();
    assert_eq!(mount.volume_identity(), Some(truth));
    assert_eq!(
      mount.mount_point().as_os_str().as_bytes(),
      c_chars_as_bytes(&fs.f_mntonname)
    );
    assert_eq!(
      mount.device().as_bytes(),
      c_chars_as_bytes(&fs.f_mntfromname)
    );
  }

  /// An open that failed for want of permission has a road of its own; nothing
  /// else does.
  ///
  /// Descriptor exhaustion, a transient I/O error and a vanished path are not
  /// facts about permission, and turning any of them into another road traded
  /// a correct refusal for a row assembled some other way.
  #[test]
  fn test_only_a_permission_failure_reaches_the_descriptor_less_road() {
    use std::io::Error;

    assert!(is_permission_denied(&Error::from_raw_os_error(
      libc::EACCES
    )));
    assert!(is_permission_denied(&Error::from_raw_os_error(libc::EPERM)));
    for errno in [
      libc::EMFILE,
      libc::ENFILE,
      libc::EIO,
      libc::ENOENT,
      libc::ELOOP,
    ] {
      assert!(
        !is_permission_denied(&Error::from_raw_os_error(errno)),
        "errno {errno} is not a permission failure"
      );
    }
    assert!(!is_permission_denied(&Error::other("not an errno at all")));
  }

  /// A path this process may reach but not open is described by its own one
  /// observation, and by nothing a descriptor opened elsewhere could say.
  ///
  /// The root-owned event store on the data volume is exactly that path. Its
  /// mount root opens, and the root's identity once stood in for the path's —
  /// accepted because the two faces named one volume UUID. A UUID names a
  /// volume rather than a mount, so a volume carrying the same one, mounted
  /// there in between, would have passed. No descriptor stands in now.
  #[test]
  fn test_a_path_that_cannot_be_opened_is_described_by_its_own_observation() {
    let path = Path::new("/System/Volumes/Data/.fseventsd");
    if pin(path).is_ok() || !path.exists() {
      // Running as root, or on a system without it: nothing to prove here.
      return;
    }

    let (pinned, fs) = pin_the_mount(path).expect("the mount is still describable");
    assert!(
      pinned.is_none(),
      "no descriptor stands in for the one the path refused"
    );
    let observed = statfs(path).expect("the path answers statfs");
    assert_eq!(
      c_chars_as_bytes(&fs.f_mntonname),
      c_chars_as_bytes(&observed.f_mntonname)
    );

    // The row is that observation and nothing more: no identity, no label and
    // nothing about removal, though the volume publishes all three — nothing
    // could tie a read made anywhere else to the volume the path is on.
    let resolved = resolve(path).unwrap();
    let mount = resolved.mount_info();
    assert_eq!(
      mount.mount_point().as_os_str().as_bytes(),
      c_chars_as_bytes(&observed.f_mntonname)
    );
    assert_eq!(
      mount.device().as_bytes(),
      c_chars_as_bytes(&observed.f_mntfromname)
    );
    assert_eq!(mount.volume_identity(), None);
    assert_eq!(mount.volume_name_assurance(), None);
    assert_eq!(mount.ejectability(), Ejectability::Unknown);
  }

  /// The label comes off the pinned descriptor, so it is the pinned volume's
  /// by construction rather than by comparison.
  #[test]
  fn test_the_label_is_read_through_the_pinned_descriptor() {
    use rustix::fd::AsFd as _;

    let root = Path::new("/");
    let pinned = pin(root).expect("the root directory opens");
    let through_fd = volume_name_at(AttrTarget::Fd(pinned.as_fd())).unwrap();
    assert!(
      through_fd.is_some(),
      "the boot volume publishes a name, and the descriptor road reads it"
    );
    assert_eq!(
      resolve(root).unwrap().mount_info().volume_name(),
      through_fd
        .as_ref()
        .and_then(|r| core::str::from_utf8(r.name.as_bytes()).ok()),
      "and that is the name the resolve reports"
    );
  }

  /// A resolve's removal answer is the pinned mount's own flag: `Ejectable`
  /// where the kernel set it, `Unknown` where it did not, never a denial.
  ///
  /// It used to be Foundation's two removal keys, asked by pathname and kept
  /// where the volume that answered named itself by the pinned volume's UUID.
  /// A UUID names a volume and not a mount, so another volume carrying the same
  /// one could answer for this one — and for a USB disk the two keys say no
  /// regardless, which made every external disk a denial.
  #[test]
  fn test_the_removal_answer_is_the_pinned_mounts_own_flag() {
    assert_eq!(
      ejectability_from_flags(MNT_REMOVABLE),
      Ejectability::Ejectable
    );
    assert_eq!(
      ejectability_from_flags(MNT_REMOVABLE | libc::MNT_LOCAL as u32),
      Ejectability::Ejectable
    );
    // A flag the kernel left clear says nothing, whatever else is set.
    assert_eq!(ejectability_from_flags(0), Ejectability::Unknown);
    assert_eq!(
      ejectability_from_flags(!MNT_REMOVABLE),
      Ejectability::Unknown
    );

    // Asked of the live kernel: every mounted volume this host can open,
    // external ones included where there are any.
    let mut paths = vec![
      PathBuf::from("/"),
      PathBuf::from("/System/Volumes/Data"),
      PathBuf::from("/private/tmp"),
    ];
    if let Ok(volumes) = std::fs::read_dir("/Volumes") {
      paths.extend(volumes.flatten().map(|entry| entry.path()));
    }
    for path in paths {
      let Ok(pinned) = pin(&path) else { continue };
      let flags = rustix::fs::fstatfs(&pinned).unwrap().f_flags;
      let answer = resolve(&path).unwrap().mount_info().ejectability();
      assert_eq!(answer, ejectability_from_flags(flags), "{path:?}");
      assert_ne!(answer, Ejectability::NotEjectable, "{path:?}");
    }
  }

  /// A listing denies only where all three keys answered, and the drive's own
  /// half of the question is the one that says an external disk leaves.
  #[test]
  fn test_a_listing_denies_only_on_all_three_answers() {
    use super::super::Ejectability::{Ejectable, NotEjectable, Unknown};

    // Media that comes out is a yes, whatever the bus.
    assert_eq!(
      ejectability_of(Some(true), Some(false), Some(true)),
      Ejectable
    );
    assert_eq!(
      ejectability_of(Some(false), Some(true), Some(true)),
      Ejectable
    );
    // A drive on an external bus leaves with its media: a USB disk, for which
    // both removal keys answer no.
    assert_eq!(
      ejectability_of(Some(false), Some(false), Some(false)),
      Ejectable
    );
    assert_eq!(ejectability_of(None, None, Some(false)), Ejectable);
    // Fixed media in a drive on an internal bus: no to both halves.
    assert_eq!(
      ejectability_of(Some(false), Some(false), Some(true)),
      NotEjectable
    );
    // A silence anywhere among the three is no denial.
    for (ejectable, removable, internal) in [
      (Some(false), Some(false), None),
      (None, Some(false), Some(true)),
      (Some(false), None, Some(true)),
      (None, None, None),
    ] {
      assert_eq!(
        ejectability_of(ejectable, removable, internal),
        Unknown,
        "{ejectable:?} {removable:?} {internal:?}"
      );
    }
  }

  /// The descriptor road and the pathname road answer the same question, and
  /// this host is the platform they run on — so both are asked for real.
  #[test]
  fn test_the_descriptor_and_the_pathname_roads_agree() {
    let root = Path::new("/");
    let pinned = pin(root).expect("the root directory opens");
    let fd = {
      use rustix::fd::AsFd as _;
      pinned.as_fd()
    };

    assert_eq!(
      volume_identity_at(AttrTarget::Fd(fd)).unwrap(),
      volume_identity(root).unwrap(),
      "one volume, one identity, whichever face asked"
    );

    let fs = rustix::fs::fstatfs(&pinned).expect("the root mount answers fstatfs");
    let fs_type = c_chars_as_bytes(&fs.f_fstypename);
    assert_eq!(
      volume_capabilities_at(AttrTarget::Fd(fd), fs_type).case_sensitive(),
      volume_capabilities(root, fs_type).case_sensitive()
    );

    // And the descriptor really does describe the same mount the pathname
    // does — kept here only as a sanity check on an unchanging mount.
    let by_path = statfs(root).expect("the root mount answers statfs");
    assert_eq!(
      c_chars_as_bytes(&fs.f_mntonname),
      c_chars_as_bytes(&by_path.f_mntonname)
    );
  }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_volume_identity_is_none() {
    // Documented gap: f_fsid is a mount-session handle, not a volume identity.
    assert_eq!(volume_identity(Path::new("/")), None);
  }

  /// OpenBSD's own `mount(8)` mounts a disc as `/dev/cd0a`, so the partition
  /// form has to be the one the matcher reads — it used to demand digits all
  /// the way to the end, and every disc these systems actually mount answered
  /// `Unknown`.
  #[test]
  fn test_a_disc_mounted_through_its_partition_still_names_a_drive() {
    for device in [
      "/dev/cd0",
      "/dev/cd0a",
      "/dev/acd0",
      "/dev/acd0c",
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
  /// these platforms have no way to make.
  #[test]
  fn test_a_name_that_is_not_a_drive_says_nothing() {
    for device in [
      "/dev/cdimages",
      "/dev/cd0extra",
      "/dev/cd",
      "/dev/da0p1",
      "/dev/sd0a",
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
