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
/// descriptor is opened on the canonical path and held for the whole call:
/// `fstatfs` and `fgetattrlist` are asked of *it*, so the mount metadata, the
/// capabilities and the identity are one observation by construction. The two
/// reads Foundation offers no descriptor form of — the label and the two
/// ejectability keys — are bracketed instead: the mount the descriptor is on is
/// read before them and again after, and a reading whose mount moved underneath
/// it is discarded rather than combined. See [`kept_on_the_same_mount`].
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
/// goes away, and on Apple every volume of one APFS container shares it. A hit
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
  let pinned = pin(&canonical).ok();
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  let fs = match pinned.as_ref() {
    Some(fd) => rustix::fs::fstatfs(fd).map_err(std::io::Error::from)?,
    None => statfs(&canonical).map_err(std::io::Error::from)?,
  };
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
        volume_identity_at(AttrTarget::Fd(fd.as_fd())),
        volume_capabilities_at(
          AttrTarget::Fd(fd.as_fd()),
          c_chars_as_bytes(&fs.f_fstypename),
        ),
      )
    }
    None => (
      volume_identity(&canonical),
      volume_capabilities(&canonical, c_chars_as_bytes(&fs.f_fstypename)),
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

  // The two reads Foundation offers no descriptor form of, bracketed by the
  // mount the held descriptor is on. A label and an ejectability answer are
  // kept only if the mount did not move between the witness taken before them
  // and the one taken after; otherwise they belong to some other volume and
  // are discarded rather than combined with the row above. Neither is ever
  // remembered either: a person can rewrite a label while the mount stays
  // exactly as it is.
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  let (ejectability, volume_name) = {
    let pinned_mount = mount_witness(&fs);
    let before = statfs(&canonical).ok();
    let reading = (ejectability(&canonical), volume_name(&canonical));
    let after = statfs(&canonical).ok();
    kept_on_the_same_mount(
      &pinned_mount,
      before.as_ref().map(mount_witness),
      after.as_ref().map(mount_witness),
      reading,
    )
    .unwrap_or((Ejectability::Unknown, None))
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
    NSURLVolumeIsLocalKey, NSURLVolumeIsRemovableKey, NSVolumeEnumerationOptions,
  };

  let fm = NSFileManager::defaultManager();
  let keys: &[&NSURLResourceKey] = unsafe {
    &[
      NSURLVolumeIsBrowsableKey,
      NSURLVolumeIsLocalKey,
      NSURLVolumeIsEjectableKey,
      NSURLVolumeIsRemovableKey,
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
    let ejectability = ejectability_of(ejectable, removable);

    // Exact states: a volume of unknown ejectability is named by neither
    // only-filter, so it is excluded by either. See `ListOptions::excludes`.
    if opts.excludes(ejectability) {
      continue;
    }

    if let Some(path) = url.path() {
      let path_bytes = path.to_string().into_bytes();
      let mount_point = SmallBytes::from_bytes(&path_bytes);

      let mp_path = Path::new(OsStr::from_bytes(&path_bytes));
      let fs = match statfs(mp_path) {
        Ok(fs) => fs,
        Err(_) => continue,
      };
      let device = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntfromname));
      let capabilities = volume_capabilities(mp_path, c_chars_as_bytes(&fs.f_fstypename));
      let identity = volume_identity(mp_path);
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
  use rustix::fs::{Mode, OFlags};

  // `O_EVTONLY` is Apple-only and rustix does not name it, so it is spelled
  // from libc's own constant and carried in as a raw bit.
  let event_only = OFlags::from_bits_retain(libc::O_EVTONLY as u32);
  rustix::fs::open(path, event_only | OFlags::CLOEXEC, Mode::empty())
    .or_else(|_| rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()))
    .map_err(std::io::Error::from)
}

/// What a `getattrlist` is addressed to: a descriptor a resolve already holds,
/// or a pathname where no descriptor could be had.
///
/// One question, one body, two faces. The descriptor form is what makes an
/// Apple resolve one observation; the pathname form serves the listing, and the
/// resolve of a path this process may reach but not open.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
enum AttrTarget<'a> {
  Fd(rustix::fd::BorrowedFd<'a>),
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
    AttrTarget::Path(path) => unsafe { libc::getattrlist(path.as_ptr(), attrs, buf, size, 0) },
  }
}

/// What identifies the mount behind an answer, for the reads that can only be
/// made by pathname.
///
/// The pair is the mount point a filesystem is attached at and the source
/// attached there. Neither alone is enough: an overmount or a move changes the
/// first while the second stays, and a volume replaced under the same mount
/// point changes the second while the first stays. A reading is kept only
/// where **both** are what the pinned descriptor says they are.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
#[derive(PartialEq, Eq)]
struct MountWitness {
  mount_point: SmallBytes,
  device: SmallBytes,
}

#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn mount_witness(fs: &rustix::fs::StatFs) -> MountWitness {
  MountWitness {
    mount_point: SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntonname)),
    device: SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntfromname)),
  }
}

/// Keeps a reading made by pathname only while that pathname led to the pinned
/// mount on both sides of it.
///
/// **A witness taken from the descriptor could not do this.** The descriptor
/// pins its object, so what it reports never changes — that is the whole point
/// of holding it. What *can* change is where the pathname leads, and that is
/// what these reads followed. So `pinned` is the mount the rest of the row
/// describes, taken from the descriptor, and `before` and `after` are the mount
/// the *pathname* resolved to immediately before and immediately after the
/// reads.
///
/// Anything but the pinned mount on both sides discards the reading, a `statfs`
/// that could not be made at all included: a call that failed is not evidence
/// that nothing moved. A label or a definitive `NotEjectable` belonging to
/// another volume must never be combined with a row describing this one, and
/// there is nothing to fall back on but the honest answers — no label, and
/// nothing established about removal.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn kept_on_the_same_mount<T>(
  pinned: &MountWitness,
  before: Option<MountWitness>,
  after: Option<MountWitness>,
  reading: T,
) -> Option<T> {
  (before.as_ref() == Some(pinned) && after.as_ref() == Some(pinned)).then_some(reading)
}

/// Apple platforms: query NSURLVolumeIsEjectableKey / NSURLVolumeIsRemovableKey.
///
/// `path` is any path on the volume rather than its mount point, for the reason
/// [`volume_name`] takes one: a volume resource key answers for the volume the
/// path lives on, so asking about the path in hand asks about the volume that
/// path is really on.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(super) fn ejectability(path: &Path) -> Ejectability {
  use objc2_foundation::{NSURLVolumeIsEjectableKey, NSURLVolumeIsRemovableKey};

  // Built from the filesystem bytes, never from a lossy spelling — see
  // [`with_file_url`]. A path this cannot represent is a volume this cannot
  // ask, which is not that volume answering no.
  with_file_url(path, |url| {
    let ejectable = get_bool_resource(url, unsafe { NSURLVolumeIsEjectableKey });
    let removable = get_bool_resource(url, unsafe { NSURLVolumeIsRemovableKey });
    ejectability_of(ejectable, removable)
  })
  .unwrap_or(Ejectability::Unknown)
}

/// Runs `ask` against an `NSURL` for `path`, built from the bytes the
/// filesystem holds.
///
/// **A lossy path is another path.** `to_string_lossy` replaces every byte no
/// `&str` carries with U+FFFD, and the result names a different file — one that
/// need not exist, and one that may sit on another volume. Every volume
/// resource key asked of it then answers about *that* volume, which for the
/// ejectable and removable keys means two `false` answers about somewhere else
/// becoming a definitive denial here. A path carrying an interior NUL is no
/// path the kernel handed out, and is refused rather than silently truncated.
///
/// `None` means the path could not be represented, and every caller reads that
/// as "not asked" rather than as an answer.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn with_file_url<R>(path: &Path, ask: impl FnOnce(&objc2_foundation::NSURL) -> R) -> Option<R> {
  use std::ffi::CString;

  use objc2_foundation::NSURL;

  let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
  let url = unsafe {
    // SAFETY: `c_path` is a NUL-terminated buffer that outlives this call, and
    // Foundation copies the bytes it is given rather than keeping the pointer.
    NSURL::fileURLWithFileSystemRepresentation_isDirectory_relativeToURL(
      core::ptr::NonNull::new(c_path.as_ptr().cast_mut())?,
      path.is_dir(),
      None,
    )
  };
  Some(ask(&url))
}

/// What the two volume keys together say, including when they say nothing.
///
/// Either key answering yes is a yes. A no needs **both** keys to have
/// answered: a volume that said it is not ejectable and never said whether it
/// is removable has not said it is fixed, and reporting
/// [`NotEjectable`](super::Ejectability::NotEjectable) on half an answer is
/// deriving a negative from a silence. Only a pair of noes is a no.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const fn ejectability_of(ejectable: Option<bool>, removable: Option<bool>) -> Ejectability {
  match (ejectable, removable) {
    (Some(true), _) | (_, Some(true)) => Ejectability::Ejectable,
    (Some(false), Some(false)) => Ejectability::NotEjectable,
    _ => Ejectability::Unknown,
  }
}

/// Apple platforms: the volume's published label, read through the same NSURL
/// resource road the ejectable flags take.
///
/// `path` is any path on the volume rather than its mount point: a volume
/// resource key answers for the volume the path lives on, so the caller passes
/// the path it was asked about and gets the label of the volume that path is
/// really on. It reaches Foundation as the bytes the filesystem holds, so a
/// path no `&str` can spell still asks about the volume it is really on.
///
/// `NSURLVolumeNameKey` is the name the volume carries — what `diskutil info`
/// prints as "Volume Name" — and `NSURLVolumeLocalizedNameKey` is what the
/// Finder displays for it, which differs only where the system localizes a name
/// it owns. The first is asked for, the second answers where the first is
/// missing, and `None` means the volume published neither (a synthetic mount);
/// the caller's fallback then names it from its mount point.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(super) fn volume_name(path: &Path) -> Option<NameReading> {
  // Built from the filesystem bytes of the path rather than from a lossy
  // `&str`: see [`with_file_url`].
  with_file_url(path, volume_name_of)?
}

/// The label an NSURL already names, for a caller holding one — the enumeration
/// in [`list`](self::list), which asked for both keys up front.
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
/// `None` when the filesystem has no UUID to report: `getattrlist` fails
/// outright on the pseudo-filesystems (`devfs`, `autofs`), and a filesystem that
/// answers but omits the attribute reports a short length rather than an error.
/// An all-zero UUID is the "no UUID" sentinel and is also reported as `None`.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_identity(path: &Path) -> Option<IdentityReading> {
  let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
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
fn volume_identity_at(target: AttrTarget<'_>) -> Option<IdentityReading> {
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
  // `length` counts the bytes the kernel wrote, including itself; anything
  // shorter than the full buffer means the UUID was not among them.
  if rc != 0 || (buf.length as usize) < core::mem::size_of::<UuidBuf>() {
    return None;
  }
  // An all-zero UUID records the absence of one; `fs_uuid` applies the same
  // rule every other backend uses.
  super::fs_uuid(buf.uuid).map(IdentityReading::vouched)
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
    let reading = volume_identity(Path::new("/")).expect("the root volume reports a UUID");
    let super::super::VolumeIdentity::FsUuid(uuid) = reading.identity() else {
      panic!("Apple volumes report a UUID, got {reading:?}");
    };
    assert_ne!(uuid, [0u8; 16]);
  }

  /// The kernel read it off the volume the path is on, on this call. Apple has
  /// no published-name road and never takes one, so the level is fixed here.
  #[test]
  fn test_the_apple_reading_is_vouched() {
    let reading = volume_identity(Path::new("/")).expect("the root volume reports a UUID");
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
      volume_identity(Path::new("/")),
      volume_identity(Path::new("/"))
    );
  }

  #[test]
  fn test_volume_identity_pseudo_filesystem_is_none() {
    // devfs has no UUID; getattrlist fails and we must report that honestly
    // rather than invent a value.
    assert_eq!(volume_identity(Path::new("/dev")), None);
  }

  /// Nothing about a mount is remembered between resolves.
  ///
  /// There used to be a thread-local entry keyed by `st_dev` holding the mount
  /// point, the mount source and the capabilities. That key is not a witness —
  /// a device number is handed to another mount once the first goes away, and
  /// on Apple every volume of one APFS container shares one — so a hit could
  /// serve another volume's mount point, which the ejectability was then asked
  /// of. The law is that every field of a resolve is what the kernel reports
  /// for that path at that moment, with no store in between that could answer
  /// for another volume.
  #[test]
  fn test_the_resolve_reads_the_mount_rather_than_remembering_it() {
    let truth = volume_identity(Path::new("/")).expect("the root volume reports a UUID");
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

  /// A reading made by pathname is kept only when the pathname led to the
  /// pinned mount on **both** sides of it.
  ///
  /// This is the whole of the discard rule, and it is a pure function so that
  /// it can be stated without a racing mount to produce.
  #[test]
  fn test_a_pathname_reading_is_discarded_unless_the_mount_stood_still() {
    let here = |mp: &[u8], dev: &[u8]| MountWitness {
      mount_point: SmallBytes::from_bytes(mp),
      device: SmallBytes::from_bytes(dev),
    };
    let pinned = here(b"/Volumes/USB", b"/dev/disk4s1");

    assert_eq!(
      kept_on_the_same_mount(
        &pinned,
        Some(here(b"/Volumes/USB", b"/dev/disk4s1")),
        Some(here(b"/Volumes/USB", b"/dev/disk4s1")),
        "kept"
      ),
      Some("kept")
    );

    // Something else was mounted there before the reads, or arrived during
    // them, or the mount was replaced by another volume at the same point.
    for (before, after) in [
      (
        Some(here(b"/Volumes/OTHER", b"/dev/disk4s1")),
        Some(here(b"/Volumes/USB", b"/dev/disk4s1")),
      ),
      (
        Some(here(b"/Volumes/USB", b"/dev/disk4s1")),
        Some(here(b"/Volumes/OTHER", b"/dev/disk4s1")),
      ),
      (
        Some(here(b"/Volumes/USB", b"/dev/disk9s1")),
        Some(here(b"/Volumes/USB", b"/dev/disk9s1")),
      ),
      (
        Some(here(b"/Volumes/USB", b"/dev/disk4s1")),
        Some(here(b"/Volumes/USB", b"/dev/disk9s1")),
      ),
      // A `statfs` that could not be made is not evidence that nothing moved.
      (None, Some(here(b"/Volumes/USB", b"/dev/disk4s1"))),
      (Some(here(b"/Volumes/USB", b"/dev/disk4s1")), None),
      (None, None),
    ] {
      assert_eq!(kept_on_the_same_mount(&pinned, before, after, "kept"), None);
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
      volume_identity_at(AttrTarget::Fd(fd)),
      volume_identity(root),
      "one volume, one identity, whichever face asked"
    );

    let fs = rustix::fs::fstatfs(&pinned).expect("the root mount answers fstatfs");
    let fs_type = c_chars_as_bytes(&fs.f_fstypename);
    assert_eq!(
      volume_capabilities_at(AttrTarget::Fd(fd), fs_type).case_sensitive(),
      volume_capabilities(root, fs_type).case_sensitive()
    );

    // And the descriptor really does describe the same mount the pathname
    // does, which is what the bracket compares.
    let by_path = statfs(root).expect("the root mount answers statfs");
    assert!(mount_witness(&fs) == mount_witness(&by_path));
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
