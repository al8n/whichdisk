//! Apple platforms and FreeBSD, OpenBSD and DragonFly: every value in a row
//! comes from one observation of one mount.
//!
//! **On Apple platforms an observation is formed once, from one native
//! identity, and a row is built from nothing else.** The identity is a path's
//! own filesystem bytes — `realpath`'s answer for a resolve, the mount point
//! the kernel wrote into its mount table for a listing, copied once into owned
//! storage — and those same bytes are what is pinned, and what a listing row's
//! guard compares. The observation is the pinned descriptor and its own
//! `fstatfs`, or, for a path this process may reach but not open, the path's
//! one `statfs` and nothing more; the row is built by
//! [`Observation::into_row`], whose only input is the observation itself, and
//! pinning a path is private to [`observed`], so no row road can do it. Path
//! text and `st_dev` identify nothing: where a firmlink spells the path
//! differently from its mount point, the split is asked of the pinned
//! descriptor itself.
//!
//! **Every platform read on Apple platforms answers one of four outcomes** — a
//! value, the platform's own "there is none", a decline [`declined`] names, or
//! a failure — and no two are merged except where a caller names what each
//! means: see [`Reading`].
//!
//! **Every listing reads the kernel's mount table as a census, into a buffer
//! this crate owns** — `getfsstat(2)`, read by [`Census::copied`] with slots to
//! spare, and taken only from an answer that left one empty. Nothing is
//! borrowed from storage the C library keeps for the process: see
//! [`mount_table`].
//!
//! **On FreeBSD, OpenBSD and DragonFly one `statfs` is the whole resolve**, and
//! each listing row is one entry of that census; those platforms name no
//! decline, so every failed read there is the operation's error.

#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
use std::ffi::CString;
use std::{
  ffi::OsStr,
  os::unix::ffi::OsStrExt,
  path::{Path, PathBuf},
};

// A pathname `statfs` is the whole resolve on the other BSDs; on Apple only
// the observation takes one, and the laws that check it.
#[cfg(any(
  test,
  not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))
))]
use rustix::fs::statfs;

use super::{Ejectability, IdentityReading, NameReading, SmallBytes, VolumeCapabilities};

#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
use super::reading::Reading;

#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
use observed::Observation;

#[cfg(feature = "list")]
use super::reading::Census;

// `getfsstat(2)`: `libc` declares it everywhere but DragonFly, where it is
// declared here with the signature DragonFly's `<sys/mount.h>` gives it.
#[cfg(all(feature = "list", not(target_os = "dragonfly")))]
use libc as sys;

#[cfg(all(feature = "list", target_os = "dragonfly"))]
mod sys {
  unsafe extern "C" {
    /// `int getfsstat(struct statfs *, long, int)`.
    pub(super) fn getfsstat(
      buf: *mut libc::statfs,
      bufsize: core::ffi::c_long,
      flags: core::ffi::c_int,
    ) -> core::ffi::c_int;
  }
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
/// rest. The row is built by [`Observation::into_row`], the one constructor a
/// listing row is built by too. See [`Observation::of`] for a path that cannot
/// be opened, and [`Observation::ejectability`] for the removal answer.
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

  // Apple: one observation of the mount — the pinned descriptor and its own
  // `fstatfs`, or, for a path that may be reached but not opened, its one
  // pathname `statfs` — and the row built out of it and out of nothing else.
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  let (mount, relative_offset) = {
    // The native bytes `realpath` answered, which are what is pinned.
    let native = CString::new(canonical.as_os_str().as_bytes()).map_err(|_| {
      std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "a canonical path carries a NUL byte",
      )
    })?;
    let observed = Observation::of(native).required()?;
    let relative_offset = observed.relative_offset()?;
    (observed.into_row()?, relative_offset)
  };

  // Elsewhere: one `statfs`, which is every call there is. The device name the
  // ejectability reads is the one `f_mntfromname` that call already returned,
  // and the identity and the label are `None` by design.
  #[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  )))]
  let (mount, relative_offset) = {
    let fs = statfs(&canonical).map_err(std::io::Error::from)?;
    let mount_point = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntonname));
    let relative_offset = relative_offset(
      canonical.as_os_str().as_bytes(),
      mount_point.as_bytes(),
      || Ok(false),
    )?;
    #[cfg(feature = "disk-usage")]
    #[allow(clippy::unnecessary_cast)]
    let (total_bytes, available_bytes) = {
      let bsize = fs.f_bsize as u64;
      (
        (fs.f_blocks as u64).saturating_mul(bsize),
        (fs.f_bavail as u64).saturating_mul(bsize),
      )
    };
    let mount = super::MountPoint {
      mount_point,
      device: SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntfromname)),
      ejectability: ejectability_from_name(c_chars_as_bytes(&fs.f_mntfromname)),
      capabilities: volume_capabilities(&canonical, c_chars_as_bytes(&fs.f_fstypename)),
      volume_identity: volume_identity(&canonical),
      volume_name: volume_name(&canonical),
      #[cfg(feature = "disk-usage")]
      total_bytes,
      #[cfg(feature = "disk-usage")]
      available_bytes,
    };
    (mount, relative_offset)
  };

  Ok(Inner {
    mount,
    canonical,
    relative_offset,
  })
}

/// Where the caller's own path begins beneath its mount point, as a byte
/// offset into the canonical path.
///
/// The mount point is normally a prefix of the canonical path. On Apple
/// platforms it need not be: a firmlink joins the sealed system volume's
/// namespace to the data volume's, so `canonicalize()` returns `/Users/...`
/// while the mount is `/System/Volumes/Data`. There the relative part is the
/// canonical path without its leading `/` — where `firmlinked` confirms it,
/// which on Apple is the pinned descriptor's own word, see
/// [`spells_the_firmlink`] — and otherwise it is empty.
fn relative_offset(
  canonical: &[u8],
  mount_point: &[u8],
  firmlinked: impl FnOnce() -> std::io::Result<bool>,
) -> std::io::Result<usize> {
  if canonical.starts_with(mount_point) {
    let off = mount_point.len();
    return Ok(if off < canonical.len() && canonical[off] == b'/' {
      off + 1
    } else {
      off
    });
  }
  // `canonicalize()` returns an absolute path, so the part beneath the root
  // starts at byte 1.
  Ok(if firmlinked()? { 1 } else { canonical.len() })
}

/// Whether `unfirmlinked` — where the pinned object sits on its own volume,
/// spelled without firmlinks — is `mount_point` followed by `path` without its
/// leading `/`: the shape a firmlink gives, and the only one in which `path`
/// splits beneath a mount point it does not begin with.
///
/// The object's own path comes from its descriptor
/// (`fcntl(F_GETPATH_NOFIRMLINK)`), so the split is held to the object the
/// row was read through rather than to anything a pathname could lead to.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn spells_the_firmlink(path: &[u8], mount_point: &[u8], unfirmlinked: &[u8]) -> bool {
  let (Some(beneath), Some(rest)) = (
    path.strip_prefix(b"/"),
    unfirmlinked.strip_prefix(mount_point),
  ) else {
    return false;
  };
  !beneath.is_empty() && rest.strip_prefix(b"/") == Some(beneath)
}

/// Apple platforms: every mount in the kernel's mount table that says of
/// itself that it is local and browsable, each described by one observation of
/// its own mount root.
///
/// **A row is one observation, exactly as a resolve's is.** The census names
/// each mount by the mount point the kernel wrote into it; those bytes are
/// then pinned, and the whole row is built by [`Observation::into_row`] out of
/// the pinned descriptor and its own `fstatfs` — the mount point, the source,
/// the filesystem type, the capacity and the removal answer — and, through
/// `fgetattrlist`, the capabilities, the identity and the label. The row is
/// reported only where that observation is of the mount the census named — its
/// mount point is the census entry's, byte for byte, so a volume that left and
/// uncovered the directory beneath is not reported in its place — and where
/// the mount says of itself, off its own descriptor, that it is local and
/// browsable.
///
/// The census entry's own flags are asked the same two things first, and only
/// so that a mount the kernel calls remote or hidden is never opened — pinning
/// a mount root is I/O, and on a network volume it can wait on a server. They
/// decide whether a mount is looked at, never what its row says.
///
/// The removal answer is the kernel's `MNT_REMOVABLE` on the pinned mount,
/// which can say yes and nothing else, so a listing never answers
/// `NotEjectable` here, any more than a resolve does.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(super) fn list(opts: super::ListOptions) -> std::io::Result<Vec<super::MountPoint>> {
  use super::reading::Reading;

  let mut mounts = Vec::new();
  for entry in mount_table()? {
    if !is_local_and_browsable(entry.f_flags) {
      continue;
    }
    // The mount point's own bytes, as the kernel wrote them into the census,
    // copied once: what is pinned and what the guard below compares.
    let native = native_bytes(&entry.f_mntonname)?;
    let observed = match Observation::of(native) {
      Reading::Value(observed) => observed,
      // The mount went away between the census and the pin, or cannot be
      // reached at all: there is no row here to describe.
      Reading::Absent | Reading::Declined(_) => continue,
      Reading::Failed(err) => return Err(err),
    };
    // The row is the mount the census named, or nothing: a volume that has
    // left leaves its mount point leading to the mount beneath, which is
    // another volume with a row of its own.
    if !observed.is_mounted_at_its_native_path() {
      continue;
    }
    // And that mount says of itself what its census entry said of it.
    if !observed.is_listed() {
      continue;
    }
    // Exact states: a volume of unknown ejectability is named by neither
    // only-filter, so it is excluded by either. See `ListOptions::excludes`.
    if opts.excludes(observed.ejectability()) {
      continue;
    }
    mounts.push(observed.into_row()?);
  }
  Ok(mounts)
}

/// Whether a mount's flags say it is stored locally (`MNT_LOCAL`) and meant to
/// be browsed (`MNT_DONTBROWSE` clear): what a listing reports a mount by.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const fn is_local_and_browsable(flags: u32) -> bool {
  flags & libc::MNT_LOCAL as u32 != 0 && flags & libc::MNT_DONTBROWSE as u32 == 0
}

/// A mount point as the kernel wrote it into a census entry: its bytes up to
/// the terminating NUL, copied once into owned storage.
///
/// An entry whose mount point carries no terminator within the array is not
/// one the kernel wrote, and fails the listing rather than being read as a
/// shorter name or passed over.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn native_bytes(chars: &[core::ffi::c_char]) -> std::io::Result<CString> {
  std::ffi::CStr::from_bytes_until_nul(c_chars(chars))
    .map(std::ffi::CStr::to_owned)
    .map_err(|_| {
      std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "a mount table entry whose mount point is not terminated",
      )
    })
}

/// Every mount the kernel's mount table holds, read with `getfsstat(2)` into a
/// buffer this crate owns: a census, complete or refused — see
/// [`Census::copied`].
///
/// **Nothing here borrows storage the platform owns.** `getmntinfo(3)`, which
/// the FreeBSD, OpenBSD and DragonFly listing used to call, answers with a
/// pointer into one buffer the C library keeps for the whole process and
/// reallocates on the next call from anywhere in it. A lock of this crate's
/// serialised this crate's own callers and nobody else's: another library, or
/// the application itself, calling `getmntinfo` while the entries were being
/// copied out could free the buffer under the copy. `getfsstat` writes into
/// the buffer it is handed, and every buffer here is allocated for the one
/// call that fills it.
///
/// `MNT_NOWAIT`: the statistics the kernel keeps for each mount, without
/// asking every filesystem to refresh them — which on a network filesystem can
/// wait on a server. The census has no absence to report: every failure of it
/// is the listing's error.
#[cfg(feature = "list")]
fn mount_table() -> std::io::Result<Census<libc::statfs>> {
  // A null buffer asks only how many mounts there are, which sizes the first
  // buffer offered and decides nothing else.
  let hint = getfsstat(None)?;
  // SAFETY: `libc::statfs` is a C structure of integers and arrays of them,
  // for which all-zero bytes are a valid value.
  let empty: libc::statfs = unsafe { core::mem::zeroed() };
  Census::copied(empty, hint, |slots| getfsstat(Some(slots)), |_| false).required()
}

/// One `getfsstat(2)`: how many entries it wrote into `slots`, or, with none,
/// how many mounts there are. The error it failed with otherwise.
#[cfg(feature = "list")]
fn getfsstat(slots: Option<&mut [libc::statfs]>) -> std::io::Result<usize> {
  /// `MNT_NOWAIT`, the same value on every one of these platforms.
  const MNT_NOWAIT: core::ffi::c_int = 2;

  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  type BufferSize = core::ffi::c_int;
  #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
  type BufferSize = core::ffi::c_long;
  #[cfg(target_os = "openbsd")]
  type BufferSize = libc::size_t;

  let (buffer, bytes) = match slots {
    Some(slots) => (slots.as_mut_ptr(), core::mem::size_of_val(slots)),
    None => (core::ptr::null_mut(), 0),
  };
  let size = BufferSize::try_from(bytes).map_err(|_| {
    std::io::Error::other("a mount table buffer larger than getfsstat can be told of")
  })?;
  // SAFETY: with a null buffer and a size of zero the call only counts, and
  // writes nothing; otherwise `buffer` is the start of `slots`, which is live
  // and exactly `size` bytes long for the call, and the kernel writes whole
  // entries, and no more bytes than it is told there are.
  let written = unsafe { sys::getfsstat(buffer, size, MNT_NOWAIT) };
  // The errno is read before anything else can overwrite it.
  usize::try_from(written).map_err(|_| std::io::Error::last_os_error())
}

/// One observation of one mount on Apple platforms, and the only place a
/// row's object is pinned or described by pathname.
///
/// **An observation is formed once, from one native identity, and a row is
/// built from nothing else.** The identity is a path's own filesystem bytes,
/// held in the observation: what `realpath` answered for a resolve, and the
/// mount point the kernel wrote into its mount table for a listing. Those
/// bytes are what is pinned, and a listing row's guard compares the pinned
/// mount's own `f_mntonname` against exactly them. The row is then built by
/// [`Observation::into_row`], which takes the observation by value and nothing
/// else, and reads every value through it; nothing outside this module can pin
/// a path, so no row road can combine a second resolution with the first.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
mod observed {
  use std::ffi::{CStr, CString};

  use rustix::fd::{AsFd as _, AsRawFd as _, OwnedFd};

  #[cfg(feature = "list")]
  use super::is_local_and_browsable;
  use super::{
    super::{Ejectability, MountPoint, SmallBytes, VolumeCapabilities},
    AttrTarget, Reading, c_chars_as_bytes, ejectability_from_flags, reading, relative_offset,
    spells_the_firmlink, volume_capabilities_at, volume_identity_at, volume_name_at,
  };

  /// One observation of one mount, which is everything an Apple row is built
  /// from.
  pub(super) struct Observation {
    /// The native filesystem bytes this observation was formed from.
    native: CString,
    /// The descriptor every descriptor-addressable value is read through, or
    /// `None` for a path this process may reach but not open.
    pinned: Option<OwnedFd>,
    /// The descriptor's own `fstatfs`, or, with no descriptor, the path's one
    /// `statfs`.
    fs: rustix::fs::StatFs,
  }

  impl Observation {
    /// Pins the object `native` names and forms the one observation every
    /// value of its row comes from.
    ///
    /// Two observations:
    ///
    /// 1. **The object opens.** Its `fstatfs` is the observation, and the
    ///    descriptor binds every descriptor-addressable read to it.
    /// 2. **The object cannot be opened for want of permission** — `EACCES` or
    ///    `EPERM`, and nothing else. A `statfs` by pathname needs only search
    ///    permission on the directories above an object, so this crate has
    ///    always answered for paths a caller can reach but not open; a
    ///    root-owned event store on the Apple data volume is one. That one
    ///    `statfs` is then the whole row: the mount point, the source, the
    ///    filesystem type and the capacity, all out of a single call, and
    ///    nothing else is asked — no identity, no label, nothing established
    ///    about removal, and the capabilities the row's own filesystem type
    ///    implies.
    ///
    /// **No other descriptor stands in for the object's.** Opening the mount
    /// root that `statfs` named, and reading the rest of the row off it, would
    /// need a witness that the root and the path are on one *live* mount, and
    /// none is to be had. A mount point and a mount source are names, reusable
    /// both. A volume UUID names a volume rather than a mount: a clone carries
    /// its original's, and a FAT or exFAT UUID is derived from a 32-bit
    /// serial, so two volumes can carry one — and the one mounted there by the
    /// time the root is opened would answer under the other's name. The
    /// mount-session handles do not close the gap either. `st_dev`,
    /// `ATTR_CMN_DEVID` and `ATTR_CMN_FSID` are shared by the sealed system
    /// volume and its data volume, two live mounts; `f_fsid` tells those two
    /// apart, but it is a private field of `libc`'s `fsid_t`, and the platform
    /// documents it as nothing more than "file system id". A held descriptor
    /// does keep its own mount mounted — `unmount(2)` answers `EBUSY` while a
    /// reference is held, and a forced unmount turns every later access
    /// through it into an error — but pinning one mount does not make an
    /// identifier that two mounts share name only one of them.
    ///
    /// **Every other outcome is the open's own.** A path that went away is a
    /// decline, which a resolve reports as its error and a listing as a volume
    /// that is no longer there; descriptor exhaustion and an I/O error are
    /// failures, which both return as the errors they are. None of them is a
    /// fact about permission, and none is a reason to describe the path some
    /// other way.
    pub(super) fn of(native: CString) -> Reading<Self> {
      match reading(pin(&native)) {
        Reading::Value(pinned) => reading(rustix::fs::fstatfs(&pinned)).map(|fs| Self {
          native,
          pinned: Some(pinned),
          fs,
        }),
        // The one observation of a path that may be reached but not opened
        // is the row, and it is asked nothing more: see above.
        Reading::Declined(err) if is_permission_denied(&err) => {
          reading(rustix::fs::statfs(native.as_c_str())).map(|fs| Self {
            native,
            pinned: None,
            fs,
          })
        }
        Reading::Absent => Reading::Absent,
        Reading::Declined(err) => Reading::Declined(err),
        Reading::Failed(err) => Reading::Failed(err),
      }
    }

    /// The mount point this observation reports.
    pub(super) fn mount_point(&self) -> &[u8] {
      c_chars_as_bytes(&self.fs.f_mntonname)
    }

    /// Whether the mount this observation pinned is mounted at exactly the
    /// bytes it was pinned from: a listing row's guard. A volume that has
    /// left leaves its mount point leading to the mount beneath, which is
    /// another volume, with a row of its own.
    #[cfg(feature = "list")]
    pub(super) fn is_mounted_at_its_native_path(&self) -> bool {
      self.mount_point() == self.native.to_bytes()
    }

    /// What this observation says about removal: the kernel's own
    /// `MNT_REMOVABLE`, off the very `fstatfs` the rest of the row comes from,
    /// where a descriptor holds the mount it describes; nothing without one.
    /// See [`ejectability_from_flags`].
    pub(super) fn ejectability(&self) -> Ejectability {
      match self.pinned {
        Some(_) => ejectability_from_flags(self.fs.f_flags),
        None => Ejectability::Unknown,
      }
    }

    /// Whether the mount says of itself, off its own `fstatfs`, what a listing
    /// reports a mount by: that it is stored locally and meant to be browsed.
    /// See [`is_local_and_browsable`].
    #[cfg(feature = "list")]
    pub(super) fn is_listed(&self) -> bool {
      is_local_and_browsable(self.fs.f_flags)
    }

    /// Where the native path begins beneath this observation's mount point,
    /// as a byte offset into it: see [`relative_offset`].
    ///
    /// Where the path does not begin with the mount point's spelling — a
    /// firmlink — the split is asked of the pinned descriptor: where its object
    /// sits on its own volume, spelled without firmlinks, must be the mount
    /// point followed by the rest of the path. What it decides is only where
    /// the caller's own path splits, never a value read about a volume, and a
    /// path with no descriptor is not split at all: nothing binds another
    /// spelling of it to the object the row describes. A lookup the platform
    /// declined is no split; one that failed is the error it is.
    pub(super) fn relative_offset(&self) -> std::io::Result<usize> {
      let path = self.native.to_bytes();
      relative_offset(path, self.mount_point(), || {
        let Some(pinned) = &self.pinned else {
          return Ok(false);
        };
        Ok(match path_without_firmlinks(pinned).answered()? {
          Some(unfirmlinked) => spells_the_firmlink(path, self.mount_point(), &unfirmlinked),
          None => false,
        })
      })
    }

    /// The row, and every value in it out of this one observation, which it
    /// takes by value and is given nothing beside: the mount point, the
    /// source, the filesystem type, the capacity and the removal answer out of
    /// the `fstatfs`, and the capabilities, the identity and the label through
    /// the observation's own descriptor with `fgetattrlist`. With no descriptor
    /// the row is the one `statfs` and nothing more: no identity, no label,
    /// nothing established about removal, and the capabilities its own
    /// filesystem type implies. See [`Observation::of`].
    pub(super) fn into_row(self) -> std::io::Result<MountPoint> {
      let fs_type = c_chars_as_bytes(&self.fs.f_fstypename);
      let (capabilities, volume_identity, volume_name) = match &self.pinned {
        Some(pinned) => (
          volume_capabilities_at(AttrTarget::Fd(pinned.as_fd()), fs_type)?,
          volume_identity_at(AttrTarget::Fd(pinned.as_fd()))?,
          volume_name_at(AttrTarget::Fd(pinned.as_fd()))?,
        ),
        None => (VolumeCapabilities::from_fs_type(fs_type), None, None),
      };
      #[cfg(feature = "disk-usage")]
      #[allow(clippy::unnecessary_cast)]
      let (total_bytes, available_bytes) = {
        let bsize = self.fs.f_bsize as u64;
        (
          (self.fs.f_blocks as u64).saturating_mul(bsize),
          (self.fs.f_bavail as u64).saturating_mul(bsize),
        )
      };
      Ok(MountPoint {
        mount_point: SmallBytes::from_bytes(self.mount_point()),
        device: SmallBytes::from_bytes(c_chars_as_bytes(&self.fs.f_mntfromname)),
        ejectability: self.ejectability(),
        capabilities,
        volume_identity,
        volume_name,
        #[cfg(feature = "disk-usage")]
        total_bytes,
        #[cfg(feature = "disk-usage")]
        available_bytes,
      })
    }

    /// Whether a descriptor holds this observation's object.
    #[cfg(test)]
    pub(super) fn is_pinned(&self) -> bool {
      self.pinned.is_some()
    }
  }

  /// A descriptor on the object a row describes, held while the row is read.
  ///
  /// Opened `O_EVTONLY` — Apple's permission-minimal open, the one file-event
  /// clients use — so a path the caller may traverse but has no right to
  /// *read* still resolves, exactly as the pathname road did. `O_RDONLY`
  /// stands in where that flag is refused. The file itself is never read: the
  /// descriptor exists so that `fstatfs` and `fgetattrlist` ask about one
  /// object instead of re-resolving a name five times.
  fn pin(path: &CStr) -> std::io::Result<OwnedFd> {
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
      // went away, a full descriptor table or an I/O error would fail the
      // second open the same way, and trying it would only replace the error
      // that says so with one that may not.
      Err(Errno::ACCESS | Errno::PERM | Errno::INVAL | Errno::NOTSUP | Errno::OPNOTSUPP) => {
        rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
          .map_err(std::io::Error::from)
      }
      Err(errno) => Err(errno.into()),
    }
  }

  /// Where the pinned object sits on its own volume, spelled without
  /// firmlinks: `fcntl(F_GETPATH_NOFIRMLINK)`, which answers about the object
  /// the descriptor holds rather than about anything a name leads to.
  /// A platform without the command declines it (`EINVAL`).
  fn path_without_firmlinks(pinned: &OwnedFd) -> Reading<Vec<u8>> {
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    // SAFETY: the command writes a NUL-terminated path of at most `MAXPATHLEN`
    // bytes, which is `PATH_MAX`, into the buffer it is given; this one is
    // that long and live for the call, and the descriptor is valid for as long
    // as `pinned` is.
    let rc = unsafe {
      libc::fcntl(
        pinned.as_raw_fd(),
        libc::F_GETPATH_NOFIRMLINK,
        buffer.as_mut_ptr(),
      )
    };
    reading(if rc == -1 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(())
    })
    .and_then(|()| match super::super::find_byte(0, &buffer) {
      Some(len) => Reading::Value(buffer[..len].to_vec()),
      None => Reading::Absent,
    })
  }

  /// Whether an open failed because this process may not open that object, as
  /// opposed to failing for any of the reasons that are not a fact about
  /// permission — a descriptor table that is full, an I/O error, a path that
  /// went away.
  fn is_permission_denied(err: &std::io::Error) -> bool {
    // `EACCES` and `EPERM` both arrive as this kind, and they are the only two
    // failures that say "you may not open this", which is the only failure the
    // descriptor-less road answers.
    err.kind() == std::io::ErrorKind::PermissionDenied
  }

  /// The pin a row would take, for the laws that ask a descriptor directly.
  #[cfg(test)]
  pub(super) fn pin_for_laws(path: &std::path::Path) -> std::io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt as _;

    pin(&CString::new(path.as_os_str().as_bytes()).expect("a path carries no NUL"))
  }

  #[cfg(test)]
  mod tests {
    use super::*;

    /// An open that failed for want of permission has a road of its own;
    /// nothing else does.
    ///
    /// Descriptor exhaustion, a transient I/O error and a vanished path are
    /// not facts about permission, and turning any of them into another road
    /// traded a correct refusal for a row assembled some other way.
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

    /// The pinned object's own unfirmlinked path is where it sits on its
    /// volume, beneath the mount point its `fstatfs` names.
    #[test]
    fn test_the_descriptor_names_where_its_object_sits() {
      let observation = Observation::of(CString::new("/Users").unwrap())
        .required()
        .unwrap();
      if observation.mount_point() != b"/System/Volumes/Data" {
        // A system without the split system volume: nothing to prove here.
        return;
      }
      let pinned = observation.pinned.as_ref().expect("/Users opens");
      let Reading::Value(unfirmlinked) = path_without_firmlinks(pinned) else {
        panic!("a firmlinked object names its own path");
      };
      assert_eq!(unfirmlinked, b"/System/Volumes/Data/Users");
    }
  }
}

/// What a `getattrlist` is addressed to: the descriptor a row holds, or — for
/// the laws alone, which compare the two faces — a pathname.
///
/// One question, one body, two faces. The descriptor form is what makes an
/// Apple row one observation, and it is the only one product code asks.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
enum AttrTarget<'a> {
  Fd(rustix::fd::BorrowedFd<'a>),
  /// No row takes this face: a row is read through its own descriptor, and a
  /// path that cannot be opened is described by its one `statfs` and asked
  /// nothing more. See [`Observation::row`].
  #[cfg(test)]
  Path(&'a std::ffi::CStr),
}

/// A buffer the kernel may fill with any bytes at all.
///
/// # Safety
///
/// Implemented only for a `#[repr(C)]` type made of integers and arrays of
/// them, for which every bit pattern is a valid value, so that whatever the
/// kernel writes into it — or leaves as it was — is a value of the type.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
unsafe trait KernelFilled {}

/// One `getattrlist`, addressed to whichever face the caller has, into the
/// caller's own buffer, and sorted into a [`Reading`] with the errno it failed
/// with.
///
/// The buffer is borrowed whole and its size is its type's, so no caller can
/// hand over a pointer or a length that does not describe live memory; the
/// kernel writes no more than that size. Nothing in either object is read
/// here.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn getattrlist_at<B: KernelFilled>(
  target: AttrTarget<'_>,
  attrs: &mut libc::attrlist,
  buf: &mut B,
) -> Reading<()> {
  let attrs = core::ptr::from_mut(attrs).cast::<core::ffi::c_void>();
  let size = core::mem::size_of::<B>();
  let buf = core::ptr::from_mut(buf).cast::<core::ffi::c_void>();
  let rc = match target {
    // SAFETY: the descriptor is valid for as long as the borrow lives; `attrs`
    // and `buf` are exclusive borrows, live for the call, and `buf` is exactly
    // `size` bytes, which is all the kernel writes; `B: KernelFilled`, so
    // whatever bytes it writes are a valid `B`.
    AttrTarget::Fd(fd) => {
      use rustix::fd::AsRawFd as _;
      unsafe { libc::fgetattrlist(fd.as_raw_fd(), attrs, buf, size, 0) }
    }
    // SAFETY: the same, with a NUL-terminated pathname that outlives the call.
    #[cfg(test)]
    AttrTarget::Path(path) => unsafe { libc::getattrlist(path.as_ptr(), attrs, buf, size, 0) },
  };
  // The errno is taken before anything else can overwrite it.
  reading(if rc == 0 {
    Ok(())
  } else {
    Err(std::io::Error::last_os_error())
  })
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

/// Apple platforms: whether the kernel says a row's storage leaves the
/// machine, read off the one `fstatfs` the row is built on.
///
/// **A row asks the kernel, not Foundation.** Foundation's removal keys answer
/// by pathname or by URL and have no descriptor form, so an answer of theirs
/// would have to be tied back to the pinned mount by something it carried, and
/// nothing documents such a tie. The volume's UUID was tried and is not one: a
/// UUID names a volume, not a mount — a clone carries its original's, and a
/// FAT or exFAT UUID is derived from a 32-bit serial — so another volume
/// mounted there for the length of the lookup could answer under this one's
/// name. `MNT_REMOVABLE` needs no tie: the kernel keeps it on the mount itself,
/// and it arrives in the same `fstatfs` the mount point, the source and the
/// capacity come from. The keys were half an answer besides: for a USB disk
/// both of Foundation's removal keys say no, because the media never leaves
/// the drive.
///
/// **It can only say yes.** A flag the kernel left clear is not the kernel
/// saying the storage stays; it only did not say that it leaves. So this road
/// answers [`Ejectable`](super::Ejectability::Ejectable) or
/// [`Unknown`](super::Ejectability::Unknown), and never a denial: on these
/// platforms no road with a descriptor form answers the removal question
/// itself, so neither a resolve nor a listing ever answers
/// [`NotEjectable`](super::Ejectability::NotEjectable).
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

/// Whether a failed read is the platform declining to answer, rather than the
/// read itself failing.
///
/// Every platform read on this backend is sorted by this set into the four
/// outcomes of a [`Reading`] — see [`reading`] — and every road that reports a
/// value with no "could not tell" of its own — the identity, the label, the
/// case flags, a listing row — ends in its documented absence on these
/// failures, and on nothing else:
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

/// Sorts what a platform call on this backend returned by [`declined`], into
/// the four outcomes every read here answers: see [`Reading`].
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn reading<T, E: Into<std::io::Error>>(read: Result<T, E>) -> Reading<T> {
  Reading::sort(read.map_err(Into::into), declined)
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
/// point; a name that is not UTF-8 is kept as the bytes the volume wrote, so
/// it is never reported as no name. `Vouched`, because the volume answered for
/// itself, on this call.
///
/// A filesystem that carries no volume name answers `EINVAL`, and that is no
/// label too; a read that failed is returned as the error it is rather than as
/// a volume with no name — see [`declined`].
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
  // SAFETY: integers and an array of bytes; every bit pattern is valid.
  unsafe impl KernelFilled for NameBuf {}

  // SAFETY: `attrlist` and `NameBuf` are C structures of integers and arrays
  // of them, for which all-zero bytes are a valid value.
  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_NAME;

  // SAFETY: as above.
  let mut buf: NameBuf = unsafe { core::mem::zeroed() };
  let answer = getattrlist_at(target, &mut attrs, &mut buf);

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
    // Kept as the volume wrote it, text or not: a name that is not UTF-8 is a
    // name all the same. See `published_label_bytes`.
    super::published_label_bytes(name, super::IdentityAssurance::Vouched)
  };
  answer
    .and_then(|()| label().map_or(Reading::Absent, Reading::Value))
    .answered()
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

/// FreeBSD, OpenBSD, DragonFlyBSD: every mount in the kernel's mount table but
/// the virtual filesystems, each row one entry of one census.
///
/// The census is [`mount_table`]: `getfsstat(2)` into a buffer this crate owns,
/// taken only from an answer that left a slot empty, so a mount added between
/// sizing the buffer and filling it is read on the next ask rather than cut
/// off. Nothing is borrowed from the buffer `getmntinfo(3)` keeps for the whole
/// process, which this used to copy out of under a lock no other caller in the
/// process was bound by.
#[cfg(feature = "list")]
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
pub(super) fn list(opts: super::ListOptions) -> std::io::Result<Vec<super::MountPoint>> {
  let mut mounts = Vec::new();
  for entry in mount_table()? {
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
    #[allow(clippy::unnecessary_cast)]
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

/// The capabilities road asked by pathname, for the laws that compare the two
/// faces. No row asks a volume anything by pathname: see [`Observation::row`].
#[cfg(test)]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_capabilities(path: &Path, fs_type: &[u8]) -> std::io::Result<VolumeCapabilities> {
  let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
    return Ok(VolumeCapabilities::from_fs_type(fs_type));
  };
  volume_capabilities_at(AttrTarget::Path(&c_path), fs_type)
}

/// Apple platforms: the volume's case handling, via `getattrlist` with
/// `ATTR_VOL_CAPABILITIES`. `fs_type` is taken from the caller's `fstatfs`
/// (`f_fstypename`). A case flag is `None` where the volume does not report
/// its `VOL_CAP_FMT_CASE_SENSITIVE` / `VOL_CAP_FMT_CASE_PRESERVING` bit as
/// valid, and both are where the platform declined the question — see
/// [`declined`]; a read that failed is returned as the error it is, never as
/// a volume whose case handling nobody can know.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_capabilities_at(
  target: AttrTarget<'_>,
  fs_type: &[u8],
) -> std::io::Result<VolumeCapabilities> {
  // getattrlist writes a leading u32 length followed by the requested
  // attributes in bitmap order; for ATTR_VOL_CAPABILITIES that is a single
  // vol_capabilities_attr_t. #[repr(C)] guarantees the layout the kernel writes.
  #[repr(C)]
  struct CapabilitiesBuf {
    length: u32,
    caps: libc::vol_capabilities_attr_t,
  }
  // SAFETY: integers and arrays of them; every bit pattern is valid.
  unsafe impl KernelFilled for CapabilitiesBuf {}

  // SAFETY: `attrlist` and `CapabilitiesBuf` are C structures of integers and
  // arrays of them, for which all-zero bytes are a valid value.
  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES;

  // SAFETY: as above.
  let mut buf: CapabilitiesBuf = unsafe { core::mem::zeroed() };
  match getattrlist_at(target, &mut attrs, &mut buf) {
    Reading::Value(()) => {}
    Reading::Absent | Reading::Declined(_) => return Ok(VolumeCapabilities::from_fs_type(fs_type)),
    Reading::Failed(err) => return Err(err),
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

  Ok(VolumeCapabilities {
    case_sensitive,
    case_preserving,
    fs_type: SmallBytes::from_bytes(fs_type),
  })
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
/// A read that failed is returned as the error it is, never as a volume with
/// no identity — see [`declined`].
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
  // SAFETY: an integer and an array of bytes; every bit pattern is valid.
  unsafe impl KernelFilled for UuidBuf {}

  // SAFETY: `attrlist` and `UuidBuf` are C structures of integers and arrays
  // of them, for which all-zero bytes are a valid value.
  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID;

  // SAFETY: as above.
  let mut buf: UuidBuf = unsafe { core::mem::zeroed() };
  let answer = getattrlist_at(target, &mut attrs, &mut buf);
  answer
    .and_then(|()| {
      // `length` counts the bytes the kernel wrote, including itself; anything
      // shorter than the full buffer means the UUID was not among them.
      if (buf.length as usize) < core::mem::size_of::<UuidBuf>() {
        return Reading::Absent;
      }
      // An all-zero UUID records the absence of one; `fs_uuid` applies the
      // same rule every other backend uses.
      super::fs_uuid(buf.uuid).map_or(Reading::Absent, |uuid| {
        Reading::Value(IdentityReading::vouched(uuid))
      })
    })
    .answered()
}

/// The identity road asked by pathname, for the laws that compare the two
/// faces. No row asks a volume anything by pathname: see [`Observation::row`].
#[cfg(test)]
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

/// A C string the kernel wrote into a fixed array, up to its terminating NUL,
/// or the whole array where it carries none.
#[cfg_attr(not(tarpaulin), inline(always))]
fn c_chars_as_bytes(chars: &[core::ffi::c_char]) -> &[u8] {
  let bytes = c_chars(chars);
  let len = super::find_byte(0, bytes).unwrap_or(bytes.len());
  &bytes[..len]
}

/// A fixed `c_char` array as the bytes it holds, terminator and all.
#[cfg_attr(not(tarpaulin), inline(always))]
fn c_chars(chars: &[core::ffi::c_char]) -> &[u8] {
  // SAFETY: `c_char` and `u8` have the same size and alignment, every bit
  // pattern is valid for both, and the new slice borrows the same memory for
  // the same lifetime.
  unsafe { &*(core::ptr::from_ref::<[core::ffi::c_char]>(chars) as *const [u8]) }
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

  /// A path's own bytes, as an observation is formed from them.
  fn native(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("a path carries no NUL")
  }

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
    if observed::pin_for_laws(path).is_ok() || !path.exists() {
      // Running as root, or on a system without it: nothing to prove here.
      return;
    }

    let observation = Observation::of(native(path))
      .required()
      .expect("the mount is still describable");
    assert!(
      !observation.is_pinned(),
      "no descriptor stands in for the one the path refused"
    );
    let observed = statfs(path).expect("the path answers statfs");
    assert_eq!(
      observation.mount_point(),
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
    let pinned = observed::pin_for_laws(root).expect("the root directory opens");
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
      let Ok(pinned) = observed::pin_for_laws(&path) else {
        continue;
      };
      let flags = rustix::fs::fstatfs(&pinned).unwrap().f_flags;
      let answer = resolve(&path).unwrap().mount_info().ejectability();
      assert_eq!(answer, ejectability_from_flags(flags), "{path:?}");
      assert_ne!(answer, Ejectability::NotEjectable, "{path:?}");
    }
  }

  /// A listing row is one observation of its own mount root, exactly as a
  /// resolve's is: every value in it is what that pinned root answers, and its
  /// removal answer is the root's own flag — `Ejectable` or `Unknown`, never a
  /// denial.
  ///
  /// It used to take Foundation's keys from the enumerated URL and the mount
  /// metadata, the capabilities and the identity from three separate pathname
  /// lookups, so a volume replaced between any two of them left one row
  /// describing two mounts — and its three removal keys denied for an internal
  /// disk with nothing binding their answer to the mount a descriptor holds.
  #[cfg(feature = "list")]
  #[test]
  fn test_a_listing_row_is_its_own_mounts_observation() {
    use rustix::fd::AsFd as _;

    let rows = list(super::super::ListOptions::all()).unwrap();
    assert!(!rows.is_empty(), "the boot volume is always listed");
    for row in rows {
      // A root this process may not open is described by its one `statfs`,
      // which the fallback law covers.
      let Ok(pinned) = observed::pin_for_laws(row.mount_point()) else {
        continue;
      };
      let fs = rustix::fs::fstatfs(&pinned).unwrap();
      assert_eq!(
        row.mount_point().as_os_str().as_bytes(),
        c_chars_as_bytes(&fs.f_mntonname)
      );
      assert_eq!(row.device().as_bytes(), c_chars_as_bytes(&fs.f_mntfromname));
      assert_eq!(
        row.ejectability(),
        ejectability_from_flags(fs.f_flags),
        "{row:?}"
      );
      assert_ne!(row.ejectability(), Ejectability::NotEjectable, "{row:?}");
      let fd = pinned.as_fd();
      assert_eq!(
        row.volume_identity(),
        volume_identity_at(AttrTarget::Fd(fd)).unwrap(),
        "{row:?}"
      );
      assert_eq!(
        row.volume_name_assurance(),
        volume_name_at(AttrTarget::Fd(fd))
          .unwrap()
          .map(|reading| reading.assurance),
        "{row:?}"
      );
    }
  }

  /// The listing is the kernel's mount table read as a census into a buffer
  /// this crate owns, and every row is one of its entries: each mount the
  /// census calls local and browsable is listed, in the census's order, and
  /// nothing else is.
  #[cfg(feature = "list")]
  #[test]
  fn test_the_listing_is_the_local_browsable_entries_of_the_census() {
    let census: Vec<libc::statfs> = mount_table().unwrap().into_iter().collect();
    let mount_point = |entry: &libc::statfs| c_chars_as_bytes(&entry.f_mntonname).to_vec();
    assert!(
      census.iter().any(|entry| mount_point(entry) == b"/"),
      "the root is always mounted"
    );
    let expected: Vec<Vec<u8>> = census
      .iter()
      .filter(|entry| is_local_and_browsable(entry.f_flags))
      .map(mount_point)
      .collect();
    let listed: Vec<Vec<u8>> = list(super::super::ListOptions::all())
      .unwrap()
      .iter()
      .map(|row| row.mount_point().as_os_str().as_bytes().to_vec())
      .collect();
    assert_eq!(listed, expected);
  }

  /// A firmlinked path is split at the mount it is really on, and the split is
  /// the pinned descriptor's own word — where its object sits on its volume,
  /// spelled without firmlinks — not what a pathname happens to lead to, and
  /// not a device number, which the system volume and its data volume share.
  #[test]
  fn test_a_firmlinked_path_splits_at_the_object_it_names() {
    let users = Observation::of(native(Path::new("/Users")))
      .required()
      .unwrap();
    if users.mount_point() != b"/System/Volumes/Data" {
      // A system without the split system volume: nothing to prove here.
      return;
    }
    assert_eq!(users.relative_offset().unwrap(), 1);
    assert_eq!(
      resolve(Path::new("/Users")).unwrap().relative_path(),
      Path::new("Users")
    );

    let data = b"/System/Volumes/Data";
    assert!(spells_the_firmlink(
      b"/Users",
      data,
      b"/System/Volumes/Data/Users"
    ));
    // Another object beneath the same mount is not this one, and a mount
    // point that is only a prefix of a longer name is no mount point of it.
    assert!(!spells_the_firmlink(
      b"/Library",
      data,
      b"/System/Volumes/Data/Users"
    ));
    assert!(!spells_the_firmlink(
      b"/Users",
      data,
      b"/System/Volumes/DataUsers"
    ));
    assert!(!spells_the_firmlink(b"/", data, b"/System/Volumes/Data/"));
    assert!(!spells_the_firmlink(
      b"Users",
      data,
      b"/System/Volumes/Data/Users"
    ));
  }

  /// The descriptor road and the pathname road answer the same question, and
  /// this host is the platform they run on — so both are asked for real.
  #[test]
  fn test_the_descriptor_and_the_pathname_roads_agree() {
    let root = Path::new("/");
    let pinned = observed::pin_for_laws(root).expect("the root directory opens");
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
      volume_capabilities_at(AttrTarget::Fd(fd), fs_type)
        .unwrap()
        .case_sensitive(),
      volume_capabilities(root, fs_type).unwrap().case_sensitive()
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
