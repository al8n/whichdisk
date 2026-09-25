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
use super::{
  filled::{Filled, KernelBuffer, invalid},
  reading::Reading,
};

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
    let read = || statfs(&canonical).map_err(std::io::Error::from);
    let fs = if cfg!(target_os = "dragonfly") {
      settled(read, same_strings)?
    } else {
      read()?
    };
    let Fields {
      mount_point,
      source,
      fs_type,
    } = Fields::of(&fs)?;
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
      ejectability: ejectability_of_source(fs_type.as_bytes(), source.as_bytes()),
      device: source,
      capabilities: volume_capabilities(&canonical, fs_type.as_bytes()),
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
/// reported where the mount says of itself, off its own descriptor, that it is
/// local and browsable, and **where the pinned mount is exactly one census
/// entry** — see [`Observation::census_entry_among`].
///
/// **A mount point binds nothing; a mount's own witness does.** Two mounts can
/// sit at one path, the later over the earlier, and a pin of that path reaches
/// the one on top whichever census entry it was taken for. So each mount
/// point is pinned once, however many entries name it, and the row is the one
/// entry among them whose filesystem id, source, type and mount point are the
/// pinned mount's own: the mount on top, observed once. A covered mount is
/// reached by no path and is not reported, and neither is anything where no
/// entry — a volume that left, and another that took its place — or more than
/// one entry is the pinned mount.
///
/// The census entry's own flags are asked the same two things first, and only
/// so that a mount the kernel calls remote or hidden is never opened — pinning
/// a mount root is I/O, and on a network volume it can wait on a server. They
/// decide whether a mount is looked at, never what its row says.
///
/// The removal answer is the pinned mount's own `MNT_REMOVABLE`, and on macOS,
/// where that says nothing, DiskArbitration's answer bound to the pinned mount:
/// see [`Observation::ejectability`].
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

  // Every entry decoded whole before any is weighed: see [`Fields`].
  let entries = mount_table()?
    .into_iter()
    .map(|entry| Fields::of(&entry).map(|fields| (entry, fields)))
    .collect::<std::io::Result<Vec<_>>>()?;
  let browsable: Vec<&(libc::statfs, Fields)> = entries
    .iter()
    .filter(|(entry, _)| is_local_and_browsable(entry.f_flags))
    .collect();
  let mut mounts = Vec::new();
  for (at, (_, fields)) in browsable.iter().enumerate() {
    let mount_point = fields.mount_point.as_bytes();
    // A mount point is pinned once, however many entries name it: a pin of it
    // reaches one mount.
    if browsable[..at]
      .iter()
      .any(|(_, earlier)| earlier.mount_point.as_bytes() == mount_point)
    {
      continue;
    }
    // The mount point's own bytes, as the kernel wrote them into the census,
    // copied once: what is pinned.
    let native = CString::new(mount_point).map_err(|_| {
      std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "a mount point with a NUL inside it",
      )
    })?;
    let observed = match Observation::of(native) {
      Reading::Value(observed) => observed,
      // The mount went away between the census and the pin, or cannot be
      // reached at all: there is no row here to describe.
      Reading::Absent | Reading::Declined(_) => continue,
      Reading::Failed(err) => return Err(err),
    };
    // The row is the one census entry the pinned mount is, or nothing: see
    // [`Observation::census_entry_among`].
    let claimants: Vec<&libc::statfs> = browsable
      .iter()
      .filter(|(_, other)| other.mount_point.as_bytes() == mount_point)
      .map(|(entry, _)| entry)
      .collect();
    if observed.census_entry_among(&claimants).is_none() {
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

/// Whether two `statfs` answers are of one mount: the same filesystem id
/// (`f_fsid`), source, filesystem type and mount point.
///
/// **The filesystem id is the witness a path is not.** The kernel gives every
/// mount one when it is mounted, and two mounts do not share one — the sealed
/// system volume and its data volume, which share a device number, have
/// different ones — so a mount stacked over another at the same path, or one
/// that took a departed volume's path, differs from the entry it did not come
/// from. The source, the type and the mount point are compared beside it, so
/// that a census entry is taken for a pinned mount only where every name the
/// kernel gave both agrees too.
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn is_same_mount(a: &libc::statfs, b: &libc::statfs) -> bool {
  let same = |a: &[core::ffi::c_char], b: &[core::ffi::c_char]| matches!((c_string(a), c_string(b)), (Ok(a), Ok(b)) if a == b);
  fsid_bytes(a) == fsid_bytes(b)
    && same(&a.f_mntfromname, &b.f_mntfromname)
    && same(&a.f_fstypename, &b.f_fstypename)
    && same(&a.f_mntonname, &b.f_mntonname)
}

/// A mount's filesystem id, `f_fsid`, as its bytes. `libc` keeps the field's
/// two words private, so it is read as the eight bytes the kernel's `fsid_t`
/// is.
#[cfg(any(feature = "list", target_os = "macos"))]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn fsid_bytes(fs: &libc::statfs) -> [u8; FSID_LEN] {
  // SAFETY: `fsid_t` is the kernel's `struct fsid { int32_t val[2]; }`, which
  // `libc` declares `#[repr(C)]` over `[i32; 2]`: `FSID_LEN` bytes — held to
  // that below — with no padding, every one of them initialised in any
  // `statfs` value, and every bit pattern of them a valid byte array.
  unsafe { core::mem::transmute_copy::<libc::fsid_t, [u8; FSID_LEN]>(&fs.f_fsid) }
}

/// The device a disk filesystem was mounted from, as the kernel wrote it into
/// the mount's filesystem id: the first of `f_fsid`'s two words, which APFS
/// and HFS set to the device node's `st_rdev` (measured on this crate's own
/// host, and asserted by the root's law). A filesystem no device backs is
/// given a first word of the kernel's choosing, which names no disk.
#[cfg(target_os = "macos")]
fn fsid_device(fs: &libc::statfs) -> libc::dev_t {
  let bytes = fsid_bytes(fs);
  libc::dev_t::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// How long a `fsid_t` is: two 32-bit words.
#[cfg(any(feature = "list", target_os = "macos"))]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const FSID_LEN: usize = 8;

#[cfg(any(feature = "list", target_os = "macos"))]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const _: () = assert!(core::mem::size_of::<libc::fsid_t>() == FSID_LEN);

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
  use std::{
    cell::OnceCell,
    ffi::{CStr, CString},
  };

  use rustix::fd::{AsFd as _, AsRawFd as _, OwnedFd};

  use super::{
    super::{Ejectability, MountPoint, VolumeCapabilities, filled::SentinelBuffer},
    AttrTarget, Fields, Reading, ejectability_from_flags, reading, relative_offset,
    spells_the_firmlink, volume_capabilities_at, volume_identity_at, volume_name_at,
  };
  #[cfg(feature = "list")]
  use super::{is_local_and_browsable, is_same_mount};

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
    /// The mount point, the source and the filesystem type out of `fs`,
    /// decoded whole when the observation was formed: see [`Fields`].
    fields: Fields,
    /// The removal answer, asked the first time it is wanted — a listing's
    /// filter or the row — and kept for the other, so the platform is asked
    /// once: see [`Observation::ejectability`].
    removal: OnceCell<Ejectability>,
  }

  impl Observation {
    /// Pins the object `native` names and forms the one observation every
    /// value of its row comes from.
    ///
    /// Two observations:
    ///
    /// 1. **The object opens.** Its `fstatfs` is the observation, and the
    ///    descriptor binds every descriptor-addressable read to it.
    /// 2. **The object cannot be opened, for want of permission or by its
    ///    kind** — `EACCES` or `EPERM`, a socket (`EOPNOTSUPP`: no open answers
    ///    one) or a device node whose device is not there (`ENXIO`), and
    ///    nothing else. A `statfs` by pathname needs only search permission on
    ///    the directories above an object, so this crate has always answered
    ///    for paths a caller can reach but not open; a root-owned event store
    ///    on the Apple data volume is one, and a socket beside the caller's
    ///    files is another. That one `statfs` is then the whole row: the mount
    ///    point, the source, the filesystem type and the capacity, all out of a
    ///    single call, and nothing else is asked — no identity, no label,
    ///    nothing established about removal, and the capabilities the row's
    ///    own filesystem type implies. See [`answers_without_a_descriptor`].
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
    /// fact about the object and this process, and none is a reason to
    /// describe the path some other way.
    ///
    /// **Its strings are decoded whole as it is formed.** A mount point, a
    /// source or a filesystem type the kernel could not have written fails
    /// the observation with `InvalidData`: see [`Fields`].
    pub(super) fn of(native: CString) -> Reading<Self> {
      let (pinned, fs) = match reading(pin(&native)) {
        Reading::Value(pinned) => match reading(rustix::fs::fstatfs(&pinned)) {
          Reading::Value(fs) => (Some(pinned), fs),
          Reading::Absent => return Reading::Absent,
          Reading::Declined(err) => return Reading::Declined(err),
          Reading::Failed(err) => return Reading::Failed(err),
        },
        // The one observation of a path that may be reached but not opened
        // is the row, and it is asked nothing more: see above.
        Reading::Declined(err) if answers_without_a_descriptor(&err) => {
          match reading(rustix::fs::statfs(native.as_c_str())) {
            Reading::Value(fs) => (None, fs),
            Reading::Absent => return Reading::Absent,
            Reading::Declined(err) => return Reading::Declined(err),
            Reading::Failed(err) => return Reading::Failed(err),
          }
        }
        Reading::Absent => return Reading::Absent,
        Reading::Declined(err) => return Reading::Declined(err),
        Reading::Failed(err) => return Reading::Failed(err),
      };
      match Fields::of(&fs) {
        Ok(fields) => Reading::Value(Self {
          native,
          pinned,
          fs,
          fields,
          removal: OnceCell::new(),
        }),
        Err(err) => Reading::Failed(err),
      }
    }

    /// The mount point this observation reports.
    pub(super) fn mount_point(&self) -> &[u8] {
      self.fields.mount_point.as_bytes()
    }

    /// The one census entry this observation is, among `claimants` — the
    /// entries naming the mount point it was pinned from — or `None` where
    /// none is or more than one is: a listing row's binding.
    ///
    /// The pinned mount's own `fstatfs` is compared with each entry by the
    /// mount's own witness, never by its path alone: see [`is_same_mount`]. A
    /// pin reaches the mount on top of its path, so the entry of a mount it
    /// covers, and of a volume that left for another to take its path, is
    /// none of them; two entries it matches are no one entry. Its mount point
    /// must also be the bytes it was pinned from.
    #[cfg(feature = "list")]
    pub(super) fn census_entry_among<'e>(
      &self,
      claimants: &[&'e libc::statfs],
    ) -> Option<&'e libc::statfs> {
      if self.mount_point() != self.native.to_bytes() {
        return None;
      }
      let mut matching = claimants
        .iter()
        .copied()
        .filter(|entry| is_same_mount(&self.fs, entry));
      let entry = matching.next()?;
      matching.next().is_none().then_some(entry)
    }

    /// What this observation says about removal, where a descriptor holds
    /// the mount it describes, and nothing without one: the kernel's own
    /// `MNT_REMOVABLE`, off the very `fstatfs` the rest of the row comes from
    /// — see [`ejectability_from_flags`] — and, on macOS, where that says
    /// nothing, DiskArbitration's answer about the device the same `fstatfs`
    /// names, bound to the held mount — see
    /// [`disk_arbitration`](super::disk_arbitration). Asked once, and kept.
    pub(super) fn ejectability(&self) -> Ejectability {
      *self.removal.get_or_init(|| {
        let Some(pinned) = &self.pinned else {
          return Ejectability::Unknown;
        };
        match ejectability_from_flags(self.fs.f_flags) {
          Ejectability::Unknown => bound_removal(pinned, &self.fs, &self.fields),
          kernel => kernel,
        }
      })
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
      let fs_type = self.fields.fs_type.as_bytes();
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
        mount_point: self.fields.mount_point.clone(),
        device: self.fields.source.clone(),
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

  /// The removal answer bound to a held mount beyond the kernel's flag:
  /// DiskArbitration's on macOS, and none on the Apple platforms that have no
  /// DiskArbitration.
  #[cfg(target_os = "macos")]
  fn bound_removal(pinned: &OwnedFd, fs: &libc::statfs, fields: &Fields) -> Ejectability {
    super::disk_arbitration::removal(pinned, fs, fields)
  }

  /// The removal answer bound to a held mount beyond the kernel's flag:
  /// DiskArbitration's on macOS, and none on the Apple platforms that have no
  /// DiskArbitration.
  #[cfg(not(target_os = "macos"))]
  fn bound_removal(_pinned: &OwnedFd, _fs: &libc::statfs, _fields: &Fields) -> Ejectability {
    Ejectability::Unknown
  }

  /// A descriptor on the object a row describes, held while the row is read.
  ///
  /// Opened `O_EVTONLY` — Apple's permission-minimal open, the one file-event
  /// clients use — so a path the caller may traverse but has no right to
  /// *read* still resolves, exactly as the pathname road did. `O_RDONLY`
  /// stands in where that flag is refused. The file itself is never read: the
  /// descriptor exists so that `fstatfs` and `fgetattrlist` ask about one
  /// object instead of re-resolving a name five times.
  ///
  /// **Both opens are non-blocking and take no controlling terminal**
  /// (`O_NONBLOCK`, `O_NOCTTY`). A caller's path can be any object, and an
  /// open for reading waits on a FIFO until a writer arrives — a resolve that
  /// never returned — and a terminal can become the process's controlling
  /// terminal. Neither flag changes what an open of a directory or a regular
  /// file does, and the descriptor is never read. A socket, which no open
  /// answers, is left to the descriptor-less road: see
  /// [`answers_without_a_descriptor`].
  fn pin(path: &CStr) -> std::io::Result<OwnedFd> {
    use rustix::{
      fs::{Mode, OFlags},
      io::Errno,
    };

    // `O_EVTONLY` is Apple-only and rustix does not name it, so it is spelled
    // from libc's own constant and carried in as a raw bit.
    let event_only = OFlags::from_bits_retain(libc::O_EVTONLY as u32);
    let quiet = OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match rustix::fs::open(path, event_only | quiet, Mode::empty()) {
      Ok(fd) => Ok(fd),
      // Only a refusal of this open itself — a right it lacks, or a filesystem
      // that does not take the flag — is a reason to try the other. A path that
      // went away, a full descriptor table or an I/O error would fail the
      // second open the same way, and trying it would only replace the error
      // that says so with one that may not.
      Err(Errno::ACCESS | Errno::PERM | Errno::INVAL | Errno::NOTSUP | Errno::OPNOTSUPP) => {
        rustix::fs::open(path, OFlags::RDONLY | quiet, Mode::empty()).map_err(std::io::Error::from)
      }
      Err(errno) => Err(errno.into()),
    }
  }

  /// Where the pinned object sits on its own volume, spelled without
  /// firmlinks: `fcntl(F_GETPATH_NOFIRMLINK)`, which answers about the object
  /// the descriptor holds rather than about anything a name leads to.
  /// A platform without the command declines it (`EINVAL`). The command
  /// reports no length, so its buffer is a [`SentinelBuffer`]: the path ends
  /// only at a terminator the command wrote, and an answer with none is
  /// `Failed(InvalidData)`.
  fn path_without_firmlinks(pinned: &OwnedFd) -> Reading<Vec<u8>> {
    let mut buffer = SentinelBuffer::<u8>::new(libc::PATH_MAX as usize);
    // SAFETY: the command writes a NUL-terminated path of at most `MAXPATHLEN`
    // bytes, which is `PATH_MAX`, into the buffer it is given; this one is
    // that long and live for the call, and the descriptor is valid for as long
    // as `pinned` is.
    let rc = unsafe {
      libc::fcntl(
        pinned.as_raw_fd(),
        libc::F_GETPATH_NOFIRMLINK,
        buffer.for_call(),
      )
    };
    reading(if rc == -1 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(())
    })
    .and_then(|()| match buffer.terminated() {
      Ok(path) => Reading::Value(path.to_vec()),
      Err(err) => Reading::Failed(err),
    })
  }

  /// Whether an open failed because of what the object is to this process —
  /// one it may not open (`EACCES`, `EPERM`), a socket, which no open answers
  /// (`EOPNOTSUPP`), or a device node whose device is not there (`ENXIO`) —
  /// as opposed to failing for any of the reasons that are not a fact about
  /// the object: a descriptor table that is full, an I/O error, a path that
  /// went away. Only the first kind is answered by the descriptor-less road.
  fn answers_without_a_descriptor(err: &std::io::Error) -> bool {
    // `EACCES` and `EPERM` both arrive as this kind.
    err.kind() == std::io::ErrorKind::PermissionDenied
      || matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENXIO))
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

    /// An open that failed because of what the object is to this process —
    /// no right to it, or a kind no open answers — has a road of its own;
    /// nothing else does.
    ///
    /// Descriptor exhaustion, a transient I/O error and a vanished path are
    /// not facts about the object, and turning any of them into another road
    /// traded a correct refusal for a row assembled some other way.
    #[test]
    fn test_only_an_unopenable_object_reaches_the_descriptor_less_road() {
      use std::io::Error;

      for errno in [libc::EACCES, libc::EPERM, libc::EOPNOTSUPP, libc::ENXIO] {
        assert!(
          answers_without_a_descriptor(&Error::from_raw_os_error(errno)),
          "errno {errno} is a fact about the object"
        );
      }
      for errno in [
        libc::EMFILE,
        libc::ENFILE,
        libc::EIO,
        libc::ENOENT,
        libc::ELOOP,
      ] {
        assert!(
          !answers_without_a_descriptor(&Error::from_raw_os_error(errno)),
          "errno {errno} is not a fact about the object"
        );
      }
      assert!(!answers_without_a_descriptor(&Error::other(
        "not an errno at all"
      )));
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

/// The leading field of every `getattrlist` answer: "the overall length, in
/// bytes, of the attributes returned", which "includes the length field
/// itself" (`getattrlist(2)`).
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const ANSWER_LENGTH: usize = core::mem::size_of::<u32>();

/// One `getattrlist`, addressed to whichever face the caller has, into the
/// caller's own buffer, sorted into a [`Reading`] with the errno it failed
/// with — and answering **only the bytes the kernel said it wrote**.
///
/// The answer's leading length is checked before anything else is read: one
/// shorter than the length field itself, or longer than the buffer the call
/// was given, is no answer the kernel writes, and is `Failed(InvalidData)`.
/// Without `FSOPT_REPORT_FULLSIZE`, which is not asked for, that length is the
/// size actually returned. What comes back is a [`Filled`] view of exactly
/// that many bytes, so a decoder can read nothing the kernel did not write:
/// see [`filled`](super::filled).
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn getattrlist_at<'b, const N: usize>(
  target: AttrTarget<'_>,
  attrs: &mut libc::attrlist,
  buf: &'b mut KernelBuffer<N>,
) -> Reading<Filled<'b>> {
  let attrs = core::ptr::from_mut(attrs).cast::<core::ffi::c_void>();
  let size = KernelBuffer::<N>::LEN;
  let rc = match target {
    // SAFETY: the descriptor is valid for as long as the borrow lives; `attrs`
    // and `buf` are exclusive borrows, live for the call, and `buf` is exactly
    // `size` bytes, which is all the kernel writes; a `KernelBuffer` is bytes
    // alone, so whatever the kernel writes into it, or leaves, is a value.
    AttrTarget::Fd(fd) => {
      use rustix::fd::AsRawFd as _;
      unsafe { libc::fgetattrlist(fd.as_raw_fd(), attrs, buf.as_mut_ptr(), size, 0) }
    }
    // SAFETY: the same, with a NUL-terminated pathname that outlives the call.
    #[cfg(test)]
    AttrTarget::Path(path) => unsafe {
      libc::getattrlist(path.as_ptr(), attrs, buf.as_mut_ptr(), size, 0)
    },
  };
  // The errno is taken before anything else can overwrite it.
  let answered = reading(if rc == 0 {
    Ok(())
  } else {
    Err(std::io::Error::last_os_error())
  });
  let buf: &'b KernelBuffer<N> = buf;
  answered.and_then(|()| match attributes_written(buf) {
    Ok(answer) => Reading::Value(answer),
    Err(err) => Reading::Failed(err),
  })
}

/// The bytes a `getattrlist` answer says it holds, by its own leading length:
/// no fewer than the length field itself, and no more than the buffer, or
/// `InvalidData`.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn attributes_written<const N: usize>(buf: &KernelBuffer<N>) -> std::io::Result<Filled<'_>> {
  let length = usize::try_from(buf.filled(ANSWER_LENGTH)?.u32_at(0)?).unwrap_or(usize::MAX);
  if length < ANSWER_LENGTH {
    return Err(invalid("a getattrlist answer shorter than its own length"));
  }
  buf.filled(length)
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
/// [`Unknown`](super::Ejectability::Unknown), and never a denial. Where it
/// leaves the answer `Unknown`, macOS asks DiskArbitration about the device
/// the same `fstatfs` names, bound to the pinned mount by hold-and-verify, and
/// that is the one road on these platforms that may answer
/// [`NotEjectable`](super::Ejectability::NotEjectable): see
/// [`disk_arbitration`]. The other Apple platforms have no DiskArbitration,
/// and never deny.
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

/// macOS: DiskArbitration's answer about the disk a pinned mount is on, bound
/// to that mount by hold-and-verify — the one road on Apple platforms that may
/// deny.
///
/// **The platform does know.** DiskArbitration describes every disk it
/// arbitrates with the location of its device (`DADeviceInternal`) and what
/// its media does (`DAMediaEjectable`, `DAMediaRemovable`) — the facts
/// `diskutil info` prints as *Device Location* and *Removable Media*. A disk
/// whose device is inside the machine and whose media neither ejects nor comes
/// out is the platform's own "this storage stays", which is what
/// [`NotEjectable`](super::Ejectability::NotEjectable) means; media that ejects
/// or comes out, and a device outside the machine, are its yes.
///
/// **Bound by hold-and-verify, since DiskArbitration answers by name.** Its
/// question is a BSD disk name, and a name is not a mount: a disk that left
/// hands its name to the next one, and a mount's source is text — a
/// user-space filesystem (macFUSE) names whatever it likes there, a disk's
/// included. So:
///
/// 1. the name is the device the pinned mount's own `fstatfs` names, read
///    through the descriptor the row holds;
/// 2. DiskArbitration is asked to describe that disk, and its description
///    must name the same disk (`DAMediaBSDName`), and **its device number
///    (`DAMediaBSDMajor`, `DAMediaBSDMinor`) must be the one the kernel
///    wrote into the pinned mount's own filesystem id**: a disk filesystem's
///    `f_fsid` carries the device it was mounted from (measured on APFS and
///    HFS, where it is the device node's `st_rdev`), while a filesystem no
///    device backs is given one of the kernel's choosing, so a source that
///    merely names a disk binds nothing. It must also say it is mounted where
///    that `fstatfs` says the pinned mount is (`DAVolumePath`), in agreement,
///    never as the binding;
/// 3. the descriptor is asked again, afterwards, and must still name the same
///    device, filesystem id and mount point.
///
/// A held descriptor keeps its mount mounted — `unmount(2)` answers `EBUSY`
/// while a reference is held, and a forced unmount turns every access through
/// it into an error — so a mount that still answers the same `fstatfs` after
/// the description was read is the mount the description was about, and the
/// device it names has not been handed on in between. Any check that fails
/// drops the fact, and the removal answer is `Unknown`. So is every question
/// DiskArbitration did not answer: no session, no disk of that name, no
/// description, a key missing or of another type.
///
/// **What is left unbound, and stated.** The description is read in one call,
/// so its keys describe one disk at one instant; a device whose location or
/// media changes while it stays mounted is not a thing a disk does. And the
/// filesystem id is the kernel's word only as far as the filesystem the kernel
/// runs is honest: a kernel-level filesystem — a kext, an FSKit module, which
/// takes root to install — that wrote a real disk's device into its own
/// `f_fsid` and mounted itself over that disk's mount point would inherit the
/// disk's description. No user-space filesystem can do either.
#[cfg(target_os = "macos")]
mod disk_arbitration {
  use core::ffi::{c_char, c_void};
  use std::ffi::{CStr, CString};

  use rustix::fd::OwnedFd;

  use super::{super::filled::SentinelBuffer, Ejectability, Fields};

  type CFTypeRef = *const c_void;
  type CFAllocatorRef = *const c_void;
  type CFDictionaryRef = *const c_void;
  type CFStringRef = *const c_void;
  type CFTypeID = usize;
  type CFIndex = isize;
  type CFStringEncoding = u32;
  type Boolean = u8;
  type DASessionRef = *const c_void;
  type DADiskRef = *const c_void;

  /// `kCFStringEncodingUTF8`, from `<CoreFoundation/CFString.h>`.
  const UTF8: CFStringEncoding = 0x0800_0100;

  /// `kCFNumberSInt32Type`, from `<CoreFoundation/CFNumber.h>`.
  const SINT32: CFIndex = 3;

  /// How long a BSD disk name may be, with its terminator: `disk3s1s1` is
  /// nine bytes, and nothing DiskArbitration names comes near this.
  const NAME_LIMIT: usize = 128;

  #[link(name = "CoreFoundation", kind = "framework")]
  unsafe extern "C" {
    fn CFRelease(object: CFTypeRef);
    fn CFGetTypeID(object: CFTypeRef) -> CFTypeID;
    fn CFBooleanGetTypeID() -> CFTypeID;
    fn CFBooleanGetValue(boolean: CFTypeRef) -> Boolean;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFStringGetCString(
      string: CFStringRef,
      buffer: *mut c_char,
      size: CFIndex,
      encoding: CFStringEncoding,
    ) -> Boolean;
    fn CFURLGetTypeID() -> CFTypeID;
    fn CFNumberGetTypeID() -> CFTypeID;
    fn CFNumberGetValue(number: CFTypeRef, kind: CFIndex, value: *mut c_void) -> Boolean;
    fn CFURLGetFileSystemRepresentation(
      url: CFTypeRef,
      resolve_against_base: Boolean,
      buffer: *mut u8,
      max_length: CFIndex,
    ) -> Boolean;
    fn CFDictionaryGetValue(dictionary: CFDictionaryRef, key: *const c_void) -> *const c_void;
  }

  #[link(name = "DiskArbitration", kind = "framework")]
  unsafe extern "C" {
    static kDADiskDescriptionDeviceInternalKey: CFStringRef;
    static kDADiskDescriptionMediaEjectableKey: CFStringRef;
    static kDADiskDescriptionMediaRemovableKey: CFStringRef;
    static kDADiskDescriptionMediaBSDNameKey: CFStringRef;
    static kDADiskDescriptionMediaBSDMajorKey: CFStringRef;
    static kDADiskDescriptionMediaBSDMinorKey: CFStringRef;
    static kDADiskDescriptionVolumePathKey: CFStringRef;
    fn DASessionCreate(allocator: CFAllocatorRef) -> DASessionRef;
    fn DADiskCreateFromBSDName(
      allocator: CFAllocatorRef,
      session: DASessionRef,
      name: *const c_char,
    ) -> DADiskRef;
    fn DADiskCopyDescription(disk: DADiskRef) -> CFDictionaryRef;
  }

  /// A Core Foundation object this module created — a session, a disk, a
  /// description — released exactly once, when it is dropped.
  struct Created(CFTypeRef);

  impl Created {
    /// Takes an object a *Create* or *Copy* function returned, which the
    /// caller owns, or `None` for the null it returns when it has none.
    fn of(object: CFTypeRef) -> Option<Self> {
      (!object.is_null()).then_some(Self(object))
    }
  }

  impl Drop for Created {
    fn drop(&mut self) {
      // SAFETY: a non-null object from a Create or Copy function, owned by
      // this value alone and released once, here.
      unsafe { CFRelease(self.0) };
    }
  }

  /// What DiskArbitration's description of one disk says: the disk it is
  /// about, where it is mounted, and the three removal facts. Every field is
  /// `None` where the key is missing or holds another type.
  #[derive(Debug, Default, PartialEq, Eq)]
  pub(super) struct Description {
    pub(super) bsd_name: Option<Vec<u8>>,
    /// The disk's device number, `makedev(DAMediaBSDMajor, DAMediaBSDMinor)`.
    pub(super) device: Option<libc::dev_t>,
    pub(super) volume_path: Option<Vec<u8>>,
    pub(super) internal: Option<bool>,
    pub(super) ejectable: Option<bool>,
    pub(super) removable: Option<bool>,
  }

  impl Description {
    /// What the description says about removal.
    ///
    /// Media that ejects or comes out is a yes, and so is a device outside
    /// the machine. A device inside it whose media does neither is the one
    /// denial — and only with all three facts stated; a missing one is no
    /// answer at all.
    pub(super) fn removal(&self) -> Ejectability {
      match (self.internal, self.ejectable, self.removable) {
        (_, Some(true), _) | (_, _, Some(true)) | (Some(false), _, _) => Ejectability::Ejectable,
        (Some(true), Some(false), Some(false)) => Ejectability::NotEjectable,
        _ => Ejectability::Unknown,
      }
    }
  }

  /// The removal answer of the disk the pinned mount `fields` was read from
  /// is on: DiskArbitration's, where the description is bound to the mount by
  /// hold-and-verify — see the module's documentation — and `Unknown`
  /// otherwise.
  pub(super) fn removal(pinned: &OwnedFd, fs: &libc::statfs, fields: &Fields) -> Ejectability {
    // 1. The device the pinned mount's own `fstatfs` names.
    let Some(name) = fields
      .source
      .as_bytes()
      .strip_prefix(b"/dev/")
      .and_then(|name| CString::new(name).ok())
    else {
      return Ejectability::Unknown;
    };
    // 2. Its description: about that disk, which is the device the kernel
    // mounted — the one the filesystem id carries — and mounted where the pin
    // is.
    let Some(description) = describe(&name) else {
      return Ejectability::Unknown;
    };
    let mounted_from = super::fsid_device(fs);
    if description.bsd_name.as_deref() != Some(name.to_bytes())
      || description.device != Some(mounted_from)
      || description.volume_path.as_deref() != Some(fields.mount_point.as_bytes())
    {
      return Ejectability::Unknown;
    }
    // 3. The descriptor still names that device, that filesystem id and that
    // mount point.
    let again = rustix::fs::fstatfs(pinned).ok().and_then(|now| {
      Fields::of(&now)
        .ok()
        .map(|now_fields| (super::fsid_device(&now), now_fields))
    });
    match again {
      Some((now_from, now))
        if now_from == mounted_from
          && now.source.as_bytes() == fields.source.as_bytes()
          && now.mount_point.as_bytes() == fields.mount_point.as_bytes() =>
      {
        description.removal()
      }
      _ => Ejectability::Unknown,
    }
  }

  /// DiskArbitration's description of the disk `name` names, in one call on a
  /// session of its own that is never scheduled, or `None` where it has none.
  pub(super) fn describe(name: &CStr) -> Option<Description> {
    // SAFETY: a null allocator is the default one; the session returned, if
    // any, is owned and released by `Created`.
    let session = Created::of(unsafe { DASessionCreate(core::ptr::null()) })?;
    // SAFETY: a live session and a NUL-terminated name, both for the call;
    // the disk returned is owned and released by `Created`.
    let disk =
      Created::of(unsafe { DADiskCreateFromBSDName(core::ptr::null(), session.0, name.as_ptr()) })?;
    // SAFETY: a live disk; the dictionary returned is a copy this module owns,
    // released by `Created`.
    let description = Created::of(unsafe { DADiskCopyDescription(disk.0) })?;
    // SAFETY (each key): the framework's own constant, initialised by the
    // time the framework is loaded, which linking it guarantees.
    let (bsd_name, major, minor, volume_path, internal, ejectable, removable) = unsafe {
      (
        kDADiskDescriptionMediaBSDNameKey,
        kDADiskDescriptionMediaBSDMajorKey,
        kDADiskDescriptionMediaBSDMinorKey,
        kDADiskDescriptionVolumePathKey,
        kDADiskDescriptionDeviceInternalKey,
        kDADiskDescriptionMediaEjectableKey,
        kDADiskDescriptionMediaRemovableKey,
      )
    };
    let device = match (
      i32_value(&description, major),
      i32_value(&description, minor),
    ) {
      (Some(major), Some(minor)) => Some(libc::makedev(major, minor)),
      _ => None,
    };
    Some(Description {
      bsd_name: string_value(&description, bsd_name),
      device,
      volume_path: path_value(&description, volume_path),
      internal: bool_value(&description, internal),
      ejectable: bool_value(&description, ejectable),
      removable: bool_value(&description, removable),
    })
  }

  /// The value `key` holds in `dictionary`, where it is of the type `type_id`
  /// names: a borrowed object, which the dictionary keeps alive.
  fn value_of(dictionary: &Created, key: CFStringRef, type_id: CFTypeID) -> Option<CFTypeRef> {
    // SAFETY: a live dictionary and a live key; the value, if any, is
    // borrowed from the dictionary and not released here.
    let value = unsafe { CFDictionaryGetValue(dictionary.0, key) };
    // SAFETY: a live object from the dictionary.
    (!value.is_null() && unsafe { CFGetTypeID(value) } == type_id).then_some(value)
  }

  /// A boolean the dictionary holds under `key`.
  fn bool_value(dictionary: &Created, key: CFStringRef) -> Option<bool> {
    // SAFETY: a pure query of the boolean type's identifier.
    let value = value_of(dictionary, key, unsafe { CFBooleanGetTypeID() })?;
    // SAFETY: a live object of the boolean type.
    Some(unsafe { CFBooleanGetValue(value) } != 0)
  }

  /// A number the dictionary holds under `key`, where a 32-bit integer holds
  /// it exactly.
  fn i32_value(dictionary: &Created, key: CFStringRef) -> Option<i32> {
    // SAFETY: a pure query of the number type's identifier.
    let value = value_of(dictionary, key, unsafe { CFNumberGetTypeID() })?;
    let mut number: i32 = 0;
    // SAFETY: a live number, asked for as `kCFNumberSInt32Type` into a live
    // `i32`, which is all the call writes; it answers false where the value
    // does not fit, and that is no answer.
    let exact = unsafe { CFNumberGetValue(value, SINT32, core::ptr::from_mut(&mut number).cast()) };
    (exact != 0).then_some(number)
  }

  /// A string the dictionary holds under `key`, as its UTF-8 bytes.
  ///
  /// The call reports no length, only that it wrote the whole string and its
  /// terminator, so its buffer is a [`SentinelBuffer`]: the string ends at a
  /// terminator the call wrote, and one that did not fit is no answer.
  fn string_value(dictionary: &Created, key: CFStringRef) -> Option<Vec<u8>> {
    // SAFETY: a pure query of the string type's identifier.
    let value = value_of(dictionary, key, unsafe { CFStringGetTypeID() })?;
    let mut buffer = SentinelBuffer::<u8>::new(NAME_LIMIT);
    // SAFETY: a live string, and a buffer live and `len()` bytes long for
    // the call, which writes no further than that.
    let ok = unsafe {
      CFStringGetCString(
        value,
        buffer.for_call().cast(),
        buffer.len() as CFIndex,
        UTF8,
      )
    };
    if ok == 0 {
      return None;
    }
    buffer.terminated().ok().map(<[u8]>::to_vec)
  }

  /// A URL the dictionary holds under `key`, as its filesystem
  /// representation: the path's own bytes, read the same way as a string.
  fn path_value(dictionary: &Created, key: CFStringRef) -> Option<Vec<u8>> {
    // SAFETY: a pure query of the URL type's identifier.
    let value = value_of(dictionary, key, unsafe { CFURLGetTypeID() })?;
    let mut buffer = SentinelBuffer::<u8>::new(libc::PATH_MAX as usize);
    // SAFETY: a live URL, and a buffer live and `len()` bytes long for the
    // call, which writes no further than that.
    let ok = unsafe {
      CFURLGetFileSystemRepresentation(value, 1, buffer.for_call(), buffer.len() as CFIndex)
    };
    if ok == 0 {
      return None;
    }
    buffer.terminated().ok().map(<[u8]>::to_vec)
  }

  #[cfg(test)]
  mod tests {
    use super::*;

    /// The one denial needs all three facts, stated; a yes needs one.
    #[test]
    fn test_a_description_denies_only_with_every_fact_stated() {
      let described = |internal, ejectable, removable| Description {
        internal,
        ejectable,
        removable,
        ..Description::default()
      };
      assert_eq!(
        described(Some(true), Some(false), Some(false)).removal(),
        Ejectability::NotEjectable
      );
      for (internal, ejectable, removable) in [
        (Some(false), Some(false), Some(false)),
        (Some(true), Some(true), Some(false)),
        (Some(true), Some(false), Some(true)),
        (None, Some(true), None),
        (None, None, Some(true)),
        (Some(false), None, None),
      ] {
        assert_eq!(
          described(internal, ejectable, removable).removal(),
          Ejectability::Ejectable,
          "{internal:?} {ejectable:?} {removable:?}"
        );
      }
      for (internal, ejectable, removable) in [
        (None, None, None),
        (Some(true), None, Some(false)),
        (Some(true), Some(false), None),
        (None, Some(false), Some(false)),
      ] {
        assert_eq!(
          described(internal, ejectable, removable).removal(),
          Ejectability::Unknown,
          "{internal:?} {ejectable:?} {removable:?}"
        );
      }
    }

    /// DiskArbitration describes the disk the root is mounted from, names that
    /// disk and the root as its mount point, and the answer bound to the root's
    /// pin is the description's own. Measured: this law prints what the host
    /// said.
    #[test]
    fn test_the_root_is_described_by_the_disk_its_own_mount_names() {
      let pinned = super::super::observed::pin_for_laws(std::path::Path::new("/")).unwrap();
      let fs = rustix::fs::fstatfs(&pinned).unwrap();
      let fields = Fields::of(&fs).unwrap();
      let name = fields.source.as_bytes().strip_prefix(b"/dev/").unwrap();
      let description =
        describe(&CString::new(name).unwrap()).expect("the root's disk is described");
      println!(
        "/: {} fsid device {:#x} {description:?}",
        String::from_utf8_lossy(fields.source.as_bytes()),
        super::super::fsid_device(&fs)
      );
      assert_eq!(description.bsd_name.as_deref(), Some(name));
      assert_eq!(
        description.device,
        Some(super::super::fsid_device(&fs)),
        "the filesystem id carries the device the root was mounted from"
      );
      assert_eq!(description.volume_path.as_deref(), Some(&b"/"[..]));
      assert_eq!(removal(&pinned, &fs, &fields), description.removal());
    }

    /// A description that names another disk, or another mount point, binds
    /// nothing: the answer is `Unknown` whatever the description says.
    #[test]
    fn test_a_description_of_another_mount_binds_nothing() {
      let pinned = super::super::observed::pin_for_laws(std::path::Path::new("/")).unwrap();
      let fs = rustix::fs::fstatfs(&pinned).unwrap();
      let mut fields = Fields::of(&fs).unwrap();
      fields.mount_point = super::super::SmallBytes::from_bytes(b"/Volumes/elsewhere");
      assert_eq!(removal(&pinned, &fs, &fields), Ejectability::Unknown);

      // A source naming the root's disk on a mount the kernel gave another
      // filesystem id — what a user-space filesystem that claims the disk
      // is — binds nothing either.
      let fields = Fields::of(&fs).unwrap();
      let mut claimed = fs;
      // SAFETY: `fsid_t` is eight bytes with no padding, and any eight bytes
      // are one.
      unsafe {
        core::ptr::write(
          core::ptr::from_mut(&mut claimed.f_fsid).cast::<[u8; 8]>(),
          [0x5A; 8],
        );
      }
      assert_eq!(removal(&pinned, &claimed, &fields), Ejectability::Unknown);
    }

    /// Every listed volume answers what its kernel flag says, and, where that
    /// says nothing, what its bound description says. Measured: this law
    /// prints every volume's answer and the description it came from.
    #[cfg(feature = "list")]
    #[test]
    fn test_every_listed_volume_on_this_machine_answers_by_its_flag_or_its_description() {
      use std::os::unix::ffi::OsStrExt as _;

      for row in crate::list().unwrap() {
        let pinned = super::super::observed::pin_for_laws(row.mount_point()).unwrap();
        let fs = rustix::fs::fstatfs(&pinned).unwrap();
        let fields = Fields::of(&fs).unwrap();
        let name = fields.source.as_bytes().strip_prefix(b"/dev/");
        let description = name.and_then(|name| describe(&CString::new(name).unwrap()));
        let expected = match super::super::ejectability_from_flags(fs.f_flags) {
          Ejectability::Unknown => removal(&pinned, &fs, &fields),
          kernel => kernel,
        };
        println!(
          "{} on {}: {:?} (MNT_REMOVABLE {}) {description:?}",
          row.mount_point().display(),
          String::from_utf8_lossy(row.device().as_bytes()),
          row.ejectability(),
          fs.f_flags & super::super::MNT_REMOVABLE != 0,
        );
        assert_eq!(row.ejectability(), expected, "{row:?}");
      }
    }
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
/// replaced could not say that — a volume resource key is asked by pathname,
/// and a pathname is re-resolved on every call.
///
/// The name is decoded out of the bytes the kernel said it wrote and nothing
/// else — see [`volume_name_in`] — so a layout the kernel could not have
/// written is `InvalidData`, never a label and never "no label". An empty
/// name is no label rather than a label that is nothing, and the caller's
/// fallback then names the volume from its mount point; a name that is not
/// UTF-8 is kept as the bytes the volume wrote, so it is never reported as no
/// name. `Vouched`, because the volume answered for itself, on this call.
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
  // SAFETY: `attrlist` is a C structure of integers, for which all-zero bytes
  // are a valid value.
  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_NAME;

  let mut buf = KernelBuffer::<{ NAME_VARIABLE + NAME_ROOM }>::new();
  getattrlist_at(target, &mut attrs, &mut buf)
    .and_then(|answer| match volume_name_in(answer) {
      Ok(name) => Reading::Value(name),
      Err(err) => Reading::Failed(err),
    })
    .answered()
    .map(Option::flatten)
}

/// Where an `ATTR_VOL_NAME` answer's reference lies: straight after the
/// answer's length, the one fixed attribute asked for.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const NAME_REFERENCE: usize = ANSWER_LENGTH;

/// Where an `ATTR_VOL_NAME` answer's variable part begins: past the length and
/// the reference, the whole of its fixed part.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const NAME_VARIABLE: usize = NAME_REFERENCE + core::mem::size_of::<libc::attrreference_t>();

/// The room a volume name can take: "not greater than NAME_MAX + 1
/// characters, which is NAME_MAX * 3 + 1 bytes, as one UTF-8-encoded character
/// may take up to three bytes" (`getattrlist(2)`), rounded up to the four
/// bytes the kernel pads variable data to. A buffer with less room than that
/// would turn a long name into an answer cut short.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const NAME_ROOM: usize = (255 * 3 + 1 + 3) & !3;

/// The label an `ATTR_VOL_NAME` answer carries, or `InvalidData` for a layout
/// the kernel could not have written.
///
/// The reference is a signed offset, counted from the reference itself, and a
/// length that counts the terminating NUL. The name it points to must begin
/// in the answer's variable part — not inside the length or the reference —
/// end inside the bytes the answer holds, and be one string: a NUL at its last
/// byte and at no other.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_name_in(answer: Filled<'_>) -> std::io::Result<Option<NameReading>> {
  let offset = answer
    .i32_at(NAME_REFERENCE + core::mem::offset_of!(libc::attrreference_t, attr_dataoffset))?;
  let length =
    answer.u32_at(NAME_REFERENCE + core::mem::offset_of!(libc::attrreference_t, attr_length))?;
  let start = i64::try_from(NAME_REFERENCE)
    .ok()
    .and_then(|reference| reference.checked_add(i64::from(offset)))
    .and_then(|start| usize::try_from(start).ok())
    .filter(|&start| start >= NAME_VARIABLE)
    .ok_or_else(|| invalid("a volume name that does not begin in the answer's variable part"))?;
  let payload = answer.bytes(start, usize::try_from(length).unwrap_or(usize::MAX))?;
  let Some((&0, name)) = payload.split_last() else {
    return Err(invalid("a volume name with no terminating NUL"));
  };
  if super::find_byte(0, name).is_some() {
    return Err(invalid("a volume name with a NUL inside it"));
  }
  // Kept as the volume wrote it, text or not: a name that is not UTF-8 is a
  // name all the same. See `published_label_bytes`.
  Ok(super::published_label_bytes(
    name,
    super::IdentityAssurance::Vouched,
  ))
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
  let read = || mount_table().map(|census| census.into_iter().collect::<Vec<_>>());
  let census = if cfg!(target_os = "dragonfly") {
    settled(read, |first: &Vec<libc::statfs>, second| {
      first.len() == second.len() && first.iter().zip(second).all(|(a, b)| same_strings(a, b))
    })?
  } else {
    read()?
  };
  // Every entry decoded whole before any is weighed: see [`Fields`].
  let entries = census
    .into_iter()
    .map(|entry| Fields::of(&entry).map(|fields| (entry, fields)))
    .collect::<std::io::Result<Vec<_>>>()?;
  let mut mounts = Vec::new();
  for (entry, fields) in &entries {
    let fs_type = fields.fs_type.as_bytes();
    if matches!(
      fs_type,
      b"autofs" | b"devfs" | b"linprocfs" | b"procfs" | b"fdescfs" | b"tmpfs" | b"linsysfs"
    ) {
      continue;
    }
    let mp_bytes = fields.mount_point.as_bytes();
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
    let mount_point = SmallBytes::from_bytes(mp_bytes);
    let device = SmallBytes::from_bytes(device_bytes);
    let capabilities = volume_capabilities(mount_point.as_path(), fs_type);
    let identity = volume_identity(mount_point.as_path());
    let name = volume_name(mount_point.as_path());
    #[cfg(not(feature = "disk-usage"))]
    let _ = entry;
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

/// What a FreeBSD, OpenBSD or DragonFly mount's source can say about
/// removal: a yes where the source is bound to the mount and names a class of
/// drive that is only ever removable media, and nothing otherwise.
///
/// **The source must be bound first.** `f_mntfromname` is text a user-space
/// filesystem chooses for itself, so a name is read only where the kernel's
/// own filesystem type proves the kernel opened the device it names: see
/// [`source_is_bound`](super::source_is_bound).
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
fn ejectability_of_source(fs_type: &[u8], source: &[u8]) -> Ejectability {
  if names_optical_or_floppy(source) && super::source_is_bound(fs_type, source) {
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
  /// The answer: its length, then the one fixed attribute asked for, a
  /// `vol_capabilities_attr_t`, and nothing else.
  const ANSWER: usize = ANSWER_LENGTH + core::mem::size_of::<libc::vol_capabilities_attr_t>();
  /// The format-capability bits, and which of them the volume reports as
  /// valid.
  const FORMAT: usize = ANSWER_LENGTH
    + core::mem::offset_of!(libc::vol_capabilities_attr_t, capabilities)
    + libc::VOL_CAPABILITIES_FORMAT * core::mem::size_of::<u32>();
  const FORMAT_VALID: usize = ANSWER_LENGTH
    + core::mem::offset_of!(libc::vol_capabilities_attr_t, valid)
    + libc::VOL_CAPABILITIES_FORMAT * core::mem::size_of::<u32>();

  // SAFETY: `attrlist` is a C structure of integers, for which all-zero bytes
  // are a valid value.
  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES;

  let mut buf = KernelBuffer::<ANSWER>::new();
  let answer = match getattrlist_at(target, &mut attrs, &mut buf) {
    Reading::Value(answer) => answer,
    Reading::Absent | Reading::Declined(_) => return Ok(VolumeCapabilities::from_fs_type(fs_type)),
    Reading::Failed(err) => return Err(err),
  };
  // The kernel answers every attribute it was asked for or fails the call, so
  // an answer of any other length is not one it wrote.
  if answer.len() != ANSWER {
    return Err(invalid(
      "a capabilities answer that is not the length and the capabilities",
    ));
  }

  // A bit is only meaningful when the matching valid bit is set.
  let format = answer.u32_at(FORMAT)?;
  let format_valid = answer.u32_at(FORMAT_VALID)?;

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
/// `EINVAL` for an attribute a filesystem does not carry, as the
/// pseudo-filesystems (`devfs`, `autofs`) do. An all-zero UUID is the
/// "no UUID" sentinel and is also reported as `None`, and so is a path that is
/// no longer there or is out of this caller's reach. A read that failed is
/// returned as the error it is, never as a volume with no identity — see
/// [`declined`] — and so is an answer that is not the length and the UUID the
/// kernel writes: the kernel answers every attribute it is asked for or fails
/// the call, so a short answer is not one it wrote, and it is `InvalidData`
/// rather than no identity.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn volume_identity_at(target: AttrTarget<'_>) -> std::io::Result<Option<IdentityReading>> {
  /// The answer: its length, then the one fixed attribute asked for, a
  /// `uuid_t`, and nothing else.
  const ANSWER: usize = ANSWER_LENGTH + core::mem::size_of::<libc::uuid_t>();

  // SAFETY: `attrlist` is a C structure of integers, for which all-zero bytes
  // are a valid value.
  let mut attrs: libc::attrlist = unsafe { core::mem::zeroed() };
  attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
  attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID;

  let mut buf = KernelBuffer::<ANSWER>::new();
  getattrlist_at(target, &mut attrs, &mut buf)
    .and_then(|answer| {
      // The kernel answers every attribute it was asked for or fails the
      // call, so an answer of any other length is not one it wrote.
      if answer.len() != ANSWER {
        return Reading::Failed(invalid("a UUID answer that is not the length and the UUID"));
      }
      match answer.array::<16>(ANSWER_LENGTH) {
        // An all-zero UUID records the absence of one; `fs_uuid` applies the
        // same rule every other backend uses.
        Ok(uuid) => super::fs_uuid(uuid).map_or(Reading::Absent, |uuid| {
          Reading::Value(IdentityReading::vouched(uuid))
        }),
        Err(err) => Reading::Failed(err),
      }
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

/// The three strings every `statfs` carries, each decoded strictly out of its
/// fixed array: the mount point, the source and the filesystem type.
///
/// **Whole, or the call fails.** Each is the bytes before its array's first
/// NUL; an array the kernel wrote always holds one, so an array with none is
/// not the kernel's writing, and is never read as far as the array happens to
/// go. And every mount has all three — a mount point, which is an absolute
/// path, a source and a type — so an entry missing one is not a mount the
/// kernel is describing. Either way the entry fails the resolve or the whole
/// listing with `InvalidData`; it is never passed over, which would leave a
/// census that reads as complete without it.
struct Fields {
  mount_point: SmallBytes,
  source: SmallBytes,
  fs_type: SmallBytes,
}

impl Fields {
  /// Every mandatory field of `fs`, or `InvalidData`.
  fn of(fs: &libc::statfs) -> std::io::Result<Self> {
    let mount_point = c_string(&fs.f_mntonname)?;
    let source = c_string(&fs.f_mntfromname)?;
    let fs_type = c_string(&fs.f_fstypename)?;
    if !mount_point.starts_with(b"/") || source.is_empty() || fs_type.is_empty() {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
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

/// An answer about the mount table taken only once two consecutive answers
/// agree, for DragonFly.
///
/// **DragonFly rewrites a mount's strings in place on every call.** Its
/// `statfs` and `getfsstat` write the mount point as the caller's root sees
/// it into the kernel's one shared copy of each mount's statistics — `bzero`,
/// then `strlcpy` (`kern_statfs`, `getfsstat_callback`,
/// `kern/vfs_syscalls.c`) — and copy that shared copy out afterwards. A call
/// made while another call anywhere on the system is between the two copies
/// out a mount point that is empty, or cut short and still spelled like a
/// path. An answer torn that way is one no second call repeats, so an answer
/// is taken only where the next one agrees with it on every string, and a
/// table that never settles is refused.
#[cfg(not(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
)))]
fn settled<T>(
  mut read: impl FnMut() -> std::io::Result<T>,
  same: impl Fn(&T, &T) -> bool,
) -> std::io::Result<T> {
  /// How many answers are compared before a table that keeps changing is
  /// refused.
  const ATTEMPTS: usize = 16;

  let mut last = read()?;
  for _ in 0..ATTEMPTS {
    let next = read()?;
    if same(&last, &next) {
      return Ok(next);
    }
    last = next;
  }
  Err(std::io::Error::other(
    "the mount table's strings changed between every two reads, so no answer is one it stood at",
  ))
}

/// Whether two answers spell one mount the same way: its mount point, source
/// and filesystem type, every byte of each array. See [`settled`].
#[cfg(not(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
)))]
fn same_strings(a: &libc::statfs, b: &libc::statfs) -> bool {
  a.f_mntonname == b.f_mntonname
    && a.f_mntfromname == b.f_mntfromname
    && a.f_fstypename == b.f_fstypename
}

/// The string the kernel wrote into a fixed `char` array: its bytes before
/// the terminating NUL, or `InvalidData` for an array that holds none.
fn c_string(chars: &[core::ffi::c_char]) -> std::io::Result<&[u8]> {
  let bytes = c_chars(chars);
  match super::find_byte(0, bytes) {
    Some(len) => Ok(&bytes[..len]),
    None => Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "a mount table string with no terminator inside its array",
    )),
  }
}

/// A string the kernel wrote into a fixed array, for the laws.
#[cfg(all(
  test,
  any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  )
))]
fn c_chars_as_bytes(chars: &[core::ffi::c_char]) -> &[u8] {
  c_string(chars).expect("the kernel terminates every string it writes")
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

  /// A `getattrlist` answer holding `name` at the kernel's own layout: the
  /// leading length, the reference — an offset counted from the reference and
  /// a length — and the name after them, as a call might have left it.
  fn name_answer(total: u32, offset: i32, length: u32, name: &[u8]) -> KernelBuffer<64> {
    let mut bytes = [0u8; 64];
    bytes[..4].copy_from_slice(&total.to_ne_bytes());
    bytes[4..8].copy_from_slice(&offset.to_ne_bytes());
    bytes[8..12].copy_from_slice(&length.to_ne_bytes());
    bytes[12..12 + name.len()].copy_from_slice(name);
    KernelBuffer::holding(bytes)
  }

  /// An answer is the bytes its own leading length names, and a length the
  /// kernel could not have written — shorter than itself, longer than the
  /// buffer — is `InvalidData` before any field is read.
  #[test]
  fn test_an_answer_is_as_long_as_it_says_and_no_longer() {
    for total in [0u32, 3, 65, u32::MAX] {
      assert_eq!(
        attributes_written(&name_answer(total, 8, 5, b"Data\0"))
          .err()
          .map(|err| err.kind()),
        Some(std::io::ErrorKind::InvalidData),
        "a leading length of {total}"
      );
    }
    assert_eq!(
      attributes_written(&name_answer(20, 8, 5, b"Data\0"))
        .unwrap()
        .len(),
      20
    );
  }

  /// A volume name is read only out of the answer's variable part and the
  /// bytes the kernel said it wrote, and only as one NUL-terminated string:
  /// a reference into the length or the reference itself, a name running past
  /// the answer, and a name with no terminator or with one inside it are each
  /// `InvalidData`, never a label and never no label.
  #[test]
  fn test_a_volume_name_is_read_only_inside_the_answer() {
    let decode = |buffer: &KernelBuffer<64>| volume_name_in(attributes_written(buffer).unwrap());
    let name = decode(&name_answer(20, 8, 5, b"Data\0"))
      .unwrap()
      .expect("a name the kernel wrote is a label");
    assert_eq!(name.name.as_bytes(), b"Data");
    assert!(
      decode(&name_answer(16, 8, 1, b"\0")).unwrap().is_none(),
      "an empty name is no label"
    );
    for (buffer, why) in [
      (name_answer(20, 0, 5, b"Data\0"), "a reference to itself"),
      (
        name_answer(20, -4, 5, b"Data\0"),
        "a reference to the length",
      ),
      (
        name_answer(20, i32::MIN, 5, b"Data\0"),
        "a reference before the answer",
      ),
      (
        name_answer(16, 8, 5, b"Data\0"),
        "a name past the answer's end",
      ),
      (
        name_answer(20, 8, 4, b"Data\0"),
        "a name with no terminator",
      ),
      (
        name_answer(20, 8, 5, b"Da\0a\0"),
        "a name with a NUL inside it",
      ),
      (name_answer(20, 8, 0, b""), "a name of no bytes at all"),
      (
        name_answer(20, 8, u32::MAX, b"Data\0"),
        "a length past any buffer",
      ),
    ] {
      assert_eq!(
        decode(&buffer).err().map(|err| err.kind()),
        Some(std::io::ErrorKind::InvalidData),
        "{why}"
      );
    }
  }

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

  /// **A FIFO, a socket and a device node resolve at once**, as the pathname
  /// `statfs` the Apple road used to be always did. The pin opens without
  /// blocking — an open for reading waits on a FIFO until a writer arrives —
  /// and a socket, which no open answers, is described by its one `statfs`:
  /// no identity, no label and nothing about removal.
  #[test]
  fn test_a_fifo_a_socket_and_a_device_node_resolve_at_once() {
    use std::{sync::mpsc, time::Duration};

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    let native_fifo = native(&fifo);
    // SAFETY: a NUL-terminated path in a directory this law owns.
    assert_eq!(unsafe { libc::mkfifo(native_fifo.as_ptr(), 0o600) }, 0);
    let socket = dir.path().join("socket");
    let _listening = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let home = resolve(dir.path())
      .unwrap()
      .mount_info()
      .mount_point()
      .to_path_buf();

    let resolved_promptly = |path: PathBuf| {
      let (answer, answered) = mpsc::channel();
      let asked = path.clone();
      std::thread::spawn(move || {
        let _ = answer.send(resolve(&asked).map(|location| location.mount_info().clone()));
      });
      answered
        .recv_timeout(Duration::from_secs(20))
        .unwrap_or_else(|_| panic!("{} did not resolve promptly", path.display()))
        .unwrap_or_else(|err| panic!("{} did not resolve: {err}", path.display()))
    };

    assert_eq!(resolved_promptly(fifo).mount_point(), home);
    let socket_row = resolved_promptly(socket);
    assert_eq!(socket_row.mount_point(), home);
    assert_eq!(socket_row.volume_identity(), None);
    assert_eq!(socket_row.volume_name_assurance(), None);
    assert_eq!(socket_row.ejectability(), Ejectability::Unknown);
    assert_eq!(
      resolved_promptly(PathBuf::from("/dev/null")).mount_point(),
      Path::new("/dev")
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

  /// The removal answer a pinned mount is owed: its own flag where the kernel
  /// set it, and otherwise — on macOS — the answer of DiskArbitration's
  /// description bound to it, and nothing on the other Apple platforms.
  fn owed_removal(pinned: &rustix::fd::OwnedFd) -> Ejectability {
    let fs = rustix::fs::fstatfs(pinned).unwrap();
    match ejectability_from_flags(fs.f_flags) {
      #[cfg(target_os = "macos")]
      Ejectability::Unknown => disk_arbitration::removal(pinned, &fs, &Fields::of(&fs).unwrap()),
      kernel => kernel,
    }
  }

  /// A resolve's removal answer is the pinned mount's own flag where the
  /// kernel set it — `Ejectable` — and otherwise the description bound to the
  /// mount: see [`owed_removal`].
  ///
  /// It used to be Foundation's two removal keys, asked by pathname and kept
  /// where the volume that answered named itself by the pinned volume's UUID.
  /// A UUID names a volume and not a mount, so another volume carrying the same
  /// one could answer for this one — and for a USB disk the two keys say no
  /// regardless, which made every external disk a denial.
  #[test]
  fn test_the_removal_answer_is_the_pinned_mounts_own_flag_or_its_bound_description() {
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
      let answer = resolve(&path).unwrap().mount_info().ejectability();
      assert_eq!(answer, owed_removal(&pinned), "{path:?}");
    }
  }

  /// A listing row is one observation of its own mount root, exactly as a
  /// resolve's is: every value in it is what that pinned root answers, and its
  /// removal answer is the one that root is owed — see [`owed_removal`].
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
      assert_eq!(row.ejectability(), owed_removal(&pinned), "{row:?}");
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
  /// this crate owns, and every row is one of its entries: each mount point
  /// the census calls local and browsable is listed once, in the census's
  /// order, and nothing else is — where two entries name one path, only the
  /// mount a pin of it reaches can be listed.
  #[cfg(feature = "list")]
  #[test]
  fn test_the_listing_is_the_local_browsable_entries_of_the_census() {
    let census: Vec<libc::statfs> = mount_table().unwrap().into_iter().collect();
    let mount_point = |entry: &libc::statfs| c_chars_as_bytes(&entry.f_mntonname).to_vec();
    assert!(
      census.iter().any(|entry| mount_point(entry) == b"/"),
      "the root is always mounted"
    );
    let mut expected: Vec<Vec<u8>> = Vec::new();
    for entry in census
      .iter()
      .filter(|entry| is_local_and_browsable(entry.f_flags))
    {
      if !expected.contains(&mount_point(entry)) {
        expected.push(mount_point(entry));
      }
    }
    let listed: Vec<Vec<u8>> = list(super::super::ListOptions::all())
      .unwrap()
      .iter()
      .map(|row| row.mount_point().as_os_str().as_bytes().to_vec())
      .collect();
    assert_eq!(listed, expected);
  }

  /// **A mount point binds nothing: a listing row is the one census entry its
  /// pin is.** The root's own entry is its pin's; an entry of a mount the
  /// root covers — same path, another source — is not, and a mount another
  /// filesystem id names is not; and two entries its pin matches are no one
  /// entry, so none is taken.
  #[cfg(feature = "list")]
  #[test]
  fn test_a_listing_row_is_the_one_census_entry_its_pin_is() {
    let census: Vec<libc::statfs> = mount_table().unwrap().into_iter().collect();
    let root = *census
      .iter()
      .find(|entry| c_chars_as_bytes(&entry.f_mntonname) == b"/")
      .expect("the root is always mounted");
    let pinned = Observation::of(native(Path::new("/"))).required().unwrap();

    let mut covered = root;
    covered.f_mntfromname = [0; 1024];
    for (slot, byte) in covered.f_mntfromname.iter_mut().zip(b"/dev/disk99s1") {
      *slot = *byte as core::ffi::c_char;
    }
    let mut elsewhere = root;
    // SAFETY: `fsid_t` is eight bytes with no padding, and any eight bytes
    // are one.
    unsafe {
      core::ptr::write(
        core::ptr::from_mut(&mut elsewhere.f_fsid).cast::<[u8; FSID_LEN]>(),
        [0xAB; FSID_LEN],
      );
    }
    assert!(fsid_bytes(&elsewhere) != fsid_bytes(&root));

    assert!(pinned.census_entry_among(&[&root]).is_some());
    assert!(
      pinned
        .census_entry_among(&[&covered, &root])
        .is_some_and(|entry| is_same_mount(entry, &root)),
      "the pin is the mount on top, and the covered one is not listed"
    );
    assert!(pinned.census_entry_among(&[&covered]).is_none());
    assert!(pinned.census_entry_among(&[&elsewhere]).is_none());
    assert!(
      pinned.census_entry_among(&[&root, &root]).is_none(),
      "two entries the pin matches are no one entry"
    );
    assert!(pinned.census_entry_among(&[]).is_none());
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
      assert!(names_optical_or_floppy(device.as_bytes()), "{device}");
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
      assert!(!names_optical_or_floppy(device.as_bytes()), "{device}");
      assert_eq!(
        ejectability_of_source(b"cd9660", device.as_bytes()),
        Ejectability::Unknown,
        "{device}"
      );
    }
  }

  /// **A source text is not a binding.** A user-space filesystem names
  /// whatever it likes — `/dev/cd0a` included — and its type says it is one, so
  /// it says nothing about removal; and a kernel filesystem's source that is
  /// no device node now binds nothing either.
  #[test]
  fn test_a_source_binds_only_where_the_kernel_opened_it() {
    for fs_type in [
      "fusefs",
      "fusefs.sshfs",
      "fuse",
      "puffs|p2k|ffs",
      "tmpfs",
      "nfs",
      "zfs",
      "",
    ] {
      assert!(
        !super::super::is_kernel_disk_filesystem(fs_type.as_bytes()),
        "{fs_type}"
      );
      assert_eq!(
        ejectability_of_source(fs_type.as_bytes(), b"/dev/cd0a"),
        Ejectability::Unknown,
        "{fs_type}"
      );
    }
    for fs_type in ["cd9660", "udf", "msdosfs", "msdos", "ufs", "ffs", "ext2fs"] {
      assert!(
        super::super::is_kernel_disk_filesystem(fs_type.as_bytes()),
        "{fs_type}"
      );
    }
    // A device node binds where the type proves the kernel opened it, and a
    // path that is no device binds nothing.
    assert!(super::super::source_is_bound(b"ufs", b"/dev/null"));
    assert!(!super::super::source_is_bound(b"fusefs", b"/dev/null"));
    assert!(!super::super::source_is_bound(b"ufs", b"/"));
    assert!(!super::super::source_is_bound(
      b"ufs",
      b"/dev/no-such-device"
    ));
  }
}
