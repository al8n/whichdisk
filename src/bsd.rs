//! Apple platforms and FreeBSD, OpenBSD and DragonFly: every value in a row
//! comes from one observation of one mount.
//!
//! **On Apple platforms an observation is formed once, from one native
//! identity, and a row is built from nothing else.** The identity is a path's
//! own filesystem bytes — `realpath`'s answer, copied once into owned storage
//! — and those same bytes are what is pinned. A listing pins nothing: each of
//! its rows is one census entry, and no mount is reached by pathname — see
//! `list`. The observation is the pinned descriptor and its own
//! `fstatfs`, or, for a path this process may reach but not open, the path's
//! one `statfs` and nothing more; the row is built by
//! `Observation::into_row`, whose only input is the observation itself, and
//! pinning a path is private to the `observed` module, so no row road can do
//! it. Path
//! text and `st_dev` identify nothing: where a firmlink spells the path
//! differently from its mount point, the split is asked of the pinned
//! descriptor itself.
//!
//! **Every platform read on Apple platforms answers one of four outcomes** — a
//! value, the platform's own "there is none", a decline `declined` names, or
//! a failure — and no two are merged except where a caller names what each
//! means: see `Reading`. These names, and the others this module's shared
//! docs give that the other BSDs do not build, are spelled rather than
//! linked, so the docs build on every platform this file serves.
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
/// rest. The row is built by `Observation::into_row`. See `Observation::of`
/// for a path that cannot be opened, and `Observation::ejectability` for the
/// removal answer. A listing row is its census entry instead: see `list`.
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
    let relative_offset =
      super::split_beneath(canonical.as_os_str().as_bytes(), mount_point.as_bytes())?;
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
      ejectability: ejectability_of_source(fs_type.as_bytes(), source.as_bytes(), fsid_word(&fs)),
      device: source,
      capabilities: volume_capabilities(&canonical, fs_type.as_bytes()),
      volume_identity: volume_identity(&canonical),
      volume_name: volume_name(&canonical),
      #[cfg(feature = "disk-usage")]
      capacity: Some((total_bytes, available_bytes)),
    };
    (mount, relative_offset)
  };

  Ok(Inner {
    mount,
    canonical,
    relative_offset,
  })
}

/// Whether `path` names its object through a firmlink beneath `mount_point`:
/// the shape a firmlink gives, and the only one in which a path lies beneath a
/// mount point none of its own directories is. A firmlink joins the sealed
/// system volume's namespace to the data volume's, so `realpath` answers
/// `/Users/...` while the mount is `/System/Volumes/Data`, and the mount point
/// followed by the path, `/System/Volumes/Data/Users/...`, names the same
/// file.
///
/// **Decided by the file system, never by a spelling**: the deepest of the
/// path and its ancestors below the root that `node_of` names — the object's
/// own file through its descriptor, where the observation holds one — must
/// be the very file the mount point followed by that same spelling names. A
/// name `node_of` cannot read is passed over for the directory above it, and
/// none that reads is no firmlink.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn firmlinked(
  path: &[u8],
  mount_point: &[u8],
  mut node_of: impl FnMut(&[u8]) -> std::io::Result<Option<super::Node>>,
) -> std::io::Result<bool> {
  let mut end = path.len();
  while end > 1 {
    let anchor = &path[..end];
    if let Some(node) = node_of(anchor)? {
      return Ok(node_of(&[mount_point, anchor].concat())? == Some(node));
    }
    end = path[..end]
      .iter()
      .rposition(|&byte| byte == b'/')
      .unwrap_or(0);
  }
  Ok(false)
}

/// Apple platforms: every mount in the kernel's mount table that says of
/// itself that it is local and browsable, **each row built out of its own
/// census entry and nothing a pathname reaches**.
///
/// **No mount is reached by pathname before it is bound.** Pinning a mount
/// point is a lookup of every component of its path, and a lookup crosses
/// every mount on the way: a local volume mounted beneath a network share —
/// `/Volumes/Share/usb` — is reached only through the share, and an
/// unreachable server holds the listing there before any binding could be
/// checked; a network mount made over a path between the census and the pin
/// is crossed the same way. Apple offers no open that stays off the mounts on
/// the way: `openbyid_np` needs a platform binary or an entitlement, and
/// opens by the path it builds (XNU `bsd/vfs/vfs_syscalls.c`,
/// `vfs_context_can_open_by_id`, then `fsgetpath_internal` and
/// `openat_internal`); `O_RESOLVE_BENEATH` keeps a lookup beneath its
/// directory, not off a mount; `fsgetpath` answers a path. So a listing row
/// is its census entry: the mount point, the source, the filesystem type and
/// the capacity `getfsstat` wrote into it, and the capabilities that type
/// implies — and none of what only a descriptor on the mount answers: no
/// identity, no label (the caller names the volume from its mount point), and
/// no case flags beyond the type's. A resolve, which pins the path its caller
/// named, keeps every one of them.
///
/// **The census entry's own flags decide what is listed**: stored locally
/// (`MNT_LOCAL`) and meant to be browsed (`MNT_DONTBROWSE` clear). Every such
/// entry is its own row, a mount another covers at the same path among them:
/// each row says only what its own entry says.
///
/// The removal answer is the entry's own `MNT_REMOVABLE`, and on macOS, where
/// that says nothing, DiskArbitration's answer about the disk the entry names,
/// bound to the entry by the device number the kernel wrote into its
/// filesystem id and by its mount point, and held by the census itself: taken
/// again after every answer, the entry must still be there, the same mount,
/// or the answer is its flag's — see
/// [`census_removal`](disk_arbitration::census_removal).
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(super) fn list(opts: super::ListOptions) -> std::io::Result<Vec<super::MountPoint>> {
  // Every entry decoded whole before any is weighed: see [`Fields`].
  let entries = decoded_census()?;
  let answered: Vec<(&libc::statfs, &Fields, Ejectability)> = entries
    .iter()
    .filter(|(entry, _)| is_local_and_browsable(entry.f_flags))
    .map(|(entry, fields)| (entry, fields, census_ejectability(entry, fields)))
    .collect();
  // The census again, after every answer: an answer asked of anything beside
  // the entry's own flags stands only where the entry is still the same mount.
  let again = decoded_census()?;
  let mut mounts = Vec::new();
  for (entry, fields, answer) in answered {
    let flag = ejectability_from_flags(entry.f_flags);
    let answer = if again.iter().any(|(now, _)| is_same_mount(now, entry)) {
      answer
    } else {
      flag
    };
    // Exact states: a volume of unknown ejectability is named by neither
    // only-filter, so it is excluded by either. See `ListOptions::excludes`.
    if opts.excludes(answer) {
      continue;
    }
    mounts.push(census_row(entry, fields, answer));
  }
  Ok(mounts)
}

/// One census, every entry decoded whole: see [`Fields`].
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn decoded_census() -> std::io::Result<Vec<(libc::statfs, Fields)>> {
  mount_table()?
    .into_iter()
    .map(|entry| Fields::of(&entry).map(|fields| (entry, fields)))
    .collect()
}

/// What a census entry says about removal: its own `MNT_REMOVABLE`, and on
/// macOS, where that says nothing, DiskArbitration's answer bound to the
/// entry — see [`census_removal`](disk_arbitration::census_removal).
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn census_ejectability(entry: &libc::statfs, fields: &Fields) -> Ejectability {
  match ejectability_from_flags(entry.f_flags) {
    #[cfg(target_os = "macos")]
    Ejectability::Unknown => disk_arbitration::census_removal(entry, fields),
    kernel => {
      let _ = fields;
      kernel
    }
  }
}

/// A listing row out of one census entry and nothing else: see [`list`].
#[cfg(feature = "list")]
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
fn census_row(
  entry: &libc::statfs,
  fields: &Fields,
  ejectability: Ejectability,
) -> super::MountPoint {
  #[cfg(feature = "disk-usage")]
  #[allow(clippy::unnecessary_cast)]
  let (total_bytes, available_bytes) = {
    let bsize = entry.f_bsize as u64;
    (
      (entry.f_blocks as u64).saturating_mul(bsize),
      (entry.f_bavail as u64).saturating_mul(bsize),
    )
  };
  #[cfg(not(feature = "disk-usage"))]
  let _ = entry;
  super::MountPoint {
    mount_point: fields.mount_point.clone(),
    device: fields.source.clone(),
    ejectability,
    capabilities: VolumeCapabilities::from_fs_type(fields.fs_type.as_bytes()),
    volume_identity: None,
    volume_name: None,
    #[cfg(feature = "disk-usage")]
    capacity: Some((total_bytes, available_bytes)),
  }
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
const FSID_LEN: usize = 8;

const _: () = assert!(core::mem::size_of::<libc::fsid_t>() == FSID_LEN);

/// The first word of a mount's filesystem id, `f_fsid`, as the kernel wrote
/// it: the number of the device a disk filesystem was mounted from, for the
/// types [`names_its_device_in_fsid`](super::names_its_device_in_fsid)
/// names. See [`source_is_bound`](super::source_is_bound).
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn fsid_word(fs: &libc::statfs) -> i32 {
  let bytes = fsid_bytes(fs);
  i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
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
/// held in the observation: what `realpath` answered for a resolve. Those
/// bytes are what is pinned; a listing pins nothing — see `list`. The row is then built by
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
    super::{
      Ejectability, MountPoint, Node, VolumeCapabilities, node_at, not_beneath, split_beneath_with,
    },
    AttrTarget, Fields, Reading, ejectability_from_flags, firmlinked, is_same_mount, reading,
    volume_capabilities_at, volume_identity_at, volume_name_at,
  };

  /// One observation of one mount, which is everything an Apple row is built
  /// from.
  pub(super) struct Observation {
    /// The native filesystem bytes this observation was formed from.
    native: CString,
    /// The descriptor every descriptor-addressable value is read through, or
    /// `None` for a path this process may reach but not open, or whose mount
    /// no witness could hold.
    pinned: Option<OwnedFd>,
    /// The observation's witness: the mount's root directory, opened for
    /// reading and proven to be the pinned object's mount — see
    /// [`mount_witness`]. Held, and read for nothing, for as long as the
    /// observation is, so that an unmount that is not forced is refused while
    /// every fact of the row is read. `None` exactly where `pinned` is.
    _witness: Option<OwnedFd>,
    /// The descriptor's own `fstatfs`, or, with no descriptor, the path's one
    /// `statfs`.
    fs: rustix::fs::StatFs,
    /// The mount point, the source and the filesystem type out of `fs`,
    /// decoded whole when the observation was formed: see [`Fields`].
    fields: Fields,
    /// The removal answer, asked the first time it is wanted and kept, so
    /// the platform is asked once: see [`Observation::ejectability`].
    removal: OnceCell<Ejectability>,
  }

  impl Observation {
    /// Pins the object `native` names and forms the one observation every
    /// value of its row comes from.
    ///
    /// **Resolving a path has no side effect on the object.** The object is
    /// asked what it is first, by `stat`, which opens nothing, and only a
    /// regular file or a directory is ever opened: opening a FIFO makes the
    /// caller one of its readers for as long as the descriptor is held, and
    /// opening a serial device raises its DTR line, which resets some boards.
    /// Every other kind — a FIFO, a socket, a device node — is described by
    /// its one `statfs`, as road 2 below describes a path that may not be
    /// opened, and is never opened; so is an object whose `stat` is refused
    /// for want of permission, whose kind is then not known.
    ///
    /// A directory is opened as one, with `O_DIRECTORY`, which XNU checks
    /// before it opens anything: a directory swapped for anything else
    /// between the `stat` and the open is that open's own `ENOTDIR`, and
    /// nothing is opened. Both opens take `O_NOFOLLOW`, so a symbolic link
    /// swapped in at the last component is that open's own `ELOOP`, and
    /// nothing is opened either; the path is `realpath`'s, which holds no
    /// symbolic link, so the flag refuses nothing a caller could name. Either
    /// refusal describes the path by its one `statfs`, like a socket.
    ///
    /// What is left is a race, not a road, and only for a regular file. One
    /// swapped for a FIFO or a device in between — at the last component, or
    /// through a directory above it swapped for a symbolic link, which
    /// `O_NOFOLLOW` does not see — is opened, non-blocking and with no
    /// controlling terminal (see [`pin`]), then found by the descriptor's own
    /// `fstat` to be neither kind, let go unread, and described like one. No
    /// Apple open flag both opens any regular file and refuses a FIFO or a
    /// device before opening it, so that window is narrowed to the two calls,
    /// not closed.
    ///
    /// Two observations:
    ///
    /// 1. **The object opens.** Its `fstatfs` is the observation, and the
    ///    descriptor binds every descriptor-addressable read to it.
    /// 2. **The object is not opened, by its kind or for want of permission**
    ///    — a FIFO, a socket or a device node, which the `stat` finds; a
    ///    `stat` or an open refused with `EACCES` or `EPERM`; and, for an
    ///    object swapped in the race above, an open that no socket answers
    ///    (`EOPNOTSUPP`) or a device node whose device is not there (`ENXIO`)
    ///    — and nothing else. A `statfs` by pathname needs only search
    ///    permission on the directories above an object, so this crate has
    ///    always answered for paths a caller can reach but not open; a
    ///    root-owned event store on the Apple data volume is one, and a socket
    ///    beside the caller's files is another. That one `statfs` is then the
    ///    whole row: the mount point, the source, the filesystem type and the
    ///    capacity, all out of a single call. Only the split of the path
    ///    beneath its mount point is asked of anything else, the files its
    ///    own directories name — see [`Observation::relative_offset`] — and
    ///    nothing else is asked: no identity, no label, nothing established
    ///    about removal, and the capabilities the row's own filesystem type
    ///    implies. See [`answers_without_a_descriptor`].
    ///
    /// **No other descriptor stands in for the object's**: every fact of the
    /// row is read through the object's own descriptor, never off another
    /// object that a name leads to. A mount point and a mount source are
    /// names, reusable both, and a volume UUID names a volume rather than a
    /// mount.
    ///
    /// **The mount is held by a witness, which is read for nothing.** The
    /// object's descriptor is opened `O_EVTONLY` (see [`pin`]), and Apple
    /// documents that such a descriptor does not keep its volume mounted
    /// ("Files opened with this option don't prevent their containing volume
    /// from being unmounted", `FileDescriptor.OpenOptions.eventOnly`; the
    /// `open(2)` manual says the same): XNU counts an event-only reference
    /// apart (`vnode_ref_ext`, `v_kusecount`), and an unmount reclaims a
    /// vnode that only such references hold (`vflush`, and the comment in
    /// `vnode_reclaim_internal`: "unmount of a volume that contains file that
    /// was opened with O_EVTONLY then the vnode can be reclaimed while the
    /// file is still opened"). So the mount's root directory is opened too,
    /// for reading, and kept for the whole observation — see
    /// [`mount_witness`]: every other reference makes a vnode busy, and an
    /// unmount that is not forced answers `EBUSY` while it is held (`vflush`
    /// in `vfs_subr.c`; for the root directory, which `dounmount`'s `vflush`
    /// skips, the filesystem's own unmount — HFS's `hfs_flushfiles`, "root
    /// directory is still open" — measured on APFS and HFS by a law). A forced
    /// unmount revokes every vnode of the mount (`vclean`: the vnode's mount
    /// becomes `dead_mountp`, its operations the dead ones), so no read
    /// through either descriptor can name the mount again. The witness is
    /// bound to the object by its own `fstatfs`: the same filesystem id,
    /// source, type and mount point ([`is_same_mount`]). A pin with no
    /// witness — the root not this caller's to open, not a directory any more,
    /// on another mount, or a descriptor the kernel made event-only — is let
    /// go, and the row is the one `fstatfs` and nothing more, as for road 2.
    ///
    /// **Every other outcome is the open's own.** A path that went away is a
    /// decline, which a resolve reports as its error; descriptor exhaustion
    /// and an I/O error are failures, which it returns as the errors they
    /// are. None of them is a
    /// fact about the object and this process, and none is a reason to
    /// describe the path some other way.
    ///
    /// **Its strings are decoded whole as it is formed.** A mount point, a
    /// source or a filesystem type the kernel could not have written fails
    /// the observation with `InvalidData`: see [`Fields`].
    pub(super) fn of(native: CString) -> Reading<Self> {
      Self::of_with(native, mount_witness)
    }

    /// [`of`](Self::of), with the witness taken by `witness`, which a law
    /// stands in for.
    fn of_with(
      native: CString,
      take_witness: impl FnOnce(&Fields, &rustix::fs::StatFs) -> Reading<Option<OwnedFd>>,
    ) -> Reading<Self> {
      // What the object is, asked without opening it: only a regular file or
      // a directory is ever opened, and a directory only as one. See
      // [`is_openable`].
      let kind = match reading(rustix::fs::stat(native.as_c_str())) {
        Reading::Value(stat) => Some(rustix::fs::FileType::from_raw_mode(stat.st_mode)),
        // A kind this process may not learn is not opened either; the one
        // `statfs` below answers for the path, or refuses it the same way.
        Reading::Declined(err) if answers_without_a_descriptor(&err) => None,
        Reading::Absent => return Reading::Absent,
        Reading::Declined(err) => return Reading::Declined(err),
        Reading::Failed(err) => return Reading::Failed(err),
      };
      let opened = match kind {
        Some(rustix::fs::FileType::Directory) => Some(pin_directory(&native)),
        Some(rustix::fs::FileType::RegularFile) => Some(pin(&native)),
        _ => None,
      };
      let pinned = match opened.map(reading) {
        Some(Reading::Value(pinned)) => Some(pinned),
        // The one observation of a path that may be reached but not opened
        // is the row, and it is asked nothing more: see above. So is a path
        // swapped since the `stat` said what it named: see [`was_swapped`].
        Some(Reading::Declined(err) | Reading::Failed(err))
          if answers_without_a_descriptor(&err) || was_swapped(&err) =>
        {
          None
        }
        Some(Reading::Absent) => return Reading::Absent,
        Some(Reading::Declined(err)) => return Reading::Declined(err),
        Some(Reading::Failed(err)) => return Reading::Failed(err),
        None => None,
      };
      // A descriptor holds the object it was opened on only where that object
      // is still one of the two kinds: a regular file swapped for a FIFO or a
      // device in between is let go, unread, and described like one.
      let pinned = match pinned {
        Some(pinned) => match reading(rustix::fs::fstat(&pinned)) {
          Reading::Value(stat) if is_openable(stat.st_mode) => Some(pinned),
          Reading::Value(_) => None,
          Reading::Absent => return Reading::Absent,
          Reading::Declined(err) => return Reading::Declined(err),
          Reading::Failed(err) => return Reading::Failed(err),
        },
        None => None,
      };
      let observed = match &pinned {
        Some(pinned) => reading(rustix::fs::fstatfs(pinned)),
        None => reading(rustix::fs::statfs(native.as_c_str())),
      };
      let fs = match observed {
        Reading::Value(fs) => fs,
        Reading::Absent => return Reading::Absent,
        Reading::Declined(err) => return Reading::Declined(err),
        Reading::Failed(err) => return Reading::Failed(err),
      };
      let fields = match Fields::of(&fs) {
        Ok(fields) => fields,
        Err(err) => return Reading::Failed(err),
      };
      // Every fact read through the pin is a live mount's only while the
      // mount is held: a pin without a witness is let go, and the row is the
      // one `fstatfs` and nothing more, as for a path that could not be
      // opened.
      let (pinned, witness) = match pinned {
        Some(pinned) => match take_witness(&fields, &fs) {
          Reading::Value(Some(held)) => (Some(pinned), Some(held)),
          Reading::Value(None) | Reading::Absent | Reading::Declined(_) => (None, None),
          Reading::Failed(err) => return Reading::Failed(err),
        },
        None => (None, None),
      };
      Reading::Value(Self {
        native,
        pinned,
        _witness: witness,
        fs,
        fields,
        removal: OnceCell::new(),
      })
    }

    /// The mount point this observation reports.
    pub(super) fn mount_point(&self) -> &[u8] {
      self.fields.mount_point.as_bytes()
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

    /// Where the native path begins beneath this observation's mount point,
    /// as a byte offset into it, **decided by the file system's own names for
    /// files, never by a spelling**: one directory answers to more than one
    /// spelling wherever its file system says so, as a case-insensitive APFS
    /// or HFS+ volume does.
    ///
    /// 1. **Beneath by its own directories**: the mount's root is the file the
    ///    mount point names, and the path splits after the deepest of itself
    ///    and its ancestors that names that file — see
    ///    [`split_beneath_with`].
    /// 2. **Beneath through a firmlink**: where no directory of the path is
    ///    the mount's root, the mount point followed by the path must name
    ///    the very file the path does — see [`firmlinked`] — and the whole
    ///    path beneath `/` is then the part beneath the mount point.
    ///
    /// Each file is named by `lstat`, and the object's own by its descriptor's
    /// `fstat` where the observation holds one, so the split is held to the
    /// object the row was read through. A name the platform declines to
    /// describe is passed over; a read that failed is the error it is. A path
    /// that splits by neither road is refused — see
    /// [`not_beneath`] — and never read as the
    /// mount's root. What this decides is only where the caller's own path
    /// splits, never a value read about a volume.
    pub(super) fn relative_offset(&self) -> std::io::Result<usize> {
      let path = self.native.to_bytes();
      let object = match &self.pinned {
        Some(pinned) => match reading(rustix::fs::fstat(pinned)) {
          Reading::Value(stat) => Some(Node::of(&stat)),
          Reading::Absent | Reading::Declined(_) => None,
          Reading::Failed(err) => return Err(err),
        },
        None => None,
      };
      let node_of = |name: &[u8]| -> std::io::Result<Option<Node>> {
        if name == path && object.is_some() {
          return Ok(object);
        }
        match reading(node_at(name)) {
          Reading::Value(node) => Ok(Some(node)),
          Reading::Absent | Reading::Declined(_) => Ok(None),
          Reading::Failed(err) => Err(err),
        }
      };
      if let Some(offset) = split_beneath_with(path, self.mount_point(), node_of)? {
        return Ok(offset);
      }
      if firmlinked(path, self.mount_point(), node_of)? {
        return Ok(1);
      }
      Err(not_beneath())
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
        capacity: Some((total_bytes, available_bytes)),
      })
    }

    /// Whether a descriptor holds this observation's object.
    #[cfg(test)]
    pub(super) fn is_pinned(&self) -> bool {
      self.pinned.is_some()
    }
  }

  /// The observation's witness for the mount `fs` describes, whose fields are
  /// `fields`: the mount's root directory, opened by its mount point for
  /// reading — `O_RDONLY`, as a directory (`O_DIRECTORY`, which XNU checks
  /// before it opens anything), not following a link at the last component,
  /// non-blocking and with no controlling terminal — and held only where it
  /// is proven to hold that very mount:
  ///
  /// - **its reference is not event-only**: XNU turns an open into an
  ///   event-only one for a process that asked for it on vnodes so tagged
  ///   (`kern.check_openevt`, `P_CHECKOPENEVT`; `vn_open_auth`), and
  ///   `F_GETFL` reports `O_EVTONLY` on the descriptor where it did
  ///   (`kern_descrip.c`);
  /// - **it is on the object's mount**: its own `fstatfs` names the same
  ///   filesystem id, source, type and mount point ([`is_same_mount`]).
  ///
  /// **Opening it has no effect on anything a caller keeps.** A directory's
  /// open reads nothing and writes nothing; a directory carries read leases
  /// only, which a read-only open does not break (`vnode_breaklease`); and
  /// the object the caller named is not opened for reading at all, so it is
  /// never made busy for a delete. What it does do is its purpose: the
  /// mount's root is in use while the observation is formed, so an unmount
  /// that is not forced waits for the resolve.
  ///
  /// `None` where it is not proven, or where the root would not open for a
  /// reason the platform declares — not this caller's to read, gone, not a
  /// directory; a failed open or `fstatfs` is the error it is.
  fn mount_witness(fields: &Fields, fs: &rustix::fs::StatFs) -> Reading<Option<OwnedFd>> {
    use rustix::fs::{Mode, OFlags};

    let Ok(root) = CString::new(fields.mount_point.as_bytes()) else {
      return Reading::Value(None);
    };
    let held = match reading(rustix::fs::open(
      root.as_c_str(),
      OFlags::RDONLY
        | OFlags::DIRECTORY
        | OFlags::NONBLOCK
        | OFlags::NOCTTY
        | OFlags::NOFOLLOW
        | OFlags::CLOEXEC,
      Mode::empty(),
    )) {
      Reading::Value(held) => held,
      Reading::Absent | Reading::Declined(_) => return Reading::Value(None),
      Reading::Failed(err) => return Reading::Failed(err),
    };
    match is_event_only(&held) {
      Ok(false) => {}
      Ok(true) => return Reading::Value(None),
      Err(err) => return reading(Err(err)),
    }
    reading(rustix::fs::fstatfs(&held))
      .and_then(|root_fs| Reading::Value(is_same_mount(&root_fs, fs).then_some(held)))
  }

  /// Whether the kernel made `fd`'s reference event-only: `O_EVTONLY` in
  /// what `F_GETFL` reports (`kern_descrip.c`, which reports the flag it
  /// keeps on the open file).
  fn is_event_only(fd: &OwnedFd) -> std::io::Result<bool> {
    // SAFETY: `F_GETFL` takes no argument and writes nothing; the descriptor
    // is valid for as long as `fd` is borrowed.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
      return Err(std::io::Error::last_os_error());
    }
    Ok(flags & libc::O_EVTONLY != 0)
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

  /// A descriptor on the regular file a row describes, held while the row is
  /// read; a directory is pinned by [`pin_directory`].
  ///
  /// Opened `O_EVTONLY` — the open file-event clients use, which XNU counts
  /// apart from every other (`vnode_ref_ext`: `v_kusecount`), so the object
  /// is not made busy for a delete while it is held. It needs the read
  /// authorization `O_RDONLY` needs (`open1` turns either into `FREAD`),
  /// and `O_RDONLY` stands in where a filesystem refuses the flag. **It
  /// holds nothing**: an event-only descriptor does not keep its volume
  /// mounted, so the observation holds the mount by a witness of its own —
  /// see [`mount_witness`]. The file itself is never read: the descriptor
  /// exists so that `fstatfs` and `fgetattrlist` ask about one object
  /// instead of re-resolving a name five times.
  ///
  /// **Both opens are non-blocking, take no controlling terminal and follow
  /// no symbolic link at the last component** (`O_NONBLOCK`, `O_NOCTTY`,
  /// `O_NOFOLLOW`). The `stat` found a regular file, but the path can name any
  /// object by the time it is opened — see [`Observation::of`] — and an open
  /// for reading waits on a FIFO until a writer arrives, a resolve that never
  /// returned, and a terminal can become the process's controlling terminal.
  /// No flag changes what an open of a regular file does, the path is
  /// `realpath`'s and holds no symbolic link, and the descriptor is never
  /// read. A socket, which no open answers, is left to the descriptor-less
  /// road: see [`answers_without_a_descriptor`].
  fn pin(path: &CStr) -> std::io::Result<OwnedFd> {
    use rustix::{
      fs::{Mode, OFlags},
      io::Errno,
    };

    // `O_EVTONLY` is Apple-only and rustix does not name it, so it is spelled
    // from libc's own constant and carried in as a raw bit.
    let event_only = OFlags::from_bits_retain(libc::O_EVTONLY as u32);
    let quiet = OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
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

  /// A descriptor on a directory — an object a resolve pins that the `stat`
  /// found to be one: see [`Observation::of`]. Opened the way
  /// [`pin`] opens, `O_NOFOLLOW` included, and never read, with `O_DIRECTORY`
  /// besides: XNU refuses anything but a directory with `ENOTDIR` before it
  /// opens it, so a path swapped for a FIFO or a device is never opened here,
  /// and a directory's open neither blocks nor disturbs it.
  fn pin_directory(path: &CStr) -> std::io::Result<OwnedFd> {
    use rustix::{
      fs::{Mode, OFlags},
      io::Errno,
    };

    let event_only = OFlags::from_bits_retain(libc::O_EVTONLY as u32);
    let quiet =
      OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::open(path, event_only | quiet, Mode::empty()) {
      Ok(fd) => Ok(fd),
      Err(Errno::ACCESS | Errno::PERM | Errno::INVAL | Errno::NOTSUP | Errno::OPNOTSUPP) => {
        rustix::fs::open(path, OFlags::RDONLY | quiet, Mode::empty()).map_err(std::io::Error::from)
      }
      Err(errno) => Err(errno.into()),
    }
  }

  /// Whether an object of this mode is one a resolve may open: a regular file
  /// or a directory, and nothing else — see [`Observation::of`].
  fn is_openable(mode: rustix::fs::RawMode) -> bool {
    matches!(
      rustix::fs::FileType::from_raw_mode(mode),
      rustix::fs::FileType::RegularFile | rustix::fs::FileType::Directory
    )
  }

  /// Whether a pin was refused because the path no longer leads where the
  /// `stat` before it said: a directory's pin that found no directory
  /// (`ENOTDIR`, which the same error spells for a directory above the object
  /// swapped for something else), or a symbolic link at the last component,
  /// which `O_NOFOLLOW` refuses (`ELOOP`). Neither open opened anything, and
  /// the path is described by its one `statfs`: see [`Observation::of`].
  fn was_swapped(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP))
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

    let native = CString::new(path.as_os_str().as_bytes()).expect("a path carries no NUL");
    if path.is_dir() {
      pin_directory(&native)
    } else {
      pin(&native)
    }
  }

  #[cfg(test)]
  mod tests {
    use super::*;

    /// **A directory's pin opens nothing else.** XNU checks `O_DIRECTORY`
    /// before it opens anything, so a FIFO answers `ENOTDIR` and gains no
    /// reader: a writer waiting on it waits through every such pin, and one
    /// reader's open afterwards, the control, lets it through. A directory
    /// swapped for a FIFO or a device is refused the same way, by the pin of
    /// a directory a resolve found and by the pin of a parent that splits an
    /// object holding no descriptor.
    #[test]
    fn test_a_directory_pin_refuses_a_fifo_unopened() {
      use std::{os::unix::ffi::OsStrExt as _, sync::mpsc, time::Duration};

      use rustix::fs::{Mode, OFlags};

      let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
      let fifo = CString::new(dir.path().join("fifo").as_os_str().as_bytes()).unwrap();
      // SAFETY: a NUL-terminated path in a directory this law owns.
      assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

      let (opened, writer_opened) = mpsc::channel();
      let _writer = {
        let fifo = fifo.clone();
        std::thread::spawn(move || {
          let writer = rustix::fs::open(
            fifo.as_c_str(),
            OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::empty(),
          );
          let _ = opened.send(writer.is_ok());
        })
      };
      std::thread::sleep(Duration::from_millis(100));
      for _ in 0..50 {
        assert_eq!(
          pin_directory(&fifo)
            .err()
            .and_then(|err| err.raw_os_error()),
          Some(libc::ENOTDIR)
        );
      }
      assert_eq!(
        writer_opened.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "a directory's pin opened the FIFO for reading"
      );

      let _reader = rustix::fs::open(
        fifo.as_c_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
      )
      .unwrap();
      assert_eq!(
        writer_opened.recv_timeout(Duration::from_secs(20)),
        Ok(true),
        "a reader's open lets the waiting writer through"
      );
    }

    /// **Neither pin follows a symbolic link at the last component**, and a
    /// path that no longer leads where its `stat` said is described by its
    /// one `statfs`, unopened. A resolve's path is `realpath`'s and holds no
    /// link, so a link there is one swapped in after the `stat`; this law
    /// hands the observation a link outright, which the `stat` follows to a
    /// directory and to a regular file, and both pins then refuse it — the
    /// directory's pin with `ENOTDIR`, as XNU checks `O_DIRECTORY` first, and
    /// the file's with `ELOOP`.
    #[test]
    fn test_a_link_at_the_last_component_is_never_opened() {
      use std::os::unix::ffi::OsStrExt as _;

      let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
      let target_dir = dir.path().join("dir");
      std::fs::create_dir(&target_dir).unwrap();
      let target_file = dir.path().join("file");
      std::fs::write(&target_file, b"whichdisk").unwrap();
      let to_dir = dir.path().join("to-dir");
      std::os::unix::fs::symlink(&target_dir, &to_dir).unwrap();
      let to_file = dir.path().join("to-file");
      std::os::unix::fs::symlink(&target_file, &to_file).unwrap();
      let native = |path: &std::path::Path| CString::new(path.as_os_str().as_bytes()).unwrap();

      // `O_DIRECTORY` is checked first, and a link is no directory.
      assert_eq!(
        pin_directory(&native(&to_dir))
          .err()
          .and_then(|err| err.raw_os_error()),
        Some(libc::ENOTDIR)
      );
      assert_eq!(
        pin(&native(&to_file))
          .err()
          .and_then(|err| err.raw_os_error()),
        Some(libc::ELOOP)
      );
      for link in [&to_dir, &to_file] {
        let observation = Observation::of(native(link))
          .required()
          .expect("a swapped path is still described");
        assert!(
          !observation.is_pinned(),
          "{} is never opened",
          link.display()
        );
      }
      assert!(
        Observation::of(native(&target_dir))
          .required()
          .unwrap()
          .is_pinned(),
        "the directory itself is pinned"
      );
      for errno in [libc::ENOTDIR, libc::ELOOP] {
        assert!(was_swapped(&std::io::Error::from_raw_os_error(errno)));
      }
      for errno in [libc::ENOENT, libc::EACCES, libc::EIO, libc::EMFILE] {
        assert!(!was_swapped(&std::io::Error::from_raw_os_error(errno)));
      }
    }

    /// **Every local mount point this host lists pins with `O_NOFOLLOW`.** A
    /// resolve of a mount point pins the bytes `realpath` answered, and a
    /// mount point spelled through a symbolic link would be refused
    /// (`ELOOP`) and described by its `statfs` alone. The kernel records the
    /// path it resolved at mount time, which holds no link; this law holds
    /// every mount on the host to that.
    #[test]
    fn test_no_mount_point_is_spelled_through_a_link() {
      let count = unsafe { libc::getfsstat(core::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
      assert!(count > 0, "{}", std::io::Error::last_os_error());
      let mut entries: Vec<libc::statfs> = Vec::with_capacity(count as usize + 8);
      // SAFETY: `entries` has room for its capacity of `statfs` structures,
      // and the call is told that many bytes; it reports how many it wrote.
      let written = unsafe {
        libc::getfsstat(
          entries.as_mut_ptr(),
          (entries.capacity() * core::mem::size_of::<libc::statfs>()) as libc::c_int,
          libc::MNT_NOWAIT,
        )
      };
      assert!(written > 0, "{}", std::io::Error::last_os_error());
      // SAFETY: the call wrote `written` structures, no more than the
      // capacity it was told of.
      unsafe { entries.set_len(written as usize) };
      let mut pinned = 0;
      for entry in &entries {
        if entry.f_flags & libc::MNT_LOCAL as u32 == 0 {
          continue;
        }
        // SAFETY: the kernel terminates `f_mntonname` within its array.
        let mount_point = unsafe { CStr::from_ptr(entry.f_mntonname.as_ptr()) };
        match pin_directory(mount_point) {
          Ok(_) => pinned += 1,
          Err(err) => assert_ne!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "{mount_point:?} is spelled through a symbolic link"
          ),
        }
      }
      assert!(pinned > 0, "the root at least pins");
    }

    /// **A name whose file is not read is passed over.** A socket beneath
    /// `/tmp` — a firmlink to the data volume — is never opened, and splits at
    /// the firmlink by its own file, which `lstat` names; with that refused
    /// (`EPERM`, as the system's privacy controls refuse it), by its parent's,
    /// beneath which the rest of the path is spelled the same; and with every
    /// name refused it does not split at all.
    #[test]
    fn test_a_name_whose_file_is_not_read_is_passed_over() {
      use std::os::unix::ffi::OsStrExt as _;

      let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
      let guarded = dir.path().join("guarded");
      std::fs::create_dir(&guarded).unwrap();
      let socket = guarded.join("socket");
      let _listening = std::os::unix::net::UnixListener::bind(&socket).unwrap();
      let canonical = socket.canonicalize().unwrap();
      let path = canonical.as_os_str().as_bytes();
      let observation = Observation::of(CString::new(path).unwrap())
        .required()
        .unwrap();
      assert!(!observation.is_pinned(), "a socket is never opened");
      if path.starts_with(observation.mount_point()) {
        // No firmlink on the way: nothing to split, and nothing to show.
        return;
      }
      assert_eq!(observation.relative_offset().unwrap(), 1);

      let mount_point = observation.mount_point();
      let read = |name: &[u8]| Ok(Some(node_at(name).unwrap()));
      assert!(firmlinked(path, mount_point, read).unwrap());
      assert!(
        firmlinked(path, mount_point, |name: &[u8]| if name == path {
          Ok(None)
        } else {
          read(name)
        })
        .unwrap(),
        "the parent of an object whose file is refused spells the same split"
      );
      assert!(
        !firmlinked(path, mount_point, |_: &[u8]| Ok(None)).unwrap(),
        "no file named is no split"
      );
    }

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

    /// **The mount is held by the witness, not by the pin.** The root's
    /// observation holds a witness whose reference is not event-only and whose
    /// `fstatfs` is the pinned object's own mount; the pin is event-only. The
    /// planted defect, side by side: the pin alone, which every observation
    /// was held by before, is an event-only reference, which Apple documents
    /// as keeping no volume mounted.
    #[test]
    fn test_the_witness_holds_what_the_pin_does_not() {
      let Reading::Value(observation) = Observation::of(CString::new("/").unwrap()) else {
        panic!("the root observes");
      };
      let (Some(pinned), Some(witness)) = (&observation.pinned, &observation._witness) else {
        panic!("the root is pinned and witnessed");
      };
      assert!(
        !is_event_only(witness).unwrap(),
        "the witness holds its mount"
      );
      let root_fs = rustix::fs::fstatfs(witness).unwrap();
      assert!(super::super::is_same_mount(&root_fs, &observation.fs));

      // The planted defect: the pin alone.
      assert!(
        is_event_only(pinned).unwrap(),
        "the pin is event-only and holds nothing"
      );
    }

    /// **A pin no witness holds is let go.** Where the root would not open,
    /// the row is the one `fstatfs` and nothing more: no identity, no label,
    /// nothing about removal. The planted defect, side by side: the same
    /// object observed with its witness, as the pin alone was observed
    /// before, answers its identity.
    #[test]
    fn test_a_pin_no_witness_holds_is_let_go() {
      let unheld =
        match Observation::of_with(CString::new("/").unwrap(), |_, _| Reading::Value(None)) {
          Reading::Value(observation) => observation,
          _ => panic!("the root observes"),
        };
      assert!(!unheld.is_pinned());
      let row = unheld.into_row().unwrap();
      assert!(row.volume_identity().is_none(), "{row:?}");
      assert!(row.volume_name_assurance().is_none(), "{row:?}");
      assert_eq!(row.ejectability(), Ejectability::Unknown, "{row:?}");

      // The planted defect: the pin read as though it held its mount.
      let Reading::Value(held) = Observation::of(CString::new("/").unwrap()) else {
        panic!("the root observes");
      };
      let row = held.into_row().unwrap();
      assert!(
        row.volume_identity().is_some(),
        "the witnessed root names itself: {row:?}"
      );
    }

    /// **A witnessed observation keeps its mount mounted; the pin alone does
    /// not.** On an APFS and an HFS disk image, each attached at a mount point
    /// of this law's own: an event-only descriptor on a file there does not
    /// stop an unmount that is not forced — the planted defect, the pin every
    /// observation was held by before — while an observation of that file,
    /// alive, makes the same unmount answer `EBUSY`, and lets it through once
    /// it is dropped. Needs `hdiutil`; a CI step runs it.
    #[test]
    #[ignore = "attaches disk images with hdiutil; a CI step runs it"]
    fn test_a_live_apple_hold_keeps_the_mount_mounted() {
      use std::{
        os::unix::ffi::OsStrExt as _,
        path::{Path, PathBuf},
        process::Command,
        time::Duration,
      };

      fn run(program: &str, args: &[&std::ffi::OsStr]) -> String {
        let output = Command::new(program).args(args).output().unwrap();
        assert!(
          output.status.success(),
          "{program} {args:?}: {}",
          String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
      }
      fn attach(image: &Path, mount: &Path) -> String {
        let out = run(
          "hdiutil",
          &[
            "attach".as_ref(),
            "-nobrowse".as_ref(),
            "-noverify".as_ref(),
            "-noautoopen".as_ref(),
            "-mountpoint".as_ref(),
            mount.as_os_str(),
            image.as_os_str(),
          ],
        );
        out
          .split_whitespace()
          .next()
          .expect("hdiutil names the device it attached")
          .to_owned()
      }
      fn detach(device: &str) {
        let _ = Command::new("hdiutil")
          .args(["detach", "-force", device])
          .output();
      }
      /// Whether an unmount that is not forced took the mount away.
      fn unmounted(mount: &Path) -> bool {
        let native = CString::new(mount.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path, for the call.
        if unsafe { libc::unmount(native.as_ptr(), 0) } == 0 {
          return true;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
          Some(libc::EBUSY) => false,
          Some(libc::EPERM) => Command::new("diskutil")
            .arg("unmount")
            .arg(mount)
            .output()
            .unwrap()
            .status
            .success(),
          _ => panic!("unmount {}: {err}", mount.display()),
        }
      }
      fn eventually_unmounted(mount: &Path) -> bool {
        (0..40).any(|_| {
          unmounted(mount) || {
            std::thread::sleep(Duration::from_millis(250));
            false
          }
        })
      }

      for fs in ["APFS", "HFS+"] {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join(".fseventsd")).unwrap();
        std::fs::write(src.join(".fseventsd").join("no_log"), b"").unwrap();
        std::fs::write(src.join(".metadata_never_index"), b"").unwrap();
        std::fs::write(src.join("file"), b"whichdisk").unwrap();
        let image = dir.path().join("image.dmg");
        let mount: PathBuf = dir.path().join("mnt");
        std::fs::create_dir(&mount).unwrap();
        run(
          "hdiutil",
          &[
            "create".as_ref(),
            "-quiet".as_ref(),
            "-srcfolder".as_ref(),
            src.as_os_str(),
            "-fs".as_ref(),
            fs.as_ref(),
            "-volname".as_ref(),
            "WDHOLD".as_ref(),
            "-format".as_ref(),
            "UDRW".as_ref(),
            image.as_os_str(),
          ],
        );

        // The planted defect: an event-only descriptor on a file, alone.
        let device = attach(&image, &mount);
        let mount = std::fs::canonicalize(&mount).unwrap();
        let file = mount.join("file");
        let event_only = rustix::fs::open(
          &file,
          rustix::fs::OFlags::from_bits_retain(libc::O_EVTONLY as u32)
            | rustix::fs::OFlags::CLOEXEC,
          rustix::fs::Mode::empty(),
        )
        .unwrap();
        let let_go = eventually_unmounted(&mount);
        drop(event_only);
        detach(&device);
        println!("{fs}: an event-only descriptor alone let the unmount through: {let_go}");
        assert!(
          let_go,
          "{fs}: an event-only descriptor held the mount, or something else did"
        );

        // The witnessed observation.
        let device = attach(&image, &mount);
        let native = CString::new(file.as_os_str().as_bytes()).unwrap();
        let Reading::Value(observation) = Observation::of(native) else {
          detach(&device);
          panic!("{fs}: the file observes");
        };
        assert!(
          observation.is_pinned(),
          "{fs}: the file is pinned and witnessed"
        );
        let while_held = unmounted(&mount);
        drop(observation);
        let after = eventually_unmounted(&mount);
        detach(&device);
        println!("{fs}: unmounted while observed: {while_held}; once dropped: {after}");
        assert!(!while_held, "{fs}: the witness did not hold the mount");
        assert!(
          after,
          "{fs}: the mount stayed held once the observation was dropped"
        );
      }
    }

    /// The pinned object's own file is the one its mount point followed by its
    /// firmlinked path names: `/Users`, through its descriptor, is the file
    /// `/System/Volumes/Data/Users` names, and not the file `/` names.
    #[test]
    fn test_the_descriptor_names_the_file_its_firmlink_spells() {
      let observation = Observation::of(CString::new("/Users").unwrap())
        .required()
        .unwrap();
      if observation.mount_point() != b"/System/Volumes/Data" {
        // A system without the split system volume: nothing to prove here.
        return;
      }
      let pinned = observation.pinned.as_ref().expect("/Users opens");
      let object = Node::of(&rustix::fs::fstat(pinned).unwrap());
      assert_eq!(node_at(b"/System/Volumes/Data/Users").unwrap(), object);
      assert_ne!(node_at(b"/").unwrap(), object);
      assert_ne!(
        node_at(b"/System/Volumes/Data").unwrap(),
        node_at(b"/").unwrap(),
        "the data volume's root is not the system volume's, whatever device they share"
      );
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
/// The observation's witness keeps its mount mounted — the mount's root
/// directory, held open for reading, which makes an unmount that is not
/// forced answer `EBUSY`; the object's own descriptor is event-only and
/// would not — and a forced unmount revokes every vnode of the mount, so no
/// `fstatfs` through the descriptor names it again: a mount that still
/// answers the same `fstatfs` after the description was read is the mount
/// the description was about, and the device it names has not been handed
/// on in between. A resolve whose mount no witness holds asks nothing of
/// DiskArbitration. Any check that fails
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
  use core::{
    ffi::{c_char, c_void},
    ptr::NonNull,
  };
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
  ///
  /// **It is never null**, by its type: `CFRelease(NULL)` aborts the process,
  /// and the *Create* and *Copy* functions here answer null for a disk that is
  /// gone or was never there, so an owner of a null — even one built only to
  /// be dropped — would turn an ordinary race into a crash.
  struct Created(NonNull<c_void>);

  impl Created {
    /// Takes an object a *Create* or *Copy* function returned, which the
    /// caller owns, or `None` for the null it returns when it has none. No
    /// owner is built for a null, so nothing is released for one.
    fn of(object: CFTypeRef) -> Option<Self> {
      NonNull::new(object.cast_mut()).map(Self)
    }

    /// The object, for a call; `self` keeps it alive while it is borrowed.
    fn get(&self) -> CFTypeRef {
      self.0.as_ptr().cast_const()
    }
  }

  impl Drop for Created {
    fn drop(&mut self) {
      // SAFETY: a non-null object from a Create or Copy function, owned by
      // this value alone and released once, here.
      unsafe { CFRelease(self.get()) };
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

  /// The description of the disk the mount `fs` — its fields `fields` — was
  /// mounted from, where it is bound to that mount: steps 1 and 2 of the
  /// module's hold-and-verify, which a caller then holds, by the descriptor
  /// or by the census. `None` where it is not bound, or not there.
  fn bound_description(fs: &libc::statfs, fields: &Fields) -> Option<Description> {
    // 1. The device the mount's own `statfs` names.
    let name = fields
      .source
      .as_bytes()
      .strip_prefix(b"/dev/")
      .and_then(|name| CString::new(name).ok())?;
    // 2. Its description: about that disk, which is the device the kernel
    // mounted — the one the filesystem id carries — and mounted where the
    // mount is.
    let description = describe(&name)?;
    let mounted_from = super::fsid_device(fs);
    (description.bsd_name.as_deref() == Some(name.to_bytes())
      && description.device == Some(mounted_from)
      && description.volume_path.as_deref() == Some(fields.mount_point.as_bytes()))
    .then_some(description)
  }

  /// The removal answer of the disk a listing's census entry, `entry`, was
  /// mounted from: DiskArbitration's, where the description is bound to the
  /// entry — steps 1 and 2 of the module's hold-and-verify, with the entry's
  /// own filesystem id and mount point — and `Unknown` otherwise. No
  /// descriptor holds the mount: the listing takes the census again after the
  /// answers, and an answer whose entry is not still the same mount does not
  /// stand — see [`list`](super::list).
  #[cfg(feature = "list")]
  pub(super) fn census_removal(entry: &libc::statfs, fields: &Fields) -> Ejectability {
    bound_description(entry, fields)
      .map_or(Ejectability::Unknown, |description| description.removal())
  }

  /// The removal answer of the disk the pinned mount `fields` was read from
  /// is on: DiskArbitration's, where the description is bound to the mount by
  /// hold-and-verify — see the module's documentation — and `Unknown`
  /// otherwise.
  pub(super) fn removal(pinned: &OwnedFd, fs: &libc::statfs, fields: &Fields) -> Ejectability {
    let Some(description) = bound_description(fs, fields) else {
      return Ejectability::Unknown;
    };
    let mounted_from = super::fsid_device(fs);
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
    let disk = Created::of(unsafe {
      DADiskCreateFromBSDName(core::ptr::null(), session.get(), name.as_ptr())
    })?;
    // SAFETY: a live disk; the dictionary returned is a copy this module owns,
    // released by `Created`.
    let description = Created::of(unsafe { DADiskCopyDescription(disk.get()) })?;
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
    let value = unsafe { CFDictionaryGetValue(dictionary.get(), key) };
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

    /// A disk that is not there has no description, and the null
    /// DiskArbitration answers for it is never owned, so nothing is released
    /// for it. An owner built before the null check (`then_some(Self(object))`)
    /// is dropped at once on the null and aborts this process in `CFRelease`.
    #[test]
    fn test_a_disk_that_is_not_there_is_no_description() {
      assert!(Created::of(core::ptr::null()).is_none());
      assert_eq!(describe(c"disk-that-is-not-there"), None);
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

    /// Every listed volume answers what its census entry's flag says, and,
    /// where that says nothing, what the description bound to that entry
    /// says. Measured: this law prints every volume's answer and the
    /// description it came from.
    #[cfg(feature = "list")]
    #[test]
    fn test_every_listed_volume_on_this_machine_answers_by_its_flag_or_its_description() {
      use std::os::unix::ffi::OsStrExt as _;

      let census = super::super::decoded_census().unwrap();
      for row in crate::list().unwrap() {
        let (entry, fields) = census
          .iter()
          .find(|(_, fields)| {
            fields.mount_point.as_bytes() == row.mount_point().as_os_str().as_bytes()
              && fields.source.as_bytes() == row.device().as_bytes()
          })
          .expect("every row is a census entry");
        let name = fields.source.as_bytes().strip_prefix(b"/dev/");
        let description = name.and_then(|name| describe(&CString::new(name).unwrap()));
        let expected = match super::super::ejectability_from_flags(entry.f_flags) {
          Ejectability::Unknown => census_removal(entry, fields),
          kernel => kernel,
        };
        println!(
          "{} on {}: {:?} (MNT_REMOVABLE {}) {description:?}",
          row.mount_point().display(),
          String::from_utf8_lossy(row.device().as_bytes()),
          row.ejectability(),
          entry.f_flags & super::super::MNT_REMOVABLE != 0,
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
    let ejectability = ejectability_of_source(fs_type, device_bytes, fsid_word(entry));
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
      capacity: Some((total_bytes, available_bytes)),
    });
  }
  Ok(mounts)
}

/// What a FreeBSD, OpenBSD or DragonFly mount's source can say about
/// removal: a yes where the source is bound to the mount and names a class of
/// drive that is only ever removable media, and nothing otherwise.
///
/// **The source must be bound first.** `f_mntfromname` is text a user-space
/// filesystem chooses for itself, and a pathname can be an alias, so a name
/// is read only where the kernel's own filesystem type proves the kernel
/// opened a device, and the node the name spells — itself, never through a
/// symbolic link — carries the number of the device the mount's own id,
/// `mounted_from`, says it was mounted from: see
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
fn ejectability_of_source(fs_type: &[u8], source: &[u8], mounted_from: i32) -> Ejectability {
  if names_optical_or_floppy(source) && super::source_is_bound(fs_type, source, mounted_from) {
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

  /// **A FIFO, a socket and a device node resolve at once, and none of them is
  /// opened.** The object is asked what it is by `stat` first, and anything
  /// but a regular file or a directory is described by its one `statfs`: no
  /// descriptor, no identity, no label and nothing about removal. Beneath a
  /// firmlink — `/tmp` is `/private/tmp`, on the data volume — each still
  /// splits where the regular file beside it does, through its parent
  /// directory's own word.
  #[test]
  fn test_a_fifo_a_socket_and_a_device_node_resolve_at_once_unopened() {
    use std::{sync::mpsc, time::Duration};

    let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"whichdisk").unwrap();
    let fifo = dir.path().join("fifo");
    let native_fifo = native(&fifo);
    // SAFETY: a NUL-terminated path in a directory this law owns.
    assert_eq!(unsafe { libc::mkfifo(native_fifo.as_ptr(), 0o600) }, 0);
    let socket = dir.path().join("socket");
    let _listening = std::os::unix::net::UnixListener::bind(&socket).unwrap();

    let resolved_promptly = |path: &Path| {
      let (answer, answered) = mpsc::channel();
      let asked = path.to_path_buf();
      std::thread::spawn(move || {
        let _ = answer.send(resolve(&asked).map(|location| {
          (
            location.mount_info().clone(),
            location.relative_path().to_path_buf(),
          )
        }));
      });
      answered
        .recv_timeout(Duration::from_secs(20))
        .unwrap_or_else(|_| panic!("{} did not resolve promptly", path.display()))
        .unwrap_or_else(|err| panic!("{} did not resolve: {err}", path.display()))
    };

    let (file_row, file_relative) = resolved_promptly(&file);
    for (path, name) in [(&fifo, "fifo"), (&socket, "socket")] {
      let (row, relative) = resolved_promptly(path);
      assert_eq!(row.mount_point(), file_row.mount_point(), "{name}");
      assert_eq!(
        relative,
        file_relative.with_file_name(name),
        "{name} splits where the file beside it does"
      );
      assert_eq!(row.volume_identity(), None, "{name}");
      assert_eq!(row.volume_name_assurance(), None, "{name}");
      assert_eq!(row.ejectability(), Ejectability::Unknown, "{name}");
      assert!(
        !Observation::of(native(&path.canonicalize().unwrap()))
          .required()
          .unwrap()
          .is_pinned(),
        "{name} is never opened"
      );
    }
    let (null_row, _) = resolved_promptly(Path::new("/dev/null"));
    assert_eq!(null_row.mount_point(), Path::new("/dev"));
    assert!(
      !Observation::of(native(Path::new("/dev/null")))
        .required()
        .unwrap()
        .is_pinned(),
      "a device node is never opened"
    );
  }

  /// **A FIFO never gains a reader from a resolve.** A writer's open of a FIFO
  /// waits until some process opens it for reading, and one reader's open,
  /// however brief, lets it through. So a writer waiting on the FIFO waits
  /// through every resolve of it — `canonicalize` included — and one reader's
  /// open afterwards, the control, is what lets it through.
  #[test]
  fn test_a_fifo_never_gains_a_reader_from_a_resolve() {
    use std::{sync::mpsc, time::Duration};

    use rustix::fs::{Mode, OFlags};

    let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let fifo = dir.path().join("fifo");
    let native_fifo = native(&fifo);
    // SAFETY: a NUL-terminated path in a directory this law owns.
    assert_eq!(unsafe { libc::mkfifo(native_fifo.as_ptr(), 0o600) }, 0);

    let (opened, writer_opened) = mpsc::channel();
    let _writer = {
      let native_fifo = native_fifo.clone();
      std::thread::spawn(move || {
        let writer = rustix::fs::open(
          native_fifo.as_c_str(),
          OFlags::WRONLY | OFlags::CLOEXEC,
          Mode::empty(),
        );
        let _ = opened.send(writer.is_ok());
      })
    };
    std::thread::sleep(Duration::from_millis(100));
    for _ in 0..200 {
      resolve(&fifo).unwrap();
    }
    assert_eq!(
      writer_opened.try_recv(),
      Err(mpsc::TryRecvError::Empty),
      "a resolve opened the FIFO for reading"
    );

    let _reader = rustix::fs::open(
      native_fifo.as_c_str(),
      OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
      Mode::empty(),
    )
    .unwrap();
    assert_eq!(
      writer_opened.recv_timeout(Duration::from_secs(20)),
      Ok(true),
      "a reader's open lets the waiting writer through"
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

  /// **A listing row is its own census entry, and nothing a pathname
  /// reaches.** Every row is a local, browsable entry of the census, its mount
  /// point and source the entry's; it carries no identity and no label of its
  /// own, which only a descriptor on the mount answers — the name falls back
  /// to the mount point — and its removal answer is its entry's flag's, or,
  /// where that says nothing, the description bound to the entry.
  #[cfg(feature = "list")]
  #[test]
  fn test_a_listing_row_is_its_census_entry() {
    let census = decoded_census().unwrap();
    let rows = list(super::super::ListOptions::all()).unwrap();
    assert!(!rows.is_empty(), "the boot volume is always listed");
    for row in rows {
      let (entry, fields) = census
        .iter()
        .find(|(_, fields)| {
          fields.mount_point.as_bytes() == row.mount_point().as_os_str().as_bytes()
            && fields.source.as_bytes() == row.device().as_bytes()
        })
        .expect("every row is a census entry");
      assert!(is_local_and_browsable(entry.f_flags), "{row:?}");
      assert_eq!(row.volume_identity(), None, "{row:?}");
      assert_eq!(row.volume_name_assurance(), None, "{row:?}");
      assert_eq!(
        row.ejectability(),
        census_ejectability(entry, fields),
        "{row:?}"
      );
    }
  }

  /// The listing is the kernel's mount table read as a census into a buffer
  /// this crate owns, and every row is one of its entries: every entry that
  /// says it is local and browsable is listed, in the order of the census,
  /// and nothing else is.
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

  /// A census entry at `mount_point`, mounted from `source`, of `fs_type`,
  /// with `flags`, as the kernel writes one, and its fields.
  #[cfg(feature = "list")]
  fn census_entry(
    mount_point: &str,
    source: &str,
    fs_type: &str,
    flags: u32,
  ) -> (libc::statfs, Fields) {
    fn fill(slots: &mut [core::ffi::c_char], text: &str) {
      for (slot, byte) in slots.iter_mut().zip(text.bytes()) {
        *slot = byte as core::ffi::c_char;
      }
    }
    // SAFETY: `libc::statfs` is a C structure of integers and arrays of them,
    // for which all-zero bytes are a valid value.
    let mut entry: libc::statfs = unsafe { core::mem::zeroed() };
    fill(&mut entry.f_mntonname, mount_point);
    fill(&mut entry.f_mntfromname, source);
    fill(&mut entry.f_fstypename, fs_type);
    entry.f_flags = flags;
    let fields = Fields::of(&entry).unwrap();
    (entry, fields)
  }

  /// **A local child under a remote parent is never reached by pathname.** A
  /// listing builds each row out of its own census entry and nothing else, so
  /// a local volume mounted beneath a network share, one a share covers, and
  /// one that covers a share are each listed as its entry says, and no path
  /// is opened or looked up for any of them: the row is built from the entry
  /// alone. The remote entries are not listed. The planted defect, side by
  /// side: the listing as it was grouped the entries by mount point and
  /// pinned a path whose every entry was local — the child beneath the share
  /// among them — and a pin of that path is a lookup through the share.
  #[cfg(feature = "list")]
  #[test]
  fn test_a_local_child_under_a_remote_parent_is_never_reached_by_pathname() {
    let local = libc::MNT_LOCAL as u32;
    let remote = 0u32;
    let entries = [
      census_entry("/", "/dev/disk3s1s1", "apfs", local),
      census_entry("/Volumes/Share", "//guest@server/share", "smbfs", remote),
      census_entry("/Volumes/Share/usb", "/dev/disk4s1", "msdos", local),
      census_entry("/Volumes/USB", "/dev/disk5s1", "msdos", local),
      census_entry("/Volumes/USB", "//guest@server/other", "smbfs", remote),
    ];
    let rows: Vec<(Vec<u8>, Vec<u8>)> = entries
      .iter()
      .filter(|(entry, _)| is_local_and_browsable(entry.f_flags))
      .map(|(entry, fields)| {
        let row = census_row(entry, fields, Ejectability::Unknown);
        (
          row.mount_point().as_os_str().as_bytes().to_vec(),
          row.device().as_bytes().to_vec(),
        )
      })
      .collect();
    assert_eq!(
      rows,
      vec![
        (b"/".to_vec(), b"/dev/disk3s1s1".to_vec()),
        (b"/Volumes/Share/usb".to_vec(), b"/dev/disk4s1".to_vec()),
        (b"/Volumes/USB".to_vec(), b"/dev/disk5s1".to_vec()),
      ]
    );
    let child = census_row(&entries[2].0, &entries[2].1, Ejectability::Unknown);
    assert_eq!(child.volume_identity(), None);
    assert_eq!(child.volume_name_assurance(), None);

    // The planted defect: the grouping as it was pinned the child's path.
    let before: Vec<&[u8]> = entries
      .iter()
      .filter(|(_, fields)| {
        let at = fields.mount_point.as_bytes();
        entries
          .iter()
          .filter(|(_, other)| other.mount_point.as_bytes() == at)
          .all(|(entry, _)| entry.f_flags & libc::MNT_LOCAL as u32 != 0)
      })
      .map(|(_, fields)| fields.mount_point.as_bytes())
      .collect();
    assert!(
      before.contains(&&b"/Volumes/Share/usb"[..]),
      "the old listing pinned the child through the share"
    );
  }

  /// A firmlinked path is split at the mount it is really on, by the file the
  /// mount point followed by the path names — the object's own, through its
  /// descriptor — and not by a device number, which the system volume and its
  /// data volume share: `/Users`, on this host, is `Users` beneath
  /// `/System/Volumes/Data`.
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
    let read = |name: &[u8]| Ok(super::super::node_at(name).ok());
    let data = b"/System/Volumes/Data";
    assert!(firmlinked(b"/Users", data, read).unwrap());
    assert!(
      !firmlinked(b"/", data, read).unwrap(),
      "the root is no firmlink"
    );
    assert!(
      !firmlinked(b"/Users", b"/System/Volumes/Preboot", read).unwrap(),
      "another mount point followed by the path names no such file"
    );
  }

  /// **A firmlinked path splits where the file system says it does, never
  /// where a spelling does.** On a scripted case-insensitive layout where
  /// `/Users` is the data volume's `Users`: `/users/AL/x` splits after its
  /// root, by the file the mount point followed by the path names, though the
  /// kernel spells the object `/System/Volumes/Data/Users/al/x`; the parent
  /// of an object whose file is not read spells the same split; a path the
  /// data volume holds under no such name does not split; and a whole path
  /// that is not refused is never answered as the mount's root. The planted
  /// defect, side by side: the byte comparison of the kernel's spelling with
  /// the caller's, which refused `/users/AL/x`, so that the path was read as
  /// the mount's root.
  #[test]
  fn test_a_firmlinked_path_splits_by_the_file_it_names() {
    use std::collections::HashMap;

    let files: HashMap<&[u8], super::super::Node> = [
      (&b"/"[..], super::super::Node::for_laws(1, 2)),
      (b"/users", super::super::Node::for_laws(1, 300)),
      (b"/users/al", super::super::Node::for_laws(1, 400)),
      (b"/users/al/x", super::super::Node::for_laws(1, 500)),
      (b"/library", super::super::Node::for_laws(1, 600)),
      (
        b"/system/volumes/data",
        super::super::Node::for_laws(1, 1 << 60),
      ),
      (
        b"/system/volumes/data/users",
        super::super::Node::for_laws(1, 300),
      ),
      (
        b"/system/volumes/data/users/al",
        super::super::Node::for_laws(1, 400),
      ),
      (
        b"/system/volumes/data/users/al/x",
        super::super::Node::for_laws(1, 500),
      ),
    ]
    .into_iter()
    .collect();
    let node_of = |name: &[u8]| Ok(files.get(&name.to_ascii_lowercase()[..]).copied());
    let data = b"/System/Volumes/Data";

    assert!(firmlinked(b"/users/AL/x", data, node_of).unwrap());
    assert!(
      firmlinked(b"/users/AL/x", data, |name: &[u8]| {
        if name == b"/users/AL/x" {
          Ok(None)
        } else {
          node_of(name)
        }
      })
      .unwrap(),
      "the parent of an object whose file is not read"
    );
    assert!(
      !firmlinked(b"/Library", data, node_of).unwrap(),
      "the data volume holds no such name"
    );
    let root = node_of(data).unwrap().unwrap();
    assert_eq!(
      super::super::beneath_offset(b"/users/AL/x", root, node_of).unwrap(),
      None,
      "no directory of a firmlinked path is the mount's root"
    );

    // The planted defect: the kernel's spelling compared with the caller's,
    // byte for byte, and the path then read as the mount's root.
    let before = |path: &[u8], mount_point: &[u8], unfirmlinked: &[u8]| {
      let (Some(beneath), Some(rest)) = (
        path.strip_prefix(b"/"),
        unfirmlinked.strip_prefix(mount_point),
      ) else {
        return false;
      };
      !beneath.is_empty() && rest.strip_prefix(b"/") == Some(beneath)
    };
    assert!(
      !before(b"/users/AL/x", data, b"/System/Volumes/Data/Users/al/x"),
      "the old comparison refused a spelling the file system accepts"
    );
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

  /// **A resolve splits its path where one of the path's own directories is
  /// the mount's root**, the file the mount point names: a file beneath a
  /// fresh directory is the rest of the path beneath its mount point, and the
  /// mount point itself is the mount's root, proven, with nothing beneath it.
  /// The shared law in the crate root holds the same road to a scripted
  /// case-insensitive layout, where a byte prefix read a nested path as the
  /// mount's root; the old road's bytes, side by side, agree here only because
  /// this layout spells every name one way.
  #[test]
  fn test_a_resolve_splits_where_its_own_directory_is_the_mount_root() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"whichdisk").unwrap();
    let resolved = resolve(&file).unwrap();
    let canonical = resolved.canonical_path().as_os_str().as_bytes().to_vec();
    let mount_point = resolved
      .mount_info()
      .mount_point()
      .as_os_str()
      .as_bytes()
      .to_vec();
    let relative = resolved.relative_path().as_os_str().as_bytes();
    assert!(relative.ends_with(b"file"), "{relative:?}");
    let root = resolve(resolved.mount_info().mount_point()).unwrap();
    assert_eq!(root.relative_path(), Path::new(""));

    let before = match canonical.strip_prefix(&mount_point[..]) {
      Some(rest) if rest.is_empty() || mount_point.ends_with(b"/") => mount_point.len(),
      Some(rest) if rest.starts_with(b"/") => mount_point.len() + 1,
      _ => canonical.len(),
    };
    assert_eq!(&canonical[before..], relative);
  }

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
        ejectability_of_source(b"cd9660", device.as_bytes(), 0),
        Ejectability::Unknown,
        "{device}"
      );
    }
  }

  /// **A source text is not a binding.** A user-space filesystem names
  /// whatever it likes — `/dev/cd0a` included — and its type says it is one, so
  /// it says nothing about removal; a kernel filesystem's source that is no
  /// device node now binds nothing either; and **a source binds only as
  /// itself and by number**: a device node carrying the number the mount's
  /// own id names binds, one carrying another number does not, and a symbolic
  /// link to the very same device — an alias — is never followed. The planted
  /// defect, side by side: the rule as it was followed the alias with `stat`
  /// and asked nothing of the number.
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
        !super::super::names_its_device_in_fsid(fs_type.as_bytes()),
        "{fs_type}"
      );
      assert_eq!(
        ejectability_of_source(fs_type.as_bytes(), b"/dev/cd0a", 0),
        Ejectability::Unknown,
        "{fs_type}"
      );
    }
    for fs_type in ["cd9660", "udf", "msdosfs", "msdos"] {
      assert!(
        super::super::names_its_device_in_fsid(fs_type.as_bytes()),
        "{fs_type}"
      );
    }
    for fs_type in ["ufs", "ffs", "ext2fs"] {
      assert!(
        !super::super::names_its_device_in_fsid(fs_type.as_bytes()),
        "{fs_type}"
      );
    }
    super::super::tests_for_bsd::a_source_binds_as_itself_and_by_number(b"cd9660");
  }
}
