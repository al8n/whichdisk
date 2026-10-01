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
//! **A row's facts are bound to its mount, on every feature set.** A resolve
//! pins the object the caller named, and reads its facts only after the pin
//! binds its line. **A listing reaches no mount by pathname** — a lookup of a
//! mount point crosses, and waits on, every mount above it, a network one
//! among them — so a listing row is its census line, its facts read about
//! the device the line prints for the mount and nothing only a descriptor
//! answers, and it stands only where the table read again after them carries
//! its line unchanged: see [`resolve`] and [`list`]. The pin, every
//! pathname the row is read through and the mount table all belong to the
//! calling thread: the table is read beneath the thread's own procfs
//! directory, because a thread may have entered a mount namespace of its own.
//! What a row's facts are read out of — the filesystem roster, udev's one
//! record of its device — is read only after its binding, and never kept for
//! a row bound later; and **a fact is read only about the device that backs the mount**:
//! a source binds only where its node is the `major:minor` the kernel printed
//! for the mount, and a source that does not bind has nothing read about it.
//!
//! **Every platform read answers one of four outcomes** — a value, the
//! platform's own "there is none", a decline [`declined`] names, or a failure
//! — and no two are merged except where a caller names what each means: see
//! [`Reading`]. Every directory is read by [`listing`], to the end the kernel
//! proves; the mount table is read only whole, by [`MountTable::read`], and
//! every record of it strictly, by [`parse_record`]; and a census is read
//! whole or refused. **Every read of a view the kernel keeps live ends within
//! a bound this backend names** — [`MOUNT_MAX`] mounts of the mount table or
//! of the unique mount ids, [`READ_LIMIT`] names of a directory — and one
//! handed more is refused whole, since what is added while it is read can lie
//! ahead of it.

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
  reading::{Census, READ_LIMIT, Reading, Unbounded},
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
/// `STATX_MNT_ID_UNIQUE` (Linux 6.8) is not read beside it: the unique id
/// names the mount *object* rather than its attachment, and a move-mount
/// reattaches the object without minting a new one — see [`resolve`]. It is
/// read for one question only, whether a pin holds the very mount object a
/// listing row was listed as: see [`STATX_MNT_ID_UNIQUE`].
const STATX_MNT_ID: u32 = 0x0000_1000;

/// `STATX_MNT_ID_UNIQUE`, added in Linux 6.8: the mount's 64-bit unique id,
/// which the kernel draws from a counter that only counts up
/// (`fs/namespace.c` `mnt_alloc_id`: `atomic64_inc_return(&mnt_id_ctr)`, at
/// v6.12) and so never hands to a second mount, where [`STATX_MNT_ID`]'s id
/// comes from an allocator that hands a freed id out again (`ida_alloc`).
/// `vfs_statx_path` answers it in `stx_mnt_id` in place of the reused id when
/// it is asked (`fs/stat.c`). A kernel before 6.8 leaves it unset in
/// `stx_mask`.
#[cfg(feature = "list")]
const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;

/// The most mounts one mount namespace holds: the kernel's `fs.mount-max`,
/// 100 000 unless an administrator raised it (`sysctl_mount_max`,
/// `fs/namespace.c` 41 at Linux v6.12), past which `count_mounts` refuses a
/// mount, and every copy a propagation would add, with `ENOSPC` (2353-2374,
/// asked by `attach_recursive_mnt` at 2470-2475 and by `propagate_one` in
/// `fs/pnode.c` 271).
///
/// **Every read of a namespace's mounts stops at it**, because the kernel
/// hands them over as a live view, not a copy. The mount table and
/// `listmount(2)` both walk the namespace's mounts in the order of their
/// unique ids, and resume, at each `read(2)` or call, after the last mount
/// they handed over: `m_start` and `m_next` keep the table's place by unique
/// id (1584-1604), which `seq_read_iter` starts every read from
/// (`fs/seq_file.c` 225), and `do_listmount` starts a page after the id it is
/// handed (5402-5423). A new mount's unique id is past every earlier one
/// (`mnt_alloc_id`, 236-245), so a mount made while a read goes on lies ahead
/// of it, and a namespace that unmounts what was read and mounts anew as fast
/// as the read proceeds keeps it from ever ending, holding few mounts at any
/// one time. A read handed more mounts than this has been handed mounts made
/// while it read — or reads a namespace an administrator let grow past the
/// kernel's own bound, which this crate does not describe — and is discarded
/// whole, never read on and never kept in part: the mount table is refused
/// (see [`MountTable::read`]), and the unique mount ids are none (see
/// `unique_mount_ids::WATERMARK`).
const MOUNT_MAX: usize = 100_000;

/// The kernel's unique ids for the mounts of the calling thread's mount
/// namespace, asked of the kernel's own tree of mounts and of no path: see
/// [`census`](unique_mount_ids::census).
#[cfg(feature = "list")]
mod unique_mount_ids {
  use std::{collections::HashMap, io};

  /// `statmount(2)` and `listmount(2)` (Linux 6.8): 457 and 458 in every
  /// table this names at v6.12 — `include/uapi/asm-generic/unistd.h`, which
  /// arm64, RISC-V and LoongArch take theirs from, and the x86-64 (not x32),
  /// i386, ARM, PowerPC and s390 tables. Every other architecture asks
  /// neither, and names no unique id: its rows are enriched by nothing.
  const CALLS: Option<(libc::c_long, libc::c_long)> = if cfg!(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv32",
    target_arch = "riscv64",
    target_arch = "loongarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "s390x",
  )) {
    Some((457, 458))
  } else {
    None
  };

  /// `LSMT_ROOT`: `listmount`'s name for the calling thread's root, beneath
  /// which it lists every mount, in the order of their unique ids.
  const LSMT_ROOT: u64 = u64::MAX;

  /// `STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC`: the superblock's device and
  /// the mount's ids, and no string.
  const BASIC: u64 = 0x1 | 0x2;

  /// `MNT_ID_REQ_SIZE_VER0`: the size of the first `struct mnt_id_req`,
  /// which every kernel with the calls takes (`copy_mnt_id_req`, zero-filling
  /// what a later one added).
  const REQUEST_SIZE: u32 = 24;

  /// How many ids one `listmount` call is handed room for.
  pub(super) const PAGE: usize = 256;

  /// The most unique ids one [`census`] reads: [`MOUNT_MAX`](super::MOUNT_MAX),
  /// the most mounts a namespace holds, since each page is a live view that
  /// a namespace mounting anew can keep a page ahead of. A census handed more
  /// ids than this is discarded whole — the part read with it — and names no
  /// unique id, as a kernel without the calls does: every row is then
  /// answered as listed, and the listing does not fail for it.
  pub(super) const WATERMARK: usize = super::MOUNT_MAX;

  /// `struct statmount`'s fixed part, which the kernel copies out as far as
  /// the buffer holds it (`copy_statmount_to_user`): 512 bytes at v6.12.
  const STATMOUNT_LEN: usize = 512;

  /// Where the fields read lie in `struct statmount`
  /// (`include/uapi/linux/mount.h` at v6.12), and how far into it they reach.
  mod field {
    pub(super) const SIZE: usize = 0;
    pub(super) const MASK: usize = 8;
    pub(super) const SB_DEV_MAJOR: usize = 16;
    pub(super) const SB_DEV_MINOR: usize = 20;
    pub(super) const MNT_ID: usize = 40;
    pub(super) const MNT_ID_OLD: usize = 56;
    pub(super) const END: usize = 64;
  }

  /// `struct mnt_id_req`, as its first published size.
  #[repr(C)]
  struct Request {
    size: u32,
    spare: u32,
    mnt_id: u64,
    param: u64,
  }

  /// `struct statmount`'s fixed part, as bytes, aligned as the kernel's.
  #[repr(C, align(8))]
  struct Answer([u8; STATMOUNT_LEN]);

  /// For every mount of the calling thread's namespace the kernel describes,
  /// the reused id its mount table line prints first → the mount's unique id
  /// and its superblock's device; `None` where the kernel names no unique id
  /// at all.
  ///
  /// **No path is looked up.** `listmount` walks the namespace's own tree of
  /// mounts, each reachable from the calling thread's root, and hands back
  /// their unique ids (`fs/namespace.c` `do_listmount`, at v6.12), and
  /// `statmount` describes one mount by that id — its unique id, the reused
  /// one (`mnt_id_old`) and the superblock's device (`statmount_mnt_basic`,
  /// `statmount_sb_basic`) — out of the mount itself. A unique id is never
  /// handed to a second mount (`mnt_alloc_id` counts up from
  /// `MNT_UNIQUE_ID_OFFSET`), so it names one mount object for good.
  ///
  /// What the kernel declares — no such call (`ENOSYS`: a kernel before 6.8,
  /// or a filter that answers so), a call refused (`EPERM`, `EACCES`), a
  /// request it does not take (`EINVAL`) — is no unique id, for any row; a
  /// mount gone between the two calls (`ENOENT`) or not the caller's to
  /// describe (`EPERM`, `EACCES`) is no unique id for that one. Every other
  /// failure is the error it is. Two mounts the kernel described under one
  /// reused id — one left and its id went to the next between the calls —
  /// name no unique id for it.
  ///
  /// **The census ends within [`WATERMARK`] ids, or it is none.** Each page
  /// is a live view: `listmount` lists the mounts after the last id it is
  /// handed as they stand at that call, so mounts made while the census reads
  /// lie ahead of it, and a namespace that unmounts what was read and mounts
  /// anew can keep a full page ahead for as long as it likes (see
  /// [`MOUNT_MAX`](super::MOUNT_MAX)). A census handed more ids than the
  /// watermark is discarded whole and names no unique id — never the part
  /// read, and never an error.
  pub(super) fn census() -> io::Result<Option<HashMap<u64, (u64, u64)>>> {
    let Some((statmount, listmount)) = CALLS else {
      return Ok(None);
    };
    census_with(
      WATERMARK,
      |last, ids| listed(listmount, last, ids),
      |unique| described(statmount, unique),
    )
  }

  /// [`census`], reading at most `most` ids: each page listed by `list` —
  /// the ids after `last`, written at the start of the page, and how many,
  /// or `None` where the kernel names no unique id — and each id described by
  /// `describe`, which laws stand in for. A census handed more than `most`
  /// ids is `None`, and nothing read before is kept.
  pub(super) fn census_with(
    most: usize,
    mut list: impl FnMut(u64, &mut [u64; PAGE]) -> io::Result<Option<usize>>,
    mut describe: impl FnMut(u64) -> io::Result<Option<(u64, u64)>>,
  ) -> io::Result<Option<HashMap<u64, (u64, u64)>>> {
    let mut named: HashMap<u64, Option<(u64, u64)>> = HashMap::new();
    let mut read = 0usize;
    let mut last = 0u64;
    loop {
      let mut ids = [0u64; PAGE];
      let Some(count) = list(last, &mut ids)? else {
        return Ok(None);
      };
      let count = count.min(PAGE);
      read = read.saturating_add(count);
      if read > most {
        return Ok(None);
      }
      for &unique in &ids[..count] {
        let Some((old, device)) = describe(unique)? else {
          continue;
        };
        named
          .entry(old)
          .and_modify(|seen| *seen = None)
          .or_insert(Some((unique, device)));
      }
      if count < PAGE {
        break;
      }
      last = ids[PAGE - 1];
    }
    Ok(Some(
      named
        .into_iter()
        .filter_map(|(old, one)| one.map(|pair| (old, pair)))
        .collect(),
    ))
  }

  /// One `listmount` page: the unique ids of the mounts after `last` beneath
  /// the calling thread's root, written at the start of `ids`, and how many;
  /// `None` where the kernel names no unique id — see [`census`].
  fn listed(
    listmount: libc::c_long,
    last: u64,
    ids: &mut [u64; PAGE],
  ) -> io::Result<Option<usize>> {
    let request = Request {
      size: REQUEST_SIZE,
      spare: 0,
      mnt_id: LSMT_ROOT,
      param: last,
    };
    // SAFETY: `request` is a live `struct mnt_id_req` of the size its first
    // field names, which the kernel reads no further than; `ids` is live and
    // writable for `PAGE` unique ids, which is the count passed, and the
    // kernel writes no more ids than that (`listmount` copies the ones it
    // listed); no flag is passed.
    let listed = unsafe {
      libc::syscall(
        listmount,
        &raw const request,
        ids.as_mut_ptr(),
        PAGE,
        0 as libc::c_uint,
      )
    };
    if listed < 0 {
      let err = io::Error::last_os_error();
      return match err.raw_os_error() {
        Some(libc::ENOSYS | libc::EPERM | libc::EACCES | libc::EINVAL) => Ok(None),
        _ => Err(err),
      };
    }
    Ok(Some(
      usize::try_from(listed).unwrap_or(usize::MAX).min(PAGE),
    ))
  }

  /// What `statmount` says of the mount `unique` names: its reused id and its
  /// superblock's device, where it answered both for exactly that mount, as
  /// far as it said it wrote; `None` where it answered for none of it — see
  /// [`census`].
  fn described(statmount: libc::c_long, unique: u64) -> io::Result<Option<(u64, u64)>> {
    let request = Request {
      size: REQUEST_SIZE,
      spare: 0,
      mnt_id: unique,
      param: BASIC,
    };
    let mut answer = Answer([0; STATMOUNT_LEN]);
    // SAFETY: `request` is a live `struct mnt_id_req` of the size its first
    // field names; `answer` is live, writable and aligned for the
    // `STATMOUNT_LEN` bytes passed as its size, and the kernel copies no more
    // of the fixed part than that and no string, since none is asked for; no
    // flag is passed.
    let rc = unsafe {
      libc::syscall(
        statmount,
        &raw const request,
        answer.0.as_mut_ptr(),
        STATMOUNT_LEN,
        0 as libc::c_uint,
      )
    };
    if rc != 0 {
      let err = io::Error::last_os_error();
      return match err.raw_os_error() {
        Some(libc::ENOENT | libc::EPERM | libc::EACCES | libc::EINVAL) => Ok(None),
        _ => Err(err),
      };
    }
    let bytes = &answer.0;
    let word = |at: usize| {
      let mut four = [0u8; 4];
      four.copy_from_slice(&bytes[at..at + 4]);
      u32::from_ne_bytes(four)
    };
    let wide = |at: usize| {
      let mut eight = [0u8; 8];
      eight.copy_from_slice(&bytes[at..at + 8]);
      u64::from_ne_bytes(eight)
    };
    let written = usize::try_from(word(field::SIZE)).unwrap_or(0);
    if written < field::END || wide(field::MASK) & BASIC != BASIC || wide(field::MNT_ID) != unique {
      return Ok(None);
    }
    let device = super::makedev(
      u64::from(word(field::SB_DEV_MAJOR)),
      u64::from(word(field::SB_DEV_MINOR)),
    );
    Ok(Some((u64::from(word(field::MNT_ID_OLD)), device)))
  }
}

/// What a listing row carries for the caller's details call, where the
/// kernel named its mount by a unique id when it was listed: the mount's
/// unique id — the one [`unique_mount_ids`] read for its line, which no other
/// mount is ever given — and the whole census line. A details call binds a
/// pin to the row only where the pin holds that very mount object and the
/// table printed while the pin is held carries that very line: see
/// `observed::details`. A row the kernel named by no unique id carries none,
/// and a details call adds nothing to it.
#[derive(Clone)]
#[cfg_attr(not(feature = "list"), allow(dead_code))]
pub(super) struct Listed {
  unique: u64,
  line: MountLine,
}

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
///   way, `ELOOP` for a symlink where a structural read forbids one, and a
///   lookup the kernel could not keep beneath its root however often it was
///   asked ([`Unproven`]) — the refusals [`KernelDir`] exists to make, beside
///   the root that is not the filesystem it must be, which [`KernelDir::open`]
///   declines itself;
/// - **refused by its bound**: a read of a view the kernel keeps live — the
///   mount table past [`MOUNT_MAX`] records, a directory past [`READ_LIMIT`]
///   names — that was stopped there ([`Unbounded`]), refused whole as a
///   census whose end no read proved;
/// - **not implemented**: `ENOSYS` — a kernel without `openat2` or `statx` —
///   `EOPNOTSUPP`, and `ENOTTY`, a filesystem that does not serve an ioctl.
///
/// Anything else — a full descriptor table, no memory, an I/O error — is a
/// failure of this process or of the machine. It says nothing about the
/// volume, so it is returned as the error it is, never reported as a volume
/// with no identity, no label or no capacity. An `EAGAIN` from any other call
/// is one of those.
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
    || err
      .get_ref()
      .is_some_and(|inner| inner.is::<Unproven>() || inner.is::<Unbounded>())
}

/// How many times [`KernelDir::open_beneath`] asks the kernel for one lookup
/// that it answered with `EAGAIN`.
const BENEATH_TRIES: usize = 8;

/// A lookup beneath a kernel root that the kernel could not prove stayed
/// beneath it: `openat2` answered `EAGAIN` under `RESOLVE_BENEATH` each of the
/// [`BENEATH_TRIES`] times it was asked.
///
/// The kernel answers `EAGAIN` there when a rename or a mount elsewhere
/// raced a `..` in the path, so that it could not show the `..` stayed inside
/// the root, and it names asking again as the remedy (`openat2(2)`; the
/// `/dev/disk/by-*` links this crate follows are `../../sda1`). One race is
/// asked again. A lookup that is never proven is refused as a climb out of
/// the root is — see [`declined`] — never taken as an answer and never a
/// failure of the whole read.
#[derive(Debug)]
struct Unproven;

impl core::fmt::Display for Unproven {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str("the kernel could not prove a lookup stayed beneath its root")
  }
}

impl std::error::Error for Unproven {}

/// Asks `lookup` until it answers anything but `EAGAIN`, at most
/// [`BENEATH_TRIES`] times, and answers [`Unproven`] if it never does.
fn beneath(mut lookup: impl FnMut() -> rustix::io::Result<OwnedFd>) -> io::Result<OwnedFd> {
  for _ in 0..BENEATH_TRIES {
    match lookup() {
      Err(rustix::io::Errno::AGAIN) => {}
      answered => return answered.map_err(io::Error::from),
    }
  }
  Err(io::Error::new(io::ErrorKind::WouldBlock, Unproven))
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
/// filesystem roster, and udev's one record of the row's device — is read
/// only after the row is bound, from a table read while its pin is held
/// ([`Facts`](observed::Facts), one per resolve; a listing's census rows,
/// which pin nothing, are held by the census taken again after them — see
/// [`listing`](observed::listing)); the line's source is resolved once, and binds only where its node is
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

  #[cfg(feature = "list")]
  use std::collections::HashMap;

  use rustix::{
    fd::{AsRawFd as _, OwnedFd},
    fs::{Mode, OFlags},
  };

  use super::{
    super::{
      BlockBackedTypes, Ejectability, IdentityAssurance, IdentityReading, MountPoint, NameReading,
      SmallBytes, VolumeIdentity, is_btrfs,
    },
    FDINFO_LIMIT, KernelDir, MountLine, MountTable, Reading, STATX_MNT_ID, reading,
  };

  #[cfg(test)]
  thread_local! {
    /// How many pathnames this thread has pinned, for the laws: a listing
    /// pins none.
    pub(super) static PATHS_PINNED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
  }

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
      #[cfg(test)]
      PATHS_PINNED.with(|pinned| pinned.set(pinned.get() + 1));
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

  /// The unique id of the mount `fd` holds: `statx` of the descriptor itself
  /// for [`STATX_MNT_ID_UNIQUE`](super::STATX_MNT_ID_UNIQUE), which the
  /// kernel answers in `stx_mnt_id`. `Absent` where it answered without it —
  /// a kernel before 6.8.
  #[cfg(feature = "list")]
  pub(super) fn unique_mount_id(fd: &OwnedFd) -> Reading<u64> {
    let unique = super::STATX_MNT_ID_UNIQUE;
    reading(rustix::fs::statx(
      fd,
      "",
      rustix::fs::AtFlags::EMPTY_PATH,
      rustix::fs::StatxFlags::from_bits_retain(unique),
    ))
    .and_then(|stx| {
      if stx.stx_mask & unique != 0 {
        Reading::Value(stx.stx_mnt_id)
      } else {
        Reading::Absent
      }
    })
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
    /// them. The source binding decides only the removal answer, which is
    /// then read from every member of the filesystem the source is a member
    /// of: see [`btrfs_removal`](super::btrfs_removal).
    ///
    /// A source is a pathname, and a pathname is not the mount: a node or a
    /// link retargeted since the mount was made, and a device an unprivileged
    /// mounter named for a filesystem no device backs (tmpfs, FUSE), name a
    /// device the mount is not on, and **no fact is read about a device that
    /// did not bind** — no identity, no label, no removal answer.
    fn bind(&self, line: &MountLine, pinned: &Pinned) -> io::Result<Binding> {
      let node = self.source_node(line)?;
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

    /// The number the kernel names `line`'s source node by, resolved once
    /// beneath `/dev`: `None` where the source names no node there, or no
    /// `/dev` could be had.
    fn source_node(&self, line: &MountLine) -> io::Result<Option<u64>> {
      Ok(
        match (&self.dev, super::device_relative(line.source.as_path())) {
          (Some(dev), Some(relative)) => dev.device_number(relative).answered()?,
          _ => None,
        },
      )
    }

    /// What a listing row's source is bound to, with no descriptor on the
    /// mount: the device the kernel printed for the mount itself, where the
    /// source's node beneath `/dev` is that number, and nothing otherwise.
    ///
    /// **Nothing on the mount is reached by pathname**: the number is the
    /// census line's own, and the node is looked up beneath `/dev`, never
    /// beneath the mount point. A btrfs mount, whose printed number is
    /// anonymous and whose membership only its filesystem can answer through
    /// a descriptor on the mount, binds nothing here: see [`listing`].
    #[cfg(feature = "list")]
    fn bind_by_number(&self, line: &MountLine) -> io::Result<Binding> {
      Ok(match self.source_node(line)? {
        Some(node) if node == line.device => Binding::Device(node),
        _ => Binding::Unbound,
      })
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
    // The FSID is the filesystem's own answer through a descriptor held to
    // the pinned mount, so it is `Vouched` whatever the line's source earns
    // (the owner's ruling 210); its durability is still the marker's.
    let lookup = if durable {
      super::BtrfsLookup::Matched(IdentityReading::published(mount.fsid))
        .at(IdentityAssurance::Vouched)
    } else {
      super::BtrfsLookup::Refused
    };
    let identity = super::identity_after_btrfs(lookup, || Ok(None));
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
    /// Until the descriptor is had (steps 1 and 2), a decline the platform
    /// declares — a mount point covered or moved, a root this process may not
    /// read — is `None`, and a read that failed is the error it is. **Once it
    /// is had, every read is the filesystem's own answer through a descriptor
    /// held to the mount, and every failure is the error it is**: its
    /// `fstatfs`, the FSID and the label (see [`btrfs_fs_info`] and
    /// [`btrfs_fs_label`]). What they declare absent is absent: a filesystem
    /// that is not btrfs, an empty label, and an FSID that is all zeros, which
    /// is no FSID mkfs writes and binds nothing.
    ///
    /// [`btrfs_fs_info`]: super::btrfs_fs_info()
    /// [`btrfs_fs_label`]: super::btrfs_fs_label
    fn of(line: &MountLine, pinned: &Pinned, proc: &KernelDir) -> io::Result<Option<Self>> {
      let Some(fd) = mount_root(line, pinned, proc, RootKind::Directory)? else {
        return Ok(None);
      };
      if !super::is_btrfs_magic(rustix::fs::fstatfs(&fd)?.f_type) {
        return Ok(None);
      }
      let fsid = super::btrfs_fs_info(&fd)?;
      if fsid == [0; super::btrfs_fs_info::FSID_LEN] {
        return Ok(None);
      }
      let label = super::btrfs_fs_label(&fd)?;
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
    kind: RootKind,
  ) -> io::Result<Option<OwnedFd>> {
    let root = match Pinned::of(line.mount_point.as_path(), proc) {
      Reading::Value(root) if root.mount_id == pinned.mount_id => root,
      Reading::Value(_) | Reading::Absent | Reading::Declined(_) => return Ok(None),
      Reading::Failed(err) => return Err(err),
    };
    let opened = match kind {
      RootKind::Directory => reopened(&root, proc),
      RootKind::DirectoryOrFile => reopened_directory_or_file(&root, proc),
    };
    let Some(fd) = opened.answered()? else {
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
    mount_root(line, pinned, &roots.proc, RootKind::DirectoryOrFile)
      .ok()
      .flatten()
  }

  /// What a mount's root may be for the question asked through it.
  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  pub(super) enum RootKind {
    /// A directory alone: btrfs's road, which declines a mount of a single
    /// file (a btrfs file bind mount is read through the mount it was bound
    /// from, whose root is a directory).
    Directory,
    /// A directory, or a regular file — a file bind mount — for the
    /// self-identity questions, which any open file on the filesystem
    /// answers.
    DirectoryOrFile,
  }

  /// `pinned`'s own object, reopened for a question about its filesystem:
  /// a directory as [`reopened`] opens one, and a regular file — a file
  /// bind mount's root — through the one road every file read takes, proven
  /// regular through the pin and held to the same device and inode
  /// ([`reopened_for_reading`](super::reopened_for_reading),
  /// `O_RDONLY | O_NONBLOCK | O_NOCTTY`). Anything else — a FIFO, a device,
  /// a socket bound over a path — is declined, and never opened.
  fn reopened_directory_or_file(pinned: &Pinned, proc: &KernelDir) -> Reading<OwnedFd> {
    reading(rustix::fs::fstat(&pinned.fd)).and_then(|named| {
      match rustix::fs::FileType::from_raw_mode(named.st_mode) {
        rustix::fs::FileType::Directory => reopened(pinned, proc),
        rustix::fs::FileType::RegularFile => {
          super::reopened_for_reading(&pinned.fd).and_then(|file| {
            super::regular(&file).and_then(|opened| {
              if (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino) {
                Reading::Value(file)
              } else {
                Reading::Declined(io::Error::new(
                  io::ErrorKind::InvalidData,
                  "the file reopened through the pin is not the file it holds",
                ))
              }
            })
          })
        }
        _ => Reading::Declined(io::Error::new(
          io::ErrorKind::InvalidData,
          "a mount root that is neither a directory nor a regular file, never opened",
        )),
      }
    })
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
  /// of beside each row's own publications: the kernel's filesystem roster.
  ///
  /// **Read only after the rows are bound, and never carried to other rows.**
  /// A `Facts` exists only once a table has been read while its rows' pins
  /// were held, so nothing in it can predate the binding of a row it serves;
  /// and it is dropped with those rows. A listing, which pins nothing, reads
  /// one for its census rows, each held by the census taken again after it.
  /// udev's facts are read for each row alone, out of the one record
  /// udev wrote for its device's attach: see
  /// [`published_facts`](Observation::published_facts).
  pub(super) struct Facts<'r> {
    roots: &'r Roots,
    /// The kernel's own filesystem table: the level a read through a mount
    /// source earns. See [`BlockBackedTypes`].
    block_backed: BlockBackedTypes,
  }

  impl<'r> Facts<'r> {
    /// The facts of a listing's census rows, read beneath `roots`: the
    /// kernel's filesystem roster, which names filesystem types and no mount.
    /// Each row is then held by the census taken again after it: see
    /// [`listing`].
    #[cfg(feature = "list")]
    fn of_census(roots: &'r Roots) -> io::Result<Self> {
      Ok(Self {
        roots,
        block_backed: super::block_backed_types(&roots.proc)?,
      })
    }

    /// The facts of the rows `held` binds, read beneath `roots` from now on.
    fn after(roots: &'r Roots, _held: &HeldTable) -> io::Result<Self> {
      Ok(Self {
        roots,
        block_backed: super::block_backed_types(&roots.proc)?,
      })
    }
  }

  /// One mount, observed: its table line and every fact of its row, read when
  /// the observation was formed.
  pub(super) struct Observation {
    line: MountLine,
    ejectability: Ejectability,
    identity: Option<IdentityReading>,
    name: Option<NameReading>,
    /// The capacity read through the pin; `None` for a listing's census row,
    /// which holds none.
    #[cfg(feature = "disk-usage")]
    capacity: Option<(u64, u64)>,
    /// A listing's census row's binding for a caller's details call: see
    /// [`Listed`](super::Listed). `None` for a resolve's row, and for a
    /// census row the kernel named by no unique mount id.
    listed: Option<Box<super::Listed>>,
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
      let (binding, ejectability) = Self::source_device(line, pinned, facts.roots)?;
      Self::formed(line.clone(), binding, ejectability, pinned, facts)
    }

    /// A listing row, formed out of its census line alone where the options
    /// keep it: the source bound by number and the removal answer first, so
    /// that a row the options leave out has nothing else read about it.
    ///
    /// **No descriptor on the mount, and no pathname of it.** The source binds
    /// only where its node beneath `/dev` is the number the line prints for
    /// the mount ([`bind_by_number`](Roots::bind_by_number)); the removal
    /// answer, the identity and the label are read about that number, beneath
    /// `/sys` and `/run`, exactly as a resolve reads them; and what only a
    /// descriptor on the mount answers is left out — the filesystem's own
    /// identity, which a resolve holds udev's record to, a btrfs mount's
    /// FSID, label and members, and the capacity, which is absent. The row
    /// stands only where the census taken again after it still carries its
    /// line: see [`listing`].
    #[cfg(feature = "list")]
    fn census_row(
      line: MountLine,
      facts: &Facts<'_>,
      opts: super::super::ListOptions,
      unique: Option<u64>,
    ) -> io::Result<Option<Self>> {
      let binding = facts.roots.bind_by_number(&line)?;
      let ejectability = Self::removal(&line, &binding, facts.roots);
      // Exact states: a volume of unknown ejectability is named by neither
      // only-filter, so it is excluded by either. See `ListOptions::excludes`.
      if opts.excludes(ejectability) {
        return Ok(None);
      }
      let fs_type = line.fs_type.as_bytes();
      let assurance = facts.block_backed.assurance_of(fs_type);
      let (identity, name) = match binding {
        Binding::Device(device) => {
          Self::published_facts(device, fs_type, assurance, None, facts.roots)?
        }
        Binding::Unbound | Binding::Btrfs { .. } => (None, None),
      };
      let listed = unique.map(|unique| {
        Box::new(super::Listed {
          unique,
          line: line.clone(),
        })
      });
      Ok(Some(Self {
        line,
        ejectability,
        identity,
        name,
        #[cfg(feature = "disk-usage")]
        capacity: None,
        listed,
      }))
    }

    /// The line's source, bound to the mount `pinned` holds — see
    /// [`Roots::bind`] — and what the kernel says about that device's removal.
    /// A single-device mount's source is read by the number its superblock
    /// carries, which the mount holds: see
    /// [`bound_removal`](super::bound_removal). A btrfs mount whose source
    /// binds as a member answers for every member of its filesystem, each
    /// held only while it is one, and held to that membership and its attach:
    /// see [`btrfs_removal`](super::btrfs_removal). A mount whose source binds
    /// no device never opens `/sys` at all, and its removal answer is
    /// `Unknown`.
    fn source_device(
      line: &MountLine,
      pinned: &Pinned,
      roots: &Roots,
    ) -> io::Result<(Binding, Ejectability)> {
      let binding = roots.bind(line, pinned)?;
      let removal = Self::removal(line, &binding, roots);
      Ok((binding, removal))
    }

    /// What the kernel says about the removal of the device `binding` holds
    /// for `line`: see [`source_device`](Self::source_device).
    fn removal(line: &MountLine, binding: &Binding, roots: &Roots) -> Ejectability {
      match (binding, roots.removal()) {
        (Binding::Device(device), Some(sysfs)) => {
          let answer = super::bound_removal(sysfs, *device);
          let fs_type = line.fs_type.as_bytes();
          // An ext filesystem's denial stands where its journal is proven to
          // lie on its source, or to be none (the owner's ruling 211).
          if answer == Ejectability::NotEjectable
            && super::ext_journal_proven_alone(sysfs, &roots.proc, fs_type, *device)
          {
            answer
          } else {
            super::filesystem_removal(answer, fs_type, line.super_options.as_bytes())
          }
        }
        (
          Binding::Btrfs {
            mount,
            device: Some(member),
            ..
          },
          Some(sysfs),
        ) => super::btrfs_removal(sysfs, *member, &mount.fsid),
        _ => Ejectability::Unknown,
      }
    }

    /// The identity the mounted filesystem names itself by, asked through the
    /// mount's root reopened for the question
    /// ([`filesystem_identity`](super::filesystem_identity)), in the form the
    /// line's filesystem type gives it. `None` wherever it names none, or the
    /// root could not be had for a reason the platform declares — covered,
    /// moved, not this caller's to open. Where it names one, it is the row's
    /// identity, `Vouched` — the filesystem answering for itself through a
    /// descriptor held to the mount (the owner's ruling 210) — and it holds
    /// udev's facts about the device to the filesystem. **A read that failed
    /// fails the row**, never `None`: udev's facts are never admitted in
    /// place of a question that failed.
    fn mounted_identity(
      line: &MountLine,
      pinned: &Pinned,
      roots: &Roots,
    ) -> io::Result<Option<VolumeIdentity>> {
      let fs_type = line.fs_type.as_bytes();
      let Some(root) = mount_root(line, pinned, &roots.proc, RootKind::DirectoryOrFile)? else {
        return Ok(None);
      };
      let Some(answered) = super::filesystem_identity(&root, fs_type)? else {
        return Ok(None);
      };
      Ok(
        super::super::linux_identity(fs_type, answered, IdentityAssurance::Vouched)
          .map(|reading| reading.identity()),
      )
    }

    /// Every other fact of the row, read from the one binding of the line's
    /// source and the one pin, at the level the source earns.
    ///
    /// For btrfs, the binding carries everything: the one census of the
    /// kernel's btrfs map that bound the source answers the identity — see
    /// [`BtrfsCensus`](super::BtrfsCensus) — and the label is the one the
    /// filesystem answered through the pinned mount, whatever the census says
    /// about the FSID's durability; the udev roads are never consulted in
    /// their place. For everything else, the identity and the label are
    /// udev's, **read out of one publication**: the one record udev wrote for
    /// the device's current attach, and read again after them, with the
    /// attach — see [`published_facts`](Self::published_facts). Where the
    /// filesystem names itself through its mount
    /// ([`mounted_identity`](Self::mounted_identity)), that record's identity
    /// must be the filesystem's own, or nothing it says — the label with the
    /// identity — is reported, since it is some other filesystem's. The
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
      pinned: &Pinned,
      facts: &Facts<'_>,
    ) -> io::Result<Self> {
      let fs_type = line.fs_type.as_bytes();
      let assurance = facts.block_backed.assurance_of(fs_type);
      let (identity, name) = match binding {
        Binding::Btrfs { mount, durable, .. } => btrfs_facts(mount, durable, assurance),
        // The filesystem's own identity through the bound mount, where it
        // names one, whether or not its source binds (the owner's ruling
        // 210): udev's record supplements it with the label, and must name
        // the same identity to.
        Binding::Unbound => (
          Self::mounted_identity(&line, pinned, facts.roots)?
            .and_then(|own| super::vouched_own_identity(fs_type, own)),
          None,
        ),
        Binding::Device(device) => {
          let mounted = Self::mounted_identity(&line, pinned, facts.roots)?;
          let (published, name) =
            Self::published_facts(device, fs_type, assurance, mounted, facts.roots)?;
          let own = mounted.and_then(|own| super::vouched_own_identity(fs_type, own));
          (own.or(published), name)
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
        capacity: Some(capacity),
        listed: None,
      })
    }

    /// udev's identity and label for `device`, read out of **one
    /// publication**: the record udev wrote for the attach the kernel names
    /// now, beneath the `/run` opened for it, taken only where the same
    /// record and the same attach stand after the facts were read — see
    /// [`published_facts_with`](super::published_facts_with). `(None, None)`
    /// wherever no publication binds them: an attach the kernel names that
    /// the record does not publish among them.
    fn published_facts(
      device: u64,
      fs_type: &[u8],
      assurance: IdentityAssurance,
      mounted: Option<VolumeIdentity>,
      roots: &Roots,
    ) -> io::Result<(Option<IdentityReading>, Option<NameReading>)> {
      let run = KernelDir::open("/run", None).answered()?;
      super::published_facts_with(
        roots.removal(),
        run.as_ref(),
        device,
        fs_type,
        assurance,
        mounted,
        || {},
      )
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
        capacity: self.capacity,
        listed: self.listed,
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

  /// Every row a listing reports, each formed out of its own census line.
  ///
  /// **A listing reaches no mount by pathname.** Pinning a mount point is a
  /// lookup of every component of its path, and the lookup crosses every
  /// mount on the way: each directory is asked for search permission and each
  /// name revalidated by the filesystem it is on (`fs/namei.c`
  /// `link_path_walk`, `may_lookup`, `lookup_fast`, `d_revalidate`, at Linux
  /// v6.12), `O_PATH` or not — `O_PATH` changes only what the last component
  /// is opened for. A local mount beneath an NFS or CIFS mount is reached only
  /// through that filesystem's `permission` and `d_revalidate`, which ask the
  /// server (`fs/nfs/dir.c` `nfs_permission`, `nfs_do_access`,
  /// `nfs_lookup_revalidate`), so a listing that pinned it would contact, and
  /// wait on, a server that does not answer before any binding could be
  /// checked. The kernel offers no open of a mount by its id: `statmount(2)`
  /// (Linux 6.8) answers a mount's device, type and mount point by its
  /// unique id, but no source before `STATMOUNT_SB_SOURCE`, which v6.12's
  /// `include/uapi/linux/mount.h` does not have, and no descriptor at all.
  ///
  /// So a row is its census line: every line the listing reports, its mount
  /// point, source and filesystem type as the table spells them, and what the
  /// kernel says about the device that line prints for the mount — the
  /// removal answer, and udev's identity and label out of its one record of
  /// that device — where the source's node beneath `/dev` is that device:
  /// see [`Observation::census_row`]. What only a descriptor on the mount
  /// answers is not read: the capacity is absent, a btrfs mount binds nothing,
  /// and udev's identity is not held to the filesystem's own. A covered mount
  /// is a row of its own, as its line is.
  ///
  /// **A row stands only where the census taken again after it carries its
  /// line unchanged**: the same id, device, mount point, filesystem type,
  /// source and superblock options — see [`still_standing`]. A mounted block
  /// device keeps its number for as long as its mount exists, so a mount
  /// that was there before the row's facts and after them held its device's
  /// number between; a line that moved, was replaced or left in between is
  /// not reported. What is left is a mount that left and was replaced, inside
  /// the window, by one the table prints identically — the same reused id,
  /// device number, mount point, source, type and options. The first table
  /// failing to read is the error it is, and so is the second.
  ///
  /// **Each row carries its mount's unique id where the kernel names one**:
  /// `listmount(2)` and `statmount(2)` (Linux 6.8) name, without a lookup of
  /// any path, every mount of the calling thread's namespace by its unique
  /// id beside the reused one the table prints and its device — see
  /// [`unique_mount_ids`](super::unique_mount_ids) — and a row whose line's
  /// id and device name exactly one of them carries that unique id and its
  /// whole line, which a caller's details call binds a pin by (see
  /// [`details`]). A row the kernel named by none — a kernel before 6.8, a
  /// filter that refuses the calls, a mount it would not describe, a census
  /// handed more ids than its watermark and so discarded whole — carries
  /// none, and a details call adds nothing to it.
  #[cfg(feature = "list")]
  pub(super) fn listing(opts: super::super::ListOptions) -> io::Result<Vec<Observation>> {
    listing_with(opts, super::unique_mount_ids::census)
  }

  /// [`listing`], with the unique mount ids read by `unique`, which a law
  /// stands in for.
  #[cfg(feature = "list")]
  pub(super) fn listing_with(
    opts: super::super::ListOptions,
    unique: impl FnOnce() -> io::Result<Option<HashMap<u64, (u64, u64)>>>,
  ) -> io::Result<Vec<Observation>> {
    let roots = Roots::open()?;
    let census = MountTable::read(&roots.proc)?;
    let unique = unique()?;
    let facts = Facts::of_census(&roots)?;
    let mut observations = Vec::new();
    for line in census.lines().filter(|line| super::is_listed(line)) {
      let named = unique
        .as_ref()
        .and_then(|ids| ids.get(&line.id))
        .filter(|&&(_, device)| device == line.device)
        .map(|&(unique, _)| unique);
      observations.extend(Observation::census_row(line.clone(), &facts, opts, named)?);
    }
    let again = MountTable::read(&roots.proc)?;
    Ok(still_standing(observations, &again))
  }

  /// The rows whose census line `again`, a table read after their facts,
  /// still carries exactly: the same id naming a line equal in every field
  /// the row was read by. See [`listing`].
  #[cfg(feature = "list")]
  pub(super) fn still_standing(
    observations: Vec<Observation>,
    again: &MountTable,
  ) -> Vec<Observation> {
    let current = again.by_id();
    observations
      .into_iter()
      .filter(|observation| {
        current
          .get(&observation.line.id)
          .is_some_and(|now| **now == observation.line)
      })
      .collect()
  }

  /// A listing row's mount, bound after the row by the mount object it was
  /// listed as, `listed` — see [`Listed`](super::Listed): the row's mount
  /// point pinned, **the pin holding that very mount object** — its unique
  /// id, which no other mount is ever given, is the one the row was listed
  /// under ([`unique_mount_id`]), and so is the reused id — and the table
  /// read while the pin is held printing, for that id, **the row's whole
  /// line**: the same device, mount point, filesystem type, source and
  /// superblock options. Then it is observed through the pin as a resolve
  /// observes it. `None` wherever the binding fails: the mount point pins
  /// another mount — a replacement mounted there after the listed one left,
  /// however its reused id and device match — the kernel names the pin no
  /// unique id, the line changed, or the mount point cannot be pinned. See
  /// [`MountPoint::details`](super::super::MountPoint::details).
  #[cfg(feature = "list")]
  pub(super) fn details(listed: &super::Listed) -> io::Result<Option<Observation>> {
    let roots = Roots::open()?;
    let mount_point = listed.line.mount_point.as_path();
    let pinned = match Pinned::of(mount_point, &roots.proc) {
      Reading::Value(pinned) if pinned.mount_id == listed.line.id => pinned,
      Reading::Value(_) | Reading::Absent | Reading::Declined(_) => return Ok(None),
      Reading::Failed(err) => return Err(err),
    };
    match unique_mount_id(&pinned.fd) {
      Reading::Value(unique) if unique == listed.unique => {}
      Reading::Value(_) | Reading::Absent | Reading::Declined(_) => return Ok(None),
      Reading::Failed(err) => return Err(err),
    }
    let table = HeldTable::read(&roots.proc, &[&pinned])?;
    if table.0.line(listed.line.id) != Some(&listed.line) {
      return Ok(None);
    }
    let facts = Facts::after(&roots, &table)?;
    Observation::resolved(&pinned, mount_point, &table, &facts).map(Some)
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

    /// **A row's details bind only the mount object it was listed as.** The
    /// root listed under its own unique id and line binds, and its facts are
    /// then read through the pin, the capacity among them. A replacement —
    /// the same reused id and device at the same mount point, but another
    /// mount object, whose unique id is not the listed one — binds nothing,
    /// and neither does a line that changed. The planted defect, side by
    /// side: the binding before, by the reused id and the device alone, which
    /// the replacement passes.
    #[cfg(feature = "list")]
    #[test]
    fn test_details_bind_only_the_mount_object_the_row_was_listed_as() {
      let proc = proc_root();
      let pinned = Pinned::of(Path::new("/"), &proc).required().unwrap();
      let Reading::Value(unique) = unique_mount_id(&pinned.fd) else {
        // A kernel before 6.8 names no unique id, and no row is bound: see
        // the law of the row the kernel named by none.
        return;
      };
      let table = MountTable::read(&proc).unwrap();
      let line = table.line(pinned.mount_id()).unwrap().clone();
      let listed = |unique: u64, line: &MountLine| super::super::Listed {
        unique,
        line: line.clone(),
      };
      let bound = details(&listed(unique, &line))
        .unwrap()
        .expect("the root binds as the mount object it is");
      assert!(bound.listed.is_none(), "a bound row is no census row");
      #[cfg(feature = "disk-usage")]
      assert!(bound.capacity.is_some(), "read through the pin");

      let replacement = listed(unique.wrapping_add(1), &line);
      assert!(
        details(&replacement).unwrap().is_none(),
        "another mount object under the same reused id and device"
      );
      let mut changed = line.clone();
      changed.super_options = SmallBytes::from_bytes(b"rw,changed");
      assert!(
        details(&listed(unique, &changed)).unwrap().is_none(),
        "another line"
      );

      // The planted defect: the binding before, which the replacement
      // passes.
      let before = |row: &super::super::Listed| {
        pinned.mount_id() == row.line.id
          && table.line(row.line.id).is_some_and(|now| {
            now.device == row.line.device && now.mount_point == row.line.mount_point
          })
      };
      assert!(
        before(&replacement),
        "the reused id and device name the replacement too"
      );
    }

    /// **A row the kernel named by no unique id is enriched by nothing.**
    /// Listed where the kernel names no unique mount id — a kernel before
    /// 6.8, a filter that refuses the calls — no row carries a binding, and a
    /// details call answers the row as it was listed.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_row_the_kernel_named_by_no_unique_id_is_enriched_by_nothing() {
      let rows = listing_with(super::super::super::ListOptions::all(), || Ok(None)).unwrap();
      assert!(rows.iter().all(|row| row.listed.is_none()));
      let root = rows
        .into_iter()
        .find(|row| row.line.mount_point.as_bytes() == b"/")
        .expect("the root is listed")
        .into_row();
      let detailed = super::super::details(&root).unwrap();
      assert!(detailed == root, "{detailed:?}");
      assert_eq!(detailed.volume_identity(), root.volume_identity());
      #[cfg(feature = "disk-usage")]
      assert!(detailed.total_bytes().is_none(), "nothing is read for it");
    }

    /// **Where the kernel names unique ids, a listed row carries its mount's
    /// own**, the one its pin answers, and its details bind. A kernel that
    /// names none leaves every row without one. A CI step prints which this
    /// machine is.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_listed_row_carries_its_mounts_own_unique_id_on_this_machine() {
      let proc = proc_root();
      let pinned = Pinned::of(Path::new("/"), &proc).required().unwrap();
      let named = super::super::unique_mount_ids::census().unwrap();
      let rows = listing(super::super::super::ListOptions::all()).unwrap();
      let root = rows
        .iter()
        .find(|row| row.line.mount_point.as_bytes() == b"/")
        .expect("the root is listed");
      match (named, unique_mount_id(&pinned.fd)) {
        (Some(_), Reading::Value(unique)) => {
          println!("the root's unique mount id: {unique}");
          let listed = root.listed.as_ref().expect("the root carries a unique id");
          assert_eq!(listed.unique, unique);
          assert!(details(listed).unwrap().is_some(), "and binds");
        }
        (None, _) => {
          println!("this kernel names no unique mount id to a listing");
          assert!(rows.iter().all(|row| row.listed.is_none()));
        }
        (Some(_), _) => println!("this kernel lists unique ids but answers statx none"),
      }
    }

    /// The first unique id a kernel hands out: `MNT_UNIQUE_ID_OFFSET` and one.
    #[cfg(feature = "list")]
    const FIRST_UNIQUE: u64 = (1 << 31) + 1;

    /// A scripted `listmount` for a namespace that unmounts what was listed
    /// and mounts anew as fast as it is listed: every page it hands over is
    /// full of ids no page before carried. It holds the census to asking
    /// after the last id it was handed, counts the pages asked, and past
    /// `stop` of them hands an empty page, which is the only end a census
    /// with no bound of its own would come to.
    #[cfg(feature = "list")]
    struct Churn {
      stop: usize,
      asked: usize,
      next: u64,
    }

    #[cfg(feature = "list")]
    impl Churn {
      fn new(stop: usize) -> Self {
        Self {
          stop,
          asked: 0,
          next: FIRST_UNIQUE,
        }
      }

      fn page(
        &mut self,
        last: u64,
        ids: &mut [u64; super::super::unique_mount_ids::PAGE],
      ) -> io::Result<Option<usize>> {
        let resumes = if self.asked == 0 { 0 } else { self.next - 1 };
        assert_eq!(last, resumes, "a page is asked after the last id handed");
        self.asked += 1;
        if self.asked > self.stop {
          return Ok(Some(0));
        }
        for id in ids.iter_mut() {
          *id = self.next;
          self.next += 1;
        }
        Ok(Some(ids.len()))
      }
    }

    /// **A census handed more ids than its watermark names no unique id, and
    /// a details call adds nothing.** A namespace mounting anew as fast as it
    /// is listed hands every page full; the census stops once it has been
    /// handed more than its watermark and is none — though the first id it
    /// was handed described the root's own line — so no listed row carries a
    /// binding, and the root's details are the row as it was listed. The
    /// planted defect, side by side: the part read before the watermark,
    /// kept, names the root, which is the binding a partial census would have
    /// carried into the listing.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_census_past_its_watermark_names_no_unique_id_and_details_add_nothing() {
      use super::super::unique_mount_ids::{PAGE, WATERMARK, census_with};

      let proc = proc_root();
      let pinned = Pinned::of(Path::new("/"), &proc).required().unwrap();
      let table = MountTable::read(&proc).unwrap();
      let root = table.line(pinned.mount_id()).unwrap().clone();
      let describe = |unique: u64| -> io::Result<Option<(u64, u64)>> {
        Ok(Some(if unique == FIRST_UNIQUE {
          (root.id, root.device)
        } else {
          (u64::MAX - unique, 0)
        }))
      };
      let stop = 2 * (WATERMARK / PAGE + 1);

      let mut churn = Churn::new(stop);
      let named = census_with(WATERMARK, |last, ids| churn.page(last, ids), describe).unwrap();
      assert!(named.is_none(), "discarded whole");

      let rows = listing_with(super::super::super::ListOptions::all(), || {
        let mut churn = Churn::new(stop);
        census_with(WATERMARK, |last, ids| churn.page(last, ids), describe)
      })
      .unwrap();
      assert!(
        rows.iter().all(|row| row.listed.is_none()),
        "no row carries a binding"
      );
      let listed_root = rows
        .into_iter()
        .find(|row| row.line.mount_point.as_bytes() == b"/")
        .expect("the root is listed")
        .into_row();
      let detailed = super::super::details(&listed_root).unwrap();
      assert!(detailed == listed_root, "{detailed:?}");
      #[cfg(feature = "disk-usage")]
      assert!(detailed.total_bytes().is_none(), "nothing is read for it");

      // The planted defect: the part read before the watermark, kept.
      let mut churn = Churn::new(WATERMARK / PAGE);
      let part = census_with(usize::MAX, |last, ids| churn.page(last, ids), describe)
        .unwrap()
        .expect("the part read");
      assert_eq!(
        part.get(&root.id),
        Some(&(FIRST_UNIQUE, root.device)),
        "the part read names the root"
      );
    }

    /// **A census under its watermark is read whole, as before.** Pages are
    /// asked after the last id of the page before until a short page ends
    /// them; every id handed is described, a reused id two described mounts
    /// share names neither, and a mount the kernel would not describe is
    /// passed over. A census of exactly as many ids as its watermark is read
    /// whole — a namespace holding the most mounts it can — and one handed a
    /// single id more is none.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_census_under_its_watermark_is_read_whole() {
      use super::super::unique_mount_ids::{PAGE, WATERMARK, census_with};

      let total = 2 * PAGE + 3;
      let ids: Vec<u64> = (0..total as u64).map(|at| FIRST_UNIQUE + 2 * at).collect();
      let mut asked = Vec::new();
      let list = |last: u64, page: &mut [u64; PAGE]| -> io::Result<Option<usize>> {
        asked.push(last);
        let from = ids.iter().position(|&id| id > last).unwrap_or(ids.len());
        let count = (ids.len() - from).min(PAGE);
        page[..count].copy_from_slice(&ids[from..from + count]);
        Ok(Some(count))
      };
      let describe = |unique: u64| -> io::Result<Option<(u64, u64)>> {
        let at = (unique - FIRST_UNIQUE) / 2;
        Ok(match at {
          5 => None,
          7 | 8 => Some((7, 1)),
          _ => Some((at, at + 100)),
        })
      };
      let named = census_with(WATERMARK, list, describe)
        .unwrap()
        .expect("read whole");
      assert_eq!(asked, [0, ids[PAGE - 1], ids[2 * PAGE - 1]]);
      let expected: HashMap<u64, (u64, u64)> = (0..total as u64)
        .filter(|at| ![5, 7, 8].contains(at))
        .map(|at| (at, (FIRST_UNIQUE + 2 * at, at + 100)))
        .collect();
      assert_eq!(named, expected);

      let handed = |total: usize| {
        let mut next = FIRST_UNIQUE;
        let mut left = total;
        census_with(
          WATERMARK,
          |_, page: &mut [u64; PAGE]| {
            let count = left.min(PAGE);
            for id in &mut page[..count] {
              *id = next;
              next += 1;
            }
            left -= count;
            Ok(Some(count))
          },
          |unique| Ok(Some((unique, 0))),
        )
        .unwrap()
      };
      assert_eq!(
        handed(WATERMARK).map(|named| named.len()),
        Some(WATERMARK),
        "the most mounts a namespace holds are read whole"
      );
      assert!(handed(WATERMARK + 1).is_none(), "one more is none");
    }

    /// **A census ends while its namespace mounts anew.** Every page is
    /// handed full of ids no page before carried; the census stops by itself
    /// once it has been handed more than its watermark — at
    /// `WATERMARK / PAGE + 1` pages, describing no id past the watermark — and
    /// is none. The planted defect, side by side: with no watermark — the
    /// census loop before — it asks every page the listing hands it, and ends
    /// only because the scripted listing stops handing them, twice as many
    /// pages on.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_census_ends_while_its_namespace_mounts_anew() {
      use super::super::unique_mount_ids::{PAGE, WATERMARK, census_with};

      let pages = WATERMARK / PAGE + 1;
      let stop = 2 * pages;
      let mut churn = Churn::new(stop);
      let mut described = 0usize;
      let named = census_with(
        WATERMARK,
        |last, ids| churn.page(last, ids),
        |unique| {
          described += 1;
          Ok(Some((unique, 0)))
        },
      )
      .unwrap();
      assert!(named.is_none(), "discarded whole");
      assert_eq!(churn.asked, pages, "it stops by itself");
      assert!(described <= WATERMARK, "and describes nothing past it");

      // The planted defect: no watermark, the loop before.
      let mut churn = Churn::new(stop);
      let before = census_with(
        usize::MAX,
        |last, ids| churn.page(last, ids),
        |unique| Ok(Some((unique, 0))),
      )
      .unwrap();
      println!(
        "with no watermark the census asked {} pages, ending where the listing did",
        churn.asked
      );
      assert_eq!(churn.asked, stop + 1, "it asked until the listing stopped");
      assert_eq!(before.map(|named| named.len()), Some(stop * PAGE));
    }

    /// A census row stands only where the table read after its facts still
    /// carries its line in every field: the same line stands; a line whose
    /// id is gone, whose mount moved, whose device, source, type or
    /// superblock options changed, is not reported. The planted defect, side
    /// by side: the listing before took whatever line the id named in the
    /// second table, and so reported a moved mount at its new place — a
    /// place no fact of the row was read about.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_census_row_stands_only_on_its_unchanged_line() {
      let roots = Roots::open().unwrap();
      let facts = Facts::of_census(&roots).unwrap();
      let first = MountTable::parse(
        b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
          36 21 8:17 / /mnt/usb rw - vfat /dev/sdb1 rw\n\
          37 21 8:33 / /mnt/a rw - ext4 /dev/sdc1 rw\n\
          38 21 8:49 / /mnt/b rw - ext4 /dev/sdd1 rw\n\
          39 21 8:65 / /mnt/c rw - xfs /dev/sde1 rw\n",
      )
      .unwrap();
      let rows = || {
        first
          .lines()
          .map(|line| {
            Observation::census_row(
              line.clone(),
              &facts,
              super::super::super::ListOptions::all(),
              None,
            )
            .unwrap()
            .unwrap()
          })
          .collect::<Vec<_>>()
      };
      // 36 moved; 37 gone; 38 names another device; 39 remounted with a log
      // device.
      let again = MountTable::parse(
        b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
          36 21 8:17 / /mnt/elsewhere rw - vfat /dev/sdb1 rw\n\
          38 21 8:50 / /mnt/b rw - ext4 /dev/sdd2 rw\n\
          39 21 8:65 / /mnt/c rw - xfs /dev/sde1 rw,logdev=/dev/sdf1\n",
      )
      .unwrap();
      let standing = still_standing(rows(), &again);
      let points: Vec<&[u8]> = standing
        .iter()
        .map(|observation| observation.line.mount_point.as_bytes())
        .collect();
      assert_eq!(points, [b"/".as_slice()]);

      // The planted defect: the id's line in the second table, wherever it is.
      let current = again.by_id();
      let before: Vec<&[u8]> = rows()
        .iter()
        .filter_map(|observation| current.get(&observation.line.id))
        .map(|line| line.mount_point.as_bytes())
        .collect();
      assert!(
        before.contains(&b"/mnt/elsewhere".as_slice()),
        "the rule before reported a moved mount where nothing was read"
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

    /// **A listing resolves no mount point's path**, with or without
    /// `disk-usage`: the listing pins no pathname at all, and every row it
    /// reports is a line of the mount table as it stands after it. The
    /// planted defect, side by side: the listing before pinned every row's
    /// mount point, which the count sees.
    #[cfg(feature = "list")]
    #[test]
    fn test_a_listing_resolves_no_mount_points_path() {
      let pinned = || PATHS_PINNED.with(core::cell::Cell::get);
      let before = pinned();
      let observations = listing(super::super::super::ListOptions::all()).unwrap();
      assert_eq!(pinned(), before, "the listing pinned a mount point");
      assert!(
        observations
          .iter()
          .any(|observation| observation.line.mount_point.as_bytes() == b"/"),
        "the root is listed"
      );
      let proc = proc_root();
      let after = MountTable::read(&proc).unwrap();
      for observation in &observations {
        assert!(
          after.lines().any(|line| line.id == observation.line.id
            && line.mount_point == observation.line.mount_point),
          "{:?}",
          observation.line.mount_point.as_bytes()
        );
        #[cfg(feature = "disk-usage")]
        assert_eq!(
          observation.capacity, None,
          "a capacity is read through a descriptor"
        );
      }

      // The planted defect: a pin of every row's mount point, as before.
      let _pins: Vec<_> = observations
        .iter()
        .map(|observation| Pinned::of(observation.line.mount_point.as_path(), &proc))
        .collect();
      assert_eq!(pinned(), before + observations.len());
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
/// missed the cache already paid, and what the listing road pays twice for a
/// whole enumeration: once for its rows and once to hold them.
#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;
  let observation = Observation::of_path(&canonical)?;

  let canonical_bytes = canonical.as_os_str().as_bytes();
  let mp_bytes = observation.mount_point().as_bytes();
  let relative_offset = if mp_bytes == b"/" {
    // Root mount: relative path is everything after the leading '/'
    1
  } else if contains_path(mp_bytes, canonical_bytes) {
    // Beneath by whole components, as the observation already required.
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

/// One record of the mount table: the mount id it prints first, and what it
/// spells for the mount point, the filesystem type and the source, all three
/// decoded — a field spelled with an escape names something other than its
/// spelling does.
#[derive(Clone, PartialEq, Eq)]
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
  /// The per-superblock options, as the kernel wrote them — `rw` or `ro` and
  /// then the filesystem's own `show_options` — undecoded: a filesystem that
  /// opened devices beside its source by name prints those names here. See
  /// [`built_on_its_source_alone`].
  super_options: SmallBytes,
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
  let super_options = fields.next()?;
  if fs_type.as_bytes().is_empty() || !is_options(super_options) || fields.next().is_some() {
    return None;
  }
  Some(MountLine {
    id,
    device,
    mount_point,
    fs_type,
    source,
    super_options: SmallBytes::from_bytes(super_options),
  })
}

/// Whether a field is an options list as the kernel writes one: `rw` or `ro`
/// first, then the rest separated by commas, none of them empty.
fn is_options(field: &[u8]) -> bool {
  let mut options = field.split(|&byte| byte == b',');
  matches!(options.next(), Some(b"rw" | b"ro")) && options.all(|option| !option.is_empty())
}

/// Whether the listing reports a mount table line: not a virtual filesystem,
/// not a mount at or under `/sys`, `/proc` or `/run` other than one at or
/// under `/run/media`, and not the sunrpc pipe. "Under" is by whole
/// components — see [`is_within`] — so `/system`, `/process` and `/runner`
/// are listed, and `/run/mediaevil` is not `/run/media`.
#[cfg(feature = "list")]
fn is_listed(line: &MountLine) -> bool {
  if IGNORED_FS_TYPES.contains(&line.fs_type.as_bytes()) {
    return false;
  }
  let mp = line.mount_point.as_bytes();
  if is_within(mp, b"/sys")
    || is_within(mp, b"/proc")
    || (is_within(mp, b"/run") && !is_within(mp, b"/run/media"))
  {
    return false;
  }
  !line.source.as_bytes().starts_with(b"sunrpc")
}

/// Whether the mount point `path` is the directory `dir` or lies beneath it:
/// `dir` itself, or `dir` and a separator before the rest. A name that only
/// begins with the same bytes — `/system` beside `/sys` — is another
/// directory.
#[cfg(feature = "list")]
fn is_within(path: &[u8], dir: &[u8]) -> bool {
  path
    .strip_prefix(dir)
    .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
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
  ///
  /// **A read ends within [`MOUNT_MAX`] records, or the table is refused.**
  /// Each `read(2)` resumes after the last mount the one before handed over,
  /// by unique id, so a mount made while the table is read lies ahead of it,
  /// and a namespace that keeps mounting anew keeps the read from reaching its
  /// end — the `poll` above is asked only once it has. A read handed more
  /// records than a namespace holds mounts is stopped there, and the table is
  /// refused with [`Unbounded`] whatever it held: see [`records_up_to`].
  fn read(proc: &KernelDir) -> io::Result<Self> {
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
        let file = std::fs::File::from(
          proc
            .open_regular(path, ResolveFlags::NO_SYMLINKS)
            .required()?,
        );
        let table = records_up_to(&file, MOUNT_MAX)?;
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

/// A mount table's records, read to its end — the `read(2)` that answers
/// nothing — or refused with [`Unbounded`] as soon as more than `most` of
/// them have been read, whatever they were: see [`MountTable::read`]. The
/// kernel ends every record with a newline (`show_mountinfo`), and the
/// newlines read are what is counted. An interrupted read is asked again.
fn records_up_to(mut table: impl std::io::Read, most: usize) -> io::Result<Vec<u8>> {
  /// How many bytes one `read(2)` is offered.
  const CHUNK: usize = 64 * 1024;

  let mut records = Vec::new();
  let mut chunk = vec![0u8; CHUNK];
  let mut ends = 0usize;
  loop {
    let read = match table.read(&mut chunk) {
      Ok(0) => return Ok(records),
      Ok(read) => &chunk[..read.min(CHUNK)],
      Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
      Err(err) => return Err(err),
    };
    ends = ends.saturating_add(read.iter().filter(|&&byte| byte == b'\n').count());
    if ends > most {
      return Err(io::Error::other(Unbounded));
    }
    records.extend_from_slice(read);
  }
}

/// `row` with every fact only a descriptor on its mount answers, where its
/// mount is still the one it was listed under — see
/// [`MountPoint::details`](super::MountPoint::details) — and `row` as it is
/// otherwise.
#[cfg(feature = "list")]
pub(super) fn details(row: &super::MountPoint) -> io::Result<super::MountPoint> {
  let Some(listed) = &row.listed else {
    return Ok(row.clone());
  };
  Ok(observed::details(listed)?.map_or_else(|| row.clone(), Observation::into_row))
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
/// a member of that filesystem, so that the removal answer is asked only of a
/// filesystem the source backs — and then of every one of its members: see
/// `observed::Roots::bind` and [`btrfs_removal`].
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
/// Neither needs a privilege, and both answer through any open file on the
/// filesystem, a directory or a regular file: `FS_IOC_GETFSUUID` is served
/// by the VFS itself out of the file's superblock (`fs/ioctl.c`
/// `do_vfs_ioctl` and `ioctl_getfsuuid` 766-777 at v6.12), and
/// `FAT_IOCTL_GET_VOLUME_ID` by `fat_generic_ioctl`, which FAT's regular-file
/// operations name directly and its directory operations fall through to
/// (`fs/fat/file.c` 156-172 and 209, `fs/fat/dir.c` 816 and 874). A zero
/// serial and an all-zero UUID are no identity, and a UUID of any length but
/// sixteen is none this crate reads.
///
/// **Only the kernel's declared "not this filesystem" is `None`**: `ENOTTY`,
/// which `ioctl_getfsuuid` answers for a superblock with no UUID, FAT's
/// ioctl answers for a command it does not serve, and `vfs_ioctl` makes of a
/// file system with no ioctl at all (`ENOIOCTLCMD`, `fs/ioctl.c` 44-52).
/// Neither road answers `EOPNOTSUPP` at v6.12. **Every other error is the
/// error it is** — `EIO`, `EINTR`, `EFAULT` — and fails the row: a failed
/// read of the filesystem's own identity never lets udev's unverified facts
/// stand in for it. See [`identity_asked`].
fn filesystem_identity(root: &OwnedFd, fs_type: &[u8]) -> io::Result<Option<VolumeIdentity>> {
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
    if !identity_asked(injected_identity_error().map_or(asked, Err))? {
      return Ok(None);
    }
    return Ok((serial != 0).then_some(VolumeIdentity::Serial32(serial)));
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
  if !identity_asked(injected_identity_error().map_or(asked, Err))? {
    return Ok(None);
  }
  Ok(
    (usize::from(answer.len) == answer.uuid.len() && answer.uuid != [0; 16])
      .then_some(VolumeIdentity::FsUuid(answer.uuid)),
  )
}

/// What a self-identity ioctl's outcome says: `true` where it answered,
/// `false` where the kernel declared the filesystem has no such identity
/// (`ENOTTY` alone), and every other error as the error it is — see
/// [`filesystem_identity`].
fn identity_asked(asked: rustix::io::Result<()>) -> io::Result<bool> {
  match asked {
    Ok(()) => Ok(true),
    Err(rustix::io::Errno::NOTTY) => Ok(false),
    Err(errno) => Err(errno.into()),
  }
}

#[cfg(test)]
thread_local! {
  /// An error a law injects into this thread's next self-identity ioctls, in
  /// place of the kernel's answer.
  static INJECTED_IDENTITY_ERROR: core::cell::Cell<Option<rustix::io::Errno>> =
    const { core::cell::Cell::new(None) };
}

/// The error a law injected, for the laws; nothing outside them.
#[cfg(test)]
fn injected_identity_error() -> Option<rustix::io::Errno> {
  INJECTED_IDENTITY_ERROR.with(core::cell::Cell::get)
}

/// No law injects anything outside the laws.
#[cfg(not(test))]
#[inline(always)]
fn injected_identity_error() -> Option<rustix::io::Errno> {
  None
}

/// The filesystem types whose own answer through the mount is their durable
/// on-disk identity: ext2, ext3 and ext4 and XFS, whose superblock UUID the
/// VFS answers for `FS_IOC_GETFSUUID` (`super_set_uuid` in `fs/ext4/super.c`
/// and `fs/xfs/xfs_mount.c` at v6.12), and FAT, whose volume serial
/// `FAT_IOCTL_GET_VOLUME_ID` answers (`fs/fat/file.c`). btrfs's FSID goes its
/// own road. Every other type stays with udev, or none: a filesystem that
/// answers `FS_IOC_GETFSUUID` with a value it minted for the mount is no
/// durable identity, and exFAT answers neither question at v6.12.
const SELF_NAMING_TYPES: [&[u8]; 6] = [b"ext2", b"ext3", b"ext4", b"xfs", b"vfat", b"msdos"];

/// A filesystem's own identity, `own` — its answer through the mount — as
/// the row reports it: `Vouched`, in the form its type gives it, for a type
/// in [`SELF_NAMING_TYPES`], and `None` for every other (the owner's ruling
/// 210).
fn vouched_own_identity(fs_type: &[u8], own: VolumeIdentity) -> Option<IdentityReading> {
  SELF_NAMING_TYPES
    .contains(&fs_type)
    .then(|| super::linux_identity(fs_type, own, IdentityAssurance::Vouched))
    .flatten()
}

/// A btrfs filesystem's FSID, asked of it through `fd`:
/// `BTRFS_IOC_FS_INFO`, which needs no privilege.
///
/// `fd` must be a descriptor opened for reading on a btrfs filesystem —
/// `fstatfs` said so — and the answer is the filesystem's `fs_devices->fsid`,
/// the one its `/sys/fs/btrfs/<fsid>` directory is named by. The kernel copies
/// the whole structure out, or fails.
///
/// **Every failure is the error it is.** `btrfs_ioctl` serves the command for
/// every file on btrfs (`fs/btrfs/ioctl.c`, `case BTRFS_IOC_FS_INFO`, at
/// Linux v6.12), and `btrfs_ioctl_fs_info` answers or fails to copy
/// (`EFAULT`, `ENOMEM`); nothing it answers is a declared absence. So a
/// refusal on the way — a security module's `EACCES` or `EPERM` among them —
/// fails the row, never reads as a filesystem with no FSID.
fn btrfs_fs_info(fd: &OwnedFd) -> io::Result<[u8; btrfs_fs_info::FSID_LEN]> {
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
  injected_identity_error().map_or(asked, Err)?;
  let mut fsid = [0; btrfs_fs_info::FSID_LEN];
  fsid.copy_from_slice(&args.0[btrfs_fs_info::FSID..btrfs_fs_info::FSID + btrfs_fs_info::FSID_LEN]);
  Ok(fsid)
}

/// A btrfs filesystem's label, asked of it through `fd`: `FS_IOC_GETFSLABEL`,
/// which needs no privilege — see [`btrfs_label_in`] for how the answer is
/// read. `None` for a filesystem that carries none: an empty label, which
/// `btrfs_ioctl_get_fslabel` answers by copying nothing (`fs/btrfs/ioctl.c`),
/// is the one absence it declares. `btrfs_ioctl` serves the command for every
/// file on btrfs (`case FS_IOC_GETFSLABEL`, the number
/// `BTRFS_IOC_GET_FSLABEL` is defined as, `include/uapi/linux/btrfs.h`), so
/// **every failure is the error it is**, never a filesystem with no label.
fn btrfs_fs_label(fd: &OwnedFd) -> io::Result<Option<SmallBytes>> {
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
  injected_identity_error().map_or(asked, Err)?;
  btrfs_label_in(&label)
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
/// zero is no answer btrfs gives, and is `InvalidData`. The bytes before the
/// first zero are weighed by the one rule every label road is
/// ([`is_a_label`](super::is_a_label)): none, or text that is nothing but
/// whitespace, is no label, and bytes that are not UTF-8 are kept whole.
fn btrfs_label_in(buffer: &[u8; FSLABEL_MAX]) -> io::Result<Option<SmallBytes>> {
  let len = buffer.iter().position(|&byte| byte == 0).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidData,
      "a btrfs label that fills the whole buffer, which btrfs never copies",
    )
  })?;
  let label = &buffer[..len];
  Ok(super::is_a_label(label).then(|| SmallBytes::from_bytes(label)))
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
  ///
  /// A lookup the kernel could not keep beneath the root because of a race
  /// is asked again, a bounded number of times, and one never proven is
  /// refused: see [`Unproven`].
  fn open_beneath(
    &self,
    path: &Path,
    oflags: OFlags,
    resolve: ResolveFlags,
  ) -> io::Result<OwnedFd> {
    beneath(|| {
      rustix::fs::openat2(
        &self.root,
        path,
        oflags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | resolve,
      )
    })
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
  /// link; and a lookup that failed is `Failed`.
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
    self.read_regular(path, ResolveFlags::NO_SYMLINKS, u64::MAX)
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
    self.read_regular(path, ResolveFlags::empty(), u64::MAX)
  }

  /// Reads at most `limit` bytes of a file beneath this root.
  ///
  /// The unbounded read is for files the kernel writes, whose length the kernel
  /// decides. A file this crate cannot authenticate is not one of those.
  fn read_bounded(&self, path: &Path, limit: u64) -> Reading<Vec<u8>> {
    self.read_regular(path, ResolveFlags::NO_SYMLINKS, limit)
  }

  /// At most `limit` bytes of the regular file `path` names beneath this
  /// root, reached under `resolve`: the one road every file read on this
  /// backend takes — see [`open_regular`](Self::open_regular).
  fn read_regular(&self, path: &Path, resolve: ResolveFlags, limit: u64) -> Reading<Vec<u8>> {
    self
      .open_regular(path, resolve)
      .and_then(|file| read_whole(file, limit))
  }

  /// The regular file `path` names beneath this root, reached under
  /// `resolve` and opened for reading **only once it is proven a regular
  /// file** — the one open for reading every file read on this backend makes.
  ///
  /// None of the roots is authenticated as to *whose* its contents are —
  /// `/run` and `/dev` are `tmpfs`, which any user may mount, and a namespace
  /// the process does not own can present its own `/proc` and `/sys` — and an
  /// open for reading acts on what it opens: a FIFO's open waits for a writer
  /// (`fs/pipe.c` `fifo_open`, `wait_for_partner`, at Linux v6.12), and a
  /// device's open is its driver's (`fs/namei.c` `may_open` lets both
  /// through). So:
  ///
  /// 1. **The name is opened `O_PATH`**, with `O_NOFOLLOW` where the road
  ///    follows no link: an `O_PATH` open resolves the name and opens nothing
  ///    (`fs/open.c` `do_dentry_open` returns before any `f_op->open`), so a
  ///    FIFO or a device there is named, not opened.
  /// 2. **What it names must be a regular file** (`fstat`, `S_ISREG`); a FIFO,
  ///    a device, a socket, a directory or a link is declined — not there as
  ///    the thing asked for — and nothing is opened.
  /// 3. **That exact file is reopened for reading through the descriptor**,
  ///    never by its name again: the calling thread's `fd/<n>` beneath the
  ///    authenticated `/proc`, whose link is the descriptor's own path
  ///    (`fs/proc/fd.c` `proc_fd_link`, followed by `nd_jump_link` in
  ///    `fs/namei.c`), so a name swapped for a FIFO or a device in between is
  ///    not what is opened. The reopen is `O_RDONLY | O_NONBLOCK | O_NOCTTY`:
  ///    no flag changes what an open of a regular file does.
  /// 4. **The reopened file must be the same file** — the same device and
  ///    inode, and still regular — or it is declined.
  ///
  /// No `/proc` to reopen through is a road closed, as everywhere here.
  fn open_regular(&self, path: &Path, resolve: ResolveFlags) -> Reading<OwnedFd> {
    let nofollow = if resolve.contains(ResolveFlags::NO_SYMLINKS) {
      OFlags::NOFOLLOW
    } else {
      OFlags::empty()
    };
    reading(self.open_beneath(path, OFlags::PATH | OFlags::CLOEXEC | nofollow, resolve))
      .and_then(|node| regular(&node).map(|stat| (node, stat)))
      .and_then(|(node, named)| {
        reopened_for_reading(&node).and_then(|file| {
          regular(&file).and_then(|opened| {
            if (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino) {
              Reading::Value(file)
            } else {
              Reading::Declined(io::Error::new(
                io::ErrorKind::InvalidData,
                "the file reopened through its descriptor is not the file the name named",
              ))
            }
          })
        })
      })
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

/// `fd`'s `stat`, where it holds a regular file; declined for anything else —
/// see [`KernelDir::open_regular`].
fn regular(fd: &OwnedFd) -> Reading<rustix::fs::Stat> {
  reading(rustix::fs::fstat(fd)).and_then(|stat| {
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::RegularFile {
      Reading::Value(stat)
    } else {
      Reading::Declined(io::Error::new(
        io::ErrorKind::InvalidData,
        "not a regular file, which is never opened for reading",
      ))
    }
  })
}

/// The file `node`, an `O_PATH` descriptor, holds, opened for reading
/// through the calling thread's `fd/<n>` beneath the authenticated `/proc`:
/// the directory reached structurally, and the one component that names the
/// descriptor followed as the kernel's magic link — by `openat`, since the
/// kernel refuses to jump a magic link inside a scoped lookup
/// (`nd_jump_link`: `LOOKUP_IS_SCOPED`). See [`KernelDir::open_regular`].
fn reopened_for_reading(node: &OwnedFd) -> Reading<OwnedFd> {
  use rustix::fd::AsRawFd as _;

  proc_root().and_then(|proc| {
    procfs_thread(&proc)
      .and_then(|thread| {
        let fds = KernelDir::at(&[&thread, b"fd"]);
        reading(proc.open_beneath(
          Path::new(OsStr::from_bytes(&fds)),
          OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
          ResolveFlags::NO_SYMLINKS,
        ))
      })
      .and_then(|fds| {
        let number = node.as_raw_fd().to_string();
        reading(rustix::fs::openat(
          &fds,
          number.as_str(),
          OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
          Mode::empty(),
        ))
      })
  })
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
///
/// **It ends within [`READ_LIMIT`] names, or the census is refused.** Every
/// directory this backend reads is one the kernel keeps beneath `/sys` or
/// `/proc`, and each is a live view: a refill resumes where the one before
/// left off in the directory as it stands then — sysfs after the hash of the
/// last name handed over, in a tree of names ordered by hash
/// (`kernfs_fop_readdir`, `kernfs_dir_pos` and `kernfs_sd_compare` in
/// `fs/kernfs/dir.c` at Linux v6.12), procfs after as many names as it handed
/// over (`proc_readdir_de`, `fs/proc/generic.c`) — so a name added while the
/// directory is read can lie ahead of it, and a directory that keeps growing
/// need never end. A read handed more names than the bound ends in
/// [`Unbounded`], which [`declined`] names: the census is refused as a declined
/// refill refuses it, never the names read before.
fn listing(dir: OwnedFd) -> Reading<Census<Vec<u8>>> {
  listing_up_to(dir, READ_LIMIT)
}

/// [`listing`], refused once it has been handed more than `most` names, which
/// laws stand in for.
fn listing_up_to(dir: OwnedFd, most: usize) -> Reading<Census<Vec<u8>>> {
  use core::mem::MaybeUninit;

  let mut buffer = vec![MaybeUninit::<u8>::uninit(); LISTING_BUFFER];
  let mut entries = rustix::fs::RawDir::new(&dir, &mut buffer);
  Census::read(
    most,
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

/// udev's own record of one block device — `/run/udev/data/b<major>:<minor>`
/// — as the facts it states: **the one publication every fact udev states
/// about a device is read out of**, and read again after them.
///
/// udev keeps a device's devlinks and its database record apart, and updates
/// them apart. A devlink under `/dev/disk/by-*` is one claim of several,
/// re-pointed as each claimant's event is processed (`udev_node_update`,
/// systemd v255 `src/udev/udev-node.c`), while the record is written once
/// for each event processed, whole, into a temporary file renamed over it
/// (`device_update_db`, `src/libsystemd/sd-device/device-private.c`:
/// `fopen_temporary`, the lines, then `rename`). So the directories are no
/// one publication — a device's `by-diskseq` link can be current while its
/// `by-uuid` link, or its record, is still another attach's — and the record
/// is: one event's devlinks (`S:`, each relative to `/dev`) and one event's
/// properties (`E:`), which a reader sees whole or not at all. It is named by
/// the device number (`b<major>:<minor>`, `device_get_device_id`), which a
/// new attach can take over; what ties it to one attach is the devlink
/// udev's rules name after the kernel's `DISKSEQ`
/// (`rules.d/60-persistent-storage.rules.in`:
/// `SYMLINK+="disk/by-diskseq/$env{DISKSEQ}$env{.PART_SUFFIX}"`).
#[derive(Debug, PartialEq)]
struct UdevRecord {
  /// The record as it was read, which the second read must equal.
  bytes: Vec<u8>,
  /// Every attach its `disk/by-diskseq/` devlinks spell — see
  /// [`parse_by_diskseq_name`] — `None` for a name that spells none.
  attaches: Vec<Option<Sequence>>,
  /// Every identity its `disk/by-uuid/` devlinks spell — see
  /// [`parse_by_uuid_name`](super::parse_by_uuid_name) — `None` for a name
  /// this crate cannot classify, which is still a name for the device.
  identities: Vec<Option<VolumeIdentity>>,
  /// Every label its `disk/by-label/` devlinks spell, decoded, `None` for one
  /// that decodes to no label — see [`is_a_label`](super::is_a_label).
  labels: Vec<Option<SmallBytes>>,
}

/// One udev database record as the facts it states — see [`UdevRecord`] —
/// held whole before any line of it is looked at: udev ends every line it
/// writes, so one cut short is no record it wrote, and a devlink's name
/// must decode strictly — see [`whole_lines`] and [`decode_udev_escapes`].
/// Either failing is `InvalidData`.
fn udev_record_in(bytes: Vec<u8>) -> io::Result<UdevRecord> {
  let mut attaches = Vec::new();
  let mut identities = Vec::new();
  let mut labels = Vec::new();
  for line in whole_lines(&bytes)? {
    let Some(devlink) = line.strip_prefix(b"S:") else {
      continue;
    };
    if let Some(name) = devlink.strip_prefix(b"disk/by-diskseq/") {
      attaches.push(parse_by_diskseq_name(name));
    } else if let Some(name) = devlink.strip_prefix(b"disk/by-uuid/") {
      identities.push(super::parse_by_uuid_name(name));
    } else if let Some(name) = devlink.strip_prefix(b"disk/by-label/") {
      let label = decode_udev_escapes(name)?;
      labels.push(super::is_a_label(label.as_bytes()).then_some(label));
    }
  }
  Ok(UdevRecord {
    bytes,
    attaches,
    identities,
    labels,
  })
}

/// udev's record of `device`, read whole beneath `run` — see [`UdevRecord`]
/// — or `None` where there is none to read. The containment is the same as
/// everywhere else: `RESOLVE_BENEATH`, `RESOLVE_NO_XDEV` and
/// `RESOLVE_NO_SYMLINKS` beneath the `/run` the caller opened, and a bounded
/// read. A read that failed is the error it is, and so is a record udev could
/// not have written.
///
/// **This source cannot be authenticated, as no `/run` and no `/dev` can.**
/// `/run` is tmpfs, which any user may mount, so what the record says is a
/// claim by whoever controls `/run`; it is reported at the level the row's
/// source earns, never vouched — see [`IdentityAssurance`].
fn udev_record(run: &KernelDir, device: u64) -> io::Result<Option<UdevRecord>> {
  /// A udev database record for one device is a short list of short lines.
  /// Reading past this is reading something that is not one.
  const LIMIT: u64 = 64 * 1024;

  let (major, minor) = unmakedev(device);
  let path = format!("udev/data/b{major}:{minor}");
  match run.read_bounded(Path::new(&path), LIMIT).answered()? {
    Some(bytes) => udev_record_in(bytes).map(Some),
    None => Ok(None),
  }
}

/// The identity and the label `record` states for `device`, read out of it
/// alone: the identity its `by-uuid` devlinks spell, in the form `fs_type`
/// gives it — two that disagree, or one this crate cannot classify, are none
/// (see [`linux_identity_for_device`](super::linux_identity_for_device)); the
/// label its `by-label` devlinks spell, at `assurance`, two that disagree
/// none; and otherwise its own `ID_FS_LABEL_ENC`, never above
/// [`Declared`](super::IdentityAssurance::Declared) — see [`udev_label_in`].
fn record_facts(
  record: &UdevRecord,
  device: u64,
  fs_type: &[u8],
  assurance: IdentityAssurance,
) -> io::Result<(Option<IdentityReading>, Option<super::NameReading>)> {
  let identity = super::linux_identity_for_device(
    record.identities.iter().map(|&identity| (device, identity)),
    device,
    fs_type,
    assurance,
  );
  let mut spelled: Option<&SmallBytes> = None;
  let mut agreed = true;
  for label in &record.labels {
    match (label, spelled) {
      (Some(label), None) => spelled = Some(label),
      (Some(label), Some(seen)) if label == seen => {}
      _ => {
        agreed = false;
        break;
      }
    }
  }
  let name = match spelled.filter(|_| agreed) {
    Some(name) => Some(super::NameReading {
      name: name.clone(),
      assurance,
    }),
    None => udev_label_in(&record.bytes)?.map(|name| super::NameReading {
      name,
      assurance: IdentityAssurance::Declared,
    }),
  };
  Ok((identity, name))
}

/// The label one udev database record carries: `ID_FS_LABEL_ENC`, decoded, or
/// `None` where the record has no such key or its value decodes to no label —
/// see [`is_a_label`](super::is_a_label).
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
  Ok(super::is_a_label(label.as_bytes()).then_some(label))
}

/// The major and minor a device number is made of — the inverse of
/// [`makedev`], for the one road that must spell a device the way udev names
/// its own records.
fn unmakedev(dev: u64) -> (u64, u64) {
  let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff);
  let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff);
  (major, minor)
}

/// The removal answer for a whole filesystem out of the answer for the device
/// its mount holds, `device_answer`: **a filesystem is as removable as every
/// device it is built on**, so a denial of the one device is the
/// filesystem's only where the filesystem is proven to be built on that
/// device alone — see [`built_on_its_source_alone`] — and is otherwise
/// [`Unknown`](super::Ejectability::Unknown). A yes about the device is a yes
/// about the filesystem, which lies on it whatever else it lies on; and an
/// `Unknown` stays one.
fn filesystem_removal(
  device_answer: Ejectability,
  fs_type: &[u8],
  super_options: &[u8],
) -> Ejectability {
  match device_answer {
    Ejectability::NotEjectable if !built_on_its_source_alone(fs_type, super_options) => {
      Ejectability::Unknown
    }
    answer => answer,
  }
}

/// Whether a filesystem of type `fs_type`, whose mount prints the
/// per-superblock options `super_options`, is **proven** to be built on the
/// one device its mount holds, and no other.
///
/// Block-layer members — what a device mapper table or an md array is built
/// from — are the device's own `slaves/`, and the removal road walks them.
/// A filesystem can also open devices of its own, which `slaves/` never
/// shows. At Linux v6.12 a filesystem opens a block device beside the one
/// its superblock holds (`fs/super.c:setup_bdev_super`) only through
/// `bdev_file_open_by_dev` or `bdev_file_open_by_path`, and in `fs/` those
/// are called by exactly these (a search of the v6.12 tree for every
/// block-device open):
///
/// - btrfs, for every member: its own road, see [`btrfs_removal`];
/// - ext4, for an external journal (`ext4_load_journal` and
///   `ext4_get_journal_blkdev`, `fs/ext4/super.c` 5977-5981 and 5828-5841),
///   by the number its superblock or a `journal_dev=` or `journal_path=`
///   option names — and the mount table never shows it: those two options
///   carry neither `MOPT_SET` nor `MOPT_CLEAR` (1879-1880), which
///   `_ext4_show_options` skips (2942-2944). The same driver mounts `ext2`
///   and `ext3`, and loads a journal wherever the superblock has one;
/// - XFS, for an external log and a realtime device (`xfs_open_devices` and
///   `xfs_blkdev_get`, `fs/xfs/xfs_super.c` 447-458 and 371), opened only
///   for a `logdev=` or `rtdev=` name, which `xfs_fs_show_options` prints
///   whenever it is set (202-205);
/// - F2FS, for every further device its superblock lists
///   (`f2fs_scan_devices`, `fs/f2fs/super.c` 4220-4275);
/// - JFS, for an external log (`lmLogOpen`, `fs/jfs/jfs_logmgr.c` 1103);
/// - EROFS, for its extra devices (`erofs_init_device`,
///   `fs/erofs/super.c` 189);
/// - bcachefs, for every member (`fs/bcachefs/super-io.c` 733-739);
/// - reiserfs, for a journal device (`fs/reiserfs/journal.c` 2619-2634);
/// - OCFS2's cluster heartbeat (`fs/ocfs2/cluster/heartbeat.c`), and the
///   pNFS block layout and `pstore`, which are no block mounts.
///
/// So the proof is by type: a filesystem the kernel implements that opens no
/// device but its source — FAT (`vfat`, `msdos`), exFAT, NTFS (`ntfs3`, and
/// `ntfs`, which ntfs3 serves at v6.12), ISO 9660, UDF, HFS, HFS+, NILFS2,
/// SquashFS, cramfs, romfs, MINIX, UFS and zonefs — or XFS whose options name
/// no `logdev` and no `rtdev`. Every other type is not proven — ext2, ext3
/// and ext4, whose external journal the table cannot show; F2FS, JFS, EROFS,
/// bcachefs, reiserfs and OCFS2; `fuseblk`, whose server may keep its data
/// anywhere; and any type outside the kernel's tree.
fn built_on_its_source_alone(fs_type: &[u8], super_options: &[u8]) -> bool {
  match fs_type {
    b"xfs" => super_options.split(|&byte| byte == b',').all(|option| {
      let name = option.split(|&byte| byte == b'=').next().unwrap_or(option);
      name != b"logdev" && name != b"rtdev"
    }),
    b"vfat" | b"msdos" | b"exfat" | b"ntfs3" | b"ntfs" | b"iso9660" | b"udf" | b"hfs"
    | b"hfsplus" | b"nilfs2" | b"squashfs" | b"cramfs" | b"romfs" | b"minix" | b"ufs"
    | b"zonefs" => true,
    _ => false,
  }
}

/// Whether an ext filesystem mounted from `device` is proven built on that
/// device alone by its journal (the owner's ruling 211), read beneath the
/// kernel's own roots: see [`ext_built_alone`]. The device's kernel name is
/// the last component of its `/sys/dev/block/<major>:<minor>` link — the
/// name `%pg` prints for it, `/` spelled `!`, as the block layer names its
/// sysfs directory — and every read that does not answer is no proof.
fn ext_journal_proven_alone(
  sysfs: &KernelDir,
  proc: &KernelDir,
  fs_type: &[u8],
  device: u64,
) -> bool {
  if !matches!(fs_type, b"ext2" | b"ext3" | b"ext4") {
    return false;
  }
  let (major, minor) = unmakedev(device);
  let link = format!("dev/block/{major}:{minor}");
  let Some(target) = sysfs.link_target(Path::new(&link)).evidence() else {
    return false;
  };
  let Some(name) = target.rsplit(|&byte| byte == b'/').next() else {
    return false;
  };
  if name.is_empty() || name == b"." || name == b".." {
    return false;
  }
  let journals: Vec<Vec<u8>> = proc
    .dir(Path::new("fs/jbd2"))
    .evidence()
    .map(|entries| entries.into_iter().collect())
    .unwrap_or_default();
  let task = KernelDir::at(&[b"fs/ext4", name, b"journal_task"]);
  let journal_task = sysfs.read(Path::new(OsStr::from_bytes(&task))).evidence();
  ext_built_alone(fs_type, name, &journals, journal_task.as_deref())
}

/// Whether an ext filesystem whose device the kernel names `name` is proven
/// built on that device alone, out of the names `/proc/fs/jbd2` lists
/// (`journals`) and its `/sys/fs/ext4/<name>/journal_task` (`journal_task`).
/// Verified against Linux v6.12:
///
/// - **ext3 and ext4: an internal journal.** jbd2 names each journal's
///   `/proc/fs/jbd2` directory by `j_devname`
///   (`fs/jbd2/journal.c` `jbd2_stats_proc_init`), which is `%pg-%lu` of the
///   filesystem's own device and the journal inode for a journal in an inode
///   (`jbd2_journal_init_inode`, whose device is `inode->i_sb->s_bdev`) and
///   `%pg` of the journal's device alone for an external one
///   (`jbd2_journal_init_dev`), `/` spelled `!` in both. So a directory named
///   exactly `<name>-<digits>` is this filesystem's journal, in an inode on
///   its own device — and a filesystem has one journal. No such directory —
///   an external journal, no journal, a journal not yet loaded — proves
///   nothing.
/// - **ext2: no journal at all.** The ext4 driver, which serves `ext2`, loads
///   a clean superblock's journal when it has one, so `ext2` proves nothing
///   by its type; its `journal_task` reads `<none>` exactly where it holds no
///   journal (`fs/ext4/sysfs.c` `journal_task_show`), under the directory
///   named `sb->s_id`, the device's `%pg`. The older ext2 driver keeps no such
///   directory, and proves nothing.
fn ext_built_alone(
  fs_type: &[u8],
  name: &[u8],
  journals: &[Vec<u8>],
  journal_task: Option<&[u8]>,
) -> bool {
  match fs_type {
    b"ext3" | b"ext4" => journals.iter().any(|journal| {
      journal
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix(b"-"))
        .is_some_and(|inode| !inode.is_empty() && inode.iter().all(u8::is_ascii_digit))
    }),
    b"ext2" => journal_task == Some(b"<none>\n"),
    _ => false,
  }
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
/// - an ancestry through a USB root hub that no `fixed` denied — the kernel
///   saying the drive hangs off a bus whose devices leave while the machine
///   runs. A root hub is what [`is_usb_root_hub`] reads, here and where the
///   denial above excepts one: `usb` and the bus number, never `usb` alone;
/// - any of those on a device a virtual device is **built from**. A dm-crypt
///   volume over a USB disk is as removable as the disk under it, so `slaves/`
///   is walked, to a bounded depth. A virtual device is denied only where every
///   device it is built from is.
///
/// **The mount's own device number is the mount's.** A mounted block device
/// keeps its number for as long as the mount exists — verified against the
/// Linux v6.12 source. The mount holds the device open
/// (`fs/super.c:setup_bdev_super`, released only by `kill_block_super`, at
/// unmount); the open holds the device (`block/bdev.c:blkdev_get_no_open`);
/// and a number is freed only after the device's last opener has gone
/// (`block/genhd.c:disk_release` and the driver's `free_disk`;
/// `block/bdev.c:bdev_free_inode` for an extended minor). A device that leaves
/// while mounted goes through `del_gendisk`, which frees no number: it only
/// unhashes the device and deletes its sysfs entry. Before the 5.11 rework,
/// `sd_open` held the same number through `scsi_disk_get`. So sysfs, read by
/// the number the superblock carries, answers for the mount's own device or,
/// once the device has left, for nothing: `dev/block/<major>:<minor>` is gone,
/// and the answer is [`Unknown`](super::Ejectability::Unknown) — never another
/// device's.
///
/// **A stack's members are another matter.** A device mapper table holds its
/// members, not the mount, and a table swapped, or an md member replaced or
/// added, changes what the held number stands for — and a member the table let
/// go can have its number handed to another device. So the members a stack is
/// built from are taken as the walk reads them — each member's `diskseq` where
/// the kernel publishes one, and each layer's member set — and must be the same
/// after the whole answer: see [`Topology`]. Anything that moved is
/// [`Unknown`](super::Ejectability::Unknown).
///
/// `sysfs` is the root [`removal_root`] opened for this question alone; like
/// every other failure on this road, one that could not be had is `Unknown`
/// rather than an error.
fn bound_removal(sysfs: &KernelDir, device: u64) -> Ejectability {
  bound_removal_with(sysfs, device, || {})
}

/// [`bound_removal`], with `between` run after the answer was read and before
/// its stacks are taken again — where a law moves one.
fn bound_removal_with(sysfs: &KernelDir, device: u64, between: impl FnOnce()) -> Ejectability {
  let mut topology = Topology::default();
  let answer = device_removal(sysfs, device, 0, &mut topology);
  between();
  if topology.still_holds(sysfs) {
    answer
  } else {
    Ejectability::Unknown
  }
}

/// The removal answer for a btrfs filesystem, `fsid` — the FSID the mount
/// answered — whose source member, `member`, the census bound to it.
///
/// **A btrfs filesystem is as removable as every device it is built on, as a
/// stack is.** One filesystem may span several devices — a RAID1 across an
/// internal disk and a USB one — and any of them can carry its data, so the
/// source the mount names, which is only the device it was mounted through,
/// answers for none of the others. So every member the kernel's btrfs map
/// lists for the filesystem (`/sys/fs/btrfs/<fsid>/devices/`, where the
/// directory is named by the same `fs_devices->fsid` the mount's
/// `BTRFS_IOC_FS_INFO` answered, and a sprout lists its seed's devices beside
/// its own) is read, and the answers are joined as a stack's members are: a
/// yes on any member is a yes; a denial needs one on every member, and also
/// the map's word that no member the filesystem counts is missing from that
/// list (one `devinfo/<devid>` entry per member listed, each `missing` reading
/// `0`, Linux 5.6: see [`btrfs_none_missing`]); anything else is
/// [`Unknown`](super::Ejectability::Unknown). The source must be one of the
/// members listed.
///
/// **A btrfs member is not a single-device superblock's device.** A btrfs
/// mount's own `st_dev` is anonymous (`fs/btrfs/super.c`, `sget_fc` with
/// `set_anon_super_fc`), so the mount holds no member through
/// `setup_bdev_super`: the filesystem holds each member itself
/// (`volumes.c:btrfs_open_one_device`), and only while it is one. An online
/// removal (`btrfs_rm_device`, which hands the member's open file back to its
/// caller to release) or a device replace (which closes the source device)
/// lets a member go while the mount lives, and its number can then be handed
/// to another device. So every member is taken with its attach — its
/// `diskseq`, where the kernel publishes one — before anything is read about
/// any of them, and after the answer the map must list exactly the same
/// members, each must keep its attach, and every stack under one must hold as
/// every stack must ([`Topology`]). Anything else, a map that cannot be read
/// whole included, is [`Unknown`](super::Ejectability::Unknown); where no
/// sequence is published, nothing is withheld for it.
fn btrfs_removal(sysfs: &KernelDir, member: u64, fsid: &VolumeIdentity) -> Ejectability {
  btrfs_removal_with(sysfs, member, fsid, || {})
}

/// [`btrfs_removal`], with `between` run after the answer was read and before
/// the members are taken again — where a law moves one.
fn btrfs_removal_with(
  sysfs: &KernelDir,
  member: u64,
  fsid: &VolumeIdentity,
  between: impl FnOnce(),
) -> Ejectability {
  let Some(members) = btrfs_members(sysfs, fsid) else {
    return Ejectability::Unknown;
  };
  if !members.contains(&member) {
    return Ejectability::Unknown;
  }
  let mut topology = Topology::default();
  for &device in &members {
    topology.member(sysfs, device);
  }
  let mut answer = None;
  let mut every_one_fixed = true;
  for &device in &members {
    match device_removal(sysfs, device, 0, &mut topology) {
      Ejectability::Ejectable => {
        answer = Some(Ejectability::Ejectable);
        break;
      }
      Ejectability::NotEjectable => {}
      _ => every_one_fixed = false,
    }
  }
  between();
  let answer = match answer {
    Some(answer) => answer,
    None if every_one_fixed && btrfs_none_missing(sysfs, fsid, members.len()) => {
      Ejectability::NotEjectable
    }
    None => return Ejectability::Unknown,
  };
  if btrfs_members(sysfs, fsid).as_ref() == Some(&members) && topology.still_holds(sysfs) {
    answer
  } else {
    Ejectability::Unknown
  }
}

/// Every device the kernel's btrfs map lists for the filesystem `fsid` names
/// (`/sys/fs/btrfs/<fsid>/devices/`, each a link to the block device, whose
/// `dev` names its number), sorted — or `None` where the listing, or any one
/// member's number, could not be read, or it lists none.
fn btrfs_members(sysfs: &KernelDir, fsid: &VolumeIdentity) -> Option<Vec<u64>> {
  let name = fsid.to_string();
  let devices = KernelDir::at(&[BTRFS_SYSFS_ROOT.as_bytes(), name.as_bytes(), b"devices"]);
  let listed = sysfs
    .dir(Path::new(OsStr::from_bytes(&devices)))
    .evidence()?;
  let mut members = Vec::new();
  for member in listed {
    // The member is a link the kernel put there on purpose, so this one read
    // follows it — still beneath `/sys` and still across no mount.
    let dev = KernelDir::at(&[&devices, &member, b"dev"]);
    members.push(sysfs_device_number(sysfs, Path::new(OsStr::from_bytes(&dev))).evidence()?);
  }
  if members.is_empty() {
    return None;
  }
  members.sort_unstable();
  Some(members)
}

/// Whether the kernel's btrfs map says that its `devices/` listing of the
/// filesystem `fsid`, `listed` members long, is the whole of it: one
/// `devinfo/<devid>` entry for each member listed, and every one's `missing`
/// reading exactly `0`.
///
/// The kernel files every device the filesystem holds, a sprout's seeds
/// included, under both directories, but links a device into `devices/` only
/// where it has a block device, and marks one without it missing
/// (`fs/btrfs/sysfs.c`, `btrfs_sysfs_add_fs_devices` and
/// `btrfs_sysfs_add_device`; `btrfs_devinfo_missing_show`). A map that says
/// nothing of it (before Linux 5.6), or cannot be read whole, says no such
/// thing.
fn btrfs_none_missing(sysfs: &KernelDir, fsid: &VolumeIdentity, listed: usize) -> bool {
  let name = fsid.to_string();
  let devinfo = KernelDir::at(&[BTRFS_SYSFS_ROOT.as_bytes(), name.as_bytes(), b"devinfo"]);
  let Some(counted) = sysfs.dir(Path::new(OsStr::from_bytes(&devinfo))).evidence() else {
    return false;
  };
  let mut count = 0usize;
  for devid in counted {
    count += 1;
    let missing = KernelDir::at(&[&devinfo, &devid, b"missing"]);
    if sysfs
      .read(Path::new(OsStr::from_bytes(&missing)))
      .evidence()
      .as_deref()
      != Some(b"0\n")
    {
      return false;
    }
  }
  count == listed
}

/// What a stack a removal answer is read from is built from, taken as the walk
/// reads it, so that it can be taken again after: see [`bound_removal`].
///
/// A member's attach is its `diskseq`, which only a new device gets
/// (`block/genhd.c:__alloc_disk_node`, the one caller of `inc_diskseq`): a
/// member the table let go and a device given its number since carry
/// different ones. Where the kernel keeps none — its own word, see
/// [`Attach::Unsupported`] — there is nothing to compare, and nothing is
/// withheld for it; a member whose attach could not be read at all
/// ([`Attach::Unread`]) is no such word, and the answer does not hold. What a
/// layer is built from is its own fact: the kernel changes no `diskseq` when a
/// device mapper table is swapped or an md member is replaced or added, so
/// each layer's members — the names its `slaves/` lists — are taken as a set,
/// and must be the same set after. The mount's own device needs neither: the
/// mount holds its number.
#[derive(Default)]
struct Topology {
  /// Every member read about whose attach the kernel publishes, with it.
  attaches: Vec<(u64, Sequence)>,
  /// Whether a member's attach could not be read: nothing witnesses it, so
  /// nothing read about it holds.
  unread: bool,
  /// Every stack layer walked, with the members it listed, sorted.
  layers: Vec<(u64, Vec<Vec<u8>>)>,
}

impl Topology {
  /// Whether every member's attach was read, every member is still the
  /// attach it was taken at, and every layer still lists exactly the members
  /// it listed.
  fn still_holds(&self, sysfs: &KernelDir) -> bool {
    !self.unread && self.attaches_hold(sysfs) && self.members_hold(sysfs)
  }

  /// Whether every member is still the attach it was taken at — one that has
  /// since left publishes none, and one whose attach cannot be read now names
  /// none, neither of which is the same.
  fn attaches_hold(&self, sysfs: &KernelDir) -> bool {
    self
      .attaches
      .iter()
      .all(|&(device, attach)| device_sequence(sysfs, device) == Attach::Named(attach))
  }

  /// Whether every layer still lists exactly the members it listed.
  fn members_hold(&self, sysfs: &KernelDir) -> bool {
    self
      .layers
      .iter()
      .all(|(layer, members)| layer_members(sysfs, *layer).as_ref() == Some(members))
  }
}

/// What the removal road takes of a stack as it reads it: see [`Topology`].
trait Holding {
  /// A member the walk is about to read about: its attach is taken where the
  /// kernel publishes one, and a member whose attach could not be read leaves
  /// nothing read about it standing.
  fn member(&mut self, sysfs: &KernelDir, device: u64);
  /// The members a stack layer listed, as the walk is about to read them.
  fn members(&mut self, layer: u64, members: &[Vec<u8>]);
}

impl Holding for Topology {
  fn member(&mut self, sysfs: &KernelDir, device: u64) {
    match device_sequence(sysfs, device) {
      Attach::Named(attach) => self.attaches.push((device, attach)),
      Attach::Unsupported => {}
      Attach::Unread => self.unread = true,
    }
  }

  fn members(&mut self, layer: u64, members: &[Vec<u8>]) {
    self.layers.push((layer, members.to_vec()));
  }
}

/// The members a stack layer's `slaves/` lists — each a block device of its
/// own — sorted, read to the end the kernel proves; `None` where the
/// directory could not be read whole.
///
/// Reached with `dir_linked`, because `dev/block/<major>:<minor>` is itself a
/// symlink: a structural open refuses it before `slaves` is ever read, and the
/// walk then never ran on any real kernel.
fn layer_members(sysfs: &KernelDir, layer: u64) -> Option<Vec<Vec<u8>>> {
  let (major, minor) = unmakedev(layer);
  let listed = sysfs
    .dir_linked(Path::new(&format!("dev/block/{major}:{minor}/slaves")))
    .evidence()?;
  let mut members: Vec<Vec<u8>> = listed.into_iter().collect();
  members.sort();
  Some(members)
}

/// The removal answer as a row asks it, `Unknown` without a root or a device,
/// for the laws that hold the topology rules of [`bound_removal`] to fixture
/// trees.
#[cfg(test)]
fn device_ejectability(sysfs: Option<&KernelDir>, device: Option<u64>) -> Ejectability {
  let (Some(sysfs), Some(device)) = (sysfs, device) else {
    return Ejectability::Unknown;
  };
  bound_removal(sysfs, device)
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

/// What sysfs says of a block device's attach: see [`device_sequence`].
///
/// **Only the kernel's own word that it keeps no sequence is an absence.** A
/// read that failed, or found what the kernel does not write, is no answer at
/// all, and nothing may stand on it: a removal answer it would have to witness
/// is [`Unknown`](super::Ejectability::Unknown), and udev's facts it would
/// have to date are not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attach {
  /// The attach the kernel names now.
  Named(Sequence),
  /// The kernel keeps no sequence for any disk: the disk's directory is
  /// there, its `dev` beside it, and it holds no `diskseq` (before Linux
  /// 5.15). A device is then held by its number alone, as it always was.
  Unsupported,
  /// Nothing was learned: a read failed, the device was not there to ask, or
  /// what was read is not the kernel's writing.
  Unread,
}

/// The attach of `device` sysfs names now — see [`Sequence`] and [`Attach`]
/// — read beneath `sysfs` by the device number, as every removal fact is.
///
/// A number that is not one decimal line, a `partition` or `diskseq` that
/// could not be read, and a device that is not there are all
/// [`Attach::Unread`]. [`Attach::Unsupported`] needs the kernel's own word: a
/// `diskseq` the lookup did not find, and then the disk's directory, listed
/// whole, holding its `dev` and no `diskseq`. On a kernel that keeps
/// sequences every disk carries `diskseq` — one of the disk type's attributes,
/// hidden on none (`block/genhd.c` at v6.12: `disk_attrs` 1112, `disk_visible`
/// 1123-1131, `disk_type` 1224-1226) — and the device core creates it, with
/// the type's attribute groups, before `dev` and the `dev/block` link, and
/// removes the link and `dev` before them (`drivers/base/core.c` at v6.12:
/// `device_add` 3626, then 3638 and 3642; `device_del` 3841-3842, then 3860).
/// So a listing that shows `dev` shows `diskseq` there too, and a disk that
/// left, or another that took its number, between the two reads is no such
/// listing.
fn device_sequence(sysfs: &KernelDir, device: u64) -> Attach {
  let (major, minor) = unmakedev(device);
  let block = format!("dev/block/{major}:{minor}");
  // A partition's sequence is its disk's, and its number within the disk
  // tells it from the disk's other partitions.
  let (disk, partition) = match sysfs.read_linked(Path::new(&format!("{block}/partition"))) {
    Reading::Value(number) => match decimal_line(&number) {
      Some(number) => (format!("{block}/.."), Some(number)),
      None => return Attach::Unread,
    },
    Reading::Declined(err) if err.kind() == io::ErrorKind::NotFound => (block, None),
    Reading::Absent | Reading::Declined(_) | Reading::Failed(_) => return Attach::Unread,
  };
  match sysfs.read_linked(Path::new(&format!("{disk}/diskseq"))) {
    Reading::Value(sequence) => match decimal_line(&sequence) {
      Some(sequence) => Attach::Named(Sequence {
        disk: sequence,
        partition,
      }),
      None => Attach::Unread,
    },
    Reading::Declined(err) if err.kind() == io::ErrorKind::NotFound => {
      match sysfs.dir_linked(Path::new(&disk)).evidence() {
        Some(names) => {
          let names: Vec<Vec<u8>> = names.into_iter().collect();
          let holds = |name: &[u8]| names.iter().any(|held| held.as_slice() == name);
          if holds(b"dev") && !holds(b"diskseq") {
            Attach::Unsupported
          } else {
            Attach::Unread
          }
        }
        None => Attach::Unread,
      }
    }
    Reading::Absent | Reading::Declined(_) | Reading::Failed(_) => Attach::Unread,
  }
}

/// One line of decimal digits, as sysfs writes a number.
fn decimal_line(contents: &[u8]) -> Option<u64> {
  parse_u64(contents.strip_suffix(b"\n")?)
}

/// Which publication of udev's the facts about a device are read out of: see
/// [`udev_publication`].
#[derive(Debug, PartialEq)]
enum UdevPublication {
  /// The record udev wrote for the attach the kernel names now: every
  /// `by-diskseq` devlink in it spells that attach, and it has one.
  Current(Sequence, UdevRecord),
  /// The kernel keeps no attach for any disk — its own word, see
  /// [`Attach::Unsupported`] — so the record is bound by the device number
  /// alone, as it always was, which the facts' `Published` and `Declared`
  /// assurances say out loud.
  Unattached(UdevRecord),
  /// No publication binds the device's facts, and nothing udev says of the
  /// device is read: the attach could not be read (no `/sys`, a read that
  /// failed, what the kernel does not write), there is no record, or the
  /// record names no attach, another attach, or one beside the current.
  Stale,
}

/// The publication udev's facts about `device` are read out of: the
/// device's attach first — see [`device_sequence`] — and then udev's record
/// of it beneath `run`, which must name that attach — see [`UdevRecord`].
///
/// **An attach the kernel names and the record does not publish is stale,
/// never unpublished.** A record that names no attach is one udev wrote
/// before it saw this attach, for another device under the number, or under
/// rules that name none (systemd before 251, and the device mapper's own
/// rules) — and nothing tells those apart, so none of its facts is read.
/// Only a kernel that keeps no attach at all leaves the record bound by the
/// number alone.
fn udev_publication(
  sysfs: Option<&KernelDir>,
  run: Option<&KernelDir>,
  device: u64,
) -> io::Result<UdevPublication> {
  let attach = match sysfs.map(|sysfs| device_sequence(sysfs, device)) {
    Some(Attach::Named(attach)) => Some(attach),
    Some(Attach::Unsupported) => None,
    Some(Attach::Unread) | None => return Ok(UdevPublication::Stale),
  };
  let record = match run {
    Some(run) => udev_record(run, device)?,
    None => None,
  };
  let Some(record) = record else {
    return Ok(UdevPublication::Stale);
  };
  Ok(match attach {
    Some(attach)
      if !record.attaches.is_empty()
        && record.attaches.iter().all(|&named| named == Some(attach)) =>
    {
      UdevPublication::Current(attach, record)
    }
    Some(_) => UdevPublication::Stale,
    None => UdevPublication::Unattached(record),
  })
}

/// Whether the publication `device`'s facts were read out of still stands
/// after them: the kernel names the same attach — or still keeps none — and
/// udev's record is, byte for byte, the record they were read out of. A
/// record rewritten while the facts were read, one removed, and an attach
/// replaced are each no longer that publication.
fn publication_holds(
  sysfs: Option<&KernelDir>,
  run: Option<&KernelDir>,
  device: u64,
  attach: Option<Sequence>,
  record: &UdevRecord,
) -> io::Result<bool> {
  let kernel = match (sysfs.map(|sysfs| device_sequence(sysfs, device)), attach) {
    (Some(Attach::Named(now)), Some(then)) => now == then,
    (Some(Attach::Unsupported), None) => true,
    _ => false,
  };
  if !kernel {
    return Ok(false);
  }
  let again = match run {
    Some(run) => udev_record(run, device)?,
    None => None,
  };
  Ok(again.is_some_and(|again| again.bytes == record.bytes))
}

/// udev's identity and label for `device`, read out of **one publication**
/// — see [`udev_publication`] — and taken only where that publication still
/// stands after them — see [`publication_holds`]; `between` runs after the
/// facts are read and before, where a law moves something. A filesystem that
/// names itself through its mount, `mounted`, holds the publication to it:
/// where the record names another identity, or none, everything it says —
/// the label with the identity — is some other filesystem's, and none of it
/// is reported. `(None, None)` wherever no publication binds the facts.
fn published_facts_with(
  sysfs: Option<&KernelDir>,
  run: Option<&KernelDir>,
  device: u64,
  fs_type: &[u8],
  assurance: IdentityAssurance,
  mounted: Option<VolumeIdentity>,
  between: impl FnOnce(),
) -> io::Result<(Option<IdentityReading>, Option<super::NameReading>)> {
  let (attach, record) = match udev_publication(sysfs, run, device)? {
    UdevPublication::Current(attach, record) => (Some(attach), record),
    UdevPublication::Unattached(record) => (None, record),
    UdevPublication::Stale => return Ok((None, None)),
  };
  let (identity, name) = record_facts(&record, device, fs_type, assurance)?;
  if mounted.is_some() && identity.map(|reading| reading.identity()) != mounted {
    return Ok((None, None));
  }
  between();
  Ok(if publication_holds(sysfs, run, device, attach, &record)? {
    (identity, name)
  } else {
    (None, None)
  })
}

/// A `/dev/disk/by-diskseq` name as the attach it spells, as systemd's rules
/// spell it (systemd 251): `<diskseq>` for a disk, `<diskseq>-part<n>` for a
/// partition. `None` for anything else, which is still a name for its device.
fn parse_by_diskseq_name(name: &[u8]) -> Option<Sequence> {
  let (disk, partition) = match name.windows(5).position(|window| window == b"-part") {
    Some(at) => (&name[..at], Some(parse_u64(&name[at + 5..])?)),
    None => (name, None),
  };
  Some(Sequence {
    disk: parse_u64(disk)?,
    partition,
  })
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
/// built from: see [`bound_removal`] for every road and its order. `holding`
/// is handed each stack layer's members as they are listed, and each member
/// before anything is read about it.
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
  holding: &mut dyn Holding,
) -> Ejectability {
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
  let Some(slaves) = layer_members(sysfs, device) else {
    return Ejectability::Unknown;
  };
  holding.members(device, &slaves);
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
    holding.member(sysfs, number);
    match device_removal(sysfs, number, depth + 1, holding) {
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
/// A USB device is what [`is_usb_device`] reads, and a root hub what
/// [`is_usb_root_hub`] reads — the one grammar the bus fallback,
/// [`names_removable_bus`], reads too.
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
/// `.<port>` for each hub below the root hub — the name `usb_alloc_dev`
/// gives every device but a root hub, `"%d-%s"` of the bus number and the
/// device's path of ports (`drivers/usb/core/usb.c` 699-717 at Linux v6.12).
/// An interface (`1-3:1.0`) and a root hub (`usb1`: see [`is_usb_root_hub`])
/// are not.
fn is_usb_device(name: &[u8]) -> bool {
  let mut halves = name.splitn(2, |&byte| byte == b'-');
  let (Some(bus), Some(ports)) = (halves.next(), halves.next()) else {
    return false;
  };
  let digits = |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
  digits(bus) && ports.split(|&byte| byte == b'.').all(digits)
}

/// Whether a device directory's name is a USB root hub's: `usb`, then one or
/// more decimal digits, and nothing else. This is **the one grammar for a USB
/// controller in a device path**, and both roads that look for one read it:
/// the root-hub exemption in [`ports_say`] and the bus fallback,
/// [`names_removable_bus`].
///
/// Verified against Linux v6.12: the USB core names the root hub of every
/// bus it registers `usb` and the bus number in decimal (`usb_alloc_dev`,
/// `"usb%d"` of `bus->busnum`, `drivers/usb/core/usb.c` 696), the child of
/// the bus's host controller (694) and the device every other device on the
/// bus hangs below (716-717; see [`is_usb_device`]). Of the other names it
/// gives, a hub's port is `usb<bus>-port<n>` (`drivers/usb/core/port.c` 763)
/// and an interface `<bus>-<port>:<configuration>.<interface>`
/// (`drivers/usb/core/message.c` 2145); and `usb` alone is the bus type's
/// name (`usb_bus_type`, `drivers/usb/core/driver.c` 2045), the directory
/// `/sys/bus/usb`, and no device's. So `usb` alone, `usb1-port1`, `usbx` and
/// `xusb1` are not root hubs.
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
/// taken out while the machine runs: whether one of its components is a USB
/// root hub, as [`is_usb_root_hub`] reads one — the one grammar, which the
/// root-hub exemption in [`ports_say`] reads too.
///
/// The kernel spells the path of `/sys/dev/block/<major>:<minor>` through the
/// devices the block device hangs off, so a USB disk reads
/// `.../usb1/1-3/1-3:1.0/host6/.../block/sdb`. A whole component is matched,
/// never a part of one, and only the root hub's own spelling: a directory
/// named `usb` alone, `usb1-port1` or `xusb1` is not the bus.
fn names_removable_bus(ancestry: &[u8]) -> bool {
  ancestry.split(|&byte| byte == b'/').any(is_usb_root_hub)
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

  /// **A filesystem is denied only where it is proven to be built on the
  /// device its mount holds alone.** A denial of that device is the
  /// filesystem's for the types the kernel implements that open no other
  /// device, and for XFS with no `logdev` or `rtdev` among the options its
  /// mount prints; for ext2, ext3 and ext4 (an external journal the table
  /// never shows), F2FS, JFS, EROFS, bcachefs, reiserfs, OCFS2, `fuseblk`, a
  /// type outside the kernel, and XFS with an external log or a realtime
  /// device, it is `Unknown`. A yes and an `Unknown` stand as they are. The
  /// planted defect, side by side: the road as it was took the device's
  /// denial for the filesystem's, whatever it was built on.
  #[test]
  fn test_a_filesystem_is_denied_only_where_it_is_built_on_its_source_alone() {
    use super::super::Ejectability::{Ejectable, NotEjectable, Unknown};

    let xfs_logdev = parse_record(
      b"36 35 8:1 / /data rw,relatime - xfs /dev/sda1 rw,relatime,attr2,inode64,logdev=/dev/sdb1,noquota",
    )
    .unwrap();
    let xfs_rtdev = parse_record(
      b"36 35 8:1 / /data rw,relatime - xfs /dev/sda1 rw,relatime,rtdev=/dev/sdc\\0541,noquota",
    )
    .unwrap();
    let xfs_alone = parse_record(
      b"36 35 8:1 / /data rw,relatime - xfs /dev/sda1 rw,relatime,attr2,logbufs=8,noquota",
    )
    .unwrap();
    let ext4 = parse_record(b"36 35 8:1 / /data rw,relatime - ext4 /dev/sda1 rw,relatime").unwrap();
    let denied = |line: &MountLine| {
      filesystem_removal(
        NotEjectable,
        line.fs_type.as_bytes(),
        line.super_options.as_bytes(),
      )
    };
    assert_eq!(denied(&xfs_alone), NotEjectable);
    assert_eq!(denied(&xfs_logdev), Unknown);
    assert_eq!(denied(&xfs_rtdev), Unknown);
    assert_eq!(denied(&ext4), Unknown);
    for fs_type in [
      &b"vfat"[..],
      b"msdos",
      b"exfat",
      b"ntfs3",
      b"ntfs",
      b"iso9660",
      b"udf",
      b"hfsplus",
      b"nilfs2",
    ] {
      assert_eq!(
        filesystem_removal(NotEjectable, fs_type, b"rw"),
        NotEjectable
      );
    }
    for fs_type in [
      &b"ext2"[..],
      b"ext3",
      b"ext4",
      b"f2fs",
      b"jfs",
      b"erofs",
      b"bcachefs",
      b"reiserfs",
      b"ocfs2",
      b"fuseblk",
      b"zfs",
      b"somefs",
    ] {
      assert_eq!(filesystem_removal(NotEjectable, fs_type, b"rw"), Unknown);
      assert_eq!(filesystem_removal(Ejectable, fs_type, b"rw"), Ejectable);
      assert_eq!(filesystem_removal(Unknown, fs_type, b"rw"), Unknown);
    }
    assert_eq!(
      filesystem_removal(Ejectable, b"xfs", xfs_logdev.super_options.as_bytes()),
      Ejectable
    );
    // An option only named like one is not it.
    assert!(built_on_its_source_alone(
      b"xfs",
      b"rw,logdevice=x,rtdevs=y"
    ));

    // The planted defect: the device's answer taken for the filesystem's.
    let before = |answer: super::super::Ejectability, _line: &MountLine| answer;
    assert_eq!(before(NotEjectable, &ext4), NotEjectable);
    assert_eq!(before(NotEjectable, &xfs_logdev), NotEjectable);
  }

  /// **A failed read of the filesystem's own identity fails the resolve;
  /// only the kernel's declared decline degrades to udev.** `ENOTTY` is
  /// "no such identity here", and anything else — `EIO`, `EINTR`, `EFAULT` —
  /// is the error it is: injected into the root's own self-identity ioctl,
  /// `EIO` fails the resolve, and `ENOTTY` leaves a resolve whose identity is
  /// not the filesystem's `Vouched` one. The planted defect, side by side:
  /// the classification before, `.ok()`, took every error for "none".
  #[test]
  fn test_a_failed_identity_read_fails_the_resolve() {
    use rustix::io::Errno;

    assert!(identity_asked(Ok(())).unwrap());
    assert!(!identity_asked(Err(Errno::NOTTY)).unwrap());
    for errno in [
      Errno::IO,
      Errno::INTR,
      Errno::FAULT,
      Errno::OPNOTSUPP,
      Errno::MFILE,
    ] {
      assert_eq!(
        identity_asked(Err(errno)).unwrap_err().raw_os_error(),
        Some(errno.raw_os_error()),
        "{errno:?}"
      );
    }

    let root_fs = {
      let proc = proc_fixture();
      let pinned = Pinned::of(Path::new("/"), &proc).required().unwrap();
      let table = MountTable::read(&proc).unwrap();
      let line = table.line(pinned.mount_id()).unwrap();
      line.fs_type.as_bytes().to_vec()
    };
    let inject = |errno: Option<Errno>| INJECTED_IDENTITY_ERROR.with(|cell| cell.set(errno));
    // btrfs asks no self-identity ioctl on this road, and a root whose own
    // answer is not asked cannot be failed by it.
    if !crate::is_btrfs(&root_fs) {
      inject(Some(Errno::IO));
      let failed = crate::resolve(Path::new("/"));
      inject(None);
      match failed {
        Err(err) => assert_eq!(err.raw_os_error(), Some(Errno::IO.raw_os_error()), "{err}"),
        // A root this process may not reopen is never asked: nothing failed.
        Ok(row) => assert!(
          !row
            .volume_identity()
            .is_some_and(|reading| reading.is_vouched()),
          "{row:?}"
        ),
      }

      inject(Some(Errno::NOTTY));
      let degraded = crate::resolve(Path::new("/"));
      inject(None);
      let degraded = degraded.expect("a declared decline fails nothing");
      assert!(
        !degraded
          .volume_identity()
          .is_some_and(|reading| reading.is_vouched()),
        "{degraded:?}"
      );
    }

    // The planted defect: every error taken for "no identity".
    let before = |asked: rustix::io::Result<()>| asked.ok().is_some();
    assert!(!before(Err(Errno::IO)), "EIO read as none");
  }

  /// **A file bind mount of a self-naming filesystem is `Vouched`**: its
  /// root is a regular file, reopened through the pin as every file read is
  /// and asked the same question a directory would be. Run against the real
  /// ext4 and FAT loop mounts a CI job makes, each with a file of it bound
  /// over a file elsewhere; ignored elsewhere.
  #[test]
  #[ignore = "needs WHICHDISK_FILE_BIND_* mounts made by a privileged CI step"]
  fn test_a_live_file_bind_mount_is_vouched() {
    let pairs = [
      (
        "WHICHDISK_FILE_BIND_EXT4_MOUNT",
        "WHICHDISK_FILE_BIND_EXT4_FILE",
      ),
      (
        "WHICHDISK_FILE_BIND_FAT_MOUNT",
        "WHICHDISK_FILE_BIND_FAT_FILE",
      ),
    ];
    for (mount, file) in pairs {
      let mount = PathBuf::from(std::env::var(mount).unwrap());
      let file = PathBuf::from(std::env::var(file).unwrap());
      let whole = crate::resolve(&mount).unwrap();
      let bound = crate::resolve(&file).unwrap();
      println!(
        "{}: {:?}\n{}: {:?}",
        mount.display(),
        whole.mount_info(),
        file.display(),
        bound.mount_info()
      );
      assert_eq!(
        bound.mount_point(),
        file.as_path(),
        "the file is its own mount"
      );
      let identity = bound
        .volume_identity()
        .expect("the filesystem names itself");
      assert!(identity.is_vouched(), "{identity:?}");
      assert_eq!(
        Some(identity),
        whole.volume_identity(),
        "the same filesystem"
      );
    }
  }

  /// **An ext filesystem's denial needs its journal proven on its own
  /// device, or none** (the owner's ruling 211): ext3 and ext4 by jbd2's
  /// `<name>-<inode>` directory, which names a journal in an inode on the
  /// filesystem's own device, and never by an external journal's `<name>`;
  /// ext2 by `journal_task` reading `<none>`. The reading road finds the
  /// name through the sysfs link and the directories beneath fixture roots.
  /// The planted defect, side by side: a match by prefix alone takes
  /// `sda10-8`, another device's journal, for `sda1`'s.
  #[test]
  fn test_an_ext_denial_needs_its_journal_proven_on_its_own_device() {
    let journals = |names: &[&str]| {
      names
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect::<Vec<_>>()
    };
    for fs_type in [&b"ext3"[..], b"ext4"] {
      assert!(ext_built_alone(
        fs_type,
        b"sda1",
        &journals(&["sda1-8"]),
        None
      ));
      assert!(ext_built_alone(
        fs_type,
        b"cciss!c0d0p1",
        &journals(&["dm-0", "cciss!c0d0p1-8"]),
        None
      ));
      assert!(
        !ext_built_alone(fs_type, b"sda1", &journals(&["sdb1"]), None),
        "an external journal"
      );
      assert!(
        !ext_built_alone(fs_type, b"sda1", &journals(&["sda10-8"]), None),
        "another device's"
      );
      assert!(!ext_built_alone(
        fs_type,
        b"sda1",
        &journals(&["sda1-"]),
        None
      ));
      assert!(!ext_built_alone(
        fs_type,
        b"sda1",
        &journals(&["sda1-8x"]),
        None
      ));
      assert!(
        !ext_built_alone(fs_type, b"sda1", &[], Some(b"<none>\n")),
        "no journal is not the letter"
      );
    }
    assert!(ext_built_alone(b"ext2", b"sda1", &[], Some(b"<none>\n")));
    assert!(!ext_built_alone(
      b"ext2",
      b"sda1",
      &journals(&["sda1-8"]),
      Some(b"1234\n")
    ));
    assert!(
      !ext_built_alone(b"ext2", b"sda1", &[], None),
      "the older driver proves nothing"
    );
    assert!(!ext_built_alone(
      b"xfs",
      b"sda1",
      &journals(&["sda1-8"]),
      Some(b"<none>\n")
    ));

    // The reading road, beneath fixture roots.
    let sys = tempfile::tempdir().unwrap();
    let block = sys.path().join("devices/pci0/block/sda/sda1");
    std::fs::create_dir_all(&block).unwrap();
    std::fs::create_dir_all(sys.path().join("dev/block")).unwrap();
    std::os::unix::fs::symlink(
      "../../devices/pci0/block/sda/sda1",
      sys.path().join("dev/block/8:1"),
    )
    .unwrap();
    std::fs::create_dir_all(sys.path().join("fs/ext4/sda1")).unwrap();
    std::fs::write(sys.path().join("fs/ext4/sda1/journal_task"), "<none>\n").unwrap();
    let proc = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(proc.path().join("fs/jbd2/sda1-8")).unwrap();
    let (sysfs, procfs) = (fixture(sys.path()), fixture(proc.path()));
    let device = makedev(8, 1);
    assert!(ext_journal_proven_alone(&sysfs, &procfs, b"ext4", device));
    assert!(ext_journal_proven_alone(&sysfs, &procfs, b"ext2", device));
    assert!(!ext_journal_proven_alone(
      &sysfs,
      &procfs,
      b"ext4",
      makedev(8, 2)
    ));
    std::fs::remove_dir(proc.path().join("fs/jbd2/sda1-8")).unwrap();
    std::fs::create_dir_all(proc.path().join("fs/jbd2/sda10-8")).unwrap();
    assert!(!ext_journal_proven_alone(&sysfs, &procfs, b"ext4", device));

    // The planted defect: a match by prefix alone.
    let before = |name: &[u8], journal: &[u8]| journal.starts_with(name);
    assert!(before(b"sda1", b"sda10-8"));
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

  // ── the containment's race ────────────────────────────────────────

  /// A lookup the kernel could not keep beneath its root is asked again, and
  /// the first other answer stands; one never proven is refused as a climb out
  /// of the root is, never failing the read and never taken as an answer. An
  /// `EAGAIN` from any other call is not a refusal.
  #[test]
  fn test_a_lookup_raced_out_of_its_root_is_asked_again_then_refused() {
    use rustix::io::Errno;

    let root = || {
      rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
      )
    };
    // Raced, then proven: the lookup's own answer, on the first or the last
    // ask the budget allows.
    for raced in [1, 2, BENEATH_TRIES - 1] {
      let mut asked = 0;
      let answered = beneath(|| {
        asked += 1;
        if asked <= raced {
          Err(Errno::AGAIN)
        } else {
          root()
        }
      });
      assert!(answered.is_ok(), "raced {raced} times");
      assert_eq!(asked, raced + 1);
    }

    // Never proven: asked exactly the budget, then refused by the
    // containment.
    let mut asked = 0;
    let err = beneath(|| {
      asked += 1;
      Err(Errno::AGAIN)
    })
    .unwrap_err();
    assert_eq!(asked, BENEATH_TRIES);
    assert!(declined(&err), "{err}");
    assert!(matches!(reading(Err::<(), _>(err)), Reading::Declined(_)));

    // Any other answer stands at once, sorted as it always was.
    for (errno, refusal) in [(Errno::XDEV, true), (Errno::LOOP, true), (Errno::IO, false)] {
      let mut asked = 0;
      let err = beneath(|| {
        asked += 1;
        Err(errno)
      })
      .unwrap_err();
      assert_eq!(asked, 1, "{errno:?}");
      assert_eq!(Errno::from_io_error(&err), Some(errno));
      assert_eq!(declined(&err), refusal, "{errno:?}");
    }

    // An `EAGAIN` from any other call is the failure it is.
    assert!(!declined(&io::Error::from(Errno::AGAIN)));

    // The planted defect, side by side: a lookup asked once hands the raced
    // `EAGAIN` back, and it fails the whole read instead of being asked again.
    let once: io::Result<OwnedFd> = Err(io::Error::from(Errno::AGAIN));
    assert!(matches!(reading(once), Reading::Failed(_)));
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

  /// **A label that is nothing but whitespace is no label on every Linux
  /// road**, by the one rule every platform's label is weighed by
  /// ([`is_a_label`](super::super::is_a_label)): btrfs's own answer, a
  /// `by-label` name in udev's record and its `ID_FS_LABEL_ENC` each answer
  /// none for spaces, a tab, a no-break space and an ideographic space —
  /// escaped as udev's encoder escapes a byte it does not keep, or kept as it
  /// keeps valid UTF-8. A label padded with spaces keeps them, and bytes that
  /// are not UTF-8 are kept byte for byte. The planted defect, side by side:
  /// the rule every road had, which kept any byte at all.
  #[test]
  fn test_a_blank_label_is_no_label_on_every_linux_road() {
    let btrfs = |label: &[u8]| {
      let mut buffer = [0u8; FSLABEL_MAX];
      buffer[..label.len()].copy_from_slice(label);
      btrfs_label_in(&buffer)
        .unwrap()
        .map(|label| label.as_bytes().to_vec())
    };
    let by_label = |name: &[u8]| {
      let record = udev_record_in([&b"S:disk/by-label/"[..], name, b"\n"].concat()).unwrap();
      record
        .labels
        .into_iter()
        .map(|label| label.map(|label| label.as_bytes().to_vec()))
        .collect::<Vec<_>>()
    };
    let encoded = |value: &[u8]| {
      udev_label_in(&[&b"E:ID_FS_LABEL_ENC="[..], value, b"\n"].concat())
        .unwrap()
        .map(|label| label.as_bytes().to_vec())
    };
    let before = |label: &[u8]| (!label.is_empty()).then(|| label.to_vec());

    let blanks: [(&[u8], &[u8]); 6] = [
      (b"   ", br"\x20\x20\x20"),
      (b"\t", br"\x09"),
      (b" \t ", br"\x20\x09\x20"),
      ("\u{a0}".as_bytes(), "\u{a0}".as_bytes()),
      ("\u{3000}".as_bytes(), "\u{3000}".as_bytes()),
      (" \u{3000} ".as_bytes(), "\\x20\u{3000}\\x20".as_bytes()),
    ];
    for (blank, written) in blanks {
      assert_eq!(btrfs(blank), None, "{blank:?}");
      assert_eq!(by_label(written), vec![None], "{written:?}");
      assert_eq!(encoded(written), None, "{written:?}");
      assert_eq!(
        before(blank),
        Some(blank.to_vec()),
        "the old rule kept {blank:?}"
      );
    }
    let labels: [(&[u8], &[u8]); 4] = [
      (b" BACKUP ", br"\x20BACKUP\x20"),
      (b"My Disk", br"My\x20Disk"),
      (b"\xff\x20", br"\xff\x20"),
      (b" \xc3", br"\x20\xc3"),
    ];
    for (label, written) in labels {
      assert_eq!(btrfs(label), Some(label.to_vec()), "{label:?}");
      assert_eq!(by_label(written), vec![Some(label.to_vec())], "{written:?}");
      assert_eq!(encoded(written), Some(label.to_vec()), "{written:?}");
    }
  }

  /// **A row whose label is blank is named from its mount point.** A blank
  /// btrfs label, and a udev record whose `by-label` name and
  /// `ID_FS_LABEL_ENC` are blank, give the row no label at all, so
  /// [`volume_name()`](super::super::MountPoint::volume_name) falls back to
  /// the mount point's last component and no label assurance is reported.
  /// The planted defect, side by side: the label as the roads kept it, which
  /// named the row with a blank and suppressed the fallback.
  #[test]
  fn test_a_row_with_a_blank_label_is_named_from_its_mount_point() {
    use observed::{BtrfsMount, btrfs_facts};

    let row = |name: Option<super::super::NameReading>| {
      let mut row = crate::resolve("/").unwrap().mount_info().clone();
      row.mount_point = SmallBytes::from_bytes(b"/media/alice/usb");
      row.volume_name = name;
      row
    };

    let mut buffer = [0u8; FSLABEL_MAX];
    buffer[..3].copy_from_slice(b"   ");
    let label = btrfs_label_in(&buffer).unwrap();
    let (_, name) = btrfs_facts(
      BtrfsMount::for_laws(
        fsid(FSID_A).unwrap(),
        label.as_ref().map(SmallBytes::as_bytes),
      ),
      true,
      IdentityAssurance::Published,
    );
    let named = row(name);
    assert_eq!(named.volume_name(), Some("usb"));
    assert_eq!(named.volume_name_assurance(), None);

    let record =
      udev_record_in(b"S:disk/by-label/\\x20\\x20\nE:ID_FS_LABEL_ENC=\\x20\\x20\n".to_vec())
        .unwrap();
    let (_, name) = record_facts(
      &record,
      makedev(8, 1),
      b"ext4",
      IdentityAssurance::Published,
    )
    .unwrap();
    let named = row(name);
    assert_eq!(named.volume_name(), Some("usb"));
    assert_eq!(named.volume_name_assurance(), None);

    // The planted defect: the blank kept as a label names the row with it.
    let kept = row(Some(super::super::NameReading {
      name: SmallBytes::from_bytes(b"  "),
      assurance: IdentityAssurance::Published,
    }));
    assert_eq!(kept.volume_name(), Some("  "));
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

  /// **A filesystem's own identity is reported `Vouched`, and only its own**
  /// (the owner's ruling 210): the root's identity is `Vouched` exactly where
  /// the mounted filesystem names itself through the pinned mount
  /// (`FS_IOC_GETFSUUID`, the FAT serial, btrfs's FSID), and is then that
  /// identity; elsewhere it is udev's, `Published` or `Declared`, or none. The
  /// planted defect, side by side: the level before, udev's record alone,
  /// which never vouched for what the filesystem itself answers.
  #[test]
  fn test_a_linux_reading_is_vouched_only_by_the_filesystem_itself() {
    use crate::is_btrfs;

    let roots = observed::Roots::open_for_laws().unwrap();
    let Some((line, pinned)) = observed::root_line_for_laws(&roots) else {
      return;
    };
    let fs_type = line.fs_type.as_bytes().to_vec();
    let own = observed::mount_root_for_laws(&line, &pinned, &roots)
      .and_then(|root| filesystem_identity(&root, &fs_type).unwrap())
      .and_then(|own| vouched_own_identity(&fs_type, own));
    let reading = root_observation(&pinned).into_row().volume_identity();
    println!(
      "root {}: the filesystem names {own:?}; the row reports {reading:?}",
      String::from_utf8_lossy(&fs_type)
    );
    match own {
      Some(own) if !is_btrfs(&fs_type) => {
        assert_eq!(reading, Some(own), "the filesystem's own identity, vouched");
      }
      _ if !is_btrfs(&fs_type) => {
        assert!(
          !reading.is_some_and(|reading| reading.is_vouched()),
          "{reading:?}"
        );
      }
      _ => {}
    }

    // The planted defect: udev's record alone, at the line's level.
    let published =
      own.map(|own| IdentityReading::at(own.identity(), IdentityAssurance::Published));
    assert!(!published.is_some_and(|reading| reading.is_vouched()));
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

  /// A mount table standing in for a namespace that mounts anew as fast as
  /// its table is read: every read hands over whole records, and there is
  /// always another, up to `stop` of them, which is the only end a read with
  /// no bound of its own would come to.
  struct Growing {
    stop: usize,
    handed: usize,
  }

  impl std::io::Read for Growing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
      const RECORD: &[u8] = b"21 1 8:1 / / rw - ext4 /dev/sda1 rw\n";
      let mut written = 0;
      while self.handed < self.stop && buf.len() - written >= RECORD.len() {
        buf[written..written + RECORD.len()].copy_from_slice(RECORD);
        written += RECORD.len();
        self.handed += 1;
      }
      Ok(written)
    }
  }

  /// **A mount table read ends within its bound, or the table is refused.**
  /// A table whose every read hands over more records — standing in, at four
  /// times the bound, for one growing as fast as it is read — is stopped once
  /// it has been handed more than the bound, and refused with [`Unbounded`] —
  /// a decline, so nothing read of it is kept — however much it held; a table
  /// of exactly as many records as the bound is read whole. The planted
  /// defect, side by side: a read with no bound — the table read to its end
  /// before — takes every record the view hands over, and ends only because
  /// the stand-in stops handing them.
  #[test]
  fn test_a_mount_table_read_past_its_bound_is_refused() {
    let err = records_up_to(
      Growing {
        stop: 4 * 64,
        handed: 0,
      },
      64,
    )
    .unwrap_err();
    assert!(
      err.get_ref().is_some_and(|inner| inner.is::<Unbounded>()),
      "{err}"
    );
    assert!(declined(&err), "refused, as a census is");

    let whole = records_up_to(
      Growing {
        stop: 64,
        handed: 0,
      },
      64,
    )
    .unwrap();
    assert_eq!(MountTable::parse(&whole).unwrap().0.len(), 64);
    assert!(
      records_up_to(
        Growing {
          stop: 65,
          handed: 0,
        },
        64,
      )
      .is_err(),
      "one record more is refused"
    );

    // The planted defect: no bound, the read to its end before.
    let mut growing = Growing {
      stop: 4 * 64,
      handed: 0,
    };
    let before = records_up_to(&mut growing, usize::MAX).unwrap();
    assert_eq!(growing.handed, 4 * 64, "it took every record handed");
    assert_eq!(MountTable::parse(&before).unwrap().0.len(), 4 * 64);
  }

  /// **A directory read ends within its bound, or its census is refused.** A
  /// directory of five names read with a bound of five is its census; with a
  /// bound of four, the read is refused with [`Unbounded`] — declined, as a
  /// refill the kernel declined refuses it — and never the four names read
  /// before. The planted defect, side by side: with no bound — the listing
  /// before — every name handed over is taken, for as long as the directory
  /// hands them.
  #[test]
  fn test_a_directory_read_past_its_bound_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a", "b", "c", "d", "e"] {
      std::fs::write(dir.path().join(name), b"").unwrap();
    }
    let open = || {
      rustix::fs::open(
        dir.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
      )
      .unwrap()
    };
    let Reading::Value(census) = listing_up_to(open(), 5) else {
      panic!("a directory within its bound is its census");
    };
    let mut names: Vec<Vec<u8>> = census.into_iter().collect();
    names.sort();
    assert_eq!(
      names,
      [b"a", b"b", b"c", b"d", b"e"].map(|name| name.to_vec())
    );

    match listing_up_to(open(), 4) {
      Reading::Declined(err) => assert!(
        err.get_ref().is_some_and(|inner| inner.is::<Unbounded>()),
        "{err}"
      ),
      Reading::Value(_) => panic!("a directory past its bound is refused"),
      Reading::Absent | Reading::Failed(_) => panic!("refused as a declined refill is"),
    }

    // The planted defect: no bound, the listing before.
    let Reading::Value(census) = listing_up_to(open(), usize::MAX) else {
      panic!("with no bound the directory is read to its end");
    };
    assert_eq!(census.into_iter().count(), 5, "every name handed over");
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

  /// Writes `devinfo/<devid>/missing` for each of `devices` — a device id
  /// and the word, `0` or `1` — under a fixture filesystem, as Linux 5.6+
  /// publishes one entry for every device the filesystem counts.
  fn btrfs_devinfo_fixture(root: &Path, fsid: &str, devices: &[(&str, &str)]) {
    for (devid, missing) in devices {
      let entry = btrfs_dir(root, fsid).join("devinfo").join(devid);
      std::fs::create_dir_all(&entry).unwrap();
      std::fs::write(entry.join("missing"), format!("{missing}\n")).unwrap();
    }
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

  /// **A FIFO where a file is read never blocks the read.** A FIFO at a
  /// udev record's place beneath a `/run` fixture, reached by name and
  /// through a link, is declined by every read road — within a deadline,
  /// with no writer ever arriving — and a regular file beside it still reads.
  /// The planted defect, side by side: the open for reading the roads made
  /// before waits on the FIFO until a writer arrives, which the law then
  /// supplies to let it go.
  #[test]
  fn test_a_fifo_where_a_file_is_read_never_blocks() {
    use std::{sync::mpsc, thread, time::Duration};

    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("udev/data")).unwrap();
    let fifo = dir.path().join("udev/data/b8:1");
    rustix::fs::mknodat(
      rustix::fs::CWD,
      &fifo,
      rustix::fs::FileType::Fifo,
      Mode::RUSR | Mode::WUSR,
      0,
    )
    .unwrap();
    std::os::unix::fs::symlink("udev/data/b8:1", dir.path().join("link")).unwrap();
    std::fs::write(dir.path().join("udev/data/b8:2"), b"S:disk/by-diskseq/9\n").unwrap();

    let reads = {
      let root = dir.path().to_path_buf();
      move || {
        let run = fixture(&root);
        [
          run.read_bounded(Path::new("udev/data/b8:1"), 64 * 1024),
          run.read(Path::new("udev/data/b8:1")),
          run.read_linked(Path::new("udev/data/b8:1")),
          run.read_linked(Path::new("link")),
        ]
        .into_iter()
        .map(|read| matches!(read, Reading::Declined(ref err) if err.raw_os_error().is_none()))
        .collect::<Vec<_>>()
      }
    };
    let (sent, answered) = mpsc::channel();
    thread::spawn(move || sent.send(reads()).unwrap());
    let declined = answered
      .recv_timeout(Duration::from_secs(10))
      .expect("a read of a FIFO blocked");
    assert_eq!(declined, [true; 4], "every road declines the FIFO unopened");
    assert!(matches!(
      fixture(dir.path()).read_bounded(Path::new("udev/data/b8:2"), 64 * 1024),
      Reading::Value(ref bytes) if bytes == b"S:disk/by-diskseq/9\n"
    ));

    // The planted defect: the open for reading the roads made before.
    let (opened, done) = mpsc::channel();
    let root = dir.path().to_path_buf();
    let before = thread::spawn(move || {
      let run = fixture(&root);
      let fd = run.open_beneath(
        Path::new("udev/data/b8:1"),
        OFlags::RDONLY | OFlags::CLOEXEC,
        ResolveFlags::NO_SYMLINKS,
      );
      opened.send(()).unwrap();
      fd.is_ok()
    });
    assert!(
      done.recv_timeout(Duration::from_millis(500)).is_err(),
      "the open for reading the roads made before waits on the FIFO"
    );
    let _writer = rustix::fs::open(
      &fifo,
      OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
      Mode::empty(),
    )
    .unwrap();
    assert!(before.join().unwrap(), "a writer lets it go");
  }

  /// **A device where a file is read is never opened.** `null` beneath the
  /// real `/dev`, reached by every read road, is declined as no regular file
  /// before any open — the decline is the read's own, not the device's
  /// answer. The planted defect, side by side: the open for reading the
  /// roads made before opens the device itself.
  #[test]
  fn test_a_device_where_a_file_is_read_is_never_opened() {
    let Some(dev) = KernelDir::open("/dev", None).evidence() else {
      return;
    };
    for read in [
      dev.read(Path::new("null")),
      dev.read_linked(Path::new("null")),
      dev.read_bounded(Path::new("null"), 16),
    ] {
      assert!(
        matches!(read, Reading::Declined(ref err) if err.raw_os_error().is_none()),
        "{read:?}"
      );
    }

    // The planted defect: the device is opened.
    let opened = dev
      .open_beneath(
        Path::new("null"),
        OFlags::RDONLY | OFlags::CLOEXEC,
        ResolveFlags::NO_SYMLINKS,
      )
      .unwrap();
    assert_eq!(
      rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(&opened).unwrap().st_mode),
      rustix::fs::FileType::CharacterDevice,
      "the open before reached the device"
    );
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
    assert_eq!(
      identity.assurance(),
      IdentityAssurance::Vouched,
      "the filesystem's own answer through the mount"
    );
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

    let (identity, name) = btrfs_facts(mount(), true, IdentityAssurance::Declared);
    assert!(
      identity.unwrap().is_vouched(),
      "the FSID is the filesystem's, whatever the source earns"
    );
    assert_eq!(
      name.map(|name| name.assurance),
      Some(IdentityAssurance::Declared),
      "the label is held to the line's level"
    );

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

  /// **The listing's exclusions are directories, matched by whole
  /// components.** A mount at or beneath `/sys`, `/proc` or `/run` is left
  /// out, and one at or beneath `/run/media` is kept; a sibling whose name
  /// only begins with the same bytes is another directory — `/system`,
  /// `/process` and `/runner` are listed, and `/run/mediaevil` is left out
  /// with the rest of `/run`.
  #[cfg(feature = "list")]
  #[test]
  fn test_a_listing_excludes_whole_directories_and_nothing_beside_them() {
    let line = |mount_point: &str| {
      listed_line(format!("40 1 8:1 / {mount_point} rw - ext4 /dev/sda1 rw").as_bytes())
    };
    for listed in [
      "/system",
      "/process",
      "/runner",
      "/sysroot/data",
      "/run/media",
      "/run/media/al/USB",
      "/mnt/sys",
      "/",
    ] {
      assert!(line(listed).is_some(), "{listed} is listed");
    }
    for left_out in [
      "/sys",
      "/sys/fs/cgroup",
      "/proc",
      "/proc/sys/fs/binfmt_misc",
      "/run",
      "/run/user/1000",
      "/run/mediaevil",
      "/run/media-backup/x",
    ] {
      assert!(line(left_out).is_none(), "{left_out} is left out");
    }

    // The planted defect, side by side: the byte prefixes left out the
    // siblings and kept `/run/mediaevil` as `/run/media`.
    let before = |mp: &[u8]| {
      !(mp.starts_with(b"/sys")
        || mp.starts_with(b"/proc")
        || (mp.starts_with(b"/run") && !mp.starts_with(b"/run/media")))
    };
    assert!(!before(b"/system"));
    assert!(!before(b"/process"));
    assert!(!before(b"/runner"));
    assert!(before(b"/run/mediaevil"));
  }

  /// A mount id names its own line and no other — not a device number, which
  /// the kernel hands on to the next mount: what a listing's second census
  /// holds each row to.
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
    // Every block device carries its `dev`, the disk as well as its
    // partition.
    std::fs::write(
      disk_dir.join("dev"),
      format!("{}:{}\n", part_dev.0, part_dev.1 - 1),
    )
    .unwrap();
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

    // A listing reaches no mount by pathname, and a btrfs mount's FSID and
    // label are answered only through a descriptor on it: a listed btrfs row
    // is its census line, with neither, and its name the mount point's.
    #[cfg(feature = "list")]
    for listed in [&mount, &subvolume] {
      let rows = crate::list().unwrap();
      let row = rows
        .iter()
        .find(|row| row.mount_point() == listed.as_path())
        .unwrap_or_else(|| panic!("{} is listed", listed.display()));
      assert!(row.volume_identity().is_none(), "{row:?}");
      assert!(row.volume_name_assurance().is_none(), "{row:?}");
      assert_eq!(row.ejectability(), Ejectability::Unknown, "{row:?}");
    }
  }

  /// **A failed read of a btrfs filesystem's own answer fails the resolve.**
  /// `EACCES` injected into the FSID and label ioctls of the real btrfs mount
  /// a CI job makes fails its resolve with that error. The planted defect,
  /// side by side: the classification before, `answered()`, which read the
  /// same `EACCES` as no FSID, so the mount resolved with no identity, label
  /// or removal answer. Ignored elsewhere; see
  /// `test_a_live_btrfs_mount_binds_through_its_own_filesystem`.
  #[test]
  #[ignore = "needs a WHICHDISK_BTRFS_MOUNT mount made by a privileged CI step"]
  fn test_a_live_btrfs_failed_read_fails_the_resolve() {
    use rustix::io::Errno;

    let mount = PathBuf::from(std::env::var("WHICHDISK_BTRFS_MOUNT").unwrap());
    INJECTED_IDENTITY_ERROR.with(|cell| cell.set(Some(Errno::ACCESS)));
    let failed = crate::resolve(&mount);
    INJECTED_IDENTITY_ERROR.with(|cell| cell.set(None));
    let err = failed.expect_err("an EACCES on the filesystem's own read fails the resolve");
    println!("{}: {err}", mount.display());
    assert_eq!(
      err.raw_os_error(),
      Some(Errno::ACCESS.raw_os_error()),
      "{err}"
    );
    crate::resolve(&mount).expect("nothing injected, the mount resolves");

    // The planted defect: the same errno read as an absence.
    assert!(matches!(
      reading::<(), _>(Err(Errno::ACCESS)).answered(),
      Ok(None)
    ));
  }

  /// A USB disk as the kernel lays it out: the disk `sdb` and its first
  /// partition, beneath the SCSI device of a mass-storage interface of the
  /// last of the USB devices `ports` — each a device directory of its own,
  /// outermost first, below root hub `usb1`, with its `removable` word, or
  /// none — the disk's media flag written as `media`, and `dev/block/8:16` and
  /// `dev/block/8:17` linked to them. Returns the partition's directory,
  /// relative to the root.
  fn usb_disk_fixture(root: &Path, ports: &[(&str, Option<&str>)], media: &str) -> PathBuf {
    usb_disk_at(root, ports, media, ("sdb", "8:16", "8:17"))
  }

  /// [`usb_disk_fixture`], for the disk `name` at the number `disk` and its
  /// first partition at `partition`, both `M:m`: several disks side by side,
  /// each below ports of its own.
  fn usb_disk_at(
    root: &Path,
    ports: &[(&str, Option<&str>)],
    media: &str,
    (name, disk_number, partition_number): (&str, &str, &str),
  ) -> PathBuf {
    let hub = PathBuf::from("devices/pci0000:00/0000:00:14.0/usb1");
    std::fs::create_dir_all(root.join(&hub)).unwrap();
    std::fs::write(root.join(&hub).join("removable"), "unknown\n").unwrap();
    let mut relative = hub;
    for (port, word) in ports {
      relative = relative.join(port);
      std::fs::create_dir_all(root.join(&relative)).unwrap();
      if let Some(word) = word {
        std::fs::write(root.join(&relative).join("removable"), format!("{word}\n")).unwrap();
      }
    }
    let interface = format!("{}:1.0", ports.last().unwrap().0);
    let disk = relative
      .join(interface)
      .join("host6/target6:0:0/6:0:0:0/block")
      .join(name);
    let partition = disk.join(format!("{name}1"));
    std::fs::create_dir_all(root.join(&partition)).unwrap();
    std::fs::write(root.join(&disk).join("removable"), media).unwrap();
    std::fs::write(root.join(&disk).join("dev"), format!("{disk_number}\n")).unwrap();
    std::fs::write(
      root.join(&partition).join("dev"),
      format!("{partition_number}\n"),
    )
    .unwrap();
    std::fs::write(root.join(&partition).join("partition"), "1\n").unwrap();
    let block = root.join("dev/block");
    std::fs::create_dir_all(&block).unwrap();
    std::os::unix::fs::symlink(Path::new("../..").join(&disk), block.join(disk_number)).unwrap();
    std::os::unix::fs::symlink(
      Path::new("../..").join(&partition),
      block.join(partition_number),
    )
    .unwrap();
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

  /// Writes udev's record of `device` beneath a fixture `/run`, `root`, as
  /// udev lays it out: `udev/data/b<major>:<minor>`.
  fn write_udev_record(root: &Path, device: u64, record: &str) {
    let (major, minor) = unmakedev(device);
    let data = root.join("udev").join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join(format!("b{major}:{minor}")), record).unwrap();
  }

  /// **A removal answer is read by the mount's own device number, which the
  /// mount holds, and needs nothing else.** With no `diskseq` anywhere and no
  /// identity asked of any filesystem — an exFAT volume's mount, say — a USB
  /// disk the kernel calls fixed throughout answers `NotEjectable` for the
  /// disk and its partition, and one behind a port that reads `removable`
  /// answers `Ejectable`. A number whose `dev/block` entry is gone — a device
  /// that left while mounted, which `del_gendisk` unhashes without freeing its
  /// number — answers `Unknown`, and never for another device.
  #[test]
  fn test_a_removal_answer_is_read_by_the_mounts_own_number() {
    let fixed = tempfile::tempdir().unwrap();
    usb_disk_fixture(fixed.path(), &[("1-3", Some("fixed"))], "0\n");
    let sysfs = fixture(fixed.path());
    for device in [makedev(8, 16), makedev(8, 17)] {
      assert_eq!(
        bound_removal(&sysfs, device),
        Ejectability::NotEjectable,
        "{device:#x}"
      );
    }

    let behind_a_removable_port = tempfile::tempdir().unwrap();
    usb_disk_fixture(
      behind_a_removable_port.path(),
      &[("1-3", Some("removable")), ("1-3.2", Some("fixed"))],
      "0\n",
    );
    assert_eq!(
      bound_removal(&fixture(behind_a_removable_port.path()), makedev(8, 17)),
      Ejectability::Ejectable
    );

    // The device that left: its entry is gone, and the fixed disk still in
    // the tree answers only for its own number. A road that read another
    // device for the absent one — the planted defect this law holds the
    // number's own entry against — would carry that disk's denial here.
    std::fs::remove_file(fixed.path().join("dev/block/8:17")).unwrap();
    assert_eq!(
      bound_removal(&sysfs, makedev(8, 17)),
      Ejectability::Unknown,
      "a number whose entry is gone answers nothing"
    );
    assert_eq!(
      bound_removal(&sysfs, makedev(8, 16)),
      Ejectability::NotEjectable,
      "what another device's entry would have answered"
    );
  }

  /// **Every member a stack's answer is read from is held to one attach, where
  /// the kernel publishes one.** A device mapper volume over the fixed USB
  /// partition is denied while the disk under it keeps its sequence, and is
  /// `Unknown` where the disk is attached again, or leaves, while the answer
  /// is read. A member whose kernel publishes no sequence withholds nothing:
  /// the stack answers through its members as ever.
  #[test]
  fn test_a_stack_is_held_to_one_attach_of_everything_under_it() {
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
    std::os::unix::fs::symlink(
      Path::new("../../devices/virtual/block/dm-0"),
      dir.path().join("dev/block/253:0"),
    )
    .unwrap();
    let sysfs = fixture(dir.path());
    let stack = makedev(253, 0);

    assert_eq!(bound_removal(&sysfs, stack), Ejectability::NotEjectable);
    assert_eq!(
      bound_removal_with(&sysfs, stack, || write_diskseq(dir.path(), &disk, 8)),
      Ejectability::Unknown,
      "the disk under the stack was attached again"
    );
    assert_eq!(
      bound_removal_with(&sysfs, stack, || {
        std::fs::remove_file(dir.path().join(&disk).join("diskseq")).unwrap();
      }),
      Ejectability::Unknown,
      "the disk under the stack left while the answer was read"
    );
    assert_eq!(
      device_sequence(&sysfs, makedev(8, 17)),
      Attach::Unsupported,
      "a disk whose directory holds its dev and no diskseq"
    );
    assert_eq!(
      bound_removal(&sysfs, stack),
      Ejectability::NotEjectable,
      "a member with no sequence withholds nothing"
    );
  }

  /// **Only the kernel's own word that it keeps no sequence is an absence.**
  /// A member's `diskseq` that is not one decimal line, a `partition` number
  /// that is not one, and a disk whose directory lists no `dev` beside its
  /// missing `diskseq` — a disk on its way out — are no answer at all: the
  /// stack over the member is `Unknown`, and udev's facts about the member are
  /// not read; neither are they with no `/sys` to ask. A disk directory
  /// holding its `dev` and no `diskseq`, which is how a kernel before 5.15
  /// lays one out, keeps the fallback: the stack is denied through its
  /// members as ever, and udev's facts are read by the device number.
  #[test]
  fn test_an_attach_that_could_not_be_read_holds_nothing() {
    /// The rule before, for the side-by-side: an attach it could not name was
    /// taken for one the kernel keeps none of.
    #[derive(Default)]
    struct Lenient(Topology);
    impl Holding for Lenient {
      fn member(&mut self, sysfs: &KernelDir, device: u64) {
        if let Attach::Named(attach) = device_sequence(sysfs, device) {
          self.0.attaches.push((device, attach));
        }
      }
      fn members(&mut self, layer: u64, members: &[Vec<u8>]) {
        self.0.members(layer, members);
      }
    }

    let dir = tempfile::tempdir().unwrap();
    let partition = usb_disk_fixture(dir.path(), &[("1-3", Some("fixed"))], "0\n");
    let disk = partition.parent().unwrap().to_path_buf();
    layer_fixture(dir.path(), "dm-0", "253:0", &[("sdb1", &partition)]);
    let sysfs = fixture(dir.path());
    let (stack, member) = (makedev(253, 0), makedev(8, 17));
    let run_dir = tempfile::tempdir().unwrap();
    write_udev_record(
      run_dir.path(),
      member,
      "S:disk/by-diskseq/7-part1\nS:disk/by-uuid/1A2B-3C4D\nE:ID_FS_LABEL_ENC=STICK\n",
    );
    let run = fixture(run_dir.path());
    let publication =
      |sysfs: Option<&KernelDir>| udev_publication(sysfs, Some(&run), member).unwrap();

    // A kernel that keeps no sequence: the fallback, by the kernel's word.
    assert_eq!(device_sequence(&sysfs, member), Attach::Unsupported);
    assert_eq!(bound_removal(&sysfs, stack), Ejectability::NotEjectable);
    assert!(matches!(
      publication(Some(&sysfs)),
      UdevPublication::Unattached(_)
    ));

    for garbled in ["", "42", "42\n\n", "4 2\n", "-1\n", "7"] {
      std::fs::write(dir.path().join(&disk).join("diskseq"), garbled).unwrap();
      assert_eq!(
        device_sequence(&sysfs, member),
        Attach::Unread,
        "{garbled:?}"
      );
      assert_eq!(
        bound_removal(&sysfs, stack),
        Ejectability::Unknown,
        "a member whose sequence reads {garbled:?}"
      );
      assert_eq!(
        publication(Some(&sysfs)),
        UdevPublication::Stale,
        "a member whose sequence reads {garbled:?}"
      );
      // The planted defect, side by side: taken for a kernel that keeps no
      // sequence, the unread attach withheld nothing and the stack was
      // denied.
      let mut lenient = Lenient::default();
      assert_eq!(
        device_removal(&sysfs, stack, 0, &mut lenient),
        Ejectability::NotEjectable
      );
      assert!(lenient.0.still_holds(&sysfs), "{garbled:?}");
    }
    write_diskseq(dir.path(), &disk, 7);
    assert_eq!(
      device_sequence(&sysfs, member),
      Attach::Named(Sequence {
        disk: 7,
        partition: Some(1)
      })
    );
    assert_eq!(bound_removal(&sysfs, stack), Ejectability::NotEjectable);
    assert!(matches!(
      publication(Some(&sysfs)),
      UdevPublication::Current(_, _)
    ));
    assert_eq!(publication(None), UdevPublication::Stale, "no /sys to ask");
    std::fs::remove_file(dir.path().join(&disk).join("diskseq")).unwrap();

    std::fs::write(dir.path().join(&partition).join("partition"), "one\n").unwrap();
    assert_eq!(
      device_sequence(&sysfs, member),
      Attach::Unread,
      "a partition number that is not the kernel's writing"
    );
    assert_eq!(bound_removal(&sysfs, stack), Ejectability::Unknown);
    std::fs::write(dir.path().join(&partition).join("partition"), "1\n").unwrap();

    std::fs::remove_file(dir.path().join(&disk).join("dev")).unwrap();
    assert_eq!(
      device_sequence(&sysfs, member),
      Attach::Unread,
      "a disk whose directory lists no dev"
    );
    assert_eq!(bound_removal(&sysfs, stack), Ejectability::Unknown);
    assert_eq!(publication(Some(&sysfs)), UdevPublication::Stale);
    std::fs::write(dir.path().join(&disk).join("dev"), "8:16\n").unwrap();

    std::fs::remove_file(dir.path().join("dev/block/8:17")).unwrap();
    assert_eq!(
      device_sequence(&sysfs, member),
      Attach::Unread,
      "a device that is not there"
    );
  }

  /// **A btrfs member is held to its membership and its attach, not to the
  /// mount.** btrfs holds a member only while it is one, so a filesystem on
  /// the fixed USB partition alone is denied while the kernel's btrfs map
  /// still lists it, counts no member missing, and its disk keeps its
  /// sequence. It is `Unknown` where the member is removed from the
  /// filesystem while the answer is read, where the listing changes to
  /// another device, where the member is listed under another filesystem
  /// instead, where the map cannot be read after the answer, where a member
  /// the filesystem counts is missing, or counted and not listed, or the map
  /// says nothing of missing members, and where the disk under it is attached
  /// again. With no sequence
  /// published, nothing is withheld for it.
  #[test]
  fn test_a_btrfs_member_is_held_to_its_membership_and_attach() {
    let dir = tempfile::tempdir().unwrap();
    let partition = usb_disk_fixture(dir.path(), &[("1-3", Some("fixed"))], "0\n");
    let disk = partition.parent().unwrap().to_path_buf();
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    btrfs_devinfo_fixture(dir.path(), FSID_A, &[("1", "0")]);
    let sysfs = fixture(dir.path());
    let fsid = crate::parse_by_uuid_name(FSID_A.as_bytes()).unwrap();
    let member = makedev(8, 17);
    let listed = btrfs_dir(dir.path(), FSID_A).join("devices/sdb1");

    assert_eq!(
      btrfs_removal(&sysfs, member, &fsid),
      Ejectability::NotEjectable,
      "a member still listed, with no sequence published"
    );
    assert_eq!(
      btrfs_removal_with(&sysfs, member, &fsid, || {
        std::fs::remove_file(&listed).unwrap();
      }),
      Ejectability::Unknown,
      "removed from the filesystem while the answer was read"
    );
    // The planted defect, a road that skips the re-verification, is the road
    // a single-device mount takes: across the removal it keeps the denial.
    assert_eq!(
      bound_removal(&sysfs, member),
      Ejectability::NotEjectable,
      "what a road with no membership re-check answers"
    );
    assert_eq!(
      btrfs_removal(&sysfs, member, &fsid),
      Ejectability::Unknown,
      "no longer a member"
    );

    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    assert_eq!(
      btrfs_removal_with(&sysfs, member, &fsid, || {
        std::fs::remove_file(&listed).unwrap();
        btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdc1", "8:33")])]);
      }),
      Ejectability::Unknown,
      "the filesystem's listing changed to another device under another number"
    );
    std::fs::remove_file(btrfs_dir(dir.path(), FSID_A).join("devices/sdc1")).unwrap();

    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    assert_eq!(
      btrfs_removal_with(&sysfs, member, &fsid, || {
        std::fs::remove_file(&listed).unwrap();
        btrfs_sysfs_fixture(dir.path(), &[(FSID_B, &[("sdb1", "8:17")])]);
      }),
      Ejectability::Unknown,
      "listed under another filesystem after the answer"
    );
    std::fs::remove_file(btrfs_dir(dir.path(), FSID_B).join("devices/sdb1")).unwrap();

    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdb1", "8:17")])]);
    let devices = btrfs_dir(dir.path(), FSID_A).join("devices");
    let hidden = btrfs_dir(dir.path(), FSID_A).join("devices-hidden");
    assert_eq!(
      btrfs_removal_with(&sysfs, member, &fsid, || {
        std::fs::rename(&devices, &hidden).unwrap();
      }),
      Ejectability::Unknown,
      "the map could not be read after the answer"
    );
    std::fs::rename(&hidden, &devices).unwrap();

    btrfs_devinfo_fixture(dir.path(), FSID_A, &[("2", "1")]);
    assert_eq!(
      btrfs_removal(&sysfs, member, &fsid),
      Ejectability::Unknown,
      "a member the filesystem counts is missing from its listing"
    );
    std::fs::remove_dir_all(btrfs_dir(dir.path(), FSID_A).join("devinfo/2")).unwrap();
    btrfs_devinfo_fixture(dir.path(), FSID_A, &[("2", "0")]);
    assert_eq!(
      btrfs_removal(&sysfs, member, &fsid),
      Ejectability::Unknown,
      "a device the filesystem counts that its listing does not carry"
    );
    std::fs::remove_dir_all(btrfs_dir(dir.path(), FSID_A).join("devinfo/2")).unwrap();
    let devinfo = btrfs_dir(dir.path(), FSID_A).join("devinfo");
    let before = btrfs_dir(dir.path(), FSID_A).join("devinfo-hidden");
    std::fs::rename(&devinfo, &before).unwrap();
    assert_eq!(
      btrfs_removal(&sysfs, member, &fsid),
      Ejectability::Unknown,
      "a map that says nothing of missing members denies nothing"
    );
    std::fs::rename(&before, &devinfo).unwrap();

    write_diskseq(dir.path(), &disk, 5);
    assert_eq!(
      btrfs_removal(&sysfs, member, &fsid),
      Ejectability::NotEjectable,
      "listed, and the same attach"
    );
    assert_eq!(
      btrfs_removal_with(&sysfs, member, &fsid, || write_diskseq(
        dir.path(),
        &disk,
        6
      )),
      Ejectability::Unknown,
      "the device under the number was attached again"
    );
  }

  /// **A btrfs filesystem across several devices answers for all of them, as
  /// a stack does.** A RAID1 across a fixed USB partition and one behind a
  /// removable port is `Ejectable` whichever of the two the mount was made
  /// through; across two fixed ones it is denied, whichever it was made
  /// through; and a member that leaves while the answer is read, a member
  /// other than the source attached again, and a member whose answer cannot
  /// be read each make it `Unknown`. A source the map does not list answers
  /// nothing.
  #[test]
  fn test_a_btrfs_filesystem_answers_for_every_member() {
    let dir = tempfile::tempdir().unwrap();
    usb_disk_at(
      dir.path(),
      &[("1-3", Some("fixed"))],
      "0\n",
      ("sdb", "8:16", "8:17"),
    );
    let other = usb_disk_at(
      dir.path(),
      &[("1-4", Some("fixed"))],
      "0\n",
      ("sdc", "8:32", "8:33"),
    );
    let other_disk = other.parent().unwrap().to_path_buf();
    usb_disk_at(
      dir.path(),
      &[("1-5", Some("removable"))],
      "0\n",
      ("sdd", "8:48", "8:49"),
    );
    let sysfs = fixture(dir.path());
    let fsid = crate::parse_by_uuid_name(FSID_A.as_bytes()).unwrap();
    let (fixed, other_fixed, removable) = (makedev(8, 17), makedev(8, 33), makedev(8, 49));

    // A RAID1 across the fixed partition and the removable one.
    btrfs_sysfs_fixture(
      dir.path(),
      &[(FSID_A, &[("sdb1", "8:17"), ("sdd1", "8:49")])],
    );
    btrfs_devinfo_fixture(dir.path(), FSID_A, &[("1", "0"), ("2", "0")]);
    for source in [fixed, removable] {
      assert_eq!(
        btrfs_removal(&sysfs, source, &fsid),
        Ejectability::Ejectable,
        "mounted through {source:#x}"
      );
    }
    // The planted defect, side by side: a road that asks only the source
    // member denies, through the fixed partition, a filesystem a removable
    // disk also carries — and says yes through the other.
    assert_eq!(
      bound_removal(&sysfs, fixed),
      Ejectability::NotEjectable,
      "what the source alone answers"
    );
    let listed_removable = btrfs_dir(dir.path(), FSID_A).join("devices/sdd1");
    assert_eq!(
      btrfs_removal_with(&sysfs, fixed, &fsid, || {
        std::fs::remove_file(&listed_removable).unwrap();
      }),
      Ejectability::Unknown,
      "the removable member left while the answer was read"
    );

    // Two fixed members.
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdc1", "8:33")])]);
    for source in [fixed, other_fixed] {
      assert_eq!(
        btrfs_removal(&sysfs, source, &fsid),
        Ejectability::NotEjectable,
        "every member fixed, mounted through {source:#x}"
      );
    }
    assert_eq!(
      btrfs_removal(&sysfs, removable, &fsid),
      Ejectability::Unknown,
      "a source the map does not list"
    );
    let listed_other = btrfs_dir(dir.path(), FSID_A).join("devices/sdc1");
    assert_eq!(
      btrfs_removal_with(&sysfs, fixed, &fsid, || {
        std::fs::remove_file(&listed_other).unwrap();
      }),
      Ejectability::Unknown,
      "a member left while the answer was read"
    );
    btrfs_sysfs_fixture(dir.path(), &[(FSID_A, &[("sdc1", "8:33")])]);
    write_diskseq(dir.path(), &other_disk, 3);
    assert_eq!(
      btrfs_removal(&sysfs, fixed, &fsid),
      Ejectability::NotEjectable
    );
    assert_eq!(
      btrfs_removal_with(&sysfs, fixed, &fsid, || {
        write_diskseq(dir.path(), &other_disk, 4);
      }),
      Ejectability::Unknown,
      "a member other than the source was attached again"
    );
    std::fs::remove_file(dir.path().join("dev/block/8:33")).unwrap();
    assert_eq!(
      btrfs_removal(&sysfs, fixed, &fsid),
      Ejectability::Unknown,
      "a member whose answer could not be read"
    );
  }

  /// A stack layer at `layer` (`devices/virtual/block/<name>`, linked from
  /// `dev/block/<number>`) whose `slaves/` lists `members`, each a device
  /// directory relative to the fixture root.
  fn layer_fixture(root: &Path, name: &str, number: &str, members: &[(&str, &Path)]) {
    let layer = root.join("devices/virtual/block").join(name);
    std::fs::create_dir_all(layer.join("slaves")).unwrap();
    std::fs::write(layer.join("dev"), format!("{number}\n")).unwrap();
    for (member, target) in members {
      std::os::unix::fs::symlink(
        Path::new("../../../../..").join(target),
        layer.join("slaves").join(member),
      )
      .unwrap();
    }
    std::os::unix::fs::symlink(
      Path::new("../../devices/virtual/block").join(name),
      root.join("dev/block").join(number),
    )
    .unwrap();
  }

  /// **A stack's members are held as a set of their own.** The kernel changes
  /// no `diskseq` when a device mapper table is swapped or an md member is
  /// replaced or added, so every member's attach can hold while the layer is
  /// built from something else. With no `diskseq` in the tree and no udev
  /// name for any layer — an LVM or LUKS volume, an md array — a `dm` layer
  /// and an `md` layer over the fixed USB partition are denied while they
  /// list the same members after the answer as before; the `dm` layer is
  /// `Unknown` where its table is swapped onto another disk while the answer
  /// is read, and the `md` layer where a member is added, and where it no
  /// longer lists its members at all.
  #[test]
  fn test_a_stack_whose_members_change_while_it_is_read_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let partition = usb_disk_fixture(dir.path(), &[("1-3", Some("fixed"))], "0\n");
    let other = PathBuf::from("devices/bus/sdc");
    std::fs::create_dir_all(dir.path().join(&other)).unwrap();
    std::fs::write(dir.path().join(&other).join("dev"), "8:32\n").unwrap();
    std::fs::write(dir.path().join(&other).join("removable"), "0\n").unwrap();
    std::os::unix::fs::symlink(
      Path::new("../..").join(&other),
      dir.path().join("dev/block/8:32"),
    )
    .unwrap();
    layer_fixture(dir.path(), "dm-0", "253:0", &[("sdb1", &partition)]);
    layer_fixture(dir.path(), "md0", "9:0", &[("sdb1", &partition)]);
    let sysfs = fixture(dir.path());
    let slaves = |layer: &str| {
      dir
        .path()
        .join("devices/virtual/block")
        .join(layer)
        .join("slaves")
    };

    for (layer, number) in [("dm-0", makedev(253, 0)), ("md0", makedev(9, 0))] {
      assert_eq!(
        bound_removal(&sysfs, number),
        Ejectability::NotEjectable,
        "{layer} over the fixed partition alone"
      );
    }

    // The attaches alone cannot see a swap: every device read about is the
    // attach it was, so a post-check of attaches alone — the planted defect
    // this law holds the membership re-read against — keeps the denial the
    // walk read before the swap.
    let mut topology = Topology::default();
    assert_eq!(
      device_removal(&sysfs, makedev(253, 0), 0, &mut topology),
      Ejectability::NotEjectable
    );
    assert!(topology.still_holds(&sysfs));
    std::fs::remove_file(slaves("dm-0").join("sdb1")).unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../../../..").join(&other),
      slaves("dm-0").join("sdc"),
    )
    .unwrap();
    assert!(
      topology.attaches_hold(&sysfs),
      "every attach holds across the swap"
    );
    assert!(
      !topology.members_hold(&sysfs),
      "the membership re-read is what sees it"
    );
    std::fs::remove_file(slaves("dm-0").join("sdc")).unwrap();
    std::os::unix::fs::symlink(
      Path::new("../../../../..").join(&partition),
      slaves("dm-0").join("sdb1"),
    )
    .unwrap();
    assert_eq!(
      bound_removal_with(&sysfs, makedev(253, 0), || {
        std::fs::remove_file(slaves("dm-0").join("sdb1")).unwrap();
        std::os::unix::fs::symlink(
          Path::new("../../../../..").join(&other),
          slaves("dm-0").join("sdc"),
        )
        .unwrap();
      }),
      Ejectability::Unknown,
      "a dm table swapped onto another disk while the answer was read"
    );
    assert_eq!(
      bound_removal_with(&sysfs, makedev(9, 0), || {
        std::os::unix::fs::symlink(
          Path::new("../../../../..").join(&other),
          slaves("md0").join("sdc"),
        )
        .unwrap();
      }),
      Ejectability::Unknown,
      "an md member added while the answer was read"
    );
    std::fs::remove_file(slaves("md0").join("sdc")).unwrap();
    assert_eq!(
      bound_removal(&sysfs, makedev(9, 0)),
      Ejectability::NotEjectable,
      "the md layer as it was"
    );
    assert_eq!(
      bound_removal_with(&sysfs, makedev(9, 0), || std::fs::remove_dir_all(slaves(
        "md0"
      ))
      .unwrap()),
      Ejectability::Unknown,
      "a layer that no longer lists its members"
    );
  }

  /// **Every fact udev states about a device is read out of one
  /// publication: the record udev wrote for the device's current attach.**
  /// The record must name the attach the kernel names now, through its
  /// `by-diskseq` devlinks, and name no other; the identity and the label are
  /// that record's and no other publication's; and after them the same attach
  /// and the same record, byte for byte, must stand. So the facts are read
  /// where the record names the current attach; nothing is read where it
  /// names an older one, two, a name that spells none — or **none at all
  /// while the kernel names one**, which was a fallback to facts nothing
  /// bound — or where there is no record, no `/run`, no `/sys`; nothing
  /// stands where the record is rewritten, or the device attached again,
  /// while the facts are read; and a filesystem that names itself holds the
  /// record whole to it, the label with the identity. Only a kernel that keeps
  /// no attach leaves the record bound by the number alone. The planted
  /// defects, side by side: the facts read beside an attach the directories
  /// did not publish, a label read from a record the mounted identity never
  /// checked, and a record rewritten under the same attach, which the
  /// kernel's `diskseq` alone does not see.
  #[test]
  fn test_udev_facts_are_read_out_of_one_publication() {
    use super::super::IdentityAssurance::{Declared, Published};

    let dir = tempfile::tempdir().unwrap();
    let partition = usb_disk_fixture(dir.path(), &[("1-3", Some("fixed"))], "0\n");
    write_diskseq(dir.path(), partition.parent().unwrap(), 42);
    let sysfs = fixture(dir.path());
    let run_dir = tempfile::tempdir().unwrap();
    let run = fixture(run_dir.path());
    let part = makedev(8, 17);
    let current = Sequence {
      disk: 42,
      partition: Some(1),
    };
    let uuid = super::super::parse_by_uuid_name(b"8f19a253-d450-3090-abf6-e651943998d1").unwrap();
    let record = |links: &str| {
      write_udev_record(
        run_dir.path(),
        part,
        &format!(
          "{links}S:disk/by-uuid/8f19a253-d450-3090-abf6-e651943998d1\nS:disk/by-label/STICK\nE:ID_FS_LABEL_ENC=STICK\nV:1\n"
        ),
      );
    };
    let facts = |mounted: Option<VolumeIdentity>, between: &dyn Fn()| {
      published_facts_with(
        Some(&sysfs),
        Some(&run),
        part,
        b"ext4",
        Published,
        mounted,
        between,
      )
      .unwrap()
    };
    let read = |facts: (Option<IdentityReading>, Option<super::super::NameReading>)| {
      (
        facts.0.map(|reading| reading.identity()),
        facts
          .1
          .map(|name| (name.name.as_bytes().to_vec(), name.assurance)),
      )
    };
    let stated = (Some(uuid), Some((b"STICK".to_vec(), Published)));

    // The record of the current attach: every fact out of it.
    record("S:disk/by-diskseq/42-part1\n");
    assert!(matches!(
      udev_publication(Some(&sysfs), Some(&run), part).unwrap(),
      UdevPublication::Current(attach, _) if attach == current
    ));
    assert_eq!(read(facts(None, &|| {})), stated);
    assert_eq!(read(facts(Some(uuid), &|| {})), stated);

    // No publication of the current attach: nothing.
    for (links, why) in [
      ("S:disk/by-diskseq/41-part1\n", "an older attach"),
      (
        "S:disk/by-diskseq/42-part1\nS:disk/by-diskseq/41-part1\n",
        "two attaches",
      ),
      (
        "S:disk/by-diskseq/42-partx\n",
        "a name that spells no attach",
      ),
      (
        "",
        "a record that names no attach while the kernel names one",
      ),
    ] {
      record(links);
      assert_eq!(
        udev_publication(Some(&sysfs), Some(&run), part).unwrap(),
        UdevPublication::Stale,
        "{why}"
      );
      assert_eq!(read(facts(None, &|| {})), (None, None), "{why}");
    }
    record("S:disk/by-diskseq/42-part1\n");
    assert_eq!(
      udev_publication(None, Some(&run), part).unwrap(),
      UdevPublication::Stale,
      "no /sys: the attach could not be read"
    );
    assert_eq!(
      udev_publication(Some(&sysfs), None, part).unwrap(),
      UdevPublication::Stale,
      "no /run: no record to read"
    );
    assert_eq!(
      udev_publication(Some(&sysfs), Some(&run), makedev(8, 18)).unwrap(),
      UdevPublication::Stale,
      "no record of the device"
    );

    // The publication must stand after the facts: a record rewritten under
    // the same attach, one removed, and an attach replaced leave nothing.
    let rewritten = || {
      record("S:disk/by-diskseq/42-part1\nS:disk/by-label/OTHER\n");
    };
    assert_eq!(read(facts(None, &rewritten)), (None, None));
    record("S:disk/by-diskseq/42-part1\n");
    let removed = || {
      let (major, minor) = unmakedev(part);
      std::fs::remove_file(run_dir.path().join(format!("udev/data/b{major}:{minor}"))).unwrap();
    };
    assert_eq!(read(facts(None, &removed)), (None, None));
    record("S:disk/by-diskseq/42-part1\n");
    let attached_again = || write_diskseq(dir.path(), partition.parent().unwrap(), 43);
    assert_eq!(read(facts(None, &attached_again)), (None, None));
    write_diskseq(dir.path(), partition.parent().unwrap(), 42);

    // A filesystem that names itself holds the record whole to it: another
    // identity, or none, and neither the identity nor the label is read.
    let other = super::super::parse_by_uuid_name(b"00000000-1111-2222-3333-444444444444").unwrap();
    assert_eq!(read(facts(Some(other), &|| {})), (None, None));

    // The label: the devlinks' at the source's level, two that disagree none,
    // and otherwise the record's own `ID_FS_LABEL_ENC` at `Declared`.
    write_udev_record(
      run_dir.path(),
      part,
      "S:disk/by-diskseq/42-part1\nS:disk/by-label/ONE\nS:disk/by-label/TWO\nE:ID_FS_LABEL_ENC=ENC\n",
    );
    assert_eq!(
      read(facts(None, &|| {})),
      (None, Some((b"ENC".to_vec(), Declared)))
    );
    write_udev_record(
      run_dir.path(),
      part,
      "S:disk/by-diskseq/42-part1\nS:disk/by-label/bad\\label\n",
    );
    assert_eq!(
      udev_publication(Some(&sysfs), Some(&run), part)
        .unwrap_err()
        .kind(),
      io::ErrorKind::InvalidData,
      "a devlink udev could not have named"
    );
    write_udev_record(run_dir.path(), part, "S:disk/by-diskseq/42-part1");
    assert_eq!(
      udev_publication(Some(&sysfs), Some(&run), part)
        .unwrap_err()
        .kind(),
      io::ErrorKind::InvalidData,
      "a record cut short"
    );

    // A kernel that keeps no attach: the record, bound by the number alone.
    record("");
    std::fs::remove_file(dir.path().join(partition.parent().unwrap()).join("diskseq")).unwrap();
    assert!(matches!(
      udev_publication(Some(&sysfs), Some(&run), part).unwrap(),
      UdevPublication::Unattached(_)
    ));
    assert_eq!(read(facts(None, &|| {})), stated);
    assert_eq!(read(facts(None, &rewritten)), (None, None));
    write_diskseq(dir.path(), partition.parent().unwrap(), 42);

    // The planted defects, side by side. The gate as it was read the
    // directories apart: a `by-diskseq` census naming the device by no attach
    // was `Unpublished`, and the facts were then read with nothing binding
    // them — here, the stale record's. It took the label beside a mounted
    // identity without asking the gate. And it checked only the kernel's
    // `diskseq` after the facts, which a record rewritten under the same
    // attach leaves as it was.
    record("");
    let before_unpublished = record_facts(
      &udev_record(&run, part).unwrap().unwrap(),
      part,
      b"ext4",
      Published,
    )
    .unwrap();
    assert_eq!(read(before_unpublished), stated);
    record("S:disk/by-diskseq/41-part1\n");
    let before_label = record_facts(
      &udev_record(&run, part).unwrap().unwrap(),
      part,
      b"ext4",
      Published,
    )
    .unwrap()
    .1;
    assert!(before_label.is_some(), "a label read with no gate at all");
    assert_eq!(
      device_sequence(&sysfs, part),
      Attach::Named(current),
      "a record rewritten under the same attach leaves the kernel's word as it was"
    );

    assert_eq!(
      parse_by_diskseq_name(b"9"),
      Some(Sequence {
        disk: 9,
        partition: None
      })
    );
    assert_eq!(
      parse_by_diskseq_name(b"9-part12"),
      Some(Sequence {
        disk: 9,
        partition: Some(12)
      })
    );
    for name in [
      &b""[..],
      b"x",
      b"9-part",
      b"-part1",
      b"9-partx",
      b"9 ",
      b"9-part1-part2",
    ] {
      assert_eq!(parse_by_diskseq_name(name), None, "{name:?}");
    }
  }

  /// **The root, on this machine**: its removal answer, read by the number the
  /// root's superblock carries, and where udev's facts about that device may
  /// be read from — the filesystem's own identity, the device's attach and
  /// the publication udev's record of it makes — printed as this machine
  /// offers them. Where udev's record names the current attach and the
  /// filesystem names itself, the record's identity for the device is the
  /// filesystem's own.
  #[test]
  fn test_the_root_answers_on_this_machine() {
    let roots = observed::Roots::open_for_laws().unwrap();
    let Some((line, pinned)) = observed::root_line_for_laws(&roots) else {
      println!("the root's line could not be had");
      return;
    };
    let fs_type = line.fs_type.as_bytes().to_vec();
    let device = line.device;
    let removal = roots
      .sysfs_for_laws()
      .map(|sysfs| bound_removal(sysfs, device));
    let mounted = observed::mount_root_for_laws(&line, &pinned, &roots)
      .and_then(|root| filesystem_identity(&root, &fs_type).unwrap());
    let attach = roots
      .sysfs_for_laws()
      .map(|sysfs| device_sequence(sysfs, device));
    let run = KernelDir::open("/run", None).answered().unwrap();
    let gate = udev_publication(roots.sysfs_for_laws(), run.as_ref(), device).unwrap();
    let identity = match &gate {
      UdevPublication::Current(_, record) | UdevPublication::Unattached(record) => {
        record_facts(record, device, &fs_type, IdentityAssurance::Published)
          .unwrap()
          .0
          .map(|reading| reading.identity())
      }
      UdevPublication::Stale => None,
    };
    let gate = match gate {
      UdevPublication::Current(attach, _) => format!("Current({attach:?})"),
      UdevPublication::Unattached(_) => "Unattached".to_owned(),
      UdevPublication::Stale => "Stale".to_owned(),
    };
    println!(
      "root: {} on {:#x}; removal {removal:?}; the filesystem names {mounted:?}; attach \
       {attach:?}; udev gate {gate:?}; udev names {identity:?}",
      String::from_utf8_lossy(&fs_type),
      device
    );
    if let (Some(mounted), true, Some(identity)) = (mounted, gate.starts_with("Current"), identity)
    {
      assert_eq!(
        crate::linux_identity(&fs_type, mounted, IdentityAssurance::Vouched)
          .map(|reading| reading.identity()),
        Some(identity),
        "udev's identity for the published attach is the mounted filesystem's own"
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

  /// The bus fallback as it was before it read [`is_usb_root_hub`]: a
  /// component that begins `usb` and has only digits after it, every byte of
  /// nothing among them. The planted defect the laws below hold the one
  /// grammar against, side by side.
  fn bus_fallback_as_it_was(ancestry: &[u8]) -> bool {
    ancestry.split(|&byte| byte == b'/').any(|component| {
      component.starts_with(b"usb") && component[3..].iter().all(u8::is_ascii_digit)
    })
  }

  /// A SCSI disk `sda` and its first partition below the device directories
  /// `chain` — outermost first beneath `devices/`, each with its `removable`
  /// word, or none — the disk's media flag written as `media`, and
  /// `dev/block/8:0` and `dev/block/8:1` linked to them. Returns the disk's
  /// ancestry: the target of its `dev/block` link, as the kernel spells one.
  fn disk_below(root: &Path, chain: &[(&str, Option<&str>)], media: &str) -> Vec<u8> {
    let mut relative = PathBuf::from("devices");
    for (name, word) in chain {
      relative = relative.join(name);
      std::fs::create_dir_all(root.join(&relative)).unwrap();
      if let Some(word) = word {
        std::fs::write(root.join(&relative).join("removable"), format!("{word}\n")).unwrap();
      }
    }
    let disk = relative.join("host6/target6:0:0/6:0:0:0/block/sda");
    let partition = disk.join("sda1");
    std::fs::create_dir_all(root.join(&partition)).unwrap();
    std::fs::write(root.join(&disk).join("removable"), media).unwrap();
    std::fs::write(root.join(&disk).join("dev"), "8:0\n").unwrap();
    std::fs::write(root.join(&partition).join("dev"), "8:1\n").unwrap();
    std::fs::write(root.join(&partition).join("partition"), "1\n").unwrap();
    let block = root.join("dev/block");
    std::fs::create_dir_all(&block).unwrap();
    let ancestry = Path::new("../..").join(&disk);
    std::os::unix::fs::symlink(&ancestry, block.join("8:0")).unwrap();
    std::os::unix::fs::symlink(Path::new("../..").join(&partition), block.join("8:1")).unwrap();
    ancestry.as_os_str().as_bytes().to_vec()
  }

  /// **A USB controller in a device path is `usb` and its bus number, and
  /// nothing else.** Exactly `usb` is not one, `usb1` and `usb12` are, and
  /// `usbx`, `usb-foo`, a root hub's port `usb1-port1`, `usb1a`, `xusb1` and
  /// `USB1` are not — to the grammar itself, and to the bus fallback asking
  /// it of a whole ancestry. The planted defect, side by side: the fallback as
  /// it was read exactly `usb` as a controller, since every byte of nothing
  /// is a digit.
  #[test]
  fn test_a_usb_controller_is_usb_and_its_bus_number() {
    let ancestry = |component: &str| {
      format!("../../devices/platform/{component}/host6/target6:0:0/6:0:0:0/block/sda").into_bytes()
    };
    for (component, controller) in [
      ("usb", false),
      ("usb1", true),
      ("usb12", true),
      ("usbx", false),
      ("usb-foo", false),
      ("usb1-port1", false),
      ("usb1a", false),
      ("xusb1", false),
      ("USB1", false),
    ] {
      assert_eq!(
        is_usb_root_hub(component.as_bytes()),
        controller,
        "{component}"
      );
      assert_eq!(
        names_removable_bus(&ancestry(component)),
        controller,
        "{component}"
      );
    }
    assert!(!is_usb_root_hub(b""));
    assert!(!names_removable_bus(
      b"../../devices/platform/host6/target6:0:0/6:0:0:0/block/sda"
    ));

    // The planted defect: `usb` alone read as a controller.
    assert!(bus_fallback_as_it_was(&ancestry("usb")));
  }

  /// **A directory named `usb` is no USB bus.** A disk below a device named
  /// exactly `usb`, with no root hub on the way and its media flag `0`,
  /// answers what the rest of the road answers without that name: `Unknown`
  /// where no device on the way carries a `removable` word — so no port says
  /// yes, no USB device is there for a `fixed` to deny through, and the
  /// fallback finds no root hub — and no `slaves/` lies below; `Ejectable`
  /// where a port above it reads `removable`. The disk and its partition
  /// answer alike. A root hub below such a directory is the bus as ever: a
  /// USB disk there whose port cannot say is `Ejectable` by the fallback. The
  /// planted defect, side by side: where the ports settle nothing the
  /// fallback decides, and the fallback as it was read the first ancestry as
  /// a controller, which answered `Ejectable`.
  #[test]
  fn test_a_directory_named_usb_is_no_usb_bus() {
    type Chain<'a> = &'a [(&'a str, Option<&'a str>)];
    let cases: [(Chain<'_>, Ejectability); 3] = [
      (&[("platform", None), ("usb", None)], Ejectability::Unknown),
      (
        &[
          ("pci0000:00", None),
          ("0000:00:1d.0", Some("removable")),
          ("usb", None),
        ],
        Ejectability::Ejectable,
      ),
      (
        &[
          ("platform", None),
          ("usb", None),
          ("usb1", Some("unknown")),
          ("1-1", Some("unknown")),
          ("1-1:1.0", None),
        ],
        Ejectability::Ejectable,
      ),
    ];
    for (at, (chain, expected)) in cases.into_iter().enumerate() {
      let dir = tempfile::tempdir().unwrap();
      let ancestry = disk_below(dir.path(), chain, "0\n");
      let sysfs = fixture(dir.path());
      for device in [makedev(8, 0), makedev(8, 1)] {
        assert_eq!(
          bound_removal(&sysfs, device),
          expected,
          "{chain:?} device {device:#x}"
        );
      }
      if at == 0 {
        // The planted defect: nothing on the way settles the answer, so the
        // fallback decides it, and the fallback as it was said yes.
        assert_eq!(ports_say(&sysfs, &ancestry, false), None);
        assert!(!names_removable_bus(&ancestry));
        assert!(bus_fallback_as_it_was(&ancestry));
      }
    }
  }

  /// **The root-hub road and the bus fallback read one grammar.** For every
  /// spelling in the table, a directory so named stands where a root hub
  /// stands — reading `unknown`, above a USB device that reads `fixed`, over
  /// a disk whose media flag reads `0` — and both roads are asked of that one
  /// ancestry: [`ports_say`] excepts the `unknown` as a root hub's only where
  /// the spelling is one, and the denial then stands; [`names_removable_bus`]
  /// reads the ancestry as the bus exactly then. The whole answer follows:
  /// `NotEjectable` below a root hub, `Unknown` below anything else. The
  /// planted defect, side by side: the fallback as it was read exactly `usb`
  /// as a controller where the root-hub road did not.
  #[test]
  fn test_the_root_hub_road_and_the_bus_fallback_read_one_grammar() {
    for spelling in [
      "usb",
      "usb1",
      "usb12",
      "usbx",
      "usb-foo",
      "usb1-port1",
      "usb1a",
      "xusb1",
      "USB1",
    ] {
      let dir = tempfile::tempdir().unwrap();
      let ancestry = disk_below(
        dir.path(),
        &[
          ("pci0000:00", None),
          ("0000:00:14.0", None),
          (spelling, Some("unknown")),
          ("1-3", Some("fixed")),
          ("1-3:1.0", None),
        ],
        "0\n",
      );
      let sysfs = fixture(dir.path());
      let root_hub_road = ports_say(&sysfs, &ancestry, false) == Some(Ports::Fixed);
      assert_eq!(names_removable_bus(&ancestry), root_hub_road, "{spelling}");
      assert_eq!(
        root_hub_road,
        is_usb_root_hub(spelling.as_bytes()),
        "{spelling}"
      );
      let expected = if root_hub_road {
        Ejectability::NotEjectable
      } else {
        Ejectability::Unknown
      };
      for device in [makedev(8, 0), makedev(8, 1)] {
        assert_eq!(
          bound_removal(&sysfs, device),
          expected,
          "{spelling} device {device:#x}"
        );
      }
      if spelling == "usb" {
        // The planted defect: the two roads apart on `usb` alone.
        assert!(!root_hub_road);
        assert!(bus_fallback_as_it_was(&ancestry));
      }
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
