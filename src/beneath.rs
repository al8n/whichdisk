//! Where a path lies beneath its mount point, on Apple platforms, the BSDs
//! and NetBSD: decided by a walk that holds every directory it passes and
//! follows no symbolic link.
//!
//! **A path is looked up by name for its observation, and never again.** A
//! resolve canonicalizes its path — `realpath`, which leaves no symbolic link
//! in it — and forms its observation from that path: Apple's pin and its
//! `fstatfs`, or one `statfs` or `statvfs`. Where the path lies beneath the
//! mount point that observation reported is not asked of a name again. A
//! lookup by name follows a symbolic link at every component but the last —
//! POSIX.1-2024, XBD 4.16 *Pathname Resolution*, where `lstat` differs from
//! `stat` only where the last component is a link, and each kernel's own
//! lookup: "Symbolic links are always followed for all other pathname
//! components other than the last" (XNU `bsd/vfs/vfs_lookup.c` 159, FreeBSD
//! `sys/kern/vfs_lookup.c` 594, OpenBSD 100, NetBSD 398; DragonFly's
//! `nlookup`, `sys/kern/vfs_nlookup.c` 940-945). So a directory of the path
//! swapped for a link after it was canonicalized — by anyone who may write
//! the directory above it — leads every such lookup wherever the link points,
//! a mount of their choosing among them, and a walk that read only the last
//! component as itself passed over the link and still found the mount's root
//! above it.
//!
//! **So the path is walked from `/`, one name at a time, each relative to the
//! directory before it, which the walk holds**: every directory of the path
//! opened with `openat`, `O_DIRECTORY` and `O_NOFOLLOW`, and its last name
//! described — never opened — by `fstatat` with `AT_SYMLINK_NOFOLLOW` through
//! the directory holding it. Every identity, `st_dev` and `st_ino` — see
//! [`Node`] — is read from a handle the walk holds, never from a name. A name
//! that is a symbolic link, and a directory's name that is no directory, are
//! refused by name ([`a_link`], [`not_a_directory`]): the canonical path held
//! neither, so either was put there since, and the walk answers nothing. One
//! name is one component — see [`one_name`] — so no lookup the walk makes
//! has a component before its last to follow a link through.
//!
//! **How each platform holds a directory.** Each kernel refuses a link and a
//! non-directory after its lookup and before it opens anything, so a FIFO or
//! a device found where a directory was is never opened:
//!
//! - **Apple platforms**: `O_SEARCH`, which is `O_EXEC | O_DIRECTORY`
//!   (`bsd/sys/fcntl.h` 186-187) and needs only search permission on the
//!   directory (`vn_authorize_open_existing`, `bsd/vfs/vfs_subr.c` 8452-8455:
//!   `KAUTH_VNODE_SEARCH`), which a lookup through it needs anyway. A link
//!   answers `ENOTDIR`, as `O_DIRECTORY` is checked before it (8358-8367).
//!   XNU first knows `O_EXEC` in macOS 13 (xnu-8792); an older kernel ignores
//!   the bit and opens for reading (`FFLAGS` adds `FREAD`), so there a
//!   directory this caller may search but not read cannot be held.
//! - **FreeBSD**: `O_PATH`, which checks no permission on the directory and
//!   opens nothing (`vn_open_vnode`, `sys/kern/vfs_vnops.c` 445-489), and
//!   whose descriptor serves `fstat`, `fstatfs` and every `*at` call
//!   (`open(2)`; `kern_fstatfs`, `sys/kern/vfs_syscalls.c` 373). A link
//!   answers `ENOTDIR` under `O_DIRECTORY` (449). FreeBSD knows `O_PATH` from
//!   13.1; 13.0 ignores the bit and opens for reading (`kern_openat`:
//!   `FFLAGS`), so there a directory this caller may search but not read
//!   cannot be held.
//! - **OpenBSD, NetBSD and DragonFly**: `O_RDONLY`, the only way each opens a
//!   directory — OpenBSD's open needs a read or a write (`vn_open`,
//!   `sys/kern/vfs_vnops.c` 98), NetBSD's drops `O_SEARCH`
//!   (`sys/kern/vfs_syscalls.c` 1768), and NetBSD's and DragonFly's `FFLAGS`
//!   give every open a read — so on these a directory this caller may search
//!   but not read cannot be held. A link answers `ELOOP` (OpenBSD 155),
//!   `EFTYPE` (NetBSD 314) or `EMLINK` (DragonFly 254).
//!
//! The lines cited are XNU's `main`, FreeBSD 15.1's, NetBSD 11's, DragonFly
//! 6.4.2's and OpenBSD's current tree's.
//!
//! A directory the walk cannot hold — for want of permission, or gone — is
//! the resolve's error: nothing about where the path lies is answered.
//!
//! **The mount's root is held the same way**, by the mount point the
//! observation reported, walked from `/` with every name of it entered, and
//! taken only where its own handle is proven to be that observation's mount
//! — `fstatfs` or `fstatvfs` of the root itself, see [`split`]. A mount point
//! that names another mount's root now, or none, is refused.
//!
//! **The file the path names is the observation's own.** Where the
//! observation holds a descriptor — Apple's pin — the walk's last name must
//! be the very file that descriptor holds; where it holds none, the deepest
//! file the walk named must lie on the root's device. A path that now
//! resolves through another mount, or to another file, is refused by name.
//!
//! **Apple's firmlinks**: a firmlink joins the sealed system volume's
//! namespace to the data volume's, so `realpath` answers `/Users/...` while
//! the mount is `/System/Volumes/Data`, and no directory of the path is that
//! mount's root. There the path lies beneath its mount point where the
//! mount's held root followed by the path's own names, walked the same way,
//! names the very file the path does.

use std::io;

use rustix::{
  fd::OwnedFd,
  fs::{AtFlags, FileType, Mode, OFlags},
  io::Errno,
};

/// A file as its file system names it: the device of the file system it is on
/// and its number there, which `stat` reports as `st_dev` and `st_ino`. POSIX
/// (`<sys/stat.h>`, 2024): "A file identity is uniquely determined by the
/// combination of st_dev and st_ino", and "At any given time in a system,
/// distinct files shall have distinct file identities".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Node {
  device: u64,
  number: u64,
}

impl Node {
  /// The file `stat` describes.
  #[allow(clippy::unnecessary_cast)]
  pub(crate) fn of(stat: &rustix::fs::Stat) -> Self {
    Self {
      device: stat.st_dev as u64,
      number: stat.st_ino as u64,
    }
  }

  /// A file of a law's own making.
  #[cfg(test)]
  pub(crate) const fn for_laws(device: u64, number: u64) -> Self {
    Self { device, number }
  }
}

/// What a walk asks of the file system: one name at a time, looked up in a
/// directory the walk holds. [`Held`] asks this platform; a law stands a
/// scripted file system in for it.
pub(crate) trait Directories {
  /// A directory the walk holds.
  type Dir;

  /// The process's root directory, `/`, held.
  fn root(&mut self) -> io::Result<Self::Dir>;

  /// The directory `name`, one component, names in `dir`, held: entered
  /// without following a symbolic link, and refused by name where it is one
  /// ([`a_link`]) or is anything but a directory ([`not_a_directory`]) —
  /// never descended into.
  fn enter(&mut self, dir: &Self::Dir, name: &[u8]) -> io::Result<Self::Dir>;

  /// The file `dir` holds, asked of its own handle.
  fn node(&mut self, dir: &Self::Dir) -> io::Result<Node>;

  /// The file `name`, one component, names in `dir`: described without
  /// following a symbolic link and without being opened, and refused by name
  /// where it is a link ([`a_link`]).
  fn named(&mut self, dir: &Self::Dir, name: &[u8]) -> io::Result<Node>;

  /// Whether a failure to describe a name is the platform declining to, which
  /// a walk passes over at a path's last name — the path is then placed by
  /// the directory that holds it — and a firmlink's comparison reads as no
  /// match.
  fn passes_over(&self, err: &io::Error) -> bool;
}

/// This platform's directories, each held by a descriptor: `/` opened with
/// `open`, every other directory with `openat` relative to the one before
/// it, and a path's last name described with `fstatat` — see the module.
pub(crate) struct Held {
  /// The failures a walk passes over at a path's last name.
  passes_over: fn(&io::Error) -> bool,
}

impl Held {
  /// This platform's directories, whose walks pass over the failures
  /// `passes_over` names at a path's last name: Apple's declines, and nothing
  /// on FreeBSD, OpenBSD, DragonFly and NetBSD, which name none.
  pub(crate) const fn new(passes_over: fn(&io::Error) -> bool) -> Self {
    Self { passes_over }
  }
}

impl Directories for Held {
  type Dir = OwnedFd;

  fn root(&mut self) -> io::Result<OwnedFd> {
    Ok(rustix::fs::open("/", HELD, Mode::empty())?)
  }

  fn enter(&mut self, dir: &OwnedFd, name: &[u8]) -> io::Result<OwnedFd> {
    opened_at(dir, name, HELD)
  }

  fn node(&mut self, dir: &OwnedFd) -> io::Result<Node> {
    Ok(Node::of(&rustix::fs::fstat(dir)?))
  }

  fn named(&mut self, dir: &OwnedFd, name: &[u8]) -> io::Result<Node> {
    let stat = rustix::fs::statat(dir, one_name(name)?, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
      return Err(a_link());
    }
    Ok(Node::of(&stat))
  }

  fn passes_over(&self, err: &io::Error) -> bool {
    (self.passes_over)(err)
  }
}

/// How a walk opens a directory it holds on Apple platforms: for search only
/// — `O_SEARCH` is `O_EXEC | O_DIRECTORY` — following no link: see the
/// module. `libc` spells the flag and `rustix` does not, so it is carried in
/// as its raw bits.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
const HELD: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as u32)
  .union(OFlags::NOFOLLOW)
  .union(OFlags::CLOEXEC);

/// How a walk opens a directory it holds on FreeBSD: as a path alone,
/// `O_PATH`, a directory, following no link: see the module.
#[cfg(target_os = "freebsd")]
const HELD: OFlags = OFlags::PATH
  .union(OFlags::DIRECTORY)
  .union(OFlags::NOFOLLOW)
  .union(OFlags::CLOEXEC);

/// How a walk opens a directory it holds on OpenBSD, NetBSD and DragonFly: for
/// reading, the only way each opens one, a directory, following no link: see
/// the module.
#[cfg(any(target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
const HELD: OFlags = OFlags::RDONLY
  .union(OFlags::DIRECTORY)
  .union(OFlags::NOFOLLOW)
  .union(OFlags::CLOEXEC);

/// `name`, one component, opened in `dir` with `flags` — `O_DIRECTORY` and
/// `O_NOFOLLOW` among them — or refused by name where it is a link or no
/// directory: see [`refusal_at`]. Every other failure is the open's own.
fn opened_at(dir: &OwnedFd, name: &[u8], flags: OFlags) -> io::Result<OwnedFd> {
  let name = one_name(name)?;
  match rustix::fs::openat(dir, name, flags, Mode::empty()) {
    Ok(held) => Ok(held),
    Err(errno @ (Errno::LOOP | Errno::MLINK | Errno::FTYPE | Errno::NOTDIR | Errno::OPNOTSUPP)) => {
      Err(refusal_at(dir, name, errno))
    }
    Err(errno) => Err(errno.into()),
  }
}

/// What an open of `name` in `dir` that answered `errno` refused. Each kernel
/// answers a link it may not follow in its own word — `ELOOP`, `EMLINK` or
/// `EFTYPE` — and XNU, and FreeBSD under `O_PATH`, answer one `ENOTDIR`, as
/// they check `O_DIRECTORY` first; OpenBSD, NetBSD and DragonFly answer a
/// socket `EOPNOTSUPP` before they weigh `O_DIRECTORY`. So the name is asked
/// what it is, through the same directory and without following it: a link
/// is refused as one, anything else but a directory as no directory, and a
/// directory, or a name gone since, leaves the open's own failure.
fn refusal_at(dir: &OwnedFd, name: &[u8], errno: Errno) -> io::Error {
  match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
    Ok(stat) => match FileType::from_raw_mode(stat.st_mode) {
      FileType::Symlink => a_link(),
      FileType::Directory => errno.into(),
      _ => not_a_directory(),
    },
    Err(_) => errno.into(),
  }
}

/// `name` as one component of a path: not empty, neither `.` nor `..`, and
/// holding no `/` — a name with one would be looked up through every
/// component before its last, following a link at each — or the refusal of
/// a name that is not one.
fn one_name(name: &[u8]) -> io::Result<&[u8]> {
  if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
    return Err(not_canonical());
  }
  Ok(name)
}

/// The file `path` names, opened with `flags` — which follow no link at the
/// last component — through the directory holding it, which a walk from `/`
/// holds: every directory on the way entered as [`Held::enter`] enters one,
/// so nothing is reached through a link. `/` itself is opened as it is.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(crate) fn opened(path: &[u8], flags: OFlags) -> io::Result<OwnedFd> {
  let names = names(path)?;
  let Some((&(last, _), parents)) = names.split_last() else {
    return Ok(rustix::fs::open("/", flags, Mode::empty())?);
  };
  let mut dirs = Held::new(|_| false);
  let mut dir = dirs.root()?;
  for &(name, _) in parents {
    dir = dirs.enter(&dir, name)?;
  }
  opened_at(&dir, last, flags)
}

/// What a walk of an absolute path found, holding every directory it passed.
struct Walk {
  /// `/` and every directory of the path beneath it, in order: where the
  /// path's spelling of each ends, and the file it is, read from its handle.
  held: Vec<(usize, Node)>,
  /// The file the whole path names, described through the directory holding
  /// its last name — or `/` itself, for the path `/` — and `None` where the
  /// platform declined to describe it.
  object: Option<Node>,
}

impl Walk {
  /// Where the path begins beneath the mount whose root is `root`, as a byte
  /// offset into a path `length` bytes long: at its end, where the path names
  /// the root itself, which is then proven to be so; else after the deepest
  /// directory of it that is the root, and its separator — after the `/` of
  /// the root directory. `None` where no file the walk named is the root: a
  /// path that only begins with the mount point's bytes — `/Volumes/USB2/x`
  /// beside `/Volumes/USB` — is not beneath it.
  fn beneath(&self, length: usize, root: Node) -> Option<usize> {
    if self.object == Some(root) {
      return Some(length);
    }
    self
      .held
      .iter()
      .rev()
      .find(|&&(_, node)| node == root)
      .map(|&(end, _)| if end == 1 { end } else { end + 1 })
  }

  /// The deepest file the walk named: the path's own, or where that was
  /// passed over, the directory holding the path's last name.
  fn deepest(&self) -> Node {
    self.object.unwrap_or(self.held[self.held.len() - 1].1)
  }
}

/// The names of `path` — an absolute path as `realpath` answers one, or a
/// mount point as the kernel recorded it — each with where its spelling
/// ends, or the refusal of a path that is not absolute or holds a name no
/// component is (see [`one_name`]): neither answers one.
fn names(path: &[u8]) -> io::Result<Vec<(&[u8], usize)>> {
  let Some(rest) = path.strip_prefix(b"/") else {
    return Err(not_canonical());
  };
  if rest.is_empty() {
    return Ok(Vec::new());
  }
  let mut names = Vec::new();
  let mut end = 0;
  for name in rest.split(|&byte| byte == b'/') {
    end += 1 + name.len();
    names.push((one_name(name)?, end));
  }
  Ok(names)
}

/// Walks `path`, an absolute path, from `/`: each of its directories entered
/// — see [`Directories::enter`] — and held while its next name is looked up
/// in it, and its last name described through the directory holding it —
/// see [`Directories::named`] — or passed over where the platform declines
/// to describe it.
fn walk<D: Directories>(dirs: &mut D, path: &[u8]) -> io::Result<Walk> {
  let names = names(path)?;
  let mut dir = dirs.root()?;
  let mut held = vec![(1, dirs.node(&dir)?)];
  let Some((&(last, _), parents)) = names.split_last() else {
    let object = Some(held[0].1);
    return Ok(Walk { held, object });
  };
  for &(name, end) in parents {
    dir = dirs.enter(&dir, name)?;
    held.push((end, dirs.node(&dir)?));
  }
  let object = match dirs.named(&dir, last) {
    Ok(node) => Some(node),
    Err(err) if dirs.passes_over(&err) => None,
    Err(err) => return Err(err),
  };
  Ok(Walk { held, object })
}

/// The mount's root, held: `mount_point` walked from `/` as a path is, every
/// name of it entered — see [`Directories::enter`] — the last as the root.
fn mount_root<D: Directories>(dirs: &mut D, mount_point: &[u8]) -> io::Result<D::Dir> {
  let mut dir = dirs.root()?;
  for (name, _) in names(mount_point)? {
    dir = dirs.enter(&dir, name)?;
  }
  Ok(dir)
}

/// Whether the deepest file the walk of `path` named is the very file the
/// mount's held root followed by the same names names, walked the same way:
/// the shape a firmlink gives — see the module. A name the platform declines
/// to describe is no match — Apple's declines hold a name that is not there
/// — and a link or a non-directory on the way is refused by name.
fn through<D: Directories>(
  dirs: &mut D,
  root: &D::Dir,
  path: &[u8],
  walk: &Walk,
) -> io::Result<bool> {
  let names = names(path)?;
  let named = match walk.object {
    Some(_) => names.len(),
    None => walk.held.len() - 1,
  };
  let Some((&(last, _), parents)) = names[..named].split_last() else {
    // Nothing below `/` was named: no firmlink is on the way.
    return Ok(false);
  };
  let mut held: Option<D::Dir> = None;
  for &(name, _) in parents {
    match dirs.enter(held.as_ref().unwrap_or(root), name) {
      Ok(next) => held = Some(next),
      Err(err) if dirs.passes_over(&err) => return Ok(false),
      Err(err) => return Err(err),
    }
  }
  match dirs.named(held.as_ref().unwrap_or(root), last) {
    Ok(node) => Ok(node == walk.deepest()),
    Err(err) if dirs.passes_over(&err) => Ok(false),
    Err(err) => Err(err),
  }
}

/// Where `path` — an absolute path, `realpath`'s answer — begins beneath the
/// mount point its observation reported, `mount_point`, as a byte offset into
/// it, **decided by walks that hold every directory they pass and follow no
/// link** — see the module:
///
/// 1. **The mount's root** is `mount_point` walked from `/`, held, and taken
///    only where `bound` proves the held root is the observation's mount —
///    else [`unbound_root`].
/// 2. **The path** is walked from `/`. Where the observation holds a
///    descriptor on the path's file, `observed` is that file, and the walk's
///    last name must be it — else [`another_file`]; with none, the deepest
///    file the walk named must lie on the root's device — else
///    [`another_device`].
/// 3. **The split**: the path's own length where it names the root itself;
///    else after the deepest of its directories that is the root and its
///    separator — after the `/` of the root directory.
/// 4. **Through a firmlink**, where `firmlinks`: where no directory of the
///    path is the root, the mount's root followed by the path's names must
///    name the very file the path does, and then the whole path beneath `/`
///    is the part beneath the mount point.
///
/// A path placed by neither is refused ([`not_beneath`]), as is any walk that
/// meets a link, a non-directory or another file: **never the mount's root,
/// and never an empty relative path**. Every read that fails is the error it
/// is.
pub(crate) fn split<D: Directories>(
  dirs: &mut D,
  path: &[u8],
  mount_point: &[u8],
  bound: impl FnOnce(&D::Dir) -> io::Result<bool>,
  observed: Option<Node>,
  firmlinks: bool,
) -> io::Result<usize> {
  let root = mount_root(dirs, mount_point)?;
  if !bound(&root)? {
    return Err(unbound_root());
  }
  let root_node = dirs.node(&root)?;
  let walk = walk(dirs, path)?;
  match observed {
    Some(observed) if walk.object != Some(observed) => return Err(another_file()),
    None if walk.deepest().device != root_node.device => return Err(another_device()),
    _ => {}
  }
  if let Some(offset) = walk.beneath(path.len(), root_node) {
    return Ok(offset);
  }
  if firmlinks && through(dirs, &root, path, &walk)? {
    return Ok(1);
  }
  Err(not_beneath())
}

/// A walk's refusal of a path the file system no longer resolves, without a
/// symbolic link, to the file its observation described beneath its mount;
/// carried in the [`io::Error`] each refusal is, so that one is told from a
/// failed read — see `is_refusal`, which Apple's witness asks.
#[derive(Debug)]
struct Refused(&'static str);

impl core::fmt::Display for Refused {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.0)
  }
}

impl std::error::Error for Refused {}

/// A refusal, as the resolve's error: the path is not found where its
/// observation placed it.
fn refused(what: &'static str) -> io::Error {
  io::Error::new(io::ErrorKind::NotFound, Refused(what))
}

/// Whether `err` is one of a walk's refusals, rather than a read that failed.
#[cfg(any(
  test,
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(crate) fn is_refusal(err: &io::Error) -> bool {
  err.get_ref().is_some_and(|inner| inner.is::<Refused>())
}

/// The refusal of a name that is a symbolic link now.
fn a_link() -> io::Error {
  refused(
    "a name on the path is a symbolic link now: the canonical path held none, so one was put \
     there since, and a walk follows no link",
  )
}

/// The refusal of a directory's name that names no directory now.
fn not_a_directory() -> io::Error {
  refused(
    "a directory of the path is no directory now: the canonical path's was one, so it was \
     replaced since",
  )
}

/// The refusal of a path whose last name is not the file its observation
/// holds through its descriptor.
fn another_file() -> io::Error {
  refused("the path names another file now than the one its observation holds")
}

/// The refusal of a path whose file lies on another device than its mount's
/// root.
fn another_device() -> io::Error {
  refused(
    "the path's file lies on another device than its mount's root: the path resolves through \
     another mount now",
  )
}

/// The refusal of a mount point whose held root is not the observed mount's.
fn unbound_root() -> io::Error {
  refused("the directory the mount point names is not the observed mount's root now")
}

/// The refusal of a path none of whose directories is its mount's root, and
/// no firmlink: the mount point the platform reported names some other
/// directory now, and no split of the path beneath it is the file system's.
/// Never read as the path being the mount's root.
fn not_beneath() -> io::Error {
  refused(
    "the path lies beneath no directory its mount point names: the file system does not place \
     it beneath that mount",
  )
}

/// The refusal of a path no walk takes: one that is not absolute, or holds a
/// name no component is — `realpath` answers neither.
fn not_canonical() -> io::Error {
  io::Error::new(
    io::ErrorKind::InvalidInput,
    "a path a walk takes is absolute, and holds no empty, `.` or `..` name and no name with a `/`",
  )
}

/// A file system of a law's own making, looked up as a real one is: a name in
/// the directory a walk holds, and — for the road the walk replaced —
/// `lstat` of a whole path, following a link at every component but the last.
#[cfg(test)]
pub(crate) mod scripted {
  use std::{collections::HashMap, io};

  use super::{Directories, Node, a_link, not_a_directory};

  /// What a scripted file system holds at one path.
  enum File {
    /// A directory, which a walk may enter.
    Directory(Node),
    /// A file that is no directory: a regular file, a socket, a device.
    Other(Node),
    /// A file the platform declines to describe: `EACCES`.
    Unread,
    /// A symbolic link, to an absolute path.
    Link(Node, Vec<u8>),
  }

  /// A file system of a law's own making.
  pub(crate) struct Scripted {
    /// Every file, by its whole path, case-folded where `folds_case`.
    files: HashMap<Vec<u8>, File>,
    /// Whether names fold case, as a case-insensitive APFS or HFS+ volume's
    /// do.
    folds_case: bool,
    /// The failures a walk passes over at a path's last name.
    passes_over: fn(&io::Error) -> bool,
  }

  impl Scripted {
    /// A file system of nothing but its root, `root`, whose names fold case
    /// where `folds_case` and whose walks pass over nothing.
    pub(crate) fn new(folds_case: bool, root: Node) -> Self {
      let mut files = HashMap::new();
      files.insert(b"/".to_vec(), File::Directory(root));
      Self {
        files,
        folds_case,
        passes_over: |_| false,
      }
    }

    /// The same file system, whose walks pass over the failures
    /// `passes_over` names at a path's last name.
    pub(crate) fn passing_over(mut self, passes_over: fn(&io::Error) -> bool) -> Self {
      self.passes_over = passes_over;
      self
    }

    /// A directory at `path`.
    pub(crate) fn directory(self, path: &str, node: Node) -> Self {
      self.with(path, File::Directory(node))
    }

    /// A file that is no directory at `path`.
    pub(crate) fn file(self, path: &str, node: Node) -> Self {
      self.with(path, File::Other(node))
    }

    /// A file at `path` the platform declines to describe.
    pub(crate) fn unread(self, path: &str) -> Self {
      self.with(path, File::Unread)
    }

    /// `path` and everything beneath it swapped for a symbolic link to
    /// `target`.
    pub(crate) fn swapped_for_link(self, path: &str, node: Node, target: &str) -> Self {
      self
        .without(path)
        .with(path, File::Link(node, target.as_bytes().to_vec()))
    }

    /// `path` and everything beneath it swapped for a file that is no
    /// directory.
    pub(crate) fn swapped_for_file(self, path: &str, node: Node) -> Self {
      self.without(path).with(path, File::Other(node))
    }

    fn with(mut self, path: &str, file: File) -> Self {
      let key = self.key(path.as_bytes());
      self.files.insert(key, file);
      self
    }

    fn without(mut self, path: &str) -> Self {
      let key = self.key(path.as_bytes());
      let beneath = [&key[..], b"/"].concat();
      self
        .files
        .retain(|name, _| *name != key && !name.starts_with(&beneath));
      self
    }

    fn key(&self, path: &[u8]) -> Vec<u8> {
      if self.folds_case {
        path.to_ascii_lowercase()
      } else {
        path.to_vec()
      }
    }

    /// `dir`'s name for `name`.
    fn joined(&self, dir: &[u8], name: &[u8]) -> Vec<u8> {
      let path = if dir == b"/" {
        [b"/", name].concat()
      } else {
        [dir, b"/", name].concat()
      };
      self.key(&path)
    }

    /// `lstat` of the whole path, as POSIX resolves one: a link at every
    /// component but the last is followed, and the last is described as
    /// itself.
    pub(crate) fn lstat(&self, path: &[u8]) -> io::Result<Node> {
      let mut pending: Vec<Vec<u8>> = path
        .split(|&byte| byte == b'/')
        .filter(|name| !name.is_empty())
        .rev()
        .map(<[u8]>::to_vec)
        .collect();
      let mut dir = b"/".to_vec();
      let mut links = 0;
      let Some(mut name) = pending.pop() else {
        return match self.files.get(&dir) {
          Some(File::Directory(node)) => Ok(*node),
          _ => Err(io::ErrorKind::NotFound.into()),
        };
      };
      loop {
        let key = self.joined(&dir, &name);
        let last = pending.is_empty();
        match self.files.get(&key) {
          None => return Err(io::ErrorKind::NotFound.into()),
          Some(File::Unread) => return Err(io::ErrorKind::PermissionDenied.into()),
          Some(File::Directory(node)) if last => return Ok(*node),
          Some(File::Other(node) | File::Link(node, _)) if last => return Ok(*node),
          Some(File::Directory(_)) => dir = key,
          Some(File::Other(_)) => return Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
          Some(File::Link(_, target)) => {
            links += 1;
            if links > 8 {
              return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            pending.extend(
              target
                .split(|&byte| byte == b'/')
                .filter(|name| !name.is_empty())
                .rev()
                .map(<[u8]>::to_vec),
            );
            dir = b"/".to_vec();
          }
        }
        name = pending.pop().expect("a name below the last one remains");
      }
    }
  }

  impl Directories for Scripted {
    type Dir = Vec<u8>;

    fn root(&mut self) -> io::Result<Vec<u8>> {
      Ok(b"/".to_vec())
    }

    fn enter(&mut self, dir: &Vec<u8>, name: &[u8]) -> io::Result<Vec<u8>> {
      let key = self.joined(dir, name);
      match self.files.get(&key) {
        Some(File::Directory(_)) => Ok(key),
        Some(File::Link(..)) => Err(a_link()),
        Some(File::Other(_)) => Err(not_a_directory()),
        Some(File::Unread) => Err(io::ErrorKind::PermissionDenied.into()),
        None => Err(io::ErrorKind::NotFound.into()),
      }
    }

    fn node(&mut self, dir: &Vec<u8>) -> io::Result<Node> {
      match self.files.get(dir) {
        Some(File::Directory(node)) => Ok(*node),
        _ => Err(io::ErrorKind::NotFound.into()),
      }
    }

    fn named(&mut self, dir: &Vec<u8>, name: &[u8]) -> io::Result<Node> {
      match self.files.get(&self.joined(dir, name)) {
        Some(File::Directory(node) | File::Other(node)) => Ok(*node),
        Some(File::Link(..)) => Err(a_link()),
        Some(File::Unread) => Err(io::ErrorKind::PermissionDenied.into()),
        None => Err(io::ErrorKind::NotFound.into()),
      }
    }

    fn passes_over(&self, err: &io::Error) -> bool {
      (self.passes_over)(err)
    }
  }
}

#[cfg(test)]
mod tests {
  use std::{
    ffi::OsStr,
    io,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
  };

  use super::{Held, Node, is_refusal, scripted::Scripted, split};

  /// Whether this platform places a path beneath its mount through a
  /// firmlink.
  const FIRMLINKS: bool = cfg!(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ));

  /// The road the walk replaced, kept for the laws to set beside it: the path
  /// and each of its ancestors, deepest first, asked which file they name by
  /// `lstat` of the whole name — `node_of` — with the observation's own file
  /// standing in for the path's; the first that names the file the mount
  /// point names splits it; and on Apple the mount point followed by the
  /// deepest name it could read compared with that name. `None` where it
  /// placed the path by neither.
  fn before(
    path: &[u8],
    mount_point: &[u8],
    observed: Option<Node>,
    firmlinks: bool,
    node_of: impl Fn(&[u8]) -> Option<Node>,
  ) -> Option<usize> {
    let node_of = |name: &[u8]| match observed {
      Some(observed) if name == path => Some(observed),
      _ => node_of(name),
    };
    let root = node_of(mount_point)?;
    let mut end = path.len();
    while end > 0 {
      if node_of(&path[..end]) == Some(root) {
        return Some(if end == path.len() || end == 1 {
          end
        } else {
          end + 1
        });
      }
      end = match path[..end].iter().rposition(|&byte| byte == b'/') {
        Some(0) if end > 1 => 1,
        Some(cut) if cut > 0 => cut,
        _ => 0,
      };
    }
    let mut end = path.len();
    while firmlinks && end > 1 {
      let anchor = &path[..end];
      if let Some(node) = node_of(anchor) {
        return (node_of(&[mount_point, anchor].concat()) == Some(node)).then_some(1);
      }
      end = path[..end]
        .iter()
        .rposition(|&byte| byte == b'/')
        .unwrap_or(0);
    }
    None
  }

  /// Whether `err` is a walk's refusal that says `what`.
  fn says(err: &io::Error, what: &str) -> bool {
    is_refusal(err) && err.to_string().contains(what)
  }

  /// The layout the scripted laws walk, case-insensitive: `/` on device 1; a
  /// volume mounted at `/Volumes/ssd` on device 7, holding `x/y`, `a/b/c` and
  /// `other/a/b/c`; another mounted beneath it at `/Volumes/ssd/m` on device
  /// 8; a directory that only begins with its bytes, `/Volumes/ssd2`; and a
  /// volume mounted at `/net` on device 9, holding `a/b/c`.
  fn volumes() -> Scripted {
    Scripted::new(true, Node::for_laws(1, 2))
      .directory("/volumes", Node::for_laws(1, 40))
      .directory("/volumes/ssd", Node::for_laws(7, 2))
      .directory("/volumes/ssd/x", Node::for_laws(7, 90))
      .file("/volumes/ssd/x/y", Node::for_laws(7, 91))
      .directory("/volumes/ssd/a", Node::for_laws(7, 100))
      .directory("/volumes/ssd/a/b", Node::for_laws(7, 101))
      .file("/volumes/ssd/a/b/c", Node::for_laws(7, 102))
      .directory("/volumes/ssd/other", Node::for_laws(7, 200))
      .directory("/volumes/ssd/other/a", Node::for_laws(7, 201))
      .directory("/volumes/ssd/other/a/b", Node::for_laws(7, 202))
      .file("/volumes/ssd/other/a/b/c", Node::for_laws(7, 203))
      .directory("/volumes/ssd/m", Node::for_laws(8, 2))
      .file("/volumes/ssd/m/z", Node::for_laws(8, 3))
      .directory("/volumes/ssd2", Node::for_laws(1, 41))
      .directory("/volumes/ssd2/x", Node::for_laws(1, 42))
      .directory("/net", Node::for_laws(9, 2))
      .directory("/net/a", Node::for_laws(9, 10))
      .directory("/net/a/b", Node::for_laws(9, 11))
      .file("/net/a/b/c", Node::for_laws(9, 12))
  }

  /// The layout of a firmlinked system, case-insensitive: the sealed system
  /// volume's `/`, whose `/Users` is the data volume's `Users`, mounted at
  /// `/System/Volumes/Data` — both spellings name one directory, as a
  /// firmlink makes them — and a volume at `/elsewhere`.
  fn firmlinked() -> Scripted {
    Scripted::new(true, Node::for_laws(1, 2))
      .directory("/users", Node::for_laws(1, 300))
      .directory("/users/al", Node::for_laws(1, 400))
      .file("/users/al/x", Node::for_laws(1, 500))
      .directory("/library", Node::for_laws(1, 600))
      .directory("/system", Node::for_laws(1, 10))
      .directory("/system/volumes", Node::for_laws(1, 11))
      .directory("/system/volumes/data", Node::for_laws(1, 1 << 60))
      .directory("/system/volumes/data/users", Node::for_laws(1, 300))
      .directory("/system/volumes/data/users/al", Node::for_laws(1, 400))
      .file("/system/volumes/data/users/al/x", Node::for_laws(1, 500))
      .directory("/elsewhere", Node::for_laws(5, 1))
      .directory("/elsewhere/al", Node::for_laws(5, 2))
      .file("/elsewhere/al/x", Node::for_laws(5, 3))
  }

  /// A platform's decline, for the laws whose walks pass one over.
  fn declined(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
  }

  /// **A directory swapped for a symbolic link after the path was
  /// canonicalized is refused by name, never placed.** On the scripted
  /// layout, `/Volumes/ssd/a` swapped for a link — onto another mount, or
  /// within its own — and then for a file, and the mount point's own
  /// `/Volumes` swapped for a link: each walk refuses. The planted defect,
  /// side by side: the road the walk replaced, which asked `lstat` of each
  /// whole name, followed the link at every name below it, read the link
  /// itself as just another file, and found the mount's root above it — and
  /// placed the path beneath the mount.
  #[test]
  fn test_a_directory_swapped_for_a_link_is_refused_by_name() {
    let path = b"/Volumes/ssd/a/b/c";
    for (target, onto) in [
      ("/net/a", "another mount"),
      ("/volumes/ssd/other/a", "its own mount"),
    ] {
      let mut fs = volumes().swapped_for_link("/volumes/ssd/a", Node::for_laws(7, 150), target);
      let refused = split(&mut fs, path, b"/Volumes/ssd", |_| Ok(true), None, false).unwrap_err();
      assert!(says(&refused, "symbolic link"), "onto {onto}: {refused}");
      assert_eq!(
        before(path, b"/Volumes/ssd", None, false, |name| fs
          .lstat(name)
          .ok()),
        Some(b"/Volumes/ssd/".len()),
        "the old walk placed a path swapped onto {onto} beneath the mount"
      );
    }

    let mut fs = volumes().swapped_for_file("/volumes/ssd/a", Node::for_laws(7, 151));
    let refused = split(&mut fs, path, b"/Volumes/ssd", |_| Ok(true), None, false).unwrap_err();
    assert!(says(&refused, "no directory"), "{refused}");

    let mut fs = volumes().swapped_for_link("/volumes", Node::for_laws(1, 152), "/net");
    let refused = split(
      &mut fs,
      b"/net/a/b/c",
      b"/Volumes/ssd",
      |_| Ok(true),
      None,
      false,
    )
    .unwrap_err();
    assert!(
      says(&refused, "symbolic link"),
      "a mount point spelled through a link: {refused}"
    );
  }

  /// **A path lies beneath its mount point by a walk of its own
  /// directories.** On the scripted case-insensitive layout, `/volumes/SSD/x`
  /// beneath the mount point `/Volumes/ssd` is `x`, not the mount's root; the
  /// mount point spelled otherwise is the mount's root itself, proven; the
  /// root splits after its `/`; a path that only begins with the mount
  /// point's bytes, `/Volumes/ssd2/x`, is not beneath it; a mount point that
  /// names no file splits nothing; and a last name whose file the platform
  /// declines to describe is placed by the directory holding it — and where
  /// the platform names no decline, it is the error it is. The road the walk
  /// replaced answers every one of these the same.
  #[test]
  fn test_a_path_lies_beneath_its_mount_point_by_a_walk_of_its_own_directories() {
    let placed = |fs: &mut Scripted, path: &'static [u8], mount_point: &[u8]| {
      split(fs, path, mount_point, |_| Ok(true), None, false).map(|at| &path[at..])
    };
    let fs = &mut volumes();
    assert_eq!(
      placed(fs, b"/volumes/SSD/x", b"/Volumes/ssd").unwrap(),
      b"x"
    );
    assert_eq!(
      placed(fs, b"/Volumes/ssd/X/Y", b"/Volumes/ssd").unwrap(),
      b"X/Y"
    );
    assert_eq!(
      placed(fs, b"/VOLUMES/SSD", b"/Volumes/ssd").unwrap(),
      b"",
      "the mount's root, proven"
    );
    assert!(
      placed(fs, b"/Volumes/ssd2/x", b"/Volumes/ssd").is_err(),
      "a sibling that begins with the same bytes"
    );
    assert_eq!(
      placed(fs, b"/Volumes/ssd2/x", b"/").unwrap(),
      b"Volumes/ssd2/x",
      "the root splits after its `/`"
    );
    assert_eq!(
      placed(fs, b"/", b"/").unwrap(),
      b"",
      "the root is its own mount's root"
    );
    assert!(
      placed(fs, b"/volumes/SSD/x", b"/Volumes/gone").is_err(),
      "a mount point that names no file splits nothing"
    );

    let fs = &mut volumes().unread("/volumes/ssd/x/u").passing_over(declined);
    assert_eq!(
      placed(fs, b"/volumes/SSD/x/u", b"/Volumes/ssd").unwrap(),
      b"x/u",
      "a last name whose file is not read is placed by its directory"
    );
    let fs = &mut volumes().unread("/volumes/ssd/x/u");
    assert!(
      placed(fs, b"/volumes/SSD/x/u", b"/Volumes/ssd").is_err(),
      "a platform that names no decline passes nothing over"
    );

    let fs = volumes();
    for (path, mount_point, relative) in [
      (&b"/volumes/SSD/x"[..], &b"/Volumes/ssd"[..], &b"x"[..]),
      (b"/VOLUMES/SSD", b"/Volumes/ssd", b""),
      (b"/Volumes/ssd2/x", b"/", b"Volumes/ssd2/x"),
    ] {
      let at = before(path, mount_point, None, false, |name| fs.lstat(name).ok()).unwrap();
      assert_eq!(&path[at..], relative, "the road the walk replaced");
    }
  }

  /// **A firmlinked path is placed by the file its names name beneath the
  /// mount's root, and a link swapped in on the way is refused.** On the
  /// scripted firmlinked layout, `/users/AL/x` splits after its root beneath
  /// `/System/Volumes/Data`; the parent of a last name whose file is not read
  /// places it the same; a name the data volume does not hold, `/Library`, is
  /// not beneath it, and nothing is placed through a firmlink where the
  /// platform has none. `/Users/al` swapped for a link to a directory on
  /// another volume is refused. The planted defect, side by side: the old
  /// comparison followed the link on both of its sides, found one file, and
  /// placed the path beneath the data volume.
  #[test]
  fn test_a_firmlinked_path_is_placed_by_a_walk_and_a_swapped_link_is_refused() {
    let data = b"/System/Volumes/Data";
    let fs = &mut firmlinked();
    assert_eq!(
      split(fs, b"/users/AL/x", data, |_| Ok(true), None, true).unwrap(),
      1
    );
    assert!(
      split(fs, b"/Library", data, |_| Ok(true), None, true).is_err(),
      "the data volume holds no such name"
    );
    assert!(
      split(fs, b"/users/AL/x", data, |_| Ok(true), None, false).is_err(),
      "no firmlink where the platform has none"
    );
    let fs = &mut firmlinked()
      .unread("/users/al/x")
      .unread("/system/volumes/data/users/al/x")
      .passing_over(declined);
    assert_eq!(
      split(fs, b"/users/AL/x", data, |_| Ok(true), None, true).unwrap(),
      1,
      "the parent of a last name whose file is not read"
    );

    let mut fs = firmlinked()
      .swapped_for_link("/users/al", Node::for_laws(1, 450), "/elsewhere/al")
      .swapped_for_link(
        "/system/volumes/data/users/al",
        Node::for_laws(1, 450),
        "/elsewhere/al",
      );
    let refused = split(&mut fs, b"/users/AL/x", data, |_| Ok(true), None, true).unwrap_err();
    assert!(says(&refused, "symbolic link"), "{refused}");
    assert_eq!(
      before(b"/users/AL/x", data, None, true, |name| fs.lstat(name).ok()),
      Some(1),
      "the old comparison followed the link on both sides"
    );
  }

  /// **A path is placed only as its observation's own file, on its
  /// observation's own mount.** On the scripted layout: a path whose last
  /// name is no longer the file the observation holds through its descriptor
  /// is refused; with no descriptor, a path whose file lies on another device
  /// than the mount's root — `/Volumes/ssd/m/z`, beneath a mount made at
  /// `/Volumes/ssd/m` since the observation — is refused; and a mount point
  /// whose held root is not the observation's mount is refused. The planted
  /// defect, side by side: the old road stood the observation's file in for
  /// the path's own, asked no device and no mount, and placed every one of
  /// these beneath `/Volumes/ssd`.
  #[test]
  fn test_a_path_is_placed_only_as_its_observations_own_file() {
    let fs = &mut volumes();
    let path = b"/Volumes/ssd/x/y";
    let held = Node::for_laws(7, 91);
    assert_eq!(
      split(fs, path, b"/Volumes/ssd", |_| Ok(true), Some(held), false).unwrap(),
      b"/Volumes/ssd/".len()
    );
    let replaced = Node::for_laws(7, 999);
    let refused = split(
      fs,
      path,
      b"/Volumes/ssd",
      |_| Ok(true),
      Some(replaced),
      false,
    )
    .unwrap_err();
    assert!(says(&refused, "another file"), "{refused}");
    assert_eq!(
      before(path, b"/Volumes/ssd", Some(replaced), false, |name| fs
        .lstat(name)
        .ok()),
      Some(b"/Volumes/ssd/".len()),
      "the old road stood the held file in for the path's own"
    );

    let mounted = b"/Volumes/ssd/m/z";
    let refused = split(fs, mounted, b"/Volumes/ssd", |_| Ok(true), None, false).unwrap_err();
    assert!(says(&refused, "another device"), "{refused}");
    assert_eq!(
      before(mounted, b"/Volumes/ssd", None, false, |name| fs
        .lstat(name)
        .ok()),
      Some(b"/Volumes/ssd/".len()),
      "the old road asked no device"
    );

    let refused = split(fs, path, b"/Volumes/ssd", |_| Ok(false), None, false).unwrap_err();
    assert!(says(&refused, "observed mount"), "{refused}");
  }

  /// A directory this law owns, beneath this host's temporary directory as
  /// `realpath` spells it — on Apple platforms beneath the data volume's own
  /// mount point, so that one of the path's own directories is its mount's
  /// root and no firmlink is on the way.
  fn owned() -> (tempfile::TempDir, PathBuf) {
    let data = Path::new("/System/Volumes/Data/private/tmp");
    let dir = if FIRMLINKS && data.is_dir() {
      tempfile::Builder::new().tempdir_in(data).unwrap()
    } else {
      tempfile::tempdir().unwrap()
    };
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
  }

  /// `base/a/b/c` and `base/elsewhere/a/b/c`, each a regular file beneath
  /// directories of its own.
  fn lay_out(base: &Path) -> PathBuf {
    for dir in ["a/b", "elsewhere/a/b"] {
      std::fs::create_dir_all(base.join(dir)).unwrap();
    }
    std::fs::write(base.join("a/b/c"), b"whichdisk").unwrap();
    std::fs::write(base.join("elsewhere/a/b/c"), b"elsewhere").unwrap();
    base.join("a/b/c")
  }

  /// `base/a` swapped for a symbolic link to `base/elsewhere/a`.
  fn swap(base: &Path) {
    std::fs::rename(base.join("a"), base.join("a.was")).unwrap();
    std::os::unix::fs::symlink(base.join("elsewhere/a"), base.join("a")).unwrap();
  }

  /// The mount point this crate's own resolve reports for `path`.
  fn mount_point_of(path: &Path) -> Vec<u8> {
    crate::resolve(path)
      .unwrap()
      .mount_point()
      .as_os_str()
      .as_bytes()
      .to_vec()
  }

  /// `lstat` of a whole name on this host: the road the walk replaced.
  fn lstat_here(name: &[u8]) -> Option<Node> {
    rustix::fs::lstat(Path::new(OsStr::from_bytes(name)))
      .ok()
      .map(|stat| Node::of(&stat))
  }

  /// **On this host, a directory swapped for a link after the path was
  /// canonicalized is refused by name, and the path as it was is placed.** A
  /// file beneath directories of this law's own is placed beneath its mount
  /// point at its own spelling; then its directory `a` is swapped for a link
  /// to a directory of the same shape, and the walk refuses it. The planted
  /// defect, side by side: `lstat` of each whole name followed the link and
  /// still found the mount's root above it.
  #[test]
  fn test_a_directory_swapped_for_a_link_on_this_host_is_refused_by_name() {
    let (_dir, base) = owned();
    let path = lay_out(&base);
    let canonical = path.as_os_str().as_bytes();
    let mount_point = mount_point_of(&path);
    let dirs = &mut Held::new(|_| false);
    let at = split(dirs, canonical, &mount_point, |_| Ok(true), None, FIRMLINKS).unwrap();
    assert!(
      canonical[at..].ends_with(b"/a/b/c"),
      "{:?}",
      &canonical[at..]
    );

    swap(&base);
    let refused = split(dirs, canonical, &mount_point, |_| Ok(true), None, FIRMLINKS).unwrap_err();
    assert!(says(&refused, "symbolic link"), "{refused}");
    assert_eq!(
      before(canonical, &mount_point, None, FIRMLINKS, lstat_here),
      Some(at),
      "the old walk followed the link and placed the path"
    );
  }

  /// **On this host, a path is placed only as the file its observation
  /// holds.** A descriptor held on `base/a/b/c` names its file; once another
  /// file is renamed over that name, the path is refused. The planted
  /// defect, side by side: the old road stood the held file in for the
  /// path's own and placed it.
  #[test]
  fn test_a_path_that_names_another_file_on_this_host_is_refused() {
    let (_dir, base) = owned();
    let path = lay_out(&base);
    let canonical = path.as_os_str().as_bytes();
    let mount_point = mount_point_of(&path);
    let held = std::fs::File::open(&path).unwrap();
    let observed = Node::of(&rustix::fs::fstat(&held).unwrap());
    let dirs = &mut Held::new(|_| false);
    let at = split(
      dirs,
      canonical,
      &mount_point,
      |_| Ok(true),
      Some(observed),
      FIRMLINKS,
    )
    .unwrap();

    std::fs::write(base.join("a/b/next"), b"another").unwrap();
    std::fs::rename(base.join("a/b/next"), &path).unwrap();
    let refused = split(
      dirs,
      canonical,
      &mount_point,
      |_| Ok(true),
      Some(observed),
      FIRMLINKS,
    )
    .unwrap_err();
    assert!(says(&refused, "another file"), "{refused}");
    assert_eq!(
      before(
        canonical,
        &mount_point,
        Some(observed),
        FIRMLINKS,
        lstat_here
      ),
      Some(at),
      "the old road placed the path by the held file"
    );
  }

  /// **On this host, a firmlinked path is placed through its firmlink, and a
  /// link swapped in beneath it is refused.** A file beneath `/private/tmp`,
  /// spelled through the `/private` firmlink, splits after its root beneath
  /// the data volume's mount point; then its directory `a` is swapped for a
  /// link, and the walk refuses it. The planted defect, side by side: the
  /// old comparison followed the link on both sides and placed the path.
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
  ))]
  #[test]
  fn test_a_firmlinked_path_on_this_host_is_placed_and_a_swapped_link_refused() {
    let dir = tempfile::Builder::new().tempdir_in("/private/tmp").unwrap();
    let base = dir.path().canonicalize().unwrap();
    let path = lay_out(&base);
    let canonical = path.as_os_str().as_bytes();
    let mount_point = mount_point_of(&path);
    if mount_point != b"/System/Volumes/Data" {
      // A system without the split system volume: nothing to prove here.
      return;
    }
    let dirs = &mut Held::new(|_| false);
    assert_eq!(
      split(dirs, canonical, &mount_point, |_| Ok(true), None, true).unwrap(),
      1
    );

    swap(&base);
    let refused = split(dirs, canonical, &mount_point, |_| Ok(true), None, true).unwrap_err();
    assert!(says(&refused, "symbolic link"), "{refused}");
    assert_eq!(
      before(canonical, &mount_point, None, true, lstat_here),
      Some(1),
      "the old comparison followed the link on both sides"
    );
  }
}
