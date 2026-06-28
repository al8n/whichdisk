use std::{
  cell::RefCell,
  collections::HashMap,
  ffi::OsStr,
  io,
  os::unix::ffi::OsStrExt,
  path::{Path, PathBuf},
};

use super::{SmallBytes, VolumeCapabilities};

struct CacheEntry {
  mount_point: SmallBytes,
  device: SmallBytes,
  capabilities: VolumeCapabilities,
}

thread_local! {
  static CACHE: RefCell<HashMap<u64, CacheEntry>> = RefCell::new(HashMap::new());
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

/// NetBSD uses `libc::statvfs` (not `statfs`) which has `f_mntonname` and
/// `f_mntfromname`. We call `libc::statvfs` on the canonicalized path to get
/// mount info, similar to the BSD `statfs` approach.
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;

  // Use stat to get st_dev for caching.
  let st = rustix::fs::stat(&canonical).map_err(io::Error::from)?;
  let dev = st.st_dev as u64;

  let cached = CACHE.with(|c| {
    c.borrow().get(&dev).map(|e| {
      (
        e.mount_point.clone(),
        e.device.clone(),
        e.capabilities.clone(),
      )
    })
  });

  #[cfg(not(feature = "disk-usage"))]
  let (mount_point, device, capabilities) = if let Some(hit) = cached {
    hit
  } else {
    let mut vfs: libc::statvfs = unsafe { core::mem::zeroed() };
    let c_path = std::ffi::CString::new(canonical.as_os_str().as_bytes())
      .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } != 0 {
      return Err(io::Error::last_os_error());
    }

    let mp = SmallBytes::from_bytes(c_chars_as_bytes(&vfs.f_mntonname));
    let dv = SmallBytes::from_bytes(c_chars_as_bytes(&vfs.f_mntfromname));
    let caps = volume_capabilities(c_chars_as_bytes(&vfs.f_fstypename));
    CACHE.with(|c| {
      c.borrow_mut().insert(
        dev,
        CacheEntry {
          mount_point: mp.clone(),
          device: dv.clone(),
          capabilities: caps.clone(),
        },
      );
    });
    (mp, dv, caps)
  };

  #[cfg(feature = "disk-usage")]
  let (mount_point, device, capabilities, total_bytes, available_bytes) =
    if let Some((mp, dv, caps)) = cached {
      // Re-query statvfs for fresh size info (sizes change, mount/device don't).
      let c_path = std::ffi::CString::new(canonical.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
      let mut vfs: libc::statvfs = unsafe { core::mem::zeroed() };
      if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } != 0 {
        (mp, dv, caps, 0, 0)
      } else {
        let frsize = if vfs.f_frsize != 0 {
          vfs.f_frsize as u64
        } else {
          vfs.f_bsize as u64
        };
        (
          mp,
          dv,
          caps,
          (vfs.f_blocks as u64).saturating_mul(frsize),
          (vfs.f_bavail as u64).saturating_mul(frsize),
        )
      }
    } else {
      let mut vfs: libc::statvfs = unsafe { core::mem::zeroed() };
      let c_path = std::ffi::CString::new(canonical.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
      if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } != 0 {
        return Err(io::Error::last_os_error());
      }

      let mp = SmallBytes::from_bytes(c_chars_as_bytes(&vfs.f_mntonname));
      let dv = SmallBytes::from_bytes(c_chars_as_bytes(&vfs.f_mntfromname));
      let caps = volume_capabilities(c_chars_as_bytes(&vfs.f_fstypename));
      let frsize = if vfs.f_frsize != 0 {
        vfs.f_frsize as u64
      } else {
        vfs.f_bsize as u64
      };
      let total = (vfs.f_blocks as u64).saturating_mul(frsize);
      let avail = (vfs.f_bavail as u64).saturating_mul(frsize);
      CACHE.with(|c| {
        c.borrow_mut().insert(
          dev,
          CacheEntry {
            mount_point: mp.clone(),
            device: dv.clone(),
            capabilities: caps.clone(),
          },
        );
      });
      (mp, dv, caps, total, avail)
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
    canonical_bytes.len()
  };

  let ejectable = is_ejectable(mount_point.as_path(), device.as_os_str());

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      is_ejectable: ejectable,
      capabilities,
      #[cfg(feature = "disk-usage")]
      total_bytes,
      #[cfg(feature = "disk-usage")]
      available_bytes,
    },
    canonical,
    relative_offset,
  })
}

/// Virtual filesystem types to exclude on NetBSD.
#[cfg(feature = "list")]
const IGNORED_FS_TYPES: &[&[u8]] = &[
  b"autofs",
  b"devfs",
  b"linprocfs",
  b"procfs",
  b"fdescfs",
  b"tmpfs",
  b"linsysfs",
  b"kernfs",
  b"ptyfs",
];

/// Lists all real (non-virtual) mounted volumes. We call `getvfsstat` directly
/// rather than the `getmntinfo` wrapper: on NetBSD the libc `getmntinfo` binding
/// hands back entries with empty `f_mntonname`/`f_mntfromname`, whereas the same
/// `struct statvfs` is populated correctly by `getvfsstat` (and by `statvfs` in
/// `resolve`). Virtual filesystems are excluded by type, like the BSD path.
#[cfg(feature = "list")]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  // ST_WAIT (1) requests fresh statistics; a null buffer returns the count.
  const ST_WAIT: core::ffi::c_int = 1;
  let count = unsafe { libc::getvfsstat(core::ptr::null_mut(), 0, ST_WAIT) };
  if count < 0 {
    return Err(io::Error::last_os_error());
  }

  let mut buf: Vec<libc::statvfs> = Vec::with_capacity(count as usize);
  let bufsize =
    (count as usize).saturating_mul(core::mem::size_of::<libc::statvfs>()) as libc::size_t;
  let n = unsafe { libc::getvfsstat(buf.as_mut_ptr(), bufsize, ST_WAIT) };
  if n < 0 {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: getvfsstat wrote `n` (<= count = capacity) fully-initialized entries.
  unsafe { buf.set_len(n as usize) };

  let mut mounts = Vec::new();
  for entry in &buf {
    if entry.f_mntfromname[0] == 0 || entry.f_mntonname[0] == 0 {
      continue;
    }

    let fs_type = c_chars_as_bytes(&entry.f_fstypename);
    // Skip virtual/pseudo filesystems.
    if IGNORED_FS_TYPES.iter().any(|t| *t == fs_type) {
      continue;
    }
    let mp_bytes = c_chars_as_bytes(&entry.f_mntonname);
    // Skip EFI boot partition.
    if mp_bytes == b"/boot/efi" {
      continue;
    }

    let device_bytes = c_chars_as_bytes(&entry.f_mntfromname);
    let is_ejectable = is_removable_netbsd(fs_type, device_bytes);
    if opts.is_ejectable_only() && !is_ejectable {
      continue;
    }
    if opts.is_non_ejectable_only() && is_ejectable {
      continue;
    }

    let mount_point = SmallBytes::from_bytes(mp_bytes);
    let device = SmallBytes::from_bytes(device_bytes);
    let capabilities = volume_capabilities(fs_type);
    #[cfg(feature = "disk-usage")]
    let (total_bytes, available_bytes) = {
      let frsize = if entry.f_frsize != 0 {
        entry.f_frsize as u64
      } else {
        entry.f_bsize as u64
      };
      (
        (entry.f_blocks as u64).saturating_mul(frsize),
        (entry.f_bavail as u64).saturating_mul(frsize),
      )
    };
    mounts.push(super::MountPoint {
      mount_point,
      device,
      is_ejectable,
      capabilities,
      #[cfg(feature = "disk-usage")]
      total_bytes,
      #[cfg(feature = "disk-usage")]
      available_bytes,
    });
  }
  Ok(mounts)
}

/// Checks if a volume is ejectable by calling `statvfs` on the mount point
/// and checking filesystem type / device path.
pub(super) fn is_ejectable(mount_point: &Path, _device: &OsStr) -> bool {
  let c_path = match std::ffi::CString::new(mount_point.as_os_str().as_bytes()) {
    Ok(p) => p,
    Err(_) => return false,
  };

  let mut vfs: libc::statvfs = unsafe { core::mem::zeroed() };
  if unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) } != 0 {
    return false;
  }

  let fs_type = c_chars_as_bytes(&vfs.f_fstypename);
  let device = c_chars_as_bytes(&vfs.f_mntfromname);
  is_removable_netbsd(fs_type, device)
}

/// Heuristic for removable media on NetBSD:
/// sd* = USB mass storage (SCSI disk), cd* = optical drives.
fn is_removable_netbsd(_fs_type: &[u8], device: &[u8]) -> bool {
  device.starts_with(b"/dev/sd") || device.starts_with(b"/dev/cd")
}

/// NetBSD: derive case semantics from the filesystem type — `Some(...)` only for
/// types that determine it (FFS/UFS are case-sensitive, msdosfs is
/// case-insensitive) and `None` otherwise (ZFS case sensitivity is a per-dataset
/// property). There is no portable per-volume query. `fs_type` comes from
/// `statvfs` (`f_fstypename`).
fn volume_capabilities(fs_type: &[u8]) -> VolumeCapabilities {
  VolumeCapabilities::from_fs_type_defaults(fs_type)
}

#[cfg_attr(not(tarpaulin), inline(always))]
fn c_chars_as_bytes(chars: &[core::ffi::c_char]) -> &[u8] {
  // SAFETY: c_char and u8 have the same size and alignment.
  let bytes: &[u8] =
    unsafe { &*(core::ptr::from_ref::<[core::ffi::c_char]>(chars) as *const [u8]) };
  let len = super::find_byte(0, bytes).unwrap_or(bytes.len());
  &bytes[..len]
}
