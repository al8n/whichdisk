use std::{
  cell::RefCell,
  collections::HashMap,
  ffi::OsStr,
  os::unix::ffi::OsStrExt,
  path::{Path, PathBuf},
};

use rustix::fs::{stat, statfs};

use super::SmallBytes;

struct CacheEntry {
  mount_point: SmallBytes,
  device: SmallBytes,
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

#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> std::io::Result<Inner> {
  let canonical = path.canonicalize()?;
  let st = stat(&canonical).map_err(std::io::Error::from)?;
  let dev = st.st_dev as u64;

  // Try thread-local cache first — avoids the statfs syscall on repeated lookups
  // for paths on the same device.
  let cached = CACHE.with(|c| {
    c.borrow()
      .get(&dev)
      .map(|e| (e.mount_point.clone(), e.device.clone()))
  });

  let (mount_point, device, total_bytes, available_bytes) = if let Some((mp, dv)) = cached {
    // Re-query statfs for fresh size info (sizes change, mount/device don't).
    let fs = statfs(&canonical).map_err(std::io::Error::from)?;
    let bsize = fs.f_bsize as u64;
    (
      mp,
      dv,
      fs.f_blocks as u64 * bsize,
      fs.f_bavail as u64 * bsize,
    )
  } else {
    let fs = statfs(&canonical).map_err(std::io::Error::from)?;
    let mp = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntonname));
    let dv = SmallBytes::from_bytes(c_chars_as_bytes(&fs.f_mntfromname));
    let bsize = fs.f_bsize as u64;
    let total = fs.f_blocks as u64 * bsize;
    let avail = fs.f_bavail as u64 * bsize;
    CACHE.with(|c| {
      c.borrow_mut().insert(
        dev,
        CacheEntry {
          mount_point: mp.clone(),
          device: dv.clone(),
        },
      );
    });
    (mp, dv, total, avail)
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

  let is_ejectable = is_ejectable(mount_point.as_path(), device.as_os_str());

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      is_ejectable,
      total_bytes,
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
    if !get_bool_resource(&url, unsafe { NSURLVolumeIsBrowsableKey }) {
      continue;
    }
    if !get_bool_resource(&url, unsafe { NSURLVolumeIsLocalKey }) {
      continue;
    }

    let ejectable = get_bool_resource(&url, unsafe { NSURLVolumeIsEjectableKey });
    let removable = get_bool_resource(&url, unsafe { NSURLVolumeIsRemovableKey });
    let is_ejectable = ejectable || removable;

    if opts.is_ejectable_only() && !is_ejectable {
      continue;
    }
    if opts.is_non_ejectable_only() && is_ejectable {
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
      let bsize = fs.f_bsize as u64;
      let total_bytes = fs.f_blocks as u64 * bsize;
      let available_bytes = fs.f_bavail as u64 * bsize;

      mounts.push(super::MountPoint {
        mount_point,
        device,
        is_ejectable,
        total_bytes,
        available_bytes,
      });
    }
  }
  Ok(mounts)
}

/// Apple platforms: query NSURLVolumeIsEjectableKey / NSURLVolumeIsRemovableKey.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
pub(super) fn is_ejectable(mount_point: &Path, _device: &OsStr) -> bool {
  use objc2_foundation::{NSURL, NSURLVolumeIsEjectableKey, NSURLVolumeIsRemovableKey};

  let url = NSURL::fileURLWithPath(&objc2_foundation::NSString::from_str(
    &mount_point.to_string_lossy(),
  ));
  let ejectable = get_bool_resource(&url, unsafe { NSURLVolumeIsEjectableKey });
  let removable = get_bool_resource(&url, unsafe { NSURLVolumeIsRemovableKey });
  ejectable || removable
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
) -> bool {
  use objc2_foundation::NSNumber;
  let val = url.resourceValuesForKeys_error(&objc2_foundation::NSArray::from_slice(&[key]));
  match val {
    Ok(dict) => {
      let obj = dict.objectForKey(key);
      match obj {
        Some(obj) => {
          let num: &NSNumber = unsafe { &*(&*obj as *const _ as *const NSNumber) };
          num.boolValue()
        }
        None => false,
      }
    }
    Err(_) => false,
  }
}

/// FreeBSD, OpenBSD, DragonFlyBSD: use getmntinfo, skip virtual filesystems.
#[cfg(feature = "list")]
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
pub(super) fn list(opts: super::ListOptions) -> std::io::Result<Vec<super::MountPoint>> {
  const MNT_NOWAIT: core::ffi::c_int = 2;

  let mut mntbuf: *mut libc::statfs = core::ptr::null_mut();
  let count = unsafe { libc::getmntinfo(&mut mntbuf, MNT_NOWAIT) };
  if count <= 0 || mntbuf.is_null() {
    return Err(std::io::Error::last_os_error());
  }

  let entries = unsafe { core::slice::from_raw_parts(mntbuf, count as usize) };
  let mut mounts = Vec::new();
  for entry in entries {
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
    let is_ejectable = is_removable_bsd(fs_type, device_bytes);
    if opts.is_ejectable_only() && !is_ejectable {
      continue;
    }
    if opts.is_non_ejectable_only() && is_ejectable {
      continue;
    }
    let mount_point = SmallBytes::from_bytes(mp_bytes);
    let device = SmallBytes::from_bytes(device_bytes);
    let bsize = entry.f_bsize as u64;
    let total_bytes = entry.f_blocks as u64 * bsize;
    let available_bytes = entry.f_bavail as u64 * bsize;
    mounts.push(super::MountPoint {
      mount_point,
      device,
      is_ejectable,
      total_bytes,
      available_bytes,
    });
  }
  Ok(mounts)
}

/// FreeBSD, OpenBSD, DragonFlyBSD: check filesystem type and device path.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
pub(super) fn is_ejectable(mount_point: &Path, _device: &OsStr) -> bool {
  match statfs(mount_point) {
    Ok(fs) => {
      let fs_type = c_chars_as_bytes(&fs.f_fstypename);
      let device = c_chars_as_bytes(&fs.f_mntfromname);
      is_removable_bsd(fs_type, device)
    }
    Err(_) => false,
  }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn is_removable_bsd(_fs_type: &[u8], device: &[u8]) -> bool {
  // da* = USB mass storage (SCSI disk), cd* = optical drives
  device.starts_with(b"/dev/da") || device.starts_with(b"/dev/cd")
}

#[cfg_attr(not(tarpaulin), inline(always))]
fn c_chars_as_bytes(chars: &[core::ffi::c_char]) -> &[u8] {
  // SAFETY: c_char and u8 have the same size and alignment.
  let bytes: &[u8] =
    unsafe { &*(core::ptr::from_ref::<[core::ffi::c_char]>(chars) as *const [u8]) };
  let len = super::find_byte(0, bytes).unwrap_or(bytes.len());
  &bytes[..len]
}
