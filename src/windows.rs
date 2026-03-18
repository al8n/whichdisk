use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{
  GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
};

use super::SmallBytes;

struct CacheEntry {
  device: SmallBytes,
}

thread_local! {
  // Cache keyed by mount point (e.g. `C:\`). There are very few distinct
  // mount points on a typical Windows system, so HashMap overhead is minimal.
  static CACHE: RefCell<HashMap<SmallBytes, CacheEntry>> = RefCell::new(HashMap::new());
}

pub(crate) struct Inner {
  mount_point: SmallBytes,
  device: SmallBytes,
  relative_path: PathBuf,
}

impl Inner {
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn mount_point(&self) -> &Path {
    self.mount_point.as_path()
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn device(&self) -> &OsStr {
    self.device.as_os_str()
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn relative_path(&self) -> &Path {
    &self.relative_path
  }
}

pub(crate) fn which_disk(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;

  // GetVolumePathNameW returns the mount point for the volume (e.g. `C:\`).
  let mount_point_path = get_volume_path_name(&canonical)?;
  let mount_point_str = mount_point_path
    .to_str()
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mount point is not valid UTF-8"))?;
  let mount_point = SmallBytes::from_bytes(mount_point_str.as_bytes());

  // Try thread-local cache — avoids GetVolumeNameForVolumeMountPointW on
  // repeated lookups for paths on the same volume.
  let cached = CACHE.with(|c| c.borrow().get(&mount_point).map(|e| e.device.clone()));

  let device = if let Some(hit) = cached {
    hit
  } else {
    // GetVolumeNameForVolumeMountPointW returns the volume GUID path
    // (e.g. `\\?\Volume{GUID}\`). For network/UNC paths this will fail,
    // so fall back to using the mount point itself as the device identifier.
    let dv = match get_volume_name(&mount_point_path) {
      Ok(name) => SmallBytes::from_bytes(name.as_bytes()),
      Err(_) => mount_point.clone(),
    };
    CACHE.with(|c| {
      c.borrow_mut()
        .insert(mount_point.clone(), CacheEntry { device: dv.clone() });
    });
    dv
  };

  // strip_prefix handles Windows path semantics (case, separators) correctly.
  let relative_path = canonical
    .strip_prefix(&mount_point_path)
    .map(|p| p.to_path_buf())
    .unwrap_or_default();

  Ok(Inner {
    mount_point,
    device,
    relative_path,
  })
}

/// Calls `GetVolumePathNameW` to get the mount point for a path.
fn get_volume_path_name(path: &Path) -> io::Result<PathBuf> {
  let wide = to_wide(path);
  // MAX_PATH (260) covers all local mount points; extended-length paths
  // with `\\?\` prefix are also handled within this size.
  let mut buf = [0u16; 260];
  let ret = unsafe { GetVolumePathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
  if ret == 0 {
    return Err(io::Error::last_os_error());
  }
  let len = wide_strlen(&buf);
  Ok(PathBuf::from(OsString::from_wide(&buf[..len])))
}

/// Calls `GetVolumeNameForVolumeMountPointW` to get the volume GUID path
/// (e.g. `\\?\Volume{GUID}\`).
fn get_volume_name(mount_point: &Path) -> io::Result<String> {
  let wide = to_wide(mount_point);
  // Volume GUID paths are at most 49 characters (`\\?\Volume{GUID}\`).
  let mut buf = [0u16; 50];
  let ret =
    unsafe { GetVolumeNameForVolumeMountPointW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
  if ret == 0 {
    return Err(io::Error::last_os_error());
  }
  let len = wide_strlen(&buf);
  String::from_utf16(&buf[..len]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Encodes an OS path to a null-terminated UTF-16 wide string for Windows API calls.
#[cfg_attr(not(tarpaulin), inline(always))]
fn to_wide(path: &Path) -> Vec<u16> {
  path
    .as_os_str()
    .encode_wide()
    .chain(core::iter::once(0))
    .collect()
}

/// Finds the length of a null-terminated UTF-16 string in a buffer.
#[cfg_attr(not(tarpaulin), inline(always))]
fn wide_strlen(buf: &[u16]) -> usize {
  buf.iter().position(|&c| c == 0).unwrap_or(buf.len())
}
