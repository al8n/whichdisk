use std::{
  cell::RefCell,
  collections::HashMap,
  ffi::{OsStr, OsString},
  io,
  os::windows::ffi::{OsStrExt, OsStringExt},
  path::{Path, PathBuf},
};

use windows_sys::Win32::Storage::FileSystem::{
  FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetDiskFreeSpaceExW, GetDriveTypeW,
  GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, GetVolumePathNamesForVolumeNameW,
};

const DRIVE_REMOVABLE: u32 = 2;

use super::SmallBytes;

struct CacheEntry {
  device: SmallBytes,
}

thread_local! {
  // Cache keyed by mount point (e.g. `C:\`). There are very few distinct
  // mount points on a typical Windows system, so HashMap overhead is minimal.
  static CACHE: RefCell<HashMap<SmallBytes, CacheEntry>> = RefCell::new(HashMap::new());
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Inner {
  mount: super::MountPoint,
  canonical: PathBuf,
  relative_path: PathBuf,
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
    &self.relative_path
  }
}

pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
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

  let ejectable = is_ejectable(mount_point_path.as_path(), device.as_os_str());
  let (total_bytes, available_bytes) = get_disk_space(&mount_point_path);

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      is_ejectable: ejectable,
      total_bytes,
      available_bytes,
    },
    canonical,
    relative_path,
  })
}

#[cfg(feature = "list")]
const DRIVE_FIXED: u32 = 3;

#[cfg(feature = "list")]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  let mut mounts = Vec::new();

  for volume_guid in get_volume_guid_paths() {
    let drive_type = unsafe { GetDriveTypeW(volume_guid.as_ptr()) };
    if drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE {
      continue;
    }
    let is_ejectable = drive_type == DRIVE_REMOVABLE;
    if opts.is_ejectable_only() && !is_ejectable {
      continue;
    }
    if opts.is_non_ejectable_only() && is_ejectable {
      continue;
    }

    let device_str = String::from_utf16_lossy(wide_to_slice(&volume_guid));
    let device = SmallBytes::from_bytes(device_str.as_bytes());

    for mount_path in get_volume_mount_paths(&volume_guid)? {
      let mount_str = String::from_utf16_lossy(wide_to_slice(&mount_path));
      let mount_point = SmallBytes::from_bytes(mount_str.as_bytes());
      let mp_path = Path::new(&mount_str);
      let (total_bytes, available_bytes) = get_disk_space(mp_path);
      mounts.push(super::MountPoint {
        mount_point,
        device: device.clone(),
        is_ejectable,
        total_bytes,
        available_bytes,
      });
    }
  }
  Ok(mounts)
}

pub(super) fn is_ejectable(mount_point: &Path, _device: &OsStr) -> bool {
  // Get the volume GUID path for this mount point, then check drive type on it.
  let mp_path = match get_volume_name(mount_point) {
    Ok(name) => name,
    Err(_) => return false,
  };
  let wide: Vec<u16> = mp_path.encode_utf16().chain(core::iter::once(0)).collect();
  let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
  drive_type == DRIVE_REMOVABLE
}

/// Enumerates all volume GUID paths using `FindFirstVolumeW` / `FindNextVolumeW`.
/// Returns paths like `\\?\Volume{GUID}\` as null-terminated wide strings.
#[cfg(feature = "list")]
fn get_volume_guid_paths() -> Vec<Vec<u16>> {
  let mut volumes = Vec::new();
  let mut buf = [0u16; 50]; // Volume GUID paths are ~49 chars

  let handle = unsafe { FindFirstVolumeW(buf.as_mut_ptr(), buf.len() as u32) };
  if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
    return volumes;
  }

  volumes.push(wide_to_vec(&buf));
  loop {
    buf.fill(0);
    let ret = unsafe { FindNextVolumeW(handle, buf.as_mut_ptr(), buf.len() as u32) };
    if ret == 0 {
      break;
    }
    volumes.push(wide_to_vec(&buf));
  }
  unsafe { FindVolumeClose(handle) };
  volumes
}

/// Gets all mount paths (drive letters, directory mounts) for a volume GUID path.
#[cfg(feature = "list")]
fn get_volume_mount_paths(volume_guid: &[u16]) -> io::Result<Vec<Vec<u16>>> {
  let mut buf = vec![0u16; 260];
  let mut required_len: u32 = 0;

  loop {
    let ret = unsafe {
      GetVolumePathNamesForVolumeNameW(
        volume_guid.as_ptr(),
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut required_len,
      )
    };
    if ret != 0 {
      break;
    }
    // Buffer too small — resize and retry.
    if required_len as usize > buf.len() {
      buf.resize(required_len as usize, 0);
      continue;
    }
    return Err(io::Error::last_os_error());
  }

  // Parse multi-string: null-separated, double-null terminated.
  let mut paths = Vec::new();
  let mut rest = &buf[..];
  while !rest.is_empty() && rest[0] != 0 {
    let len = wide_strlen(rest);
    paths.push(rest[..len + 1].to_vec()); // include null terminator
    rest = &rest[len + 1..];
  }
  Ok(paths)
}

/// Extracts a slice up to (not including) the null terminator from a wide buffer.
#[cfg(feature = "list")]
#[cfg_attr(not(tarpaulin), inline(always))]
fn wide_to_slice(buf: &[u16]) -> &[u16] {
  let len = wide_strlen(buf);
  &buf[..len]
}

/// Copies a null-terminated wide string from a buffer into a Vec (including terminator).
#[cfg(feature = "list")]
#[cfg_attr(not(tarpaulin), inline(always))]
fn wide_to_vec(buf: &[u16]) -> Vec<u16> {
  let len = wide_strlen(buf);
  buf[..len + 1].to_vec()
}

/// Calls `GetVolumePathNameW` to get the mount point for a path.
///
/// Starts with 1024 wide chars on the stack, then retries with doubling heap
/// buffers up to 32 768 wide chars if the buffer is too small.
fn get_volume_path_name(path: &Path) -> io::Result<PathBuf> {
  let wide = to_wide(path);

  let mut stack_buf = [0u16; 1024];
  let mut heap_buf: Vec<u16>;
  let mut buf: &mut [u16] = &mut stack_buf;

  loop {
    let ret = unsafe { GetVolumePathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if ret != 0 {
      let len = wide_strlen(buf);
      return Ok(PathBuf::from(OsString::from_wide(&buf[..len])));
    }
    let err = io::Error::last_os_error();
    let next_size = buf.len() * 2;
    if next_size > 32768 {
      return Err(err);
    }
    heap_buf = vec![0u16; next_size];
    buf = &mut heap_buf;
  }
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

/// Queries total and available bytes for a path using `GetDiskFreeSpaceExW`.
/// Returns `(total_bytes, available_bytes)`, or `(0, 0)` on failure.
fn get_disk_space(path: &Path) -> (u64, u64) {
  let wide = to_wide(path);
  let mut free_available: u64 = 0;
  let mut total: u64 = 0;
  let ret = unsafe {
    GetDiskFreeSpaceExW(
      wide.as_ptr(),
      &mut free_available,
      &mut total,
      core::ptr::null_mut(),
    )
  };
  if ret != 0 {
    (total, free_available)
  } else {
    (0, 0)
  }
}
