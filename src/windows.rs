use std::{
  ffi::{OsStr, OsString},
  io,
  os::windows::{
    ffi::{OsStrExt, OsStringExt},
    io::AsRawHandle,
  },
  path::{Path, PathBuf},
};

use windows_sys::Win32::System::{
  IO::DeviceIoControl,
  Ioctl::{FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER},
};

#[cfg(feature = "disk-usage")]
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows_sys::Win32::Storage::FileSystem::{
  FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, GetVolumeInformationW,
  GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
};
#[cfg(feature = "list")]
use windows_sys::Win32::Storage::FileSystem::{
  FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumePathNamesForVolumeNameW,
};

const DRIVE_REMOVABLE: u32 = 2;

// `FILE_CASE_PRESERVED_NAMES` from `GetVolumeInformationW`'s
// `lpFileSystemFlags`. Defined locally to avoid pulling in the
// `Win32_System_SystemServices` feature for one stable constant.
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;

use super::{IdentityReading, SmallBytes, VolumeCapabilities};

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

#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  resolve_with(path, volume_info)
}

/// The body of [`resolve`], with the volume query as a parameter.
///
/// Nothing here is cached, so what a resolve reports is whatever the volume
/// answered on this call — and that is a claim a test has to be able to break.
/// No test can rewrite a real volume's serial (the tools that do it work
/// offline, on an unmounted volume), so the query is passed in and a test
/// stands a changing volume in for a real one. See
/// `test_the_identity_is_read_on_every_resolve`.
fn resolve_with(
  path: &Path,
  probe: impl Fn(Option<&str>, &Path) -> (VolumeCapabilities, Option<IdentityReading>),
) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;

  // GetVolumePathNameW returns the mount point for the volume (e.g. `C:\`).
  let mount_point_path = get_volume_path_name(&canonical)?;
  let mount_point_str = mount_point_path
    .to_str()
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mount point is not valid UTF-8"))?;
  let mount_point = SmallBytes::from_bytes(mount_point_str.as_bytes());

  // GetVolumeNameForVolumeMountPointW returns the volume GUID path
  // (e.g. `\\?\Volume{GUID}\`). For network/UNC paths this will fail,
  // so fall back to using the mount point itself as the device identifier.
  // Asked on every resolve because it is also what the query below is
  // addressed to: a drive letter is a slot whose occupant can change between
  // two calls, and the GUID path names one volume for its whole life.
  let volume_guid = get_volume_name(&mount_point_path).ok();
  let device = match volume_guid.as_deref() {
    Some(name) => SmallBytes::from_bytes(name.as_bytes()),
    None => mount_point.clone(),
  };

  // Asked on every resolve, and never remembered — the same law Apple and
  // Linux follow, reached here for a reason of its own. The volume GUID names
  // *storage*, which is durable; the serial this reads is a value in the
  // filesystem written onto that storage, and an offline tool can rewrite it
  // while the GUID stays put. A key that outlives what it is supposed to vouch
  // for cannot vouch for it, so nothing is stored under it.
  //
  // There is nothing else left for an entry to hold either: one
  // `GetVolumeInformationW` yields the capabilities and the serial together, so
  // once the serial is read every time, a cache of the capabilities would save
  // no call at all. See [`Witness`](super::Witness).
  let (capabilities, volume_identity) = probe(volume_guid.as_deref(), &mount_point_path);

  // strip_prefix handles Windows path semantics (case, separators) correctly.
  let relative_path = canonical
    .strip_prefix(&mount_point_path)
    .map(|p| p.to_path_buf())
    .unwrap_or_default();

  let ejectable = is_ejectable(mount_point_path.as_path(), device.as_os_str());
  #[cfg(feature = "disk-usage")]
  let (total_bytes, available_bytes) = get_disk_space(&mount_point_path);

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      is_ejectable: ejectable,
      capabilities,
      volume_identity,
      #[cfg(feature = "disk-usage")]
      total_bytes,
      #[cfg(feature = "disk-usage")]
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
      let (capabilities, identity) = volume_info(Some(&device_str), Path::new(&mount_str));
      #[cfg(feature = "disk-usage")]
      let (total_bytes, available_bytes) = get_disk_space(Path::new(&mount_str));
      mounts.push(super::MountPoint {
        mount_point,
        device: device.clone(),
        is_ejectable,
        capabilities,
        volume_identity: identity,
        #[cfg(feature = "disk-usage")]
        total_bytes,
        #[cfg(feature = "disk-usage")]
        available_bytes,
      });
    }
  }
  Ok(mounts)
}

pub(super) fn is_ejectable(mount_point: &Path, device: &OsStr) -> bool {
  // The drive type is a property of the volume, so it is read off the volume
  // GUID path. The caller normally holds that path already as the device, and
  // asking the mount manager for the same value a second time buys nothing.
  if let Some(volume) = device
    .to_str()
    .filter(|name| name.starts_with(r"\\?\Volume{"))
  {
    return is_removable_volume(volume);
  }
  match get_volume_name(mount_point) {
    Ok(volume) => is_removable_volume(&volume),
    Err(_) => false,
  }
}

/// Whether the volume named by a `\\?\Volume{GUID}\` path is removable media.
fn is_removable_volume(volume: &str) -> bool {
  let wide: Vec<u16> = volume.encode_utf16().chain(core::iter::once(0)).collect();
  // SAFETY: `wide` is a null-terminated wide string that outlives the call.
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

/// Queries the case-handling capabilities, filesystem name and volume serial
/// number for a volume — everything one `GetVolumeInformationW` call yields.
///
/// It is asked of the **volume GUID path** wherever the volume has one, and of
/// `mount_root` (e.g. `C:\`) only when it has not. A drive letter is a slot
/// whose occupant can change between two calls, so a query addressed to one can
/// answer about the volume that has just replaced the volume the caller named;
/// the GUID path names one volume for its whole life, which binds this answer to
/// the key it will be stored under. Both forms are what `GetVolumeInformationW`
/// asks for — a root path ending in a backslash.
///
/// `case_sensitive` is derived from the filesystem type: NTFS, ReFS, FAT and
/// exFAT look up names case-**insensitively** by default (`FILE_CASE_SENSITIVE_SEARCH`
/// only advertises that case-sensitive names are *supported*, not that lookups
/// use them), so it is `Some(false)` for those and `None` for an unrecognized
/// type. `case_preserving` comes from `FILE_CASE_PRESERVED_NAMES`, which does
/// report actual name preservation. On failure (e.g. an unavailable network
/// share) the fs type is empty, both flags are `None`, and so is the identity.
///
/// The identity is the volume serial Windows stamps into the filesystem at
/// format time. `GetVolumeInformationW` reports 32 bits of it whatever the
/// filesystem, which for NTFS is the low half of a 64-bit number — so on NTFS
/// this asks [`ntfs_volume_serial`] for the full width first, and falls back to
/// the narrow half only where that cannot be read (without a GUID path there is
/// no device to open, so it always does). A serial of zero is what a volume with
/// nothing to report gives back (an unavailable share, some network
/// redirectors), so it is reported as no identity rather than as the number
/// zero.
///
/// Both readings are [`Vouched`](super::IdentityAssurance::Vouched): the volume
/// mounted at that GUID path answered for itself, on this call. A
/// `GetVolumeInformationW` that failed reports no identity for this call only —
/// there is nowhere for that moment to be recorded, so the next resolve asks
/// again.
fn volume_info(
  volume_guid: Option<&str>,
  mount_root: &Path,
) -> (VolumeCapabilities, Option<IdentityReading>) {
  let queried = volume_guid.map_or(mount_root, Path::new);
  let wide = to_wide(queried);
  let mut serial: u32 = 0;
  let mut fs_flags: u32 = 0;
  // Filesystem names ("NTFS", "exFAT", …) are short; MAX_PATH + 1 is ample.
  let mut fs_name = [0u16; 261];

  let ret = unsafe {
    GetVolumeInformationW(
      wide.as_ptr(),
      core::ptr::null_mut(),
      0,
      &mut serial,
      core::ptr::null_mut(),
      &mut fs_flags,
      fs_name.as_mut_ptr(),
      fs_name.len() as u32,
    )
  };
  if ret == 0 {
    // Not "this volume has no identity" — "this volume could not be asked".
    // Nothing keeps that answer, so the next resolve asks again.
    return (VolumeCapabilities::from_fs_type_defaults(b""), None);
  }

  // `case_sensitive` follows the filesystem-type default; `case_preserving`
  // comes from the accurate `FILE_CASE_PRESERVED_NAMES` flag, overriding the
  // type-derived value.
  let fs_type = String::from_utf16_lossy(&fs_name[..wide_strlen(&fs_name)]);
  let mut caps = VolumeCapabilities::from_fs_type_defaults(fs_type.as_bytes());
  caps.case_preserving = Some(fs_flags & FILE_CASE_PRESERVED_NAMES != 0);

  let ntfs_serial = if fs_type.eq_ignore_ascii_case("NTFS") {
    volume_guid.and_then(ntfs_volume_serial)
  } else {
    None
  };
  (
    caps,
    super::windows_identity(fs_type.as_bytes(), serial, ntfs_serial),
  )
}

/// Reads a volume's full 64-bit NTFS serial with `FSCTL_GET_NTFS_VOLUME_DATA`.
///
/// This is the same number Linux publishes under `/dev/disk/by-uuid` as sixteen
/// hex digits; `GetVolumeInformationW` reports only its low half, so without
/// this call the same NTFS disk would answer differently depending on which
/// system asked.
///
/// `volume_guid` is the volume's `\\?\Volume{GUID}\` path — the device to open
/// is that path without its trailing separator, which names the volume whether
/// it is mounted at a drive letter or in a directory. The handle asks for no
/// access rights at all: the control code is declared `FILE_ANY_ACCESS`, so
/// this needs no elevation and never reads a byte of volume data.
///
/// `None` when the volume is not NTFS after all, when the device cannot be
/// opened, or when the control code is not serviced — every one of which leaves
/// the caller with the documented narrower serial rather than a wrong number.
fn ntfs_volume_serial(volume_guid: &str) -> Option<u64> {
  use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};

  let device = volume_guid.strip_suffix('\\')?;
  let volume = OpenOptions::new()
    .access_mode(0)
    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
    .open(device)
    .ok()?;

  let mut data: NTFS_VOLUME_DATA_BUFFER = unsafe { core::mem::zeroed() };
  let mut written: u32 = 0;
  // SAFETY: `data` is a live, correctly sized output buffer for this control
  // code, and the handle is valid for as long as `volume` is alive.
  let ok = unsafe {
    DeviceIoControl(
      volume.as_raw_handle(),
      FSCTL_GET_NTFS_VOLUME_DATA,
      core::ptr::null(),
      0,
      core::ptr::from_mut(&mut data).cast::<core::ffi::c_void>(),
      core::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
      &mut written,
      core::ptr::null_mut(),
    )
  };

  // A short answer means the fields we want were not among the bytes written.
  if ok == 0 || (written as usize) < core::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() {
    return None;
  }
  Some(data.VolumeSerialNumber as u64)
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
#[cfg(feature = "disk-usage")]
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

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use super::{super::VolumeIdentity, *};

  /// The FSCTL needs a volume device path, which is the GUID path without its
  /// trailing separator. Anything else names no device and must not be opened.
  #[test]
  fn test_ntfs_volume_serial_requires_a_volume_root_path() {
    assert_eq!(
      ntfs_volume_serial(r"\\?\Volume{44444444-4444-4444-4444-444444444444}"),
      None
    );
    assert_eq!(ntfs_volume_serial(""), None);
  }

  /// Two resolves of an unchanging volume agree — each of them asked the
  /// volume, and it gave the same answer twice.
  #[test]
  fn test_resolve_is_stable_across_calls() {
    let first = resolve(Path::new("C:\\")).unwrap();
    let second = resolve(Path::new("C:\\")).unwrap();
    assert_eq!(
      first.mount_info().volume_identity(),
      second.mount_info().volume_identity()
    );
    assert_eq!(first.mount_info().device(), second.mount_info().device());
  }

  /// A volume GUID is a durable name for *storage*; the serial is a value in
  /// the filesystem written onto it, and `VolumeID` and its like rewrite that
  /// serial offline while the GUID stays exactly as it was. So the second
  /// resolve of one volume must report what the volume says now, not what it
  /// said the first time — the fixture changes its serial between the two
  /// calls, and the second resolve has to see the change.
  #[test]
  fn test_the_identity_is_read_on_every_resolve() {
    let serial = Cell::new(0x1a2b_3c4du32);
    let probe = |_guid: Option<&str>, _root: &Path| {
      let now = serial.get();
      // The volume's serial is rewritten between the two reads.
      serial.set(0x5566_7788);
      (
        VolumeCapabilities::from_fs_type_defaults(b"NTFS"),
        super::super::windows_identity(b"NTFS", now, None),
      )
    };

    let first = resolve_with(Path::new("C:\\"), probe).unwrap();
    let second = resolve_with(Path::new("C:\\"), probe).unwrap();

    assert_eq!(
      first.mount_info().volume_identity().map(|r| r.identity()),
      Some(VolumeIdentity::Serial32(0x1a2b_3c4d))
    );
    assert_eq!(
      second.mount_info().volume_identity().map(|r| r.identity()),
      Some(VolumeIdentity::Serial32(0x5566_7788)),
      "the second resolve must report the volume's serial now, not the one it \
       carried when the first resolve asked"
    );
  }

  /// Windows asks the mounted filesystem itself, so what it reports is vouched
  /// — including the documented narrowing, which is the volume's own serial
  /// with fewer of its bits rather than another volume's name.
  #[test]
  fn test_the_windows_reading_is_vouched() {
    let Some(reading) = resolve(Path::new("C:\\"))
      .unwrap()
      .mount_info()
      .volume_identity()
    else {
      return;
    };
    assert!(reading.is_vouched(), "{reading:?}");
  }
}
