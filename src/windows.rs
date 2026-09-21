use std::{
  ffi::{OsStr, OsString},
  io,
  os::windows::{
    ffi::{OsStrExt, OsStringExt},
    io::AsRawHandle,
  },
  path::{Path, PathBuf},
};

use windows_sys::Win32::{
  Storage::FileSystem::{BusTypeMmc, BusTypeSd, BusTypeUsb, STORAGE_BUS_TYPE},
  System::{
    IO::DeviceIoControl,
    Ioctl::{
      FSCTL_GET_NTFS_VOLUME_DATA, IOCTL_STORAGE_GET_HOTPLUG_INFO, IOCTL_STORAGE_QUERY_PROPERTY,
      NTFS_VOLUME_DATA_BUFFER, PropertyStandardQuery, STORAGE_DESCRIPTOR_HEADER,
      STORAGE_DEVICE_DESCRIPTOR, STORAGE_HOTPLUG_INFO, STORAGE_PROPERTY_QUERY,
      StorageDeviceProperty,
    },
  },
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

/// `GetDriveTypeW`'s two non-answers: the type could not be determined, and
/// the path names no volume at all. Neither is a denial.
const DRIVE_UNKNOWN: u32 = 0;
const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_REMOVABLE: u32 = 2;
/// Media fixed in the drive, which says nothing about whether the drive itself
/// is fixed in the machine.
///
/// Defined unconditionally, and deliberately: it is matched as a **pattern**,
/// and a constant that exists only under a feature becomes an irrefutable
/// binding without it — every remaining drive type would silently take that
/// arm, and a warning-denying build would fail. A constant this crate uses in
/// a pattern is never feature-gated.
const DRIVE_FIXED: u32 = 3;
/// Optical media, which comes out of the machine and is ejectable by the
/// definition this crate publishes.
const DRIVE_CDROM: u32 = 5;

// `FILE_CASE_PRESERVED_NAMES` from `GetVolumeInformationW`'s
// `lpFileSystemFlags`. Defined locally to avoid pulling in the
// `Win32_System_SystemServices` feature for one stable constant.
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;

use super::{
  Ejectability, IdentityAssurance, IdentityReading, NameReading, SmallBytes, VolumeCapabilities,
};

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
  probe: impl Fn(
    Option<&str>,
    &Path,
  ) -> (
    VolumeCapabilities,
    Option<IdentityReading>,
    Option<NameReading>,
  ),
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
  let (capabilities, volume_identity, volume_name) =
    probe(volume_guid.as_deref(), &mount_point_path);

  // strip_prefix handles Windows path semantics (case, separators) correctly.
  let relative_path = canonical
    .strip_prefix(&mount_point_path)
    .map(|p| p.to_path_buf())
    .unwrap_or_default();

  let ejectability = ejectability(mount_point_path.as_path(), device.as_os_str());
  #[cfg(feature = "disk-usage")]
  let (total_bytes, available_bytes) = get_disk_space(&mount_point_path);

  Ok(Inner {
    mount: super::MountPoint {
      mount_point,
      device,
      ejectability,
      capabilities,
      volume_identity,
      volume_name,
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
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  let mut mounts = Vec::new();

  for volume_guid in get_volume_guid_paths() {
    let drive_type = unsafe { GetDriveTypeW(volume_guid.as_ptr()) };
    // Optical media is storage that leaves the machine, so it belongs in a
    // listing; admitting only fixed and removable drives dropped it before it
    // could be classified at all.
    if drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE && drive_type != DRIVE_CDROM {
      continue;
    }
    let device_str = String::from_utf16_lossy(wide_to_slice(&volume_guid));
    // Classified first, filtered after: an exact-state filter cannot be
    // applied to a state that has not been worked out yet.
    let ejectability = ejectability_of(drive_type, &device_str);
    if opts.excludes(ejectability) {
      continue;
    }

    let device = SmallBytes::from_bytes(device_str.as_bytes());

    for mount_path in get_volume_mount_paths(&volume_guid)? {
      let mount_str = String::from_utf16_lossy(wide_to_slice(&mount_path));
      let mount_point = SmallBytes::from_bytes(mount_str.as_bytes());
      let (capabilities, identity, name) = volume_info(Some(&device_str), Path::new(&mount_str));
      #[cfg(feature = "disk-usage")]
      let (total_bytes, available_bytes) = get_disk_space(Path::new(&mount_str));
      mounts.push(super::MountPoint {
        mount_point,
        device: device.clone(),
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
  }
  Ok(mounts)
}

pub(super) fn ejectability(mount_point: &Path, device: &OsStr) -> Ejectability {
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
    // The volume could not be named, so it was never asked.
    Err(_) => Ejectability::Unknown,
  }
}

/// Whether the media of the volume named by a `\\?\Volume{GUID}\` path can be
/// taken out of the machine.
///
/// **The drive type alone cannot answer this.** `GetDriveTypeW` reports
/// `DRIVE_FIXED` for an external USB disk — the media is fixed *in the drive*,
/// which says nothing about whether the drive is unplugged — so reading a
/// denial out of it was deriving a negative from the absence of a positive.
/// Where it says fixed, the device itself is asked.
fn is_removable_volume(volume: &str) -> Ejectability {
  let wide: Vec<u16> = volume.encode_utf16().chain(core::iter::once(0)).collect();
  // SAFETY: `wide` is a null-terminated wide string that outlives the call.
  let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
  ejectability_of(drive_type, volume)
}

/// What a drive type says, and what the device says where the drive type
/// cannot say it.
fn ejectability_of(drive_type: u32, volume: &str) -> Ejectability {
  match drive_type {
    // Removable media, and optical media, which comes out of the machine.
    DRIVE_REMOVABLE | DRIVE_CDROM => Ejectability::Ejectable,
    // The two answers that are not answers.
    DRIVE_UNKNOWN | DRIVE_NO_ROOT_DIR => Ejectability::Unknown,
    // Fixed media in the drive. Whether the *drive* is fixed is a different
    // question, and only the device can answer it.
    DRIVE_FIXED => device_ejectability(volume),
    // A network or RAM drive is not storage that leaves the machine, and
    // saying so is no heuristic about a device: there is no device.
    _ => Ejectability::NotEjectable,
  }
}

/// What the storage device behind a volume says about itself.
///
/// `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProperty` is the device
/// answering rather than the drive letter: `RemovableMedia` is the media, and
/// `BusType` is how the drive is attached. A drive on USB, SD or MMC leaves
/// the machine while it runs whatever its media says, which is exactly the
/// case the drive type reports as fixed. No new dependency is needed — this is
/// the control-code road the NTFS serial already takes, through the same
/// `Win32_System_Ioctl` and `Win32_System_IO` features.
///
/// The handle is opened for no access at all, as that road opens one, so this
/// needs no elevation and reads no volume data. A volume that cannot be named
/// or opened at all is [`Unknown`](super::Ejectability::Unknown) — never a
/// denial. Past that, a descriptor that could not be read is a silence rather
/// than an answer, and the removal question is still put; see
/// [`device_ejectability_of`].
fn device_ejectability(volume_guid: &str) -> Ejectability {
  use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};

  let Some(device) = volume_guid.strip_suffix('\\') else {
    return Ejectability::Unknown;
  };
  let Ok(volume) = OpenOptions::new()
    .access_mode(0)
    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
    .open(device)
  else {
    return Ejectability::Unknown;
  };

  // The descriptor may only ever say yes, so everything else it can do — say
  // nothing, or not be readable at all — falls through to the removal question
  // rather than ending the road. See [`device_ejectability_of`].
  device_ejectability_of(descriptor_says_ejectable(&volume), || {
    hotplug_ejectability(&volume)
  })
}

/// What the two device roads together say, and in which order.
///
/// The descriptor may only ever answer **yes**: `RemovableMedia` is about the
/// medium and `BusType` about the transport, and neither is the removal
/// question. So everything that is not a yes — the descriptor saying nothing,
/// and equally a descriptor that could not be read at all — falls through to
/// what the device says when asked the removal question itself, which is the
/// only road to a denial on this platform.
///
/// **That fall-through is the fix.** A descriptor query that failed used to
/// return [`Unknown`](super::Ejectability::Unknown) here, before the removal
/// question was ever put — and an external USB disk is exactly the device
/// whose descriptor a fixed-size query fails to read, so it went unanswered
/// and both exact-state filters dropped it.
///
/// `ask` is taken as a closure rather than a value so that the second control
/// code is not sent when the first already answered.
fn device_ejectability_of(
  descriptor_ejectable: bool,
  ask: impl FnOnce() -> Ejectability,
) -> Ejectability {
  if descriptor_ejectable {
    Ejectability::Ejectable
  } else {
    ask()
  }
}

/// The most a storage descriptor may claim to be.
///
/// The second buffer's length comes from the driver's own answer, so it is a
/// number from outside this process and is bounded before anything is
/// allocated from it. A real descriptor is the fixed part plus a few short
/// strings — vendor, product, revision, serial — and the raw device
/// properties; 64 KiB is far above anything a driver publishes and small
/// enough that a wrong number cannot become an allocation worth noticing.
const STORAGE_DESCRIPTOR_LIMIT: u32 = 64 * 1024;

/// How long the descriptor the driver named is, or `None` where it named
/// nothing this can believe.
///
/// `written` is what the first call actually wrote, and must cover the header
/// itself: a shorter answer is no answer. `size` is the length the driver says
/// its whole descriptor is, and must cover the fixed part this goes on to read
/// and stay under [`STORAGE_DESCRIPTOR_LIMIT`].
const fn descriptor_length(written: u32, size: u32) -> Option<usize> {
  if (written as usize) < core::mem::size_of::<STORAGE_DESCRIPTOR_HEADER>() {
    return None;
  }
  if (size as usize) < core::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
    return None;
  }
  if size > STORAGE_DESCRIPTOR_LIMIT {
    return None;
  }
  Some(size as usize)
}

/// What the descriptor's two fields say, which is a yes or a silence.
///
/// Never a denial: `RemovableMedia` describes the medium and `BusType` the
/// transport, so a device that is neither removable-medium nor on a removable
/// bus has said nothing about whether it leaves the machine —
/// `BusTypeUnknown`, IEEE 1394 and an external enclosure presenting as NVMe
/// all land here.
const fn descriptor_says_removable(removable_media: bool, bus: STORAGE_BUS_TYPE) -> bool {
  // Compared rather than matched: these constants are not upper case, and in
  // pattern position the compiler cannot tell a constant from a fresh binding.
  removable_media || bus == BusTypeUsb || bus == BusTypeSd || bus == BusTypeMmc
}

/// Whether the storage device behind an open volume handle says its media
/// comes out.
///
/// **`STORAGE_DEVICE_DESCRIPTOR` is variable-sized** — vendor, product,
/// revision and serial strings and the raw device properties follow its fixed
/// part — so it is read through the two-call protocol its documentation
/// describes. The first call offers a `STORAGE_DESCRIPTOR_HEADER` alone, which
/// is what a driver writes when the buffer cannot hold the whole answer, and
/// its `Size` names the length of the answer that driver would give. The
/// second call offers exactly that many bytes.
///
/// A single fixed-size call is what a device with a long descriptor answers
/// with a buffer-overflow status carrying only that header, and reading that
/// as failure is how an external USB disk — whose drive type Windows reports
/// as fixed, so this is the road it takes — went unanswered.
///
/// False is a silence, never a denial; see [`device_ejectability_of`].
fn descriptor_says_ejectable(volume: &std::fs::File) -> bool {
  let query = STORAGE_PROPERTY_QUERY {
    PropertyId: StorageDeviceProperty,
    QueryType: PropertyStandardQuery,
    AdditionalParameters: [0],
  };

  let mut header: STORAGE_DESCRIPTOR_HEADER = unsafe { core::mem::zeroed() };
  let mut written: u32 = 0;
  // SAFETY: `query` is a live, correctly shaped input buffer and `header` a
  // live output buffer of exactly the size this call declares, and the handle
  // is valid for as long as `volume` is alive.
  let ok = unsafe {
    DeviceIoControl(
      volume.as_raw_handle(),
      IOCTL_STORAGE_QUERY_PROPERTY,
      core::ptr::from_ref(&query).cast::<core::ffi::c_void>(),
      core::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
      core::ptr::from_mut(&mut header).cast::<core::ffi::c_void>(),
      core::mem::size_of::<STORAGE_DESCRIPTOR_HEADER>() as u32,
      &mut written,
      core::ptr::null_mut(),
    )
  };
  if ok == 0 {
    return false;
  }
  let Some(length) = descriptor_length(written, header.Size) else {
    return false;
  };

  // Allocated as `u32`s so the buffer is aligned for the descriptor: every
  // field of it is four bytes or fewer, which is its alignment, and a law
  // holds it there.
  let mut buffer: Vec<u32> = vec![0; length.div_ceil(core::mem::size_of::<u32>())];
  let mut written: u32 = 0;
  // SAFETY: as above, with an output buffer of `length` bytes — the length the
  // driver itself named, bounded by `descriptor_length` — which the allocation
  // above covers.
  let ok = unsafe {
    DeviceIoControl(
      volume.as_raw_handle(),
      IOCTL_STORAGE_QUERY_PROPERTY,
      core::ptr::from_ref(&query).cast::<core::ffi::c_void>(),
      core::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
      buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
      length as u32,
      &mut written,
      core::ptr::null_mut(),
    )
  };
  // A short answer means the two fields this reads were not among the bytes
  // written, so the device did not answer.
  if ok == 0 || (written as usize) < core::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
    return false;
  }

  // SAFETY: the driver wrote at least the fixed part — `written` says so —
  // into a buffer allocated as `u32`s and therefore aligned for a struct whose
  // own alignment is that of a `u32`.
  let descriptor = unsafe { &*buffer.as_ptr().cast::<STORAGE_DEVICE_DESCRIPTOR>() };
  descriptor_says_removable(descriptor.RemovableMedia, descriptor.BusType)
}

/// What the device says when asked the removal question itself.
///
/// `IOCTL_STORAGE_GET_HOTPLUG_INFO` is the only answer on this platform that
/// is *about* removal rather than about media or transport: `DeviceHotplug` is
/// the drive leaving the machine, `MediaRemovable` and `MediaHotplug` the
/// medium leaving the drive. A device that answers, and answers no to all
/// three, has positively denied — **that is the only road to
/// [`NotEjectable`](super::Ejectability::NotEjectable) for a real device on
/// Windows.** A control code the driver does not service, a short answer, or a
/// failed query is [`Unknown`](super::Ejectability::Unknown).
///
/// No new dependency: the control code and its buffer come from
/// `Win32_System_Ioctl` and the call from `Win32_System_IO`, both already
/// enabled for the NTFS serial road.
fn hotplug_ejectability(volume: &std::fs::File) -> Ejectability {
  let mut info: STORAGE_HOTPLUG_INFO = unsafe { core::mem::zeroed() };
  info.Size = core::mem::size_of::<STORAGE_HOTPLUG_INFO>() as u32;
  let mut written: u32 = 0;
  // SAFETY: `info` is a live output buffer of the size this control code is
  // told, and the handle is valid for as long as `volume` is alive.
  let ok = unsafe {
    DeviceIoControl(
      volume.as_raw_handle(),
      IOCTL_STORAGE_GET_HOTPLUG_INFO,
      core::ptr::null(),
      0,
      core::ptr::from_mut(&mut info).cast::<core::ffi::c_void>(),
      core::mem::size_of::<STORAGE_HOTPLUG_INFO>() as u32,
      &mut written,
      core::ptr::null_mut(),
    )
  };
  if ok == 0 || (written as usize) < core::mem::size_of::<STORAGE_HOTPLUG_INFO>() {
    return Ejectability::Unknown;
  }
  if info.DeviceHotplug || info.MediaRemovable || info.MediaHotplug {
    Ejectability::Ejectable
  } else {
    // The device was asked whether it can be removed, and said no.
    Ejectability::NotEjectable
  }
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

/// Queries the case-handling capabilities, filesystem name, volume serial
/// number and volume label for a volume — everything one
/// `GetVolumeInformationW` call yields.
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
/// The label is the name the volume was given, and is the one value here that
/// is not a fact about the volume's identity at all: a person can rewrite it at
/// any moment without the volume becoming another volume. It rides along because
/// this call already reports it, and an empty buffer — an unlabeled volume — is
/// reported as no label rather than as an empty name.
///
/// Both readings are [`Vouched`](super::IdentityAssurance::Vouched): the volume
/// mounted at that GUID path answered for itself, on this call. A
/// `GetVolumeInformationW` that failed reports no identity for this call only —
/// there is nowhere for that moment to be recorded, so the next resolve asks
/// again.
fn volume_info(
  volume_guid: Option<&str>,
  mount_root: &Path,
) -> (
  VolumeCapabilities,
  Option<IdentityReading>,
  Option<NameReading>,
) {
  let queried = volume_guid.map_or(mount_root, Path::new);
  let wide = to_wide(queried);
  let mut serial: u32 = 0;
  let mut fs_flags: u32 = 0;
  // Filesystem names ("NTFS", "exFAT", …) are short; MAX_PATH + 1 is ample.
  let mut fs_name = [0u16; 261];
  // A volume label is at most 32 characters on NTFS and 11 on FAT; the same
  // MAX_PATH + 1 buffer the documentation asks for holds any of them.
  let mut label = [0u16; 261];

  let ret = unsafe {
    GetVolumeInformationW(
      wide.as_ptr(),
      label.as_mut_ptr(),
      label.len() as u32,
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
    return (VolumeCapabilities::from_fs_type_defaults(b""), None, None);
  }

  // An unlabeled volume answers with an empty buffer, which is no label rather
  // than a label that is nothing; the caller's fallback names it instead. What
  // the volume did publish is reported as published, padding and all. Vouched
  // for the reason the serial beside it is: the volume mounted at that GUID
  // path answered for itself, on this call.
  //
  // Read strictly rather than lossily: a label whose UTF-16 is malformed is one
  // no `&str` can carry, and replacing the bytes that do not decode would
  // report a name the volume does not have — and vouch for it. That is the one
  // case the label road has no answer for, so it publishes none and the mount
  // point names the volume instead.
  let volume_name = String::from_utf16(&label[..wide_strlen(&label)])
    .ok()
    .and_then(|label| super::published_label(&label, IdentityAssurance::Vouched));

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
    volume_name,
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
        Some(NameReading {
          name: SmallBytes::from_bytes(b"FIXTURE"),
          assurance: IdentityAssurance::Vouched,
        }),
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

  // ── the storage descriptor's two-call protocol ────────────────────
  //
  // These are the parts of that road that need no device: the length the
  // driver names and what the two fields say. They live here, and so run only
  // on the Windows job, because this file is the Windows backend and the
  // types they are written against — `STORAGE_DESCRIPTOR_HEADER`,
  // `STORAGE_DEVICE_DESCRIPTOR`, `STORAGE_BUS_TYPE` — exist on no other
  // target. CI runs them: `test (windows-latest)`.

  const HEADER: u32 = core::mem::size_of::<STORAGE_DESCRIPTOR_HEADER>() as u32;
  const FIXED: u32 = core::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() as u32;

  /// The length is the driver's own number, so it is believed only where it
  /// covers what will be read and stays under the bound.
  #[test]
  fn test_a_descriptor_length_is_believed_only_within_its_bounds() {
    // The driver wrote the header and named a descriptor that covers the
    // fixed part: the second call asks for exactly that.
    assert_eq!(descriptor_length(HEADER, FIXED), Some(FIXED as usize));
    assert_eq!(
      descriptor_length(HEADER, FIXED + 512),
      Some(FIXED as usize + 512),
      "the strings after the fixed part are why the second call exists"
    );
    assert_eq!(
      descriptor_length(HEADER, STORAGE_DESCRIPTOR_LIMIT),
      Some(STORAGE_DESCRIPTOR_LIMIT as usize),
      "the bound itself is still an answer"
    );

    // A first call that did not even write the header answered nothing.
    assert_eq!(descriptor_length(0, FIXED), None);
    assert_eq!(descriptor_length(HEADER - 1, FIXED), None);
    // A descriptor too short to hold the fields that will be read.
    assert_eq!(descriptor_length(HEADER, 0), None);
    assert_eq!(descriptor_length(HEADER, FIXED - 1), None);
    // A number no driver would give, which must not become an allocation.
    assert_eq!(
      descriptor_length(HEADER, STORAGE_DESCRIPTOR_LIMIT + 1),
      None
    );
    assert_eq!(descriptor_length(HEADER, u32::MAX), None);
  }

  /// The buffer the second call fills is allocated as `u32`s, which is only
  /// sound while that is the descriptor's own alignment.
  #[test]
  fn test_the_descriptor_is_aligned_like_the_buffer_it_is_read_from() {
    assert!(
      core::mem::align_of::<STORAGE_DEVICE_DESCRIPTOR>() <= core::mem::align_of::<u32>(),
      "the u32 buffer in descriptor_says_ejectable no longer aligns the descriptor"
    );
  }

  /// The descriptor answers yes or nothing, and never no.
  #[test]
  fn test_the_descriptor_says_yes_or_nothing() {
    use windows_sys::Win32::Storage::FileSystem::{BusTypeAta, BusTypeNvme, BusTypeUnknown};

    assert!(descriptor_says_removable(true, BusTypeAta));
    for bus in [BusTypeUsb, BusTypeSd, BusTypeMmc] {
      assert!(descriptor_says_removable(false, bus), "{bus}");
    }
    // Not a denial — a silence. `BusTypeUnknown` and an external enclosure
    // presenting as NVMe are exactly the devices that land here.
    for bus in [BusTypeUnknown, BusTypeAta, BusTypeNvme] {
      assert!(!descriptor_says_removable(false, bus), "{bus}");
    }
  }

  /// The removal question is asked exactly when the descriptor did not say
  /// yes — which is the regression: a descriptor query that failed used to end
  /// the road at `Unknown` before the device was ever asked, and an external
  /// USB disk is precisely the device whose descriptor a fixed-size query
  /// fails to read.
  #[test]
  fn test_the_removal_question_is_asked_whenever_the_descriptor_did_not_say_yes() {
    let mut asked = false;
    assert_eq!(
      device_ejectability_of(true, || {
        asked = true;
        Ejectability::NotEjectable
      }),
      Ejectability::Ejectable
    );
    assert!(!asked, "a yes needs no second control code");

    // Every way the descriptor can fail to say yes — it said nothing, or it
    // could not be read at all — reaches the device, and its answer is what
    // comes back, denial included.
    for answer in [
      Ejectability::Ejectable,
      Ejectability::NotEjectable,
      Ejectability::Unknown,
    ] {
      let mut asked = false;
      assert_eq!(
        device_ejectability_of(false, || {
          asked = true;
          answer
        }),
        answer
      );
      assert!(asked, "the removal question must be put: {answer:?}");
    }
  }
}
