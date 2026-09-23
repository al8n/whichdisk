//! Windows: every value in a row is read through one handle on its volume.
//!
//! **An observation is formed once, from one native identity, and a row is
//! built from nothing else.** A resolve finds its path's mount root once
//! (`GetVolumePathNameW`) and opens **one handle** on that root directory; a
//! listing opens its handle through the volume GUID path the enumeration
//! named. The volume GUID path of a resolve is read *through* the handle
//! (`GetFinalPathNameByHandleW`, `VOLUME_NAME_GUID`) and never resolved from
//! the root a second time. Every field of the row is then read through that
//! one handle: the serial and the label (`FileFsVolumeInformation`), the
//! file-system name and flags (`FileFsAttributeInformation`), the capacity
//! (`FileFsFullSizeInformation`) and the kind of device the volume is on
//! (`FileFsDeviceInformation`), all with `NtQueryVolumeInformationFile`; the
//! full NTFS serial with `FSCTL_GET_NTFS_VOLUME_DATA`; and the removal question
//! with `IOCTL_STORAGE_QUERY_PROPERTY` and `IOCTL_STORAGE_GET_HOTPLUG_INFO`.
//! Finding a mount root, opening a handle and reading its GUID path are private
//! to [`observed`], so no row road can do any of them again.
//!
//! The handle is the volume's root directory, opened for no access at all. A
//! handle on the volume device itself would not do: opened without read
//! access, which is all an unelevated process is granted there, it is a
//! direct device open that the file system never sees, so nothing but the
//! device kind is answered through it.

use std::{
  io,
  os::windows::ffi::OsStrExt as _,
  path::{Path, PathBuf},
};

use windows_sys::Win32::Storage::FileSystem::{
  BusTypeMmc, BusTypeSd, BusTypeUsb, STORAGE_BUS_TYPE,
};
use windows_sys::Win32::{
  Storage::FileSystem::{FILE_DEVICE_CD_ROM, FILE_DEVICE_DISK, FILE_DEVICE_DVD},
  System::Ioctl::{
    FILE_DEVICE_CD_ROM_FILE_SYSTEM, FILE_DEVICE_DISK_FILE_SYSTEM, STORAGE_DESCRIPTOR_HEADER,
    STORAGE_DEVICE_DESCRIPTOR,
  },
};

#[cfg(feature = "list")]
use windows_sys::Win32::Storage::FileSystem::{FindFirstVolumeW, FindNextVolumeW, FindVolumeClose};

use super::{Ejectability, SmallBytes};

use observed::{Observed, Volume};

/// `FILE_CASE_PRESERVED_NAMES`, from `FileFsAttributeInformation`'s
/// `FileSystemAttributes`. Defined locally to avoid pulling in the
/// `Win32_System_SystemServices` feature for one stable constant.
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;

/// `FILE_REMOVABLE_MEDIA`, a device characteristic (`wdm.h`): the storage
/// device's medium can be taken out of it. The one thing a device kind can say
/// yes about. Defined locally: the binding crate names it only behind a
/// feature this crate does not otherwise need.
const FILE_REMOVABLE_MEDIA: u32 = 0x0000_0001;

/// `FILE_REMOTE_DEVICE`, a device characteristic (`wdm.h`): the volume is
/// reached over a network, so no storage device of this machine holds it.
const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;

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
  resolve_with(path, Volume::read)
}

/// The body of [`resolve`], with the read of the observation as a parameter.
///
/// Nothing here is cached, so what a resolve reports is whatever the volume
/// answered on this call — and that is a claim a test has to be able to break.
/// No test can rewrite a real volume's serial (the tools that do it work
/// offline, on an unmounted volume), so the read is passed in and a test stands
/// a changing volume in for a real one. See
/// `test_the_identity_is_read_on_every_resolve`.
fn resolve_with(path: &Path, read: impl Fn(&Volume) -> Observed) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;

  // The path's mount root, found once, and the one handle every field of the
  // row is read through: see [`observed`].
  let (root, volume) = Volume::of_path(&canonical)?;
  let mount_point = root
    .to_str()
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mount point is not valid UTF-8"))?;

  // Asked on every resolve, and never remembered — the same law Apple and
  // Linux follow, reached here for a reason of its own. The volume GUID names
  // *storage*, which is durable; the serial is a value in the filesystem
  // written onto that storage, and an offline tool can rewrite it while the
  // GUID stays put. A key that outlives what it is supposed to vouch for
  // cannot vouch for it, so nothing is stored under it.
  let observed = read(&volume);

  // strip_prefix handles Windows path semantics (case, separators) correctly.
  let relative_path = canonical
    .strip_prefix(&root)
    .map(|p| p.to_path_buf())
    .unwrap_or_default();

  Ok(Inner {
    mount: observed.row(SmallBytes::from_bytes(mount_point.as_bytes())),
    canonical,
    relative_path,
  })
}

/// Every volume the mount manager enumerates, each described by one
/// observation of its own.
///
/// **A row is one observation, exactly as a resolve's is.** Each volume is
/// opened once, through the GUID path the enumeration named, and every field
/// of its rows is read through that handle. The volume's mount points are
/// asked of the mount manager while the handle is held, and the fields are read
/// after them: a volume that left in between fails those reads rather than
/// lending its mount points to the volume that took its GUID. A volume that
/// cannot be opened — no medium in the drive, no file system on it, gone — has
/// nothing to describe and is not listed.
#[cfg(feature = "list")]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  let mut mounts = Vec::new();

  for volume_guid in get_volume_guid_paths() {
    let guid = String::from_utf16_lossy(wide_to_slice(&volume_guid));
    let Ok(volume) = Volume::named(guid) else {
      continue;
    };
    let paths = volume.mount_paths()?;
    let observed = volume.read();
    // Local storage only: a disk or an optical drive, as the device kind the
    // file system reports says, and nothing reached over a network.
    if !observed.is_listed() {
      continue;
    }
    // Classified first, filtered after: an exact-state filter cannot be
    // applied to a state that has not been worked out yet.
    if opts.excludes(observed.ejectability()) {
      continue;
    }
    for path in paths {
      mounts.push(observed.row(SmallBytes::from_bytes(path.as_bytes())));
    }
  }
  Ok(mounts)
}

/// One observation of one volume, and the only place a row's volume is found,
/// opened or named.
///
/// **The observation is one handle and the GUID path it names.** Every field of
/// a row is read through the handle, and the handle is opened once, so no two
/// fields of a row can describe two volumes: a drive letter is a slot whose
/// occupant can change between two calls, and a volume GUID path, which names
/// one volume for its life, is also a name a clone of that volume is given
/// once the original has gone. Neither is resolved again once the handle is
/// open.
mod observed {
  use std::{
    ffi::OsString,
    fs::File,
    io,
    os::windows::{ffi::OsStringExt as _, fs::OpenOptionsExt as _, io::AsRawHandle as _},
    path::{Path, PathBuf},
  };

  use windows_sys::{
    Wdk::Storage::FileSystem::{
      FS_INFORMATION_CLASS, FileFsAttributeInformation, FileFsDeviceInformation,
      FileFsVolumeInformation, NtQueryVolumeInformationFile,
    },
    Win32::{
      Foundation::RtlNtStatusToDosError,
      Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFinalPathNameByHandleW, GetVolumePathNameW, VOLUME_NAME_GUID,
      },
      System::{
        IO::{DeviceIoControl, IO_STATUS_BLOCK},
        Ioctl::{
          FSCTL_GET_NTFS_VOLUME_DATA, IOCTL_STORAGE_GET_HOTPLUG_INFO, IOCTL_STORAGE_QUERY_PROPERTY,
          NTFS_VOLUME_DATA_BUFFER, PropertyStandardQuery, STORAGE_DESCRIPTOR_HEADER,
          STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
        },
      },
    },
  };

  #[cfg(feature = "disk-usage")]
  use {
    super::FsFullSizeInformation, windows_sys::Wdk::Storage::FileSystem::FileFsFullSizeInformation,
  };
  #[cfg(feature = "list")]
  use {
    super::is_local_storage,
    windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW,
  };

  use super::{
    super::{
      Ejectability, IdentityAssurance, IdentityReading, MountPoint, NameReading, SmallBytes,
      VolumeCapabilities, published_label, windows_identity,
    },
    FILE_CASE_PRESERVED_NAMES, FsAttributeInformation, FsDeviceInformation, FsVolumeInformation,
    StorageDeviceDescriptorHead, StorageHotplugInfoRaw, descriptor_length,
    descriptor_says_removable, device_ejectability_of, ejectability_of, hotplug_answer, to_wide,
    wide_strlen,
  };

  /// One handle on a volume's root directory, and the volume GUID path that
  /// names the volume it is on.
  pub(super) struct Volume {
    root: File,
    /// `\\?\Volume{GUID}\`, or `None` for a volume that has none — a network
    /// share, for which volume GUID paths are not created.
    guid: Option<String>,
  }

  /// Everything one handle answered about its volume: every field of every row
  /// that volume has.
  pub(super) struct Observed {
    guid: Option<String>,
    /// The device kind, which only a listing asks again, to decide whether it
    /// reports the volume.
    #[cfg_attr(not(feature = "list"), allow(dead_code))]
    device: Option<FsDeviceInformation>,
    ejectability: Ejectability,
    capabilities: VolumeCapabilities,
    identity: Option<IdentityReading>,
    name: Option<NameReading>,
    #[cfg(feature = "disk-usage")]
    capacity: (u64, u64),
  }

  impl Volume {
    /// A resolve's observation: the mount root of `canonical`, found once, the
    /// one handle opened on it, and the GUID path read through that handle.
    pub(super) fn of_path(canonical: &Path) -> io::Result<(PathBuf, Self)> {
      let root = volume_path_name(canonical)?;
      let handle = open_root(&root)?;
      let guid = guid_path(&handle);
      Ok((root, Self { root: handle, guid }))
    }

    /// A listing's observation: the one handle, opened through the GUID path
    /// the enumeration named.
    #[cfg(feature = "list")]
    pub(super) fn named(guid: String) -> io::Result<Self> {
      let root = open_root(Path::new(&guid))?;
      Ok(Self {
        root,
        guid: Some(guid),
      })
    }

    /// Every path the volume is mounted at, asked of the mount manager by the
    /// GUID path while this handle holds the volume. `GetVolumePathNamesForVolumeNameW`
    /// answers a multi-string, and says when its buffer is too small with the
    /// length it needs.
    #[cfg(feature = "list")]
    pub(super) fn mount_paths(&self) -> io::Result<Vec<String>> {
      let Some(guid) = &self.guid else {
        return Ok(Vec::new());
      };
      let wide = to_wide(Path::new(guid));
      let mut buf = vec![0u16; 260];
      let mut required_len: u32 = 0;
      loop {
        // SAFETY: `wide` is a NUL-terminated wide string and `buf` a live
        // buffer of the length declared, both for the length of the call.
        let ret = unsafe {
          GetVolumePathNamesForVolumeNameW(
            wide.as_ptr(),
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

      // A multi-string: NUL-separated, and ended by an empty string.
      let mut paths = Vec::new();
      let mut rest = &buf[..];
      while !rest.is_empty() && rest[0] != 0 {
        let len = wide_strlen(rest);
        paths.push(String::from_utf16_lossy(&rest[..len]));
        rest = &rest[len + 1..];
      }
      Ok(paths)
    }

    /// Every field of the volume's rows, read through the one handle.
    pub(super) fn read(&self) -> Observed {
      let volume = self.volume_information();
      let attributes = self.attributes();
      let fs_type = attributes.as_ref().map_or("", |(_, name)| name.as_str());
      // `case_sensitive` follows the filesystem-type default; `case_preserving`
      // comes from the accurate `FILE_CASE_PRESERVED_NAMES` flag, overriding
      // the type-derived value.
      let mut capabilities = VolumeCapabilities::from_fs_type_defaults(fs_type.as_bytes());
      if let Some((flags, _)) = &attributes {
        capabilities.case_preserving = Some(flags & FILE_CASE_PRESERVED_NAMES != 0);
      }
      let ntfs_serial = if fs_type.eq_ignore_ascii_case("NTFS") {
        self.ntfs_serial()
      } else {
        None
      };
      let (identity, name) = match volume {
        Some((serial, label)) => (
          windows_identity(fs_type.as_bytes(), serial, ntfs_serial),
          label.and_then(|label| published_label(&label, IdentityAssurance::Vouched)),
        ),
        None => (None, None),
      };
      let device = self.device();
      let ejectability = match device {
        Some(device) => ejectability_of(device, || {
          device_ejectability_of(self.descriptor_says_ejectable(), || self.hotplug())
        }),
        None => Ejectability::Unknown,
      };
      Observed {
        guid: self.guid.clone(),
        device,
        ejectability,
        capabilities,
        identity,
        name,
        #[cfg(feature = "disk-usage")]
        capacity: self.full_size().unwrap_or((0, 0)),
      }
    }

    /// One `NtQueryVolumeInformationFile` of `class` into `buffer`, answering
    /// how many bytes the file system wrote. A status that is not success is
    /// the error its system code names (`RtlNtStatusToDosError`).
    fn query(
      &self,
      class: FS_INFORMATION_CLASS,
      buffer: *mut core::ffi::c_void,
      length: usize,
    ) -> io::Result<usize> {
      let mut status = IO_STATUS_BLOCK::default();
      // SAFETY: the handle is valid for as long as `self.root` is, `status`
      // is a live status block, and `buffer` is the caller's live buffer of
      // `length` bytes, which the file system writes no further than.
      let nt = unsafe {
        NtQueryVolumeInformationFile(
          self.root.as_raw_handle(),
          &mut status,
          buffer,
          length as u32,
          class,
        )
      };
      if nt < 0 {
        // SAFETY: a pure conversion of a status code.
        let code = unsafe { RtlNtStatusToDosError(nt) };
        return Err(io::Error::from_raw_os_error(code as i32));
      }
      Ok(status.Information)
    }

    /// The volume's serial and its label: `FileFsVolumeInformation`.
    ///
    /// The label follows the fixed part in the same buffer, as a length in
    /// bytes and UTF-16 units; it is read only where it lies wholly inside what
    /// the file system wrote, and strictly — a label whose UTF-16 is malformed
    /// is one no `&str` can carry, and replacing the bytes that do not decode
    /// would report a name the volume does not have. An empty label is no
    /// label.
    fn volume_information(&self) -> Option<(u32, Option<String>)> {
      let mut buffer = Aligned([0u8; 576]);
      let written = self
        .query(
          FileFsVolumeInformation,
          buffer.0.as_mut_ptr().cast(),
          buffer.0.len(),
        )
        .ok()?;
      let label_at = core::mem::offset_of!(FsVolumeInformation, label);
      if written < label_at {
        return None;
      }
      // SAFETY: the buffer is aligned to 8, which covers the mirror's own
      // alignment, and at least the fixed part was written; every field of the
      // mirror is an integer, for which every bit pattern is a valid value.
      let head = unsafe { &*buffer.0.as_ptr().cast::<FsVolumeInformation>() };
      let label = label_at
        .checked_add(head.label_length as usize)
        .filter(|&end| end <= written && end <= buffer.0.len())
        .and_then(|end| utf16(&buffer.0[label_at..end]))
        .filter(|label| !label.is_empty());
      Some((head.serial, label))
    }

    /// The file system's name and its attribute flags:
    /// `FileFsAttributeInformation`. The name follows the fixed part in the
    /// same buffer and is read the same way the label is.
    fn attributes(&self) -> Option<(u32, String)> {
      let mut buffer = Aligned([0u8; 544]);
      let written = self
        .query(
          FileFsAttributeInformation,
          buffer.0.as_mut_ptr().cast(),
          buffer.0.len(),
        )
        .ok()?;
      let name_at = core::mem::offset_of!(FsAttributeInformation, name);
      if written < name_at {
        return None;
      }
      // SAFETY: as for the volume information above.
      let head = unsafe { &*buffer.0.as_ptr().cast::<FsAttributeInformation>() };
      let name = name_at
        .checked_add(head.name_length as usize)
        .filter(|&end| end <= written && end <= buffer.0.len())
        .and_then(|end| utf16(&buffer.0[name_at..end]))?;
      Some((head.attributes, name))
    }

    /// The volume's capacity, as `(total, available to this caller)` bytes:
    /// `FileFsFullSizeInformation`, in allocation units of the size it names.
    #[cfg(feature = "disk-usage")]
    fn full_size(&self) -> Option<(u64, u64)> {
      let mut info = FsFullSizeInformation::default();
      let written = self
        .query(
          FileFsFullSizeInformation,
          core::ptr::from_mut(&mut info).cast(),
          core::mem::size_of::<FsFullSizeInformation>(),
        )
        .ok()?;
      if written < core::mem::size_of::<FsFullSizeInformation>() {
        return None;
      }
      let unit = u64::from(info.sectors_per_unit).saturating_mul(u64::from(info.bytes_per_sector));
      let total = u64::try_from(info.total_units).ok()?;
      let available = u64::try_from(info.caller_available_units).ok()?;
      Some((total.saturating_mul(unit), available.saturating_mul(unit)))
    }

    /// The kind of device the volume is on and its characteristics:
    /// `FileFsDeviceInformation`, which the I/O manager answers itself, from
    /// the device object the handle was opened through.
    fn device(&self) -> Option<FsDeviceInformation> {
      let mut info = FsDeviceInformation::default();
      let written = self
        .query(
          FileFsDeviceInformation,
          core::ptr::from_mut(&mut info).cast(),
          core::mem::size_of::<FsDeviceInformation>(),
        )
        .ok()?;
      (written >= core::mem::size_of::<FsDeviceInformation>()).then_some(info)
    }

    /// The volume's full 64-bit NTFS serial, with `FSCTL_GET_NTFS_VOLUME_DATA`
    /// on the one handle.
    ///
    /// This is the same number Linux publishes under `/dev/disk/by-uuid` as
    /// sixteen hex digits; `FileFsVolumeInformation` reports only its low
    /// half. The control code is declared `FILE_ANY_ACCESS`, so the handle
    /// needs no access to ask it. `None` where it is not serviced, which
    /// leaves the caller with the documented narrower serial rather than a
    /// wrong number.
    fn ntfs_serial(&self) -> Option<u64> {
      let mut data: NTFS_VOLUME_DATA_BUFFER = unsafe { core::mem::zeroed() };
      let mut written: u32 = 0;
      // SAFETY: `data` is a live, correctly sized output buffer for this
      // control code, and the handle is valid for as long as `self.root` is.
      let ok = unsafe {
        DeviceIoControl(
          self.root.as_raw_handle(),
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

    /// Whether the storage device says its media comes out, asked on the one
    /// handle with `IOCTL_STORAGE_QUERY_PROPERTY`.
    ///
    /// **`STORAGE_DEVICE_DESCRIPTOR` is variable-sized** — vendor, product,
    /// revision and serial strings and the raw device properties follow its
    /// fixed part — so it is read through the two-call protocol its
    /// documentation describes. The first call offers a
    /// `STORAGE_DESCRIPTOR_HEADER` alone, which is what a driver writes when
    /// the buffer cannot hold the whole answer, and its `Size` names the length
    /// of the answer that driver would give. The second call offers exactly
    /// that many bytes.
    ///
    /// False is a silence, never a denial; see [`device_ejectability_of`].
    fn descriptor_says_ejectable(&self) -> bool {
      let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
      };

      let mut header: STORAGE_DESCRIPTOR_HEADER = unsafe { core::mem::zeroed() };
      let mut written: u32 = 0;
      // SAFETY: `query` is a live, correctly shaped input buffer and `header` a
      // live output buffer of exactly the size this call declares, and the
      // handle is valid for as long as `self.root` is.
      let ok = unsafe {
        DeviceIoControl(
          self.root.as_raw_handle(),
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

      // Allocated as `u32`s so the buffer is aligned for the mirror read out of
      // it: every field of that mirror is four bytes or fewer, which is its
      // alignment, and a law holds it there.
      let mut buffer: Vec<u32> = vec![0; length.div_ceil(core::mem::size_of::<u32>())];
      let mut written: u32 = 0;
      // SAFETY: as above, with an output buffer of `length` bytes — the length
      // the driver itself named, bounded by `descriptor_length` — which the
      // allocation above covers.
      let ok = unsafe {
        DeviceIoControl(
          self.root.as_raw_handle(),
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
      // into a buffer allocated as `u32`s and therefore aligned for a mirror
      // whose own alignment is that of a `u32`, and every field of that mirror
      // is an integer, for which every bit pattern is a valid value. Read
      // through [`StorageDeviceDescriptorHead`] rather than through the binding
      // crate's struct, whose `BOOLEAN` fields are Rust `bool`s a driver is
      // free to make invalid.
      let head = unsafe { &*buffer.as_ptr().cast::<StorageDeviceDescriptorHead>() };
      descriptor_says_removable(head.removable_media, head.bus_type)
    }

    /// What the device says when asked the removal question itself, on the one
    /// handle: `IOCTL_STORAGE_GET_HOTPLUG_INFO`. A control code the driver does
    /// not service, a short answer, or a failed query is
    /// [`Unknown`](Ejectability::Unknown); see [`hotplug_answer`] for what the
    /// three answer bytes say.
    fn hotplug(&self) -> Ejectability {
      let mut info = StorageHotplugInfoRaw {
        size: core::mem::size_of::<StorageHotplugInfoRaw>() as u32,
        media_removable: 0,
        media_hotplug: 0,
        device_hotplug: 0,
        _write_cache_enable_override: 0,
      };
      let mut written: u32 = 0;
      // SAFETY: `info` is a live output buffer of the size this control code is
      // told, and the handle is valid for as long as `self.root` is. Every
      // field of it is an integer, so whatever the driver writes is a valid
      // value.
      let ok = unsafe {
        DeviceIoControl(
          self.root.as_raw_handle(),
          IOCTL_STORAGE_GET_HOTPLUG_INFO,
          core::ptr::null(),
          0,
          core::ptr::from_mut(&mut info).cast::<core::ffi::c_void>(),
          core::mem::size_of::<StorageHotplugInfoRaw>() as u32,
          &mut written,
          core::ptr::null_mut(),
        )
      };
      if ok == 0 || (written as usize) < core::mem::size_of::<StorageHotplugInfoRaw>() {
        return Ejectability::Unknown;
      }
      hotplug_answer(
        info.device_hotplug,
        info.media_removable,
        info.media_hotplug,
      )
    }
  }

  impl Observed {
    /// What the volume's storage says about leaving the machine, which a
    /// listing's exact-state filters ask before the rows are built.
    #[cfg(feature = "list")]
    pub(super) fn ejectability(&self) -> Ejectability {
      self.ejectability
    }

    /// Whether a listing reports the volume: local storage, a disk or an
    /// optical drive, as the device kind says.
    #[cfg(feature = "list")]
    pub(super) fn is_listed(&self) -> bool {
      self.device.is_some_and(is_local_storage)
    }

    /// One row of the volume, mounted at `mount_point`: every field out of this
    /// one observation. The device is the volume GUID path, or, for a volume
    /// that has none, the mount point itself.
    pub(super) fn row(&self, mount_point: SmallBytes) -> MountPoint {
      MountPoint {
        device: match &self.guid {
          Some(guid) => SmallBytes::from_bytes(guid.as_bytes()),
          None => mount_point.clone(),
        },
        mount_point,
        ejectability: self.ejectability,
        capabilities: self.capabilities.clone(),
        volume_identity: self.identity,
        volume_name: self.name.clone(),
        #[cfg(feature = "disk-usage")]
        total_bytes: self.capacity.0,
        #[cfg(feature = "disk-usage")]
        available_bytes: self.capacity.1,
      }
    }

    /// The device kind the file system reported, for the laws.
    #[cfg(test)]
    pub(super) fn device(&self) -> Option<FsDeviceInformation> {
      self.device
    }

    /// An observation a law stands in for a volume's.
    #[cfg(test)]
    pub(super) fn fixture(
      capabilities: VolumeCapabilities,
      identity: Option<IdentityReading>,
      name: Option<NameReading>,
    ) -> Self {
      Self {
        guid: None,
        device: None,
        ejectability: Ejectability::Unknown,
        capabilities,
        identity,
        name,
        #[cfg(feature = "disk-usage")]
        capacity: (0, 0),
      }
    }
  }

  /// A byte buffer aligned for the `FILE_FS_*` mirrors read out of it, the
  /// widest of which holds a `LARGE_INTEGER`.
  #[repr(C, align(8))]
  struct Aligned<const N: usize>([u8; N]);

  /// UTF-16 in native byte order, decoded strictly: an odd length or a
  /// malformed sequence is no string.
  fn utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
      return None;
    }
    let units: Vec<u16> = bytes
      .chunks_exact(2)
      .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
      .collect();
    String::from_utf16(&units).ok()
  }

  /// Opens a volume's root directory for no access at all: the one handle.
  ///
  /// No access is needed for anything asked through it — the volume queries
  /// are answered on any handle, and the three control codes are declared
  /// `FILE_ANY_ACCESS` — so nothing about this open can be refused for want
  /// of a right to the volume's contents. `FILE_FLAG_BACKUP_SEMANTICS` is what
  /// opening a directory takes, and every share mode is granted, so the open
  /// stands in no one's way.
  fn open_root(root: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
      .access_mode(0)
      .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
      .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
      .open(root)
  }

  /// The volume GUID path of the volume a handle is on, read through the
  /// handle: `GetFinalPathNameByHandleW` with `VOLUME_NAME_GUID`, which for a
  /// root directory is `\\?\Volume{GUID}\` itself. `None` for a volume that
  /// has no such path.
  ///
  /// A buffer too small is answered with the length needed, terminator
  /// included, and asked again at that length.
  fn guid_path(root: &File) -> Option<String> {
    let mut buffer = vec![0u16; 64];
    loop {
      // SAFETY: `buffer` is live and as long as declared for the call, and the
      // handle is valid for as long as `root` is.
      let len = unsafe {
        GetFinalPathNameByHandleW(
          root.as_raw_handle(),
          buffer.as_mut_ptr(),
          buffer.len() as u32,
          VOLUME_NAME_GUID | FILE_NAME_NORMALIZED,
        )
      } as usize;
      if len == 0 {
        return None;
      }
      if len < buffer.len() {
        return String::from_utf16(&buffer[..len]).ok();
      }
      if len > 32_768 {
        return None;
      }
      buffer.resize(len, 0);
    }
  }

  /// `GetVolumePathNameW`: the mount root the caller's own path lies under.
  ///
  /// Starts with 1024 wide chars on the stack, then retries with doubling heap
  /// buffers up to 32 768 wide chars if the buffer is too small.
  fn volume_path_name(path: &Path) -> io::Result<PathBuf> {
    let wide = to_wide(path);

    let mut stack_buf = [0u16; 1024];
    let mut heap_buf: Vec<u16>;
    let mut buf: &mut [u16] = &mut stack_buf;

    loop {
      // SAFETY: `wide` is NUL-terminated and `buf` live and as long as
      // declared, both for the length of the call.
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
}

/// Whether a device kind is local storage a listing reports: a disk or an
/// optical drive, and nothing reached over a network.
#[cfg_attr(not(feature = "list"), allow(dead_code))]
fn is_local_storage(device: FsDeviceInformation) -> bool {
  device.characteristics & FILE_REMOTE_DEVICE == 0
    && (is_disk(device.device_type) || is_optical(device.device_type))
}

/// A disk, as the device kind names one.
fn is_disk(device_type: u32) -> bool {
  device_type == FILE_DEVICE_DISK || device_type == FILE_DEVICE_DISK_FILE_SYSTEM
}

/// An optical drive, as the device kind names one.
fn is_optical(device_type: u32) -> bool {
  device_type == FILE_DEVICE_CD_ROM
    || device_type == FILE_DEVICE_CD_ROM_FILE_SYSTEM
    || device_type == FILE_DEVICE_DVD
}

/// What the device kind the file system reports says, and what the device
/// says where the kind cannot say it.
///
/// **A device kind never denies.** It says what kind of device a volume is on,
/// which is not an answer to the removal question, and the invariant this crate
/// publishes admits no exception for any kind. Optical media and a disk whose
/// medium comes out are a yes. A disk whose medium is fixed in it — which is
/// what an external USB disk is, its medium fixed *in the drive* — says
/// nothing about whether the drive is unplugged, so the device is asked, on the
/// same handle (`ask`). Everything else — a volume reached over a network, a
/// RAM disk, a kind a later Windows adds — was not asked about removal, so it
/// says nothing about it.
fn ejectability_of(
  device: FsDeviceInformation,
  ask: impl FnOnce() -> Ejectability,
) -> Ejectability {
  if device.characteristics & FILE_REMOTE_DEVICE != 0 {
    return Ejectability::Unknown;
  }
  if is_optical(device.device_type) {
    return Ejectability::Ejectable;
  }
  if !is_disk(device.device_type) {
    return Ejectability::Unknown;
  }
  if device.characteristics & FILE_REMOVABLE_MEDIA != 0 {
    return Ejectability::Ejectable;
  }
  ask()
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

/// The fixed part of `STORAGE_DEVICE_DESCRIPTOR`, spelled so that **any** bytes
/// a driver writes are a valid value of it.
///
/// Windows' `BOOLEAN` is a byte: false is zero and true is *any* non-zero
/// value. A Rust `bool` is 0 or 1 and nothing else, so a driver answering
/// `0xFF` for true — which the protocol permits — makes a `bool` read out of
/// those bytes an invalid value, and producing one is undefined behaviour
/// however carefully the buffer was aligned and sized. The binding crate types
/// those fields as `bool`, so this crate does not read the descriptor through
/// its struct at all: the two `BOOLEAN` fields are `u8` here and are compared
/// against zero, which is what the protocol actually says.
///
/// Everything else is a plain integer, and every bit pattern of one is valid.
/// The laws below hold this mirror's alignment, its size and the offsets of the
/// fields actually read against the binding crate's own struct, so it cannot
/// drift from the shape the driver writes.
#[repr(C)]
#[derive(Clone, Copy)]
struct StorageDeviceDescriptorHead {
  _version: u32,
  _size: u32,
  _device_type: u8,
  _device_type_modifier: u8,
  removable_media: u8,
  _command_queueing: u8,
  _vendor_id_offset: u32,
  _product_id_offset: u32,
  _product_revision_offset: u32,
  _serial_number_offset: u32,
  bus_type: STORAGE_BUS_TYPE,
  _raw_properties_length: u32,
}

/// `STORAGE_HOTPLUG_INFO`, spelled the same way and for the same reason.
///
/// All four of its answer fields are `BOOLEAN`, and the binding crate types all
/// four as `bool`. The control code fills them from the driver, so reading them
/// through that struct has exactly the validity problem the descriptor had.
#[repr(C)]
#[derive(Clone, Copy)]
struct StorageHotplugInfoRaw {
  /// Set by the caller, as the control code's contract asks, and never read
  /// back — but it has to be here, and here, for the rest to line up.
  #[allow(dead_code)]
  size: u32,
  media_removable: u8,
  media_hotplug: u8,
  device_hotplug: u8,
  _write_cache_enable_override: u8,
}

/// `FILE_FS_VOLUME_INFORMATION`'s fixed part and the first unit of the label
/// that follows it, spelled so that any bytes a file system writes are a valid
/// value of it.
///
/// Its `SupportsObjects` is a `BOOLEAN`, which the binding crate types as a
/// Rust `bool` — the validity problem the storage descriptor had: a file
/// system is free to write any non-zero byte for true. It is a byte here and
/// is never read. The label is `label_length` bytes of UTF-16 starting at
/// `label`, inside the same buffer; the laws hold every offset against the
/// binding crate's own struct.
#[repr(C)]
#[derive(Clone, Copy)]
struct FsVolumeInformation {
  _creation_time: i64,
  serial: u32,
  label_length: u32,
  _supports_objects: u8,
  label: [u16; 1],
}

/// `FILE_FS_ATTRIBUTE_INFORMATION`'s fixed part and the first unit of the
/// file-system name that follows it: `name_length` bytes of UTF-16 starting at
/// `name`, inside the same buffer. Every field is an integer.
#[repr(C)]
#[derive(Clone, Copy)]
struct FsAttributeInformation {
  attributes: u32,
  _maximum_component_name_length: i32,
  name_length: u32,
  name: [u16; 1],
}

/// `FILE_FS_FULL_SIZE_INFORMATION`: the volume's size, and what is free to the
/// caller, in allocation units of `sectors_per_unit` sectors of
/// `bytes_per_sector` bytes. Every field is an integer.
#[cfg(any(feature = "disk-usage", test))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsFullSizeInformation {
  total_units: i64,
  caller_available_units: i64,
  _actual_available_units: i64,
  sectors_per_unit: u32,
  bytes_per_sector: u32,
}

/// `FILE_FS_DEVICE_INFORMATION`: the kind of device a volume is on
/// (`FILE_DEVICE_*`) and that device's characteristics (`FILE_REMOVABLE_MEDIA`,
/// `FILE_REMOTE_DEVICE`, …). Every field is an integer.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct FsDeviceInformation {
  device_type: u32,
  characteristics: u32,
}

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
///
/// `removable_media` is the `BOOLEAN` byte as the driver wrote it, compared
/// against zero the way the protocol defines rather than decoded into a Rust
/// `bool` — see [`StorageDeviceDescriptorHead`].
const fn descriptor_says_removable(removable_media: u8, bus: STORAGE_BUS_TYPE) -> bool {
  // Compared rather than matched: these constants are not upper case, and in
  // pattern position the compiler cannot tell a constant from a fresh binding.
  removable_media != 0 || bus == BusTypeUsb || bus == BusTypeSd || bus == BusTypeMmc
}

/// What the three `BOOLEAN` bytes of a hotplug answer say.
///
/// Any non-zero byte is true, which is what the protocol defines and not what a
/// Rust `bool` would accept. All three false is the device having been asked
/// the removal question and having said no — the one road to
/// [`NotEjectable`](super::Ejectability::NotEjectable) anywhere on this
/// platform.
const fn hotplug_answer(
  device_hotplug: u8,
  media_removable: u8,
  media_hotplug: u8,
) -> Ejectability {
  if device_hotplug != 0 || media_removable != 0 || media_hotplug != 0 {
    Ejectability::Ejectable
  } else {
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

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use super::{
    super::{IdentityAssurance, NameReading, VolumeCapabilities, VolumeIdentity},
    *,
  };

  /// The volume GUID path the mount manager gives a mount root, asked the way
  /// the product code never asks it — by the root's name — so that the GUID
  /// read through the one handle has something independent to agree with.
  fn guid_of_root(root: &str) -> String {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;

    let wide = to_wide(Path::new(root));
    let mut buf = [0u16; 64];
    // SAFETY: `wide` is NUL-terminated and `buf` live and as long as declared.
    let ok = unsafe {
      GetVolumeNameForVolumeMountPointW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
    };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    String::from_utf16(&buf[..wide_strlen(&buf)]).unwrap()
  }

  /// The one handle answers every field a row has, on the volume every
  /// Windows runner boots from: the device is the GUID path read through the
  /// handle, and it is the GUID path the mount manager gives that root.
  #[test]
  fn test_the_one_handle_answers_every_field_of_the_root_volume() {
    let resolved = resolve(Path::new("C:\\")).unwrap();
    let mount = resolved.mount_info();
    assert_eq!(
      mount.device().to_str().unwrap(),
      guid_of_root("C:\\"),
      "the GUID path read through the handle is the root's own"
    );
    assert!(!mount.fs_type().is_empty(), "{mount:?}");
    assert!(mount.volume_identity().is_some(), "{mount:?}");
    #[cfg(feature = "disk-usage")]
    assert!(
      mount.total_bytes() > 0 && mount.available_bytes() <= mount.total_bytes(),
      "{mount:?}"
    );

    let canonical = Path::new("C:\\").canonicalize().unwrap();
    let (_, volume) = Volume::of_path(&canonical).unwrap();
    let device = volume
      .read()
      .device()
      .expect("the I/O manager names the device kind");
    assert!(is_local_storage(device), "{device:?}");
    assert!(is_disk(device.device_type), "{device:?}");
  }

  /// NTFS names a volume by its full 64-bit serial on every platform, and the
  /// one handle is what that serial is asked through on this one.
  #[test]
  fn test_the_ntfs_serial_is_read_in_full_through_the_one_handle() {
    let resolved = resolve(Path::new("C:\\")).unwrap();
    let mount = resolved.mount_info();
    if !mount.fs_type().eq_ignore_ascii_case("NTFS") {
      return;
    }
    assert!(
      matches!(
        mount.volume_identity().map(|reading| reading.identity()),
        Some(VolumeIdentity::Serial64(_))
      ),
      "{mount:?}"
    );
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
    let probe = |_volume: &Volume| {
      let now = serial.get();
      // The volume's serial is rewritten between the two reads.
      serial.set(0x5566_7788);
      Observed::fixture(
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

  /// The descriptor answers yes or nothing, and never no — and it answers from
  /// a `BOOLEAN` byte, where **any** non-zero value is true.
  #[test]
  fn test_the_descriptor_says_yes_or_nothing() {
    use windows_sys::Win32::Storage::FileSystem::{BusTypeAta, BusTypeNvme, BusTypeUnknown};

    // A driver is free to answer 0xFF, or 2, for true. A Rust `bool` is not,
    // which is why the byte is compared rather than decoded.
    for truth in [1u8, 2, 0x7f, 0xff] {
      assert!(descriptor_says_removable(truth, BusTypeAta), "{truth:#x}");
    }
    for bus in [BusTypeUsb, BusTypeSd, BusTypeMmc] {
      assert!(descriptor_says_removable(0, bus), "{bus}");
    }
    // Not a denial — a silence. `BusTypeUnknown` and an external enclosure
    // presenting as NVMe are exactly the devices that land here.
    for bus in [BusTypeUnknown, BusTypeAta, BusTypeNvme] {
      assert!(!descriptor_says_removable(0, bus), "{bus}");
    }
  }

  /// The hotplug answer reads three `BOOLEAN` bytes the same way, and all
  /// three false is the one denial this platform can make.
  #[test]
  fn test_the_hotplug_answer_reads_bytes_not_bools() {
    assert_eq!(hotplug_answer(0, 0, 0), Ejectability::NotEjectable);
    for truth in [1u8, 2, 0xff] {
      assert_eq!(hotplug_answer(truth, 0, 0), Ejectability::Ejectable);
      assert_eq!(hotplug_answer(0, truth, 0), Ejectability::Ejectable);
      assert_eq!(hotplug_answer(0, 0, truth), Ejectability::Ejectable);
    }
  }

  /// The mirrors are the shape the driver writes, or they are not mirrors.
  ///
  /// Their whole purpose is to hold the same bytes as the binding crate's
  /// structs while typing the `BOOLEAN` fields as the bytes they are, so every
  /// offset that is read, and the alignment the buffer is chosen for, is
  /// asserted against the real thing.
  #[test]
  fn test_the_raw_mirrors_match_the_structs_they_stand_in_for() {
    use core::mem::{align_of, offset_of, size_of};

    use windows_sys::Win32::System::Ioctl::STORAGE_HOTPLUG_INFO;

    assert_eq!(
      align_of::<StorageDeviceDescriptorHead>(),
      align_of::<STORAGE_DEVICE_DESCRIPTOR>()
    );
    assert!(
      size_of::<StorageDeviceDescriptorHead>() <= size_of::<STORAGE_DEVICE_DESCRIPTOR>(),
      "the mirror covers only the fields read, so it can be no larger"
    );
    assert_eq!(
      offset_of!(StorageDeviceDescriptorHead, removable_media),
      offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia)
    );
    assert_eq!(
      offset_of!(StorageDeviceDescriptorHead, bus_type),
      offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType)
    );

    assert_eq!(
      align_of::<StorageHotplugInfoRaw>(),
      align_of::<STORAGE_HOTPLUG_INFO>()
    );
    assert_eq!(
      size_of::<StorageHotplugInfoRaw>(),
      size_of::<STORAGE_HOTPLUG_INFO>(),
      "this one is sent as the whole buffer, so it must be the whole struct"
    );
    assert_eq!(
      offset_of!(StorageHotplugInfoRaw, size),
      offset_of!(STORAGE_HOTPLUG_INFO, Size)
    );
    assert_eq!(
      offset_of!(StorageHotplugInfoRaw, media_removable),
      offset_of!(STORAGE_HOTPLUG_INFO, MediaRemovable)
    );
    assert_eq!(
      offset_of!(StorageHotplugInfoRaw, media_hotplug),
      offset_of!(STORAGE_HOTPLUG_INFO, MediaHotplug)
    );
    assert_eq!(
      offset_of!(StorageHotplugInfoRaw, device_hotplug),
      offset_of!(STORAGE_HOTPLUG_INFO, DeviceHotplug)
    );
  }

  /// **A device kind never denies.** It says what kind of device a volume is
  /// on, which is not an answer to the removal question, and the invariant
  /// admits no exception for any kind: a network volume, a RAM disk and a kind
  /// this crate does not name are `Unknown`, optical media and a removable
  /// medium are a yes, and only a disk whose medium is fixed asks the device.
  #[test]
  fn test_a_device_kind_never_denies() {
    use windows_sys::Win32::System::Ioctl::{
      FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_DEVICE_VIRTUAL_DISK,
    };

    let kind = |device_type, characteristics| FsDeviceInformation {
      device_type,
      characteristics,
    };
    let unasked = || -> Ejectability { panic!("this kind answers without asking the device") };

    for device in [
      kind(FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_VIRTUAL_DISK, 0),
      kind(0, 0),
      kind(u32::MAX, 0),
    ] {
      assert_eq!(
        ejectability_of(device, unasked),
        Ejectability::Unknown,
        "{device:?}"
      );
    }
    for device in [
      kind(FILE_DEVICE_CD_ROM, 0),
      kind(FILE_DEVICE_DVD, 0),
      kind(FILE_DEVICE_CD_ROM_FILE_SYSTEM, 0),
      kind(FILE_DEVICE_DISK, FILE_REMOVABLE_MEDIA),
    ] {
      assert_eq!(
        ejectability_of(device, unasked),
        Ejectability::Ejectable,
        "{device:?}"
      );
    }
    // A disk whose medium is fixed in it — an external USB disk among them —
    // asks the device, and what the device says is the answer.
    for answer in [Ejectability::Ejectable, Ejectability::Unknown] {
      assert_eq!(
        ejectability_of(kind(FILE_DEVICE_DISK, 0), || answer),
        answer
      );
    }
  }

  /// The `FILE_FS_*` mirrors are the shape the file system writes, or they are
  /// not mirrors: every offset read, and every alignment a buffer is chosen
  /// for, is asserted against the binding crate's own structs, and the two
  /// characteristics this crate spells itself against the binding's.
  #[test]
  fn test_the_volume_information_mirrors_match_the_structs_they_stand_in_for() {
    use core::mem::{align_of, offset_of, size_of};

    use windows_sys::Wdk::{
      Storage::FileSystem::FILE_FS_ATTRIBUTE_INFORMATION,
      System::SystemServices::{
        FILE_FS_DEVICE_INFORMATION, FILE_FS_FULL_SIZE_INFORMATION, FILE_FS_VOLUME_INFORMATION,
        FILE_REMOTE_DEVICE as REMOTE, FILE_REMOVABLE_MEDIA as REMOVABLE,
      },
    };

    assert_eq!(FILE_REMOVABLE_MEDIA, REMOVABLE);
    assert_eq!(FILE_REMOTE_DEVICE, REMOTE);

    assert_eq!(
      align_of::<FsVolumeInformation>(),
      align_of::<FILE_FS_VOLUME_INFORMATION>()
    );
    assert_eq!(
      size_of::<FsVolumeInformation>(),
      size_of::<FILE_FS_VOLUME_INFORMATION>()
    );
    assert_eq!(
      offset_of!(FsVolumeInformation, serial),
      offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeSerialNumber)
    );
    assert_eq!(
      offset_of!(FsVolumeInformation, label_length),
      offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeLabelLength)
    );
    assert_eq!(
      offset_of!(FsVolumeInformation, label),
      offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeLabel)
    );

    assert_eq!(
      align_of::<FsAttributeInformation>(),
      align_of::<FILE_FS_ATTRIBUTE_INFORMATION>()
    );
    assert_eq!(
      size_of::<FsAttributeInformation>(),
      size_of::<FILE_FS_ATTRIBUTE_INFORMATION>()
    );
    assert_eq!(
      offset_of!(FsAttributeInformation, attributes),
      offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemAttributes)
    );
    assert_eq!(
      offset_of!(FsAttributeInformation, name_length),
      offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemNameLength)
    );
    assert_eq!(
      offset_of!(FsAttributeInformation, name),
      offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)
    );

    assert_eq!(
      align_of::<FsFullSizeInformation>(),
      align_of::<FILE_FS_FULL_SIZE_INFORMATION>()
    );
    assert_eq!(
      size_of::<FsFullSizeInformation>(),
      size_of::<FILE_FS_FULL_SIZE_INFORMATION>()
    );
    assert_eq!(
      offset_of!(FsFullSizeInformation, total_units),
      offset_of!(FILE_FS_FULL_SIZE_INFORMATION, TotalAllocationUnits)
    );
    assert_eq!(
      offset_of!(FsFullSizeInformation, caller_available_units),
      offset_of!(
        FILE_FS_FULL_SIZE_INFORMATION,
        CallerAvailableAllocationUnits
      )
    );
    assert_eq!(
      offset_of!(FsFullSizeInformation, sectors_per_unit),
      offset_of!(FILE_FS_FULL_SIZE_INFORMATION, SectorsPerAllocationUnit)
    );
    assert_eq!(
      offset_of!(FsFullSizeInformation, bytes_per_sector),
      offset_of!(FILE_FS_FULL_SIZE_INFORMATION, BytesPerSector)
    );

    assert_eq!(
      size_of::<FsDeviceInformation>(),
      size_of::<FILE_FS_DEVICE_INFORMATION>()
    );
    assert_eq!(
      offset_of!(FsDeviceInformation, device_type),
      offset_of!(FILE_FS_DEVICE_INFORMATION, DeviceType)
    );
    assert_eq!(
      offset_of!(FsDeviceInformation, characteristics),
      offset_of!(FILE_FS_DEVICE_INFORMATION, Characteristics)
    );
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
