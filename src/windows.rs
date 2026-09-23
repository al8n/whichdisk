//! Windows: every value in a row is read through one handle on its volume.
//!
//! **An observation is formed once, from one native identity, and a row is
//! built from nothing else.** A resolve finds its path's mount root once
//! (`GetVolumePathNameW`) and opens **one handle** on that root directory; a
//! listing opens its handle through the volume GUID path the enumeration
//! named. Every fact of a row is then read through that one handle, inside
//! [`observed`], and stored in the [`Observation`]: the serial and the label
//! (`FileFsVolumeInformation`), the file-system name and flags
//! (`FileFsAttributeInformation`), the capacity (`FileFsFullSizeInformation`)
//! and the kind of device the volume is on (`FileFsDeviceInformation`), all
//! with `NtQueryVolumeInformationFile`, the full NTFS serial with
//! `FSCTL_GET_NTFS_VOLUME_DATA`, and the volume GUID path with
//! `GetFinalPathNameByHandleW` (`VOLUME_NAME_GUID`). The observation owns the
//! handle and the paths the volume is mounted at — a resolve's one mount root,
//! and a listing's mount points, asked of the mount manager while the handle
//! is held — and a row is built by [`Observation::into_rows`], which takes the
//! observation by value, for each of its own paths and for nothing else.
//! Finding a mount root, opening a handle and naming a volume are private to
//! [`observed`], so no row road can do any of them again, and no path, GUID or
//! field can be handed to a row from outside it.
//!
//! **A handle is accepted only once it is proven to hold a root, and no fact
//! is read before.** A resolve finds its mount root by name, and a name is
//! resolved again by the open: a volume mounted in a folder that leaves in
//! between uncovers the folder, and the open lands on the directory of the
//! volume beneath. So the handle is asked where it is, and its final path
//! must be exactly a volume GUID root — `\\?\Volume{GUID}\` with nothing
//! after it, through the one parser every volume root goes through, which the
//! enumeration's roots go through too — or, for a network share, which has no
//! GUID path, exactly the share's root. Anything else is declined, like a
//! volume that has gone.
//!
//! The handle is the volume's root directory, opened for no access at all. A
//! handle on the volume device itself would not do: opened without read
//! access, which is all an unelevated process is granted there, it is a
//! direct device open that the file system never sees, so nothing but the
//! device kind is answered through it.
//!
//! **Every platform read answers one of four outcomes** — a value, the
//! platform's own "there is none", a decline [`declined`] names, or a failure
//! — and no two are merged except where a caller names what each means: see
//! [`Reading`]. The volume enumeration is a census, complete or refused, and
//! every answer the platform writes is decoded whole or not at all, **out of
//! the bytes it said it wrote and nothing else**: a count past the buffer, an
//! answer short of its fixed part, a string whose length is odd or runs past
//! the answer, a multi-string that does not end exactly where its reported
//! length does, a path or a name that is not UTF-16 text — each fails its read
//! with `InvalidData`, and none is ever an absence; a label that is not text
//! is kept as the platform wrote it — see [`filled`](super::filled),
//! [`wide_text`] and [`multi_string`]. What each road answers, and the
//! documentation that names it:
//!
//! | Road | Absent | Declined, and what it becomes | Documentation |
//! |---|---|---|---|
//! | the path's mount root, `GetVolumePathNameW` | — | the resolve's error | *GetVolumePathNameW*: "If the function fails, the return value is zero. To get extended error information, call GetLastError." |
//! | the one handle, `CreateFileW` on the root directory | — | a resolve's error; a listing does not report the volume | *CreateFileW*; the codes in *System Error Codes* |
//! | the root the handle holds, `GetFinalPathNameByHandleW` with `VOLUME_NAME_GUID` | `ERROR_PATH_NOT_FOUND`, for a volume with no GUID path: the share's root is then asked with `VOLUME_NAME_DOS`, and the device is the mount point | a path that is not exactly a volume root, or a share's root: the observation is declined | *GetFinalPathNameByHandleW*: "Volume GUID paths are not created for network shares" |
//! | serial and label, `FileFsVolumeInformation` | a zero serial, an empty label | the volume did not answer for itself: nothing else is asked of it, a resolve reports none of its fields and a listing does not report it | *NtQueryVolumeInformationFile*, whose `NTSTATUS` is the system error *RtlNtStatusToDosError* names |
//! | file-system name and flags, `FileFsAttributeInformation` | — | no file-system type, no case flags, and no identity: a serial is an identity only in the spelling the file system's type gives it | the same |
//! | capacity, `FileFsFullSizeInformation` | — | zero | the same |
//! | device kind, `FileFsDeviceInformation` | — | removal `Unknown`; a listing does not report the volume | the same |
//! | full NTFS serial, `FSCTL_GET_NTFS_VOLUME_DATA` | — | the documented 32-bit serial | *DeviceIoControl*; the codes in *System Error Codes* |
//! | mount points, `GetVolumePathNamesForVolumeNameW` | — | the volume is not reported | *GetVolumePathNamesForVolumeNameW*: "If the buffer is not large enough to hold the complete list, the function fails and GetLastError returns ERROR_MORE_DATA", which is asked again at the length it names |
//! | volume census, `FindFirstVolumeW` / `FindNextVolumeW` | — | the listing is refused | *FindNextVolumeW*: "If no matching files can be found, the GetLastError function returns the ERROR_NO_MORE_FILES error code" — the census's proven end |
//!
//! Every failure — any code [`declined`] does not name — is the error it is:
//! a resolve's, or a listing's.
//!
//! **The removal question has the device kind's answer alone.** Optical media
//! and a device whose medium comes out of it (`FILE_REMOVABLE_MEDIA`) are a
//! yes, and every disk whose medium is fixed in it — an external USB disk
//! among them — is `Unknown`. The storage control codes that could say more,
//! `IOCTL_STORAGE_QUERY_PROPERTY` and `IOCTL_STORAGE_GET_HOTPLUG_INFO`, are
//! device controls, which NTFS and FAT service only on a volume open: on the
//! root directory they decline them with `ERROR_INVALID_PARAMETER` (FastFAT's
//! `FatCommonDeviceControl` in Microsoft's driver samples; NTFS measured on a
//! runner's system volume). A volume open needs read access to the volume,
//! which an unelevated process is not granted, and a second handle would be a
//! second resolution of the volume. So neither is asked: an answer that
//! depended on which file-system driver happened to service a device control
//! on a directory would claim more than this handle can vouch for.

use std::{
  io,
  os::windows::ffi::OsStrExt as _,
  path::{Path, PathBuf},
};

use windows_sys::Win32::{
  Storage::FileSystem::{FILE_DEVICE_CD_ROM, FILE_DEVICE_DISK, FILE_DEVICE_DVD},
  System::Ioctl::{FILE_DEVICE_CD_ROM_FILE_SYSTEM, FILE_DEVICE_DISK_FILE_SYSTEM},
};

#[cfg(feature = "list")]
use windows_sys::Win32::Storage::FileSystem::{FindFirstVolumeW, FindNextVolumeW, FindVolumeClose};

#[cfg(feature = "list")]
use super::reading::Census;
use super::{Ejectability, reading::Reading};

use observed::Observation;

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

/// Whether a failed read is the platform declining to answer, rather than the
/// read itself failing.
///
/// Every platform read on this backend is sorted by this set into the four
/// outcomes of a [`Reading`] — see [`reading`] — and every road that reports a
/// value with no "could not tell" of its own — the identity, the label, the
/// case flags, a capacity, a listing row — ends in its documented absence on
/// these failures, and on nothing else. Each code is named, with the meaning
/// quoted here, in Microsoft's *System Error Codes* reference; which road
/// answers which is in the module's table. A status an NT call returns is
/// first turned into the system error it names, by `RtlNtStatusToDosError`.
///
/// - **not there**: `ERROR_FILE_NOT_FOUND` (2) "The system cannot find the
///   file specified", `ERROR_PATH_NOT_FOUND` (3) "The system cannot find the
///   path specified", and `ERROR_DEV_NOT_EXIST` (55) "The specified network
///   resource or device is no longer available";
/// - **no volume there to ask**: `ERROR_NOT_READY` (21) "The device is not
///   ready" — a drive with no medium in it, or a volume dismounted under a
///   held handle; `ERROR_UNRECOGNIZED_VOLUME` (1005) "The volume does not
///   contain a recognized file system"; and `ERROR_FILE_INVALID` (1006) "The
///   volume for a file has been externally altered so that the opened file is
///   no longer valid" — a volume that left while a handle was held;
/// - **may not look**: `ERROR_ACCESS_DENIED` (5) "Access is denied";
/// - **not serviced on this handle**: `ERROR_INVALID_FUNCTION` (1) "Incorrect
///   function" — the code of `STATUS_INVALID_DEVICE_REQUEST`, which a driver
///   answers for a request it does not service; `ERROR_NOT_SUPPORTED` (50)
///   "The request is not supported"; and `ERROR_INVALID_PARAMETER` (87) "The
///   parameter is incorrect" — the code of `STATUS_INVALID_PARAMETER`, which
///   FastFAT (Microsoft's `Windows-driver-samples`, `FatCommonDeviceControl`)
///   answers for a device control on anything but a volume open.
///
/// Anything else — no memory, an I/O error, an answer larger than the buffer
/// it was given — is a failure of the read, says nothing about the volume, and
/// is returned as the error it is.
fn declined(err: &io::Error) -> bool {
  use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_DEV_NOT_EXIST, ERROR_FILE_INVALID, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_READY, ERROR_NOT_SUPPORTED,
    ERROR_PATH_NOT_FOUND, ERROR_UNRECOGNIZED_VOLUME,
  };

  const DECLINES: [u32; 10] = [
    ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND,
    ERROR_DEV_NOT_EXIST,
    ERROR_NOT_READY,
    ERROR_UNRECOGNIZED_VOLUME,
    ERROR_FILE_INVALID,
    ERROR_ACCESS_DENIED,
    ERROR_INVALID_FUNCTION,
    ERROR_NOT_SUPPORTED,
    ERROR_INVALID_PARAMETER,
  ];
  err
    .raw_os_error()
    .and_then(|code| u32::try_from(code).ok())
    .is_some_and(|code| DECLINES.contains(&code))
}

/// Sorts what a platform call on this backend returned by [`declined`], into
/// the four outcomes every read here answers: see [`Reading`].
fn reading<T>(read: io::Result<T>) -> Reading<T> {
  Reading::sort(read, declined)
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

#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn resolve(path: &Path) -> io::Result<Inner> {
  resolve_with(path, Observation::of_path)
}

/// The body of [`resolve`], with the forming of the observation as a
/// parameter.
///
/// Nothing here is cached, so what a resolve reports is whatever the volume
/// answered on this call — and that is a claim a test has to be able to break.
/// No test can rewrite a real volume's serial (the tools that do it work
/// offline, on an unmounted volume), so a test forms the observation of a real
/// path with a changing volume's facts standing in for the ones the handle
/// would read. See `test_the_identity_is_read_on_every_resolve`.
fn resolve_with(
  path: &Path,
  observe: impl FnOnce(&Path) -> Reading<Observation>,
) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;

  // The path's mount root, found once, the one handle opened on it, and every
  // fact of the row read through that handle: see [`observed`]. A resolve has
  // nothing to report without it, so every outcome but an observation is the
  // resolve's error.
  //
  // Asked on every resolve, and never remembered — the same law Apple and
  // Linux follow, reached here for a reason of its own. The volume GUID names
  // *storage*, which is durable; the serial is a value in the filesystem
  // written onto that storage, and an offline tool can rewrite it while the
  // GUID stays put. A key that outlives what it is supposed to vouch for
  // cannot vouch for it, so nothing is stored under it.
  let observation = observe(&canonical).required()?;
  let relative_path = observation.relative_path(&canonical);
  let mount = observation.into_rows().next().ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::NotFound,
      "the observation of a resolve holds no mount root",
    )
  })?;

  Ok(Inner {
    mount,
    canonical,
    relative_path,
  })
}

/// Every volume the mount manager enumerates, each described by one
/// observation of its own.
///
/// **A row is one observation, exactly as a resolve's is.** Each volume is
/// opened once, through the volume root the enumeration named; the handle
/// must name itself by that root before anything is read through it; its
/// mount points and every field of its rows are read while that handle holds
/// it — and the volume must then name itself by the same root again, so mount
/// points the mount manager gave for a name that moved to another volume are
/// never paired with this one. The
/// rows are built by [`Observation::into_rows`], one for each of the
/// observation's own mount points. A volume that cannot be opened — no medium
/// in the drive, no file system on it, gone — has nothing to describe and is
/// not listed.
///
/// **The enumeration is a census, complete or refused**: it ends only where
/// `FindNextVolumeW` proves it did, and any other failure of it refuses the
/// listing. See [`volume_census`].
#[cfg(feature = "list")]
pub(super) fn list(opts: super::ListOptions) -> io::Result<Vec<super::MountPoint>> {
  let mut mounts = Vec::new();

  for guid in volume_census().required()? {
    let observation = match Observation::named(guid) {
      Reading::Value(observation) => observation,
      // Nothing to describe: no medium, no file system, gone, renamed, or not
      // ours to open. A failed read is the error it is.
      Reading::Absent | Reading::Declined(_) => continue,
      Reading::Failed(err) => return Err(err),
    };
    // Mounted somewhere, answering for itself, and local storage: see
    // [`Observation::is_listed`].
    if !observation.is_listed() {
      continue;
    }
    // Classified first, filtered after: an exact-state filter cannot be
    // applied to a state that has not been worked out yet.
    if opts.excludes(observation.ejectability()) {
      continue;
    }
    mounts.extend(observation.into_rows());
  }
  Ok(mounts)
}

/// One observation of one volume, and the only place a row's volume is found,
/// opened or named, and the only place a fact of a row is read.
///
/// **The observation is one handle, the GUID path it names, the paths the
/// volume is mounted at, and every fact the handle answered.** The handle is
/// opened once and every fact is read through it, so no two fields of a row
/// can describe two volumes: a drive letter is a slot whose occupant can
/// change between two calls, and a volume GUID path, which names one volume
/// for its life, is also a name a clone of that volume is given once the
/// original has gone. Neither is resolved again once the handle is open, and
/// the observation keeps the handle for as long as it is kept.
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
        Ioctl::{FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER},
      },
    },
  };

  #[cfg(feature = "disk-usage")]
  use {super::fs_full_size, windows_sys::Wdk::Storage::FileSystem::FileFsFullSizeInformation};
  #[cfg(feature = "list")]
  use {
    super::{is_local_storage, multi_string},
    windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW,
  };

  use super::{
    super::{
      Ejectability, IdentityAssurance, IdentityReading, MountPoint, NameReading, SmallBytes,
      VolumeCapabilities,
      filled::{Filled, KernelBuffer, invalid},
      published_label, published_label_bytes,
      reading::Reading,
      windows_identity,
    },
    FILE_CASE_PRESERVED_NAMES, FsDeviceInformation, VolumeRoot, ejectability_of, fs_attribute,
    fs_device, fs_volume, is_share_root, reading, terminated, to_wide, wide_text,
  };

  /// One volume, observed through one handle: everything every row of it is
  /// built from.
  pub(super) struct Observation {
    /// The handle every fact below was read through, held for as long as the
    /// observation is.
    _root: File,
    /// `\\?\Volume{GUID}\`, as the volume named itself through the handle,
    /// or `None` for a volume that has none — a network share, for which
    /// volume GUID paths are not created, whose handle was proven to hold the
    /// share's root instead: see [`proven_root`].
    guid: Option<VolumeRoot>,
    /// The paths this volume is mounted at, as this observation found them: a
    /// resolve's one mount root, which the handle was opened on, and a
    /// listing's mount points, asked of the mount manager while the handle was
    /// held. A row is built for each of these and for nothing else.
    mount_paths: Vec<String>,
    facts: Facts,
  }

  /// Everything one handle answered about its volume: every field but the
  /// mount point of every row that volume has.
  pub(super) struct Facts {
    /// Whether the volume answered `FileFsVolumeInformation` for itself
    /// through the handle, which a listing requires.
    #[cfg_attr(not(feature = "list"), allow(dead_code))]
    answered_for_itself: bool,
    /// The device kind, which a listing asks again, to decide whether it
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

  impl Observation {
    /// A resolve's observation: the mount root of `canonical`, found once,
    /// the one handle opened on it, **the root that handle is proven to hold**
    /// — the GUID path the volume names itself by through it, or, for a
    /// network share, the share's root — and every fact the handle answers,
    /// read only after that proof. A handle that holds no root is declined,
    /// and nothing is read through it: see [`proven_root`]. A share is
    /// observed with the mount root as its device. A mount root that is not
    /// UTF-16 text is no path a row can spell, and fails the read.
    pub(super) fn of_path(canonical: &Path) -> Reading<Self> {
      Self::of_path_reading(canonical, Facts::read)
    }

    /// [`of_path`](Self::of_path), with the facts a law stands in for the
    /// ones the handle would answer.
    #[cfg(test)]
    pub(super) fn of_path_with(
      canonical: &Path,
      read: impl FnOnce(&File) -> io::Result<Facts>,
    ) -> Reading<Self> {
      Self::of_path_reading(canonical, read)
    }

    fn of_path_reading(
      canonical: &Path,
      read: impl FnOnce(&File) -> io::Result<Facts>,
    ) -> Reading<Self> {
      volume_path_name(canonical).and_then(|root| {
        let Some(mount_point) = root.to_str().map(str::to_owned) else {
          return Reading::Failed(io::Error::new(
            io::ErrorKind::InvalidData,
            "a mount root that is not UTF-16 text",
          ));
        };
        open_root(&root).and_then(|handle| {
          proven_root(&handle).and_then(|guid| match read(&handle) {
            Ok(facts) => Reading::Value(Self {
              _root: handle,
              guid,
              mount_paths: vec![mount_point],
              facts,
            }),
            Err(err) => Reading::Failed(err),
          })
        })
      })
    }

    /// A listing's observation: the one handle, opened through the volume root
    /// the enumeration named, **proven to hold that root before anything is
    /// read through it**; every path the volume is mounted at, asked of the
    /// mount manager while the handle holds the volume; every fact the handle
    /// answers, read after them; and, last, the root proven again.
    ///
    /// **The proof is the handle naming itself**, through its own final path,
    /// by exactly the census's volume root — parsed by the one parser every
    /// volume root goes through, [`VolumeRoot::parse`], and compared by GUID.
    /// Made first, it shows the handle holds that volume's root and no folder
    /// of another; made again last, it binds the mount points to the handle:
    /// they are asked of the mount manager by name, and a name is not a
    /// handle, so the volume still naming itself by the same root after they
    /// were read shows the name was its own while they were asked for. A
    /// volume that names itself by any other path — another volume's root, a
    /// folder beneath one, or none — is declined, like a volume that has gone.
    #[cfg(feature = "list")]
    pub(super) fn named(guid: VolumeRoot) -> Reading<Self> {
      open_root(Path::new(guid.as_str())).and_then(|handle| {
        holds_root(&handle, &guid)
          .and_then(|()| mount_paths(&guid))
          .and_then(|mount_paths| {
            // Mounted nowhere: the mount manager's own answer that there is
            // no row of this volume to describe, so nothing else is asked of
            // it.
            if mount_paths.is_empty() {
              return Reading::Absent;
            }
            let facts = match Facts::read(&handle) {
              Ok(facts) => facts,
              Err(err) => return Reading::Failed(err),
            };
            holds_root(&handle, &guid).and_then(|()| {
              Reading::Value(Self {
                _root: handle,
                guid: Some(guid),
                mount_paths,
                facts,
              })
            })
          })
      })
    }

    /// What the volume's storage says about leaving the machine, which a
    /// listing's exact-state filters ask before the rows are built.
    #[cfg(feature = "list")]
    pub(super) fn ejectability(&self) -> Ejectability {
      self.facts.ejectability
    }

    /// Whether a listing reports the volume: answering
    /// `FileFsVolumeInformation` for itself through the handle, and local
    /// storage — a disk or an optical drive, as the device kind says. A
    /// listing's observation is mounted somewhere by construction: see
    /// [`named`](Self::named).
    #[cfg(feature = "list")]
    pub(super) fn is_listed(&self) -> bool {
      self.facts.answered_for_itself && self.facts.device.is_some_and(is_local_storage)
    }

    /// Where `canonical` lies beneath the mount root this observation was
    /// formed from, or nothing where it does not.
    pub(super) fn relative_path(&self, canonical: &Path) -> PathBuf {
      // strip_prefix handles Windows path semantics (case, separators).
      self
        .mount_paths
        .first()
        .and_then(|root| canonical.strip_prefix(root).ok())
        .map(Path::to_path_buf)
        .unwrap_or_default()
    }

    /// Every row of the volume, one for each path this observation found it
    /// mounted at, and every field of each out of this one observation, which
    /// it takes by value and is given nothing beside. The device is the volume
    /// GUID path, or, for a volume that has none, the mount point itself.
    pub(super) fn into_rows(self) -> impl Iterator<Item = MountPoint> {
      let Self {
        guid,
        mount_paths,
        facts,
        ..
      } = self;
      mount_paths.into_iter().map(move |path| {
        let mount_point = SmallBytes::from_bytes(path.as_bytes());
        MountPoint {
          device: match &guid {
            Some(guid) => SmallBytes::from_bytes(guid.as_str().as_bytes()),
            None => mount_point.clone(),
          },
          mount_point,
          ejectability: facts.ejectability,
          capabilities: facts.capabilities.clone(),
          volume_identity: facts.identity,
          volume_name: facts.name.clone(),
          #[cfg(feature = "disk-usage")]
          total_bytes: facts.capacity.0,
          #[cfg(feature = "disk-usage")]
          available_bytes: facts.capacity.1,
        }
      })
    }

    /// The device kind the file system reported, for the laws.
    #[cfg(test)]
    pub(super) fn device(&self) -> Option<FsDeviceInformation> {
      self.facts.device
    }
  }

  impl Facts {
    /// Every fact of the volume's rows, read through the one handle.
    ///
    /// The volume is asked to answer for itself first
    /// (`FileFsVolumeInformation`, which every file system serves). Where it
    /// declines — no medium, gone, not ours to look at — nothing else is asked
    /// of it, and the facts carry none of what it would have said. Past that,
    /// each field's decline ends in that field's documented absence and each
    /// failure is the error it is. The removal answer is the device kind's
    /// alone: see [`ejectability_of`].
    fn read(root: &File) -> io::Result<Self> {
      let (serial, label) = match volume_information(root) {
        Reading::Value(volume) => volume,
        Reading::Absent | Reading::Declined(_) => return Ok(Self::unanswered()),
        Reading::Failed(err) => return Err(err),
      };
      let attributes = attributes(root).answered()?;
      let fs_type = attributes.as_ref().map_or("", |(_, name)| name.as_str());
      // `case_sensitive` follows the filesystem-type default; `case_preserving`
      // comes from the accurate `FILE_CASE_PRESERVED_NAMES` flag, overriding
      // the type-derived value.
      let mut capabilities = VolumeCapabilities::from_fs_type_defaults(fs_type.as_bytes());
      if let Some((flags, _)) = &attributes {
        capabilities.case_preserving = Some(flags & FILE_CASE_PRESERVED_NAMES != 0);
      }
      // The full serial where NTFS answers it through the handle; where it
      // declines, the 32-bit serial the volume information carries, which is
      // the documented narrowing.
      let ntfs_serial = if fs_type.eq_ignore_ascii_case("NTFS") {
        ntfs_serial(root).answered()?
      } else {
        None
      };
      // A serial is an identity only in the spelling the file system's type
      // gives it — NTFS's in full, exFAT's as the UUID derived from it, FAT's
      // as it stands — so a volume that named no file system names no
      // identity: read in the wrong spelling, an NTFS volume's low half would
      // pass for a whole 32-bit identity.
      let identity = if fs_type.is_empty() {
        None
      } else {
        windows_identity(fs_type.as_bytes(), serial, ntfs_serial)
      };
      // A label is kept as the volume wrote it: text where it is text, and the
      // units themselves where it is not, so that a label the volume does
      // carry is never reported as none.
      let name = label.and_then(|label| match label.into_string() {
        Ok(text) => published_label(&text, IdentityAssurance::Vouched),
        Err(units) => published_label_bytes(units.as_encoded_bytes(), IdentityAssurance::Vouched),
      });
      let device = device(root).answered()?;
      // The kind of device alone: see [`ejectability_of`]. Where the kind was
      // not named, nothing was said about removal.
      let ejectability = device.map_or(Ejectability::Unknown, ejectability_of);
      // A volume that declined to say how large it is has no capacity to
      // report, which is zero; a read that failed was returned above.
      #[cfg(feature = "disk-usage")]
      let capacity = full_size(root).answered()?.unwrap_or_default();
      Ok(Self {
        answered_for_itself: true,
        device,
        ejectability,
        capabilities,
        identity,
        name,
        #[cfg(feature = "disk-usage")]
        capacity,
      })
    }

    /// A volume that declined to answer for itself: nothing it would have
    /// said — no identity, no label, no file-system type, no capacity, and
    /// removal `Unknown`.
    fn unanswered() -> Self {
      Self {
        answered_for_itself: false,
        device: None,
        ejectability: Ejectability::Unknown,
        capabilities: VolumeCapabilities::from_fs_type_defaults(b""),
        identity: None,
        name: None,
        #[cfg(feature = "disk-usage")]
        capacity: (0, 0),
      }
    }

    /// Facts a law stands in for a volume's.
    #[cfg(test)]
    pub(super) fn fixture(
      capabilities: VolumeCapabilities,
      identity: Option<IdentityReading>,
      name: Option<NameReading>,
    ) -> Self {
      Self {
        answered_for_itself: true,
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

  /// One `NtQueryVolumeInformationFile` of `class` into the caller's own
  /// buffer, answering **only the bytes the file system said it wrote**. A
  /// status that is not success is the system error `RtlNtStatusToDosError`
  /// names for it, sorted.
  ///
  /// The count the file system reports in `IO_STATUS_BLOCK.Information` is
  /// checked against the buffer before anything is read: a count past it is
  /// no answer about it, and is `Failed(InvalidData)`. What comes back is a
  /// [`Filled`] view of exactly that many bytes, so a decoder can read
  /// nothing the file system did not write: see [`filled`](super::super::filled).
  fn query<'b, const N: usize>(
    root: &File,
    class: FS_INFORMATION_CLASS,
    buffer: &'b mut KernelBuffer<N>,
  ) -> Reading<Filled<'b>> {
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is valid for as long as `root` is borrowed, `status`
    // is a live status block, and `buffer` an exclusive borrow of exactly
    // `LEN` bytes, which the file system writes no further than; a
    // `KernelBuffer` is bytes alone, so whatever it writes, or leaves, is a
    // value.
    let nt = unsafe {
      NtQueryVolumeInformationFile(
        root.as_raw_handle(),
        &mut status,
        buffer.as_mut_ptr(),
        KernelBuffer::<N>::LEN as u32,
        class,
      )
    };
    if nt < 0 {
      // SAFETY: a pure conversion of a status code.
      let code = unsafe { RtlNtStatusToDosError(nt) };
      return reading(Err(io::Error::from_raw_os_error(code as i32)));
    }
    let buffer: &'b KernelBuffer<N> = buffer;
    decoded(buffer.filled(status.Information))
  }

  /// A decode's outcome as a read's: the value, or `Failed` with the
  /// `InvalidData` that says what the platform wrote that it could not have.
  fn decoded<T>(decode: io::Result<T>) -> Reading<T> {
    match decode {
      Ok(value) => Reading::Value(value),
      Err(err) => Reading::Failed(err),
    }
  }

  /// The volume's serial and its label: `FileFsVolumeInformation`.
  ///
  /// The label follows the fixed part in the same answer, `label_length`
  /// bytes of UTF-16; both are read out of the bytes the file system said it
  /// wrote and nothing else, and kept as the units the volume wrote — see
  /// [`Facts::read`] for what a label that is not text becomes. An empty label
  /// is no label. An answer short of the fixed part, a label length that is
  /// odd or runs past the answer, is none the file system writes, and is
  /// `Failed(InvalidData)`.
  fn volume_information(root: &File) -> Reading<(u32, Option<OsString>)> {
    let mut buffer = KernelBuffer::<576>::new();
    query(root, FileFsVolumeInformation, &mut buffer).and_then(|answer| decoded(volume_in(answer)))
  }

  /// The serial and the label out of a `FileFsVolumeInformation` answer.
  fn volume_in(answer: Filled<'_>) -> io::Result<(u32, Option<OsString>)> {
    let serial = answer.u32_at(fs_volume::SERIAL)?;
    let label_length = answer.u32_at(fs_volume::LABEL_LENGTH)?;
    let units = units(answer.bytes(fs_volume::LABEL, label_length as usize)?)?;
    let label = (!units.is_empty()).then(|| OsString::from_wide(&units));
    Ok((serial, label))
  }

  /// The file system's name and its attribute flags:
  /// `FileFsAttributeInformation`. The name follows the fixed part in the
  /// same answer and is read the same way the label is, and decoded whole —
  /// see [`wide_text`]; an answer short of the fixed part, a name length that
  /// is odd or runs past the answer, or a name that is not UTF-16 text is
  /// `Failed(InvalidData)`.
  fn attributes(root: &File) -> Reading<(u32, String)> {
    let mut buffer = KernelBuffer::<544>::new();
    query(root, FileFsAttributeInformation, &mut buffer)
      .and_then(|answer| decoded(attributes_in(answer)))
  }

  /// The flags and the name out of a `FileFsAttributeInformation` answer.
  fn attributes_in(answer: Filled<'_>) -> io::Result<(u32, String)> {
    let flags = answer.u32_at(fs_attribute::ATTRIBUTES)?;
    let name_length = answer.u32_at(fs_attribute::NAME_LENGTH)?;
    let name = wide_text(&units(
      answer.bytes(fs_attribute::NAME, name_length as usize)?,
    )?)?;
    Ok((flags, name))
  }

  /// The volume's capacity, as `(total, available to this caller)` bytes:
  /// `FileFsFullSizeInformation`, in allocation units of the size it names.
  /// An answer short of the whole structure, or a negative count of units, is
  /// none the file system writes, and is `Failed(InvalidData)`.
  #[cfg(feature = "disk-usage")]
  fn full_size(root: &File) -> Reading<(u64, u64)> {
    let mut buffer = KernelBuffer::<{ fs_full_size::LEN }>::new();
    query(root, FileFsFullSizeInformation, &mut buffer)
      .and_then(|answer| decoded(full_size_in(answer)))
  }

  /// The capacity out of a `FileFsFullSizeInformation` answer.
  #[cfg(feature = "disk-usage")]
  fn full_size_in(answer: Filled<'_>) -> io::Result<(u64, u64)> {
    if answer.len() < fs_full_size::LEN {
      return Err(invalid("a full-size answer short of the structure"));
    }
    let unit = u64::from(answer.u32_at(fs_full_size::SECTORS_PER_UNIT)?)
      .saturating_mul(u64::from(answer.u32_at(fs_full_size::BYTES_PER_SECTOR)?));
    let units = |at| {
      answer.i64_at(at).and_then(|units| {
        u64::try_from(units).map_err(|_| invalid("a negative count of allocation units"))
      })
    };
    let total = units(fs_full_size::TOTAL_UNITS)?;
    let available = units(fs_full_size::CALLER_AVAILABLE_UNITS)?;
    Ok((total.saturating_mul(unit), available.saturating_mul(unit)))
  }

  /// The kind of device the volume is on and its characteristics:
  /// `FileFsDeviceInformation`, which the I/O manager answers itself, from
  /// the device object the handle was opened through. An answer short of the
  /// structure is `Failed(InvalidData)`.
  fn device(root: &File) -> Reading<FsDeviceInformation> {
    let mut buffer = KernelBuffer::<{ fs_device::LEN }>::new();
    query(root, FileFsDeviceInformation, &mut buffer).and_then(|answer| decoded(device_in(answer)))
  }

  /// The device kind out of a `FileFsDeviceInformation` answer.
  fn device_in(answer: Filled<'_>) -> io::Result<FsDeviceInformation> {
    Ok(FsDeviceInformation {
      device_type: answer.u32_at(fs_device::DEVICE_TYPE)?,
      characteristics: answer.u32_at(fs_device::CHARACTERISTICS)?,
    })
  }

  /// The volume's full 64-bit NTFS serial, with `FSCTL_GET_NTFS_VOLUME_DATA`
  /// on the one handle.
  ///
  /// This is the same number Linux publishes under `/dev/disk/by-uuid` as
  /// sixteen hex digits; `FileFsVolumeInformation` reports only its low
  /// half. The control code is declared `FILE_ANY_ACCESS`, so the handle
  /// needs no access to ask it. The count the call reports is checked against
  /// the buffer, and an answer short of the whole `NTFS_VOLUME_DATA_BUFFER` —
  /// which NTFS writes in full or fails — is `Failed(InvalidData)`.
  fn ntfs_serial(root: &File) -> Reading<u64> {
    const LEN: usize = core::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>();

    let mut buffer = KernelBuffer::<LEN>::new();
    let mut written: u32 = 0;
    // SAFETY: `buffer` is a live output buffer of exactly `LEN` bytes, aligned
    // for the structure the control code writes, `written` a live count, and
    // the handle is valid for as long as `root` is borrowed.
    let ok = unsafe {
      DeviceIoControl(
        root.as_raw_handle(),
        FSCTL_GET_NTFS_VOLUME_DATA,
        core::ptr::null(),
        0,
        buffer.as_mut_ptr(),
        LEN as u32,
        &mut written,
        core::ptr::null_mut(),
      )
    };
    if ok == 0 {
      return reading(Err(io::Error::last_os_error()));
    }
    decoded(buffer.filled(written as usize).and_then(|answer| {
      if answer.len() < LEN {
        return Err(invalid("an NTFS volume answer short of the structure"));
      }
      answer
        .i64_at(core::mem::offset_of!(
          NTFS_VOLUME_DATA_BUFFER,
          VolumeSerialNumber
        ))
        .map(|serial| serial as u64)
    }))
  }

  /// Every path the volume is mounted at, asked of the mount manager by the
  /// GUID path while the caller's handle holds the volume.
  ///
  /// `GetVolumePathNamesForVolumeNameW` answers a multi-string, and says when
  /// its buffer is too small with `ERROR_MORE_DATA` and the length it needs,
  /// at which it is asked again. On success it reports how many units it
  /// copied, and **only those are decoded**: the rest of the buffer is this
  /// crate's own zeroes, which could otherwise stand in for the terminator the
  /// answer lacks. A count past the buffer is `Failed(InvalidData)`, and the
  /// multi-string is read whole or not at all — see [`multi_string`]: a mount
  /// point that is not UTF-16 text is no path a row can spell, and it fails
  /// the read rather than leaving the volume's other mount points, or none, to
  /// stand for the whole.
  #[cfg(feature = "list")]
  fn mount_paths(guid: &VolumeRoot) -> Reading<Vec<String>> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;

    /// The most a volume's multi-string of mount points is believed to need,
    /// in UTF-16 units: a length past it is not a list of paths.
    const MOUNT_PATHS_LIMIT: u32 = 1 << 20;

    let wide = to_wide(Path::new(guid.as_str()));
    let mut buf = vec![0u16; 260];
    let mut returned: u32 = 0;
    loop {
      // SAFETY: `wide` is a NUL-terminated wide string and `buf` a live
      // buffer of the length declared, both for the length of the call.
      let ret = unsafe {
        GetVolumePathNamesForVolumeNameW(
          wide.as_ptr(),
          buf.as_mut_ptr(),
          buf.len() as u32,
          &mut returned,
        )
      };
      if ret != 0 {
        break;
      }
      let err = io::Error::last_os_error();
      if err.raw_os_error() == Some(ERROR_MORE_DATA as i32)
        && returned as usize > buf.len()
        && returned <= MOUNT_PATHS_LIMIT
      {
        buf.clear();
        buf.resize(returned as usize, 0);
        continue;
      }
      return reading(Err(err));
    }
    decoded(
      buf
        .get(..returned as usize)
        .ok_or_else(|| invalid("the mount manager counted more units than the buffer holds"))
        .and_then(multi_string),
    )
  }

  /// UTF-16 units in native byte order, or `InvalidData` for an odd number of
  /// bytes, which is not UTF-16 at all.
  fn units(bytes: &[u8]) -> io::Result<Vec<u16>> {
    if bytes.len() % 2 != 0 {
      return Err(invalid("a UTF-16 string of an odd number of bytes"));
    }
    Ok(
      bytes
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect(),
    )
  }

  /// Opens a volume's root directory for no access at all: the one handle.
  ///
  /// No access is needed for anything asked through it — the volume queries
  /// are answered on any handle, and `FSCTL_GET_NTFS_VOLUME_DATA` is declared
  /// `FILE_ANY_ACCESS` — so nothing about this open can be refused for want
  /// of a right to the volume's contents. `FILE_FLAG_BACKUP_SEMANTICS` is what
  /// opening a directory takes, and every share mode is granted, so the open
  /// stands in no one's way.
  fn open_root(root: &Path) -> Reading<File> {
    reading(
      std::fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root),
    )
  }

  /// The root a handle holds, proved from the handle itself: the volume GUID
  /// root it names itself by, or `None` for the root of a network share, or a
  /// decline where the handle holds anything but a root.
  ///
  /// **A handle opened on a mount root is not proven to be one.** The root was
  /// found by name, and a name is re-resolved by the open: a volume mounted in
  /// a folder that leaves between the two uncovers the folder, and the open
  /// lands on the directory of the volume beneath. So the handle is asked
  /// where it is, and accepted only where the answer is **exactly a root**:
  /// through `VOLUME_NAME_GUID`, a volume GUID root with nothing after it —
  /// see [`VolumeRoot::parse`] — and, for a volume that has no GUID path, which
  /// the function documents for network shares alone, through
  /// `VOLUME_NAME_DOS`, a share's root, `\\?\UNC\server\share\` with nothing
  /// after it. Anything else — a GUID path with a folder after it, a share
  /// path with one — is a handle on some other volume's directory, and the
  /// observation is declined, like a volume that has gone.
  fn proven_root(root: &File) -> Reading<Option<VolumeRoot>> {
    use windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_DOS;

    match final_path(root, VOLUME_NAME_GUID) {
      Reading::Value(path) => match VolumeRoot::parse(&path) {
        Some(volume) => Reading::Value(Some(volume)),
        None => Reading::Declined(not_a_root()),
      },
      Reading::Absent => match final_path(root, VOLUME_NAME_DOS) {
        Reading::Value(path) if is_share_root(&path) => Reading::Value(None),
        Reading::Value(_) | Reading::Absent => Reading::Declined(not_a_root()),
        Reading::Declined(err) => Reading::Declined(err),
        Reading::Failed(err) => Reading::Failed(err),
      },
      Reading::Declined(err) => Reading::Declined(err),
      Reading::Failed(err) => Reading::Failed(err),
    }
  }

  /// Whether a listing's handle names itself, through its own final path, by
  /// exactly `guid`'s root: `Value` where it does, and a decline where it
  /// names any other path — another volume's root, a folder beneath one — or
  /// none.
  #[cfg(feature = "list")]
  fn holds_root(root: &File, guid: &VolumeRoot) -> Reading<()> {
    match final_path(root, VOLUME_NAME_GUID) {
      Reading::Value(named) if VolumeRoot::parse(&named).is_some_and(|named| named.is(guid)) => {
        Reading::Value(())
      }
      Reading::Value(_) | Reading::Absent => Reading::Declined(io::Error::new(
        io::ErrorKind::NotFound,
        "the volume the handle holds does not answer to the root it was listed by",
      )),
      Reading::Declined(err) => Reading::Declined(err),
      Reading::Failed(err) => Reading::Failed(err),
    }
  }

  /// The decline a handle that holds no root ends in.
  fn not_a_root() -> io::Error {
    io::Error::new(
      io::ErrorKind::NotFound,
      "the handle opened on the mount root holds no volume's root: the volume that was \
       mounted there has left",
    )
  }

  /// The final path of the object a handle holds, read through the handle:
  /// `GetFinalPathNameByHandleW`, spelled as `volume` asks — a volume GUID
  /// path, or a DOS path.
  ///
  /// `Absent` for an object whose volume has no path of that kind: the
  /// function's own documentation names `ERROR_PATH_NOT_FOUND` for it —
  /// "Volume GUID paths are not created for network shares". A path that is
  /// not UTF-16 text is no path the system writes, and fails the read. A
  /// buffer too small is answered with the length needed, terminator
  /// included, and asked again at that length; a length within the buffer is
  /// the path's, and only that much of it is read.
  fn final_path(root: &File, volume: u32) -> Reading<String> {
    use windows_sys::Win32::Foundation::ERROR_PATH_NOT_FOUND;

    let mut buffer = vec![0u16; 64];
    loop {
      // SAFETY: `buffer` is live and as long as declared for the call, and the
      // handle is valid for as long as `root` is borrowed.
      let len = unsafe {
        GetFinalPathNameByHandleW(
          root.as_raw_handle(),
          buffer.as_mut_ptr(),
          buffer.len() as u32,
          volume | FILE_NAME_NORMALIZED,
        )
      } as usize;
      if len == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_PATH_NOT_FOUND as i32) {
          return Reading::Absent;
        }
        return reading(Err(err));
      }
      if len < buffer.len() {
        return decoded(wide_text(&buffer[..len]));
      }
      if len > 32_768 {
        return Reading::Failed(invalid("a final path longer than any path"));
      }
      buffer.resize(len, 0);
    }
  }

  /// `GetVolumePathNameW`: the mount root the caller's own path lies under.
  ///
  /// Starts with 1024 wide chars on the stack, then retries with doubling heap
  /// buffers up to 32 768 wide chars; the call reports no length it needs, so
  /// a failure is asked again at twice the size until that bound, and the
  /// last one is the answer. The root is the string before the terminator the
  /// call writes, and an answer with no terminator inside the buffer is
  /// `Failed(InvalidData)`.
  fn volume_path_name(path: &Path) -> Reading<PathBuf> {
    let wide = to_wide(path);

    let mut stack_buf = [0u16; 1024];
    let mut heap_buf: Vec<u16>;
    let mut buf: &mut [u16] = &mut stack_buf;

    loop {
      // SAFETY: `wide` is NUL-terminated and `buf` live and as long as
      // declared, both for the length of the call.
      let ret = unsafe { GetVolumePathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
      if ret != 0 {
        return decoded(terminated(buf).map(|root| PathBuf::from(OsString::from_wide(root))));
      }
      let err = io::Error::last_os_error();
      let next_size = buf.len() * 2;
      if next_size > 32768 {
        return reading(Err(err));
      }
      heap_buf = vec![0u16; next_size];
      buf = &mut heap_buf;
    }
  }

  #[cfg(test)]
  mod tests {
    use super::*;

    /// A buffer holding `bytes` at its start, as a file system might have
    /// left it.
    fn answer(bytes: &[u8]) -> KernelBuffer<64> {
      let mut all = [0u8; 64];
      all[..bytes.len()].copy_from_slice(bytes);
      KernelBuffer::holding(all)
    }

    fn wide(text: &str) -> Vec<u16> {
      text.encode_utf16().collect()
    }

    fn unit_bytes(units: &[u16]) -> impl Iterator<Item = u8> + '_ {
      units.iter().flat_map(|unit| unit.to_ne_bytes())
    }

    /// A `FILE_FS_VOLUME_INFORMATION` answer: the serial, the label length it
    /// claims, and the label's units after the fixed part.
    fn volume_bytes(serial: u32, label_length: u32, label: &[u16]) -> Vec<u8> {
      let mut bytes = vec![0u8; fs_volume::LABEL];
      bytes[fs_volume::SERIAL..fs_volume::SERIAL + 4].copy_from_slice(&serial.to_ne_bytes());
      bytes[fs_volume::LABEL_LENGTH..fs_volume::LABEL_LENGTH + 4]
        .copy_from_slice(&label_length.to_ne_bytes());
      bytes.extend(unit_bytes(label));
      bytes
    }

    /// A `FILE_FS_ATTRIBUTE_INFORMATION` answer, the same way.
    fn attribute_bytes(flags: u32, name_length: u32, name: &[u16]) -> Vec<u8> {
      let mut bytes = vec![0u8; fs_attribute::NAME];
      bytes[fs_attribute::ATTRIBUTES..fs_attribute::ATTRIBUTES + 4]
        .copy_from_slice(&flags.to_ne_bytes());
      bytes[fs_attribute::NAME_LENGTH..fs_attribute::NAME_LENGTH + 4]
        .copy_from_slice(&name_length.to_ne_bytes());
      bytes.extend(unit_bytes(name));
      bytes
    }

    fn refused<T>(decode: io::Result<T>) -> bool {
      decode.err().map(|err| err.kind()) == Some(io::ErrorKind::InvalidData)
    }

    /// Every `FILE_FS_*` answer is decoded out of the bytes the file system
    /// said it wrote and nothing else, and a structure it could not have
    /// written — short of its fixed part, a string that is odd or runs past
    /// the answer, a count that is negative — is `InvalidData`, never an
    /// absence.
    #[test]
    fn test_a_volume_answer_is_read_only_inside_what_was_written() {
      let label = wide("DATA");
      let bytes = volume_bytes(0x1234_5678, 8, &label);
      let (serial, name) = volume_in(answer(&bytes).filled(bytes.len()).unwrap()).unwrap();
      assert_eq!(serial, 0x1234_5678);
      assert_eq!(name.unwrap(), "DATA");
      let empty = volume_bytes(1, 0, &[]);
      assert_eq!(
        volume_in(answer(&empty).filled(empty.len()).unwrap())
          .unwrap()
          .1,
        None,
        "an empty label is no label"
      );
      for (bytes, written, why) in [
        (
          volume_bytes(1, 8, &label),
          fs_volume::LABEL - 1,
          "short of the fixed part",
        ),
        (
          volume_bytes(1, 8, &label),
          fs_volume::LABEL + 6,
          "a label past the answer",
        ),
        (
          volume_bytes(1, 7, &label),
          fs_volume::LABEL + 8,
          "an odd label length",
        ),
        (
          volume_bytes(1, u32::MAX, &label),
          fs_volume::LABEL + 8,
          "a length past any buffer",
        ),
      ] {
        assert!(
          refused(volume_in(answer(&bytes).filled(written).unwrap())),
          "{why}"
        );
      }

      let name = wide("NTFS");
      let bytes = attribute_bytes(0x2, 8, &name);
      assert_eq!(
        attributes_in(answer(&bytes).filled(bytes.len()).unwrap()).unwrap(),
        (0x2, "NTFS".to_owned())
      );
      let unpaired = [u16::from(b'N'), 0xd800];
      for (bytes, written, why) in [
        (
          attribute_bytes(0x2, 8, &name),
          fs_attribute::NAME - 1,
          "short of the fixed part",
        ),
        (
          attribute_bytes(0x2, 8, &name),
          fs_attribute::NAME + 4,
          "a name past the answer",
        ),
        (
          attribute_bytes(0x2, 3, &name),
          fs_attribute::NAME + 8,
          "an odd name length",
        ),
        (
          attribute_bytes(0x2, 4, &unpaired),
          fs_attribute::NAME + 4,
          "a name not UTF-16",
        ),
      ] {
        assert!(
          refused(attributes_in(answer(&bytes).filled(written).unwrap())),
          "{why}"
        );
      }

      let device = [7u32.to_ne_bytes(), 1u32.to_ne_bytes()].concat();
      assert_eq!(
        device_in(answer(&device).filled(fs_device::LEN).unwrap()).unwrap(),
        FsDeviceInformation {
          device_type: 7,
          characteristics: 1,
        }
      );
      assert!(refused(device_in(
        answer(&device).filled(fs_device::LEN - 1).unwrap()
      )));
    }

    /// The capacity is read out of the whole structure or not at all, and a
    /// negative count of allocation units is none a file system writes.
    #[cfg(feature = "disk-usage")]
    #[test]
    fn test_a_capacity_is_read_only_out_of_the_whole_structure() {
      let full_size = |total: i64, available: i64| {
        [
          &total.to_ne_bytes()[..],
          &available.to_ne_bytes(),
          &available.to_ne_bytes(),
          &8u32.to_ne_bytes(),
          &512u32.to_ne_bytes(),
        ]
        .concat()
      };
      let bytes = full_size(100, 50);
      assert_eq!(
        full_size_in(answer(&bytes).filled(fs_full_size::LEN).unwrap()).unwrap(),
        (100 * 4096, 50 * 4096)
      );
      assert!(refused(full_size_in(
        answer(&bytes).filled(fs_full_size::LEN - 1).unwrap()
      )));
      let negative = full_size(-1, 50);
      assert!(refused(full_size_in(
        answer(&negative).filled(fs_full_size::LEN).unwrap()
      )));
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

/// What the device kind the file system reports says about removal, which is
/// all this platform's removal answer is.
///
/// **A device kind never denies.** It says what kind of device a volume is on,
/// which is not an answer to the removal question, and the invariant this crate
/// publishes admits no exception for any kind. Optical media and a device whose
/// medium comes out of it (`FILE_REMOVABLE_MEDIA`) are a yes. Everything else
/// is [`Unknown`](Ejectability::Unknown): a disk whose medium is fixed in it —
/// which is what an external USB disk is, its medium fixed *in the drive* —
/// says nothing about whether the drive is unplugged, and nothing the one
/// handle can ask says more (see the module's documentation); a volume reached
/// over a network, a RAM disk and a kind a later Windows adds were never asked
/// about removal at all.
fn ejectability_of(device: FsDeviceInformation) -> Ejectability {
  if device.characteristics & FILE_REMOTE_DEVICE != 0 {
    return Ejectability::Unknown;
  }
  if is_optical(device.device_type) || device.characteristics & FILE_REMOVABLE_MEDIA != 0 {
    return Ejectability::Ejectable;
  }
  Ejectability::Unknown
}

/// Where `FILE_FS_VOLUME_INFORMATION`'s fields lie in an answer: the serial,
/// the label's length in bytes, and the label, which runs that many bytes from
/// its offset. The laws hold every offset against the binding crate's own
/// structure.
mod fs_volume {
  pub(super) const SERIAL: usize = 8;
  pub(super) const LABEL_LENGTH: usize = 12;
  pub(super) const LABEL: usize = 18;
}

/// Where `FILE_FS_ATTRIBUTE_INFORMATION`'s fields lie in an answer: the
/// attribute flags, the file-system name's length in bytes, and the name.
mod fs_attribute {
  pub(super) const ATTRIBUTES: usize = 0;
  pub(super) const NAME_LENGTH: usize = 8;
  pub(super) const NAME: usize = 12;
}

/// Where `FILE_FS_FULL_SIZE_INFORMATION`'s fields lie in an answer, and how
/// long the whole structure is: the volume's size, and what is free to the
/// caller, in allocation units of `SECTORS_PER_UNIT` sectors of
/// `BYTES_PER_SECTOR` bytes.
#[cfg(any(feature = "disk-usage", test))]
mod fs_full_size {
  pub(super) const TOTAL_UNITS: usize = 0;
  pub(super) const CALLER_AVAILABLE_UNITS: usize = 8;
  pub(super) const SECTORS_PER_UNIT: usize = 24;
  pub(super) const BYTES_PER_SECTOR: usize = 28;
  pub(super) const LEN: usize = 32;
}

/// Where `FILE_FS_DEVICE_INFORMATION`'s fields lie in an answer, and how long
/// the whole structure is.
mod fs_device {
  pub(super) const DEVICE_TYPE: usize = 0;
  pub(super) const CHARACTERISTICS: usize = 4;
  pub(super) const LEN: usize = 8;
}

/// What `FileFsDeviceInformation` answered: the kind of device a volume is on
/// (`FILE_DEVICE_*`) and that device's characteristics
/// (`FILE_REMOVABLE_MEDIA`, `FILE_REMOTE_DEVICE`, …).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct FsDeviceInformation {
  device_type: u32,
  characteristics: u32,
}

/// The root of one volume, named by its volume GUID path —
/// `\\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\` — and nothing else.
///
/// **The one parser every volume root goes through**: a root the enumeration
/// names, and the path a handle names itself by. A GUID path with anything
/// after the root's separator names a folder on that volume, not the volume,
/// so it is no `VolumeRoot` at all; see [`observed`] for what a handle that
/// names one becomes.
#[derive(Clone, Debug)]
pub(super) struct VolumeRoot(String);

impl VolumeRoot {
  /// `path` as a volume root, or `None` where it is anything else: the prefix
  /// `\\?\Volume{`, a GUID spelled 8-4-4-4-12 in hexadecimal digits of
  /// either case, `}\`, and the end of the path.
  pub(super) fn parse(path: &str) -> Option<Self> {
    let guid = path.strip_prefix(r"\\?\Volume{")?.strip_suffix(r"}\")?;
    let mut groups = guid.split('-');
    for width in [8, 4, 4, 4, 12] {
      let group = groups.next()?;
      if group.len() != width || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
      }
    }
    groups.next().is_none().then(|| Self(path.to_owned()))
  }

  /// The root as the platform spelled it.
  pub(super) fn as_str(&self) -> &str {
    &self.0
  }

  /// Whether `other` names the same volume: one GUID, in either case.
  #[cfg_attr(not(feature = "list"), allow(dead_code))]
  pub(super) fn is(&self, other: &Self) -> bool {
    self.0.eq_ignore_ascii_case(&other.0)
  }
}

/// Whether `path` — a final path spelled `VOLUME_NAME_DOS` — is exactly the
/// root of a network share, `\\?\UNC\server\share` with at most its
/// trailing separator after it: a server and a share, each named, and no
/// folder beneath them.
fn is_share_root(path: &str) -> bool {
  let Some(rest) = path.strip_prefix(r"\\?\UNC\") else {
    return false;
  };
  let rest = rest.strip_suffix('\\').unwrap_or(rest);
  let mut parts = rest.split('\\');
  matches!(
    (parts.next(), parts.next(), parts.next()),
    (Some(server), Some(share), None) if !server.is_empty() && !share.is_empty()
  )
}

/// Every volume GUID path the mount manager enumerates: a census, read to the
/// end `FindNextVolumeW` proves or refused.
///
/// The enumeration ends where — and only where — `FindNextVolumeW` answers
/// `ERROR_NO_MORE_FILES`, which its documentation names as the end. Any other
/// failure of either call ends the census in that error, sorted, so a listing
/// never reports the volumes enumerated before an interruption as though they
/// were all. **Every entry must be a volume root**, through the one parser
/// every volume root goes through — see [`VolumeRoot::parse`] — and one that
/// is not, or that has no terminator inside the buffer it was written to, or
/// that is not UTF-16 text, is `InvalidData`, which fails the census: the
/// mount manager writes nothing else. The search handle is closed on every
/// road out.
#[cfg(feature = "list")]
fn volume_census() -> Reading<Census<VolumeRoot>> {
  use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH,
  };

  /// The search handle, closed however the census ends.
  struct Search(HANDLE);
  impl Drop for Search {
    fn drop(&mut self) {
      // SAFETY: the handle came from a successful `FindFirstVolumeW` and is
      // closed exactly once, here.
      unsafe { FindVolumeClose(self.0) };
    }
  }

  let decode = |buf: &[u16]| {
    terminated(buf).and_then(wide_text).and_then(|path| {
      VolumeRoot::parse(&path).ok_or_else(|| {
        io::Error::new(
          io::ErrorKind::InvalidData,
          "the mount manager enumerated a name that is not a volume root",
        )
      })
    })
  };

  let mut buf = [0u16; MAX_PATH as usize + 1];
  // SAFETY: `buf` is live and as long as declared for the call.
  let handle = unsafe { FindFirstVolumeW(buf.as_mut_ptr(), buf.len() as u32) };
  if handle == INVALID_HANDLE_VALUE {
    return reading(Err(io::Error::last_os_error()));
  }
  let search = Search(handle);
  let mut first = Some(decode(&buf));
  Census::read(
    || {
      if let Some(first) = first.take() {
        return Some(first);
      }
      buf.fill(0);
      // SAFETY: the search handle is open, and `buf` live and as long as
      // declared for the call.
      if unsafe { FindNextVolumeW(search.0, buf.as_mut_ptr(), buf.len() as u32) } == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
          return None;
        }
        return Some(Err(err));
      }
      Some(decode(&buf))
    },
    declined,
  )
}

/// UTF-16 the platform wrote, as text: whole, or the read it came from fails.
///
/// **The one decoder every path and name on this backend goes through.** A
/// string is decoded strictly, with nothing replaced — a replacement would
/// spell a path the platform never wrote — and nothing dropped: a string that
/// does not decode fails with `InvalidData`, and so does the read that asked
/// for it. See [`multi_string`] for a list of them.
fn wide_text(units: &[u16]) -> io::Result<String> {
  String::from_utf16(units).map_err(|_| {
    io::Error::new(
      io::ErrorKind::InvalidData,
      "the platform wrote a path or a name that is not UTF-16 text",
    )
  })
}

/// The string a call wrote into a buffer, up to the terminator it wrote after
/// it, or `InvalidData` for a buffer with no terminator in it — no string the
/// call finished writing.
fn terminated(units: &[u16]) -> io::Result<&[u16]> {
  units
    .iter()
    .position(|&unit| unit == 0)
    .map(|len| &units[..len])
    .ok_or_else(|| {
      io::Error::new(
        io::ErrorKind::InvalidData,
        "a string with no terminator inside the buffer it was written to",
      )
    })
}

/// A multi-string the platform wrote — NUL-terminated members, then the empty
/// one that ends the list — as every member it holds, or the read fails.
///
/// `units` are exactly the units the platform reported writing, and **the
/// list must end exactly where they do**: no end inside them is a list the
/// platform never finished, and units after the end are no part of it — a
/// buffer's own zeroes past the reported length must never stand in for the
/// terminator a list lacks. An empty list is spelled one terminator, or an
/// empty member and its terminator. **Whole or not at all**: each member goes
/// through [`wide_text`], and the first that does not decode fails the whole
/// list with `InvalidData`, since a list with a member left out is a partial
/// answer that reads exactly like a complete one.
#[cfg_attr(not(any(feature = "list", test)), allow(dead_code))]
fn multi_string(units: &[u16]) -> io::Result<Vec<String>> {
  let invalid = |what| io::Error::new(io::ErrorKind::InvalidData, what);
  if units == [0] || units == [0, 0] {
    return Ok(Vec::new());
  }
  let mut members = Vec::new();
  let mut rest = units;
  loop {
    let Some(len) = rest.iter().position(|&unit| unit == 0) else {
      return Err(invalid(
        "a multi-string with no end inside the length the platform reported",
      ));
    };
    if len == 0 {
      return if rest.len() == 1 {
        Ok(members)
      } else {
        Err(invalid("units past the end of a multi-string"))
      };
    }
    members.push(wide_text(&rest[..len])?);
    rest = &rest[len + 1..];
  }
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

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use super::{
    super::{IdentityAssurance, NameReading, SmallBytes, VolumeCapabilities, VolumeIdentity},
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
    String::from_utf16(terminated(&buf).unwrap()).unwrap()
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
    let observation = Observation::of_path(&canonical).required().unwrap();
    let device = observation
      .device()
      .expect("the I/O manager names the device kind");
    assert!(is_local_storage(device), "{device:?}");
    assert!(is_disk(device.device_type), "{device:?}");
  }

  /// A listed volume's rows are built from the mount points its own
  /// observation found, while its handle held it, and from nothing else: the
  /// volume the runner boots from is listed at its root, under the GUID path
  /// the enumeration named — the one it named itself by through the handle.
  #[cfg(feature = "list")]
  #[test]
  fn test_a_listed_volume_is_bound_to_its_own_mount_points() {
    let guid = guid_of_root("C:\\");
    let observation = Observation::named(VolumeRoot::parse(&guid).expect("a volume root"))
      .required()
      .expect("the boot volume is observed through its own GUID path");
    assert!(observation.is_listed());
    let rows: Vec<_> = observation.into_rows().collect();
    assert!(
      rows
        .iter()
        .any(|row| row.mount_point() == Path::new("C:\\")),
      "{rows:?}"
    );
    for row in &rows {
      assert_eq!(row.device().to_str(), Some(guid.as_str()), "{row:?}");
    }
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
    let probe = |canonical: &Path| {
      Observation::of_path_with(canonical, |_| {
        let now = serial.get();
        // The volume's serial is rewritten between the two reads.
        serial.set(0x5566_7788);
        Ok(observed::Facts::fixture(
          VolumeCapabilities::from_fs_type_defaults(b"NTFS"),
          super::super::windows_identity(b"NTFS", now, None),
          Some(NameReading {
            name: SmallBytes::from_bytes(b"FIXTURE"),
            assurance: IdentityAssurance::Vouched,
          }),
        ))
      })
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

  /// **A device kind never denies, and it is the whole removal answer.** It
  /// says what kind of device a volume is on, which is not an answer to the
  /// removal question: optical media and a medium that comes out are a yes,
  /// and everything else — a disk whose medium is fixed in it, a network
  /// volume, a RAM disk, a kind this crate does not name — is `Unknown`.
  #[test]
  fn test_a_device_kind_never_denies() {
    use windows_sys::Win32::System::Ioctl::{
      FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_DEVICE_VIRTUAL_DISK,
    };

    let kind = |device_type, characteristics| FsDeviceInformation {
      device_type,
      characteristics,
    };

    for device in [
      kind(FILE_DEVICE_DISK, 0),
      kind(FILE_DEVICE_DISK_FILE_SYSTEM, 0),
      kind(FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE | FILE_REMOVABLE_MEDIA),
      kind(FILE_DEVICE_VIRTUAL_DISK, 0),
      kind(0, 0),
      kind(u32::MAX, 0),
    ] {
      assert_eq!(ejectability_of(device), Ejectability::Unknown, "{device:?}");
    }
    for device in [
      kind(FILE_DEVICE_CD_ROM, 0),
      kind(FILE_DEVICE_DVD, 0),
      kind(FILE_DEVICE_CD_ROM_FILE_SYSTEM, 0),
      kind(FILE_DEVICE_DISK, FILE_REMOVABLE_MEDIA),
    ] {
      assert_eq!(
        ejectability_of(device),
        Ejectability::Ejectable,
        "{device:?}"
      );
    }
  }

  /// Every string the platform writes is decoded whole or not at all: a
  /// multi-string keeps every member, one member that is not UTF-16 text
  /// fails the whole list rather than leaving the others to stand for it, and
  /// the list must end exactly where the units the platform reported do.
  #[test]
  fn test_a_multi_string_is_whole_or_it_is_an_error() {
    let wide = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    let mut list = wide("C:\\");
    list.push(0);
    list.extend(wide("D:\\mnt\\data\\"));
    list.extend([0, 0]);
    assert_eq!(multi_string(&list).unwrap(), ["C:\\", "D:\\mnt\\data\\"]);
    assert!(multi_string(&[0]).unwrap().is_empty(), "no mount points");
    assert!(multi_string(&[0, 0]).unwrap().is_empty(), "no mount points");

    // An unpaired surrogate in the second member: the first is not kept.
    let mut broken = wide("C:\\");
    broken.push(0);
    broken.extend([u16::from(b'E'), 0xd800, u16::from(b'\\')]);
    broken.extend([0, 0]);
    // A list the platform never finished writing, whose terminator only a
    // buffer's own zeroes past the reported length could have supplied.
    let mut unfinished = wide("C:\\");
    unfinished.push(0);
    // Units past the list's end.
    let mut overrun = list.clone();
    overrun.extend(wide("E:\\"));
    overrun.push(0);
    let mut trailing = list.clone();
    trailing.push(0);
    for units in [
      &broken[..],
      &wide("C:\\"),
      &unfinished,
      &overrun,
      &trailing,
      &[],
    ] {
      assert_eq!(
        multi_string(units).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "{units:?}"
      );
    }

    assert_eq!(wide_text(&wide("NTFS")).unwrap(), "NTFS");
    assert_eq!(
      wide_text(&[0xdc00]).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
    assert_eq!(terminated(&[65, 0, 66]).unwrap(), [65]);
    assert_eq!(
      terminated(&[65, 66]).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
  }

  /// A volume root is a volume GUID path's root and nothing else, through the
  /// one parser every volume root goes through; and a share's root is a
  /// server and a share with no folder beneath them.
  #[test]
  fn test_a_root_is_exactly_a_root() {
    let root = r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\";
    assert_eq!(VolumeRoot::parse(root).unwrap().as_str(), root);
    let upper = VolumeRoot::parse(r"\\?\Volume{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}\").unwrap();
    assert!(
      VolumeRoot::parse(root).unwrap().is(&upper),
      "one GUID in either case"
    );
    for path in [
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\mnt\usb",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\mnt\",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f}\",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9-00}\",
      r"\\?\Volume{0a1b2c3d4e5f-6071-8293-a4b5c6d7e8f9}\",
      r"\\?\Volume{0g1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\",
      r"\\?\C:\",
      r"C:\",
      "",
    ] {
      assert!(VolumeRoot::parse(path).is_none(), "{path}");
    }

    for path in [r"\\?\UNC\server\share\", r"\\?\UNC\server\share"] {
      assert!(is_share_root(path), "{path}");
    }
    for path in [
      r"\\?\UNC\server\share\folder",
      r"\\?\UNC\server\share\folder\",
      r"\\?\UNC\server\",
      r"\\?\UNC\server",
      r"\\?\UNC\\share\",
      r"\\?\C:\",
      r"\\server\share\",
    ] {
      assert!(!is_share_root(path), "{path}");
    }
  }

  /// The offsets every `FILE_FS_*` answer is read at are the shape the file
  /// system writes, or they are not offsets into it: each is asserted
  /// against the binding crate's own structs, and so is each length a whole
  /// structure is required to have, and the two characteristics this crate
  /// spells itself.
  #[test]
  fn test_the_volume_information_offsets_match_the_structs_they_read() {
    use core::mem::{offset_of, size_of};

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
      fs_volume::SERIAL,
      offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeSerialNumber)
    );
    assert_eq!(
      fs_volume::LABEL_LENGTH,
      offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeLabelLength)
    );
    assert_eq!(
      fs_volume::LABEL,
      offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeLabel)
    );

    assert_eq!(
      fs_attribute::ATTRIBUTES,
      offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemAttributes)
    );
    assert_eq!(
      fs_attribute::NAME_LENGTH,
      offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemNameLength)
    );
    assert_eq!(
      fs_attribute::NAME,
      offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)
    );

    assert_eq!(
      fs_full_size::TOTAL_UNITS,
      offset_of!(FILE_FS_FULL_SIZE_INFORMATION, TotalAllocationUnits)
    );
    assert_eq!(
      fs_full_size::CALLER_AVAILABLE_UNITS,
      offset_of!(
        FILE_FS_FULL_SIZE_INFORMATION,
        CallerAvailableAllocationUnits
      )
    );
    assert_eq!(
      fs_full_size::SECTORS_PER_UNIT,
      offset_of!(FILE_FS_FULL_SIZE_INFORMATION, SectorsPerAllocationUnit)
    );
    assert_eq!(
      fs_full_size::BYTES_PER_SECTOR,
      offset_of!(FILE_FS_FULL_SIZE_INFORMATION, BytesPerSector)
    );
    assert_eq!(
      fs_full_size::LEN,
      size_of::<FILE_FS_FULL_SIZE_INFORMATION>()
    );

    assert_eq!(
      fs_device::DEVICE_TYPE,
      offset_of!(FILE_FS_DEVICE_INFORMATION, DeviceType)
    );
    assert_eq!(
      fs_device::CHARACTERISTICS,
      offset_of!(FILE_FS_DEVICE_INFORMATION, Characteristics)
    );
    assert_eq!(fs_device::LEN, size_of::<FILE_FS_DEVICE_INFORMATION>());
  }

  /// A decline is what the backend's contract names, and nothing else is.
  #[test]
  fn test_only_a_named_code_is_a_decline() {
    use windows_sys::Win32::Foundation::{
      ERROR_ACCESS_DENIED, ERROR_DEV_NOT_EXIST, ERROR_FILE_INVALID, ERROR_FILE_NOT_FOUND,
      ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_IO_DEVICE, ERROR_MORE_DATA,
      ERROR_NO_MORE_FILES, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_READY, ERROR_NOT_SUPPORTED,
      ERROR_PATH_NOT_FOUND, ERROR_TOO_MANY_OPEN_FILES, ERROR_UNRECOGNIZED_VOLUME,
    };

    for code in [
      ERROR_FILE_NOT_FOUND,
      ERROR_PATH_NOT_FOUND,
      ERROR_DEV_NOT_EXIST,
      ERROR_NOT_READY,
      ERROR_UNRECOGNIZED_VOLUME,
      ERROR_FILE_INVALID,
      ERROR_ACCESS_DENIED,
      ERROR_INVALID_FUNCTION,
      ERROR_NOT_SUPPORTED,
      ERROR_INVALID_PARAMETER,
    ] {
      assert!(
        declined(&io::Error::from_raw_os_error(code as i32)),
        "{code}"
      );
    }
    for code in [
      ERROR_NOT_ENOUGH_MEMORY,
      ERROR_TOO_MANY_OPEN_FILES,
      ERROR_IO_DEVICE,
      ERROR_MORE_DATA,
      ERROR_NO_MORE_FILES,
    ] {
      assert!(
        !declined(&io::Error::from_raw_os_error(code as i32)),
        "{code}"
      );
    }
    assert!(!declined(&io::Error::other("not a system error at all")));
  }

  /// The volume enumeration is a census: it reaches the end `FindNextVolumeW`
  /// proves, and every entry is a volume GUID path.
  #[cfg(feature = "list")]
  #[test]
  fn test_the_volume_enumeration_is_a_census() {
    let Reading::Value(volumes) = volume_census() else {
      panic!("the mount manager enumerates its volumes");
    };
    let volumes: Vec<String> = volumes
      .into_iter()
      .map(|volume| volume.as_str().to_owned())
      .collect();
    assert!(volumes.contains(&guid_of_root("C:\\")), "{volumes:?}");
    for volume in &volumes {
      assert!(VolumeRoot::parse(volume).is_some(), "{volume}");
    }
  }

  /// The volume every runner boots from is a disk whose medium is fixed in
  /// it, so its removal answer is `Unknown`: the device kind is the whole
  /// answer through the one handle, and it says nothing either way there.
  #[test]
  fn test_a_fixed_disk_is_unknown_through_the_one_handle() {
    let canonical = Path::new("C:\\").canonicalize().unwrap();
    let observation = Observation::of_path(&canonical).required().unwrap();
    let device = observation
      .device()
      .expect("the I/O manager names the device kind");
    if device.characteristics & FILE_REMOVABLE_MEDIA != 0 {
      return;
    }
    assert!(is_disk(device.device_type), "{device:?}");
    assert_eq!(
      resolve(Path::new("C:\\"))
        .unwrap()
        .mount_info()
        .ejectability(),
      Ejectability::Unknown
    );
  }

  /// Why the one handle is the root directory: a handle on the volume device
  /// itself, opened for no access — all an unelevated process is given there —
  /// is a direct device open, which the file system never sees, so the volume
  /// information is not answered through it.
  #[test]
  fn test_a_direct_open_of_the_volume_device_is_not_the_file_systems() {
    use std::os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _};

    use windows_sys::{
      Wdk::Storage::FileSystem::{FileFsVolumeInformation, NtQueryVolumeInformationFile},
      Win32::{
        Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE},
        System::IO::IO_STATUS_BLOCK,
      },
    };

    let guid = guid_of_root("C:\\");
    let device = guid.strip_suffix('\\').unwrap();
    let handle = std::fs::OpenOptions::new()
      .access_mode(0)
      .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
      .open(device)
      .expect("a volume device opens for no access");
    let mut buffer = [0u64; 72];
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: a live handle, status block and buffer of the declared length.
    let nt = unsafe {
      NtQueryVolumeInformationFile(
        handle.as_raw_handle(),
        &mut status,
        buffer.as_mut_ptr().cast(),
        core::mem::size_of_val(&buffer) as u32,
        FileFsVolumeInformation,
      )
    };
    assert!(
      nt < 0,
      "the volume device answered the file system's question: {nt:#x}"
    );
  }
}
