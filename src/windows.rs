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
//! every string the platform writes is decoded whole or not at all: a path or
//! a name that is not UTF-16 text fails its read with `InvalidData`, and a
//! label that is not is kept as the platform wrote it — see [`wide_text`] and
//! [`multi_string`]. What each road answers, and the documentation that names
//! it:
//!
//! | Road | Absent | Declined, and what it becomes | Documentation |
//! |---|---|---|---|
//! | the path's mount root, `GetVolumePathNameW` | — | the resolve's error | *GetVolumePathNameW*: "If the function fails, the return value is zero. To get extended error information, call GetLastError." |
//! | the one handle, `CreateFileW` on the root directory | — | a resolve's error; a listing does not report the volume | *CreateFileW*; the codes in *System Error Codes* |
//! | the GUID path, `GetFinalPathNameByHandleW` with `VOLUME_NAME_GUID` | `ERROR_PATH_NOT_FOUND`, for a volume with no GUID path: the device is then the mount point | no GUID path | *GetFinalPathNameByHandleW*: "Volume GUID paths are not created for network shares" |
//! | serial and label, `FileFsVolumeInformation` | a zero serial, an empty label | the volume did not answer for itself: nothing else is asked of it, a resolve reports none of its fields and a listing does not report it | *NtQueryVolumeInformationFile*, whose `NTSTATUS` is the system error *RtlNtStatusToDosError* names |
//! | file-system name and flags, `FileFsAttributeInformation` | — | no file-system type, no case flags | the same |
//! | capacity, `FileFsFullSizeInformation` | — | zero | the same |
//! | device kind, `FileFsDeviceInformation` | — | removal `Unknown`; a listing does not report the volume | the same |
//! | full NTFS serial, `FSCTL_GET_NTFS_VOLUME_DATA` | a short answer | the documented 32-bit serial | *DeviceIoControl*; the codes in *System Error Codes* |
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
/// opened once, through the GUID path the enumeration named, and its mount
/// points and every field of its rows are read while that handle holds it —
/// and the volume must then name itself, through the handle, by the GUID path
/// its mount points were asked by, so mount points the mount manager gave for
/// a name that moved to another volume are never paired with this one. The
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
  use {
    super::FsFullSizeInformation, windows_sys::Wdk::Storage::FileSystem::FileFsFullSizeInformation,
  };
  #[cfg(feature = "list")]
  use {
    super::{is_local_storage, multi_string},
    windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW,
  };

  use super::{
    super::{
      Ejectability, IdentityAssurance, IdentityReading, MountPoint, NameReading, SmallBytes,
      VolumeCapabilities, published_label, published_label_bytes, reading::Reading,
      windows_identity,
    },
    FILE_CASE_PRESERVED_NAMES, FsAttributeInformation, FsDeviceInformation, FsVolumeInformation,
    ejectability_of, reading, to_wide, wide_strlen, wide_text,
  };

  /// One volume, observed through one handle: everything every row of it is
  /// built from.
  pub(super) struct Observation {
    /// The handle every fact below was read through, held for as long as the
    /// observation is.
    _root: File,
    /// `\\?\Volume{GUID}\`, as the volume named itself through the handle,
    /// or `None` for a volume that has none — a network share, for which
    /// volume GUID paths are not created.
    guid: Option<String>,
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
    /// the one handle opened on it, the GUID path the volume names itself by
    /// through that handle, and every fact the handle answers. A mount root
    /// with no GUID path — a network share — is observed all the same, with
    /// the root as its device. A mount root that is not UTF-16 text is no path
    /// a row can spell, and fails the read.
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
          let guid = match guid_path(&handle).answered() {
            Ok(guid) => guid,
            Err(err) => return Reading::Failed(err),
          };
          match read(&handle) {
            Ok(facts) => Reading::Value(Self {
              _root: handle,
              guid,
              mount_paths: vec![mount_point],
              facts,
            }),
            Err(err) => Reading::Failed(err),
          }
        })
      })
    }

    /// A listing's observation: the one handle, opened through the GUID path
    /// the enumeration named; every path the volume is mounted at, asked of
    /// the mount manager while the handle holds the volume; every fact the
    /// handle answers, read after them; and, last, the GUID path the volume
    /// names itself by through the handle, which must be the one its mount
    /// points were asked by.
    ///
    /// **That last read is what binds the mount points to the handle.** They
    /// are asked of the mount manager by name, and a name is not a handle. The
    /// volume answering through the handle after they were read shows it was
    /// there while they were asked for; naming itself by the same GUID path
    /// then shows the name was its own. A volume that names itself by any
    /// other — or by none — is not the volume those mount points were given
    /// for, and is declined, like a volume that has gone.
    #[cfg(feature = "list")]
    pub(super) fn named(guid: String) -> Reading<Self> {
      open_root(Path::new(&guid)).and_then(|handle| {
        mount_paths(&guid).and_then(|mount_paths| {
          // Mounted nowhere: the mount manager's own answer that there is no
          // row of this volume to describe, so nothing else is asked of it.
          if mount_paths.is_empty() {
            return Reading::Absent;
          }
          let facts = match Facts::read(&handle) {
            Ok(facts) => facts,
            Err(err) => return Reading::Failed(err),
          };
          match guid_path(&handle) {
            // A GUID path is ASCII, and its hex digits are one GUID in either
            // case.
            Reading::Value(named) if named.eq_ignore_ascii_case(&guid) => Reading::Value(Self {
              _root: handle,
              guid: Some(guid),
              mount_paths,
              facts,
            }),
            Reading::Value(_) | Reading::Absent => Reading::Declined(io::Error::new(
              io::ErrorKind::NotFound,
              "the volume the handle holds no longer answers to the GUID path its mount \
               points were asked by",
            )),
            Reading::Declined(err) => Reading::Declined(err),
            Reading::Failed(err) => Reading::Failed(err),
          }
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
            Some(guid) => SmallBytes::from_bytes(guid.as_bytes()),
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
      let identity = windows_identity(fs_type.as_bytes(), serial, ntfs_serial);
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

  /// A buffer the file system may fill with any bytes at all.
  ///
  /// # Safety
  ///
  /// Implemented only for a `#[repr(C)]` type made of integers and arrays of
  /// them, for which every bit pattern is a valid value, so that whatever the
  /// file system writes into it — or leaves as it was — is a value of the
  /// type.
  unsafe trait KernelFilled {}

  // SAFETY: an array of bytes; every bit pattern is valid.
  unsafe impl<const N: usize> KernelFilled for Aligned<N> {}
  // SAFETY: integers only; every bit pattern is valid.
  #[cfg(feature = "disk-usage")]
  unsafe impl KernelFilled for FsFullSizeInformation {}
  // SAFETY: integers only; every bit pattern is valid.
  unsafe impl KernelFilled for FsDeviceInformation {}

  /// One `NtQueryVolumeInformationFile` of `class` into the caller's own
  /// buffer, answering how many bytes the file system wrote. A status that is
  /// not success is the system error `RtlNtStatusToDosError` names for it,
  /// sorted.
  ///
  /// The buffer is borrowed whole and its length is its type's, so no caller
  /// can hand over a pointer or a length that does not describe live memory.
  fn query<B: KernelFilled>(
    root: &File,
    class: FS_INFORMATION_CLASS,
    buffer: &mut B,
  ) -> Reading<usize> {
    let mut status = IO_STATUS_BLOCK::default();
    let length = core::mem::size_of::<B>();
    // SAFETY: the handle is valid for as long as `root` is borrowed, `status`
    // is a live status block, and `buffer` an exclusive borrow of exactly
    // `length` bytes, which the file system writes no further than;
    // `B: KernelFilled`, so whatever it writes is a valid `B`.
    let nt = unsafe {
      NtQueryVolumeInformationFile(
        root.as_raw_handle(),
        &mut status,
        core::ptr::from_mut(buffer).cast(),
        length as u32,
        class,
      )
    };
    if nt < 0 {
      // SAFETY: a pure conversion of a status code.
      let code = unsafe { RtlNtStatusToDosError(nt) };
      return reading(Err(io::Error::from_raw_os_error(code as i32)));
    }
    Reading::Value(status.Information)
  }

  /// The volume's serial and its label: `FileFsVolumeInformation`.
  ///
  /// The label follows the fixed part in the same buffer, as a length in
  /// bytes and UTF-16 units; it is read only where it lies wholly inside what
  /// the file system wrote, and kept as the units the volume wrote — see
  /// [`Facts::read`] for what a label that is not text becomes. An empty
  /// label is no label, and so is one whose length runs past the answer. An
  /// answer shorter than the fixed part is none.
  fn volume_information(root: &File) -> Reading<(u32, Option<OsString>)> {
    let mut buffer = Aligned([0u8; 576]);
    query(root, FileFsVolumeInformation, &mut buffer).and_then(|written| {
      let label_at = core::mem::offset_of!(FsVolumeInformation, label);
      if written < label_at {
        return Reading::Absent;
      }
      // SAFETY: the buffer is aligned to 8, which covers the mirror's own
      // alignment, and at least the fixed part was written; every field of
      // the mirror is an integer, for which every bit pattern is valid.
      let head = unsafe { &*buffer.0.as_ptr().cast::<FsVolumeInformation>() };
      let label = label_at
        .checked_add(head.label_length as usize)
        .filter(|&end| end <= written && end <= buffer.0.len())
        .and_then(|end| units(&buffer.0[label_at..end]))
        .filter(|units| !units.is_empty())
        .map(|units| OsString::from_wide(&units));
      Reading::Value((head.serial, label))
    })
  }

  /// The file system's name and its attribute flags:
  /// `FileFsAttributeInformation`. The name follows the fixed part in the
  /// same buffer and is read the same way the label is; a name that does not
  /// lie wholly inside the answer is none, and one that is not UTF-16 text is
  /// no name a file system gives itself, and fails the read.
  fn attributes(root: &File) -> Reading<(u32, String)> {
    let mut buffer = Aligned([0u8; 544]);
    query(root, FileFsAttributeInformation, &mut buffer).and_then(|written| {
      let name_at = core::mem::offset_of!(FsAttributeInformation, name);
      if written < name_at {
        return Reading::Absent;
      }
      // SAFETY: as for the volume information above.
      let head = unsafe { &*buffer.0.as_ptr().cast::<FsAttributeInformation>() };
      let Some(units) = name_at
        .checked_add(head.name_length as usize)
        .filter(|&end| end <= written && end <= buffer.0.len())
        .and_then(|end| units(&buffer.0[name_at..end]))
      else {
        return Reading::Absent;
      };
      match wide_text(&units) {
        Ok(name) => Reading::Value((head.attributes, name)),
        Err(err) => Reading::Failed(err),
      }
    })
  }

  /// The volume's capacity, as `(total, available to this caller)` bytes:
  /// `FileFsFullSizeInformation`, in allocation units of the size it names.
  /// A short answer, or a negative count of units, is none.
  #[cfg(feature = "disk-usage")]
  fn full_size(root: &File) -> Reading<(u64, u64)> {
    let mut info = FsFullSizeInformation::default();
    query(root, FileFsFullSizeInformation, &mut info).and_then(|written| {
      if written < core::mem::size_of::<FsFullSizeInformation>() {
        return Reading::Absent;
      }
      let unit = u64::from(info.sectors_per_unit).saturating_mul(u64::from(info.bytes_per_sector));
      match (
        u64::try_from(info.total_units),
        u64::try_from(info.caller_available_units),
      ) {
        (Ok(total), Ok(available)) => {
          Reading::Value((total.saturating_mul(unit), available.saturating_mul(unit)))
        }
        _ => Reading::Absent,
      }
    })
  }

  /// The kind of device the volume is on and its characteristics:
  /// `FileFsDeviceInformation`, which the I/O manager answers itself, from
  /// the device object the handle was opened through.
  fn device(root: &File) -> Reading<FsDeviceInformation> {
    let mut info = FsDeviceInformation::default();
    query(root, FileFsDeviceInformation, &mut info).and_then(|written| {
      if written < core::mem::size_of::<FsDeviceInformation>() {
        Reading::Absent
      } else {
        Reading::Value(info)
      }
    })
  }

  /// The volume's full 64-bit NTFS serial, with `FSCTL_GET_NTFS_VOLUME_DATA`
  /// on the one handle.
  ///
  /// This is the same number Linux publishes under `/dev/disk/by-uuid` as
  /// sixteen hex digits; `FileFsVolumeInformation` reports only its low
  /// half. The control code is declared `FILE_ANY_ACCESS`, so the handle
  /// needs no access to ask it. A short answer is none.
  fn ntfs_serial(root: &File) -> Reading<u64> {
    // SAFETY: `NTFS_VOLUME_DATA_BUFFER` is a C structure of integers, for
    // which all-zero bytes are a valid value.
    let mut data: NTFS_VOLUME_DATA_BUFFER = unsafe { core::mem::zeroed() };
    let mut written: u32 = 0;
    // SAFETY: `data` is a live, correctly sized output buffer for this
    // control code, `written` a live count, and the handle is valid for as
    // long as `root` is borrowed.
    let ok = unsafe {
      DeviceIoControl(
        root.as_raw_handle(),
        FSCTL_GET_NTFS_VOLUME_DATA,
        core::ptr::null(),
        0,
        core::ptr::from_mut(&mut data).cast::<core::ffi::c_void>(),
        core::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
        &mut written,
        core::ptr::null_mut(),
      )
    };
    if ok == 0 {
      return reading(Err(io::Error::last_os_error()));
    }
    // A short answer means the fields we want were not among the bytes written.
    if (written as usize) < core::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() {
      return Reading::Absent;
    }
    Reading::Value(data.VolumeSerialNumber as u64)
  }

  /// Every path the volume is mounted at, asked of the mount manager by the
  /// GUID path while the caller's handle holds the volume.
  ///
  /// `GetVolumePathNamesForVolumeNameW` answers a multi-string, and says when
  /// its buffer is too small with `ERROR_MORE_DATA` and the length it needs,
  /// at which it is asked again. The multi-string is read whole or not at all
  /// — see [`multi_string`]: a mount point that is not UTF-16 text is no path
  /// a row can spell, and it fails the read rather than leaving the volume's
  /// other mount points, or none, to stand for the whole.
  #[cfg(feature = "list")]
  fn mount_paths(guid: &str) -> Reading<Vec<String>> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;

    /// The most a volume's multi-string of mount points is believed to need,
    /// in UTF-16 units: a length past it is not a list of paths.
    const MOUNT_PATHS_LIMIT: u32 = 1 << 20;

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
      let err = io::Error::last_os_error();
      if err.raw_os_error() == Some(ERROR_MORE_DATA as i32)
        && required_len as usize > buf.len()
        && required_len <= MOUNT_PATHS_LIMIT
      {
        buf.clear();
        buf.resize(required_len as usize, 0);
        continue;
      }
      return reading(Err(err));
    }
    match multi_string(&buf) {
      Ok(paths) => Reading::Value(paths),
      Err(err) => Reading::Failed(err),
    }
  }

  /// A byte buffer aligned for the `FILE_FS_*` mirrors read out of it, the
  /// widest of which holds a `LARGE_INTEGER`.
  #[repr(C, align(8))]
  struct Aligned<const N: usize>([u8; N]);

  /// UTF-16 units in native byte order, or none for an odd number of bytes,
  /// which is not UTF-16 at all.
  fn units(bytes: &[u8]) -> Option<Vec<u16>> {
    if bytes.len() % 2 != 0 {
      return None;
    }
    Some(
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

  /// The volume GUID path of the volume a handle is on, read through the
  /// handle: `GetFinalPathNameByHandleW` with `VOLUME_NAME_GUID`, which for a
  /// root directory is `\\?\Volume{GUID}\` itself.
  ///
  /// `Absent` for a volume that has no such path: the function's own
  /// documentation names `ERROR_PATH_NOT_FOUND` for it — "Volume GUID paths
  /// are not created for network shares". A path that is not UTF-16 text is
  /// no GUID path the mount manager writes, and fails the read. A buffer too
  /// small is answered with the length needed, terminator included, and
  /// asked again at that length.
  fn guid_path(root: &File) -> Reading<String> {
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
          VOLUME_NAME_GUID | FILE_NAME_NORMALIZED,
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
        return match wide_text(&buffer[..len]) {
          Ok(guid) => Reading::Value(guid),
          Err(err) => Reading::Failed(err),
        };
      }
      if len > 32_768 {
        return Reading::Failed(io::Error::new(
          io::ErrorKind::InvalidData,
          "a volume GUID path longer than any path",
        ));
      }
      buffer.resize(len, 0);
    }
  }

  /// `GetVolumePathNameW`: the mount root the caller's own path lies under.
  ///
  /// Starts with 1024 wide chars on the stack, then retries with doubling heap
  /// buffers up to 32 768 wide chars; the call reports no length it needs, so
  /// a failure is asked again at twice the size until that bound, and the
  /// last one is the answer.
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
        let len = wide_strlen(buf);
        return Reading::Value(PathBuf::from(OsString::from_wide(&buf[..len])));
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

/// Every volume GUID path the mount manager enumerates: a census, read to the
/// end `FindNextVolumeW` proves or refused.
///
/// The enumeration ends where — and only where — `FindNextVolumeW` answers
/// `ERROR_NO_MORE_FILES`, which its documentation names as the end. Any other
/// failure of either call ends the census in that error, sorted, so a listing
/// never reports the volumes enumerated before an interruption as though they
/// were all. A GUID path that is not UTF-16 text is a failed read: the mount
/// manager writes them in ASCII. The search handle is closed on every road out.
#[cfg(feature = "list")]
fn volume_census() -> Reading<Census<String>> {
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

  let decode = |buf: &[u16]| wide_text(&buf[..wide_strlen(buf)]);

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

/// A multi-string the platform wrote — NUL-separated members, ended by an
/// empty one — as every member it holds, or the read fails.
///
/// **Whole or not at all.** Each member goes through [`wide_text`], and the
/// first that does not decode fails the whole list with `InvalidData`: a list
/// with a member left out is a partial answer that reads exactly like a
/// complete one. A multi-string whose end does not lie inside `units` is not
/// one the platform finished writing, and fails the same way.
#[cfg_attr(not(any(feature = "list", test)), allow(dead_code))]
fn multi_string(units: &[u16]) -> io::Result<Vec<String>> {
  let mut members = Vec::new();
  let mut rest = units;
  loop {
    let Some(len) = rest.iter().position(|&unit| unit == 0) else {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "a multi-string with no end inside the buffer it was written to",
      ));
    };
    if len == 0 {
      return Ok(members);
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

/// Finds the length of a null-terminated UTF-16 string in a buffer.
#[cfg_attr(not(tarpaulin), inline(always))]
fn wide_strlen(buf: &[u16]) -> usize {
  buf.iter().position(|&c| c == 0).unwrap_or(buf.len())
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
    let observation = Observation::named(guid.clone())
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
  /// multi-string keeps every member, and one member that is not UTF-16 text
  /// fails the whole list rather than leaving the others to stand for it.
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
    assert_eq!(
      multi_string(&broken).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
    // A list the platform never finished writing.
    assert_eq!(
      multi_string(&wide("C:\\")).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );

    assert_eq!(wide_text(&wide("NTFS")).unwrap(), "NTFS");
    assert_eq!(
      wide_text(&[0xdc00]).unwrap_err().kind(),
      io::ErrorKind::InvalidData
    );
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
    let volumes: Vec<String> = volumes.into_iter().collect();
    assert!(volumes.contains(&guid_of_root("C:\\")), "{volumes:?}");
    for volume in &volumes {
      assert!(
        volume.starts_with("\\\\?\\Volume{") && volume.ends_with("}\\"),
        "{volume}"
      );
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
