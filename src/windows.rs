//! Windows: every value in a row is read through one handle on its volume, and
//! the removal answer through the volume device that handle names.
//!
//! **An observation is formed once, from one native identity, and a row is
//! built from nothing else.** A resolve walks its path to the object it names
//! with nothing on the way followed unseen — see [`walk`] — asks the object's
//! own handle where it is and which volume it is on, and opens **one handle**
//! on that volume's root directory; a listing opens its handle through the
//! volume GUID path the enumeration named. Every fact of a row but the removal answer is then read through that
//! one handle, inside [`observed`], and stored in the [`Observation`]: the
//! serial and the label
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
//! is read before.** A root is opened by a name — the GUID or the share the
//! object's handle named — and a name is resolved again by the open: a volume
//! that leaves in between, and a clone given its GUID, would answer under it.
//! So the handle is asked where it is, and its final path must be exactly a
//! volume GUID root — `\\?\Volume{GUID}\` with nothing
//! after it, through the one parser every volume root goes through, which the
//! enumeration's roots go through too — or, for a network share, which has no
//! GUID path, exactly the share's root. Anything else is declined, like a
//! volume that has gone.
//!
//! The handle is the volume's root directory, opened for no access at all. A
//! handle on the volume device itself would not do: opened without read
//! access, which is all an unelevated process is granted there, it is a
//! direct device open that the file system never sees, so nothing but the
//! device's own storage questions is answered through it — which is exactly
//! what the removal answer asks it, and all it is asked: see below.
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
//! | the walk, `NtCreateFile` for each component relative to the one before, with `FILE_OPEN_REPARSE_POINT`; `FileAttributeTagInfo`; `FSCTL_GET_REPARSE_POINT` on a link; `QueryDosDeviceW` on a drive letter | — | the resolve's error; a link the walk does not follow is refused with `InvalidInput` | *NtCreateFile*, whose `NTSTATUS` is the system error *RtlNtStatusToDosError* names; *FSCTL_GET_REPARSE_POINT* |
//! | the object's place, `GetFinalPathNameByHandleW` with `VOLUME_NAME_DOS` and `VOLUME_NAME_GUID` on the walk's handle | `ERROR_PATH_NOT_FOUND` for the GUID path of a share: the share's root is the root | the resolve's error | *GetFinalPathNameByHandleW* |
//! | the one handle, `NtCreateFile` on the root through `\GLOBAL??\` | — | a resolve's error; a listing does not report the volume | *NtCreateFile*; the codes in *System Error Codes* |
//! | the root the handle holds, `GetFinalPathNameByHandleW` with `VOLUME_NAME_GUID` | `ERROR_PATH_NOT_FOUND`, for a volume with no GUID path: the share's root is then asked with `VOLUME_NAME_DOS`, and the device is the mount point | a path that is not exactly the volume root, or exactly the very share's root — server and share — the object's own path names: the observation is declined | *GetFinalPathNameByHandleW*: "Volume GUID paths are not created for network shares" |
//! | serial and label, `FileFsVolumeInformation` | a zero serial, an empty label | the volume did not answer for itself: nothing else is asked of it, a resolve reports none of its fields and a listing does not report it | *NtQueryVolumeInformationFile*, whose `NTSTATUS` is the system error *RtlNtStatusToDosError* names |
//! | file-system name and flags, `FileFsAttributeInformation` | — | no file-system type, no case flags, and no identity: a serial is an identity only in the spelling the file system's type gives it | the same |
//! | capacity, `FileFsFullSizeInformation` | — | zero | the same |
//! | device kind, `FileFsDeviceInformation` | — | removal `Unknown`; a listing does not report the volume | the same |
//! | the volume's own device, `NtCreateFile` on `\GLOBAL??\Volume{…}` — the proven GUID path without its separator, in the global namespace — through `walk::open_device`, for no access beyond its attributes; each disk interface the same way | — | nothing more is asked about removal, and the device kind's answer stands (a failure too: the removal road's contract) | *NtCreateFile*: `SYNCHRONIZE \| FILE_READ_ATTRIBUTES`, which `CreateFileW` gives a zero-access open |
//! | the disk's number, `IOCTL_STORAGE_GET_DEVICE_NUMBER` on that device, and again on each disk interface | — | no removal policy (a failure too) | *IOCTL_STORAGE_GET_DEVICE_NUMBER*, *STORAGE_DEVICE_NUMBER* |
//! | the disk interfaces, `CM_Get_Device_Interface_List_SizeW` / `CM_Get_Device_Interface_ListW` (`GUID_DEVINTERFACE_DISK`) | `CR_NO_SUCH_*`: none | no removal policy (a failure too) | *CM_Get_Device_Interface_ListW*: "CR_BUFFER_SMALL" where the list grew, which is asked again |
//! | the disk's device node and its removal policy, `CM_Get_Device_Interface_PropertyW` (`DEVPKEY_Device_InstanceId`), `CM_Locate_DevNodeW`, `CM_Get_DevNode_Registry_PropertyW` (`CM_DRP_REMOVAL_POLICY`) | `CR_NO_SUCH_*`: none | no removal policy (a failure too) | *CM_Get_DevNode_Registry_PropertyW*; *CM_REMOVAL_POLICY* |
//! | storage descriptor, `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty`) on that device, where no policy answered | a member its `Version` does not hold | no yes (a failure too) | *IOCTL_STORAGE_QUERY_PROPERTY*, *STORAGE_DEVICE_DESCRIPTOR*: `Version` "Contains the size of this structure, in bytes. The value of this member will change as members are added to the structure" |
//! | full NTFS serial, `FSCTL_GET_NTFS_VOLUME_DATA` | — | the documented 32-bit serial | *DeviceIoControl*; the codes in *System Error Codes* |
//! | mount points, `GetVolumePathNamesForVolumeNameW` | — | the volume is not reported | *GetVolumePathNamesForVolumeNameW*: "If the buffer is not large enough to hold the complete list, the function fails and GetLastError returns ERROR_MORE_DATA", which is asked again at the length it names |
//! | volume census, `FindFirstVolumeW` / `FindNextVolumeW` | — | the listing is refused | *FindNextVolumeW*: "If no matching files can be found, the GetLastError function returns the ERROR_NO_MORE_FILES error code" — the census's proven end |
//!
//! Every failure — any code [`declined`] does not name — is the error it is:
//! a resolve's, or a listing's.
//!
//! **The removal question is asked of the device kind first, and then of the
//! volume's own device.** Optical media and a device whose medium comes out of
//! it (`FILE_REMOVABLE_MEDIA`) are a yes from the kind alone. A disk whose
//! medium is fixed in it — which is what an external USB disk is — is asked
//! through **one more handle, and only one**: the volume's own device, opened
//! by the volume GUID path the one handle proved it holds, and by nothing
//! else. A GUID path read through the handle names the volume the handle
//! holds, so the second handle cannot land on another volume the way a second
//! resolution of a *path* could; and it is opened for no access at all, which
//! an unelevated process is granted on a volume device (a law opens one under
//! a restricted token on every Windows runner). The storage control codes are
//! device controls: NTFS and FAT decline them on the root directory the one
//! handle is (`ERROR_INVALID_PARAMETER`: FastFAT's `FatCommonDeviceControl` in
//! Microsoft's driver samples; NTFS measured on a runner's system volume), and
//! the volume device services them, declared `FILE_ANY_ACCESS`.
//!
//! Through that device the platform's own answer is asked first: **the Plug
//! and Play removal policy of the disk the volume lies on**, reached from the
//! storage device number the device answers (`IOCTL_STORAGE_GET_DEVICE_NUMBER`)
//! and bound to it by hold-and-verify — the one disk interface carrying that
//! number, its device node, the policy, and the number read again through
//! both handles afterwards. `EXPECT_NO_REMOVAL` is the one denial this backend
//! gives; the two policies that expect removal are a yes. Where the policy is
//! not reached, the device's storage descriptor (`IOCTL_STORAGE_QUERY_PROPERTY`)
//! is a yes where its bus is USB or SD, or its medium comes out. A volume whose
//! device could not be opened so, or answered neither, is asked nothing more,
//! and its removal answer is the device kind's: `Unknown`. **The removal road
//! is the one road on this backend where a failure is not an error**: every
//! outcome but a value on it leaves the answer `Unknown`, which is what that
//! state means — see [`Reading::evidence`].

use std::{
  fs::File,
  io,
  os::windows::ffi::OsStrExt as _,
  path::{Path, PathBuf},
};

use windows_sys::Win32::{
  Storage::FileSystem::{
    BusTypeSd, BusTypeUsb, FILE_DEVICE_CD_ROM, FILE_DEVICE_DISK, FILE_DEVICE_DVD, STORAGE_BUS_TYPE,
  },
  System::Ioctl::{FILE_DEVICE_CD_ROM_FILE_SYSTEM, FILE_DEVICE_DISK_FILE_SYSTEM},
};

#[cfg(feature = "list")]
use windows_sys::Win32::Storage::FileSystem::{FindFirstVolumeW, FindNextVolumeW, FindVolumeClose};

#[cfg(any(feature = "list", test))]
use super::filled::SentinelBuffer;
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
  resolve_with(path, Observation::of_object)
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
  observe: impl FnOnce(&File) -> Reading<(Observation, PathBuf)>,
) -> io::Result<Inner> {
  // A path that names a device, not a file on a volume, is refused before
  // anything is opened, and every other path is walked to its object with
  // nothing followed unseen: see [`device_free_full_path`] and [`walk`].
  let object = walk::walk(&device_free_full_path(path)?)?;

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
  let (observation, canonical) = observe(&object).required()?;
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

/// The full path of the caller's `path` — [`full_path`], computed once — or
/// `InvalidInput` for a path that names a device rather than a file on a
/// volume, decided on the string alone, before anything is opened: see
/// [`names_a_device`]. `CreateFileW` takes the whole path `CONIN$` or
/// `CONOUT$` for the console's own buffers, whatever the full path says, so
/// those two are asked of the path as given; a walk never hands a path to
/// `CreateFileW`, and refuses them all the same.
fn device_free_full_path(path: &Path) -> io::Result<String> {
  let raw = path.as_os_str();
  let full = if raw.eq_ignore_ascii_case("CONIN$") || raw.eq_ignore_ascii_case("CONOUT$") {
    None
  } else {
    Some(full_path(path)?).filter(|full| !names_a_device(full))
  };
  full.ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidInput,
      "the path names a device, which is on no volume and is not opened",
    )
  })
}

/// The full path Windows makes of `path`, without touching anything:
/// `GetFullPathNameW`, which works on the string and the current directory
/// alone. It reports the length it needs, terminator included, and then the
/// length it wrote, without it; only that much is decoded. A path with a NUL
/// inside it is refused, as `canonicalize` refuses it: the call would read
/// only the part before it.
fn full_path(path: &Path) -> io::Result<String> {
  use windows_sys::Win32::Storage::FileSystem::GetFullPathNameW;

  let wide = to_wide(path);
  if wide[..wide.len() - 1].contains(&0) {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "a path with a NUL inside it names nothing",
    ));
  }
  let mut buffer = vec![0u16; 260];
  for _ in 0..4 {
    // SAFETY: `wide` is NUL-terminated and `buffer` live and as long as
    // declared for the call; no file-part pointer is asked for.
    let len = unsafe {
      GetFullPathNameW(
        wide.as_ptr(),
        buffer.len() as u32,
        buffer.as_mut_ptr(),
        core::ptr::null_mut(),
      )
    } as usize;
    if len == 0 {
      return Err(io::Error::last_os_error());
    }
    if len < buffer.len() {
      return wide_text(&buffer[..len]);
    }
    if len > 32_768 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "a full path longer than any path",
      ));
    }
    buffer.resize(len, 0);
  }
  Err(io::Error::other("the full path kept growing"))
}

/// Whether a full path — [`full_path`]'s answer — names a device rather than a
/// file on a volume. `GetFullPathNameW` is the conversion `CreateFileW` makes
/// of a path before it opens it, so a DOS device name comes back as the device
/// the open would reach: `NUL` as `\\.\NUL`, `COM1` as `\\.\COM1`. A device
/// is:
///
/// - anything in the Win32 device namespace (`\\.\` or `\\?\`) but a drive's
///   root (`C:\`), a share (`UNC\`) or a volume GUID's root spelled exactly
///   (`Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\`, see [`volume_name`]):
///   a port, `NUL`, a raw drive (`\\.\PhysicalDrive0`, `\\.\C:`), a named
///   pipe (`\\.\pipe\…`), a path through `GLOBALROOT`, and any other name
///   that only begins like a volume's (`\\?\Volume{pipe}\…`), which a link a
///   service or a driver defined could map onto anything;
/// - a host's `pipe`, `mailslot` or `IPC$` share, however it is spelled
///   (`\\host\pipe\…`, `\\?\UNC\host\pipe\…`): the named-pipe and mailslot
///   file systems of that host, which no volume is;
/// - a UNC path whose server or share is no name — empty, `.` or `..` — or
///   whose server begins with `;`, the multiple UNC provider's own form for a
///   redirector named after it (`\\;LanmanRedirector\;Z:…\host\pipe`), in
///   which the component after the server is no share at all: see
///   [`is_share_name`].
///
/// **Resolving a path never acts on the object it names.** Opening a serial
/// port raises its DTR line, which resets some boards, and opening a named
/// pipe connects to its server and takes one of its instances; a device is on
/// no volume, so there is nothing for a resolve to find there, and it is
/// refused before anything is opened. **Every root is admitted only in the
/// exact shape the walk will open**, by the parser the walk names it with:
/// nothing is admitted loosely here and parsed later.
fn names_a_device(full: &str) -> bool {
  let unc = match full
    .strip_prefix(r"\\.\")
    .or_else(|| full.strip_prefix(r"\\?\"))
  {
    Some(rest) => {
      let bytes = rest.as_bytes();
      let drive_root =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
      if drive_root || volume_name(rest).is_some() {
        return false;
      }
      match rest.get(..4) {
        Some(head) if head.eq_ignore_ascii_case(r"UNC\") => &rest[4..],
        _ => return true,
      }
    }
    None => match full.strip_prefix(r"\\") {
      Some(unc) => unc,
      None => return false,
    },
  };
  // `host\share\…`: both must be names, and the share decides.
  let mut parts = unc.split('\\');
  match (parts.next(), parts.next()) {
    (Some(server), Some(share)) => {
      !is_share_name(server, share)
        || ["pipe", "mailslot", "IPC$"]
          .iter()
          .any(|device| share.eq_ignore_ascii_case(device))
    }
    // A server with no share after it is no path to anything on a volume;
    // the walk refuses it as no full path.
    _ => false,
  }
}

/// Whether `server` and `share` name a share on a server: each non-empty and
/// neither `.` nor `..`, and the server not beginning with `;`. The multiple
/// UNC provider reads a first component that begins with `;` as the name of
/// a redirector, not of a server (`\Device\Mup\;LanmanRedirector\…`, which is
/// what `\Device\LanmanRedirector` links to), so the components after it are
/// that redirector's own — a connection, then a server and a share — and the
/// second is no share at all.
fn is_share_name(server: &str, share: &str) -> bool {
  let named = |part: &str| !part.is_empty() && part != "." && part != "..";
  named(server) && named(share) && !server.starts_with(';')
}

/// The volume GUID name `rest` begins with, spelled exactly —
/// `Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`, the word in either case
/// and the GUID as 8-4-4-4-12 hexadecimal digits of either case — and
/// followed by a separator: the root of a volume. `None` for any other
/// spelling, which names no volume the mount manager made.
fn volume_name(rest: &str) -> Option<&str> {
  const WORD: &str = "Volume{";
  const LEN: usize = WORD.len() + GUID_LEN + 1;
  let name = rest.get(..LEN)?;
  let guid = name
    .get(..WORD.len())
    .filter(|word| word.eq_ignore_ascii_case(WORD))
    .and(name.get(WORD.len()..LEN - 1))?;
  (is_guid(guid) && name.ends_with('}') && rest[LEN..].starts_with('\\')).then_some(name)
}

/// How long a GUID is, spelled 8-4-4-4-12.
const GUID_LEN: usize = 36;

/// Whether `text` is exactly a GUID spelled 8-4-4-4-12 in hexadecimal digits
/// of either case, and nothing else.
fn is_guid(text: &str) -> bool {
  let mut groups = text.split('-');
  [8, 4, 4, 4, 12].iter().all(|&width| {
    groups.next().is_some_and(|group| {
      group.len() == width && group.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
  }) && groups.next().is_none()
}

/// A caller's path, walked to the object it names one component at a time,
/// with nothing along the way followed by the system.
///
/// **No caller path is opened or followed until it is proven to stay in the
/// file system namespace.** `CreateFileW` — and `canonicalize` on top of it —
/// follows every reparse point on the way, and a symbolic link or a junction
/// may lead to a named pipe or a serial port as readily as to a folder: one an
/// unprivileged user plants in a folder a resolve walks through would have
/// connected the resolve to that user's pipe server. So a resolve never hands
/// the system a path to follow:
///
/// 1. **The root is opened by name, and nothing else is.** A drive letter's
///    definition in the caller's logon session is read first, whole
///    (`QueryDosDeviceW`; see [`letter_target_in`](walk::letter_target_in)),
///    and read as the object manager reads it, without regard to case (see
///    [`classified`](walk::classified)): a letter defined onto a path — `subst`,
///    or any spelling of the DOS device namespace, `\??\`, `\DosDevices\`,
///    `\GLOBAL??\` — has that path walked instead, so no folder on the way to
///    it is followed unseen; a letter defined onto a device with nothing after
///    it has exactly the device the query answered opened, never the letter
///    again, and nothing beneath that device's root until the root is proven
///    a local file system's (see [`file_system_root`](walk::file_system_root));
///    a mapped drive's connection is opened through its share, which
///    must be a network root, and its folders after the share are walked; and
///    any other definition is refused. A failed query is the walk's error. A
///    share's root and a volume GUID's root are opened through the global
///    namespace (`\GLOBAL??\`), which no user's session can shadow. **After a
///    link, no root that names a server is opened**: a share and a
///    connection are refused before any open, so a link cannot make a resolve
///    look a host up, connect to it or offer it credentials.
/// 2. **Each component is opened relative to the handle on the one before**
///    (`NtCreateFile` with a root directory), with `FILE_OPEN_REPARSE_POINT`,
///    for no access beyond its attributes: the name is looked up in the
///    directory the walk holds, and a reparse point there is opened as itself,
///    never followed.
/// 3. **Each is asked whether it is a reparse point, and of which kind**
///    (`FileAttributeTagInfo`). A data reparse point — a cloud file's
///    placeholder, a deduplicated file, a Unix socket — is a file like any
///    other, and the walk goes on through it. A name surrogate is a
///    redirection, and is followed only after its target is read through the
///    very handle that holds it (`FSCTL_GET_REPARSE_POINT`) and proven to be a
///    drive's, a share's or a volume GUID's path — never the device namespace:
///    see [`win32_of`](walk::win32_of) and [`names_a_device`]. An absolute
///    target is walked from its own root again, the same way; a relative one
///    is resolved against the folders the walk holds, below.
///
/// Refused by name, before anything is opened beyond the link itself:
///
/// - a name surrogate that is neither a symbolic link nor a junction — the
///   walk reads no other kind's target, and follows nothing it has not read;
/// - any link on a network share, and any link from a local volume that leads
///   to one: Windows evaluates those under a policy of its own
///   (`fsutil behavior set SymlinkEvaluation`) that a walk which follows by
///   hand cannot honour, and a junction's target on a share is a path on the
///   server, not here;
/// - a relative link whose `..` climbs above its volume's root;
/// - a path with an empty, `.` or `..` component the system would not have
///   resolved — `GetFullPathNameW` has already resolved them in every path
///   but a `\\?\` one, where the file system refuses them too;
/// - more than 63 links followed, which is `ERROR_CANT_RESOLVE_FILENAME`,
///   the error `CreateFileW` gives a loop.
///
/// **Every directory on the way is held, from the root down, for the whole
/// walk**, which is what proves no link on the way was followed, and what a
/// relative link is resolved against: its names are opened beneath the folder
/// that holds the link, and `..` returns to the folder held above it — see
/// [`walk_with`](walk::walk_with). No folder already inspected is looked up
/// by name again, so a folder renamed or replaced, or a drive letter defined
/// anew, while the walk runs changes nothing it resolves. A directory this
/// process may not open for its attributes — whose access list names the
/// caller nowhere, which an open by full path passes through on the traverse
/// privilege — ends the walk with the access error it gives.
///
/// What is left is a DOS device name the caller's own logon session, or an
/// administrator, defines onto a device (`DefineDosDevice`): a drive letter so
/// defined, onto `\Device\<name>` with nothing after it, has that device's
/// root opened, as the query answered it, and nothing beneath the root unless
/// the device is one a local file system serves: a letter onto the named-pipe
/// file system, a port or a redirector's bare device opens its root and no
/// more. The mount manager's by-name queries — `FindFirstVolumeW`,
/// `FindNextVolumeW`, `GetVolumePathNamesForVolumeNameW` — open
/// `\\.\MountPointManager` by a DOS name a session could shadow too; a shadow
/// can only make them fail, since no other device answers the mount manager's
/// control codes, and every row stays bound by its GUID root handle. Every
/// letter the system and the mount manager make names a volume or a
/// redirector's connection, and refusing the rest would refuse the file
/// systems a user mounts with a letter of their own (WinFsp, Dokan) — a local
/// one; one mounted as a network file system on a bare device is refused
/// with the redirectors' bare devices, which it cannot be told from.
mod walk {
  use std::{
    collections::VecDeque,
    fs::File,
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
  };

  use windows_sys::{
    Wdk::{
      Foundation::OBJECT_ATTRIBUTES,
      Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile, SYMLINK_FLAG_RELATIVE,
      },
    },
    Win32::{
      Foundation::{
        ERROR_CANT_RESOLVE_FILENAME, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER,
        ERROR_NOT_SUPPORTED, HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
      },
      Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileAttributeTagInfo, FileBasicInfo, GetFileInformationByHandleEx,
        MAXIMUM_REPARSE_DATA_BUFFER_SIZE, QueryDosDeviceW, SYNCHRONIZE,
      },
      System::{
        IO::{DeviceIoControl, IO_STATUS_BLOCK},
        Ioctl::{FILE_DEVICE_NETWORK_FILE_SYSTEM, FSCTL_GET_REPARSE_POINT},
      },
    },
  };

  use super::{
    super::filled::{Filled, KernelBuffer, invalid},
    Reading, is_share_name, names_a_device, volume_name, wide_text,
  };

  /// How many links one walk follows before it answers as `CreateFileW`
  /// answers a loop.
  const FOLLOWS: usize = 63;

  /// The refusal of a network path reached through a link on a local volume.
  const LINKED_TO_NETWORK: &str =
    "a link on a local volume leads to a network path, which a resolve does not follow";

  /// `FILE_REMOTE_DEVICE` (`wdm.h`): a device characteristic the I/O manager
  /// reports for every volume a redirector serves. Defined locally, as the
  /// two tags below are, rather than pulling in a feature for one stable
  /// constant; a law holds all three to the binding crate's own.
  pub(super) const FILE_REMOTE_DEVICE: u32 = 0x10;

  /// `IO_REPARSE_TAG_SYMLINK` (`winnt.h`): a symbolic link.
  pub(super) const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

  /// `IO_REPARSE_TAG_MOUNT_POINT` (`winnt.h`): a junction, or a volume
  /// mounted in a folder.
  pub(super) const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

  /// The reparse data a walk may read: `MAXIMUM_REPARSE_DATA_BUFFER_SIZE`.
  const REPARSE_LEN: usize = MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize;

  /// Walks `full` — a full path, [`full_path`](super::full_path)'s answer or
  /// a link's target — to the object it names, and returns the one handle on
  /// it, opened for no access beyond its attributes. See the module.
  pub(super) fn walk(full: &str) -> io::Result<File> {
    walk_with(full, || {})
  }

  /// [`walk`], with `between` run after each link's target is read and the
  /// link let go, and before the target is walked — where a law moves a
  /// folder the walk holds.
  ///
  /// **Every folder the walk enters is held, from the root down, for the
  /// whole walk**, and a relative link is resolved against those handles:
  /// its target's names are opened beneath the folder that holds the link,
  /// `..` returns to the folder held above it, and a target that begins with
  /// a separator returns to the root — see [`relative_steps`]. No folder
  /// already inspected is looked up by name again, so a folder renamed or
  /// replaced, or a drive letter defined anew, while the walk is under way
  /// changes nothing it resolves. Only an absolute target, a path by its
  /// nature, is walked from its own root again.
  pub(super) fn walk_with(full: &str, mut between: impl FnMut()) -> io::Result<File> {
    let mut path = full.to_owned();
    let mut follows = 0usize;
    // Whether the walk has followed a link on a volume, which a network path
    // may not be reached through.
    let mut linked = false;
    'path: loop {
      let (root, parts) = split(&path)?;
      // **After a link, no root that names a server is opened**: opening one
      // is the network's I/O — a name lookup, a connection, credentials
      // offered — which a refusal after the open would come too late for. A
      // share and a redirector's connection name a server by their form and
      // are refused before any open. Every other root a letter can reach
      // names none: a device with nothing after it, whose root is opened and
      // then proven a file system's before anything is opened beneath it.
      //
      // Each arm answers the root it opened, the folders on a connection's
      // share to walk, and whether the root was named as a network share's —
      // by a share's path or a connection's — which is what it must then be
      // proven to be.
      let (root, beneath, network) = match root {
        Root::Drive(letter) => match letter_target(letter)? {
          LetterTarget::Path(target) => {
            follows += 1;
            if follows > FOLLOWS {
              return Err(too_many_links());
            }
            path = appended(target, &parts);
            continue 'path;
          }
          // The exact device the query answered, never the letter again: a
          // letter redefined after the query is not what is opened.
          LetterTarget::Device(device) => {
            (open(None, &format!(r"{device}\"), true)?, Vec::new(), false)
          }
          LetterTarget::Connection {
            device,
            connection,
            beneath,
          } => {
            if linked {
              return Err(refused(LINKED_TO_NETWORK));
            }
            // The redirector's own device first: an open of the device
            // object, which names no server and resolves no folder, and the
            // I/O manager's word that it is a network device. The same form
            // onto a local volume — a folder named `;…` on it, a junction
            // beneath — is refused here, before any component of it is
            // resolved.
            if remoteness(&open_device(&device)?) != Some(true) {
              return Err(refused(
                "a drive letter defined onto a connection whose device is no network device",
              ));
            }
            let root = open(None, &format!(r"{connection}\"), true)?;
            if remoteness(&root) != Some(true) {
              return Err(refused(
                "a drive letter defined onto a connection that reaches no network share",
              ));
            }
            (root, beneath, true)
          }
        },
        Root::Share(share) => {
          if linked {
            return Err(refused(LINKED_TO_NETWORK));
          }
          (
            open(None, &format!(r"\GLOBAL??\UNC\{share}\"), true)?,
            Vec::new(),
            true,
          )
        }
        Root::Volume(guid) => (
          open(None, &format!(r"\GLOBAL??\{guid}\"), true)?,
          Vec::new(),
          false,
        ),
      };
      // **Nothing is opened beneath a root until the root is proven a file
      // system's**: see [`file_system_root`]. A root named as a share must be
      // a network one, and every other root a local volume's, so what a link
      // on it may reach follows from how it was named: no link on a network
      // share is followed, and none is reached through one — a share and a
      // connection are refused after a link before they are opened.
      file_system_root(&root, network)?;
      let remote = network;
      // Every folder entered beneath the root, in order, each held by the
      // handle it was opened through.
      let mut held: Vec<File> = Vec::new();
      // A connection's folders on its share, walked as every folder on a share
      // is: a link among them is not followed.
      for name in &beneath {
        let child = open(Some(held.last().unwrap_or(&root)), name, false)?;
        if reparse_tag(&child)?.is_some_and(is_name_surrogate) {
          return Err(refused(
            "a link on a network share, which a resolve does not follow",
          ));
        }
        held.push(child);
      }
      let mut names: VecDeque<String> = parts.into();
      while let Some(name) = names.pop_front() {
        let child = open(Some(held.last().unwrap_or(&root)), &name, false)?;
        let Some(tag) = reparse_tag(&child)? else {
          held.push(child);
          continue;
        };
        if !is_name_surrogate(tag) {
          held.push(child);
          continue;
        }
        if remote {
          return Err(refused(
            "a link on a network share, which a resolve does not follow",
          ));
        }
        follows += 1;
        if follows > FOLLOWS {
          return Err(too_many_links());
        }
        let target = link_target(&child, tag)?;
        drop(child);
        linked = true;
        between();
        match target {
          Target::Absolute(nt) => {
            let next = win32_of(&nt).ok_or_else(|| {
              refused("a link whose target is not a path on a drive, a share or a volume")
            })?;
            path = appended(next, names.make_contiguous());
            continue 'path;
          }
          // Resolved against the folders held: the link's own folder is the
          // last of them, and none is looked up by name again.
          Target::Relative(relative) => {
            let (keep, steps) = relative_steps(held.len(), &relative)
              .ok_or_else(|| refused("a relative link that climbs above its volume's root"))?;
            held.truncate(keep);
            for step in steps.into_iter().rev() {
              names.push_front(step);
            }
          }
        }
      }
      return Ok(held.pop().unwrap_or(root));
    }
  }

  /// What a relative link's target does to the folders a walk holds beneath
  /// its root, `depth` of them, the last of which holds the link: how many of
  /// them it keeps, and the names it then opens beneath the last one kept, in
  /// order. Windows reads a relative link's `.` and `..` lexically, against the
  /// path the link was reached by, and so does this — against the handles
  /// held for that path's folders: a `..` after a name of the target takes
  /// the name back, any other `..` leaves one folder held, a target that
  /// begins with a separator leaves them all, and `.` and empty names are
  /// passed over. `None` where `..` would climb above the root.
  pub(super) fn relative_steps(depth: usize, target: &str) -> Option<(usize, Vec<String>)> {
    let mut keep = if target.starts_with('\\') { 0 } else { depth };
    let mut steps: Vec<String> = Vec::new();
    for part in target.split('\\') {
      match part {
        "" | "." => {}
        ".." => {
          if steps.pop().is_none() {
            keep = keep.checked_sub(1)?;
          }
        }
        name => steps.push(name.to_owned()),
      }
    }
    Some((keep, steps))
  }

  /// The root a full path begins at.
  #[derive(Debug, PartialEq, Eq)]
  pub(super) enum Root {
    /// A drive letter, `C:\`, as its ASCII letter.
    Drive(u8),
    /// A share, `\\server\share\`, as `server\share`.
    Share(String),
    /// A volume GUID's root, `\\?\Volume{…}\`, as `Volume{…}`.
    Volume(String),
  }

  /// A full path, as the root it begins at and the components after it —
  /// or the refusal of one that names a device, or has a component the
  /// system would not have resolved: see the module.
  pub(super) fn split(path: &str) -> io::Result<(Root, Vec<String>)> {
    if names_a_device(path) {
      return Err(refused(
        "the path names a device, which is on no volume and is not opened",
      ));
    }
    let (root, tail) = match path
      .strip_prefix(r"\\?\")
      .or_else(|| path.strip_prefix(r"\\.\"))
    {
      Some(rest) => {
        if let Some(letter) = drive(rest) {
          (Root::Drive(letter), &rest[3..])
        } else if rest
          .get(..4)
          .is_some_and(|head| head.eq_ignore_ascii_case(r"UNC\"))
        {
          share(&rest[4..])?
        } else {
          // `names_a_device` let only a volume GUID's root spelled exactly
          // through, and the root is named by the same parser: nothing opened
          // as a volume was admitted in any looser shape.
          let name = volume_name(rest).ok_or_else(|| {
            refused("the path names a device, which is on no volume and is not opened")
          })?;
          (Root::Volume(name.to_owned()), &rest[name.len() + 1..])
        }
      }
      None => match path.strip_prefix(r"\\") {
        Some(rest) => share(rest)?,
        None => (Root::Drive(drive(path).ok_or_else(not_full)?), &path[3..]),
      },
    };
    let mut parts: Vec<String> = tail.split('\\').map(str::to_owned).collect();
    // A separator at the end names the directory itself.
    if parts.last().is_some_and(String::is_empty) {
      parts.pop();
    }
    if parts
      .iter()
      .any(|part| part.is_empty() || part == "." || part == "..")
    {
      return Err(refused(
        "a path with an empty, `.` or `..` component, which the file system does not resolve",
      ));
    }
    Ok((root, parts))
  }

  /// The drive letter `rest` begins with, `X:\`, or `None`.
  fn drive(rest: &str) -> Option<u8> {
    let bytes = rest.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
      .then(|| bytes[0].to_ascii_uppercase())
  }

  /// A share's root, `server\share`, and the rest of the path after it: a
  /// server and a share each a name — see [`is_share_name`] — or no full
  /// path.
  fn share(rest: &str) -> io::Result<(Root, &str)> {
    let mut halves = rest.splitn(3, '\\');
    let (Some(server), Some(share)) = (halves.next(), halves.next()) else {
      return Err(not_full());
    };
    if !is_share_name(server, share) {
      return Err(not_full());
    }
    Ok((
      Root::Share(format!(r"{server}\{share}")),
      halves.next().unwrap_or(""),
    ))
  }

  /// `path` with `parts` after it.
  fn appended(mut path: String, parts: &[String]) -> String {
    for part in parts {
      if !path.ends_with('\\') {
        path.push('\\');
      }
      path.push_str(part);
    }
    path
  }

  /// The Win32 spelling of a link's absolute target — the NT path its reparse
  /// point holds — where that target is a drive's, a share's or a volume
  /// GUID's path: `\??\C:\…` becomes `\\?\C:\…`. `None` for anything else —
  /// a path into the device namespace (`\??\pipe\…`, `\??\COM1`,
  /// `\Device\…`), or one that names no root at all.
  pub(super) fn win32_of(nt: &str) -> Option<String> {
    let rest = nt.strip_prefix(r"\??\")?;
    let win32 = format!(r"\\?\{rest}");
    split(&win32).ok().map(|_| win32)
  }

  /// What a drive letter stands for, as the caller's logon session defines it
  /// now: see [`letter_target`] and [`classified`].
  #[derive(Debug, PartialEq, Eq)]
  pub(super) enum LetterTarget {
    /// A path — `subst`, or a definition onto a DOS path through any spelling
    /// of the DOS device namespace — in Win32 spelling, which the walk walks
    /// like any other path.
    Path(String),
    /// A device, `\Device\<name>` with nothing after it — a volume, or
    /// whatever else the definition names — whose root is opened exactly as
    /// the query answered it. No component of a file system lies on the way.
    Device(String),
    /// A network redirector's connection to a share,
    /// `\Device\<redirector>\;<connection>\<server>\<share>`, and the folders
    /// the definition names on the share after it.
    Connection {
      /// The redirector's own device, `\Device\<redirector>`, which is opened
      /// first and must answer that it is a network device before anything
      /// else is opened.
      device: String,
      /// The connection's path through the share, which is then opened as the
      /// query answered it and must be a network root.
      connection: String,
      /// The folders after the share, which the walk walks.
      beneath: Vec<String>,
    },
  }

  /// `text` without `prefix`, matched as the object manager matches a name
  /// opened with `OBJ_CASE_INSENSITIVE`: without regard to ASCII case.
  fn strip_ignoring_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head
      .eq_ignore_ascii_case(prefix)
      .then(|| &text[prefix.len()..])
  }

  /// What a drive letter's definition, `definition`, names: see
  /// [`LetterTarget`].
  ///
  /// **The definition is read as the object manager will read it**, which is
  /// without regard to case (`NtCreateFile` is given `OBJ_CASE_INSENSITIVE`):
  ///
  /// - Every spelling of the DOS device namespace — `\??\`, `\DosDevices\`,
  ///   `\GLOBAL??\` (so `\Global??\`, `\dOsDeViCeS\`), and `GLOBAL\` after the
  ///   session's own, which is the global directory again — names a DOS path,
  ///   which is walked one component at a time like any other path: never
  ///   handed to one open that would resolve its folders unseen. One that
  ///   names another drive letter through the global directory is refused,
  ///   since the walk looks a letter up in the caller's session.
  /// - `\Device\<name>`, with nothing after it, is a device whose root is
  ///   opened as defined: no folder of a file system lies on the way.
  /// - `\Device\<redirector>\;<connection>\<server>\<share>` is a network
  ///   redirector's connection — what a mapped drive is defined onto — whose
  ///   prefix no file system serves and no walk could open a component at a
  ///   time. The redirector's device, `\Device\<redirector>`, is named apart:
  ///   the walk opens it first and requires a network device of it, and only
  ///   then opens the connection as defined, through the share; what the
  ///   definition names after the share is walked.
  /// - Anything else is refused: a device with a path after it, where one
  ///   open would resolve a file system's folders unseen, and any name
  ///   outside the DOS and device namespaces.
  pub(super) fn classified(definition: &str) -> io::Result<LetterTarget> {
    const OUTSIDE: &str = "a drive letter defined onto a path on a device, or onto an object \
                           outside the DOS and device namespaces, which the walk cannot prove \
                           one component at a time";

    let dos = strip_ignoring_case(definition, r"\GLOBAL??\")
      .map(|rest| (true, rest))
      .or_else(|| {
        strip_ignoring_case(definition, r"\??\")
          .or_else(|| strip_ignoring_case(definition, r"\DosDevices\"))
          .map(|rest| (false, rest))
      });
    if let Some((mut global, mut rest)) = dos {
      while let Some(inner) = strip_ignoring_case(rest, r"GLOBAL\") {
        global = true;
        rest = inner;
      }
      let bytes = rest.as_bytes();
      if global && bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(refused(
          "a drive letter defined onto another letter through the global namespace, which the \
           walk would look up in the caller's session",
        ));
      }
      return Ok(LetterTarget::Path(format!(r"\\?\{rest}")));
    }

    let whole = definition.strip_suffix('\\').unwrap_or(definition);
    let body = strip_ignoring_case(whole, r"\Device\").ok_or_else(|| refused(OUTSIDE))?;
    let parts: Vec<&str> = body.split('\\').collect();
    if parts
      .iter()
      .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
      return Err(refused(OUTSIDE));
    }
    match parts.as_slice() {
      [_] => Ok(LetterTarget::Device(whole.to_owned())),
      [device, connection, server, share, beneath @ ..] if connection.starts_with(';') => {
        // The server and the share are held to what a caller's own share path
        // is held to: names, and no host's named-pipe or mailslot file system.
        if !is_share_name(server, share)
          || ["pipe", "mailslot", "IPC$"]
            .iter()
            .any(|device| share.eq_ignore_ascii_case(device))
        {
          return Err(refused(OUTSIDE));
        }
        // `\Device\` and the device's name are the prefix the device is; each
        // folder after the share is one separator and its name.
        let device_len = whole.len() - body.len() + device.len();
        let beneath_len: usize = beneath.iter().map(|part| part.len() + 1).sum();
        Ok(LetterTarget::Connection {
          device: whole[..device_len].to_owned(),
          connection: whole[..whole.len() - beneath_len].to_owned(),
          beneath: beneath.iter().map(|part| (*part).to_owned()).collect(),
        })
      }
      _ => Err(refused(OUTSIDE)),
    }
  }

  /// What drive letter `letter` stands for: `QueryDosDeviceW`, read whole —
  /// see [`letter_target_in`].
  fn letter_target(letter: u8) -> io::Result<LetterTarget> {
    letter_target_in(letter, 256)
  }

  /// [`letter_target`], asked first with room for `len` units, which a law
  /// makes small.
  ///
  /// **A failed query is no mapping, and is refused.** The call fails for a
  /// buffer too small (`ERROR_INSUFFICIENT_BUFFER`), which is asked again at
  /// twice the room until the mapping is whole or longer than any mapping is;
  /// any other failure — a letter defined onto nothing among them — is the
  /// walk's error, never a letter to open by name. The answer is a
  /// multi-string of the definition in force and those it replaced, and the
  /// call reports how many units it wrote, which is all that is read: the
  /// first string is the definition, and [`classified`] says what it names. A
  /// definition that is empty or is not UTF-16 is `InvalidData`.
  pub(super) fn letter_target_in(letter: u8, len: usize) -> io::Result<LetterTarget> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;

    /// Longer than any definition a letter holds.
    const LIMIT: usize = 1 << 20;

    let name: Vec<u16> = [u16::from(letter), u16::from(b':'), 0].to_vec();
    let mut len = len.max(1);
    let units = loop {
      let mut target = vec![0u16; len];
      // SAFETY: `name` is NUL-terminated, and `target` live and as long as
      // declared for the call; the call writes a multi-string within it and
      // reports how many units it wrote.
      let written =
        unsafe { QueryDosDeviceW(name.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
      if written != 0 {
        target.truncate(written as usize);
        break target;
      }
      let err = io::Error::last_os_error();
      if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(err);
      }
      len *= 2;
      if len > LIMIT {
        return Err(invalid("a drive letter's definition longer than any path"));
      }
    };
    let first = units.split(|&unit| unit == 0).next().unwrap_or(&[]);
    if first.is_empty() {
      return Err(invalid(
        "a drive letter defined onto nothing the query spelled",
      ));
    }
    classified(&wide_text(first)?)
  }

  /// Opens `name` — beneath `parent`, or, with none, an NT path from the
  /// object namespace's root — as itself, reparse point or not, for no access
  /// beyond its attributes, sharing it with everything; `directory` refuses
  /// anything but a directory. The one open a walk makes: see the module.
  pub(super) fn open(parent: Option<&File>, name: &str, directory: bool) -> io::Result<File> {
    let options = FILE_OPEN_FOR_BACKUP_INTENT
      | FILE_OPEN_REPARSE_POINT
      | if directory { FILE_DIRECTORY_FILE } else { 0 };
    nt_open(parent, name, options)
  }

  /// Opens a device by its NT path, `name` — a volume's own device through
  /// `\GLOBAL??\Volume{…}`, or a redirector's `\Device\<name>`, with no
  /// separator after it — for no access beyond its attributes, sharing it
  /// with everything: the access, the sharing and the options `CreateFileW`
  /// gives a zero-access open of a device.
  pub(super) fn open_device(name: &str) -> io::Result<File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_NON_DIRECTORY_FILE;

    nt_open(None, name, FILE_NON_DIRECTORY_FILE)
  }

  /// The one `NtCreateFile` of this module: `name` beneath `parent`, or an NT
  /// path from the object namespace's root, opened as an existing object for
  /// `SYNCHRONIZE | FILE_READ_ATTRIBUTES` — which `CreateFileW` adds to every
  /// open, so a zero-access open asks exactly this — synchronously, sharing
  /// it with everything, with `options` besides.
  fn nt_open(parent: Option<&File>, name: &str, options: u32) -> io::Result<File> {
    let wide: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(wide.len() * 2)
      .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name longer than any path"))?;
    let object_name = UNICODE_STRING {
      Length: length,
      MaximumLength: length,
      Buffer: wide.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
      Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
      RootDirectory: parent.map_or(core::ptr::null_mut(), |parent| parent.as_raw_handle()),
      ObjectName: &object_name,
      Attributes: OBJ_CASE_INSENSITIVE,
      SecurityDescriptor: core::ptr::null(),
      SecurityQualityOfService: core::ptr::null(),
    };
    let options = FILE_SYNCHRONOUS_IO_NONALERT | options;
    let mut handle: HANDLE = core::ptr::null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: `handle` and `status` are live for the call to write; the
    // attributes, and the name and the wide string they point to, outlive it;
    // the parent handle, where there is one, is valid for as long as `parent`
    // is borrowed; and no allocation size or extended attributes are passed.
    let nt = unsafe {
      NtCreateFile(
        &mut handle,
        SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        &attributes,
        &mut status,
        core::ptr::null(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        options,
        core::ptr::null(),
        0,
      )
    };
    if nt < 0 {
      // SAFETY: a pure conversion of a status code.
      let code = unsafe { RtlNtStatusToDosError(nt) };
      return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: a successful open handed this call one handle, which nothing
    // else owns.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
  }

  /// **Whether a root the walk opened is a file system's, proven before any
  /// name is opened beneath it** — a network share's where the root was
  /// named as one (`network`), and a local volume's otherwise — or its
  /// refusal.
  ///
  /// A name opened beneath a root is handed to whatever serves the root's
  /// device, and only a file system reads it as a file's name. A drive letter
  /// a session defines onto `\Device\NamedPipe` makes `X:\name` an open of
  /// `name` beneath the named-pipe file system's root, which is a client's
  /// open of that pipe: it connects to the pipe's server and takes one of its
  /// instances before anything could be asked of the handle. A letter onto
  /// a redirector's bare device makes the first name a server's, looked up
  /// and connected to, and the next a share no share name was held to — the
  /// host's `pipe` among them.
  ///
  /// The proof is the device kind the I/O manager reports for the root
  /// (`FileFsDeviceInformation`), which the I/O manager answers from the
  /// device object itself for every device but a network file system's; the
  /// device serving it does not. A local root must be on a device a volume is
  /// mounted on — a disk, an optical drive or a RAM disk, the kinds the I/O
  /// manager gives a volume parameter block and so routes every open beneath
  /// to the file system mounted there — or be a file system's own device,
  /// and must not be remote; see [`opens_into_a_file_system`]. A network root
  /// must be a redirector's, as [`remoteness`] reads one. A root that does
  /// not answer is proven neither. The root itself is opened before it is
  /// asked, as it always was: that open names nothing beneath the device.
  pub(super) fn file_system_root(root: &File, network: bool) -> io::Result<()> {
    let device = match super::observed::device(root) {
      Reading::Value(device) => device,
      Reading::Failed(err) => return Err(err),
      Reading::Absent | Reading::Declined(_) => {
        return Err(refused(
          "a root whose device does not say what it is, beneath which nothing is opened",
        ));
      }
    };
    let proven = if network {
      is_remote(device)
    } else {
      opens_into_a_file_system(device)
    };
    if proven {
      Ok(())
    } else if network {
      Err(refused(
        "a share's root that is no network file system's, beneath which nothing is opened",
      ))
    } else {
      Err(refused(
        "a root on a device that is no local file system's — a named pipe, a mailslot, a \
         port, a redirector's bare device — beneath which nothing is opened",
      ))
    }
  }

  /// Whether a device kind is one every open beneath whose root reaches a
  /// local file system: not remote, and a disk, a CD-ROM or a RAM disk
  /// (`FILE_DEVICE_DISK`, `FILE_DEVICE_CD_ROM`, `FILE_DEVICE_VIRTUAL_DISK`) —
  /// the device objects `IoCreateDevice` gives a volume parameter block, on
  /// which the I/O manager mounts a file system, or the raw one, before any
  /// open reaches them — or a file system's own device
  /// (`FILE_DEVICE_DISK_FILE_SYSTEM`, `FILE_DEVICE_CD_ROM_FILE_SYSTEM`), whose
  /// driver is the file system. Anything else is refused: the named-pipe and
  /// mailslot file systems, whose names are pipes and mailslots; every other
  /// device, whose driver reads a name as it likes; a redirector, whose first
  /// name is a server; and a tape or a DVD kind, which no volume a letter
  /// names is on.
  pub(super) fn opens_into_a_file_system(device: super::FsDeviceInformation) -> bool {
    use windows_sys::Win32::{
      Storage::FileSystem::{FILE_DEVICE_CD_ROM, FILE_DEVICE_DISK},
      System::Ioctl::{
        FILE_DEVICE_CD_ROM_FILE_SYSTEM, FILE_DEVICE_DISK_FILE_SYSTEM, FILE_DEVICE_VIRTUAL_DISK,
      },
    };

    !is_remote(device)
      && [
        FILE_DEVICE_DISK,
        FILE_DEVICE_CD_ROM,
        FILE_DEVICE_VIRTUAL_DISK,
        FILE_DEVICE_DISK_FILE_SYSTEM,
        FILE_DEVICE_CD_ROM_FILE_SYSTEM,
      ]
      .contains(&device.device_type)
  }

  /// Whether a device kind is a network volume's: a network file system's
  /// device, or one the I/O manager reports remote.
  fn is_remote(device: super::FsDeviceInformation) -> bool {
    device.device_type == FILE_DEVICE_NETWORK_FILE_SYSTEM
      || device.characteristics & FILE_REMOTE_DEVICE != 0
  }

  /// Whether what the walk opened — a connection's root, or a redirector's
  /// device — is a network volume's: `Some(true)` for a device a redirector
  /// serves, by the kind or the characteristics the I/O manager reports for
  /// it (`FileFsDeviceInformation`; see [`is_remote`]), `Some(false)` for any
  /// other, and `None` where the device does not answer, which admits no
  /// connection.
  fn remoteness(root: &File) -> Option<bool> {
    match super::observed::device(root) {
      Reading::Value(device) => Some(is_remote(device)),
      Reading::Absent | Reading::Declined(_) | Reading::Failed(_) => None,
    }
  }

  /// The reparse tag of what `file` holds, or `None` where it is no reparse
  /// point: `FileAttributeTagInfo`. A file system that does not serve that
  /// class is asked its attributes instead (`FileBasicInfo`), and a reparse
  /// point whose tag it cannot say is refused, since nothing shows it is no
  /// link.
  pub(super) fn reparse_tag(file: &File) -> io::Result<Option<u32>> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO {
      FileAttributes: 0,
      ReparseTag: 0,
    };
    // SAFETY: `info` is live, and exactly as large as declared, for the call.
    let ok = unsafe {
      GetFileInformationByHandleEx(
        file.as_raw_handle(),
        FileAttributeTagInfo,
        (&raw mut info).cast(),
        core::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
      )
    };
    if ok != 0 {
      return Ok(
        (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0).then_some(info.ReparseTag),
      );
    }
    let err = io::Error::last_os_error();
    let unserved = [
      ERROR_INVALID_PARAMETER,
      ERROR_INVALID_FUNCTION,
      ERROR_NOT_SUPPORTED,
    ]
    .iter()
    .any(|&code| err.raw_os_error() == Some(code as i32));
    if !unserved {
      return Err(err);
    }
    let mut basic = FILE_BASIC_INFO {
      CreationTime: 0,
      LastAccessTime: 0,
      LastWriteTime: 0,
      ChangeTime: 0,
      FileAttributes: 0,
    };
    // SAFETY: `basic` is live, and exactly as large as declared, for the call.
    let ok = unsafe {
      GetFileInformationByHandleEx(
        file.as_raw_handle(),
        FileBasicInfo,
        (&raw mut basic).cast(),
        core::mem::size_of::<FILE_BASIC_INFO>() as u32,
      )
    };
    if ok == 0 {
      return Err(io::Error::last_os_error());
    }
    if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
      return Err(refused(
        "a reparse point whose kind its file system does not say, which a resolve does not follow",
      ));
    }
    Ok(None)
  }

  /// Whether a reparse tag marks a name surrogate — a redirection to another
  /// name, which a walk must not pass through unread: `IsReparseTagNameSurrogate`.
  pub(super) fn is_name_surrogate(tag: u32) -> bool {
    tag & 0x2000_0000 != 0
  }

  /// Where a link leads.
  #[derive(Debug, PartialEq, Eq)]
  pub(super) enum Target {
    /// An NT path: `\??\C:\…`, `\??\UNC\…`, `\??\Volume{…}\…`, or anything
    /// else a link may hold, which [`win32_of`] decides.
    Absolute(String),
    /// A symbolic link's path relative to the directory that holds it.
    Relative(String),
  }

  /// A link's target, read through the handle that holds the link:
  /// `FSCTL_GET_REPARSE_POINT`, a control code declared `FILE_ANY_ACCESS`.
  /// Only a symbolic link's and a junction's are read; every other name
  /// surrogate is refused by name, unread.
  fn link_target(link: &File, tag: u32) -> io::Result<Target> {
    if tag != IO_REPARSE_TAG_SYMLINK && tag != IO_REPARSE_TAG_MOUNT_POINT {
      return Err(refused(
        "a name-surrogate reparse point that is neither a symbolic link nor a junction, which a \
         resolve does not follow",
      ));
    }
    let mut buffer = KernelBuffer::<REPARSE_LEN>::new();
    let mut written: u32 = 0;
    // SAFETY: `buffer` is a live output buffer of exactly `REPARSE_LEN` bytes,
    // `written` a live count, and the handle is valid for as long as `link`
    // is borrowed; the control code takes no input.
    let ok = unsafe {
      DeviceIoControl(
        link.as_raw_handle(),
        FSCTL_GET_REPARSE_POINT,
        core::ptr::null(),
        0,
        buffer.as_mut_ptr(),
        REPARSE_LEN as u32,
        &mut written,
        core::ptr::null_mut(),
      )
    };
    if ok == 0 {
      return Err(io::Error::last_os_error());
    }
    target_in(buffer.filled(written as usize)?, tag)
  }

  /// The target a `REPARSE_DATA_BUFFER` (`ntifs.h`) holds, out of the bytes
  /// the file system said it wrote: an eight-byte header — the tag, the
  /// length of the data after it, two reserved bytes — and the data, which
  /// must end the answer exactly. A symbolic link's data is four `u16`s
  /// locating its two names, a `u32` of flags and the names; a junction's is
  /// the same without the flags. Only the substitute name is read — the path
  /// the system itself would follow — and it must lie wholly inside the data
  /// and be whole UTF-16. An answer for another tag than the one the walk
  /// asked about is a link that changed while it was read. Anything else is
  /// `InvalidData`.
  pub(super) fn target_in(answer: Filled<'_>, tag: u32) -> io::Result<Target> {
    const HEADER: usize = 8;

    if answer.u32_at(0)? != tag {
      return Err(io::Error::new(
        io::ErrorKind::NotFound,
        "the link changed while it was read",
      ));
    }
    let length = usize::from(u16::from_ne_bytes(answer.array(4)?));
    answer.tail(HEADER, length)?;
    let (names, relative) = if tag == IO_REPARSE_TAG_SYMLINK {
      (
        HEADER + 12,
        answer.u32_at(HEADER + 8)? & SYMLINK_FLAG_RELATIVE != 0,
      )
    } else {
      (HEADER + 8, false)
    };
    let offset = usize::from(u16::from_ne_bytes(answer.array(HEADER)?));
    let bytes = usize::from(u16::from_ne_bytes(answer.array(HEADER + 2)?));
    if bytes % 2 != 0 {
      return Err(invalid("a link's name of an odd number of bytes"));
    }
    let name = answer.bytes(names + offset, bytes)?;
    let units: Vec<u16> = name
      .chunks_exact(2)
      .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
      .collect();
    let name = wide_text(&units)?;
    Ok(if relative {
      Target::Relative(name)
    } else {
      Target::Absolute(name)
    })
  }

  /// The refusal of a path a resolve does not walk, by name.
  fn refused(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
  }

  /// The refusal of a path that is not a full path at all.
  fn not_full() -> io::Error {
    refused("a path that names no drive, share or volume root")
  }

  /// What `CreateFileW` answers a loop of links with.
  fn too_many_links() -> io::Error {
    io::Error::from_raw_os_error(ERROR_CANT_RESOLVE_FILENAME as i32)
  }
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
/// the observation keeps the handle for as long as it is kept. The one fact
/// the file system cannot answer on it — whether the storage leaves the
/// machine — is asked of the volume's own device, opened by the GUID path the
/// handle proved and held while it is asked: see
/// [`VolumeDevice`](observed::VolumeDevice).
mod observed {
  use std::{
    ffi::OsString,
    fs::File,
    io,
    os::windows::{ffi::OsStringExt as _, io::AsRawHandle as _},
    path::{Path, PathBuf},
  };

  use windows_sys::{
    Wdk::Storage::FileSystem::{
      FS_INFORMATION_CLASS, FileFsAttributeInformation, FileFsDeviceInformation,
      FileFsVolumeInformation, NtQueryVolumeInformationFile,
    },
    Win32::{
      Devices::{
        DeviceAndDriverInstallation::{
          CM_DRP_REMOVAL_POLICY, CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
          CM_Get_DevNode_Registry_PropertyW, CM_Get_Device_Interface_List_SizeW,
          CM_Get_Device_Interface_ListW, CM_Get_Device_Interface_PropertyW,
          CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CONFIGRET, CR_BUFFER_SMALL,
          CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_DEVNODE, CR_NO_SUCH_VALUE, CR_SUCCESS,
        },
        Properties::{DEVPKEY_Device_InstanceId, DEVPROP_TYPE_STRING, DEVPROPTYPE},
      },
      Foundation::RtlNtStatusToDosError,
      Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_GUID},
      System::{
        IO::{DeviceIoControl, IO_STATUS_BLOCK},
        Ioctl::{
          FSCTL_GET_NTFS_VOLUME_DATA, GUID_DEVINTERFACE_DISK, IOCTL_STORAGE_GET_DEVICE_NUMBER,
          IOCTL_STORAGE_QUERY_PROPERTY, NTFS_VOLUME_DATA_BUFFER, PropertyStandardQuery,
          STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
        },
      },
    },
  };

  #[cfg(feature = "disk-usage")]
  use {super::fs_full_size, windows_sys::Wdk::Storage::FileSystem::FileFsFullSizeInformation};
  #[cfg(feature = "list")]
  use {
    super::is_local_storage,
    windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW,
  };

  use super::{
    super::{
      Ejectability, IdentityAssurance, IdentityReading, MountPoint, NameReading, SmallBytes,
      VolumeCapabilities,
      filled::{Filled, KernelBuffer, SentinelBuffer, invalid},
      published_label, published_label_bytes,
      reading::Reading,
      windows_identity,
    },
    DeviceNumber, FILE_CASE_PRESERVED_NAMES, FsDeviceInformation, REG_DWORD, ShareRoot,
    StorageDescriptor, VolumeRoot, device_number, ejectability_of, fs_attribute, fs_device,
    fs_volume, is_fixed_local_disk, multi_string, policy_answer, reading, storage_descriptor,
    to_wide, wide_text,
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
    /// A resolve's observation of the object a walk holds — see [`walk`](super::walk)
    /// — and the object's canonical path. Nothing is found by a name the
    /// caller gave: the object's own handle names its path and its volume.
    ///
    /// 1. **The object names itself** twice through its handle
    ///    (`GetFinalPathNameByHandleW`): by its volume GUID path — the volume's
    ///    root and the path beneath it — and by its DOS path, which is the
    ///    canonical path a row reports. The mount point is the DOS path without
    ///    that path beneath the root. A volume with no DOS path — no drive
    ///    letter and no folder it is mounted in — is named by its GUID path,
    ///    which is then the canonical path, and its GUID root the mount point.
    ///    A network share has no GUID path, and its root is the share's own,
    ///    `\\?\UNC\server\share\`. See [`location_of`].
    /// 2. **The one handle is opened on that root** through the global
    ///    namespace, which no logon session can shadow — see
    ///    [`open_volume_root`] — and **proven to hold it** before anything is
    ///    read through it: its own final path must be exactly that root — see
    ///    [`proven_root`] — and **the object is asked again where it is**: its
    ///    own handle must still name the same place, on that root — see
    ///    [`still_located`].
    /// 3. **Every fact is read through it**, and last **the root is proven
    ///    again, and the object asked again**: see [`still_holds`].
    ///
    /// The second proof binds the removal answer: it was asked through the
    /// volume's own device, opened by the GUID name the first proof read, and a
    /// name is not the handle — a volume that left in between, and a clone
    /// given its GUID, would answer under it. The root handle still naming
    /// itself by the same root after every fact was read shows the name was
    /// its own throughout, as the listing's second proof does. A DOS path that
    /// does not end in the path beneath the root — the object moved between
    /// the two answers — and any other answer decline the observation.
    ///
    /// **The object's own handle binds the root to the object.** The root was
    /// opened by a name, and a name can pass to another volume while the
    /// object's handle stays on the first: a volume surprise-removed, and a
    /// clone of it given its GUID, would have the root, and every fact, be the
    /// clone's, beside the path of an object on a volume that has gone. So
    /// the object is asked again after the root is opened, and after the facts
    /// are read: a handle whose volume has left answers nothing, and a handle
    /// that names another root, mount point or path is no longer where the
    /// observation found it; each declines it.
    pub(super) fn of_object(object: &File) -> Reading<(Self, PathBuf)> {
      Self::of_located(|| location(object), Facts::read)
    }

    /// [`of_object`](Self::of_object), with the facts a law stands in for the
    /// ones the handle would answer.
    #[cfg(test)]
    pub(super) fn of_object_with(
      object: &File,
      read: impl FnOnce(&File, Option<&VolumeRoot>) -> io::Result<Facts>,
    ) -> Reading<(Self, PathBuf)> {
      Self::of_located(|| location(object), read)
    }

    /// [`of_object`](Self::of_object), with the object's location, as often
    /// as it is asked, and the facts, both stood in by a law.
    #[cfg(test)]
    pub(super) fn of_located_with(
      locate: impl FnMut() -> Reading<Location>,
      read: impl FnOnce(&File, Option<&VolumeRoot>) -> io::Result<Facts>,
    ) -> Reading<(Self, PathBuf)> {
      Self::of_located(locate, read)
    }

    /// The body of [`of_object`](Self::of_object): `locate` asks the object
    /// where it is — once to find the root, and again after the root is
    /// opened and after the facts are read.
    fn of_located(
      mut locate: impl FnMut() -> Reading<Location>,
      read: impl FnOnce(&File, Option<&VolumeRoot>) -> io::Result<Facts>,
    ) -> Reading<(Self, PathBuf)> {
      let (guid, mount_point, canonical) = match locate() {
        Reading::Value(location) => location,
        Reading::Absent => return Reading::Absent,
        Reading::Declined(err) => return Reading::Declined(err),
        Reading::Failed(err) => return Reading::Failed(err),
      };
      // The root the object lies on, exactly: its volume's GUID root, or the
      // very share its own path names.
      let expected = match &guid {
        Some(guid) => Proven::Volume(guid.clone()),
        None => match ShareRoot::parse(&mount_point) {
          Some(share) => Proven::Share(share),
          None => return Reading::Declined(not_a_root()),
        },
      };
      let opened = match &expected {
        Proven::Volume(guid) => open_volume_root(guid),
        Proven::Share(share) => open_share_root(share),
      };
      opened.and_then(move |root| {
        proven_root(&root).and_then(move |proven| {
          if !proven.is(&expected) {
            return Reading::Declined(not_a_root());
          }
          still_located(locate(), guid.as_ref(), &mount_point, &canonical).and_then(move |()| {
            match read(&root, guid.as_ref()) {
              Ok(facts) => still_holds(&root, &expected)
                .and_then(|()| still_located(locate(), guid.as_ref(), &mount_point, &canonical))
                .and_then(move |()| {
                  Reading::Value((
                    Self {
                      _root: root,
                      guid,
                      mount_paths: vec![mount_point],
                      facts,
                    },
                    PathBuf::from(canonical),
                  ))
                }),
              Err(err) => Reading::Failed(err),
            }
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
      open_volume_root(&guid).and_then(|handle| {
        holds_root(&handle, &guid)
          .and_then(|()| mount_paths(&guid))
          .and_then(|mount_paths| {
            // Mounted nowhere: the mount manager's own answer that there is
            // no row of this volume to describe, so nothing else is asked of
            // it.
            if mount_paths.is_empty() {
              return Reading::Absent;
            }
            let facts = match Facts::read(&handle, Some(&guid)) {
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
          capacity: Some((facts.capacity.0, facts.capacity.1)),
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
    /// Every fact of the volume's rows, read through the one handle, and the
    /// removal answer through the volume device `guid` names.
    ///
    /// The volume is asked to answer for itself first
    /// (`FileFsVolumeInformation`, which every file system serves). Where it
    /// declines — no medium, gone, not ours to look at — nothing else is asked
    /// of it, and the facts carry none of what it would have said. Past that,
    /// each field's decline ends in that field's documented absence and each
    /// failure is the error it is. The removal answer is the device kind's,
    /// and for a disk whose medium is fixed in it the volume device's: see
    /// [`removal`]. `guid` is the root the one handle was proven to hold, and
    /// `None` for a share, which has none.
    fn read(root: &File, guid: Option<&VolumeRoot>) -> io::Result<Self> {
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
      // The kind of device first, and the volume's own device where the kind
      // cannot answer: see [`removal`].
      let ejectability = removal(device, guid);
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

  /// What the volume's storage says about leaving the machine: the device
  /// kind's answer, and, for a local disk whose medium is fixed in it — which
  /// the kind has nothing to say about — its own device's.
  ///
  /// `guid` is the root the one handle was proven to hold, and the only name
  /// the volume device is opened by; a share has none, and is asked nothing.
  /// Every outcome of the device road but a value leaves the kind's answer
  /// standing, a failure included: the removal answer is `Unknown` wherever it
  /// could not be asked, which is that state's meaning, and it never fails a
  /// row — see [`Reading::evidence`]. That is also ruling 181's fallback, by
  /// name: a volume device this process may not open answers nothing, and the
  /// row's removal answer is the kind's.
  fn removal(device: Option<FsDeviceInformation>, guid: Option<&VolumeRoot>) -> Ejectability {
    // The kind was not named: nothing was said about removal.
    let Some(device) = device else {
      return Ejectability::Unknown;
    };
    let kind = ejectability_of(device);
    if kind.is_known() || !is_fixed_local_disk(device) {
      return kind;
    }
    match guid.and_then(|guid| VolumeDevice::open(guid).evidence()) {
      Some(volume) => volume.removal(),
      None => kind,
    }
  }

  /// The volume's own device: the one more handle a row may hold, opened only
  /// by the volume GUID path the row's one handle proved it holds, for no
  /// access at all, and asked the storage questions alone.
  ///
  /// **Opened by a name the one handle read, and by no other.** A GUID path
  /// read through the handle names the volume the handle holds, for as long as
  /// the volume is there. A second resolution of a *path* lands on whatever is
  /// mounted there by then, which is why a row is read through one handle; a
  /// GUID path is not such a resolution. The volume device is the proven root
  /// without its separator ([`VolumeRoot::device`]), and nothing a caller
  /// wrote goes into it.
  ///
  /// **For no access.** Every control code asked through it is declared
  /// `FILE_ANY_ACCESS`, and a handle with no access is what the system grants
  /// an unelevated process on a volume device — a law opens one under a
  /// restricted token on every Windows runner. It is a direct device open the
  /// file system never sees, so nothing but the device's own storage questions
  /// is answered through it — the disk it lies on and the device's storage
  /// descriptor — and nothing else is asked of it.
  #[derive(Debug)]
  pub(super) struct VolumeDevice(File);

  impl VolumeDevice {
    /// Opens the volume device `root` names for no access, sharing it with
    /// everything — **through the global namespace**, `\GLOBAL??\Volume{…}`
    /// with no separator after it, where [`open_volume_root`] opens the root
    /// the first proof holds: a DOS device name a logon session defines of
    /// its own is looked up before the global one through `\\?\`, and would
    /// leave the root describing one volume while this answered for another.
    pub(super) fn open(root: &VolumeRoot) -> Reading<Self> {
      // `\\?\Volume{…}` without its `\\?\`.
      let volume = &root.device()[4..];
      reading(super::walk::open_device(&format!(r"\GLOBAL??\{volume}"))).map(Self)
    }

    /// What the device says about leaving the machine.
    ///
    /// The platform's own answer first: the removal policy Plug and Play holds
    /// for the disk the volume lies on, where it is reached and bound — see
    /// [`removal_policy`](Self::removal_policy) and [`policy_answer`]. Where
    /// it is not, a yes where the storage descriptor gives one, and `Unknown`
    /// otherwise — a failure of either read included. See
    /// [`StorageDescriptor::says_removable`].
    fn removal(&self) -> Ejectability {
      match self.removal_policy().evidence().map(policy_answer) {
        Some(answer) if answer.is_known() => answer,
        _ => match self.descriptor().evidence() {
          Some(descriptor) if descriptor.says_removable() => Ejectability::Ejectable,
          _ => Ejectability::Unknown,
        },
      }
    }

    /// The removal policy Plug and Play holds for the disk this volume lies
    /// on (`CM_DRP_REMOVAL_POLICY`), reached from the storage device number
    /// read through this device and bound to it by hold-and-verify.
    ///
    /// 1. **The number**, read through this device: the kind and number of
    ///    the disk the volume lies on (`IOCTL_STORAGE_GET_DEVICE_NUMBER`). A
    ///    volume on more than one disk has none, and has no answer here.
    /// 2. **The disk**: every present disk interface the configuration
    ///    manager lists (`GUID_DEVINTERFACE_DISK`), each opened for no access
    ///    and asked its own number. Exactly one must carry this volume's —
    ///    none is no answer, and so are two. The configuration manager has no
    ///    other door from a device number to a device node, and a disk handle
    ///    is not a volume's: it names that disk and is matched by the number
    ///    alone.
    /// 3. **Its device node**: the interface's own instance id
    ///    (`DEVPKEY_Device_InstanceId`), located (`CM_Locate_DevNodeW`).
    /// 4. **The policy**, a `REG_DWORD`.
    /// 5. **The number again**, through this device and through the disk's
    ///    handle, both after the policy was read, and both still the one read
    ///    in 1. A handle keeps its device object, so the disk that handle
    ///    holds cannot have left and handed its number on while it answers the
    ///    same; a check that fails drops the answer.
    pub(super) fn removal_policy(&self) -> Reading<u32> {
      self.number().and_then(|number| {
        disk_carrying(number).and_then(|(interface, disk)| {
          instance_id(&interface)
            .and_then(|id| located(&id))
            .and_then(policy_of)
            .and_then(|policy| {
              match (self.number(), device_number_of(&disk)) {
                (Reading::Value(volume), Reading::Value(held))
                  if volume.names_disk(number) && held.names_disk(number) =>
                {
                  Reading::Value(policy)
                }
                // The volume or the disk no longer names what the policy was
                // read for: the answer is dropped.
                _ => Reading::Absent,
              }
            })
        })
      })
    }

    /// The storage device number this device answers: see
    /// [`device_number_of`].
    fn number(&self) -> Reading<DeviceNumber> {
      device_number_of(&self.0)
    }

    /// The device's storage descriptor: `IOCTL_STORAGE_QUERY_PROPERTY` with
    /// `StorageDeviceProperty` and `PropertyStandardQuery`.
    ///
    /// The descriptor is variable-sized — the vendor, product, revision and
    /// serial strings and the raw device properties follow its fixed part — and
    /// only the fixed part is read, so it is asked for once, into a buffer far
    /// longer than any descriptor a driver writes. The count the call reports
    /// is checked against the buffer before anything is read, and the answer
    /// is decoded out of that prefix alone: see [`descriptor_in`].
    pub(super) fn descriptor(&self) -> Reading<StorageDescriptor> {
      let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
      };
      let mut buffer = KernelBuffer::<{ storage_descriptor::LIMIT }>::new();
      let mut written: u32 = 0;
      // SAFETY: `query` is a live input buffer of exactly the size declared,
      // `buffer` a live output buffer of exactly `LIMIT` bytes that the driver
      // writes no further than, and `written` a live count; the handle is valid
      // for as long as `self` is borrowed. A `KernelBuffer` is bytes alone, so
      // whatever the driver writes, or leaves, is a value.
      let ok = unsafe {
        DeviceIoControl(
          self.0.as_raw_handle(),
          IOCTL_STORAGE_QUERY_PROPERTY,
          core::ptr::from_ref(&query).cast(),
          core::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
          buffer.as_mut_ptr(),
          storage_descriptor::LIMIT as u32,
          &mut written,
          core::ptr::null_mut(),
        )
      };
      if ok == 0 {
        return reading(Err(io::Error::last_os_error()));
      }
      decoded(buffer.filled(written as usize).and_then(descriptor_in))
    }
  }

  /// The removal fields of a `STORAGE_DEVICE_DESCRIPTOR` answer, read out of
  /// the bytes the driver said it wrote and nothing else, **and only as far
  /// as the descriptor's own version holds them**.
  ///
  /// `Version` is the size of the structure the driver wrote, and grows as
  /// members are added to it (*STORAGE_DEVICE_DESCRIPTOR*: "Contains the
  /// size of this structure, in bytes. The value of this member will change
  /// as members are added to the structure"); `Size` is the whole
  /// descriptor, the strings and bus data appended after the structure
  /// included. So a member is read only where the version covers it —
  /// `RemovableMedia` from 11 bytes on, `BusType` from 32 — and a descriptor
  /// of an older version answers only what its version holds: where a later
  /// member would lie, it wrote its appended strings, not that member.
  ///
  /// A driver copies exactly `Size` bytes, or all the buffer holds where the
  /// buffer is shorter: an answer of any other length, a version too short to
  /// hold `Version` and `Size` themselves, and a `Size` short of the version's
  /// structure are no descriptor a driver writes, and are `InvalidData`.
  /// `RemovableMedia` is a `BOOLEAN`, a byte that is true whenever it is not
  /// zero, and is compared against zero rather than read as a Rust `bool`,
  /// which a driver's `0xFF` would make an invalid value.
  fn descriptor_in(answer: Filled<'_>) -> io::Result<StorageDescriptor> {
    use storage_descriptor::{BUS_TYPE, LIMIT, REMOVABLE_MEDIA, SIZE, VERSION};

    let version = answer.u32_at(VERSION)? as usize;
    let size = answer.u32_at(SIZE)? as usize;
    if version < SIZE + 4 {
      return Err(invalid(
        "a storage descriptor whose version does not hold its own version and size",
      ));
    }
    if size < version {
      return Err(invalid(
        "a storage descriptor whose own size is short of its version's structure",
      ));
    }
    if answer.len() != size.min(LIMIT) {
      return Err(invalid(
        "a storage descriptor answer that does not end where its own size does",
      ));
    }
    let holds = |offset: usize, len: usize| version >= offset + len;
    Ok(StorageDescriptor {
      removable_media: if holds(REMOVABLE_MEDIA, 1) {
        Some(answer.bytes(REMOVABLE_MEDIA, 1)?[0] != 0)
      } else {
        None
      },
      bus: if holds(BUS_TYPE, 4) {
        Some(answer.i32_at(BUS_TYPE)?)
      } else {
        None
      },
    })
  }

  /// The storage device number a device handle answers:
  /// `IOCTL_STORAGE_GET_DEVICE_NUMBER`, declared `FILE_ANY_ACCESS`, decoded
  /// out of the bytes the driver said it wrote — see [`device_number_in`].
  pub(super) fn device_number_of(device: &File) -> Reading<DeviceNumber> {
    let mut buffer = KernelBuffer::<{ device_number::LEN }>::new();
    let mut written: u32 = 0;
    // SAFETY: no input buffer; `buffer` a live output buffer of exactly `LEN`
    // bytes that the driver writes no further than, and `written` a live
    // count; the handle is valid for as long as `device` is borrowed. A
    // `KernelBuffer` is bytes alone, so whatever the driver writes is a value.
    let ok = unsafe {
      DeviceIoControl(
        device.as_raw_handle(),
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        core::ptr::null(),
        0,
        buffer.as_mut_ptr(),
        device_number::LEN as u32,
        &mut written,
        core::ptr::null_mut(),
      )
    };
    if ok == 0 {
      return reading(Err(io::Error::last_os_error()));
    }
    decoded(buffer.filled(written as usize).and_then(device_number_in))
  }

  /// A `STORAGE_DEVICE_NUMBER` answer: the whole structure, or `InvalidData`.
  fn device_number_in(answer: Filled<'_>) -> io::Result<DeviceNumber> {
    if answer.len() != device_number::LEN {
      return Err(invalid(
        "a device number answer that is not the whole structure",
      ));
    }
    Ok(DeviceNumber {
      device_type: answer.u32_at(device_number::DEVICE_TYPE)?,
      number: answer.u32_at(device_number::NUMBER)?,
    })
  }

  /// The one present disk that carries `number`, and a handle on it held
  /// while the rest of the policy is read: see
  /// [`VolumeDevice::removal_policy`].
  ///
  /// Each disk interface is opened for no access, which is all its number
  /// needs, through the global namespace (`\GLOBAL??\…`): an interface name a
  /// logon session shadows would open one disk while the configuration
  /// manager, which is asked by the name itself, answered for another. One
  /// that this process may not open, or that has gone, is passed
  /// over: it carries some other number, or the answer is lost, and neither
  /// can make it another disk's. `Absent` where no disk carries the number,
  /// and where two do.
  fn disk_carrying(number: DeviceNumber) -> Reading<(Vec<u16>, File)> {
    disk_interfaces().and_then(|interfaces| {
      let mut found = None;
      for interface in interfaces {
        // Through the global namespace, as every device a volume's answer is
        // read through is opened: see [`VolumeDevice::open`].
        let Some(global) = interface.strip_prefix(r"\\?\") else {
          return Reading::Failed(invalid(
            "a disk interface the configuration manager spelled without `\\\\?\\`",
          ));
        };
        let disk = match reading(super::walk::open_device(&format!(r"\GLOBAL??\{global}"))) {
          Reading::Value(disk) => disk,
          Reading::Absent | Reading::Declined(_) => continue,
          Reading::Failed(err) => return Reading::Failed(err),
        };
        match device_number_of(&disk) {
          Reading::Value(held) if held.names_disk(number) => {
            if found.is_some() {
              return Reading::Absent;
            }
            found = Some((to_wide(Path::new(&interface)), disk));
          }
          Reading::Value(_) | Reading::Absent | Reading::Declined(_) => {}
          Reading::Failed(err) => return Reading::Failed(err),
        }
      }
      found.map_or(Reading::Absent, Reading::Value)
    })
  }

  /// Every present disk interface the configuration manager lists, whole or
  /// refused.
  ///
  /// The list is asked for at the length the configuration manager names,
  /// and asked again where it grew in between (`CR_BUFFER_SMALL`), a bounded
  /// number of times. The call reports no length it wrote, so its buffer is a
  /// [`SentinelBuffer`]: the list ends at the empty member the call wrote, and
  /// every member of it is decoded whole — see [`multi_string`].
  fn disk_interfaces() -> Reading<Vec<String>> {
    /// The most units a list of disk interfaces is believed to need.
    const LIMIT: u32 = 1 << 20;
    /// How many times a list that grew between its size and itself is asked
    /// again.
    const ATTEMPTS: usize = 4;

    for _ in 0..ATTEMPTS {
      let mut len: u32 = 0;
      // SAFETY: a live count, the interface class's own GUID, and no device
      // id; the call writes the count alone.
      let cr = unsafe {
        CM_Get_Device_Interface_List_SizeW(
          &mut len,
          &GUID_DEVINTERFACE_DISK,
          core::ptr::null(),
          CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        )
      };
      if let Some(outcome) = unanswered(configured(cr)) {
        return outcome;
      }
      if len == 0 || len > LIMIT {
        return Reading::Failed(invalid(
          "a disk interface list of no length, or of more than any list is",
        ));
      }
      let mut buffer = SentinelBuffer::<u16>::new(len as usize);
      // SAFETY: the class GUID, no device id, and a buffer live and `len()`
      // units long for the call, which writes no further than that.
      let cr = unsafe {
        CM_Get_Device_Interface_ListW(
          &GUID_DEVINTERFACE_DISK,
          core::ptr::null(),
          buffer.for_call(),
          buffer.len() as u32,
          CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        )
      };
      if cr == CR_BUFFER_SMALL {
        continue;
      }
      if let Some(outcome) = unanswered(configured(cr)) {
        return outcome;
      }
      return decoded(buffer.list_terminated().and_then(multi_string));
    }
    Reading::Failed(io::Error::other(
      "the disk interface list kept growing between its size and itself",
    ))
  }

  /// The device instance id of the device an interface belongs to
  /// (`DEVPKEY_Device_InstanceId`), with its terminator, as the configuration
  /// manager locates a device node by it.
  ///
  /// The call reports the size it wrote, and only that much is read: a
  /// property that is not a string, a size that is odd or past the buffer, or
  /// a string with no terminator at its end or one inside it, is
  /// `InvalidData`. An instance id is at most 200 characters
  /// (`MAX_DEVICE_ID_LEN`), which the buffer holds with room to spare.
  fn instance_id(interface: &[u16]) -> Reading<Vec<u16>> {
    let mut buffer = KernelBuffer::<512>::new();
    let mut size = KernelBuffer::<512>::LEN as u32;
    let mut kind: DEVPROPTYPE = 0;
    // SAFETY: a NUL-terminated interface path, the property key's own
    // constant, a live type and size, and a buffer live and `size` bytes long
    // for the call, which writes no further than that.
    let cr = unsafe {
      CM_Get_Device_Interface_PropertyW(
        interface.as_ptr(),
        &DEVPKEY_Device_InstanceId,
        &mut kind,
        buffer.as_mut_ptr().cast(),
        &mut size,
        0,
      )
    };
    if let Some(outcome) = unanswered(configured(cr)) {
      return outcome;
    }
    if kind != DEVPROP_TYPE_STRING {
      return Reading::Failed(invalid("an instance id that is not a string"));
    }
    decoded(buffer.filled(size as usize).and_then(|answer| {
      let units = units(answer.bytes(0, answer.len())?)?;
      match units.split_last() {
        Some((0, id)) if !id.is_empty() && !id.contains(&0) => Ok(units),
        _ => Err(invalid(
          "an instance id that is not one string and its terminator",
        )),
      }
    }))
  }

  /// The device node an instance id names, where it is present.
  fn located(id: &[u16]) -> Reading<u32> {
    let mut node: u32 = 0;
    // SAFETY: a live node out-pointer and a NUL-terminated instance id.
    let cr = unsafe { CM_Locate_DevNodeW(&mut node, id.as_ptr(), CM_LOCATE_DEVNODE_NORMAL) };
    configured(cr).map(|()| node)
  }

  /// The removal policy a device node holds (`CM_DRP_REMOVAL_POLICY`): a
  /// `REG_DWORD` of four bytes, or `InvalidData`.
  fn policy_of(node: u32) -> Reading<u32> {
    let mut kind: u32 = 0;
    let mut policy: u32 = 0;
    let mut len = core::mem::size_of::<u32>() as u32;
    // SAFETY: a live type, a live four-byte value and its length, which the
    // call writes no further than; any four bytes are a `u32`.
    let cr = unsafe {
      CM_Get_DevNode_Registry_PropertyW(
        node,
        CM_DRP_REMOVAL_POLICY,
        &mut kind,
        core::ptr::from_mut(&mut policy).cast(),
        &mut len,
        0,
      )
    };
    configured(cr).and_then(|()| {
      if kind == REG_DWORD && len as usize == core::mem::size_of::<u32>() {
        Reading::Value(policy)
      } else {
        Reading::Failed(invalid("a removal policy that is not a REG_DWORD"))
      }
    })
  }

  /// What a read that produced no value answered, carried to a read of
  /// another type; `None` where it produced one.
  fn unanswered<T>(outcome: Reading<()>) -> Option<Reading<T>> {
    match outcome {
      Reading::Value(()) => None,
      Reading::Absent => Some(Reading::Absent),
      Reading::Declined(err) => Some(Reading::Declined(err)),
      Reading::Failed(err) => Some(Reading::Failed(err)),
    }
  }

  /// A configuration manager answer as a read's outcome: `CR_SUCCESS` is the
  /// value; a device, an interface or a value that is not there is `Absent`,
  /// its own "there is none"; anything else is `Failed`, carrying the code.
  fn configured(cr: CONFIGRET) -> Reading<()> {
    match cr {
      CR_SUCCESS => Reading::Value(()),
      CR_NO_SUCH_DEVNODE | CR_NO_SUCH_VALUE | CR_NO_SUCH_DEVICE_INTERFACE => Reading::Absent,
      code => Reading::Failed(io::Error::other(format!(
        "the configuration manager answered CONFIGRET {code}"
      ))),
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
  /// [`Facts::read`] for what a label that is not text becomes. The length
  /// counts "the trailing null, if present" (MS-FSCC 2.5.9), so one NUL at
  /// the end is the terminator's and not the label's; an empty label is no
  /// label. The answer ends where the label does: MS-FSA has a file system
  /// report exactly the fixed part and the label bytes it copied. An answer
  /// short of the fixed part, a label length that is odd or does not end the
  /// answer exactly, and a NUL anywhere else in the label are none the file
  /// system writes, and are `Failed(InvalidData)`.
  fn volume_information(root: &File) -> Reading<(u32, Option<OsString>)> {
    let mut buffer = KernelBuffer::<576>::new();
    query(root, FileFsVolumeInformation, &mut buffer).and_then(|answer| decoded(volume_in(answer)))
  }

  /// The serial and the label out of a `FileFsVolumeInformation` answer.
  fn volume_in(answer: Filled<'_>) -> io::Result<(u32, Option<OsString>)> {
    let serial = answer.u32_at(fs_volume::SERIAL)?;
    let label_length = answer.u32_at(fs_volume::LABEL_LENGTH)?;
    let units = units(answer.tail(fs_volume::LABEL, label_length as usize)?)?;
    let label = match units.split_last() {
      Some((&0, label)) => label,
      _ => &units[..],
    };
    if label.contains(&0) {
      return Err(invalid("a volume label with a NUL inside it"));
    }
    Ok((
      serial,
      (!label.is_empty()).then(|| OsString::from_wide(label)),
    ))
  }

  /// The file system's name and its attribute flags:
  /// `FileFsAttributeInformation`. The name follows the fixed part in the
  /// same answer and is read the same way the label is, and decoded whole —
  /// see [`wide_text`]. Its length "MUST be greater than 0" and the name "MUST
  /// NOT be null-terminated" (MS-FSCC 2.5.1), and the answer ends where the
  /// name does (MS-FSA), so an answer short of the fixed part, a name length
  /// that is zero, odd or does not end the answer exactly, a NUL in the name,
  /// or a name that is not UTF-16 text is `Failed(InvalidData)`.
  fn attributes(root: &File) -> Reading<(u32, String)> {
    let mut buffer = KernelBuffer::<544>::new();
    query(root, FileFsAttributeInformation, &mut buffer)
      .and_then(|answer| decoded(attributes_in(answer)))
  }

  /// The flags and the name out of a `FileFsAttributeInformation` answer.
  fn attributes_in(answer: Filled<'_>) -> io::Result<(u32, String)> {
    let flags = answer.u32_at(fs_attribute::ATTRIBUTES)?;
    let name_length = answer.u32_at(fs_attribute::NAME_LENGTH)?;
    if name_length == 0 {
      return Err(invalid("a file system name of no length"));
    }
    let units = units(answer.tail(fs_attribute::NAME, name_length as usize)?)?;
    if units.contains(&0) {
      return Err(invalid("a file system name with a NUL in it"));
    }
    Ok((flags, wide_text(&units)?))
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
  pub(super) fn device(root: &File) -> Reading<FsDeviceInformation> {
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

  /// Opens a volume's root directory, named by its GUID, for no access
  /// beyond its attributes: the one handle.
  ///
  /// **Through the global namespace**, `\GLOBAL??\Volume{…}\`: the name the
  /// mount manager keeps, which a DOS device name a logon session defines of
  /// its own cannot shadow, as it could the same name looked up through the
  /// session first. Opened by [`walk::open`](super::walk::open), as itself:
  /// nothing about a volume's root is a link. No access is needed for
  /// anything asked through it — the volume queries are answered on any
  /// handle, and `FSCTL_GET_NTFS_VOLUME_DATA` is declared `FILE_ANY_ACCESS` —
  /// so nothing about this open can be refused for want of a right to the
  /// volume's contents, and every share mode is granted, so the open stands
  /// in no one's way.
  fn open_volume_root(guid: &VolumeRoot) -> Reading<File> {
    // `\\?\Volume{…}\` without its `\\?\`.
    let volume = &guid.as_str()[4..];
    reading(super::walk::open(
      None,
      &format!(r"\GLOBAL??\{volume}"),
      true,
    ))
  }

  /// Opens a share's root, `\\?\UNC\server\share\`, the same way, through
  /// the global namespace's `UNC`, which names the multiple UNC provider.
  fn open_share_root(share: &ShareRoot) -> Reading<File> {
    // `\\?\UNC\server\share\` without its `\\?\UNC\`.
    let root = share.root();
    reading(super::walk::open(
      None,
      &format!(r"\GLOBAL??\UNC\{}", &root[8..]),
      true,
    ))
  }

  /// Where an object lies: its volume's GUID root (`None` for a network
  /// share), the mount point, and the canonical path — see [`location_of`].
  pub(super) type Location = (Option<VolumeRoot>, String, String);

  /// Where the object a walk holds lies now, as its own handle names it: see
  /// [`location_of`].
  fn location(object: &File) -> Reading<Location> {
    use windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_DOS;

    location_of(final_path(object, VOLUME_NAME_GUID), || {
      final_path(object, VOLUME_NAME_DOS)
    })
  }

  /// Whether the object is still where the observation found it:
  /// `located`, the object's own handle asked again, names the same root —
  /// the same volume GUID root, or a share's for a share — the same mount
  /// point and the same canonical path. A handle whose volume has left
  /// answers the platform's decline or failure, which stands; anything else
  /// that is not the same place is a decline.
  fn still_located(
    located: Reading<Location>,
    guid: Option<&VolumeRoot>,
    mount_point: &str,
    canonical: &str,
  ) -> Reading<()> {
    match located {
      Reading::Value((again, at, path)) => {
        let same_root = match (again.as_ref(), guid) {
          (Some(again), Some(guid)) => again.is(guid),
          (None, None) => true,
          _ => false,
        };
        if same_root && at == mount_point && path == canonical {
          Reading::Value(())
        } else {
          Reading::Declined(io::Error::new(
            io::ErrorKind::NotFound,
            "the object is no longer where its observation found it: it moved, or its volume left",
          ))
        }
      }
      Reading::Absent => Reading::Declined(io::Error::new(
        io::ErrorKind::NotFound,
        "the object's handle names no place now: its volume left",
      )),
      Reading::Declined(err) => Reading::Declined(err),
      Reading::Failed(err) => Reading::Failed(err),
    }
  }

  /// Where the object a walk holds lies, out of its two final paths: its
  /// volume's GUID root (`None` for a network share), the mount point, and
  /// the canonical path.
  ///
  /// **The GUID path is asked first, and neither answer stands in for the
  /// other.** `GetFinalPathNameByHandleW` documents `ERROR_PATH_NOT_FOUND` —
  /// `Absent` here — for both spellings: `VOLUME_NAME_DOS` for a volume with
  /// no drive letter ("If a volume has no drive letter, you can use the
  /// volume GUID path to identify it"), and `VOLUME_NAME_GUID` for a network
  /// share ("Volume GUID paths are not created for network shares"). So:
  ///
  /// - both paths: the DOS path is canonical, and the mount point is the DOS
  ///   path without the path beneath the GUID root — which it must end in
  ///   after a separator, or the two answers are not of one place and the
  ///   observation is declined;
  /// - a GUID path and no DOS path: the GUID path is canonical, and the GUID
  ///   root is the mount point;
  /// - a DOS path and no GUID path: the share's root, where the DOS path is a
  ///   share's, or a decline;
  /// - neither: `Absent`.
  fn location_of(
    guid_path: Reading<String>,
    dos_path: impl FnOnce() -> Reading<String>,
  ) -> Reading<Location> {
    match guid_path {
      Reading::Value(guid_path) => {
        let Some((guid, beneath)) = VolumeRoot::split(&guid_path) else {
          return Reading::Declined(not_a_root());
        };
        match dos_path() {
          Reading::Value(canonical) => match mount_point_of(&canonical, beneath) {
            Some(mount_point) => Reading::Value((Some(guid), mount_point, canonical)),
            None => Reading::Declined(not_a_root()),
          },
          Reading::Absent => {
            let mount_point = guid.as_str().to_owned();
            Reading::Value((Some(guid), mount_point, guid_path))
          }
          Reading::Declined(err) => Reading::Declined(err),
          Reading::Failed(err) => Reading::Failed(err),
        }
      }
      Reading::Absent => dos_path().and_then(|canonical| match ShareRoot::of_path(&canonical) {
        Some(share) => Reading::Value((None, share.root(), canonical)),
        None => Reading::Declined(not_a_root()),
      }),
      Reading::Declined(err) => Reading::Declined(err),
      Reading::Failed(err) => Reading::Failed(err),
    }
  }

  /// The mount point a DOS final path lies beneath: the path without
  /// `beneath`, the path beneath the volume's root its GUID final path spells.
  /// `None` where the DOS path does not end in it after a separator — the two
  /// answers are not of one place.
  fn mount_point_of(canonical: &str, beneath: &str) -> Option<String> {
    let head = canonical.strip_suffix(beneath)?;
    head.ends_with('\\').then(|| head.to_owned())
  }

  /// The root a handle proved it holds: see [`proven_root`].
  #[derive(Clone, Debug)]
  pub(super) enum Proven {
    /// A volume, by its GUID root.
    Volume(VolumeRoot),
    /// A network share, which has no GUID path, by its exact root: its server
    /// and its share.
    Share(ShareRoot),
  }

  impl Proven {
    /// Whether `other` is the very same root: the same volume GUID, or the
    /// same server and share — see [`ShareRoot::is`].
    pub(super) fn is(&self, other: &Self) -> bool {
      match (self, other) {
        (Self::Volume(one), Self::Volume(other)) => one.is(other),
        (Self::Share(one), Self::Share(other)) => one.is(other),
        _ => false,
      }
    }
  }

  /// The root a handle holds, proved from the handle itself: the volume GUID
  /// root it names itself by, or, for a network share, **the exact share
  /// root it names itself by** — its server and its share — or a decline
  /// where the handle holds anything but a root.
  ///
  /// **A handle opened on a mount root is not proven to be one.** The root was
  /// found by name, and a name is re-resolved by the open: a volume mounted in
  /// a folder that leaves between the two uncovers the folder, and the open
  /// lands on the directory of the volume beneath; a share's name is resolved
  /// by the multiple UNC provider, and a DFS referral or a connection rebound
  /// in between would land it on another server's share. So the handle is
  /// asked where it is, and accepted only where the answer is **exactly a
  /// root**: through `VOLUME_NAME_GUID`, a volume GUID root with nothing after
  /// it — see [`VolumeRoot::parse`] — and, for a volume that has no GUID path,
  /// which the function documents for network shares alone, through
  /// `VOLUME_NAME_DOS`, a share's root, `\\?\UNC\server\share\` with nothing
  /// after it — see [`ShareRoot::parse`]. Anything else — a GUID path with a
  /// folder after it, a share path with one — is a handle on some other
  /// volume's directory, and the observation is declined, like a volume that
  /// has gone. Which root it is, the caller compares.
  fn proven_root(root: &File) -> Reading<Proven> {
    use windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_DOS;

    match final_path(root, VOLUME_NAME_GUID) {
      Reading::Value(path) => match VolumeRoot::parse(&path) {
        Some(volume) => Reading::Value(Proven::Volume(volume)),
        None => Reading::Declined(not_a_root()),
      },
      Reading::Absent => match final_path(root, VOLUME_NAME_DOS) {
        Reading::Value(path) => match ShareRoot::parse(&path) {
          Some(share) => Reading::Value(Proven::Share(share)),
          None => Reading::Declined(not_a_root()),
        },
        Reading::Absent => Reading::Declined(not_a_root()),
        Reading::Declined(err) => Reading::Declined(err),
        Reading::Failed(err) => Reading::Failed(err),
      },
      Reading::Declined(err) => Reading::Declined(err),
      Reading::Failed(err) => Reading::Failed(err),
    }
  }

  /// Whether a handle names itself, through its own final path, by exactly
  /// `guid`'s root: `Value` where it does, and a decline where it names any
  /// other path — another volume's root, a folder beneath one — or none.
  fn holds_root(root: &File, guid: &VolumeRoot) -> Reading<()> {
    match final_path(root, VOLUME_NAME_GUID) {
      Reading::Value(named) if VolumeRoot::parse(&named).is_some_and(|named| named.is(guid)) => {
        Reading::Value(())
      }
      Reading::Value(_) | Reading::Absent => Reading::Declined(io::Error::new(
        io::ErrorKind::NotFound,
        "the volume the handle holds does not answer to the root its facts were read for",
      )),
      Reading::Declined(err) => Reading::Declined(err),
      Reading::Failed(err) => Reading::Failed(err),
    }
  }

  /// A resolve's second proof, after every fact was read: the handle still
  /// holds exactly the root the first proof found — the same volume GUID
  /// root, or, for a share, the same server and share. Anything else, another
  /// share's root among it, is a decline, like a volume that has gone.
  fn still_holds(root: &File, expected: &Proven) -> Reading<()> {
    match expected {
      Proven::Volume(guid) => holds_root(root, guid),
      Proven::Share(_) => match proven_root(root) {
        Reading::Value(proven) if proven.is(expected) => Reading::Value(()),
        Reading::Value(_) | Reading::Absent => Reading::Declined(not_a_root()),
        Reading::Declined(err) => Reading::Declined(err),
        Reading::Failed(err) => Reading::Failed(err),
      },
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
  /// function's own documentation names `ERROR_PATH_NOT_FOUND` for it — a
  /// DOS path of a volume with no drive letter, and a GUID path of a network
  /// share: see [`location_of`]. A path that is
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

    /// **A volume with no drive letter is named by its GUID path.** The GUID
    /// path is asked first and each answer stands on its own: with both, the
    /// DOS path is canonical and the mount point is it without the path
    /// beneath the root; with no DOS path (`ERROR_PATH_NOT_FOUND`, a volume
    /// with no letter), the GUID path is canonical and its root the mount
    /// point; with no GUID path, a share's root; with neither, nothing; and
    /// two answers not of one place are declined.
    #[test]
    fn test_a_volume_with_no_dos_path_is_located_by_its_guid_path() {
      const ROOT: &str = r"\\?\Volume{0e4a7d8c-5c1b-11ef-9d2a-806e6f6e6963}\";
      let within = format!(r"{ROOT}dir\file");
      let text = |path: &str| Reading::Value(path.to_owned());

      let Reading::Value((Some(guid), mount_point, canonical)) =
        location_of(text(&within), || text(r"\\?\C:\mnt\dir\file"))
      else {
        panic!("both paths locate the object");
      };
      assert_eq!(
        (guid.as_str(), mount_point.as_str(), canonical.as_str()),
        (ROOT, r"\\?\C:\mnt\", r"\\?\C:\mnt\dir\file")
      );

      let Reading::Value((Some(guid), mount_point, canonical)) =
        location_of(text(&within), || Reading::Absent)
      else {
        panic!("a volume with no letter is located by its GUID path");
      };
      assert_eq!(
        (guid.as_str(), mount_point.as_str(), canonical.as_str()),
        (ROOT, ROOT, within.as_str())
      );

      let Reading::Value((None, mount_point, canonical)) =
        location_of(Reading::Absent, || text(r"\\?\UNC\server\share\dir"))
      else {
        panic!("a share is located by its root");
      };
      assert_eq!(
        (mount_point.as_str(), canonical.as_str()),
        (r"\\?\UNC\server\share\", r"\\?\UNC\server\share\dir")
      );

      assert!(matches!(
        location_of(Reading::Absent, || Reading::Absent),
        Reading::Absent
      ));
      assert!(matches!(
        location_of(text(&within), || text(r"\\?\C:\elsewhere\other")),
        Reading::Declined(_)
      ));
      assert!(matches!(
        location_of(Reading::Absent, || text(r"\\?\C:\not-a-share")),
        Reading::Declined(_)
      ));
      assert!(matches!(
        location_of(text(r"\\?\C:\not-a-guid-path"), || text(r"\\?\C:\x")),
        Reading::Declined(_)
      ));

      // The planted defect, side by side: the DOS path asked first, as the
      // prerequisite of everything else, made its absence the whole answer,
      // and a volume with no letter never reached its GUID path.
      let before = |dos: Reading<String>| dos.and_then(|_| Reading::Value(()));
      assert!(matches!(before(Reading::Absent), Reading::Absent));
    }

    /// **The object stays bound to the root its facts are read through.** A
    /// resolve's object is asked where it is once to find the root, again
    /// after the root is opened, and again after the facts are read, and must
    /// name the same place each time. A handle whose volume has left — the
    /// stale handle of a volume surprise-removed while a clone of it is given
    /// its GUID, which `ERROR_FILE_INVALID` stands in for here — declines the
    /// observation at either asking, and so does a handle that names another
    /// volume's root, and one whose path moved; the platform's own failure
    /// stands as it is. Asked the same place throughout, the observation is
    /// formed.
    #[test]
    fn test_the_object_stays_bound_to_its_root_while_it_is_observed() {
      use windows_sys::Win32::Foundation::ERROR_FILE_INVALID;

      const OTHER: &str = r"\\?\Volume{0e4a7d8c-5c1b-11ef-9d2a-806e6f6e6963}\";
      let object = super::super::walk::walk(r"C:\Windows").unwrap();
      let facts = |_: &File, _: Option<&VolumeRoot>| {
        Ok(Facts::fixture(
          VolumeCapabilities::from_fs_type_defaults(b"NTFS"),
          None,
          None,
        ))
      };
      let gone = || Reading::Declined(io::Error::from_raw_os_error(ERROR_FILE_INVALID as i32));
      // Asks the object where it is, the place `then` names from the
      // `from`-th asking on, and counts the askings.
      let asked = |from: usize, then: &dyn Fn() -> Reading<Location>| {
        let mut asking = 0usize;
        let outcome = Observation::of_located_with(
          || {
            asking += 1;
            if asking >= from {
              then()
            } else {
              location(&object)
            }
          },
          facts,
        );
        (outcome, asking)
      };

      let (formed, asking) = asked(usize::MAX, &|| location(&object));
      assert!(matches!(formed, Reading::Value(_)));
      assert_eq!(
        asking, 3,
        "asked to find the root, after it opened, after the facts"
      );

      for from in [2, 3] {
        let (outcome, asking) = asked(from, &gone);
        assert!(
          matches!(&outcome, Reading::Declined(err) if err.raw_os_error() == Some(ERROR_FILE_INVALID as i32)),
          "a volume that left by the asking {from}"
        );
        assert_eq!(asking, from);

        let elsewhere = || {
          location(&object).and_then(|(_, mount_point, canonical)| {
            Reading::Value((VolumeRoot::parse(OTHER), mount_point, canonical))
          })
        };
        let (outcome, _) = asked(from, &elsewhere);
        assert!(
          matches!(outcome, Reading::Declined(_)),
          "another volume's root by the asking {from}"
        );

        let moved = || {
          location(&object).and_then(|(guid, mount_point, canonical)| {
            Reading::Value((guid, mount_point, format!(r"{canonical}\moved")))
          })
        };
        let (outcome, _) = asked(from, &moved);
        assert!(
          matches!(outcome, Reading::Declined(_)),
          "a path that moved by the asking {from}"
        );

        let failed = || Reading::Failed(io::Error::other("a failure of the read itself"));
        let (outcome, _) = asked(from, &failed);
        assert!(matches!(outcome, Reading::Failed(_)), "{from}");
      }

      // The planted defect, side by side: the observation before asked the
      // object once, and read the facts through a root opened and proven by
      // name — nothing in that road asks the object again, so it forms the
      // observation whatever became of the object's volume after the first
      // asking.
      let before = |located: Reading<Location>| {
        located.and_then(|(guid, _, _)| {
          let guid = guid.expect("the boot volume has a GUID path");
          open_volume_root(&guid).and_then(|root| {
            proven_root(&root).and_then(|_| still_holds(&root, &Proven::Volume(guid.clone())))
          })
        })
      };
      assert!(matches!(before(location(&object)), Reading::Value(())));
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
      let terminated = [wide("DATA"), vec![0]].concat();
      let bytes = volume_bytes(1, 10, &terminated);
      assert_eq!(
        volume_in(answer(&bytes).filled(bytes.len()).unwrap())
          .unwrap()
          .1
          .unwrap(),
        "DATA",
        "the trailing NUL the length counts is not the label's"
      );
      for (label, label_length) in [(&[][..], 0), (&[0][..], 2)] {
        let empty = volume_bytes(1, label_length, label);
        assert_eq!(
          volume_in(answer(&empty).filled(empty.len()).unwrap())
            .unwrap()
            .1,
          None,
          "an empty label is no label: {label:?}"
        );
      }
      let inner = [u16::from(b'D'), 0, u16::from(b'A'), 0];
      let bytes = volume_bytes(1, 8, &inner);
      assert!(
        refused(volume_in(answer(&bytes).filled(bytes.len()).unwrap())),
        "a NUL inside the label"
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
        (
          volume_bytes(1, 8, &label),
          fs_volume::LABEL + 10,
          "bytes past the label the answer reports",
        ),
        (
          volume_bytes(1, 6, &label),
          fs_volume::LABEL + 8,
          "a label that ends before the answer does",
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
        (
          attribute_bytes(0x2, 0, &[]),
          fs_attribute::NAME,
          "a name of no length",
        ),
        (
          attribute_bytes(0x2, 10, &[wide("NTFS"), vec![0]].concat()),
          fs_attribute::NAME + 10,
          "a terminated name",
        ),
        (
          attribute_bytes(0x2, 8, &name),
          fs_attribute::NAME + 10,
          "bytes past the name the answer reports",
        ),
        (
          attribute_bytes(0x2, 6, &name),
          fs_attribute::NAME + 8,
          "a name that ends before the answer does",
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

    /// A storage descriptor's removal fields are read out of the bytes the
    /// driver said it wrote and nothing else: an answer short of the fixed
    /// part, and a descriptor whose own size is, are `InvalidData`; any
    /// non-zero `RemovableMedia` byte is true, as a `BOOLEAN` is.
    #[test]
    fn test_a_storage_descriptor_is_read_only_inside_what_was_written() {
      use windows_sys::Win32::Storage::FileSystem::{BusTypeNvme, BusTypeUsb};

      let descriptor = |size: u32, removable: u8, bus: i32| {
        let mut bytes = vec![0u8; storage_descriptor::LEN];
        bytes[storage_descriptor::VERSION..storage_descriptor::VERSION + 4]
          .copy_from_slice(&(storage_descriptor::LEN as u32).to_ne_bytes());
        bytes[storage_descriptor::SIZE..storage_descriptor::SIZE + 4]
          .copy_from_slice(&size.to_ne_bytes());
        bytes[storage_descriptor::REMOVABLE_MEDIA] = removable;
        bytes[storage_descriptor::BUS_TYPE..storage_descriptor::BUS_TYPE + 4]
          .copy_from_slice(&bus.to_ne_bytes());
        bytes
      };
      let full = storage_descriptor::LEN as u32;

      // The fixed part and the strings after it, as long as its own size says.
      let mut bytes = descriptor(full + 24, 0, BusTypeUsb);
      bytes.extend([b'x'; 24]);
      assert_eq!(
        descriptor_in(answer(&bytes).filled(bytes.len()).unwrap()).unwrap(),
        StorageDescriptor {
          removable_media: Some(false),
          bus: Some(BusTypeUsb),
        }
      );
      let bytes = descriptor(full, 0xFF, BusTypeNvme);
      assert_eq!(
        descriptor_in(answer(&bytes).filled(bytes.len()).unwrap()).unwrap(),
        StorageDescriptor {
          removable_media: Some(true),
          bus: Some(BusTypeNvme),
        },
        "any non-zero BOOLEAN is true"
      );
      assert!(refused(descriptor_in(
        answer(&bytes).filled(storage_descriptor::LEN - 1).unwrap()
      )));
      let bytes = descriptor(full - 1, 0, BusTypeUsb);
      assert!(refused(descriptor_in(
        answer(&bytes).filled(bytes.len()).unwrap()
      )));
      // The answer ends where the descriptor's own size says it does.
      let bytes = descriptor(full + 8, 0, BusTypeUsb);
      assert!(refused(descriptor_in(
        answer(&bytes).filled(storage_descriptor::LEN).unwrap()
      )));
      let mut longer = descriptor(full, 0, BusTypeUsb);
      longer.extend([0; 8]);
      assert!(refused(descriptor_in(
        answer(&longer).filled(longer.len()).unwrap()
      )));

      // **A descriptor answers only what its version holds.** A structure
      // written before `BusType` was added — a version of 28 bytes — and its
      // strings after it: the bytes where `BusType` lies now are its strings,
      // and are read as no bus at all.
      let versioned = |version: u32, size: u32, removable: u8, at_bus: i32| {
        let mut bytes = descriptor(size, removable, at_bus);
        bytes[storage_descriptor::VERSION..storage_descriptor::VERSION + 4]
          .copy_from_slice(&version.to_ne_bytes());
        bytes
      };
      let read = |bytes: &[u8]| descriptor_in(answer(bytes).filled(bytes.len()).unwrap());
      let older = versioned(28, full, 0, BusTypeUsb);
      let decoded = read(&older).unwrap();
      assert_eq!(
        decoded,
        StorageDescriptor {
          removable_media: Some(false),
          bus: None,
        }
      );
      assert!(
        !decoded.says_removable(),
        "a bus the version does not hold says nothing"
      );
      // The planted defect, side by side: the decoder as it was read
      // `BusType` at its offset whatever the version, and took the strings
      // there for USB.
      let before = StorageDescriptor {
        removable_media: Some(older[storage_descriptor::REMOVABLE_MEDIA] != 0),
        bus: Some(i32::from_ne_bytes(
          older[storage_descriptor::BUS_TYPE..storage_descriptor::BUS_TYPE + 4]
            .try_into()
            .unwrap(),
        )),
      };
      assert!(before.says_removable(), "the old decoder answered yes");
      assert_eq!(
        read(&versioned(11, full, 1, BusTypeUsb)).unwrap(),
        StorageDescriptor {
          removable_media: Some(true),
          bus: None,
        }
      );
      assert_eq!(
        read(&versioned(8, full, 1, BusTypeUsb)).unwrap(),
        StorageDescriptor {
          removable_media: None,
          bus: None,
        }
      );
      // A version that does not hold even its own version and size, and a
      // size short of the version's structure, are no descriptor.
      assert!(refused(read(&versioned(4, full, 0, BusTypeUsb))));
      assert!(refused(read(&versioned(full + 4, full, 0, BusTypeUsb))));
      // A version past the structure this crate knows reads the members it
      // knows.
      let mut later = versioned(full + 8, full + 8, 0, BusTypeUsb);
      later.extend([0; 8]);
      assert_eq!(
        read(&later).unwrap(),
        StorageDescriptor {
          removable_media: Some(false),
          bus: Some(BusTypeUsb),
        }
      );
    }

    /// A resolve's second proof holds exactly where the handle still names the
    /// root the first proof found: the boot volume's own GUID root holds, and
    /// another volume's root, or a share's where the volume has a GUID root,
    /// is a decline.
    #[test]
    fn test_the_second_proof_holds_only_the_first_proofs_root() {
      let handle = super::super::walk::walk(r"C:\").unwrap();
      let Proven::Volume(guid) = proven_root(&handle).required().unwrap() else {
        panic!("the boot volume has a GUID root");
      };
      assert!(matches!(
        still_holds(&handle, &Proven::Volume(guid.clone())),
        Reading::Value(())
      ));
      let other = VolumeRoot::parse(r"\\?\Volume{00000000-0000-0000-0000-000000000000}\").unwrap();
      assert!(matches!(
        still_holds(&handle, &Proven::Volume(other)),
        Reading::Declined(_)
      ));
      let share = ShareRoot::parse(r"\\?\UNC\server\share\").unwrap();
      assert!(matches!(
        still_holds(&handle, &Proven::Share(share)),
        Reading::Declined(_)
      ));
    }

    /// **A share's root is proven exactly: its server and its share.** The
    /// root an object's path lies on and the root a handle names itself by
    /// are the same only where both the server and the share are, compared
    /// without regard to ASCII case; another server's share — where a DFS
    /// referral or a rebound connection would have landed the open — or
    /// another share on the same server is another root, and so is a volume.
    /// The planted defect, side by side: the proof as it was, which answered
    /// "some share" for every share root, held the object on `\\A\share` to
    /// a handle on `\\B\other`.
    #[test]
    fn test_a_share_is_proven_by_its_exact_root() {
      let root = |path: &str| Proven::Share(ShareRoot::parse(path).unwrap());
      let object = root(r"\\?\UNC\A\share\");
      assert!(object.is(&root(r"\\?\UNC\A\share")));
      assert!(object.is(&root(r"\\?\UNC\a\SHARE\")));
      for other in [
        r"\\?\UNC\B\other\",
        r"\\?\UNC\B\share\",
        r"\\?\UNC\A\other\",
        r"\\?\UNC\A.example\share\",
      ] {
        assert!(!object.is(&root(other)), "{other}");
      }
      let volume = Proven::Volume(
        VolumeRoot::parse(r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\").unwrap(),
      );
      assert!(!object.is(&volume) && !volume.is(&object));
      // The root an object's own path lies on is the share's, whatever is
      // beneath it.
      let of_path = ShareRoot::of_path(r"\\?\UNC\A\share\folder\file").unwrap();
      assert!(object.is(&Proven::Share(of_path.clone())));
      assert_eq!(of_path.root(), r"\\?\UNC\A\share\");
      // The planted defect: every share root proven as the same nothing.
      let before = |path: &str| ShareRoot::parse(path).map(|_| ());
      assert_eq!(
        before(r"\\?\UNC\A\share\"),
        before(r"\\?\UNC\B\other\"),
        "the old proof could not tell two shares apart"
      );
    }

    /// A device number is the whole structure or `InvalidData`, and names a
    /// disk by its kind and number alone.
    #[test]
    fn test_a_device_number_is_the_whole_structure() {
      use windows_sys::Win32::Storage::FileSystem::{FILE_DEVICE_CD_ROM, FILE_DEVICE_DISK};

      let bytes = [
        &FILE_DEVICE_DISK.to_ne_bytes()[..],
        &3u32.to_ne_bytes(),
        &2u32.to_ne_bytes(),
      ]
      .concat();
      let number = device_number_in(answer(&bytes).filled(device_number::LEN).unwrap()).unwrap();
      assert_eq!(
        number,
        DeviceNumber {
          device_type: FILE_DEVICE_DISK,
          number: 3,
        }
      );
      assert!(refused(device_number_in(
        answer(&bytes).filled(device_number::LEN - 1).unwrap()
      )));
      assert!(refused(device_number_in(
        answer(&bytes).filled(device_number::LEN + 1).unwrap()
      )));
      assert!(number.names_disk(DeviceNumber {
        device_type: FILE_DEVICE_DISK,
        number: 3,
      }));
      assert!(!number.names_disk(DeviceNumber {
        device_type: FILE_DEVICE_DISK,
        number: 4,
      }));
      assert!(!number.names_disk(DeviceNumber {
        device_type: FILE_DEVICE_CD_ROM,
        number: 3,
      }));
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

/// A local disk whose medium is fixed in it: the one kind of volume whose
/// removal the device kind cannot answer and the volume's own device is asked
/// about.
fn is_fixed_local_disk(device: FsDeviceInformation) -> bool {
  device.characteristics & (FILE_REMOTE_DEVICE | FILE_REMOVABLE_MEDIA) == 0
    && is_disk(device.device_type)
}

/// What the device kind the file system reports says about removal, which is
/// where this platform's removal answer starts.
///
/// **A device kind never denies.** It says what kind of device a volume is on,
/// which is not an answer to the removal question, and the invariant this crate
/// publishes admits no exception for any kind. Optical media and a device whose
/// medium comes out of it (`FILE_REMOVABLE_MEDIA`) are a yes. Everything else
/// is [`Unknown`](Ejectability::Unknown): a disk whose medium is fixed in it —
/// which is what an external USB disk is, its medium fixed *in the drive* —
/// says nothing about whether the drive is unplugged, and is asked of its own
/// device instead (see the module's documentation); a volume reached over a
/// network, a RAM disk and a kind a later Windows adds are not asked about
/// removal at all.
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

/// Where the fixed part of `STORAGE_DEVICE_DESCRIPTOR` lies in an answer: the
/// descriptor's version and its own size, its `RemovableMedia` byte and its
/// `BusType`, how long the fixed part is, and how much of a descriptor is
/// asked for. The laws hold every offset and the length against the binding
/// crate's own struct.
mod storage_descriptor {
  pub(super) const VERSION: usize = 0;
  pub(super) const SIZE: usize = 4;
  pub(super) const REMOVABLE_MEDIA: usize = 10;
  pub(super) const BUS_TYPE: usize = 28;
  /// The whole fixed part of the version this crate knows, which the laws
  /// hold to the binding crate's struct; a descriptor is read by its own
  /// version, not by this.
  #[cfg(test)]
  pub(super) const LEN: usize = 40;
  /// The fixed part and a few short strings are what a driver writes; this
  /// is far past any of them, and only the fixed part is read.
  pub(super) const LIMIT: usize = 4096;
}

/// What a storage descriptor says about removal: whether the device's medium
/// comes out of it, and the bus it hangs off — each `None` where the
/// descriptor's version does not hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StorageDescriptor {
  removable_media: Option<bool>,
  bus: Option<STORAGE_BUS_TYPE>,
}

impl StorageDescriptor {
  /// A yes, or nothing.
  ///
  /// A medium that comes out is a yes, and so is a device on USB or SD, buses
  /// whose devices are unplugged or pulled while the machine runs. Nothing
  /// here denies: `RemovableMedia` describes the medium and `BusType` the
  /// transport, so a device on any other bus — SATA, NVMe, SAS, a virtual one,
  /// and MMC, which carries soldered eMMC as often as a card — has said
  /// nothing about whether it leaves. A member the descriptor's version
  /// does not hold says nothing either.
  fn says_removable(self) -> bool {
    // Compared rather than matched: these constants are not upper case, and
    // in pattern position the compiler cannot tell a constant from a binding.
    self.removable_media == Some(true)
      || self
        .bus
        .is_some_and(|bus| bus == BusTypeUsb || bus == BusTypeSd)
  }
}

/// Where `STORAGE_DEVICE_NUMBER`'s fields lie in an answer, and how long the
/// whole structure is. The laws hold every offset and the length against the
/// binding crate's own struct.
mod device_number {
  pub(super) const DEVICE_TYPE: usize = 0;
  pub(super) const NUMBER: usize = 4;
  pub(super) const LEN: usize = 12;
}

/// What `IOCTL_STORAGE_GET_DEVICE_NUMBER` answered: the kind of device
/// (`FILE_DEVICE_*`) and its number among devices of that kind. A volume
/// answers the disk it lies on; a disk answers itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceNumber {
  device_type: u32,
  number: u32,
}

impl DeviceNumber {
  /// Whether this answer names the disk `other` names: the same kind and the
  /// same number. A volume's partition number is not asked: a disk has none.
  fn names_disk(self, other: Self) -> bool {
    self.device_type == other.device_type && self.number == other.number
  }
}

/// `REG_DWORD`, the type a removal policy is stored as. Defined locally: the
/// binding crate names it only behind a feature this crate does not otherwise
/// need, and a law holds it to that one.
const REG_DWORD: u32 = 4;

/// What a disk's Plug and Play removal policy says about leaving the machine
/// (`CM_REMOVAL_POLICY`, `cfgmgr32.h`).
///
/// **The platform's own answer to the removal question**, which the system
/// derives from the device's own capabilities and whatever an administrator
/// overrode them with: `EXPECT_NO_REMOVAL` is its "this storage stays", the
/// one denial on this backend; `EXPECT_ORDERLY_REMOVAL` — a device that is
/// stopped before it is unplugged, an eSATA or Thunderbolt disk — and
/// `EXPECT_SURPRISE_REMOVAL` — one that is simply pulled, a USB disk — are
/// its yes. Any other value is none this crate knows, and says nothing.
fn policy_answer(policy: u32) -> Ejectability {
  use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL, CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL,
    CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL,
  };

  match policy {
    CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL => Ejectability::NotEjectable,
    CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL | CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL => {
      Ejectability::Ejectable
    }
    _ => Ejectability::Unknown,
  }
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
    is_guid(guid).then(|| Self(path.to_owned()))
  }

  /// The root as the platform spelled it.
  pub(super) fn as_str(&self) -> &str {
    &self.0
  }

  /// The volume device the root names: `\\?\Volume{GUID}`, the root without
  /// its separator, which [`parse`](Self::parse) required it to end in.
  pub(super) fn device(&self) -> &str {
    &self.0[..self.0.len() - 1]
  }

  /// A final path spelled `VOLUME_NAME_GUID` — `\\?\Volume{…}\` and the
  /// path beneath that root — as the root, through [`parse`](Self::parse),
  /// and the path beneath it; `None` where it begins with no volume root.
  pub(super) fn split(path: &str) -> Option<(Self, &str)> {
    const PREFIX: &str = r"\\?\Volume{";
    let end = PREFIX.len() + path.strip_prefix(PREFIX)?.find('}')?;
    let root = path.get(..end + 2)?;
    Some((Self::parse(root)?, &path[end + 2..]))
  }

  /// Whether `other` names the same volume: one GUID, in either case.
  pub(super) fn is(&self, other: &Self) -> bool {
    self.0.eq_ignore_ascii_case(&other.0)
  }
}

/// The root of one network share, `\\?\UNC\server\share\`, as its server and
/// its share — and nothing else.
///
/// **The one parser every share root goes through**: the root an object's own
/// final path lies on, and the root a handle opened on that root names itself
/// by. A share has no GUID path, so this is the whole of what proves a
/// share's root: **the exact root**, never merely some share's. A server and a
/// share are each a name — see [`is_share_name`] — and two roots are the same
/// only where both are, compared without regard to ASCII case, as the server
/// compares them; a letter outside ASCII must be spelled alike, and a root
/// spelled otherwise there is another root, which only ever declines.
#[derive(Clone, Debug)]
pub(super) struct ShareRoot {
  server: String,
  share: String,
}

impl ShareRoot {
  /// `path` — a final path spelled `VOLUME_NAME_DOS` — as a share's root:
  /// exactly `\\?\UNC\server\share`, with at most its trailing separator after
  /// it. `None` for anything else, a folder beneath a share among them.
  pub(super) fn parse(path: &str) -> Option<Self> {
    let rest = path.strip_prefix(r"\\?\UNC\")?;
    let (server, share) = rest.strip_suffix('\\').unwrap_or(rest).split_once('\\')?;
    (!share.contains('\\') && is_share_name(server, share)).then(|| Self {
      server: server.to_owned(),
      share: share.to_owned(),
    })
  }

  /// The root of the share a DOS final path lies on, whatever lies beneath
  /// it on the share; `None` where the path is no share's.
  pub(super) fn of_path(path: &str) -> Option<Self> {
    let rest = path.strip_prefix(r"\\?\UNC\")?;
    let mut parts = rest.splitn(3, '\\');
    let (server, share) = (parts.next()?, parts.next()?);
    is_share_name(server, share).then(|| Self {
      server: server.to_owned(),
      share: share.to_owned(),
    })
  }

  /// The root as a path, `\\?\UNC\server\share\`.
  pub(super) fn root(&self) -> String {
    format!(r"\\?\UNC\{}\{}\", self.server, self.share)
  }

  /// Whether `other` is this very root: the same server and the same share.
  pub(super) fn is(&self, other: &Self) -> bool {
    self.server.eq_ignore_ascii_case(&other.server) && self.share.eq_ignore_ascii_case(&other.share)
  }
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

  let decode = |buf: &SentinelBuffer<u16>| {
    buf.terminated().and_then(wide_text).and_then(|path| {
      VolumeRoot::parse(&path).ok_or_else(|| {
        io::Error::new(
          io::ErrorKind::InvalidData,
          "the mount manager enumerated a name that is not a volume root",
        )
      })
    })
  };

  // Neither call reports the length it wrote, so an entry ends only at a
  // terminator the call itself wrote: see `SentinelBuffer`.
  let mut buf = SentinelBuffer::<u16>::new(MAX_PATH as usize + 1);
  // SAFETY: `buf` is live and `buf.len()` units long for the call.
  let handle = unsafe { FindFirstVolumeW(buf.for_call(), buf.len() as u32) };
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
      // SAFETY: the search handle is open, and `buf` live and `buf.len()`
      // units long for the call.
      if unsafe { FindNextVolumeW(search.0, buf.for_call(), buf.len() as u32) } == 0 {
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
    let mut buf = SentinelBuffer::<u16>::new(64);
    // SAFETY: `wide` is NUL-terminated and `buf` live and `buf.len()` units
    // long.
    let ok =
      unsafe { GetVolumeNameForVolumeMountPointW(wide.as_ptr(), buf.for_call(), buf.len() as u32) };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    String::from_utf16(buf.terminated().unwrap()).unwrap()
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
      mount.total_bytes().is_some_and(|total| total > 0)
        && mount.available_bytes() <= mount.total_bytes(),
      "{mount:?}"
    );

    let (observation, canonical) = Observation::of_object(&walk::walk(r"C:\").unwrap())
      .required()
      .unwrap();
    assert_eq!(canonical, Path::new(r"\\?\C:\"));
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
    let probe = |object: &File| {
      Observation::of_object_with(object, |_, _| {
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

  /// **A device kind never denies.** It says what kind of device a volume is
  /// on, which is not an answer to the removal question: optical media and a
  /// medium that comes out are a yes, and everything else — a disk whose
  /// medium is fixed in it, a network volume, a RAM disk, a kind this crate
  /// does not name — is `Unknown` from the kind alone.
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
    assert_eq!(
      SentinelBuffer::holding(&[65u16, 0, 66])
        .terminated()
        .unwrap(),
      [65]
    );
    assert_eq!(
      SentinelBuffer::holding(&[65u16, 66])
        .terminated()
        .unwrap_err()
        .kind(),
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
    assert_eq!(
      VolumeRoot::parse(root).unwrap().device(),
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}",
      "the volume device is the root without its separator"
    );
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
      assert!(ShareRoot::parse(path).is_some(), "{path}");
    }
    for path in [
      r"\\?\UNC\server\share\folder",
      r"\\?\UNC\server\share\folder\",
      r"\\?\UNC\server\",
      r"\\?\UNC\server",
      r"\\?\UNC\\share\",
      r"\\?\UNC\..\share\",
      r"\\?\UNC\server\.\",
      r"\\?\UNC\;LanmanRedirector\share\",
      r"\\?\C:\",
      r"\\server\share\",
    ] {
      assert!(ShareRoot::parse(path).is_none(), "{path}");
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

  /// The storage descriptor's removal fields are read at the offsets the
  /// driver writes them at, and its fixed part is as long as the binding
  /// crate's struct is.
  #[test]
  fn test_the_storage_descriptor_offsets_match_the_struct_they_read() {
    use core::mem::{offset_of, size_of};

    use windows_sys::Win32::System::Ioctl::STORAGE_DEVICE_DESCRIPTOR;

    assert_eq!(
      storage_descriptor::VERSION,
      offset_of!(STORAGE_DEVICE_DESCRIPTOR, Version)
    );
    assert_eq!(
      storage_descriptor::SIZE,
      offset_of!(STORAGE_DEVICE_DESCRIPTOR, Size)
    );
    assert_eq!(
      storage_descriptor::REMOVABLE_MEDIA,
      offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia)
    );
    assert_eq!(
      storage_descriptor::BUS_TYPE,
      offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType)
    );
    assert_eq!(
      storage_descriptor::LEN,
      size_of::<STORAGE_DEVICE_DESCRIPTOR>()
    );
  }

  /// **A storage descriptor says yes or nothing.** A medium that comes out,
  /// and a device on USB or SD, are a yes; every other bus — MMC among them,
  /// which carries soldered eMMC — says nothing, and nothing here denies.
  #[test]
  fn test_a_storage_descriptor_says_yes_or_nothing() {
    use windows_sys::Win32::Storage::FileSystem::{
      BusType1394, BusTypeAta, BusTypeMmc, BusTypeNvme, BusTypeRAID, BusTypeSas, BusTypeSata,
      BusTypeScsi, BusTypeSpaces, BusTypeUnknown, BusTypeVirtual,
    };

    let descriptor = |removable_media, bus| StorageDescriptor {
      removable_media: Some(removable_media),
      bus: Some(bus),
    };
    for bus in [BusTypeUsb, BusTypeSd] {
      assert!(descriptor(false, bus).says_removable(), "bus {bus}");
    }
    // A member the descriptor's version does not hold says nothing.
    let unheld = StorageDescriptor {
      removable_media: None,
      bus: None,
    };
    assert!(!unheld.says_removable());
    for bus in [
      BusTypeUnknown,
      BusTypeScsi,
      BusTypeAta,
      BusType1394,
      BusTypeRAID,
      BusTypeSas,
      BusTypeSata,
      BusTypeMmc,
      BusTypeVirtual,
      BusTypeSpaces,
      BusTypeNvme,
    ] {
      assert!(!descriptor(false, bus).says_removable(), "bus {bus}");
      assert!(descriptor(true, bus).says_removable(), "bus {bus}");
    }
  }

  /// The device number's fields are read at the offsets the driver writes
  /// them at, and the whole structure is as long as the binding crate's is;
  /// `REG_DWORD` is the binding crate's.
  #[test]
  fn test_the_device_number_offsets_match_the_struct_they_read() {
    use core::mem::{offset_of, size_of};

    use windows_sys::Win32::System::{Ioctl::STORAGE_DEVICE_NUMBER, Registry::REG_DWORD as DWORD};

    assert_eq!(
      device_number::DEVICE_TYPE,
      offset_of!(STORAGE_DEVICE_NUMBER, DeviceType)
    );
    assert_eq!(
      device_number::NUMBER,
      offset_of!(STORAGE_DEVICE_NUMBER, DeviceNumber)
    );
    assert_eq!(device_number::LEN, size_of::<STORAGE_DEVICE_NUMBER>());
    assert_eq!(REG_DWORD, DWORD);
  }

  /// **A removal policy is the platform's own answer.** Expecting no removal
  /// is the one denial; expecting an orderly or a surprise removal is a yes;
  /// any other value says nothing.
  #[test]
  fn test_a_removal_policy_answers_for_itself() {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
      CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL, CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL,
      CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL,
    };

    assert_eq!(
      policy_answer(CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL),
      Ejectability::NotEjectable
    );
    for policy in [
      CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL,
      CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL,
    ] {
      assert_eq!(policy_answer(policy), Ejectability::Ejectable, "{policy}");
    }
    for policy in [0, 4, u32::MAX] {
      assert_eq!(policy_answer(policy), Ejectability::Unknown, "{policy}");
    }
  }

  /// **The volume device opens for no access without any privilege, and
  /// answers the storage descriptor.** Ruling 181 admitted the second handle
  /// only where an unprivileged process may open it; a runner's process is
  /// elevated, so the open and the question are made while the thread
  /// impersonates a restricted copy of its own token — the Administrators
  /// group for deny only, every privilege removed — which is what a standard
  /// user's process holds, and the law first proves that token is no
  /// administrator's.
  #[test]
  fn test_the_volume_device_on_this_machine_opens_for_no_access_without_privilege() {
    use windows_sys::Win32::{
      Foundation::{CloseHandle, HANDLE},
      Security::{
        CheckTokenMembership, CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
        ImpersonateLoggedOnUser, LUA_TOKEN, RevertToSelf, SECURITY_MAX_SID_SIZE,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
        WinBuiltinAdministratorsSid,
      },
      System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct Token(HANDLE);
    impl Drop for Token {
      fn drop(&mut self) {
        // SAFETY: a token handle this law opened, closed once.
        unsafe { CloseHandle(self.0) };
      }
    }
    struct Impersonating;
    impl Drop for Impersonating {
      fn drop(&mut self) {
        // SAFETY: undoes this thread's impersonation, which this law began.
        unsafe { RevertToSelf() };
      }
    }

    let mut own: HANDLE = core::ptr::null_mut();
    // SAFETY: the current-process pseudo-handle, and a live out-pointer.
    let ok = unsafe {
      OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE,
        &mut own,
      )
    };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    let own = Token(own);
    let mut restricted: HANDLE = core::ptr::null_mut();
    // SAFETY: a token handle opened above with duplicate access, no SIDs or
    // privileges listed, and a live out-pointer.
    let ok = unsafe {
      CreateRestrictedToken(
        own.0,
        DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
        0,
        core::ptr::null(),
        0,
        core::ptr::null(),
        0,
        core::ptr::null(),
        &mut restricted,
      )
    };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    let restricted = Token(restricted);

    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: a buffer of `len` bytes, the largest a SID is.
    let ok = unsafe {
      CreateWellKnownSid(
        WinBuiltinAdministratorsSid,
        core::ptr::null_mut(),
        sid.as_mut_ptr().cast(),
        &mut len,
      )
    };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());

    // SAFETY: a restricted primary token of this process's own user.
    let ok = unsafe { ImpersonateLoggedOnUser(restricted.0) };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    let _impersonating = Impersonating;

    let mut member = 0;
    // SAFETY: a null token asks the impersonation token of this thread; the
    // SID was written above.
    let ok =
      unsafe { CheckTokenMembership(core::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member) };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    assert_eq!(member, 0, "the restricted token is no administrator's");

    let guid = VolumeRoot::parse(&guid_of_root("C:\\")).expect("a volume root");
    let device = match observed::VolumeDevice::open(&guid) {
      Reading::Value(device) => device,
      other => panic!("the boot volume's device did not open for no access: {other:?}"),
    };
    match device.descriptor() {
      Reading::Value(descriptor) => {
        println!("the boot volume's storage descriptor: {descriptor:?}");
        assert!(
          descriptor.removable_media.is_some() && descriptor.bus.is_some(),
          "the boot disk's driver writes a version that holds both members: {descriptor:?}"
        );
      }
      other => panic!("the boot volume's device did not answer its descriptor: {other:?}"),
    }
    match device.removal_policy() {
      Reading::Value(policy) => {
        println!(
          "the boot volume's disk's removal policy: {policy} ({:?})",
          policy_answer(policy)
        );
      }
      other => panic!("the boot volume's disk's removal policy was not reached: {other:?}"),
    }
  }

  /// **A device path is refused before anything is opened**: a DOS device
  /// name, a port, a raw drive or volume, a named pipe or a mailslot — local,
  /// or a host's `pipe`, `mailslot` or `IPC$` share — and the console's own
  /// buffers are refused with no open, where `canonicalize` would have opened
  /// them, and so is a path with a NUL inside it. A drive's, a share's and a
  /// volume GUID's paths through the device namespace are files like any
  /// other.
  #[test]
  fn test_a_device_path_is_refused_before_anything_is_opened() {
    for full in [
      r"\\.\COM1",
      r"\\.\NUL",
      r"\\.\pipe\whichdisk",
      r"\\.\PhysicalDrive0",
      r"\\?\GLOBALROOT\Device\Serial0",
      r"\\.\C:",
      r"\\?\C:",
      r"\\.\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}",
      r"\\.\",
      "\\\\.\\\u{e4}bc",
      r"\\server\pipe\whichdisk",
      r"\\localhost\PIPE\whichdisk",
      r"\\?\UNC\server\pipe\whichdisk",
      r"\\.\UNC\server\mailslot\whichdisk",
      r"\\server\ipc$\srvsvc",
      r"\\server\pipe",
    ] {
      assert!(names_a_device(full), "{full}");
    }
    for full in [
      r"C:\Windows",
      r"\\server\share\file",
      r"\\.\C:\Windows",
      r"\\?\C:\Windows",
      r"\\?\UNC\server\share\file",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\file",
      r"\\server\pipes\file",
      r"\\server\share\pipe",
      r"\\server",
    ] {
      assert!(!names_a_device(full), "{full}");
    }
    for path in ["CONIN$", "conout$"] {
      assert_eq!(
        device_free_full_path(Path::new(path))
          .err()
          .map(|err| err.kind()),
        Some(io::ErrorKind::InvalidInput),
        "{path}"
      );
    }
    assert!(device_free_full_path(Path::new(r"C:\Windows")).is_ok());
    assert!(
      resolve(Path::new("")).is_err(),
      "an empty path names nothing"
    );
    for path in [
      "NUL",
      "COM1",
      "CONIN$",
      r"\\.\pipe\whichdisk-none",
      r"\\localhost\pipe\whichdisk-none",
      r"\\.\PhysicalDrive0",
      "C:\\Windows\0\\\\.\\COM1",
    ] {
      assert_eq!(
        resolve(Path::new(path)).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidInput),
        "{path} is refused, not opened"
      );
    }
    assert!(resolve(Path::new(r"\\?\C:\Windows")).is_ok());
  }

  /// **A root is admitted only in the exact shape the walk opens it by.** A
  /// volume's root is `Volume{` and a GUID spelled 8-4-4-4-12 in hexadecimal
  /// digits, `}` and a separator — any other name that only begins like one
  /// is a device path, refused before anything is opened, by the resolve's
  /// guard and by the walk's own parser alike, however it is reached (a
  /// caller's path, or a link's target); a share's server and share must be
  /// names, and a server that begins with `;` — the multiple UNC provider's
  /// form for a redirector — is no server; and a drive letter defined onto a
  /// connection is held to the same share names. The planted defect, side by
  /// side: the guard as it was, which admitted `Volume{`, anything, `}` and a
  /// separator, let `\\?\Volume{pipe}\x` through to the walk.
  #[test]
  fn test_a_root_is_admitted_only_in_the_shape_it_is_opened_by() {
    use walk::{LetterTarget, Root, classified, split, win32_of};

    const GUID: &str = "Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}";
    for malformed in [
      r"\\?\Volume{pipe}\x",
      r"\\?\Volume{}\x",
      r"\\.\Volume{whichdisk}\x",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9-00}\x",
      r"\\?\Volume{0g1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\x",
      r"\\?\Volume{0a1b2c3d4e5f-6071-8293-a4b5c6d7e8f9}\x",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f}\x",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}x\y",
      r"\\?\Volumes{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}\x",
      r"\\?\Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}",
      r"\\;LanmanRedirector\;Z:0000000000012345\server\pipe\x",
      r"\\?\UNC\;LanmanRedirector\;Z:0\server\share\x",
      r"\\?\UNC\..\share\x",
      r"\\server\.\x",
      r"\\server\..\x",
    ] {
      assert!(names_a_device(malformed), "{malformed}");
      assert_eq!(
        split(malformed).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidInput),
        "{malformed}"
      );
    }
    for target in [r"\??\Volume{pipe}\x", r"\??\UNC\;LanmanRedirector\x\y\z"] {
      assert_eq!(win32_of(target), None, "{target}");
    }
    for exact in [
      format!(r"\\?\{GUID}\x"),
      format!(r"\\.\{GUID}\x"),
      r"\\?\volume{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}\x".to_owned(),
    ] {
      assert!(!names_a_device(&exact), "{exact}");
      let (root, parts) = split(&exact).unwrap();
      assert!(
        matches!(&root, Root::Volume(name) if name.eq_ignore_ascii_case(GUID)),
        "{exact}"
      );
      assert_eq!(parts, vec!["x".to_owned()]);
    }
    for definition in [
      r"\Device\LanmanRedirector\;Z:0000000000012345\server\IPC$",
      r"\Device\LanmanRedirector\;Z:0000000000012345\server\pipe\x",
      r"\Device\LanmanRedirector\;Z:0000000000012345\;server\share",
    ] {
      assert!(classified(definition).is_err(), "{definition}");
    }
    assert!(matches!(
      classified(r"\Device\LanmanRedirector\;Z:0000000000012345\server\share"),
      Ok(LetterTarget::Connection { .. })
    ));

    // The planted defect: the guard as it was.
    let before = |full: &str| {
      full.strip_prefix(r"\\?\").is_some_and(|rest| {
        rest
          .get(..7)
          .is_some_and(|head| head.eq_ignore_ascii_case("Volume{"))
          && rest
            .find('}')
            .is_some_and(|end| rest[end + 1..].starts_with('\\'))
      })
    };
    assert!(
      before(r"\\?\Volume{pipe}\x"),
      "the old guard admitted a malformed volume name as a volume's root"
    );
  }

  /// **A walk holds only a drive's, a share's or a volume GUID's root, and a
  /// path the file system would resolve**: the device namespace, a host's
  /// pipe share, and an empty, `.` or `..` component are refused, and a
  /// link's target is proven to be one of the three roots before it is
  /// followed — or, relative, resolved against the folders held for the
  /// link's own folder, read lexically, without climbing above its root.
  #[test]
  fn test_the_walk_holds_only_what_names_a_root() {
    use walk::{Root, relative_steps, split, win32_of};

    const GUID: &str = "Volume{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}";
    let parts = split;
    assert_eq!(
      parts(r"C:\a\b").unwrap(),
      (Root::Drive(b'C'), vec!["a".to_owned(), "b".to_owned()])
    );
    assert_eq!(parts(r"c:\").unwrap(), (Root::Drive(b'C'), vec![]));
    assert_eq!(
      parts(r"\\?\C:\a\").unwrap(),
      (Root::Drive(b'C'), vec!["a".to_owned()])
    );
    assert_eq!(
      parts(r"\\server\share\a").unwrap(),
      (
        Root::Share(r"server\share".to_owned()),
        vec!["a".to_owned()]
      )
    );
    assert_eq!(
      parts(r"\\?\UNC\server\share").unwrap(),
      (Root::Share(r"server\share".to_owned()), vec![])
    );
    assert_eq!(
      parts(&format!(r"\\?\{GUID}\x")).unwrap(),
      (Root::Volume(GUID.to_owned()), vec!["x".to_owned()])
    );
    for refused in [
      r"\\.\pipe\x",
      r"\\?\C:",
      r"\\server\pipe\x",
      r"\\?\C:\a\..\b",
      r"\\?\C:\a\\b",
      r"\\?\C:\.\b",
      r"relative\path",
      r"\\server",
      r"\\server\",
    ] {
      assert_eq!(
        split(refused).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidInput),
        "{refused}"
      );
    }

    // Beneath `C:\a\b`, two folders held: `..\c` keeps `a` and opens `c`.
    let steps = |names: &[&str]| {
      names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>()
    };
    assert_eq!(relative_steps(2, r"..\c"), Some((1, steps(&["c"]))));
    assert_eq!(relative_steps(1, r".\b\.\c"), Some((1, steps(&["b", "c"]))));
    assert_eq!(relative_steps(1, r"\x\y"), Some((0, steps(&["x", "y"]))));
    assert_eq!(relative_steps(1, "b"), Some((1, steps(&["b"]))));
    assert_eq!(
      relative_steps(3, r"x\..\y"),
      Some((3, steps(&["y"]))),
      "a name the target takes back is never opened"
    );
    assert_eq!(
      relative_steps(3, r"..\x\..\..\y\\z\"),
      Some((1, steps(&["y", "z"])))
    );
    assert_eq!(relative_steps(2, ""), Some((2, Vec::new())));
    assert_eq!(relative_steps(1, r"..\..\c"), None, "above the root");
    assert_eq!(relative_steps(0, ".."), None, "above the root");

    assert_eq!(win32_of(r"\??\C:\t").as_deref(), Some(r"\\?\C:\t"));
    assert_eq!(
      win32_of(r"\??\UNC\s\sh\x").as_deref(),
      Some(r"\\?\UNC\s\sh\x")
    );
    assert_eq!(
      win32_of(&format!(r"\??\{GUID}\x")),
      Some(format!(r"\\?\{GUID}\x"))
    );
    for device in [
      r"\??\pipe\x",
      r"\??\COM1",
      r"\??\NUL",
      r"\Device\NamedPipe\x",
      r"\??\C:",
      r"\??\GLOBALROOT\Device\Serial0",
      r"\??\UNC\s\pipe\x",
      r"C:\t",
    ] {
      assert_eq!(win32_of(device), None, "{device}");
    }
    assert_eq!(win32_of(&format!(r"\??\{GUID}")), None, "a raw volume");
  }

  /// **A link's target is read out of what the file system wrote, whole**:
  /// the substitute name a symbolic link or a junction holds, relative or
  /// not, and nothing past the data the header declares; a tag other than
  /// the one asked about, a declared length that does not end the answer, an
  /// odd name length and a name outside the data are refusals.
  #[test]
  fn test_a_link_target_is_read_whole() {
    use walk::{IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK, Target, target_in};

    fn buffer(tag: u32, flags: Option<u32>, name: &str) -> Vec<u8> {
      let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_ne_bytes).collect();
      let mut data = Vec::new();
      data.extend_from_slice(&0u16.to_ne_bytes());
      data.extend_from_slice(&(name.len() as u16).to_ne_bytes());
      data.extend_from_slice(&(name.len() as u16 + 2).to_ne_bytes());
      data.extend_from_slice(&0u16.to_ne_bytes());
      if let Some(flags) = flags {
        data.extend_from_slice(&flags.to_ne_bytes());
      }
      data.extend_from_slice(&name);
      data.extend_from_slice(&[0, 0, 0, 0]);
      let mut bytes = Vec::new();
      bytes.extend_from_slice(&tag.to_ne_bytes());
      bytes.extend_from_slice(&(data.len() as u16).to_ne_bytes());
      bytes.extend_from_slice(&0u16.to_ne_bytes());
      bytes.extend_from_slice(&data);
      bytes
    }
    fn read(bytes: &[u8], tag: u32) -> io::Result<Target> {
      let mut held = [0u8; 256];
      held[..bytes.len()].copy_from_slice(bytes);
      let buffer = super::super::filled::KernelBuffer::<256>::holding(held);
      target_in(buffer.filled(bytes.len())?, tag)
    }

    let absolute = buffer(IO_REPARSE_TAG_SYMLINK, Some(0), r"\??\C:\target");
    assert_eq!(
      read(&absolute, IO_REPARSE_TAG_SYMLINK).unwrap(),
      Target::Absolute(r"\??\C:\target".to_owned())
    );
    let relative = buffer(IO_REPARSE_TAG_SYMLINK, Some(1), r"..\target");
    assert_eq!(
      read(&relative, IO_REPARSE_TAG_SYMLINK).unwrap(),
      Target::Relative(r"..\target".to_owned())
    );
    let junction = buffer(IO_REPARSE_TAG_MOUNT_POINT, None, r"\??\C:\target\");
    assert_eq!(
      read(&junction, IO_REPARSE_TAG_MOUNT_POINT).unwrap(),
      Target::Absolute(r"\??\C:\target\".to_owned())
    );

    assert_eq!(
      read(&absolute, IO_REPARSE_TAG_MOUNT_POINT)
        .err()
        .map(|err| err.kind()),
      Some(io::ErrorKind::NotFound),
      "an answer for another tag is a link that changed"
    );
    let mut long = absolute.clone();
    long.extend_from_slice(&[0, 0]);
    assert!(
      read(&long, IO_REPARSE_TAG_SYMLINK).is_err(),
      "bytes past the data"
    );
    assert!(
      read(&absolute[..absolute.len() - 2], IO_REPARSE_TAG_SYMLINK).is_err(),
      "data short of its length"
    );
    let mut odd = absolute.clone();
    odd[10..12].copy_from_slice(&3u16.to_ne_bytes());
    assert!(
      read(&odd, IO_REPARSE_TAG_SYMLINK).is_err(),
      "an odd name length"
    );
    let mut outside = absolute.clone();
    outside[8..10].copy_from_slice(&200u16.to_ne_bytes());
    assert!(
      read(&outside, IO_REPARSE_TAG_SYMLINK).is_err(),
      "a name outside the data"
    );
  }

  /// The constants a walk spells itself are the platform's own.
  #[test]
  fn test_the_walk_constants_are_the_platforms() {
    assert_eq!(
      walk::FILE_REMOTE_DEVICE,
      windows_sys::Wdk::System::SystemServices::FILE_REMOTE_DEVICE
    );
    assert_eq!(
      walk::IO_REPARSE_TAG_SYMLINK,
      windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_SYMLINK
    );
    assert_eq!(
      walk::IO_REPARSE_TAG_MOUNT_POINT,
      windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT
    );
    assert!(walk::is_name_surrogate(walk::IO_REPARSE_TAG_SYMLINK));
    assert!(walk::is_name_surrogate(walk::IO_REPARSE_TAG_MOUNT_POINT));
    // A cloud file's placeholder, a deduplicated file, a Unix socket.
    for data in [0x9000_601Au32, 0x8000_0013, 0x8000_0023] {
      assert!(!walk::is_name_surrogate(data), "{data:#x}");
    }
  }

  /// Sets a reparse point on `path`, which must exist — a directory for a
  /// junction — out of the whole `REPARSE_DATA_BUFFER` or
  /// `REPARSE_GUID_DATA_BUFFER` in `bytes`.
  fn set_reparse_point(path: &Path, bytes: &[u8]) {
    use std::os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _};

    use windows_sys::Win32::{
      Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
      System::{IO::DeviceIoControl, Ioctl::FSCTL_SET_REPARSE_POINT},
    };

    let file = std::fs::OpenOptions::new()
      .write(true)
      .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
      .open(path)
      .unwrap();
    let mut written = 0u32;
    // SAFETY: `bytes` is live and as long as declared, `written` a live count,
    // and the handle valid for as long as `file` is held.
    let ok = unsafe {
      DeviceIoControl(
        file.as_raw_handle(),
        FSCTL_SET_REPARSE_POINT,
        bytes.as_ptr().cast(),
        bytes.len() as u32,
        core::ptr::null_mut(),
        0,
        &mut written,
        core::ptr::null_mut(),
      )
    };
    assert_ne!(ok, 0, "{}: {}", path.display(), io::Error::last_os_error());
  }

  /// Makes `link`, a new empty directory, a junction to `target`, an NT path
  /// such as `\??\C:\dir` — or `\??\pipe\name`, which no tool that checks
  /// would write, and a junction holds all the same.
  fn junction(link: &Path, target: &str) {
    std::fs::create_dir(link).unwrap();
    let name: Vec<u8> = target.encode_utf16().flat_map(u16::to_ne_bytes).collect();
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_ne_bytes());
    data.extend_from_slice(&(name.len() as u16).to_ne_bytes());
    data.extend_from_slice(&(name.len() as u16 + 2).to_ne_bytes());
    data.extend_from_slice(&0u16.to_ne_bytes());
    data.extend_from_slice(&name);
    data.extend_from_slice(&[0, 0, 0, 0]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&walk::IO_REPARSE_TAG_MOUNT_POINT.to_ne_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_ne_bytes());
    bytes.extend_from_slice(&0u16.to_ne_bytes());
    bytes.extend_from_slice(&data);
    set_reparse_point(link, &bytes);
  }

  /// Gives `file` a third-party reparse point of `tag` — a
  /// `REPARSE_GUID_DATA_BUFFER`, with four bytes of data no filter reads.
  fn guid_tagged(file: &Path, tag: u32) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&tag.to_ne_bytes());
    bytes.extend_from_slice(&4u16.to_ne_bytes());
    bytes.extend_from_slice(&0u16.to_ne_bytes());
    bytes.extend_from_slice(&[
      0x5c, 0x2e, 0x1d, 0x3b, 0x4a, 0x59, 0x68, 0x77, 0x86, 0x95, 0xa4, 0xb3, 0xc2, 0xd1, 0xe0,
      0xff,
    ]);
    bytes.extend_from_slice(b"wdsk");
    set_reparse_point(file, &bytes);
  }

  /// A symbolic link at `link` to `target`, as `CreateSymbolicLinkW` makes
  /// one, or `false` where this process may not make one.
  fn symlink(link: &Path, target: &str, directory: bool) -> bool {
    use windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;

    let made = if directory {
      std::os::windows::fs::symlink_dir(target, link)
    } else {
      std::os::windows::fs::symlink_file(target, link)
    };
    match made {
      Ok(()) => true,
      Err(err) if err.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD as i32) => false,
      Err(err) => panic!("{}: {err}", link.display()),
    }
  }

  /// A named pipe's server, waiting for a client with an overlapped connect.
  struct PipeServer {
    pipe: windows_sys::Win32::Foundation::HANDLE,
    event: windows_sys::Win32::Foundation::HANDLE,
    _overlapped: Box<windows_sys::Win32::System::IO::OVERLAPPED>,
  }

  impl PipeServer {
    fn serve(name: &str) -> Self {
      use windows_sys::Win32::{
        Foundation::{ERROR_IO_PENDING, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX},
        System::{
          IO::OVERLAPPED,
          Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT},
          Threading::CreateEventW,
        },
      };

      let wide = to_wide(Path::new(name));
      // SAFETY: `wide` is NUL-terminated, and no security attributes are
      // passed.
      let pipe = unsafe {
        CreateNamedPipeW(
          wide.as_ptr(),
          PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
          PIPE_TYPE_BYTE | PIPE_WAIT,
          1,
          512,
          512,
          0,
          core::ptr::null(),
        )
      };
      assert_ne!(pipe, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
      // SAFETY: a manual-reset event, unsignalled, unnamed, with no
      // security attributes.
      let event = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
      assert!(!event.is_null(), "{}", io::Error::last_os_error());
      let mut overlapped = Box::new(OVERLAPPED::default());
      overlapped.hEvent = event;
      // SAFETY: the pipe is this server's, and the boxed overlapped outlives
      // the connect, which this server holds until it is dropped.
      let connected = unsafe { ConnectNamedPipe(pipe, &mut *overlapped) };
      assert_eq!(connected, 0, "no client has connected yet");
      assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(ERROR_IO_PENDING as i32)
      );
      Self {
        pipe,
        event,
        _overlapped: overlapped,
      }
    }

    /// Whether a client has connected, waiting `millis` for one.
    fn connected(&self, millis: u32) -> bool {
      use windows_sys::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject};

      // SAFETY: the event is this server's, live until it is dropped.
      unsafe { WaitForSingleObject(self.event, millis) == WAIT_OBJECT_0 }
    }
  }

  impl Drop for PipeServer {
    fn drop(&mut self) {
      use windows_sys::Win32::{Foundation::CloseHandle, System::IO::CancelIoEx};

      // SAFETY: both handles are this server's, and the pending connect is
      // cancelled before the overlapped it writes to is freed.
      unsafe {
        CancelIoEx(self.pipe, core::ptr::null());
        CloseHandle(self.pipe);
        CloseHandle(self.event);
      }
    }
  }

  /// **A link to a device is refused, and nothing is opened**: a junction
  /// and a symbolic link to a named pipe a server here waits on, and to
  /// `COM1` and `NUL`, are all refused as a path that names a device, and the
  /// server's connect is still pending after every one of them — the walk
  /// read the link's target and followed nothing. A client's open afterwards,
  /// the control, is what completes it. `canonicalize` followed both links
  /// and connected.
  #[test]
  fn test_a_link_to_a_device_on_this_machine_is_refused_unopened() {
    let dir = tempfile::tempdir().unwrap();
    let name = format!(r"\\.\pipe\whichdisk-walk-{}", std::process::id());
    let server = PipeServer::serve(&name);
    let pipe_nt = format!(r"\??\pipe\whichdisk-walk-{}", std::process::id());

    let mut links = Vec::new();
    let to_pipe = dir.path().join("junction-to-pipe");
    junction(&to_pipe, &pipe_nt);
    links.push(to_pipe);
    for (device, nt) in [("com1", r"\??\COM1"), ("nul", r"\??\NUL")] {
      let link = dir.path().join(format!("junction-to-{device}"));
      junction(&link, nt);
      links.push(link);
    }
    let symlinked = symlink(&dir.path().join("symlink-to-pipe"), &name, false);
    if symlinked {
      links.push(dir.path().join("symlink-to-pipe"));
      for device in [r"\\.\COM1", r"\\.\NUL"] {
        let link = dir.path().join(format!("symlink-to-{}", &device[4..]));
        assert!(symlink(&link, device, false));
        links.push(link);
      }
    }
    println!(
      "links to devices on this machine: {} ({})",
      links.len(),
      if symlinked {
        "junctions and symbolic links"
      } else {
        "junctions only: symbolic links need a privilege this runner lacks"
      }
    );

    for link in &links {
      for path in [link.clone(), link.join("beneath")] {
        assert_eq!(
          resolve(&path).err().map(|err| err.kind()),
          Some(io::ErrorKind::InvalidInput),
          "{} is refused",
          path.display()
        );
      }
    }
    assert!(
      !server.connected(0),
      "a resolve connected to the pipe a link leads to"
    );

    let _client = std::fs::OpenOptions::new()
      .read(true)
      .write(true)
      .open(&name)
      .unwrap();
    assert!(server.connected(5_000), "a client's open connects");
  }

  /// **A link that stays on a volume is followed, and its target is walked
  /// the same way**: a junction to a folder, and — where this process may make
  /// them — an absolute and a relative symbolic link to it and one to a file
  /// in it, resolve to the target's own path beneath the same mount point.
  #[test]
  fn test_a_link_that_stays_on_a_volume_is_followed() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("file"), b"whichdisk").unwrap();
    let canonical = target.join("file").canonicalize().unwrap();
    let nt = format!(r"\??\{}", target.display());

    let mut paths = Vec::new();
    let through_junction = dir.path().join("junction");
    junction(&through_junction, &nt);
    paths.push(through_junction.join("file"));
    if symlink(
      &dir.path().join("absolute"),
      &target.display().to_string(),
      true,
    ) {
      paths.push(dir.path().join("absolute").join("file"));
      assert!(symlink(&dir.path().join("relative"), "target", true));
      paths.push(dir.path().join("relative").join("file"));
      assert!(symlink(&dir.path().join("to-file"), r"target\file", false));
      paths.push(dir.path().join("to-file"));
    }

    let direct = resolve(&target.join("file")).unwrap();
    assert_eq!(direct.canonical_path(), canonical);
    for path in &paths {
      let resolved = resolve(path).unwrap();
      assert_eq!(resolved.canonical_path(), canonical, "{}", path.display());
      assert_eq!(
        resolved.relative_path(),
        direct.relative_path(),
        "{}",
        path.display()
      );
      assert_eq!(
        resolved.mount_info().mount_point(),
        direct.mount_info().mount_point()
      );
    }
  }

  /// The file a handle holds, as its volume's serial and its index on that
  /// volume: `GetFileInformationByHandle`.
  fn file_id(file: &File) -> (u32, u64) {
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::Storage::FileSystem::{
      BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `info` is live and as large as the call writes, and the handle
    // is valid for as long as `file` is borrowed.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    (
      info.dwVolumeSerialNumber,
      (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    )
  }

  /// Renames `from` to `to`, asked again for a moment where something else —
  /// a scanner — holds a file beneath `from` open.
  fn rename_soon(from: &Path, to: &Path) {
    for _ in 0..50 {
      match std::fs::rename(from, to) {
        Ok(()) => return,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
          std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(err) => panic!("{} -> {}: {err}", from.display(), to.display()),
      }
    }
    panic!("{} -> {}: still held", from.display(), to.display());
  }

  /// **A relative link is resolved against the folders the walk holds, never
  /// against their names.** Each walk reads a relative symbolic link, and
  /// then, while it holds the folders on the way, a folder it holds is
  /// renamed and a decoy made under the old name: the link's own folder, for
  /// `sub\link` to `t`; and, for `sub\up` to `..\t`, the folder the `..`
  /// returns to, once the link's folder has been moved out of it. The walk
  /// still reaches the target beside the link through the folders it holds —
  /// the renamed ones — and never the decoy, which a walk that spelled the
  /// link's folder as a path and looked it up again would have opened.
  #[test]
  fn test_a_relative_link_is_resolved_against_the_folders_held() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let sub = a.join("sub");
    std::fs::create_dir_all(sub.join("t")).unwrap();
    std::fs::write(sub.join("t").join("file"), b"held").unwrap();
    if !symlink(&sub.join("link"), "t", true) {
      println!("relative links: none on this runner, which may not make symbolic links");
      return;
    }
    let full = device_free_full_path(&sub.join("link").join("file")).unwrap();
    let moved = a.join("moved");
    let mut swapped = false;
    let walked = walk::walk_with(&full, || {
      if !swapped {
        swapped = true;
        rename_soon(&sub, &moved);
        std::fs::create_dir_all(sub.join("t")).unwrap();
        std::fs::write(sub.join("t").join("file"), b"decoy").unwrap();
      }
    })
    .unwrap();
    assert!(swapped, "the walk read the link");
    let held = file_id(&File::open(moved.join("t").join("file")).unwrap());
    let decoy = file_id(&File::open(sub.join("t").join("file")).unwrap());
    assert_ne!(held, decoy);
    assert_eq!(file_id(&walked), held, "the link's own folder, renamed");
    // The planted defect, side by side: the link's folder spelled as a path
    // and walked again by name is the decoy.
    let rebound = walk::walk(&device_free_full_path(&sub.join("t").join("file")).unwrap()).unwrap();
    assert_eq!(file_id(&rebound), decoy);

    // `..` returns to the folder held above the link's own.
    let b = dir.path().join("b");
    let (inner, elsewhere) = (b.join("inner"), dir.path().join("elsewhere"));
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::create_dir_all(b.join("t")).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(b.join("t").join("file"), b"held").unwrap();
    assert!(symlink(&inner.join("up"), r"..\t", true));
    let full = device_free_full_path(&inner.join("up").join("file")).unwrap();
    let renamed = dir.path().join("b-renamed");
    let mut swapped = false;
    let walked = walk::walk_with(&full, || {
      if !swapped {
        swapped = true;
        rename_soon(&inner, &elsewhere.join("inner"));
        rename_soon(&b, &renamed);
        std::fs::create_dir_all(b.join("t")).unwrap();
        std::fs::write(b.join("t").join("file"), b"decoy").unwrap();
      }
    })
    .unwrap();
    assert!(swapped, "the walk read the link");
    let held = file_id(&File::open(renamed.join("t").join("file")).unwrap());
    let decoy = file_id(&File::open(b.join("t").join("file")).unwrap());
    assert_ne!(held, decoy);
    assert_eq!(file_id(&walked), held, "the folder above, renamed");
    let rebound = walk::walk(&device_free_full_path(&b.join("t").join("file")).unwrap()).unwrap();
    assert_eq!(file_id(&rebound), decoy);
  }

  /// **A data reparse point is a file like any other, and a name surrogate
  /// the walk cannot read is refused by name.** A third-party tag without the
  /// name-surrogate bit — as a cloud file's placeholder, a deduplicated file
  /// and a Unix socket carry — resolves to the file itself, which
  /// `canonicalize` could not open at all: no filter serves the tag. The same
  /// tag with the bit set is a redirection whose target this crate does not
  /// read, and is refused.
  #[test]
  fn test_a_data_reparse_point_is_the_file_and_an_unread_link_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::write(&data, b"whichdisk").unwrap();
    guid_tagged(&data, 0x0000_1234);
    let resolved = resolve(&data).unwrap();
    assert!(
      resolved.canonical_path().ends_with("data"),
      "{:?}",
      resolved.canonical_path()
    );

    let surrogate = dir.path().join("surrogate");
    std::fs::write(&surrogate, b"whichdisk").unwrap();
    guid_tagged(&surrogate, 0x2000_1234);
    assert_eq!(
      resolve(&surrogate).err().map(|err| err.kind()),
      Some(io::ErrorKind::InvalidInput)
    );
  }

  /// **A loop of links is the error `CreateFileW` gives a loop**:
  /// `ERROR_CANT_RESOLVE_FILENAME`, after 63 links.
  #[test]
  fn test_a_loop_of_links_ends() {
    use windows_sys::Win32::Foundation::ERROR_CANT_RESOLVE_FILENAME;

    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    junction(&a, &format!(r"\??\{}", b.display()));
    junction(&b, &format!(r"\??\{}", a.display()));
    assert_eq!(
      resolve(&a.join("x"))
        .err()
        .and_then(|err| err.raw_os_error()),
      Some(ERROR_CANT_RESOLVE_FILENAME as i32)
    );
  }

  /// **A drive letter's definition is read whole, or the walk is refused.** A
  /// letter defined onto nothing is the query's own error, never a letter to
  /// open by name; a definition longer than the room the query is first given
  /// is asked again until it is whole; and a letter defined onto a device
  /// names exactly the device the query answered, which the walk opens
  /// without looking the letter up again.
  #[test]
  fn test_a_drive_letters_definition_is_read_whole() {
    use walk::{LetterTarget, letter_target_in};
    use windows_sys::Win32::Storage::FileSystem::{
      DDD_EXACT_MATCH_ON_REMOVE, DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION, DefineDosDeviceW,
      QueryDosDeviceW,
    };

    /// A drive letter this law defines, and removes when it is done.
    struct Letter(u32, Vec<u16>, Vec<u16>);
    impl Drop for Letter {
      fn drop(&mut self) {
        // SAFETY: both strings are NUL-terminated.
        unsafe {
          DefineDosDeviceW(
            self.0 | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
            self.1.as_ptr(),
            self.2.as_ptr(),
          )
        };
      }
    }
    fn free_letter() -> u8 {
      // Letters of this law's own: the laws that define letters run in
      // parallel, and two taking the same free letter undo each other's.
      for letter in (b'U'..=b'Y').rev() {
        let name: Vec<u16> = [u16::from(letter), u16::from(b':'), 0].to_vec();
        let mut probe = [0u16; 16];
        // SAFETY: `name` is NUL-terminated and `probe` as long as declared.
        if unsafe { QueryDosDeviceW(name.as_ptr(), probe.as_mut_ptr(), probe.len() as u32) } == 0 {
          return letter;
        }
      }
      panic!("no free drive letter");
    }
    fn define(letter: u8, flags: u32, target: &str) -> Letter {
      let name: Vec<u16> = [u16::from(letter), u16::from(b':'), 0].to_vec();
      let target: Vec<u16> = target.encode_utf16().chain(core::iter::once(0)).collect();
      // SAFETY: both strings are NUL-terminated.
      let ok = unsafe { DefineDosDeviceW(flags, name.as_ptr(), target.as_ptr()) };
      assert_ne!(ok, 0, "{}", io::Error::last_os_error());
      Letter(flags, name, target)
    }

    let letter = free_letter();
    assert!(
      letter_target_in(letter, 256).is_err(),
      "a letter defined onto nothing"
    );
    assert!(
      resolve(Path::new(&format!(r"{}:\anything", char::from(letter)))).is_err(),
      "a walk through it is refused"
    );

    let dir = tempfile::tempdir().unwrap();
    let mut deep = dir.path().to_path_buf();
    for _ in 0..4 {
      deep.push("a-folder-with-a-long-enough-name");
    }
    std::fs::create_dir_all(&deep).unwrap();
    let deep = deep.display().to_string();
    let _defined = define(letter, 0, &deep);
    assert_eq!(
      letter_target_in(letter, 4).unwrap(),
      LetterTarget::Path(format!(r"\\?\{deep}")),
      "asked with room for four units, the definition is still read whole"
    );
    drop(_defined);

    let raw = define(letter, DDD_RAW_TARGET_PATH, r"\Device\Null");
    assert_eq!(
      letter_target_in(letter, 256).unwrap(),
      LetterTarget::Device(r"\Device\Null".to_owned())
    );
    drop(raw);

    // The DOS namespace in any case is a path the walk walks: a raw
    // definition onto `\dOsDeViCeS\…\junction-to-pipe\leaf` is refused like
    // the junction, the pipe's server still waiting — never one open that
    // resolves the junction unseen.
    let pipe = format!("whichdisk-raw-{}", std::process::id());
    let server = PipeServer::serve(&format!(r"\\.\pipe\{pipe}"));
    let to_pipe = dir.path().join("junction-to-pipe");
    junction(&to_pipe, &format!(r"\??\pipe\{pipe}"));
    let raw = define(
      letter,
      DDD_RAW_TARGET_PATH,
      &format!(r"\dOsDeViCeS\{}\leaf", to_pipe.display()),
    );
    assert_eq!(
      letter_target_in(letter, 256).unwrap(),
      LetterTarget::Path(format!(r"\\?\{}\leaf", to_pipe.display()))
    );
    assert_eq!(
      resolve(Path::new(&format!(r"{}:\", char::from(letter))))
        .err()
        .map(|err| err.kind()),
      Some(io::ErrorKind::InvalidInput)
    );
    assert!(
      !server.connected(0),
      "the definition's junction was followed"
    );
    drop(raw);

    // After a link, a redirector's connection is refused before it is
    // opened: the refusal is the walk's own, never the network's answer about
    // a host that does not exist.
    let raw = define(
      letter,
      DDD_RAW_TARGET_PATH,
      &format!(
        r"\Device\LanmanRedirector\;{}:0000000000000000\whichdisk-no-such-host.invalid\share",
        char::from(letter)
      ),
    );
    assert!(matches!(
      letter_target_in(letter, 256).unwrap(),
      LetterTarget::Connection { beneath, .. } if beneath.is_empty()
    ));
    let to_letter = dir.path().join("junction-to-letter");
    junction(&to_letter, &format!(r"\??\{}:\x", char::from(letter)));
    let Err(err) = resolve(&to_letter.join("y")) else {
      panic!("a link to a connection resolved");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
    assert_eq!(err.raw_os_error(), None, "the network was asked: {err}");
    drop(raw);

    // The connection's form onto a local volume: a folder named `;…` at the
    // root of the boot volume, and beneath it a junction to the named-pipe
    // root, where a pipe's server waits. The redirector's device is asked
    // first — here the boot volume's own, no network device — and the
    // definition is refused before the connection's path, and the junction in
    // it, is opened: the server is still waiting.
    let LetterTarget::Device(boot) = letter_target_in(b'C', 256).unwrap() else {
      panic!("the boot volume's letter is defined onto its device");
    };
    /// The folder at the boot volume's root this law makes, and the junction
    /// in it, removed when it is done.
    struct Made(std::path::PathBuf);
    impl Drop for Made {
      fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.0.join("pipes"));
        let _ = std::fs::remove_dir(&self.0);
      }
    }
    let folder = format!(";whichdisk-{}", std::process::id());
    let made = Made(Path::new(r"C:\").join(&folder));
    std::fs::create_dir(&made.0).unwrap();
    junction(&made.0.join("pipes"), r"\??\pipe");
    let pipe = format!("whichdisk-local-{}", std::process::id());
    let server = PipeServer::serve(&format!(r"\\.\pipe\{pipe}"));
    let local = format!(r"{boot}\{folder}\pipes\{pipe}");
    let raw = define(letter, DDD_RAW_TARGET_PATH, &local);
    assert!(matches!(
      letter_target_in(letter, 256).unwrap(),
      LetterTarget::Connection { device, .. } if device == boot
    ));
    let Err(err) = resolve(Path::new(&format!(r"{}:\", char::from(letter)))) else {
      panic!("a connection's form onto a local volume resolved");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
    assert_eq!(err.raw_os_error(), None, "{err}");
    assert!(
      !server.connected(0),
      "the junction in the connection's path was resolved"
    );
    drop(raw);
    // The planted defect, side by side: the one open the arm made first
    // before, of the connection's whole path, resolves the junction inside
    // it, and a client's open of that path reaches the server.
    let _client = std::fs::OpenOptions::new()
      .read(true)
      .write(true)
      .open(format!(r"\\?\GLOBALROOT{local}"))
      .unwrap();
    assert!(
      server.connected(5_000),
      "one open of the path resolves its junction"
    );
    drop(made);
  }

  /// **Nothing is opened beneath a root that is no file system's.** A local
  /// root must be a disk's, a CD-ROM's, a RAM disk's or a file system's own
  /// device, and not remote; a share's root a network one. The named-pipe and
  /// mailslot file systems, the null device, a port, a redirector's or the
  /// multiple UNC provider's bare device, a remote disk, and a kind no device
  /// has are refused as a local root; a local disk as a share's. The planted
  /// defect, side by side: the walk before opened beneath every root, which is
  /// the rule that admits them all.
  #[test]
  fn test_only_a_file_systems_root_is_opened_beneath() {
    use walk::opens_into_a_file_system;
    use windows_sys::Win32::{
      Storage::FileSystem::FILE_DEVICE_TAPE,
      System::Ioctl::{
        FILE_DEVICE_MAILSLOT, FILE_DEVICE_MULTI_UNC_PROVIDER, FILE_DEVICE_NAMED_PIPE,
        FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_DEVICE_NULL, FILE_DEVICE_SERIAL_PORT,
        FILE_DEVICE_VIRTUAL_DISK,
      },
    };

    let kind = |device_type, characteristics| FsDeviceInformation {
      device_type,
      characteristics,
    };
    let local = [
      kind(FILE_DEVICE_DISK, 0),
      kind(FILE_DEVICE_DISK, FILE_REMOVABLE_MEDIA),
      kind(FILE_DEVICE_CD_ROM, FILE_REMOVABLE_MEDIA),
      kind(FILE_DEVICE_VIRTUAL_DISK, 0),
      kind(FILE_DEVICE_DISK_FILE_SYSTEM, 0),
      kind(FILE_DEVICE_CD_ROM_FILE_SYSTEM, 0),
    ];
    let refused = [
      kind(FILE_DEVICE_NAMED_PIPE, 0),
      kind(FILE_DEVICE_MAILSLOT, 0),
      kind(FILE_DEVICE_NULL, 0),
      kind(FILE_DEVICE_SERIAL_PORT, 0),
      kind(FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0),
      kind(FILE_DEVICE_MULTI_UNC_PROVIDER, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_DISK_FILE_SYSTEM, FILE_REMOTE_DEVICE),
      kind(FILE_DEVICE_TAPE, 0),
      kind(FILE_DEVICE_DVD, 0),
      kind(0, 0),
      kind(u32::MAX, 0),
    ];
    for device in local {
      assert!(opens_into_a_file_system(device), "{device:?}");
    }
    for device in refused {
      assert!(!opens_into_a_file_system(device), "{device:?}");
    }

    // The planted defect: no rule at all between the root's open and the
    // first name opened beneath it.
    let before = |_: FsDeviceInformation| true;
    assert!(
      refused.into_iter().all(before),
      "the walk before opened beneath the named-pipe file system's root"
    );
  }

  /// **A drive letter defined onto the named-pipe file system opens no pipe.**
  /// A pipe's server waits; a letter this session defines onto
  /// `\Device\NamedPipe` names it as `X:\<pipe>`; the walk opens the device's
  /// root, is told it is the named-pipe file system's, and refuses the path
  /// before the pipe's name is opened: the server is still waiting. The same
  /// holds for the letter's root and for `\Device\Null`. The planted defect,
  /// side by side: the one open the walk made next before — the pipe's name
  /// beneath the root it holds — is a client's open, and the server's
  /// connect completes.
  #[test]
  fn test_a_letter_onto_the_named_pipe_file_system_opens_no_pipe() {
    use windows_sys::Win32::Storage::FileSystem::{
      DDD_EXACT_MATCH_ON_REMOVE, DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION, DefineDosDeviceW,
      QueryDosDeviceW,
    };

    /// A drive letter this law defines, and removes when it is done.
    struct Letter(Vec<u16>, Vec<u16>);
    impl Drop for Letter {
      fn drop(&mut self) {
        // SAFETY: both strings are NUL-terminated.
        unsafe {
          DefineDosDeviceW(
            DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
            self.0.as_ptr(),
            self.1.as_ptr(),
          )
        };
      }
    }
    fn define(target: &str) -> (u8, Letter) {
      // Letters of this law's own: the laws that define letters run in
      // parallel, and two taking the same free letter undo each other's.
      for letter in (b'P'..=b'T').rev() {
        let name: Vec<u16> = [u16::from(letter), u16::from(b':'), 0].to_vec();
        let mut probe = [0u16; 16];
        // SAFETY: `name` is NUL-terminated and `probe` as long as declared.
        if unsafe { QueryDosDeviceW(name.as_ptr(), probe.as_mut_ptr(), probe.len() as u32) } != 0 {
          continue;
        }
        let target: Vec<u16> = target.encode_utf16().chain(core::iter::once(0)).collect();
        // SAFETY: both strings are NUL-terminated.
        let ok = unsafe { DefineDosDeviceW(DDD_RAW_TARGET_PATH, name.as_ptr(), target.as_ptr()) };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        return (letter, Letter(name, target));
      }
      panic!("no free drive letter");
    }
    let refused_unasked = |path: &str| {
      let Err(err) = resolve(Path::new(path)) else {
        panic!("{path} resolved");
      };
      assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{path}: {err}");
      assert_eq!(err.raw_os_error(), None, "{path}: {err}");
    };

    let pipe = format!("whichdisk-npfs-{}", std::process::id());
    let server = PipeServer::serve(&format!(r"\\.\pipe\{pipe}"));
    let (letter, defined) = define(r"\Device\NamedPipe");
    let letter = char::from(letter);
    refused_unasked(&format!(r"{letter}:\{pipe}"));
    refused_unasked(&format!(r"{letter}:\{pipe}\x"));
    refused_unasked(&format!(r"{letter}:\"));
    assert!(
      !server.connected(200),
      "the walk opened the pipe beneath the named-pipe file system's root"
    );
    drop(defined);

    let (null, defined) = define(r"\Device\Null");
    refused_unasked(&format!(r"{}:\x", char::from(null)));
    drop(defined);

    // The planted defect, side by side: the walk before opened the pipe's
    // name beneath the root it held, which connects to the server.
    let root = walk::open(None, r"\Device\NamedPipe\", true).unwrap();
    let _client = walk::open(Some(&root), &pipe, false).unwrap();
    assert!(
      server.connected(5_000),
      "an open beneath the named-pipe file system's root is a client's"
    );
  }

  /// **After a link, no share is opened**: a junction on a local volume to a
  /// share is refused before the share's root is opened. The refusal is the
  /// walk's own, not a name lookup's failure: the host does not exist, and a
  /// walk that opened the share first would have asked the network for it
  /// and answered with the network's error.
  #[test]
  fn test_a_link_to_a_share_is_refused_before_the_share_is_opened() {
    let dir = tempfile::tempdir().unwrap();
    let to_share = dir.path().join("junction-to-share");
    junction(&to_share, r"\??\UNC\whichdisk-no-such-host.invalid\share");
    let Err(err) = resolve(&to_share.join("x")) else {
      panic!("a link to a share resolved");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
    assert_eq!(err.raw_os_error(), None, "the network was asked: {err}");
  }

  /// **A letter's definition is read as the object manager reads it**,
  /// without regard to case: every spelling of the DOS device namespace names
  /// a path the walk walks; a device with nothing after it is opened as
  /// defined; a redirector's connection is opened through its share and the
  /// folders after the share walked; and anything else — a device with a path
  /// after it, a name outside both namespaces, another letter through the
  /// global directory — is refused.
  #[test]
  fn test_a_definition_is_read_as_the_object_manager_reads_it() {
    use walk::{LetterTarget, classified, split};

    const GUID: &str = "Volume{0e4a7d8c-5c1b-11ef-9d2a-806e6f6e6963}";
    for (definition, path) in [
      (r"\??\C:\x\y".to_owned(), r"\\?\C:\x\y".to_owned()),
      (r"\DosDevices\C:\x".to_owned(), r"\\?\C:\x".to_owned()),
      (
        r"\dOsDeViCeS\C:\controlled\junction\leaf".to_owned(),
        r"\\?\C:\controlled\junction\leaf".to_owned(),
      ),
      (r"\DOSDEVICES\C:\".to_owned(), r"\\?\C:\".to_owned()),
      (
        r"\GLOBAL??\UNC\server\share\x".to_owned(),
        r"\\?\UNC\server\share\x".to_owned(),
      ),
      (format!(r"\Global??\{GUID}\x"), format!(r"\\?\{GUID}\x")),
      (
        r"\??\GLOBAL\UNC\server\share".to_owned(),
        r"\\?\UNC\server\share".to_owned(),
      ),
      (
        r"\dosdevices\global\UNC\server\share".to_owned(),
        r"\\?\UNC\server\share".to_owned(),
      ),
    ] {
      assert_eq!(
        classified(&definition).unwrap(),
        LetterTarget::Path(path),
        "{definition}"
      );
    }
    // The object namespace's root through the DOS namespace is a path the walk
    // then refuses as a device.
    let LetterTarget::Path(root) = classified(r"\??\GLOBALROOT\Device\HarddiskVolume1\x").unwrap()
    else {
      panic!("the DOS namespace names a path");
    };
    assert!(split(&root).is_err());

    for (definition, device) in [
      (r"\Device\Null", r"\Device\Null"),
      (r"\Device\HarddiskVolume3", r"\Device\HarddiskVolume3"),
      (r"\device\HarddiskVolume3\", r"\device\HarddiskVolume3"),
    ] {
      assert_eq!(
        classified(definition).unwrap(),
        LetterTarget::Device(device.to_owned()),
        "{definition}"
      );
    }

    let connection = r"\Device\LanmanRedirector\;Z:0000000000012345\server\share";
    assert_eq!(
      classified(connection).unwrap(),
      LetterTarget::Connection {
        device: r"\Device\LanmanRedirector".to_owned(),
        connection: connection.to_owned(),
        beneath: Vec::new(),
      }
    );
    assert_eq!(
      classified(&format!(r"{connection}\folder\deeper\")).unwrap(),
      LetterTarget::Connection {
        device: r"\Device\LanmanRedirector".to_owned(),
        connection: connection.to_owned(),
        beneath: vec!["folder".to_owned(), "deeper".to_owned()],
      }
    );
    // WinFsp's network mode (SSHFS-Win) defines its letter onto its own
    // volume device in the connection form; the device is its own.
    let winfsp = format!(r"\Device\{GUID}\;X:\sshfs\host");
    assert_eq!(
      classified(&winfsp).unwrap(),
      LetterTarget::Connection {
        device: format!(r"\Device\{GUID}"),
        connection: winfsp.clone(),
        beneath: Vec::new(),
      }
    );
    // The device is named in the case the definition spells it.
    assert!(matches!(
      classified(r"\DEVICE\WebDavRedirector\;Y:0000000000012345\host\DavWWWRoot").unwrap(),
      LetterTarget::Connection { device, .. } if device == r"\DEVICE\WebDavRedirector"
    ));

    for definition in [
      r"\Device\HarddiskVolume3\controlled\junction\leaf",
      r"\Device\Mup\server\share",
      r"\Device\LanmanRedirector\;Z:0000000000012345\server",
      r"\Device\LanmanRedirector\;Z:0000000000012345\server\share\..",
      r"\Device\",
      r"\Device\\Null",
      r"\Sessions\0\DosDevices\00000000-000003e7\C:\x",
      r"\RPC Control\link",
      r"\GLOBAL??\C:\x",
      r"\Global??\c:",
      r"\??\GLOBAL\C:\x",
      r"\DosDevices\Global\D:\x",
      r"C:\x",
    ] {
      assert_eq!(
        classified(definition).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidInput),
        "{definition}"
      );
    }

    // The planted defect, side by side: the classifier before knew the DOS
    // namespace in one case and one spelling, and took these for devices,
    // each opened in one call that resolves its folders unseen.
    let before = |definition: &str| {
      definition
        .strip_prefix(r"\??\")
        .or_else(|| definition.strip_prefix(r"\DosDevices\"))
        .is_some()
    };
    assert!(!before(r"\dOsDeViCeS\C:\controlled\junction\leaf"));
    assert!(!before(r"\GLOBAL??\UNC\server\share\x"));
    assert!(!before(r"\Device\HarddiskVolume3\controlled\junction\leaf"));
  }

  /// **A drive letter defined onto a path is walked as that path**: `subst`
  /// — `DefineDosDeviceW` — onto a folder resolves to the folder's own file;
  /// and onto a junction to a named pipe, it is refused like the junction,
  /// the pipe's server still waiting: the letter's own definition is read,
  /// and never followed unseen.
  #[test]
  fn test_a_substituted_drive_is_walked_as_its_path() {
    use windows_sys::Win32::Storage::FileSystem::{
      DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION, DefineDosDeviceW, QueryDosDeviceW,
    };

    /// A drive letter this law defines, and removes when it is done.
    struct Letter(Vec<u16>, Vec<u16>);
    impl Drop for Letter {
      fn drop(&mut self) {
        // SAFETY: both strings are NUL-terminated.
        unsafe {
          DefineDosDeviceW(
            DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
            self.0.as_ptr(),
            self.1.as_ptr(),
          )
        };
      }
    }
    fn define(target: &Path) -> (char, Letter) {
      // Letters of this law's own: the laws that define letters run in
      // parallel, and two taking the same free letter undo each other's.
      for letter in ('K'..='O').rev() {
        let name: Vec<u16> = format!("{letter}:\0").encode_utf16().collect();
        let mut probe = [0u16; 16];
        // SAFETY: `name` is NUL-terminated and `probe` as long as declared.
        if unsafe { QueryDosDeviceW(name.as_ptr(), probe.as_mut_ptr(), probe.len() as u32) } != 0 {
          continue;
        }
        let path = to_wide(target);
        // SAFETY: both strings are NUL-terminated.
        let ok = unsafe { DefineDosDeviceW(0, name.as_ptr(), path.as_ptr()) };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        return (letter, Letter(name, path));
      }
      panic!("no free drive letter");
    }

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file"), b"whichdisk").unwrap();
    let (letter, _defined) = define(dir.path());
    let resolved = resolve(Path::new(&format!(r"{letter}:\file"))).unwrap();
    assert_eq!(
      resolved.canonical_path(),
      dir.path().join("file").canonicalize().unwrap()
    );

    let name = format!(r"\\.\pipe\whichdisk-subst-{}", std::process::id());
    let server = PipeServer::serve(&name);
    let to_pipe = dir.path().join("junction-to-pipe");
    junction(
      &to_pipe,
      &format!(r"\??\pipe\whichdisk-subst-{}", std::process::id()),
    );
    let (letter, _defined) = define(&to_pipe);
    assert_eq!(
      resolve(Path::new(&format!(r"{letter}:\beneath")))
        .err()
        .map(|err| err.kind()),
      Some(io::ErrorKind::InvalidInput)
    );
    assert!(!server.connected(0), "the letter's junction was followed");
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
  /// it, so the device kind says nothing about its removal and its own device
  /// is asked: its removal answer is its disk's removal policy, and where that
  /// says nothing the storage descriptor's yes, or `Unknown`.
  #[test]
  fn test_a_fixed_disk_answers_through_its_own_device() {
    let (observation, _) = Observation::of_object(&walk::walk(r"C:\").unwrap())
      .required()
      .unwrap();
    let device = observation
      .device()
      .expect("the I/O manager names the device kind");
    if device.characteristics & FILE_REMOVABLE_MEDIA != 0 {
      return;
    }
    assert!(is_disk(device.device_type), "{device:?}");
    let guid = VolumeRoot::parse(&guid_of_root("C:\\")).expect("a volume root");
    let device = observed::VolumeDevice::open(&guid).required().unwrap();
    let policy = device.removal_policy().required().unwrap();
    let descriptor = device.descriptor().required().unwrap();
    let expected = match policy_answer(policy) {
      Ejectability::Unknown if descriptor.says_removable() => Ejectability::Ejectable,
      answer => answer,
    };
    assert_eq!(
      resolve(Path::new("C:\\"))
        .unwrap()
        .mount_info()
        .ejectability(),
      expected,
      "policy {policy}, {descriptor:?}"
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
