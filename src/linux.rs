use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use bytes::{BufMut, BytesMut};

use rustix::fs::stat;

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
  mount_point: SmallBytes,
  device: SmallBytes,
  canonical: PathBuf,
  relative_offset: usize,
}

impl Inner {
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn mount_point(&self) -> &Path {
    self.mount_point.as_path()
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn device(&self) -> &OsStr {
    self.device.as_os_str()
  }

  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(super) fn relative_path(&self) -> &Path {
    let bytes = self.canonical.as_os_str().as_bytes();
    Path::new(OsStr::from_bytes(&bytes[self.relative_offset..]))
  }
}

#[cfg_attr(not(tarpaulin), inline(always))]
pub(super) fn which_disk(path: &Path) -> io::Result<Inner> {
  let canonical = path.canonicalize()?;
  let st = stat(&canonical).map_err(io::Error::from)?;
  let dev = st.st_dev;

  // Try thread-local cache first — avoids re-reading /proc/self/mountinfo
  // for paths on the same device.
  let cached = CACHE.with(|c| {
    c.borrow()
      .get(&dev)
      .map(|e| (e.mount_point.clone(), e.device.clone()))
  });

  let (mount_point, device) = if let Some(hit) = cached {
    hit
  } else {
    let (mp, dv) = lookup_mountinfo(dev)?;
    CACHE.with(|c| {
      c.borrow_mut().insert(
        dev,
        CacheEntry {
          mount_point: mp.clone(),
          device: dv.clone(),
        },
      );
    });
    (mp, dv)
  };

  let canonical_bytes = canonical.as_os_str().as_bytes();
  let mp_bytes = mount_point.as_bytes();

  let relative_offset = if mp_bytes == b"/" {
    // Root mount: relative path is everything after the leading '/'
    1
  } else if canonical_bytes.starts_with(mp_bytes) {
    let off = mp_bytes.len();
    if off < canonical_bytes.len() && canonical_bytes[off] == b'/' {
      off + 1
    } else {
      off
    }
  } else {
    canonical_bytes.len() // empty relative path
  };

  Ok(Inner {
    mount_point,
    device,
    canonical,
    relative_offset,
  })
}

/// Reads `/proc/self/mountinfo` and finds the entry matching `target_dev`.
fn lookup_mountinfo(target_dev: u64) -> io::Result<(SmallBytes, SmallBytes)> {
  let mountinfo = std::fs::read("/proc/self/mountinfo")?;

  let mut best: Option<(SmallBytes, SmallBytes)> = None;
  let mut best_len: usize = 0;
  let mut start = 0;

  // Use memchr to split lines instead of byte-by-byte closure.
  while start < mountinfo.len() {
    let end = super::find_byte(b'\n', &mountinfo[start..])
      .map(|pos| start + pos)
      .unwrap_or(mountinfo.len());

    let line = &mountinfo[start..end];
    start = end + 1;

    if line.is_empty() {
      continue;
    }

    if let Some((dev_major, dev_minor, mp_raw, source_raw)) = parse_mountinfo_line(line) {
      // Compare major:minor against stat's st_dev using Linux makedev encoding.
      let line_dev = makedev(dev_major, dev_minor);
      if line_dev != target_dev {
        continue;
      }

      // Among entries for the same device, pick the longest mount point
      // (handles bind mounts where multiple entries share a device).
      let mp = decode_octal_escapes(mp_raw);
      if mp.as_bytes().len() > best_len {
        best_len = mp.as_bytes().len();
        let device = decode_octal_escapes(source_raw);
        best = Some((mp, device));
      }
    }
  }

  best.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no mount point found for device"))
}

/// Parses a single line from `/proc/self/mountinfo`.
///
/// Format: `mount_id parent_id major:minor root mount_point options [optional]... - fs_type source super_options`
///
/// Returns `(major, minor, mount_point_raw, source_raw)`.
fn parse_mountinfo_line(line: &[u8]) -> Option<(u64, u64, &[u8], &[u8])> {
  let mut fields = line.split(|&b| b == b' ');

  fields.next()?; // mount_id
  fields.next()?; // parent_id
  let dev_field = fields.next()?; // major:minor
  fields.next()?; // root
  let mount_point_raw = fields.next()?; // mount_point (octal-escaped)

  // Parse major:minor
  let colon = super::find_byte(b':', dev_field)?;
  let major = parse_u64(&dev_field[..colon])?;
  let minor = parse_u64(&dev_field[colon + 1..])?;

  // Skip options and optional tagged fields until the "-" separator.
  let mut found_sep = false;
  for field in fields.by_ref() {
    if field == b"-" {
      found_sep = true;
      break;
    }
  }
  if !found_sep {
    return None;
  }

  fields.next()?; // fs_type
  let source_raw = fields.next()?; // mount source (device)

  Some((major, minor, mount_point_raw, source_raw))
}

/// Reconstructs a `dev_t` from major and minor numbers using the Linux encoding.
#[cfg_attr(not(tarpaulin), inline(always))]
fn makedev(major: u64, minor: u64) -> u64 {
  ((major & 0xffff_f000) << 32)
    | ((major & 0x0000_0fff) << 8)
    | ((minor & 0xffff_ff00) << 12)
    | (minor & 0x0000_00ff)
}

/// Parses an ASCII decimal byte string into u64.
#[cfg_attr(not(tarpaulin), inline(always))]
fn parse_u64(bytes: &[u8]) -> Option<u64> {
  if bytes.is_empty() {
    return None;
  }
  let mut n: u64 = 0;
  for &b in bytes {
    let d = b.wrapping_sub(b'0');
    if d > 9 {
      return None;
    }
    n = n.checked_mul(10)?.checked_add(d as u64)?;
  }
  Some(n)
}

/// Decodes octal escape sequences (`\040`, `\011`, `\012`, `\134`) used
/// in `/proc/self/mountinfo` and `/proc/mounts`.
fn decode_octal_escapes(input: &[u8]) -> SmallBytes {
  // Fast path: no backslash means no escapes to decode.
  if super::find_byte(b'\\', input).is_none() {
    return SmallBytes::from_bytes(input);
  }

  // Decoding only shrinks (4-byte escape → 1 byte), so if input fits in 64
  // bytes the output is guaranteed to as well — decode into a stack buffer.
  if input.len() <= super::INLINE_CAPACITY {
    let mut data = [0u8; super::INLINE_CAPACITY];
    let mut out = 0;
    let mut i = 0;
    while i < input.len() {
      if input[i] == b'\\' && i + 3 < input.len() {
        let a = input[i + 1].wrapping_sub(b'0');
        let b = input[i + 2].wrapping_sub(b'0');
        let c = input[i + 3].wrapping_sub(b'0');
        if a < 8 && b < 8 && c < 8 {
          data[out] = a * 64 + b * 8 + c;
          out += 1;
          i += 4;
          continue;
        }
      }
      data[out] = input[i];
      out += 1;
      i += 1;
    }
    SmallBytes::Inline {
      data,
      len: out as u8,
    }
  } else {
    let mut out = BytesMut::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
      if input[i] == b'\\' && i + 3 < input.len() {
        let a = input[i + 1].wrapping_sub(b'0');
        let b = input[i + 2].wrapping_sub(b'0');
        let c = input[i + 3].wrapping_sub(b'0');
        if a < 8 && b < 8 && c < 8 {
          out.put_u8(a * 64 + b * 8 + c);
          i += 4;
          continue;
        }
      }
      out.put_u8(input[i]);
      i += 1;
    }
    SmallBytes::Heap(out.freeze())
  }
}
