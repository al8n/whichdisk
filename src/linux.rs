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
#[cfg_attr(not(tarpaulin), inline(always))]
fn decode_octal_escapes(input: &[u8]) -> SmallBytes {
  // Fast path: no backslash means no escapes to decode.
  if super::find_byte(b'\\', input).is_none() {
    return SmallBytes::from_bytes(input);
  }

  // Decoding only shrinks (4-byte escape → 1 byte), so if input fits in
  // INLINE_CAPACITY bytes the output is guaranteed to as well — decode into
  // a stack buffer.
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

#[cfg(test)]
mod tests {
  use super::*;

  // ── parse_u64 ─────────────────────────────────────────────────────

  #[test]
  fn test_parse_u64_valid() {
    assert_eq!(parse_u64(b"0"), Some(0));
    assert_eq!(parse_u64(b"123"), Some(123));
    assert_eq!(parse_u64(b"259"), Some(259));
  }

  #[test]
  fn test_parse_u64_empty() {
    assert_eq!(parse_u64(b""), None);
  }

  #[test]
  fn test_parse_u64_non_digit() {
    assert_eq!(parse_u64(b"12a3"), None);
    assert_eq!(parse_u64(b"abc"), None);
  }

  #[test]
  fn test_parse_u64_overflow() {
    // u64::MAX = 18446744073709551615, adding one more digit should overflow
    assert_eq!(parse_u64(b"99999999999999999999"), None);
  }

  // ── makedev ───────────────────────────────────────────────────────

  #[test]
  fn test_makedev() {
    // major=8, minor=1 → /dev/sda1 on typical Linux
    let dev = makedev(8, 1);
    assert_eq!(dev, (8 << 8) | 1);
  }

  #[test]
  fn test_makedev_large() {
    // Verify extended device number encoding
    let dev = makedev(259, 0);
    let reconstructed_major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let reconstructed_minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    assert_eq!(reconstructed_major, 259);
    assert_eq!(reconstructed_minor, 0);
  }

  // ── parse_mountinfo_line ──────────────────────────────────────────

  #[test]
  fn test_parse_mountinfo_valid() {
    let line = b"36 35 98:0 / /mnt rw,noatime shared:1 - ext3 /dev/root rw,errors=continue";
    let (major, minor, mp, source) = parse_mountinfo_line(line).unwrap();
    assert_eq!(major, 98);
    assert_eq!(minor, 0);
    assert_eq!(mp, b"/mnt");
    assert_eq!(source, b"/dev/root");
  }

  #[test]
  fn test_parse_mountinfo_with_optional_fields() {
    // Multiple optional fields before the separator
    let line = b"100 50 8:1 / /boot rw master:1 shared:2 - ext4 /dev/sda1 rw";
    let (major, minor, mp, source) = parse_mountinfo_line(line).unwrap();
    assert_eq!(major, 8);
    assert_eq!(minor, 1);
    assert_eq!(mp, b"/boot");
    assert_eq!(source, b"/dev/sda1");
  }

  #[test]
  fn test_parse_mountinfo_no_separator() {
    // Malformed line without " - "
    let line = b"36 35 98:0 / /mnt rw,noatime shared:1";
    assert!(parse_mountinfo_line(line).is_none());
  }

  #[test]
  fn test_parse_mountinfo_too_few_fields() {
    let line = b"36 35";
    assert!(parse_mountinfo_line(line).is_none());
  }

  // ── decode_octal_escapes ──────────────────────────────────────────

  #[test]
  fn test_decode_no_escapes() {
    let result = decode_octal_escapes(b"/mnt/data");
    assert_eq!(result.as_bytes(), b"/mnt/data");
  }

  #[test]
  fn test_decode_space_escape_inline() {
    // \040 = space (0o40 = 32)
    let result = decode_octal_escapes(b"/mnt/my\\040drive");
    assert_eq!(result.as_bytes(), b"/mnt/my drive");
    assert!(matches!(result, SmallBytes::Inline { .. }));
  }

  #[test]
  fn test_decode_backslash_escape() {
    // \134 = backslash (0o134 = 92)
    let result = decode_octal_escapes(b"/mnt/back\\134slash");
    assert_eq!(result.as_bytes(), b"/mnt/back\\slash");
  }

  #[test]
  fn test_decode_multiple_escapes() {
    // \011 = tab (0o11 = 9), \012 = newline (0o12 = 10)
    let result = decode_octal_escapes(b"a\\011b\\012c");
    assert_eq!(result.as_bytes(), b"a\tb\nc");
  }

  #[test]
  fn test_decode_escape_at_end_truncated() {
    // Backslash near end without enough chars for a full octal — treated as literal
    let result = decode_octal_escapes(b"abc\\04");
    assert_eq!(result.as_bytes(), b"abc\\04");
  }

  #[test]
  fn test_decode_invalid_octal_digits() {
    // \089 — '8' and '9' are not valid octal digits, treated as literal
    let result = decode_octal_escapes(b"x\\089y");
    assert_eq!(result.as_bytes(), b"x\\089y");
  }

  #[test]
  fn test_decode_heap_path() {
    // Input longer than INLINE_CAPACITY with escapes
    let mut input = vec![b'a'; super::super::INLINE_CAPACITY + 10];
    // Insert \040 (space) near the start
    input[1] = b'\\';
    input[2] = b'0';
    input[3] = b'4';
    input[4] = b'0';
    let result = decode_octal_escapes(&input);
    assert!(matches!(result, SmallBytes::Heap(_)));
    // The result should have a space at position 1
    assert_eq!(result.as_bytes()[1], b' ');
  }

  #[test]
  fn test_decode_heap_literal_backslash() {
    // Heap path with a backslash that's not a valid octal escape
    let mut input = vec![b'x'; super::super::INLINE_CAPACITY + 5];
    input[0] = b'\\';
    input[1] = b'z'; // not octal
    let result = decode_octal_escapes(&input);
    assert!(matches!(result, SmallBytes::Heap(_)));
    assert_eq!(result.as_bytes()[0], b'\\');
    assert_eq!(result.as_bytes()[1], b'z');
  }

  // ── lookup_mountinfo ──────────────────────────────────────────────

  #[test]
  fn test_lookup_mountinfo_nonexistent_dev() {
    // Device 0xDEADBEEF should not exist
    let result = lookup_mountinfo(0xDEAD_BEEF);
    assert!(result.is_err());
  }

  // ── which_disk relative_offset branches ───────────────────────────

  #[test]
  fn test_which_disk_root() {
    let info = which_disk(Path::new("/")).unwrap();
    assert_eq!(info.mount_point(), Path::new("/"));
    assert_eq!(info.relative_path(), Path::new(""));
  }

  #[test]
  fn test_which_disk_deep_path() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("a/b/c");
    std::fs::create_dir_all(&deep).unwrap();
    let info = which_disk(&deep).unwrap();
    assert!(info.mount_point().is_absolute());
    assert!(info.relative_path().is_relative());
  }

  #[test]
  fn test_which_disk_cache_hit() {
    let info1 = which_disk(Path::new("/")).unwrap();
    let info2 = which_disk(Path::new("/")).unwrap();
    assert_eq!(info1.mount_point(), info2.mount_point());
    assert_eq!(info1.device(), info2.device());
  }

  #[test]
  fn test_which_disk_nonexistent() {
    assert!(which_disk(Path::new("/nonexistent/xyz")).is_err());
  }

  /// Try to cover the non-root mount point prefix branch.
  /// On many Linux systems, /boot, /home, or /tmp may be separate mounts.
  #[test]
  fn test_which_disk_non_root_mount() {
    for candidate in ["/boot", "/home", "/tmp", "/var", "/proc"] {
      let p = Path::new(candidate);
      if !p.exists() {
        continue;
      }
      let info = which_disk(p).unwrap();
      // If this path IS a mount point itself, relative_path should be empty
      // If it's on a non-root mount, the branch at line 85-88 is exercised
      let _ = info.relative_path();
    }
  }
}
