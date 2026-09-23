//! A buffer a platform call writes its answer into, read only as far as the
//! call says it wrote.
//!
//! **A kernel-filled buffer is read only within the length the kernel says it
//! wrote.** A call that fills a caller's buffer reports how much of it the
//! answer is — `getattrlist`'s leading length, `IO_STATUS_BLOCK.Information`,
//! `DeviceIoControl`'s byte count — and every byte past that is whatever the
//! buffer held before the call, not the platform's answer. So a
//! [`KernelBuffer`] hands its decoders nothing but a [`Filled`] view of that
//! prefix, and a view exists only once the reported length has been checked
//! against the buffer: a count beyond it is no answer about it, and fails as
//! `InvalidData`. Every field a decoder reads is then taken out of the view by
//! offset and length, and one that does not lie wholly inside it is
//! `InvalidData` too — so no decoder can read a byte the platform did not say
//! it wrote, and a structure the platform could not have written is an error,
//! never an absence.

use std::io;

/// Bytes a platform call is handed to write its answer into.
///
/// Nothing but bytes, so every byte of it is initialised whatever the call
/// writes or leaves, and no padding lies anywhere in it; aligned to 8, so the
/// call may lay its own structures — the widest of which hold a 64-bit
/// integer — at its start.
#[repr(C, align(8))]
pub(crate) struct KernelBuffer<const N: usize>([u8; N]);

impl<const N: usize> KernelBuffer<N> {
  /// The length a call is told the buffer has, which is all it may write.
  pub(crate) const LEN: usize = N;

  /// A buffer of zeroes.
  pub(crate) const fn new() -> Self {
    Self([0; N])
  }

  /// A buffer holding `bytes`, as a call might have left it, for the laws.
  #[cfg(test)]
  pub(crate) const fn holding(bytes: [u8; N]) -> Self {
    Self(bytes)
  }

  /// The start of the buffer, for the one call that fills it.
  pub(crate) fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
    self.0.as_mut_ptr().cast()
  }

  /// The prefix the call said it wrote: `written` bytes, or `InvalidData`
  /// where that is more than the buffer holds.
  pub(crate) fn filled(&self, written: usize) -> io::Result<Filled<'_>> {
    self
      .0
      .get(..written)
      .map(|bytes| Filled { bytes })
      .ok_or_else(|| invalid("the platform said it wrote more than the buffer it was given holds"))
  }
}

/// The bytes of one answer a platform call said it wrote, and no others.
#[derive(Clone, Copy)]
pub(crate) struct Filled<'b> {
  bytes: &'b [u8],
}

impl<'b> Filled<'b> {
  /// How many bytes the call said it wrote.
  pub(crate) const fn len(&self) -> usize {
    self.bytes.len()
  }

  /// `len` bytes at `at`, wholly inside what was written, or `InvalidData`.
  pub(crate) fn bytes(&self, at: usize, len: usize) -> io::Result<&'b [u8]> {
    at.checked_add(len)
      .and_then(|end| self.bytes.get(at..end))
      .ok_or_else(|| invalid("a field that does not lie inside what the platform wrote"))
  }

  /// `M` bytes at `at`, the same way.
  pub(crate) fn array<const M: usize>(&self, at: usize) -> io::Result<[u8; M]> {
    self.bytes(at, M).and_then(|bytes| {
      <[u8; M]>::try_from(bytes)
        .map_err(|_| invalid("a field that does not lie inside what the platform wrote"))
    })
  }

  /// A native-endian `u32` at `at`, the same way.
  pub(crate) fn u32_at(&self, at: usize) -> io::Result<u32> {
    self.array(at).map(u32::from_ne_bytes)
  }

  /// A native-endian `i32` at `at`, the same way.
  #[cfg_attr(windows, allow(dead_code))]
  pub(crate) fn i32_at(&self, at: usize) -> io::Result<i32> {
    self.array(at).map(i32::from_ne_bytes)
  }

  /// A native-endian `i64` at `at`, the same way.
  #[cfg_attr(not(windows), allow(dead_code))]
  pub(crate) fn i64_at(&self, at: usize) -> io::Result<i64> {
    self.array(at).map(i64::from_ne_bytes)
  }
}

/// The error a structure the platform could not have written ends in.
pub(crate) fn invalid(what: &'static str) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, what)
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A view is the prefix the call reported and nothing past it: a count
  /// beyond the buffer is refused, and so is every field that does not lie
  /// wholly inside what was written.
  #[test]
  fn test_a_filled_view_is_the_reported_prefix_and_nothing_past_it() {
    let mut buffer = KernelBuffer::<16>::new();
    buffer.0[..8].copy_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(KernelBuffer::<16>::LEN, 16);
    assert_eq!(
      buffer.filled(17).err().map(|err| err.kind()),
      Some(io::ErrorKind::InvalidData),
      "a count past the buffer is no answer about it"
    );
    let filled = buffer.filled(8).unwrap();
    assert_eq!(filled.len(), 8);
    assert_eq!(filled.u32_at(0).unwrap(), u32::from_ne_bytes([1, 0, 0, 0]));
    assert_eq!(filled.u32_at(4).unwrap(), u32::from_ne_bytes([2, 0, 0, 0]));
    for (at, len) in [(5, 4), (8, 1), (0, 9), (usize::MAX, 2)] {
      assert_eq!(
        filled.bytes(at, len).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidData),
        "{at}+{len} lies past what was written"
      );
    }
    assert!(filled.bytes(8, 0).unwrap().is_empty());
    assert!(filled.u32_at(6).is_err());
    assert!(filled.i64_at(4).is_err());
    assert_eq!(filled.i32_at(4).unwrap(), 2);
    assert_eq!(
      filled.i64_at(0).unwrap(),
      i64::from_ne_bytes([1, 0, 0, 0, 2, 0, 0, 0])
    );
  }
}
