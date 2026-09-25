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
//!
//! A call that reports no length at all marks the end of its answer only with
//! the terminator it promises, so its buffer is a [`SentinelBuffer`]: no unit
//! of it is zero when the call is handed it, and the terminator search is the
//! buffer's own reader — a zero the call did not write can never end a string.

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

  /// The `len` bytes at `at` that end the answer: a structure's variable
  /// part, which the platform declares by its length, ending exactly where
  /// the count the call reported does — or `InvalidData`. Bytes the call
  /// said it wrote past the declared part are no part of the structure it
  /// describes, and a declared part that runs past them is not one it wrote.
  #[cfg(any(windows, test))]
  pub(crate) fn tail(&self, at: usize, len: usize) -> io::Result<&'b [u8]> {
    if at.checked_add(len) != Some(self.bytes.len()) {
      return Err(invalid(
        "a declared length that does not end where the platform said its answer does",
      ));
    }
    self.bytes(at, len)
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
  pub(crate) fn i32_at(&self, at: usize) -> io::Result<i32> {
    self.array(at).map(i32::from_ne_bytes)
  }

  /// A native-endian `i64` at `at`, the same way.
  #[cfg_attr(not(windows), allow(dead_code))]
  pub(crate) fn i64_at(&self, at: usize) -> io::Result<i64> {
    self.array(at).map(i64::from_ne_bytes)
  }
}

/// A unit of a string a platform call writes: a byte, or a UTF-16 code unit.
pub(crate) trait Unit: Copy + PartialEq {
  /// The terminator a call writes after its string.
  const NUL: Self;
  /// What every unit of a [`SentinelBuffer`] holds until a call writes it.
  /// Nonzero, so it is never taken for a terminator; and never part of
  /// well-formed text — a byte UTF-8 never uses, a lone low surrogate — so a
  /// unit a call skipped cannot pass for text either.
  const UNWRITTEN: Self;
}

impl Unit for u8 {
  const NUL: Self = 0;
  const UNWRITTEN: Self = 0xFF;
}

impl Unit for u16 {
  const NUL: Self = 0;
  const UNWRITTEN: Self = 0xDFFF;
}

/// Room for a call that reports no length — only that it succeeded — and
/// promises a terminator after the string it wrote: `FindFirstVolumeW`,
/// `FindNextVolumeW`, `fcntl(F_GETPATH_NOFIRMLINK)`; and, ended by an empty
/// member, `CM_Get_Device_Interface_ListW`'s list.
///
/// **A terminator counts only where the call wrote it.** Such a call's one
/// mark of how far it wrote is that terminator, so a zero the buffer held
/// before the call — a zeroed allocation, what an earlier call left — would
/// pass for one and turn a string the call never finished into an answer.
/// This buffer holds no zero whenever a call is handed it: every unit is
/// [`Unit::UNWRITTEN`] again before each call ([`Self::for_call`]), and its
/// one reader, [`Self::terminated`], is the units before the first zero —
/// which only the call can have written. No zero in it is `InvalidData`.
pub(crate) struct SentinelBuffer<U: Unit> {
  units: Vec<U>,
}

impl<U: Unit> SentinelBuffer<U> {
  /// Room for `len` units, none of them a terminator.
  pub(crate) fn new(len: usize) -> Self {
    Self {
      units: vec![U::UNWRITTEN; len],
    }
  }

  /// A buffer holding `units`, as a call might have left it, for the laws.
  #[cfg(test)]
  pub(crate) fn holding(units: &[U]) -> Self {
    Self {
      units: units.to_vec(),
    }
  }

  /// How many units a call may write.
  #[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
  pub(crate) fn len(&self) -> usize {
    self.units.len()
  }

  /// The start of the buffer for one call, every unit of it unwritten again,
  /// so that no terminator a call before left can end this call's string.
  pub(crate) fn for_call(&mut self) -> *mut U {
    self.units.fill(U::UNWRITTEN);
    self.units.as_mut_ptr()
  }

  /// The string the call wrote: the units before the terminator it wrote
  /// after them, or `InvalidData` where the buffer holds none — no string the
  /// call finished writing.
  #[cfg_attr(all(windows, not(any(feature = "list", test))), allow(dead_code))]
  pub(crate) fn terminated(&self) -> io::Result<&[U]> {
    self
      .units
      .iter()
      .position(|&unit| unit == U::NUL)
      .map(|len| &self.units[..len])
      .ok_or_else(|| invalid("a string with no terminator the call wrote"))
  }

  /// The list of strings the call wrote — each member and the terminator it
  /// wrote after it, then the empty member that ends the list — up to and
  /// including that last terminator, or `InvalidData` where the buffer holds
  /// no end of a list the call wrote. What follows the end is no part of the
  /// list, and is never read.
  #[cfg(any(windows, test))]
  pub(crate) fn list_terminated(&self) -> io::Result<&[U]> {
    let mut start = 0;
    loop {
      let len = self
        .units
        .get(start..)
        .and_then(|rest| rest.iter().position(|&unit| unit == U::NUL))
        .ok_or_else(|| invalid("a list of strings with no end the call wrote"))?;
      if len == 0 {
        return Ok(&self.units[..=start]);
      }
      start += len + 1;
    }
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

  /// A declared variable part ends the answer exactly: it is read where the
  /// count the call reported ends with it, and refused where bytes the call
  /// reported lie past it or it runs past them.
  #[test]
  fn test_a_declared_tail_ends_the_answer_exactly() {
    let buffer = KernelBuffer::<16>::holding([7; 16]);
    let filled = buffer.filled(12).unwrap();
    assert_eq!(filled.tail(4, 8).unwrap(), [7; 8]);
    assert_eq!(filled.tail(12, 0).unwrap(), [0u8; 0]);
    for (at, len) in [(4, 7), (4, 9), (0, 11), (13, 0), (usize::MAX, 2)] {
      assert_eq!(
        filled.tail(at, len).err().map(|err| err.kind()),
        Some(io::ErrorKind::InvalidData),
        "{at}+{len} does not end a 12-byte answer"
      );
    }
  }

  /// A call that reports no length ends its string only at a terminator it
  /// wrote: a fresh buffer holds none, a terminator an earlier call left is
  /// gone before the next call, and a string with none is refused.
  #[test]
  fn test_a_terminator_counts_only_where_the_call_wrote_it() {
    let mut buffer = SentinelBuffer::<u16>::new(8);
    assert_eq!(buffer.len(), 8);
    assert_eq!(
      buffer.terminated().unwrap_err().kind(),
      io::ErrorKind::InvalidData,
      "no call wrote a terminator into a fresh buffer"
    );

    let units = buffer.for_call();
    // SAFETY: `units` points at the buffer's 8 units, live for these writes.
    unsafe {
      units.write(u16::from(b'C'));
      units.add(1).write(0);
    }
    assert_eq!(buffer.terminated().unwrap(), [u16::from(b'C')]);

    let units = buffer.for_call();
    // SAFETY: as above; this call writes a string and no terminator.
    unsafe { units.write(u16::from(b'D')) };
    assert_eq!(
      buffer.terminated().unwrap_err().kind(),
      io::ErrorKind::InvalidData,
      "the terminator the earlier call left does not end this call's string"
    );

    let bytes = SentinelBuffer::<u8>::holding(b"/a\0b");
    assert_eq!(bytes.terminated().unwrap(), b"/a");
    assert!(SentinelBuffer::<u8>::new(4).terminated().is_err());
    assert!(String::from_utf16(&[u16::UNWRITTEN]).is_err());
    assert!(core::str::from_utf8(&[u8::UNWRITTEN]).is_err());
  }

  /// A list of strings ends at the empty member the call wrote after its
  /// last: members and their terminators up to it, nothing past it, and a
  /// list the call never ended is refused.
  #[test]
  fn test_a_list_ends_only_where_the_call_ended_it() {
    let w = u16::UNWRITTEN;
    let list = SentinelBuffer::<u16>::holding(&[1, 2, 0, 3, 0, 0, w, 7, 0, 0]);
    assert_eq!(list.list_terminated().unwrap(), [1, 2, 0, 3, 0, 0]);
    let empty = SentinelBuffer::<u16>::holding(&[0, w, w]);
    assert_eq!(empty.list_terminated().unwrap(), [0]);
    for units in [&[1, 0, w][..], &[1, 2, w, w][..], &[w, w][..], &[][..]] {
      assert_eq!(
        SentinelBuffer::<u16>::holding(units)
          .list_terminated()
          .unwrap_err()
          .kind(),
        io::ErrorKind::InvalidData,
        "{units:?}"
      );
    }
  }
}
