//! MD5 (RFC 1321), used for one thing only: reproducing the version-3 volume
//! UUIDs that Apple platforms derive for FAT-class filesystems.
//!
//! This is not a general-purpose hash and must never be used as one — MD5 has
//! been broken for collision resistance since 2004. It is here because the
//! *identity* of an exFAT volume, as every Apple platform reports it, is
//! literally an MD5 of the volume's serial number: to answer with the same
//! identity on Linux and Windows, this crate has to compute the same hash.
//! See [`VolumeIdentity`](crate::VolumeIdentity) for the derivation and why it
//! is the canonical form.

/// The 64 round constants, `floor(2^32 * abs(sin(i + 1)))`.
const K: [u32; 64] = [
  0xd76a_a478,
  0xe8c7_b756,
  0x2420_70db,
  0xc1bd_ceee,
  0xf57c_0faf,
  0x4787_c62a,
  0xa830_4613,
  0xfd46_9501,
  0x6980_98d8,
  0x8b44_f7af,
  0xffff_5bb1,
  0x895c_d7be,
  0x6b90_1122,
  0xfd98_7193,
  0xa679_438e,
  0x49b4_0821,
  0xf61e_2562,
  0xc040_b340,
  0x265e_5a51,
  0xe9b6_c7aa,
  0xd62f_105d,
  0x0244_1453,
  0xd8a1_e681,
  0xe7d3_fbc8,
  0x21e1_cde6,
  0xc337_07d6,
  0xf4d5_0d87,
  0x455a_14ed,
  0xa9e3_e905,
  0xfcef_a3f8,
  0x676f_02d9,
  0x8d2a_4c8a,
  0xfffa_3942,
  0x8771_f681,
  0x6d9d_6122,
  0xfde5_380c,
  0xa4be_ea44,
  0x4bde_cfa9,
  0xf6bb_4b60,
  0xbebf_bc70,
  0x289b_7ec6,
  0xeaa1_27fa,
  0xd4ef_3085,
  0x0488_1d05,
  0xd9d4_d039,
  0xe6db_99e5,
  0x1fa2_7cf8,
  0xc4ac_5665,
  0xf429_2244,
  0x432a_ff97,
  0xab94_23a7,
  0xfc93_a039,
  0x655b_59c3,
  0x8f0c_cc92,
  0xffef_f47d,
  0x8584_5dd1,
  0x6fa8_7e4f,
  0xfe2c_e6e0,
  0xa301_4314,
  0x4e08_11a1,
  0xf753_7e82,
  0xbd3a_f235,
  0x2ad7_d2bb,
  0xeb86_d391,
];

/// The per-round left-rotation amounts.
const SHIFTS: [u32; 64] = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const INITIAL_STATE: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// Returns the MD5 digest of `input`.
pub(crate) fn digest(input: &[u8]) -> [u8; 16] {
  let mut state = INITIAL_STATE;

  let mut blocks = input.chunks_exact(64);
  for block in &mut blocks {
    compress(&mut state, block);
  }

  // Padding: a `0x80` byte, then zeros, then the bit length as a little-endian
  // u64 — one extra block, or two when the remainder leaves no room for the
  // length.
  let remainder = blocks.remainder();
  let mut tail = [0u8; 128];
  tail[..remainder.len()].copy_from_slice(remainder);
  tail[remainder.len()] = 0x80;
  let tail_len = if remainder.len() < 56 { 64 } else { 128 };
  let bit_len = (input.len() as u64).wrapping_mul(8);
  tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_le_bytes());
  for block in tail[..tail_len].chunks_exact(64) {
    compress(&mut state, block);
  }

  let mut out = [0u8; 16];
  for (word, chunk) in state.iter().zip(out.chunks_exact_mut(4)) {
    chunk.copy_from_slice(&word.to_le_bytes());
  }
  out
}

/// Mixes one 64-byte block into `state`.
fn compress(state: &mut [u32; 4], block: &[u8]) {
  debug_assert_eq!(block.len(), 64);

  let mut words = [0u32; 16];
  for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
    // The chunk is exactly 4 bytes, so the conversion cannot fail.
    *word = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
  }

  let [mut a, mut b, mut c, mut d] = *state;
  for round in 0..64 {
    let (mix, word) = match round / 16 {
      0 => ((b & c) | (!b & d), round),
      1 => ((d & b) | (!d & c), (5 * round + 1) % 16),
      2 => (b ^ c ^ d, (3 * round + 5) % 16),
      _ => (c ^ (b | !d), (7 * round) % 16),
    };
    let rotated = mix
      .wrapping_add(a)
      .wrapping_add(K[round])
      .wrapping_add(words[word])
      .rotate_left(SHIFTS[round]);
    a = d;
    d = c;
    c = b;
    b = b.wrapping_add(rotated);
  }

  state[0] = state[0].wrapping_add(a);
  state[1] = state[1].wrapping_add(b);
  state[2] = state[2].wrapping_add(c);
  state[3] = state[3].wrapping_add(d);
}

#[cfg(test)]
mod tests {
  use super::digest;

  fn hex(bytes: [u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
  }

  /// The test suite from RFC 1321, appendix A.5 — including the inputs that
  /// straddle the one-block and two-block padding cases.
  #[test]
  fn test_rfc1321_vectors() {
    for (input, expected) in [
      ("", "d41d8cd98f00b204e9800998ecf8427e"),
      ("a", "0cc175b9c0f1b6a831c399e269772661"),
      ("abc", "900150983cd24fb0d6963f7d28e17f72"),
      ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
      (
        "abcdefghijklmnopqrstuvwxyz",
        "c3fcd3d76192e4007dfb496cca67e13b",
      ),
      (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "d174ab98d277d9f5a5611c2c9f419d9f",
      ),
      (
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "57edf4a22be3c955ac49da2e2107b67a",
      ),
    ] {
      assert_eq!(hex(digest(input.as_bytes())), expected, "input: {input:?}");
    }
  }

  /// 55 bytes is the largest input that still pads into a single block, 56 the
  /// smallest that needs a second one — the boundary the padding code branches
  /// on.
  #[test]
  fn test_padding_block_boundary() {
    assert_eq!(hex(digest(&[b'x'; 55])), "04364420e25c512fd958a70738aa8f72");
    assert_eq!(hex(digest(&[b'x'; 56])), "668a72d5ba17f08e62dabcafad6db14b");
    assert_eq!(hex(digest(&[b'x'; 64])), "c1bb4f81d892b2d57947682aeb252456");
  }
}
