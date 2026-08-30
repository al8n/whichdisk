use super::*;

fn root_path() -> &'static str {
  if cfg!(windows) { "C:\\" } else { "/" }
}

// ── accessor wiring ───────────────────────────────────────────────────

#[test]
fn test_volume_identity_accessor_matches_mount_info() {
  let info = resolve(root_path()).unwrap();
  assert_eq!(info.volume_identity(), info.mount_info().volume_identity());
}

#[test]
fn test_volume_identity_is_stable_across_calls() {
  // The value is read off the volume, not off the mount, so two independent
  // resolves of the same volume must agree.
  let first = resolve(root_path()).unwrap();
  let second = resolve(root_path()).unwrap();
  assert_eq!(first.volume_identity(), second.volume_identity());
}

#[test]
fn test_path_location_debug_contains_volume_identity() {
  let info = resolve(root_path()).unwrap();
  assert!(format!("{info:?}").contains("volume_identity"));
  assert!(format!("{:?}", info.mount_info()).contains("volume_identity"));
}

/// Apple platforms always answer for a real volume: every APFS and HFS+ volume
/// carries a UUID, and `getattrlist` reports it without privileges.
#[cfg(any(
  target_os = "macos",
  target_os = "ios",
  target_os = "watchos",
  target_os = "tvos",
  target_os = "visionos",
))]
#[test]
fn test_root_volume_reports_a_uuid() {
  let info = resolve(root_path()).unwrap();
  let reading = info.volume_identity().expect("Apple volumes carry a UUID");
  assert!(matches!(reading.identity(), VolumeIdentity::FsUuid(uuid) if uuid != [0u8; 16]));
  // `getattrlist` asked the volume the path is on, on this call.
  assert_eq!(reading.assurance(), IdentityAssurance::Vouched);
}

/// Windows answers with the volume serial it can read. A local volume always
/// has one, but a runner could conceivably resolve onto a share, so this
/// asserts the shape rather than the presence.
#[cfg(windows)]
#[test]
fn test_root_volume_identity_shape() {
  let info = resolve(root_path()).unwrap();
  let Some(reading) = info.volume_identity() else {
    return;
  };
  let identity = reading.identity();
  assert!(
    match identity {
      VolumeIdentity::FsUuid(uuid) => uuid != [0u8; 16],
      VolumeIdentity::Serial32(serial) => serial != 0,
      VolumeIdentity::Serial64(serial) => serial != 0,
    },
    "{identity:?}"
  );
  // The filesystem mounted at the volume's own GUID path answered for itself.
  assert_eq!(reading.assurance(), IdentityAssurance::Vouched);
  if info.capabilities().fs_type().eq_ignore_ascii_case("NTFS") {
    // The full 64-bit serial where the volume FSCTL answered, the documented
    // low half where it did not — an NTFS volume is never named by a UUID.
    assert!(
      matches!(
        identity,
        VolumeIdentity::Serial64(_) | VolumeIdentity::Serial32(_)
      ),
      "{identity:?}"
    );
  }
}

// ── VolumeIdentity value semantics ────────────────────────────────────

#[test]
fn test_identity_is_copy_and_comparable() {
  let uuid = VolumeIdentity::FsUuid([0x11; 16]);
  let copied = uuid;
  assert_eq!(uuid, copied);
  // Same numeric payload, different width: never equal.
  assert_ne!(VolumeIdentity::Serial32(1), VolumeIdentity::Serial64(1));
}

#[test]
fn test_identity_hashes_by_value() {
  use std::collections::HashSet;

  let mut set = HashSet::new();
  assert!(set.insert(VolumeIdentity::Serial32(0x1a2b_3c4d)));
  assert!(!set.insert(VolumeIdentity::Serial32(0x1a2b_3c4d)));
  assert!(set.insert(VolumeIdentity::Serial64(0x1a2b_3c4d)));
}

#[test]
fn test_identity_debug_renders_the_platform_spelling() {
  let uuid = VolumeIdentity::FsUuid([
    0x8f, 0x19, 0xa2, 0x53, 0xd4, 0x50, 0x30, 0x90, 0xab, 0xf6, 0xe6, 0x51, 0x94, 0x39, 0x98, 0xd1,
  ]);
  assert_eq!(
    format!("{uuid:?}"),
    "FsUuid(8f19a253-d450-3090-abf6-e651943998d1)"
  );
  assert_eq!(
    format!("{:?}", VolumeIdentity::Serial32(0x1a2b_3c4d)),
    "Serial32(1a2b3c4d)"
  );
  assert_eq!(
    format!("{:?}", VolumeIdentity::Serial64(0x1a2b_3c4d_5e6f_7788)),
    "Serial64(1a2b3c4d5e6f7788)"
  );
  // Leading zeros are kept: the width is part of what the value means.
  assert_eq!(
    format!("{:?}", VolumeIdentity::Serial32(0xd4d)),
    "Serial32(00000d4d)"
  );
}

// ── /dev/disk/by-uuid name classification ─────────────────────────────

#[test]
fn test_parse_by_uuid_name_uuid() {
  assert_eq!(
    parse_by_uuid_name(b"8f19a253-d450-3090-abf6-e651943998d1"),
    Some(VolumeIdentity::FsUuid([
      0x8f, 0x19, 0xa2, 0x53, 0xd4, 0x50, 0x30, 0x90, 0xab, 0xf6, 0xe6, 0x51, 0x94, 0x39, 0x98,
      0xd1,
    ]))
  );
}

#[test]
fn test_parse_by_uuid_name_uuid_is_case_insensitive() {
  assert_eq!(
    parse_by_uuid_name(b"8F19A253-D450-3090-ABF6-E651943998D1"),
    parse_by_uuid_name(b"8f19a253-d450-3090-abf6-e651943998d1")
  );
}

#[test]
fn test_parse_by_uuid_name_uuid_round_trips_through_debug() {
  let name = "550e8400-e29b-41d4-a716-446655440000";
  let identity = parse_by_uuid_name(name.as_bytes()).unwrap();
  assert_eq!(format!("{identity:?}"), format!("FsUuid({name})"));
}

#[test]
fn test_parse_by_uuid_name_fat_serial() {
  // udev prints the FAT/exFAT serial as two 16-bit halves; the value is the
  // whole 32-bit number, in that printed order.
  assert_eq!(
    parse_by_uuid_name(b"1A2B-3C4D"),
    Some(VolumeIdentity::Serial32(0x1a2b_3c4d))
  );
}

#[test]
fn test_parse_by_uuid_name_wide_serial() {
  // NTFS and HFS+ get 16 bare hex digits.
  assert_eq!(
    parse_by_uuid_name(b"1A2B3C4D5E6F7788"),
    Some(VolumeIdentity::Serial64(0x1a2b_3c4d_5e6f_7788))
  );
  assert_eq!(
    parse_by_uuid_name(b"ffffffffffffffff"),
    Some(VolumeIdentity::Serial64(u64::MAX))
  );
}

#[test]
fn test_parse_by_uuid_name_rejects_non_identities() {
  // An ISO9660 volume is named by its creation timestamp — right length class,
  // not an identity.
  assert_eq!(parse_by_uuid_name(b"2019-05-01-12-00-00-00"), None);
  // Non-hex where hex is required.
  assert_eq!(parse_by_uuid_name(b"zzzz-3c4d"), None);
  assert_eq!(parse_by_uuid_name(b"1a2b3c4d5e6f77gg"), None);
  assert_eq!(
    parse_by_uuid_name(b"8f19a253-d450-3090-abf6-e65194399zzz"),
    None
  );
  // Right length, misplaced separators.
  assert_eq!(
    parse_by_uuid_name(b"8f19a2-53d450-3090-abf6-e651943998d1"),
    None
  );
  assert_eq!(parse_by_uuid_name(b"1a2b3-c4d"), None);
  // Lengths that name nothing we know.
  assert_eq!(parse_by_uuid_name(b""), None);
  assert_eq!(parse_by_uuid_name(b"1a2b3c4d"), None);
  assert_eq!(parse_by_uuid_name(b"MY-USB-STICK"), None);
}

// ── the canonical form, across the per-OS classifiers ─────────────────
//
// Each platform reads different values off the same volume. These fixtures feed
// one synthetic volume to each platform's classifier and require the answers to
// be the same variant carrying the same value — the property the platforms are
// supposed to share, checked on whichever host happens to run the tests.
//
// It is the *value* that has to agree. The assurance is a fact about the road
// the value came by, and the roads differ per platform by construction — which
// is why it is not part of the identity and cannot make two readings of one
// volume compare unequal.

/// The identity a platform classifier named, with the assurance set aside.
fn value(reading: Option<IdentityReading>) -> Option<VolumeIdentity> {
  reading.map(|r| r.identity())
}

/// The UUID macOS reports for an exFAT volume whose serial is `6A93-F27D`,
/// read off a real volume rather than assumed.
const EXFAT_UUID_6A93F27D: [u8; 16] = [
  0x99, 0x79, 0x55, 0x71, 0x0a, 0x3e, 0x3f, 0x40, 0xb4, 0x2b, 0xe2, 0x10, 0x71, 0x86, 0xf0, 0x5d,
];

/// The same, for a second volume — `6A93-F2DF`, on a disk of a different size,
/// which is how we know the size is not part of the exFAT derivation.
const EXFAT_UUID_6A93F2DF: [u8; 16] = [
  0x99, 0x62, 0x16, 0xfc, 0xcd, 0xd1, 0x36, 0x32, 0xa0, 0xfd, 0xd3, 0xc9, 0xdf, 0x08, 0xcd, 0xa0,
];

#[test]
fn test_ntfs_is_one_serial64_on_every_platform() {
  // One NTFS volume. Linux reads all 64 bits out of the by-uuid name; Windows
  // reads the low 32 from `GetVolumeInformationW` and the full width from the
  // volume FSCTL.
  let canonical = Some(VolumeIdentity::Serial64(0x1a2b_3c4d_5e6f_7788));
  let from_linux = linux_identity(b"ntfs", parse_by_uuid_name(b"1A2B3C4D5E6F7788").unwrap());
  let from_windows = windows_identity(b"NTFS", 0x5e6f_7788, Some(0x1a2b_3c4d_5e6f_7788));
  assert_eq!(value(from_linux), canonical);
  assert_eq!(value(from_windows), canonical);
  // Same volume, same key, and each platform says how it read it.
  assert_eq!(
    from_linux.map(|r| r.assurance()),
    Some(IdentityAssurance::Published)
  );
  assert_eq!(
    from_windows.map(|r| r.assurance()),
    Some(IdentityAssurance::Vouched)
  );
}

#[test]
fn test_ntfs_without_the_volume_fsctl_narrows_to_the_low_half() {
  // The documented narrowing: the same bits, fewer of them. It does not compare
  // equal to the full width, which is exactly why it is documented rather than
  // quietly returned as if it did.
  let narrow = windows_identity(b"NTFS", 0x5e6f_7788, None);
  assert_eq!(value(narrow), Some(VolumeIdentity::Serial32(0x5e6f_7788)));
  assert_ne!(
    value(narrow),
    Some(VolumeIdentity::Serial64(0x1a2b_3c4d_5e6f_7788))
  );
  // Narrower, and still the volume's own number read from the volume: the
  // narrowing is about width, not about freshness.
  assert!(narrow.unwrap().is_vouched());
}

#[test]
fn test_exfat_is_one_uuid_on_every_platform() {
  for (name, windows_fs, serial, uuid) in [
    (
      &b"6A93-F27D"[..],
      "exFAT",
      0x6a93_f27du32,
      EXFAT_UUID_6A93F27D,
    ),
    (&b"6A93-F2DF"[..], "exFAT", 0x6a93_f2df, EXFAT_UUID_6A93F2DF),
  ] {
    // What an Apple platform hands back from the kernel, unchanged.
    let canonical = fs_uuid(uuid);
    assert!(canonical.is_some());
    // Linux has only the serial udev published, Windows only the serial
    // `GetVolumeInformationW` reports — both derive the same UUID from it.
    assert_eq!(
      value(linux_identity(b"exfat", parse_by_uuid_name(name).unwrap())),
      canonical,
      "{name:?}"
    );
    assert_eq!(
      value(windows_identity(windows_fs.as_bytes(), serial, None)),
      canonical,
      "{name:?}"
    );
  }
}

#[test]
fn test_fat32_keeps_its_serial_off_apple() {
  // FAT32's derivation also takes the BPB sector count, which nothing
  // unprivileged reports off Apple, so both platforms that can only read the
  // serial report the serial — the same way, as the documented narrower form.
  let narrow = Some(VolumeIdentity::Serial32(0xbf7a_1cef));
  assert_eq!(
    value(linux_identity(
      b"vfat",
      parse_by_uuid_name(b"BF7A-1CEF").unwrap()
    )),
    narrow
  );
  assert_eq!(
    value(linux_identity(
      b"msdos",
      VolumeIdentity::Serial32(0xbf7a_1cef)
    )),
    narrow
  );
  assert_eq!(value(windows_identity(b"FAT32", 0xbf7a_1cef, None)), narrow);
  assert_eq!(value(windows_identity(b"FAT", 0xbf7a_1cef, None)), narrow);
}

#[test]
fn test_apple_derivation_matches_a_real_volume() {
  // Pins the derivation this crate documents against values read off real
  // volumes on macOS. exFAT hashes the serial alone; FAT32 appends the BPB
  // total-sector count, here 131 070 sectors for a 64 MiB volume reporting
  // `BF7A-1CEF`, whose UUID macOS gives as 60300193-cb2f-39aa-a94c-fcd108a53057.
  assert_eq!(
    apple_derived_uuid(&0x6a93_f27du32.to_le_bytes()),
    EXFAT_UUID_6A93F27D
  );

  let mut fat32_seed = [0u8; 8];
  fat32_seed[..4].copy_from_slice(&0xbf7a_1cefu32.to_le_bytes());
  fat32_seed[4..].copy_from_slice(&131_070u32.to_le_bytes());
  assert_eq!(
    apple_derived_uuid(&fat32_seed),
    [
      0x60, 0x30, 0x01, 0x93, 0xcb, 0x2f, 0x39, 0xaa, 0xa9, 0x4c, 0xfc, 0xd1, 0x08, 0xa5, 0x30,
      0x57,
    ]
  );
}

#[test]
fn test_derived_uuids_are_stamped_version_3() {
  // The version and variant nibbles are part of the value, not decoration: get
  // them wrong and the UUID no longer matches what the platform reports.
  for seed in [&[0u8; 4][..], &[0xff; 4], &0x1a2b_3c4du32.to_le_bytes()] {
    let uuid = apple_derived_uuid(seed);
    assert_eq!(uuid[6] & 0xf0, 0x30, "{uuid:02x?}");
    assert_eq!(uuid[8] & 0xc0, 0x80, "{uuid:02x?}");
  }
}

#[test]
fn test_zero_is_never_an_identity() {
  // The same rule on every platform: these record the absence of a serial or a
  // UUID, and every volume that was never given one carries them.
  assert_eq!(parse_by_uuid_name(b"0000-0000"), None);
  assert_eq!(parse_by_uuid_name(b"0000000000000000"), None);
  assert_eq!(
    parse_by_uuid_name(b"00000000-0000-0000-0000-000000000000"),
    None
  );
  assert_eq!(fs_uuid([0u8; 16]), None);
  assert_eq!(identity_from_serial32(b"exfat", 0), None);
  assert_eq!(identity_from_serial32(b"vfat", 0), None);
  assert_eq!(windows_identity(b"NTFS", 0, Some(0)), None);
  assert_eq!(windows_identity(b"exFAT", 0, None), None);
  assert_eq!(windows_identity(b"FAT32", 0, None), None);
}

#[test]
fn test_unknown_filesystem_keeps_the_serial_it_was_given() {
  // Only a proven exFAT volume is named by a derived UUID. A type this crate
  // does not know keeps the serial rather than guessing.
  assert_eq!(
    identity_from_serial32(b"", 0x1a2b_3c4d),
    Some(VolumeIdentity::Serial32(0x1a2b_3c4d))
  );
  assert_eq!(
    identity_from_serial32(b"ext4", 0x1a2b_3c4d),
    Some(VolumeIdentity::Serial32(0x1a2b_3c4d))
  );
}

#[test]
fn test_exfat_through_fuse_agrees_where_the_subtype_names_it() {
  // One disk, two ways to mount it on Linux. The in-kernel driver and a FUSE
  // mount that publishes its subtype both prove the format, so both reduce to
  // the identity the volume carries.
  let canonical = fs_uuid(EXFAT_UUID_6A93F27D);
  for fs_type in [
    &b"exfat"[..],
    b"fuse.exfat",
    b"fuse.exfat-fuse",
    b"exfat-fuse",
  ] {
    assert_eq!(
      identity_from_serial32(fs_type, 0x6a93_f27d),
      canonical,
      "{}",
      String::from_utf8_lossy(fs_type)
    );
  }
  assert!(is_exfat(b"exFAT"), "Windows spells it with capitals");
}

#[test]
fn test_btrfs_is_named_by_its_kernel_driver_and_nothing_else() {
  // The one multi-device filesystem here, and the only mount type that takes
  // the `/sys/fs/btrfs` road. There is no FUSE spelling to admit, and no name
  // that merely might be btrfs: a wrong answer here would send some other
  // filesystem's device number looking for an FSID.
  assert!(is_btrfs(b"btrfs"));
  assert!(is_btrfs(b"BTRFS"), "matched as every other fs name is");
  for other in [&b"btrfs2"[..], b"fuseblk", b"fuse.btrfs", b"ext4", b""] {
    assert!(!is_btrfs(other), "{}", String::from_utf8_lossy(other));
  }
}

#[test]
fn test_bare_fuseblk_proves_nothing_and_keeps_its_serial() {
  // `fuseblk` names the transport, not the format: ntfs-3g, exfat-fuse and
  // every other block-backed FUSE helper share it. Deriving the exFAT UUID
  // from a serial that might belong to something else would invent an identity
  // no platform reports, so the serial is reported in its narrower form — the
  // documented divergence from the same disk mounted on the kernel driver.
  assert!(!is_exfat(b"fuseblk"));
  assert_eq!(
    identity_from_serial32(b"fuseblk", 0x6a93_f27d),
    Some(VolumeIdentity::Serial32(0x6a93_f27d))
  );
  // NTFS is untouched by the same gap: its identity is the serial itself, so
  // ntfs-3g under `fuseblk` reports what the kernel driver reports.
  assert_eq!(
    value(linux_identity(
      b"fuseblk",
      parse_by_uuid_name(b"1A2B3C4D5E6F7788").unwrap()
    )),
    Some(VolumeIdentity::Serial64(0x1a2b_3c4d_5e6f_7788))
  );
}

#[test]
fn test_exfat_with_a_native_volume_guid_diverges_off_apple() {
  // A real 48 MiB exFAT volume, stamped with `exfat.util -s` and read back
  // through this crate on macOS. Its root directory carries a Volume GUID
  // entry, so `ATTR_VOL_UUID` reports that GUID; its boot-sector serial is
  // 6A94-0381, which is all Linux and Windows can see.
  const STAMPED_SERIAL: u32 = 0x6a94_0381;
  const APPLE_REPORTED_GUID: [u8; 16] = [
    0xdc, 0x23, 0xf5, 0xd3, 0x44, 0x4a, 0x44, 0x56, 0x94, 0x27, 0x31, 0xc3, 0x09, 0xdc, 0xfb, 0xf3,
  ];
  // What `exfat.util -k` reported for the very same volume *before* it was
  // stamped, and what the derivation off Apple still produces for it.
  const DERIVED_FROM_SERIAL: [u8; 16] = [
    0x24, 0x29, 0x7b, 0xde, 0x9e, 0xc0, 0x31, 0x35, 0x9a, 0x5b, 0x50, 0x79, 0xa4, 0x1e, 0x74, 0x15,
  ];

  assert_eq!(
    identity_from_serial32(b"exfat", STAMPED_SERIAL),
    fs_uuid(DERIVED_FROM_SERIAL),
    "off Apple the serial is all there is, so the derivation is what it yields"
  );
  assert_ne!(
    DERIVED_FROM_SERIAL, APPLE_REPORTED_GUID,
    "and it is not the identity the volume carries — the documented narrowing"
  );
  // A missed match, never a false one: the derived value is a hash of the
  // serial and cannot be mistaken for the GUID of any other volume.
  assert_eq!(
    apple_derived_uuid(&STAMPED_SERIAL.to_le_bytes()),
    DERIVED_FROM_SERIAL
  );

  // The control, minted and read the same way: a volume with no Volume GUID
  // entry, whose serial is 6A94-06D9. Here macOS reports the derived value
  // itself, which is what makes the derivation canonical for such volumes and
  // a narrowing only for the stamped ones.
  const PLAIN_SERIAL: u32 = 0x6a94_06d9;
  const APPLE_REPORTED_DERIVED: [u8; 16] = [
    0x06, 0x64, 0x74, 0x09, 0x79, 0x6c, 0x3a, 0x3a, 0xb7, 0x84, 0x5f, 0x98, 0x04, 0xfe, 0xb9, 0x02,
  ];
  assert_eq!(
    identity_from_serial32(b"exfat", PLAIN_SERIAL),
    fs_uuid(APPLE_REPORTED_DERIVED)
  );
}

// ── what a mount cache may serve ──────────────────────────────────────

#[test]
fn test_a_witness_vouches_only_when_both_sides_exist_and_agree() {
  assert_eq!(Witness::of(Some(7), Some(7)), Witness::Agrees);
  assert_eq!(Witness::of(Some(7), Some(8)), Witness::Disagrees);
  // A platform with no witness to give vouches for nothing — in particular it
  // does not vouch that the mount is unchanged.
  assert_eq!(Witness::of(None, Some(7)), Witness::Unavailable);
  assert_eq!(Witness::of(Some(7), None), Witness::Unavailable);
  assert_eq!(Witness::of(None, None), Witness::Unavailable);

  // Only agreement opens an entry. Both other answers close it completely: one
  // says the mount is gone and the other says nothing at all, and neither is a
  // licence to reuse a single field of what is stored under it.
  assert!(Witness::Agrees.holds());
  assert!(!Witness::Disagrees.holds());
  assert!(!Witness::Unavailable.holds());
}

// ── the Linux by-uuid reverse lookup ──────────────────────────────────

#[test]
fn test_the_published_name_is_matched_against_the_mount_source() {
  let ours = Path::new("/dev/sdb1");
  let other = Path::new("/dev/sda1");
  let mine = VolumeIdentity::Serial32(0x1a2b_3c4d);
  let theirs = VolumeIdentity::Serial32(0x5566_7788);

  assert_eq!(
    value(linux_identity_for_device(
      [(other, theirs), (ours, mine)].into_iter(),
      ours,
      b"vfat"
    )),
    Some(mine)
  );
  // A device the directory says nothing about has no identity — never whatever
  // the directory did have.
  assert_eq!(
    linux_identity_for_device([(other, theirs)].into_iter(), ours, b"vfat"),
    None
  );
}

/// The one window the Linux backend leaves open, and what it is honest to claim
/// inside it. udev re-points `/dev/disk/by-uuid` from a uevent, so a read can
/// land while the departed volume's name still resolves to the node.
///
/// Two things follow, and the test asserts both. The answer is **published**,
/// never vouched — the level is what tells a caller that this reading might
/// have lagged its volume, and it is the level, not the value, that a caller
/// with something irreversible to do should look at. And nothing remembers the
/// answer, so the next read reports what the directory says then: the window
/// closes itself, which is a fact about *later* calls and not a promise about
/// this one.
#[test]
fn test_a_published_name_says_so_and_is_corrected_by_the_next_read() {
  let node = Path::new("/dev/sdb1");
  let departed = VolumeIdentity::Serial32(0xdead_beef);
  let arrived = VolumeIdentity::Serial32(0x1a2b_3c4d);

  // The instant before udev catches up.
  let stale = linux_identity_for_device([(node, departed)].into_iter(), node, b"vfat");
  assert_eq!(value(stale), Some(departed));
  assert_eq!(
    stale.map(|r| r.assurance()),
    Some(IdentityAssurance::Published),
    "the window is why this level exists; a reading taken inside it must not \
     claim to have been read from the volume"
  );
  assert!(!stale.unwrap().is_vouched());

  // And the instant after: no cache stands between the two reads.
  let fresh = linux_identity_for_device([(node, arrived)].into_iter(), node, b"vfat");
  assert_eq!(value(fresh), Some(arrived));
  // Correct now, and still published: nothing about being right this time makes
  // the road a different road, and nothing here ever promotes one to the other.
  assert_eq!(
    fresh.map(|r| r.assurance()),
    Some(IdentityAssurance::Published)
  );
}

/// Republishing can leave the departed volume's name and the arriving one's
/// both resolving to the same node. Whichever the directory yields first is a
/// coin toss, so neither is reported as the volume's identity.
#[test]
fn test_two_names_for_one_node_name_no_volume() {
  let node = Path::new("/dev/sdb1");
  let departed = VolumeIdentity::Serial32(0xdead_beef);
  let arrived = VolumeIdentity::Serial32(0x1a2b_3c4d);

  assert_eq!(
    linux_identity_for_device(
      [(node, departed), (node, arrived)].into_iter(),
      node,
      b"vfat"
    ),
    None
  );
  // Two spellings of one identity are not a disagreement: `1a2b-3c4d` and
  // `1A2B-3C4D` parse to the same value and name the same volume.
  assert_eq!(
    value(linux_identity_for_device(
      [(node, arrived), (node, arrived)].into_iter(),
      node,
      b"vfat"
    )),
    Some(arrived)
  );
}

#[test]
fn test_a_width_the_filesystem_cannot_carry_is_not_its_identity() {
  // The other half of the same window: a name udev has not re-pointed can be of
  // a width the mount's own format has no room for, and that is provable
  // without reading anything off the volume.
  let uuid = parse_by_uuid_name(b"8f19a253-d450-3090-abf6-e651943998d1").unwrap();
  let wide = parse_by_uuid_name(b"1a2b3c4d5e6f7788").unwrap();
  let serial = parse_by_uuid_name(b"1a2b-3c4d").unwrap();

  for fs_type in [&b"vfat"[..], b"msdos", b"exfat", b"fuse.exfat"] {
    let named = String::from_utf8_lossy(fs_type).into_owned();
    assert_eq!(linux_identity(fs_type, uuid), None, "{named}");
    assert_eq!(linux_identity(fs_type, wide), None, "{named}");
    assert!(
      linux_identity(fs_type, serial).is_some(),
      "{named} carries exactly this width"
    );
  }
  for fs_type in [&b"ntfs"[..], b"ntfs3", b"fuse.ntfs-3g"] {
    let named = String::from_utf8_lossy(fs_type).into_owned();
    assert_eq!(linux_identity(fs_type, uuid), None, "{named}");
    assert_eq!(linux_identity(fs_type, serial), None, "{named}");
    assert_eq!(
      value(linux_identity(fs_type, wide)),
      Some(VolumeIdentity::Serial64(0x1a2b_3c4d_5e6f_7788)),
      "{named} carries exactly this width"
    );
  }
  // Nothing is claimed about a type whose format this crate cannot pin, or one
  // whose width could only be asserted from a roster of every UUID-carrying
  // filesystem — the first one left out of such a roster would be a missed
  // identity, which is a worse answer than an unchecked one.
  for fs_type in [&b"fuseblk"[..], b"ext4", b""] {
    let named = String::from_utf8_lossy(fs_type).into_owned();
    assert!(linux_identity(fs_type, uuid).is_some(), "{named}");
    assert!(linux_identity(fs_type, wide).is_some(), "{named}");
    assert!(linux_identity(fs_type, serial).is_some(), "{named}");
  }
}

// ── the assurance a reading carries ───────────────────────────────────

#[test]
fn test_a_reading_carries_both_the_identity_and_how_it_was_read() {
  let identity = VolumeIdentity::Serial32(0x1a2b_3c4d);

  let vouched = IdentityReading::vouched(identity);
  assert_eq!(vouched.identity(), identity);
  assert_eq!(vouched.assurance(), IdentityAssurance::Vouched);
  assert!(vouched.is_vouched());

  let published = IdentityReading::published(identity);
  assert_eq!(published.identity(), identity);
  assert_eq!(published.assurance(), IdentityAssurance::Published);
  assert!(!published.is_vouched());
}

/// The identity is the key; the assurance is a fact about the read that
/// produced it. One volume carried between platforms is read two ways and must
/// still be one key — so the levels differ while the values do not, and a
/// consumer keys on [`IdentityReading::identity`] rather than on the reading.
#[test]
fn test_the_assurance_is_not_part_of_the_identity() {
  let identity = VolumeIdentity::FsUuid([0x11; 16]);
  let apple = IdentityReading::vouched(identity);
  let linux = IdentityReading::published(identity);

  assert_eq!(apple.identity(), linux.identity());
  assert_ne!(
    apple, linux,
    "two readings that were taken differently are different readings"
  );

  use std::collections::HashSet;
  let mut keys = HashSet::new();
  assert!(keys.insert(apple.identity()));
  assert!(
    !keys.insert(linux.identity()),
    "the same volume must not occupy two registry keys because it was read \
     on a platform that reads it differently"
  );
}

/// The one thing the level must never do is improve on its own. A published
/// name cannot be checked for freshness without reading the volume, so there is
/// no road from `Published` to `Vouched` here — only the platform's own way of
/// reading decides, and each platform has exactly one.
#[test]
fn test_a_published_reading_is_never_promoted() {
  let published = linux_identity(b"ext4", VolumeIdentity::FsUuid([0x22; 16])).unwrap();
  assert_eq!(published.assurance(), IdentityAssurance::Published);

  // Reducing, re-classifying and re-reading a published name all keep the
  // level: they are operations on the name, not reads of the volume.
  let reduced = linux_identity(b"exfat", VolumeIdentity::Serial32(0x6a93_f27d)).unwrap();
  assert!(matches!(reduced.identity(), VolumeIdentity::FsUuid(_)));
  assert_eq!(reduced.assurance(), IdentityAssurance::Published);
}
