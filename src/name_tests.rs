use super::*;

fn root_path() -> &'static str {
  if cfg!(windows) { "C:\\" } else { "/" }
}

// ── accessor wiring ───────────────────────────────────────────────────

#[test]
fn test_volume_name_accessor_matches_mount_info() {
  let info = resolve(root_path()).unwrap();
  assert_eq!(info.volume_name(), info.mount_info().volume_name());
}

#[test]
fn test_debug_contains_volume_name() {
  let info = resolve(root_path()).unwrap();
  assert!(format!("{:?}", info.mount_info()).contains("volume_name"));
}

// ── a name is not an identity ─────────────────────────────────────────

/// The label is what a person wrote on the volume, and a person may rewrite it
/// without the volume becoming another volume. So a renamed mount point is
/// still the same mount point, and the identity it is keyed by does not move
/// with the name.
#[test]
fn test_a_rename_leaves_the_mount_point_and_its_identity_alone() {
  let info = resolve(root_path()).unwrap();
  let before = info.mount_info().clone();

  let mut renamed = before.clone();
  renamed.volume_name = Some(NameReading {
    name: SmallBytes::from_bytes(b"a name nobody chose"),
    assurance: IdentityAssurance::Vouched,
  });

  assert_eq!(renamed, before, "a rename is not a different mount point");
  assert_eq!(renamed.volume_identity(), before.volume_identity());
  assert_ne!(renamed.volume_name(), before.volume_name());
}

// ── the documented fallback ───────────────────────────────────────────

#[test]
fn test_the_fallback_is_the_mount_points_last_component() {
  assert_eq!(name_from_mount_point(b"/media/alice/usb"), Some("usb"));
  assert_eq!(name_from_mount_point(b"/home"), Some("home"));
}

#[test]
fn test_the_fallback_ignores_trailing_separators() {
  assert_eq!(name_from_mount_point(b"/media/alice/usb/"), Some("usb"));
  assert_eq!(name_from_mount_point(b"/media/alice/usb///"), Some("usb"));
}

/// A filesystem root has no last component, so it stands for itself rather than
/// falling through to an empty name.
#[test]
fn test_a_root_names_itself() {
  assert_eq!(name_from_mount_point(b"/"), Some("/"));
  // A run of separators has no last component either, and so also stands for
  // itself rather than being given a name it does not have. No platform reports
  // such a mount point; nothing here invents an answer for one.
  assert_eq!(name_from_mount_point(b"///"), Some("///"));
}

#[cfg(windows)]
#[test]
fn test_a_windows_mount_point_splits_on_its_own_separator() {
  assert_eq!(name_from_mount_point(b"C:\\"), Some("C:"));
  assert_eq!(name_from_mount_point(b"C:\\mnt\\data"), Some("data"));
  assert_eq!(name_from_mount_point(b"C:\\mnt\\data\\"), Some("data"));
}

/// The one thing neither road can spell: bytes a `&str` cannot carry. The path
/// itself is still whole in `mount_point()`.
#[cfg(unix)]
#[test]
fn test_a_name_that_is_not_utf8_is_no_name() {
  assert_eq!(name_from_mount_point(b"/media/\xff\xfe"), None);
  assert_eq!(name_from_mount_point(b""), None);
}

// ── the cross-platform law ────────────────────────────────────────────

/// Every platform answers for the volume the system booted from: with the label
/// it published, or with the fallback. Never with nothing, and never with an
/// empty string.
#[test]
fn test_the_root_volume_has_a_name() {
  let info = root().unwrap();
  let name = info.volume_name().expect("the root volume has a name");
  assert!(!name.is_empty(), "{info:?}");
}

/// The same law across an enumeration: a listed volume whose mount point a
/// `&str` can carry has a name, and no volume has an empty one.
#[cfg(feature = "list")]
#[test]
fn test_every_listed_volume_has_a_name() {
  for mount in list().unwrap() {
    assert_ne!(mount.volume_name(), Some(""), "{mount:?}");
    if mount.mount_point().to_str().is_some() {
      assert!(mount.volume_name().is_some(), "{mount:?}");
    }
  }
}

// ── per-platform roads ────────────────────────────────────────────────

/// Apple platforms publish a name for every volume, and `diskutil` prints the
/// same one this reads: the two go to `NSURLVolumeNameKey` and to the volume's
/// own attributes for one value. Where `diskutil` is not there to ask, or names
/// no volume for `/`, the law above still holds and this one has nothing to
/// compare against.
#[cfg(target_os = "macos")]
#[test]
fn test_the_root_name_is_what_diskutil_prints() {
  let Ok(output) = std::process::Command::new("diskutil")
    .args(["info", "/"])
    .output()
  else {
    return;
  };
  if !output.status.success() {
    return;
  }
  let printed = String::from_utf8_lossy(&output.stdout);
  let Some(oracle) = printed.lines().find_map(|line| {
    line
      .trim()
      .strip_prefix("Volume Name:")
      .map(str::trim)
      .filter(|name| !name.is_empty())
  }) else {
    return;
  };

  let info = root().unwrap();
  assert_eq!(info.volume_name(), Some(oracle));
}

/// Linux reads the label out of `/dev/disk/by-label`, so where udev published
/// one for the root device that is the name; where it published none, the
/// fallback answers with the mount point. Labels carrying udev's `\x20`-style
/// escapes are left to the decoder's own test rather than re-decoded here.
#[cfg(target_os = "linux")]
#[test]
fn test_the_root_name_follows_udevs_label() {
  let info = root().unwrap();
  let Ok(device) = std::path::Path::new(info.device()).canonicalize() else {
    return;
  };

  let mut labels: Vec<String> = Vec::new();
  if let Ok(entries) = std::fs::read_dir("/dev/disk/by-label") {
    for entry in entries.flatten() {
      if entry.path().canonicalize().ok().as_deref() == Some(device.as_path()) {
        labels.push(entry.file_name().to_string_lossy().into_owned());
      }
    }
  }
  labels.sort();
  labels.dedup();

  match labels.as_slice() {
    // udev published exactly one name for this node, and it is the name.
    [label] if !label.contains('\\') => assert_eq!(info.volume_name(), Some(label.as_str())),
    // Nothing published under `/dev/disk/by-label` for this node. The name is
    // then either one udev recorded per device in its runtime database — which
    // the by-label directory cannot hold twice, and which is reported at
    // `Declared` — or the mount point, where that database says nothing
    // either. Both are names; which one it is, the assurance says.
    [] => match info.mount_info().volume_name_assurance() {
      Some(assurance) => assert_eq!(
        assurance,
        IdentityAssurance::Declared,
        "a label no authenticated road published is a claim, never more"
      ),
      None => assert_eq!(info.volume_name(), Some("/")),
    },
    // Two names for one node name no volume, and an escaped one is the
    // decoder's business; either way the law above still holds.
    _ => assert!(info.volume_name().is_some_and(|name| !name.is_empty())),
  }
}

/// These platforms publish no label at all, so the fallback is the whole road,
/// and for the root mount point it is the mount point itself.
#[cfg(any(
  target_os = "freebsd",
  target_os = "openbsd",
  target_os = "dragonfly",
  target_os = "netbsd",
))]
#[test]
fn test_a_platform_without_labels_falls_back_to_the_mount_point() {
  let info = root().unwrap();
  assert_eq!(info.volume_name(), Some("/"));
  assert!(info.mount_info().volume_name.is_none());
}

/// Windows answers with `GetVolumeInformationW`'s label where the volume has
/// one, and an unlabeled volume falls back to its drive root (`C:`).
#[cfg(windows)]
#[test]
fn test_the_root_name_is_the_label_or_the_drive() {
  let info = root().unwrap();
  let name = info.volume_name().expect("the root volume has a name");
  assert!(!name.is_empty());
  match info.mount_info().volume_name.as_ref() {
    Some(reading) => assert_eq!(name.as_bytes(), reading.name.as_bytes()),
    None => {
      let mount = info
        .mount_point()
        .to_str()
        .expect("Windows mount points are valid UTF-8");
      assert_eq!(Some(name), name_from_mount_point(mount.as_bytes()));
    }
  }
}

// ── the identity's text form, which the CLI prints ────────────────────

#[test]
fn test_a_uuid_prints_in_its_canonical_form() {
  let uuid = VolumeIdentity::FsUuid([
    0x8f, 0x19, 0xa2, 0x53, 0xd4, 0x50, 0x30, 0x90, 0xab, 0xf6, 0xe6, 0x51, 0x94, 0x39, 0x98, 0xd1,
  ]);
  assert_eq!(uuid.to_string(), "8f19a253-d450-3090-abf6-e651943998d1");
}

#[test]
fn test_a_fat_serial_prints_in_its_two_halves() {
  assert_eq!(
    VolumeIdentity::Serial32(0x1a2b_3c4d).to_string(),
    "1a2b-3c4d"
  );
  assert_eq!(
    VolumeIdentity::Serial32(0x0000_00ff).to_string(),
    "0000-00ff"
  );
}

#[test]
fn test_a_wide_serial_prints_its_sixteen_digits() {
  assert_eq!(
    VolumeIdentity::Serial64(0x1a2b_3c4d_5e6f_7a8b).to_string(),
    "1a2b3c4d5e6f7a8b"
  );
  assert_eq!(VolumeIdentity::Serial64(1).to_string(), "0000000000000001");
}
