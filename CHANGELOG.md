# UNRELEASED

# 0.5.0

FEATURES

- Add `VolumeCapabilities`, exposing per-volume **case-sensitivity**, **case-preservation**, and **filesystem type** via `capabilities()` / `case_sensitive()` / `case_preserving()` / `fs_type()` accessors on `MountPoint` and `PathLocation`. Case-sensitivity is sourced per-OS — Apple `getattrlist` (`VOL_CAP_FMT_CASE_SENSITIVE` / `VOL_CAP_FMT_CASE_PRESERVING`), Windows `GetVolumeInformationW`, and a filesystem-type mapping elsewhere — and honors a `None`-means-unknown contract: it reports `Some(..)` only when the platform or filesystem type proves the answer.

# 0.1.2 (January 6th, 2022)

FEATURES


