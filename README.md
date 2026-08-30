<div align="center">
<h1>whichdisk</h1>
</div>
<div align="center">

Cross-platform disk/volume resolver — given a path, tells you which disk it's on, its mount point, relative path, disk usage, and per-volume capabilities (case-sensitivity, filesystem type)

[<img alt="github" src="https://img.shields.io/badge/github-al8n/whichdisk-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Fwhichdisk" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/whichdisk/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/whichdisk?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-whichdisk-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/whichdisk?style=for-the-badge&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDE5LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPg0KPHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCINCgkgdmlld0JveD0iMCAwIDUxMiA1MTIiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0yNTYsMEwzMS41MjgsMTEyLjIzNnYyODcuNTI4TDI1Niw1MTJsMjI0LjQ3Mi0xMTIuMjM2VjExMi4yMzZMMjU2LDB6IE0yMzQuMjc3LDQ1Mi41NjRMNzQuOTc0LDM3Mi45MTNWMTYwLjgxDQoJCQlsMTU5LjMwMyw3OS42NTFWNDUyLjU2NHogTTEwMS44MjYsMTI1LjY2MkwyNTYsNDguNTc2bDE1NC4xNzQsNzcuMDg3TDI1NiwyMDIuNzQ5TDEwMS44MjYsMTI1LjY2MnogTTQzNy4wMjYsMzcyLjkxMw0KCQkJbC0xNTkuMzAzLDc5LjY1MVYyNDAuNDYxbDE1OS4zMDMtNzkuNjUxVjM3Mi45MTN6IiBmaWxsPSIjRkZGIi8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+DQo=" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/whichdisk?color=critical&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/PjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+PHN2ZyB0PSIxNjQ1MTE3MzMyOTU5IiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjM0MjEiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkzIiB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj48ZGVmcz48c3R5bGUgdHlwZT0idGV4dC9jc3MiPjwvc3R5bGU+PC9kZWZzPjxwYXRoIGQ9Ik00NjkuMzEyIDU3MC4yNHYtMjU2aDg1LjM3NnYyNTZoMTI4TDUxMiA3NTYuMjg4IDM0MS4zMTIgNTcwLjI0aDEyOHpNMTAyNCA2NDAuMTI4QzEwMjQgNzgyLjkxMiA5MTkuODcyIDg5NiA3ODcuNjQ4IDg5NmgtNTEyQzEyMy45MDQgODk2IDAgNzYxLjYgMCA1OTcuNTA0IDAgNDUxLjk2OCA5NC42NTYgMzMxLjUyIDIyNi40MzIgMzAyLjk3NiAyODQuMTYgMTk1LjQ1NiAzOTEuODA4IDEyOCA1MTIgMTI4YzE1Mi4zMiAwIDI4Mi4xMTIgMTA4LjQxNiAzMjMuMzkyIDI2MS4xMkM5NDEuODg4IDQxMy40NCAxMDI0IDUxOS4wNCAxMDI0IDY0MC4xOTJ6IG0tMjU5LjItMjA1LjMxMmMtMjQuNDQ4LTEyOS4wMjQtMTI4Ljg5Ni0yMjIuNzItMjUyLjgtMjIyLjcyLTk3LjI4IDAtMTgzLjA0IDU3LjM0NC0yMjQuNjQgMTQ3LjQ1NmwtOS4yOCAyMC4yMjQtMjAuOTI4IDIuOTQ0Yy0xMDMuMzYgMTQuNC0xNzguMzY4IDEwNC4zMi0xNzguMzY4IDIxNC43MiAwIDExNy45NTIgODguODMyIDIxNC40IDE5Ni45MjggMjE0LjRoNTEyYzg4LjMyIDAgMTU3LjUwNC03NS4xMzYgMTU3LjUwNC0xNzEuNzEyIDAtODguMDY0LTY1LjkyLTE2NC45MjgtMTQ0Ljk2LTE3MS43NzZsLTI5LjUwNC0yLjU2LTUuODg4LTMwLjk3NnoiIGZpbGw9IiNmZmZmZmYiIHAtaWQ9IjM0MjIiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkwIiBjbGFzcz0iIj48L3BhdGg+PC9zdmc+&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076&logo=data:image/svg+xml;base64,PCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KDTwhLS0gVXBsb2FkZWQgdG86IFNWRyBSZXBvLCB3d3cuc3ZncmVwby5jb20sIFRyYW5zZm9ybWVkIGJ5OiBTVkcgUmVwbyBNaXhlciBUb29scyAtLT4KPHN2ZyBmaWxsPSIjZmZmZmZmIiBoZWlnaHQ9IjgwMHB4IiB3aWR0aD0iODAwcHgiIHZlcnNpb249IjEuMSIgaWQ9IkNhcGFfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgdmlld0JveD0iMCAwIDI3Ni43MTUgMjc2LjcxNSIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSIgc3Ryb2tlPSIjZmZmZmZmIj4KDTxnIGlkPSJTVkdSZXBvX2JnQ2FycmllciIgc3Ryb2tlLXdpZHRoPSIwIi8+Cg08ZyBpZD0iU1ZHUmVwb190cmFjZXJDYXJyaWVyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KDTxnIGlkPSJTVkdSZXBvX2ljb25DYXJyaWVyIj4gPGc+IDxwYXRoIGQ9Ik0xMzguMzU3LDBDNjIuMDY2LDAsMCw2Mi4wNjYsMCwxMzguMzU3czYyLjA2NiwxMzguMzU3LDEzOC4zNTcsMTM4LjM1N3MxMzguMzU3LTYyLjA2NiwxMzguMzU3LTEzOC4zNTcgUzIxNC42NDgsMCwxMzguMzU3LDB6IE0xMzguMzU3LDI1OC43MTVDNzEuOTkyLDI1OC43MTUsMTgsMjA0LjcyMywxOCwxMzguMzU3UzcxLjk5MiwxOCwxMzguMzU3LDE4IHMxMjAuMzU3LDUzLjk5MiwxMjAuMzU3LDEyMC4zNTdTMjA0LjcyMywyNTguNzE1LDEzOC4zNTcsMjU4LjcxNXoiLz4gPHBhdGggZD0iTTE5NC43OTgsMTYwLjkwM2MtNC4xODgtMi42NzctOS43NTMtMS40NTQtMTIuNDMyLDIuNzMyYy04LjY5NCwxMy41OTMtMjMuNTAzLDIxLjcwOC0zOS42MTQsMjEuNzA4IGMtMjUuOTA4LDAtNDYuOTg1LTIxLjA3OC00Ni45ODUtNDYuOTg2czIxLjA3Ny00Ni45ODYsNDYuOTg1LTQ2Ljk4NmMxNS42MzMsMCwzMC4yLDcuNzQ3LDM4Ljk2OCwyMC43MjMgYzIuNzgyLDQuMTE3LDguMzc1LDUuMjAxLDEyLjQ5NiwyLjQxOGM0LjExOC0yLjc4Miw1LjIwMS04LjM3NywyLjQxOC0xMi40OTZjLTEyLjExOC0xNy45MzctMzIuMjYyLTI4LjY0NS01My44ODItMjguNjQ1IGMtMzUuODMzLDAtNjQuOTg1LDI5LjE1Mi02NC45ODUsNjQuOTg2czI5LjE1Miw2NC45ODYsNjQuOTg1LDY0Ljk4NmMyMi4yODEsMCw0Mi43NTktMTEuMjE4LDU0Ljc3OC0zMC4wMDkgQzIwMC4yMDgsMTY5LjE0NywxOTguOTg1LDE2My41ODIsMTk0Ljc5OCwxNjAuOTAzeiIvPiA8L2c+IDwvZz4KDTwvc3ZnPg==" height="22">

[<img alt="Discord" src="https://img.shields.io/discord/835936528140206122?style=for-the-badge&logo=discord&logoColor=white&label=Discord&color=7289da" height="22">][discord]

</div>

## Installation

### As a library

```toml
[dependencies]
whichdisk = "0.5"
```

### As a CLI tool

```bash
cargo install whichdisk --features cli
```

## CLI Usage

### Resolve a path

```bash
# Resolve the current working directory
whichdisk

# Resolve a specific path
whichdisk -p /home/user/documents

# Output as JSON
whichdisk -o json

# Output as YAML
whichdisk -o yaml

# Combine options
whichdisk -p /tmp -o json
```

**Default output:**
```text
device="/dev/disk3s5"
mount_point="/System/Volumes/Data"
relative_path="Users/user/Develop/personal/whichdisk"
total=926.35 GiB
available=701.81 GiB
used=224.55 GiB
```

**JSON output** (`-o json`):
```json
{
  "device": "/dev/disk3s5",
  "mount_point": "/System/Volumes/Data",
  "relative_path": "Users/user/Develop/personal/whichdisk",
  "total_bytes": 994662584320,
  "available_bytes": 753886154752,
  "used_bytes": 240776429568
}
```

### List mounted volumes

```bash
# List all mounted volumes
whichdisk list

# Shorthand
whichdisk l

# Skip ejectable/removable volumes (show only internal disks)
whichdisk list --skip-ejectable

# Skip non-ejectable volumes (show only removable disks)
whichdisk list --skip-non-ejectable

# Output as JSON
whichdisk list -o json

# Output as YAML
whichdisk list -o yaml
```

**Default output:**
```text
mount_point="/" device="/dev/disk3s1s1" total=926.35 GiB available=701.81 GiB used=224.55 GiB
```

**JSON output** (`list -o json`):
```json
[
  {
    "device": "/dev/disk3s1s1",
    "mount_point": "/",
    "is_ejectable": false,
    "total_bytes": 994662584320,
    "available_bytes": 753886154752,
    "used_bytes": 240776429568
  }
]
```

## Library Usage

### Resolve a path to its disk

```rust,ignore
use whichdisk::resolve;

fn main() -> std::io::Result<()> {
    let info = resolve("/home/user/documents/report.pdf")?;

    println!("Mount point:    {}", info.mount_point().display());
    println!("Device:         {:?}", info.device());
    println!("Relative path:  {}", info.relative_path().display());
    println!("Ejectable:      {}", info.is_ejectable());
    println!("Total:          {} bytes", info.total_bytes());
    println!("Available:      {} bytes", info.available_bytes());
    println!("Used:           {} bytes", info.used_bytes());

    Ok(())
}
```

### Get the root filesystem

```rust,ignore
use whichdisk::root;

fn main() -> std::io::Result<()> {
    let info = root()?;
    println!("Root mount:  {}", info.mount_point().display());
    println!("Root device: {:?}", info.device());
    Ok(())
}
```

### List mounted volumes

```rust,ignore
use whichdisk::{list, list_with, list_ejectable, list_non_ejectable, ListOptions};

fn main() -> std::io::Result<()> {
    // List all real (non-virtual) volumes
    for m in list()? {
        println!("{:?} -> {:?} (ejectable: {})",
            m.device(), m.mount_point(), m.is_ejectable());
    }

    // List only ejectable/removable volumes
    for m in list_ejectable()? {
        println!("Removable: {:?}", m.mount_point());
    }

    // List only non-ejectable volumes
    for m in list_non_ejectable()? {
        println!("Internal: {:?}", m.mount_point());
    }

    // Using ListOptions
    let opts = ListOptions::all().set_ejectable_only(true);
    let removable = list_with(opts)?;

    Ok(())
}
```

### Volume capabilities

Every `MountPoint` / `PathLocation` also reports the volume's case-sensitivity, case-preservation, and filesystem type. Capability values are `Option<bool>` where `None` means "unknown on this platform/filesystem" — never conflated with `Some(false)`.

```rust,ignore
use whichdisk::resolve;

fn main() -> std::io::Result<()> {
    let info = resolve("/some/path")?;

    println!("Filesystem:      {}", info.fs_type());
    println!("Case-sensitive:  {:?}", info.case_sensitive());   // Option<bool>
    println!("Case-preserving: {:?}", info.case_preserving());  // Option<bool>

    Ok(())
}
```

### Volume identity

`volume_identity()` reports the identity the volume carries *on itself* — unlike the mount point and the device node, which are session-local, it survives unmounting, replugging into another port, and moving the disk to another machine. It exposes the raw fact rather than a composed string, so a consumer decides how to qualify it:

```rust,ignore
use whichdisk::{VolumeIdentity, resolve};

fn main() -> std::io::Result<()> {
    let info = resolve("/some/path")?;

    let key = match info.volume_identity().map(|reading| reading.identity()) {
        Some(VolumeIdentity::FsUuid(uuid)) => {
            let hex: String = uuid.iter().map(|b| format!("{b:02x}")).collect();
            format!("fsuuid:{hex}")
        }
        Some(VolumeIdentity::Serial64(serial)) => format!("serial64:{serial:016x}"),
        // 32 bits is weak — widen it with another invariant.
        Some(VolumeIdentity::Serial32(serial)) => {
            format!("fatserial:{serial:08x}+size:{}", info.total_bytes())
        }
        None => "unknown".to_string(),
    };
    println!("volume key: {key}");

    Ok(())
}
```

`None` means the platform or the filesystem genuinely reports no identity — a pseudo-filesystem, a network mount, or a platform with no durable-identity query — never a failure to look.

#### The reading says how it was read

The identity is durable on the volume, but not every platform lets an unprivileged caller read it *from* the volume. Apple and Windows ask the mounted filesystem itself; Linux has no such call and recovers the value from a name udev published about the mount's source device, which can lag the media now behind it. That difference is a fact about the answer, so it comes back with the answer: `volume_identity()` hands over an `IdentityReading`, which is the `VolumeIdentity` plus the `IdentityAssurance` it was read at.

- `Vouched` — read from the mounted filesystem on this call (Apple `getattrlist`, Windows `GetVolumeInformationW` / `FSCTL_GET_NTFS_VOLUME_DATA` against the volume's own GUID path). Media that replaced other media under the same mount point answers as itself.
- `Published` — read from a name the platform publishes about a device (Linux `/dev/disk/by-uuid`, and `/sys/fs/btrfs/<fsid>/devices/` for btrfs). Correct once udev has run, and possibly the departed volume's name for the instant before it does.

```rust,ignore
// A consumer with something irreversible to do can require the stronger level;
// `Published` is then "not now", not "no".
if let Some(reading) = info.volume_identity().filter(whichdisk::IdentityReading::is_vouched) {
    migrate_onto(reading.identity());
}
```

The identity itself is the key, and the assurance is not part of it: one disk read on macOS and on Linux gives one `VolumeIdentity` and two assurances, so it occupies one registry key either way. Nothing promotes a `Published` reading to a `Vouched` one — settling a published name means reading the volume's superblock, which needs elevation this crate never takes.

### Feature Flags

| Feature      | Default? | Description                                                       |
| ------------ | -------- | ----------------------------------------------------------------- |
| `disk-usage` | Yes      | Enables `total_bytes()`, `available_bytes()`, and `used_bytes()`  |
| `list`       | Yes      | Enables `list()`, `list_with()`, and `ListOptions`                |
| `cli`        | No       | Builds the `whichdisk` CLI binary                                 |

To use only the core `resolve()` API with minimal dependencies:

```toml
[dependencies]
whichdisk = { version = "0.5", default-features = false }
```

## Supported Platforms

| Platform | Resolve backend | List backend | Ejectable detection |
|---|---|---|---|
| macOS, iOS, watchOS, tvOS, visionOS | `statfs` via [`rustix`](https://crates.io/crates/rustix) | `NSFileManager` via [`objc2-foundation`](https://crates.io/crates/objc2-foundation) | `NSURLVolumeIsEjectableKey` / `NSURLVolumeIsRemovableKey` |
| FreeBSD, OpenBSD, DragonFlyBSD | `statfs` via [`rustix`](https://crates.io/crates/rustix) | `getmntinfo` via [`libc`](https://crates.io/crates/libc) | `/dev/da*` or `/dev/cd*` device prefix |
| NetBSD | `statvfs` via [`libc`](https://crates.io/crates/libc) | `getmntinfo` via [`libc`](https://crates.io/crates/libc) | `/dev/sd*` or `/dev/cd*` device prefix |
| Linux | `/proc/self/mountinfo` parsing | `/proc/self/mountinfo` parsing | `/dev/disk/by-id/usb-*` |
| Windows | `GetVolumePathNameW` via [`windows-sys`](https://crates.io/crates/windows-sys) | `FindFirstVolumeW` / `FindNextVolumeW` | `GetDriveTypeW` = `DRIVE_REMOVABLE` |

**Volume capabilities** (`case_sensitive()` / `case_preserving()` / `fs_type()`) are sourced per-OS: Apple via `getattrlist` (`VOL_CAP_FMT_CASE_SENSITIVE` / `VOL_CAP_FMT_CASE_PRESERVING`), Windows via `GetVolumeInformationW`, and elsewhere from the filesystem type. They follow a `None`-means-unknown contract — `Some(..)` only when the platform or filesystem type definitively proves the answer.

**Volume identity** (`volume_identity()`) is sourced per-OS, and follows the same `None`-means-nothing-to-report contract:

| Platform | Source | Assurance | Reports |
|---|---|---|---|
| macOS, iOS, watchOS, tvOS, visionOS | `getattrlist` with `ATTR_VOL_UUID` | `Vouched` | `FsUuid` for every volume carrying a UUID (APFS, HFS+ — the same value `diskutil info` prints as "Volume UUID") and for the UUID the kernel derives for FAT-class volumes; `None` on `devfs` / `autofs` |
| Linux | `/dev/disk/by-uuid` reverse lookup, and `/sys/fs/btrfs/<fsid>/devices/` for btrfs (no root, no `libblkid`; sysfs-only for btrfs — by-uuid is never consulted, even where sysfs finds no claimant; a btrfs identity is reported only when the kernel positively states the FSID is permanent — `temp_fsid = 0`, Linux 6.7+) | `Published` | `FsUuid` (ext2/3/4, XFS, btrfs, f2fs …, and HFS+, whose UUID `blkid` derives exactly as Apple does), `Serial64` (NTFS), `FsUuid` for exFAT (derived from the serial), `Serial32` (FAT12/16/32); `None` where udev published nothing |
| Windows | `GetVolumeInformationW`, plus `FSCTL_GET_NTFS_VOLUME_DATA` on NTFS | `Vouched` | `Serial64` on NTFS (the full width; `Serial32` of the low half where the volume device cannot be opened), `FsUuid` for exFAT, `Serial32` for FAT12/16/32; `None` when the call fails or the serial is zero |
| FreeBSD, OpenBSD, DragonFlyBSD | — | — | `None`. `statfs`'s `f_fsid` is a mount-session handle assigned by `vfs_getnewfsid()`, not a property of the volume, so it survives neither a reboot nor a move to another machine |
| NetBSD | — | — | `None`, for the same reason (`f_fsidx`) |

A **btrfs** filesystem can span several devices, and every member carries the same FSID — so `blkid` reads one name off all of them and udev can publish only one `/dev/disk/by-uuid` link, pointing at whichever member it saw last. Mounting by any other member is equally valid, and then that link names nothing the mount table knows about. The kernel's own map, `/sys/fs/btrfs/<fsid>/devices/`, is read first for btrfs mounts and matches the mount source's device number against the filesystem's members, so the FSID is reported whichever member carries the mount.

Two narrowings sit beside that map rather than in it, and both refuse rather than fall back to `/dev/disk/by-uuid` in their place: a **temporary FSID** — the runtime-only identity Linux 6.7+ mints for a clone mounted beside its on-disk original, marked by `<fsid>/temp_fsid` reading `1` — is not reported, since it does not survive to the next mount or the next machine; and a device number claimed by more than one filesystem — a **seed device**, recognized read-only and so able to seed several sprouts at once, linked into every one of their `devices/` directories — is ambiguous, and none of the claimants is preferred over the rest. A sysfs read that fails partway through — an unreadable `devices/` directory, a member's unreadable `dev` file, a `temp_fsid` marker that exists but cannot be read — refuses the same way: the census is indeterminate, so no identity is reported from either road, and `/dev/disk/by-uuid` is never consulted in a refusal's place.

Absence is never evidence, either. A mount `mountinfo` already reports as btrfs, whose sysfs census names no claimant at all — a readable-but-empty root, a bind mount that masks it, an FSID directory torn down between the `mountinfo` snapshot and this read — is refused rather than read as "not btrfs": the caller already knows otherwise, and a btrfs mount's identity is read from sysfs or not at all. A btrfs identity is reported only when the kernel positively states the FSID is permanent — `<fsid>/temp_fsid` reading exactly `0` on the matched candidate, an attribute present since Linux 6.7. Every other reading of that file — missing, unreadable, malformed, or `1` — refuses, regardless of a kernel-wide feature flag, another filesystem's own marker, or the running kernel's own release: earlier attempts inferred a missing marker's meaning from exactly those signals, and each one turned out spoofable or decoupled from what the running kernel actually ships (`uname(2)` is process-modifiable — the `UNAME26` personality reports a 2.6.x release on an arbitrarily new kernel — and a vendor backport of `temp_fsid` can just as easily ship it under a release numbered below 6.7). A kernel that predates Linux 6.7 and a masked or namespaced sysfs view on one that doesn't are indistinguishable from here, and both report no btrfs identity — a missed match, never a false one.

The form is chosen **per filesystem**, so one volume keeps one identity wherever it is read. Four narrowings cannot be avoided, and each is documented rather than left to be discovered — in all four the failure is a *missed* match, never two volumes made to look alike:

- an **NTFS** volume on Windows falls back to the low 32 bits of its serial where the volume device cannot be opened;
- a **FAT12/16/32** volume on an Apple platform reports a UUID the kernel derives from the serial *and the BPB total-sector count* — a value no other platform can reach, because nothing unprivileged there reports that sector count;
- an **exFAT** volume carrying a native Volume GUID is named by that GUID, which lives in the root directory and so needs elevation to read: Apple reports it, while Linux and Windows report the UUID derived from the serial they can see (`exfat.util -s` stamps such a volume; no format tool writes one by default);
- an **exFAT** volume mounted through `exfat-fuse` as bare `fuseblk` does not prove its own format — that name is shared with ntfs-3g and every other block-backed FUSE helper — so its serial is reported as `Serial32` rather than run through a derivation that may not be its. A FUSE mount that publishes its subtype (`fuse.exfat`) does prove it, and agrees with the kernel driver.

See the [`VolumeIdentity`](https://docs.rs/whichdisk/latest/whichdisk/enum.VolumeIdentity.html) docs for the derivations and the full table. A zero serial and the nil UUID are never identities: they record the absence of one, on every platform.

On Linux the answer is only ever as fresh as udev's links, which is what `Published` says out loud. udev re-points `/dev/disk/by-uuid` from a uevent, so in the instant between new media appearing under a device node and udev catching up, the departed volume's name still resolves to that node — and a resolve landing inside that window reports the identity that left. The window is transient and closes itself: nothing caches the answer, so the next call reads the directory again. Two cheap checks narrow it further — a published name of a width the mount's own filesystem cannot carry (a UUID on a `vfat` mount, a FAT serial on `ntfs`) is not that volume's and is refused, and where two names resolve to one device node, neither is reported. Settling it outright would mean reading the superblock, which needs a raw device handle and so elevation; this crate does not take one. A caller that cannot afford to act on a name that may have lagged does not have to guess at any of this: it asks for `Vouched` and gets nothing here.

## Performance

- **Thread-local cache** — repeated lookups for paths on the same mount skip the underlying syscall/file read. Two rules govern what it may hold and what it may serve:
  - **No backend caches a volume's identity.** Every platform reads it on every resolve — Apple asks `getattrlist`, Windows asks `GetVolumeInformationW`, Linux scans `/dev/disk/by-uuid` — because no key here can promise the volume behind it is still the one an entry describes. A Windows volume GUID comes closest and still cannot: it names durable *storage*, while the serial is a value in the filesystem written onto that storage, and an offline tool rewrites the serial without touching the GUID
  - **A mount-session key serves the mount's own metadata, and only under an agreeing witness.** Linux takes the mount's unique id (`statx`, Linux 6.8+) on every resolve; where it agrees the entry is served whole, and where it disagrees — or where the kernel has no id to give, as before 6.8 — it is a complete miss and `/proc/self/mountinfo` is read again. No field of an unvouched entry is reused, the filesystem type least of all, since that is what decides the form an identity takes. Windows keeps nothing at all: one `GetVolumeInformationW` yields the capabilities and the serial together, so once the serial is read every time there is no call left for an entry to save
- **What reading the identity per resolve costs** — on Linux, a `/dev/disk/by-uuid` scan, and only for a mount whose source is a device node: measured at ~39 µs against 8 published names and ~107 µs against 24 (a Linux 6.4 container on an Apple-silicon host, `--release`), or about 4.5 µs per published name. A pseudo filesystem names itself as its own source, which the scan skips outright in ~1 ns — the hot "no identity" case costs nothing. On a kernel with no witness to give, a resolve also re-reads `/proc/self/mountinfo` — ~26 µs for a 20-line file on the same host, against ~2 µs for everything else a resolve does. On Windows the same rule costs one local `GetVolumeInformationW` per resolve, plus one handle-open and one `FSCTL_GET_NTFS_VOLUME_DATA` on NTFS; Apple's `getattrlist` was already per-resolve
- **Small-buffer optimization** — mount points and device names (typically < 56 bytes) are stored inline on the stack; longer values use reference-counted `bytes::Bytes` (clone is a pointer copy)
- **SIMD-accelerated scanning** — uses [`memchr`](https://crates.io/crates/memchr) for null-terminator and newline searches in the BSD `statfs` buffers and Linux mountinfo parsing

## MSRV

The minimum supported Rust version is **1.85**.

#### License

`whichdisk` is under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[Github-url]: https://github.com/al8n/whichdisk/
[CI-url]: https://github.com/al8n/whichdisk/actions/workflows/ci.yml
[doc-url]: https://docs.rs/whichdisk
[crates-url]: https://crates.io/crates/whichdisk
[codecov-url]: https://app.codecov.io/gh/al8n/whichdisk/
[discord]: https://discord.gg/PHwxDzsz7f

