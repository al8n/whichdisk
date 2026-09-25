<div align="center">
<h1>whichdisk</h1>
</div>
<div align="center">

Cross-platform disk/volume resolver — given a path, tells you which disk it's on, its mount point, relative path, disk usage, per-volume capabilities (case-sensitivity, filesystem type), a durable volume identity (filesystem UUID or serial), and the volume's name

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
whichdisk = "0.6"
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
volume_name="Macintosh HD"
volume_identity="8f19a253-d450-3090-abf6-e651943998d1"
identity_assurance="vouched"
ejectability="not_ejectable"
relative_path="Users/user/Develop/personal/whichdisk"
total_bytes=926.35 GiB
available_bytes=701.81 GiB
used_bytes=224.55 GiB
```

`volume_identity` is the identity the volume carries on itself and
`identity_assurance` is how it was read; a platform or filesystem that reports
neither prints the bare word `none` rather than empty quotes. `volume_name` is
the label a user sees, which is **not** an identity — see
[Volume name](#volume-name).

**JSON output** (`-o json`):
```json
{
  "device": "/dev/disk3s5",
  "mount_point": "/System/Volumes/Data",
  "volume_name": "Macintosh HD",
  "volume_identity": "8f19a253-d450-3090-abf6-e651943998d1",
  "identity_assurance": "vouched",
  "ejectability": "not_ejectable",
  "relative_path": "Users/user/Develop/personal/whichdisk",
  "total_bytes": 994662584320,
  "available_bytes": 753886154752,
  "used_bytes": 240776429568
}
```

`ejectability` is three-valued, not two: `ejectable`, `not_ejectable`, and
`unknown` for a volume the platform could not be asked about or said nothing
about. `not_ejectable` is only ever the platform's own answer to the removal
question, bound to the mount the row holds: on macOS DiskArbitration's word
that the device is inside the machine and its media neither ejects nor comes
out — the internal volume above — on Windows the disk's Plug and Play removal
policy, and on Linux a USB disk the kernel calls `fixed` on every port between
it and its host controller. The BSDs have no such answer, and never deny. A
`bool` spelled every `unknown` `false`, which is a denial the platform never
made. On Windows the policy is Plug and Play's expectation for the disk's
device node, so a Storage Spaces virtual disk or an iSCSI LUN whose node
expects no removal answers `not_ejectable` whatever storage lies behind it,
and a hypervisor's hot-pluggable virtual disk — a virtual machine's boot disk
included — answers `ejectable`, as Windows itself offers to eject it.

A volume's `volume_name_assurance` and `identity_assurance` say how each was
read: `vouched` is the mounted filesystem answering for itself, `published` is a
name the platform published about a device, and `declared` is a name published
about a device that only the mounter says is the one — on Linux any user may
make a `fuse` mount and name its source `/dev/sda1`, so what udev published
about that node is reported at `declared` rather than refused, and a consumer
keying on a volume should take nothing at that level.

Every field is named once and printed by all three formats alike: the plain
output, JSON and YAML carry the same fields under the same names, and differ
only in how they spell a value. A byte count is an exact number where a machine
reads it and a human-readable size where a person does, and a field the platform
cannot answer for is the bare word `none` in the plain output, `null` in JSON
and `~` — YAML's own null — in YAML. None of the three is ever an empty string,
which would read as a volume whose name, or identity, is nothing.

A text value in the plain output is quoted and escaped the way Rust spells a
string, because a volume's label is whatever a person wrote on it: a label
carrying a quote, a newline or a terminal control sequence cannot close its own
field, forge the next one, or reach the terminal that prints it.

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
device="/dev/disk3s1s1" mount_point="/" volume_name="Macintosh HD" volume_identity="8f19a253-d450-3090-abf6-e651943998d1" identity_assurance="vouched" ejectability="not_ejectable" total_bytes=926.35 GiB available_bytes=701.81 GiB used_bytes=224.55 GiB
```

**JSON output** (`list -o json`):
```json
[
  {
    "device": "/dev/disk3s1s1",
    "mount_point": "/",
    "volume_name": "Macintosh HD",
    "volume_identity": "8f19a253-d450-3090-abf6-e651943998d1",
    "identity_assurance": "vouched",
    "ejectability": "not_ejectable",
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
    println!("Volume name:    {:?}", info.volume_name());
    println!("Relative path:  {}", info.relative_path().display());
    println!("Ejectable:      {:?}", info.ejectability());
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
        println!("{:?} -> {:?} (ejectable: {:?})",
            m.device(), m.mount_point(), m.ejectability());
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

`None` means the platform or the filesystem genuinely reports no identity — a pseudo-filesystem, a network mount, or a platform with no durable-identity query — or that the platform declined to let the caller look: the volume went away, reading it is not permitted, the filesystem does not implement the question. On Apple platforms, Linux and Windows it is never a failure to look: a read that failed for any other reason — no descriptors left, no memory, an I/O error — comes back as the error it is. On Linux it is also a directory of published names that could not be read whole, for every device: see [A failed read is not an answer](#a-failed-read-is-not-an-answer). On Windows it is also a volume whose file system declined `FileFsVolumeInformation` through the one handle the row is read through.

#### The reading says how it was read

The identity is durable on the volume, but not every platform lets an unprivileged caller read it *from* the volume. Apple and Windows ask the mounted filesystem itself; Linux has no such call and recovers the value from a name udev published about the mount's source device, which can lag the media now behind it. That difference is a fact about the answer, so it comes back with the answer: `volume_identity()` hands over an `IdentityReading`, which is the `VolumeIdentity` plus the `IdentityAssurance` it was read at.

- `Vouched` — read from the mounted filesystem on this call (Apple `getattrlist` through the row's descriptor, Windows `FileFsVolumeInformation` / `FSCTL_GET_NTFS_VOLUME_DATA` through the row's one handle). Media that replaced other media under the same mount point answers as itself.
- `Published` — read from a name the platform publishes about a device (Linux `/dev/disk/by-uuid`, and `/sys/fs/btrfs/<fsid>/devices/` for btrfs). Correct once udev has run, and possibly the departed volume's name for the instant before it does.

```rust,ignore
// A consumer with something irreversible to do can require the stronger level;
// `Published` is then "not now", not "no".
if let Some(reading) = info.volume_identity().filter(whichdisk::IdentityReading::is_vouched) {
    migrate_onto(reading.identity());
}
```

The identity itself is the key, and the assurance is not part of it: one disk read on macOS and on Linux gives one `VolumeIdentity` and two assurances, so it occupies one registry key either way. Nothing promotes a `Published` reading to a `Vouched` one — settling a published name means reading the volume's superblock, which needs elevation this crate never takes.

### Volume name

`volume_name()` reports the label a user sees beside the volume — `Macintosh HD`, `BACKUP`, `Untitled` — which is what to *show*, never what to *key on*.

**A name is not an identity.** A person can rewrite a label at any moment without the volume becoming another volume, two volumes may carry the same one, and a volume renamed while it was unmounted comes back under a name nothing recorded. `volume_identity()` is the durable key; `volume_name()` is the caption. A rename does not even make a mount point a different mount point: the name takes no part in `MountPoint`'s `PartialEq`.

```rust,ignore
use whichdisk::resolve;

fn main() -> std::io::Result<()> {
    let info = resolve("/some/path")?;

    // What to show a user...
    println!("volume: {}", info.volume_name().unwrap_or("unnamed"));
    // ...and what to remember it by.
    println!("key:    {:?}", info.volume_identity().map(|r| r.identity()));

    Ok(())
}
```

Where the platform publishes no label, the **fallback** is the mount point's last path component — `usb` for `/media/alice/usb` — and the whole mount point where it has none, which is the filesystem root (`/`) and a Windows drive root (`C:`). The result is never `Some("")`: a platform label that comes back empty is no label, and falls back like any other. `None` is left for the one case neither road can spell — a label or mount point whose bytes are not valid UTF-8.

| Platform | Source | Reports |
|---|---|---|
| macOS, iOS, watchOS, tvOS, visionOS | `getattrlist` with `ATTR_VOL_NAME`, through the descriptor the row is read through — a resolve's and a listing row's alike | the volume's name, the same one `diskutil info` prints as "Volume Name" |
| Linux | a `/dev/disk/by-label` reverse lookup (no root, no `libblkid`) | the label udev published for the mount's source device, with its `\x20`-style escapes decoded; nothing where two labels resolve to one device node, for the reason the identity gives |
| Windows | `FileFsVolumeInformation`, through the one handle the row is read through | the volume label; nothing for an unlabeled volume |
| FreeBSD, OpenBSD, DragonFlyBSD, NetBSD | — | nothing: a UFS or ZFS label lives behind a GEOM provider name, a dataset name or a `disklabel` road this crate does not take. The fallback answers |

### One row, one observation

Every value in one row — a resolve's or a listing's — describes one mount, because **an observation is formed once, from one native identity, and a row is built from nothing else.** On each platform one observation type holds the pinned descriptor or handle together with the native identity it was pinned from; every field of the row is read through it, and on Linux and Windows every fact is read when the observation is formed and stored in it. The row is built by one constructor whose only input is the observation itself, taken by value — no root, path, GUID, table or field can be handed to it — and finding a path, a mount root or a volume GUID is private to the observation's constructor, so no road of a row can do it a second time. Path text and a device number (`st_dev`) never identify anything.

- **Apple platforms**: the observation is a path's own filesystem bytes — `realpath`'s answer for a resolve, the mount point the kernel wrote into its mount table for a listing, copied once — the descriptor pinned from exactly those bytes, and that descriptor's own `fstatfs`. The row is the `fstatfs` — mount point, source, filesystem type, capacity and the kernel's `MNT_REMOVABLE` — and what `fgetattrlist` answers through the descriptor: capabilities, identity and label; on macOS, where `MNT_REMOVABLE` says nothing, the removal answer is DiskArbitration's description of the disk the kernel wrote into the pinned mount's own filesystem id, re-checked through the descriptor afterwards. A listing pins each mount point once, and a row is the one census entry whose filesystem id, source, type and mount point are the pinned mount's own — never a path's: a mount covered by another at the same path, and one that took a departed volume's path, are not reported. The census entry's own flags are asked whether the mount is local and browsable, so that a remote or hidden volume is never opened, and the row must then say the same of itself. A firmlinked path is split beneath its mount by the descriptor's own word (`F_GETPATH_NOFIRMLINK`). **A resolve never acts on the object it names**: the object is `stat`ed first, and only a regular file or a directory is ever opened, a directory only as one (`O_DIRECTORY`). Both opens take `O_NOFOLLOW` — the path is `realpath`'s and holds no link — so a link swapped in at the last component is refused like a directory that is no longer one, and described by its `statfs`. A FIFO, a socket, a device node and a path that can be reached but not opened are described by their one `statfs` and nothing more, split beneath a firmlink by the `F_GETPATH_NOFIRMLINK` of the nearest directory above them that opens on their mount — a parent the system's privacy controls guard is passed over for the one above it. The window left is a regular file swapped for a FIFO or a device between the `stat` and the open, at the last component or through a directory above it swapped for a link: it is opened non-blocking, with no controlling terminal, and let go unread.
- **Linux**: the observation is an `O_PATH` descriptor and the mount id it holds — `statx`'s `STATX_MNT_ID`, else the `mnt_id:` line of the descriptor's own `fdinfo` read beneath the authenticated `/proc`, else a named refusal — and the mount table line that id names in a table read while the descriptor is held, with every fact of the row read, when the observation is formed, from the one resolution of that line's source and the one pin: the identity, the label, the removal answer and the capacity, beneath roots the observation's own constructor opens. A btrfs mount's identity and label are its filesystem's own answer — `BTRFS_IOC_FS_INFO` and `FS_IOC_GETFSLABEL`, asked of a descriptor reopened from a pin of the mount point that holds the same mount id — and its source binds, for the removal answer, only where the one census of the kernel's btrfs map names that FSID for it. A resolve pins the object the caller named. A listing pins every row's mount point, whatever the features, and a row is the line its pin's held id names in the table read again while the pin is held — wherever the mount is now — or it is not reported: a mount point that cannot be pinned, one covered by another mount, and one that left between the two reads are each a mount no fact can be bound to, and no fact is ever read about a line nothing proved. The mount table is the calling thread's own, read beneath the thread's procfs directory, because a thread may have entered a mount namespace of its own and the pin and every pathname a row is read through resolve in it. What the facts are read out of — the kernel's filesystem roster and udev's two censuses — is read only after the rows it serves are bound, once per resolve and once per batch of listed pins, and never kept for a row bound later. **A fact is read only about the device that backs the mount**: a source binds only where its node beneath `/dev` is the `major:minor` the kernel prints for the mount itself, or, for btrfs, whose mounts carry an anonymous device, where it is a member of the filesystem the pinned mount answers for; and a source that does not bind — a retargeted node or link, a device a `tmpfs` or FUSE mount merely names — has no identity, label or removal answer read about it. **A device number binds nothing on its own**: a disk that left while mounted can see its number handed to another, and a device mapper table or an NBD device can change what stands behind one. So the removal answer is given only where the mounted filesystem names itself through the mount — its UUID (`FS_IOC_GETFSUUID`, Linux 6.9), a FAT volume's serial, btrfs's FSID — and udev names the same identity for the device, published for the device's current attach (its `diskseq`, Linux 5.15, has a `/dev/disk/by-diskseq` link, systemd 251), and every device the answer is read from — a stack's included — is the same attach after the answer as before, and every stack layer lists the same members (`slaves/`): the kernel changes no `diskseq` when a device mapper table is swapped or an md member replaced, so a layer's membership is re-read as a set of its own. That keeps a removal answer for ext4, XFS, btrfs, f2fs and every other filesystem that gives its superblock a UUID on Linux 6.9 and later, and for btrfs, vfat and msdos on any kernel with `diskseq`; exFAT, NTFS, ISO 9660 and UDF — and ext4 and XFS before 6.9 — answer `Unknown`. A device mapper or md device answers only where udev publishes a `by-diskseq` link for it too: systemd's own rules give those none, and lvm2's rules give device mapper devices one only in recent versions. Where the filesystem does name itself, udev's identity for the device must be that one or no udev fact is reported; where it names none, udev's identity and label are read only for the attach udev published, wherever `/dev/disk/by-diskseq` names the device — a name for another attach withholds them — and stay bound by the device number where it names none, which their `Published` and `Declared` assurances say out loud.
- **Windows**: the observation is one handle on the volume's root directory, the volume GUID path it names, the paths the volume is mounted at and every fact the handle answered, and a row is built for each of its own mount paths and for nothing else. A resolve finds its path's mount root once and opens the handle on it, and the handle is accepted only where its own final path is exactly a volume GUID root — or, for a network share, exactly the share's root — so an open that landed on a folder because the volume mounted there left in between is declined, not read; a listing opens the handle through the GUID path the enumeration named, asks for the volume's mount points while the handle holds it, reads every fact after them, and keeps the volume only where it then names itself, through the handle, by the GUID path its mount points were asked by. Every field is read through that handle: `NtQueryVolumeInformationFile` for the serial and label, the file-system name and flags, the capacity and the device kind, and `FSCTL_GET_NTFS_VOLUME_DATA` for the full NTFS serial. The one fact asked through a second handle is removal, for a disk whose medium is fixed in it: the volume's own device, opened only by the GUID path the first handle proved and for no access, answers the disk's device number — which leads to its Plug and Play removal policy, re-checked through both the volume's and the disk's handles afterwards — and its storage descriptor's bus. **A resolve never acts on the object it names, and follows nothing it has not read**: a path that names a device — a DOS device name such as `NUL` or `COM1`, a raw drive or volume, a named pipe or mailslot, locally or through a host's `pipe`, `mailslot` or `IPC$` share, or the console's `CONIN$` and `CONOUT$` — is refused with `InvalidInput` before anything is opened, decided on the string through `GetFullPathNameW`, which touches nothing. Every other path is walked one component at a time, each opened with `NtCreateFile` relative to the handle on the one before and with `FILE_OPEN_REPARSE_POINT`, so no link is followed by the system: a data reparse point (a cloud file's placeholder, a deduplicated file) is a file like any other, and a symbolic link or a junction is followed only after its target, read through the handle that holds it, is proven to be a drive's, a share's or a volume GUID's path — a link to a named pipe, a serial port or anything else in the device namespace is refused, unopened. A drive letter the caller's session defines onto a path (`subst`) is walked as that path. Refused by name: any other name surrogate; a link on a network share, or one from a local volume to a network path, which Windows evaluates under a policy of its own a hand-follow cannot honour; a relative link that climbs above its root; and more than 63 links, which is `ERROR_CANT_RESOLVE_FILENAME`, as a loop is. The resolve's root handle is then opened by the GUID — or the share — the object's own handle names, through the global namespace. What is left: a drive letter the caller's own session, or an administrator, defines onto a raw device (`DDD_RAW_TARGET_PATH`) is opened as defined, since refusing letters the mount manager does not know would refuse WinFsp and Dokan mounts.
- **FreeBSD, OpenBSD, DragonFlyBSD, NetBSD**: one `statfs` or `statvfs` is the whole resolve, and one entry of one enumeration is the whole listing row, its mount point, source and filesystem type decoded whole — a string with no terminator inside its array, or an entry missing one of the three, fails the call rather than being passed over. DragonFly rewrites a mount's mount point in the kernel's shared copy on every call, so a call overlapping another can be handed one torn in half; there an answer is taken only once the next one agrees with it on every string. A mount's source is text a user-space filesystem chooses for itself, so it is read about removal only where the kernel's own filesystem type proves the kernel opened the device it names.

### A failed read is not an answer

On Apple platforms, Linux and Windows every platform read answers one of four outcomes — a value; the platform's own "there is no such thing"; a decline, which is one of the errors each backend names (the object is not there, the caller may not look, the containment refused the path, the question is not implemented or not serviced on that handle); or a failure — and no two of them are merged except by a road that says what each means. Only a decline or an absence may end in a value's documented absence — `None`, a zero, the mount-point fallback — and a failed read, no descriptors or no memory or an I/O error, is returned as the error it is. Windows' system error codes are sorted to the same contract, each road's listed in the backend's own documentation beside the Microsoft page that names it. The one road on which a failure leaves an answer rather than an error is ejectability, whose `unknown` is defined as "could not be asked".

A **census** — a whole `/dev/disk/by-uuid` or `/dev/disk/by-label` directory, the btrfs map in sysfs, a `slaves/` directory, the Linux mount table, the Windows volume enumeration, the BSD and Apple mount tables — is read whole or not at all, and there is one census type for it, built only by a reader that proves the enumeration complete: to an end the platform proves (`getdents64` returning nothing, `FindNextVolumeW` answering `ERROR_NO_MORE_FILES`); into a buffer this crate owns with slots to spare, taken only from an answer that left one empty (`getfsstat`, `getvfsstat`, which answer with the buffer's length when there were more entries than it holds); or, for the Linux mount table, from a read the kernel proves no mount event overlapped (`poll` answering no `POLLPRI`). A refill declined partway refuses it rather than leaving the entries read before it standing, and no census borrows storage the platform owns: `getmntinfo`'s process-wide buffer is not read at all. Every string a census or a row decodes is decoded whole or fails its read: a record of the Linux mount table that breaks the kernel's grammar anywhere — a field short, a field past its end, an escape the kernel does not write, a last record with no newline — and a Windows mount point or GUID path that is not UTF-16 text, are `InvalidData`, never a member passed over. A udev name or database value is decoded strictly: a backslash that does not begin `\xNN` is `InvalidData`, never a byte of a label. **An answer a platform writes into a buffer is read only as far as the platform says it wrote**: `getattrlist`'s leading length, `IO_STATUS_BLOCK.Information` and `DeviceIoControl`'s count are checked against the buffer before any field is read, and every field is taken out of that prefix alone, so a count past the buffer, a structure short of its fixed part, a string that is odd, runs past the answer or lacks its terminator is `InvalidData` — never a value read out of bytes the platform did not write, and never an absence. A structure whose variable part the platform declares by length — a Windows label, a file-system name, a storage descriptor — must end exactly where the reported answer does. A call that reports no length (`GetVolumePathNameW`, `FindFirstVolumeW`, `FindNextVolumeW`, `F_GETPATH_NOFIRMLINK`, the configuration manager's interface list, Core Foundation's string and URL copies) is handed a buffer with no zero in it, so the terminator its string or list ends at is one the call wrote. btrfs's label copy writes no terminator and no zero, so its label ends at the first zero of the buffer it was handed zeroed, which the length the kernel copied puts there. NetBSD's census asks for the statistics the kernel keeps (`ST_NOWAIT`), because a census that asks every filesystem to refresh them is one the kernel silently leaves a mount out of wherever the refresh fails. On Linux every directory is read through `getdents64` for that reason: `rustix`'s `Dir` reads a refill that fails with `ENOENT` as the end of the directory. An entry declined while it is resolved refuses the whole census, because it could be exactly the second name the two-names-one-node refusal exists for; only an entry that opened and is not a block device is passed over, and a name that is not a value the road reads still counts as a name for its node. A refused census reports nothing, for any device, and a refused volume enumeration fails the listing.

FreeBSD, OpenBSD, DragonFlyBSD and NetBSD name no decline: every failed read there is the operation's error.

### Feature Flags

| Feature      | Default? | Description                                                       |
| ------------ | -------- | ----------------------------------------------------------------- |
| `disk-usage` | Yes      | Enables `total_bytes()`, `available_bytes()`, and `used_bytes()`  |
| `list`       | Yes      | Enables `list()`, `list_with()`, and `ListOptions`                |
| `cli`        | No       | Builds the `whichdisk` CLI binary                                 |

To use only the core `resolve()` API with minimal dependencies:

```toml
[dependencies]
whichdisk = { version = "0.6", default-features = false }
```

## Supported Platforms

| Platform | Resolve backend | List backend | Ejectable detection | Volume name |
|---|---|---|---|---|
| macOS, iOS, watchOS, tvOS, visionOS | `fstatfs` / `fgetattrlist` on one held descriptor, via [`rustix`](https://crates.io/crates/rustix) | `getfsstat` via [`libc`](https://crates.io/crates/libc), a census into a buffer this crate owns; each local, browsable mount is then read through its own pinned root, as a resolve is | the kernel's `MNT_REMOVABLE` on the mount the row's descriptor holds (yes or nothing), then, on macOS, DiskArbitration's description of the disk the mount's filesystem id names: internal with fixed media denies, external or removable media says yes | `ATTR_VOL_NAME`, through the row's descriptor |
| FreeBSD, OpenBSD, DragonFlyBSD | `statfs` via [`rustix`](https://crates.io/crates/rustix) | `getfsstat` via [`libc`](https://crates.io/crates/libc), a census into a buffer this crate owns | `cd`, `acd` and `fd` device names say yes, for a source the kernel's own filesystem type binds; nothing denies | — (mount point fallback) |
| NetBSD | `statvfs` via [`libc`](https://crates.io/crates/libc) | `getvfsstat` via [`libc`](https://crates.io/crates/libc), a census into a buffer this crate owns | `cd` and `fd` device names say yes, for a source the kernel's own filesystem type binds; nothing denies | — (mount point fallback) |
| Linux | the calling thread's `mountinfo` | the calling thread's `mountinfo` | sysfs `removable`, a device on the way reading `removable`, a USB ancestry, or an MMC card whose `type` is `SD`, down `slaves/`, for a source bound to the mount; a USB disk the kernel calls `fixed` on every port, its media flag `0`, denies | `/dev/disk/by-label` reverse lookup |
| Windows | `GetVolumePathNameW` once, then one handle on the volume's root directory, read with `NtQueryVolumeInformationFile` via [`windows-sys`](https://crates.io/crates/windows-sys) | `FindFirstVolumeW` / `FindNextVolumeW`, a census complete or refused; one handle per volume | `FileFsDeviceInformation` (optical, removable media), then, for a fixed disk, through the volume's own device: the disk's Plug and Play removal policy (expecting no removal denies, expecting removal says yes), else a USB or SD bus | `FileFsVolumeInformation` |

**Volume capabilities** (`case_sensitive()` / `case_preserving()` / `fs_type()`) are sourced per-OS: Apple via `getattrlist` (`VOL_CAP_FMT_CASE_SENSITIVE` / `VOL_CAP_FMT_CASE_PRESERVING`), Windows via `FileFsAttributeInformation` through the row's one handle, and elsewhere from the filesystem type. They follow a `None`-means-unknown contract — `Some(..)` only when the platform or filesystem type definitively proves the answer.

**Volume identity** (`volume_identity()`) is sourced per-OS, and follows the same `None`-means-nothing-to-report contract:

| Platform | Source | Assurance | Reports |
|---|---|---|---|
| macOS, iOS, watchOS, tvOS, visionOS | `getattrlist` with `ATTR_VOL_UUID` | `Vouched` | `FsUuid` for every volume carrying a UUID (APFS, HFS+ — the same value `diskutil info` prints as "Volume UUID") and for the UUID the kernel derives for FAT-class volumes; `None` on `devfs` / `autofs` |
| Linux | `/dev/disk/by-uuid` reverse lookup, and for btrfs `/sys/fs/btrfs/<fsid>/devices/`, bound by the FSID the mounted filesystem answers through the pinned mount (no root, no `libblkid`; sysfs-only for btrfs — by-uuid is never consulted, even where sysfs finds no claimant; a btrfs identity is reported only when the kernel positively states the FSID is permanent — `temp_fsid = 0`, Linux 6.7+) | `Published` | `FsUuid` (ext2/3/4, XFS, btrfs, f2fs …, and HFS+, whose UUID `blkid` derives exactly as Apple does), `Serial64` (NTFS), `FsUuid` for exFAT (derived from the serial), `Serial32` (FAT12/16/32); `None` where udev published nothing |
| Windows | `FileFsVolumeInformation`, plus `FSCTL_GET_NTFS_VOLUME_DATA` on NTFS, through the row's one handle | `Vouched` | `Serial64` on NTFS (the full width; `Serial32` of the low half where the file system declines the FSCTL on that handle), `FsUuid` for exFAT, `Serial32` for FAT12/16/32; `None` where the volume declines the question or the serial is zero |
| FreeBSD, OpenBSD, DragonFlyBSD | — | — | `None`. `statfs`'s `f_fsid` is a mount-session handle assigned by `vfs_getnewfsid()`, not a property of the volume, so it survives neither a reboot nor a move to another machine |
| NetBSD | — | — | `None`, for the same reason (`f_fsidx`) |

A **btrfs** filesystem can span several devices, and every member carries the same FSID — so `blkid` reads one name off all of them and udev can publish only one `/dev/disk/by-uuid` link, pointing at whichever member it saw last. Mounting by any other member is equally valid, and then that link names nothing the mount table knows about. The kernel's own map, `/sys/fs/btrfs/<fsid>/devices/`, matches the mount source's device number against the filesystem's members, so the FSID is reported whichever member carries the mount. A btrfs mount carries an anonymous device in the mount table rather than any member's, so the mounted filesystem is asked its FSID (`BTRFS_IOC_FS_INFO`) and its label (`FS_IOC_GETFSLABEL`) through a descriptor held to the pinned mount. Those two answers are the identity — where `<fsid>/temp_fsid` says the FSID outlives the mount — and the label, whether or not the source resolves beneath `/dev`, so a container whose `/dev` holds no disk nodes still has both. The map binds the source device, which the removal answer is asked about, only where it names that FSID for the source — see *One row, one observation*. A mount root this process may not open for reading answers neither question.

Two narrowings sit beside that map rather than in it, and both refuse rather than fall back to `/dev/disk/by-uuid` in their place: a **temporary FSID** — the runtime-only identity Linux 6.7+ mints for a clone mounted beside its on-disk original, marked by `<fsid>/temp_fsid` reading `1` — is not reported, since it does not survive to the next mount or the next machine; and a device number claimed by more than one filesystem — a **seed device**, recognized read-only and so able to seed several sprouts at once, linked into every one of their `devices/` directories — is ambiguous, and none of the claimants is preferred over the rest. A sysfs read declined partway through — an unreadable `devices/` directory, a member's missing `dev` file, a `temp_fsid` marker that exists but cannot be read — refuses the same way: the census is indeterminate, so no identity is reported from either road, and `/dev/disk/by-uuid` is never consulted in a refusal's place. A read that fails for any other reason — no descriptors left, an I/O error — is not a census at all, and comes back as the error it is.

Absence is never evidence, either. A mount `mountinfo` already reports as btrfs, whose sysfs census names no claimant at all — a readable-but-empty root, a bind mount that masks it, an FSID directory torn down between the `mountinfo` snapshot and this read — is refused rather than read as "not btrfs": the caller already knows otherwise, and a btrfs mount's identity is read from sysfs or not at all. A btrfs identity is reported only when the kernel positively states the FSID is permanent — `<fsid>/temp_fsid` reading exactly `0` on the matched candidate, an attribute present since Linux 6.7. Every other reading of that file — missing, unreadable, or `1` — refuses (and one that is neither `0` nor `1` is not the kernel's writing, and fails with `InvalidData`), regardless of a kernel-wide feature flag, another filesystem's own marker, or the running kernel's own release: earlier attempts inferred a missing marker's meaning from exactly those signals, and each one turned out spoofable or decoupled from what the running kernel actually ships (`uname(2)` is process-modifiable — the `UNAME26` personality reports a 2.6.x release on an arbitrarily new kernel — and a vendor backport of `temp_fsid` can just as easily ship it under a release numbered below 6.7). A kernel that predates Linux 6.7 and a masked or namespaced sysfs view on one that doesn't are indistinguishable from here, and both report no btrfs identity — a missed match, never a false one.

The form is chosen **per filesystem**, so one volume keeps one identity wherever it is read. Four narrowings cannot be avoided, and each is documented rather than left to be discovered — in all four the failure is a *missed* match, never two volumes made to look alike:

- an **NTFS** volume on Windows falls back to the low 32 bits of its serial where the file system declines the full-serial FSCTL on the row's one handle;
- a **FAT12/16/32** volume on an Apple platform reports a UUID the kernel derives from the serial *and the BPB total-sector count* — a value no other platform can reach, because nothing unprivileged there reports that sector count;
- an **exFAT** volume carrying a native Volume GUID is named by that GUID, which lives in the root directory and so needs elevation to read: Apple reports it, while Linux and Windows report the UUID derived from the serial they can see (`exfat.util -s` stamps such a volume; no format tool writes one by default);
- an **exFAT** volume mounted through `exfat-fuse` as bare `fuseblk` does not prove its own format — that name is shared with ntfs-3g and every other block-backed FUSE helper — so its serial is reported as `Serial32` rather than run through a derivation that may not be its. A FUSE mount that publishes its subtype (`fuse.exfat`) does prove it, and agrees with the kernel driver.

See the [`VolumeIdentity`](https://docs.rs/whichdisk/latest/whichdisk/enum.VolumeIdentity.html) docs for the derivations and the full table. A zero serial and the nil UUID are never identities: they record the absence of one, on every platform.

On Linux the answer is only ever as fresh as udev's links, which is what `Published` says out loud. udev re-points `/dev/disk/by-uuid` from a uevent, so in the instant between new media appearing under a device node and udev catching up, the departed volume's name still resolves to that node — and a resolve landing inside that window reports the identity that left. The window is transient and closes itself: nothing caches the answer, so the next call reads the directory again. Two cheap checks narrow it further — a published name of a width the mount's own filesystem cannot carry (a UUID on a `vfat` mount, a FAT serial on `ntfs`) is not that volume's and is refused, and where two names resolve to one device node, neither is reported. Settling it outright would mean reading the superblock, which needs a raw device handle and so elevation; this crate does not take one. A caller that cannot afford to act on a name that may have lagged does not have to guess at any of this: it asks for `Vouched` and gets nothing here.

## Performance

- **No cache** — nothing kernel-derived is remembered between calls, on any platform. No key a cache could be held under can vouch that what it names is still the mount or the volume an entry describes: `st_dev` names a mount session the kernel hands to the next mount, Linux's unique mount id names the mount object and not where it is attached, and a Windows volume GUID names durable storage while the serial is a value in the filesystem written onto it. So every resolve reads the kernel again
- **What that costs** — on Linux, a `/dev/disk/by-uuid` scan, and only for a mount whose source is a device node, and a fresh `/dev/disk/by-uuid` scan for each row whose removal answer is asked, since it is read after that row's attach is taken — and, for a filesystem that names no identity, a `/dev/disk/by-diskseq` scan and fresh `by-uuid` and `by-label` scans per row: measured at ~39 µs against 8 published names and ~107 µs against 24 (a Linux 6.4 container on an Apple-silicon host, `--release`), or about 4.5 µs per published name. A pseudo filesystem names itself as its own source, which the scan skips outright in ~1 ns — the hot "no identity" case costs nothing. Every resolve also reads the calling thread's `mountinfo` — ~26 µs for a 20-line file on the same host, against ~2 µs for everything else a resolve does. On Windows the same rule costs one handle-open, one final-path read that proves the handle holds a volume's root, and four volume queries per resolve, plus one `FSCTL_GET_NTFS_VOLUME_DATA` on NTFS; Apple's `fgetattrlist` reads are per resolve and per listing row
- **What the removal answer costs** — every Windows resolve of a volume on a fixed disk enumerates the present disk interfaces and opens each for no access, to find the one carrying its disk's number, and every macOS resolve whose `MNT_REMOVABLE` is clear asks `diskarbitrationd` on a session of its own; nothing is cached, by design, so a daemon that hangs stalls the resolve that asked it
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

