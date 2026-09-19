use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::Serialize;

/// Cross-platform disk/volume resolver — given a path, tells you which disk
/// it's on, its mount point, and the relative path.
#[derive(Parser)]
#[command(name = "whichdisk", version)]
struct Cli {
  #[command(subcommand)]
  command: Option<Command>,

  /// Path to resolve. Defaults to the current working directory.
  /// (Used when no subcommand is given.)
  #[arg(short, long)]
  path: Option<PathBuf>,

  /// Output format: json, yaml/yml. Omit for plain text.
  #[arg(short, long, global = true)]
  output: Option<String>,
}

#[derive(Subcommand)]
enum Command {
  /// List mounted volumes.
  #[command(alias = "l")]
  List {
    /// Skip ejectable/removable volumes.
    #[arg(long, conflicts_with = "skip_non_ejectable")]
    skip_ejectable: bool,

    /// Skip non-ejectable/non-removable volumes.
    #[arg(long, conflicts_with = "skip_ejectable")]
    skip_non_ejectable: bool,
  },
}

#[derive(Serialize)]
struct ResolveOutput {
  device: String,
  mount_point: String,
  volume_name: Option<String>,
  volume_identity: Option<String>,
  identity_assurance: Option<String>,
  is_ejectable: bool,
  relative_path: String,
  total_bytes: u64,
  available_bytes: u64,
  used_bytes: u64,
}

impl ResolveOutput {
  fn from_disk(disk: &whichdisk::PathLocation) -> Self {
    Self {
      device: disk.device().to_string_lossy().into_owned(),
      mount_point: disk.mount_point().display().to_string(),
      volume_name: disk.volume_name().map(str::to_owned),
      volume_identity: identity_text(disk.volume_identity()),
      identity_assurance: assurance_text(disk.volume_identity()),
      is_ejectable: disk.is_ejectable(),
      relative_path: disk.relative_path().display().to_string(),
      total_bytes: disk.total_bytes(),
      available_bytes: disk.available_bytes(),
      used_bytes: disk.used_bytes(),
    }
  }
}

#[derive(Serialize)]
struct MountOutput {
  device: String,
  mount_point: String,
  volume_name: Option<String>,
  volume_identity: Option<String>,
  identity_assurance: Option<String>,
  is_ejectable: bool,
  total_bytes: u64,
  available_bytes: u64,
  used_bytes: u64,
}

impl MountOutput {
  fn from_mount(m: &whichdisk::MountPoint) -> Self {
    Self {
      device: m.device().to_string_lossy().into_owned(),
      mount_point: m.mount_point().display().to_string(),
      volume_name: m.volume_name().map(str::to_owned),
      volume_identity: identity_text(m.volume_identity()),
      identity_assurance: assurance_text(m.volume_identity()),
      is_ejectable: m.is_ejectable(),
      total_bytes: m.total_bytes(),
      available_bytes: m.available_bytes(),
      used_bytes: m.used_bytes(),
    }
  }
}

/// The volume's durable identity, in the spelling the type itself prints —
/// a UUID in its canonical form, a FAT-class serial in its two halves, an NTFS
/// serial in its sixteen digits. `None` where the platform or the filesystem
/// reports no identity, which is not a failure to look.
fn identity_text(reading: Option<whichdisk::IdentityReading>) -> Option<String> {
  reading.map(|reading| reading.identity().to_string())
}

/// How that identity was read, which is a fact about the answer rather than
/// about the volume: `vouched` is the mounted filesystem answering for itself,
/// `published` is a name the platform published about a device.
fn assurance_text(reading: Option<whichdisk::IdentityReading>) -> Option<String> {
  reading.map(|reading| {
    match reading.assurance() {
      whichdisk::IdentityAssurance::Vouched => "vouched",
      whichdisk::IdentityAssurance::Published => "published",
    }
    .to_owned()
  })
}

/// An optional value in the plain output: quoted where there is one, and the
/// bare word `none` where there is not, so that the two never read alike.
fn plain(value: Option<&str>) -> String {
  match value {
    Some(value) => format!("\"{value}\""),
    None => "none".to_owned(),
  }
}

fn human_bytes(bytes: u64) -> String {
  const KIB: u64 = 1024;
  const MIB: u64 = 1024 * KIB;
  const GIB: u64 = 1024 * MIB;
  const TIB: u64 = 1024 * GIB;

  if bytes >= TIB {
    format!("{:.2} TiB", bytes as f64 / TIB as f64)
  } else if bytes >= GIB {
    format!("{:.2} GiB", bytes as f64 / GIB as f64)
  } else if bytes >= MIB {
    format!("{:.2} MiB", bytes as f64 / MIB as f64)
  } else if bytes >= KIB {
    format!("{:.2} KiB", bytes as f64 / KIB as f64)
  } else {
    format!("{bytes} B")
  }
}

fn format_resolve(out: &ResolveOutput, format: Option<&str>) -> Result<String, String> {
  match format {
    Some("json") => {
      serde_json::to_string_pretty(out).map_err(|e| format!("failed to serialize JSON: {e}"))
    }
    Some("yaml" | "yml") => {
      use yaml_rust2::{Yaml, yaml::Hash};
      let mut map = Hash::new();
      {
        let mut put = |key: &str, value: Yaml| {
          map.insert(Yaml::String(key.into()), value);
        };
        put("device", Yaml::String(out.device.clone()));
        put("mount_point", Yaml::String(out.mount_point.clone()));
        put("volume_name", yaml_text(&out.volume_name));
        put("volume_identity", yaml_text(&out.volume_identity));
        put("identity_assurance", yaml_text(&out.identity_assurance));
        put("is_ejectable", Yaml::Boolean(out.is_ejectable));
        put("relative_path", Yaml::String(out.relative_path.clone()));
        put("total_bytes", Yaml::String(out.total_bytes.to_string()));
        put(
          "available_bytes",
          Yaml::String(out.available_bytes.to_string()),
        );
        put("used_bytes", Yaml::String(out.used_bytes.to_string()));
      }
      emit_yaml(&Yaml::Hash(map))
    }
    Some(fmt) => Err(format!(
      "unknown output format '{fmt}'. Supported: json, yaml, yml"
    )),
    None => Ok(format!(
      "device=\"{}\"\nmount_point=\"{}\"\nvolume_name={}\nvolume_identity={}\nidentity_assurance={}\nejectable={}\nrelative_path=\"{}\"\ntotal={}\navailable={}\nused={}",
      out.device,
      out.mount_point,
      plain(out.volume_name.as_deref()),
      plain(out.volume_identity.as_deref()),
      plain(out.identity_assurance.as_deref()),
      out.is_ejectable,
      out.relative_path,
      human_bytes(out.total_bytes),
      human_bytes(out.available_bytes),
      human_bytes(out.used_bytes),
    )),
  }
}

fn format_list(mounts: &[MountOutput], format: Option<&str>) -> Result<String, String> {
  match format {
    Some("json") => {
      serde_json::to_string_pretty(mounts).map_err(|e| format!("failed to serialize JSON: {e}"))
    }
    Some("yaml" | "yml") => {
      use yaml_rust2::{Yaml, yaml::Hash};
      let docs: Vec<Yaml> = mounts
        .iter()
        .map(|m| {
          let mut map = Hash::new();
          map.insert(
            Yaml::String("device".into()),
            Yaml::String(m.device.clone()),
          );
          map.insert(
            Yaml::String("mount_point".into()),
            Yaml::String(m.mount_point.clone()),
          );
          map.insert(
            Yaml::String("volume_name".into()),
            yaml_text(&m.volume_name),
          );
          map.insert(
            Yaml::String("volume_identity".into()),
            yaml_text(&m.volume_identity),
          );
          map.insert(
            Yaml::String("identity_assurance".into()),
            yaml_text(&m.identity_assurance),
          );
          map.insert(
            Yaml::String("is_ejectable".into()),
            Yaml::Boolean(m.is_ejectable),
          );
          map.insert(
            Yaml::String("total_bytes".into()),
            Yaml::String(m.total_bytes.to_string()),
          );
          map.insert(
            Yaml::String("available_bytes".into()),
            Yaml::String(m.available_bytes.to_string()),
          );
          map.insert(
            Yaml::String("used_bytes".into()),
            Yaml::String(m.used_bytes.to_string()),
          );
          Yaml::Hash(map)
        })
        .collect();
      emit_yaml(&Yaml::Array(docs))
    }
    Some(fmt) => Err(format!(
      "unknown output format '{fmt}'. Supported: json, yaml, yml"
    )),
    None => {
      let mut lines = Vec::new();
      for m in mounts {
        lines.push(format!(
          "mount_point=\"{}\" volume_name={} device=\"{}\" volume_identity={} \
           identity_assurance={} ejectable={} total={} available={} used={}",
          m.mount_point,
          plain(m.volume_name.as_deref()),
          m.device,
          plain(m.volume_identity.as_deref()),
          plain(m.identity_assurance.as_deref()),
          m.is_ejectable,
          human_bytes(m.total_bytes),
          human_bytes(m.available_bytes),
          human_bytes(m.used_bytes),
        ));
      }
      Ok(lines.join("\n"))
    }
  }
}

/// A value for the YAML output: the string where there is one, and YAML's own
/// null where there is not — `""` would read as a volume named nothing.
fn yaml_text(value: &Option<String>) -> yaml_rust2::Yaml {
  match value {
    Some(value) => yaml_rust2::Yaml::String(value.clone()),
    None => yaml_rust2::Yaml::Null,
  }
}

fn emit_yaml(doc: &yaml_rust2::Yaml) -> Result<String, String> {
  let mut buf = String::new();
  yaml_rust2::YamlEmitter::new(&mut buf)
    .dump(doc)
    .map_err(|e| format!("failed to serialize YAML: {e}"))?;
  Ok(buf.strip_prefix("---\n").unwrap_or(&buf).to_string())
}

fn run(cli: Cli) -> Result<String, String> {
  match cli.command {
    Some(Command::List {
      skip_ejectable,
      skip_non_ejectable,
    }) => {
      let opts = whichdisk::ListOptions::all()
        .set_non_ejectable_only(skip_ejectable)
        .set_ejectable_only(skip_non_ejectable);
      let mounts = whichdisk::list_with(opts).map_err(|e| e.to_string())?;
      let out: Vec<MountOutput> = mounts.iter().map(MountOutput::from_mount).collect();
      format_list(&out, cli.output.as_deref())
    }
    None => {
      let path = match &cli.path {
        Some(p) => p.clone(),
        None => {
          std::env::current_dir().map_err(|e| format!("failed to get current directory: {e}"))?
        }
      };
      let disk = whichdisk::resolve(&path).map_err(|e| e.to_string())?;
      let out = ResolveOutput::from_disk(&disk);
      format_resolve(&out, cli.output.as_deref())
    }
  }
}

fn main() {
  let cli = Cli::parse();
  match run(cli) {
    Ok(output) => println!("{output}"),
    Err(e) => {
      eprintln!("error: {e}");
      std::process::exit(1);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_resolve_output() -> ResolveOutput {
    ResolveOutput {
      device: "/dev/sda1".into(),
      mount_point: "/".into(),
      volume_name: Some("BACKUP".into()),
      volume_identity: Some("8f19a253-d450-3090-abf6-e651943998d1".into()),
      identity_assurance: Some("published".into()),
      is_ejectable: false,
      relative_path: "home/user".into(),
      total_bytes: 500_000_000_000,
      available_bytes: 200_000_000_000,
      used_bytes: 300_000_000_000,
    }
  }

  fn root_path() -> PathBuf {
    if cfg!(windows) {
      PathBuf::from("C:\\")
    } else {
      PathBuf::from("/")
    }
  }

  // ── format_resolve tests ──────────────────────────────────────────

  #[test]
  fn test_format_resolve_plain() {
    let out = make_resolve_output();
    let result = format_resolve(&out, None).unwrap();
    assert!(result.contains("device=\"/dev/sda1\""));
    assert!(result.contains("mount_point=\"/\""));
    assert!(result.contains("relative_path=\"home/user\""));
    assert!(result.contains("volume_name=\"BACKUP\""));
    assert!(result.contains("volume_identity=\"8f19a253-d450-3090-abf6-e651943998d1\""));
    assert!(result.contains("identity_assurance=\"published\""));
    assert!(result.contains("ejectable=false"));
    assert!(result.contains("total="));
    assert!(result.contains("GiB"));
  }

  /// A volume the platform reports no identity for says so in a word no value
  /// can be confused with, rather than printing an empty pair of quotes.
  #[test]
  fn test_format_resolve_plain_without_an_identity() {
    let mut out = make_resolve_output();
    out.volume_identity = None;
    out.identity_assurance = None;
    let result = format_resolve(&out, None).unwrap();
    assert!(result.contains("volume_identity=none"));
    assert!(result.contains("identity_assurance=none"));
  }

  #[test]
  fn test_format_resolve_json() {
    let out = make_resolve_output();
    let result = format_resolve(&out, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["device"], "/dev/sda1");
    assert_eq!(parsed["mount_point"], "/");
    assert_eq!(parsed["relative_path"], "home/user");
    assert_eq!(parsed["volume_name"], "BACKUP");
    assert_eq!(
      parsed["volume_identity"],
      "8f19a253-d450-3090-abf6-e651943998d1"
    );
    assert_eq!(parsed["identity_assurance"], "published");
    assert_eq!(parsed["is_ejectable"], false);
  }

  /// JSON carries "no identity" as null — the absence of a value, not the empty
  /// string, which would read as a volume whose identity is nothing.
  #[test]
  fn test_format_resolve_json_without_an_identity() {
    let mut out = make_resolve_output();
    out.volume_identity = None;
    out.identity_assurance = None;
    out.volume_name = None;
    let result = format_resolve(&out, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed["volume_identity"].is_null());
    assert!(parsed["identity_assurance"].is_null());
    assert!(parsed["volume_name"].is_null());
  }

  #[test]
  fn test_format_resolve_yaml() {
    let out = make_resolve_output();
    let result = format_resolve(&out, Some("yaml")).unwrap();
    assert!(result.contains("device: /dev/sda1"));
    assert!(!result.starts_with("---"));
  }

  #[test]
  fn test_format_resolve_yml() {
    let out = make_resolve_output();
    let result = format_resolve(&out, Some("yml")).unwrap();
    assert!(result.contains("device: /dev/sda1"));
  }

  #[test]
  fn test_format_resolve_unknown() {
    let out = make_resolve_output();
    let result = format_resolve(&out, Some("xml"));
    assert!(result.unwrap_err().contains("unknown output format"));
  }

  // ── format_list tests ─────────────────────────────────────────────

  fn make_mount_output() -> MountOutput {
    MountOutput {
      device: "/dev/sda1".into(),
      mount_point: "/".into(),
      volume_name: Some("BACKUP".into()),
      volume_identity: Some("8f19a253-d450-3090-abf6-e651943998d1".into()),
      identity_assurance: Some("published".into()),
      is_ejectable: false,
      total_bytes: 500_000_000_000,
      available_bytes: 200_000_000_000,
      used_bytes: 300_000_000_000,
    }
  }

  #[test]
  fn test_format_list_plain() {
    let mounts = vec![make_mount_output()];
    let result = format_list(&mounts, None).unwrap();
    assert!(result.contains("mount_point=\"/\""));
    assert!(result.contains("device=\"/dev/sda1\""));
    assert!(result.contains("volume_name=\"BACKUP\""));
    assert!(result.contains("volume_identity=\"8f19a253-d450-3090-abf6-e651943998d1\""));
    assert!(result.contains("identity_assurance=\"published\""));
    assert!(result.contains("ejectable=false"));
    assert!(result.contains("GiB"));
  }

  #[test]
  fn test_format_list_json() {
    let mut m = make_mount_output();
    m.device = "/dev/sdb1".into();
    m.mount_point = "/mnt/usb".into();
    m.is_ejectable = true;
    let mounts = vec![m];
    let result = format_list(&mounts, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed[0]["is_ejectable"].as_bool().unwrap());
    assert!(parsed[0]["total_bytes"].is_u64());
    assert_eq!(parsed[0]["volume_name"], "BACKUP");
    assert_eq!(
      parsed[0]["volume_identity"],
      "8f19a253-d450-3090-abf6-e651943998d1"
    );
    assert_eq!(parsed[0]["identity_assurance"], "published");
  }

  #[test]
  fn test_format_list_yaml() {
    let mounts = vec![make_mount_output()];
    let result = format_list(&mounts, Some("yaml")).unwrap();
    assert!(result.contains("device: /dev/sda1"));
    assert!(result.contains("volume_name: BACKUP"));
    assert!(result.contains("volume_identity: 8f19a253-d450-3090-abf6-e651943998d1"));
  }

  /// A row with nothing to report carries YAML's null rather than an empty
  /// string, for the same reason the JSON one does.
  #[test]
  fn test_format_list_yaml_without_an_identity() {
    let mut mount = make_mount_output();
    mount.volume_identity = None;
    mount.identity_assurance = None;
    let result = format_list(&[mount], Some("yaml")).unwrap();
    assert!(result.contains("volume_identity: ~"), "{result}");
  }

  #[test]
  fn test_format_list_unknown() {
    let result = format_list(&[], Some("toml"));
    assert!(result.unwrap_err().contains("unknown output format"));
  }

  // ── run tests ─────────────────────────────────────────────────────

  #[test]
  fn test_run_resolve_default() {
    let cli = Cli {
      command: None,
      path: None,
      output: None,
    };
    let result = run(cli).unwrap();
    assert!(result.contains("device="));
  }

  #[test]
  fn test_run_resolve_with_path() {
    let cli = Cli {
      command: None,
      path: Some(root_path()),
      output: Some("json".into()),
    };
    let result = run(cli).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed["mount_point"].is_string());
    assert!(parsed["device"].is_string());
    assert!(parsed["relative_path"].is_string());
  }

  #[test]
  fn test_run_resolve_nonexistent() {
    let bad = if cfg!(windows) {
      PathBuf::from("Z:\\nonexistent\\path\\xyz")
    } else {
      PathBuf::from("/nonexistent/path/xyz")
    };
    let cli = Cli {
      command: None,
      path: Some(bad),
      output: None,
    };
    assert!(run(cli).is_err());
  }

  #[test]
  fn test_run_resolve_bad_format() {
    let cli = Cli {
      command: None,
      path: Some(root_path()),
      output: Some("toml".into()),
    };
    assert!(run(cli).unwrap_err().contains("unknown output format"));
  }

  #[test]
  fn test_run_list() {
    let cli = Cli {
      command: Some(Command::List {
        skip_ejectable: false,
        skip_non_ejectable: false,
      }),
      path: None,
      output: None,
    };
    let result = run(cli).unwrap();
    assert!(result.contains("mount_point="));
    assert!(result.contains("device="));
  }

  #[test]
  fn test_run_list_ejectable_only() {
    let cli = Cli {
      command: Some(Command::List {
        skip_ejectable: false,
        skip_non_ejectable: true,
      }),
      path: None,
      output: None,
    };
    // Should succeed even if no ejectable volumes exist.
    let _ = run(cli).unwrap();
  }

  #[test]
  fn test_run_list_json() {
    let cli = Cli {
      command: Some(Command::List {
        skip_ejectable: false,
        skip_non_ejectable: false,
      }),
      path: None,
      output: Some("json".into()),
    };
    let result = run(cli).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed.is_array());
  }

  #[test]
  fn test_output_from_disk() {
    let disk = whichdisk::resolve(root_path()).unwrap();
    let out = ResolveOutput::from_disk(&disk);
    assert!(!out.device.is_empty());
    assert!(!out.mount_point.is_empty());
    // Whatever the library knows about this volume, the output carries it.
    assert_eq!(out.volume_name.as_deref(), disk.volume_name());
    assert_eq!(out.volume_identity, identity_text(disk.volume_identity()));
    assert_eq!(out.is_ejectable, disk.is_ejectable());
    assert!(
      out
        .volume_name
        .as_deref()
        .is_some_and(|name| !name.is_empty()),
      "every volume has a name: {out:?}",
      out = out.volume_name
    );
  }
}
