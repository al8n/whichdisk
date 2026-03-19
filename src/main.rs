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
  #[arg(short, long, global = true)]
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
    /// Only list ejectable/removable volumes.
    #[arg(long)]
    ejectable_only: bool,
  },
}

#[derive(Serialize)]
struct ResolveOutput {
  device: String,
  mount_point: String,
  relative_path: String,
}

impl ResolveOutput {
  fn from_disk(disk: &whichdisk::FileDiskInfo) -> Self {
    Self {
      device: disk.device().to_string_lossy().into_owned(),
      mount_point: disk.mount_point().display().to_string(),
      relative_path: disk.relative_path().display().to_string(),
    }
  }
}

#[derive(Serialize)]
struct MountOutput {
  device: String,
  mount_point: String,
  is_ejectable: bool,
}

impl MountOutput {
  fn from_mount(m: &whichdisk::MountPoint) -> Self {
    Self {
      device: m.device().to_string_lossy().into_owned(),
      mount_point: m.mount_point().display().to_string(),
      is_ejectable: m.is_ejectable(),
    }
  }
}

fn format_resolve(out: &ResolveOutput, format: Option<&str>) -> Result<String, String> {
  match format {
    Some("json") => {
      serde_json::to_string_pretty(out).map_err(|e| format!("failed to serialize JSON: {e}"))
    }
    Some("yaml" | "yml") => yaml_from_pairs(&[
      ("device", &out.device),
      ("mount_point", &out.mount_point),
      ("relative_path", &out.relative_path),
    ]),
    Some(fmt) => Err(format!(
      "unknown output format '{fmt}'. Supported: json, yaml, yml"
    )),
    None => Ok(format!(
      "device=\"{}\"\nmount_point=\"{}\"\nrelative_path=\"{}\"",
      out.device, out.mount_point, out.relative_path
    )),
  }
}

fn format_list(mounts: &[MountOutput], format: Option<&str>) -> Result<String, String> {
  match format {
    Some("json") => {
      serde_json::to_string_pretty(mounts).map_err(|e| format!("failed to serialize JSON: {e}"))
    }
    Some("yaml" | "yml") => {
      use yaml_rust2::{Yaml, YamlEmitter, yaml::Hash};
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
            Yaml::String("is_ejectable".into()),
            Yaml::Boolean(m.is_ejectable),
          );
          Yaml::Hash(map)
        })
        .collect();
      let doc = Yaml::Array(docs);
      let mut buf = String::new();
      YamlEmitter::new(&mut buf)
        .dump(&doc)
        .map_err(|e| format!("failed to serialize YAML: {e}"))?;
      Ok(buf.strip_prefix("---\n").unwrap_or(&buf).to_string())
    }
    Some(fmt) => Err(format!(
      "unknown output format '{fmt}'. Supported: json, yaml, yml"
    )),
    None => {
      let mut lines = Vec::new();
      for m in mounts {
        lines.push(format!(
          "mount_point=\"{}\" device=\"{}\"",
          m.mount_point, m.device
        ));
      }
      Ok(lines.join("\n"))
    }
  }
}

fn yaml_from_pairs(pairs: &[(&str, &str)]) -> Result<String, String> {
  use yaml_rust2::{Yaml, YamlEmitter, yaml::Hash};
  let mut map = Hash::new();
  for (k, v) in pairs {
    map.insert(Yaml::String((*k).into()), Yaml::String((*v).into()));
  }
  let doc = Yaml::Hash(map);
  let mut buf = String::new();
  YamlEmitter::new(&mut buf)
    .dump(&doc)
    .map_err(|e| format!("failed to serialize YAML: {e}"))?;
  Ok(buf.strip_prefix("---\n").unwrap_or(&buf).to_string())
}

fn run(cli: Cli) -> Result<String, String> {
  match cli.command {
    Some(Command::List { ejectable_only }) => {
      let opts = whichdisk::ListOptions::all().set_ejectable_only(ejectable_only);
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
      relative_path: "home/user".into(),
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
  }

  #[test]
  fn test_format_resolve_json() {
    let out = make_resolve_output();
    let result = format_resolve(&out, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["device"], "/dev/sda1");
    assert_eq!(parsed["mount_point"], "/");
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

  #[test]
  fn test_format_list_plain() {
    let mounts = vec![MountOutput {
      device: "/dev/sda1".into(),
      mount_point: "/".into(),
      is_ejectable: false,
    }];
    let result = format_list(&mounts, None).unwrap();
    assert!(result.contains("mount_point=\"/\" device=\"/dev/sda1\""));
  }

  #[test]
  fn test_format_list_json() {
    let mounts = vec![MountOutput {
      device: "/dev/sdb1".into(),
      mount_point: "/mnt/usb".into(),
      is_ejectable: true,
    }];
    let result = format_list(&mounts, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed[0]["is_ejectable"].as_bool().unwrap());
  }

  #[test]
  fn test_format_list_yaml() {
    let mounts = vec![MountOutput {
      device: "/dev/sda1".into(),
      mount_point: "/".into(),
      is_ejectable: false,
    }];
    let result = format_list(&mounts, Some("yaml")).unwrap();
    assert!(result.contains("device: /dev/sda1"));
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
        ejectable_only: false,
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
        ejectable_only: true,
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
        ejectable_only: false,
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
  }
}
