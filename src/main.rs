use std::path::PathBuf;

use clap::Parser;
use serde::Serialize;

/// Cross-platform disk/volume resolver — given a path, tells you which disk
/// it's on, its mount point, and the relative path.
#[derive(Parser)]
#[command(name = "whichdisk", version)]
struct Cli {
  /// Path to resolve. Defaults to the current working directory.
  #[arg(short, long)]
  path: Option<PathBuf>,

  /// Output format: json, yaml/yml. Omit for plain text.
  #[arg(short, long)]
  output: Option<String>,
}

#[derive(Serialize)]
struct Output {
  device: String,
  mount_point: String,
  relative_path: String,
}

impl Output {
  fn from_disk(disk: &whichdisk::Disk) -> Self {
    Self {
      device: disk.device().to_string_lossy().into_owned(),
      mount_point: disk.mount_point().display().to_string(),
      relative_path: disk.relative_path().display().to_string(),
    }
  }
}

fn format_output(out: &Output, format: Option<&str>) -> Result<String, String> {
  match format {
    Some("json") => {
      serde_json::to_string_pretty(out).map_err(|e| format!("failed to serialize JSON: {e}"))
    }
    Some("yaml" | "yml") => {
      use yaml_rust2::{Yaml, YamlEmitter, yaml::Hash};
      let mut map = Hash::new();
      map.insert(
        Yaml::String("device".into()),
        Yaml::String(out.device.clone()),
      );
      map.insert(
        Yaml::String("mount_point".into()),
        Yaml::String(out.mount_point.clone()),
      );
      map.insert(
        Yaml::String("relative_path".into()),
        Yaml::String(out.relative_path.clone()),
      );
      let doc = Yaml::Hash(map);
      let mut buf = String::new();
      YamlEmitter::new(&mut buf)
        .dump(&doc)
        .map_err(|e| format!("failed to serialize YAML: {e}"))?;
      Ok(buf.strip_prefix("---\n").unwrap_or(&buf).to_string())
    }
    Some(fmt) => Err(format!(
      "unknown output format '{fmt}'. Supported: json, yaml, yml"
    )),
    None => Ok(format!(
      "device=\"{}\"\nmount_point=\"{}\"\nrelative_path=\"{}\"",
      out.device, out.mount_point, out.relative_path
    )),
  }
}

fn run(cli: Cli) -> Result<String, String> {
  let path = match &cli.path {
    Some(p) => p.clone(),
    None => std::env::current_dir().map_err(|e| format!("failed to get current directory: {e}"))?,
  };

  let disk = whichdisk::which_disk(&path).map_err(|e| e.to_string())?;
  let out = Output::from_disk(&disk);
  format_output(&out, cli.output.as_deref())
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

  fn make_output() -> Output {
    Output {
      device: "/dev/sda1".into(),
      mount_point: "/".into(),
      relative_path: "home/user".into(),
    }
  }

  #[test]
  fn test_format_plain() {
    let out = make_output();
    let result = format_output(&out, None).unwrap();
    assert!(result.contains("device=\"/dev/sda1\""));
    assert!(result.contains("mount_point=\"/\""));
    assert!(result.contains("relative_path=\"home/user\""));
  }

  #[test]
  fn test_format_json() {
    let out = make_output();
    let result = format_output(&out, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["device"], "/dev/sda1");
    assert_eq!(parsed["mount_point"], "/");
    assert_eq!(parsed["relative_path"], "home/user");
  }

  #[test]
  fn test_format_yaml() {
    let out = make_output();
    let result = format_output(&out, Some("yaml")).unwrap();
    assert!(result.contains("device: /dev/sda1"));
    assert!(result.contains("mount_point: /"));
    assert!(result.contains("relative_path: home/user"));
    assert!(!result.starts_with("---"), "should strip YAML header");
  }

  #[test]
  fn test_format_yml() {
    let out = make_output();
    let result = format_output(&out, Some("yml")).unwrap();
    assert!(result.contains("device: /dev/sda1"));
  }

  #[test]
  fn test_format_unknown() {
    let out = make_output();
    let result = format_output(&out, Some("xml"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("unknown output format 'xml'"));
  }

  #[test]
  fn test_run_default_path() {
    let cli = Cli {
      path: None,
      output: None,
    };
    let result = run(cli);
    assert!(result.is_ok());
    let text = result.unwrap();
    assert!(text.contains("device="));
    assert!(text.contains("mount_point="));
    assert!(text.contains("relative_path="));
  }

  fn root_path() -> PathBuf {
    if cfg!(windows) {
      PathBuf::from("C:\\")
    } else {
      PathBuf::from("/")
    }
  }

  #[test]
  fn test_run_explicit_path() {
    let cli = Cli {
      path: Some(root_path()),
      output: Some("json".into()),
    };
    let result = run(cli).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed["mount_point"].is_string());
    assert!(parsed["device"].is_string());
  }

  #[test]
  fn test_run_nonexistent_path() {
    let bad = if cfg!(windows) {
      PathBuf::from("Z:\\nonexistent\\path\\xyz")
    } else {
      PathBuf::from("/nonexistent/path/xyz")
    };
    let cli = Cli {
      path: Some(bad),
      output: None,
    };
    let result = run(cli);
    assert!(result.is_err());
  }

  #[test]
  fn test_run_bad_format() {
    let cli = Cli {
      path: Some(root_path()),
      output: Some("toml".into()),
    };
    let result = run(cli);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("unknown output format"));
  }

  #[test]
  fn test_output_from_disk() {
    let disk = whichdisk::which_disk(root_path()).unwrap();
    let out = Output::from_disk(&disk);
    assert!(!out.device.is_empty());
    assert!(!out.mount_point.is_empty());
  }
}
