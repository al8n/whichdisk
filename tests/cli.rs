#![cfg(feature = "cli")]

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
  Command::cargo_bin("whichdisk").unwrap()
}

fn root_path() -> &'static str {
  if cfg!(windows) { "C:\\" } else { "/" }
}

// ── resolve (default, no subcommand) ────────────────────────────────

#[test]
fn test_cli_resolve_default() {
  cmd()
    .assert()
    .success()
    .stdout(predicate::str::contains("device="))
    .stdout(predicate::str::contains("mount_point="))
    .stdout(predicate::str::contains("relative_path="));
}

#[test]
fn test_cli_resolve_with_path() {
  cmd()
    .args(["-p", root_path()])
    .assert()
    .success()
    .stdout(predicate::str::contains("mount_point="));
}

#[test]
fn test_cli_resolve_json() {
  let output = cmd()
    .args(["-p", root_path(), "-o", "json"])
    .assert()
    .success();
  let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
  let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
  assert!(parsed["device"].is_string());
  assert!(parsed["mount_point"].is_string());
  assert!(parsed["relative_path"].is_string());
}

#[test]
fn test_cli_resolve_yaml() {
  cmd()
    .args(["-p", root_path(), "-o", "yaml"])
    .assert()
    .success()
    .stdout(predicate::str::contains("device:"))
    .stdout(predicate::str::contains("mount_point:"));
}

#[test]
fn test_cli_resolve_unknown_format() {
  cmd()
    .args(["-p", root_path(), "-o", "xml"])
    .assert()
    .failure()
    .stderr(predicate::str::contains("unknown output format"));
}

#[test]
fn test_cli_resolve_nonexistent_path() {
  let bad_path = if cfg!(windows) {
    "Z:\\nonexistent\\path\\xyz"
  } else {
    "/nonexistent/path/xyz"
  };
  cmd()
    .args(["-p", bad_path])
    .assert()
    .failure()
    .stderr(predicate::str::contains("error:"));
}

// ── list subcommand ─────────────────────────────────────────────────

#[test]
fn test_cli_list() {
  cmd()
    .arg("list")
    .assert()
    .success()
    .stdout(predicate::str::contains("mount_point="))
    .stdout(predicate::str::contains("device="));
}

#[test]
fn test_cli_list_alias() {
  cmd()
    .arg("l")
    .assert()
    .success()
    .stdout(predicate::str::contains("mount_point="));
}

#[test]
fn test_cli_list_skip_non_ejectable() {
  // Should succeed even if no ejectable volumes exist (empty output).
  cmd()
    .args(["list", "--skip-non-ejectable"])
    .assert()
    .success();
}

#[test]
fn test_cli_list_skip_ejectable() {
  cmd().args(["list", "--skip-ejectable"]).assert().success();
}

#[test]
fn test_cli_list_json() {
  let output = cmd().args(["list", "-o", "json"]).assert().success();
  let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
  let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
  assert!(parsed.is_array());
}

#[test]
fn test_cli_list_yaml() {
  cmd().args(["list", "-o", "yaml"]).assert().success();
}

// ── what the binary prints about the volume ─────────────────────────

/// The binary prints what the library knows about the volume it resolved: the
/// volume's durable identity, its name, and whether it is ejectable. 0.6.0 gave
/// the library an identity and left the CLI unable to print one; this law keeps
/// the two together, by comparing the spawned binary's output against the same
/// question asked in-process.
#[test]
fn test_cli_resolve_prints_identity_name_and_ejectable() {
  let disk = whichdisk::resolve(root_path()).unwrap();
  let name = disk.volume_name().expect("the root volume has a name");
  assert!(!name.is_empty());

  let assert = cmd().args(["-p", root_path()]).assert().success();
  let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

  assert!(
    stdout.contains(&format!("volume_name=\"{name}\"")),
    "{stdout}"
  );
  match disk.volume_identity() {
    Some(reading) => {
      let identity = reading.identity().to_string();
      assert!(!identity.is_empty());
      assert!(
        stdout.contains(&format!("volume_identity=\"{identity}\"")),
        "{stdout}"
      );
    }
    // A platform that reports no identity says so in a word, not in empty
    // quotes — and never silently omits the row.
    None => assert!(stdout.contains("volume_identity=none"), "{stdout}"),
  }
  assert!(
    stdout.contains(&format!("is_ejectable={}", disk.is_ejectable())),
    "{stdout}"
  );
}

#[test]
fn test_cli_resolve_json_carries_identity_and_name() {
  let disk = whichdisk::resolve(root_path()).unwrap();

  let assert = cmd()
    .args(["-p", root_path(), "-o", "json"])
    .assert()
    .success();
  let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
  let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

  assert_eq!(parsed["volume_name"].as_str(), disk.volume_name());
  assert_eq!(parsed["is_ejectable"].as_bool(), Some(disk.is_ejectable()));
  match disk.volume_identity() {
    Some(reading) => {
      assert_eq!(
        parsed["volume_identity"].as_str(),
        Some(reading.identity().to_string().as_str())
      );
      assert!(parsed["identity_assurance"].is_string());
    }
    None => {
      assert!(parsed["volume_identity"].is_null());
      assert!(parsed["identity_assurance"].is_null());
    }
  }
}

/// Every listed row carries the same three, so that a listing and a resolve
/// answer with the same facts about one volume.
#[test]
fn test_cli_list_rows_carry_identity_name_and_ejectable() {
  let assert = cmd().arg("list").assert().success();
  let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

  for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
    assert!(line.contains("volume_name="), "{line}");
    assert!(line.contains("volume_identity="), "{line}");
    assert!(line.contains("is_ejectable="), "{line}");
  }
}
