#![cfg(feature = "cli")]

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
  Command::cargo_bin("whichdisk").unwrap()
}

/// Returns a known-valid root path and its expected mount point for the current OS.
fn root_path() -> &'static str {
  if cfg!(windows) { "C:\\" } else { "/" }
}

#[test]
fn test_cli_default() {
  cmd()
    .assert()
    .success()
    .stdout(predicate::str::contains("device="))
    .stdout(predicate::str::contains("mount_point="))
    .stdout(predicate::str::contains("relative_path="));
}

#[test]
fn test_cli_with_path() {
  cmd()
    .args(["-p", root_path()])
    .assert()
    .success()
    .stdout(predicate::str::contains("mount_point="));
}

#[test]
fn test_cli_json() {
  let output = cmd()
    .args(["-p", root_path(), "-o", "json"])
    .assert()
    .success();
  // Validate that the output is parseable JSON with the required keys.
  let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
  let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
  assert!(parsed["device"].is_string());
  assert!(parsed["mount_point"].is_string());
  assert!(parsed["relative_path"].is_string());
}

#[test]
fn test_cli_yaml() {
  cmd()
    .args(["-p", root_path(), "-o", "yaml"])
    .assert()
    .success()
    .stdout(predicate::str::contains("device:"))
    .stdout(predicate::str::contains("mount_point:"));
}

#[test]
fn test_cli_yml() {
  cmd()
    .args(["-p", root_path(), "-o", "yml"])
    .assert()
    .success()
    .stdout(predicate::str::contains("device:"));
}

#[test]
fn test_cli_unknown_format() {
  cmd()
    .args(["-p", root_path(), "-o", "xml"])
    .assert()
    .failure()
    .stderr(predicate::str::contains("unknown output format"));
}

#[test]
fn test_cli_nonexistent_path() {
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
