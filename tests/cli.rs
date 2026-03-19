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
fn test_cli_list_ejectable_only() {
  // Should succeed even if no ejectable volumes exist (empty output).
  cmd().args(["list", "--ejectable-only"]).assert().success();
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
