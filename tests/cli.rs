#![cfg(feature = "cli")]

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
  Command::cargo_bin("whichdisk").unwrap()
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
    .args(["-p", "/"])
    .assert()
    .success()
    .stdout(predicate::str::contains("mount_point=\"/\""));
}

#[test]
fn test_cli_json() {
  cmd()
    .args(["-p", "/", "-o", "json"])
    .assert()
    .success()
    .stdout(predicate::str::contains("\"mount_point\": \"/\""));
}

#[test]
fn test_cli_yaml() {
  cmd()
    .args(["-p", "/", "-o", "yaml"])
    .assert()
    .success()
    .stdout(predicate::str::contains("mount_point: /"));
}

#[test]
fn test_cli_yml() {
  cmd()
    .args(["-p", "/", "-o", "yml"])
    .assert()
    .success()
    .stdout(predicate::str::contains("mount_point: /"));
}

#[test]
fn test_cli_unknown_format() {
  cmd()
    .args(["-p", "/", "-o", "xml"])
    .assert()
    .failure()
    .stderr(predicate::str::contains("unknown output format"));
}

#[test]
fn test_cli_nonexistent_path() {
  cmd()
    .args(["-p", "/nonexistent/path/xyz"])
    .assert()
    .failure()
    .stderr(predicate::str::contains("error:"));
}
