use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::ser::{Serialize, SerializeMap, Serializer};

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
    /// Skip volumes the platform says are ejectable. Volumes whose
    /// ejectability it could not determine are kept.
    #[arg(long, conflicts_with = "skip_non_ejectable")]
    skip_ejectable: bool,

    /// Skip volumes the platform says are not ejectable. Volumes whose
    /// ejectability it could not determine are kept.
    #[arg(long, conflicts_with = "skip_ejectable")]
    skip_non_ejectable: bool,
  },
}

struct ResolveOutput {
  device: String,
  mount_point: String,
  volume_name: Option<String>,
  volume_name_assurance: Option<String>,
  volume_identity: Option<String>,
  identity_assurance: Option<String>,
  ejectability: String,
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
      volume_name_assurance: disk
        .volume_name_assurance()
        .map(|assurance| assurance_word(assurance).to_owned()),
      volume_identity: identity_text(disk.volume_identity()),
      identity_assurance: assurance_text(disk.volume_identity()),
      ejectability: ejectability_word(disk.ejectability()).to_owned(),
      relative_path: disk.relative_path().display().to_string(),
      total_bytes: disk.total_bytes(),
      available_bytes: disk.available_bytes(),
      used_bytes: disk.used_bytes(),
    }
  }

  /// This record's roster: every field it prints, named once and in the one
  /// order all three formats print them in.
  fn fields(&self) -> Record<'_> {
    vec![
      ("device", Field::Text(&self.device)),
      ("mount_point", Field::Text(&self.mount_point)),
      ("volume_name", Field::MaybeText(self.volume_name.as_deref())),
      (
        "volume_name_assurance",
        Field::MaybeText(self.volume_name_assurance.as_deref()),
      ),
      (
        "volume_identity",
        Field::MaybeText(self.volume_identity.as_deref()),
      ),
      (
        "identity_assurance",
        Field::MaybeText(self.identity_assurance.as_deref()),
      ),
      ("ejectability", Field::Text(&self.ejectability)),
      ("relative_path", Field::Text(&self.relative_path)),
      ("total_bytes", Field::Bytes(self.total_bytes)),
      ("available_bytes", Field::Bytes(self.available_bytes)),
      ("used_bytes", Field::Bytes(self.used_bytes)),
    ]
  }
}

struct MountOutput {
  device: String,
  mount_point: String,
  volume_name: Option<String>,
  volume_name_assurance: Option<String>,
  volume_identity: Option<String>,
  identity_assurance: Option<String>,
  ejectability: String,
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
      volume_name_assurance: m
        .volume_name_assurance()
        .map(|assurance| assurance_word(assurance).to_owned()),
      volume_identity: identity_text(m.volume_identity()),
      identity_assurance: assurance_text(m.volume_identity()),
      ejectability: ejectability_word(m.ejectability()).to_owned(),
      total_bytes: m.total_bytes(),
      available_bytes: m.available_bytes(),
      used_bytes: m.used_bytes(),
    }
  }

  /// This record's roster, read exactly as [`ResolveOutput::fields`] is: a
  /// listed volume and a resolved one name the fields they share alike.
  fn fields(&self) -> Record<'_> {
    vec![
      ("device", Field::Text(&self.device)),
      ("mount_point", Field::Text(&self.mount_point)),
      ("volume_name", Field::MaybeText(self.volume_name.as_deref())),
      (
        "volume_name_assurance",
        Field::MaybeText(self.volume_name_assurance.as_deref()),
      ),
      (
        "volume_identity",
        Field::MaybeText(self.volume_identity.as_deref()),
      ),
      (
        "identity_assurance",
        Field::MaybeText(self.identity_assurance.as_deref()),
      ),
      ("ejectability", Field::Text(&self.ejectability)),
      ("total_bytes", Field::Bytes(self.total_bytes)),
      ("available_bytes", Field::Bytes(self.available_bytes)),
      ("used_bytes", Field::Bytes(self.used_bytes)),
    ]
  }
}

/// The volume's durable identity, in the spelling the type itself prints —
/// a UUID in its canonical form, a FAT-class serial in its two halves, an NTFS
/// serial in its sixteen digits. `None` where the platform or the filesystem
/// reports no identity, which is not a failure to look.
fn identity_text(reading: Option<whichdisk::IdentityReading>) -> Option<String> {
  reading.map(|reading| reading.identity().to_string())
}

/// How a value was read, which is a fact about the answer rather than about
/// the volume: `vouched` is the mounted filesystem answering for itself,
/// `published` is a name the platform published about a device, and `declared`
/// is a name published about a device that only the mounter says is the one.
fn assurance_word(assurance: whichdisk::IdentityAssurance) -> &'static str {
  match assurance {
    whichdisk::IdentityAssurance::Vouched => "vouched",
    whichdisk::IdentityAssurance::Published => "published",
    whichdisk::IdentityAssurance::Declared => "declared",
  }
}

/// Whether the volume's media can be taken out of the machine, or that the
/// platform could not tell — which `unknown` says outright rather than
/// spelling it `false`.
fn ejectability_word(ejectability: whichdisk::Ejectability) -> &'static str {
  match ejectability {
    whichdisk::Ejectability::Ejectable => "ejectable",
    whichdisk::Ejectability::NotEjectable => "not_ejectable",
    whichdisk::Ejectability::Unknown => "unknown",
  }
}

/// How the identity was read.
fn assurance_text(reading: Option<whichdisk::IdentityReading>) -> Option<String> {
  reading.map(|reading| assurance_word(reading.assurance()).to_owned())
}

/// One field of a record, as what it is rather than as how it prints.
///
/// Each output format renders the same variant its own way: a count of bytes
/// is an exact number where a machine reads it and a human-readable size in
/// the plain output, and an absent value is the bare word `none` in plain and
/// each structured format's own null. No variant ever renders as an empty
/// string, which would read as a volume named nothing.
///
/// There is deliberately no flag: a value with two states and a way to fail to
/// read it has three, and spelling the third one `false` is what
/// [`Ejectability`](whichdisk::Ejectability) exists to stop.
enum Field<'a> {
  /// Text that is always there.
  Text(&'a str),
  /// Text the platform may not have to give.
  MaybeText(Option<&'a str>),
  /// A count of bytes.
  Bytes(u64),
}

/// A record the CLI prints: its fields, named once, in one order.
///
/// The three output formats are three renderings of this one roster rather
/// than three hand-written copies of it. A copy per format is how a field
/// comes to be called `ejectable` in one and `is_ejectable` in the next, to be
/// a number in one and a quoted string in another, or to stand in a different
/// place in each — so there is one roster, and adding a field to it adds it to
/// all three at once.
type Record<'a> = Vec<(&'static str, Field<'a>)>;

/// The plain rendering: `name=value` pairs in roster order.
fn plain_fields(record: &Record<'_>) -> Vec<String> {
  record
    .iter()
    .map(|(name, field)| {
      let value = match field {
        Field::Text(text) | Field::MaybeText(Some(text)) => plain_text(text),
        // Bare, where every text value is quoted, so that a volume actually
        // named `none` cannot be read as a volume without a name.
        Field::MaybeText(None) => "none".to_owned(),
        Field::Bytes(bytes) => human_bytes(*bytes),
      };
      format!("{name}={value}")
    })
    .collect()
}

/// A text value in the plain output: quoted, and escaped the way Rust spells a
/// string.
///
/// A volume's label is whatever a person wrote on it, and on Linux it arrives
/// with udev's escapes already decoded, so it can carry a quote, a newline or a
/// terminal control sequence. Unescaped, such a label could close its own field
/// and forge the next one, add a row to a listing, or run an escape sequence on
/// the terminal that prints it. An ordinary label is spelled exactly as it
/// reads.
fn plain_text(value: &str) -> String {
  format!("{value:?}")
}

/// A roster as JSON: a map, in roster order.
struct JsonRecord<'a>(&'a Record<'a>);

impl Serialize for JsonRecord<'_> {
  fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(self.0.len()))?;
    for (name, field) in self.0 {
      match field {
        Field::Text(text) => map.serialize_entry(name, text)?,
        Field::MaybeText(text) => map.serialize_entry(name, text)?,
        Field::Bytes(bytes) => map.serialize_entry(name, bytes)?,
      }
    }
    map.end()
  }
}

/// A roster as a YAML mapping, in roster order.
fn yaml_record(record: &Record<'_>) -> yaml_rust2::Yaml {
  use yaml_rust2::{Yaml, yaml::Hash};

  let mut map = Hash::new();
  for (name, field) in record {
    map.insert(Yaml::String((*name).to_owned()), yaml_field(field));
  }
  Yaml::Hash(map)
}

/// One field as YAML.
fn yaml_field(field: &Field<'_>) -> yaml_rust2::Yaml {
  use yaml_rust2::Yaml;

  match field {
    Field::Text(text) | Field::MaybeText(Some(text)) => Yaml::String((*text).to_owned()),
    // YAML's own null, which this emitter writes in the canonical short form
    // `~`. A reader parses it as null exactly as it parses JSON's `null`; what
    // both say, and what `none` says in the plain output, is that there is no
    // value here rather than that the value is empty.
    Field::MaybeText(None) => Yaml::Null,
    // Handed to the emitter as a raw scalar, which is how it carries a number
    // given to it as text. `Yaml::Integer` is an `i64` where a count is a
    // `u64`, so a value above `i64::MAX` — which a synthetic filesystem can
    // drive the size arithmetic to — would have to be capped into a wrong
    // number or turned into a quoted string, and a machine format whose type
    // depends on its value is not one schema. The digits go out exactly as
    // JSON writes them, across the whole range.
    Field::Bytes(bytes) => Yaml::Real(bytes.to_string()),
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
  let record = out.fields();
  match format {
    Some("json") => serde_json::to_string_pretty(&JsonRecord(&record))
      .map_err(|e| format!("failed to serialize JSON: {e}")),
    Some("yaml" | "yml") => emit_yaml(&yaml_record(&record)),
    Some(fmt) => Err(format!(
      "unknown output format '{fmt}'. Supported: json, yaml, yml"
    )),
    None => Ok(plain_fields(&record).join("\n")),
  }
}

fn format_list(mounts: &[MountOutput], format: Option<&str>) -> Result<String, String> {
  let records: Vec<Record<'_>> = mounts.iter().map(MountOutput::fields).collect();
  match format {
    Some("json") => {
      let records: Vec<JsonRecord<'_>> = records.iter().map(JsonRecord).collect();
      serde_json::to_string_pretty(&records).map_err(|e| format!("failed to serialize JSON: {e}"))
    }
    Some("yaml" | "yml") => {
      let docs = records.iter().map(yaml_record).collect();
      emit_yaml(&yaml_rust2::Yaml::Array(docs))
    }
    Some(fmt) => Err(format!(
      "unknown output format '{fmt}'. Supported: json, yaml, yml"
    )),
    None => Ok(
      records
        .iter()
        .map(|record| plain_fields(record).join(" "))
        .collect::<Vec<_>>()
        .join("\n"),
    ),
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
      // A skip removes the state it names and nothing else. The library's
      // only-filters are exact — they keep one state and drop the other two —
      // so using one to serve a skip would silently drop every volume whose
      // ejectability could not be established, which the flag does not ask
      // for. The whole listing is taken and the named state removed from it.
      let mounts = whichdisk::list().map_err(|e| e.to_string())?;
      let out: Vec<MountOutput> = mounts
        .iter()
        .filter(|mount| match mount.ejectability() {
          whichdisk::Ejectability::Ejectable => !skip_ejectable,
          whichdisk::Ejectability::NotEjectable => !skip_non_ejectable,
          // Neither flag names it, so neither flag removes it.
          whichdisk::Ejectability::Unknown => true,
        })
        .map(MountOutput::from_mount)
        .collect();
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
      volume_name_assurance: Some("published".into()),
      volume_identity: Some("8f19a253-d450-3090-abf6-e651943998d1".into()),
      identity_assurance: Some("published".into()),
      ejectability: "not_ejectable".into(),
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
    assert!(result.contains("ejectability=\"not_ejectable\""));
    assert!(result.contains("total_bytes="));
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
    assert_eq!(parsed["ejectability"], "not_ejectable");
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

  /// The one roster is what each format prints: the same names, and in plain
  /// and YAML the same order. A format that grew a field of its own, lost one,
  /// or spelled one its own way would part company here.
  #[test]
  fn test_resolve_prints_one_roster_in_every_format() {
    let out = make_resolve_output();
    let names: Vec<String> = out
      .fields()
      .iter()
      .map(|(name, _)| (*name).to_owned())
      .collect();

    let plain = format_resolve(&out, None).unwrap();
    let plain_names: Vec<String> = plain
      .lines()
      .map(|line| line.split('=').next().unwrap_or_default().to_owned())
      .collect();
    assert_eq!(plain_names, names, "{plain}");

    let json = format_resolve(&out, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let object = parsed.as_object().unwrap();
    assert_eq!(object.len(), names.len(), "{json}");
    for name in &names {
      assert!(object.contains_key(name.as_str()), "{json}");
    }

    let yaml = format_resolve(&out, Some("yaml")).unwrap();
    let yaml_names: Vec<String> = yaml
      .lines()
      .map(|line| line.split(':').next().unwrap_or_default().to_owned())
      .collect();
    assert_eq!(yaml_names, names, "{yaml}");
  }

  /// A label is whatever a person wrote on the volume, and on Linux it arrives
  /// with udev's escapes already decoded. In the plain output it is quoted and
  /// escaped, so that one carrying a quote, a newline or a terminal control
  /// sequence cannot close its own field, forge the next one, or run that
  /// sequence on the terminal printing it.
  #[test]
  fn test_plain_escapes_what_a_person_wrote_on_a_volume() {
    let mut out = make_resolve_output();
    out.volume_name = Some("ev\"il\nmount_point=\"/forged\u{1b}[31m".into());
    let plain = format_resolve(&out, None).unwrap();

    // One line per field of the roster, however many newlines the label holds.
    assert_eq!(plain.lines().count(), out.fields().len(), "{plain}");
    assert_eq!(
      plain
        .lines()
        .filter(|line| line.starts_with("mount_point="))
        .count(),
      1,
      "{plain}"
    );
    assert!(!plain.contains('\u{1b}'), "{plain}");
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
      volume_name_assurance: Some("published".into()),
      volume_identity: Some("8f19a253-d450-3090-abf6-e651943998d1".into()),
      identity_assurance: Some("published".into()),
      ejectability: "not_ejectable".into(),
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
    assert!(result.contains("ejectability=\"not_ejectable\""));
    assert!(result.contains("GiB"));
  }

  #[test]
  fn test_format_list_json() {
    let mut m = make_mount_output();
    m.device = "/dev/sdb1".into();
    m.mount_point = "/mnt/usb".into();
    m.ejectability = "ejectable".into();
    let mounts = vec![m];
    let result = format_list(&mounts, Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed[0]["ejectability"], "ejectable");
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

  /// A listed volume answers to the same roster a resolved one does.
  #[test]
  fn test_list_prints_one_roster_in_every_format() {
    let mount = make_mount_output();
    let record = mount.fields();
    let names: Vec<String> = record.iter().map(|(name, _)| (*name).to_owned()).collect();

    let plain_names: Vec<String> = plain_fields(&record)
      .iter()
      .map(|pair| pair.split('=').next().unwrap_or_default().to_owned())
      .collect();
    assert_eq!(plain_names, names);

    let json = format_list(std::slice::from_ref(&mount), Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let object = parsed[0].as_object().unwrap();
    assert_eq!(object.len(), names.len(), "{json}");
    for name in &names {
      assert!(object.contains_key(name.as_str()), "{json}");
    }

    let yaml = format_list(std::slice::from_ref(&mount), Some("yaml")).unwrap();
    let yaml_names: Vec<String> = yaml
      .lines()
      .map(|line| {
        line
          .trim_start_matches("- ")
          .trim_start()
          .split(':')
          .next()
          .unwrap_or_default()
          .to_owned()
      })
      .collect();
    assert_eq!(yaml_names, names, "{yaml}");
  }

  /// A byte count is a number where a machine reads it, in YAML as in JSON,
  /// and a human-readable size only where a person does.
  #[test]
  fn test_byte_counts_are_numbers_in_both_machine_formats() {
    let mount = make_mount_output();
    let yaml = format_list(std::slice::from_ref(&mount), Some("yaml")).unwrap();
    assert!(yaml.contains("total_bytes: 500000000000"), "{yaml}");
    let json = format_list(std::slice::from_ref(&mount), Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed[0]["total_bytes"].is_u64(), "{json}");
  }

  /// And the type of that field does not depend on its value: a count above
  /// `i64::MAX`, which a synthetic filesystem can drive the size arithmetic to,
  /// is still a number in both machine formats rather than a quoted string in
  /// one of them.
  #[test]
  fn test_a_byte_count_past_the_signed_range_is_still_a_number() {
    let mut mount = make_mount_output();
    mount.total_bytes = u64::MAX;
    let yaml = format_list(std::slice::from_ref(&mount), Some("yaml")).unwrap();
    assert!(
      yaml.contains(&format!("total_bytes: {}", u64::MAX)),
      "{yaml}"
    );
    let json = format_list(std::slice::from_ref(&mount), Some("json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["total_bytes"].as_u64(), Some(u64::MAX), "{json}");
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

  /// The JSON rows a `list` run prints under the two skip flags.
  fn listed_rows(skip_ejectable: bool, skip_non_ejectable: bool) -> Vec<serde_json::Value> {
    let cli = Cli {
      command: Some(Command::List {
        skip_ejectable,
        skip_non_ejectable,
      }),
      path: None,
      output: Some("json".into()),
    };
    let printed = run(cli).unwrap();
    serde_json::from_str::<serde_json::Value>(&printed)
      .unwrap()
      .as_array()
      .unwrap()
      .clone()
  }

  /// How many volumes the library itself puts in each of the three states.
  fn states() -> (usize, usize, usize) {
    let mounts = whichdisk::list().unwrap();
    let count = |wanted| mounts.iter().filter(|m| m.ejectability() == wanted).count();
    (
      count(whichdisk::Ejectability::Ejectable),
      count(whichdisk::Ejectability::NotEjectable),
      count(whichdisk::Ejectability::Unknown),
    )
  }

  /// A skip removes the state it names **and nothing else**.
  ///
  /// The flag asks the opposite question from the library's only-filters, which
  /// are exact: serving `--skip-non-ejectable` with `ejectable_only` would drop
  /// every volume whose ejectability no platform answer established along with
  /// the ones the flag actually names — on Linux and the BSDs, which never deny,
  /// that is nearly the whole listing.
  #[test]
  fn test_run_list_skip_removes_only_the_named_state() {
    let (ejectable, not_ejectable, unknown) = states();

    assert_eq!(
      listed_rows(false, false).len(),
      ejectable + not_ejectable + unknown,
      "no flag removes nothing"
    );

    let kept = listed_rows(true, false);
    assert_eq!(kept.len(), not_ejectable + unknown);
    assert!(
      kept.iter().all(|row| row["ejectability"] != "ejectable"),
      "--skip-ejectable leaves no ejectable row"
    );
    assert_eq!(
      kept
        .iter()
        .filter(|row| row["ejectability"] == "unknown")
        .count(),
      unknown,
      "--skip-ejectable keeps every unknown row"
    );

    let kept = listed_rows(false, true);
    assert_eq!(kept.len(), ejectable + unknown);
    assert!(
      kept
        .iter()
        .all(|row| row["ejectability"] != "not_ejectable"),
      "--skip-non-ejectable leaves no non-ejectable row"
    );
    assert_eq!(
      kept
        .iter()
        .filter(|row| row["ejectability"] == "unknown")
        .count(),
      unknown,
      "--skip-non-ejectable keeps every unknown row"
    );
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
    assert_eq!(
      out.ejectability,
      ejectability_word(disk.ejectability()).to_owned()
    );
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
