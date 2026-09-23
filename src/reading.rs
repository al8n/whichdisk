//! What one platform read answered.
//!
//! **Every platform read on the Apple and Linux backends answers one of four
//! outcomes, and no two of them are merged except by a caller that names, at
//! the call, what each one means for the value it is reading.** A value; the
//! platform's own documented "there is no such thing"; a decline the backend's
//! contract names; or a failure. The last is never a fact about a volume, so
//! nothing on those backends reads it as one: a failed read is returned as the
//! error it is, and only a decline or an absence may end in a value's
//! documented absence.
//!
//! A **census** — a whole `/dev/disk/by-*` directory, the btrfs map in sysfs, a
//! mount table — is read whole or not at all. A decline anywhere in it refuses
//! the census, because what was not read could be the very entry that would
//! have changed the answer; only an entry that was read and turned out to be
//! nothing the census counts is passed over.
//!
//! FreeBSD, OpenBSD, DragonFly and NetBSD name no decline: every read there is
//! a value or the operation's error, and nothing is sorted. Windows keeps the
//! failure behaviour each of its roads documents.

use std::io;

/// What one platform read answered.
///
/// - [`Value`](Self::Value) — the platform answered, with a value.
/// - [`Absent`](Self::Absent) — the platform answered that there is none: its
///   documented "no such property", such as a node that is not a block device,
///   an attribute a volume does not carry, or a resource key Foundation has no
///   value for.
/// - [`Declined`](Self::Declined) — the platform declined to answer, with an
///   error the backend's contract names: the object is not there, the caller
///   may not look, the containment refused the path, or the question is not
///   implemented. Each backend lists its own in its `declined`.
/// - [`Failed`](Self::Failed) — the read itself failed: no descriptors, no
///   memory, an I/O error. That says something about this process or the
///   machine and nothing about a volume.
///
/// There is deliberately no `ok()`. The ways out are named for the contract
/// they apply: [`answered`](Self::answered) for a value whose contract makes a
/// decline its absence, [`required`](Self::required) for a read that has no
/// absence to report, and, on Linux, [`evidence`](Self::evidence) for the one
/// road on which nothing but a yes is ever read. Anything else is a `match`
/// that says what each outcome is — which is how a census tells an entry that
/// was declined, and refuses, from one that is simply not what it counts.
#[must_use = "a reading holds a failure until it is sorted, and dropping it erases one"]
#[derive(Debug)]
pub(crate) enum Reading<T> {
  /// The platform answered, with a value.
  Value(T),
  /// The platform answered that there is no such thing.
  Absent,
  /// The platform declined, with an error the backend's contract names.
  Declined(io::Error),
  /// The read failed. Never a fact about a volume.
  Failed(io::Error),
}

impl<T> Reading<T> {
  /// Sorts what a platform call returned by a backend's decline set.
  pub(crate) fn sort(read: io::Result<T>, declined: fn(&io::Error) -> bool) -> Self {
    match read {
      Ok(value) => Self::Value(value),
      Err(err) if declined(&err) => Self::Declined(err),
      Err(err) => Self::Failed(err),
    }
  }

  /// Reads the value further, into another value or into the platform's "there
  /// is none" where what came back is not the thing asked for. Every other
  /// outcome is carried through as it is.
  pub(crate) fn and_then<U>(self, read: impl FnOnce(T) -> Reading<U>) -> Reading<U> {
    match self {
      Self::Value(value) => read(value),
      Self::Absent => Reading::Absent,
      Self::Declined(err) => Reading::Declined(err),
      Self::Failed(err) => Reading::Failed(err),
    }
  }

  /// The same outcome, with the value carried through `f`.
  pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Reading<U> {
    self.and_then(|value| Reading::Value(f(value)))
  }

  /// What the platform answered, for a value whose contract makes a decline
  /// its absence: the value, or `None` where the platform answered that there
  /// is none or declined to answer. A failed read is the error it is.
  pub(crate) fn answered(self) -> io::Result<Option<T>> {
    match self {
      Self::Value(value) => Ok(Some(value)),
      Self::Absent | Self::Declined(_) => Ok(None),
      Self::Failed(err) => Err(err),
    }
  }

  /// The value, for a read that has no absence to report: a decline and a
  /// failure are both the operation's error, and so is an answer of none.
  pub(crate) fn required(self) -> io::Result<T> {
    match self {
      Self::Value(value) => Ok(value),
      Self::Absent => Err(io::Error::new(
        io::ErrorKind::NotFound,
        "the platform answered that there is none",
      )),
      Self::Declined(err) | Self::Failed(err) => Err(err),
    }
  }

  /// The value, and nothing for every other outcome — **for the removal
  /// question alone.**
  ///
  /// That road can only ever say yes, and its contract makes every other
  /// outcome, a failure included,
  /// [`Ejectability::Unknown`](crate::Ejectability::Unknown): "could not be
  /// asked". Nothing else may read a failure as nothing, so nothing else calls
  /// this.
  #[cfg(target_os = "linux")]
  pub(crate) fn evidence(self) -> Option<T> {
    match self {
      Self::Value(value) => Some(value),
      Self::Absent | Self::Declined(_) | Self::Failed(_) => None,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn declines_not_found(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound
  }

  fn outcome<T>(reading: &Reading<T>) -> &'static str {
    match reading {
      Reading::Value(_) => "value",
      Reading::Absent => "absent",
      Reading::Declined(_) => "declined",
      Reading::Failed(_) => "failed",
    }
  }

  fn not_found() -> io::Error {
    io::Error::from(io::ErrorKind::NotFound)
  }

  fn broken() -> io::Error {
    io::Error::other("the read itself failed")
  }

  /// A decline is what the backend's set names, and nothing else is.
  #[test]
  fn test_a_read_is_sorted_by_the_decline_set_it_is_given() {
    assert_eq!(outcome(&Reading::sort(Ok(1), declines_not_found)), "value");
    assert_eq!(
      outcome(&Reading::<u8>::sort(Err(not_found()), declines_not_found)),
      "declined"
    );
    assert_eq!(
      outcome(&Reading::<u8>::sort(Err(broken()), declines_not_found)),
      "failed"
    );
  }

  /// `answered` ends a decline and an absence in none, and never a failure.
  #[test]
  fn test_answered_never_reads_a_failure_as_none() {
    assert_eq!(Reading::Value(7).answered().unwrap(), Some(7));
    assert_eq!(Reading::<u8>::Absent.answered().unwrap(), None);
    assert_eq!(
      Reading::<u8>::Declined(not_found()).answered().unwrap(),
      None
    );
    assert!(Reading::<u8>::Failed(broken()).answered().is_err());
  }

  /// `required` has no absence to give, so every outcome but a value is an
  /// error, and the error a decline or a failure carried is the one returned.
  #[test]
  fn test_required_gives_a_value_or_the_error() {
    assert_eq!(Reading::Value(7).required().unwrap(), 7);
    assert_eq!(
      Reading::<u8>::Absent.required().unwrap_err().kind(),
      io::ErrorKind::NotFound
    );
    assert_eq!(
      Reading::<u8>::Declined(not_found())
        .required()
        .unwrap_err()
        .kind(),
      io::ErrorKind::NotFound
    );
    assert_eq!(
      Reading::<u8>::Failed(broken())
        .required()
        .unwrap_err()
        .to_string(),
      "the read itself failed"
    );
  }

  /// Reading a value further keeps every other outcome exactly as it was.
  #[test]
  fn test_and_then_carries_every_other_outcome_through() {
    let absent: Reading<u8> = Reading::Value(0).and_then(|_| Reading::Absent);
    assert_eq!(outcome(&absent), "absent");
    assert_eq!(
      outcome(&Reading::<u8>::Declined(not_found()).map(|value| value + 1)),
      "declined"
    );
    assert_eq!(
      outcome(&Reading::<u8>::Failed(broken()).and_then(Reading::Value)),
      "failed"
    );
    assert_eq!(
      Reading::Value(1).map(|value| value + 1).answered().unwrap(),
      Some(2)
    );
  }

  /// The removal question's own way out: a yes or nothing, whatever the
  /// nothing was.
  #[cfg(target_os = "linux")]
  #[test]
  fn test_evidence_is_a_value_or_nothing() {
    assert_eq!(Reading::Value(1).evidence(), Some(1));
    assert_eq!(Reading::<u8>::Absent.evidence(), None);
    assert_eq!(Reading::<u8>::Declined(not_found()).evidence(), None);
    assert_eq!(Reading::<u8>::Failed(broken()).evidence(), None);
  }
}
