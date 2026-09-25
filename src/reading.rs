//! What one platform read answered.
//!
//! **Every platform read on the Apple, Linux and Windows backends answers one
//! of four outcomes, and no two of them are merged except by a caller that
//! names, at the call, what each one means for the value it is reading.** A
//! value; the platform's own documented "there is no such thing"; a decline the
//! backend's contract names; or a failure. The last is never a fact about a
//! volume, so nothing on those backends reads it as one: a failed read is
//! returned as the error it is, and only a decline or an absence may end in a
//! value's documented absence.
//!
//! A **census** — a whole `/dev/disk/by-*` directory, the btrfs map in sysfs, a
//! `slaves/` directory, the Linux mount table, the Windows volume enumeration,
//! the BSD mount table — is read whole or not at all, and a [`Census`] is the
//! only shape one takes: it exists only once the platform has proved the
//! enumeration complete, by one of three protocols, one constructor each —
//! [`read`](Census::read) to an end the platform proves, [`copied`](Census::copied)
//! into a caller-owned buffer with slots to spare, and
//! [`snapshot`](Census::snapshot) of a table no change overlapped. A decline
//! anywhere in it refuses the census, because what was not read could be the
//! very entry that would have changed the answer; only an entry that was read
//! and turned out to be nothing the census counts is passed over.
//!
//! FreeBSD, OpenBSD, DragonFly and NetBSD name no decline: every read there is
//! a value or the operation's error, and nothing is sorted.

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
/// absence to report, and, on Linux and Windows, `evidence` for the removal
/// road, on which nothing but a platform's own answer is ever
/// read. Anything else is a `match`
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
  #[cfg(any(target_os = "linux", windows, test))]
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
  /// That road answers only what a platform positively said, and its contract
  /// makes every other outcome, a failure included,
  /// [`Ejectability::Unknown`](crate::Ejectability::Unknown): "could not be
  /// asked". Nothing else may read a failure as nothing, so nothing else calls
  /// this.
  #[cfg(any(target_os = "linux", windows))]
  pub(crate) fn evidence(self) -> Option<T> {
    match self {
      Self::Value(value) => Some(value),
      Self::Absent | Self::Declined(_) | Self::Failed(_) => None,
    }
  }
}

/// Everything one enumeration holds, read to the end the platform proved.
///
/// **There is no partial census.** One is built only by a constructor that
/// proves the enumeration whole, and otherwise ends in the sorted error of the
/// step that failed:
///
/// - [`read`](Self::read) keeps asking until the platform itself says the
///   enumeration is over — `getdents64` returning nothing, `FindNextVolumeW`
///   answering `ERROR_NO_MORE_FILES`;
/// - [`copied`](Self::copied) hands the platform a buffer this crate owns, with
///   slots to spare, and asks again with more whenever the answer fills it —
///   `getfsstat`, `getvfsstat`;
/// - [`snapshot`](Self::snapshot) reads a table the platform streams, and reads
///   it again until the platform proves no change overlapped the read — the
///   Linux mount table.
///
/// A refill declined partway is a census refused, never the prefix read before
/// it: what was not read could be the very entry that settles an answer. And
/// no census borrows storage the platform owns: every entry is in memory this
/// crate allocated before the platform wrote it.
#[cfg(any(target_os = "linux", feature = "list", test))]
#[must_use = "a census is read so that every entry of it is weighed"]
#[derive(Debug)]
pub(crate) struct Census<T>(Vec<T>);

/// How many times a census whose table kept changing, or kept filling every
/// buffer it was offered, is asked again before it is refused.
#[cfg(any(target_os = "linux", all(feature = "list", not(windows)), test))]
const CENSUS_ATTEMPTS: usize = 16;

/// The most entries [`Census::copied`] offers the platform room for. A mount
/// table that outgrows it is refused rather than read in part.
#[cfg(any(all(feature = "list", not(any(target_os = "linux", windows))), test))]
const COPIED_LIMIT: usize = 1 << 16;

#[cfg(any(target_os = "linux", feature = "list", test))]
impl<T> Census<T> {
  /// Reads an enumeration to its end.
  ///
  /// `step` hands over the next entry, or the error the platform answered, or
  /// `None` where — and only where — the platform proved the enumeration
  /// ended. An error ends the census in that error, sorted by the backend's
  /// decline set: a declined step refuses the census, and any other is a
  /// failed read.
  #[cfg(any(target_os = "linux", all(windows, feature = "list"), test))]
  pub(crate) fn read(
    mut step: impl FnMut() -> Option<io::Result<T>>,
    declined: fn(&io::Error) -> bool,
  ) -> Reading<Self> {
    let mut entries = Vec::new();
    loop {
      match step() {
        None => return Reading::Value(Self(entries)),
        Some(Ok(entry)) => entries.push(entry),
        Some(Err(err)) => return Reading::sort(Err(err), declined),
      }
    }
  }

  /// Reads a table the platform copies into a buffer the caller owns, and
  /// answers with how many entries it wrote.
  ///
  /// **A buffer the answer fills is no proof.** `getfsstat` and `getvfsstat`
  /// copy as many entries as the buffer holds and answer with that number when
  /// there were more, so an answer equal to the buffer's length cannot be told
  /// from a table that happened to fit exactly. So the buffer always has slots
  /// to spare — `hint`, the number of entries the platform last said there
  /// are, and half as many again, and a few more — and whenever an answer
  /// fills it, the table is asked again with twice the room. The census is
  /// taken only from an answer that left a slot empty, which is the platform
  /// proving there were fewer entries than slots. A table that outgrows
  /// [`COPIED_LIMIT`], or fills every buffer for [`CENSUS_ATTEMPTS`] asks, is
  /// refused rather than read in part.
  ///
  /// `fill` is given the whole buffer, every slot a copy of `empty`, and
  /// answers with the number of entries the platform wrote at its start; an
  /// answer larger than the buffer is not an answer about it, and fails the
  /// census. Each buffer is allocated and filled here, so nothing the platform
  /// owns is ever borrowed.
  #[cfg(any(all(feature = "list", not(any(target_os = "linux", windows))), test))]
  pub(crate) fn copied(
    empty: T,
    hint: usize,
    mut fill: impl FnMut(&mut [T]) -> io::Result<usize>,
    declined: fn(&io::Error) -> bool,
  ) -> Reading<Self>
  where
    T: Clone,
  {
    let mut capacity = hint
      .saturating_add(hint / 2)
      .saturating_add(8)
      .min(COPIED_LIMIT);
    for _ in 0..CENSUS_ATTEMPTS {
      let mut slots = vec![empty.clone(); capacity];
      match fill(&mut slots) {
        Ok(written) if written < capacity => {
          slots.truncate(written);
          return Reading::Value(Self(slots));
        }
        Ok(written) if written == capacity => {
          if capacity == COPIED_LIMIT {
            break;
          }
          capacity = capacity.saturating_mul(2).min(COPIED_LIMIT);
        }
        Ok(_) => {
          return Reading::Failed(io::Error::new(
            io::ErrorKind::InvalidData,
            "the platform counted more entries than the buffer it was given holds",
          ));
        }
        Err(err) => return Reading::sort(Err(err), declined),
      }
    }
    Reading::Failed(io::Error::other(
      "the table filled every buffer it was offered, so no answer proved it whole",
    ))
  }

  /// Reads a table the platform hands over as one stream, again and again
  /// until a read is one the platform proves no change overlapped.
  ///
  /// `read` reads the whole table once and answers with its entries and with
  /// whether the platform proved nothing changed between the start of that
  /// read and its end — for the Linux mount table, no mount event since the
  /// table was opened. A read that a change overlapped may have skipped an
  /// entry or carried one twice, so it is discarded and the table read again;
  /// a table that changed under every one of [`CENSUS_ATTEMPTS`] reads is
  /// refused rather than read in part. An error ends the census in that error,
  /// sorted by the backend's decline set.
  #[cfg(any(target_os = "linux", test))]
  pub(crate) fn snapshot(
    mut read: impl FnMut() -> io::Result<(Vec<T>, bool)>,
    declined: fn(&io::Error) -> bool,
  ) -> Reading<Self> {
    for _ in 0..CENSUS_ATTEMPTS {
      match read() {
        Ok((entries, true)) => return Reading::Value(Self(entries)),
        Ok((_, false)) => {}
        Err(err) => return Reading::sort(Err(err), declined),
      }
    }
    Reading::Failed(io::Error::other(
      "the table changed during every read of it, so no read of it is whole",
    ))
  }
}

#[cfg(any(target_os = "linux", feature = "list", test))]
impl<T> IntoIterator for Census<T> {
  type Item = T;
  type IntoIter = std::vec::IntoIter<T>;

  fn into_iter(self) -> Self::IntoIter {
    self.0.into_iter()
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

  /// A census is every entry up to the end the platform proved, or it is the
  /// error that stopped it — never the entries read before that error.
  #[test]
  fn test_a_census_is_whole_or_it_is_the_error_that_stopped_it() {
    let mut steps = vec![Some(Ok(1u8)), Some(Ok(2)), None].into_iter();
    let Reading::Value(census) = Census::read(|| steps.next().flatten(), declines_not_found) else {
      panic!("an enumeration that reached its proven end is a census");
    };
    assert_eq!(census.into_iter().collect::<Vec<_>>(), [1, 2]);

    let mut steps = vec![Some(Ok(1u8)), Some(Err(not_found())), Some(Ok(2))].into_iter();
    assert_eq!(
      outcome(&Census::read(|| steps.next().flatten(), declines_not_found)),
      "declined",
      "a declined refill refuses the census, and the entry read before it is not kept"
    );
    let mut steps = vec![Some(Ok(1u8)), Some(Err(broken()))].into_iter();
    assert_eq!(
      outcome(&Census::read(|| steps.next().flatten(), declines_not_found)),
      "failed"
    );

    let Reading::Value(empty) = Census::<u8>::read(|| None, declines_not_found) else {
      panic!("an enumeration that ended at once is an empty census");
    };
    assert_eq!(empty.into_iter().count(), 0);
  }

  /// A table copied into a buffer is a census only where the answer left a
  /// slot empty: an answer that fills the buffer could have been cut short, so
  /// the table is asked again with more room, and a count larger than the
  /// buffer is no answer at all.
  #[test]
  fn test_a_copied_census_is_taken_only_from_an_answer_with_room_to_spare() {
    // Twelve entries, and a hint that says there were only two: the first
    // buffer fills, the next one does not.
    let table: Vec<u8> = (1..=12).collect();
    let mut offered = Vec::new();
    let Reading::Value(census) = Census::copied(
      0u8,
      2,
      |slots| {
        offered.push(slots.len());
        let written = table.len().min(slots.len());
        slots[..written].copy_from_slice(&table[..written]);
        Ok(written)
      },
      declines_not_found,
    ) else {
      panic!("a table that fits a buffer with room to spare is a census");
    };
    assert_eq!(census.into_iter().collect::<Vec<_>>(), table);
    assert!(offered.len() >= 2, "{offered:?}");
    assert!(
      offered.windows(2).all(|pair| pair[1] > pair[0]),
      "every refill offers more room: {offered:?}"
    );
    assert!(offered.last().unwrap() > &table.len());

    // A table that is exactly as long as the buffer is never taken as whole
    // on that answer alone.
    let mut asked = 0;
    let Reading::Value(census) = Census::copied(
      0u8,
      0,
      |slots| {
        asked += 1;
        let written = slots.len().min(8);
        slots[..written].fill(7);
        Ok(written)
      },
      declines_not_found,
    ) else {
      panic!("an answer with an empty slot proves the table whole");
    };
    assert_eq!(census.into_iter().count(), 8);
    assert_eq!(asked, 2, "an answer that filled the buffer is asked again");

    assert_eq!(
      outcome(&Census::copied(
        0u8,
        4,
        |slots| Ok(slots.len() + 1),
        declines_not_found
      )),
      "failed",
      "a count past the end of the buffer is not an answer about it"
    );
    assert_eq!(
      outcome(&Census::copied(
        0u8,
        4,
        |slots| Ok(slots.len()),
        declines_not_found
      )),
      "failed",
      "a table that fills every buffer is refused, never read in part"
    );
    assert_eq!(
      outcome(&Census::<u8>::copied(
        0,
        4,
        |_| Err(not_found()),
        declines_not_found
      )),
      "declined"
    );
    assert_eq!(
      outcome(&Census::<u8>::copied(
        0,
        4,
        |_| Err(broken()),
        declines_not_found
      )),
      "failed"
    );
  }

  /// A streamed table is a census only from a read no change overlapped.
  #[test]
  fn test_a_snapshot_is_taken_only_from_a_read_no_change_overlapped() {
    let mut reads = 0;
    let Reading::Value(census) = Census::snapshot(
      || {
        reads += 1;
        Ok((vec![reads], reads == 3))
      },
      declines_not_found,
    ) else {
      panic!("a read the platform proved unchanged is a census");
    };
    assert_eq!(census.into_iter().collect::<Vec<_>>(), [3]);

    assert_eq!(
      outcome(&Census::<u8>::snapshot(
        || Ok((vec![1], false)),
        declines_not_found
      )),
      "failed",
      "a table that changed under every read is refused"
    );
    assert_eq!(
      outcome(&Census::<u8>::snapshot(
        || Err(not_found()),
        declines_not_found
      )),
      "declined"
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
