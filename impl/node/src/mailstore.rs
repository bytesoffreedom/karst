//! Durable mailbox log (R2-5, #161) — the optional disk side of `RelayNode::mailboxes`.
//!
//! Without it, an `Accepted` message lives only in the relay process's memory: an ordinary
//! restart between "the relay took it" and "the recipient polled" loses the message with no
//! resend signal, because the sender retired its outbox entry on `Accepted`. That is a
//! guaranteed loss window on a routine restart, not an exotic crash.
//!
//! **What this buys, stated exactly.** Single-relay durability turns "guaranteed loss on
//! restart" into "loss if that relay's disk or the relay itself goes away". It does NOT make
//! delivery reliable — that needs replication across relays (#149) or an end-to-end receipt from
//! the recipient, neither of which exists. A client that wants the guarantee still has to pick a
//! relay that advertises it (`RelayPolicy::mailbox_durability`).
//!
//! **At-least-once, on purpose.** Deposits are fsynced BEFORE the relay answers `Accepted`, so an
//! accepted message is on disk. Deletions (fetch drain, ACK, TTL sweep) are appended WITHOUT an
//! fsync, so a crash in the window between "the recipient got it" and "the delete record reached
//! the platter" resurrects an already-delivered message. That is the deliberate trade: the cost
//! of exactly-once here is an fsync on every fetch — the hot, latency-visible path — to prevent a
//! duplicate the client already absorbs (the receive path dedups by `payload_id` in its own
//! persistent ring). Paying the write barrier on the rare, loss-bearing side and not on the
//! common, duplicate-bearing side is the whole design.
//!
//! **Layout.** One append-only file, `mail.log`: a 4-byte magic followed by records, each
//! `u32 LE length ‖ postcard(MailRecord)`. A torn tail from a crash (a short length, or a record
//! that will not decode) ends the replay there — everything before it is intact and kept, which
//! is exactly the at-least-once contract again. A wrong magic is LOUD (the caller refuses to
//! start), on the same principle as the OPK batch file: a mailbox log that cannot be read is an
//! operator problem, not something to paper over by silently serving an empty relay.
//!
//! The relay only ever holds E2E ciphertext, so this changes how long opaque bytes linger on the
//! operator's disk — the same fat-relay trade the blob store already makes — not what the relay
//! can read (nothing). It is opt-in for exactly that reason: `Volatile` stays the default, and
//! the choice is advertised so a client can prefer one posture or the other.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::node::{payload_id, Payload};

/// Magic + version of the mail log. `KML1` = this record layout.
const LOG_MAGIC: &[u8; 4] = b"KML1";

/// Ceiling on one record's encoded length. A mailbox entry is a sealed payload bounded by the
/// wire frame long before it reaches here; this is the allocation guard on a file that a
/// corrupt/hostile disk could otherwise use to demand an arbitrary `Vec`.
const MAX_RECORD_LEN: usize = 256 * 1024;

/// Compaction triggers on DEAD records — what the log holds that the live set no longer needs —
/// not on total size. Keying it to total size would make a relay with a large but entirely LIVE
/// mailbox rewrite the whole log periodically to reclaim nothing: pure O(n) waste on the epoch
/// tick. With this rule the file stays under roughly `2 × live + COMPACT_MIN_DEAD` records —
/// rewrite once the garbage outweighs the useful content and there is enough of it to be worth
/// the write.
const COMPACT_MIN_DEAD: usize = 512;

/// One durable event. Leases are deliberately absent: a lease is a short-lived visibility hint
/// whose whole purpose is to expire, and re-delivering a leased-but-unacked message after a
/// restart is the same outcome the lease timeout already produces.
// The size gap between the two variants is inherent and harmless here: a record is built,
// serialized, and dropped one at a time — never held in a collection — so the larger variant's
// footprint is a stack frame, not per-entry memory. Boxing the payload would add an allocation
// to the hot deposit path to save nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
enum MailRecord {
    /// A message was admitted into `mailbox`.
    Deposit { mailbox: [u8; 32], enqueued_at: u64, payload: Payload },
    /// A message left the mailbox (fetched without leasing, ACKed, or TTL-swept).
    Delete { mailbox: [u8; 32], payload_id: [u8; 32] },
}

/// One replayed entry: what the relay needs to rebuild its in-memory mailbox table.
pub struct ReplayedEntry {
    pub mailbox: [u8; 32],
    pub enqueued_at: u64,
    pub payload: Payload,
}

/// The append-only durable mailbox log.
pub struct MailLog {
    dir: PathBuf,
    file: File,
    /// Records currently in the file — the compaction trigger's numerator.
    records: usize,
    /// Set while `self.file` may not point at the live `mail.log` (a compaction that got past
    /// the rename and then failed). An append to an unlinked inode SUCCEEDS and fsyncs happily,
    /// so without this flag a failed compaction would silently turn a durable relay into one
    /// that answers `Accepted` for messages nobody will ever read back — the exact bug this
    /// module exists to close. While set, every write fails, which the deposit path turns into
    /// a `Rejected` the sender can retry.
    broken: bool,
    /// Test-only: see `poison_for_test`.
    #[cfg(test)]
    poisoned: bool,
}

impl MailLog {
    /// Open (or create) the log in `dir` and replay it.
    ///
    /// The returned entries are in deposit order with deletions already applied; the CALLER
    /// re-applies its own bounds (mailbox-table cap, per-mailbox cap, TTL) before installing
    /// them, because a file that predates a tightened bound — or one an attacker with disk
    /// access wrote — must not be able to smuggle state past a limit the live path enforces.
    pub fn open(dir: PathBuf) -> io::Result<(Self, Vec<ReplayedEntry>)> {
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("mail.log");
        let (entries, records) = match File::open(&path) {
            Ok(mut f) => {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                replay(&buf)?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Vec::new(), 0),
            Err(e) => return Err(e),
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let mut log = MailLog {
            dir,
            file,
            records,
            broken: false,
            #[cfg(test)]
            poisoned: false,
        };
        if log.records == 0 {
            log.write_magic_if_empty()?;
        }
        if log.should_compact(entries.len()) {
            log.compact(&entries)?;
        }
        Ok((log, entries))
    }

    fn write_magic_if_empty(&mut self) -> io::Result<()> {
        if self.file.metadata()?.len() == 0 {
            self.file.write_all(LOG_MAGIC)?;
            self.file.sync_data()?;
        }
        Ok(())
    }

    /// Record an admitted message. Fsynced: this returns only once the bytes are durable, so the
    /// caller may answer `Accepted` on the strength of it.
    pub fn deposit(&mut self, mailbox: [u8; 32], enqueued_at: u64, payload: &Payload) -> io::Result<()> {
        self.append(&MailRecord::Deposit { mailbox, enqueued_at, payload: payload.clone() })?;
        self.file.sync_data()
    }

    /// Record that a message left the mailbox. NOT fsynced — see the module doc: this is the
    /// duplicate-bearing side of the trade, and the client's dedup ring absorbs it.
    pub fn delete(&mut self, mailbox: [u8; 32], payload: &Payload) {
        let _ = self.append(&MailRecord::Delete { mailbox, payload_id: payload_id(payload) });
    }

    fn append(&mut self, rec: &MailRecord) -> io::Result<()> {
        #[cfg(test)]
        if self.poisoned {
            return Err(io::Error::other("poisoned for test"));
        }
        if self.broken {
            return Err(io::Error::other("mail log handle is stale after a failed compaction"));
        }
        let body = postcard::to_stdvec(rec)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mail record encode"))?;
        if body.len() > MAX_RECORD_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "mail record too large"));
        }
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        framed.extend_from_slice(&body);
        // ONE write call: a partial write inside a record is what the replay's torn-tail handling
        // exists for, but not splitting the record across syscalls keeps that window as small as
        // the filesystem allows.
        self.file.write_all(&framed)?;
        self.records += 1;
        Ok(())
    }

    /// Rewrite the log as exactly `live` (durably: temp file → fsync → rename → fsync dir), so a
    /// crash mid-compaction leaves either the old log or the new one, never a half-written mix.
    pub fn compact(&mut self, live: &[ReplayedEntry]) -> io::Result<()> {
        let tmp_path = self.dir.join("mail.log.tmp");
        {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(LOG_MAGIC)?;
            for e in live {
                let rec = MailRecord::Deposit {
                    mailbox: e.mailbox,
                    enqueued_at: e.enqueued_at,
                    payload: e.payload.clone(),
                };
                let body = postcard::to_stdvec(&rec)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mail record encode"))?;
                tmp.write_all(&(body.len() as u32).to_le_bytes())?;
                tmp.write_all(&body)?;
            }
            tmp.sync_data()?;
        }
        let path = self.dir.join("mail.log");
        // Everything above is harmless to fail: the live log is untouched. Past the rename it is
        // not — `self.file` now names an unlinked inode, and appends to one still SUCCEED, so the
        // handle is marked unusable until it has actually been replaced.
        std::fs::rename(&tmp_path, &path)?;
        self.broken = true;
        sync_dir(&self.dir)?;
        self.file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.records = live.len();
        self.broken = false;
        Ok(())
    }

    /// TEST-ONLY fault injection: make every subsequent write fail, standing in for a full or
    /// broken disk. The fail-closed deposit path (a relay that promised `Durable` must not answer
    /// `Accepted` for a message it could not write) has no other way to be exercised — an open
    /// file handle keeps working through `chmod`, and an unlinked file still accepts appends.
    #[cfg(test)]
    pub fn poison_for_test(&mut self) {
        self.poisoned = true;
    }

    /// Is the log carrying enough dead records (relative to `live` entries) that a rewrite is
    /// worth it? The caller owns the live set, so it owns the decision to pay for the scan.
    pub fn should_compact(&self, live: usize) -> bool {
        let dead = self.records.saturating_sub(live);
        dead >= COMPACT_MIN_DEAD && dead > live
    }

    /// Records currently in the file (test/diagnostic view of compaction).
    pub fn record_count(&self) -> usize {
        self.records
    }
}

/// Fsync a directory so a rename inside it is durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Decode the log and apply its deletions. Returns the surviving entries in deposit order and
/// how many records the file actually held (the compaction numerator).
fn replay(buf: &[u8]) -> io::Result<(Vec<ReplayedEntry>, usize)> {
    if buf.len() < LOG_MAGIC.len() || &buf[..LOG_MAGIC.len()] != LOG_MAGIC {
        // LOUD, not silently empty: an unreadable mail log means the operator's durability
        // promise is already broken, and starting up as if the relay simply had no mail would
        // hide that from everyone who chose this relay for it.
        return Err(io::Error::new(io::ErrorKind::InvalidData, "mail log: bad magic"));
    }
    let mut pos = LOG_MAGIC.len();
    let mut records = 0usize;
    // Deposit order is preserved by keeping the payloads in a Vec and marking removals, rather
    // than rebuilding from a map at the end (a mailbox's order is the order it will be served).
    let mut entries: Vec<Option<ReplayedEntry>> = Vec::new();
    let mut index: HashMap<([u8; 32], [u8; 32]), usize> = HashMap::new();
    while pos + 4 <= buf.len() {
        let len = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
        if len > MAX_RECORD_LEN || pos + 4 + len > buf.len() {
            break; // torn tail from a crash — everything before it stands
        }
        let body = &buf[pos + 4..pos + 4 + len];
        let Ok(rec) = postcard::from_bytes::<MailRecord>(body) else {
            break; // same: a record that will not decode ends the replay
        };
        pos += 4 + len;
        records += 1;
        match rec {
            MailRecord::Deposit { mailbox, enqueued_at, payload } => {
                let key = (mailbox, payload_id(&payload));
                // A re-deposit of a message already present is the idempotent-deposit case; keep
                // the first slot rather than growing a duplicate.
                if let std::collections::hash_map::Entry::Vacant(slot) = index.entry(key) {
                    slot.insert(entries.len());
                    entries.push(Some(ReplayedEntry { mailbox, enqueued_at, payload }));
                }
            }
            MailRecord::Delete { mailbox, payload_id } => {
                if let Some(i) = index.remove(&(mailbox, payload_id)) {
                    entries[i] = None;
                }
            }
        }
    }
    Ok((entries.into_iter().flatten().collect(), records))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(n: u8) -> Payload {
        Payload::Skeleton(crate::seal::SkeletonSeal {
            ephemeral_pub: [n; 32],
            nonce: [n; 12],
            ciphertext: vec![n; 8],
        })
    }

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "karst-mailstore-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn deposits_survive_and_deletes_apply() {
        let dir = tmp("basic");
        let (mut log, entries) = MailLog::open(dir.clone()).unwrap();
        assert!(entries.is_empty(), "a fresh log replays empty");
        log.deposit([1u8; 32], 10, &seal(1)).unwrap();
        log.deposit([1u8; 32], 11, &seal(2)).unwrap();
        log.deposit([2u8; 32], 12, &seal(3)).unwrap();
        log.delete([1u8; 32], &seal(1));
        drop(log);

        let (_log, entries) = MailLog::open(dir.clone()).unwrap();
        let got: Vec<_> = entries.iter().map(|e| (e.mailbox[0], e.enqueued_at)).collect();
        assert_eq!(got, vec![(1, 11), (2, 12)], "deleted entry gone, order preserved");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_torn_tail_keeps_everything_before_it() {
        // The crash case: the process died mid-append. Everything fully written must survive —
        // truncating the whole log instead would be exactly the loss this module exists to stop.
        let dir = tmp("torn");
        let (mut log, _) = MailLog::open(dir.clone()).unwrap();
        log.deposit([1u8; 32], 10, &seal(1)).unwrap();
        log.deposit([1u8; 32], 11, &seal(2)).unwrap();
        drop(log);

        let path = dir.join("mail.log");
        let len = std::fs::metadata(&path).unwrap().len();
        // Chop the last 3 bytes: the final record's length prefix is intact, its body is not.
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 3).unwrap();
        drop(f);

        let (_log, entries) = MailLog::open(dir.clone()).unwrap();
        assert_eq!(entries.len(), 1, "the complete record before the torn one survives");
        assert_eq!(entries[0].enqueued_at, 10);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The at-least-once trade made VISIBLE. A delete is appended without an fsync, so a crash
    /// can lose it while the deposit before it survives. Truncating the log to just before the
    /// delete record reproduces exactly that state — and the entry must come back, because a
    /// redelivered message is what this design chose over an fsync on every fetch. An
    /// exactly-once implementation would fail this test.
    #[test]
    fn a_delete_lost_to_a_crash_redelivers_the_message() {
        let dir = tmp("atleastonce");
        let (mut log, _) = MailLog::open(dir.clone()).unwrap();
        log.deposit([1u8; 32], 10, &seal(1)).unwrap();
        let after_deposit = std::fs::metadata(dir.join("mail.log")).unwrap().len();
        log.delete([1u8; 32], &seal(1));
        drop(log);

        let (_log, entries) = MailLog::open(dir.clone()).unwrap();
        assert!(entries.is_empty(), "control: with the delete on disk, the entry is gone");

        // The crash: the delete never reached the platter.
        let f = OpenOptions::new().write(true).open(dir.join("mail.log")).unwrap();
        f.set_len(after_deposit).unwrap();
        drop(f);
        let (_log, entries) = MailLog::open(dir.clone()).unwrap();
        assert_eq!(entries.len(), 1, "at-least-once: the message comes back rather than vanishing");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_foreign_file_is_loud_not_silently_empty() {
        let dir = tmp("magic");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mail.log"), b"NOPE and then some bytes").unwrap();
        assert!(
            MailLog::open(dir.clone()).is_err(),
            "an unreadable log must refuse to start, not pretend the relay has no mail"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compaction_shrinks_the_log_without_changing_what_it_holds() {
        let dir = tmp("compact");
        let (mut log, _) = MailLog::open(dir.clone()).unwrap();
        // Deposit then delete far past the compaction threshold, leaving one live entry.
        for i in 0..COMPACT_MIN_DEAD {
            let p = seal((i % 251) as u8);
            log.deposit([1u8; 32], i as u64, &p).unwrap();
            log.delete([1u8; 32], &p);
        }
        log.deposit([9u8; 32], 7, &seal(200)).unwrap();
        let before = log.record_count();
        drop(log);

        let (log, entries) = MailLog::open(dir.clone()).unwrap();
        assert_eq!(entries.len(), 1, "only the live entry replays");
        assert_eq!(entries[0].mailbox[0], 9);
        assert!(log.record_count() < before, "compaction rewrote {before} records to {}", log.record_count());
        std::fs::remove_dir_all(&dir).ok();
    }
}
