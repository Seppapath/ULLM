// SPDX-License-Identifier: Apache-2.0
//! Append-only log with optional file-backed persistence.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::merkle::merkle_root;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub id_pk_hex: String,
    pub evidence_sha256_hex: String,
    pub observed_at_unix: u64,
}

impl LogEntry {
    /// Canonical serialization for hashing — JSON sorted by key, no
    /// whitespace. P7-5/6/7 audit: use an explicit `BTreeMap` so the
    /// ordering is independent of `serde_json`'s internal map type
    /// (newer releases use `IndexMap` which preserves insertion order
    /// rather than sorting). The previous form happened to produce
    /// sorted output because of an implementation detail; this form is
    /// future-proof.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut m: std::collections::BTreeMap<&'static str, serde_json::Value> =
            std::collections::BTreeMap::new();
        m.insert(
            "evidence_sha256_hex",
            serde_json::json!(self.evidence_sha256_hex),
        );
        m.insert("id_pk_hex", serde_json::json!(self.id_pk_hex));
        m.insert("observed_at_unix", serde_json::json!(self.observed_at_unix));
        m.insert("seq", serde_json::json!(self.seq));
        serde_json::to_vec(&m).expect("json")
    }

    /// Convenience for callers that haven't computed the evidence hash yet.
    pub fn from_evidence(seq: u64, id_pk: [u8; 32], evidence_bytes: &[u8], observed_at_unix: u64) -> Self {
        let evidence_sha256_hex = hex::encode(Sha256::digest(evidence_bytes));
        Self {
            seq,
            id_pk_hex: hex::encode(id_pk),
            evidence_sha256_hex,
            observed_at_unix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStatus {
    pub size: u64,
    pub root_hex: String,
}

/// Persistence-durability policy for `TransparencyLog::append`.
///
/// PR-3 audit: per-append `f.sync_data()` is correct (every successful
/// `append` is durable) but caps throughput at ~the disk's
/// fsync-rate, ~100 req/sec on commodity SSDs. Production deployments
/// running behind a witness-cosigner can safely batch fsync's at the
/// cost of losing up to `every_n - 1` recent entries on crash. The
/// loss is detectable by witnesses, so the audit chain stays sound.
#[derive(Debug, Clone, Copy)]
pub enum FsyncPolicy {
    /// fsync after every successful `append`. Default. Throughput is
    /// bounded by disk fsync rate but no entries are ever lost.
    Always,
    /// fsync every Nth append. A crash loses up to `n - 1` recent
    /// entries; witnesses see the truncation. Setting `n = 1` is
    /// equivalent to `Always`.
    Periodic { every_n: u32 },
}

impl Default for FsyncPolicy {
    fn default() -> Self {
        Self::Always
    }
}

struct State {
    entries: Vec<LogEntry>,
    file: Option<std::fs::File>,
    /// Counts appends since the last fsync — drives the `Periodic`
    /// policy. Unused under `Always`.
    appends_since_sync: u32,
    fsync_policy: FsyncPolicy,
}

pub struct TransparencyLog {
    inner: Mutex<State>,
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

/// P9-FIX-A: best-effort fsync on drop. The gateway binary's normal
/// shutdown path drops the `Arc<TransparencyLog>` when `main` returns;
/// under `FsyncPolicy::Periodic` the tail of unsynced appends would
/// otherwise be lost if the orchestrator force-terminated the process
/// before the next periodic fsync. We can't return an error from
/// `Drop`, so we swallow it — operators see the same "tail loss"
/// detection through the witness chain as documented. Mutex poison is
/// ignored: we still want the fsync attempt to run.
impl Drop for TransparencyLog {
    fn drop(&mut self) {
        // `Mutex::get_mut` bypasses the lock since we have unique
        // access via `&mut self`. Cannot fail spuriously.
        let state = self.inner.get_mut();
        if let Some(f) = state.file.as_mut() {
            let _ = f.sync_data();
        }
    }
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(State {
                entries: Vec::new(),
                file: None,
                appends_since_sync: 0,
                fsync_policy: FsyncPolicy::default(),
            }),
        }
    }

    /// Switch the log's fsync policy. Takes effect immediately on the
    /// next `append`. Safe to call from operator code (e.g., a binary
    /// that reads `ULLM_LOG_FSYNC_EVERY_N` from the environment).
    pub fn set_fsync_policy(&self, policy: FsyncPolicy) {
        let mut state = self.inner.lock();
        state.fsync_policy = policy;
        state.appends_since_sync = 0;
    }

    /// Force an fsync of any pending appends. Operators (and the
    /// pre-STH signing path) call this when they need a durability
    /// barrier — e.g. before signing a tree head under the `Periodic`
    /// policy.
    pub fn flush(&self) -> std::io::Result<()> {
        let mut state = self.inner.lock();
        if let Some(f) = state.file.as_mut() {
            f.sync_data()?;
        }
        state.appends_since_sync = 0;
        Ok(())
    }

    /// Open or create a JSONL-backed log at `path`. If the file exists, all
    /// existing entries are loaded into memory and the next append continues
    /// from the highest seq.
    ///
    /// SECURITY: the `seq` field on each persisted line is **re-derived
    /// from file position** rather than trusted as-stored. If an attacker
    /// edits the JSONL out-of-band and tampers with the `seq`, we detect
    /// it and refuse to open the log rather than silently importing a
    /// re-ordered history.
    pub fn open_persistent(path: PathBuf) -> std::io::Result<Self> {
        use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write as IoWrite};

        // P11-FIX-B: hard cap on per-line bytes during reopen. The
        // previous P10-FIX-C used `read_to_end` which slurped the
        // entire file into RAM — an attacker (or accumulated growth)
        // producing a multi-GB log would OOM the binary at startup.
        // We now stream with `read_until(b'\n', ...)` and refuse
        // overly-long single lines so an adversarial file can't
        // exhaust memory.
        const MAX_REOPEN_LINE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

        let mut entries: Vec<LogEntry> = Vec::new();
        // P10-FIX-C: under `FsyncPolicy::Periodic`, a crash mid-write
        // can leave the file's tail as an unterminated, partially-
        // flushed line. The reopen path parses lines one by one. On
        // JSON-parse failure *at the last line only and without a
        // trailing newline*, assume torn write, log a warning, and
        // truncate the file to the end of the last good line.
        // Failures earlier in the file are fatal (tampering / real
        // corruption mid-stream).
        //
        // P11-FIX-B: track whether the *last* successfully-parsed
        // line was newline-terminated. If it wasn't, the file ends
        // exactly at a JSON `}`. The previous code set `good_end =
        // cursor` and let the next `append(true)` write at EOF —
        // gluing the new line's `{"seq":...}` directly onto the prior
        // `}` and producing an irreparable double-object line that
        // would refuse to parse on the NEXT reopen. We now write a
        // single `\n` to the file before opening it for append, so
        // every subsequent append starts on its own line.
        let mut last_good_terminated = true;
        if path.exists() {
            let f = std::fs::File::open(&path)?;
            let mut reader = BufReader::new(f);
            let mut good_end: u64 = 0; // byte offset of the end of the last successfully-parsed line (incl. its `\n` if any)
            let mut cursor: u64 = 0;
            // P12-FIX-C: strip a leading UTF-8 BOM if present. A log
            // file accidentally re-saved through a BOM-adding editor
            // (PowerShell `Out-File` default, Notepad "UTF-8 with
            // signature") would otherwise make `serde_json::from_str`
            // reject line 0 — the gateway would refuse to start.
            // BOM is 3 bytes (`\xef\xbb\xbf`); we peek-and-consume.
            {
                use std::io::BufRead as _;
                let buf = reader.fill_buf()?;
                if buf.starts_with(b"\xef\xbb\xbf") {
                    reader.consume(3);
                    cursor = 3;
                    good_end = 3;
                    tracing::info!(
                        path = %path.display(),
                        "transparency log: stripped leading UTF-8 BOM on reopen"
                    );
                }
            }
            loop {
                let mut chunk = Vec::new();
                // P12-FIX-C: off-by-one fix on the cap. We want to
                // ACCEPT a line whose content is up to
                // `MAX_REOPEN_LINE_BYTES` and reject anything larger.
                // `read_until` includes the trailing `\n` in the
                // chunk, so a legitimate max-size line reads
                // `MAX + 1` bytes total. Cap the underlying reader
                // at `MAX + 2` and reject only if `read > MAX + 1`
                // (content + newline).
                let read = reader.by_ref()
                    .take(MAX_REOPEN_LINE_BYTES + 2)
                    .read_until(b'\n', &mut chunk)?;
                if read == 0 {
                    break;
                }
                if read as u64 > MAX_REOPEN_LINE_BYTES + 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "log file line at offset {} exceeds {}-byte cap (got {} bytes); \
                             refusing to load",
                            cursor, MAX_REOPEN_LINE_BYTES, read
                        ),
                    ));
                }
                let chunk_len = chunk.len() as u64;
                let cursor_start = cursor;
                cursor += chunk_len;
                let terminated = chunk.last() == Some(&b'\n');
                let is_last_chunk = !terminated; // read_until returns unterminated only at EOF
                let trimmed: &[u8] = if terminated {
                    &chunk[..chunk.len() - 1]
                } else {
                    &chunk
                };
                if trimmed.iter().all(|b| b.is_ascii_whitespace()) {
                    if terminated {
                        good_end = cursor;
                    }
                    continue;
                }
                let line = std::str::from_utf8(trimmed).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("log line at offset {cursor_start}: {e}"),
                    )
                })?;
                // P12-FIX-D: defense-in-depth pre-scan. serde_json's
                // default recursion limit is 128 so a deeply-nested
                // attacker-planted JSON cannot stack-overflow, but
                // `LogEntry` is a flat struct with at most depth ~4 in
                // legitimate use (object → array of hex strings).
                // Reject anything with > 32 unmatched `{`/`[` brackets
                // early so a malicious file never reaches the
                // serde_json deserializer at adversarial depth.
                const MAX_JSON_DEPTH: usize = 32;
                let mut depth = 0usize;
                let mut max_depth = 0usize;
                let mut in_string = false;
                let mut escaped = false;
                for &b in line.as_bytes() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if in_string {
                        match b {
                            b'\\' => escaped = true,
                            b'"' => in_string = false,
                            _ => {}
                        }
                        continue;
                    }
                    match b {
                        b'"' => in_string = true,
                        b'{' | b'[' => {
                            depth += 1;
                            if depth > max_depth {
                                max_depth = depth;
                            }
                            if depth > MAX_JSON_DEPTH {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "log line at offset {cursor_start}: JSON nesting \
                                         depth exceeds {MAX_JSON_DEPTH} (LogEntry is flat; \
                                         deep nesting is unexpected and refused)"
                                    ),
                                ));
                            }
                        }
                        b'}' | b']' => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                }
                let _ = max_depth; // for future telemetry
                match serde_json::from_str::<LogEntry>(line) {
                    Ok(entry) => {
                        let expected_seq = entries.len() as u64;
                        if entry.seq != expected_seq {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "log file tampered at offset {cursor_start}: \
                                     entry at position {expected_seq} declared seq {}",
                                    entry.seq
                                ),
                            ));
                        }
                        entries.push(entry);
                        good_end = cursor;
                        last_good_terminated = terminated;
                    }
                    Err(e) => {
                        if is_last_chunk {
                            // Torn-write recovery: truncate to the
                            // end of the last good line.
                            tracing::warn!(
                                path = %path.display(),
                                bytes_dropped = chunk_len,
                                "transparency log: torn-write tail detected on reopen; \
                                 truncating to last good line"
                            );
                            let trunc = OpenOptions::new().write(true).open(&path)?;
                            trunc.set_len(good_end)?;
                            trunc.sync_data()?;
                        } else {
                            // Mid-stream parse error = real corruption.
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("log line at offset {cursor_start}: {e}"),
                            ));
                        }
                    }
                }
            }
            // Belt-and-suspenders: leave the read handle at EOF so
            // the OS releases any read-side caching pin before reopen.
            let _ = reader.seek(SeekFrom::End(0));
            // P11-FIX-B: if the last successfully-parsed line lacked
            // a trailing newline (perfectly-clean prior append that
            // happened not to flush its own `\n` somehow, or a
            // file-format pre-fix from earlier ullm versions), pad
            // the file with a `\n` so subsequent appends start on
            // their own line.
            if !last_good_terminated && !entries.is_empty() {
                let mut pad = OpenOptions::new().append(true).open(&path)?;
                pad.write_all(b"\n")?;
                pad.sync_data()?;
                tracing::warn!(
                    path = %path.display(),
                    "transparency log: prior tail lacked terminating newline; \
                     padded with `\\n` before resuming append"
                );
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            inner: Mutex::new(State {
                entries,
                file: Some(file),
                appends_since_sync: 0,
                fsync_policy: FsyncPolicy::default(),
            }),
        })
    }

    /// Append a new attested-bundle observation. Returns the assigned seq
    /// on success; returns `Err` if the persistence write or fsync fails
    /// (callers should treat that as a hard error rather than continuing
    /// with a divergent in-memory log).
    pub fn append(
        &self,
        id_pk: [u8; 32],
        evidence_bytes: &[u8],
        observed_at_unix: u64,
    ) -> std::io::Result<u64> {
        let mut state = self.inner.lock();
        let seq = state.entries.len() as u64;
        let entry = LogEntry::from_evidence(seq, id_pk, evidence_bytes, observed_at_unix);
        // Destructure so the borrow checker can see `file`, the counter,
        // and the policy as disjoint fields. PR-3.
        let State {
            ref mut file,
            ref mut appends_since_sync,
            fsync_policy,
            ..
        } = *state;
        if let Some(f) = file.as_mut() {
            let line = serde_json::to_string(&entry)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
            // PR-3: fsync policy. `Always` matches the original behaviour
            // (every successful `append` is durable). `Periodic { every_n }`
            // amortises the fsync cost across batches at the price of
            // crash-losing up to `every_n - 1` recent entries; operators
            // running behind witnesses opt into this for throughput.
            *appends_since_sync = appends_since_sync.saturating_add(1);
            let should_sync = match fsync_policy {
                FsyncPolicy::Always => true,
                FsyncPolicy::Periodic { every_n } => {
                    every_n <= 1 || *appends_since_sync >= every_n
                }
            };
            if should_sync {
                f.sync_data()?;
                *appends_since_sync = 0;
            }
        }
        state.entries.push(entry);
        Ok(seq)
    }

    pub fn status(&self) -> LogStatus {
        let state = self.inner.lock();
        LogStatus {
            size: state.entries.len() as u64,
            root_hex: hex::encode(merkle_root(&state.entries)),
        }
    }

    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.inner.lock().entries.clone()
    }

    pub fn entry(&self, seq: u64) -> Option<LogEntry> {
        let state = self.inner.lock();
        state.entries.get(seq as usize).cloned()
    }

    pub fn entries_slice(&self, start: u64, end_exclusive: u64) -> Vec<LogEntry> {
        let state = self.inner.lock();
        let start = (start as usize).min(state.entries.len());
        let end = (end_exclusive as usize).min(state.entries.len());
        state.entries[start..end].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn append_and_status() {
        let log = TransparencyLog::new();
        assert_eq!(log.status().size, 0);
        log.append([1u8; 32], b"evidence-1", 100).unwrap();
        log.append([2u8; 32], b"evidence-2", 200).unwrap();
        let s = log.status();
        assert_eq!(s.size, 2);
        // Same two appends produce the same root.
        let log2 = TransparencyLog::new();
        log2.append([1u8; 32], b"evidence-1", 100).unwrap();
        log2.append([2u8; 32], b"evidence-2", 200).unwrap();
        assert_eq!(log2.status().root_hex, s.root_hex);
    }

    #[test]
    fn persistence_survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        {
            let log = TransparencyLog::open_persistent(path.clone()).unwrap();
            log.append([1u8; 32], b"a", 1).unwrap();
            log.append([2u8; 32], b"b", 2).unwrap();
            assert_eq!(log.status().size, 2);
        }
        let reopened = TransparencyLog::open_persistent(path).unwrap();
        let s = reopened.status();
        assert_eq!(s.size, 2);
        let entries = reopened.snapshot();
        assert_eq!(entries[0].id_pk_hex, hex::encode([1u8; 32]));
        assert_eq!(entries[1].id_pk_hex, hex::encode([2u8; 32]));

        // Continued append picks up where it left off.
        reopened.append([3u8; 32], b"c", 3).unwrap();
        assert_eq!(reopened.status().size, 3);
        let lines: Vec<_> = std::fs::read_to_string(dir.path().join("log.jsonl"))
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(lines.len(), 3);
    }

    /// Regression for PR-3: `FsyncPolicy::Periodic { every_n: 1 }`
    /// behaves identically to `Always` (degenerate batch), and
    /// `Periodic { every_n: 3 }` only emits one fsync per three
    /// appends but every entry is still flushed by an explicit
    /// `flush()` call before reopen.
    #[test]
    fn batched_fsync_preserves_durability_after_flush() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let log = TransparencyLog::open_persistent(path.clone()).unwrap();
        log.set_fsync_policy(FsyncPolicy::Periodic { every_n: 3 });
        log.append([1u8; 32], b"a", 1).unwrap();
        log.append([2u8; 32], b"b", 2).unwrap();
        // Only one fsync would have happened by here (after the 3rd
        // append). Force a flush so the buffered second entry hits
        // disk before we close.
        log.flush().unwrap();
        drop(log);

        // Reopen and confirm both entries are durable.
        let reopened = TransparencyLog::open_persistent(path).unwrap();
        assert_eq!(reopened.status().size, 2);
    }

    /// Regression for F-10: a tampered seq on disk must be detected on reopen.
    #[test]
    fn rejects_tampered_seq_on_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        {
            let log = TransparencyLog::open_persistent(path.clone()).unwrap();
            log.append([1u8; 32], b"a", 1).unwrap();
            log.append([2u8; 32], b"b", 2).unwrap();
        }
        // Tamper: rewrite the first line so its seq claims position 5.
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
        lines[0] = lines[0].replace("\"seq\":0", "\"seq\":5");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // Reopen must reject the tampered file.
        let result = TransparencyLog::open_persistent(path);
        assert!(
            result.is_err(),
            "expected reopen to refuse a tampered seq, got {:?}",
            result.as_ref().map(|_| "Ok(...)").err()
        );
    }

    /// Regression for P12-FIX-C: a log file accidentally re-saved
    /// through a BOM-adding editor (PowerShell `Out-File`, Notepad
    /// "UTF-8 with signature") has a leading 3-byte UTF-8 BOM. The
    /// pre-fix reopen path passed the BOM bytes to
    /// `serde_json::from_str` which rejected line 0 as malformed,
    /// making the gateway refuse to start. Now we strip the BOM on
    /// reopen and continue normally.
    #[test]
    fn reopen_strips_leading_utf8_bom() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        {
            let log = TransparencyLog::open_persistent(path.clone()).unwrap();
            log.append([1u8; 32], b"a", 1).unwrap();
            log.append([2u8; 32], b"b", 2).unwrap();
        }
        // Prepend BOM to the file. Rewrite atomically via a buffer.
        let raw = std::fs::read(&path).unwrap();
        let mut prefixed = Vec::with_capacity(raw.len() + 3);
        prefixed.extend_from_slice(b"\xef\xbb\xbf");
        prefixed.extend_from_slice(&raw);
        std::fs::write(&path, &prefixed).unwrap();
        // Reopen must succeed and report both entries.
        let reopened = TransparencyLog::open_persistent(path).unwrap();
        assert_eq!(reopened.status().size, 2, "BOM-prefixed log must reopen cleanly");
    }

    /// Regression for P10-FIX-C: a torn-write tail (a partially-flushed
    /// final line, the realistic crash-under-Periodic-fsync scenario)
    /// must NOT cause `open_persistent` to refuse the file. Instead the
    /// tail bytes are truncated, a `tracing::warn!` is emitted, and
    /// reopen succeeds with the prior-good-line set of entries.
    #[test]
    fn torn_write_tail_recovers_on_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        {
            let log = TransparencyLog::open_persistent(path.clone()).unwrap();
            log.append([1u8; 32], b"a", 1).unwrap();
            log.append([2u8; 32], b"b", 2).unwrap();
        }
        // Simulate a torn write: append a partial JSON object without a
        // trailing newline, as if the process crashed mid-write.
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"{\"seq\":2,\"id_pk_hex\":\"deadbe").unwrap();
        drop(f);

        // Reopen must succeed, drop the torn line, and report size 2.
        let reopened = TransparencyLog::open_persistent(path.clone()).unwrap();
        assert_eq!(
            reopened.status().size,
            2,
            "torn-write recovery left the wrong number of entries"
        );
        // The file should be truncated to the end of line 2 — confirm
        // by reading and counting newlines.
        let raw = std::fs::read_to_string(&path).unwrap();
        let nl_count = raw.bytes().filter(|b| *b == b'\n').count();
        assert_eq!(nl_count, 2, "expected exactly 2 newlines after recovery");

        // A subsequent append must continue cleanly from seq=2.
        reopened.append([3u8; 32], b"c", 3).unwrap();
        assert_eq!(reopened.status().size, 3);
    }
}
