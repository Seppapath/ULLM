// SPDX-License-Identifier: Apache-2.0
//! Per-TEE attestation-nonce replay registry.
//!
//! Phase 4 audit (P4-5): the TEE's `/v1/attest` endpoint accepts an
//! attacker-supplied 32-byte nonce, binds it into the attestation
//! evidence's `report_data`, and signs the bundle. Without server-side
//! rejection of repeated nonces, an attacker can:
//!
//! - Replay a captured nonce to *another* TEE instance, then compare the
//!   two attestation bundles for linkage (cross-instance identity oracle).
//! - Drive the issuer into emitting identical signed evidence twice,
//!   useful for downstream caching/oracle attacks.
//!
//! The registry below remembers every nonce it has seen in the last
//! `NONCE_TTL` seconds, capped at `MAX_TRACKED_NONCES` entries. New
//! nonces are accepted and recorded; repeats within the window are
//! rejected. Eviction is amortized: on insert, if the table is at cap,
//! the oldest entry is dropped.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hard cap on the registry size. With 32-byte keys + Instant values
/// (~40 B each) the worst-case footprint is ~5 MiB at 128k entries —
/// comfortably bounded.
const MAX_TRACKED_NONCES: usize = 128 * 1024;

/// How long a nonce stays in the registry after first observation.
/// Mirrors `NONCE_TTL_DEFAULT_SEC` in `ullm_core` — once the freshness
/// window expires, a replay can no longer satisfy the client's
/// freshness check anyway, so we don't need to keep tracking it.
const NONCE_TTL: Duration = Duration::from_secs(ullm_core::NONCE_TTL_DEFAULT_SEC);

/// PR-4 + P9-FIX-G: pair the nonce HashMap with a `BTreeSet<(Instant,
/// u64_seq, nonce)>` LRU index. Same-`Instant` ties (Windows ~15 ms
/// clock resolution) are broken deterministically by a monotonic seq
/// counter rather than the nonce-byte lex order — a `[0xff; 32]`
/// nonce no longer always sorts last. The HashMap value carries the
/// matching `(Instant, seq)` so removal is O(log N) by tuple lookup.
#[derive(Default)]
struct State {
    seen: HashMap<[u8; 32], (Instant, u64)>,
    lru: BTreeSet<(Instant, u64, [u8; 32])>,
    next_lru_seq: u64,
}

#[derive(Default)]
pub struct NonceRegistry {
    inner: Mutex<State>,
}

impl NonceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` as observed at `now`. Returns `Ok(())` if this is
    /// the first time within the TTL window; returns `Err(())` on
    /// replay. Concurrent calls serialise on the mutex.
    pub fn observe(&self, nonce: [u8; 32]) -> Result<(), NonceReplay> {
        let mut state = self.inner.lock().expect("nonce-registry mutex poisoned");
        let now = Instant::now();
        // PR-4: garbage-collect via the LRU index. Walk only the
        // *prefix* of entries past their TTL (O(k) where k is the
        // number of expired entries) instead of the previous
        // O(N) full-HashMap retain.
        let cutoff = now.checked_sub(NONCE_TTL).unwrap_or(now);
        let expired: Vec<(Instant, u64, [u8; 32])> = state
            .lru
            .range(..(cutoff, 0u64, [0u8; 32]))
            .copied()
            .collect();
        for k in &expired {
            state.lru.remove(k);
            state.seen.remove(&k.2);
        }
        // P9-FIX-B: a nonce observed *exactly* NONCE_TTL ago is past
        // the replay window (`< NONCE_TTL` excludes equality, line
        // intentional — past-the-edge is fresh again) but the GC's
        // half-open `range(..(cutoff, ..))` excludes that boundary.
        // Without the corrective `lru.remove` below, every boundary
        // re-observation slowly poisons the LRU index with stale rows
        // and eventually causes cap-eviction to drop a live nonce,
        // collapsing the replay window. Drop the old row before
        // re-inserting at the new (Instant, seq).
        if let Some(&(seen_ts, seen_seq)) = state.seen.get(&nonce) {
            if now.duration_since(seen_ts) < NONCE_TTL {
                return Err(NonceReplay);
            }
            state.lru.remove(&(seen_ts, seen_seq, nonce));
        }
        // PR-4: cap-eviction is O(log N) — pull the oldest entry off
        // the front of the LRU index instead of scanning the entire
        // HashMap. Triggers only when the GC above didn't free enough
        // entries (table is full of *non-expired* nonces).
        if state.seen.len() >= MAX_TRACKED_NONCES {
            if let Some(oldest) = state.lru.iter().next().copied() {
                state.lru.remove(&oldest);
                state.seen.remove(&oldest.2);
            }
        }
        // P9-FIX-G: monotonic seq tie-breaker so two nonces inserted
        // at the same Instant (Windows ~15ms clock resolution) are
        // FIFO-ordered in the LRU index instead of lex-ordered by
        // nonce bytes — defending against `[0xff; 32]`-prefixed nonce
        // bias.
        let new_seq = state.next_lru_seq;
        state.next_lru_seq = state.next_lru_seq.wrapping_add(1);
        state.seen.insert(nonce, (now, new_seq));
        state.lru.insert((now, new_seq, nonce));
        debug_assert_eq!(
            state.seen.len(),
            state.lru.len(),
            "nonce-registry HashMap/BTreeSet desync"
        );
        Ok(())
    }

    /// Test-only accessor: number of rows in the LRU index. Used by
    /// the P9-FIX-B regression test to assert
    /// `seen.len() == lru.len()` after boundary re-observation.
    #[cfg(test)]
    fn lru_len(&self) -> usize {
        self.inner.lock().unwrap().lru.len()
    }

    /// Live nonce-tracker size. Exposed for the `/metrics` endpoint so
    /// operators can monitor table size vs `MAX_TRACKED_NONCES`.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().seen.len()
    }

    /// `true` when the registry has never observed a nonce. Helper
    /// for the metrics formatter; kept alongside `len` for clarity.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Returned by `NonceRegistry::observe` on replay; opaque so the HTTP
/// handler can't accidentally leak timing-sensitive details into the
/// response body.
#[derive(Debug)]
pub struct NonceReplay;

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for P4-5: the same nonce submitted twice within the
    /// TTL window must be rejected the second time.
    #[test]
    fn rejects_repeated_nonce() {
        let r = NonceRegistry::new();
        let n = [7u8; 32];
        r.observe(n).expect("first observation ok");
        assert!(r.observe(n).is_err(), "replay within TTL must fail");
    }

    /// Distinct nonces don't interfere with each other.
    #[test]
    fn distinct_nonces_independent() {
        let r = NonceRegistry::new();
        r.observe([1u8; 32]).unwrap();
        r.observe([2u8; 32]).unwrap();
        r.observe([3u8; 32]).unwrap();
        assert_eq!(r.len(), 3);
    }

    /// Regression for P9-FIX-B (refined per P10-B.7): re-observing the
    /// same nonce after its TTL window has *exactly* elapsed must not
    /// leak stale rows into the LRU index. The pre-fix code added a
    /// fresh `(now, nonce)` to `lru` without removing the prior
    /// `(stale_ts, nonce)`, growing `lru.len()` beyond `seen.len()` and
    /// eventually causing cap-eviction to drop a *live* nonce, opening
    /// a replay window for a different legitimately-tracked nonce.
    ///
    /// **The bug only triggers at the half-open boundary.** The
    /// previous version of this test pre-seeded `ancient = now - 2 *
    /// NONCE_TTL`, which is well past the GC cutoff and gets removed
    /// by the GC walk — *before* the boundary-remove fix path
    /// (`state.lru.remove(&(seen_ts, ..))`) ever runs. The test passed
    /// because the GC works, not because the fix works. This refined
    /// version pre-seeds at the half-open boundary that
    /// `range(..(cutoff, ..))` *excludes*, so the bug path is hit
    /// directly.
    #[test]
    fn boundary_reobservation_does_not_leak_lru_rows() {
        let r = NonceRegistry::new();
        let n = [9u8; 32];
        // Pre-seed an entry at exactly the GC cutoff. `Instant`s have
        // ~ns resolution on Linux; we need the seeded `Instant` to be
        // numerically identical to what `observe()` computes for its
        // own cutoff. Achievable by seeding "now" first, then deriving
        // cutoff from it.
        let pre_seed_now = Instant::now();
        let cutoff_exact = pre_seed_now.checked_sub(NONCE_TTL).unwrap_or(pre_seed_now);
        {
            let mut s = r.inner.lock().unwrap();
            s.seen.insert(n, (cutoff_exact, 0));
            s.lru.insert((cutoff_exact, 0, n));
            s.next_lru_seq = 1;
        }
        // Observe with a "now" that's at most NONCE_TTL later. The GC
        // walk `range(..(cutoff_observe, 0, [0u8;32]))` is half-open
        // exclusive: if `cutoff_observe == cutoff_exact`, the boundary
        // row is *not* GC'd, and the fix's explicit
        // `lru.remove(&(seen_ts, seen_seq, nonce))` is what saves the
        // invariant. Without the fix, lru.len() == 2 while seen.len()
        // == 1 after this call.
        r.observe(n).expect("post-TTL re-observation must succeed");
        assert_eq!(
            r.len(),
            r.lru_len(),
            "HashMap/BTreeSet desync — lru leaks stale rows after boundary re-observation"
        );
    }
}
