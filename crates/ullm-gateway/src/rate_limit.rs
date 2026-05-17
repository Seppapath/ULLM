// SPDX-License-Identifier: Apache-2.0
//! Blind token-bucket rate limiter keyed on tenant identity.
//!
//! The gateway cannot inspect plaintext, but it CAN see:
//! - tenant ID from the auth header
//! - ciphertext byte count per direction
//! - request rate
//!
//! Per-tenant buckets refill at a configured rate. The bucket map is hard
//! capped at `max_tenants` to deny an attacker the "spam unique tenants
//! until the gateway OOMs" path (P2-3); once the cap is hit, the LRU bucket
//! (the one with the oldest `last_refill`) is evicted to make room.
//!
//! Phase 2 will add per-session sub-buckets.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Copy)]
pub struct RateLimiterConfig {
    pub bytes_per_sec: u64,
    pub burst_bytes: u64,
    /// Hard cap on the number of distinct tenants we'll track simultaneously.
    /// Setting this to 0 disables the limit (not recommended in prod).
    pub max_tenants: usize,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            bytes_per_sec: 1_000_000,
            burst_bytes: 4_000_000,
            // 16K distinct tenants × ~200 B per bucket ≈ 3 MB worst case —
            // a comfortable ceiling for legit multi-tenant deployments,
            // small enough that an attacker can't fill RAM by spamming
            // unique tenant IDs.
            max_tenants: 16 * 1024,
        }
    }
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    /// P9-FIX-G: monotonic per-insert sequence number. Two updates that
    /// land on the same `Instant` (Windows ~15 ms clock resolution
    /// under burst load) used to tie-break by tenant-string lex order
    /// — an attacker picking a `"\xff..."`-prefixed tenant ID then
    /// always sorted last and pushed legitimate `"acme"`-style names
    /// to be evicted first. The seq counter is monotonic per access
    /// so collisions are tie-broken deterministically FIFO, regardless
    /// of tenant-string bytes.
    lru_seq: u64,
}

struct Inner {
    buckets: HashMap<String, Bucket>,
    /// PR-4 + P9-FIX-G: LRU index sorted by `(last_refill, lru_seq,
    /// tenant)`. Eviction finds the oldest bucket in O(log N) via
    /// `BTreeSet::first()`. Same-`Instant` ties are broken by the
    /// monotonic seq (FIFO), then by tenant string (defensive — seq
    /// is already unique).
    lru_index: BTreeSet<(Instant, u64, String)>,
    /// Source of `lru_seq` values — increments on every insert into
    /// `lru_index`. Wraps at u64::MAX; in practice would take ~6
    /// million years at a billion ops/sec, so the wrap is unreachable.
    next_lru_seq: u64,
    /// Wall-clock of the most recent eviction event. P3-4: when buckets
    /// are being evicted faster than they refill, the table is under
    /// adversarial pressure and new entrants should not receive a full
    /// burst allowance.
    last_eviction: Option<Instant>,
}

pub struct RateLimiter {
    cfg: RateLimiterConfig,
    inner: Mutex<Inner>,
}

/// Cooldown window after an eviction during which new buckets are
/// "throttled-fresh": instead of starting at the full `burst_bytes`, they
/// start at 1/8 burst. An attacker rotating unique tenant IDs to evade
/// rate-limiting now pays a 7/8 quota penalty for every cycle, and the
/// per-bucket refill rate is the only way to recover. Legitimate first-time
/// tenants encountered during quiescent periods still get the full burst.
const EVICTION_COOLDOWN_SECS: f64 = 60.0;

/// Fraction of `burst_bytes` granted to a new bucket created while the
/// table is under eviction pressure.
const COLD_BURST_FRACTION: f64 = 0.125;

impl RateLimiter {
    pub fn new(cfg: RateLimiterConfig) -> Self {
        Self {
            cfg,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                lru_index: BTreeSet::new(),
                next_lru_seq: 0,
                last_eviction: None,
            }),
        }
    }

    /// Try to charge `bytes` to `tenant`. Returns `true` if allowed.
    pub fn try_charge(&self, tenant: &str, bytes: u64) -> bool {
        let mut inner = self.inner.lock().expect("rate-limiter mutex poisoned");
        let now = Instant::now();
        if !inner.buckets.contains_key(tenant) {
            // PR-4: evict the LRU bucket in O(log N) via `BTreeSet::first`
            // instead of the previous full-table linear scan.
            let mut evicted_now = false;
            if self.cfg.max_tenants > 0 && inner.buckets.len() >= self.cfg.max_tenants {
                if let Some((victim_ts, victim_seq, victim_key)) =
                    inner.lru_index.iter().next().cloned()
                {
                    inner.buckets.remove(&victim_key);
                    inner.lru_index.remove(&(victim_ts, victim_seq, victim_key));
                    evicted_now = true;
                }
            }
            // P3-4: if the table is hot (eviction within the cooldown
            // window, including the eviction we just performed), seed the
            // new bucket with `COLD_BURST_FRACTION * burst` rather than the
            // full burst. This denies an attacker the "rotate tenants to
            // reset bucket" amplification path.
            let under_pressure = evicted_now
                || inner.last_eviction.map_or(false, |t| {
                    now.duration_since(t).as_secs_f64() < EVICTION_COOLDOWN_SECS
                });
            let starting_tokens = if under_pressure {
                self.cfg.burst_bytes as f64 * COLD_BURST_FRACTION
            } else {
                self.cfg.burst_bytes as f64
            };
            if evicted_now {
                inner.last_eviction = Some(now);
            }
            let new_seq = inner.next_lru_seq;
            inner.next_lru_seq = inner.next_lru_seq.wrapping_add(1);
            let tenant_owned = tenant.to_string();
            inner.buckets.insert(
                tenant_owned.clone(),
                Bucket {
                    tokens: starting_tokens,
                    last_refill: now,
                    lru_seq: new_seq,
                },
            );
            inner.lru_index.insert((now, new_seq, tenant_owned));
        }
        // Pull the current timestamp + seq out of the bucket so we can
        // update the LRU index *before* taking the &mut borrow on
        // `buckets`.
        let (old_ts, old_seq) = {
            let b = inner
                .buckets
                .get(tenant)
                .expect("tenant inserted above if absent");
            (b.last_refill, b.lru_seq)
        };
        inner
            .lru_index
            .remove(&(old_ts, old_seq, tenant.to_string()));
        let new_seq = inner.next_lru_seq;
        inner.next_lru_seq = inner.next_lru_seq.wrapping_add(1);
        inner
            .lru_index
            .insert((now, new_seq, tenant.to_string()));
        let bucket = inner
            .buckets
            .get_mut(tenant)
            .expect("tenant inserted above if absent");
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.cfg.bytes_per_sec as f64).min(self.cfg.burst_bytes as f64);
        bucket.last_refill = now;
        bucket.lru_seq = new_seq;
        if bucket.tokens >= bytes as f64 {
            bucket.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// Live tenant count. Exposed for the `/metrics` endpoint so
    /// operators can monitor table size vs `max_tenants`. Cheap (one
    /// mutex lock + `HashMap::len`).
    pub fn tenant_count(&self) -> usize {
        self.inner.lock().unwrap().buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_burst() {
        let rl = RateLimiter::new(RateLimiterConfig {
            bytes_per_sec: 100,
            burst_bytes: 1000,
            max_tenants: 1024,
        });
        assert!(rl.try_charge("acme", 500));
        assert!(rl.try_charge("acme", 500));
        assert!(!rl.try_charge("acme", 1));
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(RateLimiterConfig {
            bytes_per_sec: 10,
            burst_bytes: 10,
            max_tenants: 1024,
        });
        assert!(rl.try_charge("acme", 10));
        assert!(!rl.try_charge("acme", 10));
        std::thread::sleep(std::time::Duration::from_millis(1200));
        assert!(rl.try_charge("acme", 10));
    }

    /// Regression for P2-3: a flood of unique tenant strings must NOT grow
    /// the bucket map without bound. Once we hit `max_tenants`, each new
    /// tenant evicts the LRU one, keeping the working set steady.
    #[test]
    fn bucket_map_bounded_by_max_tenants() {
        let rl = RateLimiter::new(RateLimiterConfig {
            bytes_per_sec: 1_000_000,
            burst_bytes: 1_000_000,
            max_tenants: 4,
        });
        for i in 0..1000 {
            // Stagger timestamps so the LRU pick is well-defined.
            std::thread::sleep(std::time::Duration::from_micros(50));
            assert!(rl.try_charge(&format!("attacker-{i}"), 1));
        }
        assert_eq!(rl.tenant_count(), 4, "bucket map must respect max_tenants");
    }

    /// Regression for P3-4: once the table is under eviction pressure,
    /// brand-new tenants must NOT receive a full-burst allowance, so an
    /// attacker rotating identifiers can't amplify their effective rate by
    /// resetting their own bucket.
    #[test]
    fn eviction_pressure_throttles_new_bucket_burst() {
        let rl = RateLimiter::new(RateLimiterConfig {
            bytes_per_sec: 0, // disable refill so we measure starting tokens cleanly
            burst_bytes: 1_000_000,
            max_tenants: 2,
        });
        // Saturate the table.
        assert!(rl.try_charge("legit-a", 1));
        assert!(rl.try_charge("legit-b", 1));
        // A burst-sized request from a fresh tenant should fail because the
        // table is at cap → eviction → cold-burst seed = 1/8 burst = 125 000.
        // 500 000 is well over the cold-burst budget, so reject.
        assert!(!rl.try_charge("attacker-1", 500_000));
        // But a small request fits inside the cold burst — confirm that
        // we're not 0-tokens, just throttled.
        assert!(rl.try_charge("attacker-2", 50_000));
    }
}
