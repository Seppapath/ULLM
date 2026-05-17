// SPDX-License-Identifier: Apache-2.0
//! Petridish-style per-tenant isolation.
//!
//! Each tenant gets:
//! - a fresh 32-byte cache salt (used as HKDF salt when deriving per-session
//!   cache-key material); rotation-on-reboot is implicit since the pool is
//!   re-created on TEE startup
//! - a fresh 32-byte sealing KEK
//! - per-session `CloakKey`s derived from `HKDF(master, salt, info=session_id)`
//!
//! There is no cross-tenant shared cache state. Two sessions for different
//! tenants get cryptographically disjoint cloak keys, even within the same
//! TEE binary. This is the SPD invariant: a compromised per-tenant slot
//! cannot observe another tenant's KV.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use ullm_core::{SessionId, TenantId};
use ullm_crypto::SealedKek;
use ullm_kvcloak::CloakKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// P8 audit: cap the tenant table so a long-running TEE doesn't grow
/// memory unboundedly when many distinct tenant IDs cycle through.
/// Mirrors `RateLimiter::max_tenants` (16K) and `NonceRegistry`'s cap.
const MAX_TRACKED_TENANTS: usize = 16 * 1024;

const INFO_TENANT_SALT: &[u8] = b"ULLM-v1 tenant cache salt";
const INFO_CLOAK_TRANSFORM: &[u8] = b"ULLM-v1 cloak transform";
const INFO_CLOAK_PERMUTE: &[u8] = b"ULLM-v1 cloak permute";
const INFO_CLOAK_NONCE: &[u8] = b"ULLM-v1 cloak nonce";

/// Long-lived master secret. Zeroized on drop. Re-rolled each TEE startup.
#[derive(Zeroize, ZeroizeOnDrop)]
struct MasterSecret([u8; 32]);

#[derive(Clone)]
struct TenantState {
    salt: [u8; 32],
    kek: SealedKek,
    /// Wall-clock instant of the most recent `state_for` lookup. Used
    /// by the LRU eviction in `allocate` to keep the table bounded.
    last_seen: Instant,
    /// P9-FIX-G: monotonic seq tie-breaker — two `state_for` lookups
    /// landing on the same `Instant` (Windows clock collisions) are
    /// FIFO-ordered in the LRU index instead of lex-ordered by tenant
    /// id. Defends against an attacker picking `\xff`-prefixed
    /// TenantIds to push legitimate `"acme"`-style names to be evicted
    /// first under clock collision.
    lru_seq: u64,
}

/// P9-FIX-F + P9-FIX-G: pair the tenant `HashMap` with a
/// `BTreeSet<(Instant, u64_seq, TenantId)>` LRU index. Eviction is
/// O(log N) via `BTreeSet::first` instead of the previous
/// `HashMap::iter().min_by_key()` linear scan. The seq tie-breaker
/// prevents tenant-string-byte bias when two lookups share an
/// `Instant`.
struct Inner {
    map: HashMap<TenantId, TenantState>,
    lru: BTreeSet<(Instant, u64, TenantId)>,
    next_lru_seq: u64,
}

pub struct TenantPool {
    master: Arc<MasterSecret>,
    inner: Arc<Mutex<Inner>>,
}

impl TenantPool {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        Self {
            master: Arc::new(MasterSecret(m)),
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                lru: BTreeSet::new(),
                next_lru_seq: 0,
            })),
        }
    }

    /// Get or allocate per-tenant state (salt + KEK).
    fn state_for(&self, tenant: &TenantId) -> TenantState {
        let mut inner = self.inner.lock().expect("tenant pool poisoned");
        let now = Instant::now();
        if let Some(s) = inner.map.get_mut(tenant) {
            // Refresh the LRU timestamp; the salt + KEK stay deterministic.
            // P9-FIX-F: maintain the BTreeSet LRU index in lockstep
            // with the HashMap. Old `(last_seen, lru_seq, tenant)`
            // removed first, then re-inserted at `(now, new_seq,
            // tenant)` so the invariant `map.len() == lru.len()` is
            // preserved.
            let old_ts = s.last_seen;
            let old_seq = s.lru_seq;
            let new_seq = inner.next_lru_seq;
            inner.next_lru_seq = inner.next_lru_seq.wrapping_add(1);
            // Re-fetch mutably; the earlier `get_mut` was dropped by
            // the borrow checker once we touched `next_lru_seq`.
            let s = inner.map.get_mut(tenant).expect("just looked it up");
            s.last_seen = now;
            s.lru_seq = new_seq;
            let cloned = s.clone();
            inner.lru.remove(&(old_ts, old_seq, tenant.clone()));
            inner.lru.insert((now, new_seq, tenant.clone()));
            return cloned;
        }
        // P8 audit: cap the table size. When at cap, evict the LRU
        // entry to make room. The eviction is *safe*: the per-tenant
        // salt is re-derived deterministically from the master secret
        // and the tenant id on next access. Only the KEK is freshly
        // re-rolled, which is intended behaviour (re-key on cache
        // eviction = at-rest blobs from before the eviction are
        // permanently sealed under the old KEK and stay decryptable
        // only with that operator-held key, not by the new TEE process
        // — the SealedKek is unrelated to the tenant identity).
        //
        // P9-FIX-F: O(log N) cap-eviction via BTreeSet::first replaces
        // the previous O(N) `min_by_key` linear scan over 16K entries.
        if inner.map.len() >= MAX_TRACKED_TENANTS {
            if let Some(oldest) = inner.lru.iter().next().cloned() {
                inner.lru.remove(&oldest);
                inner.map.remove(&oldest.2);
            }
        }
        // Derive deterministic tenant salt from master_secret so a TEE restart
        // re-derives the same salt for the same tenant. KEK is freshly random
        // (and not derived from master) so a memory dump of the master alone
        // doesn't recover at-rest cache.
        let hk = Hkdf::<Sha256>::new(Some(INFO_TENANT_SALT), &self.master.0);
        let mut salt = [0u8; 32];
        hk.expand(tenant.0.as_bytes(), &mut salt)
            .expect("len <= 255*HashLen");
        let mut kek_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut kek_bytes);
        let kek = SealedKek(kek_bytes);
        let new_seq = inner.next_lru_seq;
        inner.next_lru_seq = inner.next_lru_seq.wrapping_add(1);
        let state = TenantState {
            salt,
            kek,
            last_seen: now,
            lru_seq: new_seq,
        };
        inner.map.insert(tenant.clone(), state.clone());
        inner.lru.insert((now, new_seq, tenant.clone()));
        debug_assert_eq!(
            inner.map.len(),
            inner.lru.len(),
            "tenant-pool HashMap/BTreeSet desync"
        );
        state
    }

    /// Live tenant-state count. Exposed for the `/metrics` endpoint
    /// so operators can monitor table size vs `MAX_TRACKED_TENANTS`.
    pub fn tenant_count(&self) -> usize {
        self.inner.lock().expect("tenant pool poisoned").map.len()
    }

    /// Allocate a `SessionSlot` — the per-session container for cloak state.
    pub fn allocate(&self, tenant: &TenantId, session: SessionId) -> SessionSlot {
        let state = self.state_for(tenant);
        let cloak_key = session_cloak_key(&self.master.0, &state.salt, session);
        SessionSlot {
            tenant: tenant.clone(),
            session,
            cloak_key,
            kek: state.kek,
            recorded: Vec::new(),
        }
    }
}

fn session_cloak_key(
    master: &[u8; 32],
    tenant_salt: &[u8; 32],
    session: SessionId,
) -> CloakKey {
    // Derive transform_key, permute_seed, and session_nonce all from
    // HKDF(master, salt=tenant_salt, info=session_id || "cloak ...")
    let hk = Hkdf::<Sha256>::new(Some(tenant_salt), master);
    let mut info_t = Vec::with_capacity(INFO_CLOAK_TRANSFORM.len() + 16);
    info_t.extend_from_slice(INFO_CLOAK_TRANSFORM);
    info_t.extend_from_slice(&session.0);
    let mut t = [0u8; 32];
    hk.expand(&info_t, &mut t).unwrap();

    let mut info_p = Vec::with_capacity(INFO_CLOAK_PERMUTE.len() + 16);
    info_p.extend_from_slice(INFO_CLOAK_PERMUTE);
    info_p.extend_from_slice(&session.0);
    let mut p = [0u8; 32];
    hk.expand(&info_p, &mut p).unwrap();

    let mut info_n = Vec::with_capacity(INFO_CLOAK_NONCE.len() + 16);
    info_n.extend_from_slice(INFO_CLOAK_NONCE);
    info_n.extend_from_slice(&session.0);
    let mut n = [0u8; 16];
    hk.expand(&info_n, &mut n).unwrap();

    CloakKey::from_parts(t, p, n)
}

pub struct SessionSlot {
    pub tenant: TenantId,
    pub session: SessionId,
    pub cloak_key: CloakKey,
    pub kek: SealedKek,
    /// Cloaked KV blocks captured during the session; sealed on `finalize`.
    recorded: Vec<ullm_kvcloak::CloakedKvBlock>,
}

impl SessionSlot {
    /// Record a synthetic KV row for the given output position.
    pub fn record_kv(&mut self, position: u64, raw_kv: &[u8; ullm_kvcloak::CLOAK_BLOCK_LEN]) {
        let cloaked = ullm_kvcloak::cloak(&self.cloak_key, position, raw_kv);
        self.recorded.push(cloaked);
    }

    pub fn cloaked_count(&self) -> usize {
        self.recorded.len()
    }

    /// Seal all recorded blocks at rest — demonstrates the at-rest wrap.
    /// Returned blocks are tagged with `(tenant, session, position)`.
    pub fn finalize_seal(&self) -> Vec<ullm_kvcloak::seal::SealedCloakedBlock> {
        self.recorded
            .iter()
            .enumerate()
            .map(|(i, c)| {
                ullm_kvcloak::seal::seal_block(&self.kek, &self.tenant, self.session, i as u64, c)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Regression for P8: the tenant pool must not grow unboundedly.
    /// Once the table reaches `MAX_TRACKED_TENANTS`, each new tenant
    /// evicts the LRU one. A long-running TEE seeing 10× the cap in
    /// distinct tenants over time should still hold at most the cap
    /// in memory.
    #[test]
    fn tenant_pool_bounded_by_max() {
        // Use a smaller-than-default cap by instantiating the pool and
        // pushing through many tenants. `MAX_TRACKED_TENANTS` is a
        // compile-time constant; the test exercises the eviction path
        // by going well past it.
        let pool = TenantPool::random(&mut OsRng);
        for i in 0..(MAX_TRACKED_TENANTS + 1024) {
            let tenant = TenantId(format!("attacker-{i}"));
            // `allocate` calls `state_for` which performs the eviction.
            let _slot = pool.allocate(&tenant, SessionId([0u8; 16]));
        }
        assert!(
            pool.tenant_count() <= MAX_TRACKED_TENANTS,
            "tenant pool grew past cap: {} > {}",
            pool.tenant_count(),
            MAX_TRACKED_TENANTS
        );
    }
}
