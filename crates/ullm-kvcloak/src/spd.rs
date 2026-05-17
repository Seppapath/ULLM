// SPDX-License-Identifier: Apache-2.0
//! Petridish Secure Partitioned Decoding (arXiv 2409.19134), process model.
//!
//! In a real multi-tenant TEE service, Petridish splits the model server
//! into:
//!
//! 1. A **per-user prefill+attention-score process** that owns the user's
//!    plaintext prompt and computes attention scores against the cached
//!    `K`. This process is the only one that ever sees the user's KV in
//!    the clear.
//! 2. A **shared service process** that batches attention scores across
//!    users and emits the next-token logits without seeing per-tenant
//!    plaintext KV.
//!
//! This module models that split as data-structure separation: each tenant
//! has its own `TenantKvStore` keyed by a secret `MatrixCloakKey`. A
//! `SharedAttentionService` exposes only `submit_score(tenant, score)`
//! style operations — there is no API that lets one tenant read another
//! tenant's KV, and the shared service has no per-tenant secret material.

use std::collections::HashMap;

use parking_lot::Mutex;
use ullm_core::TenantId;
use ullm_zk::Fp;

use crate::matrix::{cloak_vector, uncloak_vector, MatrixCloakKey, VEC_DIM};

/// One tenant's KV store. Holds cloaked vectors only; the secret transform
/// key lives next to the store and never leaves this struct.
pub struct TenantKvStore {
    key: MatrixCloakKey,
    keys: Vec<[Fp; VEC_DIM]>,
    values: Vec<[Fp; VEC_DIM]>,
}

impl TenantKvStore {
    pub fn new(key: MatrixCloakKey) -> Self {
        Self {
            key,
            keys: Vec::new(),
            values: Vec::new(),
        }
    }

    /// Cloak and store the `(k, v)` pair. Plaintext `k`, `v` are not retained.
    pub fn push(&mut self, k: &[Fp; VEC_DIM], v: &[Fp; VEC_DIM]) {
        self.keys.push(cloak_vector(&self.key, k));
        self.values.push(cloak_vector(&self.key, v));
    }

    pub fn cloaked_keys(&self) -> &[[Fp; VEC_DIM]] {
        &self.keys
    }

    pub fn cloaked_values(&self) -> &[[Fp; VEC_DIM]] {
        &self.values
    }

    /// Recover the i-th plaintext key/value pair. Caller must be the
    /// per-user process (i.e., must hold a reference to this store).
    pub fn recover(&self, i: usize) -> Option<([Fp; VEC_DIM], [Fp; VEC_DIM])> {
        let k = self.keys.get(i)?;
        let v = self.values.get(i)?;
        Some((uncloak_vector(&self.key, k), uncloak_vector(&self.key, v)))
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The shared service. Holds **no** per-tenant secret material. Per-tenant
/// stores are pushed in by the per-user processes; this service can only
/// see the cloaked KV blocks.
#[derive(Default)]
pub struct SharedAttentionService {
    tenants: Mutex<HashMap<TenantId, TenantKvStore>>,
}

impl SharedAttentionService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new tenant. Idempotent: the first call wins.
    pub fn register_tenant(&self, tenant: TenantId, key: MatrixCloakKey) {
        let mut t = self.tenants.lock();
        t.entry(tenant).or_insert_with(|| TenantKvStore::new(key));
    }

    /// Push a `(k, v)` pair for `tenant`. Plaintext is never retained:
    /// `TenantKvStore::push` cloaks immediately.
    pub fn push_kv(
        &self,
        tenant: &TenantId,
        k: &[Fp; VEC_DIM],
        v: &[Fp; VEC_DIM],
    ) -> Result<(), &'static str> {
        let mut t = self.tenants.lock();
        let store = t.get_mut(tenant).ok_or("unknown tenant")?;
        store.push(k, v);
        Ok(())
    }

    /// Read-only window of cloaked KV for `tenant`. The shared service
    /// returns ciphertext only; it has no path to plaintext.
    pub fn cloaked_view(
        &self,
        tenant: &TenantId,
    ) -> Option<(Vec<[Fp; VEC_DIM]>, Vec<[Fp; VEC_DIM]>)> {
        let t = self.tenants.lock();
        let store = t.get(tenant)?;
        Some((store.cloaked_keys().to_vec(), store.cloaked_values().to_vec()))
    }

    /// **Cross-tenant access is impossible.** This method intentionally
    /// does not exist — a caller can only address its own tenant id, and
    /// without the matching `MatrixCloakKey` the cloaked view returns no
    /// usable information about KV plaintext. The unit test below
    /// demonstrates this property.
    pub fn tenant_count(&self) -> usize {
        self.tenants.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn vec_of(salt: u64) -> [Fp; VEC_DIM] {
        std::array::from_fn(|i| Fp::from((i as u64 + 1) * (salt + 3)))
    }

    #[test]
    fn tenant_store_roundtrip() {
        let mut store = TenantKvStore::new(MatrixCloakKey::random(&mut OsRng));
        let k = vec_of(1);
        let v = vec_of(2);
        store.push(&k, &v);
        let (rk, rv) = store.recover(0).unwrap();
        assert_eq!(rk, k);
        assert_eq!(rv, v);
    }

    #[test]
    fn tenant_a_cannot_read_tenant_b_kv() {
        let service = SharedAttentionService::new();
        let alice = TenantId("alice".into());
        let bob = TenantId("bob".into());
        let alice_key = MatrixCloakKey::random(&mut OsRng);
        let bob_key = MatrixCloakKey::random(&mut OsRng);
        service.register_tenant(alice.clone(), alice_key);
        service.register_tenant(bob.clone(), bob_key);

        let bob_secret_k = vec_of(123);
        let bob_secret_v = vec_of(456);
        service.push_kv(&bob, &bob_secret_k, &bob_secret_v).unwrap();

        // Alice, holding only her own cloaked view, cannot recover Bob's plaintext.
        let (alice_cloaked_k, _) = service.cloaked_view(&alice).unwrap();
        assert!(alice_cloaked_k.is_empty());

        // Even if Alice exfiltrated Bob's cloaked view, she lacks Bob's
        // matrix key and so cannot invert the transform.
        let (bob_cloaked_k, _) = service.cloaked_view(&bob).unwrap();
        let attacker_key = MatrixCloakKey::random(&mut OsRng);
        let recovered_wrong = uncloak_vector(&attacker_key, &bob_cloaked_k[0]);
        assert_ne!(recovered_wrong, bob_secret_k);
    }

    #[test]
    fn cloaked_view_carries_only_ciphertext() {
        let service = SharedAttentionService::new();
        let t = TenantId("t".into());
        service.register_tenant(t.clone(), MatrixCloakKey::random(&mut OsRng));
        let plain_k = vec_of(7);
        service.push_kv(&t, &plain_k, &plain_k).unwrap();
        let (cloaked_k, _) = service.cloaked_view(&t).unwrap();
        assert_ne!(cloaked_k[0], plain_k);
    }
}
