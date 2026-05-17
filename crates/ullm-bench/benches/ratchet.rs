// SPDX-License-Identifier: Apache-2.0
//! Symmetric ratchet step + per-turn X25519 DH ratchet step.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use ullm_crypto::{ChainKey, DhRatchet, RootKey, SymRatchet, X25519PublicKey, X25519SecretKey};

fn bench_ratchet(c: &mut Criterion) {
    c.bench_function("symmetric_ratchet_step", |b| {
        let mut r = SymRatchet::new(ChainKey([42u8; 32]));
        b.iter(|| r.next_key());
    });

    let mut rng = OsRng;
    let our_sk = X25519SecretKey::random_from_rng(&mut rng);
    let peer_sk = X25519SecretKey::random_from_rng(&mut rng);
    let peer_pk = X25519PublicKey::from(&peer_sk);
    let root = RootKey([7u8; 32]);
    c.bench_function("x25519_dh_ratchet_step", |b| {
        b.iter(|| DhRatchet::step(&root, &our_sk, &peer_pk));
    });
}

criterion_group!(benches, bench_ratchet);
criterion_main!(benches);
