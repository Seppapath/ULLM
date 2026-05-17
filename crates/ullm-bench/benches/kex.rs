// SPDX-License-Identifier: Apache-2.0
//! Hybrid KEX (ML-KEM-768 + X25519) encap + decap.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use ullm_crypto::{hybrid_decap, hybrid_encap, ml_kem_keypair, X25519PublicKey, X25519SecretKey};

fn bench_kex(c: &mut Criterion) {
    let mut rng = OsRng;
    let (mlkem_sk, mlkem_pk) = ml_kem_keypair(&mut rng);
    let x25519_sk = X25519SecretKey::random_from_rng(&mut rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    c.bench_function("hybrid_encap (ML-KEM-768 + X25519)", |b| {
        b.iter(|| hybrid_encap(&mut OsRng, &mlkem_pk, &x25519_pk))
    });

    let (ct, client_pk, _) = hybrid_encap(&mut OsRng, &mlkem_pk, &x25519_pk);
    c.bench_function("hybrid_decap (ML-KEM-768 + X25519)", |b| {
        b.iter(|| hybrid_decap(&mlkem_sk, &x25519_sk, &ct, &client_pk))
    });
}

criterion_group!(benches, bench_kex);
criterion_main!(benches);
