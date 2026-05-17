// SPDX-License-Identifier: Apache-2.0
//! Full PQXDH-shaped handshake (ClientHello → ServerHello → key derivation).

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use ullm_crypto::{ml_kem_keypair, ml_kem_pk_bytes, X25519PublicKey, X25519SecretKey};
use ullm_handshake::{ClientHandshake, PreKeyBundle, ServerHandshake};

fn bench_handshake(c: &mut Criterion) {
    let mut rng = OsRng;
    let spk_sk = X25519SecretKey::random_from_rng(&mut rng);
    let spk_pk = X25519PublicKey::from(&spk_sk);
    let (pq_sk, pq_pk) = ml_kem_keypair(&mut rng);
    let bundle = PreKeyBundle {
        id_pk: [0u8; 32],
        spk_pk_x25519: *spk_pk.as_bytes(),
        pq_pk_mlkem: ml_kem_pk_bytes(&pq_pk),
        attestation_evidence: vec![],
        signature: [0u8; 64],
    };

    c.bench_function("client_initiate", |b| {
        b.iter(|| ClientHandshake::initiate(&mut OsRng, &bundle).unwrap());
    });

    c.bench_function("full_1rtt_handshake", |b| {
        b.iter(|| {
            let (client, hello_bytes) =
                ClientHandshake::initiate(&mut OsRng, &bundle).unwrap();
            let ratchet_sk = X25519SecretKey::random_from_rng(&mut OsRng);
            let server = ServerHandshake {
                spk_sk_x25519: &spk_sk,
                pq_sk_mlkem: &pq_sk,
            };
            let (server_hello, _) = server
                .respond(&mut OsRng, &hello_bytes, &ratchet_sk, |_, _| {
                    Ok((vec![], [0u8; 64]))
                })
                .unwrap();
            client
                .complete(&server_hello, |_hash, _sig| Ok(()))
                .unwrap();
        });
    });
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
