// SPDX-License-Identifier: Apache-2.0
//! 3-hop onion wrap + peel.

use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use ullm_overlay::{layer::wrap_layers, InMemoryRelay};
use x25519_dalek::{PublicKey, StaticSecret};

fn bench_onion(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut secrets = HashMap::new();
    let mut publics: Vec<(String, PublicKey)> = Vec::new();
    for label in ["guard", "middle", "exit"] {
        let sk = StaticSecret::random_from_rng(&mut rng);
        let pk = PublicKey::from(&sk);
        secrets.insert(label.to_string(), sk);
        publics.push((label.to_string(), pk));
    }
    let payload = vec![0u8; 256];

    c.bench_function("onion_wrap_3hop_256B", |b| {
        b.iter(|| wrap_layers(&mut OsRng, &publics, &payload).unwrap());
    });

    let wrapped = wrap_layers(&mut OsRng, &publics, &payload).unwrap();
    let registry = InMemoryRelay::new(secrets);
    c.bench_function("onion_route_3hop_256B", |b| {
        b.iter(|| {
            registry.route("guard", &wrapped).unwrap();
            registry.take_delivered();
        });
    });
}

criterion_group!(benches, bench_onion);
criterion_main!(benches);
