// SPDX-License-Identifier: Apache-2.0
//! XChaCha20-Poly1305 seal + open at representative frame sizes.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ullm_crypto::{aead_open, aead_seal, AeadKey};

fn bench_aead(c: &mut Criterion) {
    let key = AeadKey([7u8; 32]);
    let nonce = [3u8; 24];
    let aad = [0u8; 28]; // wire header is 28 bytes

    let mut group = c.benchmark_group("aead xchacha20-poly1305");
    for &size in &[64usize, 1024, 4096, 16384] {
        let plaintext = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("seal", size), &plaintext, |b, pt| {
            b.iter(|| aead_seal(&key, &nonce, &aad, pt));
        });
        let ct = aead_seal(&key, &nonce, &aad, &plaintext);
        group.bench_with_input(BenchmarkId::new("open", size), &ct, |b, ct| {
            b.iter(|| aead_open(&key, &nonce, &aad, ct).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aead);
criterion_main!(benches);
