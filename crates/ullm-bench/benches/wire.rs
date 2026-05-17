// SPDX-License-Identifier: Apache-2.0
//! Frame codec encode + decode at representative sizes.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ullm_core::{Epoch, Seq};
use ullm_crypto::{AeadKey, NonceSalt};
use ullm_wire::{decode_frame, encode_frame, FrameFlags, FrameType};

fn bench_wire(c: &mut Criterion) {
    let key = AeadKey([7u8; 32]);
    let salt = NonceSalt([0x11u8; 24]);

    let mut group = c.benchmark_group("wire codec");
    for &size in &[64usize, 1024, 4096, 16384] {
        let pt = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encode", size), &pt, |b, pt| {
            b.iter(|| {
                encode_frame(
                    &key,
                    &salt,
                    FrameType::Data,
                    FrameFlags::empty(),
                    Epoch(0),
                    Seq(0),
                    pt,
                )
                .unwrap()
            });
        });
        let encoded = encode_frame(
            &key,
            &salt,
            FrameType::Data,
            FrameFlags::empty(),
            Epoch(0),
            Seq(0),
            &pt,
        )
        .unwrap();
        group.bench_with_input(BenchmarkId::new("decode", size), &encoded.wire, |b, wire| {
            b.iter(|| decode_frame(&key, &salt, wire).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_wire);
criterion_main!(benches);
