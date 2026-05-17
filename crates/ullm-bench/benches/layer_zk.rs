// SPDX-License-Identifier: Apache-2.0
//! Per-layer Halo2 ZK prove + verify (the core Phase 3 cost).
//!
//! Setup is amortized; only the per-proof work is timed.

use criterion::{criterion_group, criterion_main, Criterion};
use ullm_model::Model;
use ullm_zk::layer::vector_hash_native;
use ullm_zk::{setup_layer, Fp, LayerProver, LayerVerifier};

fn bench_layer_zk(c: &mut Criterion) {
    let model = Model::from_seed(&[0u8; 32]);
    let layer = &model.layers[0];
    let (pp, vp) = setup_layer(0, layer.w, layer.b);

    let x: [Fp; ullm_model::VEC_DIM] =
        std::array::from_fn(|i| Fp::from((i as u64 + 1) * 11));
    let mut y = [Fp::zero(); ullm_model::VEC_DIM];
    for i in 0..ullm_model::VEC_DIM {
        let mut acc = layer.b[i];
        for j in 0..ullm_model::VEC_DIM {
            acc += layer.w[i][j] * x[j];
        }
        y[i] = acc;
    }
    let xc = vector_hash_native(&x);
    let yc = vector_hash_native(&y);

    // P13-FIX-C: the prove/verify API now requires `(layer_idx,
    // session_id, weight_commit)` bound into each proof. The bench
    // uses fixed dummy values for these — what's measured is the raw
    // Halo2 prove/verify cost, not the identity check.
    let session_id: [u8; 16] = [0u8; 16];
    let weight_commit: [u8; 32] = [0u8; 32];
    let layer_idx: usize = 0;

    let mut group = c.benchmark_group("layer_zk");
    group.sample_size(10); // proving is multi-hundred-ms; keep the run bounded.
    group.bench_function("prove_one_layer", |b| {
        b.iter(|| {
            LayerProver(&pp).prove(
                x, y, xc, yc, layer.w, layer.b, layer_idx, &session_id, &weight_commit,
            )
        });
    });
    let proof = LayerProver(&pp).prove(
        x, y, xc, yc, layer.w, layer.b, layer_idx, &session_id, &weight_commit,
    );
    group.bench_function("verify_one_layer", |b| {
        b.iter(|| {
            LayerVerifier(&vp)
                .verify(xc, yc, layer_idx, &session_id, &weight_commit, &proof)
                .unwrap()
        });
    });
    group.finish();
}

criterion_group!(benches, bench_layer_zk);
criterion_main!(benches);
