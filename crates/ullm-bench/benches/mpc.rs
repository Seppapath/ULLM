// SPDX-License-Identifier: Apache-2.0
//! 2PC session: share split + both parties run + reconstruct.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use ullm_model::{Model, VEC_DIM};
use ullm_mpc::MpcSession;
use ullm_zk::Fp;

fn bench_mpc(c: &mut Criterion) {
    let model = Model::from_seed(&[0u8; 32]);
    let session = MpcSession::new(&model);
    let input: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i + 1) as u64 * 5));

    c.bench_function("mpc_session_full_8layer", |b| {
        let mut rng = OsRng;
        b.iter(|| session.run(&mut rng, input));
    });
}

criterion_group!(benches, bench_mpc);
criterion_main!(benches);
