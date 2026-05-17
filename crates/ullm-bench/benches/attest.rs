// SPDX-License-Identifier: Apache-2.0
//! Mock attestation issue + verify; structural TDX/SNP parse.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use ullm_attest::{
    snp::synthesize_report, tdx::synthesize_quote, MockIssuer, MockVerifier, SnpReport, TdxQuote,
    VerificationContext, Verifier,
};

fn bench_attest(c: &mut Criterion) {
    let mut rng = OsRng;
    let issuer = MockIssuer::random(&mut rng);
    let verifier = MockVerifier::new(issuer.verifying_key());
    let rd = [3u8; 64];

    c.bench_function("mock_issue", |b| {
        b.iter(|| issuer.issue(&rd, 100));
    });

    let evidence = issuer.issue(&rd, 100);
    c.bench_function("mock_verify", |b| {
        let ctx = VerificationContext {
            expected_report_data: &rd,
            now_unix: 100,
            max_age_sec: 60,
        };
        b.iter(|| verifier.verify(&evidence, &ctx).unwrap());
    });

    let tdx_bytes = synthesize_quote([7u8; 64], [9u8; 48]);
    c.bench_function("tdx_quote_parse", |b| {
        b.iter(|| TdxQuote::parse(&tdx_bytes).unwrap());
    });

    let snp_bytes = synthesize_report([11u8; 64], [22u8; 48]);
    c.bench_function("snp_report_parse", |b| {
        b.iter(|| SnpReport::parse(&snp_bytes).unwrap());
    });
}

criterion_group!(benches, bench_attest);
criterion_main!(benches);
