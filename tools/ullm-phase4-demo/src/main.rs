// SPDX-License-Identifier: Apache-2.0
//! Phase 4 walkthrough. Four independent scenarios, end-to-end, in one run:
//!
//! 1. **MPC** — honest-but-curious 2PC over the synthetic model, matching plaintext.
//! 2. **Multi-vendor k-of-n attestation** — 2-of-3 across (TDX, SNP, NVIDIA) mock issuers.
//! 3. **Threshold receipts** — 2-of-3 FROST-Ed25519 signature on a federation receipt.
//! 4. **Onion routing** — 3-hop nested AEAD; middle hop cannot decrypt contents.

use std::collections::HashMap;

use ed25519_dalek::Verifier;
use rand::rngs::OsRng;
use ullm_attest::{MockIssuer, MockVerifier, VerificationContext};
use ullm_federation::{
    MultiVendorVerifier, Provider, ProviderManifest, ProviderPool, VendorKind, VendorVerifier,
    BuildHash, ReproducibleBuildVerifier,
};
use ullm_mpc::MpcSession;
use ullm_model::{Model, VEC_DIM};
use ullm_overlay::{deliver, send_through, InMemoryRelay};
use ullm_threshold::{
    distribute_with_trusted_dealer, sign::group_verifying_key, sign_once, Participant,
};
use ullm_zk::Fp;
use x25519_dalek::StaticSecret;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let mut rng = OsRng;

    println!("\n=== Scenario 1: MPC over the synthetic model ===");
    mpc_scenario(&mut rng)?;

    println!("\n=== Scenario 2: Multi-vendor 2-of-3 attestation ===");
    multi_vendor_scenario(&mut rng)?;

    println!("\n=== Scenario 3: 2-of-3 FROST threshold receipt ===");
    threshold_scenario(&mut rng)?;

    println!("\n=== Scenario 4: 3-hop onion routing ===");
    onion_scenario(&mut rng)?;

    println!("\n✓ Phase 4 scenarios complete");
    Ok(())
}

fn mpc_scenario(rng: &mut OsRng) -> anyhow::Result<()> {
    let model = Model::from_seed(&[0u8; 32]);
    let input: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i + 1) as u64 * 11));
    let plain = model.run(input);
    let (transcript, _resp) = MpcSession::new(&model).run(rng, input);
    assert_eq!(transcript.output, *plain.output());
    println!(
        "  client → party0 + party1 → reconstructed output matches plaintext ({} layers)",
        transcript.per_layer_outputs.len() - 1
    );
    println!("  neither party alone learns the input — shares are uniformly random in Fp");
    Ok(())
}

fn multi_vendor_scenario(rng: &mut OsRng) -> anyhow::Result<()> {
    // Three "vendors" — each with its own attestation issuer.
    let tdx_issuer = MockIssuer::random(rng);
    let snp_issuer = MockIssuer::random(rng);
    let nv_issuer = MockIssuer::random(rng);

    let report_data = [3u8; 64];
    let now = 100u64;

    // Each issuer attests to a different reproducible-build hash.
    let admitted_hash = BuildHash::of(b"ullm-tee:v0.1.0");
    let mut tdx_ev = tdx_issuer.issue(&report_data, now);
    tdx_ev.cert_chain.push(admitted_hash.0.to_vec());
    let mut snp_ev = snp_issuer.issue(&report_data, now);
    snp_ev.cert_chain.push(admitted_hash.0.to_vec());
    let mut nv_ev = nv_issuer.issue(&report_data, now);
    nv_ev.cert_chain.push(admitted_hash.0.to_vec());

    // Wrap each Mock verifier with build-admission control.
    let tdx_v = ReproducibleBuildVerifier::new(MockVerifier::new(tdx_issuer.verifying_key()), [admitted_hash]);
    let snp_v = ReproducibleBuildVerifier::new(MockVerifier::new(snp_issuer.verifying_key()), [admitted_hash]);
    let nv_v = ReproducibleBuildVerifier::new(MockVerifier::new(nv_issuer.verifying_key()), [admitted_hash]);

    let mv = MultiVendorVerifier::new(
        vec![
            VendorVerifier::new(VendorKind::Tdx, tdx_v),
            VendorVerifier::new(VendorKind::Snp, snp_v),
            VendorVerifier::new(VendorKind::Nvidia, nv_v),
        ],
        2,
    )?;
    let ctx = VerificationContext {
        expected_report_data: &report_data,
        now_unix: now,
        max_age_sec: 60,
    };

    // Happy path: all 3 pass.
    let passing = mv.verify(&[tdx_ev.clone(), snp_ev.clone(), nv_ev.clone()], &ctx)?;
    println!("  happy path: {} disjoint vendors verified", passing.len());

    // Sad path: tamper with TDX; SNP+NVIDIA still satisfy threshold of 2.
    let mut tdx_bad = tdx_ev.clone();
    tdx_bad.cpu_quote[0] ^= 0xFF;
    let passing = mv.verify(&[tdx_bad, snp_ev.clone(), nv_ev.clone()], &ctx)?;
    println!("  one-vendor failure ({} passing) still meets threshold k=2", passing.len());

    // Below threshold: tamper with TDX and SNP.
    let mut snp_bad = snp_ev;
    snp_bad.cpu_quote[0] ^= 0xFF;
    let mut tdx_bad2 = tdx_ev;
    tdx_bad2.cpu_quote[0] ^= 0xFF;
    let res = mv.verify(&[tdx_bad2, snp_bad, nv_ev], &ctx);
    assert!(res.is_err());
    println!("  two-vendor failure rejected (only 1 < k=2 vendor verifying)");

    // Demonstrate the provider-pool routing plan.
    let pool = ProviderPool::new(vec![
        Provider {
            manifest: ProviderManifest {
                provider_id: "tee-tdx-eu-1".into(),
                build_hash: admitted_hash,
                region: "eu-west".into(),
            },
            vendor: VendorKind::Tdx,
            url: "https://tee-tdx-eu-1/v1".into(),
            healthy: true,
        },
        Provider {
            manifest: ProviderManifest {
                provider_id: "tee-snp-us-1".into(),
                build_hash: admitted_hash,
                region: "us-east".into(),
            },
            vendor: VendorKind::Snp,
            url: "https://tee-snp-us-1/v1".into(),
            healthy: true,
        },
        Provider {
            manifest: ProviderManifest {
                provider_id: "tee-nv-ap-1".into(),
                build_hash: admitted_hash,
                region: "ap-south".into(),
            },
            vendor: VendorKind::Nvidia,
            url: "https://tee-nv-ap-1/v1".into(),
            healthy: true,
        },
    ]);
    let plan = pool.plan_disjoint(2)?;
    println!(
        "  provider pool produced k=2 vendor-disjoint plan: {}",
        plan.providers
            .iter()
            .map(|p| format!("{}({:?})", p.manifest.provider_id, p.vendor))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

fn threshold_scenario(rng: &mut OsRng) -> anyhow::Result<()> {
    let shares = distribute_with_trusted_dealer(2, 3, rng)?;
    let group_pk = group_verifying_key(&shares.public_pkg)?;
    println!(
        "  trusted-dealer DKG: t=2 n=3, group_pk={}",
        hex::encode(group_pk.as_bytes())
    );

    // Pick 2 of 3 participants to co-sign a "federation receipt".
    let participants: Vec<Participant> = shares
        .key_packages
        .iter()
        .take(2)
        .map(|(id, kp)| Participant::new(*id, kp.clone()))
        .collect();

    let message = b"federation receipt: tenant=acme model=mock tokens=42";
    let sig = sign_once(rng, &participants, &shares.public_pkg, message)?;
    group_pk.verify(message, &sig).expect("group verifies");
    println!("  2-of-3 signed and verified under the group key");

    // Sub-threshold attempt fails at aggregation.
    let one_party: Vec<Participant> = shares
        .key_packages
        .iter()
        .take(1)
        .map(|(id, kp)| Participant::new(*id, kp.clone()))
        .collect();
    let res = sign_once(rng, &one_party, &shares.public_pkg, message);
    assert!(res.is_err());
    println!("  sub-threshold (1-of-3) attempt rejected");
    Ok(())
}

fn onion_scenario(rng: &mut OsRng) -> anyhow::Result<()> {
    let mut secrets = HashMap::new();
    for label in ["guard", "middle", "exit"] {
        secrets.insert(label.to_string(), StaticSecret::random_from_rng(&mut *rng));
    }
    let registry = InMemoryRelay::new(secrets);

    let payload = b"top-secret prompt that no relay should learn";
    send_through(
        rng,
        &registry,
        &["guard".into(), "middle".into(), "exit".into()],
        payload,
    )?;
    let delivered = deliver(&registry).expect("exit delivered the payload");
    assert_eq!(delivered, payload);
    println!("  3-hop onion delivered payload of {} bytes through guard → middle → exit", delivered.len());
    println!("  middle relay sees only ciphertext addressed to exit (verified in unit tests)");
    Ok(())
}
