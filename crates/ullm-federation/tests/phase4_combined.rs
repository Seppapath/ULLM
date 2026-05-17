// SPDX-License-Identifier: Apache-2.0
//! Combined Phase 4 integration test: a tenant rejecting all hardware roots
//! AND requiring gateway-blind privacy gets MPC + onion together.

use std::collections::HashMap;

use ed25519_dalek::Verifier;
use rand::rngs::OsRng;
use ullm_federation::{
    BuildHash, MultiVendorVerifier, Provider, ProviderManifest, ProviderPool,
    ReproducibleBuildVerifier, VendorKind, VendorVerifier,
};
use ullm_mpc::MpcSession;
use ullm_model::{Model, VEC_DIM};
use ullm_overlay::{deliver, send_through, InMemoryRelay};
use ullm_threshold::{
    distribute_with_trusted_dealer, sign::group_verifying_key, sign_once, Participant,
};
use ullm_zk::Fp;
use x25519_dalek::StaticSecret;

#[test]
fn mpc_fallback_with_threshold_signed_receipt_through_onion_overlay() {
    let mut rng = OsRng;

    // 1) Tenant runs the model under 2PC. Neither MPC operator alone learns
    //    the prompt.
    let model = Model::from_seed(&[42u8; 32]);
    let input: [Fp; VEC_DIM] = std::array::from_fn(|i| Fp::from((i + 1) as u64));
    let (transcript, _) = MpcSession::new(&model).run(&mut rng, input);
    assert_eq!(transcript.output, *model.run(input).output());

    // 2) Three federation operators co-sign the resulting "MPC receipt"
    //    via FROST-Ed25519 2-of-3.
    let shares = distribute_with_trusted_dealer(2, 3, &mut rng).unwrap();
    let participants: Vec<Participant> = shares
        .key_packages
        .iter()
        .take(2)
        .map(|(id, kp)| Participant::new(*id, kp.clone()))
        .collect();
    let receipt_message = format!(
        "mpc-receipt tenant=alice model=mock weights_commit={}",
        hex::encode(model.weight_commit())
    );
    let sig = sign_once(&mut rng, &participants, &shares.public_pkg, receipt_message.as_bytes())
        .unwrap();
    let group_pk = group_verifying_key(&shares.public_pkg).unwrap();
    group_pk.verify(receipt_message.as_bytes(), &sig).unwrap();

    // 3) Tenant delivers the receipt to the auditor via 3-hop onion so the
    //    transport network cannot link this receipt to their identity.
    let mut secrets = HashMap::new();
    for l in ["guard", "middle", "exit"] {
        secrets.insert(l.to_string(), StaticSecret::random_from_rng(&mut rng));
    }
    let overlay = InMemoryRelay::new(secrets);

    let mut payload = Vec::with_capacity(receipt_message.len() + 64);
    payload.extend_from_slice(receipt_message.as_bytes());
    payload.extend_from_slice(&sig.to_bytes());

    send_through(
        &mut rng,
        &overlay,
        &["guard".into(), "middle".into(), "exit".into()],
        &payload,
    )
    .unwrap();
    let delivered = deliver(&overlay).expect("onion delivered the receipt");
    assert_eq!(delivered, payload);

    // 4) Audit at the exit: verify the FROST signature on the message half.
    let (msg, sig_bytes) = delivered.split_at(receipt_message.len());
    let recovered_sig =
        ed25519_dalek::Signature::from_bytes(sig_bytes.try_into().expect("64-byte sig"));
    group_pk
        .verify(msg, &recovered_sig)
        .expect("auditor verifies threshold signature");
}

#[test]
fn provider_pool_routes_only_through_admitted_builds() {
    // Two providers running the admitted image, one running a foreign image.
    // The provider pool happily plans across all three, but the admission
    // verifier rejects the foreign one when it tries to ratify a session.
    let admitted = BuildHash::of(b"ullm-tee:v0.1.0");
    let foreign = BuildHash::of(b"ullm-tee:rogue");

    let pool = ProviderPool::new(vec![
        Provider {
            manifest: ProviderManifest {
                provider_id: "tee-tdx-1".into(),
                build_hash: admitted,
                region: "eu".into(),
            },
            vendor: VendorKind::Tdx,
            url: "https://a/v1".into(),
            healthy: true,
        },
        Provider {
            manifest: ProviderManifest {
                provider_id: "tee-snp-rogue".into(),
                build_hash: foreign,
                region: "??".into(),
            },
            vendor: VendorKind::Snp,
            url: "https://b/v1".into(),
            healthy: true,
        },
        Provider {
            manifest: ProviderManifest {
                provider_id: "tee-nv-1".into(),
                build_hash: admitted,
                region: "us".into(),
            },
            vendor: VendorKind::Nvidia,
            url: "https://c/v1".into(),
            healthy: true,
        },
    ]);
    let plan = pool.plan_disjoint(2).unwrap();
    // Build a multi-vendor verifier that only accepts the admitted hash.
    use ullm_attest::{MockIssuer, MockVerifier, VerificationContext};
    let mut rng = OsRng;
    let rd = [9u8; 64];
    let now = 100u64;
    let mut verifiers = Vec::new();
    let mut evidences = Vec::new();
    for p in &plan.providers {
        let issuer = MockIssuer::random(&mut rng);
        let mut ev = issuer.issue(&rd, now);
        ev.cert_chain.push(p.manifest.build_hash.0.to_vec());
        let v = ReproducibleBuildVerifier::new(
            MockVerifier::new(issuer.verifying_key()),
            [admitted],
        );
        verifiers.push(VendorVerifier::new(p.vendor, v));
        evidences.push(ev);
    }
    let mv = MultiVendorVerifier::new(verifiers, 2).unwrap();
    let ctx = VerificationContext {
        expected_report_data: &rd,
        now_unix: now,
        max_age_sec: 60,
    };
    let result = mv.verify(&evidences, &ctx);
    // If the rogue provider got into the plan (depends on enumeration order),
    // expect the verifier to reject below threshold. Otherwise both admitted
    // pass.
    let rogue_in_plan = plan
        .providers
        .iter()
        .any(|p| p.manifest.provider_id == "tee-snp-rogue");
    if rogue_in_plan {
        assert!(result.is_err());
    } else {
        assert!(result.is_ok());
    }
}
