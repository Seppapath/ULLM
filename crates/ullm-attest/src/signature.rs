// SPDX-License-Identifier: Apache-2.0
//! Vendor signature verification for TDX (ECDSA-P256) and SEV-SNP
//! (ECDSA-P384) quotes.
//!
//! The signature covers the header + TD report (TDX) or the first 0x2A0
//! bytes of the report struct (SNP). This module only does the crypto;
//! chaining the attestation key to Intel/AMD vendor PKI is the next layer
//! (live PCS / VCEK lookup) and lives behind a deployment feature flag.

use p256::ecdsa::signature::Verifier as _;
use ullm_core::{Error, Result};

use crate::snp::{SnpReport, REPORT_LEN, SIGNATURE_LEN as SNP_SIGNATURE_LEN};
use crate::tdx::{TdxQuote, HEADER_LEN as TDX_HEADER_LEN, TD_REPORT_LEN};

/// Bytes the TDX attestation key signs: the 48-byte header concatenated
/// with the 584-byte TD report (632 bytes total).
pub fn tdx_signed_body<'a>(quote_bytes: &'a [u8]) -> Result<&'a [u8]> {
    let need = TDX_HEADER_LEN + TD_REPORT_LEN;
    if quote_bytes.len() < need {
        return Err(Error::AttestationFailed(format!(
            "tdx quote shorter than signed-body length ({need} bytes)"
        )));
    }
    Ok(&quote_bytes[..need])
}

/// Verify ECDSA-P256 signature on a TDX quote using the attestation key
/// the quote itself carries (uncompressed 64-byte public key in the
/// signature_data block). Returns `Ok(())` iff the signature is valid.
pub fn verify_tdx_quote_signature(quote: &TdxQuote, raw_quote_bytes: &[u8]) -> Result<()> {
    use p256::ecdsa::{Signature, VerifyingKey};

    let body = tdx_signed_body(raw_quote_bytes)?;

    // The attestation key in TDX quotes is the uncompressed point (x || y),
    // 64 bytes. p256 wants `0x04 || x || y`.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&quote.signature.attestation_key);
    // P3-10: opaque error string for every signature failure path —
    // attestation-key parse, signature parse, and signature verify all
    // collapse to the same message, denying an attacker an oracle on
    // which sub-step rejected their crafted input. Internal `tracing`
    // logs still capture the underlying cause for operators.
    let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| {
        tracing::debug!(error = %e, "tdx attestation key parse failed");
        Error::AttestationFailed("tdx signature verification failed".into())
    })?;

    let sig = Signature::from_slice(&quote.signature.ecdsa_signature).map_err(|e| {
        tracing::debug!(error = %e, "tdx signature decode failed");
        Error::AttestationFailed("tdx signature verification failed".into())
    })?;
    // P5-1: ECDSA permits two valid encodings per signature `(r, s)` and
    // `(r, n - s)`. The `p256` crate's `verify` accepts both, opening a
    // malleability channel: an attacker can present a re-encoded copy of
    // a legitimate signature and it verifies, breaking any downstream
    // dedup that hashes the signature bytes. Normalising `s` to the
    // canonical low half collapses the two encodings into one before we
    // hand it to `verify` — `normalize_s()` returns `Some(canonical)`
    // when the input was high-s, `None` when it was already low-s.
    let sig = sig.normalize_s().unwrap_or(sig);

    vk.verify(body, &sig).map_err(|e| {
        tracing::debug!(error = %e, "tdx signature verify failed");
        Error::AttestationFailed("tdx signature verification failed".into())
    })
}

/// Bytes the SEV-SNP VCEK signs: the leading 0x2A0 = 672 bytes of the
/// report struct.
pub const SNP_SIGNED_PREFIX: usize = 0x2A0;

/// Bytes covered by the SNP signature.
pub fn snp_signed_body<'a>(report_bytes: &'a [u8]) -> Result<&'a [u8]> {
    if report_bytes.len() < REPORT_LEN {
        return Err(Error::AttestationFailed(format!(
            "snp report shorter than {REPORT_LEN} bytes"
        )));
    }
    Ok(&report_bytes[..SNP_SIGNED_PREFIX])
}

/// Verify the ECDSA-P384 signature on a SEV-SNP report given the VCEK
/// (caller-supplied; obtained via vendor PKI fetch).
///
/// The signature is stored in the trailing 512 bytes of the report, in
/// AMD's r || s layout (each component 0x48 = 72 bytes, little-endian).
pub fn verify_snp_report_signature(
    report: &SnpReport,
    raw_report_bytes: &[u8],
    vcek_uncompressed: &[u8; 97],
) -> Result<()> {
    use p384::ecdsa::{Signature, VerifyingKey};

    // P3-10: collapse all SNP-signature failure paths into a single
    // opaque error so an attacker probing crafted reports cannot tell
    // whether the VCEK parsed, the signature decoded, or the verify
    // itself rejected. Verbose context still reaches tracing.
    let body = snp_signed_body(raw_report_bytes)?;
    let vk = VerifyingKey::from_sec1_bytes(vcek_uncompressed).map_err(|e| {
        tracing::debug!(error = %e, "snp vcek parse failed");
        Error::AttestationFailed("snp signature verification failed".into())
    })?;

    // AMD stores r and s as 72-byte little-endian blocks within the 512-byte
    // signature field. The ECDSA-P384 signature itself is 96 bytes (r || s,
    // each 48 bytes big-endian for the p384 crate).
    let sig_block = &report.signature[..];
    if sig_block.len() < SNP_SIGNATURE_LEN {
        return Err(Error::AttestationFailed(
            "snp signature block truncated".into(),
        ));
    }
    let mut r_be = [0u8; 48];
    let mut s_be = [0u8; 48];
    for i in 0..48 {
        r_be[i] = sig_block[47 - i];
        s_be[i] = sig_block[0x48 + 47 - i];
    }
    let mut sig_bytes = [0u8; 96];
    sig_bytes[..48].copy_from_slice(&r_be);
    sig_bytes[48..].copy_from_slice(&s_be);
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| {
        tracing::debug!(error = %e, "snp signature decode failed");
        Error::AttestationFailed("snp signature verification failed".into())
    })?;
    // P5-1: same low-s normalization as the TDX path — see comment there.
    let sig = sig.normalize_s().unwrap_or(sig);

    vk.verify(body, &sig).map_err(|e| {
        tracing::debug!(error = %e, "snp signature verify failed");
        Error::AttestationFailed("snp signature verification failed".into())
    })
}

#[cfg(test)]
pub mod test_support {
    //! Helpers that mint a real ECDSA-P256-signed TDX quote for tests. Not
    //! exposed outside the crate.

    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use rand_core::CryptoRngCore;

    use crate::tdx::{
        synthesize_quote, ECDSA_P256_PUBLIC_KEY_LEN, ECDSA_P256_SIGNATURE_LEN, HEADER_LEN,
        TD_REPORT_LEN,
    };

    /// Build a TDX quote whose `signature_data` carries a *real* ECDSA-P256
    /// signature over `header || td_report` by an ephemeral key.
    pub fn signed_tdx_quote<R: CryptoRngCore>(
        rng: &mut R,
        report_data: [u8; 64],
        mrtd: [u8; 48],
    ) -> Vec<u8> {
        let template = synthesize_quote(report_data, mrtd);
        let body = &template[..HEADER_LEN + TD_REPORT_LEN];
        let signing_key = SigningKey::random(rng);
        let sig: Signature = signing_key.sign(body);
        let sig_bytes = sig.to_bytes();
        let verifying_key = signing_key.verifying_key();
        let pk_sec1 = verifying_key.to_encoded_point(false);
        let pk_xy = &pk_sec1.as_bytes()[1..]; // strip leading 0x04 → 64 bytes

        // Rebuild the quote with the real signature + real attestation key in
        // place of the all-zero placeholders.
        let mut out = body.to_vec();
        let sig_data_len = (ECDSA_P256_SIGNATURE_LEN + ECDSA_P256_PUBLIC_KEY_LEN) as u32;
        out.extend_from_slice(&sig_data_len.to_le_bytes());
        out.extend_from_slice(&sig_bytes);
        out.extend_from_slice(pk_xy);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::{TdxQuote, HEADER_LEN, TD_REPORT_LEN};
    use rand_core::OsRng;

    #[test]
    fn signed_tdx_quote_verifies() {
        let mut rng = OsRng;
        let bytes = test_support::signed_tdx_quote(&mut rng, [7u8; 64], [9u8; 48]);
        let quote = TdxQuote::parse(&bytes).unwrap();
        verify_tdx_quote_signature(&quote, &bytes).unwrap();
    }

    #[test]
    fn tampered_signed_body_fails_signature() {
        let mut rng = OsRng;
        let mut bytes = test_support::signed_tdx_quote(&mut rng, [7u8; 64], [9u8; 48]);
        // Flip a byte inside the TD report — the signature should no longer verify.
        bytes[HEADER_LEN + 10] ^= 0xFF;
        let quote = TdxQuote::parse(&bytes).unwrap();
        assert!(verify_tdx_quote_signature(&quote, &bytes).is_err());
    }

    #[test]
    fn wrong_attestation_key_rejected() {
        let mut rng = OsRng;
        let mut bytes = test_support::signed_tdx_quote(&mut rng, [7u8; 64], [9u8; 48]);
        // Overwrite a byte of the attestation key — verify must fail.
        let pk_off =
            HEADER_LEN + TD_REPORT_LEN + 4 + crate::tdx::ECDSA_P256_SIGNATURE_LEN;
        bytes[pk_off] ^= 0xFF;
        // Re-parse: if the corruption breaks SEC1 decoding entirely, that
        // surfaces as an AttestationFailed; either failure path is acceptable.
        match TdxQuote::parse(&bytes) {
            Ok(q) => {
                assert!(verify_tdx_quote_signature(&q, &bytes).is_err());
            }
            Err(_) => { /* corruption broke parsing — counts as rejection */ }
        }
    }
}
