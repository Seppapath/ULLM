// SPDX-License-Identifier: Apache-2.0
//! Persistence wrap for cloaked KV blocks. The cloak itself protects against
//! in-TEE inversion attacks; AES-GCM-SIV-on-KEK protects against at-rest
//! exfiltration if the cloak material were somehow exposed too.

use ullm_core::{SessionId, TenantId};
use ullm_crypto::{seal, unseal, SealError, SealedKek};

use crate::cloak::{CloakedKvBlock, CLOAK_BLOCK_LEN};

/// Seal a cloaked block at rest. AAD binds the ciphertext to
/// `(tenant, session, position)` so reordering or cross-tenant replay is
/// rejected on unseal.
pub fn seal_block(
    kek: &SealedKek,
    tenant: &TenantId,
    session: SessionId,
    position: u64,
    cloaked: &CloakedKvBlock,
) -> SealedCloakedBlock {
    let nonce = derive_nonce(session, position);
    let aad = aad_bytes(tenant, session, position);
    let ct = seal(kek, &nonce, &aad, &cloaked.0);
    SealedCloakedBlock {
        nonce,
        ciphertext: ct,
    }
}

pub fn unseal_block(
    kek: &SealedKek,
    tenant: &TenantId,
    session: SessionId,
    position: u64,
    sealed: &SealedCloakedBlock,
) -> Result<CloakedKvBlock, SealError> {
    let expected_nonce = derive_nonce(session, position);
    if sealed.nonce != expected_nonce {
        return Err(SealError::Open);
    }
    let aad = aad_bytes(tenant, session, position);
    let pt = unseal(kek, &sealed.nonce, &aad, &sealed.ciphertext)?;
    let mut block = [0u8; CLOAK_BLOCK_LEN];
    if pt.len() != CLOAK_BLOCK_LEN {
        return Err(SealError::Open);
    }
    block.copy_from_slice(&pt);
    Ok(CloakedKvBlock(block))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCloakedBlock {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn derive_nonce(session: SessionId, position: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&session.0[..4]);
    n[4..].copy_from_slice(&position.to_be_bytes());
    n
}

fn aad_bytes(tenant: &TenantId, session: SessionId, position: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"ULLM-v1 kv-at-rest");
    v.extend_from_slice(tenant.0.as_bytes());
    v.push(0xFF);
    v.extend_from_slice(&session.0);
    v.extend_from_slice(&position.to_be_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloak::{cloak, CloakKey};
    use rand::rngs::OsRng;

    #[test]
    fn sealed_block_roundtrip() {
        let kek = SealedKek::random(&mut OsRng);
        let ck = CloakKey::random(&mut OsRng);
        let kv = [0x33; CLOAK_BLOCK_LEN];
        let c = cloak(&ck, 5, &kv);
        let tenant = TenantId("acme".into());
        let session = SessionId([7u8; 16]);
        let sealed = seal_block(&kek, &tenant, session, 5, &c);
        let opened = unseal_block(&kek, &tenant, session, 5, &sealed).unwrap();
        assert_eq!(opened, c);
    }

    #[test]
    fn cross_tenant_rejected() {
        let kek = SealedKek::random(&mut OsRng);
        let ck = CloakKey::random(&mut OsRng);
        let c = cloak(&ck, 5, &[0xAA; CLOAK_BLOCK_LEN]);
        let session = SessionId([7u8; 16]);
        let sealed = seal_block(&kek, &TenantId("acme".into()), session, 5, &c);
        let other = TenantId("evil".into());
        assert!(unseal_block(&kek, &other, session, 5, &sealed).is_err());
    }

    #[test]
    fn cross_position_rejected() {
        let kek = SealedKek::random(&mut OsRng);
        let ck = CloakKey::random(&mut OsRng);
        let c = cloak(&ck, 5, &[0xAA; CLOAK_BLOCK_LEN]);
        let tenant = TenantId("acme".into());
        let session = SessionId([7u8; 16]);
        let sealed = seal_block(&kek, &tenant, session, 5, &c);
        assert!(unseal_block(&kek, &tenant, session, 6, &sealed).is_err());
    }
}
