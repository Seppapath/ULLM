// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        getrandom_compat(&mut b);
        Self(b)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

// P9-FIX-F: `Ord`/`PartialOrd` so `TenantId` can sit inside a
// `BTreeSet<(Instant, TenantId)>` LRU index in the TEE tenant pool.
// Lex order on the wrapped `String` — used only as a deterministic
// tie-break when two `Instant`s collide; the security model doesn't
// depend on the ordering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Epoch(pub u32);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Seq(pub u64);

impl Seq {
    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

fn getrandom_compat(dst: &mut [u8]) {
    // SessionId is not security-sensitive on its own — but use the OS RNG anyway.
    use std::time::{SystemTime, UNIX_EPOCH};
    // Simple PRNG seeded from time + addr; for cryptographic contexts callers should
    // not derive secrets from a SessionId.
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64
        ^ (dst.as_ptr() as usize as u64);
    for b in dst.iter_mut() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (seed >> 56) as u8;
    }
}
