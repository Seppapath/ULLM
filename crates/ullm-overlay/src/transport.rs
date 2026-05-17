// SPDX-License-Identifier: Apache-2.0
//! Caller-friendly helpers for the in-memory overlay.

use rand_core::CryptoRngCore;
use ullm_core::Result;
use x25519_dalek::PublicKey;

use crate::layer::wrap_layers;
use crate::relay::InMemoryRelay;

/// Wrap and route a payload through `relay_chain`. The final relay is
/// treated as the terminal: it strips its layer and delivers the plaintext
/// to the registry's `delivered` queue.
pub fn send_through<R: CryptoRngCore>(
    rng: &mut R,
    registry: &InMemoryRelay,
    relay_chain: &[String],
    payload: &[u8],
) -> Result<()> {
    let chain: Vec<(String, PublicKey)> = relay_chain
        .iter()
        .map(|id| {
            let pk = registry
                .public(id)
                .ok_or_else(|| ullm_core::Error::Other(format!("unknown relay {id}")))?;
            Ok((id.clone(), pk))
        })
        .collect::<Result<_>>()?;
    let wrapped = wrap_layers(rng, &chain, payload)?;
    registry.route(&relay_chain[0], &wrapped)
}

/// Pop the first delivered payload (for tests / linear demos).
pub fn deliver(registry: &InMemoryRelay) -> Option<Vec<u8>> {
    registry.take_delivered().into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::RelayId;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use x25519_dalek::StaticSecret;

    fn registry_with(labels: &[&str]) -> InMemoryRelay {
        let mut rng = OsRng;
        let mut secrets: HashMap<RelayId, StaticSecret> = HashMap::new();
        for l in labels {
            secrets.insert((*l).to_string(), StaticSecret::random_from_rng(&mut rng));
        }
        InMemoryRelay::new(secrets)
    }

    #[test]
    fn end_to_end_three_hop() {
        let mut rng = OsRng;
        let reg = registry_with(&["guard", "middle", "exit"]);
        send_through(
            &mut rng,
            &reg,
            &["guard".into(), "middle".into(), "exit".into()],
            b"hello onion",
        )
        .unwrap();
        let got = deliver(&reg).expect("payload delivered");
        assert_eq!(got, b"hello onion");
    }

    #[test]
    fn malformed_layer_at_entry_is_rejected() {
        let mut rng = OsRng;
        let reg = registry_with(&["guard"]);
        let bad: Vec<u8> = (0u8..32).collect();
        let _ = bad;
        // Wrap to "guard" but corrupt; routing should fail.
        let res = send_through(&mut rng, &reg, &["guard".into()], b"x");
        assert!(res.is_ok());
        // Now corrupt: rewrap properly then tamper before routing.
        let chain: Vec<(String, PublicKey)> = vec![("guard".into(), reg.public("guard").unwrap())];
        let mut wrapped = crate::layer::wrap_layers(&mut rng, &chain, b"x").unwrap();
        wrapped[5] ^= 0xFF;
        assert!(reg.route("guard", &wrapped).is_err());
    }
}
