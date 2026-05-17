// SPDX-License-Identifier: Apache-2.0
//! In-memory relay implementation for the demo + tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ullm_core::{Error, Result};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::layer::peel_layer;

pub type RelayId = String;

/// In-process relay registry. Each relay holds its X25519 secret; messages
/// are forwarded via a shared queue keyed by relay label.
#[derive(Clone, Default)]
pub struct InMemoryRelay {
    secrets: Arc<HashMap<RelayId, StaticSecret>>,
    publics: HashMap<RelayId, PublicKey>,
    delivered: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl InMemoryRelay {
    pub fn new(secrets: HashMap<RelayId, StaticSecret>) -> Self {
        let publics: HashMap<_, _> = secrets
            .iter()
            .map(|(k, v)| (k.clone(), PublicKey::from(v)))
            .collect();
        Self {
            secrets: Arc::new(secrets),
            publics,
            delivered: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn public(&self, id: &str) -> Option<PublicKey> {
        self.publics.get(id).copied()
    }

    /// Synchronously route an onion message: starts at `entry`, follows the
    /// `next_hop` labels through the registry, delivers the terminal payload
    /// to the internal `delivered` queue.
    pub fn route(&self, entry: &str, layer_bytes: &[u8]) -> Result<()> {
        let mut current_relay = entry.to_string();
        let mut current_bytes = layer_bytes.to_vec();
        loop {
            let sk = self
                .secrets
                .get(&current_relay)
                .ok_or_else(|| Error::Other(format!("unknown relay {current_relay}")))?;
            let (next, inner) = peel_layer(sk, &current_bytes)?;
            match next {
                None => {
                    self.delivered.lock().unwrap().push(inner);
                    return Ok(());
                }
                Some(next_label) => {
                    current_relay = next_label;
                    current_bytes = inner;
                }
            }
        }
    }

    /// Drain the delivered queue.
    pub fn take_delivered(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.delivered.lock().unwrap())
    }
}
