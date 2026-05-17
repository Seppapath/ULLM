// SPDX-License-Identifier: Apache-2.0
//! Wall-clock helpers that fail closed instead of silently producing 0.
//!
//! P6 audit (clock-skew):
//!
//! ```text
//! SystemTime::now()
//!     .duration_since(UNIX_EPOCH)
//!     .map(|d| d.as_secs())
//!     .unwrap_or(0)
//! ```
//!
//! was a foot-gun. If the system clock was set to a date before
//! 1970-01-01 (an attacker-influenceable scenario in containers, VMs, or
//! anywhere NTP can be poisoned), `duration_since` returns `Err`, the
//! fallback substitutes 0, and downstream freshness checks of the form
//! `now.saturating_sub(issued_at) > TTL` become a tautological "no" —
//! every stale attestation looks fresh.
//!
//! The helpers here surface the failure as a `Result` so the call site
//! decides explicitly: fail closed (security path) or use a fallback
//! timestamp (non-security metadata).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, Result};

/// Wall-clock seconds since the UNIX epoch. Returns `Err` if the system
/// clock is set to a date before 1970-01-01, leaving the caller to
/// decide how to fail. Use this on every security-critical freshness
/// path. For non-security metadata (e.g., a "timestamp this entry was
/// observed" field whose ordering is informational only) prefer
/// `now_unix_or_zero`.
pub fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            Error::Other(format!(
                "system clock before UNIX epoch ({e}) — refusing to issue/verify timestamp"
            ))
        })
}

/// Wall-clock seconds since the UNIX epoch, or `0` if the clock is
/// pre-1970. Reserved for **non-security** uses — e.g. populating a
/// `issued_at_unix` field whose ordering invariant is informational and
/// where a synthetic zero is preferable to refusing the operation. Do
/// not use on freshness-check paths.
pub fn now_unix_or_zero() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
