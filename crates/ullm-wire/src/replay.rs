// SPDX-License-Identifier: Apache-2.0
//! 64-slot sliding-window anti-replay, per receive direction per epoch.
//!
//! Bitmap convention: bit `b` is set iff the receiver has seen
//! `seq = high - (WINDOW_BITS - 1 - b)`. So bit 63 corresponds to `seq == high`,
//! bit 62 to `seq == high - 1`, …, bit 0 to `seq == high - 63`. When `high`
//! advances by `gap`, every previously seen entry slides DOWN — i.e. the
//! bitmap must shift **right** by `gap` so old seqs end up at the correct
//! lower bit positions (an old `seq=high` at bit 63 becomes `seq=high-gap`
//! at bit `63-gap`).
//!
//! Pre-audit: the first revision shifted **left** by mistake, which dropped
//! the high-water mark on every advance and let replays of older seqs
//! through. The regression test `replays_after_advance_rejected` pins the
//! correct behaviour.

use ullm_core::{Error, Result, Seq};

const WINDOW_BITS: u32 = 64;

/// Tracks the highest-seen sequence number plus a bitmap of the previous 64.
///
/// Reset on epoch change.
pub struct ReplayWindow {
    high: u64,
    bitmap: u64,
    /// Tracks whether `seq=0` at the initial `high=0` was already accepted.
    /// Without this we'd accept `seq=0` twice (once as the freshly initialized
    /// high, once as a "replay within window" check).
    seen_zero_at_init: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            high: 0,
            bitmap: 0,
            seen_zero_at_init: false,
        }
    }

    /// Check + record `seq`. Returns `Ok(())` if the frame is acceptable
    /// (not replayed, within the window). Updates internal state.
    pub fn check_and_update(&mut self, seq: Seq) -> Result<()> {
        let s = seq.0;
        if s > self.high {
            let gap = s - self.high;
            if gap > u64::MAX / 2 {
                // Implausible: protect against wraparound abuse.
                return Err(Error::SeqGap { gap });
            }
            if gap >= WINDOW_BITS as u64 {
                self.bitmap = 0;
            } else {
                // Slide all previously seen entries DOWN by `gap` positions.
                self.bitmap >>= gap;
            }
            // Mark the new top.
            self.bitmap |= 1u64 << (WINDOW_BITS - 1);
            self.high = s;
            Ok(())
        } else {
            // s <= self.high
            if s == 0 && self.high == 0 {
                if self.seen_zero_at_init {
                    return Err(Error::Replay { seq: 0 });
                }
                self.seen_zero_at_init = true;
                // Mirror the new-top branch so subsequent advances slide it correctly.
                self.bitmap |= 1u64 << (WINDOW_BITS - 1);
                return Ok(());
            }
            let diff = self.high - s;
            if diff >= WINDOW_BITS as u64 {
                return Err(Error::SeqGap { gap: diff });
            }
            let bit = WINDOW_BITS as u64 - 1 - diff;
            let mask = 1u64 << bit;
            if self.bitmap & mask != 0 {
                return Err(Error::Replay { seq: s });
            }
            self.bitmap |= mask;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_progress_accepted() {
        let mut w = ReplayWindow::new();
        for i in 1..100u64 {
            assert!(w.check_and_update(Seq(i)).is_ok());
        }
    }

    #[test]
    fn replay_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(Seq(5)).is_ok());
        assert!(w.check_and_update(Seq(5)).is_err());
    }

    #[test]
    fn within_window_out_of_order_ok_once() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(Seq(10)).is_ok());
        assert!(w.check_and_update(Seq(8)).is_ok());
        assert!(w.check_and_update(Seq(8)).is_err());
    }

    #[test]
    fn beyond_window_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(Seq(100)).is_ok());
        assert!(w.check_and_update(Seq(20)).is_err());
    }

    /// Regression for the pre-audit shift-direction bug.
    ///
    /// Sequence: receive seq=0, advance to seq=1, then try to replay
    /// seq=0. The faulty `<<=` slid the high-water mark off the top of
    /// the bitmap and accepted the replay; the correct `>>=` keeps the
    /// "seen" mark for old seqs and rejects.
    #[test]
    fn replays_after_advance_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(Seq(0)).is_ok(), "first seq=0");
        assert!(w.check_and_update(Seq(1)).is_ok(), "advance to seq=1");
        assert!(
            w.check_and_update(Seq(0)).is_err(),
            "replay of seq=0 must be rejected after advancing"
        );
        assert!(w.check_and_update(Seq(2)).is_ok(), "advance to seq=2");
        assert!(
            w.check_and_update(Seq(1)).is_err(),
            "replay of seq=1 must be rejected after advancing"
        );
    }

    #[test]
    fn long_run_then_replay_anywhere_rejected() {
        let mut w = ReplayWindow::new();
        for i in 0..50u64 {
            assert!(w.check_and_update(Seq(i)).is_ok());
        }
        // Every seq 0..=49 must now be rejected as a replay.
        for i in 0..50u64 {
            assert!(
                w.check_and_update(Seq(i)).is_err(),
                "seq={i} should be replay or beyond-window",
            );
        }
    }
}
