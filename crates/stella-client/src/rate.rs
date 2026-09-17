//! Monotonic bounded admission shared by production data paths.

use std::time::Duration;

const TOKEN_SCALE: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug)]
pub(crate) struct TokenBucket {
    rate: u32,
    capacity: u32,
    tokens_scaled: u128,
    last_refill: Duration,
}

impl TokenBucket {
    pub(crate) fn new(rate: u32, capacity: u32, now: Duration) -> Self {
        Self {
            rate,
            capacity,
            tokens_scaled: u128::from(capacity) * TOKEN_SCALE,
            last_refill: now,
        }
    }

    pub(crate) fn take(&mut self, now: Duration) -> bool {
        let elapsed = now.saturating_sub(self.last_refill);
        let refill = elapsed.as_nanos().saturating_mul(u128::from(self.rate));
        let ceiling = u128::from(self.capacity) * TOKEN_SCALE;
        self.tokens_scaled = self.tokens_scaled.saturating_add(refill).min(ceiling);
        self.last_refill = self.last_refill.max(now);
        if self.tokens_scaled < TOKEN_SCALE {
            return false;
        }
        self.tokens_scaled -= TOKEN_SCALE;
        true
    }
}
