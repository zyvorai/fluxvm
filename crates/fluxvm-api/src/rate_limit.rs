// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! A small, hand-rolled per-key token-bucket rate limiter for
//! `fluxvm-api`'s REST surface -- no new dependency for what a basic
//! token bucket takes in well under a hundred lines (`governor` was
//! considered and skipped for that reason). See `lib.rs`'s
//! `rate_limit_middleware` for the one place this is used: bounding
//! request volume per authenticated caller (`auth.rate_limit_rps`/
//! `.rate_limit_burst`, both opt-in, `None` = no rate limiting at all).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    last_seen: Instant,
}

/// Tracks one token bucket per key (here, the authenticated caller's
/// actor name -- see `rate_limit_middleware`). Not a global -- callers
/// construct one and pass it explicitly via axum's `State`, matching how
/// `AuthState`/`Arc<VmManager>` are already threaded through this crate.
pub struct Limiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    rps: f64,
    burst: f64,
}

impl Limiter {
    /// Builds a Limiter allowing, per key, an average of `rps` requests
    /// per second with bursts up to `burst` requests before throttling
    /// kicks in. A key's bucket starts full, so a key's very first
    /// request is never throttled by an empty bucket it never had a
    /// chance to fill.
    pub fn new(rps: f64, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rps,
            burst: burst as f64,
        }
    }

    /// Reports whether a request identified by `key` is allowed right
    /// now, consuming one token from `key`'s bucket if so. `Err`'s
    /// `Duration` is how long until `key`'s bucket would have at least
    /// one token again -- round up before using it as a `Retry-After`
    /// header value.
    pub fn allow(&self, key: &str) -> Result<(), Duration> {
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_seen: now,
        });

        let elapsed = now.duration_since(bucket.last_seen).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let deficit = 1.0 - bucket.tokens;
        Err(Duration::from_secs_f64(deficit / self.rps))
    }

    /// Removes any key whose bucket hasn't been touched in longer than
    /// `max_age`, bounding memory growth from a stream of distinct keys
    /// (many distinct tokens/OIDC actors over the process lifetime) that
    /// each only ever make a handful of requests.
    pub fn prune(&self, max_age: Duration) {
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        let cutoff = Instant::now() - max_age;
        buckets.retain(|_, b| b.last_seen >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_burst_then_denies() {
        let l = Limiter::new(1.0, 3);
        assert!(l.allow("a").is_ok());
        assert!(l.allow("a").is_ok());
        assert!(l.allow("a").is_ok());
        assert!(l.allow("a").is_err());
    }

    #[test]
    fn distinct_keys_have_independent_buckets() {
        let l = Limiter::new(1.0, 1);
        assert!(l.allow("a").is_ok());
        assert!(l.allow("a").is_err());
        assert!(l.allow("b").is_ok());
    }

    #[test]
    fn denial_reports_a_positive_retry_after() {
        let l = Limiter::new(2.0, 1);
        assert!(l.allow("a").is_ok());
        let retry_after = l.allow("a").unwrap_err();
        assert!(retry_after > Duration::ZERO);
        assert!(retry_after <= Duration::from_secs(1));
    }

    #[test]
    fn prune_drops_only_stale_keys() {
        let l = Limiter::new(1.0, 1);
        assert!(l.allow("stale").is_ok());
        std::thread::sleep(Duration::from_millis(20));
        assert!(l.allow("fresh").is_ok());
        l.prune(Duration::from_millis(10));
        {
            let buckets = l.buckets.lock().unwrap();
            assert!(!buckets.contains_key("stale"));
            assert!(buckets.contains_key("fresh"));
        }
    }
}
