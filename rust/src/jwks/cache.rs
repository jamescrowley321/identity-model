//! TTL cache for JWK Sets, keyed by `jwks_uri`.
//!
//! Backed by a [`tokio::sync::RwLock`] so concurrent readers share a fresh entry
//! without contention (JWKS-005) while a refresh takes the write lock. A
//! [`Cache::invalidate`] drops an entry so the next fetch re-fetches from the
//! provider (JWKS-006).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use super::key::JsonWebKeySet;

/// A cached key set paired with the instant it expires. `expires_at` is `None`
/// when the TTL is so large that `Instant::now() + ttl` would overflow (e.g.
/// `Duration::MAX`), in which case the entry never expires.
struct CacheEntry {
    key_set: JsonWebKeySet,
    expires_at: Option<Instant>,
}

/// A TTL cache mapping a `jwks_uri` to its parsed [`JsonWebKeySet`].
pub(crate) struct Cache {
    entries: RwLock<HashMap<String, CacheEntry>>,
}

impl Cache {
    /// Returns an empty cache.
    pub(crate) fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the cached key set for `key` if present and unexpired (JWKS-005);
    /// returns `None` once the TTL has elapsed.
    pub(crate) async fn get(&self, key: &str) -> Option<JsonWebKeySet> {
        let entries = self.entries.read().await;
        let entry = entries.get(key)?;
        // A `None` expiry never elapses; otherwise the entry is fresh until then.
        if entry.expires_at.is_none_or(|at| Instant::now() < at) {
            Some(entry.key_set.clone())
        } else {
            None
        }
    }

    /// Stores `key_set` for `key`, expiring `ttl` from now.
    pub(crate) async fn put(&self, key: String, key_set: JsonWebKeySet, ttl: Duration) {
        // `checked_add` guards against an overflow panic for a very large TTL
        // (e.g. `Duration::MAX`); `None` means the entry never expires.
        let expires_at = Instant::now().checked_add(ttl);
        let mut entries = self.entries.write().await;
        entries.insert(
            key,
            CacheEntry {
                key_set,
                expires_at,
            },
        );
    }

    /// Drops the cached entry for `key` so the next fetch re-fetches it from the
    /// provider (JWKS-006).
    pub(crate) async fn invalidate(&self, key: &str) {
        self.entries.write().await.remove(key);
    }
}
