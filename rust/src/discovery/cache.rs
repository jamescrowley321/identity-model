//! TTL cache for discovery documents, keyed by issuer URL.
//!
//! Backed by a [`tokio::sync::RwLock`] so concurrent readers share a fresh
//! entry without contention (DISC-004) while a refresh takes the write lock
//! (DISC-005).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use super::metadata::ProviderMetadata;

/// A cached document paired with the instant it expires. `expires_at` is
/// `None` when the TTL is so large that `Instant::now() + ttl` would overflow
/// (e.g. `Duration::MAX`), in which case the entry never expires.
struct CacheEntry {
    metadata: ProviderMetadata,
    expires_at: Option<Instant>,
}

/// A TTL cache mapping an issuer URL to its parsed [`ProviderMetadata`].
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

    /// Returns the cached metadata for `key` if present and unexpired
    /// (DISC-004); returns `None` once the TTL has elapsed (DISC-005).
    pub(crate) async fn get(&self, key: &str) -> Option<ProviderMetadata> {
        let entries = self.entries.read().await;
        let entry = entries.get(key)?;
        // A `None` expiry never elapses; otherwise the entry is fresh until then.
        if entry.expires_at.is_none_or(|at| Instant::now() < at) {
            Some(entry.metadata.clone())
        } else {
            None
        }
    }

    /// Stores `metadata` for `key`, expiring `ttl` from now.
    pub(crate) async fn put(&self, key: String, metadata: ProviderMetadata, ttl: Duration) {
        // `checked_add` guards against an overflow panic for a very large TTL
        // (e.g. `Duration::MAX`); `None` means the entry never expires.
        let expires_at = Instant::now().checked_add(ttl);
        let mut entries = self.entries.write().await;
        entries.insert(
            key,
            CacheEntry {
                metadata,
                expires_at,
            },
        );
    }
}
