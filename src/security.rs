use crate::time_variant_blake3::{hash_payload, ConsensusTemporal, TimeVariantBlake3Config};

/// Request digests using **Time-Variant BLAKE3** IV construction from `third_party/Time-VariantBlake3`,
/// with consensus-bound `(view, sequence)` so all replicas agree on the IV.
#[derive(Debug, Clone)]
pub struct SecurityManager {
    pub tvb3: TimeVariantBlake3Config,
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            tvb3: TimeVariantBlake3Config::default(),
        }
    }

    pub fn with_tvb3_config(cfg: TimeVariantBlake3Config) -> Self {
        Self { tvb3: cfg }
    }

    /// PBFT request digest: IV derived from `(view, sequence)` and config, then BLAKE3(`IV || data`).
    #[inline]
    pub fn hash_consensus(&self, view: u64, sequence: u64, data: &[u8]) -> [u8; 32] {
        hash_payload(
            ConsensusTemporal { view, sequence },
            &self.tvb3,
            data,
        )
    }

    /// Convenience: uses `(view=0, sequence=0)` — only for tests or non-consensus hashing.
    #[inline]
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        self.hash_consensus(0, 0, data)
    }
}
