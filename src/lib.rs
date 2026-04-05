//! PBFT-style consensus with **in-tree BLAKE3** (reference implementation) and Time-Variant IV
//! construction. **No external crates** — only `std` / `core`.
//!
//! Fan [`PbftMessage`](consensus::PbftMessage) over your own transport. Optional liveness timeouts
//! use [`ConsensusCore::spawn_liveness_watcher`].

/// Standalone BLAKE3 reference hasher (same as upstream reference impl).
pub mod blake3_reference;

pub mod consensus;
pub mod error;
pub mod harness;
pub mod security;
pub mod time_variant_blake3;

pub use harness::{local_cluster, local_cluster_with_timeouts};

pub use consensus::{
    CommittedUpdate, ConsensusConfig, ConsensusCore, MessageBody, NodeId, PbftMessage, TimeoutConfig,
};
pub use error::ConsensusError;
pub use security::SecurityManager;
pub use time_variant_blake3::{hash_payload, ConsensusTemporal, TimeVariantBlake3Config};
