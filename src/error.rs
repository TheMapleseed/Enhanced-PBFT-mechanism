use core::fmt;

#[derive(Debug)]
pub enum ConsensusError {
    InsufficientReplicas { n: usize, f: usize },
    NotPrimary,
    StaleView { expected: u64, got: u64 },
    DigestMismatch,
    SequenceSkew { expected: u64, got: u64 },
    UnknownReplica,
    SendError,
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientReplicas { n, f: ft } => {
                write!(f, "replica set size {n} is below 3f+1 for f={ft}")
            }
            Self::NotPrimary => write!(f, "only the primary for the current view may propose"),
            Self::StaleView { expected, got } => {
                write!(f, "message view {got} does not match current view {expected}")
            }
            Self::DigestMismatch => write!(f, "digest does not match payload"),
            Self::SequenceSkew { expected, got } => write!(
                f,
                "strict ordering violation: expected sequence {expected}, got {got}"
            ),
            Self::UnknownReplica => write!(f, "unknown replica index"),
            Self::SendError => write!(f, "failed to deliver message to a peer"),
        }
    }
}

impl std::error::Error for ConsensusError {}
