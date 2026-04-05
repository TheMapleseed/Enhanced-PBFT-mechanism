//! Local fully-connected mesh for tests and examples (no real network).

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use crate::consensus::{ConsensusConfig, ConsensusCore, NodeId, TimeoutConfig};
use crate::error::ConsensusError;
use crate::security::SecurityManager;

pub fn local_cluster(f: usize, n: usize) -> Result<Vec<Arc<ConsensusCore>>, ConsensusError> {
    local_cluster_with_timeouts(f, n, None)
}

pub fn local_cluster_with_timeouts(
    f: usize,
    n: usize,
    timeouts: Option<TimeoutConfig>,
) -> Result<Vec<Arc<ConsensusCore>>, ConsensusError> {
    let replica_ids: Vec<NodeId> = (0..n).map(|i| NodeId(format!("r{}", i))).collect();
    let config = ConsensusConfig {
        fault_tolerance: f,
        replica_ids: replica_ids.clone(),
        timeouts,
    };
    config.validate()?;

    let mut txs = Vec::with_capacity(n);
    let mut rxs = Vec::with_capacity(n);
    for _ in 0..n {
        let (tx, rx) = mpsc::channel();
        txs.push(tx);
        rxs.push(rx);
    }
    let peers = Arc::new(txs);
    let security = Arc::new(SecurityManager::new());

    let mut rx_iter = rxs.into_iter();
    let mut cores = Vec::with_capacity(n);
    for id in replica_ids {
        let core = ConsensusCore::new(
            id,
            config.clone(),
            Arc::clone(&security),
            Arc::clone(&peers),
        )?;
        ConsensusCore::spawn_liveness_watcher(&core);
        let runner = Arc::clone(&core);
        let rx = rx_iter.next().expect("rx per replica");
        thread::spawn(move || {
            runner.run_inbound(rx);
        });
        cores.push(core);
    }
    Ok(cores)
}
