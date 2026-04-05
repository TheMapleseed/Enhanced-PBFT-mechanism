//! PBFT core with **time-invariant safety** (quorum logic) and **time-variant mechanisms**:
//! - **Safety**: commits follow only from digests, matching certificates, and `2f+1` quorums.
//! - **Digests**: Time-Variant BLAKE3 IV pipeline (`time_variant_blake3`) with `(view, sequence)`.
//! - **Liveness** (optional): [`TimeoutConfig`] and [`ConsensusCore::spawn_liveness_watcher`].

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::error::ConsensusError;
use crate::security::SecurityManager;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct NodeId(pub String);

#[derive(Debug, Clone)]
pub enum MessageBody {
    PrePrepare {
        view: u64,
        sequence: u64,
        digest: [u8; 32],
        data: Vec<u8>,
    },
    Prepare {
        view: u64,
        sequence: u64,
        digest: [u8; 32],
    },
    Commit {
        view: u64,
        sequence: u64,
        digest: [u8; 32],
    },
    ViewChange {
        new_view: u64,
        last_stable_seq: u64,
    },
}

#[derive(Debug, Clone)]
pub struct PbftMessage {
    pub from: NodeId,
    pub body: MessageBody,
}

#[derive(Debug, Clone)]
pub struct CommittedUpdate {
    pub view: u64,
    pub sequence: u64,
    pub data: Vec<u8>,
}

/// Fan-out commit notifications to subscribers (std has no broadcast channel).
struct CommitFanout {
    subs: Mutex<Vec<mpsc::Sender<CommittedUpdate>>>,
}

impl CommitFanout {
    fn new() -> Self {
        Self {
            subs: Mutex::new(Vec::new()),
        }
    }

    fn subscribe(&self) -> mpsc::Receiver<CommittedUpdate> {
        let (tx, rx) = mpsc::channel();
        self.subs.lock().expect("commit fanout lock").push(tx);
        rx
    }

    fn broadcast(&self, u: CommittedUpdate) {
        let mut v = self.subs.lock().expect("commit fanout lock");
        v.retain(|s| s.send(u.clone()).is_ok());
    }
}

/// Wall-clock deadlines for **liveness only**.
#[derive(Clone, Debug)]
pub struct TimeoutConfig {
    pub wait_pre_prepare: Duration,
    pub prepare_certificate: Duration,
    pub commit_certificate: Duration,
    pub view_change_resend: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            wait_pre_prepare: Duration::from_secs(5),
            prepare_certificate: Duration::from_secs(3),
            commit_certificate: Duration::from_secs(3),
            view_change_resend: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub fault_tolerance: usize,
    pub replica_ids: Vec<NodeId>,
    pub timeouts: Option<TimeoutConfig>,
}

#[derive(Debug, Clone)]
enum LivenessPhase {
    Inactive,
    WaitPrePrepare { deadline: Instant },
    WaitPrepareQuorum { deadline: Instant },
    WaitCommitQuorum { deadline: Instant },
}

impl ConsensusConfig {
    #[inline]
    pub fn quorum(&self) -> usize {
        2 * self.fault_tolerance + 1
    }

    pub fn validate(&self) -> Result<(), ConsensusError> {
        let n = self.replica_ids.len();
        let f = self.fault_tolerance;
        if n < 3 * f + 1 {
            return Err(ConsensusError::InsufficientReplicas { n, f });
        }
        Ok(())
    }

    #[inline]
    pub fn primary_for_view(&self, view: u64) -> NodeId {
        let n = self.replica_ids.len();
        self.replica_ids[(view as usize) % n].clone()
    }
}

struct Slot {
    digest: [u8; 32],
    data: Vec<u8>,
    prepares: HashSet<NodeId>,
    commits: HashSet<NodeId>,
    sent_prepare: bool,
    sent_commit: bool,
    executed: bool,
}

struct ReplicaState {
    view: u64,
    last_committed_seq: u64,
    slots: HashMap<u64, Slot>,
    view_change_supporters: HashMap<u64, HashMap<NodeId, u64>>,
    liveness: LivenessPhase,
}

pub struct ConsensusCore {
    node_id: NodeId,
    config: ConsensusConfig,
    security: Arc<SecurityManager>,
    peers: Arc<Vec<mpsc::Sender<PbftMessage>>>,
    state: RwLock<ReplicaState>,
    commit_fanout: Arc<CommitFanout>,
}

impl ConsensusCore {
    /// `peers[i]` is the inbox for `config.replica_ids[i]`. Run [`Self::run_inbound`] on a worker thread.
    pub fn new(
        node_id: NodeId,
        config: ConsensusConfig,
        security: Arc<SecurityManager>,
        peers: Arc<Vec<mpsc::Sender<PbftMessage>>>,
    ) -> Result<Arc<Self>, ConsensusError> {
        config.validate()?;
        if !config.replica_ids.contains(&node_id) {
            return Err(ConsensusError::UnknownReplica);
        }
        let liveness = match &config.timeouts {
            None => LivenessPhase::Inactive,
            Some(t) => LivenessPhase::WaitPrePrepare {
                deadline: Instant::now() + t.wait_pre_prepare,
            },
        };
        Ok(Arc::new(Self {
            node_id,
            config,
            security,
            peers,
            state: RwLock::new(ReplicaState {
                view: 0,
                last_committed_seq: 0,
                slots: HashMap::new(),
                view_change_supporters: HashMap::new(),
                liveness,
            }),
            commit_fanout: Arc::new(CommitFanout::new()),
        }))
    }

    pub fn spawn_liveness_watcher(this: &Arc<Self>) {
        if this.config.timeouts.is_none() {
            return;
        }
        let c = Arc::clone(this);
        std::thread::spawn(move || {
            let tick = Duration::from_millis(50);
            loop {
                std::thread::sleep(tick);
                let _ = c.tick_liveness();
            }
        });
    }

    fn tick_liveness(&self) -> Result<(), ConsensusError> {
        let Some(tcfg) = self.config.timeouts.as_ref() else {
            return Ok(());
        };
        let now = Instant::now();
        let should_fire = {
            let s = self.state.read().expect("state read");
            match &s.liveness {
                LivenessPhase::Inactive => false,
                LivenessPhase::WaitPrePrepare { deadline }
                | LivenessPhase::WaitPrepareQuorum { deadline }
                | LivenessPhase::WaitCommitQuorum { deadline } => now >= *deadline,
            }
        };
        if !should_fire {
            return Ok(());
        }
        let (nv, stable) = {
            let mut s = self.state.write().expect("state write");
            let fired = match &s.liveness {
                LivenessPhase::Inactive => false,
                LivenessPhase::WaitPrePrepare { deadline }
                | LivenessPhase::WaitPrepareQuorum { deadline }
                | LivenessPhase::WaitCommitQuorum { deadline } => now >= *deadline,
            };
            if !fired {
                return Ok(());
            }
            let nv = s.view + 1;
            let stable = s.last_committed_seq;
            s.liveness = LivenessPhase::WaitPrePrepare {
                deadline: now + tcfg.view_change_resend,
            };
            (nv, stable)
        };
        let msg = PbftMessage {
            from: self.node_id.clone(),
            body: MessageBody::ViewChange {
                new_view: nv,
                last_stable_seq: stable,
            },
        };
        self.dispatch(&msg)
    }

    fn arm_wait_prepare_quorum(&self, view: u64) {
        let Some(t) = self.config.timeouts.as_ref() else {
            return;
        };
        let mut s = self.state.write().expect("state write");
        if s.view != view {
            return;
        }
        s.liveness = LivenessPhase::WaitPrepareQuorum {
            deadline: Instant::now() + t.prepare_certificate,
        };
    }

    fn arm_wait_commit_quorum(&self, view: u64) {
        let Some(t) = self.config.timeouts.as_ref() else {
            return;
        };
        let mut s = self.state.write().expect("state write");
        if s.view != view {
            return;
        }
        s.liveness = LivenessPhase::WaitCommitQuorum {
            deadline: Instant::now() + t.commit_certificate,
        };
    }

    fn arm_wait_next_pre_prepare(&self) {
        let Some(t) = self.config.timeouts.as_ref() else {
            return;
        };
        let mut s = self.state.write().expect("state write");
        s.liveness = LivenessPhase::WaitPrePrepare {
            deadline: Instant::now() + t.wait_pre_prepare,
        };
    }

    pub fn replica_id(&self) -> NodeId {
        self.node_id.clone()
    }

    pub fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    pub fn subscribe_commits(&self) -> mpsc::Receiver<CommittedUpdate> {
        self.commit_fanout.subscribe()
    }

    pub fn last_committed_seq(&self) -> u64 {
        self.state.read().expect("state read").last_committed_seq
    }

    pub fn view(&self) -> u64 {
        self.state.read().expect("state read").view
    }

    pub fn is_primary(&self) -> bool {
        let v = self.state.read().expect("state read").view;
        self.config.primary_for_view(v) == self.node_id
    }

    pub fn propose(&self, data: Vec<u8>) -> Result<(), ConsensusError> {
        if !self.is_primary() {
            return Err(ConsensusError::NotPrimary);
        }
        let (view, sequence) = {
            let s = self.state.read().expect("state read");
            (s.view, s.last_committed_seq + 1)
        };
        let digest = self.security.hash_consensus(view, sequence, &data);
        let msg = PbftMessage {
            from: self.node_id.clone(),
            body: MessageBody::PrePrepare {
                view,
                sequence,
                digest,
                data,
            },
        };
        self.dispatch(&msg)
    }

    pub fn run_inbound(self: Arc<Self>, rx: mpsc::Receiver<PbftMessage>) {
        while let Ok(msg) = rx.recv() {
            let _ = self.handle_message(msg);
        }
    }

    fn handle_message(&self, msg: PbftMessage) -> Result<(), ConsensusError> {
        match msg.body {
            MessageBody::PrePrepare {
                view,
                sequence,
                digest,
                data,
            } => self.on_pre_prepare(msg.from, view, sequence, digest, data),
            MessageBody::Prepare {
                view,
                sequence,
                digest,
            } => self.on_prepare(msg.from, view, sequence, digest),
            MessageBody::Commit {
                view,
                sequence,
                digest,
            } => self.on_commit(msg.from, view, sequence, digest),
            MessageBody::ViewChange {
                new_view,
                last_stable_seq,
            } => self.on_view_change(msg.from, new_view, last_stable_seq),
        }
    }

    fn on_pre_prepare(
        &self,
        from: NodeId,
        view: u64,
        sequence: u64,
        digest: [u8; 32],
        data: Vec<u8>,
    ) -> Result<(), ConsensusError> {
        let primary = self.config.primary_for_view(view);
        if from != primary {
            return Ok(());
        }
        let expected_seq = {
            let s = self.state.read().expect("state read");
            if view != s.view {
                return Ok(());
            }
            s.last_committed_seq + 1
        };
        if sequence != expected_seq {
            return Ok(());
        }
        let computed = self.security.hash_consensus(view, sequence, &data);
        if computed != digest {
            return Ok(());
        }
        let maybe_prepare = {
            let mut s = self.state.write().expect("state write");
            if s.view != view || sequence != s.last_committed_seq + 1 {
                None
            } else {
                use std::collections::hash_map::Entry;
                match s.slots.entry(sequence) {
                    Entry::Occupied(mut e) => {
                        let slot = e.get_mut();
                        if slot.digest != digest || slot.sent_prepare {
                            None
                        } else {
                            slot.prepares.insert(self.node_id.clone());
                            slot.sent_prepare = true;
                            Some(PbftMessage {
                                from: self.node_id.clone(),
                                body: MessageBody::Prepare {
                                    view,
                                    sequence,
                                    digest,
                                },
                            })
                        }
                    }
                    Entry::Vacant(e) => {
                        e.insert(Slot {
                            digest,
                            data: data.clone(),
                            prepares: HashSet::new(),
                            commits: HashSet::new(),
                            sent_prepare: false,
                            sent_commit: false,
                            executed: false,
                        });
                        let slot = s.slots.get_mut(&sequence).unwrap();
                        slot.prepares.insert(self.node_id.clone());
                        slot.sent_prepare = true;
                        Some(PbftMessage {
                            from: self.node_id.clone(),
                            body: MessageBody::Prepare {
                                view,
                                sequence,
                                digest,
                            },
                        })
                    }
                }
            }
        };
        if let Some(p) = maybe_prepare {
            self.dispatch(&p)?;
            self.arm_wait_prepare_quorum(view);
        }
        Ok(())
    }

    fn on_prepare(
        &self,
        from: NodeId,
        view: u64,
        sequence: u64,
        digest: [u8; 32],
    ) -> Result<(), ConsensusError> {
        let q = self.config.quorum();
        let maybe_commit = {
            let mut s = self.state.write().expect("state write");
            if view != s.view {
                None
            } else if let Some(slot) = s.slots.get_mut(&sequence) {
                if slot.digest != digest {
                    None
                } else {
                    slot.prepares.insert(from);
                    if slot.prepares.len() < q || slot.sent_commit {
                        None
                    } else {
                        slot.sent_commit = true;
                        slot.commits.insert(self.node_id.clone());
                        Some(PbftMessage {
                            from: self.node_id.clone(),
                            body: MessageBody::Commit {
                                view,
                                sequence,
                                digest: slot.digest,
                            },
                        })
                    }
                }
            } else {
                None
            }
        };
        if let Some(c) = maybe_commit {
            self.dispatch(&c)?;
            self.arm_wait_commit_quorum(view);
        }
        Ok(())
    }

    fn on_commit(
        &self,
        from: NodeId,
        view: u64,
        sequence: u64,
        digest: [u8; 32],
    ) -> Result<(), ConsensusError> {
        let q = self.config.quorum();
        let maybe_done = {
            let mut s = self.state.write().expect("state write");
            if view != s.view {
                None
            } else if let Some(slot) = s.slots.get_mut(&sequence) {
                if slot.digest != digest || slot.executed {
                    None
                } else {
                    slot.commits.insert(from);
                    if slot.commits.len() < q {
                        None
                    } else {
                        slot.executed = true;
                        let data = slot.data.clone();
                        s.last_committed_seq = s.last_committed_seq.max(sequence);
                        s.slots.remove(&sequence);
                        Some(CommittedUpdate {
                            view,
                            sequence,
                            data,
                        })
                    }
                }
            } else {
                None
            }
        };
        if let Some(update) = maybe_done {
            self.commit_fanout.broadcast(update);
            self.arm_wait_next_pre_prepare();
        }
        Ok(())
    }

    fn on_view_change(
        &self,
        from: NodeId,
        new_view: u64,
        last_stable_seq: u64,
    ) -> Result<(), ConsensusError> {
        let q = self.config.quorum();
        let switched = {
            let mut s = self.state.write().expect("state write");
            if new_view <= s.view {
                false
            } else {
                let supporters = s
                    .view_change_supporters
                    .entry(new_view)
                    .or_insert_with(HashMap::new);
                supporters.insert(from, last_stable_seq);
                if supporters.len() < q {
                    false
                } else {
                    let max_stable = supporters.values().copied().max().unwrap_or(0);
                    s.view = new_view;
                    s.last_committed_seq = s.last_committed_seq.max(max_stable);
                    s.slots.clear();
                    s.view_change_supporters.clear();
                    true
                }
            }
        };
        if switched {
            self.arm_wait_next_pre_prepare();
        }
        Ok(())
    }

    pub(crate) fn dispatch(&self, msg: &PbftMessage) -> Result<(), ConsensusError> {
        for tx in self.peers.iter() {
            tx.send(msg.clone()).map_err(|_| ConsensusError::SendError)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::local_cluster;
    use std::time::Duration;

    fn await_all_committed(nodes: &[Arc<ConsensusCore>], seq: u64) {
        for _ in 0..400 {
            if nodes.iter().all(|n| n.last_committed_seq() >= seq) {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!(
            "timeout waiting for seq {seq}: {:?}",
            nodes.iter().map(|n| n.last_committed_seq()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn four_replicas_one_fault_happy_path() {
        let nodes = local_cluster(1, 4).expect("cluster");
        let mut subs: Vec<_> = nodes.iter().map(|n| n.subscribe_commits()).collect();
        let primary = nodes[0].clone();
        let data = b"batch-1".to_vec();
        primary.propose(data.clone()).expect("propose");
        await_all_committed(&nodes, 1);
        for n in &nodes {
            assert_eq!(n.last_committed_seq(), 1);
        }
        for sub in &mut subs {
            let u = sub.recv().expect("commit recv");
            assert_eq!(u.sequence, 1);
            assert_eq!(u.data, data);
        }
    }

    #[test]
    fn quorum_matches_pbft_2f_plus_one() {
        let ids: Vec<_> = (0..5).map(|i| NodeId(format!("r{i}"))).collect();
        let c = ConsensusConfig {
            fault_tolerance: 1,
            replica_ids: ids,
            timeouts: None,
        };
        assert_eq!(c.quorum(), 3);
        assert_ne!(
            c.replica_ids.len() - c.fault_tolerance,
            c.quorum(),
            "n-f must not be used as the prepare/commit threshold when n > 3f+1"
        );
    }

    #[test]
    fn non_primary_cannot_propose() {
        let nodes = local_cluster(1, 4).expect("cluster");
        let err = nodes[1].propose(vec![1]).err().expect("err");
        assert!(matches!(err, ConsensusError::NotPrimary));
    }

    #[test]
    fn forged_pre_prepare_from_non_primary_is_ignored() {
        let nodes = local_cluster(1, 4).expect("cluster");
        let rogue = PbftMessage {
            from: nodes[1].replica_id(),
            body: MessageBody::PrePrepare {
                view: 0,
                sequence: 1,
                digest: [0u8; 32],
                data: vec![9],
            },
        };
        nodes[0].dispatch(&rogue).expect("dispatch");
        std::thread::sleep(Duration::from_millis(120));
        for n in &nodes {
            assert_eq!(n.last_committed_seq(), 0, "must not commit forged pre-prepare");
        }
    }

    #[test]
    fn liveness_timeout_advances_view_when_primary_silent() {
        use crate::harness::local_cluster_with_timeouts;
        let timeouts = TimeoutConfig {
            wait_pre_prepare: Duration::from_millis(150),
            prepare_certificate: Duration::from_secs(60),
            commit_certificate: Duration::from_secs(60),
            view_change_resend: Duration::from_secs(60),
        };
        let nodes = local_cluster_with_timeouts(1, 4, Some(timeouts)).expect("cluster");
        std::thread::sleep(Duration::from_millis(800));
        assert!(
            nodes.iter().all(|n| n.view() >= 1),
            "expected time-variant liveness to raise the view; got {:?}",
            nodes.iter().map(|n| n.view()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn view_change_advances_primary() {
        let nodes = local_cluster(1, 4).expect("cluster");
        let stable = nodes[0].last_committed_seq();
        let q = nodes[0].config.quorum();
        assert_eq!(q, 3);
        for i in 0..3 {
            let msg = PbftMessage {
                from: nodes[i].replica_id(),
                body: MessageBody::ViewChange {
                    new_view: 1,
                    last_stable_seq: stable,
                },
            };
            nodes[0].dispatch(&msg).expect("dispatch vc");
        }
        std::thread::sleep(Duration::from_millis(120));
        for n in &nodes {
            assert_eq!(n.view(), 1);
        }
        assert!(nodes[1].is_primary());
        nodes[1].propose(b"v2".to_vec()).expect("new primary proposes");
        await_all_committed(&nodes, 1);
        for n in &nodes {
            assert_eq!(n.last_committed_seq(), 1);
        }
    }
}

#[cfg(test)]
mod hash_tests {
    use crate::security::SecurityManager;

    #[test]
    fn security_hash_deterministic_for_same_input() {
        let sec = SecurityManager::new();
        let bytes: Vec<u8> = (0..200).map(|i| (i * 7) as u8).collect();
        assert_eq!(sec.hash(&bytes), sec.hash(&bytes));
    }
}
