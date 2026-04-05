# Enhanced PBFT mechanism

This repository is a **Rust library** that gives you two things in one place:

1. A **PBFT-style consensus core** (Practical Byzantine Fault Tolerance): replicas agree on an ordered stream of client requests even when some nodes misbehave, up to a configured fault bound.
2. A **Time-Variant BLAKE3** digest construction: request digests are computed with an initialization vector (IV) built from the mathematical recipe in the accompanying specification (see **Specification** below), then hashed with an **in-tree BLAKE3** implementation.

The library is written so it depends on **no other crates**—only the Rust standard library and `core`. You bring your own network, cryptography for transport, and process wiring.

---

## Table of contents

- [What problem this solves](#what-problem-this-solves)
- [What PBFT does here (in plain language)](#what-pbft-does-here-in-plain-language)
- [What “Time-Variant BLAKE3” means here](#what-time-variant-blake3-means-here)
- [Time-invariant safety vs time-variant liveness](#time-invariant-safety-vs-time-variant-liveness)
- [What this library does *not* include](#what-this-library-does-not-include)
- [How the pieces fit together](#how-the-pieces-fit-together)
- [How to use it in your project](#how-to-use-it-in-your-project)
- [Crate layout](#crate-layout)
- [Specification and third-party material](#specification-and-third-party-material)
- [Building, testing, and publishing](#building-testing-and-publishing)
- [License](#license)
- [Security](#security)

---

## What problem this solves

In a **distributed system**, several computers (“replicas”) need to **agree** on what happened and in what order—for example which transfers were executed, which configuration was active, or which block of data was committed.

Some replicas might **crash**, **stall**, or **lie**. **Byzantine** fault tolerance means the protocol still keeps **honest** replicas consistent with each other, as long as **no more than `f`** replicas are faulty and you have at least **`3f + 1`** replicas in total.

This crate implements a **simplified** multi-phase protocol in the PBFT family: **pre-prepare**, **prepare**, and **commit**, plus a minimal **view-change** path when progress stalls. It is meant as a **clear, embeddable core** you can connect to real networking and production-hardening—not a full enterprise PBFT product out of the box.

---

## What PBFT does here (in plain language)

Think of one replica as the **primary** for the current **view** (a logical epoch). The primary proposes the next request in sequence.

Roughly:

1. **Pre-prepare**  
   The primary broadcasts “I propose this payload at this `(view, sequence)` with this **digest**.”  
   The digest is a 32-byte fingerprint of the payload, produced by the **Time-Variant BLAKE3** path so every honest replica computes the **same** digest for the same `(view, sequence, payload)`.

2. **Prepare**  
   Each replica that accepts the pre-prepare (correct primary, correct view, expected sequence, digest matches payload) broadcasts a **prepare** attesting that digest.

3. **Commit**  
   When enough distinct replicas have prepared (**`2f + 1`** including the implicit quorum math for PBFT), each broadcasts **commit** for that digest.

4. **Execute**  
   When enough commits are seen, the request is **executed** (in this library: delivered via a local “commit fan-out” channel). The **last committed sequence** advances; the next proposal must be the next sequence number (**strict serial** ordering in this implementation).

5. **View change**  
   If you enable **timeouts**, background logic can broadcast **view-change** messages when the primary appears silent. When **`2f + 1`** replicas agree on a higher view, the view advances and the **primary rotates** according to the fixed replica list.

**Important:** The **safety** of “what got committed” does **not** depend on wall-clock time. **Timeouts** only affect **liveness** (how fast you move to a new view), not the mathematical commit rule.

---

## What “Time-Variant BLAKE3” means here

The **Time-Variant BLAKE3** idea (described precisely in the TeX/PDF in the related spec repo) builds an **8-word IV** in \(\mathbb{F}_{2^{32}}^8\) using:

- Eight **timestamps** \(t_1,\ldots,t_8\) (in this library, for consensus, derived **deterministically** from `(view, sequence)` so all replicas match),
- A configured **CPU frequency** term \(\nu_{\text{cpu}}\) in the \(\tau\) step,
- A **prime-distance** map \(\delta_p\),
- An **entropy-mixing** function \(\mathcal{E}\) with a **64-byte** entropy pool (deterministic in the consensus profile),
- An auxiliary **\(\mathcal{H}(m_i)\)** term per word (implemented as a small BLAKE3-derived value standing in for “memory statistics” in the paper).

The final digest used in PBFT is **BLAKE3( IV_as_bytes ‖ payload )** using the **reference BLAKE3** code vendored in this crate. The paper’s idealized form XORs the IV into the compression function’s chaining value; the public reference code here does not expose that hook, so **IV is prefixed** to the message before hashing—documented in code as the binding mechanism.

---

## Time-invariant safety vs time-variant liveness

- **Time-invariant safety:** Whether a request is committed is decided from **messages and quorum counts** and **matching digests**, not from “what time your clock says.” Clock skew between machines does **not** change the digest for a given `(view, sequence)` in the consensus profile.

- **Time-variant liveness:** Optional **timeouts** use **real time** (`std::time`) to detect stalls and trigger **view-change** retries. That is the part of the system that **does** care about clocks, and it should be tuned for your network and hardware.

---

## What this library does *not* include

Be explicit about limits so you do not mistake this for a full blockchain or production BFT stack:

- **No network stack** — you pass `std::sync::mpsc::Sender` handles (or wrap them) to fan out [`PbftMessage`](src/consensus.rs).
- **No TLS, no QUIC, no noise** — confidentiality and integrity on the wire are **your** responsibility.
- **No digital signatures on messages** — authenticity of `from` fields is **not** cryptographically enforced inside this core.
- **No dynamic membership** — the replica set is fixed in [`ConsensusConfig::replica_ids`](src/consensus.rs).
- **No checkpoints, state transfer, or full PBFT view-change protocol** — only a **reduced** view-change sufficient for demos and integration tests.
- **No persistence** — optional feature flags exist as stubs for future work.

---

## How the pieces fit together

```
┌─────────────────────────────────────────────────────────────┐
│  Your application                                           │
│  - Open network connections                                 │
│  - Deserialize PbftMessage, send into each replica’s mpsc    │
│  - Call propose() on the current primary                    │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  ConsensusCore (per replica)                                 │
│  - run_inbound(rx) on a thread                               │
│  - optional spawn_liveness_watcher()                         │
│  - subscribe_commits() for executed payloads                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────┴─────────────────────────────────┐
│  SecurityManager                                             │
│  - hash_consensus(view, sequence, payload) → digest        │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────┴─────────────────────────────────┐
│  time_variant_blake3 + blake3_reference                      │
│  - IV from TeX-aligned formulas                              │
│  - BLAKE3 reference implementation (no external blake3 crate) │
└─────────────────────────────────────────────────────────────┘
```

---

## How to use it in your project

### 1. Add the dependency

From the same repository (or after publishing to crates.io):

```toml
[dependencies]
enhanced-pbft = "0.2"
```

Path dependency during development:

```toml
[dependencies]
enhanced-pbft = { path = "." }
```

### 2. Configure replicas

Every replica must use the **same** ordered `replica_ids` list. The primary for `view` is `replica_ids[view as usize % n]`.

```rust
use enhanced_pbft::{
    ConsensusConfig, ConsensusCore, NodeId, SecurityManager,
};
use std::sync::{mpsc, Arc};

let replica_ids: Vec<NodeId> = (0..4)
    .map(|i| NodeId(format!("node-{i}")))
    .collect();

let config = ConsensusConfig {
    fault_tolerance: 1,           // f; need n >= 3f + 1 → 4 nodes OK
    replica_ids: replica_ids.clone(), // same order on every replica
    timeouts: None,               // or Some(TimeoutConfig::default())
};
// Keep `replica_ids` for the construction loop below.
```

### 3. Build the message mesh

Create **one `std::sync::mpsc::channel` per replica**. The `i`-th sender must point at the `i`-th replica’s receiver (the harness does this for you).

```rust
let mut txs = Vec::new();
let mut rxs = Vec::new();
for _ in 0..n {
    let (tx, rx) = mpsc::channel();
    txs.push(tx);
    rxs.push(rx);
}
let peers = Arc::new(txs);
```

### 4. Construct each `ConsensusCore`

```rust
let security = Arc::new(SecurityManager::new());
let mut rx_iter = rxs.into_iter();
let mut cores = Vec::new();

for id in replica_ids {
    let core = ConsensusCore::new(
        id,
        config.clone(),
        Arc::clone(&security),
        Arc::clone(&peers),
    )?;

    ConsensusCore::spawn_liveness_watcher(&core);

    let runner = Arc::clone(&core);
    let rx = rx_iter.next().expect("one receiver per replica");
    std::thread::spawn(move || {
        runner.run_inbound(rx);
    });

    cores.push(core);
}
```

The same pattern appears in [`src/harness.rs`](src/harness.rs).

### 5. Propose (primary only)

```rust
primary.propose(my_payload_bytes)?;
```

### 6. Observe commits

```rust
let rx = core.subscribe_commits();
// ... later, on another thread ...
let update = rx.recv().expect("commit");
// update.view, update.sequence, update.data
```

### 7. Optional: timeouts for liveness

```rust
use enhanced_pbft::TimeoutConfig;
use std::time::Duration;

let timeouts = TimeoutConfig {
    wait_pre_prepare: Duration::from_secs(5),
    prepare_certificate: Duration::from_secs(3),
    commit_certificate: Duration::from_secs(3),
    view_change_resend: Duration::from_secs(5),
};
// Pass Some(timeouts) in ConsensusConfig and call spawn_liveness_watcher.
```

### 8. Tests and local simulation

For a fully connected in-process mesh (no real network):

```rust
use enhanced_pbft::harness::local_cluster;

let nodes = local_cluster(1, 4)?; // f=1, n=4
nodes[0].propose(b"hello".to_vec())?;
```

---

## Crate layout

| Module / path | Purpose |
|---------------|---------|
| [`consensus`](src/consensus.rs) | PBFT messages, config, core state machine, optional liveness |
| [`time_variant_blake3`](src/time_variant_blake3.rs) | IV generation aligned with the TeX spec; `hash_payload` |
| [`blake3_reference`](src/blake3_reference.rs) | BLAKE3 reference implementation (CC0 upstream) |
| [`security`](src/security.rs) | `SecurityManager` wrapping config + consensus digest API |
| [`harness`](src/harness.rs) | Local `mpsc` mesh for tests and examples |
| [`error`](src/error.rs) | `ConsensusError` |

---

## Specification and third-party material

The mathematical write-up for **Time-Variant BLAKE3** lives in the **[Time-VariantBlake3](https://github.com/TheMapleseed/Time-VariantBlake3)** repository (TeX and PDF). This repo can include it as a **git submodule** under `third_party/Time-VariantBlake3` for convenient offline reading; the **published crate tarball** lists the spec URL instead of vendoring the PDF, to keep the package small and avoid submodule checkout issues on `cargo publish`.

**BLAKE3** reference code is derived from the [BLAKE3 reference implementation](https://github.com/BLAKE3-team/BLAKE3) (public domain / CC0) and lives in `src/blake3_reference.rs`.

---

## Building, testing, and publishing

```bash
cargo build --release
cargo test
```

Check what will be uploaded to crates.io:

```bash
cargo package --list
```

Publish (owners only):

```bash
cargo publish
```

Clone with submodule (for local spec tree):

```bash
git clone --recurse-submodules https://github.com/TheMapleseed/Enhanced-PBFT-mechanism.git
# or, after clone:
git submodule update --init --recursive
```

---

## License

This project is licensed under the **GNU General Public License v3.0** — see [`LICENSE`](LICENSE). The vendored **BLAKE3 reference** implementation follows the BLAKE3 project’s **CC0 / public domain** terms (see file header in `src/blake3_reference.rs`).

---

## Security

This code is a **research and integration-oriented** core. It is **not** a substitute for a full security architecture: you still need authenticated channels, key management, rate limiting, and deployment review.

To report a security issue, open a private advisory or contact the maintainers through the repository’s GitHub **Security** tab if enabled.

---

## Supported versions

| Version | Status   |
|--------|----------|
| 0.2.x  | Current  |
| 0.1.x  | Unmigrated / unsupported in this tree |
