//! Time-differential BLAKE3 IV generation per `third_party/Time-VariantBlake3/TimeVariantBlake3.tex`.
//!
//! This module follows the **Algorithm Definition** section (§1) of that document:
//!
//! 1. **Temporal signature (§1.1)**  
//!    \(i \in \{1,\ldots,8\}\), \(\tau(t_i) = t_i \oplus (\nu_{\mathrm{cpu}} \cdot i)\),  
//!    \(\sigma_t = \bigoplus_{i=1}^{8} \tau(t_i)\) as bitwise XOR of 64-bit words, then identified with
//!    \(\mathbb{F}_{2^{32}}\) by folding \(x \mapsto (x \bmod 2^{32}) \oplus \lfloor x/2^{32}\rfloor\) (low/high XOR).
//!
//! 2. **Prime distance (§1.2)**  
//!    \(\delta_p(x) = \min\{p - x \mid p \in \mathcal{P},\, p > x\}\) on \(x \in \mathbb{F}_{2^{32}}\),  
//!    \(\delta_i = \delta_p(\sigma_t + i\cdot\omega)\) with \(\omega = 32\) (word size in bits), \(i \in \{1,\ldots,8\}\).  
//!    Search for \(p\) is capped at \(2^{20}\) steps per **Implementation Constraints** §3.2.
//!
//! 3. **Entropy mixing (§1.3)**  
//!    \(\mathcal{E}(x) = x \oplus \mathrm{ROT}_r(x) \oplus \eta\) with  
//!    \(r = \lfloor\log_2(x)\rfloor \bmod 32\) (and \(r = 0\) if \(x = 0\)).  
//!    **§3.3** requires \(|\eta| \geq 64\) bytes at the pool level; we derive a **64-byte** pool once, then each
//!    \(\eta\) used in \(\mathcal{E}(\delta_i)\) is a 32-bit word formed from that pool (two little-endian words XORed).
//!
//! 4. **IV (§1.4)**  
//!    \(IV_i = \mathcal{E}(\delta_i) \oplus \mathcal{H}(m_i)\) for \(i \in \{1,\ldots,8\}\).  
//!    \(\mathcal{H}(m_i)\) is implemented as the first 32 bits of an auxiliary BLAKE3 digest (stand-in for memory statistics \(m_i\)).
//!
//! **Compression (§4):** \(G'(h,m,t) = G(h \oplus IV(t), m, t)\). The in-tree reference hasher does not expose \(G\);
//! we approximate binding by hashing **`IV \,\|\, \text{payload}`** with standard BLAKE3 (see [`hash_payload`]).
//!
//! **PBFT / agreement:** [`ConsensusTemporal`] supplies eight timestamps \(t_1,\ldots,t_8\) deterministically from
//! `(view, sequence)` so all replicas compute the same \(IV\).

use crate::blake3_reference::Hasher;

/// \(\nu_{\mathrm{cpu}}\) in Hz (§1.1).
#[derive(Clone, Debug)]
pub struct TimeVariantBlake3Config {
    pub nu_cpu_hz: u64,
}

impl Default for TimeVariantBlake3Config {
    fn default() -> Self {
        Self {
            nu_cpu_hz: 3_000_000_000,
        }
    }
}

/// Logical timestamps \(t_1,\ldots,t_8\) for one IV evaluation.  
/// For replicated consensus, all honest nodes share the same `(view, sequence)`.
#[derive(Clone, Copy, Debug)]
pub struct ConsensusTemporal {
    pub view: u64,
    pub sequence: u64,
}

impl ConsensusTemporal {
    /// Paper index \(i \in \{1,\ldots,8\}\): value \(t_i \in \mathcal{T}\) (here: deterministic `u64`).
    #[must_use]
    pub fn t_i(&self, i: u8) -> u64 {
        assert!((1..=8).contains(&i), "TeX requires i in {{1,...,8}}");
        let j = u64::from(i - 1);
        let mut x = self.view ^ self.sequence.rotate_left(17);
        x ^= j << (8 + (j as u32 % 48));
        x = x.wrapping_mul(0x9E37_79B97F4A7C15);
        x ^ self.sequence.wrapping_mul(0xC2B2_AE3D_27D4_EB4F + j)
    }
}

/// \(\tau(t_i) = t_i \oplus (\nu_{\mathrm{cpu}} \cdot i)\) with the **same** \(i \in \{1,\ldots,8\}\) as in \(t_i\).
#[inline]
fn tau(t_i: u64, nu_cpu_hz: u64, i: u8) -> u64 {
    debug_assert!((1..=8).contains(&i));
    t_i ^ nu_cpu_hz.wrapping_mul(u64::from(i))
}

/// Fold a 64-bit XOR accumulator into \(\mathbb{F}_{2^{32}}\).
#[inline]
fn fold_u64_to_f32(x: u64) -> u32 {
    (x as u32) ^ ((x >> 32) as u32)
}

/// \(\sigma_t = \bigoplus_{i=1}^{8} \tau(t_i)\) (bitwise XOR of full \(\tau\) values), then fold into \(\mathbb{F}_{2^{32}}\) (§1.1).
fn sigma_t(temporal: &ConsensusTemporal, nu_cpu_hz: u64) -> u32 {
    let mut acc: u64 = 0;
    for i in 1u8..=8 {
        let ti = temporal.t_i(i);
        let taui = tau(ti, nu_cpu_hz, i);
        acc ^= taui;
    }
    fold_u64_to_f32(acc)
}

fn is_prime_u32(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }
    let mut d = 5u32;
    while (d as u64).saturating_mul(d as u64) <= n as u64 {
        if n % d == 0 || n % d.wrapping_add(2) == 0 {
            return false;
        }
        d = d.wrapping_add(6);
    }
    true
}

/// \(\delta_p(x)\) for \(x \in \mathbb{F}_{2^{32}}\) (§1.2). Search length bounded by §3.2 (\(\leq 2^{20}\)).
fn delta_p(x: u32) -> u32 {
    const MAX_STEPS: u32 = 1 << 20;
    let mut steps = 0u32;
    let mut y = x.wrapping_add(1);
    loop {
        if is_prime_u32(y) {
            return y.wrapping_sub(x);
        }
        steps = steps.wrapping_add(1);
        if steps >= MAX_STEPS {
            return 1;
        }
        y = y.wrapping_add(1);
    }
}

/// \(r = \lfloor\log_2(x)\rfloor \bmod 32\); for \(x = 0\), use \(r = 0\) (§1.3).
#[inline]
fn r_rot_bits(x: u32) -> u32 {
    if x == 0 {
        0
    } else {
        let floor_log2 = 31 - x.leading_zeros();
        floor_log2 % 32
    }
}

/// \(\mathcal{E}(x) = x \oplus \mathrm{ROT}_r(x) \oplus \eta\) (§1.3).
#[inline]
fn mathcal_e(x: u32, eta: u32) -> u32 {
    let r = r_rot_bits(x);
    x ^ x.rotate_right(r) ^ eta
}

/// 64-byte entropy pool (§3.3: \(|\eta| \geq 64\) bytes at pool level).  
/// In consensus mode, pool bytes are deterministic from `(view, sequence)`.
fn entropy_pool_64(temporal: ConsensusTemporal) -> [u8; 64] {
    let mut h = Hasher::new();
    h.update(b"TimeVariantBlake3|eta-pool|v1");
    h.update(&temporal.view.to_le_bytes());
    h.update(&temporal.sequence.to_le_bytes());
    let mut pool = [0u8; 64];
    h.finalize(&mut pool);
    pool
}

/// \(\eta\) for index \(i \in \{1,\ldots,8\}\) drawn from the 64-byte pool (first and second half).
#[inline]
fn eta_i(pool: &[u8; 64], i: u8) -> u32 {
    debug_assert!((1..=8).contains(&i));
    let o = usize::from(i - 1) * 4;
    let lo = u32::from_le_bytes(pool[o..o + 4].try_into().unwrap());
    let hi = u32::from_le_bytes(pool[32 + o..32 + o + 4].try_into().unwrap());
    lo ^ hi
}

/// \(\mathcal{H}(m_i)\) as 32 bits: auxiliary BLAKE3 (stand-in for memory statistics \(m_i\), §1.4).
fn h_mi(temporal: ConsensusTemporal, i: u8) -> u32 {
    debug_assert!((1..=8).contains(&i));
    let mut h = Hasher::new();
    h.update(b"TimeVariantBlake3|H|m_i|v1");
    h.update(&temporal.view.to_le_bytes());
    h.update(&temporal.sequence.to_le_bytes());
    h.update(&[i]);
    let mut b = [0u8; 32];
    h.finalize(&mut b);
    u32::from_le_bytes(b[0..4].try_into().unwrap())
}

/// \(IV \in \mathbb{F}_{2^{32}}^8\) with \(IV_i\) at index \(i-1\) (§1.4).
#[must_use]
pub fn iv_words(temporal: ConsensusTemporal, cfg: &TimeVariantBlake3Config) -> [u32; 8] {
    let sigma = sigma_t(&temporal, cfg.nu_cpu_hz);
    let pool = entropy_pool_64(temporal);
    let mut iv = [0u32; 8];
    for i in 1u8..=8 {
        // δ_i = δ_p(σ_t + i·ω), ω = 32 (§1.2).
        let x = sigma.wrapping_add(u32::from(i).wrapping_mul(32));
        let delta_i = delta_p(x);
        let eta = eta_i(&pool, i);
        let e = mathcal_e(delta_i, eta);
        iv[usize::from(i - 1)] = e ^ h_mi(temporal, i);
    }
    iv
}

#[inline]
fn iv_to_bytes_le(words: &[u32; 8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (k, w) in words.iter().enumerate() {
        b[k * 4..][..4].copy_from_slice(&w.to_le_bytes());
    }
    b
}

/// BLAKE3 digest of **`IV_bytes || payload`** (§4 binding; `IV` from [`iv_words`]).
#[must_use]
pub fn hash_payload(temporal: ConsensusTemporal, cfg: &TimeVariantBlake3Config, payload: &[u8]) -> [u8; 32] {
    let words = iv_words(temporal, cfg);
    let prefix = iv_to_bytes_le(&words);
    let mut h = Hasher::new();
    h.update(&prefix);
    h.update(payload);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tex_indices_one_through_eight_only() {
        let t = ConsensusTemporal { view: 0, sequence: 1 };
        for i in 1u8..=8 {
            let _ = t.t_i(i);
        }
    }

    #[test]
    #[should_panic]
    fn t_i_rejects_zero_index() {
        let t = ConsensusTemporal { view: 0, sequence: 1 };
        let _ = t.t_i(0);
    }

    #[test]
    fn consensus_digest_is_deterministic_across_calls() {
        let cfg = TimeVariantBlake3Config::default();
        let t = ConsensusTemporal { view: 0, sequence: 1 };
        let d = b"payload";
        let a = hash_payload(t, &cfg, d);
        let b = hash_payload(t, &cfg, d);
        assert_eq!(a, b);
    }

    #[test]
    fn different_sequence_changes_digest() {
        let cfg = TimeVariantBlake3Config::default();
        let d = b"same";
        let a = hash_payload(ConsensusTemporal { view: 0, sequence: 1 }, &cfg, d);
        let b = hash_payload(ConsensusTemporal { view: 0, sequence: 2 }, &cfg, d);
        assert_ne!(a, b);
    }

    #[test]
    fn iv_words_nonzero_typical() {
        let w = iv_words(
            ConsensusTemporal { view: 1, sequence: 99 },
            &TimeVariantBlake3Config::default(),
        );
        assert!(w.iter().any(|&x| x != 0));
    }

    #[test]
    fn delta_p_smoke() {
        assert_eq!(delta_p(0), 2);
    }

    #[test]
    fn mathcal_e_zero() {
        let p = entropy_pool_64(ConsensusTemporal { view: 3, sequence: 7 });
        let y = mathcal_e(0, eta_i(&p, 1));
        assert_eq!(y, 0 ^ 0 ^ eta_i(&p, 1));
    }
}
