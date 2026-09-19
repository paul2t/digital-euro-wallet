//! Wallet identity and its encoding as field elements.
//!
//! A wallet identity is 256 bits (in practice the hash of the secure element's
//! attestation public key). The field `F_p` used for the secret-sharing lines
//! only holds 61 bits, so the identity is cut into [`LIMBS`] limbs of
//! [`LIMB_BITS`] bits each. Each limb becomes the slope of its own line
//! `f_j(x) = I_j * x + s_j`, all evaluated at the *same* merchant challenge
//! `x`. One double-spend therefore reveals every limb at once, and the full
//! identity reassembles exactly.

use crate::error::{Error, Result};
use crate::field::Fp;
use std::fmt;

/// Number of parallel lines carried by one token.
pub const LIMBS: usize = 5;
/// Bits of identity carried per line (`5 * 52 = 260 >= 256`).
pub const LIMB_BITS: u32 = 52;

/// A 256-bit wallet identity — the value that anonymity protects and that a
/// double-spend unavoidably discloses.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalletId([u8; 32]);

impl WalletId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        WalletId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Short human-readable form for logs and fraud reports.
    pub fn short(&self) -> String {
        self.0[..6].iter().map(|b| format!("{b:02x}")).collect()
    }

    fn words(&self) -> [u64; 4] {
        let mut words = [0u64; 4];
        for (i, word) in words.iter_mut().enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&self.0[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(buf);
        }
        words
    }

    /// Extracts `len` bits starting at bit `start` of the little-endian
    /// 256-bit integer.
    fn extract_bits(words: &[u64; 4], start: u32, len: u32) -> u64 {
        debug_assert!(len <= 64);
        let mut out = 0u64;
        for bit in 0..len {
            let index = start + bit;
            if index >= 256 {
                break;
            }
            let word = words[(index / 64) as usize];
            let value = (word >> (index % 64)) & 1;
            out |= value << bit;
        }
        out
    }

    /// Splits the identity into the slopes of the [`LIMBS`] lines.
    pub fn to_limbs(&self) -> [Fp; LIMBS] {
        let words = self.words();
        let mut limbs = [Fp::ZERO; LIMBS];
        for (j, limb) in limbs.iter_mut().enumerate() {
            *limb = Fp::new(Self::extract_bits(&words, j as u32 * LIMB_BITS, LIMB_BITS));
        }
        limbs
    }

    /// Reassembles an identity from recovered slopes.
    ///
    /// Fails if a limb exceeds its bit budget, which is how the backend
    /// notices that the recovered slopes are not a well-formed identity (a
    /// tampered wallet that answered with garbage rather than its real `I`).
    pub fn from_limbs(limbs: &[Fp; LIMBS]) -> Result<Self> {
        let mut bytes = [0u8; 32];
        for (j, limb) in limbs.iter().enumerate() {
            let value = limb.value();
            let start = j as u32 * LIMB_BITS;
            let budget = LIMB_BITS.min(256 - start);
            if budget < 64 && value >= (1u64 << budget) {
                return Err(Error::MalformedIdentity {
                    limb: j,
                    value,
                    budget,
                });
            }
            for bit in 0..budget {
                if (value >> bit) & 1 == 1 {
                    let index = (start + bit) as usize;
                    bytes[index / 8] |= 1 << (index % 8);
                }
            }
        }
        Ok(WalletId(bytes))
    }
}

impl fmt::Debug for WalletId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WalletId({}…)", self.short())
    }
}

impl fmt::Display for WalletId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn limb_roundtrip_is_lossless() {
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..500 {
            let id = WalletId::from_bytes(rng.gen());
            let limbs = id.to_limbs();
            assert_eq!(WalletId::from_limbs(&limbs).unwrap(), id);
        }
    }

    #[test]
    fn out_of_range_limb_is_rejected() {
        let mut limbs = WalletId::from_bytes([0u8; 32]).to_limbs();
        limbs[0] = Fp::new(1u64 << 60);
        assert!(WalletId::from_limbs(&limbs).is_err());
    }
}
