//! Arithmetic in the prime field `F_p` with `p = 2^61 - 1` (a Mersenne prime).
//!
//! The whole double-spending trap is linear algebra over this field, so every
//! operation here must be exact and constant-modulus. `p` is small enough that
//! a product of two elements fits in a `u128`, which keeps the code free of a
//! bignum dependency on the hot path. It is *not* large enough to hold a
//! 256-bit wallet identity, so [`crate::identity`] splits the identity into
//! several 52-bit limbs and runs one line per limb (see `identity.rs`).

use rand::Rng;
use std::fmt;

/// The field modulus, `2^61 - 1`.
pub const P: u64 = (1u64 << 61) - 1;

/// An element of `F_p`, always kept in canonical form (`0 <= value < P`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Fp(u64);

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    /// Reduces an arbitrary `u64` into the field.
    pub fn new(v: u64) -> Self {
        Fp(v % P)
    }

    /// Reduces an arbitrary `u128` into the field (used after multiplication
    /// and when deriving challenges from hashes).
    pub fn from_u128(v: u128) -> Self {
        Fp((v % P as u128) as u64)
    }

    /// The canonical representative in `[0, P)`.
    pub fn value(self) -> u64 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Big-endian encoding, for hashing and commitments.
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Uniform sampling by rejection — modulo bias would leak a sliver of the
    /// blinding factor `s`, which is exactly what must stay perfectly secret.
    pub fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let candidate = rng.gen::<u64>() & ((1u64 << 61) - 1);
            if candidate < P {
                return Fp(candidate);
            }
        }
    }

    pub fn add(self, other: Fp) -> Fp {
        let sum = self.0 + other.0; // < 2^62, no overflow
        Fp(if sum >= P { sum - P } else { sum })
    }

    pub fn sub(self, other: Fp) -> Fp {
        Fp(if self.0 >= other.0 {
            self.0 - other.0
        } else {
            self.0 + P - other.0
        })
    }

    pub fn neg(self) -> Fp {
        if self.0 == 0 {
            self
        } else {
            Fp(P - self.0)
        }
    }

    pub fn mul(self, other: Fp) -> Fp {
        Fp(((self.0 as u128 * other.0 as u128) % P as u128) as u64)
    }

    /// Square-and-multiply exponentiation.
    pub fn pow(self, mut exp: u64) -> Fp {
        let mut base = self;
        let mut acc = Fp::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse via Fermat's little theorem: `a^(p-2) = a^-1`.
    ///
    /// Returns `None` for zero. The double-spend solver calls this on
    /// `x1 - x2`, which is non-zero precisely when the two merchants issued
    /// distinct challenges.
    pub fn inv(self) -> Option<Fp> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow(P - 2))
        }
    }
}

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp({})", self.0)
    }
}

impl fmt::Display for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn add_sub_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..1000 {
            let a = Fp::random(&mut rng);
            let b = Fp::random(&mut rng);
            assert_eq!(a.add(b).sub(b), a);
            assert_eq!(a.sub(b).add(b), a);
            assert_eq!(a.add(a.neg()), Fp::ZERO);
        }
    }

    #[test]
    fn inverse_is_inverse() {
        let mut rng = StdRng::seed_from_u64(11);
        for _ in 0..500 {
            let a = Fp::random(&mut rng);
            if a.is_zero() {
                continue;
            }
            assert_eq!(a.mul(a.inv().unwrap()), Fp::ONE);
        }
        assert!(Fp::ZERO.inv().is_none());
    }

    #[test]
    fn multiplication_does_not_overflow_near_modulus() {
        let big = Fp(P - 1);
        assert_eq!(big.mul(big), Fp::ONE); // (-1)^2 = 1
    }
}
