//! Chaum RSA blind signatures, used by the issuer to certify offline tokens
//! without learning which token it certified.
//!
//! Wallet computes `m' = FDH(m) * r^e mod n`, the bank returns
//! `s' = (m')^d mod n`, and the wallet unblinds with `s = s' * r^-1 mod n`,
//! which is a plain signature `s = FDH(m)^d` on a message the bank never saw.
//!
//! # Scope
//!
//! This is a readable reference implementation: schoolbook modexp, a
//! hash-expansion full-domain hash, and no side-channel hardening. A
//! production wallet would delegate the private key to an HSM and use a
//! reviewed scheme (RSA-FDH per RFC 9474, or a blind Schnorr / BBS variant).

use crate::hash::tagged;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::Rng;

/// Public verification key of the issuer (the Eurosystem backend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

impl IssuerPublicKey {
    /// Size of the modulus in bytes.
    pub fn modulus_bytes(&self) -> usize {
        (self.n.bits() as usize + 7) / 8
    }

    /// Full-domain hash: expand the 32-byte message digest to the width of the
    /// modulus and reduce. Prevents the multiplicative forgeries that plain
    /// "sign the raw hash" RSA allows.
    pub fn full_domain_hash(&self, digest: &[u8; 32]) -> BigUint {
        let width = self.modulus_bytes();
        let mut expanded = Vec::with_capacity(width + 32);
        let mut counter: u32 = 0;
        while expanded.len() < width {
            expanded.extend_from_slice(&tagged("euro/fdh", &[digest, &counter.to_be_bytes()]));
            counter += 1;
        }
        expanded.truncate(width);
        expanded[0] &= 0x3f; // keep it comfortably below n before reduction
        BigUint::from_bytes_be(&expanded).mod_floor(&self.n)
    }

    /// Verifies an unblinded signature: `s^e == FDH(m) mod n`.
    pub fn verify(&self, digest: &[u8; 32], signature: &BigUint) -> bool {
        if signature >= &self.n {
            return false;
        }
        signature.modpow(&self.e, &self.n) == self.full_domain_hash(digest)
    }

    /// Samples a blinding factor `r` invertible mod `n`.
    pub fn blinding_factor<R: Rng + ?Sized>(&self, rng: &mut R) -> BigUint {
        loop {
            let r = rng.gen_biguint_below(&self.n);
            if !r.is_zero() && r.gcd(&self.n).is_one() {
                return r;
            }
        }
    }

    /// `FDH(m) * r^e mod n` — what the wallet sends to the issuer.
    pub fn blind(&self, digest: &[u8; 32], r: &BigUint) -> BigUint {
        let masked = r.modpow(&self.e, &self.n);
        (self.full_domain_hash(digest) * masked).mod_floor(&self.n)
    }

    /// `s' * r^-1 mod n` — turns the issuer's answer into a usable signature.
    pub fn unblind(&self, blinded_signature: &BigUint, r: &BigUint) -> BigUint {
        let inverse = mod_inverse(r, &self.n).expect("blinding factor is invertible by construction");
        (blinded_signature * inverse).mod_floor(&self.n)
    }
}

/// Issuer signing key. Never leaves the backend.
#[derive(Clone, Debug)]
pub struct IssuerKeypair {
    pub public: IssuerPublicKey,
    d: BigUint,
}

impl IssuerKeypair {
    /// Generates a fresh RSA keypair with public exponent 65537.
    ///
    /// `bits` is the modulus size; use >= 2048 for anything but tests.
    pub fn generate<R: Rng + ?Sized>(bits: u64, rng: &mut R) -> Self {
        assert!(bits >= 512 && bits % 2 == 0, "modulus size must be even and >= 512");
        let e = BigUint::from(65537u32);
        loop {
            let p = generate_prime(bits / 2, rng);
            let q = generate_prime(bits / 2, rng);
            if p == q {
                continue;
            }
            let n = &p * &q;
            if n.bits() != bits {
                continue;
            }
            let phi = (&p - 1u32) * (&q - 1u32);
            if !phi.gcd(&e).is_one() {
                continue;
            }
            let d = mod_inverse(&e, &phi).expect("e is coprime to phi");
            return IssuerKeypair {
                public: IssuerPublicKey { n, e },
                d,
            };
        }
    }

    /// Raw signing operation on an already-blinded message. The issuer sees a
    /// uniformly random residue and learns nothing about the token inside.
    pub fn sign_blinded(&self, blinded: &BigUint) -> BigUint {
        blinded.modpow(&self.d, &self.public.n)
    }

    /// Non-blinded signing, used for issuer-side test vectors.
    pub fn sign(&self, digest: &[u8; 32]) -> BigUint {
        self.public
            .full_domain_hash(digest)
            .modpow(&self.d, &self.public.n)
    }
}

/// Extended-Euclid modular inverse.
pub fn mod_inverse(a: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let a = BigInt::from_biguint(Sign::Plus, a.clone());
    let m = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let gcd = a.extended_gcd(&m);
    if !gcd.gcd.is_one() {
        return None;
    }
    let inverse = gcd.x.mod_floor(&m);
    inverse.to_biguint()
}

fn generate_prime<R: Rng + ?Sized>(bits: u64, rng: &mut R) -> BigUint {
    loop {
        let mut candidate = rng.gen_biguint(bits);
        candidate.set_bit(bits - 1, true); // full size
        candidate.set_bit(bits - 2, true); // keeps p*q at the target width
        candidate.set_bit(0, true); // odd
        if is_probable_prime(&candidate, 40, rng) {
            return candidate;
        }
    }
}

const SMALL_PRIMES: [u32; 20] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
];

/// Miller-Rabin with `rounds` random bases, after trial division.
pub fn is_probable_prime<R: Rng + ?Sized>(n: &BigUint, rounds: u32, rng: &mut R) -> bool {
    let two = BigUint::from(2u32);
    if n < &two {
        return false;
    }
    if n == &two {
        return true;
    }
    if n.is_even() {
        return false;
    }
    for small in SMALL_PRIMES {
        let small = BigUint::from(small);
        if n == &small {
            return true;
        }
        if n.mod_floor(&small).is_zero() {
            return false;
        }
    }

    let n_minus_one = n - 1u32;
    let shift = n_minus_one.trailing_zeros().unwrap_or(0);
    let odd_part = &n_minus_one >> shift;

    'outer: for _ in 0..rounds {
        let base = rng.gen_biguint_range(&two, &n_minus_one);
        let mut x = base.modpow(&odd_part, n);
        if x.is_one() || x == n_minus_one {
            continue;
        }
        for _ in 1..shift {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn keypair() -> (IssuerKeypair, StdRng) {
        let mut rng = StdRng::seed_from_u64(42);
        let keypair = IssuerKeypair::generate(512, &mut rng);
        (keypair, rng)
    }

    #[test]
    fn blind_signature_matches_direct_signature() {
        let (bank, mut rng) = keypair();
        let digest = tagged("test", &[b"token"]);
        let r = bank.public.blinding_factor(&mut rng);
        let blinded = bank.public.blind(&digest, &r);
        let blinded_signature = bank.sign_blinded(&blinded);
        let signature = bank.public.unblind(&blinded_signature, &r);
        assert!(bank.public.verify(&digest, &signature));
        assert_eq!(signature, bank.sign(&digest));
    }

    #[test]
    fn signature_does_not_verify_for_other_message() {
        let (bank, mut rng) = keypair();
        let digest = tagged("test", &[b"token-a"]);
        let other = tagged("test", &[b"token-b"]);
        let r = bank.public.blinding_factor(&mut rng);
        let signature = bank
            .public
            .unblind(&bank.sign_blinded(&bank.public.blind(&digest, &r)), &r);
        assert!(!bank.public.verify(&other, &signature));
    }

    #[test]
    fn miller_rabin_agrees_with_known_values() {
        let mut rng = StdRng::seed_from_u64(1);
        assert!(is_probable_prime(&BigUint::from(2_147_483_647u32), 20, &mut rng)); // 2^31-1
        assert!(!is_probable_prime(&BigUint::from(2_147_483_649u32), 20, &mut rng));
    }
}
