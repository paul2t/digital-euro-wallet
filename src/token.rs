//! Token data structures and the double-spend solver.
//!
//! A token is a bearer instrument: a bank-signed payload plus a secret set of
//! lines held inside the secure element. Spending it means answering one
//! challenge point per line. Answering two different challenges with the same
//! token hands the backend two points per line, which is exactly one point too
//! many for the identity to stay hidden.

use crate::error::{Error, Result};
use crate::field::Fp;
use crate::hash::tagged;
use crate::identity::{WalletId, LIMBS};
use num_bigint::BigUint;

/// Unique per-token serial, chosen by the wallet and hidden from the issuer by
/// the blind signature.
pub type Serial = [u8; 16];

/// The part of a token the issuer signs (blindly) and merchants verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPayload {
    pub serial: Serial,
    pub amount_cents: u64,
    pub expiry_epoch: u64,
    /// Binding commitment to the secret lines inside the secure element.
    pub commitment: [u8; 32],
}

impl TokenPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 16 + 8 + 8 + 32);
        out.push(1u8); // format version
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&self.amount_cents.to_be_bytes());
        out.extend_from_slice(&self.expiry_epoch.to_be_bytes());
        out.extend_from_slice(&self.commitment);
        out
    }

    /// The message the blind signature actually covers.
    pub fn digest(&self) -> [u8; 32] {
        tagged("euro/token", &[&self.encode()])
    }
}

/// A funded, issuer-certified offline token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub payload: TokenPayload,
    pub signature: BigUint,
}

/// The secret held by the secure element: one line `f_j(x) = I_j * x + s_j`
/// per identity limb.
///
/// A single evaluation of each line reveals nothing about `I_j`: for any
/// candidate slope there is exactly one intercept passing through the observed
/// point, so the payment is information-theoretically anonymous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretLines {
    /// `(slope I_j, intercept s_j)` for each limb.
    pub coefficients: [(Fp, Fp); LIMBS],
    /// Commitment randomness, so the commitment hides the intercepts.
    pub nonce: [u8; 32],
}

impl SecretLines {
    /// Binds the lines to the token payload. Opened during cut-and-choose,
    /// opaque afterwards.
    pub fn commitment(&self) -> [u8; 32] {
        let mut buffer = Vec::with_capacity(LIMBS * 16 + 32);
        for (slope, intercept) in self.coefficients.iter() {
            buffer.extend_from_slice(&slope.to_bytes());
            buffer.extend_from_slice(&intercept.to_bytes());
        }
        tagged("euro/lines", &[&buffer, &self.nonce])
    }

    /// Evaluates every line at the merchant's challenge.
    pub fn respond(&self, challenge: Fp) -> [Fp; LIMBS] {
        let mut response = [Fp::ZERO; LIMBS];
        for (out, (slope, intercept)) in response.iter_mut().zip(self.coefficients.iter()) {
            *out = slope.mul(challenge).add(*intercept);
        }
        response
    }

    /// The identity embedded in the slopes.
    pub fn embedded_identity(&self) -> Result<WalletId> {
        let mut slopes = [Fp::ZERO; LIMBS];
        for (out, (slope, _)) in slopes.iter_mut().zip(self.coefficients.iter()) {
            *out = *slope;
        }
        WalletId::from_limbs(&slopes)
    }
}

/// What the payer hands the merchant alongside the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendProof {
    pub challenge: Fp,
    pub response: [Fp; LIMBS],
}

/// A merchant's record of an accepted offline payment, deposited later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub token: Token,
    pub proof: SpendProof,
    pub merchant_id: [u8; 8],
    pub timestamp: u64,
}

/// Solves for the payer's identity from two spends of the same token.
///
/// ```text
/// y1_j = I_j * x1 + s_j
/// y2_j = I_j * x2 + s_j
/// I_j  = (y1_j - y2_j) * (x1 - x2)^-1
/// ```
///
/// Returns `None` when the two challenges are equal (same merchant, same
/// transaction data) — that is a replay, not a double-spend, and no identity
/// can or should be extracted from it.
pub fn recover_identity(first: &SpendProof, second: &SpendProof) -> Option<Result<WalletId>> {
    let delta_x = first.challenge.sub(second.challenge);
    let inverse = delta_x.inv()?; // None iff x1 == x2
    let mut slopes = [Fp::ZERO; LIMBS];
    for (j, slope) in slopes.iter_mut().enumerate() {
        *slope = first.response[j].sub(second.response[j]).mul(inverse);
    }
    Some(WalletId::from_limbs(&slopes))
}

/// Recomputes a merchant challenge from the transaction data, so that both
/// sides derive the same `x` and neither can steer it.
pub fn derive_challenge(
    merchant_id: &[u8; 8],
    timestamp: u64,
    amount_cents: u64,
    nonce: &[u8; 16],
) -> Result<Fp> {
    let digest = tagged(
        "euro/challenge",
        &[
            merchant_id,
            &timestamp.to_be_bytes(),
            &amount_cents.to_be_bytes(),
            nonce,
        ],
    );
    let mut wide = [0u8; 16];
    wide.copy_from_slice(&digest[..16]);
    let challenge = Fp::from_u128(u128::from_be_bytes(wide));
    if challenge.is_zero() {
        // `f(0) = s` would reveal only the blinding factor, never the identity.
        return Err(Error::DegenerateChallenge);
    }
    Ok(challenge)
}
