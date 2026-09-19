//! The payee side: an offline terminal that challenges the payer and banks the
//! receipt whenever it next reaches the network.

use crate::blind_sig::IssuerPublicKey;
use crate::error::{Error, Result};
use crate::field::Fp;
use crate::token::{derive_challenge, Receipt, SpendProof, Token};
use rand::Rng;

/// The challenge a terminal issues for one sale.
///
/// `challenge` is derived from the transaction data, so the merchant cannot
/// quietly reuse a previous `x` — reusing one would keep a double-spender
/// anonymous, since two points on the same abscissa do not determine a line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    pub amount_cents: u64,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub challenge: Fp,
}

pub struct Merchant<R: Rng> {
    id: [u8; 8],
    issuer: IssuerPublicKey,
    rng: R,
    pending_deposits: Vec<Receipt>,
}

impl<R: Rng> Merchant<R> {
    pub fn new(id: [u8; 8], issuer: IssuerPublicKey, rng: R) -> Self {
        Merchant {
            id,
            issuer,
            rng,
            pending_deposits: Vec::new(),
        }
    }

    pub fn id(&self) -> [u8; 8] {
        self.id
    }

    /// Generates a fresh challenge for a sale.
    pub fn request_payment(&mut self, amount_cents: u64, timestamp: u64) -> Result<PaymentRequest> {
        loop {
            let nonce: [u8; 16] = self.rng.gen();
            match derive_challenge(&self.id, timestamp, amount_cents, &nonce) {
                Ok(challenge) => {
                    return Ok(PaymentRequest {
                        amount_cents,
                        timestamp,
                        nonce,
                        challenge,
                    })
                }
                // Astronomically unlikely; just draw another nonce.
                Err(Error::DegenerateChallenge) => continue,
                Err(other) => return Err(other),
            }
        }
    }

    /// Validates an offline payment.
    ///
    /// The terminal can check everything except whether the payer answered
    /// honestly — that is the part only the backend can settle, and only after
    /// the fact. Accepting here is a (bounded) risk decision, same as taking a
    /// banknote.
    pub fn accept(
        &mut self,
        request: &PaymentRequest,
        token: Token,
        proof: SpendProof,
        now_epoch: u64,
    ) -> Result<Receipt> {
        if !self.issuer.verify(&token.payload.digest(), &token.signature) {
            return Err(Error::InvalidTokenSignature);
        }
        if token.payload.amount_cents != request.amount_cents {
            return Err(Error::AmountMismatch {
                expected: request.amount_cents,
                found: token.payload.amount_cents,
            });
        }
        if token.payload.expiry_epoch < now_epoch {
            return Err(Error::Expired {
                expiry: token.payload.expiry_epoch,
                now: now_epoch,
            });
        }
        let expected = derive_challenge(
            &self.id,
            request.timestamp,
            request.amount_cents,
            &request.nonce,
        )?;
        if proof.challenge != expected || proof.challenge != request.challenge {
            return Err(Error::ChallengeMismatch);
        }

        let receipt = Receipt {
            token,
            proof,
            merchant_id: self.id,
            timestamp: request.timestamp,
        };
        self.pending_deposits.push(receipt.clone());
        Ok(receipt)
    }

    /// Receipts not yet deposited.
    pub fn pending(&self) -> &[Receipt] {
        &self.pending_deposits
    }

    /// Hands over the collected receipts for settlement once back online.
    pub fn drain_deposits(&mut self) -> Vec<Receipt> {
        std::mem::take(&mut self.pending_deposits)
    }
}
