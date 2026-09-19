//! The Eurosystem-side backend: funds tokens under cut-and-choose, settles
//! deposits, and runs the double-spend solver.

use crate::blind_sig::{IssuerKeypair, IssuerPublicKey};
use crate::error::{Error, Result};
use crate::identity::WalletId;
use crate::token::{recover_identity, Receipt, Serial, SpendProof};
use crate::wallet::{CutChallenge, Opening, WithdrawalRequest};
use num_bigint::BigUint;
use rand::Rng;
use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Account {
    balance_cents: u64,
    suspended: bool,
}

#[derive(Clone, Debug)]
struct LedgerEntry {
    proof: SpendProof,
    merchant_id: [u8; 8],
    amount_cents: u64,
}

/// What the backend concluded about one deposited receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// First sighting of this serial: merchant credited.
    Credited { amount_cents: u64 },
    /// Same serial, same challenge, same answer — the merchant deposited twice.
    /// Paid once, no fraud, no identity revealed.
    DuplicateDeposit,
    /// Same serial, two different challenges: the token was spent twice and the
    /// payer's identity falls out of the algebra.
    DoubleSpend(Box<FraudReport>),
    /// The receipt did not verify at all.
    Rejected(Error),
}

/// Evidence assembled from two conflicting spends of one token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FraudReport {
    pub serial: Serial,
    pub amount_cents: u64,
    pub first_merchant: [u8; 8],
    pub second_merchant: [u8; 8],
    /// `Ok` with the recovered identity, or `Err` if the slopes were not a
    /// well-formed identity (a tampered wallet answering with noise).
    pub culprit: Result<WalletId>,
    /// Whether the recovered identity matches a registered account.
    pub account_known: bool,
}

pub struct Issuer {
    keypair: IssuerKeypair,
    accounts: HashMap<WalletId, Account>,
    ledger: HashMap<Serial, LedgerEntry>,
    outstanding_cents: u64,
}

impl Issuer {
    pub fn new(keypair: IssuerKeypair) -> Self {
        Issuer {
            keypair,
            accounts: HashMap::new(),
            ledger: HashMap::new(),
            outstanding_cents: 0,
        }
    }

    pub fn public_key(&self) -> IssuerPublicKey {
        self.keypair.public.clone()
    }

    pub fn open_account(&mut self, identity: WalletId, balance_cents: u64) {
        self.accounts.insert(
            identity,
            Account {
                balance_cents,
                suspended: false,
            },
        );
    }

    pub fn balance_of(&self, identity: &WalletId) -> Option<u64> {
        self.accounts.get(identity).map(|a| a.balance_cents)
    }

    pub fn is_suspended(&self, identity: &WalletId) -> bool {
        self.accounts
            .get(identity)
            .map(|a| a.suspended)
            .unwrap_or(false)
    }

    /// Face value of issued tokens not yet redeemed.
    pub fn outstanding_cents(&self) -> u64 {
        self.outstanding_cents
    }

    /// Picks which candidate survives the cut. Every other candidate must be
    /// opened, so a wallet that embedded a forged identity in `k` of `n`
    /// candidates escapes with probability `1/n` at best.
    pub fn cut<R: Rng + ?Sized>(
        &self,
        request: &WithdrawalRequest,
        rng: &mut R,
    ) -> Result<CutChallenge> {
        let account = self
            .accounts
            .get(&request.account)
            .ok_or(Error::UnknownAccount(request.account))?;
        if account.suspended {
            return Err(Error::UnknownAccount(request.account));
        }
        if request.candidates.len() < 2 {
            return Err(Error::BadParameters(
                "cut-and-choose needs at least 2 candidates",
            ));
        }
        if account.balance_cents < request.amount_cents {
            return Err(Error::InsufficientFunds {
                requested: request.amount_cents,
                available: account.balance_cents,
            });
        }
        Ok(CutChallenge {
            keep: rng.gen_range(0..request.candidates.len()),
        })
    }

    /// Verifies every opened candidate, debits the online account, and blindly
    /// signs the surviving candidate.
    pub fn issue(
        &mut self,
        request: &WithdrawalRequest,
        cut: &CutChallenge,
        opening: &Opening,
    ) -> Result<BigUint> {
        let total = request.candidates.len();
        if cut.keep >= total || opening.openings.len() + 1 != total {
            return Err(Error::BadOpening);
        }

        let mut seen = vec![false; total];
        for (index, revealed) in opening.openings.iter() {
            let index = *index;
            if index >= total || index == cut.keep || seen[index] {
                return Err(Error::BadOpening);
            }
            seen[index] = true;

            // The commitment must bind the revealed lines and the payload.
            if revealed.lines.commitment() != revealed.payload.commitment
                || revealed.payload.commitment != request.candidates[index].commitment
            {
                return Err(Error::CommitmentMismatch { index });
            }
            // The payload must be worth what was asked for.
            if revealed.payload.amount_cents != request.amount_cents
                || revealed.payload.expiry_epoch != request.expiry_epoch
            {
                return Err(Error::CommitmentMismatch { index });
            }
            // The slopes must carry the account holder's true identity.
            match revealed.lines.embedded_identity() {
                Ok(identity) if identity == request.account => {}
                _ => return Err(Error::IdentityNotEmbedded { index }),
            }
            // And the blinded message must really be that payload.
            let expected = self
                .keypair
                .public
                .blind(&revealed.payload.digest(), &revealed.blinding_factor);
            if expected != request.candidates[index].blinded_message {
                return Err(Error::BlindingMismatch { index });
            }
        }

        let account = self
            .accounts
            .get_mut(&request.account)
            .ok_or(Error::UnknownAccount(request.account))?;
        if account.balance_cents < request.amount_cents {
            return Err(Error::InsufficientFunds {
                requested: request.amount_cents,
                available: account.balance_cents,
            });
        }
        account.balance_cents -= request.amount_cents;
        self.outstanding_cents += request.amount_cents;

        // The issuer signs a value it cannot read: it knows the token is
        // well-formed, not which token it is.
        Ok(self
            .keypair
            .sign_blinded(&request.candidates[cut.keep].blinded_message))
    }

    /// Settles one deposited receipt.
    pub fn redeem(&mut self, receipt: &Receipt) -> Settlement {
        if !self
            .keypair
            .public
            .verify(&receipt.token.payload.digest(), &receipt.token.signature)
        {
            return Settlement::Rejected(Error::InvalidTokenSignature);
        }
        if receipt.proof.challenge.is_zero() {
            return Settlement::Rejected(Error::DegenerateChallenge);
        }

        let serial = receipt.token.payload.serial;
        let amount_cents = receipt.token.payload.amount_cents;

        let previous = match self.ledger.get(&serial) {
            None => {
                self.ledger.insert(
                    serial,
                    LedgerEntry {
                        proof: receipt.proof.clone(),
                        merchant_id: receipt.merchant_id,
                        amount_cents,
                    },
                );
                self.outstanding_cents = self.outstanding_cents.saturating_sub(amount_cents);
                return Settlement::Credited { amount_cents };
            }
            Some(entry) => entry.clone(),
        };

        if previous.proof.challenge == receipt.proof.challenge {
            return if previous.proof.response == receipt.proof.response {
                Settlement::DuplicateDeposit
            } else {
                // Same abscissa, different ordinate: the two points are not on
                // any single line, so this is a forged response rather than a
                // double-spend. No identity can be extracted.
                Settlement::Rejected(Error::ChallengeMismatch)
            };
        }

        // Two points, two different abscissae — solve for the slope.
        let culprit = recover_identity(&previous.proof, &receipt.proof)
            .expect("challenges differ, so the inverse exists");
        let account_known =
            matches!(&culprit, Ok(identity) if self.accounts.contains_key(identity));
        if let Ok(identity) = &culprit {
            if let Some(account) = self.accounts.get_mut(identity) {
                account.suspended = true;
                // Claw back the duplicated value from the online balance.
                account.balance_cents = account.balance_cents.saturating_sub(amount_cents);
            }
        }

        Settlement::DoubleSpend(Box::new(FraudReport {
            serial,
            amount_cents: previous.amount_cents,
            first_merchant: previous.merchant_id,
            second_merchant: receipt.merchant_id,
            culprit,
            account_known,
        }))
    }
}
