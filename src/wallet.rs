//! The payer side: a secure element holding tokens and the lines that bind
//! them to the holder's identity.

use crate::blind_sig::IssuerPublicKey;
use crate::error::{Error, Result};
use crate::field::Fp;
use crate::identity::{WalletId, LIMBS};
use crate::token::{SecretLines, Serial, SpendProof, Token, TokenPayload};
use num_bigint::BigUint;
use rand::Rng;
use std::collections::BTreeMap;

/// Whether the secure element still enforces its spend-once rule.
///
/// `Cracked` models the threat the whole scheme is built around: an attacker
/// who rolls back the element's state and replays a token. The protocol does
/// not prevent this offline; it makes it self-incriminating once the merchants
/// come back online.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElementState {
    Sealed,
    Cracked,
}

#[derive(Clone, Debug)]
struct StoredToken {
    token: Token,
    lines: SecretLines,
    spent_with: Option<SpendProof>,
}

/// One candidate offered to the issuer during cut-and-choose.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub commitment: [u8; 32],
    pub blinded_message: BigUint,
}

/// What the wallet sends to open a candidate the issuer asked to inspect.
#[derive(Clone, Debug)]
pub struct CandidateOpening {
    pub payload: TokenPayload,
    pub lines: SecretLines,
    pub blinding_factor: BigUint,
}

/// A withdrawal request: `candidates.len()` structurally identical tokens, of
/// which all but one will be torn open by the issuer.
#[derive(Clone, Debug)]
pub struct WithdrawalRequest {
    pub account: WalletId,
    pub amount_cents: u64,
    pub expiry_epoch: u64,
    pub candidates: Vec<Candidate>,
}

/// The issuer's cut: every index except `keep` must be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutChallenge {
    pub keep: usize,
}

/// The wallet's answer to the cut.
#[derive(Clone, Debug)]
pub struct Opening {
    pub openings: Vec<(usize, CandidateOpening)>,
}

/// Wallet-side state for an in-flight withdrawal. Consumed by
/// [`Wallet::finish_withdrawal`].
#[derive(Clone, Debug)]
pub struct WithdrawalSession {
    secrets: Vec<CandidateOpening>,
}

/// An offline wallet backed by a (possibly compromised) secure element.
pub struct Wallet<R: Rng> {
    identity: WalletId,
    issuer: IssuerPublicKey,
    tokens: BTreeMap<Serial, StoredToken>,
    state: ElementState,
    rng: R,
}

impl<R: Rng> Wallet<R> {
    pub fn new(identity: WalletId, issuer: IssuerPublicKey, rng: R) -> Self {
        Wallet {
            identity,
            issuer,
            tokens: BTreeMap::new(),
            state: ElementState::Sealed,
            rng,
        }
    }

    pub fn identity(&self) -> WalletId {
        self.identity
    }

    pub fn state(&self) -> ElementState {
        self.state
    }

    /// Simulates a hardware attack that rolls back the anti-replay counter.
    pub fn crack_secure_element(&mut self) {
        self.state = ElementState::Cracked;
    }

    /// Serials currently held, spent or not.
    pub fn serials(&self) -> Vec<Serial> {
        self.tokens.keys().copied().collect()
    }

    /// Face value of the tokens the element still considers unspent.
    pub fn offline_balance(&self) -> u64 {
        self.tokens
            .values()
            .filter(|stored| stored.spent_with.is_none())
            .map(|stored| stored.token.payload.amount_cents)
            .sum()
    }

    /// Step 1 of a withdrawal: build `candidate_count` independent candidate
    /// tokens, each embedding the *real* identity in its slopes, and blind
    /// them all.
    pub fn begin_withdrawal(
        &mut self,
        amount_cents: u64,
        expiry_epoch: u64,
        candidate_count: usize,
    ) -> Result<(WithdrawalRequest, WithdrawalSession)> {
        if candidate_count < 2 {
            return Err(Error::BadParameters(
                "cut-and-choose needs at least 2 candidates",
            ));
        }

        let limbs = self.identity.to_limbs();
        let mut candidates = Vec::with_capacity(candidate_count);
        let mut secrets = Vec::with_capacity(candidate_count);

        for _ in 0..candidate_count {
            let mut coefficients = [(Fp::ZERO, Fp::ZERO); LIMBS];
            for (slot, slope) in coefficients.iter_mut().zip(limbs.iter()) {
                // Fresh intercept per line per candidate: reusing one across
                // tokens would let two different tokens be combined.
                *slot = (*slope, Fp::random(&mut self.rng));
            }
            let lines = SecretLines {
                coefficients,
                nonce: self.rng.gen(),
            };
            let payload = TokenPayload {
                serial: self.rng.gen(),
                amount_cents,
                expiry_epoch,
                commitment: lines.commitment(),
            };
            let blinding_factor = self.issuer.blinding_factor(&mut self.rng);
            let blinded_message = self.issuer.blind(&payload.digest(), &blinding_factor);

            candidates.push(Candidate {
                commitment: payload.commitment,
                blinded_message,
            });
            secrets.push(CandidateOpening {
                payload,
                lines,
                blinding_factor,
            });
        }

        Ok((
            WithdrawalRequest {
                account: self.identity,
                amount_cents,
                expiry_epoch,
                candidates,
            },
            WithdrawalSession { secrets },
        ))
    }

    /// Step 2: open every candidate except the one the issuer kept.
    pub fn answer_cut(&self, session: &WithdrawalSession, cut: &CutChallenge) -> Result<Opening> {
        if cut.keep >= session.secrets.len() {
            return Err(Error::BadOpening);
        }
        let openings = session
            .secrets
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != cut.keep)
            .map(|(index, secret)| (index, secret.clone()))
            .collect();
        Ok(Opening { openings })
    }

    /// Step 3: unblind the issuer's signature and store the finished token.
    pub fn finish_withdrawal(
        &mut self,
        session: WithdrawalSession,
        cut: &CutChallenge,
        blinded_signature: &BigUint,
    ) -> Result<Token> {
        let secret = session
            .secrets
            .into_iter()
            .nth(cut.keep)
            .ok_or(Error::BadOpening)?;
        let signature = self
            .issuer
            .unblind(blinded_signature, &secret.blinding_factor);
        if !self.issuer.verify(&secret.payload.digest(), &signature) {
            return Err(Error::InvalidTokenSignature);
        }
        let token = Token {
            payload: secret.payload,
            signature,
        };
        self.tokens.insert(
            token.payload.serial,
            StoredToken {
                token: token.clone(),
                lines: secret.lines,
                spent_with: None,
            },
        );
        Ok(token)
    }

    /// Answers a merchant challenge with one point per line.
    ///
    /// A sealed element refuses a second spend. A cracked one answers again —
    /// and in doing so releases the second point that solves for its identity.
    pub fn pay(&mut self, serial: &Serial, challenge: Fp) -> Result<(Token, SpendProof)> {
        if challenge.is_zero() {
            return Err(Error::DegenerateChallenge);
        }
        let stored = self.tokens.get_mut(serial).ok_or(Error::UnknownToken)?;
        if let Some(previous) = &stored.spent_with {
            match self.state {
                ElementState::Sealed => return Err(Error::TokenAlreadySpent),
                ElementState::Cracked => {
                    // Replaying the exact same challenge is a merchant-side
                    // retry and stays anonymous; a fresh challenge is the
                    // double-spend that burns the identity.
                    let _ = previous;
                }
            }
        }
        let proof = SpendProof {
            challenge,
            response: stored.lines.respond(challenge),
        };
        stored.spent_with = Some(proof.clone());
        Ok((stored.token.clone(), proof))
    }
}
