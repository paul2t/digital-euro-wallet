//! # Offline digital euro wallet
//!
//! A working Rust model of the Chaum-Fiat-Naor style offline e-cash scheme
//! discussed for the digital euro: payments that are anonymous like cash, but
//! where spending the same token twice mathematically discloses the payer's
//! device identity.
//!
//! ## The shape of the protocol
//!
//! ```text
//!   online funding        offline payment            settlement
//!   ──────────────        ───────────────            ──────────
//!   wallet ──n candidates──► issuer
//!   wallet ◄──── cut ────── issuer      merchant ──x──► wallet
//!   wallet ──n-1 openings──► issuer     merchant ◄(x,y)─ wallet
//!   wallet ◄─blind signature─ issuer    merchant ──receipt──► issuer
//! ```
//!
//! 1. **Funding.** The wallet builds `n` candidate tokens. Each embeds the
//!    wallet identity `I`, split into 52-bit limbs, as the *slopes* of `n`
//!    lines `f_j(x) = I_j·x + s_j (mod p)`, with fresh random intercepts
//!    `s_j`. The issuer opens `n-1` of them, checks that the real identity is
//!    embedded, and blindly signs the one left ([`issuer::Issuer::issue`]).
//!    Cheating survives the cut with probability `1/n`.
//!
//! 2. **Payment.** The merchant derives a challenge `x` from the transaction
//!    data ([`token::derive_challenge`]) and the wallet answers with one point
//!    `y_j = f_j(x)` per line. One point per line is perfect secrecy: every
//!    slope remains equally possible.
//!
//! 3. **Settlement.** If the same serial arrives twice with different
//!    challenges, the backend holds two points per line and solves
//!    `I_j = (y1_j − y2_j)·(x1 − x2)^{-1}`, reassembling `I`
//!    ([`token::recover_identity`]).
//!
//! ## What this models, and what it does not
//!
//! Modelled: the secret-sharing trap, blind issuance, cut-and-choose,
//! challenge derivation, ledger settlement, and a secure element that can be
//! "cracked" to replay a token.
//!
//! Not modelled: secure-element attestation and key storage, transport
//! security between devices, token denominations and change, offline holding
//! limits, expiry-driven re-anchoring, revocation, and everything about the
//! legal framework. The cryptography here is written for clarity, not for
//! production: no constant-time discipline, no reviewed padding scheme, no
//! HSM. Do not put money behind it.
//!
//! ## Example
//!
//! See `examples/offline_payment.rs` for an end-to-end run, including a
//! double-spend that unmasks the payer.

pub mod blind_sig;
pub mod error;
pub mod field;
pub mod hash;
pub mod identity;
pub mod issuer;
pub mod merchant;
pub mod token;
pub mod wallet;

pub use error::{Error, Result};
pub use field::Fp;
pub use identity::WalletId;
pub use issuer::{FraudReport, Issuer, Settlement};
pub use merchant::{Merchant, PaymentRequest};
pub use token::{recover_identity, Receipt, SecretLines, SpendProof, Token, TokenPayload};
pub use wallet::{ElementState, Wallet, WithdrawalRequest};

use rand::Rng;

/// Convenience helper: runs the three-move withdrawal protocol between a
/// wallet and an issuer.
pub fn withdraw<WR: Rng, IR: Rng + ?Sized>(
    wallet: &mut Wallet<WR>,
    issuer: &mut Issuer,
    amount_cents: u64,
    expiry_epoch: u64,
    candidate_count: usize,
    issuer_rng: &mut IR,
) -> Result<Token> {
    let (request, session) = wallet.begin_withdrawal(amount_cents, expiry_epoch, candidate_count)?;
    let cut = issuer.cut(&request, issuer_rng)?;
    let opening = wallet.answer_cut(&session, &cut)?;
    let blinded_signature = issuer.issue(&request, &cut, &opening)?;
    wallet.finish_withdrawal(session, &cut, &blinded_signature)
}
