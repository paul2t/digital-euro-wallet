//! Protocol errors.

use crate::identity::WalletId;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The bank's blind signature on the token does not verify.
    InvalidTokenSignature,
    /// The payer answered a challenge other than the one the merchant issued.
    ChallengeMismatch,
    /// A merchant tried to issue the degenerate challenge `x = 0`, which would
    /// leak nothing on a double-spend (`f(0) = s`) — refused.
    DegenerateChallenge,
    /// Token face value does not match the amount being paid.
    AmountMismatch { expected: u64, found: u64 },
    /// Token is past its expiry epoch.
    Expired { expiry: u64, now: u64 },
    /// The secure element refuses to spend a token it has already spent.
    TokenAlreadySpent,
    /// No such token in the wallet.
    UnknownToken,
    /// Cut-and-choose: an opened candidate does not match its commitment.
    CommitmentMismatch { index: usize },
    /// Cut-and-choose: an opened candidate does not embed the account's real
    /// identity, i.e. the wallet tried to hide behind a forged `I`.
    IdentityNotEmbedded { index: usize },
    /// Cut-and-choose: the blinded message does not correspond to the opened
    /// payload and blinding factor.
    BlindingMismatch { index: usize },
    /// The withdrawal opening does not cover exactly the requested indices.
    BadOpening,
    /// Recovered slopes are not a well-formed wallet identity.
    MalformedIdentity {
        limb: usize,
        value: u64,
        budget: u32,
    },
    /// Account unknown to the issuer.
    UnknownAccount(WalletId),
    /// Not enough funds on the online account to fund the requested tokens.
    InsufficientFunds { requested: u64, available: u64 },
    /// A sanity bound on the cut-and-choose parameter.
    BadParameters(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTokenSignature => write!(f, "invalid bank signature on token"),
            Error::ChallengeMismatch => write!(f, "payer answered the wrong challenge"),
            Error::DegenerateChallenge => write!(f, "challenge x = 0 is not allowed"),
            Error::AmountMismatch { expected, found } => {
                write!(
                    f,
                    "amount mismatch: expected {expected} cents, token is {found}"
                )
            }
            Error::Expired { expiry, now } => write!(f, "token expired at {expiry} (now {now})"),
            Error::TokenAlreadySpent => write!(f, "secure element refused: token already spent"),
            Error::UnknownToken => write!(f, "unknown token"),
            Error::CommitmentMismatch { index } => {
                write!(
                    f,
                    "candidate {index}: commitment does not match opened values"
                )
            }
            Error::IdentityNotEmbedded { index } => {
                write!(
                    f,
                    "candidate {index}: slopes do not encode the account identity"
                )
            }
            Error::BlindingMismatch { index } => {
                write!(
                    f,
                    "candidate {index}: blinded message inconsistent with opening"
                )
            }
            Error::BadOpening => write!(f, "opening does not match the requested indices"),
            Error::MalformedIdentity {
                limb,
                value,
                budget,
            } => write!(
                f,
                "recovered limb {limb} = {value} exceeds its {budget}-bit budget"
            ),
            Error::UnknownAccount(id) => write!(f, "unknown account {}", id.short()),
            Error::InsufficientFunds {
                requested,
                available,
            } => {
                write!(f, "insufficient funds: need {requested}, have {available}")
            }
            Error::BadParameters(message) => write!(f, "bad parameters: {message}"),
        }
    }
}

impl std::error::Error for Error {}
