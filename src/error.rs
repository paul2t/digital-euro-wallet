//! Protocol errors.

use crate::id::{AccountId, DeviceId};
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A device certificate is not signed by the issuer, or does not match
    /// the key it is presented with.
    InvalidCertificate,
    /// A message is not signed by the key it claims.
    InvalidSignature,
    /// A transfer or funding addressed to another device.
    NotForThisDevice,
    /// Payer and payee are the same device.
    SelfPayment,
    /// Zero-value payment, funding, or defunding.
    ZeroAmount,
    /// Not enough value to cover a debit.
    InsufficientFunds {
        requested: u64,
        available: u64,
    },
    /// Crediting this much would take the device over its holding limit.
    HoldingLimitExceeded {
        requested: u64,
        headroom: u64,
    },
    /// A transfer or funding answers no request this device has open.
    UnknownRequest,
    /// A transfer or funding that has already been credited.
    AlreadyCredited,
    /// The amount credited does not match the amount requested.
    AmountMismatch {
        expected: u64,
        found: u64,
    },
    /// A defunding counter or funding nonce the issuer has already seen.
    Replay,
    UnknownAccount(AccountId),
    UnknownDevice(DeviceId),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidCertificate => {
                write!(f, "device certificate not issued by the Eurosystem")
            }
            Error::InvalidSignature => write!(f, "signature does not verify"),
            Error::NotForThisDevice => write!(f, "message is addressed to another device"),
            Error::SelfPayment => write!(f, "a device cannot pay itself"),
            Error::ZeroAmount => write!(f, "amount must be non-zero"),
            Error::InsufficientFunds {
                requested,
                available,
            } => write!(
                f,
                "insufficient funds: need {requested} cents, have {available}"
            ),
            Error::HoldingLimitExceeded {
                requested,
                headroom,
            } => write!(
                f,
                "holding limit: {requested} cents requested, only {headroom} of room left"
            ),
            Error::UnknownRequest => write!(f, "no open request matches this message"),
            Error::AlreadyCredited => write!(f, "already credited"),
            Error::AmountMismatch { expected, found } => {
                write!(
                    f,
                    "amount mismatch: requested {expected} cents, got {found}"
                )
            }
            Error::Replay => write!(f, "message already processed"),
            Error::UnknownAccount(id) => write!(f, "unknown account {}", id.short()),
            Error::UnknownDevice(id) => write!(f, "unknown device {}", id.short()),
        }
    }
}

impl std::error::Error for Error {}
