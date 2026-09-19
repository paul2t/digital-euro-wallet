//! Messages exchanged between devices (offline) and between a device and the
//! issuer (online, for funding and defunding).
//!
//! The ECB has not published a wire protocol for offline payments; these
//! messages are this model's own. What they are built to respect is what the
//! ECB has said: value moves between certified devices, settles locally, and
//! is re-spendable at once.
//!
//! ```text
//!   offline payment                      funding / defunding (online)
//!   ───────────────                      ────────────────────────────
//!   payee ──PaymentRequest──► payer      device ──FundingRequest──► issuer
//!   payee ◄────Transfer────── payer      device ◄─────Funding────── issuer
//!                                        device ──────Defunding───► issuer
//! ```

use crate::certificate::DeviceCertificate;
use crate::hash::tagged;
use crate::id::DeviceId;
use num_bigint::BigUint;

/// Payee → payer. Issued only once the payee's element has reserved room for
/// the amount under its holding limit, so the credit cannot fail later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    pub payee: DeviceCertificate,
    pub amount_cents: u64,
    /// Fresh per request. The payee credits each nonce at most once, which is
    /// what makes a replayed transfer worthless.
    pub nonce: [u8; 16],
}

/// Payer → payee. The payer's element has already debited itself when it
/// produces this; the payee's element credits on receipt. Settlement is final
/// at that point, and nothing is reported to anyone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub payer: DeviceCertificate,
    pub payee: DeviceId,
    pub amount_cents: u64,
    pub nonce: [u8; 16],
    /// The payer element's monotonic counter at the time of the debit.
    pub counter: u64,
    /// Signed by the payer's device key.
    pub signature: BigUint,
}

impl Transfer {
    pub fn digest(&self) -> [u8; 32] {
        tagged(
            "euro/transfer",
            &[
                &self.payer.device.0,
                &self.payee.0,
                &self.amount_cents.to_be_bytes(),
                &self.nonce,
                &self.counter.to_be_bytes(),
            ],
        )
    }
}

/// Device → issuer: "move this much from my account onto me". Issued only once
/// the element has reserved room for it under the holding limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingRequest {
    pub device: DeviceId,
    pub amount_cents: u64,
    pub nonce: [u8; 16],
    /// Signed by the device key, so the issuer knows the request came from
    /// the element that holds the reservation.
    pub signature: BigUint,
}

impl FundingRequest {
    pub fn digest(&self) -> [u8; 32] {
        tagged(
            "euro/funding-request",
            &[
                &self.device.0,
                &self.amount_cents.to_be_bytes(),
                &self.nonce,
            ],
        )
    }
}

/// Issuer → device: the account has been debited; credit the element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Funding {
    pub device: DeviceId,
    pub amount_cents: u64,
    pub nonce: [u8; 16],
    /// Signed by the issuer.
    pub signature: BigUint,
}

impl Funding {
    pub fn digest(&self) -> [u8; 32] {
        tagged(
            "euro/funding",
            &[
                &self.device.0,
                &self.amount_cents.to_be_bytes(),
                &self.nonce,
            ],
        )
    }
}

/// Device → issuer: the element has debited itself; credit the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Defunding {
    pub device: DeviceId,
    pub amount_cents: u64,
    /// Must exceed every counter the issuer has seen from this device, so a
    /// defunding message cannot be cashed twice.
    pub counter: u64,
    /// Signed by the device key.
    pub signature: BigUint,
}

impl Defunding {
    pub fn digest(&self) -> [u8; 32] {
        tagged(
            "euro/defunding",
            &[
                &self.device.0,
                &self.amount_cents.to_be_bytes(),
                &self.counter.to_be_bytes(),
            ],
        )
    }
}
