//! Device certificates: the Eurosystem's statement that a public key belongs
//! to a genuine secure element, and what that element may hold.
//!
//! Offline payments only move between certified devices. A payer's element
//! checks the payee's certificate before debiting, and a payee's element
//! checks the payer's before crediting, so value never enters or leaves the
//! offline circuit through a device the issuer has not vouched for.

use crate::hash::tagged;
use crate::id::DeviceId;
use crate::signature::PublicKey;
use num_bigint::BigUint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    pub device: DeviceId,
    pub public_key: PublicKey,
    /// Most value the device may hold offline. A parameter of the model,
    /// set per device by the issuer; not a figure published by the ECB.
    pub holding_limit_cents: u64,
    /// The issuer's signature over the fields above.
    pub signature: BigUint,
}

impl DeviceCertificate {
    /// What the issuer signs. The owning account is deliberately left out:
    /// the certificate travels with every payment, and the counterparty has
    /// no business learning whose device it is.
    pub fn digest(&self) -> [u8; 32] {
        tagged(
            "euro/device-certificate",
            &[
                &self.device.0,
                &self.public_key.n.to_bytes_be(),
                &self.public_key.e.to_bytes_be(),
                &self.holding_limit_cents.to_be_bytes(),
            ],
        )
    }

    pub fn verify(&self, issuer: &PublicKey) -> bool {
        issuer.verify(&self.digest(), &self.signature)
    }
}
