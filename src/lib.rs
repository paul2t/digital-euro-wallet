//! # Offline digital euro wallet
//!
//! A Rust model of the offline digital euro as the ECB has described it:
//! value held as a balance on a secure element, moved directly between
//! certified devices, settled locally, and immediately re-spendable offline.
//!
//! ```text
//!   online                          offline, device to device
//!   ──────                          ─────────────────────────
//!   account ──funding──► device A   device B ──PaymentRequest──► device A
//!   account ◄─defunding─ device A   device B ◄──────Transfer──── device A
//! ```
//!
//! * **Funding** moves value from an online account onto a device, up to the
//!   device's holding limit. **Defunding** moves it back.
//! * **Paying** debits the payer's element and credits the payee's, for any
//!   amount up to the payer's balance. Paying 6 € from 10 € leaves 4 € that
//!   can be spent later; the payee can spend its 6 € straight away.
//! * Nothing about an offline payment is reported to the issuer or anyone
//!   else. The payee learns the payer's device pseudonym, not its account.
//!
//! ## Where the security comes from
//!
//! From the hardware. Two devices with no shared record cannot, by
//! cryptography alone, stop one of them presenting the same value twice, so
//! the design relies on the secure element refusing to. Signatures only make
//! sure value moves between genuine, certified elements. If an element is
//! cracked ([`ElementState::Cracked`]) it can pay out value it does not have,
//! and nobody offline can tell. The issuer sees the damage only in aggregate,
//! and only if enough of the created value is defunded to drive the offline
//! float negative; it never learns the source.
//!
//! ## What this models, and what it does not
//!
//! Modelled: device certification, funding and defunding, partial payments,
//! re-spending received value, holding limits, replay protection, a lost
//! device, and a cracked element.
//!
//! Not modelled: any wire protocol the ECB will actually specify (it has not
//! published one), transaction recovery after a dropped connection beyond
//! resending the same signed transfer, device revocation, secure-element
//! attestation, and the legal framework. The cryptography is written for
//! clarity, not production.

pub mod certificate;
pub mod error;
pub mod hash;
pub mod id;
pub mod issuer;
pub mod message;
pub mod signature;
pub mod wallet;

pub use certificate::DeviceCertificate;
pub use error::{Error, Result};
pub use id::{AccountId, DeviceId};
pub use issuer::Issuer;
pub use message::{Defunding, Funding, FundingRequest, PaymentRequest, Transfer};
pub use signature::{Keypair, PublicKey};
pub use wallet::{ElementState, Wallet};

use rand::Rng;

/// Gives an account a new device: generates the element's key, has the issuer
/// certify it, and installs the certificate.
pub fn enrol<R: Rng, G: Rng + ?Sized>(
    issuer: &mut Issuer,
    account: AccountId,
    holding_limit_cents: u64,
    key_bits: u64,
    device_rng: R,
    rng: &mut G,
) -> Result<Wallet<R>> {
    let keypair = Keypair::generate(key_bits, rng);
    let certificate = issuer.certify_device(account, &keypair.public, holding_limit_cents, rng)?;
    Wallet::new(certificate, keypair, issuer.public_key(), device_rng)
}

/// Moves value from the device's online account onto the device.
pub fn fund<R: Rng>(wallet: &mut Wallet<R>, issuer: &mut Issuer, amount_cents: u64) -> Result<u64> {
    let request = wallet.request_funding(amount_cents)?;
    match issuer.fund(&request) {
        Ok(funding) => wallet.apply_funding(&funding),
        Err(error) => {
            wallet.cancel_funding(&request.nonce);
            Err(error)
        }
    }
}

/// Moves value from the device back to its online account.
pub fn defund<R: Rng>(
    wallet: &mut Wallet<R>,
    issuer: &mut Issuer,
    amount_cents: u64,
) -> Result<u64> {
    let defunding = wallet.defund(amount_cents)?;
    issuer.defund(&defunding)
}

/// One offline payment, both sides: the payee requests, the payer pays, the
/// payee credits. If the payer refuses, the payee's reservation is released.
pub fn pay<P: Rng, Q: Rng>(
    payer: &mut Wallet<P>,
    payee: &mut Wallet<Q>,
    amount_cents: u64,
) -> Result<u64> {
    let request = payee.request_payment(amount_cents)?;
    let transfer = match payer.pay(&request) {
        Ok(transfer) => transfer,
        Err(error) => {
            payee.cancel_request(&request.nonce);
            return Err(error);
        }
    };
    payee.receive(&transfer)
}
