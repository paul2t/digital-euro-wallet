//! The offline applet on a secure element: a balance it debits and credits,
//! a device key, and the Eurosystem's certificate for that key.
//!
//! Every device is both payer and payee. Value received is spendable at once,
//! offline, and in any amount up to the balance, so paying 6 € out of 10 €
//! simply leaves 4 € on the element.
//!
//! Two rules keep value from being stranded between devices:
//!
//! * The payer's element runs every check that could make it refuse *before*
//!   it debits itself. A payment it will not complete costs nothing.
//! * The payee's element reserves room under its holding limit when it issues
//!   the request, not when the transfer arrives. By the time the payer has
//!   debited, the credit cannot fail.

use crate::certificate::DeviceCertificate;
use crate::error::{Error, Result};
use crate::id::DeviceId;
use crate::message::{Defunding, Funding, FundingRequest, PaymentRequest, Transfer};
use crate::signature::{Keypair, PublicKey};
use rand::Rng;
use std::collections::{HashMap, HashSet};

/// Whether the element still enforces its own rules.
///
/// The ECB design rests double-spending protection on tamper-resistant
/// hardware. `Cracked` models that protection failing: the attacker rolls the
/// balance back after every debit, so the element keeps paying out value it
/// no longer has. Counterparties cannot tell — the signatures are genuine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElementState {
    Sealed,
    Cracked,
}

pub struct Wallet<R: Rng> {
    certificate: DeviceCertificate,
    keypair: Keypair,
    issuer: PublicKey,
    balance_cents: u64,
    /// Room reserved for payment requests not yet paid, by nonce.
    incoming: HashMap<[u8; 16], u64>,
    /// Room reserved for funding requests not yet answered, by nonce.
    pending_funding: HashMap<[u8; 16], u64>,
    /// Nonces already credited, so a replayed message credits nothing.
    credited: HashSet<[u8; 16]>,
    counter: u64,
    state: ElementState,
    rng: R,
}

impl<R: Rng> Wallet<R> {
    /// Installs a certified key on a fresh element.
    pub fn new(
        certificate: DeviceCertificate,
        keypair: Keypair,
        issuer: PublicKey,
        rng: R,
    ) -> Result<Self> {
        if !certificate.verify(&issuer) || certificate.public_key != keypair.public {
            return Err(Error::InvalidCertificate);
        }
        Ok(Wallet {
            certificate,
            keypair,
            issuer,
            balance_cents: 0,
            incoming: HashMap::new(),
            pending_funding: HashMap::new(),
            credited: HashSet::new(),
            counter: 0,
            state: ElementState::Sealed,
            rng,
        })
    }

    pub fn device(&self) -> DeviceId {
        self.certificate.device
    }

    pub fn certificate(&self) -> &DeviceCertificate {
        &self.certificate
    }

    pub fn balance(&self) -> u64 {
        self.balance_cents
    }

    pub fn holding_limit(&self) -> u64 {
        self.certificate.holding_limit_cents
    }

    /// Value promised to the element but not yet credited.
    pub fn reserved(&self) -> u64 {
        self.incoming.values().sum::<u64>() + self.pending_funding.values().sum::<u64>()
    }

    /// How much more the element could accept right now.
    pub fn headroom(&self) -> u64 {
        self.holding_limit()
            .saturating_sub(self.balance_cents)
            .saturating_sub(self.reserved())
    }

    pub fn state(&self) -> ElementState {
        self.state
    }

    /// Simulates a hardware attack that defeats the element's balance
    /// bookkeeping.
    pub fn crack_secure_element(&mut self) {
        self.state = ElementState::Cracked;
    }

    fn reserve(&mut self, amount_cents: u64) -> Result<[u8; 16]> {
        if amount_cents == 0 {
            return Err(Error::ZeroAmount);
        }
        let headroom = self.headroom();
        if amount_cents > headroom {
            return Err(Error::HoldingLimitExceeded {
                requested: amount_cents,
                headroom,
            });
        }
        Ok(self.rng.gen())
    }

    /// Debits the element. A cracked element signs as if it had, and keeps
    /// the value.
    fn debit(&mut self, amount_cents: u64) -> Result<u64> {
        if amount_cents == 0 {
            return Err(Error::ZeroAmount);
        }
        if amount_cents > self.balance_cents {
            return Err(Error::InsufficientFunds {
                requested: amount_cents,
                available: self.balance_cents,
            });
        }
        if self.state == ElementState::Sealed {
            self.balance_cents -= amount_cents;
        }
        self.counter += 1;
        Ok(self.counter)
    }

    // ─────────────────────────── as payee ───────────────────────────

    /// Opens a payment request, reserving room for the amount.
    pub fn request_payment(&mut self, amount_cents: u64) -> Result<PaymentRequest> {
        let nonce = self.reserve(amount_cents)?;
        self.incoming.insert(nonce, amount_cents);
        Ok(PaymentRequest {
            payee: self.certificate.clone(),
            amount_cents,
            nonce,
        })
    }

    /// Abandons an unpaid request and releases its reservation.
    pub fn cancel_request(&mut self, nonce: &[u8; 16]) -> bool {
        self.incoming.remove(nonce).is_some()
    }

    /// Verifies and credits a transfer. Returns the amount credited.
    pub fn receive(&mut self, transfer: &Transfer) -> Result<u64> {
        if transfer.payee != self.device() {
            return Err(Error::NotForThisDevice);
        }
        if !transfer.payer.verify(&self.issuer) {
            return Err(Error::InvalidCertificate);
        }
        if !transfer
            .payer
            .public_key
            .verify(&transfer.digest(), &transfer.signature)
        {
            return Err(Error::InvalidSignature);
        }
        if self.credited.contains(&transfer.nonce) {
            return Err(Error::AlreadyCredited);
        }
        let expected = *self
            .incoming
            .get(&transfer.nonce)
            .ok_or(Error::UnknownRequest)?;
        if transfer.amount_cents != expected {
            return Err(Error::AmountMismatch {
                expected,
                found: transfer.amount_cents,
            });
        }
        self.incoming.remove(&transfer.nonce);
        self.credited.insert(transfer.nonce);
        // Room was reserved when the request was issued, so this stays
        // within the holding limit.
        self.balance_cents += expected;
        Ok(expected)
    }

    // ─────────────────────────── as payer ───────────────────────────

    /// Pays a request out of the balance.
    ///
    /// Everything that could make the payment fail is checked first; only
    /// then is the element debited and the transfer signed.
    pub fn pay(&mut self, request: &PaymentRequest) -> Result<Transfer> {
        if !request.payee.verify(&self.issuer) {
            return Err(Error::InvalidCertificate);
        }
        if request.payee.device == self.device() {
            return Err(Error::SelfPayment);
        }
        let counter = self.debit(request.amount_cents)?;
        let mut transfer = Transfer {
            payer: self.certificate.clone(),
            payee: request.payee.device,
            amount_cents: request.amount_cents,
            nonce: request.nonce,
            counter,
            signature: Default::default(),
        };
        transfer.signature = self.keypair.sign(&transfer.digest());
        Ok(transfer)
    }

    // ─────────────────────── funding / defunding ───────────────────────

    /// Asks the issuer to move value from the online account onto the
    /// element, reserving room for it first.
    pub fn request_funding(&mut self, amount_cents: u64) -> Result<FundingRequest> {
        let nonce = self.reserve(amount_cents)?;
        self.pending_funding.insert(nonce, amount_cents);
        let mut request = FundingRequest {
            device: self.device(),
            amount_cents,
            nonce,
            signature: Default::default(),
        };
        request.signature = self.keypair.sign(&request.digest());
        Ok(request)
    }

    /// Abandons a funding request the issuer refused.
    pub fn cancel_funding(&mut self, nonce: &[u8; 16]) -> bool {
        self.pending_funding.remove(nonce).is_some()
    }

    /// Credits the element with value the issuer has debited from the account.
    pub fn apply_funding(&mut self, funding: &Funding) -> Result<u64> {
        if funding.device != self.device() {
            return Err(Error::NotForThisDevice);
        }
        if !self.issuer.verify(&funding.digest(), &funding.signature) {
            return Err(Error::InvalidSignature);
        }
        if self.credited.contains(&funding.nonce) {
            return Err(Error::AlreadyCredited);
        }
        let expected = *self
            .pending_funding
            .get(&funding.nonce)
            .ok_or(Error::UnknownRequest)?;
        if funding.amount_cents != expected {
            return Err(Error::AmountMismatch {
                expected,
                found: funding.amount_cents,
            });
        }
        self.pending_funding.remove(&funding.nonce);
        self.credited.insert(funding.nonce);
        self.balance_cents += expected;
        Ok(expected)
    }

    /// Debits the element and signs an order to credit the online account.
    pub fn defund(&mut self, amount_cents: u64) -> Result<Defunding> {
        let counter = self.debit(amount_cents)?;
        let mut defunding = Defunding {
            device: self.device(),
            amount_cents,
            counter,
            signature: Default::default(),
        };
        defunding.signature = self.keypair.sign(&defunding.digest());
        Ok(defunding)
    }
}
