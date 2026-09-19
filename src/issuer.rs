//! The online side: the Eurosystem certifying devices, and intermediaries
//! holding accounts and moving value on and off devices. The model folds both
//! roles into one `Issuer`.
//!
//! The issuer never sees an offline payment. What it does see is every euro
//! entering the offline circuit (funding) and every euro leaving it
//! (defunding). The difference is the offline float: what ought to be sitting
//! on devices. A cracked element can create value offline, which leaves real
//! holdings above the float — but the issuer cannot see real holdings. It only
//! notices once more has been defunded than was ever funded and the float
//! goes negative, which may be never. Even then nothing on record says which
//! device minted the money.

use crate::certificate::DeviceCertificate;
use crate::error::{Error, Result};
use crate::id::{AccountId, DeviceId};
use crate::message::{Defunding, Funding, FundingRequest};
use crate::signature::{Keypair, PublicKey};
use rand::Rng;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
struct DeviceRecord {
    account: AccountId,
    public_key: PublicKey,
    last_defunding_counter: u64,
}

pub struct Issuer {
    keypair: Keypair,
    accounts: HashMap<AccountId, u64>,
    devices: HashMap<DeviceId, DeviceRecord>,
    funding_nonces: HashSet<(DeviceId, [u8; 16])>,
    /// Funded minus defunded. Signed, because counterfeiting can drive it
    /// below zero.
    offline_float: i128,
}

impl Issuer {
    pub fn new(keypair: Keypair) -> Self {
        Issuer {
            keypair,
            accounts: HashMap::new(),
            devices: HashMap::new(),
            funding_nonces: HashSet::new(),
            offline_float: 0,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public.clone()
    }

    pub fn open_account(&mut self, account: AccountId, balance_cents: u64) {
        self.accounts.insert(account, balance_cents);
    }

    pub fn balance_of(&self, account: &AccountId) -> Option<u64> {
        self.accounts.get(account).copied()
    }

    /// The account a device was certified for. Only the issuer knows this.
    pub fn account_of(&self, device: &DeviceId) -> Option<AccountId> {
        self.devices.get(device).map(|record| record.account)
    }

    /// Value that ought to be on devices: everything funded, less everything
    /// defunded. Counterfeiting pushes real holdings above this figure
    /// invisibly; only a negative float proves it happened.
    pub fn offline_float(&self) -> i128 {
        self.offline_float
    }

    /// Certifies a device key for an account and assigns the device an id.
    pub fn certify_device<R: Rng + ?Sized>(
        &mut self,
        account: AccountId,
        public_key: &PublicKey,
        holding_limit_cents: u64,
        rng: &mut R,
    ) -> Result<DeviceCertificate> {
        if !self.accounts.contains_key(&account) {
            return Err(Error::UnknownAccount(account));
        }
        let device = DeviceId(rng.gen());
        let mut certificate = DeviceCertificate {
            device,
            public_key: public_key.clone(),
            holding_limit_cents,
            signature: Default::default(),
        };
        certificate.signature = self.keypair.sign(&certificate.digest());
        self.devices.insert(
            device,
            DeviceRecord {
                account,
                public_key: public_key.clone(),
                last_defunding_counter: 0,
            },
        );
        Ok(certificate)
    }

    fn device(&self, device: &DeviceId) -> Result<&DeviceRecord> {
        self.devices
            .get(device)
            .ok_or(Error::UnknownDevice(*device))
    }

    /// Debits the device's account and signs the funding for the element.
    pub fn fund(&mut self, request: &FundingRequest) -> Result<Funding> {
        let record = self.device(&request.device)?;
        if !record
            .public_key
            .verify(&request.digest(), &request.signature)
        {
            return Err(Error::InvalidSignature);
        }
        if request.amount_cents == 0 {
            return Err(Error::ZeroAmount);
        }
        if self
            .funding_nonces
            .contains(&(request.device, request.nonce))
        {
            return Err(Error::Replay);
        }
        let account = record.account;
        let balance = self
            .accounts
            .get_mut(&account)
            .ok_or(Error::UnknownAccount(account))?;
        if *balance < request.amount_cents {
            return Err(Error::InsufficientFunds {
                requested: request.amount_cents,
                available: *balance,
            });
        }
        *balance -= request.amount_cents;
        self.offline_float += request.amount_cents as i128;
        self.funding_nonces.insert((request.device, request.nonce));

        let mut funding = Funding {
            device: request.device,
            amount_cents: request.amount_cents,
            nonce: request.nonce,
            signature: Default::default(),
        };
        funding.signature = self.keypair.sign(&funding.digest());
        Ok(funding)
    }

    /// Credits the device's account with value the element has debited.
    pub fn defund(&mut self, defunding: &Defunding) -> Result<u64> {
        let record = self.device(&defunding.device)?;
        if !record
            .public_key
            .verify(&defunding.digest(), &defunding.signature)
        {
            return Err(Error::InvalidSignature);
        }
        if defunding.counter <= record.last_defunding_counter {
            return Err(Error::Replay);
        }
        let account = record.account;
        let balance = self
            .accounts
            .get_mut(&account)
            .ok_or(Error::UnknownAccount(account))?;
        *balance += defunding.amount_cents;
        self.offline_float -= defunding.amount_cents as i128;
        if let Some(record) = self.devices.get_mut(&defunding.device) {
            record.last_defunding_counter = defunding.counter;
        }
        Ok(defunding.amount_cents)
    }
}
