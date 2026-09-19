//! Identifiers for online accounts and certified devices.

use std::fmt;

/// An online digital euro account, held with an intermediary. Funding and
/// defunding move value between this account and a device.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(pub [u8; 16]);

/// A certified secure element.
///
/// This is all a counterparty learns about the other side of an offline
/// payment: a pseudonym for the device, not the account or the person behind
/// it. Only the issuer, which certified the device, can map it to an account.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(pub [u8; 16]);

macro_rules! hex_id {
    ($name:ident) => {
        impl $name {
            /// Short form for logs.
            pub fn short(&self) -> String {
                self.0[..4].iter().map(|b| format!("{b:02x}")).collect()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0.iter() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({}…)", stringify!($name), self.short())
            }
        }
    };
}

hex_id!(AccountId);
hex_id!(DeviceId);
