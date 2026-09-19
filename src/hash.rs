//! Domain-separated hashing helpers.
//!
//! Every hash in the protocol goes through [`tagged`] so that a signed message
//! of one kind — a transfer, say — can never be passed off as another, such as
//! a defunding order or a device certificate.

use sha2::{Digest, Sha256};

/// `SHA-256(tag || len(part) || part ...)` with length prefixes so that
/// concatenation is unambiguous.
pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((tag.len() as u32).to_be_bytes());
    hasher.update(tag.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
