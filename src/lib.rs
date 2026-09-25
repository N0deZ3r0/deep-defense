//! Deep Defense - a self-contained password manager.
//!
//! The vault file is encrypted twice over, by two unrelated ciphers with
//! independent keys: XChaCha20-Poly1305 wrapped in AES-256-GCM, both derived
//! from one Argon2id pass over the master password (see [`crypto`]). That is
//! the whole of the protection by default, and it needs nothing installed.
//!
//! A VeraCrypt container can be layered on top for those who want it (see
//! [`session`]), but it is optional: mounting a volume needs a kernel driver
//! and therefore administrator rights, which is a price the default mode does
//! not ask anyone to pay.

pub mod breach;
pub mod clipboard;
pub mod config;
pub mod crypto;
pub mod errors;
pub mod generator;
pub mod i18n;
pub mod model;
pub mod platform;
pub mod portable;
pub mod secret;
#[cfg(test)]
mod robustness;
pub mod session;
pub mod shamir;
pub mod slots;
pub mod totp;
pub mod vault;
pub mod veracrypt;
#[cfg(test)]
mod vectors;

pub mod ui;
