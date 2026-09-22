//! Error types.
//!
//! One rule runs through this module: an error message may describe *what*
//! failed, never *what the secret was*. No variant carries a password, a key,
//! or a decrypted entry, so no log line or crash report can leak one.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    /// Wrong master password / keyfile, or the vault was modified.
    ///
    /// Deliberately one variant for both. Telling the caller which of the two
    /// happened would tell an attacker whether a guess was close, and would
    /// tell a tamperer that their edit was noticed.
    Authentication,

    /// Key derivation or AEAD setup failed for a structural reason.
    Crypto(String),

    /// The vault file is not in a format we understand.
    Format(String),

    /// The decrypted payload is valid but the operation cannot proceed.
    Vault(String),

    EntryNotFound(String),
    EntryExists(String),

    /// The VeraCrypt binary is missing or an invocation failed.
    VeraCrypt(String),

    /// The vault on disk is older than the revision we last recorded.
    Rollback { on_disk: u64, expected: u64 },

    Config(String),

    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Authentication => write!(
                f,
                "Cannot open the vault: wrong master password or keyfile, \
                 or the file has been altered."
            ),
            Error::Crypto(msg) => write!(f, "Cryptography error: {msg}"),
            Error::Format(msg) => write!(f, "Unrecognised vault format: {msg}"),
            Error::Vault(msg) => write!(f, "{msg}"),
            Error::EntryNotFound(name) => write!(f, "No entry named \"{name}\"."),
            Error::EntryExists(name) => write!(f, "An entry named \"{name}\" already exists."),
            Error::VeraCrypt(msg) => write!(f, "VeraCrypt: {msg}"),
            Error::Rollback { on_disk, expected } => write!(
                f,
                "This vault is revision {on_disk}, but revision {expected} was last seen \
                 on this machine. An older copy may have been restored in place of the \
                 current one. Continue only if you restored a backup on purpose."
            ),
            Error::Config(msg) => write!(f, "Configuration: {msg}"),
            Error::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn format(msg: impl Into<String>) -> Self {
        Error::Format(msg.into())
    }

    pub fn vault(msg: impl Into<String>) -> Self {
        Error::Vault(msg.into())
    }

    pub fn veracrypt(msg: impl Into<String>) -> Self {
        Error::VeraCrypt(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// The message to put in front of the user, in their own language.
    ///
    /// `Display` stays English on purpose: it is what ends up in logs, panic
    /// messages and test failures, where a stable wording is worth more than a
    /// translated one. Technical detail carried inside a variant is passed
    /// through untranslated — it comes from libraries we do not control, and a
    /// half-translated sentence reads worse than an honest English clause.
    pub fn localized(&self, strings: &crate::i18n::Strings) -> String {
        use crate::i18n::{fill1, fill2};
        let e = &strings.errors;
        match self {
            Error::Authentication => e.authentication.to_owned(),
            Error::Crypto(msg) => fill1(e.crypto, msg),
            Error::Format(msg) => fill1(e.format, msg),
            Error::Vault(msg) => msg.clone(),
            Error::EntryNotFound(name) => fill1(e.entry_not_found, name),
            Error::EntryExists(name) => fill1(e.entry_exists, name),
            Error::VeraCrypt(msg) => fill1(e.veracrypt, msg),
            Error::Rollback { on_disk, expected } => fill2(e.rollback, on_disk, expected),
            Error::Config(msg) => fill1(e.config, msg),
            Error::Io { path, source } => fill2(e.io, path.display(), source),
        }
    }

    /// True when retrying with different input could plausibly succeed.
    /// The UI uses this to decide whether to keep the password field open.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Authentication | Error::VeraCrypt(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
