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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{EN, RU};

    /// One of every variant, so a new one cannot be added without deciding
    /// what it says.
    fn one_of_each() -> Vec<Error> {
        vec![
            Error::Authentication,
            Error::crypto("the tag did not verify"),
            Error::format("that is not a share"),
            Error::vault("the vault is not open"),
            Error::EntryNotFound("Bank".into()),
            Error::EntryExists("Bank".into()),
            Error::veracrypt("the volume did not mount"),
            Error::Rollback {
                on_disk: 7,
                expected: 11,
            },
            Error::config("the timeout is out of range"),
            Error::io(
                std::path::PathBuf::from("C:/vault.ddv"),
                std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            ),
        ]
    }

    #[test]
    fn every_error_says_something_in_both_languages() {
        for error in one_of_each() {
            for (language, strings) in [("EN", &EN), ("RU", &RU)] {
                let text = error.localized(strings);
                assert!(
                    !text.trim().is_empty(),
                    "{error:?} says nothing in {language}"
                );
                assert!(
                    !text.contains("{}"),
                    "{error:?} left a placeholder unfilled in {language}: {text}"
                );
            }
        }
    }

    #[test]
    fn the_two_languages_do_not_hand_back_the_same_sentence() {
        // A missing match arm, or a template copied from one block to the
        // other, shows up as an English sentence in a Russian interface — and
        // nothing else in the build would notice.
        for error in one_of_each() {
            let english = error.localized(&EN);
            let russian = error.localized(&RU);
            // Three are the same in both languages on purpose. `Vault` is
            // the caller's own message, passed through untranslated.
            // `VeraCrypt: {}` is a product name followed by that tool's own
            // output, and `{}: {}` is a path and an operating-system error.
            // There is nothing in any of them left to translate, and inventing
            // a difference to satisfy a test would mean translating a product
            // name.
            if matches!(error, Error::Vault(_) | Error::VeraCrypt(_) | Error::Io { .. }) {
                assert_eq!(english, russian, "{error:?} should pass through unchanged");
                continue;
            }
            assert_ne!(
                english, russian,
                "{error:?} reads identically in both languages"
            );
            assert!(
                russian.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)),
                "{error:?} has no Cyrillic in its Russian form: {russian}"
            );
        }
    }

    #[test]
    fn what_the_error_is_about_survives_translation() {
        assert!(Error::EntryNotFound("Bank".into())
            .localized(&RU)
            .contains("Bank"));
        assert!(Error::EntryExists("Bank".into())
            .localized(&RU)
            .contains("Bank"));

        let rollback = Error::Rollback {
            on_disk: 7,
            expected: 11,
        };
        let text = rollback.localized(&RU);
        assert!(text.contains('7') && text.contains("11"), "{text}");

        let io = Error::io(
            std::path::PathBuf::from("C:/vault.ddv"),
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        assert!(io.localized(&RU).contains("vault.ddv"));
    }

    #[test]
    fn display_stays_english_for_the_log() {
        // Two audiences: `localized` is for the person, `Display` is for a log
        // line or a panic message, which is read by whoever is debugging and
        // is searched for in English.
        let error = Error::EntryNotFound("Bank".into());
        let printed = format!("{error}");
        assert!(printed.contains("Bank"));
        assert!(
            !printed.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)),
            "a log line came out in Russian: {printed}"
        );
    }

    #[test]
    fn only_a_second_attempt_worth_making_is_retryable() {
        // A wrong password or a volume that did not mount are worth another
        // go; a broken file or a missing entry are not, and offering to retry
        // them would be a lie.
        assert!(Error::Authentication.is_retryable());
        assert!(Error::veracrypt("did not mount").is_retryable());

        assert!(!Error::format("not a share").is_retryable());
        assert!(!Error::EntryNotFound("Bank".into()).is_retryable());
        assert!(!Error::crypto("the tag did not verify").is_retryable());
        assert!(!Error::Rollback {
            on_disk: 1,
            expected: 2
        }
        .is_retryable());
    }

    #[test]
    fn an_authentication_failure_says_nothing_about_which_slot() {
        // The whole point of the hidden vault is that a wrong password cannot
        // be told from a password belonging to a slot that does not exist.
        for strings in [&EN, &RU] {
            let text = Error::Authentication.localized(strings).to_lowercase();
            for giveaway in ["slot", "hidden", "primary", "слот", "скрыт"] {
                assert!(
                    !text.contains(giveaway),
                    "the refusal mentions {giveaway}: {text}"
                );
            }
        }
    }

    #[test]
    fn a_debug_line_is_still_useful() {
        // Errors are logged with `{:?}` in places; it must name the variant.
        assert!(format!("{:?}", Error::Authentication).contains("Authentication"));
        assert!(format!("{:?}", Error::EntryNotFound("Bank".into())).contains("Bank"));
    }
}
