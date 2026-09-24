//! Non-secret settings, kept outside the encrypted container.
//!
//! Everything here is paths, timeouts and cost parameters. It deliberately
//! never holds a password, a key, or a keyfile's contents — if this file
//! leaks, the attacker learns where the container lives, which they could
//! have found by looking at the disk anyway.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::KdfParams;
use crate::errors::{Error, Result};
use crate::i18n::Lang;
use crate::ui::theme::Appearance;

pub const APP_NAME: &str = "DeepDefense";
pub const VAULT_FILENAME: &str = "vault.ddv";
const CONFIG_FILENAME: &str = "config.json";

/// Per-user directory for settings and the rollback anchor.
pub fn app_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("DEEP_DEFENSE_HOME") {
        if !override_dir.trim().is_empty() {
            return PathBuf::from(override_dir);
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_NAME)
}


/// A scratch app directory, held for as long as the returned value lives.
///
/// `DEEP_DEFENSE_HOME` is process-global and `cargo test` runs tests as
/// threads in one process, so every test that can reach [`app_dir`] has to
/// take the *same* lock. Two modules with two locks is two tests writing to
/// one path, which is how a passing suite starts failing at random.
///
/// It also keeps the suite out of the real user profile: without it, anything
/// that creates a vault writes a rollback anchor into the actual settings
/// directory, and running the tests would edit the anchor of a vault somebody
/// depends on.
#[cfg(test)]
pub(crate) mod test_home {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    pub(crate) struct TestHome {
        pub(crate) path: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TestHome {
        pub(crate) fn new(tag: &str) -> Self {
            // A panicking test poisons the lock. What it guards is one
            // environment variable, so taking it anyway is right.
            let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let path = std::env::temp_dir()
                .join(format!("dd-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            std::env::set_var("DEEP_DEFENSE_HOME", &path);
            Self {
                path,
                _guard: guard,
            }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            std::env::remove_var("DEEP_DEFENSE_HOME");
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

pub fn ensure_app_dir() -> Result<PathBuf> {
    let dir = app_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(dir.clone(), e))?;
    Ok(dir)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Put the vault inside a VeraCrypt container.
    ///
    /// Off by default, because VeraCrypt needs a kernel driver and therefore
    /// administrator rights; the vault's own cascade is strong on its own. Turn
    /// it on for the extra outer layer if VeraCrypt is installed.
    pub use_container: bool,

    /// Where the vault file lives when `use_container` is off.
    pub vault_path: PathBuf,

    /// The VeraCrypt container holding the vault, when `use_container` is on.
    pub container_path: PathBuf,
    /// Optional keyfiles, required in addition to the master password.
    pub keyfiles: Vec<PathBuf>,
    /// VeraCrypt Personal Iterations Multiplier. 0 means the default.
    pub pim: u32,

    /// A second copy of the container's `.ddmeta` sidecar.
    ///
    /// The sidecar holds the container's volume password, sealed under the
    /// master password. It is useless to anyone without that password, but
    /// losing it makes the container unopenable - so we keep a second copy
    /// here, on the reasoning that both are unlikely to be lost at once.
    pub container_meta: Option<crate::session::ContainerMeta>,

    /// Cost of one master-password guess. Mirrored here for display only;
    /// the vault header is authoritative.
    pub kdf: KdfParams,

    /// How long a copied password survives on the clipboard.
    pub clipboard_seconds: u64,
    /// Idle time before the vault locks and the volume is dismounted.
    pub autolock_seconds: u64,
    /// Lock and dismount when the screen locks or the session disconnects.
    pub lock_on_screen_lock: bool,
    /// Hide passwords in the list until explicitly revealed.
    pub mask_passwords: bool,

    /// Interface language. Guessed from the OS on first run, then remembered.
    pub language: Lang,
    /// Light or dark palette.
    pub appearance: Appearance,

    pub veracrypt_binary: PathBuf,
    pub veracrypt_format_binary: PathBuf,
    /// VeraCrypt cipher cascade, e.g. "AES" or "AES(Twofish(Serpent))".
    pub encryption: String,
    pub hash_algo: String,

    /// Warn when a password has not been changed in this many days.
    pub warn_password_age_days: i64,

    /// A second directory that every save is copied into.
    ///
    /// The numbered backups sit beside the vault, so one dying disk or one
    /// folder reached by ransomware takes every copy at once. This is where
    /// the second, independent copy goes. Holding a path here gives nothing
    /// away that the disk does not already show.
    pub backup_mirror: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            use_container: false,
            vault_path: default_vault_path(),
            container_path: PathBuf::new(),
            keyfiles: Vec::new(),
            pim: 0,
            container_meta: None,
            kdf: KdfParams::default(),
            clipboard_seconds: 15,
            autolock_seconds: 300,
            lock_on_screen_lock: true,
            mask_passwords: true,
            language: Lang::from_system(),
            appearance: Appearance::Dark,
            veracrypt_binary: PathBuf::new(),
            veracrypt_format_binary: PathBuf::new(),
            encryption: "AES".to_string(),
            hash_algo: "sha512".to_string(),
            warn_password_age_days: 365,
            backup_mirror: None,
        }
    }
}

impl Config {
    pub fn path() -> PathBuf {
        app_dir().join(CONFIG_FILENAME)
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.is_file() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).map_err(|e| Error::io(path.clone(), e))?;
        // Strip a UTF-8 BOM. Notepad and PowerShell's `Out-File -Encoding utf8`
        // both write one, and serde_json rejects it — which would silently cost
        // the user every setting they had, since the caller falls back to
        // defaults when this returns an error.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text.as_str());
        let config: Config = serde_json::from_str(text).map_err(|e| {
            Error::config(format!(
                "{} is not valid JSON ({e}). Delete it to start from defaults.",
                path.display()
            ))
        })?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        ensure_app_dir()?;
        let path = Self::path();
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| Error::config(format!("cannot serialise settings: {e}")))?;
        std::fs::write(&tmp, text).map_err(|e| Error::io(tmp.clone(), e))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::io(path.clone(), e))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=300).contains(&self.clipboard_seconds) {
            return Err(Error::config(
                "clipboard timeout must be between 1 and 300 seconds",
            ));
        }
        if !(10..=86_400).contains(&self.autolock_seconds) {
            return Err(Error::config(
                "auto-lock timeout must be between 10 seconds and 24 hours",
            ));
        }
        for keyfile in &self.keyfiles {
            if !keyfile.is_file() {
                return Err(Error::config(format!(
                    "keyfile is missing: {}",
                    keyfile.display()
                )));
            }
        }
        self.kdf.validate()?;
        Ok(())
    }

    /// Where the vault file sits once the container is mounted at `mount`.
    pub fn vault_path_in(mount: &Path) -> PathBuf {
        mount.join(VAULT_FILENAME)
    }

    /// True when there is something to unlock.
    pub fn is_configured(&self) -> bool {
        if self.use_container {
            !self.container_path.as_os_str().is_empty() && self.container_path.is_file()
        } else {
            !self.vault_path.as_os_str().is_empty() && self.vault_path.is_file()
        }
    }
}

/// Default home for a standalone vault: alongside the user's own documents,
/// where they will think to back it up, rather than buried in AppData.
pub fn default_vault_path() -> PathBuf {
    dirs::document_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("DeepDefense")
        .join(VAULT_FILENAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_home::TestHome;
    use crate::i18n::Lang;
    use crate::ui::theme::Appearance;

    #[test]
    fn with_no_file_at_all_the_defaults_are_used() {
        let _home = TestHome::new("cfg-absent");
        assert!(!Config::path().exists());
        let config = Config::load().expect("an absent file is not an error");
        assert_eq!(config.clipboard_seconds, Config::default().clipboard_seconds);
    }

    #[test]
    fn every_setting_survives_a_round_trip() {
        let home = TestHome::new("cfg-roundtrip");
        let mirror = home.join("elsewhere");

        let mut written = Config::default();
        written.use_container = true;
        written.vault_path = home.join("vault.ddv");
        written.container_path = home.join("box.hc");
        written.keyfiles = vec![home.join("a.key"), home.join("b.key")];
        written.pim = 485;
        written.clipboard_seconds = 42;
        written.autolock_seconds = 900;
        written.lock_on_screen_lock = false;
        written.mask_passwords = false;
        written.language = Lang::En;
        written.appearance = Appearance::Light;
        written.encryption = "AES(Twofish(Serpent))".into();
        written.hash_algo = "sha256".into();
        written.warn_password_age_days = 90;
        written.backup_mirror = Some(mirror.clone());
        written.kdf.t_cost = 5;
        written.save().unwrap();

        let read = Config::load().unwrap();
        assert_eq!(read.use_container, true);
        assert_eq!(read.vault_path, written.vault_path);
        assert_eq!(read.container_path, written.container_path);
        assert_eq!(read.keyfiles, written.keyfiles);
        assert_eq!(read.pim, 485);
        assert_eq!(read.clipboard_seconds, 42);
        assert_eq!(read.autolock_seconds, 900);
        assert_eq!(read.lock_on_screen_lock, false);
        assert_eq!(read.mask_passwords, false);
        assert_eq!(read.language, Lang::En);
        assert_eq!(read.appearance, Appearance::Light);
        assert_eq!(read.encryption, "AES(Twofish(Serpent))");
        assert_eq!(read.hash_algo, "sha256");
        assert_eq!(read.warn_password_age_days, 90);
        assert_eq!(read.backup_mirror, Some(mirror));
        assert_eq!(read.kdf.t_cost, 5);
    }

    /// The regression that matters most in this file.
    ///
    /// Notepad and PowerShell's `Out-File -Encoding utf8` both write a byte
    /// order mark, serde_json refuses it, and the caller answers a load error
    /// by falling back to defaults — so one invisible character silently reset
    /// the language, the theme and the vault path at once. It was found by
    /// noticing a screenshot came out Russian when English was asked for.
    #[test]
    fn a_byte_order_mark_does_not_reset_every_setting() {
        let _home = TestHome::new("cfg-bom");
        let mut written = Config::default();
        written.clipboard_seconds = 37;
        written.language = Lang::En;
        written.save().unwrap();

        let text = std::fs::read_to_string(Config::path()).unwrap();
        std::fs::write(Config::path(), format!("\u{feff}{text}")).unwrap();

        let read = Config::load().expect("a BOM must not make the file unreadable");
        assert_eq!(read.clipboard_seconds, 37, "the settings survived the BOM");
        assert_eq!(read.language, Lang::En);
    }

    #[test]
    fn a_broken_file_is_reported_rather_than_silently_replaced() {
        // Returning the defaults here would look like the program forgetting
        // everything for no reason. The caller shows the error instead.
        let _home = TestHome::new("cfg-broken");
        std::fs::create_dir_all(Config::path().parent().unwrap()).unwrap();
        std::fs::write(Config::path(), "{ this is not json").unwrap();

        let err = Config::load().unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("config.json"), "names the file: {message}");
        assert!(message.contains("Delete it"), "says what to do: {message}");
    }

    #[test]
    fn a_setting_this_version_does_not_know_is_ignored() {
        // A file written by a newer build must not stop an older one from
        // starting, or a downgrade would cost the user their settings.
        let _home = TestHome::new("cfg-forward");
        std::fs::create_dir_all(Config::path().parent().unwrap()).unwrap();
        std::fs::write(
            Config::path(),
            r#"{"clipboard_seconds": 21, "something_from_the_future": [1, 2, 3]}"#,
        )
        .unwrap();

        let read = Config::load().unwrap();
        assert_eq!(read.clipboard_seconds, 21);
    }

    #[test]
    fn a_setting_added_since_the_file_was_written_takes_its_default() {
        // The mirror directory did not exist in the first release; a file from
        // then must still load, with mirroring simply off.
        let _home = TestHome::new("cfg-backward");
        std::fs::create_dir_all(Config::path().parent().unwrap()).unwrap();
        std::fs::write(Config::path(), r#"{"clipboard_seconds": 19}"#).unwrap();

        let read = Config::load().unwrap();
        assert_eq!(read.clipboard_seconds, 19);
        assert_eq!(read.backup_mirror, None);
        assert_eq!(read.language, Config::default().language);
    }

    #[test]
    fn implausible_timeouts_are_refused() {
        let mut config = Config::default();
        config.clipboard_seconds = 0;
        assert!(config.validate().is_err(), "zero would clear instantly");

        config = Config::default();
        config.clipboard_seconds = 100_000;
        assert!(config.validate().is_err(), "a day on the clipboard");

        config = Config::default();
        config.autolock_seconds = 1;
        assert!(config.validate().is_err(), "unusable, not secure");

        config = Config::default();
        config.autolock_seconds = 999_999;
        assert!(config.validate().is_err());

        assert!(Config::default().validate().is_ok(), "the defaults must pass");
    }

    #[test]
    fn a_missing_keyfile_is_refused_before_it_is_needed() {
        // Caught at validation rather than at unlock, where the failure would
        // look like a wrong password.
        let home = TestHome::new("cfg-keyfile");
        let mut config = Config::default();
        config.keyfiles = vec![home.join("never-existed.key")];
        let err = config.validate().unwrap_err();
        assert!(format!("{err}").contains("missing"));
    }

    /// The claim in this file's own doc comment, under test.
    #[test]
    fn the_settings_file_holds_no_secret() {
        let _home = TestHome::new("cfg-nosecrets");
        let config = Config::default();
        config.save().unwrap();
        let text = std::fs::read_to_string(Config::path()).unwrap();

        // `container_meta` may hold a *wrapped* volume password; nothing else
        // in this file is allowed to resemble a secret at all.
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let object = parsed.as_object().expect("a settings object");
        for (key, value) in object {
            if key == "container_meta" {
                continue;
            }
            assert!(
                !key.contains("password") && !key.contains("secret") && !key.contains("key_"),
                "a settings field called {key} looks like it holds a secret"
            );
            assert!(
                !value.to_string().to_lowercase().contains("password"),
                "the value of {key} mentions a password"
            );
        }
    }

    #[test]
    fn saving_creates_the_directory_it_needs() {
        let home = TestHome::new("cfg-mkdir");
        let nested = home.join("not").join("there").join("yet");
        std::env::set_var("DEEP_DEFENSE_HOME", &nested);
        let outcome = Config::default().save();
        std::env::set_var("DEEP_DEFENSE_HOME", home.path());
        outcome.expect("save must create the settings directory");
        assert!(nested.join("config.json").is_file());
    }

    #[test]
    fn the_home_override_is_honoured() {
        let home = TestHome::new("cfg-home");
        assert_eq!(app_dir(), home.path());
        assert!(Config::path().starts_with(home.path()));
    }

    #[test]
    fn a_blank_home_override_falls_back_to_the_real_profile() {
        // An empty environment variable is how a shell passes "unset", and
        // treating it as a path would put the settings in the current
        // directory.
        let home = TestHome::new("cfg-blank");
        std::env::set_var("DEEP_DEFENSE_HOME", "   ");
        let resolved = app_dir();
        std::env::set_var("DEEP_DEFENSE_HOME", home.path());
        assert_ne!(resolved, std::path::PathBuf::from("   "));
        assert!(resolved.ends_with(APP_NAME));
    }
}
