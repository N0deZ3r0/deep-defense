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
