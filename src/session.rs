//! Opening and closing the vault, in either of its two modes.
//!
//! By default the vault is a single sealed file: [`crate::crypto`] already
//! encrypts it under two independent ciphers, and that needs nothing installed
//! and no administrator rights. The optional VeraCrypt container adds an outer
//! layer for those who want it; everything below about wrapping applies only
//! to that mode.
//!
//! # Why the container password is not your master password
//!
//! On Windows, VeraCrypt takes the volume password as a command-line
//! argument, and any process running as the same user can read another
//! process's command line. If we passed the master password there, an
//! attacker who scraped it would hold the key to *both* layers.
//!
//! So the container gets a password of its own: 64 characters drawn straight
//! from the OS random generator, generated once when the container is made
//! and never shown to anyone. It is stored *wrapped* — sealed with a key
//! derived from the master password — in a `.ddmeta` file beside the
//! container:
//!
//! ```text
//! wrap_key   = Argon2id(master_secret, salt_in_sidecar)
//! sidecar    = AES-256-GCM(wrap_key, container_password)
//! vault_key  = Argon2id(master_secret, salt_in_vault_file)
//! ```
//!
//! Scraping the container password off a command line therefore reveals
//! nothing about the master password — it is independent random data — and
//! gets the attacker no further than the sealed vault file and a second
//! Argon2id wall.
//!
//! It also means **the master password can be changed without touching the
//! container**: we simply re-wrap the same volume password under a new key.
//! That matters, because VeraCrypt on Windows offers no way to change a
//! volume password without a human clicking through its GUI.

use std::path::{Path, PathBuf};
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::clipboard::ClipboardManager;
use crate::config::{Config, VAULT_FILENAME};
use crate::crypto::{self, KdfParams, VaultHeader};
use crate::errors::{Error, Result};
use crate::secret::Secret;
use crate::vault::Vault;
use crate::veracrypt::{MountPoint, VeraCrypt};

const SIDECAR_EXTENSION: &str = "ddmeta";
/// VeraCrypt accepts up to 64 characters without a keyfile; 48 random bytes
/// encode to exactly that, and every character carries real entropy.
const CONTAINER_PASSWORD_BYTES: usize = 48;

/// Public metadata stored beside the container.
///
/// Nothing in here is usable without the master password, but it *is*
/// required to open the container, so it is mirrored into the settings file
/// as well. Losing both copies makes the container unopenable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerMeta {
    pub version: u32,
    /// The volume password, sealed under one or more master passwords.
    ///
    /// There is normally exactly one. A second appears only while a master
    /// password change is in flight, so that a crash mid-change leaves the
    /// container openable with *either* password rather than neither.
    pub wrapped: Vec<String>,
}

impl ContainerMeta {
    /// Mint a fresh volume password and seal it under `secret`.
    pub fn create(secret: &Secret, kdf: &KdfParams) -> Result<(Self, Secret)> {
        let container_password = random_container_password()?;
        let wrapped = wrap(&container_password, secret, kdf)?;
        Ok((
            Self {
                version: 1,
                wrapped: vec![wrapped],
            },
            container_password,
        ))
    }

    /// Recover the volume password, trying each wrapping in turn.
    ///
    /// Returns the password and which wrapping opened it, so the caller can
    /// prune the leftovers of an interrupted password change.
    pub fn unwrap_password(&self, secret: &Secret) -> Result<(Secret, usize)> {
        if self.wrapped.is_empty() {
            return Err(Error::config(
                "the container metadata holds no key material — it is corrupt",
            ));
        }
        for (index, encoded) in self.wrapped.iter().enumerate() {
            let Ok(blob) = BASE64.decode(encoded) else {
                continue;
            };
            if let Ok((plaintext, _, _)) = crypto::unseal(&blob, secret) {
                return Ok((Secret::new(plaintext.to_vec()), index));
            }
        }
        Err(Error::Authentication)
    }

    /// Add a wrapping under a new master password, keeping the existing ones.
    pub fn add_wrapping(
        &mut self,
        container_password: &Secret,
        new_secret: &Secret,
        kdf: &KdfParams,
    ) -> Result<String> {
        let wrapped = wrap(container_password, new_secret, kdf)?;
        self.wrapped.push(wrapped.clone());
        Ok(wrapped)
    }

    pub fn keep_only(&mut self, wrapped: &str) {
        self.wrapped.retain(|w| w == wrapped);
        if self.wrapped.is_empty() {
            self.wrapped.push(wrapped.to_string());
        }
    }

    pub fn sidecar_path(container: &Path) -> PathBuf {
        let mut path = container.to_path_buf();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "container".into());
        path.set_file_name(format!("{name}.{SIDECAR_EXTENSION}"));
        path
    }

    pub fn save(&self, container: &Path) -> Result<()> {
        let path = Self::sidecar_path(container);
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| Error::config(format!("cannot serialise container metadata: {e}")))?;
        let tmp = path.with_extension("ddmeta.tmp");
        std::fs::write(&tmp, text).map_err(|e| Error::io(tmp.clone(), e))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::io(path, e))
    }

    /// Load from the sidecar, falling back to the copy in settings.
    ///
    /// A missing sidecar is survivable as long as the settings file lives,
    /// and vice versa — which is exactly why we keep both.
    pub fn load(container: &Path, fallback: Option<&ContainerMeta>) -> Result<Self> {
        let path = Self::sidecar_path(container);
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(meta) = serde_json::from_str::<ContainerMeta>(&text) {
                return Ok(meta);
            }
        }
        if let Some(meta) = fallback {
            // Put the sidecar back, so the container is self-sufficient again.
            let _ = meta.save(container);
            return Ok(meta.clone());
        }
        Err(Error::config(format!(
            "cannot find {}.\n\n\
             This file holds the key needed to open the container. Without it — or the \
             spare copy in the settings file — the container cannot be opened. Restore \
             it from your backup.",
            path.display()
        )))
    }
}

fn random_container_password() -> Result<Secret> {
    let mut material = [0u8; CONTAINER_PASSWORD_BYTES];
    crypto::random_bytes(&mut material)?;
    let encoded = BASE64URL.encode(material);
    material.zeroize();
    Ok(Secret::from_string(encoded))
}

fn wrap(container_password: &Secret, secret: &Secret, kdf: &KdfParams) -> Result<String> {
    let header = VaultHeader::new(kdf.clone())?;
    let key = crypto::derive_master_key(secret, &header.salt_bytes()?, &header.kdf)?;
    let blob = crypto::seal(container_password.expose(), &key, &header)?;
    Ok(BASE64.encode(blob))
}

/// The VeraCrypt half of an open vault, when the container layer is in use.
pub struct OpenContainer {
    pub mount: MountPoint,
    /// Kept for the life of the session so the master password can be changed
    /// without asking the user to prove themselves twice. Wiped on lock.
    pub password: Secret,
    pub meta: ContainerMeta,
}

/// An open vault, with or without a container around it.
pub struct OpenVault {
    pub vault: Vault,
    /// `None` in standalone mode - the default, since the container layer
    /// needs VeraCrypt and therefore administrator rights.
    pub container: Option<OpenContainer>,
}

/// What the UI holds while the program is running.
pub struct Session {
    pub config: Config,
    pub clipboard: ClipboardManager,
    veracrypt: VeraCrypt,
    open: Option<OpenVault>,
    last_activity: Instant,
}

impl Session {
    pub fn new(config: Config) -> Self {
        let veracrypt =
            VeraCrypt::from_config(&config.veracrypt_binary, &config.veracrypt_format_binary);
        Self {
            config,
            clipboard: ClipboardManager::new(),
            veracrypt,
            open: None,
            last_activity: Instant::now(),
        }
    }

    pub fn veracrypt(&self) -> &VeraCrypt {
        &self.veracrypt
    }

    pub fn refresh_veracrypt(&mut self) {
        self.veracrypt = VeraCrypt::from_config(
            &self.config.veracrypt_binary,
            &self.config.veracrypt_format_binary,
        );
    }

    pub fn is_unlocked(&self) -> bool {
        self.open.is_some()
    }

    pub fn vault(&self) -> Option<&Vault> {
        self.open.as_ref().map(|o| &o.vault)
    }

    pub fn vault_mut(&mut self) -> Option<&mut Vault> {
        self.open.as_mut().map(|o| &mut o.vault)
    }

    pub fn open_vault_mut(&mut self) -> Option<&mut OpenVault> {
        self.open.as_mut()
    }

    pub fn mount_path(&self) -> Option<&Path> {
        self.open
            .as_ref()
            .and_then(|o| o.container.as_ref())
            .map(|c| c.mount.path.as_path())
    }

    /// True when the vault currently sits inside a VeraCrypt container.
    pub fn uses_container(&self) -> bool {
        self.open
            .as_ref()
            .is_some_and(|o| o.container.is_some())
    }

    pub fn adopt(&mut self, mut open: OpenVault) {
        // Every route to an open vault passes through here, which is the only
        // reason the mirror cannot be forgotten on one of them.
        open.vault.set_mirror(self.config.backup_mirror.clone());
        self.open = Some(open);
        self.touch();
    }

    /// Point saves at a second directory, or stop mirroring, and remember it.
    pub fn set_backup_mirror(&mut self, directory: Option<std::path::PathBuf>) {
        self.config.backup_mirror = directory.clone();
        if let Some(open) = self.open.as_mut() {
            open.vault.set_mirror(directory);
        }
    }

    // ------------------------------------------------------------- idle lock

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn idle_seconds(&self) -> u64 {
        self.last_activity.elapsed().as_secs()
    }

    pub fn seconds_until_autolock(&self) -> Option<u64> {
        if !self.is_unlocked() {
            return None;
        }
        Some(
            self.config
                .autolock_seconds
                .saturating_sub(self.idle_seconds()),
        )
    }

    pub fn should_autolock(&self) -> bool {
        self.is_unlocked() && self.idle_seconds() >= self.config.autolock_seconds
    }

    /// Change the master password for both layers.
    ///
    /// Lives here rather than on the UI side because it needs the open vault
    /// and the settings at once, and only this type can hand out disjoint
    /// borrows of its own fields.
    pub fn change_master_password(
        &mut self,
        new_password: &Secret,
        params: KdfParams,
    ) -> Result<()> {
        let open = self
            .open
            .as_mut()
            .ok_or_else(|| Error::vault("the vault is not open"))?;
        change_master_password(open, &mut self.config, new_password, params)
    }

    // ----------------------------------------------------------------- lock

    /// Save pending changes, close the vault and dismount the container.
    ///
    /// Returns an error only if *saving* failed. A stubborn dismount is
    /// handled by forcing it: by that point the secrets are already gone from
    /// memory, so the volume is just a mounted drive with ciphertext on it.
    pub fn lock(&mut self) -> Result<()> {
        self.clipboard.clear_now();
        let Some(mut open) = self.open.take() else {
            return Ok(());
        };

        let save_result = if open.vault.is_dirty() {
            open.vault.save()
        } else {
            Ok(())
        };

        // Drop the vault before dismounting: that zeroizes the master key and
        // every decrypted entry while the volume is still there to write to.
        drop(open.vault);

        if let Some(container) = open.container {
            drop(container.password);
            if !self.veracrypt.dismount(&container.mount, false) {
                self.veracrypt.dismount(&container.mount, true);
            }
        }
        save_result
    }

    /// Last-resort teardown for panics and unexpected exits.
    pub fn emergency_lock(&mut self) {
        self.clipboard.clear_now();
        if let Some(open) = self.open.take() {
            drop(open.vault);
            if let Some(container) = open.container {
                drop(container.password);
                if !self.veracrypt.dismount(&container.mount, false) {
                    self.veracrypt.dismount(&container.mount, true);
                }
            }
        }
    }
}

/// Dismount on the way out, whatever route we took to get here.
impl Drop for Session {
    fn drop(&mut self) {
        self.emergency_lock();
    }
}

// ------------------------------------------------------------------ actions
//
// These block for seconds at a time (Argon2id twice, plus a mount), so the
// GUI runs them on a worker thread.

/// Create a new vault and leave it open.
///
/// Dispatches on `config.use_container`: standalone is the default, because
/// the container layer needs VeraCrypt's kernel driver and therefore
/// administrator rights, while the vault's own cipher cascade does not.
pub fn create_vault(
    veracrypt: &VeraCrypt,
    config: &Config,
    password: &Secret,
    size_bytes: u64,
) -> Result<OpenVault> {
    if config.use_container {
        create_in_container(veracrypt, config, password, size_bytes)
    } else {
        create_standalone(config, password)
    }
}

/// A plain vault file: no container, no mounting, no driver, no UAC prompt.
fn create_standalone(config: &Config, password: &Secret) -> Result<OpenVault> {
    let path = &config.vault_path;
    if path.as_os_str().is_empty() {
        return Err(Error::config("choose where to put the vault first"));
    }
    if path.exists() {
        return Err(Error::config(format!(
            "{} already exists. Pick a different name, or open it instead.",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent.to_path_buf(), e))?;
    }

    let secret = crypto::combine_secret(password, &config.keyfiles)?;
    let vault = Vault::create(path, &secret, config.kdf.clone())?;
    Ok(OpenVault {
        vault,
        container: None,
    })
}

/// Create a VeraCrypt container and put a fresh vault inside it.
fn create_in_container(
    veracrypt: &VeraCrypt,
    config: &Config,
    password: &Secret,
    size_bytes: u64,
) -> Result<OpenVault> {
    let container = config.container_path.clone();
    if container.as_os_str().is_empty() {
        return Err(Error::config("choose where to put the container first"));
    }
    if container.exists() {
        return Err(Error::config(format!(
            "{} already exists. Pick a different name, or open it instead.",
            container.display()
        )));
    }

    let secret = crypto::combine_secret(password, &config.keyfiles)?;
    let (meta, container_password) = ContainerMeta::create(&secret, &config.kdf)?;

    veracrypt.create_volume(
        &container,
        size_bytes,
        &container_password,
        &config.keyfiles,
        &config.encryption,
        &config.hash_algo,
        false, // full format: fills the container with random data
    )?;
    // Write the sidecar before anything else can fail: without it the
    // container we just made would already be unopenable.
    meta.save(&container)?;

    let mount = veracrypt.mount(
        &container,
        &container_password,
        &config.keyfiles,
        config.pim,
        false,
    )?;

    let vault_path = mount.path.join(VAULT_FILENAME);
    match Vault::create(&vault_path, &secret, config.kdf.clone()) {
        Ok(vault) => Ok(OpenVault {
            vault,
            container: Some(OpenContainer {
                mount,
                password: container_password,
                meta,
            }),
        }),
        Err(e) => {
            // Never leave a volume mounted after a failed setup.
            veracrypt.dismount(&mount, true);
            Err(e)
        }
    }
}

/// Open an existing vault, mounting the container first if one is in use.
pub fn unlock(
    veracrypt: &VeraCrypt,
    config: &Config,
    password: &Secret,
    allow_rollback: bool,
) -> Result<OpenVault> {
    if config.use_container {
        unlock_in_container(veracrypt, config, password, allow_rollback)
    } else {
        unlock_standalone(config, password, allow_rollback)
    }
}

fn unlock_standalone(
    config: &Config,
    password: &Secret,
    allow_rollback: bool,
) -> Result<OpenVault> {
    let path = &config.vault_path;
    if !path.is_file() {
        return Err(Error::config(format!(
            "no vault at {}. Check the path in Settings.",
            path.display()
        )));
    }
    let secret = crypto::combine_secret(password, &config.keyfiles)?;
    let vault = Vault::open(path, &secret, allow_rollback)?;
    Ok(OpenVault {
        vault,
        container: None,
    })
}

fn unlock_in_container(
    veracrypt: &VeraCrypt,
    config: &Config,
    password: &Secret,
    allow_rollback: bool,
) -> Result<OpenVault> {
    let container = &config.container_path;
    if !container.is_file() {
        return Err(Error::config(format!(
            "no container at {}. Check the path in Settings.",
            container.display()
        )));
    }

    let secret = crypto::combine_secret(password, &config.keyfiles)?;
    // The sidecar is authoritative; the copy in settings is the safety net.
    let mut meta = ContainerMeta::load(container, config.container_meta.as_ref())?;
    let (container_password, used) = meta.unwrap_password(&secret)?;

    // Tidy up after an interrupted password change: now that we know which
    // wrapping is the live one, the others are dead weight.
    if meta.wrapped.len() > 1 {
        let live = meta.wrapped[used].clone();
        meta.keep_only(&live);
        let _ = meta.save(container);
    }

    let mount = veracrypt.mount(
        container,
        &container_password,
        &config.keyfiles,
        config.pim,
        false,
    )?;

    let vault_path = mount.path.join(VAULT_FILENAME);
    if !vault_path.is_file() {
        veracrypt.dismount(&mount, true);
        return Err(Error::vault(format!(
            "the container opened, but there is no {VAULT_FILENAME} inside it. \
             This container was not created by Deep Defense."
        )));
    }

    match Vault::open(&vault_path, &secret, allow_rollback) {
        Ok(vault) => Ok(OpenVault {
            vault,
            container: Some(OpenContainer {
                mount,
                password: container_password,
                meta,
            }),
        }),
        Err(e) => {
            veracrypt.dismount(&mount, true);
            Err(e)
        }
    }
}

/// Change the master password for every layer in use.
///
/// Standalone, this is one atomic re-key of the vault file. With a container,
/// the container's own volume password never changes — we re-wrap it under a
/// key derived from the new master password, ordered so that an interruption
/// at any point leaves the vault openable with *one* of the two passwords,
/// never neither:
///
/// 1. add the new wrapping alongside the old one, and persist it;
/// 2. re-key the vault file (atomic, and self-restoring on failure);
/// 3. drop the old wrapping.
pub fn change_master_password(
    open: &mut OpenVault,
    config: &mut Config,
    new_password: &Secret,
    params: KdfParams,
) -> Result<()> {
    params.validate()?;
    let new_secret = crypto::combine_secret(new_password, &config.keyfiles)?;

    let Some(container) = open.container.as_mut() else {
        // Standalone: one file, one re-key, nothing else to keep in step.
        // The Argon2id parameters stay as the file was created with — see
        // `Vault::change_master` for why they cannot move.
        open.vault.change_master(&new_secret)?;
        let _ = config.save();
        return Ok(());
    };

    let container_path = config.container_path.clone();

    // Step 1: both passwords now open the container.
    let new_wrapping = container
        .meta
        .add_wrapping(&container.password, &new_secret, &params)?;
    container.meta.save(&container_path)?;
    config.container_meta = Some(container.meta.clone());
    let _ = config.save();

    // Step 2: re-key the vault. On failure it restores its previous key, and
    // the old password still opens everything.
    open.vault.change_master(&new_secret)?;

    // Step 3: retire the old wrapping.
    container.meta.keep_only(&new_wrapping);
    let _ = container.meta.save(&container_path);
    config.container_meta = Some(container.meta.clone());
    let _ = config.save();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams {
            m_cost: KdfParams::MIN_M_COST,
            t_cost: 2,
            p_cost: 1,
            algorithm: "argon2id".into(),
        }
    }

    /// A config wired for standalone use, pointing into a scratch directory.
    fn standalone_config(dir: &Path) -> Config {
        Config {
            use_container: false,
            vault_path: dir.join("vault.ddv"),
            kdf: params(),
            ..Config::default()
        }
    }

    /// Creating a vault writes a rollback anchor into the app directory, so
    /// these tests need the same lock and the same redirection as the vault
    /// tests — otherwise they write into whichever directory another test has
    /// pointed at, or into the real user profile.
    struct Scratch(crate::config::test_home::TestHome);

    impl Scratch {
        fn new(tag: &str) -> Self {
            Self(crate::config::test_home::TestHome::new(tag))
        }
    }

    #[test]
    fn a_standalone_vault_needs_no_veracrypt_at_all() {
        // The whole point of the default mode: an absent VeraCrypt must not
        // stop anything.
        let scratch = Scratch::new("create");
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let config = standalone_config(scratch.0.path());
        let password = Secret::from_str("master password");

        let open = create_vault(&absent, &config, &password, 0).unwrap();
        assert!(open.container.is_none(), "standalone must not mount anything");
        assert!(config.vault_path.is_file());
        drop(open);

        let reopened = unlock(&absent, &config, &password, false).unwrap();
        assert!(reopened.container.is_none());
    }

    #[test]
    fn a_standalone_vault_round_trips_an_entry() {
        let scratch = Scratch::new("roundtrip");
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let config = standalone_config(scratch.0.path());
        let password = Secret::from_str("pw");

        {
            let mut open = create_vault(&absent, &config, &password, 0).unwrap();
            let mut entry = crate::model::Entry::new("GitHub");
            entry.set_password("s3cret".into());
            open.vault.add(entry).unwrap();
            open.vault.save().unwrap();
        }

        let open = unlock(&absent, &config, &password, true).unwrap();
        assert_eq!(open.vault.data.find("github").unwrap().password, "s3cret");
    }

    #[test]
    fn a_standalone_vault_file_is_ciphertext() {
        let scratch = Scratch::new("ciphertext");
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let config = standalone_config(scratch.0.path());

        let mut open = create_vault(&absent, &config, &Secret::from_str("pw"), 0).unwrap();
        let mut entry = crate::model::Entry::new("Bank");
        entry.set_password("unmistakable-marker".into());
        open.vault.add(entry).unwrap();
        open.vault.save().unwrap();
        drop(open);

        // Without a container there is no outer layer to hide behind, so the
        // file itself must give nothing away.
        let bytes = std::fs::read(&config.vault_path).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("unmistakable-marker"));
        assert!(!text.contains("Bank"));
    }

    #[test]
    fn a_wrong_password_cannot_open_a_standalone_vault() {
        let scratch = Scratch::new("wrongpw");
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let config = standalone_config(scratch.0.path());
        create_vault(&absent, &config, &Secret::from_str("right"), 0).unwrap();

        let err = unlock(&absent, &config, &Secret::from_str("wrong"), true)
            .err()
            .expect("a wrong password must fail");
        assert!(matches!(err, Error::Authentication));
    }

    #[test]
    fn creating_over_an_existing_standalone_vault_is_refused() {
        let scratch = Scratch::new("overwrite");
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let config = standalone_config(scratch.0.path());
        create_vault(&absent, &config, &Secret::from_str("pw"), 0).unwrap();

        let err = create_vault(&absent, &config, &Secret::from_str("other"), 0)
            .err()
            .expect("must not clobber an existing vault");
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn changing_the_master_password_standalone_invalidates_the_old_one() {
        let scratch = Scratch::new("rekey");
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let mut config = standalone_config(scratch.0.path());
        let old = Secret::from_str("old password");
        let new = Secret::from_str("new password");

        {
            let mut open = create_vault(&absent, &config, &old, 0).unwrap();
            let mut entry = crate::model::Entry::new("Server");
            entry.set_password("keep-me".into());
            open.vault.add(entry).unwrap();
            open.vault.save().unwrap();
            change_master_password(&mut open, &mut config, &new, params()).unwrap();
        }

        assert!(matches!(
            unlock(&absent, &config, &old, true).err().unwrap(),
            Error::Authentication
        ));
        let reopened = unlock(&absent, &config, &new, true).unwrap();
        assert_eq!(reopened.vault.data.find("server").unwrap().password, "keep-me");
    }

    #[test]
    fn a_missing_standalone_vault_names_the_path() {
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let config = Config {
            use_container: false,
            vault_path: PathBuf::from(r"C:\definitely\not\here.ddv"),
            ..Config::default()
        };
        let err = unlock(&absent, &config, &Secret::from_str("pw"), true)
            .err()
            .unwrap();
        assert!(err.to_string().contains("here.ddv"));
    }

    #[test]
    fn standalone_vaults_use_the_cipher_cascade() {
        let scratch = Scratch::new("suite");
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        let config = standalone_config(scratch.0.path());
        let open = create_vault(&absent, &config, &Secret::from_str("pw"), 0).unwrap();
        assert_eq!(open.vault.suite(), crate::crypto::Suite::Cascade);
    }

    #[test]
    fn the_container_password_is_unrelated_to_the_master_password() {
        // The whole two-layer argument rests on this.
        let master = Secret::from_str("my master password");
        let (_, container) = ContainerMeta::create(&master, &params()).unwrap();
        assert_ne!(container.expose(), master.expose());
        assert!(!container
            .expose_str()
            .unwrap()
            .contains("my master password"));
    }

    #[test]
    fn two_containers_get_different_passwords() {
        let master = Secret::from_str("same master password");
        let (_, first) = ContainerMeta::create(&master, &params()).unwrap();
        let (_, second) = ContainerMeta::create(&master, &params()).unwrap();
        assert_ne!(first.expose(), second.expose());
    }

    #[test]
    fn the_master_password_recovers_the_container_password() {
        let master = Secret::from_str("pw");
        let (meta, original) = ContainerMeta::create(&master, &params()).unwrap();
        let (recovered, index) = meta.unwrap_password(&master).unwrap();
        assert_eq!(recovered.expose(), original.expose());
        assert_eq!(index, 0);
    }

    #[test]
    fn a_wrong_master_password_does_not_recover_it() {
        let (meta, _) = ContainerMeta::create(&Secret::from_str("right"), &params()).unwrap();
        let err = meta
            .unwrap_password(&Secret::from_str("wrong"))
            .unwrap_err();
        assert!(matches!(err, Error::Authentication));
    }

    #[test]
    fn the_container_password_fits_veracrypts_limit() {
        let (_, container) = ContainerMeta::create(&Secret::from_str("pw"), &params()).unwrap();
        let text = container.expose_str().unwrap();
        assert_eq!(text.len(), 64);
        // VeraCrypt receives it as ASCII on the command line.
        assert!(text.chars().all(|c| c.is_ascii_graphic()));
    }

    #[test]
    fn re_wrapping_lets_a_new_password_open_the_same_container() {
        let old = Secret::from_str("old master");
        let new = Secret::from_str("new master");
        let (mut meta, container) = ContainerMeta::create(&old, &params()).unwrap();

        let fresh = meta.add_wrapping(&container, &new, &params()).unwrap();

        // Mid-change: both passwords work, so an interruption cannot brick it.
        assert_eq!(
            meta.unwrap_password(&old).unwrap().0.expose(),
            container.expose()
        );
        assert_eq!(
            meta.unwrap_password(&new).unwrap().0.expose(),
            container.expose()
        );

        // After the change: only the new one does.
        meta.keep_only(&fresh);
        assert_eq!(
            meta.unwrap_password(&new).unwrap().0.expose(),
            container.expose()
        );
        assert!(meta.unwrap_password(&old).is_err());
    }

    #[test]
    fn keep_only_never_empties_the_metadata() {
        let (mut meta, _) = ContainerMeta::create(&Secret::from_str("pw"), &params()).unwrap();
        // Pruning to something absent must not leave the container unopenable.
        meta.keep_only("not-a-real-wrapping");
        assert_eq!(meta.wrapped.len(), 1);
    }

    #[test]
    fn the_sidecar_sits_next_to_the_container() {
        let path = ContainerMeta::sidecar_path(Path::new(r"C:\vaults\secrets.hc"));
        assert!(path.to_string_lossy().ends_with("secrets.hc.ddmeta"));
    }

    #[test]
    fn a_missing_sidecar_is_recovered_from_the_settings_copy() {
        let dir = std::env::temp_dir().join(format!("dd-meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let container = dir.join("box.hc");
        std::fs::write(&container, b"not a real container").unwrap();

        let (original, _) = ContainerMeta::create(&Secret::from_str("pw"), &params()).unwrap();
        let loaded = ContainerMeta::load(&container, Some(&original)).unwrap();
        assert_eq!(loaded.wrapped, original.wrapped);
        // The fallback path rewrites the sidecar so it is there next time.
        assert!(ContainerMeta::sidecar_path(&container).is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_sidecar_and_no_fallback_is_a_clear_error() {
        let missing = Path::new(r"C:\definitely\not\here.hc");
        let err = ContainerMeta::load(missing, None).unwrap_err();
        assert!(err.to_string().contains("ddmeta"));
    }
}
