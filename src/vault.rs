//! Reading, writing and mutating the encrypted vault file.
//!
//! The file normally sits wherever the user keeps it; with the optional
//! container layer it sits inside the mounted volume instead. Either way it is
//! sealed by [`crate::crypto`] first, so it is ciphertext on disk and on a
//! mounted drive alike. Nothing here ever writes a plaintext secret.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, KeyInit as MacInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::{app_dir, ensure_app_dir};
use crate::crypto::{self, KdfParams};
use crate::slots::{self, SlotFile};
use crate::errors::{Error, Result};
use crate::model::{AuditAction, Entry, VaultData};
use crate::secret::{Key, Secret};

/// How many previous vault files to keep beside the current one.
const BACKUP_COUNT: usize = 5;
const ANCHOR_FILENAME: &str = "revision.anchor";
const ANCHOR_CONTEXT: &[u8] = b"deep-defense/rollback-anchor/v1";

/// A tamper-evident note of the highest revision we have seen for a vault.
///
/// It lives outside the container on purpose. Inside, an attacker who can
/// swap the vault file can swap the anchor with it; outside, they would have
/// to compromise two places at once — and forging the MAC needs the master
/// key they are trying to attack.
#[derive(Serialize, Deserialize)]
struct Anchor {
    vault_id: String,
    revision: u64,
    mac: String,
}

fn anchor_path() -> PathBuf {
    app_dir().join(ANCHOR_FILENAME)
}

/// The version of the store written since there has been a record per slot.
const ANCHOR_STORE_VERSION: u32 = 2;
const ANCHOR_SEAL_INFO: &[u8] = b"deep-defense/rollback-anchor/seal/v2";
const ANCHOR_NONCE_LEN: usize = 24;
/// Nonce, the revision as eight bytes, and the tag.
const ANCHOR_SEALED_LEN: usize = ANCHOR_NONCE_LEN + 8 + 16;
/// Years of password changes across several vaults. Past it, the records
/// untouched longest go first.
const MAX_ANCHOR_ENTRIES: usize = 64;
const MACHINE_TAG_CONTEXT: &[u8] = b"deep-defense/machine/v1";

/// One slot's record in the store.
///
/// The revision is sealed rather than written out: a plain number would show
/// which records belong to vaults in use and which are placeholders, and a
/// placeholder for a slot is only worth anything if it cannot be told apart
/// from a real record.
#[derive(Clone, Serialize, Deserialize)]
struct AnchorEntry {
    id: String,
    sealed: String,
}

/// Every record this computer holds, for every vault file it has seen.
#[derive(Default, Serialize, Deserialize)]
struct AnchorStore {
    version: u32,
    entries: Vec<AnchorEntry>,
}

/// What is on disk where the store should be.
enum StoredAnchors {
    Missing,
    /// Present, but not something this program wrote. Kept as evidence rather
    /// than overwritten on the spot.
    Unreadable,
    Store(AnchorStore),
    /// The single record earlier builds wrote.
    Legacy(Anchor),
}

fn read_anchors() -> StoredAnchors {
    let text = match std::fs::read_to_string(anchor_path()) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StoredAnchors::Missing,
        Err(_) => return StoredAnchors::Unreadable,
    };
    if let Ok(store) = serde_json::from_str::<AnchorStore>(&text) {
        if store.version == ANCHOR_STORE_VERSION {
            return StoredAnchors::Store(store);
        }
    }
    match serde_json::from_str::<Anchor>(&text) {
        Ok(anchor) => StoredAnchors::Legacy(anchor),
        Err(_) => StoredAnchors::Unreadable,
    }
}

/// The identifier a slot has, from its salt and its position.
///
/// Hashed rather than used directly so the store, which lives outside the
/// vault, never carries a copy of a salt.
fn id_for(salt: &[u8], slot: usize) -> String {
    let mut digest = Sha256::new();
    digest.update(b"deep-defense/vault-id/v2");
    digest.update(salt);
    digest.update([slot as u8]);
    hex(&digest.finalize()[..16])
}

/// What an absent record means, given whether one was ever made here.
fn absent_record(seen_here: bool) -> AnchorState {
    if seen_here {
        AnchorState::Removed
    } else {
        AnchorState::FirstSeenHere
    }
}

/// Random bytes the shape of a sealed record, for slots this vault is not.
fn placeholder_seal() -> Option<String> {
    let mut raw = [0u8; ANCHOR_SEALED_LEN];
    crypto::random_bytes(&mut raw).ok()?;
    Some(BASE64.encode(raw))
}

/// This computer's identity, as far as the vault is concerned.
fn this_machine_id() -> Option<String> {
    // Tests move a vault between "computers" without leaving the one they run
    // on; nothing outside a test build reads this.
    #[cfg(test)]
    if let Ok(forced) = std::env::var("DEEP_DEFENSE_TEST_MACHINE") {
        return Some(forced);
    }
    crate::platform::machine_id()
}

/// What the rollback check was actually able to establish.
///
/// The check used to answer `Ok(())` in five different situations, only one of
/// which meant "verified". The other four meant "I had nothing to compare
/// against" — which is the same answer a swapped file would produce, and the
/// user was never told the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorState {
    /// An anchor for this vault existed, its MAC checked out, and the
    /// revision on disk is not behind it.
    Verified,
    /// No anchor for this vault on this machine: a first run, or a first run
    /// *here* after moving the file. Rollback protection did not apply to this
    /// open, which matters most in exactly that situation.
    FirstSeenHere,
    /// An anchor exists but could not be authenticated, so it says nothing.
    Unverifiable,
    /// This vault has had a record on this computer before, and now there is
    /// none. Either it was deleted — which is exactly what someone swapping
    /// in an older file would do first — or this is an older copy of the file,
    /// from before it was first opened here. Neither should pass in silence.
    Removed,
}

impl AnchorState {
    /// Whether the user should be told. `Verified` is the silent case.
    pub fn is_noteworthy(self) -> bool {
        !matches!(self, AnchorState::Verified)
    }
}

/// What a resize did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub old_capacity: usize,
    pub new_capacity: usize,
    /// Whether the other slot was carried across rather than discarded.
    pub other_slot_carried: bool,
    /// Whether the cost of a password guess changed, which re-keys the file.
    pub kdf_changed: bool,
}

fn backup_path_for(path: &Path, index: usize) -> PathBuf {
    let mut name = path.to_path_buf();
    let file_name = name
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault.ddv".into());
    name.set_file_name(format!("{file_name}.bak{index}"));
    name
}

/// Shift the numbered backups along and copy the current file to `.bak1`.
///
/// Shared by the vault directory and the mirror, so a mirror is a real
/// rotation rather than a single overwritten copy — otherwise one bad save
/// propagated to the mirror would destroy the only off-site history.
fn rotate_backups_at(path: &Path) {
    if !path.is_file() {
        return;
    }
    let _ = std::fs::remove_file(backup_path_for(path, BACKUP_COUNT));
    for index in (1..BACKUP_COUNT).rev() {
        let from = backup_path_for(path, index);
        if from.is_file() {
            let _ = std::fs::rename(&from, backup_path_for(path, index + 1));
        }
    }
    let _ = std::fs::copy(path, backup_path_for(path, 1));
}

/// One of the numbered backups beside a vault file.
#[derive(Debug, Clone)]
pub struct Backup {
    /// 1 is the newest.
    pub index: usize,
    pub path: PathBuf,
    pub modified: Option<std::time::SystemTime>,
    pub bytes: u64,
}

/// Where backup `index` of `vault_path` lives.
pub fn backup_path(vault_path: &Path, index: usize) -> PathBuf {
    backup_path_for(vault_path, index)
}

/// The backups that exist beside `vault_path`, newest first.
pub fn list_backups(vault_path: &Path) -> Vec<Backup> {
    (1..=BACKUP_COUNT)
        .filter_map(|index| {
            let path = backup_path_for(vault_path, index);
            let meta = std::fs::metadata(&path).ok()?;
            meta.is_file().then(|| Backup {
                index,
                modified: meta.modified().ok(),
                bytes: meta.len(),
                path,
            })
        })
        .collect()
}

/// Put backup `index` back as the vault file. Nothing may have the vault open.
pub fn restore_backup(vault_path: &Path, index: usize) -> Result<()> {
    if !(1..=BACKUP_COUNT).contains(&index) {
        return Err(Error::format("there is no backup with that number"));
    }
    let source = backup_path_for(vault_path, index);
    let bytes = std::fs::read(&source).map_err(|e| Error::io(source.clone(), e))?;
    restore_backup_bytes(vault_path, &bytes)
}

/// Make `bytes` the vault file.
///
/// The bytes are checked to be a vault file before anything on disk is
/// touched: restoring something that is not one would replace the real vault
/// with a file that opens nothing. The file being replaced becomes backup 1,
/// so a restore can be undone the same way it was done.
///
/// Opening the result will be reported as a rollback, correctly — it is older
/// than the record says it should be — and the usual prompt asks whether that
/// was intended.
pub fn restore_backup_bytes(vault_path: &Path, bytes: &[u8]) -> Result<()> {
    SlotFile::parse(bytes)?;
    rotate_backups_at(vault_path);
    let tmp = vault_path.with_extension("ddv.restore-tmp");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp).map_err(|e| Error::io(tmp.clone(), e))?;
        file.write_all(bytes).map_err(|e| Error::io(tmp.clone(), e))?;
        file.sync_all().map_err(|e| Error::io(tmp.clone(), e))?;
    }
    crate::platform::rename_durably(&tmp, vault_path)
}

/// An open vault. Build one with [`Vault::create`] or [`Vault::open`].
///
/// Holds the whole file, not just its own slot: saving rewrites one slot and
/// copies the rest through untouched, which is what keeps a hidden vault
/// intact while the decoy is edited.
pub struct Vault {
    pub path: PathBuf,
    pub data: VaultData,
    file: SlotFile,
    slot: usize,
    /// Fixed for the life of the slot. Only the per-save seed changes, so the
    /// expensive Argon2id pass happens once per unlock rather than per save.
    salt: Vec<u8>,
    master_key: Key,
    dirty: bool,
    /// What the last rollback check established. Reported, not enforced.
    anchor: AnchorState,
    /// A second directory to copy every save into.
    ///
    /// The rotation of `.bak` files lives beside the vault, which makes five
    /// copies of one point of failure: one dying disk, or one directory
    /// reached by ransomware, takes all six at once.
    mirror: Option<PathBuf>,
    /// Why the last mirror copy failed. A mirror that cannot be written is
    /// worth saying out loud, and is never a reason to fail the save itself.
    mirror_error: Option<String>,
}

/// Never prints the key or any entry: this type exists to hold secrets.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("entries", &self.data.entries.len())
            .field("revision", &self.data.revision)
            .field("dirty", &self.dirty)
            // Deliberately omits which slot is open: a debug line naming the
            // hidden slot would undo the point of having one.
            .finish_non_exhaustive()
    }
}

impl Vault {
    // ------------------------------------------------------------ lifecycle

    /// Create a vault in the primary slot of a new file.
    pub fn create(path: &Path, secret: &Secret, params: KdfParams) -> Result<Self> {
        Self::create_in_slot(path, secret, params, slots::PRIMARY_SLOT, None)
    }

    /// Create a vault in a specific slot.
    ///
    /// `capacity` is only honoured for a new file; an existing one keeps the
    /// slot size it was made with, because every slot has to be the same size
    /// for the padding to hide anything.
    pub fn create_in_slot(
        path: &Path,
        secret: &Secret,
        params: KdfParams,
        slot: usize,
        capacity: Option<usize>,
    ) -> Result<Self> {
        let file = if path.exists() {
            // Adding a hidden vault to a file that already holds a decoy: the
            // existing slots must survive untouched.
            let bytes = std::fs::read(path).map_err(|e| Error::io(path.to_path_buf(), e))?;
            SlotFile::parse(&bytes)?
        } else {
            let header =
                slots::FileHeader::new(params, capacity.unwrap_or(slots::DEFAULT_SLOT_CAPACITY))?;
            SlotFile::new_random(header)?
        };

        let (master_key, salt) = file.prepare_slot(secret)?;
        let mut data = VaultData::default();
        data.record(AuditAction::Created, "");
        let mut vault = Self {
            path: path.to_path_buf(),
            data,
            file,
            slot,
            salt,
            master_key,
            dirty: true,
            // A vault created here is the newest thing there is; the anchor
            // written by the save below is authoritative from that moment.
            anchor: AnchorState::Verified,
            mirror: None,
            mirror_error: None,
        };
        vault.note_this_machine();
        vault.save()?;
        Ok(vault)
    }

    /// Open whichever slot this password belongs to.
    ///
    /// The caller is not told which slot was tried and failed, only that the
    /// password did not open anything — the program must behave identically
    /// whether or not a second vault exists.
    pub fn open(path: &Path, secret: &Secret, allow_rollback: bool) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| Error::io(path.to_path_buf(), e))?;
        let file = SlotFile::parse(&bytes)?;
        let (slot, opened) = file.open_any(secret)?;

        let data: VaultData = serde_json::from_slice(&opened.payload).map_err(|e| {
            Error::vault(format!(
                "the vault decrypted correctly but its contents are unreadable ({e}). \
                 Try one of the .bak files beside it."
            ))
        })?;

        let mut vault = Self {
            path: path.to_path_buf(),
            data,
            file,
            slot,
            salt: opened.salt,
            master_key: opened.master_key,
            dirty: false,
            anchor: AnchorState::Verified,
            mirror: None,
            mirror_error: None,
        };

        vault.anchor = if allow_rollback {
            // The user chose to open an older file knowingly. Reset the
            // anchor to it, or every later open would report the same thing.
            vault.write_anchor();
            AnchorState::Verified
        } else {
            vault.check_rollback()?
        };

        // The first open on a computer is saved at once, so that from here on
        // a missing record on this computer means something. Once per computer
        // per vault; a failure only postpones it to the next save.
        if vault.note_this_machine() {
            vault.dirty = true;
            let _ = vault.save();
        }
        Ok(vault)
    }

    /// Pull in any slot written since we opened the file.
    ///
    /// A missing or unreadable file is not an error here: `save` will simply
    /// write ours out fresh, which is the right outcome if the file was
    /// deleted underneath us.
    fn refresh_other_slots(&mut self) -> Result<()> {
        let Ok(bytes) = std::fs::read(&self.path) else {
            return Ok(());
        };
        let Ok(current) = SlotFile::parse(&bytes) else {
            return Ok(());
        };
        self.file.adopt_other_slots(&current, self.slot)
    }

    /// Whether a second vault can be added to this file under another password.
    ///
    /// Answering honestly is safe here: the vault is already open, so whoever
    /// is asking has the password. Reads from disk rather than from our own
    /// copy, which may predate a hidden vault created moments ago.
    pub fn hidden_slot_is_free(&self, candidate: &Secret) -> bool {
        if self.slot == slots::HIDDEN_SLOT {
            return false;
        }
        match self.current_file() {
            Ok(file) => !file.slot_opens(slots::HIDDEN_SLOT, candidate),
            Err(_) => !self.file.slot_opens(slots::HIDDEN_SLOT, candidate),
        }
    }

    fn current_file(&self) -> Result<SlotFile> {
        let bytes = std::fs::read(&self.path).map_err(|e| Error::io(self.path.clone(), e))?;
        SlotFile::parse(&bytes)
    }

    /// Whether this secret is the one that opens the slot we have open.
    ///
    /// Runs the same derivation an unlock would and checks it against the
    /// slot, so a candidate password can be confirmed as current without
    /// being shown, stored, or compared against anything we keep in memory in
    /// plaintext. Answering honestly is safe: the vault is already open, so
    /// whoever is asking has the password.
    pub fn secret_opens_this_slot(&self, secret: &Secret) -> bool {
        self.file.slot_opens(self.slot, secret)
    }

    /// True when the open vault is the hidden one.
    pub fn is_hidden(&self) -> bool {
        self.slot == slots::HIDDEN_SLOT
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// What the rollback check managed to establish when this vault opened.
    pub fn anchor_state(&self) -> AnchorState {
        self.anchor
    }

    /// The size of each slot in this file, fixed when the file was created.
    pub fn slot_capacity(&self) -> usize {
        self.file.header.slot_capacity
    }

    /// Point saves at a second directory, or pass `None` to stop mirroring.
    pub fn set_mirror(&mut self, directory: Option<PathBuf>) {
        self.mirror = directory;
        self.mirror_error = None;
    }

    pub fn mirror(&self) -> Option<&Path> {
        self.mirror.as_deref()
    }

    /// Why the last mirror copy failed, if it did.
    pub fn mirror_error(&self) -> Option<&str> {
        self.mirror_error.as_deref()
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn kdf(&self) -> &KdfParams {
        &self.file.header.kdf
    }

    pub fn suite(&self) -> crypto::Suite {
        crypto::Suite::Cascade
    }

    /// Room left in this slot, in bytes, for attachments and entries.
    pub fn free_capacity(&self) -> usize {
        let used = serde_json::to_vec(&self.data).map(|v| v.len()).unwrap_or(0);
        self.file.header.max_payload().saturating_sub(used)
    }

    // ------------------------------------------------------- rollback anchor

    /// Stable per-slot identifier, derived from the slot's (secret) salt.
    fn vault_id(&self) -> String {
        id_for(&self.salt, self.slot)
    }

    /// The identifier of every slot in this file, as if each held a vault.
    ///
    /// Computable by anyone holding the file: the first bytes of a slot are
    /// its salt when it holds a vault and random noise when it does not, and
    /// the two cannot be told apart — so neither can the identifiers.
    fn slot_ids(&self) -> Vec<String> {
        (0..slots::SLOT_COUNT)
            .map(|index| {
                if index == self.slot {
                    self.vault_id()
                } else {
                    id_for(self.file.slot_salt(index), index)
                }
            })
            .collect()
    }

    fn anchor_mac(&self, revision: u64) -> Result<Vec<u8>> {
        let mut mac = <Hmac<Sha256> as MacInit>::new_from_slice(self.master_key.as_bytes())
            .map_err(|e| Error::crypto(format!("anchor MAC setup failed: {e}")))?;
        mac.update(ANCHOR_CONTEXT);
        mac.update(self.vault_id().as_bytes());
        mac.update(&revision.to_be_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// The key the stored revision is sealed under.
    fn anchor_key(&self) -> Option<Key> {
        let hkdf = hkdf::Hkdf::<Sha256>::new(None, self.master_key.as_bytes());
        let mut key = Key::zeroed();
        hkdf.expand(ANCHOR_SEAL_INFO, key.as_mut()).ok()?;
        Some(key)
    }

    fn seal_revision(&self, id: &str, revision: u64) -> Option<String> {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        let key = self.anchor_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).ok()?;
        // Random, not derived: the same key seals this record every time it is
        // written, so the nonce is what keeps two writes from colliding.
        let mut nonce = [0u8; ANCHOR_NONCE_LEN];
        crypto::random_bytes(&mut nonce).ok()?;
        let body = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &revision.to_be_bytes(),
                    aad: id.as_bytes(),
                },
            )
            .ok()?;
        let mut raw = nonce.to_vec();
        raw.extend_from_slice(&body);
        Some(BASE64.encode(raw))
    }

    fn open_revision(&self, entry: &AnchorEntry) -> Option<u64> {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        let raw = BASE64.decode(&entry.sealed).ok()?;
        if raw.len() != ANCHOR_SEALED_LEN {
            return None;
        }
        let (nonce, body) = raw.split_at(ANCHOR_NONCE_LEN);
        let nonce: [u8; ANCHOR_NONCE_LEN] = nonce.try_into().ok()?;
        let key = self.anchor_key()?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).ok()?;
        let plain = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: body,
                    aad: entry.id.as_bytes(),
                },
            )
            .ok()?;
        let bytes: [u8; 8] = plain.as_slice().try_into().ok()?;
        Some(u64::from_be_bytes(bytes))
    }

    /// Record the current revision. Failure here degrades rollback detection
    /// but must never stop the user from saving their passwords.
    ///
    /// Writes a record for every slot of this file, not just its own: a real
    /// one for this vault, and a placeholder for any other slot that has none
    /// yet. That way the store looks the same whether or not a hidden vault
    /// exists, and a hidden vault opened here later finds a slot waiting.
    /// A record some other vault wrote is never touched.
    fn write_anchor(&self) {
        let own = self.vault_id();
        let Some(sealed) = self.seal_revision(&own, self.data.revision) else {
            return;
        };
        let mut store = match read_anchors() {
            StoredAnchors::Store(store) => store,
            // An older single record, or something unreadable: whatever it
            // said about this vault, the record written now says it better.
            _ => AnchorStore::default(),
        };
        store.version = ANCHOR_STORE_VERSION;

        // This file's records go to the end, in slot order, so the ones
        // untouched longest are the first to go when the store is full.
        let mut this_file = Vec::with_capacity(slots::SLOT_COUNT);
        for id in self.slot_ids() {
            let existing = store
                .entries
                .iter()
                .position(|entry| entry.id == id)
                .map(|at| store.entries.remove(at));
            let entry = if id == own {
                AnchorEntry {
                    id,
                    sealed: sealed.clone(),
                }
            } else if let Some(entry) = existing {
                entry
            } else {
                let Some(sealed) = placeholder_seal() else {
                    return;
                };
                AnchorEntry { id, sealed }
            };
            this_file.push(entry);
        }
        store.entries.extend(this_file);
        let excess = store.entries.len().saturating_sub(MAX_ANCHOR_ENTRIES);
        store.entries.drain(..excess);

        if ensure_app_dir().is_err() {
            return;
        }
        let Ok(text) = serde_json::to_string(&store) else {
            return;
        };
        let path = anchor_path();
        let tmp = path.with_extension("anchor.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = crate::platform::rename_durably(&tmp, &path);
        }
    }

    fn check_rollback(&self) -> Result<AnchorState> {
        // Whether this vault has had a record on this computer before — the
        // one fact that separates "the record was deleted" from "never here".
        let seen_here = self.seen_on_this_machine();
        let own = self.vault_id();

        let state = match read_anchors() {
            // Kept as it is: whatever put it there, overwriting it now would
            // destroy the only evidence.
            StoredAnchors::Unreadable => return Ok(AnchorState::Unverifiable),
            StoredAnchors::Missing => absent_record(seen_here),
            StoredAnchors::Legacy(anchor) => {
                if anchor.vault_id != own {
                    absent_record(seen_here)
                } else {
                    let genuine = BASE64
                        .decode(&anchor.mac)
                        .ok()
                        .zip(self.anchor_mac(anchor.revision).ok())
                        .is_some_and(|(recorded, expected)| constant_time_eq(&expected, &recorded));
                    if !genuine {
                        return Ok(AnchorState::Unverifiable);
                    }
                    if anchor.revision > self.data.revision {
                        return Err(Error::Rollback {
                            on_disk: self.data.revision,
                            expected: anchor.revision,
                        });
                    }
                    AnchorState::Verified
                }
            }
            StoredAnchors::Store(store) => match store.entries.iter().find(|entry| entry.id == own) {
                None => absent_record(seen_here),
                Some(entry) => match self.open_revision(entry) {
                    Some(revision) if revision > self.data.revision => {
                        return Err(Error::Rollback {
                            on_disk: self.data.revision,
                            expected: revision,
                        })
                    }
                    Some(_) => AnchorState::Verified,
                    // A record under this vault's identifier that its key
                    // cannot open. After this vault has been here, that is a
                    // record replaced or tampered with. Before, it is the
                    // placeholder the other slot of this file left for it.
                    None if seen_here => return Ok(AnchorState::Unverifiable),
                    None => AnchorState::FirstSeenHere,
                },
            },
        };
        self.write_anchor();
        Ok(state)
    }

    // ------------------------------------------------------ which computers

    /// This computer's tag for this vault.
    ///
    /// Keyed with a secret kept inside the vault, so the list of tags says
    /// nothing to anyone who has not opened it — and even then only answers
    /// "was it this machine?", never "which machines were they?".
    fn machine_tag(&self) -> Option<String> {
        let key = unhex(&self.data.machine_key.0)?;
        let machine = this_machine_id()?;
        let mut mac = <Hmac<Sha256> as MacInit>::new_from_slice(&key).ok()?;
        mac.update(MACHINE_TAG_CONTEXT);
        mac.update(machine.as_bytes());
        Some(hex(&mac.finalize().into_bytes()[..16]))
    }

    fn seen_on_this_machine(&self) -> bool {
        self.machine_tag()
            .is_some_and(|tag| self.data.anchored_on.contains(&tag))
    }

    /// Add this computer to the vault's list. Returns whether anything changed.
    fn note_this_machine(&mut self) -> bool {
        if this_machine_id().is_none() {
            return false;
        }
        if self.data.machine_key.0.is_empty() {
            let mut key = [0u8; 32];
            if crypto::random_bytes(&mut key).is_err() {
                return false;
            }
            self.data.machine_key = crate::model::MachineKey(hex(&key));
        }
        let Some(tag) = self.machine_tag() else {
            return false;
        };
        if self.data.anchored_on.contains(&tag) {
            return false;
        }
        self.data.anchored_on.push(tag);
        true
    }

    /// Write the anchor somewhere the user can carry it.
    ///
    /// The anchor is per-machine, so moving a vault to a new computer silently
    /// leaves the first open there unprotected — which is the one open where a
    /// swapped file is most likely. Carrying the anchor across closes that gap.
    /// It is safe to copy: it holds a hash, a number and a MAC, and forging it
    /// needs the master key.
    pub fn export_anchor(&self, path: &Path) -> Result<()> {
        let mac = self.anchor_mac(self.data.revision)?;
        let anchor = Anchor {
            vault_id: self.vault_id(),
            revision: self.data.revision,
            mac: BASE64.encode(mac),
        };
        let text = serde_json::to_string_pretty(&anchor)
            .map_err(|e| Error::vault(format!("cannot write the anchor: {e}")))?;
        std::fs::write(path, text).map_err(|e| Error::io(path.to_path_buf(), e))
    }

    /// Adopt an anchor carried from another machine.
    ///
    /// Refuses anything it cannot authenticate with the master key, so a
    /// planted anchor cannot be used to make a current vault look rolled back.
    pub fn import_anchor(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path.to_path_buf(), e))?;
        let anchor: Anchor = serde_json::from_str(&text)
            .map_err(|e| Error::format(format!("that is not an anchor file ({e})")))?;

        if anchor.vault_id != self.vault_id() {
            return Err(Error::format("that anchor belongs to a different vault"));
        }
        let recorded = BASE64
            .decode(&anchor.mac)
            .map_err(|_| Error::format("that anchor is damaged"))?;
        let expected = self.anchor_mac(anchor.revision)?;
        if !constant_time_eq(&expected, &recorded) {
            return Err(Error::format(
                "that anchor was not written for this vault by this password",
            ));
        }

        if anchor.revision > self.data.revision {
            return Err(Error::Rollback {
                on_disk: self.data.revision,
                expected: anchor.revision,
            });
        }

        // Ours is at least as new, so recording it is what keeps the guarantee
        // going forward.
        self.write_anchor();
        self.anchor = AnchorState::Verified;
        Ok(())
    }

    // ----------------------------------------------------------- persistence

    /// Seal and write atomically, keeping a rotation of backups.
    ///
    /// Order matters: rotate first, write to a sibling temp file, flush to
    /// the platter, then rename. A crash at any point leaves either the old
    /// file or the new one — never a half-written vault.
    /// Seal this slot and write the whole file atomically.
    ///
    /// Order matters: rotate backups first, write to a sibling temp file,
    /// flush to the platter, then rename. A crash at any point leaves either
    /// the old file or the new one — never a half-written vault, which for a
    /// multi-slot file would mean losing the other slot too.
    pub fn save(&mut self) -> Result<()> {
        // Re-read first: another slot may have been written since we opened
        // the file — most importantly by `create_hidden` — and our in-memory
        // copy of it would be stale. Writing that back would erase a hidden
        // vault without a word.
        self.refresh_other_slots()?;
        self.persist()
    }

    /// The write itself, without re-reading the file first.
    ///
    /// Split out for `migrate_capacity`, which deliberately replaces the whole
    /// file: adopting slots from the old one would mean adopting its header,
    /// which is the very thing being changed.
    fn persist(&mut self) -> Result<()> {
        self.data.bump();
        let payload = Zeroizing::new(
            serde_json::to_vec(&self.data)
                .map_err(|e| Error::vault(format!("cannot serialise the vault: {e}")))?,
        );
        // Only our slot is touched; the others are copied through byte for
        // byte, including a hidden vault we have no password for.
        self.file
            .write_slot(self.slot, &payload, &self.master_key, &self.salt)?;
        drop(payload);
        let blob = self.file.to_bytes();

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent.to_path_buf(), e))?;
        }
        self.rotate_backups();

        let tmp = self.path.with_extension("ddv.tmp");
        {
            use std::io::Write;
            let mut file =
                std::fs::File::create(&tmp).map_err(|e| Error::io(tmp.clone(), e))?;
            file.write_all(&blob).map_err(|e| Error::io(tmp.clone(), e))?;
            // Without this, a power cut can leave the rename committed and
            // the contents not.
            file.sync_all().map_err(|e| Error::io(tmp.clone(), e))?;
        }
        crate::platform::rename_durably(&tmp, &self.path)?;

        self.dirty = false;
        self.write_anchor();
        self.write_mirror(&blob);
        Ok(())
    }

    /// Copy the saved file to the mirror directory, if one is set.
    ///
    /// Records a failure rather than returning one. A missing memory stick
    /// must not stand between the user and saving their passwords — but it
    /// must not pass unmentioned either, or the mirror quietly stops being a
    /// backup while still looking like one.
    fn write_mirror(&mut self, blob: &[u8]) {
        self.mirror_error = None;
        let Some(directory) = self.mirror.clone() else {
            return;
        };
        if let Err(e) = self.try_mirror(&directory, blob) {
            self.mirror_error = Some(e.to_string());
        }
    }

    fn try_mirror(&self, directory: &Path, blob: &[u8]) -> Result<()> {
        let name = self
            .path
            .file_name()
            .ok_or_else(|| Error::vault("the vault has no file name to mirror"))?;
        let target = directory.join(name);

        // Mirroring onto the vault itself would rotate the real backups on
        // every save and, worse, look like it was working.
        if target == self.path {
            return Err(Error::format(
                "the mirror directory is where the vault already lives",
            ));
        }

        std::fs::create_dir_all(directory)
            .map_err(|e| Error::io(directory.to_path_buf(), e))?;
        rotate_backups_at(&target);

        let tmp = target.with_extension("ddv.mirror-tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp).map_err(|e| Error::io(tmp.clone(), e))?;
            file.write_all(blob).map_err(|e| Error::io(tmp.clone(), e))?;
            file.sync_all().map_err(|e| Error::io(tmp.clone(), e))?;
        }
        crate::platform::rename_durably(&tmp, &target)?;
        Ok(())
    }

    // -------------------------------------------------------------- resizing

    /// Rebuild the file with a different slot size.
    ///
    /// The slot size is fixed when a file is created, because every slot has
    /// to be the same size for the padding to hide which ones are in use. That
    /// left anyone who filled a vault with scans stuck: the only way out was
    /// to export to plaintext and start again.
    ///
    /// `other_slot` is the password of the slot this vault is *not* in. Given
    /// one, that vault is carried across; given `None`, the slot is refilled
    /// with fresh random bytes and anything in it is gone. The caller has to
    /// decide, because from inside one slot there is no way to tell whether
    /// the other holds a vault or noise — which is the whole point of the
    /// format.
    pub fn migrate_capacity(
        &mut self,
        new_capacity: usize,
        other_slot: Option<&Secret>,
    ) -> Result<MigrationReport> {
        let kdf = self.file.header.kdf.clone();
        self.rebuild(new_capacity, kdf, None, other_slot)
    }

    /// Rebuild the file with a different slot size, a different work factor,
    /// or both.
    ///
    /// `own` is this vault's master password. It is required whenever the work
    /// factor changes and ignored otherwise: new Argon2 parameters produce a
    /// different key from the same password, and the key we are holding was
    /// made with the old ones, so it cannot be reproduced under the new ones.
    /// It is verified against the current slot before anything is written —
    /// re-keying to a password that is not the current one would seal the
    /// vault with a string nobody knows.
    ///
    /// `other_slot` is the password of the slot this vault is *not* in, and
    /// carries that vault across. Without it the slot is refilled with fresh
    /// random bytes. When the work factor changes this is stricter than it
    /// looks: the other slot's key cannot be re-derived from what we can read,
    /// so its password is the only way for it to survive.
    pub fn rebuild(
        &mut self,
        new_capacity: usize,
        new_kdf: KdfParams,
        own: Option<&Secret>,
        other_slot: Option<&Secret>,
    ) -> Result<MigrationReport> {
        let old_capacity = self.file.header.slot_capacity;
        let kdf_changed = new_kdf != self.file.header.kdf;
        if new_capacity == old_capacity && !kdf_changed {
            return Err(Error::format("that would change nothing"));
        }
        new_kdf.validate()?;

        let header = slots::FileHeader::new(new_kdf, new_capacity)?;
        let payload = Zeroizing::new(
            serde_json::to_vec(&self.data)
                .map_err(|e| Error::vault(format!("cannot serialise the vault: {e}")))?,
        );
        if payload.len() > header.max_payload() {
            return Err(Error::format(format!(
                "this vault holds {} bytes and would not fit in the new size",
                payload.len()
            )));
        }

        // Work from the freshest copy on disk, not our snapshot of it.
        self.refresh_other_slots()?;

        let own = if kdf_changed {
            let secret = own.ok_or_else(|| {
                Error::format("changing the work factor needs the master password")
            })?;
            if !self.file.slot_opens(self.slot, secret) {
                return Err(Error::Authentication);
            }
            Some(secret)
        } else {
            None
        };

        let other_index = if self.slot == slots::PRIMARY_SLOT {
            slots::HIDDEN_SLOT
        } else {
            slots::PRIMARY_SLOT
        };
        let carried = match other_slot {
            Some(secret) => {
                let opened = self.file.open_slot(other_index, secret)?;
                if opened.payload.len() > header.max_payload() {
                    return Err(Error::format(
                        "the other vault in this file would not fit in the new size",
                    ));
                }
                Some((opened, secret))
            }
            None => None,
        };

        let mut fresh = slots::SlotFile::new_random(header)?;

        // Derived against the *new* header, so the cost written into the file
        // and the cost the key was made with are the same thing.
        let rekeyed = match own {
            Some(secret) => Some(fresh.prepare_slot(secret)?),
            None => None,
        };
        {
            let (key, salt) = match &rekeyed {
                Some((key, salt)) => (key, salt.as_slice()),
                None => (&self.master_key, self.salt.as_slice()),
            };
            fresh.write_slot(self.slot, &payload, key, salt)?;
        }

        if let Some((opened, secret)) = &carried {
            let re = if kdf_changed {
                Some(fresh.prepare_slot(secret)?)
            } else {
                None
            };
            let (key, salt) = match &re {
                Some((key, salt)) => (key, salt.as_slice()),
                None => (&opened.master_key, opened.salt.as_slice()),
            };
            fresh.write_slot(other_index, &opened.payload, key, salt)?;
        }

        self.file = fresh;
        if let Some((key, salt)) = rekeyed {
            self.master_key = key;
            self.salt = salt;
        }

        if new_capacity != old_capacity {
            self.data.record(
                AuditAction::VaultResized,
                format!("{old_capacity} -> {new_capacity}"),
            );
        }
        if kdf_changed {
            self.data
                .record(
                    AuditAction::WorkFactorChanged,
                    format!(
                        "{} MiB x{}",
                        self.file.header.kdf.memory_mib(),
                        self.file.header.kdf.t_cost
                    ),
                );
        }
        self.dirty = true;
        // `persist`, not `save`: re-reading would pull slots sealed against
        // the old header, which no longer authenticates them.
        self.persist()?;

        Ok(MigrationReport {
            old_capacity,
            new_capacity,
            other_slot_carried: carried.is_some(),
            kdf_changed,
        })
    }

    fn backup_path(&self, index: usize) -> PathBuf {
        backup_path_for(&self.path, index)
    }

    fn rotate_backups(&self) {
        rotate_backups_at(&self.path);
    }

    /// Backup files that exist beside the vault, newest first.
    pub fn available_backups(&self) -> Vec<PathBuf> {
        (1..=BACKUP_COUNT)
            .map(|i| self.backup_path(i))
            .filter(|p| p.is_file())
            .collect()
    }

    // -------------------------------------------------------------- mutation

    pub fn add(&mut self, entry: Entry) -> Result<()> {
        if entry.name.trim().is_empty() {
            return Err(Error::vault("an entry needs a name"));
        }
        if self.data.find(&entry.name).is_some() {
            return Err(Error::EntryExists(entry.name.clone()));
        }
        self.data.record(AuditAction::EntryAdded, &entry.name);
        self.data.entries.push(entry);
        self.dirty = true;
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<Entry> {
        let index = self
            .data
            .position(name)
            .ok_or_else(|| Error::EntryNotFound(name.to_string()))?;
        let removed = self.data.entries.remove(index);
        self.data.record(AuditAction::EntryDeleted, &removed.name);
        self.dirty = true;
        Ok(removed)
    }

    /// Rename, rejecting a collision with a different existing entry.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        let new_key = new.trim().to_lowercase();
        if new_key.is_empty() {
            return Err(Error::vault("an entry needs a name"));
        }
        let index = self
            .data
            .position(old)
            .ok_or_else(|| Error::EntryNotFound(old.to_string()))?;
        if let Some(clash) = self.data.position(new) {
            if clash != index {
                return Err(Error::EntryExists(new.to_string()));
            }
        }
        let former = self.data.entries[index].name.clone();
        self.data.entries[index].name = new.trim().to_string();
        self.data.entries[index].touch();
        self.data
            .record(AuditAction::EntryRenamed, format!("{former} → {new}"));
        self.dirty = true;
        Ok(())
    }

    // ---------------------------------------------------------------- re-key

    /// Re-derive this slot under a fresh salt and re-seal it.
    ///
    /// The Argon2id parameters are *not* changed here, and cannot be: they
    /// live in the file header, which is authenticated as associated data for
    /// every slot. Rewriting them would invalidate any other slot in the file
    /// — including a hidden vault whose password we do not have. They are
    /// therefore fixed when the file is created.
    pub fn change_master(&mut self, new_secret: &Secret) -> Result<()> {
        self.data.record(AuditAction::MasterPasswordChanged, "");
        let (new_key, new_salt) = self.file.prepare_slot(new_secret)?;
        let old_key = std::mem::replace(&mut self.master_key, new_key);
        let old_salt = std::mem::replace(&mut self.salt, new_salt);

        match self.save() {
            Ok(()) => Ok(()),
            Err(e) => {
                // Put the working key back so the caller still holds an open
                // vault they can retry or save under the previous password.
                self.master_key = old_key;
                self.salt = old_salt;
                Err(e)
            }
        }
    }

    /// Create a second, hidden vault in this file under another password.
    ///
    /// Returns the new vault, open and empty. The vault this was called on is
    /// left untouched on disk.
    pub fn create_hidden(&self, secret: &Secret) -> Result<Vault> {
        if self.is_hidden() {
            return Err(Error::vault(
                "this is already the hidden vault; a file holds at most two",
            ));
        }
        // Against the file on disk: a hidden vault may have been created
        // since this one was opened.
        let current = self.current_file().unwrap_or_else(|_| {
            // Unreadable file: fall back to our copy rather than refusing.
            // `create_in_slot` will fail loudly straight after if it is really
            // gone.
            self.file.clone()
        });
        if current.slot_opens(slots::HIDDEN_SLOT, secret) {
            return Err(Error::vault(
                "a hidden vault already exists under that password",
            ));
        }
        Vault::create_in_slot(
            &self.path,
            secret,
            self.file.header.kdf.clone(),
            slots::HIDDEN_SLOT,
            None,
        )
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::test_home::TestHome;

    /// The shared scratch directory, plus the one file these tests care about.
    struct TempDir {
        home: TestHome,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            Self {
                home: TestHome::new(tag),
            }
        }

        fn vault(&self) -> PathBuf {
            self.home.join("vault.ddv")
        }
    }

    /// Kept so the existing tests can go on saying `dir.path`.
    impl std::ops::Deref for TempDir {
        type Target = TestHome;

        fn deref(&self) -> &Self::Target {
            &self.home
        }
    }

    fn params() -> KdfParams {
        KdfParams {
            m_cost: KdfParams::MIN_M_COST,
            t_cost: 2,
            p_cost: 1,
            algorithm: "argon2id".into(),
        }
    }

    /// A vault with the smallest legal slot: the tests are about behaviour,
    /// not about how long it takes to encrypt four megabytes of padding.
    fn small_vault(path: &Path, secret: &Secret) -> Vault {
        Vault::create_in_slot(
            path,
            secret,
            params(),
            slots::PRIMARY_SLOT,
            Some(slots::MIN_SLOT_CAPACITY),
        )
        .unwrap()
    }

    fn sample_entry(name: &str, password: &str) -> Entry {
        let mut entry = Entry::new(name);
        entry.username = "user@example.com".into();
        entry.set_password(password.to_string());
        entry
    }

    #[test]
    fn create_then_reopen_round_trips_entries() {
        let dir = TempDir::new("roundtrip");
        let secret = Secret::from_str("master password");
        {
            let mut vault = small_vault(&dir.vault(), &secret);
            vault.add(sample_entry("GitHub", "s3cret-value")).unwrap();
            vault.save().unwrap();
        }
        let vault = Vault::open(&dir.vault(), &secret, false).unwrap();
        let entry = vault.data.find("github").expect("entry survives a reopen");
        assert_eq!(entry.password, "s3cret-value");
        assert_eq!(entry.username, "user@example.com");
    }

    #[test]
    fn the_file_on_disk_never_contains_the_password() {
        let dir = TempDir::new("ciphertext");
        let secret = Secret::from_str("master password");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault
            .add(sample_entry("Bank", "unmistakable-plaintext-marker"))
            .unwrap();
        vault.save().unwrap();

        let bytes = std::fs::read(dir.vault()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("unmistakable-plaintext-marker"));
        assert!(!text.contains("user@example.com"));
        // The entry name must not leak either - it is inside the ciphertext.
        assert!(!text.contains("Bank"));
    }

    #[test]
    fn a_wrong_master_password_cannot_open_it() {
        let dir = TempDir::new("wrongpw");
        let mut vault =
            small_vault(&dir.vault(), &Secret::from_str("right"));
        vault.add(sample_entry("Mail", "pw")).unwrap();
        vault.save().unwrap();

        let err = Vault::open(&dir.vault(), &Secret::from_str("wrong"), false).unwrap_err();
        assert!(matches!(err, Error::Authentication));
    }

    #[test]
    fn duplicate_names_are_refused_case_insensitively() {
        let dir = TempDir::new("dupes");
        let mut vault = Vault::create(&dir.vault(), &Secret::from_str("pw"), params()).unwrap();
        vault.add(sample_entry("GitHub", "a")).unwrap();
        let err = vault.add(sample_entry("github", "b")).unwrap_err();
        assert!(matches!(err, Error::EntryExists(_)));
    }

    #[test]
    fn changing_the_master_password_invalidates_the_old_one() {
        let dir = TempDir::new("rekey");
        let old = Secret::from_str("old password");
        let new = Secret::from_str("new password");
        {
            let mut vault = small_vault(&dir.vault(), &old);
            vault.add(sample_entry("Server", "keep-me")).unwrap();
            vault.save().unwrap();
            vault.change_master(&new).unwrap();
        }
        assert!(matches!(
            Vault::open(&dir.vault(), &old, true).unwrap_err(),
            Error::Authentication
        ));
        let reopened = Vault::open(&dir.vault(), &new, true).unwrap();
        assert_eq!(reopened.data.find("server").unwrap().password, "keep-me");
    }

    #[test]
    fn restoring_an_older_vault_is_reported_as_a_rollback() {
        let dir = TempDir::new("rollback");
        let secret = Secret::from_str("pw");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault.add(sample_entry("Account", "old-password")).unwrap();
        vault.save().unwrap();
        let stale = std::fs::read(dir.vault()).unwrap();

        // The user rotates the password a few times.
        for i in 0..3 {
            vault
                .data
                .find_mut("account")
                .unwrap()
                .set_password(format!("new-password-{i}"));
            vault.save().unwrap();
        }
        drop(vault);

        // An attacker puts the old, still validly signed file back.
        std::fs::write(dir.vault(), &stale).unwrap();
        let err = Vault::open(&dir.vault(), &secret, false).unwrap_err();
        assert!(matches!(err, Error::Rollback { .. }));

        // The user can still say "yes, I restored that backup deliberately".
        assert!(Vault::open(&dir.vault(), &secret, true).is_ok());
    }

    #[test]
    fn saving_rotates_backups() {
        let dir = TempDir::new("backups");
        let secret = Secret::from_str("pw");
        let mut vault = small_vault(&dir.vault(), &secret);
        for i in 0..3 {
            vault.add(sample_entry(&format!("Entry{i}"), "pw")).unwrap();
            vault.save().unwrap();
        }
        assert!(!vault.available_backups().is_empty());
    }

    #[test]
    fn a_hidden_vault_lives_beside_the_decoy_in_one_file() {
        let dir = TempDir::new("hidden");
        let decoy_pw = Secret::from_str("the password I would hand over");
        let real_pw = Secret::from_str("the one I would not");

        {
            let mut decoy = small_vault(&dir.vault(), &decoy_pw);
            decoy.add(sample_entry("Some forum", "plausible")).unwrap();
            decoy.save().unwrap();

            let mut hidden = decoy.create_hidden(&real_pw).unwrap();
            assert!(hidden.is_hidden());
            hidden.add(sample_entry("Real bank", "what matters")).unwrap();
            hidden.save().unwrap();
        }

        // Each password opens its own vault, and neither sees the other.
        let decoy = Vault::open(&dir.vault(), &decoy_pw, true).unwrap();
        assert!(!decoy.is_hidden());
        assert!(decoy.data.find("some forum").is_some());
        assert!(decoy.data.find("real bank").is_none());

        let hidden = Vault::open(&dir.vault(), &real_pw, true).unwrap();
        assert!(hidden.is_hidden());
        assert!(hidden.data.find("real bank").is_some());
        assert!(hidden.data.find("some forum").is_none());
    }

    #[test]
    fn editing_the_decoy_leaves_the_hidden_vault_intact() {
        // The scenario the whole design exists for: you are made to open the
        // decoy and use it, and the real vault must survive that.
        let dir = TempDir::new("coercion");
        let decoy_pw = Secret::from_str("handed over");
        let real_pw = Secret::from_str("not handed over");

        {
            let decoy = small_vault(&dir.vault(), &decoy_pw);
            let mut hidden = decoy.create_hidden(&real_pw).unwrap();
            hidden.add(sample_entry("Real bank", "precious")).unwrap();
            hidden.save().unwrap();
        }

        for round in 0..3 {
            let mut decoy = Vault::open(&dir.vault(), &decoy_pw, true).unwrap();
            decoy
                .add(sample_entry(&format!("Filler {round}"), "whatever"))
                .unwrap();
            decoy.save().unwrap();
        }

        let hidden = Vault::open(&dir.vault(), &real_pw, true).unwrap();
        assert_eq!(hidden.data.find("real bank").unwrap().password, "precious");
        assert_eq!(hidden.data.entries.len(), 1);
    }

    #[test]
    fn a_wrong_password_opens_neither_slot() {
        let dir = TempDir::new("neither");
        let decoy = small_vault(&dir.vault(), &Secret::from_str("decoy"));
        let _ = decoy.create_hidden(&Secret::from_str("hidden")).unwrap();

        let err = Vault::open(&dir.vault(), &Secret::from_str("wrong"), true)
            .expect_err("neither slot should open");
        assert!(matches!(err, Error::Authentication));
    }

    /// The deniability claim at the file level: with and without a hidden
    /// vault, the file is the same size.
    #[test]
    fn a_file_with_a_hidden_vault_is_the_same_size_as_one_without() {
        let plain_dir = TempDir::new("plain");
        let plain = small_vault(&plain_dir.vault(), &Secret::from_str("decoy"));
        drop(plain);
        let plain_len = std::fs::metadata(plain_dir.vault()).unwrap().len();
        drop(plain_dir);

        let hidden_dir = TempDir::new("withhidden");
        let decoy = small_vault(&hidden_dir.vault(), &Secret::from_str("decoy"));
        let mut hidden = decoy.create_hidden(&Secret::from_str("hidden")).unwrap();
        hidden.add(sample_entry("Secret", "value")).unwrap();
        hidden.save().unwrap();
        drop(hidden);
        drop(decoy);
        let hidden_len = std::fs::metadata(hidden_dir.vault()).unwrap().len();

        assert_eq!(plain_len, hidden_len);
    }

    #[test]
    fn the_hidden_slot_cannot_be_claimed_twice() {
        let dir = TempDir::new("twice");
        let decoy = small_vault(&dir.vault(), &Secret::from_str("decoy"));
        let secret = Secret::from_str("hidden");
        let _first = decoy.create_hidden(&secret).unwrap();
        assert!(decoy.create_hidden(&secret).is_err());
    }

    /// The other half of the same question, and the uncomfortable half.
    ///
    /// The check above only works because the same password is offered twice.
    /// Under a *different* password there is nothing to check against: finding
    /// a hidden vault without its password is precisely what the format is
    /// built to prevent, so `hidden_slot_is_free` answers "free" and the
    /// existing vault is overwritten.
    ///
    /// This is not a defect that could be fixed without giving up deniability,
    /// so it is asserted rather than left to be discovered. The interface says
    /// so in as many words before the button is pressed.
    #[test]
    fn a_second_hidden_vault_under_another_password_destroys_the_first() {
        let dir = TempDir::new("twice-other");
        let decoy_secret = Secret::from_str("decoy");
        let first_secret = Secret::from_str("the first hidden one");
        let second_secret = Secret::from_str("the second hidden one");

        let decoy = small_vault(&dir.vault(), &decoy_secret);
        let mut first = decoy.create_hidden(&first_secret).unwrap();
        first.add(sample_entry("Real", "irreplaceable")).unwrap();
        first.save().unwrap();
        drop(first);

        // The program cannot tell the slot is taken, and says so.
        let decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        assert!(
            decoy.hidden_slot_is_free(&second_secret),
            "it answers from what it can check, which is only this password"
        );

        let _second = decoy.create_hidden(&second_secret).unwrap();
        assert!(
            Vault::open(&dir.vault(), &first_secret, true).is_err(),
            "the first hidden vault is gone, and nothing could have warned by checking"
        );
        assert!(Vault::open(&dir.vault(), &second_secret, true).is_ok());
        assert!(Vault::open(&dir.vault(), &decoy_secret, true).is_ok());
    }

    #[test]
    fn a_hidden_vault_cannot_nest_another() {
        let dir = TempDir::new("nest");
        let decoy = small_vault(&dir.vault(), &Secret::from_str("decoy"));
        let hidden = decoy.create_hidden(&Secret::from_str("hidden")).unwrap();
        let err = hidden
            .create_hidden(&Secret::from_str("third"))
            .unwrap_err();
        assert!(err.to_string().contains("at most two"));
    }

    #[test]
    fn changing_the_decoy_password_does_not_disturb_the_hidden_vault() {
        let dir = TempDir::new("rekey_decoy");
        let old = Secret::from_str("old decoy");
        let new = Secret::from_str("new decoy");
        let real = Secret::from_str("hidden");

        {
            let mut decoy = small_vault(&dir.vault(), &old);
            let mut hidden = decoy.create_hidden(&real).unwrap();
            hidden.add(sample_entry("Kept", "value")).unwrap();
            hidden.save().unwrap();
            decoy.change_master(&new).unwrap();
        }

        assert!(Vault::open(&dir.vault(), &old, true).is_err());
        assert!(Vault::open(&dir.vault(), &new, true).is_ok());
        let hidden = Vault::open(&dir.vault(), &real, true).unwrap();
        assert_eq!(hidden.data.find("kept").unwrap().password, "value");
    }

    #[test]
    fn the_change_log_records_what_happened() {
        let dir = TempDir::new("audit");
        let mut vault = small_vault(&dir.vault(), &Secret::from_str("pw"));
        vault.add(sample_entry("GitHub", "pw")).unwrap();
        vault.rename("GitHub", "GitHub work").unwrap();
        vault.remove("GitHub work").unwrap();

        use crate::model::AuditAction::*;
        let actions: Vec<_> = vault.data.audit.iter().map(|r| r.action).collect();
        assert_eq!(actions, vec![Created, EntryAdded, EntryRenamed, EntryDeleted]);
        assert_eq!(vault.data.verify_audit(), Ok(()));
    }

    #[test]
    fn password_history_keeps_the_previous_value() {
        let mut entry = sample_entry("Site", "first");
        entry.set_password("second".to_string());
        assert_eq!(entry.password, "second");
        assert_eq!(entry.history.len(), 1);
        assert_eq!(entry.history[0].password, "first");
    }

    #[test]
    fn search_ignores_the_password_field() {
        let entry = sample_entry("Bank", "zzz-secret-zzz");
        assert!(entry.matches("bank"));
        assert!(entry.matches("user@example"));
        // Matching on the password would let a shoulder-surfer confirm a guess.
        assert!(!entry.matches("zzz-secret-zzz"));
    }

    // ------------------------------------------------------------ the mirror

    #[test]
    fn a_mirror_receives_a_copy_of_every_save() {
        let dir = TempDir::new("mirror-copy");
        let mirror = dir.path.join("elsewhere");
        let secret = Secret::from_str("mirror me");

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.set_mirror(Some(mirror.clone()));
        vault.add(sample_entry("Bank", "s3cret")).unwrap();
        vault.save().unwrap();

        assert_eq!(vault.mirror_error(), None, "the copy should have worked");
        let copied = mirror.join("vault.ddv");
        assert!(copied.is_file(), "the mirror has no vault in it");
        assert_eq!(
            std::fs::read(&copied).unwrap(),
            std::fs::read(dir.vault()).unwrap(),
            "the mirror must be byte for byte the same file"
        );
    }

    #[test]
    fn a_mirrored_vault_actually_opens() {
        // Byte equality is not the point; being able to recover from it is.
        let dir = TempDir::new("mirror-opens");
        let mirror = dir.path.join("elsewhere");
        let secret = Secret::from_str("mirror me");

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.set_mirror(Some(mirror.clone()));
        vault.add(sample_entry("Bank", "s3cret")).unwrap();
        vault.save().unwrap();
        drop(vault);

        let recovered = Vault::open(&mirror.join("vault.ddv"), &secret, true).unwrap();
        assert_eq!(recovered.data.entries.len(), 1);
        assert_eq!(recovered.data.entries[0].password, "s3cret");
    }

    #[test]
    fn a_mirror_keeps_its_own_rotation() {
        let dir = TempDir::new("mirror-rotate");
        let mirror = dir.path.join("elsewhere");
        let secret = Secret::from_str("mirror me");

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.set_mirror(Some(mirror.clone()));
        for index in 0..4 {
            vault.add(sample_entry(&format!("Site {index}"), "pw")).unwrap();
            vault.save().unwrap();
        }

        // A single overwritten copy would mean one bad save destroys the only
        // off-site history, so the mirror rotates like the local one.
        assert!(mirror.join("vault.ddv.bak1").is_file());
        assert!(mirror.join("vault.ddv.bak2").is_file());
        assert!(mirror.join("vault.ddv.bak3").is_file());
    }

    #[test]
    fn a_mirror_that_cannot_be_written_never_fails_the_save() {
        let dir = TempDir::new("mirror-broken");
        let secret = Secret::from_str("mirror me");

        // A file where a directory should be: `create_dir_all` cannot win.
        let blocker = dir.path.join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.set_mirror(Some(blocker.join("inside")));
        vault.add(sample_entry("Bank", "s3cret")).unwrap();

        vault.save().expect("a missing mirror must not block saving");
        assert!(
            vault.mirror_error().is_some(),
            "but it must not pass unmentioned either"
        );
        // The real vault is untouched by any of it.
        let reopened = Vault::open(&dir.vault(), &secret, true).unwrap();
        assert_eq!(reopened.data.entries.len(), 1);
    }

    #[test]
    fn a_mirror_pointed_at_the_vault_itself_is_refused() {
        let dir = TempDir::new("mirror-self");
        let secret = Secret::from_str("mirror me");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault.set_mirror(Some(dir.path.clone()));
        vault.save().unwrap();
        assert!(
            vault.mirror_error().is_some(),
            "mirroring onto the vault would rotate the real backups every save"
        );
    }

    #[test]
    fn turning_the_mirror_off_stops_the_copying() {
        let dir = TempDir::new("mirror-off");
        let mirror = dir.path.join("elsewhere");
        let secret = Secret::from_str("mirror me");

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.set_mirror(Some(mirror.clone()));
        vault.save().unwrap();
        let after_first = std::fs::read(mirror.join("vault.ddv")).unwrap();

        vault.set_mirror(None);
        vault.add(sample_entry("Later", "pw")).unwrap();
        vault.save().unwrap();

        assert_eq!(
            std::fs::read(mirror.join("vault.ddv")).unwrap(),
            after_first,
            "the mirror should be frozen at the moment it was switched off"
        );
        assert_eq!(vault.mirror_error(), None);
    }

    // ---------------------------------------------------------- resizing

    #[test]
    fn a_vault_can_be_grown_and_still_opens() {
        let dir = TempDir::new("resize-grow");
        let secret = Secret::from_str("grow me");
        let bigger = slots::MIN_SLOT_CAPACITY * 4;

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.add(sample_entry("Bank", "s3cret")).unwrap();
        vault.save().unwrap();

        let report = vault.migrate_capacity(bigger, None).unwrap();
        assert_eq!(report.old_capacity, slots::MIN_SLOT_CAPACITY);
        assert_eq!(report.new_capacity, bigger);
        assert!(!report.other_slot_carried);
        assert_eq!(vault.slot_capacity(), bigger);
        drop(vault);

        let reopened = Vault::open(&dir.vault(), &secret, true).unwrap();
        assert_eq!(reopened.slot_capacity(), bigger);
        assert_eq!(reopened.data.entries.len(), 1);
        assert_eq!(reopened.data.entries[0].password, "s3cret");
        assert!(reopened.free_capacity() > slots::MIN_SLOT_CAPACITY);
    }

    #[test]
    fn the_file_grows_with_the_slots() {
        let dir = TempDir::new("resize-size");
        let secret = Secret::from_str("grow me");
        let mut vault = small_vault(&dir.vault(), &secret);
        let before = std::fs::metadata(dir.vault()).unwrap().len();

        vault
            .migrate_capacity(slots::MIN_SLOT_CAPACITY * 4, None)
            .unwrap();
        let after = std::fs::metadata(dir.vault()).unwrap().len();
        assert!(after > before * 3, "{before} -> {after} is not a real resize");
    }

    #[test]
    fn growing_carries_the_other_vault_when_its_password_is_given() {
        let dir = TempDir::new("resize-hidden");
        let decoy_secret = Secret::from_str("the decoy one");
        let hidden_secret = Secret::from_str("the hidden one");
        let bigger = slots::MIN_SLOT_CAPACITY * 2;

        let mut decoy = small_vault(&dir.vault(), &decoy_secret);
        decoy.add(sample_entry("Shopping", "visible")).unwrap();
        decoy.save().unwrap();

        let mut hidden = decoy.create_hidden(&hidden_secret).unwrap();
        hidden.add(sample_entry("Real", "invisible")).unwrap();
        hidden.save().unwrap();
        drop(hidden);

        let mut decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        let report = decoy.migrate_capacity(bigger, Some(&hidden_secret)).unwrap();
        assert!(report.other_slot_carried);
        drop(decoy);

        // Both vaults survived, at the new size.
        let decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        assert_eq!(decoy.data.entries[0].name, "Shopping");
        assert_eq!(decoy.slot_capacity(), bigger);

        let hidden = Vault::open(&dir.vault(), &hidden_secret, true).unwrap();
        assert_eq!(hidden.data.entries[0].password, "invisible");
        assert_eq!(hidden.slot_capacity(), bigger);
    }

    #[test]
    fn growing_without_the_other_password_discards_the_other_slot() {
        // Documented, deliberate and destructive: from inside one slot there
        // is no way to know whether the other holds a vault or noise, so the
        // caller has to answer for it. The UI asks in as many words.
        let dir = TempDir::new("resize-discard");
        let decoy_secret = Secret::from_str("the decoy one");
        let hidden_secret = Secret::from_str("the hidden one");

        let mut decoy = small_vault(&dir.vault(), &decoy_secret);
        decoy.save().unwrap();
        let mut hidden = decoy.create_hidden(&hidden_secret).unwrap();
        hidden.add(sample_entry("Real", "invisible")).unwrap();
        hidden.save().unwrap();
        drop(hidden);

        let mut decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        decoy
            .migrate_capacity(slots::MIN_SLOT_CAPACITY * 2, None)
            .unwrap();
        drop(decoy);

        assert!(
            Vault::open(&dir.vault(), &hidden_secret, true).is_err(),
            "the hidden vault was supposed to be discarded"
        );
        assert!(
            Vault::open(&dir.vault(), &decoy_secret, true).is_ok(),
            "and the open one was supposed to survive"
        );
    }

    #[test]
    fn a_vault_cannot_be_shrunk_below_what_it_already_holds() {
        let dir = TempDir::new("resize-shrink");
        let secret = Secret::from_str("shrink me");
        let mut vault = Vault::create_in_slot(
            &dir.vault(),
            &secret,
            params(),
            slots::PRIMARY_SLOT,
            Some(slots::MIN_SLOT_CAPACITY * 8),
        )
        .unwrap();

        // Fill it past the smallest slot.
        let filler = "x".repeat(slots::MIN_SLOT_CAPACITY);
        vault.add(sample_entry("Big", &filler)).unwrap();
        vault.save().unwrap();

        let err = vault
            .migrate_capacity(slots::MIN_SLOT_CAPACITY, None)
            .unwrap_err();
        assert!(format!("{err}").contains("would not fit"));
        // And the vault is untouched by the refusal.
        assert_eq!(vault.slot_capacity(), slots::MIN_SLOT_CAPACITY * 8);
        assert_eq!(vault.data.entries.len(), 1);
    }

    #[test]
    fn resizing_to_the_size_it_already_has_is_refused() {
        let dir = TempDir::new("resize-same");
        let secret = Secret::from_str("same size");
        let mut vault = small_vault(&dir.vault(), &secret);
        assert!(vault
            .migrate_capacity(slots::MIN_SLOT_CAPACITY, None)
            .is_err());
    }

    #[test]
    fn an_impossible_size_is_refused() {
        let dir = TempDir::new("resize-absurd");
        let secret = Secret::from_str("absurd");
        let mut vault = small_vault(&dir.vault(), &secret);
        assert!(vault.migrate_capacity(1, None).is_err());
        assert!(vault
            .migrate_capacity(slots::MAX_SLOT_CAPACITY * 2, None)
            .is_err());
    }

    #[test]
    fn a_resize_is_written_into_the_change_log() {
        let dir = TempDir::new("resize-log");
        let secret = Secret::from_str("log it");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault
            .migrate_capacity(slots::MIN_SLOT_CAPACITY * 2, None)
            .unwrap();

        assert!(vault
            .data
            .audit
            .iter()
            .any(|r| r.action == AuditAction::VaultResized));
        assert!(vault.data.verify_audit().is_ok(), "the chain must survive");
    }

    // ------------------------------------------------------ the anchor

    #[test]
    fn a_first_open_on_this_machine_says_so() {
        let dir = TempDir::new("anchor-first");
        let secret = Secret::from_str("anchor me");
        let vault = small_vault(&dir.vault(), &secret);
        assert_eq!(vault.anchor_state(), AnchorState::Verified, "freshly created");
        drop(vault);

        // Simulate carrying the file to a machine that has never seen it.
        std::env::set_var("DEEP_DEFENSE_TEST_MACHINE", "another computer");
        std::fs::remove_file(anchor_path()).unwrap();
        let moved = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(
            moved.anchor_state(),
            AnchorState::FirstSeenHere,
            "the one open where a swapped file is most likely must be flagged"
        );
        assert!(moved.anchor_state().is_noteworthy());

        // And the next one is protected again.
        let again = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(again.anchor_state(), AnchorState::Verified);
        assert!(!again.anchor_state().is_noteworthy());
    }

    #[test]
    fn a_damaged_anchor_is_reported_rather_than_trusted() {
        let dir = TempDir::new("anchor-damaged");
        let secret = Secret::from_str("anchor me");
        let vault = small_vault(&dir.vault(), &secret);
        let id = vault.vault_id();
        drop(vault);

        // Right vault, wrong MAC: an anchor someone else wrote.
        let forged = format!(
            "{{\"vault_id\":\"{id}\",\"revision\":9999,\"mac\":\"{}\"}}",
            BASE64.encode([0u8; 32])
        );
        std::fs::write(anchor_path(), forged).unwrap();

        let opened = Vault::open(&dir.vault(), &secret, false)
            .expect("an unauthenticated anchor must not block opening");
        assert_eq!(opened.anchor_state(), AnchorState::Unverifiable);
    }

    #[test]
    fn nonsense_in_the_anchor_file_is_survivable() {
        let dir = TempDir::new("anchor-nonsense");
        let secret = Secret::from_str("anchor me");
        drop(small_vault(&dir.vault(), &secret));

        std::fs::write(anchor_path(), b"\x00\xff not json at all").unwrap();
        let opened = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(opened.anchor_state(), AnchorState::Unverifiable);
    }

    #[test]
    fn an_anchor_can_be_carried_to_another_machine() {
        let dir = TempDir::new("anchor-carry");
        let secret = Secret::from_str("anchor me");
        let carried = dir.path.join("carried.anchor");

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.add(sample_entry("Bank", "s3cret")).unwrap();
        vault.save().unwrap();
        vault.export_anchor(&carried).unwrap();
        drop(vault);

        // A machine that has never seen this vault.
        std::env::set_var("DEEP_DEFENSE_TEST_MACHINE", "another computer");
        std::fs::remove_file(anchor_path()).unwrap();
        let mut moved = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(moved.anchor_state(), AnchorState::FirstSeenHere);

        moved.import_anchor(&carried).unwrap();
        assert_eq!(moved.anchor_state(), AnchorState::Verified);
        drop(moved);

        let after = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(after.anchor_state(), AnchorState::Verified);
    }

    #[test]
    fn an_anchor_newer_than_the_file_is_a_rollback() {
        let dir = TempDir::new("anchor-rollback");
        let secret = Secret::from_str("anchor me");
        let carried = dir.path.join("carried.anchor");

        let mut vault = small_vault(&dir.vault(), &secret);
        for index in 0..3 {
            vault.add(sample_entry(&format!("Site {index}"), "pw")).unwrap();
            vault.save().unwrap();
        }
        vault.export_anchor(&carried).unwrap();
        let newest = vault.data.revision;
        drop(vault);

        // Put an older copy back, the way an attacker restoring a backup would.
        std::fs::copy(dir.path.join("vault.ddv.bak3"), dir.vault()).unwrap();
        let mut older = Vault::open(&dir.vault(), &secret, true).unwrap();
        assert!(older.data.revision < newest);

        let err = older.import_anchor(&carried).unwrap_err();
        assert!(
            matches!(err, Error::Rollback { .. }),
            "a carried anchor must still catch a rolled-back file, got {err}"
        );
    }

    #[test]
    fn an_anchor_from_a_different_vault_is_refused() {
        let dir = TempDir::new("anchor-foreign");
        let mine = Secret::from_str("mine");
        let theirs = Secret::from_str("theirs");
        let other_path = dir.path.join("other.ddv");
        let carried = dir.path.join("theirs.anchor");

        let other = small_vault(&other_path, &theirs);
        other.export_anchor(&carried).unwrap();
        drop(other);

        let mut mine_vault = small_vault(&dir.vault(), &mine);
        let err = mine_vault.import_anchor(&carried).unwrap_err();
        assert!(format!("{err}").contains("different vault"));
    }

    #[test]
    fn a_forged_anchor_is_refused_on_import() {
        let dir = TempDir::new("anchor-forged");
        let secret = Secret::from_str("anchor me");
        let carried = dir.path.join("carried.anchor");

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.export_anchor(&carried).unwrap();

        // Claim a far higher revision, keeping the vault id honest. Without
        // the master key the MAC cannot be recomputed to match, so this is
        // exactly what an attacker could produce — and it must not work.
        let text = std::fs::read_to_string(&carried).unwrap();
        let tampered: serde_json::Value = serde_json::from_str(&text).unwrap();
        let forged = serde_json::json!({
            "vault_id": tampered["vault_id"],
            "revision": 999_999,
            "mac": tampered["mac"],
        });
        std::fs::write(&carried, forged.to_string()).unwrap();

        let err = vault.import_anchor(&carried).unwrap_err();
        assert!(
            !matches!(err, Error::Rollback { .. }),
            "a forged anchor must be rejected outright, not believed"
        );
        assert!(format!("{err}").contains("not written for this vault"));
    }

    #[test]
    fn a_mangled_anchor_file_is_refused_on_import() {
        let dir = TempDir::new("anchor-mangled");
        let secret = Secret::from_str("anchor me");
        let mut vault = small_vault(&dir.vault(), &secret);

        let bad = dir.path.join("bad.anchor");
        std::fs::write(&bad, b"certainly not json").unwrap();
        assert!(vault.import_anchor(&bad).is_err());

        assert!(vault.import_anchor(&dir.path.join("absent.anchor")).is_err());
    }

    // -------------------------------------------------------- the work factor

    fn stronger_params() -> KdfParams {
        KdfParams {
            m_cost: KdfParams::MIN_M_COST * 2,
            t_cost: 3,
            p_cost: 1,
            algorithm: "argon2id".into(),
        }
    }

    #[test]
    fn the_work_factor_can_be_raised_and_the_password_still_opens_it() {
        let dir = TempDir::new("rekey-raise");
        let secret = Secret::from_str("stays the same");

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.add(sample_entry("Bank", "s3cret")).unwrap();
        vault.save().unwrap();
        assert_eq!(vault.kdf().t_cost, params().t_cost);

        let report = vault
            .rebuild(
                slots::MIN_SLOT_CAPACITY,
                stronger_params(),
                Some(&secret),
                None,
            )
            .unwrap();
        assert!(report.kdf_changed);
        assert_eq!(report.old_capacity, report.new_capacity, "size untouched");
        drop(vault);

        let reopened = Vault::open(&dir.vault(), &secret, true).unwrap();
        assert_eq!(reopened.kdf().t_cost, 3);
        assert_eq!(reopened.kdf().m_cost, KdfParams::MIN_M_COST * 2);
        assert_eq!(reopened.data.entries[0].password, "s3cret");
    }

    #[test]
    fn the_new_cost_is_what_the_file_header_says() {
        // The key must be derived against the header that gets written, not
        // the one it replaced — otherwise the file would claim one cost and
        // need another, and nothing would open it.
        let dir = TempDir::new("rekey-header");
        let secret = Secret::from_str("stays the same");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault
            .rebuild(slots::MIN_SLOT_CAPACITY, stronger_params(), Some(&secret), None)
            .unwrap();
        drop(vault);

        let bytes = std::fs::read(dir.vault()).unwrap();
        let file = SlotFile::parse(&bytes).unwrap();
        assert_eq!(file.header.kdf, stronger_params());
        assert!(file.slot_opens(slots::PRIMARY_SLOT, &secret));
    }

    #[test]
    fn the_vault_stays_usable_in_memory_after_re_keying() {
        // The in-memory key is replaced along with the file's. If it were not,
        // the next save would seal with a key the header no longer describes.
        let dir = TempDir::new("rekey-memory");
        let secret = Secret::from_str("stays the same");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault
            .rebuild(slots::MIN_SLOT_CAPACITY, stronger_params(), Some(&secret), None)
            .unwrap();

        vault.add(sample_entry("Added after", "pw")).unwrap();
        vault.save().unwrap();
        drop(vault);

        let reopened = Vault::open(&dir.vault(), &secret, true).unwrap();
        assert_eq!(reopened.data.entries.len(), 1);
        assert_eq!(reopened.data.entries[0].name, "Added after");
    }

    #[test]
    fn re_keying_without_the_password_is_refused() {
        let dir = TempDir::new("rekey-nopw");
        let secret = Secret::from_str("stays the same");
        let mut vault = small_vault(&dir.vault(), &secret);

        let err = vault
            .rebuild(slots::MIN_SLOT_CAPACITY, stronger_params(), None, None)
            .unwrap_err();
        assert!(format!("{err}").contains("needs the master password"));
        assert_eq!(vault.kdf().t_cost, params().t_cost, "nothing changed");
    }

    #[test]
    fn re_keying_with_the_wrong_password_is_refused_before_anything_is_written() {
        // The dangerous case: sealing the vault under a password the owner
        // does not have would be unrecoverable and completely silent.
        let dir = TempDir::new("rekey-wrongpw");
        let secret = Secret::from_str("the real one");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault.add(sample_entry("Bank", "s3cret")).unwrap();
        vault.save().unwrap();
        let before = std::fs::read(dir.vault()).unwrap();

        let err = vault
            .rebuild(
                slots::MIN_SLOT_CAPACITY,
                stronger_params(),
                Some(&Secret::from_str("not the real one")),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, Error::Authentication), "got {err}");

        assert_eq!(
            std::fs::read(dir.vault()).unwrap(),
            before,
            "the file must not have been touched"
        );
        drop(vault);
        assert!(Vault::open(&dir.vault(), &secret, true).is_ok());
    }

    #[test]
    fn re_keying_carries_the_hidden_vault_when_its_password_is_given() {
        let dir = TempDir::new("rekey-hidden");
        let decoy_secret = Secret::from_str("the decoy one");
        let hidden_secret = Secret::from_str("the hidden one");

        let mut decoy = small_vault(&dir.vault(), &decoy_secret);
        decoy.add(sample_entry("Shopping", "visible")).unwrap();
        decoy.save().unwrap();
        let mut hidden = decoy.create_hidden(&hidden_secret).unwrap();
        hidden.add(sample_entry("Real", "invisible")).unwrap();
        hidden.save().unwrap();
        drop(hidden);

        let mut decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        let report = decoy
            .rebuild(
                slots::MIN_SLOT_CAPACITY,
                stronger_params(),
                Some(&decoy_secret),
                Some(&hidden_secret),
            )
            .unwrap();
        assert!(report.kdf_changed && report.other_slot_carried);
        drop(decoy);

        // Both slots re-derived under the new cost, both still open.
        let decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        assert_eq!(decoy.data.entries[0].name, "Shopping");
        assert_eq!(decoy.kdf().t_cost, 3);

        let hidden = Vault::open(&dir.vault(), &hidden_secret, true).unwrap();
        assert_eq!(hidden.data.entries[0].password, "invisible");
        assert_eq!(hidden.kdf().t_cost, 3);
    }

    #[test]
    fn re_keying_without_the_other_password_discards_the_other_slot() {
        // Stricter than a resize: the other slot's key cannot be re-derived
        // from anything readable here, so its password is the only way for it
        // to survive a change of cost.
        let dir = TempDir::new("rekey-discard");
        let decoy_secret = Secret::from_str("the decoy one");
        let hidden_secret = Secret::from_str("the hidden one");

        let mut decoy = small_vault(&dir.vault(), &decoy_secret);
        decoy.save().unwrap();
        let mut hidden = decoy.create_hidden(&hidden_secret).unwrap();
        hidden.add(sample_entry("Real", "invisible")).unwrap();
        hidden.save().unwrap();
        drop(hidden);

        let mut decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        decoy
            .rebuild(slots::MIN_SLOT_CAPACITY, stronger_params(), Some(&decoy_secret), None)
            .unwrap();
        drop(decoy);

        assert!(Vault::open(&dir.vault(), &hidden_secret, true).is_err());
        assert!(Vault::open(&dir.vault(), &decoy_secret, true).is_ok());
    }

    #[test]
    fn the_size_and_the_cost_can_change_in_one_rebuild() {
        let dir = TempDir::new("rekey-both");
        let secret = Secret::from_str("stays the same");
        let bigger = slots::MIN_SLOT_CAPACITY * 2;

        let mut vault = small_vault(&dir.vault(), &secret);
        vault.add(sample_entry("Bank", "s3cret")).unwrap();
        vault.save().unwrap();

        let report = vault
            .rebuild(bigger, stronger_params(), Some(&secret), None)
            .unwrap();
        assert!(report.kdf_changed);
        assert_eq!(report.new_capacity, bigger);
        drop(vault);

        let reopened = Vault::open(&dir.vault(), &secret, true).unwrap();
        assert_eq!(reopened.slot_capacity(), bigger);
        assert_eq!(reopened.kdf().t_cost, 3);
        assert_eq!(reopened.data.entries[0].password, "s3cret");
    }

    #[test]
    fn a_rebuild_that_changes_nothing_is_refused() {
        let dir = TempDir::new("rekey-noop");
        let secret = Secret::from_str("stays the same");
        let mut vault = small_vault(&dir.vault(), &secret);
        let same = vault.kdf().clone();
        let err = vault
            .rebuild(slots::MIN_SLOT_CAPACITY, same, Some(&secret), None)
            .unwrap_err();
        assert!(format!("{err}").contains("change nothing"));
    }

    #[test]
    fn an_implausible_work_factor_is_refused() {
        let dir = TempDir::new("rekey-absurd");
        let secret = Secret::from_str("stays the same");
        let mut vault = small_vault(&dir.vault(), &secret);
        let floor_breaking = KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            algorithm: "argon2id".into(),
        };
        assert!(vault
            .rebuild(slots::MIN_SLOT_CAPACITY, floor_breaking, Some(&secret), None)
            .is_err());
        assert_eq!(vault.kdf().m_cost, params().m_cost, "left alone");
    }

    #[test]
    fn re_keying_is_written_into_the_change_log() {
        let dir = TempDir::new("rekey-log");
        let secret = Secret::from_str("stays the same");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault
            .rebuild(slots::MIN_SLOT_CAPACITY, stronger_params(), Some(&secret), None)
            .unwrap();

        assert!(vault
            .data
            .audit
            .iter()
            .any(|r| r.action == AuditAction::WorkFactorChanged));
        assert!(vault.data.verify_audit().is_ok());
    }

    #[test]
    fn a_resize_alone_does_not_claim_the_cost_changed() {
        let dir = TempDir::new("rekey-resize-only");
        let secret = Secret::from_str("stays the same");
        let mut vault = small_vault(&dir.vault(), &secret);
        let report = vault
            .migrate_capacity(slots::MIN_SLOT_CAPACITY * 2, None)
            .unwrap();
        assert!(!report.kdf_changed);
        assert!(!vault
            .data
            .audit
            .iter()
            .any(|r| r.action == AuditAction::WorkFactorChanged));
    }

    // ------------------------------------------- confirming a password

    #[test]
    fn a_password_can_be_confirmed_without_being_revealed() {
        let dir = TempDir::new("confirm-pw");
        let secret = Secret::from_str("the right one");
        let vault = small_vault(&dir.vault(), &secret);

        assert!(vault.secret_opens_this_slot(&secret));
        assert!(!vault.secret_opens_this_slot(&Secret::from_str("the wrong one")));
        assert!(!vault.secret_opens_this_slot(&Secret::from_str("")));
    }

    #[test]
    fn confirming_a_password_follows_it_across_a_change() {
        let dir = TempDir::new("confirm-after-change");
        let old = Secret::from_str("the old one");
        let new = Secret::from_str("the new one");
        let mut vault = small_vault(&dir.vault(), &old);

        vault.change_master(&new).unwrap();
        assert!(vault.secret_opens_this_slot(&new));
        assert!(
            !vault.secret_opens_this_slot(&old),
            "recovery pieces made before the change must report as stale"
        );
    }

    // ---------------------------------------------------- restoring backups

    #[test]
    fn a_backup_can_be_restored_and_the_restore_undone() {
        let dir = TempDir::new("restore-undo");
        let secret = Secret::from_str("restore me");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault.add(sample_entry("First", "one")).unwrap();
        vault.save().unwrap();
        vault.add(sample_entry("Second", "two")).unwrap();
        vault.save().unwrap();
        drop(vault);

        restore_backup(&dir.vault(), 1).unwrap();
        let older = Vault::open(&dir.vault(), &secret, true).unwrap();
        let names: Vec<_> = older.data.entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, vec!["First".to_string()], "the file before the last save");
        drop(older);

        // The file that was replaced became backup 1, so this undoes it.
        restore_backup(&dir.vault(), 1).unwrap();
        let newer = Vault::open(&dir.vault(), &secret, true).unwrap();
        assert_eq!(newer.data.entries.len(), 2);
    }

    /// The case this exists for.
    #[test]
    fn a_hidden_vault_overwritten_by_a_second_one_comes_back_from_the_backup() {
        let dir = TempDir::new("restore-hidden");
        let decoy_secret = Secret::from_str("the decoy");
        let first_secret = Secret::from_str("the first hidden one");
        let second_secret = Secret::from_str("the second hidden one");

        let decoy = small_vault(&dir.vault(), &decoy_secret);
        let mut first = decoy.create_hidden(&first_secret).unwrap();
        first.add(sample_entry("Real", "irreplaceable")).unwrap();
        first.save().unwrap();
        drop(first);
        drop(decoy);

        let decoy = Vault::open(&dir.vault(), &decoy_secret, true).unwrap();
        let _second = decoy.create_hidden(&second_secret).unwrap();
        assert!(Vault::open(&dir.vault(), &first_secret, true).is_err(), "gone");

        // The save that overwrote it copied the file aside first.
        restore_backup(&dir.vault(), 1).unwrap();
        let back = Vault::open(&dir.vault(), &first_secret, true).unwrap();
        assert_eq!(back.data.entries[0].password, "irreplaceable");
        assert!(Vault::open(&dir.vault(), &decoy_secret, true).is_ok());
    }

    #[test]
    fn something_that_is_not_a_vault_is_never_restored_over_one() {
        let dir = TempDir::new("restore-garbage");
        let secret = Secret::from_str("restore me");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault.save().unwrap();
        drop(vault);

        std::fs::write(backup_path(&dir.vault(), 1), b"not a vault at all").unwrap();
        let before = std::fs::read(dir.vault()).unwrap();
        assert!(restore_backup(&dir.vault(), 1).is_err());
        assert_eq!(std::fs::read(dir.vault()).unwrap(), before, "untouched");
    }

    #[test]
    fn there_is_no_backup_zero_and_none_past_the_last() {
        let dir = TempDir::new("restore-range");
        let secret = Secret::from_str("restore me");
        drop(small_vault(&dir.vault(), &secret));
        assert!(restore_backup(&dir.vault(), 0).is_err());
        assert!(restore_backup(&dir.vault(), BACKUP_COUNT + 1).is_err());
    }

    #[test]
    fn a_restored_older_file_is_announced_as_a_rollback() {
        // Which is how the interface comes to ask "did you mean to open an
        // older version?" — the answer the person restoring expects to give.
        let dir = TempDir::new("restore-rollback");
        let secret = Secret::from_str("restore me");
        let mut vault = small_vault(&dir.vault(), &secret);
        for index in 0..3 {
            vault.add(sample_entry(&format!("Site {index}"), "pw")).unwrap();
            vault.save().unwrap();
        }
        drop(vault);

        restore_backup(&dir.vault(), 2).unwrap();
        let refused = Vault::open(&dir.vault(), &secret, false).unwrap_err();
        assert!(matches!(refused, Error::Rollback { .. }), "got {refused}");
        assert!(Vault::open(&dir.vault(), &secret, true).is_ok());
    }

    #[test]
    fn the_backups_are_listed_newest_first() {
        let dir = TempDir::new("restore-list");
        let secret = Secret::from_str("restore me");
        let mut vault = small_vault(&dir.vault(), &secret);
        vault.save().unwrap();
        vault.save().unwrap();
        vault.save().unwrap();
        let listed = list_backups(&dir.vault());
        let indices: Vec<_> = listed.iter().map(|b| b.index).collect();
        assert_eq!(indices, vec![1, 2, 3]);
        assert!(listed.iter().all(|b| b.bytes > 0 && b.path.is_file()));
    }

    // ------------------------------------------------ records per slot

    #[test]
    fn a_deleted_record_on_a_computer_that_had_one_is_reported() {
        // What someone swapping in an older file would do first. It used to be
        // indistinguishable from a first run.
        let dir = TempDir::new("anchor-removed");
        let secret = Secret::from_str("anchor me");
        drop(small_vault(&dir.vault(), &secret));

        std::fs::remove_file(anchor_path()).unwrap();
        let opened = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(opened.anchor_state(), AnchorState::Removed);
        assert!(opened.anchor_state().is_noteworthy());
        drop(opened);

        let again = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(again.anchor_state(), AnchorState::Verified, "recorded again");
    }

    #[test]
    fn a_decoy_and_a_hidden_vault_no_longer_overwrite_each_others_record() {
        // They shared one record before, and each open replaced the other's:
        // for anyone with a hidden vault, rollback protection covered neither.
        let dir = TempDir::new("anchor-both");
        let decoy_secret = Secret::from_str("the decoy");
        let hidden_secret = Secret::from_str("the hidden one");

        let decoy = small_vault(&dir.vault(), &decoy_secret);
        drop(decoy.create_hidden(&hidden_secret).unwrap());
        drop(decoy);

        for secret in [&decoy_secret, &hidden_secret, &decoy_secret, &hidden_secret] {
            let opened = Vault::open(&dir.vault(), secret, false).unwrap();
            assert_eq!(opened.anchor_state(), AnchorState::Verified);
        }
    }

    #[test]
    fn a_rolled_back_hidden_vault_is_caught_while_its_decoy_is_not_blamed() {
        let dir = TempDir::new("anchor-hidden-rollback");
        let decoy_secret = Secret::from_str("the decoy");
        let hidden_secret = Secret::from_str("the hidden one");

        let decoy = small_vault(&dir.vault(), &decoy_secret);
        let mut hidden = decoy.create_hidden(&hidden_secret).unwrap();
        drop(decoy);
        hidden.add(sample_entry("Earlier", "pw")).unwrap();
        hidden.save().unwrap();
        let earlier = std::fs::read(dir.vault()).unwrap();
        hidden.add(sample_entry("Later", "pw")).unwrap();
        hidden.save().unwrap();
        drop(hidden);

        // The older file goes back. Only the hidden vault moved between the
        // two, so only the hidden vault is behind its record.
        std::fs::write(dir.vault(), &earlier).unwrap();
        let refused = Vault::open(&dir.vault(), &hidden_secret, false).unwrap_err();
        assert!(matches!(refused, Error::Rollback { .. }), "got {refused}");
        let decoy = Vault::open(&dir.vault(), &decoy_secret, false).unwrap();
        assert_eq!(decoy.anchor_state(), AnchorState::Verified);
    }

    #[test]
    fn the_store_holds_a_record_for_every_slot_whether_or_not_it_is_used() {
        // A file with no hidden vault must leave the same traces as one with.
        let dir = TempDir::new("anchor-shape");
        let secret = Secret::from_str("anchor me");
        drop(small_vault(&dir.vault(), &secret));

        let text = std::fs::read_to_string(anchor_path()).unwrap();
        let store: serde_json::Value = serde_json::from_str(&text).unwrap();
        let entries = store["entries"].as_array().unwrap();
        assert_eq!(entries.len(), slots::SLOT_COUNT);
        let lengths: Vec<_> = entries
            .iter()
            .map(|e| e["sealed"].as_str().unwrap().len())
            .collect();
        assert!(lengths.windows(2).all(|pair| pair[0] == pair[1]), "{lengths:?}");
        assert_ne!(entries[0]["id"], entries[1]["id"]);
        assert!(
            !text.contains("revision"),
            "a plain revision number would show which records are real"
        );
    }

    #[test]
    fn a_hidden_vault_new_to_a_computer_is_not_taken_for_tampering() {
        // On a computer where only the decoy has been opened, the hidden
        // vault's slot holds the placeholder the decoy left. The first open
        // there must read that as a first visit, not as a forged record.
        let dir = TempDir::new("anchor-placeholder");
        let decoy_secret = Secret::from_str("the decoy");
        let hidden_secret = Secret::from_str("the hidden one");
        let decoy = small_vault(&dir.vault(), &decoy_secret);
        drop(decoy.create_hidden(&hidden_secret).unwrap());
        drop(decoy);

        std::env::set_var("DEEP_DEFENSE_TEST_MACHINE", "a second computer");
        std::fs::remove_file(anchor_path()).unwrap();
        drop(Vault::open(&dir.vault(), &decoy_secret, false).unwrap());

        let hidden = Vault::open(&dir.vault(), &hidden_secret, false).unwrap();
        assert_eq!(hidden.anchor_state(), AnchorState::FirstSeenHere);
        drop(hidden);
        let again = Vault::open(&dir.vault(), &hidden_secret, false).unwrap();
        assert_eq!(again.anchor_state(), AnchorState::Verified);
    }

    #[test]
    fn a_record_from_before_the_store_existed_is_carried_over() {
        let dir = TempDir::new("anchor-legacy");
        let secret = Secret::from_str("anchor me");
        let vault = small_vault(&dir.vault(), &secret);
        // The single-record form earlier builds wrote, written where they
        // wrote it.
        vault.export_anchor(&anchor_path()).unwrap();
        drop(vault);

        let opened = Vault::open(&dir.vault(), &secret, false).unwrap();
        assert_eq!(opened.anchor_state(), AnchorState::Verified);
        let text = std::fs::read_to_string(anchor_path()).unwrap();
        assert!(text.contains("\"version\":2"), "rewritten in the new form");
    }

    #[test]
    fn the_vault_names_no_computer_it_can_be_read_back_from() {
        let dir = TempDir::new("anchor-tags");
        let secret = Secret::from_str("anchor me");
        let vault = small_vault(&dir.vault(), &secret);
        let machine = this_machine_id().expect("tests run somewhere");
        assert_eq!(vault.data.anchored_on.len(), 1);
        assert!(
            !vault.data.anchored_on[0].contains(&machine),
            "a tag, never the identity itself"
        );
        assert!(!format!("{:?}", vault.data).contains(&vault.data.machine_key.0));
    }
}
