//! The vault's own encryption.
//!
//! This is the whole of the protection by default, and it is self-sufficient:
//! no container, no driver, no administrator rights. When the optional
//! VeraCrypt layer *is* in use this still runs underneath it, so mounting the
//! volume — by us, by a backup agent, by malware that catches the drive while
//! it happens to be mounted — reveals ciphertext and nothing else.
//!
//! Construction — two ciphers in cascade:
//!
//! ```text
//! master_key = Argon2id(secret, salt)                        // 32 bytes
//! seed       = 32 fresh random bytes, per save
//! key_inner  = HKDF-SHA256(master_key, salt = seed, "xchacha…")
//! key_outer  = HKDF-SHA256(master_key, salt = seed, "aes…")
//!
//! inner = XChaCha20-Poly1305(key_inner, nonce = 0, aad = header, plaintext)
//! blob  = header ‖ AES-256-GCM(key_outer, nonce = 0, aad = header, inner)
//! ```
//!
//! A fresh 32-byte `seed` per save makes both keys unique per save, so the
//! all-zero nonces can never repeat under a given key. This is the standard
//! derive-a-key-per-message construction (the same idea as XAES-256-GCM); it
//! removes the birthday-bound concern that random 96-bit GCM nonces carry, and
//! it means no nonce counter has to survive across saves.
//!
//! # Why two ciphers, and why only one Argon2id
//!
//! The cascade guards against a catastrophic break or an implementation bug in
//! one primitive: AES-GCM and XChaCha20-Poly1305 share no structure, and the
//! two keys are independent HKDF outputs.
//!
//! Argon2id still runs **once**. Running it twice, once per cipher, would
//! double the honest user's unlock time and buy nothing: an attacker testing a
//! password guess only has to derive the outer key and see whether its tag
//! verifies, so their cost per guess would not change. The expensive step
//! protects the password; the cascade protects against the ciphers.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};
use crate::secret::{Key, Secret};

pub const MAGIC: &[u8; 8] = b"DDVAULT1";
pub const FORMAT_VERSION: u8 = 1;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const SEED_LEN: usize = 32;
const GCM_TAG_LEN: usize = 16;
const GCM_NONCE: [u8; 12] = [0u8; 12];
const XCHACHA_NONCE: [u8; 24] = [0u8; 24];
/// Distinct labels are what make the two cipher keys independent.
const HKDF_INFO_OUTER: &[u8] = b"deep-defense/vault-data-key/v1";
const HKDF_INFO_INNER: &[u8] = b"deep-defense/vault-inner-key/xchacha20poly1305/v1";

/// Cipher suite names as they appear in the vault header.
const CIPHER_CASCADE: &str = "AES-256-GCM+XChaCha20-Poly1305";
/// Written by builds before the cascade existed; still readable.
const CIPHER_LEGACY_AES: &str = "AES-256-GCM";

/// Which cipher arrangement a given vault file uses.
///
/// Recorded in the header rather than in the format version, because the
/// container layout is unchanged — only the cipher stack differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    /// AES-256-GCM alone.
    Aes,
    /// XChaCha20-Poly1305 wrapped in AES-256-GCM.
    Cascade,
}

impl Suite {
    fn from_name(name: &str) -> Result<Self> {
        match name {
            CIPHER_CASCADE => Ok(Suite::Cascade),
            CIPHER_LEGACY_AES => Ok(Suite::Aes),
            other => Err(Error::format(format!("unsupported cipher \"{other}\""))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Suite::Cascade => CIPHER_CASCADE,
            Suite::Aes => CIPHER_LEGACY_AES,
        }
    }

    /// What to show the user in the vault-information panel.
    pub fn display(self) -> &'static str {
        match self {
            Suite::Cascade => "XChaCha20-Poly1305 → AES-256-GCM",
            Suite::Aes => "AES-256-GCM",
        }
    }
}

/// Argon2id cost parameters, stored in the clear inside the vault header.
///
/// They have to be readable before decryption — we cannot derive the key
/// without them — and publishing them costs nothing: an attacker holding the
/// file can see how expensive each guess will be, which is the entire point.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory per guess, in KiB.
    pub m_cost: u32,
    /// Passes over memory.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "argon2id".to_string()
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 262_144, // 256 MiB per guess
            t_cost: 4,
            p_cost: 4,
            algorithm: default_algorithm(),
        }
    }
}

impl KdfParams {
    /// Floors, not suggestions. Below these, a GPU farm makes brute force
    /// cheap enough that the master password carries the entire burden.
    pub const MIN_M_COST: u32 = 65_536; // 64 MiB
    pub const MIN_T_COST: u32 = 2;

    pub fn validate(&self) -> Result<()> {
        if self.algorithm != "argon2id" {
            return Err(Error::crypto(format!(
                "unsupported KDF \"{}\" — this vault was written by a different tool",
                self.algorithm
            )));
        }
        if self.m_cost < Self::MIN_M_COST {
            return Err(Error::crypto(format!(
                "Argon2 memory cost {} KiB is below the safe floor of {} KiB",
                self.m_cost,
                Self::MIN_M_COST
            )));
        }
        if self.t_cost < Self::MIN_T_COST {
            return Err(Error::crypto(format!(
                "Argon2 time cost {} is below the safe floor of {}",
                self.t_cost,
                Self::MIN_T_COST
            )));
        }
        if self.p_cost < 1 {
            return Err(Error::crypto("Argon2 parallelism must be at least 1"));
        }
        Ok(())
    }

    pub fn memory_mib(&self) -> u32 {
        self.m_cost / 1024
    }

    /// Roughly how long one guess takes here, measured rather than assumed.
    pub fn measure(&self) -> Result<std::time::Duration> {
        let salt = [0x42u8; SALT_LEN];
        let probe = Secret::from_str("calibration-probe");
        let start = std::time::Instant::now();
        let _ = derive_master_key(&probe, &salt, self)?;
        Ok(start.elapsed())
    }

    /// Pick the heaviest parameters this machine can run in `target`.
    ///
    /// Tuning to the defender's hardware is the only honest way to set these:
    /// a fixed constant is either painful on a laptop or trivial on a server.
    pub fn calibrated(target: std::time::Duration, max_memory_mib: u32) -> Self {
        let mut best = Self {
            m_cost: Self::MIN_M_COST,
            ..Default::default()
        };
        let mut m_cost = Self::MIN_M_COST;
        while m_cost <= max_memory_mib * 1024 {
            let candidate = Self {
                m_cost,
                ..Default::default()
            };
            match candidate.measure() {
                Ok(elapsed) if elapsed <= target => {
                    best = candidate;
                    m_cost = match m_cost.checked_mul(2) {
                        Some(next) => next,
                        None => break,
                    };
                }
                _ => break,
            }
        }
        best
    }
}

/// Authenticated-but-public metadata prepended to every sealed blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultHeader {
    pub cipher: String,
    pub kdf: KdfParams,
    /// Base64, because the header travels as JSON.
    pub salt: String,
    #[serde(default)]
    pub created_at: String,
}

impl VaultHeader {
    pub fn new(kdf: KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        Ok(Self {
            cipher: CIPHER_CASCADE.to_string(),
            kdf,
            salt: BASE64.encode(salt),
            created_at: chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
    }

    pub fn suite(&self) -> Result<Suite> {
        Suite::from_name(&self.cipher)
    }

    pub fn salt_bytes(&self) -> Result<Vec<u8>> {
        let salt = BASE64
            .decode(&self.salt)
            .map_err(|_| Error::format("vault salt is not valid base64"))?;
        if salt.len() < 16 {
            return Err(Error::format("vault salt is too short to be safe"));
        }
        Ok(salt)
    }

    fn validate(&self) -> Result<()> {
        self.suite()?;
        self.kdf.validate()
    }
}

/// Fill a buffer from the operating system's CSPRNG.
///
/// Every random byte in this program comes through here. A failure is fatal
/// rather than silently degraded: generating a key from a broken entropy
/// source is worse than refusing to generate one at all.
pub fn random_bytes(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|e| {
        Error::crypto(format!(
            "the operating system's random number generator failed ({e}); \
             refusing to generate a key"
        ))
    })
}

/// Run Argon2id. This is the deliberately slow step — never cache its input.
pub fn derive_master_key(secret: &Secret, salt: &[u8], params: &KdfParams) -> Result<Key> {
    params.validate()?;
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| Error::crypto(format!("invalid Argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Key::zeroed();
    argon
        .hash_password_into(secret.expose(), salt, key.as_mut())
        .map_err(|e| Error::crypto(format!("Argon2id failed: {e}")))?;
    Ok(key)
}

/// Bind a password and any keyfiles into the single secret fed to Argon2id.
///
/// With keyfiles present, the password alone is not enough and the keyfiles
/// alone are not enough either. The fold is order-independent, matching
/// VeraCrypt's behaviour, so the user never has to remember which keyfile
/// they listed first.
pub fn combine_secret(password: &Secret, keyfiles: &[std::path::PathBuf]) -> Result<Secret> {
    use hmac::{Hmac, KeyInit as MacInit, Mac};
    use sha2::Digest;

    if keyfiles.is_empty() {
        return Ok(Secret::new(password.expose().to_vec()));
    }

    let mut digests: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(keyfiles.len());
    for path in keyfiles {
        let data = Zeroizing::new(
            std::fs::read(path).map_err(|e| Error::io(path.clone(), e))?,
        );
        digests.push(Zeroizing::new(Sha512::digest(&data).to_vec()));
    }
    // Sort the digests, not the paths, so the result does not depend on the
    // order the user happened to list their keyfiles in.
    digests.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));

    let combined = {
        let mut hasher = Sha512::new();
        for digest in &digests {
            hasher.update(digest.as_slice());
        }
        Zeroizing::new(hasher.finalize().to_vec())
    };

    let mut mac = <Hmac<Sha512> as MacInit>::new_from_slice(&combined)
        .map_err(|e| Error::crypto(format!("keyfile HMAC setup failed: {e}")))?;
    mac.update(password.expose());
    Ok(Secret::new(mac.finalize().into_bytes().to_vec()))
}

fn subkey(master_key: &Key, seed: &[u8], info: &[u8]) -> Result<Key> {
    let hkdf = Hkdf::<sha2::Sha256>::new(Some(seed), master_key.as_bytes());
    let mut derived = Key::zeroed();
    hkdf.expand(info, derived.as_mut())
        .map_err(|e| Error::crypto(format!("HKDF expansion failed: {e}")))?;
    Ok(derived)
}

/// The inner XChaCha20-Poly1305 layer.
fn seal_inner(plaintext: &[u8], key: &Key, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| Error::crypto("XChaCha20-Poly1305 rejected the derived key"))?;
    cipher
        .encrypt(
            &XNonce::from(XCHACHA_NONCE),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::crypto("XChaCha20-Poly1305 encryption failed"))
}

fn open_inner(ciphertext: &[u8], key: &Key, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| Error::crypto("XChaCha20-Poly1305 rejected the derived key"))?;
    cipher
        .decrypt(
            &XNonce::from(XCHACHA_NONCE),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)
}

/// Assemble the authenticated prefix: magic, version, header and seed.
///
/// Everything before the ciphertext is fed to GCM as associated data, so an
/// attacker cannot downgrade the KDF parameters or swap the salt without the
/// tag check failing.
fn build_prefix(header_json: &[u8], seed: &[u8]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(MAGIC.len() + 3 + header_json.len() + seed.len());
    prefix.extend_from_slice(MAGIC);
    prefix.push(FORMAT_VERSION);
    prefix.extend_from_slice(&(header_json.len() as u16).to_be_bytes());
    prefix.extend_from_slice(header_json);
    prefix.extend_from_slice(seed);
    prefix
}

/// Encrypt with both ciphers, given an explicit seed and associated data.
///
/// Split out from [`seal`] so the multi-slot format in [`crate::slots`] can
/// use the same construction without inheriting the v1 file layout.
pub fn seal_cascade(
    plaintext: &[u8],
    master_key: &Key,
    seed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    // Inward-out: XChaCha20-Poly1305 first, then AES-256-GCM over its output,
    // so breaking AES alone still leaves an authenticated ChaCha layer.
    let inner = {
        let key = subkey(master_key, seed, HKDF_INFO_INNER)?;
        Zeroizing::new(seal_inner(plaintext, &key, aad)?)
    };
    let outer_key = subkey(master_key, seed, HKDF_INFO_OUTER)?;
    let cipher = Aes256Gcm::new_from_slice(outer_key.as_bytes())
        .map_err(|_| Error::crypto("AES-256-GCM rejected the derived key"))?;
    cipher
        .encrypt(
            &Nonce::from(GCM_NONCE),
            Payload {
                msg: &inner,
                aad,
            },
        )
        .map_err(|_| Error::crypto("AES-GCM encryption failed"))
}

/// The inverse of [`seal_cascade`].
pub fn open_cascade(
    ciphertext: &[u8],
    master_key: &Key,
    seed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let outer_key = subkey(master_key, seed, HKDF_INFO_OUTER)?;
    let cipher = Aes256Gcm::new_from_slice(outer_key.as_bytes())
        .map_err(|_| Error::crypto("AES-256-GCM rejected the derived key"))?;
    let inner = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(GCM_NONCE),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let key = subkey(master_key, seed, HKDF_INFO_INNER)?;
    Ok(Zeroizing::new(open_inner(&inner, &key, aad)?))
}

/// Encrypt `plaintext` into the on-disk blob format.
pub fn seal(plaintext: &[u8], master_key: &Key, header: &VaultHeader) -> Result<Vec<u8>> {
    header.validate()?;
    let header_json = serde_json::to_vec(header)
        .map_err(|e| Error::crypto(format!("cannot serialise vault header: {e}")))?;
    if header_json.len() > u16::MAX as usize {
        return Err(Error::crypto("vault header is implausibly large"));
    }

    let mut seed = [0u8; SEED_LEN];
    random_bytes(&mut seed)?;
    let prefix = build_prefix(&header_json, &seed);
    let suite = header.suite()?;

    let ciphertext = match suite {
        Suite::Cascade => seal_cascade(plaintext, master_key, &seed, &prefix)?,
        Suite::Aes => {
            let outer_key = subkey(master_key, &seed, HKDF_INFO_OUTER)?;
            let cipher = Aes256Gcm::new_from_slice(outer_key.as_bytes())
                .map_err(|_| Error::crypto("AES-256-GCM rejected the derived key"))?;
            cipher
                .encrypt(
                    &Nonce::from(GCM_NONCE),
                    Payload {
                        msg: plaintext,
                        aad: &prefix,
                    },
                )
                .map_err(|_| Error::crypto("AES-GCM encryption failed"))?
        }
    };

    let mut blob = prefix;
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Split a blob into (header, raw header bytes, seed offset), without the key.
fn split(blob: &[u8]) -> Result<(VaultHeader, usize)> {
    if blob.len() < MAGIC.len() + 3 || &blob[..MAGIC.len()] != MAGIC {
        return Err(Error::format(
            "this file is not a Deep Defense vault (wrong magic bytes)",
        ));
    }
    let version = blob[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(Error::format(format!(
            "vault format version {version} was written by a newer build of this program"
        )));
    }
    let len_at = MAGIC.len() + 1;
    let header_len = u16::from_be_bytes([blob[len_at], blob[len_at + 1]]) as usize;
    let header_at = len_at + 2;
    let seed_at = header_at + header_len;
    if blob.len() < seed_at + SEED_LEN + GCM_TAG_LEN {
        return Err(Error::format("vault file is truncated"));
    }
    let header: VaultHeader = serde_json::from_slice(&blob[header_at..seed_at])
        .map_err(|e| Error::format(format!("vault header is unreadable: {e}")))?;
    header.validate()?;
    Ok((header, seed_at))
}

/// Read the public header without needing the key.
pub fn parse_header(blob: &[u8]) -> Result<VaultHeader> {
    split(blob).map(|(header, _)| header)
}

/// Authenticate and decrypt a sealed blob.
///
/// Returns the plaintext, the header, and the derived master key, so the
/// caller can re-seal later without paying for Argon2id a second time.
pub fn unseal(blob: &[u8], secret: &Secret) -> Result<(Zeroizing<Vec<u8>>, VaultHeader, Key)> {
    let (header, seed_at) = split(blob)?;
    let salt = header.salt_bytes()?;
    let seed = &blob[seed_at..seed_at + SEED_LEN];
    let ciphertext = &blob[seed_at + SEED_LEN..];
    // Authenticate exactly the bytes on disk, not a re-serialisation of the
    // parsed header — otherwise a change in serde's field order across
    // versions would silently break every existing vault.
    let prefix = &blob[..seed_at + SEED_LEN];

    let suite = header.suite()?;
    let master_key = derive_master_key(secret, &salt, &header.kdf)?;

    let plaintext = match suite {
        Suite::Cascade => open_cascade(ciphertext, &master_key, seed, prefix)?,
        Suite::Aes => {
            let outer_key = subkey(&master_key, seed, HKDF_INFO_OUTER)?;
            let cipher = Aes256Gcm::new_from_slice(outer_key.as_bytes())
                .map_err(|_| Error::crypto("AES-256-GCM rejected the derived key"))?;
            Zeroizing::new(
                cipher
                    .decrypt(
                        &Nonce::from(GCM_NONCE),
                        Payload {
                            msg: ciphertext,
                            aad: prefix,
                        },
                    )
                    // A tag failure means either a wrong key or a modified
                    // file, and we deliberately do not say which.
                    .map_err(|_| Error::Authentication)?,
            )
        }
    };

    Ok((plaintext, header, master_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        // Fast enough for a test suite, still above the validation floor.
        KdfParams {
            m_cost: KdfParams::MIN_M_COST,
            t_cost: 2,
            p_cost: 1,
            algorithm: "argon2id".into(),
        }
    }

    fn sealed(plaintext: &[u8], password: &str) -> (Vec<u8>, VaultHeader) {
        let header = VaultHeader::new(test_params()).unwrap();
        let secret = Secret::from_str(password);
        let key = derive_master_key(&secret, &header.salt_bytes().unwrap(), &header.kdf).unwrap();
        (seal(plaintext, &key, &header).unwrap(), header)
    }

    #[test]
    fn roundtrip_recovers_the_plaintext() {
        let (blob, _) = sealed(b"correct data", "master password");
        let (plaintext, _, _) = unseal(&blob, &Secret::from_str("master password")).unwrap();
        assert_eq!(plaintext.as_slice(), b"correct data");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (blob, _) = sealed(b"correct data", "master password");
        let err = unseal(&blob, &Secret::from_str("wrong password")).unwrap_err();
        assert!(matches!(err, Error::Authentication));
    }

    #[test]
    fn flipping_a_ciphertext_bit_is_detected() {
        let (mut blob, _) = sealed(b"correct data", "pw");
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(matches!(
            unseal(&blob, &Secret::from_str("pw")).unwrap_err(),
            Error::Authentication
        ));
    }

    #[test]
    fn downgrading_the_kdf_in_the_header_is_detected() {
        // The header is the AAD, so an attacker cannot lower the Argon2 cost
        // to make brute force cheap without breaking the tag.
        let (blob, _) = sealed(b"correct data", "pw");
        // Search the raw bytes: the blob is not valid UTF-8, and a lossy
        // conversion shifts indices wherever it substitutes U+FFFD.
        let needle = b"\"m_cost\":";
        let start = blob
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("the header is JSON and carries m_cost");
        let mut tampered = blob.clone();
        // Rewrite 65536 -> 65535 in place: same byte length, lower cost.
        let digits = start + needle.len();
        tampered[digits..digits + 5].copy_from_slice(b"65535");
        let err = unseal(&tampered, &Secret::from_str("pw")).unwrap_err();
        // Either the floor check or the tag rejects it — both are correct.
        assert!(matches!(err, Error::Authentication | Error::Crypto(_)));
    }

    #[test]
    fn new_vaults_use_the_cascade() {
        let header = VaultHeader::new(test_params()).unwrap();
        assert_eq!(header.suite().unwrap(), Suite::Cascade);
        assert!(header.cipher.contains("XChaCha20"));
    }

    #[test]
    fn the_cascade_really_applies_both_layers() {
        // Decrypting only the outer AES layer must NOT reveal the plaintext.
        // If this ever passes trivially, the inner layer has stopped running.
        let header = VaultHeader::new(test_params()).unwrap();
        let secret = Secret::from_str("pw");
        let salt = header.salt_bytes().unwrap();
        let master = derive_master_key(&secret, &salt, &header.kdf).unwrap();
        let plaintext = b"a recognisable marker string";
        let blob = seal(plaintext, &master, &header).unwrap();

        let header_len = serde_json::to_vec(&header).unwrap().len();
        let offset = MAGIC.len() + 1 + 2 + header_len;
        let seed = &blob[offset..offset + SEED_LEN];
        let prefix = &blob[..offset + SEED_LEN];
        let ciphertext = &blob[offset + SEED_LEN..];

        let outer_key = subkey(&master, seed, HKDF_INFO_OUTER).unwrap();
        let cipher = Aes256Gcm::new_from_slice(outer_key.as_bytes()).unwrap();
        let after_outer = cipher
            .decrypt(
                &Nonce::from(GCM_NONCE),
                Payload {
                    msg: ciphertext,
                    aad: prefix,
                },
            )
            .expect("the outer layer is AES-256-GCM and must open");

        assert_ne!(after_outer.as_slice(), plaintext, "inner layer is missing");
        assert!(!after_outer
            .windows(plaintext.len())
            .any(|w| w == plaintext));

        // ...and peeling the inner layer too does reveal it.
        let inner_key = subkey(&master, seed, HKDF_INFO_INNER).unwrap();
        let recovered = open_inner(&after_outer, &inner_key, prefix).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn the_two_cipher_keys_are_different() {
        // Same key for both layers would make the cascade decorative.
        let secret = Secret::from_str("pw");
        let master = derive_master_key(&secret, &[3u8; SALT_LEN], &test_params()).unwrap();
        let seed = [9u8; SEED_LEN];
        let outer = subkey(&master, &seed, HKDF_INFO_OUTER).unwrap();
        let inner = subkey(&master, &seed, HKDF_INFO_INNER).unwrap();
        assert_ne!(outer.as_bytes(), inner.as_bytes());
    }

    #[test]
    fn tampering_with_the_inner_ciphertext_is_caught() {
        let (mut blob, _) = sealed(b"data worth protecting", "pw");
        // Flip a byte in the middle of the ciphertext rather than the tag.
        let middle = blob.len() - 24;
        blob[middle] ^= 0x40;
        assert!(matches!(
            unseal(&blob, &Secret::from_str("pw")).unwrap_err(),
            Error::Authentication
        ));
    }

    #[test]
    fn a_legacy_single_cipher_vault_still_opens() {
        // Vaults written before the cascade existed must keep working; the
        // header names the suite, so we can tell them apart.
        let mut header = VaultHeader::new(test_params()).unwrap();
        header.cipher = CIPHER_LEGACY_AES.to_string();
        assert_eq!(header.suite().unwrap(), Suite::Aes);

        let secret = Secret::from_str("old vault");
        let key = derive_master_key(&secret, &header.salt_bytes().unwrap(), &header.kdf).unwrap();
        let blob = seal(b"written by an older build", &key, &header).unwrap();

        let (plaintext, reopened, _) = unseal(&blob, &secret).unwrap();
        assert_eq!(plaintext.as_slice(), b"written by an older build");
        assert_eq!(reopened.suite().unwrap(), Suite::Aes);
    }

    #[test]
    fn an_unknown_cipher_name_is_refused() {
        let mut header = VaultHeader::new(test_params()).unwrap();
        header.cipher = "AES-128-CBC".to_string();
        assert!(header.suite().is_err());
    }

    /// The nonce is a constant, so safety rests entirely on the *key* being
    /// fresh for every save. This is the test that holds that claim up.
    ///
    /// Reusing a (key, nonce) pair under AES-GCM is catastrophic: it leaks the
    /// XOR of the two plaintexts and, worse, the authentication subkey. The
    /// usual defence is a unique IV per message; here it is a unique key per
    /// message instead, derived from 32 fresh random bytes. That is the same
    /// construction as XAES-256-GCM, and it is stronger than random 96-bit
    /// nonces, which start colliding around 2^32 messages.
    #[test]
    fn every_save_uses_a_fresh_key_so_the_fixed_nonce_is_safe() {
        use std::collections::HashSet;

        const SAVES: usize = 256;
        let header = VaultHeader::new(test_params()).unwrap();
        let secret = Secret::from_str("pw");
        let master =
            derive_master_key(&secret, &header.salt_bytes().unwrap(), &header.kdf).unwrap();

        let header_len = serde_json::to_vec(&header).unwrap().len();
        let seed_at = MAGIC.len() + 1 + 2 + header_len;

        let mut seeds = HashSet::new();
        let mut outer_keys = HashSet::new();
        let mut inner_keys = HashSet::new();
        let mut ciphertexts = HashSet::new();

        for _ in 0..SAVES {
            // Identical plaintext every time: any repetition in the output
            // would then be entirely down to key reuse.
            let blob = seal(b"the same plaintext every time", &master, &header).unwrap();
            let seed = blob[seed_at..seed_at + SEED_LEN].to_vec();

            outer_keys.insert(subkey(&master, &seed, HKDF_INFO_OUTER).unwrap().as_bytes().to_vec());
            inner_keys.insert(subkey(&master, &seed, HKDF_INFO_INNER).unwrap().as_bytes().to_vec());
            ciphertexts.insert(blob[seed_at + SEED_LEN..].to_vec());
            seeds.insert(seed);
        }

        assert_eq!(seeds.len(), SAVES, "a seed repeated across saves");
        assert_eq!(outer_keys.len(), SAVES, "an AES key repeated across saves");
        assert_eq!(inner_keys.len(), SAVES, "a ChaCha key repeated across saves");
        assert_eq!(ciphertexts.len(), SAVES, "a ciphertext repeated across saves");
    }

    #[test]
    fn the_seed_is_full_length_and_not_a_constant() {
        // A seed that was accidentally left zeroed would make every key equal
        // and every one of the assertions above trivially true in the wrong
        // direction, so check the seed itself looks random.
        let (blob, header) = sealed(b"data", "pw");
        let header_len = serde_json::to_vec(&header).unwrap().len();
        let seed_at = MAGIC.len() + 1 + 2 + header_len;
        let seed = &blob[seed_at..seed_at + SEED_LEN];

        assert_eq!(seed.len(), 32);
        assert!(seed.iter().any(|b| *b != 0), "the seed is all zeroes");
        assert!(
            seed.iter().collect::<std::collections::HashSet<_>>().len() > 8,
            "the seed has suspiciously little variety"
        );
    }

    #[test]
    fn a_different_salt_gives_a_different_master_key() {
        // Two vaults created with the same password must not share a key.
        let secret = Secret::from_str("same password");
        let a = derive_master_key(&secret, &[1u8; SALT_LEN], &test_params()).unwrap();
        let b = derive_master_key(&secret, &[2u8; SALT_LEN], &test_params()).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn two_seals_of_identical_data_differ() {
        // A fresh seed per save is what lets us use a fixed nonce safely.
        let header = VaultHeader::new(test_params()).unwrap();
        let secret = Secret::from_str("pw");
        let key = derive_master_key(&secret, &header.salt_bytes().unwrap(), &header.kdf).unwrap();
        let first = seal(b"same plaintext", &key, &header).unwrap();
        let second = seal(b"same plaintext", &key, &header).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn keyfiles_change_the_derived_secret_and_ignore_order() {
        let dir = std::env::temp_dir().join("dd-keyfile-test");
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.key");
        let b = dir.join("b.key");
        std::fs::write(&a, b"first keyfile").unwrap();
        std::fs::write(&b, b"second keyfile").unwrap();

        let password = Secret::from_str("pw");
        let plain = combine_secret(&password, &[]).unwrap();
        let with_ab = combine_secret(&password, &[a.clone(), b.clone()]).unwrap();
        let with_ba = combine_secret(&password, &[b.clone(), a.clone()]).unwrap();

        assert_ne!(plain.expose(), with_ab.expose());
        assert_eq!(with_ab.expose(), with_ba.expose());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_files_are_rejected_cleanly() {
        let (blob, _) = sealed(b"data", "pw");
        let err = unseal(&blob[..blob.len() / 2], &Secret::from_str("pw")).unwrap_err();
        assert!(matches!(err, Error::Format(_)));
    }

    #[test]
    fn a_foreign_file_is_rejected_by_magic() {
        let err = parse_header(b"this is just some other file entirely").unwrap_err();
        assert!(matches!(err, Error::Format(_)));
    }

    #[test]
    fn weak_kdf_parameters_are_refused() {
        let weak = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            algorithm: "argon2id".into(),
        };
        assert!(weak.validate().is_err());
    }
}
