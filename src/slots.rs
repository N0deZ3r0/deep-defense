//! The multi-slot vault file, and the deniability it buys.
//!
//! # The problem this solves
//!
//! Encryption is no help against a person who can compel you to hand over the
//! password — the threat the README calls "принуждение". The only defence that
//! works there is being able to hand over *a* password: one that opens a
//! plausible vault, while the real one stays invisible.
//!
//! # Why every vault has slots, always
//!
//! The obvious design — a special "vault with a hidden compartment" format —
//! defeats itself: possessing that format is the confession. So every file
//! this program writes has the same fixed number of slots, in the same fixed
//! layout, whether or not a second vault exists.
//!
//! A slot is `salt ‖ seed ‖ ciphertext`. All three are indistinguishable from
//! random bytes, so an unused slot filled with `getrandom` output cannot be
//! told apart from one holding a vault. There is no count, no flag, no length
//! anywhere in the file to say which is which — the only way to learn that a
//! slot holds data is to know its password.
//!
//! # What it does not do
//!
//! Someone who knows this program exists knows the file has two slots. They
//! cannot prove the second one holds anything, but they can ask. Deniability
//! is a position you can hold, not a proof of innocence. It also cannot help
//! if your machine is already compromised: a keylogger sees whichever password
//! you type, including the real one.

use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, SALT_LEN, SEED_LEN};
use crate::errors::{Error, Result};
use crate::secret::{Key, Secret};

/// Slots per file. Fixed, and deliberately not configurable: a file with an
/// unusual slot count would stand out from every other file this program
/// writes, which is exactly what the design is trying to avoid.
pub const SLOT_COUNT: usize = 2;

/// The slot an ordinary vault lives in.
pub const PRIMARY_SLOT: usize = 0;
/// The slot a hidden vault lives in, when there is one.
pub const HIDDEN_SLOT: usize = 1;

pub const MAGIC: &[u8; 8] = b"DDVAULT2";
pub const FORMAT_VERSION: u8 = 2;

/// Default room per slot for the encrypted payload, before padding overhead.
///
/// Every slot is padded to exactly this size, so the file never reveals how
/// much any slot actually holds — or whether it holds anything. The cost is a
/// file of a fixed size regardless of content.
pub const DEFAULT_SLOT_CAPACITY: usize = 4 * 1024 * 1024;
pub const MIN_SLOT_CAPACITY: usize = 64 * 1024;
pub const MAX_SLOT_CAPACITY: usize = 64 * 1024 * 1024;

/// Four bytes of length prefix inside the padded plaintext.
const LENGTH_PREFIX: usize = 4;
/// One authentication tag per cipher in the cascade.
const CASCADE_OVERHEAD: usize = 32;

/// Bytes on disk for one slot.
pub fn slot_size(capacity: usize) -> usize {
    SALT_LEN + SEED_LEN + capacity + CASCADE_OVERHEAD
}

/// Public, authenticated file header. Identical for every file this program
/// writes, apart from the cost parameters and the slot size.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FileHeader {
    pub kdf: KdfParams,
    pub slot_capacity: usize,
    pub cipher: String,
}

impl FileHeader {
    pub fn new(kdf: KdfParams, slot_capacity: usize) -> Result<Self> {
        if !(MIN_SLOT_CAPACITY..=MAX_SLOT_CAPACITY).contains(&slot_capacity) {
            return Err(Error::format(format!(
                "slot capacity {slot_capacity} is outside the supported range"
            )));
        }
        Ok(Self {
            kdf,
            slot_capacity,
            cipher: crypto::Suite::Cascade.name().to_owned(),
        })
    }

    fn validate(&self) -> Result<()> {
        if !(MIN_SLOT_CAPACITY..=MAX_SLOT_CAPACITY).contains(&self.slot_capacity) {
            return Err(Error::format("slot capacity in the file header is implausible"));
        }
        self.kdf.validate()
    }

    /// The largest payload a slot can hold.
    pub fn max_payload(&self) -> usize {
        self.slot_capacity - LENGTH_PREFIX
    }
}

/// What opening a slot yields: the payload plus everything needed to write it
/// back later without paying for Argon2id a second time.
pub struct Opened {
    pub payload: Zeroizing<Vec<u8>>,
    pub master_key: Key,
    pub salt: Vec<u8>,
}

/// A whole vault file: a header and a fixed number of fixed-size slots.
#[derive(Clone)]
pub struct SlotFile {
    pub header: FileHeader,
    header_json: Vec<u8>,
    slots: Vec<Vec<u8>>,
}

impl SlotFile {
    /// A brand-new file in which *every* slot is random noise.
    ///
    /// Writing all slots as random up front is what makes an unused slot
    /// indistinguishable later: the bytes were never zero, never a recognisable
    /// structure, and were not written at a different time from the rest.
    pub fn new_random(header: FileHeader) -> Result<Self> {
        header.validate()?;
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| Error::format(format!("cannot serialise the file header: {e}")))?;

        let size = slot_size(header.slot_capacity);
        let mut slots = Vec::with_capacity(SLOT_COUNT);
        for _ in 0..SLOT_COUNT {
            let mut noise = vec![0u8; size];
            crypto::random_bytes(&mut noise)?;
            slots.push(noise);
        }
        Ok(Self {
            header,
            header_json,
            slots,
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() + 3 || &bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::format(
                "this file is not a Deep Defense vault (wrong magic bytes)",
            ));
        }
        let version = bytes[MAGIC.len()];
        if version != FORMAT_VERSION {
            return Err(Error::format(format!(
                "vault format version {version} was written by a different build"
            )));
        }
        let len_at = MAGIC.len() + 1;
        let header_len = u16::from_be_bytes([bytes[len_at], bytes[len_at + 1]]) as usize;
        let header_at = len_at + 2;
        let slots_at = header_at + header_len;
        if bytes.len() < slots_at {
            return Err(Error::format("vault file is truncated"));
        }

        let header: FileHeader = serde_json::from_slice(&bytes[header_at..slots_at])
            .map_err(|e| Error::format(format!("vault header is unreadable: {e}")))?;
        header.validate()?;

        let size = slot_size(header.slot_capacity);
        if bytes.len() != slots_at + size * SLOT_COUNT {
            return Err(Error::format(
                "vault file is the wrong length for its header — it may be truncated",
            ));
        }

        let slots = (0..SLOT_COUNT)
            .map(|i| bytes[slots_at + size * i..slots_at + size * (i + 1)].to_vec())
            .collect();
        Ok(Self {
            header,
            header_json: bytes[header_at..slots_at].to_vec(),
            slots,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MAGIC.len() + 3 + self.header_json.len() + self.slots.iter().map(Vec::len).sum::<usize>(),
        );
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&(self.header_json.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.header_json);
        for slot in &self.slots {
            out.extend_from_slice(slot);
        }
        out
    }

    /// Associated data for one slot: the header plus the slot's position.
    ///
    /// Binding the index stops an attacker swapping two slots around, and
    /// binding the header stops them lowering the Argon2 cost.
    fn aad(&self, index: usize) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.header_json.len() + 9);
        aad.extend_from_slice(MAGIC);
        aad.push(FORMAT_VERSION);
        aad.extend_from_slice(&self.header_json);
        aad.push(index as u8);
        aad
    }

    /// Try to open one slot. Failure is indistinguishable from "this slot is
    /// noise", which is the entire point.
    /// The first bytes of a slot: its salt when it holds a vault, noise when
    /// it does not. Nothing here can tell which, and nothing needs to.
    pub fn slot_salt(&self, index: usize) -> &[u8] {
        &self.slots[index][..SALT_LEN]
    }

    pub fn open_slot(&self, index: usize, secret: &Secret) -> Result<Opened> {
        let slot = self
            .slots
            .get(index)
            .ok_or_else(|| Error::format("slot index out of range"))?;
        let salt = slot[..SALT_LEN].to_vec();
        let master_key = crypto::derive_master_key(secret, &salt, &self.header.kdf)?;
        let payload = self.open_slot_with_key(index, &master_key)?;
        Ok(Opened {
            payload,
            master_key,
            salt,
        })
    }

    /// Open a slot with a key that has already been derived.
    ///
    /// For comparing copies of a vault that is open: the key is the one its
    /// slot was derived with, so a copy it opens is a copy of the same vault
    /// under the same password — and no Argon2id pass is paid per copy.
    pub fn open_slot_with_key(&self, index: usize, master_key: &Key) -> Result<Zeroizing<Vec<u8>>> {
        let slot = self
            .slots
            .get(index)
            .ok_or_else(|| Error::format("slot index out of range"))?;
        let aad = self.aad(index);
        let seed = &slot[SALT_LEN..SALT_LEN + SEED_LEN];
        let ciphertext = &slot[SALT_LEN + SEED_LEN..];
        let padded = crypto::open_cascade(ciphertext, master_key, seed, &aad)?;
        unpad(&padded)
    }

    /// Derive a key and salt for a slot that has never been written.
    pub fn prepare_slot(&self, secret: &Secret) -> Result<(Key, Vec<u8>)> {
        let mut salt = vec![0u8; SALT_LEN];
        crypto::random_bytes(&mut salt)?;
        let key = crypto::derive_master_key(secret, &salt, &self.header.kdf)?;
        Ok((key, salt))
    }

    /// Seal `payload` into `index`, leaving every other slot byte-identical.
    ///
    /// Only the slot being saved is rewritten. That is what lets the decoy be
    /// edited without destroying the hidden vault — and it is also deliberate
    /// for deniability: an untouched slot looks the same whether it holds
    /// noise or a vault whose password we do not have. Refreshing the noise
    /// would make "this region never changes" a tell for a hidden vault, to
    /// anyone comparing two snapshots of the file over time.
    ///
    /// `salt` and `master_key` come from [`Self::open_slot`] or
    /// [`Self::prepare_slot`]; the salt stays with the slot for its lifetime
    /// while the per-save seed is fresh, so no (key, nonce) pair repeats.
    pub fn write_slot(
        &mut self,
        index: usize,
        payload: &[u8],
        master_key: &Key,
        salt: &[u8],
    ) -> Result<()> {
        if index >= SLOT_COUNT {
            return Err(Error::format("slot index out of range"));
        }
        if salt.len() != SALT_LEN {
            return Err(Error::format("slot salt is the wrong length"));
        }
        if payload.len() > self.header.max_payload() {
            return Err(Error::vault(format!(
                "this vault holds {} bytes, more than the {} a slot was created with. \
                 Remove some attachments, or create a new vault with a larger slot size.",
                payload.len(),
                self.header.max_payload()
            )));
        }

        let mut seed = [0u8; SEED_LEN];
        crypto::random_bytes(&mut seed)?;

        let padded = pad(payload, self.header.slot_capacity)?;
        let aad = self.aad(index);
        let ciphertext = crypto::seal_cascade(&padded, master_key, &seed, &aad)?;

        let mut slot = Vec::with_capacity(slot_size(self.header.slot_capacity));
        slot.extend_from_slice(salt);
        slot.extend_from_slice(&seed);
        slot.extend_from_slice(&ciphertext);
        debug_assert_eq!(slot.len(), slot_size(self.header.slot_capacity));
        self.slots[index] = slot;
        Ok(())
    }

    /// Open whichever slot this password belongs to, trying each in turn.
    ///
    /// The slots are tried in parallel when the memory cost allows it: two
    /// Argon2id passes back to back would double the wait on every unlock,
    /// and the whole point is that the user cannot be asked which slot they
    /// meant. Above a gigabyte of total Argon2 memory it falls back to
    /// sequential, because two simultaneous large allocations are a worse
    /// failure than a slower unlock.
    pub fn open_any(&self, secret: &Secret) -> Result<(usize, Opened)> {
        let parallel = (self.header.kdf.m_cost as u64) * (SLOT_COUNT as u64) <= 1024 * 1024;

        if parallel {
            let found = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..SLOT_COUNT)
                    .map(|index| scope.spawn(move || (index, self.open_slot(index, secret))))
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|h| h.join().ok())
                    .find_map(|(index, result)| result.ok().map(|opened| (index, opened)))
            });
            if let Some(found) = found {
                return Ok(found);
            }
        } else {
            for index in 0..SLOT_COUNT {
                if let Ok(opened) = self.open_slot(index, secret) {
                    return Ok((index, opened));
                }
            }
        }
        Err(Error::Authentication)
    }

    /// True when `index` holds something this password can open.
    pub fn slot_opens(&self, index: usize, secret: &Secret) -> bool {
        self.open_slot(index, secret).is_ok()
    }

    /// Take every slot except `keep` from `other`.
    ///
    /// Used just before saving, so that slots written since we opened the file
    /// survive. The headers must match: a slot's associated data includes the
    /// header, so slots from a file with a different one could never be opened
    /// again anyway, and silently mixing them would destroy both.
    pub fn adopt_other_slots(&mut self, other: &SlotFile, keep: usize) -> Result<()> {
        if self.header_json != other.header_json {
            return Err(Error::vault(
                "the vault file on disk was replaced by a different one while this \
                 vault was open. Close without saving and reopen it, or your changes \
                 will overwrite the file that is there now.",
            ));
        }
        for index in 0..SLOT_COUNT {
            if index != keep {
                self.slots[index] = other.slots[index].clone();
            }
        }
        Ok(())
    }

    /// Overwrite a slot with fresh noise, erasing whatever was there.
    pub fn erase_slot(&mut self, index: usize) -> Result<()> {
        if index >= SLOT_COUNT {
            return Err(Error::format("slot index out of range"));
        }
        let mut noise = vec![0u8; slot_size(self.header.slot_capacity)];
        crypto::random_bytes(&mut noise)?;
        self.slots[index] = noise;
        Ok(())
    }
}

/// Pad `payload` to exactly `capacity` bytes: a 4-byte length, the data, then
/// random filler.
///
/// The filler is random rather than zero so that a future weakness in either
/// cipher is not handed a large block of known plaintext to work with.
fn pad(payload: &[u8], capacity: usize) -> Result<Zeroizing<Vec<u8>>> {
    let length = u32::try_from(payload.len())
        .map_err(|_| Error::vault("vault payload is implausibly large"))?;
    let mut padded = Zeroizing::new(vec![0u8; capacity]);
    padded[..LENGTH_PREFIX].copy_from_slice(&length.to_be_bytes());
    padded[LENGTH_PREFIX..LENGTH_PREFIX + payload.len()].copy_from_slice(payload);
    crypto::random_bytes(&mut padded[LENGTH_PREFIX + payload.len()..])?;
    Ok(padded)
}

fn unpad(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if padded.len() < LENGTH_PREFIX {
        return Err(Error::format("slot payload is too short to be valid"));
    }
    let length = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if length > padded.len() - LENGTH_PREFIX {
        // Authentication already passed, so this means the writer and reader
        // disagree about the format rather than that someone tampered.
        return Err(Error::format("slot payload claims a length that does not fit"));
    }
    Ok(Zeroizing::new(
        padded[LENGTH_PREFIX..LENGTH_PREFIX + length].to_vec(),
    ))
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

    fn header() -> FileHeader {
        FileHeader::new(params(), MIN_SLOT_CAPACITY).unwrap()
    }

    /// First write into a slot: derive a fresh salt and key, then seal.
    fn write(file: &mut SlotFile, index: usize, payload: &[u8], secret: &Secret) {
        let (key, salt) = file.prepare_slot(secret).unwrap();
        file.write_slot(index, payload, &key, &salt).unwrap();
    }

    #[test]
    fn a_fresh_file_has_every_slot_full_of_noise() {
        let file = SlotFile::new_random(header()).unwrap();
        // Nothing opens, because nothing was written.
        for index in 0..SLOT_COUNT {
            assert!(file.open_slot(index, &Secret::from_str("anything")).is_err());
        }
    }

    #[test]
    fn a_written_slot_round_trips() {
        let mut file = SlotFile::new_random(header()).unwrap();
        let secret = Secret::from_str("primary password");
        write(&mut file, PRIMARY_SLOT, b"the real contents", &secret);

        let reparsed = SlotFile::parse(&file.to_bytes()).unwrap();
        let opened = reparsed.open_slot(PRIMARY_SLOT, &secret).unwrap();
        assert_eq!(opened.payload.as_slice(), b"the real contents");
    }

    #[test]
    fn two_slots_hold_different_vaults_under_different_passwords() {
        let mut file = SlotFile::new_random(header()).unwrap();
        let decoy = Secret::from_str("the password I hand over");
        let real = Secret::from_str("the password I do not");

        write(&mut file, PRIMARY_SLOT, b"plausible but dull", &decoy);
        write(&mut file, HIDDEN_SLOT, b"what actually matters", &real);

        let reparsed = SlotFile::parse(&file.to_bytes()).unwrap();
        assert_eq!(
            reparsed.open_slot(PRIMARY_SLOT, &decoy).unwrap().payload.as_slice(),
            b"plausible but dull"
        );
        assert_eq!(
            reparsed.open_slot(HIDDEN_SLOT, &real).unwrap().payload.as_slice(),
            b"what actually matters"
        );
        // Neither password opens the other slot.
        assert!(reparsed.open_slot(HIDDEN_SLOT, &decoy).is_err());
        assert!(reparsed.open_slot(PRIMARY_SLOT, &real).is_err());
    }

    #[test]
    fn a_derived_key_opens_its_own_slot_in_another_copy_of_the_file() {
        // What comparing a vault against its backups rests on: the key held by
        // an open vault opens the same slot in a later copy, without Argon2id.
        let mut file = SlotFile::new_random(header()).unwrap();
        let secret = Secret::from_str("primary password");
        let (key, salt) = file.prepare_slot(&secret).unwrap();
        file.write_slot(PRIMARY_SLOT, b"first version", &key, &salt).unwrap();
        file.write_slot(PRIMARY_SLOT, b"second version", &key, &salt).unwrap();

        let copy = SlotFile::parse(&file.to_bytes()).unwrap();
        assert_eq!(
            copy.open_slot_with_key(PRIMARY_SLOT, &key).unwrap().as_slice(),
            b"second version"
        );
        assert_eq!(
            copy.open_slot(PRIMARY_SLOT, &secret).unwrap().payload.as_slice(),
            b"second version",
            "the two ways in agree"
        );
    }

    #[test]
    fn a_derived_key_opens_nothing_else() {
        let mut file = SlotFile::new_random(header()).unwrap();
        let (key, salt) = file.prepare_slot(&Secret::from_str("mine")).unwrap();
        file.write_slot(PRIMARY_SLOT, b"mine", &key, &salt).unwrap();
        write(&mut file, HIDDEN_SLOT, b"theirs", &Secret::from_str("theirs"));

        // Not the other vault, not the same bytes moved to the other position,
        // and not a slot of a file with a different header.
        assert!(file.open_slot_with_key(HIDDEN_SLOT, &key).is_err());
        let other_header = FileHeader::new(params(), MIN_SLOT_CAPACITY * 2).unwrap();
        let mut bigger = SlotFile::new_random(other_header).unwrap();
        bigger.write_slot(PRIMARY_SLOT, b"mine", &key, &salt).unwrap();
        bigger.slots[PRIMARY_SLOT].truncate(file.slots[PRIMARY_SLOT].len());
        bigger.slots[PRIMARY_SLOT].copy_from_slice(&file.slots[PRIMARY_SLOT]);
        assert!(
            bigger.open_slot_with_key(PRIMARY_SLOT, &key).is_err(),
            "the header is part of what the slot is sealed to"
        );
        assert!(file.open_slot_with_key(SLOT_COUNT, &key).is_err(), "out of range");
    }

    /// The deniability claim, stated as a test: a file with a hidden vault and
    /// a file without one are the same size and the same shape.
    #[test]
    fn a_hidden_vault_does_not_change_the_file_at_all() {
        let decoy = Secret::from_str("decoy");
        let real = Secret::from_str("real");

        let mut without = SlotFile::new_random(header()).unwrap();
        write(&mut without, PRIMARY_SLOT, b"same decoy contents", &decoy);

        let mut with = SlotFile::new_random(header()).unwrap();
        write(&mut with, PRIMARY_SLOT, b"same decoy contents", &decoy);
        write(&mut with, HIDDEN_SLOT, b"a secret", &real);

        assert_eq!(without.to_bytes().len(), with.to_bytes().len());
        // And the header — the only plaintext in the file — is identical.
        let cut = MAGIC.len() + 3 + without.header_json.len();
        assert_eq!(&without.to_bytes()[..cut], &with.to_bytes()[..cut]);
    }

    /// An unused slot must not be distinguishable from a used one by any
    /// statistic an attacker can compute without the password.
    #[test]
    fn a_used_slot_looks_no_different_from_noise() {
        let mut file = SlotFile::new_random(header()).unwrap();
        write(&mut file, PRIMARY_SLOT, b"real data", &Secret::from_str("pw"));

        let used = &file.slots[PRIMARY_SLOT];
        let unused = &file.slots[HIDDEN_SLOT];
        assert_eq!(used.len(), unused.len());

        // Byte-value spread: ciphertext and CSPRNG output both look uniform.
        // A slot left as zeroes, or holding compressible plaintext, would not.
        for (name, slot) in [("used", used), ("unused", unused)] {
            let distinct = slot.iter().collect::<std::collections::HashSet<_>>().len();
            assert!(distinct > 200, "{name} slot uses only {distinct} byte values");
            let ones: u32 = slot.iter().map(|b| b.count_ones()).sum();
            let ratio = ones as f64 / (slot.len() * 8) as f64;
            assert!(
                (0.45..0.55).contains(&ratio),
                "{name} slot has a bit ratio of {ratio:.3}"
            );
        }
    }

    #[test]
    fn writing_one_slot_leaves_the_other_byte_identical() {
        // The decoy must be editable without destroying the hidden vault.
        let mut file = SlotFile::new_random(header()).unwrap();
        let real = Secret::from_str("real");
        write(&mut file, HIDDEN_SLOT, b"precious", &real);
        let before = file.slots[HIDDEN_SLOT].clone();

        write(&mut file, PRIMARY_SLOT, b"decoy v1", &Secret::from_str("decoy"));
        write(&mut file, PRIMARY_SLOT, b"decoy v2", &Secret::from_str("decoy"));

        assert_eq!(file.slots[HIDDEN_SLOT], before);
        assert_eq!(
            file.open_slot(HIDDEN_SLOT, &real).unwrap().payload.as_slice(),
            b"precious"
        );
    }

    #[test]
    fn a_slot_cannot_be_moved_to_another_position() {
        // The index is authenticated, so swapping slots invalidates both.
        let mut file = SlotFile::new_random(header()).unwrap();
        let secret = Secret::from_str("pw");
        write(&mut file, PRIMARY_SLOT, b"data", &secret);
        file.slots.swap(PRIMARY_SLOT, HIDDEN_SLOT);
        assert!(file.open_slot(HIDDEN_SLOT, &secret).is_err());
    }

    #[test]
    fn payload_length_is_hidden_by_padding() {
        let mut short = SlotFile::new_random(header()).unwrap();
        let mut long = SlotFile::new_random(header()).unwrap();
        let secret = Secret::from_str("pw");
        write(&mut short, PRIMARY_SLOT, b"x", &secret);
        write(&mut long, PRIMARY_SLOT, &vec![b'y'; 20_000], &secret);
        assert_eq!(
            short.slots[PRIMARY_SLOT].len(),
            long.slots[PRIMARY_SLOT].len()
        );
    }

    #[test]
    fn an_oversized_payload_is_refused_with_advice() {
        let mut file = SlotFile::new_random(header()).unwrap();
        let huge = vec![0u8; MIN_SLOT_CAPACITY + 1];
        let secret = Secret::from_str("pw");
        let (key, salt) = file.prepare_slot(&secret).unwrap();
        let err = file
            .write_slot(PRIMARY_SLOT, &huge, &key, &salt)
            .unwrap_err();
        assert!(err.to_string().contains("larger slot size"));
    }

    #[test]
    fn tampering_with_a_slot_is_detected() {
        let mut file = SlotFile::new_random(header()).unwrap();
        let secret = Secret::from_str("pw");
        write(&mut file, PRIMARY_SLOT, b"data", &secret);
        let middle = file.slots[PRIMARY_SLOT].len() / 2;
        file.slots[PRIMARY_SLOT][middle] ^= 1;
        assert!(file.open_slot(PRIMARY_SLOT, &secret).is_err());
    }

    #[test]
    fn erasing_a_slot_makes_it_unopenable_again() {
        let mut file = SlotFile::new_random(header()).unwrap();
        let secret = Secret::from_str("pw");
        write(&mut file, HIDDEN_SLOT, b"data", &secret);
        file.erase_slot(HIDDEN_SLOT).unwrap();
        assert!(file.open_slot(HIDDEN_SLOT, &secret).is_err());
    }

    #[test]
    fn adopting_other_slots_preserves_them() {
        // Two independent handles on the same file, as happens when a hidden
        // vault is created while the decoy is open.
        let mut first = SlotFile::new_random(header()).unwrap();
        let decoy = Secret::from_str("decoy");
        write(&mut first, PRIMARY_SLOT, b"decoy contents", &decoy);

        let mut second = SlotFile::parse(&first.to_bytes()).unwrap();
        let hidden = Secret::from_str("hidden");
        write(&mut second, HIDDEN_SLOT, b"hidden contents", &hidden);

        // `first` still has noise in the hidden slot; adopting fixes that.
        first.adopt_other_slots(&second, PRIMARY_SLOT).unwrap();
        assert_eq!(
            first.open_slot(HIDDEN_SLOT, &hidden).unwrap().payload.as_slice(),
            b"hidden contents"
        );
        assert_eq!(
            first.open_slot(PRIMARY_SLOT, &decoy).unwrap().payload.as_slice(),
            b"decoy contents"
        );
    }

    #[test]
    fn adopting_from_a_different_file_is_refused() {
        let mut ours = SlotFile::new_random(header()).unwrap();
        let bigger = FileHeader::new(params(), MIN_SLOT_CAPACITY * 2).unwrap();
        let theirs = SlotFile::new_random(bigger).unwrap();
        assert!(ours.adopt_other_slots(&theirs, PRIMARY_SLOT).is_err());
    }

    #[test]
    fn a_truncated_file_is_rejected() {
        let file = SlotFile::new_random(header()).unwrap();
        let bytes = file.to_bytes();
        assert!(SlotFile::parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn padding_round_trips_at_the_edges() {
        for length in [0usize, 1, 100, MIN_SLOT_CAPACITY - LENGTH_PREFIX] {
            let payload = vec![7u8; length];
            let padded = pad(&payload, MIN_SLOT_CAPACITY).unwrap();
            assert_eq!(padded.len(), MIN_SLOT_CAPACITY);
            assert_eq!(unpad(&padded).unwrap().as_slice(), payload.as_slice());
        }
    }
}
