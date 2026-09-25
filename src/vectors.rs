//! Known-answer tests: the Rust code against an implementation that is not it.
//!
//! Every value below was produced by `tools/reference_vault.py`, which is
//! written from docs/FORMAT.md on top of different libraries — OpenSSL through
//! `cryptography`, and the Argon2 authors' own C code through `argon2-cffi` —
//! and which checks itself against the published RFC and IETF vectors before
//! it is trusted to produce anything.
//!
//! These are not regression snapshots of whatever this code happens to output.
//! A snapshot only notices that something changed. Two independent
//! implementations agreeing on the same bytes is evidence that the
//! specification describes what the program does — which is the thing a
//! reviewer needs before reviewing anything.
//!
//! If one of these fails, do not update the expected value to match. Find out
//! which implementation is wrong. Regenerate with
//! `python tools/reference_vault.py kat`.

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::crypto::{self, KdfParams};
    use crate::errors::Error;
    use crate::secret::{Key, Secret};
    use crate::slots::{FileHeader, SlotFile, MIN_SLOT_CAPACITY};

    /// Written by the reference implementation, never by this code.
    static REFERENCE_FILE: &[u8] = include_bytes!("../tests/vectors/reference-v2.ddv");
    const REFERENCE_FILE_SHA256: &str =
        "29f5bc02fe1b2761194fc7887bba30a4194ca95c2ae8ab3c72bc65549b6569ee";

    const PASSWORD: &str = "correct horse battery staple";
    const PAYLOAD: &[u8] =
        br#"{"note":"written by tools/reference_vault.py, not by the Rust code"}"#;

    fn kdf() -> KdfParams {
        KdfParams {
            m_cost: 65_536,
            t_cost: 2,
            p_cost: 1,
            algorithm: "argon2id".into(),
        }
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn range_key(start: u8) -> [u8; 32] {
        std::array::from_fn(|i| start + i as u8)
    }

    // ------------------------------------------------------------ primitives

    #[test]
    fn argon2id_agrees_with_the_argon2_authors_c_implementation() {
        let salt = unhex("c099cbf1e12128657f3a35cb7b0b11645dd6684742d6a8cd659ef5be9cc5f8fc");
        let key = crypto::derive_master_key(&Secret::from_str(PASSWORD), &salt, &kdf()).unwrap();
        assert_eq!(
            hex(key.as_bytes()),
            "120d29316edde9040d1c5491303532783df34b1326d63c6f2d42e115f899ab35"
        );
    }

    #[test]
    fn the_two_cipher_keys_agree_with_the_reference() {
        // Separately from the cascade below, so a disagreement says which step
        // went wrong: the key schedule or the ciphers.
        let master = Key::new(range_key(0x40));
        let seed = range_key(0x80);
        let inner = crypto::subkey(&master, &seed, crypto::HKDF_INFO_INNER).unwrap();
        let outer = crypto::subkey(&master, &seed, crypto::HKDF_INFO_OUTER).unwrap();
        assert_eq!(
            hex(inner.as_bytes()),
            "1abf19cb7990e8982cdd8cdfe32ae66365b826ffb01ec646b9fbc2c0626188ac"
        );
        assert_eq!(
            hex(outer.as_bytes()),
            "6c9ae2d37d92310efa8f074b1b60b5e6648f32ae58b3825c530ef11e8bc40689"
        );
    }

    #[test]
    fn the_cascade_agrees_with_the_reference_byte_for_byte() {
        let master = Key::new(range_key(0x40));
        let seed = range_key(0x80);
        let aad = b"deep-defense known-answer test";
        let sealed =
            crypto::seal_cascade(b"Two ciphers, one password.", &master, &seed, aad).unwrap();
        assert_eq!(
            hex(&sealed),
            "171f489761d7a0511a18fdd599d503f4567e2247d92cd1192c6ce413ce01dd09\
             ee40207689331f1355ed3dd8a1b8486dc51d89c9a3077b2ce175"
        );
        let opened = crypto::open_cascade(&sealed, &master, &seed, aad).unwrap();
        assert_eq!(opened.as_slice(), b"Two ciphers, one password.");
    }

    #[test]
    fn keyfiles_combine_the_way_the_reference_combines_them() {
        // A change here would not fail loudly: it would silently produce a
        // different secret, and every vault protected by a keyfile would stop
        // opening. So it is pinned to an outside implementation.
        let home = crate::config::test_home::TestHome::new("vectors-keyfiles");
        let first = home.join("a.key");
        let second = home.join("b.key");
        std::fs::write(&first, b"first keyfile").unwrap();
        std::fs::write(&second, b"second keyfile").unwrap();

        let expected = "1ddbdadd150cc77d8f09033e992b515459b72a73bc2f796db2826ffcd22b5637\
                        1c49c52a2ed0e6aac84b818b1ac2035558fd8a2e815ad9adeca708d8a85cf422";
        let password = Secret::from_str(PASSWORD);
        for order in [[first.clone(), second.clone()], [second, first]] {
            let combined = crypto::combine_secret(&password, &order).unwrap();
            assert_eq!(hex(combined.expose()), expected, "the order must not matter");
        }
    }

    // -------------------------------------------------------- the whole file

    #[test]
    fn the_reference_file_is_the_one_the_vectors_describe() {
        // Guards the fixture itself, so a damaged or regenerated file is
        // reported as that rather than as a mysterious decryption failure.
        assert_eq!(hex(&Sha256::digest(REFERENCE_FILE)), REFERENCE_FILE_SHA256);
    }

    #[test]
    fn a_file_written_by_the_reference_opens_here() {
        let file = SlotFile::parse(REFERENCE_FILE).expect("the reference file parses");
        let secret = Secret::from_str(PASSWORD);

        let opened = file.open_slot(0, &secret).expect("slot 0 holds the vault");
        assert_eq!(opened.payload.as_slice(), PAYLOAD);

        assert!(
            file.open_slot(1, &secret).is_err(),
            "slot 1 is noise, and must look like it to a password that is not its own"
        );
        let (slot, found) = file.open_any(&secret).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(found.payload.as_slice(), PAYLOAD);
    }

    #[test]
    fn this_code_writes_the_header_exactly_as_the_specification_does() {
        // Opening a file uses the header bytes stored in it, so this is not
        // what keeps old vaults readable. It is what keeps the specification
        // true of new files: if serde ever reordered these fields, files written
        // afterwards would stop matching docs/FORMAT.md.
        let header = FileHeader::new(kdf(), MIN_SLOT_CAPACITY).unwrap();
        let ours = serde_json::to_vec(&header).unwrap();

        let length = u16::from_be_bytes([REFERENCE_FILE[9], REFERENCE_FILE[10]]) as usize;
        let theirs = &REFERENCE_FILE[11..11 + length];
        assert_eq!(
            String::from_utf8_lossy(&ours),
            String::from_utf8_lossy(theirs)
        );
    }

    // ------------------------------------------------- what the format refuses

    /// The cipher name, one character changed. Same length, still valid JSON,
    /// still accepted by the parser — so the only thing that can refuse it is
    /// the header being part of what every slot authenticates.
    #[test]
    fn a_changed_header_stops_every_slot_opening() {
        let mut altered = REFERENCE_FILE.to_vec();
        let needle = b"XChaCha20-Poly1305";
        let at = altered
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the header names the inner cipher");
        altered[at + needle.len() - 1] = b'6';

        let file = SlotFile::parse(&altered).expect("still a well-formed file");
        let refused = file.open_slot(0, &Secret::from_str(PASSWORD));
        assert!(
            matches!(refused, Err(Error::Authentication)),
            "a header nobody signed must not be accepted"
        );
    }

    #[test]
    fn a_slot_moved_to_the_other_position_does_not_open() {
        // The index is authenticated too, so a slot cannot be relocated — for
        // instance to swap which vault a password opens.
        let header_len = u16::from_be_bytes([REFERENCE_FILE[9], REFERENCE_FILE[10]]) as usize;
        let start = 11 + header_len;
        let size = crate::slots::slot_size(MIN_SLOT_CAPACITY);

        let mut swapped = REFERENCE_FILE[..start].to_vec();
        swapped.extend_from_slice(&REFERENCE_FILE[start + size..start + 2 * size]);
        swapped.extend_from_slice(&REFERENCE_FILE[start..start + size]);

        let file = SlotFile::parse(&swapped).unwrap();
        let secret = Secret::from_str(PASSWORD);
        assert!(file.open_slot(1, &secret).is_err(), "the slot moved and must not open");
        assert!(matches!(file.open_any(&secret), Err(Error::Authentication)));
    }

    #[test]
    fn one_changed_ciphertext_byte_is_refused() {
        let header_len = u16::from_be_bytes([REFERENCE_FILE[9], REFERENCE_FILE[10]]) as usize;
        // Well inside the first slot's ciphertext, past its salt and seed.
        let target = 11 + header_len + 32 + 32 + 1000;
        let mut altered = REFERENCE_FILE.to_vec();
        altered[target] ^= 0x01;

        let file = SlotFile::parse(&altered).unwrap();
        assert!(matches!(
            file.open_slot(0, &Secret::from_str(PASSWORD)),
            Err(Error::Authentication)
        ));
    }
}
