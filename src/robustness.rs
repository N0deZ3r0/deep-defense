//! Feeding every parser deliberately broken input and demanding it not crash.
//!
//! The vault file is the one thing an attacker controls completely. Swapping
//! it for a crafted one costs nothing, and a parser that panics on a bad
//! header turns that into an easy denial of service — and, in a language with
//! less nerve than this one, into much worse. The same goes for every file the
//! program is *asked* to read: a CSV from another manager, a wordlist, a
//! recovery share copied out by hand.
//!
//! There are unit tests for the obvious damage — a truncated file, a wrong
//! magic number. Those check the cases somebody thought of. This checks the
//! ones nobody did, by taking valid input and breaking it at random, tens of
//! thousands of times, in ways real corruption and real attackers both
//! produce: a flipped bit, a truncation, a length field replaced with
//! something absurd.
//!
//! # What counts as a failure
//!
//! Exactly one thing: a panic. Every parser here is allowed to reject
//! anything it likes, and a wrong answer is not what is being tested. What it
//! may not do is bring the process down, because an index computed from a
//! length the file supplied is the classic way that happens.
//!
//! Every run is seeded, so a failure reports the seed and the round that
//! produced it and can be replayed exactly.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// SplitMix64. Chosen because it is four lines and reproducible across
/// platforms, which matters more here than statistical quality.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.byte()).collect()
    }
}

/// Where to break the input.
///
/// Biased towards the front: headers, magic numbers and length fields all live
/// in the first hundred bytes, and a uniform choice across a hundred-kilobyte
/// file would almost never touch them.
fn position(rng: &mut Rng, length: usize) -> usize {
    if length == 0 {
        return 0;
    }
    if rng.next().is_multiple_of(2) {
        rng.below(length.min(128))
    } else {
        rng.below(length)
    }
}

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    let operations = 1 + rng.below(4);
    for _ in 0..operations {
        if out.is_empty() {
            out.push(rng.byte());
            continue;
        }
        let at = position(rng, out.len());
        match rng.next() % 8 {
            0 => out[at] ^= 1 << (rng.next() % 8),
            1 => out[at] = rng.byte(),
            2 => out.truncate(at),
            3 => out.insert(at, rng.byte()),
            4 => {
                let span = rng.below(out.len() - at).min(64);
                out[at..at + span].fill(0);
            }
            5 => {
                let span = rng.below(out.len() - at).min(64);
                out[at..at + span].fill(0xFF);
            }
            6 => {
                let other = position(rng, out.len());
                out.swap(at, other);
            }
            _ => {
                let extra = 1 + rng.below(32);
                let tail = rng.bytes(extra);
                out.extend_from_slice(&tail);
            }
        }
    }
    out
}

/// Runs `probe` against `rounds` broken versions of `corpus`.
///
/// Reports the seed and round of anything that panics, so the exact input can
/// be rebuilt without storing it.
fn hunt<F>(label: &str, seed: u64, rounds: usize, corpus: &[Vec<u8>], probe: F)
where
    F: Fn(&[u8]),
{
    assert!(!corpus.is_empty(), "{label}: nothing to mutate");
    let mut rng = Rng(seed);
    for round in 0..rounds {
        let base = &corpus[rng.below(corpus.len())];
        let broken = mutate(&mut rng, base);
        let outcome = catch_unwind(AssertUnwindSafe(|| probe(&broken)));
        if outcome.is_err() {
            let head: Vec<String> = broken
                .iter()
                .take(48)
                .map(|byte| format!("{byte:02x}"))
                .collect();
            panic!(
                "{label} panicked at round {round} of seed {seed} \
                 on {} bytes beginning {}",
                broken.len(),
                head.join(" ")
            );
        }
    }
}

/// The same, for parsers that take text rather than bytes.
fn hunt_text<F>(label: &str, seed: u64, rounds: usize, corpus: &[Vec<u8>], probe: F)
where
    F: Fn(&str),
{
    hunt(label, seed, rounds, corpus, |bytes| {
        // Lossy on purpose: the conversion itself is part of what the real
        // import does, and it is a place index arithmetic has gone wrong here
        // before.
        let text = String::from_utf8_lossy(bytes);
        probe(&text);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::model::VaultData;
    use crate::slots::{self, FileHeader, SlotFile};

    fn params() -> KdfParams {
        KdfParams {
            m_cost: KdfParams::MIN_M_COST,
            t_cost: 2,
            p_cost: 1,
            algorithm: "argon2id".into(),
        }
    }

    fn a_vault_file() -> Vec<u8> {
        let header = FileHeader::new(params(), slots::MIN_SLOT_CAPACITY).unwrap();
        SlotFile::new_random(header).unwrap().to_bytes()
    }

    /// The headline case: the file the program is pointed at on startup.
    #[test]
    fn the_vault_file_parser_survives_being_broken() {
        let corpus = vec![
            a_vault_file(),
            // A plausible-looking prefix, so the mutations spend their time
            // past the magic number rather than being rejected at byte zero.
            {
                let mut short = a_vault_file();
                short.truncate(4096);
                short
            },
            b"DDVAULT2".to_vec(),
            Vec::new(),
        ];
        hunt("SlotFile::parse", 0xDEFEA7ED, 20_000, &corpus, |bytes| {
            let _ = SlotFile::parse(bytes);
        });
    }

    /// Every truncation, not a random sample of them: the length checks in a
    /// parser are exactly what an off-by-one hides in.
    #[test]
    fn every_prefix_of_a_vault_file_is_refused_cleanly() {
        let full = a_vault_file();
        for length in 0..2048.min(full.len()) {
            let outcome = catch_unwind(|| SlotFile::parse(&full[..length]));
            assert!(
                outcome.is_ok(),
                "a {length}-byte prefix of a vault file panicked"
            );
            assert!(
                outcome.unwrap().is_err(),
                "a {length}-byte prefix was accepted as a whole file"
            );
        }
        assert!(SlotFile::parse(&full).is_ok(), "the control must still parse");
    }

    /// A header that claims more than the file holds is the first thing a
    /// crafted file gets wrong, and believing it means reading off the end.
    #[test]
    fn an_absurd_length_field_is_not_believed() {
        let full = a_vault_file();
        for offset in 0..32.min(full.len().saturating_sub(8)) {
            for pattern in [u64::MAX, u32::MAX as u64, i64::MAX as u64, 1 << 40] {
                let mut lying = full.clone();
                lying[offset..offset + 8].copy_from_slice(&pattern.to_be_bytes());
                let outcome = catch_unwind(|| SlotFile::parse(&lying));
                assert!(
                    outcome.is_ok(),
                    "a length of {pattern} at byte {offset} brought the parser down"
                );
            }
        }
    }

    #[test]
    fn the_password_filter_parser_survives_being_broken() {
        let mut filter = crate::breach::Filter::new(1 << 14, 7).unwrap();
        filter.add("something");
        let corpus = vec![
            filter.to_bytes(),
            b"DDBLOOM1".to_vec(),
            vec![0u8; 64],
            Vec::new(),
        ];
        hunt("Filter::parse", 0xB100_F117, 20_000, &corpus, |bytes| {
            let _ = crate::breach::Filter::parse_owned(bytes);
        });
    }

    #[test]
    fn the_csv_importer_survives_being_broken() {
        let corpus: Vec<Vec<u8>> = vec![
            b"name,username,password,url,notes\nBank,me,hunter2,https://b.example,hi\n".to_vec(),
            b"Title,Username,Password\n\"quoted, comma\",\"line\nbreak\",\"\"\"escaped\"\"\"\n"
                .to_vec(),
            b"url,username,password\nhttps://x,u,p\n".to_vec(),
            b"\xef\xbb\xbfname,password\na,b\n".to_vec(),
            Vec::new(),
        ];
        hunt_text("portable::from_csv", 0xC5F_0000, 20_000, &corpus, |text| {
            let mut data = VaultData::default();
            let _ = crate::portable::from_csv(&mut data, text);
        });
    }

    #[test]
    fn the_json_importer_survives_being_broken() {
        let mut data = VaultData::default();
        let mut entry = crate::model::Entry::new("Bank");
        entry.username = "me".into();
        entry.set_password("hunter2".into());
        data.entries.push(entry);
        let good = crate::portable::to_json(&data).unwrap();

        let corpus = vec![
            good.as_bytes().to_vec(),
            br#"{"entries":[]}"#.to_vec(),
            br#"{"entries":[{"name":"a"}]}"#.to_vec(),
            b"{}".to_vec(),
            Vec::new(),
        ];
        hunt_text("portable::from_json", 0x1507_0000, 20_000, &corpus, |text| {
            let mut into = VaultData::default();
            let _ = crate::portable::from_json(&mut into, text);
        });
    }

    /// The vault's own contents, after decryption. Reaching this needs the
    /// master password, so it is a smaller worry — but a corrupted disk
    /// produces the same bytes as a clever attacker, and neither should crash.
    #[test]
    fn the_vault_contents_parser_survives_being_broken() {
        let mut data = VaultData::default();
        let mut entry = crate::model::Entry::new("Bank");
        entry.set_password("hunter2".into());
        data.entries.push(entry);
        data.record(crate::model::AuditAction::Created, "");
        data.record(crate::model::AuditAction::EntryAdded, "Bank");

        let corpus = vec![serde_json::to_vec(&data).unwrap(), b"{}".to_vec()];
        hunt_text("VaultData", 0x7A17_7A17, 20_000, &corpus, |text| {
            let Ok(parsed) = serde_json::from_str::<VaultData>(text) else {
                return;
            };
            // Whatever came out, the operations the program runs on freshly
            // opened data must hold.
            let _ = parsed.verify_audit();
            let _ = parsed.entries.iter().filter(|e| e.matches("bank")).count();
            let _ = serde_json::to_vec(&parsed);
        });
    }

    #[test]
    fn the_recovery_share_reader_survives_being_broken() {
        let shares = crate::shamir::split(b"a master password", 2, 3).unwrap();
        let printed = format!(
            "Deep Defense recovery\n{}\n{}\n",
            shares[0].to_text(),
            shares[1].to_text()
        );
        let corpus = vec![
            shares[0].to_text().into_bytes(),
            printed.into_bytes(),
            b"AAAA-AAAA-AAAA".to_vec(),
            Vec::new(),
        ];
        hunt_text("shamir::parse_share", 0x5A5E_C2E7, 20_000, &corpus, |text| {
            let _ = crate::shamir::parse_share(text);
            let found = crate::shamir::parse_shares(text);
            // Combining whatever turned up must also be survivable: these are
            // attacker-supplied indices going into field arithmetic.
            let _ = crate::shamir::combine(&found);
        });
    }

    #[test]
    fn the_authenticator_secret_reader_survives_being_broken() {
        let corpus = vec![
            b"JBSWY3DPEHPK3PXP".to_vec(),
            b"otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6"
                .to_vec(),
            b"otpauth://totp/x?secret=A&period=0&digits=99&algorithm=SHA512".to_vec(),
            Vec::new(),
        ];
        hunt_text("totp", 0x707_0000, 20_000, &corpus, |text| {
            let _ = crate::totp::decode_base32(text);
            if let Ok(totp) = crate::totp::TotpConfig::parse(text) {
                // Code generation is where the arithmetic lives, and it has
                // overflowed on a hostile digit count before.
                let _ = totp.validate();
                let _ = totp.code_at(0);
                let _ = totp.code_at(u64::MAX);
            }
        });
    }

    #[test]
    fn a_wordlist_import_survives_being_broken() {
        let corpus = vec![
            b"password\n123456\n# comment\n\n".to_vec(),
            b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n".to_vec(),
            vec![b'x'; 4096],
            Vec::new(),
        ];
        hunt_text("breach::import", 0xC0FF_EE11, 5_000, &corpus, |text| {
            let mut catalogue = crate::breach::Catalogue::bundled_only();
            let _ = catalogue.import(text);
        });
    }

    /// Not a mutation of anything: purely random bytes, which is what a parser
    /// pointed at the wrong file actually sees.
    #[test]
    fn purely_random_input_is_refused_by_everything() {
        let mut rng = Rng(0x0FF_0FF);
        for round in 0..2_000 {
            let length = rng.below(512);
            let noise = rng.bytes(length);
            let text = String::from_utf8_lossy(&noise).to_string();

            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _ = SlotFile::parse(&noise);
                let _ = crate::breach::Filter::parse_owned(&noise);
                let _ = crate::shamir::parse_share(&text);
                let _ = crate::shamir::parse_shares(&text);
                let _ = crate::totp::decode_base32(&text);
                let mut data = VaultData::default();
                let _ = crate::portable::from_csv(&mut data, &text);
                let _ = crate::portable::from_json(&mut data, &text);
            }));
            assert!(outcome.is_ok(), "round {round} of random noise panicked");
        }
    }
}
