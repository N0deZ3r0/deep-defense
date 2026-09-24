//! Telling the user that a password is already public.
//!
//! The strength meter measures how hard a password would be to *guess*. It
//! cannot know that the password has already been guessed — that it sits in a
//! published dump and is the first thing any attacker tries. `Tr0ub4dor&3`
//! scores well and is worthless; so does every mangled dictionary word.
//!
//! # Why a Bloom filter
//!
//! The obvious implementations are both unacceptable. Asking a web service
//! sends something about the password off the machine, which is the one thing
//! this program must never do. Shipping the list itself would be hundreds of
//! megabytes and would hand an attacker a ready-made wordlist.
//!
//! A Bloom filter is a fixed block of bits with two properties that fit
//! exactly: it can say "definitely not in the list", and it cannot be read
//! backwards into the list it was built from. The cost is a small chance of a
//! false alarm — at the bundled size, well under one in a million — and a
//! false alarm only ever asks someone to pick a different password.
//!
//! # What is actually in the bundled list
//!
//! Not a breach corpus: a generated one. `tools/make_breach_filter.py` builds
//! the shapes that dominate every published leak — keyboard walks, dates, a
//! word with a year on the end, a Russian word typed without switching layout.
//! That is most of what people really choose, and it needs no download and no
//! questions about where a wordlist came from.
//!
//! Anyone who wants the real thing can import Have I Been Pwned's list, or any
//! other; [`Catalogue::import`] reads both plaintext and SHA-1 digests and
//! keeps the result beside the settings, separate from the bundled block.

use std::borrow::Cow;
use std::path::PathBuf;

use sha1::{Digest, Sha1};

use crate::config::app_dir;
use crate::errors::{Error, Result};

const MAGIC: &[u8; 8] = b"DDBLOOM1";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 4 + 8 + 8;
const USER_FILENAME: &str = "breached.user.bloom";

/// Generous, but bounded: the header is read from a file on disk, and a length
/// taken on trust is how a parser becomes a denial of service.
const MAX_M_BITS: u64 = 1 << 28;
/// Below this a filter is so crowded that every answer is "yes".
const MIN_M_BITS: u64 = 1 << 10;

/// The block of bits shipped inside the executable.
static BUNDLED: &[u8] = include_bytes!("../assets/breached.bloom");

/// A set of passwords that can answer "no" with certainty and "yes" with a
/// known, tiny error rate — and cannot be read back into a wordlist.
pub struct Filter {
    k: u32,
    m_bits: u64,
    count: u64,
    bits: Cow<'static, [u8]>,
}

impl Filter {
    /// An empty filter of the given shape.
    pub fn new(m_bits: u64, k: u32) -> Result<Self> {
        if !(MIN_M_BITS..=MAX_M_BITS).contains(&m_bits) || !m_bits.is_multiple_of(8) {
            return Err(Error::format("that filter size is not usable"));
        }
        if k == 0 || k > 64 {
            return Err(Error::format("that number of hashes is not usable"));
        }
        Ok(Self {
            k,
            m_bits,
            count: 0,
            bits: Cow::Owned(vec![0u8; (m_bits / 8) as usize]),
        })
    }

    /// Reads a filter without copying its body.
    ///
    /// Every field is checked against the body that follows it. A header that
    /// promises more bits than the file holds is the first thing a corrupt or
    /// hostile file gets wrong, and believing it would mean reading past the
    /// end of the block.
    pub fn parse(bytes: &'static [u8]) -> Result<Self> {
        Self::parse_inner(bytes).map(|(k, m_bits, count, body)| Self {
            k,
            m_bits,
            count,
            bits: Cow::Borrowed(body),
        })
    }

    /// The same, for bytes read at runtime rather than compiled in.
    pub fn parse_owned(bytes: &[u8]) -> Result<Self> {
        Self::parse_inner(bytes).map(|(k, m_bits, count, body)| Self {
            k,
            m_bits,
            count,
            bits: Cow::Owned(body.to_vec()),
        })
    }

    fn parse_inner(bytes: &[u8]) -> Result<(u32, u64, u64, &[u8])> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::format("that file is too short to be a filter"));
        }
        if &bytes[..8] != MAGIC {
            return Err(Error::format("that file is not a password filter"));
        }
        if bytes[8] != VERSION {
            return Err(Error::format("that filter was written by another version"));
        }
        let k = u32::from_be_bytes(bytes[9..13].try_into().unwrap_or([0; 4]));
        let m_bits = u64::from_be_bytes(bytes[13..21].try_into().unwrap_or([0; 8]));
        let count = u64::from_be_bytes(bytes[21..29].try_into().unwrap_or([0; 8]));

        if k == 0 || k > 64 {
            return Err(Error::format("that filter claims an impossible hash count"));
        }
        if !(MIN_M_BITS..=MAX_M_BITS).contains(&m_bits) || m_bits % 8 != 0 {
            return Err(Error::format("that filter claims an impossible size"));
        }
        let body = &bytes[HEADER_LEN..];
        if body.len() as u64 != m_bits / 8 {
            return Err(Error::format(
                "that filter's header and body disagree about its size",
            ));
        }
        Ok((k, m_bits, count, body))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.bits.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.k.to_be_bytes());
        out.extend_from_slice(&self.m_bits.to_be_bytes());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.bits);
        out
    }

    /// Where in the block this digest lands.
    ///
    /// Double hashing: one step, added repeatedly. The step is forced odd
    /// because the modulus is a power of two, and an even step there walks a
    /// short cycle that would use a fraction of the available bits.
    fn probes(&self, digest: &[u8; 20]) -> impl Iterator<Item = u64> + '_ {
        let h1 = u64::from_be_bytes(digest[0..8].try_into().unwrap_or([0; 8]));
        let h2 = u64::from_be_bytes(digest[8..16].try_into().unwrap_or([0; 8])) | 1;
        let mut index = h1;
        (0..self.k).map(move |_| {
            let at = index % self.m_bits;
            index = index.wrapping_add(h2);
            at
        })
    }

    pub fn contains(&self, password: &str) -> bool {
        self.contains_digest(&digest_of(password))
    }

    pub fn contains_digest(&self, digest: &[u8; 20]) -> bool {
        self.probes(digest)
            .all(|at| self.bits[(at / 8) as usize] & (1 << (at % 8)) != 0)
    }

    pub fn add(&mut self, password: &str) {
        self.add_digest(&digest_of(password));
    }

    pub fn add_digest(&mut self, digest: &[u8; 20]) {
        let positions: Vec<u64> = self.probes(digest).collect();
        let bits = self.bits.to_mut();
        for at in positions {
            bits[(at / 8) as usize] |= 1 << (at % 8);
        }
        self.count += 1;
    }

    /// How many passwords were fed in. Not a count of what it can answer for —
    /// a filter cannot be enumerated — just a record of what went in.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The fraction of bits set. Past roughly seven tenths the false-alarm
    /// rate climbs fast, which is worth telling the user about.
    pub fn saturation(&self) -> f32 {
        let set: u64 = self.bits.iter().map(|b| b.count_ones() as u64).sum();
        set as f32 / self.m_bits as f32
    }

    /// The chance that a password never added is reported as present.
    pub fn false_positive_rate(&self) -> f32 {
        self.saturation().powi(self.k as i32)
    }
}

fn digest_of(password: &str) -> [u8; 20] {
    Sha1::digest(password.as_bytes()).into()
}

/// What an import did, for reporting back without guessing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub added: u64,
    pub as_digests: u64,
    pub skipped: u64,
}

/// The bundled list plus whatever the user has imported.
pub struct Catalogue {
    bundled: Option<Filter>,
    user: Option<Filter>,
}

impl Catalogue {
    /// Never fails. A filter that will not load is a reason to check fewer
    /// passwords, not a reason to refuse to run a password manager.
    pub fn load() -> Self {
        let bundled = match Filter::parse(BUNDLED) {
            Ok(filter) => Some(filter),
            Err(_) => {
                debug_assert!(false, "the bundled filter must always parse");
                None
            }
        };
        let user = std::fs::read(user_path())
            .ok()
            .and_then(|bytes| Filter::parse_owned(&bytes).ok());
        Self { bundled, user }
    }

    /// Only the compiled-in list, for tests and for a first run.
    pub fn bundled_only() -> Self {
        Self {
            bundled: Filter::parse(BUNDLED).ok(),
            user: None,
        }
    }

    pub fn contains(&self, password: &str) -> bool {
        if password.is_empty() {
            return false;
        }
        let digest = digest_of(password);
        self.bundled
            .as_ref()
            .is_some_and(|f| f.contains_digest(&digest))
            || self.user.as_ref().is_some_and(|f| f.contains_digest(&digest))
    }

    pub fn bundled(&self) -> Option<&Filter> {
        self.bundled.as_ref()
    }

    pub fn user(&self) -> Option<&Filter> {
        self.user.as_ref()
    }

    /// Adds a wordlist. Understands plaintext, one per line, and the SHA-1
    /// digests that Have I Been Pwned publishes, with or without a trailing
    /// `:count`. Lines beginning with `#` are comments.
    pub fn import(&mut self, text: &str) -> Result<ImportSummary> {
        let candidates: Vec<&str> = text
            .lines()
            .map(|line| line.trim_end_matches('\r'))
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .collect();

        if candidates.is_empty() {
            return Err(Error::format("that file holds no passwords"));
        }

        if self.user.is_none() {
            self.user = Some(Filter::new(
                size_for(candidates.len() as u64),
                hashes_for(size_for(candidates.len() as u64), candidates.len() as u64),
            )?);
        }
        let filter = self
            .user
            .as_mut()
            .ok_or_else(|| Error::format("no list to add to"))?;

        let mut summary = ImportSummary::default();
        for line in candidates {
            match parse_digest_line(line) {
                Some(digest) => {
                    filter.add_digest(&digest);
                    summary.as_digests += 1;
                    summary.added += 1;
                }
                None => {
                    // Anything that is not a digest is the password itself.
                    // Leading and trailing spaces are kept: a list cannot tell
                    // us whether they were meant, and dropping them silently
                    // would be the wrong guess to make on a password.
                    filter.add(line);
                    summary.added += 1;
                }
            }
        }
        Ok(summary)
    }

    pub fn save_user(&self) -> Result<()> {
        let Some(filter) = &self.user else {
            return Ok(());
        };
        crate::config::ensure_app_dir()?;
        let path = user_path();
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, filter.to_bytes()).map_err(|e| Error::io(tmp.clone(), e))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::io(path.clone(), e))?;
        Ok(())
    }

    /// Discards the imported list, leaving the bundled one.
    pub fn forget_user(&mut self) -> Result<()> {
        self.user = None;
        let path = user_path();
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| Error::io(path, e))?;
        }
        Ok(())
    }
}

fn user_path() -> PathBuf {
    app_dir().join(USER_FILENAME)
}

/// A digest line is exactly forty hex characters, optionally followed by a
/// colon and a count. Anything else is a password that merely looks like one.
fn parse_digest_line(line: &str) -> Option<[u8; 20]> {
    let candidate = line.split(':').next()?.trim();
    if candidate.len() != 40 || !candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&candidate[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Sixteen bits per entry keeps the false-alarm rate near one in a thousand,
/// rounded up to a power of two so the modulus stays cheap.
fn size_for(entries: u64) -> u64 {
    // Clamped *before* rounding up, not after: `next_power_of_two` overflows
    // rather than saturating, so a list claiming billions of lines would
    // otherwise bring the program down instead of producing a crowded filter.
    let wanted = entries.saturating_mul(16).clamp(MIN_M_BITS, MAX_M_BITS);
    wanted.next_power_of_two().clamp(MIN_M_BITS, MAX_M_BITS)
}

/// The textbook optimum, `(m / n) * ln 2`, clamped to what the format allows.
fn hashes_for(m_bits: u64, entries: u64) -> u32 {
    if entries == 0 {
        return 1;
    }
    let optimal = (m_bits as f64 / entries as f64) * std::f64::consts::LN_2;
    (optimal.round() as i64).clamp(1, 64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic, so a failure can be reproduced from the seed alone.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // SplitMix64.
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }

        fn password(&mut self, length: usize) -> String {
            const ALPHABET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            (0..length)
                .map(|_| ALPHABET[(self.next() % ALPHABET.len() as u64) as usize] as char)
                .collect()
        }
    }

    // --------------------------------------------------------- the bundled list

    #[test]
    fn the_bundled_filter_parses_and_is_about_half_full() {
        let filter = Filter::parse(BUNDLED).expect("the bundled filter must load");
        assert!(filter.count() > 100_000, "the corpus should not be tiny");
        let saturation = filter.saturation();
        assert!(
            (0.3..0.7).contains(&saturation),
            "a filter {:.1} per cent full is badly sized",
            saturation * 100.0
        );
        assert!(
            filter.false_positive_rate() < 0.001,
            "false alarms must be rare"
        );
    }

    /// Also proves that the Rust and Python bit placement agree: if the index
    /// derivation differed by so much as the endianness of one word, none of
    /// these would be found.
    #[test]
    fn the_passwords_everyone_picks_are_recognised() {
        let catalogue = Catalogue::bundled_only();
        let known = [
            "123456",
            "123456789",
            "password",
            "Password1",
            "password123",
            "qwerty",
            "qwerty123",
            "QWERTY",
            "1q2w3e4r",
            "zaq12wsx",
            "111111",
            "000000",
            "1234",
            "0000",
            "abc123",
            "letmein",
            "welcome",
            "admin",
            "admin123",
            "iloveyou",
            "monkey",
            "dragon",
            "sunshine",
            "princess",
            "football",
            "master",
            "shadow",
            "trustno1",
            "superman",
            "batman",
            "starwars",
            "P@ssw0rd",
            "Passw0rd",
            "secret",
            "summer2024",
            "Summer2025",
            "moscow2024",
            "parol123",
            "gfhjkm",
            "gfhjkm123",
            "natasha",
            "sergey1",
            "Alex2024",
            "010190",
            "31121999",
            "asdfgh",
            "zxcvbnm",
            "poiuytrewq",
        ];
        let missed: Vec<&str> = known
            .iter()
            .copied()
            .filter(|p| !catalogue.contains(p))
            .collect();
        assert!(missed.is_empty(), "these should be flagged: {missed:?}");
    }

    #[test]
    fn a_generated_password_is_not_flagged() {
        let catalogue = Catalogue::bundled_only();
        let mut rng = Rng(0x0D06F00D);
        let trials = 20_000;
        let mut false_alarms = 0;
        for _ in 0..trials {
            if catalogue.contains(&rng.password(20)) {
                false_alarms += 1;
            }
        }
        assert!(
            false_alarms <= 2,
            "{false_alarms} false alarms in {trials} is too many"
        );
    }

    #[test]
    fn an_empty_password_is_never_reported() {
        // It is caught by the length rule long before this, and reporting it
        // as "leaked" would be a confusing way to say "you typed nothing".
        assert!(!Catalogue::bundled_only().contains(""));
    }

    // ------------------------------------------------------------ the mechanics

    #[test]
    fn what_goes_in_always_comes_back_out() {
        let mut filter = Filter::new(1 << 16, 7).unwrap();
        let mut rng = Rng(7);
        let words: Vec<String> = (0..1000).map(|_| rng.password(12)).collect();
        for word in &words {
            filter.add(word);
        }
        for word in &words {
            assert!(filter.contains(word), "a filter may never miss {word}");
        }
        assert_eq!(filter.count(), 1000);
    }

    #[test]
    fn an_empty_filter_says_no_to_everything() {
        let filter = Filter::new(1 << 16, 7).unwrap();
        let mut rng = Rng(11);
        for _ in 0..1000 {
            assert!(!filter.contains(&rng.password(9)));
        }
        assert_eq!(filter.saturation(), 0.0);
    }

    #[test]
    fn the_measured_false_alarm_rate_matches_the_prediction() {
        let mut filter = Filter::new(1 << 18, 7).unwrap();
        let mut rng = Rng(23);
        for _ in 0..20_000 {
            let word = rng.password(10);
            filter.add(&word);
        }
        let predicted = filter.false_positive_rate();

        let mut misses = 0;
        let trials = 50_000;
        for _ in 0..trials {
            if filter.contains(&rng.password(16)) {
                misses += 1;
            }
        }
        let measured = misses as f32 / trials as f32;
        assert!(
            measured < predicted.max(0.001) * 3.0,
            "measured {measured:.4} against a predicted {predicted:.4}"
        );
    }

    #[test]
    fn the_probes_spread_across_the_whole_block() {
        // A weak index derivation shows up here first: if the step were ever
        // even, the probes would revisit a handful of positions.
        let filter = Filter::new(1 << 16, 16).unwrap();
        let mut rng = Rng(101);
        for _ in 0..200 {
            let digest = digest_of(&rng.password(8));
            let positions: Vec<u64> = filter.probes(&digest).collect();
            assert_eq!(positions.len(), 16);
            let distinct: std::collections::HashSet<u64> = positions.iter().copied().collect();
            assert!(
                distinct.len() >= 15,
                "the probes collapsed onto {} positions",
                distinct.len()
            );
            assert!(positions.iter().all(|at| *at < filter.m_bits));
        }
    }

    // -------------------------------------------------------------- the format

    #[test]
    fn a_filter_survives_a_round_trip_through_bytes() {
        let mut filter = Filter::new(1 << 14, 5).unwrap();
        filter.add("hello");
        filter.add("goodbye");
        let blob = filter.to_bytes();

        let read = Filter::parse_owned(&blob).unwrap();
        assert_eq!(read.k, 5);
        assert_eq!(read.m_bits, 1 << 14);
        assert_eq!(read.count(), 2);
        assert!(read.contains("hello"));
        assert!(read.contains("goodbye"));
        assert!(!read.contains("something else entirely"));
    }

    #[test]
    fn a_damaged_header_is_refused_rather_than_believed() {
        let filter = Filter::new(1 << 14, 5).unwrap();
        let good = filter.to_bytes();

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("header only", good[..HEADER_LEN].to_vec()),
            ("truncated header", good[..HEADER_LEN - 1].to_vec()),
            ("wrong magic", {
                let mut bad = good.clone();
                bad[0] = b'X';
                bad
            }),
            ("wrong version", {
                let mut bad = good.clone();
                bad[8] = 9;
                bad
            }),
            ("zero hashes", {
                let mut bad = good.clone();
                bad[9..13].copy_from_slice(&0u32.to_be_bytes());
                bad
            }),
            ("absurd hashes", {
                let mut bad = good.clone();
                bad[9..13].copy_from_slice(&9999u32.to_be_bytes());
                bad
            }),
            ("body shorter than the header claims", {
                let mut bad = good.clone();
                bad.truncate(good.len() - 1);
                bad
            }),
            ("body longer than the header claims", {
                let mut bad = good.clone();
                bad.push(0);
                bad
            }),
            ("size not a whole number of bytes", {
                let mut bad = good.clone();
                bad[13..21].copy_from_slice(&((1u64 << 14) + 1).to_be_bytes());
                bad
            }),
            ("size beyond the cap", {
                let mut bad = good.clone();
                bad[13..21].copy_from_slice(&(MAX_M_BITS * 2).to_be_bytes());
                bad
            }),
            ("size below the floor", {
                let mut bad = good.clone();
                bad[13..21].copy_from_slice(&8u64.to_be_bytes());
                bad
            }),
        ];

        for (what, bytes) in cases {
            assert!(
                Filter::parse_owned(&bytes).is_err(),
                "a filter with a {what} was accepted"
            );
        }
        assert!(Filter::parse_owned(&good).is_ok(), "the control must load");
    }

    #[test]
    fn impossible_shapes_are_refused() {
        assert!(Filter::new(0, 5).is_err());
        assert!(Filter::new(1 << 14, 0).is_err());
        assert!(Filter::new(1 << 14, 65).is_err());
        assert!(Filter::new((1 << 14) + 1, 5).is_err(), "not a whole byte");
        assert!(Filter::new(MAX_M_BITS * 2, 5).is_err());
    }

    // --------------------------------------------------------------- importing

    #[test]
    fn a_plaintext_list_is_imported() {
        let mut catalogue = Catalogue {
            bundled: None,
            user: None,
        };
        let summary = catalogue
            .import("hunter2\ncorrect-horse\n\n# a comment\nтройка\n")
            .unwrap();
        assert_eq!(summary.added, 3);
        assert_eq!(summary.as_digests, 0);
        assert!(catalogue.contains("hunter2"));
        assert!(catalogue.contains("correct-horse"));
        assert!(catalogue.contains("тройка"), "non-ASCII must work too");
        assert!(!catalogue.contains("a comment"));
        assert!(!catalogue.contains("never seen"));
    }

    #[test]
    fn a_list_of_digests_is_imported() {
        // The published form: an uppercase SHA-1 and how often it was seen.
        // "password" hashes to this.
        let mut catalogue = Catalogue {
            bundled: None,
            user: None,
        };
        let summary = catalogue
            .import("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n")
            .unwrap();
        assert_eq!(summary.as_digests, 1);
        assert!(catalogue.contains("password"));
    }

    #[test]
    fn a_digest_without_a_count_is_still_a_digest() {
        let mut catalogue = Catalogue {
            bundled: None,
            user: None,
        };
        catalogue
            .import("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n")
            .unwrap();
        assert!(catalogue.contains("password"), "lowercase hex must work");
    }

    #[test]
    fn a_word_that_merely_looks_like_a_digest_is_treated_as_a_password() {
        assert!(parse_digest_line("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd").is_none());
        assert!(parse_digest_line("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd88").is_none());
        assert!(parse_digest_line("zbaa61e4c9b93f3f0682250b6cf8331b7ee68fd8").is_none());
        assert!(parse_digest_line("password").is_none());
        assert!(parse_digest_line("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8").is_some());
    }

    #[test]
    fn a_mixed_list_is_imported_and_counted_honestly() {
        let mut catalogue = Catalogue {
            bundled: None,
            user: None,
        };
        let summary = catalogue
            .import(
                "# two of each\n\
                 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:100\n\
                 7C4A8D09CA3762AF61E59520943DC26494F8941B:200\n\
                 my-own-password\n\
                 another one\n\
                 \n",
            )
            .unwrap();
        assert_eq!(summary.added, 4);
        assert_eq!(summary.as_digests, 2);
        assert!(catalogue.contains("password"));
        assert!(catalogue.contains("123456"));
        assert!(catalogue.contains("my-own-password"));
        assert!(catalogue.contains("another one"), "spaces are part of it");
    }

    #[test]
    fn an_empty_list_is_refused_rather_than_silently_doing_nothing() {
        let mut catalogue = Catalogue {
            bundled: None,
            user: None,
        };
        assert!(catalogue.import("").is_err());
        assert!(catalogue.import("\n\n   \n# only comments\n").is_err());
    }

    #[test]
    fn a_second_import_adds_to_the_first() {
        let mut catalogue = Catalogue {
            bundled: None,
            user: None,
        };
        catalogue.import("first\n").unwrap();
        catalogue.import("second\n").unwrap();
        assert!(catalogue.contains("first"));
        assert!(catalogue.contains("second"));
        assert_eq!(catalogue.user().unwrap().count(), 2);
    }

    #[test]
    fn an_imported_list_is_sized_for_what_it_holds() {
        for entries in [1u64, 100, 10_000, 1_000_000, 50_000_000] {
            let m = size_for(entries);
            assert!(m.is_power_of_two());
            assert!((MIN_M_BITS..=MAX_M_BITS).contains(&m));
            let k = hashes_for(m, entries);
            assert!((1..=64).contains(&k));
        }
        // A list far larger than the cap still produces a usable filter, just
        // a crowded one — which `saturation` then reports.
        assert_eq!(size_for(u64::MAX), MAX_M_BITS);
    }

    #[test]
    fn the_bundled_and_imported_lists_are_both_consulted() {
        let mut catalogue = Catalogue::bundled_only();
        catalogue.import("a-password-of-my-own\n").unwrap();
        assert!(catalogue.contains("a-password-of-my-own"), "from the import");
        assert!(catalogue.contains("qwerty"), "from the bundled list");
    }

    #[test]
    fn a_catalogue_with_no_lists_at_all_answers_no() {
        // What `load` falls back to if both blocks are unreadable. It must
        // degrade into "I cannot check", never into "everything is leaked".
        let catalogue = Catalogue {
            bundled: None,
            user: None,
        };
        assert!(!catalogue.contains("password"));
        assert!(!catalogue.contains("anything"));
    }

    // --------------------------------------------------- through the disk

    #[test]
    fn an_imported_list_is_still_there_after_a_restart() {
        // Everything above this point builds a catalogue in memory. The path
        // that actually matters is the one that writes it and reads it back,
        // and it was the one with no test.
        let _home = crate::config::test_home::TestHome::new("breach-restart");

        let mut catalogue = Catalogue::bundled_only();
        catalogue.import("a-password-of-my-own\nanother-one\n").unwrap();
        catalogue.save_user().unwrap();

        let reopened = Catalogue::load();
        assert!(reopened.contains("a-password-of-my-own"));
        assert!(reopened.contains("another-one"));
        assert!(reopened.contains("qwerty"), "and the bundled list as well");
        assert_eq!(reopened.user().map(|f| f.count()), Some(2));
    }

    #[test]
    fn forgetting_the_imported_list_removes_it_from_the_disk_too() {
        let _home = crate::config::test_home::TestHome::new("breach-forget");

        let mut catalogue = Catalogue::bundled_only();
        catalogue.import("a-password-of-my-own\n").unwrap();
        catalogue.save_user().unwrap();
        assert!(user_path().is_file());

        catalogue.forget_user().unwrap();
        assert!(!user_path().exists(), "a forgotten list must not be left behind");
        assert!(!catalogue.contains("a-password-of-my-own"));
        assert!(catalogue.contains("qwerty"), "the bundled list stays");

        // Forgetting a list that is not there is not an error: the button is
        // allowed to be pressed twice.
        catalogue.forget_user().unwrap();
    }

    #[test]
    fn a_damaged_list_on_disk_costs_the_list_and_nothing_else() {
        // A filter that will not load is a reason to check fewer passwords,
        // not a reason to refuse to run a password manager.
        let _home = crate::config::test_home::TestHome::new("breach-damaged");
        crate::config::ensure_app_dir().unwrap();
        std::fs::write(user_path(), b"this is not a filter").unwrap();

        let catalogue = Catalogue::load();
        assert!(catalogue.user().is_none(), "the damaged list is dropped");
        assert!(catalogue.contains("qwerty"), "the bundled one still answers");
        assert!(!catalogue.contains("a-password-nobody-has-used"));
    }

    #[test]
    fn saving_with_nothing_imported_writes_nothing() {
        let _home = crate::config::test_home::TestHome::new("breach-nosave");
        Catalogue::bundled_only().save_user().unwrap();
        assert!(
            !user_path().exists(),
            "an empty save must not leave a file that load would then read"
        );
    }
}
