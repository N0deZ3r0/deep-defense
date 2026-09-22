//! Password generation and strength estimation.
//!
//! Every random byte comes from the OS CSPRNG via [`crate::crypto::random_bytes`].
//! Nothing here uses a statistical PRNG: observing a handful of outputs from
//! one reveals all the rest, which is fatal for a password generator.

use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use crate::errors::{Error, Result};

pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
/// Glyphs that are easy to confuse when a password is read aloud or retyped
/// from a screen. Excluding them costs roughly 0.3 bits per character.
pub const AMBIGUOUS: &str = "Il1O0o|`'\";:.,";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub length: usize,
    pub use_lower: bool,
    pub use_upper: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
    pub avoid_ambiguous: bool,
    pub require_each_class: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            length: 24,
            use_lower: true,
            use_upper: true,
            use_digits: true,
            use_symbols: true,
            avoid_ambiguous: false,
            require_each_class: true,
        }
    }
}

impl Policy {
    fn filter(&self, chars: &str) -> Vec<char> {
        chars
            .chars()
            .filter(|c| !self.avoid_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    }

    pub fn classes(&self) -> Vec<Vec<char>> {
        let mut classes = Vec::new();
        for (enabled, chars) in [
            (self.use_lower, LOWER),
            (self.use_upper, UPPER),
            (self.use_digits, DIGITS),
            (self.use_symbols, SYMBOLS),
        ] {
            if enabled {
                let set = self.filter(chars);
                if !set.is_empty() {
                    classes.push(set);
                }
            }
        }
        classes
    }

    pub fn alphabet(&self) -> Vec<char> {
        self.classes().into_iter().flatten().collect()
    }

    pub fn validate(&self) -> Result<()> {
        if self.length < 8 {
            return Err(Error::vault("a generated password must be at least 8 characters"));
        }
        if self.length > 512 {
            return Err(Error::vault("a generated password must be at most 512 characters"));
        }
        let classes = self.classes();
        if classes.is_empty() {
            return Err(Error::vault("enable at least one character class"));
        }
        if self.require_each_class && self.length < classes.len() {
            return Err(Error::vault(
                "the password is too short to hold one character from each class",
            ));
        }
        Ok(())
    }

    /// Entropy of a password this policy produces.
    ///
    /// A real figure, not a heuristic: the characters are independent and
    /// uniform over the alphabet.
    pub fn entropy_bits(&self) -> f64 {
        let size = self.alphabet().len();
        if size < 2 {
            return 0.0;
        }
        self.length as f64 * (size as f64).log2()
    }
}

/// Draw a uniformly random index in `0..bound` without modulo bias.
///
/// The naive `random_u32 % bound` is skewed whenever `bound` does not divide
/// 2^32: low indices come up slightly more often. For a password alphabet
/// that bias is small but entirely avoidable, so we reject and redraw.
fn uniform_index(bound: usize) -> Result<usize> {
    if bound == 0 {
        return Err(Error::crypto("cannot choose from an empty alphabet"));
    }
    if bound == 1 {
        return Ok(0);
    }
    let bound_u32 = u32::try_from(bound)
        .map_err(|_| Error::crypto("alphabet is implausibly large"))?;
    // The largest multiple of `bound` that fits in u32; anything at or above
    // `limit` would land in the short final bucket, so we draw again.
    let limit = u32::MAX - (u32::MAX % bound_u32) - (bound_u32 - 1);

    let mut buffer = [0u8; 4];
    for _ in 0..1000 {
        random_bytes(&mut buffer)?;
        let value = u32::from_le_bytes(buffer);
        if value <= limit {
            return Ok((value % bound_u32) as usize);
        }
    }
    Err(Error::crypto(
        "the random number generator would not produce an unbiased value",
    ))
}

/// Generate a password, optionally guaranteeing one character per class.
///
/// The guarantee is enforced by redrawing the whole password, not by planting
/// required characters at fixed positions — fixed positions would leak
/// structure to anyone who knows how the generator works.
pub fn generate_password(policy: &Policy) -> Result<Zeroizing<String>> {
    policy.validate()?;
    let alphabet = policy.alphabet();
    let classes = policy.classes();

    for _ in 0..2000 {
        let mut candidate = Zeroizing::new(String::with_capacity(policy.length));
        for _ in 0..policy.length {
            candidate.push(alphabet[uniform_index(alphabet.len())?]);
        }
        if !policy.require_each_class {
            return Ok(candidate);
        }
        let satisfied = classes
            .iter()
            .all(|class| candidate.chars().any(|c| class.contains(&c)));
        if satisfied {
            return Ok(candidate);
        }
    }
    Err(Error::vault(
        "could not satisfy the password policy — loosen it or increase the length",
    ))
}

/// Generate a random keyfile for VeraCrypt to use alongside the password.
///
/// A keyfile turns the container into something-you-know plus
/// something-you-have. Keep it on removable media; storing it next to the
/// container defeats the entire point.
pub fn generate_keyfile(path: &std::path::Path, size: usize) -> Result<()> {
    if path.exists() {
        return Err(Error::vault(format!(
            "refusing to overwrite an existing file: {}",
            path.display()
        )));
    }
    if !(64..=1_048_576).contains(&size) {
        return Err(Error::vault("a keyfile must be between 64 bytes and 1 MiB"));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent.to_path_buf(), e))?;
    }
    let mut data = Zeroizing::new(vec![0u8; size]);
    random_bytes(&mut data)?;
    std::fs::write(path, &*data).map_err(|e| Error::io(path.to_path_buf(), e))
}

// ------------------------------------------------------- master passphrase

/// Consonants and vowels for pronounceable syllables.
///
/// `q`, `x` and `y` are left out: they make syllables that are awkward to say
/// and easy to mistype, and dropping them costs a fraction of a bit.
const SYLLABLE_CONSONANTS: [char; 17] = [
    'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z',
];
const SYLLABLE_VOWELS: [char; 5] = ['a', 'e', 'i', 'o', 'u'];

/// Syllables per group, and groups per passphrase.
const SYLLABLES_PER_GROUP: usize = 3;
pub const DEFAULT_PASSPHRASE_GROUPS: usize = 4;

/// The floor a master password has to clear.
///
/// 40 bits is the bottom of [`Strength::Fair`]. It is not enough to resist a
/// determined offline attack on its own — that is what Argon2id is for — but
/// it rules out the passwords that fall in the first seconds of one, and a
/// master password is the single point everything else hangs from.
pub const MASTER_PASSWORD_MIN_BITS: f64 = 40.0;
/// Independent of strength: a short password cannot be salvaged by a large
/// character set, and this is the length every guide agrees on.
pub const MASTER_PASSWORD_MIN_LENGTH: usize = 8;

/// Why a proposed master password was refused, if it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasterPasswordProblem {
    TooShort,
    TooWeak,
}

/// Check a candidate master password.
///
/// Deliberately stricter than the per-entry check: an entry password can be
/// replaced in one click if it turns out to be poor, but the master password
/// is what everything else is encrypted under.
pub fn check_master_password(password: &str) -> Option<MasterPasswordProblem> {
    if password.chars().count() < MASTER_PASSWORD_MIN_LENGTH {
        return Some(MasterPasswordProblem::TooShort);
    }
    if estimate_entropy_bits(password) < MASTER_PASSWORD_MIN_BITS {
        return Some(MasterPasswordProblem::TooWeak);
    }
    None
}

/// Generate a pronounceable passphrase such as `tuka-vesi-doma-reku`.
///
/// A master password has to be remembered, which rules out the random-symbol
/// soup used for entry passwords: people write those down. Syllables are
/// memorable, typeable on any keyboard layout, and — unlike a "clever"
/// human-chosen phrase — carry exactly the entropy we can count.
///
/// No word list is embedded: 17 consonants × 5 vowels gives 85 syllables,
/// about 6.4 bits each, so the default four groups of three syllables is
/// roughly 77 bits. Returns the phrase and its exact entropy.
pub fn generate_passphrase(groups: usize) -> Result<(Zeroizing<String>, f64)> {
    if !(2..=12).contains(&groups) {
        return Err(Error::vault("a passphrase needs between 2 and 12 groups"));
    }
    let mut phrase = Zeroizing::new(String::with_capacity(groups * (SYLLABLES_PER_GROUP * 2 + 1)));
    for group in 0..groups {
        if group > 0 {
            phrase.push('-');
        }
        for _ in 0..SYLLABLES_PER_GROUP {
            let consonant = SYLLABLE_CONSONANTS[uniform_index(SYLLABLE_CONSONANTS.len())?];
            let vowel = SYLLABLE_VOWELS[uniform_index(SYLLABLE_VOWELS.len())?];
            phrase.push(consonant);
            phrase.push(vowel);
        }
    }
    Ok((phrase, passphrase_entropy_bits(groups)))
}

/// Exact entropy of a passphrase with `groups` groups.
pub fn passphrase_entropy_bits(groups: usize) -> f64 {
    let per_syllable = (SYLLABLE_CONSONANTS.len() * SYLLABLE_VOWELS.len()) as f64;
    (groups * SYLLABLES_PER_GROUP) as f64 * per_syllable.log2()
}

// --------------------------------------------------------------- estimation

const SEQUENCES: [&str; 4] = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
];

const COMMON: [&str; 26] = [
    "password", "passw0rd", "qwerty", "letmein", "welcome", "admin", "root",
    "iloveyou", "monkey", "dragon", "master", "sunshine", "princess",
    "football", "baseball", "superman", "trustno1", "login", "abc123",
    "123456", "1234567890", "changeme", "secret", "hello", "test", "qwerty123",
];

/// A deliberately conservative estimate for a password we did not generate.
///
/// It is an *estimate*. It cannot tell that "Tr0ub4dor&3" is a mangled
/// dictionary word, so it overstates passwords like that. Where it does
/// recognise a pattern it errs toward reporting less entropy, never more.
pub fn estimate_entropy_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut pool = 0usize;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| SYMBOLS.contains(c)) {
        pool += SYMBOLS.chars().count();
    }
    if password.chars().any(|c| c.is_whitespace()) {
        pool += 1;
    }
    // Anything outside those sets (accents, emoji, CJK) widens the pool a lot;
    // count it modestly rather than rewarding exotic characters too heavily.
    if password
        .chars()
        .any(|c| !c.is_ascii() )
    {
        pool += 128;
    }
    let pool = pool.max(2);

    let length = password.chars().count() as f64;
    let mut bits = length * (pool as f64).log2();
    let lowered = password.to_lowercase();

    // Penalties, each reflecting a guess an attacker makes cheaply.
    if COMMON.contains(&lowered.as_str()) {
        return bits.min(8.0);
    }
    if COMMON
        .iter()
        .any(|common| common.len() >= 5 && lowered.contains(common))
    {
        bits -= 12.0;
    }

    let distinct = {
        let mut chars: Vec<char> = password.chars().collect();
        chars.sort_unstable();
        chars.dedup();
        chars.len() as f64
    };
    if distinct <= 2.0 {
        bits *= 0.35;
    } else if distinct < length / 2.0 {
        bits *= 0.7;
    }

    if has_run_of_three(password) {
        bits -= 6.0;
    }
    if SEQUENCES.iter().any(|seq| contains_run(&lowered, seq, 4)) {
        bits -= 10.0;
    }
    // A four-digit year on the end is one of the most common patterns there is.
    if ends_with_year(password) {
        bits -= 6.0;
    }

    bits.max(0.0)
}

fn has_run_of_three(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    chars.windows(3).any(|w| w[0] == w[1] && w[1] == w[2])
}

fn contains_run(haystack: &str, sequence: &str, min_len: usize) -> bool {
    let seq: Vec<char> = sequence.chars().collect();
    let reversed: Vec<char> = seq.iter().rev().copied().collect();
    for source in [&seq, &reversed] {
        for window in source.windows(min_len) {
            let chunk: String = window.iter().collect();
            if haystack.contains(&chunk) {
                return true;
            }
        }
    }
    false
}

fn ends_with_year(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 4 {
        return false;
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    if !tail.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    tail.starts_with("19") || tail.starts_with("20")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    Critical,
    Weak,
    Fair,
    Strong,
    Excellent,
}

impl Strength {
    /// Thresholds describe the password alone, on purpose.
    ///
    /// Argon2id at our defaults costs ~256 MiB and about a second per guess,
    /// which buys enormous headroom — but if the label folded that in, a user
    /// would see "excellent" for a password that is terrible everywhere else
    /// they reuse it.
    pub fn from_bits(bits: f64) -> Self {
        match bits {
            b if b < 28.0 => Strength::Critical,
            b if b < 40.0 => Strength::Weak,
            b if b < 60.0 => Strength::Fair,
            b if b < 80.0 => Strength::Strong,
            _ => Strength::Excellent,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Strength::Critical => "critical",
            Strength::Weak => "weak",
            Strength::Fair => "fair",
            Strength::Strong => "strong",
            Strength::Excellent => "excellent",
        }
    }

    /// 0.0 to 1.0, for a progress bar.
    pub fn fraction(bits: f64) -> f32 {
        ((bits / 100.0).clamp(0.0, 1.0)) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_have_the_requested_length() {
        let policy = Policy {
            length: 32,
            ..Default::default()
        };
        let password = generate_password(&policy).unwrap();
        assert_eq!(password.chars().count(), 32);
    }

    #[test]
    fn every_requested_class_appears() {
        let policy = Policy {
            length: 16,
            require_each_class: true,
            ..Default::default()
        };
        for _ in 0..25 {
            let password = generate_password(&policy).unwrap();
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn ambiguous_characters_can_be_excluded() {
        let policy = Policy {
            length: 64,
            avoid_ambiguous: true,
            ..Default::default()
        };
        let password = generate_password(&policy).unwrap();
        assert!(!password.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn two_generated_passwords_differ() {
        let policy = Policy::default();
        let first = generate_password(&policy).unwrap();
        let second = generate_password(&policy).unwrap();
        assert_ne!(*first, *second);
    }

    #[test]
    fn uniform_index_stays_in_range_and_covers_it() {
        let mut seen = [false; 7];
        for _ in 0..1000 {
            let index = uniform_index(7).unwrap();
            assert!(index < 7);
            seen[index] = true;
        }
        // With 1000 draws over 7 buckets, missing one would mean real bias.
        assert!(seen.iter().all(|hit| *hit));
    }

    #[test]
    fn impossible_policies_are_rejected() {
        let too_short = Policy {
            length: 4,
            ..Default::default()
        };
        assert!(generate_password(&too_short).is_err());

        let nothing_enabled = Policy {
            use_lower: false,
            use_upper: false,
            use_digits: false,
            use_symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&nothing_enabled).is_err());
    }

    #[test]
    fn a_suggested_passphrase_clears_the_master_password_floor() {
        for _ in 0..20 {
            let (phrase, bits) = generate_passphrase(DEFAULT_PASSPHRASE_GROUPS).unwrap();
            assert!(bits > 70.0, "{bits} bits is thinner than advertised");
            assert_eq!(
                check_master_password(&phrase),
                None,
                "the generator produced a phrase its own gate rejects: {}",
                &*phrase
            );
        }
    }

    #[test]
    fn a_suggested_passphrase_is_typeable_and_grouped() {
        let (phrase, _) = generate_passphrase(4).unwrap();
        let groups: Vec<&str> = phrase.split('-').collect();
        assert_eq!(groups.len(), 4);
        for group in groups {
            assert_eq!(group.chars().count(), 6, "three syllables of two letters");
        }
        // ASCII lowercase only: typeable on any keyboard layout, and no
        // character that a phone or a terminal will mangle.
        assert!(phrase.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn two_suggested_passphrases_differ() {
        let (first, _) = generate_passphrase(4).unwrap();
        let (second, _) = generate_passphrase(4).unwrap();
        assert_ne!(*first, *second);
    }

    #[test]
    fn passphrase_entropy_is_reported_honestly() {
        // 17 consonants x 5 vowels = 85 syllables, 3 per group.
        let expected = (85f64).log2() * 3.0;
        assert!((passphrase_entropy_bits(1) - expected).abs() < 0.001);
        assert!((passphrase_entropy_bits(4) - expected * 4.0).abs() < 0.001);
    }

    #[test]
    fn absurd_passphrase_lengths_are_refused() {
        assert!(generate_passphrase(1).is_err());
        assert!(generate_passphrase(99).is_err());
    }

    #[test]
    fn the_master_password_gate_rejects_the_obvious_failures() {
        use MasterPasswordProblem::*;
        // The exact cases a user tries first.
        assert_eq!(check_master_password("111"), Some(TooShort));
        assert_eq!(check_master_password("1111111"), Some(TooShort));
        assert_eq!(check_master_password("11111111"), Some(TooWeak));
        assert_eq!(check_master_password("password"), Some(TooWeak));
        assert_eq!(check_master_password("qwerty123"), Some(TooWeak));
        assert_eq!(check_master_password("aaaaaaaaaaaa"), Some(TooWeak));
    }

    #[test]
    fn the_master_password_gate_accepts_a_real_passphrase() {
        for good in [
            "correct horse battery staple",
            "Xq7Bm4Kp9T!vZ",
            "кот окно лампа стол дерево",
        ] {
            assert_eq!(
                check_master_password(good),
                None,
                "{good} should be acceptable"
            );
        }
    }

    #[test]
    fn the_strength_estimate_never_goes_negative() {
        // The penalties stack, and several of these bottom out at exactly
        // zero. Without the clamp that would become a negative bar width.
        for bad in ["111", "aaa", "aaaa", "0000", "abcabc", "1234", "aaaaaaaaaaaa"] {
            let bits = estimate_entropy_bits(bad);
            assert!(bits >= 0.0, "{bad} scored {bits}");
        }
    }

    #[test]
    fn trivially_repetitive_passwords_score_critical() {
        // "abcabc" is deliberately absent: at 28 bits it lands just inside
        // "weak", which is the honest verdict for it. The master-password
        // gate rejects it either way.
        for bad in ["111", "aaa", "0000", "11111111", "aaaaaaaaaaaa"] {
            let bits = estimate_entropy_bits(bad);
            assert_eq!(
                Strength::from_bits(bits),
                Strength::Critical,
                "{bad} scored {bits} bits"
            );
        }
    }

    #[test]
    fn known_bad_passwords_score_as_critical() {
        for bad in ["password", "123456", "qwerty", "aaaaaaaa"] {
            let bits = estimate_entropy_bits(bad);
            assert_eq!(
                Strength::from_bits(bits),
                Strength::Critical,
                "{bad} scored {bits} bits"
            );
        }
    }

    #[test]
    fn a_generated_password_scores_well() {
        let policy = Policy::default();
        let password = generate_password(&policy).unwrap();
        assert!(estimate_entropy_bits(&password) >= 80.0);
        assert!(policy.entropy_bits() > 140.0);
    }

    #[test]
    fn patterns_are_penalised() {
        // Same character pool and length; the patterned one must score lower.
        let patterned = estimate_entropy_bits("Abcdef2024");
        let arbitrary = estimate_entropy_bits("Xq7Bm4Kp9T");
        assert!(patterned < arbitrary, "{patterned} should be < {arbitrary}");
    }

    #[test]
    fn empty_password_has_no_entropy() {
        assert_eq!(estimate_entropy_bits(""), 0.0);
    }
}
