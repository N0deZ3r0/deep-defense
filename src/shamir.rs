//! Splitting the master password so that forgetting it is survivable.
//!
//! The most likely way to lose a vault is not an attacker. It is the owner
//! forgetting one string. Everything else in this program is built to make
//! that string irreplaceable, which means the failure is total and silent.
//!
//! Shamir's scheme turns one secret into `n` shares of which any `k` rebuild
//! it, and any `k - 1` say nothing at all — not "almost", not "hard to
//! reverse": the remaining possibilities are exactly as numerous as before.
//! Three shares at 2-of-3, kept at home, at a relative's and in a safe, mean
//! no single place is either a weakness or a single point of failure.
//!
//! # What is split, and why that choice
//!
//! We split **the master password itself**, not a key stored somewhere that
//! unwraps it. That costs nothing and buys a lot:
//!
//! - the vault file format is untouched, so a vault with recovery shares is
//!   byte-for-byte the same shape as one without;
//! - nothing lands on disk, so there is no second object to find, steal or
//!   back up, and no way to tell from the file that recovery exists;
//! - recovery needs no special code path — the reconstructed password is
//!   typed into the ordinary unlock screen.
//!
//! The price is that shares go stale when the master password changes. The
//! program says so, out loud, at the moment of the change.
//!
//! # Why a share carries no hash of the secret
//!
//! The obvious way to tell "you combined the wrong shares" is to store a hash
//! of the secret alongside them. We deliberately do not: a share is written on
//! paper and will eventually be photographed, and a hash of the master
//! password would turn that one photograph into an offline cracking target —
//! precisely the attack the whole program exists to prevent.
//!
//! Instead each set carries a random identifier, so shares from different sets
//! are refused structurally, and each share carries a checksum over *itself*,
//! so a mistyped character is caught. Whether the reconstruction is right is
//! answered by the vault opening. That is the only check that leaks nothing.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::random_bytes;
use crate::errors::{Error, Result};

/// Fewer than two makes the share a copy of the secret, not a share of it.
pub const MIN_THRESHOLD: u8 = 2;
/// The field allows 255. Sixteen is where hand-copying stops being realistic,
/// and a limit people can actually meet is worth more than one they cannot.
pub const MAX_SHARES: u8 = 16;

const VERSION: u8 = 1;
const SET_ID_LEN: usize = 8;
const CHECKSUM_LEN: usize = 4;
/// version, threshold, index, set id.
const HEADER_LEN: usize = 3 + SET_ID_LEN;

/// RFC 4648 base32. Chosen over base64 because it has one case and omits the
/// characters that ruin handwritten copies.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ------------------------------------------------------------------ GF(2^8)

/// Multiplication in the AES field, without lookup tables.
///
/// A table-driven version would be faster and would leak which entries were
/// touched through the cache. At thirty-two bytes times sixteen shares the
/// speed does not matter, so there is no reason to accept the leak.
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        // 0xFF when the low bit of b is set, 0x00 otherwise — the branch-free
        // spelling of "add a into the result if this bit is set".
        let add = (b & 1).wrapping_neg();
        result ^= a & add;
        let overflow = (a >> 7).wrapping_neg();
        a <<= 1;
        a ^= 0x1b & overflow;
        b >>= 1;
    }
    result
}

/// The multiplicative inverse, as `a^254`. Zero has none and maps to zero.
///
/// The exponent is a constant, so the sequence of operations does not depend
/// on `a` — only the values do.
fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut power = a;
    for bit in 0..8 {
        if (254u32 >> bit) & 1 == 1 {
            result = gf_mul(result, power);
        }
        power = gf_mul(power, power);
    }
    result
}

fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

// ------------------------------------------------------------------- shares

/// One piece of a split secret. Useless on its own, by construction.
#[derive(Clone)]
pub struct Share {
    version: u8,
    threshold: u8,
    /// The x coordinate. Never zero: `f(0)` is the secret.
    index: u8,
    set_id: [u8; SET_ID_LEN],
    data: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Hand-written: a derived one would print the share body, which is the one
/// thing that must not end up in a log line or a panic message.
impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("threshold", &self.threshold)
            .field("bytes", &self.data.len())
            .finish()
    }
}

impl Share {
    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Identifies the set this share came from, for telling the user which
    /// pile a stray card belongs to.
    pub fn set_label(&self) -> String {
        self.set_id[..3]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("")
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.data.len());
        out.push(self.version);
        out.push(self.threshold);
        out.push(self.index);
        out.extend_from_slice(&self.set_id);
        out.extend_from_slice(&self.data);
        out
    }

    /// The share as written on paper: base32 in groups of four.
    pub fn to_text(&self) -> String {
        let mut blob = self.body();
        let checksum = Sha256::digest(&blob);
        blob.extend_from_slice(&checksum[..CHECKSUM_LEN]);
        let encoded = base32_encode(&blob);
        blob.zeroize();

        encoded
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("-")
    }
}

// ------------------------------------------------------------------- base32

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes what someone actually typed, not what the encoder produced.
///
/// Everything outside the alphabet is dropped, so dashes, spaces and line
/// breaks are free. The three characters base32 leaves out are exactly the
/// three that get confused in handwriting, so they are mapped back rather than
/// rejected; a wrong guess is caught by the checksum a moment later.
fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8 + 1);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for raw in text.chars() {
        let ch = match raw.to_ascii_uppercase() {
            '0' => 'O',
            '1' => 'I',
            '8' => 'B',
            other => other,
        };
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => continue,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    out
}

// -------------------------------------------------------------- split/combine

/// Splits `secret` into `count` shares, any `threshold` of which rebuild it.
pub fn split(secret: &[u8], threshold: u8, count: u8) -> Result<Vec<Share>> {
    if secret.is_empty() {
        return Err(Error::format("there is nothing to split"));
    }
    if threshold < MIN_THRESHOLD {
        return Err(Error::format(
            "a threshold below two would make every share a copy of the secret",
        ));
    }
    if count < threshold {
        return Err(Error::format(
            "fewer shares than the threshold could never be combined",
        ));
    }
    if count > MAX_SHARES {
        return Err(Error::format("too many shares"));
    }

    let mut set_id = [0u8; SET_ID_LEN];
    random_bytes(&mut set_id)?;

    // One random coefficient per degree per byte. These are the whole secret
    // of the scheme: if they are predictable, so is the polynomial.
    let degrees = threshold as usize - 1;
    let mut coefficients = Zeroizing::new(vec![0u8; secret.len() * degrees]);
    random_bytes(&mut coefficients)?;

    let mut shares = Vec::with_capacity(count as usize);
    for index in 1..=count {
        let mut data = vec![0u8; secret.len()];
        for (position, out) in data.iter_mut().enumerate() {
            // Horner, from the highest coefficient down to the secret byte at
            // the constant term.
            let mut acc = 0u8;
            for degree in (1..=degrees).rev() {
                acc = gf_mul(acc, index) ^ coefficients[position * degrees + degree - 1];
            }
            *out = gf_mul(acc, index) ^ secret[position];
        }
        shares.push(Share {
            version: VERSION,
            threshold,
            index,
            set_id,
            data,
        });
    }

    // Prove the set works before handing it over. A bug here would be found by
    // the user at the exact moment they had no other way in, so the cost of one
    // extra interpolation is not worth arguing about.
    let rebuilt = combine(&shares[..threshold as usize])?;
    if rebuilt.as_slice() != secret {
        return Err(Error::crypto(
            "the freshly split secret did not rebuild; refusing to hand out shares",
        ));
    }

    Ok(shares)
}

/// Rebuilds the secret from `threshold` or more shares of one set.
pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
    let first = shares
        .first()
        .ok_or_else(|| Error::format("no shares were given"))?;

    if first.version != VERSION {
        return Err(Error::format("these shares were made by another version"));
    }
    let threshold = first.threshold as usize;
    let length = first.data.len();

    for share in shares {
        if share.threshold != first.threshold || share.version != first.version {
            return Err(Error::format("these shares do not belong to one set"));
        }
        if share.set_id != first.set_id {
            return Err(Error::format("these shares come from different splits"));
        }
        if share.data.len() != length {
            return Err(Error::format("these shares are of different lengths"));
        }
        if share.index == 0 {
            return Err(Error::format("a share carries an impossible index"));
        }
    }

    // Two shares with the same index are one share counted twice, and would
    // divide by zero below. Catching it here turns a wrong answer into a
    // readable message.
    for (position, share) in shares.iter().enumerate() {
        if shares[..position].iter().any(|s| s.index == share.index) {
            return Err(Error::format("the same share was given twice"));
        }
    }

    if shares.len() < threshold {
        return Err(Error::format("not enough shares"));
    }

    let used = &shares[..threshold];
    let mut secret = Zeroizing::new(vec![0u8; length]);

    // Lagrange interpolation evaluated at zero. Subtraction is XOR here, so
    // (0 - x_j) is just x_j and (x_i - x_j) is x_i ^ x_j.
    for (i, share) in used.iter().enumerate() {
        let mut basis = 1u8;
        for (j, other) in used.iter().enumerate() {
            if i == j {
                continue;
            }
            basis = gf_mul(basis, gf_div(other.index, share.index ^ other.index));
        }
        for (position, byte) in share.data.iter().enumerate() {
            secret[position] ^= gf_mul(*byte, basis);
        }
    }

    Ok(secret)
}

// --------------------------------------------------------------- share text

/// Reads one written share. Leading labels and trailing notes are tolerated
/// only insofar as they are not base32 — see [`parse_shares`] for pasted cards.
pub fn parse_share(text: &str) -> Result<Share> {
    let blob = base32_decode(text);
    if blob.len() < HEADER_LEN + CHECKSUM_LEN + 1 {
        return Err(Error::format("that is too short to be a share"));
    }
    let split_at = blob.len() - CHECKSUM_LEN;
    let (body, checksum) = blob.split_at(split_at);

    let expected = Sha256::digest(body);
    if expected[..CHECKSUM_LEN] != *checksum {
        return Err(Error::format(
            "that share did not check out — a character is probably wrong",
        ));
    }

    let mut set_id = [0u8; SET_ID_LEN];
    set_id.copy_from_slice(&body[3..3 + SET_ID_LEN]);
    Ok(Share {
        version: body[0],
        threshold: body[1],
        index: body[2],
        set_id,
        data: body[HEADER_LEN..].to_vec(),
    })
}

/// Picks every share out of pasted text, ignoring everything else.
///
/// People paste the whole printed card, headings and all. Scanning line by line
/// and keeping what checksums is more useful than demanding one share, bare,
/// per attempt.
pub fn parse_shares(text: &str) -> Vec<Share> {
    let mut found: Vec<Share> = Vec::new();
    for line in text.lines() {
        let Ok(share) = parse_share(line) else {
            continue;
        };
        // The same card pasted twice is a slip, not a second share.
        if found
            .iter()
            .any(|s| s.index == share.index && s.set_id == share.set_id)
        {
            continue;
        }
        found.push(share);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"correct horse battery staple";

    // ------------------------------------------------------------- the field

    #[test]
    fn multiplication_matches_the_aes_field() {
        // The worked example from the Rijndael specification.
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        // A field is commutative and has one as its identity.
        assert_eq!(gf_mul(0x83, 0x57), 0xc1);
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(a, 0), 0);
        }
    }

    #[test]
    fn multiplication_is_associative_and_distributive() {
        // Spot-checked rather than exhaustive: 16.7M triples is too slow for a
        // test that runs on every build.
        for a in (0..=255u8).step_by(17) {
            for b in (0..=255u8).step_by(13) {
                for c in (0..=255u8).step_by(11) {
                    assert_eq!(gf_mul(gf_mul(a, b), c), gf_mul(a, gf_mul(b, c)));
                    assert_eq!(gf_mul(a, b ^ c), gf_mul(a, b) ^ gf_mul(a, c));
                }
            }
        }
    }

    #[test]
    fn every_nonzero_byte_has_an_inverse() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "{a} has no inverse");
            assert_eq!(gf_div(a, a), 1);
        }
        assert_eq!(gf_inv(0), 0, "zero has no inverse and must not pretend to");
    }

    // -------------------------------------------------------- split/combine

    #[test]
    fn any_subset_of_the_threshold_size_rebuilds_the_secret() {
        let shares = split(SECRET, 3, 5).unwrap();
        let mut subsets = 0;
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let picked = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(combine(&picked).unwrap().as_slice(), SECRET);
                    subsets += 1;
                }
            }
        }
        assert_eq!(subsets, 10, "all ten three-of-five subsets must be covered");
    }

    #[test]
    fn a_range_of_shapes_round_trips() {
        for (threshold, count) in [(2u8, 2u8), (2, 3), (3, 3), (3, 7), (5, 8), (16, 16)] {
            let shares = split(SECRET, threshold, count).unwrap();
            assert_eq!(shares.len(), count as usize);
            let rebuilt = combine(&shares[..threshold as usize]).unwrap();
            assert_eq!(rebuilt.as_slice(), SECRET, "{threshold}-of-{count} failed");
        }
    }

    #[test]
    fn more_shares_than_the_threshold_are_accepted() {
        let shares = split(SECRET, 2, 5).unwrap();
        assert_eq!(combine(&shares).unwrap().as_slice(), SECRET);
    }

    #[test]
    fn a_long_secret_round_trips() {
        let long: Vec<u8> = (0..=255u8).collect();
        let shares = split(&long, 4, 6).unwrap();
        assert_eq!(combine(&shares[1..5]).unwrap().as_slice(), &long[..]);
    }

    #[test]
    fn no_share_contains_the_secret() {
        let shares = split(SECRET, 2, 3).unwrap();
        for share in &shares {
            assert_ne!(share.data.as_slice(), SECRET);
        }
    }

    /// The information-theoretic claim, tested exactly rather than argued.
    ///
    /// With a two-of-two split of a single byte, one share plus *every*
    /// possible partner yields every possible secret exactly once. So holding
    /// one share leaves all 256 secrets equally likely: it says nothing.
    #[test]
    fn one_share_of_two_leaves_every_secret_equally_possible() {
        let shares = split(&[0x42], 2, 2).unwrap();
        let held = shares[0].clone();

        let mut reached = [0u32; 256];
        for candidate in 0..=255u8 {
            let partner = Share {
                version: VERSION,
                threshold: 2,
                index: shares[1].index,
                set_id: held.set_id,
                data: vec![candidate],
            };
            let rebuilt = combine(&[held.clone(), partner]).unwrap();
            reached[rebuilt[0] as usize] += 1;
        }
        assert!(
            reached.iter().all(|&count| count == 1),
            "one share must not narrow the secret at all"
        );
    }

    #[test]
    fn two_shares_of_three_leave_every_secret_possible() {
        let shares = split(&[0x42], 3, 3).unwrap();
        let mut reached = [0u32; 256];
        for candidate in 0..=255u8 {
            let partner = Share {
                version: VERSION,
                threshold: 3,
                index: shares[2].index,
                set_id: shares[0].set_id,
                data: vec![candidate],
            };
            let rebuilt = combine(&[shares[0].clone(), shares[1].clone(), partner]).unwrap();
            reached[rebuilt[0] as usize] += 1;
        }
        assert!(reached.iter().all(|&count| count == 1));
    }

    #[test]
    fn each_split_gets_its_own_set_id() {
        let a = split(SECRET, 2, 2).unwrap();
        let b = split(SECRET, 2, 2).unwrap();
        assert_ne!(a[0].set_id, b[0].set_id);
    }

    // ----------------------------------------------------- what is refused

    #[test]
    fn impossible_shapes_are_refused() {
        assert!(split(SECRET, 1, 3).is_err(), "a threshold of one is a copy");
        assert!(split(SECRET, 0, 3).is_err());
        assert!(split(SECRET, 4, 3).is_err(), "unreachable threshold");
        assert!(split(SECRET, 2, MAX_SHARES + 1).is_err());
        assert!(split(b"", 2, 3).is_err(), "nothing to split");
    }

    #[test]
    fn too_few_shares_are_refused() {
        let shares = split(SECRET, 3, 5).unwrap();
        let err = combine(&shares[..2]).unwrap_err();
        assert!(format!("{err}").contains("not enough"));
        assert!(combine(&[]).is_err());
    }

    #[test]
    fn shares_from_different_splits_are_refused() {
        let a = split(SECRET, 2, 2).unwrap();
        let b = split(SECRET, 2, 2).unwrap();
        let mixed = [a[0].clone(), b[1].clone()];
        let err = combine(&mixed).unwrap_err();
        assert!(format!("{err}").contains("different splits"));
    }

    #[test]
    fn the_same_share_twice_is_refused() {
        let shares = split(SECRET, 2, 3).unwrap();
        let err = combine(&[shares[0].clone(), shares[0].clone()]).unwrap_err();
        assert!(format!("{err}").contains("twice"));
    }

    #[test]
    fn mismatched_thresholds_are_refused() {
        let shares = split(SECRET, 2, 3).unwrap();
        let mut odd = shares[1].clone();
        odd.threshold = 3;
        assert!(combine(&[shares[0].clone(), odd]).is_err());
    }

    // ------------------------------------------------------------ share text

    #[test]
    fn the_written_form_round_trips() {
        let shares = split(SECRET, 3, 5).unwrap();
        let text: Vec<String> = shares.iter().map(|s| s.to_text()).collect();
        let parsed: Vec<Share> = text.iter().map(|t| parse_share(t).unwrap()).collect();
        assert_eq!(combine(&parsed[..3]).unwrap().as_slice(), SECRET);
        for (original, round_tripped) in shares.iter().zip(&parsed) {
            assert_eq!(original.index, round_tripped.index);
            assert_eq!(original.set_id, round_tripped.set_id);
            assert_eq!(original.data, round_tripped.data);
        }
    }

    #[test]
    fn the_written_form_is_grouped_for_copying_by_hand() {
        let shares = split(SECRET, 2, 2).unwrap();
        let text = shares[0].to_text();
        assert!(text.contains('-'));
        for group in text.split('-') {
            assert!(group.len() <= 4, "groups longer than four are hard to track");
            assert!(group.chars().all(|c| ALPHABET.contains(&(c as u8))));
        }
    }

    #[test]
    fn punctuation_and_case_do_not_matter() {
        let shares = split(SECRET, 2, 2).unwrap();
        let text = shares[0].to_text();
        let mangled = format!("  {}  ", text.to_lowercase().replace('-', " "));
        assert_eq!(parse_share(&mangled).unwrap().data, shares[0].data);

        let no_separators = text.replace('-', "");
        assert_eq!(parse_share(&no_separators).unwrap().data, shares[0].data);
    }

    #[test]
    fn handwriting_confusions_are_read_as_intended() {
        // Base32 leaves out the lookalikes precisely because of this.
        let shares = split(SECRET, 2, 2).unwrap();
        let text = shares[0].to_text();
        let confused = text.replace('O', "0").replace('I', "1").replace('B', "8");
        assert_eq!(parse_share(&confused).unwrap().data, shares[0].data);
    }

    #[test]
    fn a_single_wrong_character_is_caught() {
        let shares = split(SECRET, 2, 2).unwrap();
        let original = shares[0].to_text();
        let text: Vec<char> = original.chars().collect();
        let truth = base32_decode(&original);

        let mut caught = 0;
        let mut harmless = 0;
        for position in 0..text.len() {
            if text[position] == '-' {
                continue;
            }
            for replacement in ALPHABET.iter().map(|&b| b as char) {
                if replacement == text[position] {
                    continue;
                }
                let mut wrong = text.clone();
                wrong[position] = replacement;
                let typo: String = wrong.into_iter().collect();

                // The final character carries fewer than five significant
                // bits, so a couple of letters there decode to the very same
                // bytes. Those are not typos that could corrupt anything —
                // see `the_last_character_has_a_slack_bit`. Every change that
                // does alter the bytes must be refused.
                if base32_decode(&typo) == truth {
                    harmless += 1;
                    continue;
                }
                assert!(
                    parse_share(&typo).is_err(),
                    "a wrong character at {position} slipped through"
                );
                caught += 1;
            }
        }
        assert!(caught > 1000, "the sweep should cover every position");
        assert!(
            harmless <= 2,
            "only the trailing slack bit may absorb a change, not {harmless}"
        );
    }

    /// Documents why the sweep above has an exemption at all.
    ///
    /// An unpadded base32 string almost never lands on a five-bit boundary, so
    /// the last character has spare low bits that decode to nothing. A strict
    /// reader would reject a non-zero remainder; this one ignores it, because
    /// tolerating a mis-copied final letter is worth more than diagnosing it,
    /// and the value it decodes to cannot change.
    #[test]
    fn the_last_character_has_a_slack_bit() {
        let shares = split(SECRET, 2, 2).unwrap();
        let text = shares[0].to_text();
        let truth = base32_decode(&text);

        let significant = truth.len() * 8;
        let carried = text.chars().filter(|c| *c != '-').count() * 5;
        assert!(carried > significant, "there is always some slack");
        assert!(carried - significant < 5, "never a whole spare character");

        let identical = ALPHABET
            .iter()
            .map(|&b| {
                let mut chars: Vec<char> = text.chars().collect();
                *chars.last_mut().unwrap() = b as char;
                base32_decode(&chars.into_iter().collect::<String>())
            })
            .filter(|decoded| *decoded == truth)
            .count();
        assert_eq!(
            identical,
            1 << (carried - significant),
            "exactly the slack bits may vary without changing the value"
        );
    }

    #[test]
    fn truncated_and_empty_text_is_refused() {
        assert!(parse_share("").is_err());
        assert!(parse_share("AAAA-AAAA").is_err());
        let shares = split(SECRET, 2, 2).unwrap();
        let text = shares[0].to_text();
        for cut in 1..text.len() {
            assert!(parse_share(&text[..cut]).is_err(), "prefix of {cut} accepted");
        }
    }

    #[test]
    fn a_printed_card_is_read_line_by_line() {
        let shares = split(SECRET, 2, 3).unwrap();
        let card = format!(
            "Deep Defense recovery\n\
             Keep this away from the other copies.\n\
             \n\
             Share 1 of 3 (any 2 rebuild the password)\n\
             {}\n\
             \n\
             Share 2 of 3\n\
             {}\n\
             \n\
             Written 2026-09-22.\n",
            shares[0].to_text(),
            shares[1].to_text()
        );
        let found = parse_shares(&card);
        assert_eq!(found.len(), 2, "both shares and nothing else");
        assert_eq!(combine(&found).unwrap().as_slice(), SECRET);
    }

    #[test]
    fn the_same_card_pasted_twice_counts_once() {
        let shares = split(SECRET, 2, 3).unwrap();
        let text = shares[0].to_text();
        let pasted = format!("{text}\n{text}\n{}", shares[1].to_text());
        let found = parse_shares(&pasted);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn prose_alone_yields_no_shares() {
        assert!(parse_shares("no shares here, just words\nand another line").is_empty());
    }

    #[test]
    fn a_share_debug_does_not_print_its_body() {
        let shares = split(b"unmistakable", 2, 2).unwrap();
        let printed = format!("{:?}", shares[0]);
        assert!(!printed.contains("unmistakable"));
    }

    #[test]
    fn the_set_label_is_short_and_stable_across_a_set() {
        let shares = split(SECRET, 2, 3).unwrap();
        let label = shares[0].set_label();
        assert_eq!(label.len(), 6);
        assert!(shares.iter().all(|s| s.set_label() == label));
    }

    // ---------------------------------------------------------------- base32

    #[test]
    fn base32_round_trips_every_length() {
        for length in 1..40usize {
            let bytes: Vec<u8> = (0..length).map(|i| (i * 7 + 3) as u8).collect();
            let text = base32_encode(&bytes);
            assert_eq!(base32_decode(&text), bytes, "length {length} failed");
        }
    }

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI"), b"foobar".to_vec());
    }
}
