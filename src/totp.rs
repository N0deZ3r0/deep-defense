//! Time-based one-time passwords (RFC 6238), so the vault can hold the
//! second factor alongside the first.
//!
//! A deliberate note on threat model: storing a TOTP seed next to the
//! password it protects collapses two factors into one. It is still worth
//! having — it defeats password reuse, phishing replay and credential-stuffing
//! — but if an attacker opens this vault, they have both. The UI says so where
//! the user enters the seed.

use hmac::{EagerHash, Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn parse(text: &str) -> Self {
        match text.to_ascii_uppercase().as_str() {
            "SHA256" => Algorithm::Sha256,
            "SHA512" => Algorithm::Sha512,
            _ => Algorithm::Sha1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TotpConfig {
    pub secret_base32: String,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret_base32: String::new(),
            // The values every mainstream authenticator uses.
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
        }
    }
}

impl TotpConfig {
    /// Accept either a bare base32 seed or a full `otpauth://` URI.
    ///
    /// Users copy whichever the site gave them, so we take both rather than
    /// making them hand-extract the seed.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(Error::vault("no TOTP secret given"));
        }
        if input.to_ascii_lowercase().starts_with("otpauth://") {
            return Self::parse_uri(input);
        }
        let config = Self {
            secret_base32: normalise_base32(input),
            ..Default::default()
        };
        config.validate()?;
        Ok(config)
    }

    fn parse_uri(uri: &str) -> Result<Self> {
        let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut config = Self::default();
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let value = percent_decode(value);
            match key.to_ascii_lowercase().as_str() {
                "secret" => config.secret_base32 = normalise_base32(&value),
                "digits" => config.digits = value.parse().unwrap_or(6),
                "period" => config.period = value.parse().unwrap_or(30),
                "algorithm" => config.algorithm = Algorithm::parse(&value),
                _ => {}
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.secret_base32.is_empty() {
            return Err(Error::vault("the TOTP secret is empty"));
        }
        decode_base32(&self.secret_base32)?;
        if !(6..=10).contains(&self.digits) {
            return Err(Error::vault("TOTP codes must have between 6 and 10 digits"));
        }
        if !(5..=300).contains(&self.period) {
            return Err(Error::vault(
                "the TOTP period must be between 5 and 300 seconds",
            ));
        }
        Ok(())
    }

    /// The current code, and how many seconds remain before it rolls over.
    pub fn current(&self) -> Result<(String, u64)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::vault("the system clock is before 1970"))?
            .as_secs();
        let code = self.code_at(now)?;
        let remaining = self.period - (now % self.period);
        Ok((code, remaining))
    }

    pub fn code_at(&self, unix_seconds: u64) -> Result<String> {
        let counter = unix_seconds / self.period;
        let secret = decode_base32(&self.secret_base32)?;
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac_digest::<Sha1>(&secret, counter)?,
            Algorithm::Sha256 => hmac_digest::<Sha256>(&secret, counter)?,
            Algorithm::Sha512 => hmac_digest::<Sha512>(&secret, counter)?,
        };
        Ok(truncate(&digest, self.digits))
    }
}

fn hmac_digest<D>(secret: &[u8], counter: u64) -> Result<Zeroizing<Vec<u8>>>
where
    D: EagerHash,
    Hmac<D>: KeyInit + Mac,
{
    let mut mac = <Hmac<D> as KeyInit>::new_from_slice(secret)
        .map_err(|_| Error::vault("the TOTP secret is not a usable key"))?;
    mac.update(&counter.to_be_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

/// RFC 4226 dynamic truncation.
fn truncate(digest: &[u8], digits: u32) -> String {
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    // u64, not u32: `validate` permits up to 10 digits, and 10^10 does not
    // fit in a u32 - it would panic in debug and wrap silently in release.
    let modulus = 10u64.pow(digits);
    format!(
        "{:0width$}",
        u64::from(binary) % modulus,
        width = digits as usize
    )
}

/// Strip the spaces and lowercase letters that authenticator sites sprinkle
/// through the seed when they display it for copying.
fn normalise_base32(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Decode RFC 4648 base32, tolerating missing padding.
pub fn decode_base32(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for c in input.chars() {
        if c == '=' {
            continue;
        }
        let upper = c.to_ascii_uppercase() as u8;
        let Some(value) = ALPHABET.iter().position(|a| *a == upper) else {
            return Err(Error::vault(format!(
                "\"{c}\" is not a valid base32 character — check the secret"
            )));
        };
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }

    if output.is_empty() {
        return Err(Error::vault("the TOTP secret decodes to nothing"));
    }
    Ok(output)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(if bytes[index] == b'+' { b' ' } else { bytes[index] });
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 test vectors, with the seed the document specifies.
    #[test]
    fn matches_rfc6238_sha1_vectors() {
        // "12345678901234567890" in base32.
        let config = TotpConfig {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 8,
            period: 30,
            algorithm: Algorithm::Sha1,
        };
        assert_eq!(config.code_at(59).unwrap(), "94287082");
        assert_eq!(config.code_at(1_111_111_109).unwrap(), "07081804");
        assert_eq!(config.code_at(1_111_111_111).unwrap(), "14050471");
        assert_eq!(config.code_at(1_234_567_890).unwrap(), "89005924");
        assert_eq!(config.code_at(2_000_000_000).unwrap(), "69279037");
    }

    #[test]
    fn matches_rfc6238_sha256_vector() {
        // "12345678901234567890123456789012" in base32.
        let config = TotpConfig {
            secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA".into(),
            digits: 8,
            period: 30,
            algorithm: Algorithm::Sha256,
        };
        assert_eq!(config.code_at(59).unwrap(), "46119246");
    }

    #[test]
    fn parses_an_otpauth_uri() {
        let config = TotpConfig::parse(
            "otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(config.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
    }

    #[test]
    fn accepts_a_seed_with_the_spacing_sites_display() {
        let config = TotpConfig::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(config.secret_base32, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn rejects_a_secret_that_is_not_base32() {
        assert!(TotpConfig::parse("not-valid-base32!!").is_err());
    }

    #[test]
    fn ten_digit_codes_do_not_overflow() {
        // 10^10 does not fit in a u32; this panicked in debug builds before
        // the modulus was widened.
        let config = TotpConfig {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            digits: 10,
            period: 30,
            algorithm: Algorithm::Sha1,
        };
        let code = config.code_at(1_700_000_000).unwrap();
        assert_eq!(code.len(), 10);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn codes_have_the_requested_digit_count() {
        let config = TotpConfig::parse("JBSWY3DPEHPK3PXP").unwrap();
        let code = config.code_at(1_700_000_000).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn the_code_changes_when_the_period_rolls_over() {
        let config = TotpConfig::parse("JBSWY3DPEHPK3PXP").unwrap();
        // Anchor on a real period boundary. Periods are counted from the Unix
        // epoch, so a round-looking timestamp is usually mid-period.
        let start = 1_700_000_000 - (1_700_000_000 % config.period);

        let at_start = config.code_at(start).unwrap();
        assert_eq!(at_start, config.code_at(start + config.period - 1).unwrap());
        assert_ne!(at_start, config.code_at(start + config.period).unwrap());
    }
}
