//! The data that lives inside the vault.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const SCHEMA_VERSION: u32 = 1;
/// How many previous passwords to keep per entry. Enough to undo a bad edit,
/// few enough that a stale password does not linger for years.
pub const MAX_HISTORY: usize = 12;

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The same stamp, for callers outside this module that record a moment.
pub fn timestamp() -> String {
    now()
}

/// Days since an RFC 3339 timestamp, or `None` if it will not parse.
pub fn age_days(stamp: &str) -> Option<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(stamp).ok()?;
    let delta = chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc));
    Some(delta.num_days().max(0))
}

/// A password this entry used to have, kept so a bad edit is recoverable.
#[derive(Clone, Serialize, Deserialize)]
pub struct HistoricPassword {
    pub password: String,
    #[serde(default = "now")]
    pub replaced_at: String,
}

impl Drop for HistoricPassword {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Hand-written so a stray `{:?}` cannot print an old password.
impl std::fmt::Debug for HistoricPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoricPassword")
            .field("password", &"[redacted]")
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
}

/// One credential.
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    /// Base32 TOTP seed, if this account has one.
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "now")]
    pub created_at: String,
    #[serde(default = "now")]
    pub updated_at: String,
    #[serde(default)]
    pub history: Vec<HistoricPassword>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub fields: Vec<CustomField>,
}

/// Every plaintext field is wiped when the entry is dropped, so closing the
/// vault or deleting an entry does not leave the password in freed memory.
impl Drop for Entry {
    fn drop(&mut self) {
        self.password.zeroize();
        self.totp_secret.zeroize();
        self.notes.zeroize();
    }
}

/// Hand-written, and deliberately not derived. A derived `Debug` would print
/// `password` in full, and the single most common way a secret escapes is a
/// `{:?}` someone added while debugging and forgot to remove.
impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("url", &self.url)
            .field("notes", &"[redacted]")
            .field("totp_secret", &if self.has_totp() { "[set]" } else { "" })
            .field("tags", &self.tags)
            .field("updated_at", &self.updated_at)
            .field("history", &self.history.len())
            .field("attachments", &self.attachments.len())
            .field("fields", &self.fields.len())
            .finish()
    }
}

impl Entry {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp_secret: String::new(),
            tags: Vec::new(),
            created_at: now(),
            updated_at: now(),
            history: Vec::new(),
            attachments: Vec::new(),
            fields: Vec::new(),
        }
    }

    /// Case-insensitive identity. Two entries may not share one.
    pub fn key(&self) -> String {
        self.name.trim().to_lowercase()
    }

    pub fn age_days(&self) -> Option<i64> {
        age_days(&self.updated_at)
    }

    pub fn touch(&mut self) {
        self.updated_at = now();
    }

    /// Replace the password, pushing the old one onto the history.
    /// Returns whether the password actually changed, so the caller can log
    /// it without having to compare the strings a second time.
    pub fn set_password(&mut self, new_password: String) -> bool {
        let changed = self.password != new_password;
        if !self.password.is_empty() && new_password != self.password {
            self.history.insert(
                0,
                HistoricPassword {
                    password: std::mem::take(&mut self.password),
                    replaced_at: now(),
                },
            );
            self.history.truncate(MAX_HISTORY);
        }
        self.password = new_password;
        self.touch();
        changed
    }

    /// Search across everything except the password itself.
    ///
    /// Searching the password field would let someone looking over the user's
    /// shoulder confirm a guess without it ever appearing on screen.
    pub fn matches(&self, needle: &str) -> bool {
        let needle = needle.trim().to_lowercase();
        if needle.is_empty() {
            return true;
        }
        self.matches_folded(&needle)
    }

    /// The same search, given a needle that is already lower-cased.
    ///
    /// The list calls this once per entry on every frame the search box has
    /// text in it. The old spelling built a `Vec<String>` of the custom
    /// fields, joined it, formatted six more strings into one and lower-cased
    /// the result — four-odd allocations per entry, sixty times a second. At a
    /// few hundred entries nobody notices; at a few thousand it is felt while
    /// typing, which is exactly when a search box must not stutter.
    pub fn matches_folded(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        contains_folded(&self.name, needle)
            || contains_folded(&self.username, needle)
            || contains_folded(&self.url, needle)
            || contains_folded(&self.notes, needle)
            || self.tags.iter().any(|tag| contains_folded(tag, needle))
            || self.fields.iter().any(|field| {
                // A secret field is as sensitive as the password, so searching
                // it would let a shoulder-surfer confirm a guess the same way.
                contains_folded(&field.name, needle)
                    || (!field.secret && contains_folded(&field.value, needle))
            })
    }

    pub fn has_totp(&self) -> bool {
        !self.totp_secret.trim().is_empty()
    }
}

/// Case-insensitive substring search that allocates nothing.
///
/// `needle` must already be lower-case. There is no standard
/// case-insensitive `contains`, and the usual workaround — lower-casing the
/// haystack — is an allocation per field per entry per frame.
fn contains_folded(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    // Only ever starts at a character boundary, so this is safe for any text.
    haystack
        .char_indices()
        .any(|(at, _)| starts_with_folded(&haystack[at..], needle))
}

fn starts_with_folded(haystack: &str, needle: &str) -> bool {
    // One source character can lower-case into several — the Turkish dotted I
    // and the German sharp S both do — so the haystack is flattened into a
    // stream of lower-case characters rather than compared one for one.
    let mut folded = haystack.chars().flat_map(char::to_lowercase);
    let mut wanted = needle.chars();
    loop {
        match (wanted.next(), folded.next()) {
            (None, _) => return true,
            (Some(_), None) => return false,
            (Some(want), Some(have)) => {
                if want != have {
                    return false;
                }
            }
        }
    }
}

/// A named value beside the password: a PIN, an account number, the answer to
/// a security question.
#[derive(Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    /// Masked on screen and excluded from search, like the password itself.
    #[serde(default)]
    pub secret: bool,
}

impl Drop for CustomField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Hand-written: a derived one would print the value of a secret field.
impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", &if self.secret { "[redacted]" } else { &self.value })
            .field("secret", &self.secret)
            .finish()
    }
}

/// A file kept inside an entry.
///
/// Stored base64-encoded in the vault payload, so it is protected by exactly
/// the same two ciphers as the passwords and never touches the disk in the
/// clear. The slot has a fixed capacity, so attachments are what will fill a
/// vault up — the UI shows how much room is left.
#[derive(Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    /// Base64 of the file's bytes.
    pub data: String,
    /// Length of the decoded bytes, so the UI need not decode to show a size.
    pub size: usize,
    #[serde(default = "now")]
    pub added_at: String,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Hand-written so a stray `{:?}` cannot dump a file into a log.
impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("size", &self.size)
            .field("data", &"[redacted]")
            .finish()
    }
}

impl Attachment {
    pub fn new(name: impl Into<String>, bytes: &[u8]) -> Self {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        Self {
            name: name.into(),
            data: BASE64.encode(bytes),
            size: bytes.len(),
            added_at: now(),
        }
    }

    pub fn decode(&self) -> Option<Zeroizing<Vec<u8>>> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        BASE64.decode(&self.data).ok().map(Zeroizing::new)
    }
}

/// What happened to the vault, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    Created,
    EntryAdded,
    EntryEdited,
    PasswordChanged,
    EntryRenamed,
    EntryDeleted,
    AttachmentAdded,
    AttachmentRemoved,
    MasterPasswordChanged,
    /// The slot size of the file was changed, which rewrites the whole file.
    VaultResized,
    /// A set of recovery pieces was handed out.
    RecoveryCreated,
    /// The cost of one master-password guess was changed.
    WorkFactorChanged,
}

/// One link in the vault's change history.
///
/// Each record carries the hash of the one before it, so the log cannot be
/// edited after the fact: removing or altering a line breaks every hash that
/// follows, and the break is visible without needing a copy of the original.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub at: String,
    pub action: AuditAction,
    /// The entry involved, where there is one. Never a password.
    pub target: String,
    /// Hex SHA-256 over the previous hash and this record's own fields.
    pub hash: String,
}

/// Entries kept in the log before the oldest are dropped.
///
/// Trimming breaks the chain at the front by definition, which is why
/// [`VaultData::verify_audit`] checks only from the oldest surviving record.
pub const MAX_AUDIT_RECORDS: usize = 500;

fn audit_hash(previous: &str, at: &str, action: AuditAction, target: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"deep-defense/audit/v1");
    digest.update(previous.as_bytes());
    digest.update(at.as_bytes());
    digest.update(format!("{action:?}").as_bytes());
    digest.update(target.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Why the audit log failed to verify, if it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditProblem {
    /// Record `index` does not hash to what it claims.
    BrokenAt(usize),
}

/// A random key, kept inside the vault, that the per-computer tags are made
/// with. Its own type so that printing the vault data cannot print it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MachineKey(pub String);

impl std::fmt::Debug for MachineKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() { "MachineKey(unset)" } else { "MachineKey([redacted])" })
    }
}

/// The whole decrypted payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default = "default_schema")]
    pub schema_version: u32,
    #[serde(default = "now")]
    pub created_at: String,
    #[serde(default = "now")]
    pub modified_at: String,
    /// Bumped on every save. Lets us notice a rollback: an attacker swapping
    /// in an older, still validly signed vault to restore a password the user
    /// has already rotated away from.
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub entries: Vec<Entry>,
    /// Hash-chained history of what happened to this vault.
    #[serde(default)]
    pub audit: Vec<AuditRecord>,
    /// When a set of recovery pieces was last handed out, if any still work.
    ///
    /// Cleared when the master password changes, because pieces of the old
    /// password rebuild a string that no longer opens anything. So `Some`
    /// means "pieces that currently work exist", which is the only claim
    /// worth storing.
    #[serde(default)]
    pub recovery_made_at: Option<String>,

    /// Keys the tags in `anchored_on`. Made once, and kept here rather than
    /// derived from the master key, so a change of password does not make
    /// every computer look new.
    #[serde(default)]
    pub machine_key: MachineKey,
    /// Which computers have held a rollback record for this vault, as keyed
    /// tags of their identity rather than the identity itself. This is what
    /// lets a missing record be told apart from a first visit.
    #[serde(default)]
    pub anchored_on: Vec<String>,
}

fn default_schema() -> u32 {
    SCHEMA_VERSION
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            created_at: now(),
            modified_at: now(),
            revision: 0,
            entries: Vec::new(),
            audit: Vec::new(),
            recovery_made_at: None,
            machine_key: MachineKey::default(),
            anchored_on: Vec::new(),
        }
    }
}

impl VaultData {
    /// Append to the change log, chaining it to whatever came before.
    ///
    /// `target` is an entry name, never a password: the log is meant to be
    /// readable by whoever opens the vault, and it survives the entry it
    /// describes being deleted.
    pub fn record(&mut self, action: AuditAction, target: impl Into<String>) {
        let target = target.into();
        let at = now();
        let previous = self
            .audit
            .last()
            .map(|r| r.hash.as_str())
            .unwrap_or("genesis");
        let hash = audit_hash(previous, &at, action, &target);
        self.audit.push(AuditRecord {
            at,
            action,
            target,
            hash,
        });
        // Trimming the front breaks the chain there by construction; see
        // `verify_audit`, which starts from the oldest surviving record.
        if self.audit.len() > MAX_AUDIT_RECORDS {
            let excess = self.audit.len() - MAX_AUDIT_RECORDS;
            self.audit.drain(..excess);
        }
    }

    /// Recompute the chain and report the first record that does not fit.
    ///
    /// Starts from the oldest record present rather than from "genesis", so a
    /// log that has simply been trimmed still verifies.
    pub fn verify_audit(&self) -> std::result::Result<(), AuditProblem> {
        let mut previous: Option<&str> = None;
        for (index, record) in self.audit.iter().enumerate() {
            let expected = match previous {
                // The first surviving record may be a continuation, so accept
                // its stated hash and chain forward from there.
                None => record.hash.clone(),
                Some(prev) => audit_hash(prev, &record.at, record.action, &record.target),
            };
            if expected != record.hash {
                return Err(AuditProblem::BrokenAt(index));
            }
            previous = Some(&record.hash);
        }
        Ok(())
    }

    pub fn bump(&mut self) {
        self.revision = self.revision.saturating_add(1);
        self.modified_at = now();
    }

    pub fn find(&self, name: &str) -> Option<&Entry> {
        let key = name.trim().to_lowercase();
        self.entries.iter().find(|e| e.key() == key)
    }

    pub fn find_mut(&mut self, name: &str) -> Option<&mut Entry> {
        let key = name.trim().to_lowercase();
        self.entries.iter_mut().find(|e| e.key() == key)
    }

    pub fn position(&self, name: &str) -> Option<usize> {
        let key = name.trim().to_lowercase();
        self.entries.iter().position(|e| e.key() == key)
    }

    /// Entries in a stable, case-insensitive order, as indices into `entries`.
    pub fn sorted_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..self.entries.len()).collect();
        indices.sort_by_key(|&i| self.entries[i].key());
        indices
    }

    pub fn all_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .entries
            .iter()
            .flat_map(|e| e.tags.iter().cloned())
            .collect();
        tags.sort();
        tags.dedup();
        tags
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    fn logged(actions: &[(AuditAction, &str)]) -> VaultData {
        let mut data = VaultData::default();
        for (action, target) in actions {
            data.record(*action, *target);
        }
        data
    }

    #[test]
    fn an_untouched_log_verifies() {
        let data = logged(&[
            (AuditAction::Created, ""),
            (AuditAction::EntryAdded, "GitHub"),
            (AuditAction::PasswordChanged, "GitHub"),
        ]);
        assert_eq!(data.verify_audit(), Ok(()));
        assert_eq!(data.audit.len(), 3);
    }

    /// The point of the chain: a line cannot be quietly removed.
    #[test]
    fn deleting_a_line_from_the_middle_is_detected() {
        let mut data = logged(&[
            (AuditAction::Created, ""),
            (AuditAction::EntryAdded, "Bank"),
            (AuditAction::EntryDeleted, "Bank"),
            (AuditAction::EntryAdded, "Mail"),
        ]);
        data.audit.remove(2);
        assert_eq!(data.verify_audit(), Err(AuditProblem::BrokenAt(2)));
    }

    #[test]
    fn rewriting_a_line_is_detected() {
        let mut data = logged(&[
            (AuditAction::Created, ""),
            (AuditAction::EntryDeleted, "Bank"),
        ]);
        data.audit[1].target = "Something harmless".into();
        assert_eq!(data.verify_audit(), Err(AuditProblem::BrokenAt(1)));
    }

    #[test]
    fn changing_a_timestamp_is_detected() {
        let mut data = logged(&[
            (AuditAction::Created, ""),
            (AuditAction::EntryAdded, "Mail"),
        ]);
        data.audit[1].at = "2000-01-01T00:00:00Z".into();
        assert_eq!(data.verify_audit(), Err(AuditProblem::BrokenAt(1)));
    }

    #[test]
    fn appending_a_forged_line_is_detected() {
        let mut data = logged(&[(AuditAction::Created, "")]);
        let forged = AuditRecord {
            at: "2030-01-01T00:00:00Z".into(),
            action: AuditAction::EntryAdded,
            target: "Never happened".into(),
            hash: "0".repeat(64),
        };
        data.audit.push(forged);
        assert_eq!(data.verify_audit(), Err(AuditProblem::BrokenAt(1)));
    }

    #[test]
    fn a_trimmed_log_still_verifies() {
        // Trimming the front breaks the chain there by construction, so
        // verification starts from the oldest surviving record.
        let mut data = VaultData::default();
        for i in 0..(MAX_AUDIT_RECORDS + 50) {
            data.record(AuditAction::EntryAdded, format!("entry {i}"));
        }
        assert_eq!(data.audit.len(), MAX_AUDIT_RECORDS);
        assert_eq!(data.verify_audit(), Ok(()));
    }

    #[test]
    fn the_log_never_contains_a_password() {
        // Everything recorded is a name or an action; nothing else is passed
        // to `record`, and this is the test that keeps it that way.
        let mut data = VaultData::default();
        let mut entry = Entry::new("Bank");
        entry.set_password("unmistakable-marker".into());
        data.record(AuditAction::EntryAdded, &entry.name);
        data.record(AuditAction::PasswordChanged, &entry.name);

        let serialised = serde_json::to_string(&data.audit).unwrap();
        assert!(!serialised.contains("unmistakable-marker"));
    }

    #[test]
    fn setting_the_same_password_reports_no_change() {
        // The edit screen calls this on every save, changed or not. Reporting
        // a change here would put an untrue entry in the audit log.
        let mut entry = Entry::new("Bank");
        assert!(entry.set_password("first".into()), "a first value is a change");
        assert!(!entry.set_password("first".into()), "the same value is not");
        assert!(entry.set_password("second".into()));
        assert_eq!(entry.history.len(), 1);
    }

    #[test]
    fn search_is_case_insensitive_in_both_alphabets() {
        let mut entry = Entry::new("Сбербанк");
        entry.username = "Ivan.Petrov@Example.COM".into();
        for needle in ["сбербанк", "СБЕРБАНК", "СберБанк", "банк"] {
            assert!(entry.matches(needle), "{needle} should have matched");
        }
        for needle in ["ivan.petrov", "IVAN.PETROV", "example.com"] {
            assert!(entry.matches(needle), "{needle} should have matched");
        }
        assert!(!entry.matches("tinkoff"));
    }

    #[test]
    fn folded_search_agrees_with_lower_casing_the_whole_haystack() {
        // The property the old implementation had, kept as the definition of
        // correct while the implementation underneath it changed.
        let samples = [
            ("Bank", "ban"),
            ("Bank", "BAN"),
            ("Bank", "nk"),
            ("Bank", "bank!"),
            ("Bank", ""),
            ("ÄÖÜ", "äöü"),
            ("Straße", "strasse"),
            ("ПАРОЛЬ", "пароль"),
            ("a", "aa"),
            ("", "a"),
        ];
        for (haystack, needle) in samples {
            let expected = haystack.to_lowercase().contains(&needle.to_lowercase());
            let actual = contains_folded(haystack, &needle.to_lowercase());
            assert_eq!(
                actual, expected,
                "searching {haystack:?} for {needle:?}"
            );
        }
    }

    #[test]
    fn search_still_never_looks_at_the_password() {
        let mut entry = Entry::new("Bank");
        entry.set_password("unmistakable".into());
        assert!(!entry.matches("unmistakable"));
    }

    #[test]
    fn search_finds_a_needle_at_the_very_end_of_a_field() {
        // An off-by-one in the scan shows up here first.
        let mut entry = Entry::new("Bank");
        entry.url = "https://example.com/login".into();
        assert!(entry.matches("login"));
        assert!(entry.matches("n"));
        assert!(!entry.matches("logins"));
    }

    #[test]
    fn a_plain_custom_field_is_searchable() {
        let mut entry = Entry::new("Bank");
        entry.fields.push(CustomField {
            name: "Account".into(),
            value: "40817810".into(),
            secret: false,
        });
        assert!(entry.matches("40817810"));
        assert!(entry.matches("account"));
    }

    #[test]
    fn a_secret_custom_field_is_not_searchable_by_value() {
        // Same reasoning as the password: matching on it would let someone
        // watching confirm a guess without it ever appearing on screen.
        let mut entry = Entry::new("Bank");
        entry.fields.push(CustomField {
            name: "PIN".into(),
            value: "4821".into(),
            secret: true,
        });
        assert!(entry.matches("pin"), "the name is still searchable");
        assert!(!entry.matches("4821"), "the value must not be");
    }

    #[test]
    fn a_secret_field_debug_does_not_print_its_value() {
        let field = CustomField {
            name: "PIN".into(),
            value: "unmistakable".into(),
            secret: true,
        };
        assert!(!format!("{field:?}").contains("unmistakable"));
    }

    #[test]
    fn an_attachment_round_trips_and_reports_its_size() {
        let bytes = b"a file's worth of bytes";
        let attachment = Attachment::new("notes.txt", bytes);
        assert_eq!(attachment.size, bytes.len());
        assert_eq!(attachment.decode().unwrap().as_slice(), bytes);
    }

    #[test]
    fn an_attachment_debug_does_not_print_the_file() {
        let attachment = Attachment::new("secret.key", b"unmistakable-marker");
        let rendered = format!("{attachment:?}");
        assert!(rendered.contains("secret.key"));
        assert!(!rendered.contains("unmistakable-marker"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn an_empty_attachment_is_handled() {
        let attachment = Attachment::new("empty", b"");
        assert_eq!(attachment.size, 0);
        assert_eq!(attachment.decode().unwrap().len(), 0);
    }
}
