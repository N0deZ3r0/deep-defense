//! Getting data in and out.
//!
//! A vault you cannot leave is a trap, however good its encryption. Export
//! exists so the answer to "what if I stop trusting this program" is "take
//! your passwords and go", not "retype two hundred entries".
//!
//! Both formats write **plaintext**. That is the whole point of an export, and
//! it is why the UI asks twice and why the written file is the user's problem
//! to delete. Nothing here encrypts anything; [`crate::crypto`] does that.

use std::path::Path;

use zeroize::Zeroizing;

use crate::errors::{Error, Result};
use crate::model::{Entry, VaultData};

/// What an import did, for reporting back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub added: usize,
    /// Skipped because an entry of that name already existed.
    pub duplicates: usize,
    /// Skipped because the row had no usable name.
    pub malformed: usize,
}

// ------------------------------------------------------------------- export

/// The vault as CSV, with the column names other managers expect.
///
/// Attachments and password history are dropped: CSV has nowhere to put them.
/// Use the JSON export to keep everything.
pub fn to_csv(data: &VaultData) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    out.push_str("name,username,password,url,notes,totp,tags\n");
    for entry in &data.entries {
        let row = [
            entry.name.as_str(),
            entry.username.as_str(),
            entry.password.as_str(),
            entry.url.as_str(),
            entry.notes.as_str(),
            entry.totp_secret.as_str(),
            &entry.tags.join(" "),
        ]
        .iter()
        .map(|field| escape_csv(field))
        .collect::<Vec<_>>()
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// The vault as JSON: everything, including attachments and history.
pub fn to_json(data: &VaultData) -> Result<Zeroizing<String>> {
    // Which computers this vault has been opened on is a fact about this
    // installation, not about the passwords, and has no business in a file
    // made to be carried somewhere else.
    let mut exported = data.clone();
    exported.machine_key = crate::model::MachineKey::default();
    exported.anchored_on.clear();
    serde_json::to_string_pretty(&exported)
        .map(Zeroizing::new)
        .map_err(|e| Error::vault(format!("cannot serialise the vault: {e}")))
}

fn escape_csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

// ------------------------------------------------------------------- import

/// Merge CSV rows into `data`, skipping names that already exist.
///
/// Column order is taken from the header rather than assumed: every manager
/// exports the same fields under slightly different names and in a different
/// order, and guessing by position corrupts data silently.
pub fn from_csv(data: &mut VaultData, text: &str) -> Result<ImportReport> {
    let rows = parse_csv(text);
    let Some(header) = rows.first() else {
        return Err(Error::vault("the file is empty"));
    };

    let find = |names: &[&str]| -> Option<usize> {
        header.iter().position(|column| {
            let column = column.trim().trim_start_matches('\u{feff}').to_lowercase();
            names.contains(&column.as_str())
        })
    };
    // The spellings used by KeePass, Bitwarden, 1Password, Chrome and Firefox.
    let name_at = find(&["name", "title", "account", "item name"]);
    let user_at = find(&["username", "login_username", "user name", "login", "email"]);
    let pass_at = find(&["password", "login_password", "pass"]);
    let url_at = find(&["url", "login_uri", "website", "web site", "uri"]);
    let notes_at = find(&["notes", "note", "comments"]);
    let totp_at = find(&["totp", "login_totp", "otpauth", "otp"]);
    let tags_at = find(&["tags", "group", "folder", "category"]);

    let Some(name_at) = name_at else {
        return Err(Error::vault(
            "no name column found. The first line must be a header with a \
             \"name\" or \"title\" column.",
        ));
    };

    let mut report = ImportReport::default();
    for row in rows.iter().skip(1) {
        let cell = |index: Option<usize>| -> String {
            index
                .and_then(|i| row.get(i))
                .map(|s| s.trim().to_owned())
                .unwrap_or_default()
        };
        let name = cell(Some(name_at));
        if name.is_empty() {
            report.malformed += 1;
            continue;
        }
        if data.find(&name).is_some() {
            report.duplicates += 1;
            continue;
        }

        let mut entry = Entry::new(&name);
        entry.username = cell(user_at);
        entry.url = cell(url_at);
        entry.notes = cell(notes_at);
        entry.totp_secret = cell(totp_at);
        entry.tags = cell(tags_at)
            .split([' ', ';', ','])
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        entry.set_password(cell(pass_at));
        data.entries.push(entry);
        report.added += 1;
    }
    Ok(report)
}

/// Merge a JSON export back in, skipping names that already exist.
pub fn from_json(data: &mut VaultData, text: &str) -> Result<ImportReport> {
    // Every field of `VaultData` has a default, so any JSON object at all
    // deserialises into an empty vault. Without this check, picking the wrong
    // file would report "imported 0 entries" instead of saying it was the
    // wrong file.
    let shape: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| Error::vault(format!("this is not a Deep Defense export ({e})")))?;
    if !shape.get("entries").is_some_and(|e| e.is_array()) {
        return Err(Error::vault(
            "this is not a Deep Defense export: it has no \"entries\" list.",
        ));
    }

    let incoming: VaultData = serde_json::from_str(text)
        .map_err(|e| Error::vault(format!("this is not a Deep Defense export ({e})")))?;

    let mut report = ImportReport::default();
    for entry in incoming.entries {
        if entry.name.trim().is_empty() {
            report.malformed += 1;
            continue;
        }
        if data.find(&entry.name).is_some() {
            report.duplicates += 1;
            continue;
        }
        data.entries.push(entry);
        report.added += 1;
    }
    Ok(report)
}

/// Read a file as UTF-8, tolerating a BOM and Windows-1251.
///
/// Exports from Russian-locale tools are routinely written in the system
/// codepage, and refusing them with "invalid UTF-8" would be unhelpful when
/// the mapping is unambiguous.
pub fn read_text_file(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = std::fs::read(path).map_err(|e| Error::io(path.to_path_buf(), e))?;
    match String::from_utf8(bytes.clone()) {
        Ok(text) => Ok(Zeroizing::new(
            text.trim_start_matches('\u{feff}').to_owned(),
        )),
        Err(_) => Ok(Zeroizing::new(decode_windows_1251(&bytes))),
    }
}

fn decode_windows_1251(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x00..=0x7F => b as char,
            0x80..=0xBF => WIN1251_HIGH[(b - 0x80) as usize],
            // 0xC0..=0xFF map onto А..я contiguously.
            _ => char::from_u32(0x0410 + (b - 0xC0) as u32).unwrap_or('\u{fffd}'),
        })
        .collect()
}

/// The punctuation and stray letters in the 0x80..0xBF range of CP1251.
const WIN1251_HIGH: [char; 64] = [
    'Ђ', 'Ѓ', '‚', 'ѓ', '„', '…', '†', '‡', '€', '‰', 'Љ', '‹', 'Њ', 'Ќ', 'Ћ', 'Џ',
    'ђ', '‘', '’', '“', '”', '•', '–', '—', '\u{fffd}', '™', 'љ', '›', 'њ', 'ќ', 'ћ', 'џ',
    '\u{a0}', 'Ў', 'ў', 'Ј', '¤', 'Ґ', '¦', '§', 'Ё', '©', 'Є', '«', '¬', '\u{ad}', '®', 'Ї',
    '°', '±', 'І', 'і', 'ґ', 'µ', '¶', '·', 'ё', '№', 'є', '»', 'ј', 'Ѕ', 'ѕ', 'ї',
];

/// A minimal RFC 4180 reader: quoted fields, doubled quotes, CRLF or LF.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            }
            (true, _) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, _) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    // A trailing newline leaves one empty row; it is not a record.
    rows.retain(|r| !(r.len() == 1 && r[0].is_empty()));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with(entries: &[(&str, &str, &str)]) -> VaultData {
        let mut data = VaultData::default();
        for (name, user, password) in entries {
            let mut entry = Entry::new(*name);
            entry.username = (*user).into();
            entry.set_password((*password).into());
            data.entries.push(entry);
        }
        data
    }

    #[test]
    fn csv_round_trips_through_an_import() {
        let original = vault_with(&[("GitHub", "me", "s3cret"), ("Bank", "acct", "other")]);
        let csv = to_csv(&original);

        let mut fresh = VaultData::default();
        let report = from_csv(&mut fresh, &csv).unwrap();
        assert_eq!(report.added, 2);
        assert_eq!(fresh.find("github").unwrap().password, "s3cret");
        assert_eq!(fresh.find("bank").unwrap().username, "acct");
    }

    #[test]
    fn csv_escapes_commas_quotes_and_newlines() {
        let mut data = VaultData::default();
        let mut entry = Entry::new("Tricky, \"quoted\"");
        entry.notes = "line one\nline two".into();
        entry.set_password("pa,ss\"word".into());
        data.entries.push(entry);

        let mut back = VaultData::default();
        from_csv(&mut back, &to_csv(&data)).unwrap();
        let recovered = back.find("tricky, \"quoted\"").expect("name survives");
        assert_eq!(recovered.password, "pa,ss\"word");
        assert_eq!(recovered.notes, "line one\nline two");
    }

    #[test]
    fn columns_are_found_by_name_not_position() {
        // Bitwarden's order, which is nothing like ours.
        let csv = "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
                   Work,,login,GitHub,a note,,https://github.com,me@example.com,s3cret,JBSWY3DPEHPK3PXP\n";
        let mut data = VaultData::default();
        assert_eq!(from_csv(&mut data, csv).unwrap().added, 1);

        let entry = data.find("github").unwrap();
        assert_eq!(entry.username, "me@example.com");
        assert_eq!(entry.password, "s3cret");
        assert_eq!(entry.url, "https://github.com");
        assert_eq!(entry.totp_secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.tags, vec!["Work"]);
    }

    #[test]
    fn a_title_column_works_as_well_as_a_name_one() {
        // KeePass says "Title"; Chrome says "name".
        let csv = "Title,Username,Password\nRouter,admin,admin\n";
        let mut data = VaultData::default();
        assert_eq!(from_csv(&mut data, csv).unwrap().added, 1);
        assert!(data.find("router").is_some());
    }

    #[test]
    fn importing_never_overwrites_an_existing_entry() {
        // The one outcome an import must never produce: silently replacing a
        // password the user already has.
        let mut data = vault_with(&[("GitHub", "me", "the real one")]);
        let csv = "name,username,password\nGitHub,someone,imported\n";
        let report = from_csv(&mut data, csv).unwrap();

        assert_eq!(report.added, 0);
        assert_eq!(report.duplicates, 1);
        assert_eq!(data.find("github").unwrap().password, "the real one");
    }

    #[test]
    fn rows_without_a_name_are_counted_not_guessed_at() {
        let csv = "name,password\n,orphan\nReal,value\n";
        let mut data = VaultData::default();
        let report = from_csv(&mut data, csv).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(report.malformed, 1);
    }

    #[test]
    fn a_file_without_a_name_column_is_refused_with_advice() {
        let csv = "col1,col2\nfoo,bar\n";
        let mut data = VaultData::default();
        let err = from_csv(&mut data, csv).unwrap_err();
        assert!(err.to_string().contains("header"));
    }

    #[test]
    fn json_keeps_what_csv_cannot() {
        let mut data = vault_with(&[("Server", "root", "current")]);
        let entry = data.find_mut("server").unwrap();
        entry.set_password("rotated".into()); // creates history
        entry
            .attachments
            .push(crate::model::Attachment::new("key.pem", b"PRIVATE KEY"));

        let json = to_json(&data).unwrap();
        let mut back = VaultData::default();
        assert_eq!(from_json(&mut back, &json).unwrap().added, 1);

        let recovered = back.find("server").unwrap();
        assert_eq!(recovered.password, "rotated");
        assert_eq!(recovered.history.len(), 1);
        assert_eq!(recovered.attachments.len(), 1);
        assert_eq!(
            recovered.attachments[0].decode().unwrap().as_slice(),
            b"PRIVATE KEY"
        );
    }

    #[test]
    fn a_json_file_that_is_not_ours_is_refused() {
        let mut data = VaultData::default();
        assert!(from_json(&mut data, "{\"something\": \"else\"}").is_err());
        assert!(from_json(&mut data, "not json at all").is_err());
    }

    #[test]
    fn crlf_and_a_trailing_newline_are_handled() {
        let csv = "name,password\r\nOne,a\r\nTwo,b\r\n";
        let mut data = VaultData::default();
        assert_eq!(from_csv(&mut data, csv).unwrap().added, 2);
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_first_column() {
        // Excel writes one, and it would otherwise make "name" unrecognisable.
        let csv = "\u{feff}name,password\nOne,a\n";
        let mut data = VaultData::default();
        assert_eq!(from_csv(&mut data, csv).unwrap().added, 1);
    }

    #[test]
    fn windows_1251_text_is_decoded_rather_than_rejected() {
        // "Почта" in CP1251, as a Russian-locale export would write it.
        let bytes = [0xCF, 0xEE, 0xF7, 0xF2, 0xE0];
        assert_eq!(decode_windows_1251(&bytes), "Почта");
    }

    #[test]
    fn an_empty_file_is_refused() {
        let mut data = VaultData::default();
        assert!(from_csv(&mut data, "").is_err());
    }

    // ------------------------------------------------- the whole way round

    fn a_full_entry() -> crate::model::Entry {
        let mut entry = crate::model::Entry::new("Bank");
        entry.username = "me@example.com".into();
        entry.url = "https://bank.example".into();
        entry.notes = "line one\nline two, with a comma".into();
        entry.tags = vec!["money".into(), "важное".into()];
        entry.totp_secret = "JBSWY3DPEHPK3PXP".into();
        entry.fields.push(crate::model::CustomField {
            name: "PIN".into(),
            value: "4821".into(),
            secret: true,
        });
        entry.attachments.push(crate::model::Attachment::new(
            "scan.txt",
            b"the contents of a document",
        ));
        // Two set_password calls, so there is a history to lose or keep.
        entry.set_password("the old one".into());
        entry.set_password("the current one".into());
        entry
    }

    #[test]
    fn json_carries_everything_back() {
        let mut original = VaultData::default();
        original.entries.push(a_full_entry());

        let text = to_json(&original).unwrap();
        let mut restored = VaultData::default();
        let report = from_json(&mut restored, &text).unwrap();
        assert_eq!(report.added, 1);

        let entry = &restored.entries[0];
        assert_eq!(entry.name, "Bank");
        assert_eq!(entry.username, "me@example.com");
        assert_eq!(entry.url, "https://bank.example");
        assert_eq!(entry.notes, "line one\nline two, with a comma");
        assert_eq!(entry.tags, vec!["money".to_string(), "важное".to_string()]);
        assert_eq!(entry.password, "the current one");
        assert_eq!(entry.totp_secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(entry.fields.len(), 1, "custom fields survive JSON");
        assert_eq!(entry.fields[0].value, "4821");
        assert!(entry.fields[0].secret);
        assert_eq!(entry.attachments.len(), 1, "attachments survive JSON");
        assert_eq!(entry.history.len(), 1, "the password history survives");
        assert_eq!(entry.history[0].password, "the old one");
    }

    #[test]
    fn csv_carries_what_a_csv_can_and_the_rest_is_lost_on_purpose() {
        // Said out loud in the interface, and asserted here so it stays true:
        // a spreadsheet has no column for a file or a password's history.
        let mut original = VaultData::default();
        original.entries.push(a_full_entry());

        let text = to_csv(&original);
        let mut restored = VaultData::default();
        from_csv(&mut restored, &text).unwrap();

        let entry = &restored.entries[0];
        assert_eq!(entry.name, "Bank");
        assert_eq!(entry.username, "me@example.com");
        assert_eq!(entry.password, "the current one");
        assert_eq!(entry.notes, "line one\nline two, with a comma",
                   "a newline and a comma inside a field must survive quoting");
        assert!(entry.attachments.is_empty(), "documented loss");
        assert!(entry.history.is_empty(), "documented loss");
    }

    #[test]
    fn importing_the_same_export_twice_adds_nothing_the_second_time() {
        // The one outcome an import must never produce: a vault with every
        // entry in it twice.
        let mut original = VaultData::default();
        original.entries.push(a_full_entry());
        let text = to_json(&original).unwrap();

        let mut restored = VaultData::default();
        assert_eq!(from_json(&mut restored, &text).unwrap().added, 1);
        let second = from_json(&mut restored, &text).unwrap();
        assert_eq!(second.added, 0);
        assert_eq!(second.duplicates, 1);
        assert_eq!(restored.entries.len(), 1);
    }

    #[test]
    fn an_export_of_nothing_still_reads_back_as_nothing() {
        let empty = VaultData::default();
        let mut restored = VaultData::default();
        from_json(&mut restored, &to_json(&empty).unwrap()).unwrap();
        assert!(restored.entries.is_empty());

        let mut from_table = VaultData::default();
        from_csv(&mut from_table, &to_csv(&empty)).unwrap();
        assert!(from_table.entries.is_empty());
    }
}
