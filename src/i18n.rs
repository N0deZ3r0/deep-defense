//! Interface text in English and Russian.
//!
//! Strings live in one `struct` per screen rather than in a runtime hash map,
//! so the compiler refuses to build if a translation is missing a field. That
//! is the whole reason for the verbosity: a missing key becomes a build error
//! instead of a blank label someone notices in production.
//!
//! Text with values in it is stored as a template containing `{}`, filled by
//! [`fill1`] / [`fill2`]. Templates let a translation move the value where its
//! own grammar needs it, which `format!("{} entries")` would not allow.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Lang {
    #[default]
    En,
    Ru,
}

impl Lang {
    pub fn strings(self) -> &'static Strings {
        match self {
            Lang::En => &EN,
            Lang::Ru => &RU,
        }
    }

    /// The name of the language *in that language* — a reader who cannot read
    /// the current one still needs to recognise their own.
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Ru => "Русский",
        }
    }

    pub const ALL: [Lang; 2] = [Lang::En, Lang::Ru];

    /// Guess from the operating system's UI language, used on first run only.
    pub fn from_system() -> Self {
        #[cfg(windows)]
        {
            // The low 10 bits of a LANGID are the primary language; 0x19 is
            // Russian. Anything we do not recognise falls back to English.
            let langid = unsafe {
                windows_sys::Win32::Globalization::GetUserDefaultUILanguage()
            };
            if langid & 0x3FF == 0x19 {
                return Lang::Ru;
            }
        }
        #[cfg(not(windows))]
        {
            for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
                if let Ok(value) = std::env::var(key) {
                    if value.to_lowercase().starts_with("ru") {
                        return Lang::Ru;
                    }
                }
            }
        }
        Lang::En
    }
}

/// Substitute one value into a template.
pub fn fill1(template: &str, a: impl std::fmt::Display) -> String {
    template.replacen("{}", &a.to_string(), 1)
}

/// Substitute two values, left to right.
pub fn fill2(template: &str, a: impl std::fmt::Display, b: impl std::fmt::Display) -> String {
    fill1(&fill1(template, a), b)
}

pub struct Strings {
    pub common: Common,
    pub shell: Shell,
    pub setup: Setup,
    pub unlock: Unlock,
    pub entry: EntryText,
    pub generator: GeneratorText,
    pub settings: SettingsText,
    pub audit: AuditText,
    pub strength: StrengthText,
    pub attachments: AttachmentsText,
    pub hidden: HiddenText,
    pub history: HistoryText,
    pub errors: ErrorsText,
    pub portable: PortableText,
    pub mirror: MirrorText,
    pub resize: ResizeText,
    pub anchor: AnchorText,
    pub recovery: RecoveryText,
    pub breach: BreachText,
}

pub struct MirrorText {
    pub section: &'static str,
    pub hint: &'static str,
    pub choose: &'static str,
    pub clear: &'static str,
    pub none: &'static str,
    pub dialog_title: &'static str,
    pub failed_title: &'static str,
    /// "{}" is the reason the copy failed.
    pub failed_body: &'static str,
    /// "{}" is a directory.
    pub working: &'static str,
}

pub struct ResizeText {
    pub section: &'static str,
    pub hint: &'static str,
    /// "{}" is the slot size, "{}" the room left.
    pub current: &'static str,
    pub slot_size: &'static str,
    pub work_factor: &'static str,
    /// "{}" is mebibytes, "{}" is passes.
    pub cost: &'static str,
    pub work_factor_hint: &'static str,
    pub own_password: &'static str,
    pub own_password_hint: &'static str,
    pub apply: &'static str,
    pub carry_hidden: &'static str,
    pub carry_hint: &'static str,
    pub carry_hint_rekey: &'static str,
    pub warning_title: &'static str,
    pub warning_body: &'static str,
    pub done_title: &'static str,
    /// "{}" is the old size, "{}" the new one.
    pub done_body: &'static str,
}

pub struct AnchorText {
    pub section: &'static str,
    pub hint: &'static str,
    pub verified: &'static str,
    pub first_seen: &'static str,
    pub first_seen_body: &'static str,
    pub unverifiable: &'static str,
    pub unverifiable_body: &'static str,
    pub export: &'static str,
    pub import: &'static str,
    /// "{}" is a path.
    pub exported: &'static str,
    pub imported_title: &'static str,
    pub imported_body: &'static str,
    pub dialog_export: &'static str,
    pub dialog_import: &'static str,
    pub filter: &'static str,
}

pub struct RecoveryText {
    pub section: &'static str,
    pub hint: &'static str,
    pub threshold: &'static str,
    pub count: &'static str,
    pub confirm_password: &'static str,
    pub create: &'static str,
    pub card_heading: &'static str,
    /// "{}" is this share's number, "{}" the total.
    pub card_share: &'static str,
    /// "{}" is the threshold.
    pub card_note: &'static str,
    pub save: &'static str,
    pub done: &'static str,
    pub warning_title: &'static str,
    pub warning_body: &'static str,
    pub stale_title: &'static str,
    pub stale_body: &'static str,
    /// "{}" is a date.
    pub made_on: &'static str,
    pub none_made: &'static str,
    pub verify_open: &'static str,
    pub verify_hint: &'static str,
    pub verify_button: &'static str,
    pub verify_ok: &'static str,
    pub verify_bad: &'static str,
    /// "{}" is a path.
    pub saved: &'static str,
    pub unlock_open: &'static str,
    pub unlock_hint: &'static str,
    pub unlock_paste: &'static str,
    pub unlock_rebuild: &'static str,
    /// "{}" is how many were recognised, "{}" how many are needed.
    pub unlock_found: &'static str,
    pub unlock_none: &'static str,
    pub unlock_done: &'static str,
}

pub struct BreachText {
    pub section: &'static str,
    pub hint: &'static str,
    /// "{}" is a count.
    pub bundled_body: &'static str,
    /// "{}" is a count.
    pub imported_body: &'static str,
    pub import: &'static str,
    pub forget: &'static str,
    pub dialog_title: &'static str,
    pub filter: &'static str,
    /// "{}" is how many were added, "{}" how many were digests.
    pub import_done: &'static str,
    pub crowded: &'static str,
    pub warning_master: &'static str,
    pub warning_entry: &'static str,
}

pub struct PortableText {
    pub section: &'static str,
    pub hint: &'static str,
    pub import: &'static str,
    pub export: &'static str,
    pub export_csv: &'static str,
    pub export_json: &'static str,
    pub export_warning_title: &'static str,
    pub export_warning_body: &'static str,
    pub export_title: &'static str,
    pub import_title: &'static str,
    pub filter_csv: &'static str,
    pub filter_json: &'static str,
    pub filter_any: &'static str,
    pub exported_title: &'static str,
    /// "{}" is a path.
    pub exported_body: &'static str,
    pub imported_title: &'static str,
    /// "{}" is a count.
    pub report_added: &'static str,
    /// "{}" is a count.
    pub report_duplicates: &'static str,
    /// "{}" is a count.
    pub report_malformed: &'static str,
    /// "{}" is a count, used as the audit log target.
    pub audit_import: &'static str,
}

pub struct ErrorsText {
    pub authentication: &'static str,
    /// Prefix for a cryptography failure; "{}" is the technical detail.
    pub crypto: &'static str,
    /// "{}" is the technical detail.
    pub format: &'static str,
    /// "{}" is the technical detail.
    pub veracrypt: &'static str,
    /// "{}" is the technical detail.
    pub config: &'static str,
    /// "{}" is an entry name.
    pub entry_not_found: &'static str,
    /// "{}" is an entry name.
    pub entry_exists: &'static str,
    /// "{}" the revision on disk, "{}" the one recorded here.
    pub rollback: &'static str,
    /// "{}" a path, "{}" the operating system's own message.
    pub io: &'static str,
}
pub struct AttachmentsText {
    pub section: &'static str,
    pub add: &'static str,
    pub save_as: &'static str,
    pub remove: &'static str,
    pub none: &'static str,
    pub hint: &'static str,
    pub pick_title: &'static str,
    pub save_title: &'static str,
    /// "{}" is a human-readable size.
    pub too_large: &'static str,
    pub read_failed: &'static str,
    pub saved: &'static str,
    pub added: &'static str,
    pub removed: &'static str,
    /// "{}" is a human-readable size.
    pub space_left: &'static str,
}

pub struct HiddenText {
    pub section: &'static str,
    pub explain: &'static str,
    pub create_button: &'static str,
    pub password: &'static str,
    pub confirm: &'static str,
    pub warning_title: &'static str,
    pub warning_body: &'static str,
    pub create_confirm: &'static str,
    pub created_title: &'static str,
    pub created_body: &'static str,
    pub same_password: &'static str,
    pub exists: &'static str,
    pub in_hidden_title: &'static str,
    pub in_hidden_body: &'static str,
    pub unavailable: &'static str,
}

pub struct HistoryText {
    pub title: &'static str,
    pub note: &'static str,
    pub empty: &'static str,
    pub intact_title: &'static str,
    /// "{}" is a number of records.
    pub intact_body: &'static str,
    pub broken_title: &'static str,
    /// "{}" is a record number.
    pub broken_body: &'static str,
    pub action_created: &'static str,
    pub action_entry_added: &'static str,
    pub action_entry_edited: &'static str,
    pub action_password_changed: &'static str,
    pub action_entry_renamed: &'static str,
    pub action_entry_deleted: &'static str,
    pub action_attachment_added: &'static str,
    pub action_attachment_removed: &'static str,
    pub action_master_changed: &'static str,
    pub action_vault_resized: &'static str,
    pub action_recovery_created: &'static str,
    pub action_work_factor: &'static str,
}


pub struct Common {
    pub save: &'static str,
    pub cancel: &'static str,
    pub delete: &'static str,
    pub close: &'static str,
    pub copy: &'static str,
    pub show: &'static str,
    pub hide: &'static str,
    pub generate: &'static str,
    pub search: &'static str,
    pub settings: &'static str,
    pub health: &'static str,
    pub history: &'static str,
    pub lock: &'static str,
    pub unlock: &'static str,
    pub dismiss: &'static str,
    pub language: &'static str,
    pub theme: &'static str,
    pub theme_light: &'static str,
    pub theme_dark: &'static str,
    pub unknown: &'static str,
    pub optional: &'static str,
    /// Abbreviation for minutes, as in "5m 04s".
    pub minutes_short: &'static str,
    /// Abbreviation for seconds.
    pub seconds_short: &'static str,
    pub browse: &'static str,
}

pub struct Shell {
    pub subtitle: &'static str,
    /// "{}" is a duration such as "4m 30s".
    pub locks_in: &'static str,
    /// "{}" is a whole number of seconds.
    pub clipboard_clears_in: &'static str,
    pub busy_unlocking: &'static str,
    pub busy_creating: &'static str,
    pub busy_note: &'static str,
    pub error_title: &'static str,
    pub locked_notice: &'static str,
    pub autolocked_title: &'static str,
    pub autolocked_body: &'static str,
    pub screen_locked_title: &'static str,
    pub screen_locked_body: &'static str,
    pub rollback_title: &'static str,
    /// "{}" on-disk revision, "{}" recorded revision.
    pub rollback_body: &'static str,
    pub rollback_accept: &'static str,
    pub saved: &'static str,
    pub shortcut_hint: &'static str,
}

pub struct Setup {
    pub heading: &'static str,
    pub subheading: &'static str,
    pub veracrypt_missing_title: &'static str,
    pub veracrypt_missing_body: &'static str,
    pub section_mode: &'static str,
    pub mode_standalone: &'static str,
    pub mode_container: &'static str,
    pub mode_hint_standalone: &'static str,
    pub mode_hint_container: &'static str,
    pub mode_container_unavailable: &'static str,
    pub section_location: &'static str,
    pub location_hint: &'static str,
    pub location_hint_standalone: &'static str,
    pub section_size: &'static str,
    /// Slider suffix, e.g. " MB".
    pub size_suffix: &'static str,
    pub size_hint: &'static str,
    pub section_master: &'static str,
    pub master_placeholder: &'static str,
    pub confirm_placeholder: &'static str,
    pub show_typing: &'static str,
    pub mismatch: &'static str,
    pub master_hint: &'static str,
    pub section_keyfile: &'static str,
    pub keyfile_enable: &'static str,
    pub keyfile_generate: &'static str,
    pub keyfile_hint: &'static str,
    pub keyfile_missing: &'static str,
    pub keyfile_need_path_title: &'static str,
    pub keyfile_need_path_body: &'static str,
    pub keyfile_written: &'static str,
    pub backup_title: &'static str,
    pub backup_body: &'static str,
    pub acknowledge: &'static str,
    pub create_button: &'static str,
    pub password_too_short: &'static str,
    pub master_too_short: &'static str,
    pub master_too_weak: &'static str,
    pub suggest_passphrase: &'static str,
    pub suggest_passphrase_hint: &'static str,
    pub suggested_title: &'static str,
    /// "{}" is a number of bits.
    pub suggested_body: &'static str,
    pub pick_vault_title: &'static str,
    pub pick_container_title: &'static str,
    pub pick_keyfile_title: &'static str,
    pub filter_vault: &'static str,
    pub filter_container: &'static str,
    pub filter_keyfile: &'static str,
    pub existing_title: &'static str,
    pub existing_body: &'static str,
    pub open_existing: &'static str,
    pub created_success: &'static str,
    pub created_success_standalone: &'static str,
    pub backup_body_standalone: &'static str,
}

pub struct Unlock {
    pub subheading: &'static str,
    pub master_placeholder: &'static str,
    /// "{}" is how many keyfiles.
    pub keyfiles_used: &'static str,
    /// "{}" is a path.
    pub keyfile_missing: &'static str,
    /// "{}" is a path.
    pub container_label: &'static str,
    /// "{}" is a path.
    pub vault_label: &'static str,
    pub different_container: &'static str,
    pub different_container_hint: &'static str,
    pub veracrypt_path_label: &'static str,
    pub veracrypt_missing_title: &'static str,
    pub veracrypt_missing_body: &'static str,
    pub pick_container_notice: &'static str,
}

pub struct EntryText {
    pub new_title: &'static str,
    pub edit_title: &'static str,
    pub new_button: &'static str,
    pub name: &'static str,
    pub name_placeholder: &'static str,
    pub username: &'static str,
    pub username_placeholder: &'static str,
    pub url: &'static str,
    pub url_placeholder: &'static str,
    pub tags: &'static str,
    pub tags_placeholder: &'static str,
    pub notes: &'static str,
    pub password: &'static str,
    pub password_placeholder: &'static str,
    pub totp_section: &'static str,
    pub totp_placeholder: &'static str,
    pub totp_hint: &'static str,
    pub totp_copy: &'static str,
    /// "{}" is a count.
    pub history_title: &'static str,
    pub history_hint: &'static str,
    pub no_selection: &'static str,
    pub needs_name: &'static str,
    /// "{}" is a count.
    pub entries_count: &'static str,
    /// "{}" matches, "{}" total.
    pub matches_count: &'static str,
    pub empty_list: &'static str,
    pub no_matches: &'static str,
    /// "{}" is the entry name.
    pub delete_title: &'static str,
    pub delete_body: &'static str,
    pub deleted: &'static str,
    pub copied_username: &'static str,
    /// "{}" is a number of seconds.
    pub copied_password: &'static str,
    pub autotype: &'static str,
    pub autotype_hint: &'static str,
    /// "{}" is a number of seconds.
    pub autotype_waiting: &'static str,
    /// "{}" is a window title.
    pub autotype_done: &'static str,
    pub copied_code: &'static str,
    pub copied_old: &'static str,
    pub marker_weak: &'static str,
    pub marker_old: &'static str,
    pub marker_totp: &'static str,
    pub filter_all: &'static str,
    pub fields_section: &'static str,
    pub fields_none: &'static str,
    pub field_name: &'static str,
    pub field_value: &'static str,
    pub field_secret: &'static str,
    pub field_add: &'static str,
}

pub struct GeneratorText {
    pub title: &'static str,
    /// "{}" is a number of bits.
    pub entropy: &'static str,
    pub length: &'static str,
    pub lowercase: &'static str,
    pub uppercase: &'static str,
    pub digits: &'static str,
    pub symbols: &'static str,
    pub avoid_ambiguous: &'static str,
    pub require_each: &'static str,
    pub another: &'static str,
    pub use_this: &'static str,
}

pub struct SettingsText {
    pub title: &'static str,
    pub section_appearance: &'static str,
    pub section_locking: &'static str,
    pub autolock: &'static str,
    pub clipboard: &'static str,
    pub warn_age: &'static str,
    pub locking_hint: &'static str,
    pub lock_on_screen_lock: &'static str,
    pub mask_passwords: &'static str,
    pub calibrate: &'static str,
    pub calibrate_hint: &'static str,
    pub section_kdf: &'static str,
    pub kdf_memory: &'static str,
    pub kdf_passes: &'static str,
    pub measure: &'static str,
    /// "{}" is a duration in seconds.
    pub measured: &'static str,
    pub kdf_hint: &'static str,
    pub section_master: &'static str,
    pub change_button: &'static str,
    pub change_hint: &'static str,
    pub new_password: &'static str,
    pub confirm_password: &'static str,
    pub change_warning_title: &'static str,
    pub change_warning_body: &'static str,
    pub change_confirm: &'static str,
    pub changed: &'static str,
    pub section_veracrypt: &'static str,
    pub veracrypt_binary: &'static str,
    pub veracrypt_format_binary: &'static str,
    pub veracrypt_found: &'static str,
    pub veracrypt_not_found: &'static str,
    pub section_vault: &'static str,
    pub vault_entries: &'static str,
    pub vault_revision: &'static str,
    pub vault_cipher: &'static str,
    pub vault_kdf: &'static str,
    /// "{}" MiB, "{}" passes.
    pub vault_kdf_value: &'static str,
    pub vault_mounted_at: &'static str,
    pub vault_backups: &'static str,
    pub vault_location: &'static str,
    pub vault_layers: &'static str,
    pub vault_layers_standalone: &'static str,
    pub vault_layers_container: &'static str,
}

pub struct AuditText {
    pub title: &'static str,
    pub offline_note: &'static str,
    pub all_good_title: &'static str,
    /// "{}" is a count.
    pub all_good_body: &'static str,
    /// "{}" flagged, "{}" total.
    pub needs_attention: &'static str,
    pub problem_no_password: &'static str,
    pub detail_no_password: &'static str,
    /// "{}" is a strength label.
    pub problem_weak: &'static str,
    /// "{}" is a number of bits.
    pub detail_weak: &'static str,
    pub problem_reused: &'static str,
    pub detail_reused: &'static str,
    pub problem_breached: &'static str,
    pub detail_breached: &'static str,
    pub problem_old: &'static str,
    /// "{}" is a number of days.
    pub detail_old: &'static str,
}

pub struct StrengthText {
    pub critical: &'static str,
    pub weak: &'static str,
    pub fair: &'static str,
    pub strong: &'static str,
    pub excellent: &'static str,
    /// "{}" is a strength label, "{}" a number of bits.
    pub summary: &'static str,
    /// "{}" is a number of bits.
    pub exact: &'static str,
}

pub static EN: Strings = Strings {
    common: Common {
        save: "Save",
        cancel: "Cancel",
        delete: "Delete",
        close: "Close",
        copy: "Copy",
        show: "Show",
        hide: "Hide",
        generate: "Generate",
        search: "Search",
        settings: "Settings",
        health: "Health",
        history: "History",
        lock: "Lock",
        unlock: "Unlock",
        dismiss: "Dismiss",
        language: "Language",
        theme: "Theme",
        theme_light: "Light",
        theme_dark: "Dark",
        unknown: "an unknown window",
        optional: "optional",
        minutes_short: "m",
        seconds_short: "s",
        browse: "Browse…",
    },
    shell: Shell {
        subtitle: "Argon2id · two-cipher vault",
        locks_in: "Locks in {}",
        clipboard_clears_in: "Clipboard clears in {}s",
        busy_unlocking: "Deriving keys and mounting the container…",
        busy_creating: "Creating the container. Filling it with random data takes a while…",
        busy_note: "Argon2id is deliberately slow — that is what makes guessing expensive.",
        error_title: "Something went wrong",
        locked_notice: "Locked. The container is dismounted.",
        autolocked_title: "Locked automatically",
        screen_locked_title: "Locked with the desktop",
        screen_locked_body: "The screen locked, so the vault was saved and closed straight away rather than waiting out the idle timer.",
        autolocked_body: "The vault was idle, so it was saved, closed and dismounted.",
        rollback_title: "This vault is older than the last one seen on this machine",
        rollback_body: "The file is revision {}; revision {} was recorded here earlier. \
                        Either you restored a backup, or someone replaced the vault with \
                        an older copy to bring back a password you have since changed.",
        rollback_accept: "I restored this backup — open it",
        saved: "Saved.",
        shortcut_hint: "Ctrl+N new · Ctrl+F search · Ctrl+L lock · Esc close",
    },
    setup: Setup {
        heading: "Create your vault",
        subheading: "Your passwords are encrypted twice over, by two unrelated ciphers, \
                     behind one master password that is never stored anywhere.",
        veracrypt_missing_title: "VeraCrypt was not found",
        veracrypt_missing_body: "Install VeraCrypt from veracrypt.fr, then restart this \
                                 program. If it is installed somewhere unusual, you can \
                                 set the path in Settings once a vault exists.",
        section_mode: "Protection",
        mode_standalone: "Vault file only",
        mode_container: "Also inside a VeraCrypt container",
        mode_hint_standalone: "The vault is encrypted twice over, by two unrelated ciphers: \
                               XChaCha20-Poly1305 wrapped in AES-256-GCM, each with its own \
                               key. Nothing to install, no administrator rights.",
        mode_hint_container: "Adds a third, outer layer: a VeraCrypt volume mounted as a \
                              drive while the vault is open. VeraCrypt loads a kernel driver, \
                              so Windows will ask for administrator rights.",
        mode_container_unavailable: "VeraCrypt is not installed, so this option is \
                                     unavailable. The vault file on its own is still \
                                     encrypted by two independent ciphers.",
        section_location: "Where to keep it",
        location_hint: "A single file. Back it up like any other — it is useless to anyone \
                        without your master password.",
        location_hint_standalone: "A single file, and the only file you need to back up. It \
                                   is useless to anyone without your master password.",
        section_size: "Size",
        size_suffix: " MB",
        size_hint: "64 MB holds tens of thousands of entries. The container is filled with \
                    random data on creation, so a larger size takes longer to make.",
        section_master: "Master password",
        master_placeholder: "The one password you will have to remember",
        confirm_placeholder: "Type it again",
        show_typing: "Show what I am typing",
        mismatch: "The two entries do not match.",
        master_hint: "This password is never stored anywhere. If you forget it, the data is \
                      gone — that is the point, and nobody can undo it for you. A long \
                      passphrase of four or five unrelated words beats a short cryptic one.",
        section_keyfile: "Keyfile",
        keyfile_enable: "Also require a keyfile to open the vault",
        keyfile_generate: "Generate a new keyfile here",
        keyfile_hint: "Turns the vault into something you know plus something you have. Keep \
                       it on a USB stick: storing it next to the container defeats the point. \
                       Lose it and the vault cannot be opened.",
        keyfile_missing: "That keyfile does not exist yet.",
        keyfile_need_path_title: "Give the keyfile a path first",
        keyfile_need_path_body: "Somewhere on removable media is ideal.",
        keyfile_written: "Keyfile written.",
        backup_title: "Two files, one backup",
        backup_body: "Creating the vault also writes a small .ddmeta file next to the \
                      container. It holds the container's key, sealed under your master \
                      password — useless to anyone without it, but the container cannot be \
                      opened without the file. Copy it wherever you copy the container.",
        acknowledge: "I understand that a forgotten master password means the data is \
                      unrecoverable",
        create_button: "Create the vault",
        password_too_short: "The master password must be at least 8 characters and match.",
        master_too_short: "At least 8 characters.",
        master_too_weak: "Too easy to guess. Use a longer phrase, or press Suggest — this is \
                          the one password everything else depends on.",
        suggest_passphrase: "Suggest",
        suggest_passphrase_hint: "Generate a pronounceable passphrase you can actually \
                                  remember",
        suggested_title: "Write this down before you continue",
        suggested_body: "About {} bits of entropy. It is shown in full so you can memorise \
                         or copy it — once the vault is created, nobody can recover it.",
        pick_vault_title: "Where to create the vault",
        pick_container_title: "Where to create the container",
        pick_keyfile_title: "Where to put the keyfile",
        filter_vault: "Deep Defense vault",
        filter_container: "VeraCrypt container",
        filter_keyfile: "Keyfile",
        existing_title: "There is already a container at that path",
        existing_body: "Nothing will be overwritten. Open it with its own master password.",
        open_existing: "Open this container",
        created_success: "Vault created. Back up the container and its .ddmeta file together.",
        created_success_standalone: "Vault created. Back up the .ddv file — that one file is \
                                     everything, and it is useless without your password.",
        backup_body_standalone: "Everything lives in one .ddv file. Copy it wherever you keep \
                                 backups: it is ciphertext, so a copy in the cloud or on a \
                                 stick gives away nothing without your master password. Five \
                                 previous versions are kept beside it automatically.",
    },
    unlock: Unlock {
        subheading: "The vault is locked and the container is dismounted.",
        master_placeholder: "Master password",
        keyfiles_used: "{} keyfile(s) will also be used.",
        keyfile_missing: "Missing: {}",
        container_label: "Container: {}",
        vault_label: "Vault: {}",
        different_container: "Use a different container…",
        different_container_hint: "Go back to the setup screen",
        veracrypt_path_label: "VeraCrypt.exe:",
        veracrypt_missing_title: "VeraCrypt was not found",
        veracrypt_missing_body: "The container cannot be mounted without it. Install \
                                 VeraCrypt, or set the path to it below.",
        pick_container_notice: "Point at an existing container, or create a new one.",
    },
    entry: EntryText {
        new_title: "New entry",
        edit_title: "Edit entry",
        new_button: "New",
        name: "Name",
        name_placeholder: "GitHub",
        username: "Username",
        username_placeholder: "you@example.com",
        url: "Address",
        url_placeholder: "https://github.com",
        tags: "Tags",
        tags_placeholder: "work, email, critical",
        notes: "Notes",
        password: "Password",
        password_placeholder: "Password",
        totp_section: "Two-factor secret",
        totp_placeholder: "Base32 seed, or a full otpauth:// link",
        totp_hint: "Storing the 2FA seed here is convenient, but it puts both factors behind \
                    one password. Good against phishing and reused passwords; no help if \
                    this vault itself is opened.",
        totp_copy: "Copy code",
        history_title: "Previous passwords ({})",
        history_hint: "Kept so a mistaken change can be undone. They are encrypted with \
                       everything else.",
        no_selection: "Select an entry, or press Ctrl+N to add one.",
        needs_name: "An entry needs a name before it can be saved.",
        entries_count: "{} entries",
        matches_count: "{} of {} match",
        empty_list: "No entries yet. Press Ctrl+N to add the first one.",
        no_matches: "Nothing matches that search.",
        delete_title: "Delete \"{}\"?",
        delete_body: "The entry and its password history are removed from the vault. Earlier \
                      .bak files beside the vault will still contain it.",
        deleted: "Entry deleted.",
        copied_username: "Username copied.",
        copied_password: "Password copied. The clipboard clears in {}s.",
        autotype: "Type into the active window",
        autotype_hint: "No clipboard involved: switch to the window you need while the countdown runs. The program refuses to type into its own window.",
        autotype_waiting: "typing in {}s — switch to the window",
        autotype_done: "Typed into {}",
        copied_code: "One-time code copied.",
        copied_old: "Old password copied.",
        marker_weak: "weak",
        marker_old: "old",
        marker_totp: "2FA",
        filter_all: "All",
        fields_section: "Other fields",
        fields_none: "Nothing yet. A PIN, an account number, a security answer.",
        field_name: "Name",
        field_value: "Value",
        field_secret: "Hide this value",
        field_add: "Add a field",
    },
    generator: GeneratorText {
        title: "Password generator",
        entropy: "{} bits of entropy — this figure is exact, not estimated",
        length: "Length",
        lowercase: "a–z",
        uppercase: "A–Z",
        digits: "0–9",
        symbols: "Symbols",
        avoid_ambiguous: "Avoid look-alike characters (l, 1, O, 0)",
        require_each: "Require one of each enabled class",
        another: "Generate another",
        use_this: "Use this one",
    },
    settings: SettingsText {
        title: "Settings",
        section_appearance: "Appearance",
        section_locking: "Locking",
        autolock: "Auto-lock after (seconds idle)",
        clipboard: "Clear clipboard after (seconds)",
        warn_age: "Flag passwords older than (days)",
        lock_on_screen_lock: "Lock when the desktop locks",
        mask_passwords: "Hide passwords until I reveal them",
        calibrate: "Tune to this machine",
        calibrate_hint: "Measure how heavy Argon2id can be here while still unlocking in about a second",
        locking_hint: "Auto-lock saves the vault, wipes the keys from memory and dismounts \
                       the container. It is the difference between a stolen laptop and a \
                       stolen vault.",
        section_kdf: "Key derivation cost",
        kdf_memory: "Memory per guess (MiB)",
        kdf_passes: "Passes",
        measure: "Measure on this machine",
        measured: "{}s per guess here",
        kdf_hint: "This is how long one password guess costs an attacker — and how long your \
                   own unlock takes. Around one second is a good trade. These settings apply \
                   the next time you change the master password.",
        section_master: "Master password",
        change_button: "Change the master password…",
        change_hint: "Re-keys the vault under a fresh salt. The old password stops working \
                      immediately.",
        new_password: "New master password",
        confirm_password: "Confirm",
        change_warning_title: "Both layers are re-keyed",
        change_warning_body: "The vault is re-encrypted under the new password, and the \
                              container's key is re-wrapped. This runs Argon2id twice, so \
                              the window will stop responding for a few seconds — that is \
                              the work happening, not a crash. If it is interrupted, the old \
                              password still works; you cannot be locked out halfway through.",
        change_confirm: "Change it",
        changed: "Master password changed. Both layers now use the new one.",
        section_veracrypt: "VeraCrypt",
        veracrypt_binary: "VeraCrypt program",
        veracrypt_format_binary: "VeraCrypt Format program",
        veracrypt_found: "VeraCrypt found",
        veracrypt_not_found: "VeraCrypt not found",
        section_vault: "This vault",
        vault_entries: "Entries",
        vault_revision: "Revision",
        vault_cipher: "Inner cipher",
        vault_kdf: "Key derivation",
        vault_kdf_value: "Argon2id, {} MiB, {} passes",
        vault_mounted_at: "Mounted at",
        vault_backups: "Backups kept",
        vault_location: "File",
        vault_layers: "Layers",
        vault_layers_standalone: "2 — cipher cascade",
        vault_layers_container: "3 — cascade + VeraCrypt container",
    },
    audit: AuditText {
        title: "Password health",
        offline_note: "Checked entirely offline. Nothing here is sent anywhere.",
        all_good_title: "Nothing to flag",
        all_good_body: "All {} entries look healthy.",
        needs_attention: "{} of {} entries need attention",
        problem_no_password: "no password",
        detail_no_password: "This entry has no password stored.",
        problem_weak: "{} password",
        detail_weak: "About {} bits of entropy. Generate a replacement — it takes one click.",
        problem_reused: "reused",
        detail_reused: "The same password is used by another entry. One breach then opens both.",
        problem_breached: "in a published leak",
        detail_breached: "Tried first, whatever its length suggests. Change it wherever it is used.",
        problem_old: "not changed recently",
        detail_old: "Last changed {} days ago.",
    },
    strength: StrengthText {
        critical: "critical",
        weak: "weak",
        fair: "fair",
        strong: "strong",
        excellent: "excellent",
        summary: "{} — about {} bits",
        exact: "{} bits",
    },

    attachments: AttachmentsText {
        section: "Attachments",
        add: "Add file…",
        save_as: "Save as…",
        remove: "Remove",
        none: "No files attached.",
        hint: "Files are encrypted with everything else and never written to disk in \
               the clear. They share the vault's fixed capacity, so large files are \
               what will fill it up.",
        pick_title: "Choose a file to attach",
        save_title: "Save the attachment",
        too_large: "That file does not fit: {} is left in this vault.",
        read_failed: "That file could not be read.",
        saved: "File saved.",
        added: "File attached.",
        removed: "Attachment removed.",
        space_left: "{} free",
    },
    hidden: HiddenText {
        section: "Hidden vault",
        explain: "A second vault in the same file, under a different password. Encryption \
                  cannot help against someone who can make you hand over a password — but \
                  being able to hand over a real one that opens a plausible vault can. \
                  Every vault file has room for two, whether or not you use it, so the \
                  file itself gives nothing away.",
        create_button: "Create a hidden vault…",
        password: "Password for the hidden vault",
        confirm: "Confirm",
        warning_title: "Read this before you create one",
        warning_body: "You will have to remember two passwords, and there is no way to \
                       recover the hidden one — not even this vault knows it exists. Keep \
                       using this vault normally: one that is obviously empty is not \
                       plausible. And be aware that anyone comparing copies of the file \
                       over time may notice which parts never change.",
        create_confirm: "Create it",
        created_title: "The hidden vault exists",
        created_body: "Lock, then unlock with the new password to open it. This vault is \
                       unchanged and still opens with the password you used to get here.",
        same_password: "It must differ from this vault's password.",
        exists: "A hidden vault already exists under that password.",
        in_hidden_title: "You are in the hidden vault",
        in_hidden_body: "The other vault in this file is untouched and still opens with \
                         its own password.",
        unavailable: "This is already the hidden vault; a file holds at most two.",
    },
    history: HistoryText {
        title: "Change history",
        note: "Each record carries the hash of the one before it, so a line cannot be \
               removed or rewritten without breaking every hash that follows. The log \
               never holds a password — only names and actions.",
        empty: "Nothing recorded yet.",
        intact_title: "The chain is intact",
        intact_body: "{} records, all consistent.",
        broken_title: "The chain is broken",
        broken_body: "Record {} does not match what came before it. The log has been \
                      altered, or the file is damaged.",
        action_created: "vault created",
        action_entry_added: "entry added",
        action_entry_edited: "entry edited",
        action_password_changed: "password changed",
        action_entry_renamed: "entry renamed",
        action_entry_deleted: "entry deleted",
        action_attachment_added: "file attached",
        action_attachment_removed: "attachment removed",
        action_master_changed: "master password changed",
        action_vault_resized: "vault resized",
        action_recovery_created: "recovery pieces made",
        action_work_factor: "work factor changed",
    },

    errors: ErrorsText {
        authentication: "Cannot open the vault: wrong master password or keyfile, or the \
                         file has been altered.",
        crypto: "Cryptography error: {}",
        format: "Unrecognised vault format: {}",
        veracrypt: "VeraCrypt: {}",
        config: "Settings: {}",
        entry_not_found: "No entry named \"{}\".",
        entry_exists: "An entry named \"{}\" already exists.",
        rollback: "This vault is revision {}, but revision {} was last seen on this \
                   machine. An older copy may have been restored in place of the current \
                   one. Continue only if you restored a backup on purpose.",
        io: "{}: {}",
    },

    portable: PortableText {
        section: "Import and export",
        hint: "Import reads CSV from KeePass, Bitwarden, 1Password, Chrome and Firefox, \
               and JSON written by this program. An entry whose name already exists is \
               never overwritten — it is skipped and counted.",
        import: "Import…",
        export: "Export…",
        export_csv: "Export as CSV",
        export_json: "Export as JSON",
        export_warning_title: "An export is not encrypted",
        export_warning_body: "Every password will be written to an ordinary file that \
                              anyone who can read your disk can read. That is what an \
                              export is for — but delete it once you are done, and do \
                              not leave it in Downloads. CSV drops attachments and \
                              password history; JSON keeps everything.",
        export_title: "Where to write the export",
        import_title: "Choose a file to import",
        filter_csv: "CSV",
        filter_json: "JSON",
        filter_any: "CSV or JSON",
        exported_title: "Exported — now delete it",
        exported_body: "Plaintext written to {}",
        imported_title: "Import finished",
        report_added: "{} added",
        report_duplicates: "{} already present",
        report_malformed: "{} without a name",
        audit_import: "{} imported",
    },

    mirror: MirrorText {
        section: "Second copy",
        hint: "The numbered backups live beside the vault, which makes five copies of \
               one accident: a failing disk, or a folder reached by ransomware, takes \
               all of them at once. A memory stick, a network share or a synced folder \
               fixes that — the file is already encrypted, so it is safe anywhere.",
        choose: "Choose a folder…",
        clear: "Stop copying",
        none: "Not set — every copy is on this one disk.",
        dialog_title: "Where to keep the second copy",
        failed_title: "The second copy did not get written",
        failed_body: "Your passwords were saved. Only the copy failed: {}",
        working: "Copying every save to {}",
    },
    resize: ResizeText {
        section: "Vault size",
        hint: "Every slot in the file is the same fixed size, which is what stops the \
               file admitting whether a second vault exists. It is chosen when the file \
               is made, so outgrowing it needs the file rebuilt.",
        current: "{} per slot, {} still free",
        slot_size: "Slot size",
        work_factor: "Cost of one guess",
        cost: "{} MiB, {} passes",
        work_factor_hint: "What one guess at the master password costs. It is fixed when the file is made, so raising it needs a rebuild. Hardware gets cheaper: what was expensive today will not be in five years.",
        own_password: "This vault's master password",
        own_password_hint: "A new cost makes a different key from the same password, so it has to be derived again. The password is checked before anything is written.",
        apply: "Rebuild at the new size",
        carry_hidden: "Also carry the second vault across",
        carry_hint: "Its password, so it can be unsealed and written into the new file.",
        carry_hint_rekey: "When the cost changes this is the only way the other slot can survive: its key cannot be derived again without its password.",
        warning_title: "Anything in the other slot will be lost",
        warning_body: "From inside this vault there is no way to tell whether the other \
                       slot holds a hidden vault or random padding — which is the point \
                       of the format. Leave the password blank and that slot is refilled \
                       with fresh noise. If a hidden vault is in there, it is gone.",
        done_title: "Vault rebuilt",
        done_body: "Slots grew from {} to {}",
    },
    anchor: AnchorText {
        section: "Rollback record",
        hint: "A note of the newest version seen, kept outside the vault so an attacker \
               would have to reach two places at once. It lives on this computer, so a \
               vault carried to another one arrives with nothing to compare against.",
        verified: "Checked against this computer's record",
        first_seen: "No record on this computer",
        first_seen_body: "This is the first time this vault has been opened here, so \
                          nothing could be compared. That is exactly the moment a \
                          swapped file would go unnoticed. Carry the record across if \
                          you moved the vault.",
        unverifiable: "The record could not be read",
        unverifiable_body: "A record exists but does not authenticate, so it says \
                            nothing either way. It has been left alone.",
        export: "Save the record…",
        import: "Load a record…",
        exported: "Record written to {}",
        imported_title: "Record accepted",
        imported_body: "This vault is at least as new as the record, and the record \
                        now applies here.",
        dialog_export: "Where to save the rollback record",
        dialog_import: "Choose a rollback record",
        filter: "Rollback record",
    },
    recovery: RecoveryText {
        section: "If you forget the master password",
        hint: "The password can be split into pieces, of which any few rebuild it. \
               Keep them apart — one at home, one with someone you trust, one in a \
               safe. Fewer than the required number say nothing at all, so no single \
               place is either a weakness or a way to lose everything. Nothing is \
               stored: the pieces exist only where you put them.",
        threshold: "Pieces needed",
        count: "Pieces made",
        confirm_password: "Master password, to be sure it is you",
        create: "Make the pieces…",
        card_heading: "Deep Defense — recovery",
        card_share: "Piece {} of {}",
        card_note: "Any {} of these rebuild the master password. Keep them apart.",
        save: "Save to a file…",
        done: "Done",
        warning_title: "Write these down before closing this",
        warning_body: "They are shown once and kept nowhere. Anyone holding the \
                       required number of pieces can open the vault, so treat each one \
                       the way you treat the password itself.",
        stale_title: "The recovery pieces are now out of date",
        stale_body: "They rebuild the old password, which no longer opens anything. \
                     Make a new set.",
        made_on: "Pieces made on {}",
        none_made: "No pieces have been made.",
        verify_open: "Check pieces you already have",
        verify_hint: "Paste them to confirm they still rebuild the current password. Nothing is shown and nothing is changed.",
        verify_button: "Check",
        verify_ok: "These pieces rebuild the current master password.",
        verify_bad: "These pieces do not rebuild the current master password. They are probably from before it was changed.",
        saved: "Written to {} — now print it and delete the file",
        unlock_open: "Forgotten the password?",
        unlock_hint: "Paste the pieces you have, headings and all. Whatever is not a \
                      piece is ignored.",
        unlock_paste: "Recovery pieces",
        unlock_rebuild: "Rebuild the password",
        unlock_found: "{} recognised, {} needed",
        unlock_none: "Nothing here looks like a recovery piece.",
        unlock_done: "Password rebuilt — now unlock as usual.",
    },
    breach: BreachText {
        section: "Passwords known to be public",
        hint: "A password that already appears in a published leak is the first thing \
               tried, however strong it looks. The check runs on this computer against \
               a compressed list built into the program: nothing is sent anywhere, and \
               the list cannot be read back out into a wordlist.",
        bundled_body: "Built in: {} passwords",
        imported_body: "Added by you: {} passwords",
        import: "Add a list…",
        forget: "Remove the added list",
        dialog_title: "Choose a password list",
        filter: "Word list",
        import_done: "Added {}, of which {} were published digests",
        crowded: "That list is larger than the space for it, so the check will start \
                  reporting passwords it has not actually seen.",
        warning_master: "This password appears in published leaks. It is the first \
                         thing an attacker tries, whatever its length suggests.",
        warning_entry: "Appears in published leaks — change it wherever it is used.",
    },
};

pub static RU: Strings = Strings {
    common: Common {
        save: "Сохранить",
        cancel: "Отмена",
        delete: "Удалить",
        close: "Закрыть",
        copy: "Копировать",
        show: "Показать",
        hide: "Скрыть",
        generate: "Сгенерировать",
        search: "Поиск",
        settings: "Настройки",
        health: "Проверка",
        history: "История",
        lock: "Заблокировать",
        unlock: "Открыть",
        dismiss: "Скрыть",
        language: "Язык",
        theme: "Тема",
        theme_light: "Светлая",
        theme_dark: "Тёмная",
        unknown: "неизвестно",
        optional: "необязательно",
        minutes_short: "м",
        seconds_short: "с",
        browse: "Обзор…",
    },
    shell: Shell {
        subtitle: "Argon2id · двойной шифр",
        locks_in: "Блокировка через {}",
        clipboard_clears_in: "Буфер очистится через {} с",
        busy_unlocking: "Вывод ключей и монтирование контейнера…",
        busy_creating: "Создание контейнера. Заполнение случайными данными занимает время…",
        busy_note: "Argon2id медленный намеренно — именно это делает перебор дорогим.",
        error_title: "Что-то пошло не так",
        locked_notice: "Заблокировано. Контейнер размонтирован.",
        autolocked_title: "Автоблокировка",
        screen_locked_title: "Заблокировано вместе с экраном",
        screen_locked_body: "Экран заблокировался, поэтому хранилище сохранено и закрыто сразу, не дожидаясь таймера простоя.",
        autolocked_body: "Хранилище простаивало: оно сохранено, закрыто и размонтировано.",
        rollback_title: "Это хранилище старше последнего, которое видел этот компьютер",
        rollback_body: "В файле ревизия {}, а здесь ранее была записана ревизия {}. Либо вы \
                        восстановили резервную копию, либо кто-то подменил хранилище старой \
                        копией, чтобы вернуть пароль, который вы уже сменили.",
        rollback_accept: "Я сам восстановил копию — открыть",
        saved: "Сохранено.",
        shortcut_hint: "Ctrl+N создать · Ctrl+F поиск · Ctrl+L заблокировать · Esc закрыть",
    },
    setup: Setup {
        heading: "Создание хранилища",
        subheading: "Пароли шифруются дважды двумя не связанными между собой шифрами под \
                     одним мастер-паролем, который нигде не сохраняется.",
        veracrypt_missing_title: "VeraCrypt не найден",
        veracrypt_missing_body: "Установите VeraCrypt с veracrypt.fr и перезапустите \
                                 программу. Если он стоит в нестандартном месте, путь можно \
                                 будет указать в настройках после создания хранилища.",
        section_mode: "Защита",
        mode_standalone: "Только файл хранилища",
        mode_container: "Ещё и внутри контейнера VeraCrypt",
        mode_hint_standalone: "Хранилище зашифровано дважды двумя не связанными между собой \
                               шифрами: XChaCha20-Poly1305 внутри AES-256-GCM, у каждого свой \
                               ключ. Ничего не устанавливать, админправа не нужны.",
        mode_hint_container: "Добавляет третий, внешний слой: том VeraCrypt, смонтированный \
                              как диск, пока хранилище открыто. VeraCrypt загружает драйвер \
                              ядра, поэтому Windows запросит права администратора.",
        mode_container_unavailable: "VeraCrypt не установлен, поэтому этот вариант недоступен. \
                                     Сам файл хранилища всё равно зашифрован двумя \
                                     независимыми шифрами.",
        section_location: "Где хранить",
        location_hint: "Один файл. Копируйте как любой другой — без мастер-пароля он \
                        бесполезен для кого угодно.",
        location_hint_standalone: "Один файл, и это единственное, что нужно копировать. Без \
                                   мастер-пароля он бесполезен для кого угодно.",
        section_size: "Размер",
        size_suffix: " МБ",
        size_hint: "64 МБ хватает на десятки тысяч записей. При создании контейнер \
                    заполняется случайными данными, поэтому больший размер создаётся дольше.",
        section_master: "Мастер-пароль",
        master_placeholder: "Единственный пароль, который придётся помнить",
        confirm_placeholder: "Повторите его",
        show_typing: "Показывать вводимое",
        mismatch: "Введённое не совпадает.",
        master_hint: "Этот пароль нигде не сохраняется. Если вы его забудете, данные \
                      потеряны — в этом и смысл, и отменить это не сможет никто. Длинная \
                      фраза из четырёх-пяти несвязанных слов надёжнее короткой абракадабры.",
        section_keyfile: "Файл-ключ",
        keyfile_enable: "Требовать ещё и файл-ключ для открытия хранилища",
        keyfile_generate: "Создать здесь новый файл-ключ",
        keyfile_hint: "Превращает защиту в «то, что вы знаете» плюс «то, что у вас есть». \
                       Держите его на флешке: рядом с контейнером он теряет смысл. \
                       Потеряете — хранилище не открыть.",
        keyfile_missing: "Такого файла-ключа пока нет.",
        keyfile_need_path_title: "Сначала укажите путь к файлу-ключу",
        keyfile_need_path_body: "Лучше всего — на съёмном носителе.",
        keyfile_written: "Файл-ключ создан.",
        backup_title: "Два файла, одна резервная копия",
        backup_body: "При создании рядом с контейнером появится небольшой файл .ddmeta. В нём \
                      лежит ключ контейнера, зашифрованный вашим мастер-паролем: без пароля \
                      он бесполезен, но и контейнер без него не открыть. Копируйте его всюду, \
                      куда копируете контейнер.",
        acknowledge: "Я понимаю, что забытый мастер-пароль означает безвозвратную потерю данных",
        create_button: "Создать хранилище",
        password_too_short: "Мастер-пароль должен быть не короче 8 символов и совпадать.",
        master_too_short: "Не короче 8 символов.",
        master_too_weak: "Слишком легко подобрать. Возьмите фразу подлиннее или нажмите \
                          «Предложить» — от этого пароля зависит всё остальное.",
        suggest_passphrase: "Предложить",
        suggest_passphrase_hint: "Сгенерировать произносимую фразу, которую реально \
                                  запомнить",
        suggested_title: "Запишите её, прежде чем продолжить",
        suggested_body: "Около {} бит энтропии. Она показана полностью, чтобы вы могли её \
                         запомнить или скопировать — после создания хранилища восстановить \
                         её не сможет никто.",
        pick_vault_title: "Где создать хранилище",
        pick_container_title: "Где создать контейнер",
        pick_keyfile_title: "Где разместить файл-ключ",
        filter_vault: "Хранилище Deep Defense",
        filter_container: "Контейнер VeraCrypt",
        filter_keyfile: "Файл-ключ",
        existing_title: "По этому пути уже есть контейнер",
        existing_body: "Ничего не будет перезаписано. Откройте его своим мастер-паролем.",
        open_existing: "Открыть этот контейнер",
        created_success: "Хранилище создано. Копируйте контейнер вместе с файлом .ddmeta.",
        created_success_standalone: "Хранилище создано. Копируйте файл .ddv — в нём всё, и без \
                                     вашего пароля он бесполезен.",
        backup_body_standalone: "Всё лежит в одном файле .ddv. Копируйте его туда, где храните \
                                 резервные копии: это шифротекст, поэтому копия в облаке или на \
                                 флешке без мастер-пароля не выдаёт ничего. Пять предыдущих \
                                 версий хранятся рядом автоматически.",
    },
    unlock: Unlock {
        subheading: "Хранилище заблокировано, контейнер размонтирован.",
        master_placeholder: "Мастер-пароль",
        keyfiles_used: "Также будет использовано файлов-ключей: {}.",
        keyfile_missing: "Отсутствует: {}",
        container_label: "Контейнер: {}",
        vault_label: "Хранилище: {}",
        different_container: "Выбрать другой контейнер…",
        different_container_hint: "Вернуться к экрану настройки",
        veracrypt_path_label: "VeraCrypt.exe:",
        veracrypt_missing_title: "VeraCrypt не найден",
        veracrypt_missing_body: "Без него контейнер не смонтировать. Установите VeraCrypt или \
                                 укажите путь к нему ниже.",
        pick_container_notice: "Укажите существующий контейнер или создайте новый.",
    },
    entry: EntryText {
        new_title: "Новая запись",
        edit_title: "Изменение записи",
        new_button: "Создать",
        name: "Название",
        name_placeholder: "GitHub",
        username: "Логин",
        username_placeholder: "you@example.com",
        url: "Адрес",
        url_placeholder: "https://github.com",
        tags: "Метки",
        tags_placeholder: "работа, почта, важное",
        notes: "Заметки",
        password: "Пароль",
        password_placeholder: "Пароль",
        totp_section: "Секрет двухфакторной аутентификации",
        totp_placeholder: "Base32-секрет или полная ссылка otpauth://",
        totp_hint: "Хранить здесь секрет 2FA удобно, но это сводит оба фактора к одному \
                    паролю. Защищает от фишинга и повторного использования паролей; не \
                    поможет, если вскрыли само хранилище.",
        totp_copy: "Копировать код",
        history_title: "Прежние пароли ({})",
        history_hint: "Хранятся, чтобы можно было отменить ошибочную замену. Зашифрованы \
                       вместе со всем остальным.",
        no_selection: "Выберите запись или нажмите Ctrl+N, чтобы создать.",
        needs_name: "Без названия запись сохранить нельзя.",
        entries_count: "Записей: {}",
        matches_count: "Найдено {} из {}",
        empty_list: "Записей пока нет. Нажмите Ctrl+N, чтобы создать первую.",
        no_matches: "По этому запросу ничего нет.",
        delete_title: "Удалить «{}»?",
        delete_body: "Запись и история её паролей будут удалены из хранилища. В прежних \
                      файлах .bak рядом с хранилищем она останется.",
        deleted: "Запись удалена.",
        copied_username: "Логин скопирован.",
        copied_password: "Пароль скопирован. Буфер очистится через {} с.",
        autotype: "Набрать в активном окне",
        autotype_hint: "Без буфера обмена: перейдите в нужное окно, пока идёт отсчёт. В своё собственное окно программа набирать откажется.",
        autotype_waiting: "набор через {} с — перейдите в окно",
        autotype_done: "Набрано в окне: {}",
        copied_code: "Одноразовый код скопирован.",
        copied_old: "Прежний пароль скопирован.",
        marker_weak: "слабый",
        marker_old: "устарел",
        marker_totp: "2FA",
        filter_all: "Все",
        fields_section: "Другие поля",
        fields_none: "Пока пусто. ПИН, номер счёта, ответ на контрольный вопрос.",
        field_name: "Название",
        field_value: "Значение",
        field_secret: "Скрывать значение",
        field_add: "Добавить поле",
    },
    generator: GeneratorText {
        title: "Генератор паролей",
        entropy: "{} бит энтропии — это точная величина, а не оценка",
        length: "Длина",
        lowercase: "а–я строчные (a–z)",
        uppercase: "А–Я прописные (A–Z)",
        digits: "0–9",
        symbols: "Символы",
        avoid_ambiguous: "Избегать похожих знаков (l, 1, O, 0)",
        require_each: "Требовать по одному знаку из каждого набора",
        another: "Сгенерировать другой",
        use_this: "Использовать этот",
    },
    settings: SettingsText {
        title: "Настройки",
        section_appearance: "Оформление",
        section_locking: "Блокировка",
        autolock: "Автоблокировка при простое (секунд)",
        clipboard: "Очистка буфера обмена (секунд)",
        warn_age: "Помечать пароли старше (дней)",
        lock_on_screen_lock: "Блокировать вместе с рабочим столом",
        mask_passwords: "Скрывать пароли, пока не покажу",
        calibrate: "Подобрать под этот компьютер",
        calibrate_hint: "Измерить, насколько тяжёлым может быть Argon2id здесь, чтобы открытие занимало около секунды",
        locking_hint: "Автоблокировка сохраняет хранилище, затирает ключи в памяти и \
                       размонтирует контейнер. Это разница между украденным ноутбуком и \
                       украденным хранилищем.",
        section_kdf: "Стоимость вывода ключа",
        kdf_memory: "Памяти на одну попытку (МиБ)",
        kdf_passes: "Проходов",
        measure: "Измерить на этом компьютере",
        measured: "{} с на попытку здесь",
        kdf_hint: "Столько стоит атакующему одна попытка подбора — и столько же длится ваше \
                   открытие хранилища. Около одной секунды — хороший компромисс. Настройки \
                   применятся при следующей смене мастер-пароля.",
        section_master: "Мастер-пароль",
        change_button: "Сменить мастер-пароль…",
        change_hint: "Перешифровывает хранилище с новой солью. Старый пароль перестаёт \
                      работать сразу же.",
        new_password: "Новый мастер-пароль",
        confirm_password: "Повторите",
        change_warning_title: "Перешифровываются оба слоя",
        change_warning_body: "Хранилище перешифровывается новым паролем, а ключ контейнера \
                              заново заворачивается. Argon2id выполняется дважды, поэтому \
                              окно на несколько секунд перестанет отвечать — это работа, а \
                              не сбой. Если процесс прервётся, старый пароль продолжит \
                              работать: остаться без доступа на полпути невозможно.",
        change_confirm: "Сменить",
        changed: "Мастер-пароль изменён. Оба слоя используют новый.",
        section_veracrypt: "VeraCrypt",
        veracrypt_binary: "Программа VeraCrypt",
        veracrypt_format_binary: "Программа VeraCrypt Format",
        veracrypt_found: "VeraCrypt найден",
        veracrypt_not_found: "VeraCrypt не найден",
        section_vault: "Это хранилище",
        vault_entries: "Записей",
        vault_revision: "Ревизия",
        vault_cipher: "Внутренний шифр",
        vault_kdf: "Вывод ключа",
        vault_kdf_value: "Argon2id, {} МиБ, проходов: {}",
        vault_mounted_at: "Смонтировано в",
        vault_backups: "Резервных копий",
        vault_location: "Файл",
        vault_layers: "Слоёв защиты",
        vault_layers_standalone: "2 — каскад шифров",
        vault_layers_container: "3 — каскад + контейнер VeraCrypt",
    },
    audit: AuditText {
        title: "Проверка паролей",
        offline_note: "Проверка полностью офлайн. Отсюда ничего никуда не отправляется.",
        all_good_title: "Замечаний нет",
        all_good_body: "Все записи в порядке: {}.",
        needs_attention: "Требуют внимания: {} из {}",
        problem_no_password: "нет пароля",
        detail_no_password: "В этой записи пароль не сохранён.",
        problem_weak: "пароль: {}",
        detail_weak: "Около {} бит энтропии. Сгенерируйте замену — это один щелчок.",
        problem_reused: "повторяется",
        detail_reused: "Тот же пароль используется в другой записи. Одна утечка вскроет обе.",
        problem_breached: "в опубликованной утечке",
        detail_breached: "Пробуют первым, что бы ни говорила его длина. Смените его везде, где он используется.",
        problem_old: "давно не менялся",
        detail_old: "Последняя смена {} дней назад.",
    },
    strength: StrengthText {
        critical: "критический",
        weak: "слабый",
        fair: "средний",
        strong: "надёжный",
        excellent: "отличный",
        summary: "{} — около {} бит",
        exact: "{} бит",
    },

    attachments: AttachmentsText {
        section: "Вложения",
        add: "Добавить файл…",
        save_as: "Сохранить как…",
        remove: "Удалить",
        none: "Файлов не приложено.",
        hint: "Файлы шифруются вместе со всем остальным и никогда не попадают на диск в \
               открытом виде. Они делят фиксированный объём хранилища, поэтому именно \
               крупные файлы его и заполнят.",
        pick_title: "Выберите файл для вложения",
        save_title: "Сохранить вложение",
        too_large: "Файл не помещается: в хранилище осталось {}.",
        read_failed: "Не удалось прочитать этот файл.",
        saved: "Файл сохранён.",
        added: "Файл вложен.",
        removed: "Вложение удалено.",
        space_left: "свободно {}",
    },
    hidden: HiddenText {
        section: "Скрытое хранилище",
        explain: "Второе хранилище в том же файле под другим паролем. Шифрование не \
                  спасает от того, кто может заставить выдать пароль, — но возможность \
                  выдать настоящий пароль, открывающий правдоподобное хранилище, спасает. \
                  Место под второе есть в каждом файле, используете вы его или нет, \
                  поэтому сам файл ничего не выдаёт.",
        create_button: "Создать скрытое хранилище…",
        password: "Пароль скрытого хранилища",
        confirm: "Повторите",
        warning_title: "Прочитайте, прежде чем создавать",
        warning_body: "Придётся помнить два пароля, и восстановить скрытый нельзя — даже \
                       это хранилище не знает о его существовании. Продолжайте нормально \
                       пользоваться этим: очевидно пустое хранилище неправдоподобно. И \
                       учтите, что тот, кто сравнивает копии файла во времени, может \
                       заметить, какие части никогда не меняются.",
        create_confirm: "Создать",
        created_title: "Скрытое хранилище создано",
        created_body: "Заблокируйте и откройте новым паролем. Это хранилище не изменилось \
                       и по-прежнему открывается тем паролем, которым вы вошли.",
        same_password: "Он должен отличаться от пароля этого хранилища.",
        exists: "Скрытое хранилище с таким паролем уже существует.",
        in_hidden_title: "Вы в скрытом хранилище",
        in_hidden_body: "Второе хранилище в этом файле не затронуто и открывается своим \
                         паролем.",
        unavailable: "Это и есть скрытое хранилище; в файле их не больше двух.",
    },
    history: HistoryText {
        title: "История изменений",
        note: "Каждая запись содержит хеш предыдущей, поэтому строку нельзя удалить или \
               переписать, не сломав все последующие хеши. Паролей в журнале нет — только \
               названия и действия.",
        empty: "Пока ничего не записано.",
        intact_title: "Цепочка цела",
        intact_body: "Записей: {}, все согласованы.",
        broken_title: "Цепочка нарушена",
        broken_body: "Запись {} не сходится с предыдущей. Журнал изменён или файл повреждён.",
        action_created: "хранилище создано",
        action_entry_added: "запись добавлена",
        action_entry_edited: "запись изменена",
        action_password_changed: "пароль изменён",
        action_entry_renamed: "запись переименована",
        action_entry_deleted: "запись удалена",
        action_attachment_added: "файл вложен",
        action_attachment_removed: "вложение удалено",
        action_master_changed: "мастер-пароль изменён",
        action_vault_resized: "изменён размер хранилища",
        action_recovery_created: "созданы части для восстановления",
        action_work_factor: "изменена стоимость подбора",
    },

    errors: ErrorsText {
        authentication: "Не удаётся открыть хранилище: неверный мастер-пароль или \
                         файл-ключ, либо файл был изменён.",
        crypto: "Ошибка криптографии: {}",
        format: "Неизвестный формат хранилища: {}",
        veracrypt: "VeraCrypt: {}",
        config: "Настройки: {}",
        entry_not_found: "Записи «{}» нет.",
        entry_exists: "Запись «{}» уже существует.",
        rollback: "В файле ревизия {}, а на этом компьютере в последний раз была {}. \
                   Возможно, вместо текущей копии восстановили старую. Продолжайте, \
                   только если вы сами восстановили резервную копию.",
        io: "{}: {}",
    },

    portable: PortableText {
        section: "Импорт и экспорт",
        hint: "Импорт читает CSV из KeePass, Bitwarden, 1Password, Chrome и Firefox, а \
               также JSON, созданный этой программой. Запись с уже существующим \
               названием никогда не перезаписывается — она пропускается и \
               подсчитывается.",
        import: "Импорт…",
        export: "Экспорт…",
        export_csv: "Выгрузить в CSV",
        export_json: "Выгрузить в JSON",
        export_warning_title: "Экспорт не зашифрован",
        export_warning_body: "Все пароли будут записаны в обычный файл, который прочитает \
                              любой, у кого есть доступ к вашему диску. Для этого экспорт \
                              и нужен — но удалите файл, когда закончите, и не оставляйте \
                              его в «Загрузках». CSV теряет вложения и историю паролей, \
                              JSON сохраняет всё.",
        export_title: "Куда сохранить выгрузку",
        import_title: "Выберите файл для импорта",
        filter_csv: "CSV",
        filter_json: "JSON",
        filter_any: "CSV или JSON",
        exported_title: "Выгружено — теперь удалите файл",
        exported_body: "Открытый текст записан в {}",
        imported_title: "Импорт завершён",
        report_added: "добавлено: {}",
        report_duplicates: "уже было: {}",
        report_malformed: "без названия: {}",
        audit_import: "импортировано записей: {}",
    },
    mirror: MirrorText {
        section: "Вторая копия",
        hint: "Нумерованные резервные копии лежат рядом с хранилищем, а значит это пять копий одной и той же беды: умирающий диск или шифровальщик, добравшийся до папки, забирают их все сразу. Флешка, сетевая папка или облачная это исправляют — файл уже зашифрован, ему везде безопасно.",
        choose: "Выбрать папку…",
        clear: "Перестать копировать",
        none: "Не задана — все копии на одном диске.",
        dialog_title: "Где держать вторую копию",
        failed_title: "Вторая копия не записалась",
        failed_body: "Пароли сохранены. Не удалась только копия: {}",
        working: "Каждое сохранение копируется в {}",
    },
    resize: ResizeText {
        section: "Размер хранилища",
        hint: "Все слоты в файле одного размера — именно это не даёт файлу выдать, есть ли в нём второе хранилище. Размер задаётся при создании, поэтому вырасти из него можно только с пересборкой файла.",
        current: "{} на слот, свободно {}",
        slot_size: "Размер слота",
        work_factor: "Стоимость подбора",
        cost: "{} МиБ, проходов: {}",
        work_factor_hint: "Сколько стоит одна попытка подбора мастер-пароля. Задаётся при создании файла, поэтому поднять её можно только пересборкой. Железо дешевеет — то, что было дорого сегодня, через пять лет таким не будет.",
        own_password: "Мастер-пароль этого хранилища",
        own_password_hint: "Новая стоимость даёт другой ключ из того же пароля, поэтому его нужно вывести заново. Пароль проверяется до того, как что-либо будет записано.",
        apply: "Пересобрать в новом размере",
        carry_hidden: "Перенести и второе хранилище",
        carry_hint: "Его пароль, чтобы распечатать его и записать в новый файл.",
        carry_hint_rekey: "При смене стоимости это единственный способ сохранить соседний слот: его ключ нельзя вывести заново без пароля.",
        warning_title: "Всё, что в другом слоте, будет потеряно",
        warning_body: "Изнутри этого хранилища никак не узнать, скрытое ли хранилище в соседнем слоте или случайный шум, — в этом весь смысл формата. Оставьте пароль пустым — и слот заполнится свежим шумом. Если там было скрытое хранилище, его больше нет.",
        done_title: "Хранилище пересобрано",
        done_body: "Слоты выросли с {} до {}",
    },
    anchor: AnchorText {
        section: "Запись об откате",
        hint: "Отметка о самой свежей виденной версии, хранится вне хранилища, чтобы подмена требовала доступа сразу к двум местам. Она лежит на этом компьютере, поэтому хранилище, перенесённое на другой, приезжает без неё.",
        verified: "Сверено с записью на этом компьютере",
        first_seen: "На этом компьютере записи нет",
        first_seen_body: "Хранилище открывается здесь впервые, сравнивать было не с чем. Это ровно тот момент, когда подменённый файл остался бы незамеченным. Если вы переносили хранилище, перенесите и запись.",
        unverifiable: "Запись не удалось прочитать",
        unverifiable_body: "Запись есть, но не подтверждается, значит ничего не говорит ни за, ни против. Её оставили как есть.",
        export: "Сохранить запись…",
        import: "Загрузить запись…",
        exported: "Запись сохранена в {}",
        imported_title: "Запись принята",
        imported_body: "Это хранилище не старше записи, и теперь запись действует здесь.",
        dialog_export: "Куда сохранить запись об откате",
        dialog_import: "Выберите запись об откате",
        filter: "Запись об откате",
    },
    recovery: RecoveryText {
        section: "Если вы забудете мастер-пароль",
        hint: "Пароль можно разрезать на части, любые несколько из которых его собирают. Держите их порознь: одну дома, одну у близкого человека, одну в сейфе. Меньшее число частей не говорит ровно ничего, поэтому ни одно место не является ни слабым звеном, ни способом потерять всё. Ничего не сохраняется: части существуют только там, куда вы их положите.",
        threshold: "Сколько нужно",
        count: "Сколько создать",
        confirm_password: "Мастер-пароль, чтобы убедиться, что это вы",
        create: "Создать части…",
        card_heading: "Deep Defense — восстановление",
        card_share: "Часть {} из {}",
        card_note: "Любые {} из них собирают мастер-пароль. Держите их порознь.",
        save: "Сохранить в файл…",
        done: "Готово",
        warning_title: "Запишите их, прежде чем закрыть",
        warning_body: "Они показываются один раз и нигде не хранятся. Кто держит нужное число частей, тот откроет хранилище, — обращайтесь с каждой как с самим паролем.",
        stale_title: "Части для восстановления устарели",
        stale_body: "Они собирают старый пароль, который больше ничего не открывает. Создайте новый набор.",
        made_on: "Части созданы {}",
        none_made: "Части не создавались.",
        verify_open: "Проверить имеющиеся части",
        verify_hint: "Вставьте их, чтобы убедиться, что они всё ещё собирают действующий пароль. Ничего не показывается и ничего не меняется.",
        verify_button: "Проверить",
        verify_ok: "Эти части собирают действующий мастер-пароль.",
        verify_bad: "Эти части не собирают действующий мастер-пароль. Скорее всего, они сделаны до его смены.",
        saved: "Записано в {} — распечатайте и удалите файл",
        unlock_open: "Забыли пароль?",
        unlock_hint: "Вставьте имеющиеся части целиком, вместе с заголовками. Всё, что не является частью, будет пропущено.",
        unlock_paste: "Части для восстановления",
        unlock_rebuild: "Собрать пароль",
        unlock_found: "распознано {}, нужно {}",
        unlock_none: "Здесь нет ничего похожего на часть для восстановления.",
        unlock_done: "Пароль собран — теперь откройте как обычно.",
    },
    breach: BreachText {
        section: "Пароли, ставшие публичными",
        hint: "Пароль, уже попавший в опубликованную утечку, пробуют первым — как бы крепко он ни выглядел. Проверка идёт на этом компьютере по сжатому списку внутри программы: ничего никуда не отправляется, а сам список нельзя развернуть обратно в словарь.",
        bundled_body: "Встроено: {} паролей",
        imported_body: "Добавлено вами: {} паролей",
        import: "Добавить список…",
        forget: "Убрать добавленный список",
        dialog_title: "Выберите список паролей",
        filter: "Список слов",
        import_done: "Добавлено {}, из них свёрток: {}",
        crowded: "Список больше отведённого под него места, и проверка начнёт сообщать о паролях, которых на самом деле не видела.",
        warning_master: "Этот пароль есть в опубликованных утечках. Его пробуют первым, что бы ни говорила его длина.",
        warning_entry: "Есть в опубликованных утечках — смените его везде, где он используется.",
    },
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_match_between_languages() {
        // A translation that drops a "{}" silently loses the number it was
        // supposed to show, and one that adds an extra leaves "{}" on screen.
        let pairs: [(&str, &str, &str); 46] = [
            ("shell.locks_in", EN.shell.locks_in, RU.shell.locks_in),
            (
                "shell.clipboard_clears_in",
                EN.shell.clipboard_clears_in,
                RU.shell.clipboard_clears_in,
            ),
            ("shell.rollback_body", EN.shell.rollback_body, RU.shell.rollback_body),
            ("unlock.keyfiles_used", EN.unlock.keyfiles_used, RU.unlock.keyfiles_used),
            ("unlock.keyfile_missing", EN.unlock.keyfile_missing, RU.unlock.keyfile_missing),
            ("unlock.container_label", EN.unlock.container_label, RU.unlock.container_label),
            ("unlock.vault_label", EN.unlock.vault_label, RU.unlock.vault_label),
            ("setup.suggested_body", EN.setup.suggested_body, RU.setup.suggested_body),
            ("entry.history_title", EN.entry.history_title, RU.entry.history_title),
            ("entry.entries_count", EN.entry.entries_count, RU.entry.entries_count),
            ("entry.matches_count", EN.entry.matches_count, RU.entry.matches_count),
            ("entry.delete_title", EN.entry.delete_title, RU.entry.delete_title),
            ("entry.copied_password", EN.entry.copied_password, RU.entry.copied_password),
            ("generator.entropy", EN.generator.entropy, RU.generator.entropy),
            ("settings.measured", EN.settings.measured, RU.settings.measured),
            (
                "settings.vault_kdf_value",
                EN.settings.vault_kdf_value,
                RU.settings.vault_kdf_value,
            ),
            ("audit.all_good_body", EN.audit.all_good_body, RU.audit.all_good_body),
            ("audit.needs_attention", EN.audit.needs_attention, RU.audit.needs_attention),
            ("audit.detail_weak", EN.audit.detail_weak, RU.audit.detail_weak),
            ("strength.summary", EN.strength.summary, RU.strength.summary),
            ("attachments.too_large", EN.attachments.too_large, RU.attachments.too_large),
            ("attachments.space_left", EN.attachments.space_left, RU.attachments.space_left),
            ("history.intact_body", EN.history.intact_body, RU.history.intact_body),
            ("history.broken_body", EN.history.broken_body, RU.history.broken_body),
            ("errors.rollback", EN.errors.rollback, RU.errors.rollback),
            ("errors.io", EN.errors.io, RU.errors.io),
            ("portable.exported_body", EN.portable.exported_body, RU.portable.exported_body),
            ("portable.report_added", EN.portable.report_added, RU.portable.report_added),
            ("errors.entry_not_found", EN.errors.entry_not_found, RU.errors.entry_not_found),
            ("errors.crypto", EN.errors.crypto, RU.errors.crypto),
            ("mirror.working", EN.mirror.working, RU.mirror.working),
            ("mirror.failed_body", EN.mirror.failed_body, RU.mirror.failed_body),
            ("resize.current", EN.resize.current, RU.resize.current),
            ("resize.done_body", EN.resize.done_body, RU.resize.done_body),
            ("anchor.exported", EN.anchor.exported, RU.anchor.exported),
            ("recovery.card_share", EN.recovery.card_share, RU.recovery.card_share),
            ("recovery.card_note", EN.recovery.card_note, RU.recovery.card_note),
            ("recovery.saved", EN.recovery.saved, RU.recovery.saved),
            ("recovery.unlock_found", EN.recovery.unlock_found, RU.recovery.unlock_found),
            ("breach.bundled_body", EN.breach.bundled_body, RU.breach.bundled_body),
            ("breach.imported_body", EN.breach.imported_body, RU.breach.imported_body),
            ("breach.import_done", EN.breach.import_done, RU.breach.import_done),
            ("resize.cost", EN.resize.cost, RU.resize.cost),
            ("recovery.made_on", EN.recovery.made_on, RU.recovery.made_on),
            ("entry.autotype_waiting", EN.entry.autotype_waiting, RU.entry.autotype_waiting),
            ("entry.autotype_done", EN.entry.autotype_done, RU.entry.autotype_done),
        ];
        for (name, en, ru) in pairs {
            assert_eq!(
                en.matches("{}").count(),
                ru.matches("{}").count(),
                "{name}: placeholder count differs between English and Russian"
            );
        }
    }

    #[test]
    fn no_string_is_empty() {
        // An empty label is invisible on screen, so it would never be noticed.
        for (lang, s) in [("en", &EN), ("ru", &RU)] {
            for (name, value) in [
                ("common.save", s.common.save),
                ("common.cancel", s.common.cancel),
                ("common.lock", s.common.lock),
                ("setup.heading", s.setup.heading),
                ("setup.create_button", s.setup.create_button),
                ("unlock.master_placeholder", s.unlock.master_placeholder),
                ("entry.name", s.entry.name),
                ("entry.password", s.entry.password),
                ("generator.title", s.generator.title),
                ("settings.title", s.settings.title),
                ("audit.title", s.audit.title),
                ("strength.weak", s.strength.weak),
            ] {
                assert!(!value.trim().is_empty(), "{lang}: {name} is empty");
            }
        }
    }

    #[test]
    fn fill_substitutes_left_to_right() {
        assert_eq!(fill1("Locks in {}", "4m"), "Locks in 4m");
        assert_eq!(fill2("{} of {} match", 3, 40), "3 of 40 match");
        // A template with no placeholder must survive untouched.
        assert_eq!(fill1("Saved.", 7), "Saved.");
    }

    #[test]
    fn russian_text_is_real_cyrillic() {
        // Guards against a copy-paste that leaves English in the RU table.
        assert!(RU.common.save.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)));
        assert!(RU.setup.heading.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)));
        assert_ne!(RU.common.save, EN.common.save);
        assert_ne!(RU.settings.title, EN.settings.title);
    }

    #[test]
    fn every_language_names_itself() {
        for lang in Lang::ALL {
            assert!(!lang.native_name().is_empty());
        }
        assert_eq!(Lang::Ru.native_name(), "Русский");
    }
}
