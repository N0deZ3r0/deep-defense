//! Settings, master-password change, and the password health report.

use std::collections::HashMap;

use eframe::egui;
use zeroize::Zeroizing;

use crate::crypto::KdfParams;
use crate::generator::{check_master_password, estimate_entropy_bits, MasterPasswordProblem, Strength};
use crate::i18n::{fill1, fill2, Lang, Strings};
use crate::secret::Secret;

use super::app::{App, Status};
use super::icons::Icon;
use super::theme::{self, Appearance, Palette};
use super::widgets;

pub struct SettingsState {
    pub autolock_seconds: u64,
    pub clipboard_seconds: u64,
    pub warn_password_age_days: i64,
    pub veracrypt_binary: String,
    pub veracrypt_format_binary: String,

    pub new_password: Zeroizing<String>,
    pub new_password_confirm: Zeroizing<String>,
    pub changing_password: bool,

    pub hidden_password: Zeroizing<String>,
    pub hidden_confirm: Zeroizing<String>,
    pub creating_hidden: bool,
    pub confirming_export: bool,

    /// Slot size picked for a rebuild, in mebibytes. Zero means none chosen.
    pub resize_target_mib: u32,
    /// The other slot's password, so a hidden vault survives a rebuild.
    pub resize_other_password: Zeroizing<String>,
    /// This vault's own password, needed when the work factor changes.
    pub resize_own_password: Zeroizing<String>,
    /// Target work factor. Zero memory means "not read from the vault yet".
    pub resize_memory_mib: u32,
    pub resize_time_cost: u32,

    pub recovery_threshold: u8,
    pub recovery_count: u8,
    pub recovery_password: Zeroizing<String>,
    /// Pieces pasted in to confirm they still work.
    pub recovery_verify: Zeroizing<String>,
    pub recovery_verify_open: bool,
    /// The last answer, kept so it survives the frame that produced it.
    pub recovery_verify_result: Option<bool>,
    /// Shown once, in a window, and dropped when it closes.
    pub recovery_shares: Vec<String>,
    /// The backup a restore has been asked for and not yet confirmed.
    pub restoring_backup: Option<usize>,

    pub kdf_memory_mib: u32,
    pub kdf_time_cost: u32,
    pub measured: Option<f64>,
}

impl SettingsState {
    pub fn new(config: &crate::config::Config) -> Self {
        Self {
            autolock_seconds: config.autolock_seconds,
            clipboard_seconds: config.clipboard_seconds,
            warn_password_age_days: config.warn_password_age_days,
            veracrypt_binary: config.veracrypt_binary.display().to_string(),
            veracrypt_format_binary: config.veracrypt_format_binary.display().to_string(),
            new_password: Zeroizing::new(String::new()),
            new_password_confirm: Zeroizing::new(String::new()),
            changing_password: false,
            hidden_password: Zeroizing::new(String::new()),
            hidden_confirm: Zeroizing::new(String::new()),
            creating_hidden: false,
            confirming_export: false,
            resize_target_mib: 0,
            resize_other_password: Zeroizing::new(String::new()),
            resize_own_password: Zeroizing::new(String::new()),
            resize_memory_mib: 0,
            resize_time_cost: 0,
            // Two of three: enough redundancy that losing one piece is not a
            // disaster, few enough that they can realistically be kept apart.
            recovery_threshold: 2,
            recovery_count: 3,
            recovery_password: Zeroizing::new(String::new()),
            recovery_verify: Zeroizing::new(String::new()),
            recovery_verify_open: false,
            recovery_verify_result: None,
            recovery_shares: Vec::new(),
            restoring_backup: None,
            kdf_memory_mib: config.kdf.memory_mib(),
            kdf_time_cost: config.kdf.t_cost,
            measured: None,
        }
    }
}

pub fn show_window(app: &mut App, ui: &mut egui::Ui) {
    if !app.show_settings {
        return;
    }
    let palette = app.palette();
    let strings = app.strings();
    let mut open = true;
    let ctx = ui.ctx().clone();

    egui::Window::new(strings.settings.title)
        .open(&mut open)
        .resizable(true)
        .collapsible(false)
        .default_width(540.0)
        .default_height(600.0)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(&ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    appearance_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    locking_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    kdf_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    master_password_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    hidden_vault_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    portability_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    mirror_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    backups_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    recovery_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    breach_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    anchor_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    resize_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                    if app.session.config.use_container {
                        veracrypt_section(app, ui, palette, strings);
                        ui.add_space(theme::space::MD);
                    }
                    vault_section(app, ui, palette, strings);
                    ui.add_space(theme::space::MD);
                });
        });

    if !open {
        app.show_settings = false;
    }
}

fn appearance_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.settings.section_appearance);

        ui.horizontal(|ui| {
            ui.label(theme::muted(palette, strings.common.language));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let index = Lang::ALL
                    .iter()
                    .position(|l| *l == app.session.config.language)
                    .unwrap_or(0);
                let options: Vec<(Icon, &str)> = Lang::ALL
                    .iter()
                    .map(|l| (Icon::Globe, l.native_name()))
                    .collect();
                if let Some(picked) =
                    widgets::segmented(ui, palette, "settings_lang", &options, index)
                {
                    app.set_language(Lang::ALL[picked]);
                }
            });
        });

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.label(theme::muted(palette, strings.common.theme));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let index = if app.session.config.appearance == Appearance::Dark {
                    1
                } else {
                    0
                };
                let options = [
                    (Icon::Sun, strings.common.theme_light),
                    (Icon::Moon, strings.common.theme_dark),
                ];
                if let Some(picked) =
                    widgets::segmented(ui, palette, "settings_theme", &options, index)
                {
                    let ctx = ui.ctx().clone();
                    app.set_appearance(
                        &ctx,
                        if picked == 1 {
                            Appearance::Dark
                        } else {
                            Appearance::Light
                        },
                    );
                }
            });
        });
    });
}

fn locking_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.settings.section_locking);
        let mut changed = false;

        changed |= ui
            .add(
                egui::Slider::new(&mut app.settings.autolock_seconds, 30..=3600)
                    .text(strings.settings.autolock)
                    .logarithmic(true),
            )
            .changed();
        changed |= ui
            .add(
                egui::Slider::new(&mut app.settings.clipboard_seconds, 5..=120)
                    .text(strings.settings.clipboard),
            )
            .changed();
        changed |= ui
            .add(
                egui::Slider::new(&mut app.settings.warn_password_age_days, 30..=1095)
                    .text(strings.settings.warn_age),
            )
            .changed();

        ui.add_space(theme::space::SM);
        changed |= ui
            .checkbox(
                &mut app.session.config.lock_on_screen_lock,
                strings.settings.lock_on_screen_lock,
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut app.session.config.mask_passwords,
                strings.settings.mask_passwords,
            )
            .changed();

        if changed {
            app.session.config.autolock_seconds = app.settings.autolock_seconds;
            app.session.config.clipboard_seconds = app.settings.clipboard_seconds;
            app.session.config.warn_password_age_days = app.settings.warn_password_age_days;
            let _ = app.session.config.save();
        }
        widgets::hint(ui, palette, strings.settings.locking_hint);
    });
}

fn kdf_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.settings.section_kdf);

        ui.add(
            egui::Slider::new(&mut app.settings.kdf_memory_mib, 64..=2048)
                .text(strings.settings.kdf_memory)
                .logarithmic(true),
        );
        ui.add(
            egui::Slider::new(&mut app.settings.kdf_time_cost, 2..=12)
                .text(strings.settings.kdf_passes),
        );

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            if ui
                .button(strings.settings.calibrate)
                .on_hover_text(strings.settings.calibrate_hint)
                .clicked()
            {
                // Blocks for a few seconds by design: it is measuring, and a
                // measurement taken in the background while the UI animates
                // would be measuring the wrong thing.
                let picked = KdfParams::calibrated(std::time::Duration::from_secs(1), 1024);
                app.settings.kdf_memory_mib = picked.memory_mib();
                app.settings.kdf_time_cost = picked.t_cost;
                app.settings.measured = picked.measure().ok().map(|d| d.as_secs_f64());
                app.session.config.kdf = picked;
                let _ = app.session.config.save();
            }
            if ui.button(strings.settings.measure).clicked() {
                let params = KdfParams {
                    m_cost: app.settings.kdf_memory_mib * 1024,
                    t_cost: app.settings.kdf_time_cost,
                    p_cost: app.session.config.kdf.p_cost,
                    algorithm: "argon2id".into(),
                };
                match params.measure() {
                    Ok(elapsed) => {
                        app.settings.measured = Some(elapsed.as_secs_f64());
                        // Remember what was measured: these become the
                        // parameters of the next vault created.
                        if params.validate().is_ok() {
                            app.session.config.kdf = params;
                            let _ = app.session.config.save();
                        }
                    }
                    Err(e) => app.status = Some(Status::error(strings, &e)),
                }
            }
            if let Some(seconds) = app.settings.measured {
                // Under ~0.3s a guess is cheap enough to be worth warning about.
                let color = if seconds < 0.3 {
                    palette.warning
                } else {
                    palette.success
                };
                ui.label(
                    egui::RichText::new(fill1(
                        strings.settings.measured,
                        format!("{seconds:.2}"),
                    ))
                    .color(color)
                    .size(12.0),
                );
            }
        });
        widgets::hint(ui, palette, strings.settings.kdf_hint);
    });
}

fn master_password_section(
    app: &mut App,
    ui: &mut egui::Ui,
    palette: &Palette,
    strings: &Strings,
) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.settings.section_master);

        if !app.settings.changing_password {
            if ui.button(strings.settings.change_button).clicked() {
                app.settings.changing_password = true;
            }
            widgets::hint(ui, palette, strings.settings.change_hint);
            return;
        }

        let width = ui.available_width();
        widgets::secret_field(
            ui,
            &mut app.settings.new_password,
            strings.settings.new_password,
            false,
            width,
            strings.settings.new_password,
        );
        ui.add_space(theme::space::XS);
        widgets::secret_field(
            ui,
            &mut app.settings.new_password_confirm,
            strings.settings.confirm_password,
            false,
            width,
            strings.settings.confirm_password,
        );

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(strings.setup.suggest_passphrase)
                    .on_hover_text(strings.setup.suggest_passphrase_hint)
                    .clicked()
                {
                    match crate::generator::generate_passphrase(
                        crate::generator::DEFAULT_PASSPHRASE_GROUPS,
                    ) {
                        Ok((phrase, bits)) => {
                            app.settings.new_password = phrase.clone();
                            app.settings.new_password_confirm = phrase;
                            app.status = Some(Status::warn(
                                strings.setup.suggested_title,
                                fill1(strings.setup.suggested_body, format!("{bits:.0}")),
                            ));
                        }
                        Err(e) => app.status = Some(Status::error(strings, &e)),
                    }
                }
            });
        });

        widgets::strength_meter(ui, palette, strings, &app.settings.new_password);

        match check_master_password(&app.settings.new_password) {
            Some(MasterPasswordProblem::TooWeak) if !app.settings.new_password.is_empty() => {
                widgets::error_text(ui, palette, strings.setup.master_too_weak);
            }
            Some(MasterPasswordProblem::TooShort) if !app.settings.new_password.is_empty() => {
                widgets::error_text(ui, palette, strings.setup.master_too_short);
            }
            _ => {}
        }
        if app.breach.contains(&app.settings.new_password) {
            widgets::error_text(ui, palette, strings.breach.warning_master);
        }

        ui.add_space(theme::space::MD);
        widgets::notice(
            ui,
            palette,
            palette.warning,
            Icon::Warning,
            strings.settings.change_warning_title,
            strings.settings.change_warning_body,
        );

        ui.add_space(theme::space::MD);
        ui.horizontal(|ui| {
            // Same floor as the creation screen: a weak password is no
            // less dangerous for arriving later.
            let matching = check_master_password(&app.settings.new_password).is_none()
                && !app.breach.contains(&app.settings.new_password)
                && *app.settings.new_password == *app.settings.new_password_confirm;
            if widgets::primary_button(ui, palette, strings.settings.change_confirm, matching)
                .clicked()
            {
                change_master_password(app);
            }
            if ui.button(strings.common.cancel).clicked() {
                app.settings.changing_password = false;
                app.settings.new_password = Zeroizing::new(String::new());
                app.settings.new_password_confirm = Zeroizing::new(String::new());
            }
        });
    });
}

fn change_master_password(app: &mut App) {
    let strings = app.strings();
    let params = KdfParams {
        m_cost: app.settings.kdf_memory_mib * 1024,
        t_cost: app.settings.kdf_time_cost,
        p_cost: app.session.config.kdf.p_cost,
        algorithm: "argon2id".into(),
    };
    if let Err(e) = params.validate() {
        app.status = Some(Status::error(strings, &e));
        return;
    }

    let had_recovery = app
        .session
        .vault()
        .is_some_and(|v| v.data.recovery_made_at.is_some());

    let password = Secret::from_str(&app.settings.new_password);
    match app.session.change_master_password(&password, params) {
        Ok(()) => {
            app.settings.changing_password = false;
            app.settings.new_password = Zeroizing::new(String::new());
            app.settings.new_password_confirm = Zeroizing::new(String::new());

            if had_recovery {
                // The pieces rebuild the old password, so they are now paper.
                // Said as a warning, which does not fade on its own: someone
                // who misses this keeps a recovery plan that cannot work.
                if let Some(vault) = app.session.vault_mut() {
                    vault.data.recovery_made_at = None;
                    let _ = vault.save();
                }
                app.status = Some(Status::warn(
                    strings.recovery.stale_title,
                    strings.recovery.stale_body,
                ));
            } else {
                app.status = Some(Status::success(strings.settings.changed));
            }
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

fn hidden_vault_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.hidden.section);

        // Already inside the hidden vault: say so plainly. Anyone reading this
        // screen has the password, so there is nothing left to conceal from
        // them — and quietly hiding the section would be more confusing.
        if app.session.vault().is_some_and(|v| v.is_hidden()) {
            widgets::notice(
                ui,
                palette,
                palette.accent,
                Icon::Info,
                strings.hidden.in_hidden_title,
                strings.hidden.in_hidden_body,
            );
            return;
        }

        if !app.settings.creating_hidden {
            if ui.button(strings.hidden.create_button).clicked() {
                app.settings.creating_hidden = true;
            }
            widgets::hint(ui, palette, strings.hidden.explain);
            return;
        }

        widgets::notice(
            ui,
            palette,
            palette.warning,
            Icon::Warning,
            strings.hidden.warning_title,
            strings.hidden.warning_body,
        );
        ui.add_space(theme::space::SM);
        // Separate from the warning above, because it is a different kind of
        // thing: that one is about remembering two passwords, this one is
        // about destroying a vault the program is structurally unable to warn
        // you about by checking.
        widgets::notice(
            ui,
            palette,
            palette.danger,
            Icon::Warning,
            strings.hidden.replaces_existing_title,
            strings.hidden.replaces_existing_body,
        );
        ui.add_space(theme::space::MD);

        let width = ui.available_width();
        widgets::secret_field(
            ui,
            &mut app.settings.hidden_password,
            strings.hidden.password,
            false,
            width,
            strings.hidden.password,
        );
        ui.add_space(theme::space::XS);
        widgets::secret_field(
            ui,
            &mut app.settings.hidden_confirm,
            strings.hidden.confirm,
            false,
            width,
            strings.hidden.confirm,
        );

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(strings.setup.suggest_passphrase)
                    .on_hover_text(strings.setup.suggest_passphrase_hint)
                    .clicked()
                {
                    if let Ok((phrase, bits)) = crate::generator::generate_passphrase(
                        crate::generator::DEFAULT_PASSPHRASE_GROUPS,
                    ) {
                        app.settings.hidden_password = phrase.clone();
                        app.settings.hidden_confirm = phrase;
                        app.status = Some(Status::warn(
                            strings.setup.suggested_title,
                            fill1(strings.setup.suggested_body, format!("{bits:.0}")),
                        ));
                    }
                }
            });
        });

        widgets::strength_meter(ui, palette, strings, &app.settings.hidden_password);

        let matches_confirm =
            *app.settings.hidden_password == *app.settings.hidden_confirm;
        // Reusing this vault's own password would put both vaults behind one
        // secret and defeat the point entirely.
        let same_as_current = !app.settings.hidden_password.is_empty()
            && app
                .session
                .vault()
                .is_some_and(|v| !v.hidden_slot_is_free(&Secret::from_str(
                    &app.settings.hidden_password,
                )));

        if !app.settings.hidden_password.is_empty() {
            match check_master_password(&app.settings.hidden_password) {
                Some(MasterPasswordProblem::TooWeak) => {
                    widgets::error_text(ui, palette, strings.setup.master_too_weak);
                }
                Some(MasterPasswordProblem::TooShort) => {
                    widgets::error_text(ui, palette, strings.setup.master_too_short);
                }
                None => {}
            }
            if app.breach.contains(&app.settings.hidden_password) {
                widgets::error_text(ui, palette, strings.breach.warning_master);
            }
        }
        if same_as_current {
            widgets::error_text(ui, palette, strings.hidden.exists);
        }

        ui.add_space(theme::space::MD);
        ui.horizontal(|ui| {
            let ready = matches_confirm
                && !same_as_current
                && !app.breach.contains(&app.settings.hidden_password)
                && check_master_password(&app.settings.hidden_password).is_none();
            if widgets::primary_button(ui, palette, strings.hidden.create_confirm, ready)
                .clicked()
            {
                create_hidden_vault(app);
            }
            if ui.button(strings.common.cancel).clicked() {
                app.settings.creating_hidden = false;
                app.settings.hidden_password = Zeroizing::new(String::new());
                app.settings.hidden_confirm = Zeroizing::new(String::new());
            }
        });
    });
}

fn create_hidden_vault(app: &mut App) {
    let strings = app.strings();
    let password = Secret::from_str(&app.settings.hidden_password);
    let keyfiles = app.session.config.keyfiles.clone();

    let outcome = (|| -> crate::errors::Result<()> {
        let secret = crate::crypto::combine_secret(&password, &keyfiles)?;
        let vault = app
            .session
            .vault()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;
        // The new vault is written and closed immediately: opening it here
        // would mean holding two vaults at once, and the user has to lock and
        // unlock anyway to prove the password works.
        let hidden = vault.create_hidden(&secret)?;
        drop(hidden);
        Ok(())
    })();

    match outcome {
        Ok(()) => {
            app.settings.creating_hidden = false;
            app.settings.hidden_password = Zeroizing::new(String::new());
            app.settings.hidden_confirm = Zeroizing::new(String::new());
            // Said now, while it is still true: the file as it was is
            // backup 1, and five more saves will push it out.
            app.status = Some(Status::warn(
                strings.hidden.created_title,
                format!("{} {}", strings.hidden.created_body, strings.backups.hidden_note),
            ));
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

// ------------------------------------------------------------------ history

pub fn show_history_window(app: &mut App, ui: &mut egui::Ui) {
    if !app.show_history {
        return;
    }
    let palette = app.palette();
    let strings = app.strings();
    let mut open = true;
    let ctx = ui.ctx().clone();

    let Some(vault) = app.session.vault() else {
        app.show_history = false;
        return;
    };
    let verdict = vault.data.verify_audit();
    let records: Vec<(String, &'static str, String)> = vault
        .data
        .audit
        .iter()
        .rev()
        .map(|record| {
            (
                record.at.clone(),
                action_label(strings, record.action),
                record.target.clone(),
            )
        })
        .collect();
    let count = records.len();

    egui::Window::new(strings.history.title)
        .open(&mut open)
        .resizable(true)
        .collapsible(false)
        .default_width(560.0)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(&ctx, |ui| {
            match &verdict {
                Ok(()) => widgets::notice(
                    ui,
                    palette,
                    palette.success,
                    Icon::Check,
                    strings.history.intact_title,
                    &fill1(strings.history.intact_body, count),
                ),
                Err(crate::model::AuditProblem::BrokenAt(index)) => widgets::notice(
                    ui,
                    palette,
                    palette.danger,
                    Icon::Warning,
                    strings.history.broken_title,
                    &fill1(strings.history.broken_body, index + 1),
                ),
            }
            ui.add_space(theme::space::SM);
            ui.label(theme::muted(palette, strings.history.note));
            ui.add_space(theme::space::MD);

            if records.is_empty() {
                ui.label(theme::muted(palette, strings.history.empty));
                return;
            }

            egui::ScrollArea::vertical()
                .max_height(420.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("history_grid")
                        .num_columns(3)
                        .spacing([14.0, 6.0])
                        .striped(true)
                        .show(ui, |ui| {
                            for (at, action, target) in &records {
                                ui.label(theme::muted(palette, at.clone()));
                                ui.label(egui::RichText::new(*action).size(12.5));
                                ui.label(
                                    egui::RichText::new(target)
                                        .size(12.5)
                                        .color(palette.text_muted),
                                );
                                ui.end_row();
                            }
                        });
                });
        });

    if !open {
        app.show_history = false;
    }
}

fn action_label(strings: &Strings, action: crate::model::AuditAction) -> &'static str {
    use crate::model::AuditAction::*;
    match action {
        Created => strings.history.action_created,
        EntryAdded => strings.history.action_entry_added,
        EntryEdited => strings.history.action_entry_edited,
        PasswordChanged => strings.history.action_password_changed,
        EntryRenamed => strings.history.action_entry_renamed,
        EntryDeleted => strings.history.action_entry_deleted,
        AttachmentAdded => strings.history.action_attachment_added,
        AttachmentRemoved => strings.history.action_attachment_removed,
        MasterPasswordChanged => strings.history.action_master_changed,
        VaultResized => strings.history.action_vault_resized,
        RecoveryCreated => strings.history.action_recovery_created,
        WorkFactorChanged => strings.history.action_work_factor,
    }
}

fn portability_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.portable.section);

        ui.horizontal(|ui| {
            if ui.button(strings.portable.import).clicked() {
                import_vault(app);
            }
            if ui.button(strings.portable.export).clicked() {
                // Two steps on purpose: an export writes every password to
                // disk in the clear, and that should never be one stray click
                // away.
                app.settings.confirming_export = true;
            }
        });
        widgets::hint(ui, palette, strings.portable.hint);

        if !app.settings.confirming_export {
            return;
        }
        ui.add_space(theme::space::MD);
        widgets::notice(
            ui,
            palette,
            palette.danger,
            Icon::Warning,
            strings.portable.export_warning_title,
            strings.portable.export_warning_body,
        );
        ui.add_space(theme::space::MD);
        ui.horizontal(|ui| {
            if widgets::danger_button(ui, palette, strings.portable.export_csv).clicked() {
                export_vault(app, false);
            }
            if widgets::danger_button(ui, palette, strings.portable.export_json).clicked() {
                export_vault(app, true);
            }
            if ui.button(strings.common.cancel).clicked() {
                app.settings.confirming_export = false;
            }
        });
    });
}

fn export_vault(app: &mut App, as_json: bool) {
    let strings = app.strings();
    let (extension, filter) = if as_json {
        ("json", strings.portable.filter_json)
    } else {
        ("csv", strings.portable.filter_csv)
    };

    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.portable.export_title)
        .add_filter(filter, &[extension])
        .set_file_name(format!("deep-defense-export.{extension}"))
        .save_file()
    else {
        return;
    };

    let outcome = (|| -> crate::errors::Result<()> {
        let vault = app
            .session
            .vault()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;
        let text = if as_json {
            crate::portable::to_json(&vault.data)?
        } else {
            crate::portable::to_csv(&vault.data)
        };
        std::fs::write(&path, text.as_bytes())
            .map_err(|e| crate::errors::Error::io(path.clone(), e))
    })();

    app.settings.confirming_export = false;
    match outcome {
        // Deliberately a warning, not a success: the job is not done until
        // the user decides what happens to that file.
        Ok(()) => {
            app.status = Some(Status::warn(
                strings.portable.exported_title,
                fill1(strings.portable.exported_body, path.display()),
            ))
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

fn import_vault(app: &mut App) {
    let strings = app.strings();
    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.portable.import_title)
        .add_filter(strings.portable.filter_any, &["csv", "json"])
        .pick_file()
    else {
        return;
    };

    let outcome = (|| -> crate::errors::Result<crate::portable::ImportReport> {
        let text = crate::portable::read_text_file(&path)?;
        let json = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        let vault = app
            .session
            .vault_mut()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;
        let report = if json {
            crate::portable::from_json(&mut vault.data, &text)?
        } else {
            crate::portable::from_csv(&mut vault.data, &text)?
        };
        if report.added > 0 {
            vault
                .data
                .record(crate::model::AuditAction::EntryAdded, fill1(
                    strings.portable.audit_import,
                    report.added,
                ));
            vault.save()?;
        }
        Ok(report)
    })();

    match outcome {
        Ok(report) => {
            let body = format!(
                "{} · {} · {}",
                fill1(strings.portable.report_added, report.added),
                fill1(strings.portable.report_duplicates, report.duplicates),
                fill1(strings.portable.report_malformed, report.malformed),
            );
            app.status = Some(Status::warn(strings.portable.imported_title, body));
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}


// ------------------------------------------------------------------ backups

/// How one backup is described in a list: its number, when, and how large.
pub(crate) fn describe_backup(strings: &Strings, backup: &crate::vault::Backup) -> String {
    let when = backup
        .modified
        .map(|at| {
            chrono::DateTime::<chrono::Local>::from(at)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| "\u{2014}".to_string());
    fill2(
        strings.backups.entry,
        backup.index,
        format!("{when} \u{b7} {}", human_bytes(backup.bytes as usize)),
    )
}

/// The list, with a two-step restore. Returns the number the user has
/// confirmed they want back, if any.
///
/// Two steps because a restore replaces the vault file. It can be undone —
/// the replaced file becomes backup 1 — but only by someone who knows that,
/// and a single stray click is the wrong way to find out.
pub(crate) fn backups_list(
    ui: &mut egui::Ui,
    palette: &Palette,
    strings: &Strings,
    backups: &[crate::vault::Backup],
    confirming: &mut Option<usize>,
) -> Option<usize> {
    if backups.is_empty() {
        ui.label(theme::muted(palette, strings.backups.none));
        return None;
    }
    let mut chosen = None;
    for backup in backups {
        ui.horizontal(|ui| {
            ui.label(describe_backup(strings, backup));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if *confirming == Some(backup.index) {
                    if ui.button(strings.common.cancel).clicked() {
                        *confirming = None;
                    }
                    if widgets::danger_button(ui, palette, strings.backups.restore).clicked() {
                        chosen = Some(backup.index);
                    }
                } else if ui.button(strings.backups.restore).clicked() {
                    *confirming = Some(backup.index);
                }
            });
        });
    }
    if let Some(index) = *confirming {
        ui.add_space(theme::space::SM);
        widgets::notice(
            ui,
            palette,
            palette.warning,
            Icon::Warning,
            strings.backups.confirm_title,
            &fill1(strings.backups.confirm_body, index),
        );
    }
    chosen
}

fn backups_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let Some(path) = app.session.vault().map(|v| v.path.clone()) else {
        return;
    };
    let backups = crate::vault::list_backups(&path);

    let mut chosen = None;
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.backups.section);
        widgets::hint(ui, palette, strings.backups.hint);
        ui.add_space(theme::space::SM);
        chosen = backups_list(ui, palette, strings, &backups, &mut app.settings.restoring_backup);
    });

    if let Some(index) = chosen {
        restore_while_open(app, index);
    }
}

/// Restore from inside the vault. Ends locked, whatever happens.
fn restore_while_open(app: &mut App, index: usize) {
    let strings = app.strings();
    let outcome = app.session.restore_backup_and_lock(index);
    app.settings.restoring_backup = None;
    // Everything the lock button resets, reset here too. The session is
    // already locked, so this only tidies the screen.
    app.lock_now();
    app.status = Some(match outcome {
        Ok(()) => Status::warn(strings.backups.restored_title, strings.backups.restored_body),
        Err(e) => Status::error(strings, &e),
    });
}

// ------------------------------------------------------------- second copy

fn mirror_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.mirror.section);

        match app.session.config.backup_mirror.clone() {
            Some(directory) => {
                widgets::status_chip(
                    ui,
                    Icon::Check,
                    &fill1(strings.mirror.working, directory.display()),
                    palette.success,
                );
            }
            None => {
                widgets::status_chip(ui, Icon::Warning, strings.mirror.none, palette.warning);
            }
        }

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            if ui.button(strings.mirror.choose).clicked() {
                if let Some(directory) = rfd::FileDialog::new()
                    .set_title(strings.mirror.dialog_title)
                    .pick_folder()
                {
                    app.session.set_backup_mirror(Some(directory));
                    let _ = app.session.config.save();
                }
            }
            if app.session.config.backup_mirror.is_some()
                && ui.button(strings.mirror.clear).clicked()
            {
                app.session.set_backup_mirror(None);
                let _ = app.session.config.save();
            }
        });
        widgets::hint(ui, palette, strings.mirror.hint);

        // A mirror that has quietly stopped working still looks like a backup,
        // which is worse than not having one.
        if let Some(reason) = app.session.vault().and_then(|v| v.mirror_error()) {
            let reason = reason.to_string();
            ui.add_space(theme::space::MD);
            widgets::notice(
                ui,
                palette,
                palette.danger,
                Icon::Warning,
                strings.mirror.failed_title,
                &fill1(strings.mirror.failed_body, reason),
            );
        }
    });
}

// ------------------------------------------------------------- vault size

/// Sizes offered for a rebuild, in mebibytes.
const SLOT_SIZES_MIB: [u32; 5] = [1, 4, 16, 32, 64];

fn human_bytes(bytes: usize) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    let mib = bytes as f64 / MIB;
    if mib >= 1.0 {
        format!("{mib:.0} MiB")
    } else {
        format!("{:.0} KiB", bytes as f64 / 1024.0)
    }
}

fn resize_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let Some((capacity, free, kdf)) = app
        .session
        .vault()
        .map(|v| (v.slot_capacity(), v.free_capacity(), v.kdf().clone()))
    else {
        return;
    };

    // Start from what the vault actually has, so leaving the controls alone
    // means "change nothing" rather than "change to whatever was default".
    if app.settings.resize_memory_mib == 0 {
        app.settings.resize_memory_mib = kdf.memory_mib();
        app.settings.resize_time_cost = kdf.t_cost;
    }

    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.resize.section);
        widgets::info_row(
            ui,
            palette,
            strings.resize.slot_size,
            &fill2(
                strings.resize.current,
                human_bytes(capacity),
                human_bytes(free),
            ),
        );
        widgets::info_row(
            ui,
            palette,
            strings.resize.work_factor,
            &fill2(strings.resize.cost, kdf.memory_mib(), kdf.t_cost),
        );
        widgets::hint(ui, palette, strings.resize.hint);

        ui.add_space(theme::space::MD);
        widgets::field_label_first(ui, palette, strings.resize.slot_size);
        ui.horizontal(|ui| {
            for mib in SLOT_SIZES_MIB {
                let bytes = mib as usize * 1024 * 1024;
                let picked = app.settings.resize_target_mib == mib
                    || (app.settings.resize_target_mib == 0 && bytes == capacity);
                if ui.selectable_label(picked, format!("{mib} MiB")).clicked() {
                    app.settings.resize_target_mib = mib;
                }
            }
        });

        ui.add_space(theme::space::MD);
        widgets::field_label_first(ui, palette, strings.resize.work_factor);
        widgets::hint(ui, palette, strings.resize.work_factor_hint);
        ui.add_space(theme::space::XS);
        ui.horizontal(|ui| {
            ui.label(theme::muted(palette, strings.settings.kdf_memory));
            ui.add(
                egui::DragValue::new(&mut app.settings.resize_memory_mib)
                    .range(KdfParams::MIN_M_COST / 1024..=KdfParams::MAX_M_COST / 1024)
                    .speed(8.0)
                    .suffix(" MiB"),
            );
            ui.add_space(theme::space::MD);
            ui.label(theme::muted(palette, strings.settings.kdf_passes));
            ui.add(
                egui::DragValue::new(&mut app.settings.resize_time_cost)
                    .range(KdfParams::MIN_T_COST..=KdfParams::MAX_T_COST),
            );
        });

        let target_capacity = if app.settings.resize_target_mib == 0 {
            capacity
        } else {
            app.settings.resize_target_mib as usize * 1024 * 1024
        };
        let target_kdf = KdfParams {
            m_cost: app.settings.resize_memory_mib * 1024,
            t_cost: app.settings.resize_time_cost,
            p_cost: kdf.p_cost,
            algorithm: kdf.algorithm.clone(),
        };
        let cost_changed = target_kdf != kdf;
        let size_changed = target_capacity != capacity;
        if !cost_changed && !size_changed {
            return;
        }

        ui.add_space(theme::space::MD);
        widgets::notice(
            ui,
            palette,
            palette.warning,
            Icon::Warning,
            strings.resize.warning_title,
            strings.resize.warning_body,
        );

        let width = ui.available_width();
        if cost_changed {
            // Required, and verified before anything is written: re-keying to
            // a password that is not the current one would seal the vault
            // with a string nobody knows.
            ui.add_space(theme::space::MD);
            widgets::field_label_first(ui, palette, strings.resize.own_password);
            widgets::hint(ui, palette, strings.resize.own_password_hint);
            ui.add_space(theme::space::XS);
            widgets::secret_field(
                ui,
                &mut app.settings.resize_own_password,
                strings.resize.own_password,
                false,
                width,
                strings.resize.own_password,
            );
        }

        ui.add_space(theme::space::MD);
        widgets::field_label_first(ui, palette, strings.resize.carry_hidden);
        widgets::hint(
            ui,
            palette,
            if cost_changed {
                strings.resize.carry_hint_rekey
            } else {
                strings.resize.carry_hint
            },
        );
        ui.add_space(theme::space::XS);
        widgets::secret_field(
            ui,
            &mut app.settings.resize_other_password,
            strings.resize.carry_hidden,
            false,
            width,
            strings.resize.carry_hidden,
        );

        ui.add_space(theme::space::MD);
        let ready = !cost_changed || !app.settings.resize_own_password.trim().is_empty();
        if ready {
            if widgets::danger_button(ui, palette, strings.resize.apply).clicked() {
                apply_rebuild(app, target_capacity, target_kdf, capacity);
            }
        } else {
            ui.add_enabled_ui(false, |ui| {
                let _ = ui.button(strings.resize.apply);
            });
        }
    });
}

fn apply_rebuild(
    app: &mut App,
    new_capacity: usize,
    new_kdf: KdfParams,
    old_capacity: usize,
) {
    let strings = app.strings();
    let own_typed = app.settings.resize_own_password.trim().to_string();
    let other_typed = app.settings.resize_other_password.trim().to_string();
    let own = if own_typed.is_empty() {
        None
    } else {
        Some(Secret::from_str(&own_typed))
    };
    let other = if other_typed.is_empty() {
        None
    } else {
        Some(Secret::from_str(&other_typed))
    };

    let outcome = (|| -> crate::errors::Result<crate::vault::MigrationReport> {
        let vault = app
            .session
            .vault_mut()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;
        vault.rebuild(new_capacity, new_kdf, own.as_ref(), other.as_ref())
    })();

    app.settings.resize_own_password = Zeroizing::new(String::new());
    app.settings.resize_other_password = Zeroizing::new(String::new());
    match outcome {
        Ok(report) => {
            app.settings.resize_target_mib = 0;
            app.settings.resize_memory_mib = 0; // re-read from the vault
            // Mirrored into the settings so the next vault created inherits
            // the cost the user just decided was right.
            if let Some(vault) = app.session.vault() {
                app.session.config.kdf = vault.kdf().clone();
                let _ = app.session.config.save();
            }
            app.status = Some(Status::warn(
                strings.resize.done_title,
                fill2(
                    strings.resize.done_body,
                    human_bytes(report.old_capacity.min(old_capacity)),
                    human_bytes(report.new_capacity),
                ),
            ));
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

// ---------------------------------------------------------- rollback record

fn anchor_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let Some(state) = app.session.vault().map(|v| v.anchor_state()) else {
        return;
    };

    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.anchor.section);

        match state {
            crate::vault::AnchorState::Verified => {
                widgets::status_chip(ui, Icon::Check, strings.anchor.verified, palette.success);
            }
            crate::vault::AnchorState::FirstSeenHere => {
                widgets::notice(
                    ui,
                    palette,
                    palette.warning,
                    Icon::Warning,
                    strings.anchor.first_seen,
                    strings.anchor.first_seen_body,
                );
            }
            crate::vault::AnchorState::Unverifiable => {
                widgets::notice(
                    ui,
                    palette,
                    palette.warning,
                    Icon::Warning,
                    strings.anchor.unverifiable,
                    strings.anchor.unverifiable_body,
                );
            }
            crate::vault::AnchorState::Removed => {
                widgets::notice(
                    ui,
                    palette,
                    palette.danger,
                    Icon::Warning,
                    strings.anchor.removed_title,
                    strings.anchor.removed_body,
                );
            }
        }

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            if ui.button(strings.anchor.export).clicked() {
                export_anchor(app);
            }
            if ui.button(strings.anchor.import).clicked() {
                import_anchor(app);
            }
        });
        widgets::hint(ui, palette, strings.anchor.hint);
    });
}

fn export_anchor(app: &mut App) {
    let strings = app.strings();
    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.anchor.dialog_export)
        .add_filter(strings.anchor.filter, &["anchor"])
        .set_file_name("deep-defense.anchor")
        .save_file()
    else {
        return;
    };
    let outcome = app
        .session
        .vault()
        .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))
        .and_then(|vault| vault.export_anchor(&path));
    match outcome {
        Ok(()) => {
            app.status = Some(Status::success(fill1(
                strings.anchor.exported,
                path.display(),
            )))
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

fn import_anchor(app: &mut App) {
    let strings = app.strings();
    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.anchor.dialog_import)
        .add_filter(strings.anchor.filter, &["anchor"])
        .pick_file()
    else {
        return;
    };
    let outcome = match app.session.vault_mut() {
        Some(vault) => vault.import_anchor(&path),
        None => Err(crate::errors::Error::vault("the vault is not open")),
    };
    match outcome {
        Ok(()) => {
            app.status = Some(Status::warn(
                strings.anchor.imported_title,
                strings.anchor.imported_body,
            ))
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

// ------------------------------------------------------- recovery pieces

fn recovery_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.recovery.section);

        match app
            .session
            .vault()
            .and_then(|v| v.data.recovery_made_at.clone())
        {
            Some(when) => widgets::status_chip(
                ui,
                Icon::Check,
                &fill1(strings.recovery.made_on, when),
                palette.success,
            ),
            None => widgets::status_chip(
                ui,
                Icon::Warning,
                strings.recovery.none_made,
                palette.warning,
            ),
        }
        ui.add_space(theme::space::SM);
        widgets::hint(ui, palette, strings.recovery.hint);

        ui.add_space(theme::space::MD);
        ui.horizontal(|ui| {
            ui.label(theme::muted(palette, strings.recovery.threshold));
            ui.add(egui::DragValue::new(&mut app.settings.recovery_threshold).range(
                crate::shamir::MIN_THRESHOLD..=app.settings.recovery_count.max(2),
            ));
            ui.add_space(theme::space::MD);
            ui.label(theme::muted(palette, strings.recovery.count));
            ui.add(
                egui::DragValue::new(&mut app.settings.recovery_count)
                    .range(crate::shamir::MIN_THRESHOLD..=crate::shamir::MAX_SHARES),
            );
        });
        // Keep the pair sane without arguing with the user about which of the
        // two they just moved.
        if app.settings.recovery_threshold > app.settings.recovery_count {
            app.settings.recovery_threshold = app.settings.recovery_count;
        }

        ui.add_space(theme::space::MD);
        widgets::field_label_first(ui, palette, strings.recovery.confirm_password);
        let width = ui.available_width();
        widgets::secret_field(
            ui,
            &mut app.settings.recovery_password,
            strings.recovery.confirm_password,
            false,
            width,
            strings.recovery.confirm_password,
        );

        ui.add_space(theme::space::MD);
        let ready = !app.settings.recovery_password.trim().is_empty();
        if widgets::primary_button(ui, palette, strings.recovery.create, ready).clicked() {
            create_recovery_shares(app);
        }

        ui.add_space(theme::space::MD);
        ui.separator();
        ui.add_space(theme::space::SM);
        verify_recovery_panel(app, ui, palette, strings);
    });
}

/// Confirm an existing set without having to rely on it first.
fn verify_recovery_panel(
    app: &mut App,
    ui: &mut egui::Ui,
    palette: &Palette,
    strings: &Strings,
) {
    if !app.settings.recovery_verify_open {
        if ui.link(strings.recovery.verify_open).clicked() {
            app.settings.recovery_verify_open = true;
            app.settings.recovery_verify_result = None;
        }
        return;
    }

    widgets::field_label_first(ui, palette, strings.recovery.verify_open);
    widgets::hint(ui, palette, strings.recovery.verify_hint);
    ui.add_space(theme::space::SM);

    let field = ui.add(
        egui::TextEdit::multiline(&mut *app.settings.recovery_verify)
            .desired_width(f32::INFINITY)
            .desired_rows(4)
            .font(egui::TextStyle::Monospace)
            .hint_text(strings.recovery.unlock_paste),
    );
    widgets::describe(ui, &field, strings.recovery.unlock_paste);
    if field.changed() {
        // A verdict about text that has since been edited is worse than none.
        app.settings.recovery_verify_result = None;
    }

    let found = crate::shamir::parse_shares(&app.settings.recovery_verify);
    ui.add_space(theme::space::SM);
    if !found.is_empty() {
        let needed = found[0].threshold();
        widgets::status_chip(
            ui,
            Icon::Info,
            &fill2(strings.recovery.unlock_found, found.len(), needed),
            palette.accent,
        );
        ui.add_space(theme::space::SM);
    }

    ui.horizontal(|ui| {
        let enough = !found.is_empty() && found.len() >= found[0].threshold() as usize;
        if widgets::primary_button(ui, palette, strings.recovery.verify_button, enough)
            .clicked()
        {
            app.settings.recovery_verify_result = Some(verify_shares(app, &found));
        }
        if ui.button(strings.common.cancel).clicked() {
            app.settings.recovery_verify = Zeroizing::new(String::new());
            app.settings.recovery_verify_open = false;
            app.settings.recovery_verify_result = None;
        }
    });

    match app.settings.recovery_verify_result {
        Some(true) => {
            ui.add_space(theme::space::SM);
            widgets::status_chip(ui, Icon::Check, strings.recovery.verify_ok, palette.success);
        }
        Some(false) => {
            ui.add_space(theme::space::SM);
            widgets::error_text(ui, palette, strings.recovery.verify_bad);
        }
        None => {}
    }
}

/// Rebuild from the pieces and ask the vault whether that is its password.
///
/// The rebuilt password is never shown and never leaves this function.
fn verify_shares(app: &App, shares: &[crate::shamir::Share]) -> bool {
    let Ok(bytes) = crate::shamir::combine(shares) else {
        return false;
    };
    let Ok(password) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let candidate = Secret::from_str(password);
    // Through the same combination unlocking uses, or a vault with keyfiles
    // would report every correct set as wrong.
    let Ok(secret) = crate::crypto::combine_secret(&candidate, &app.session.config.keyfiles)
    else {
        return false;
    };
    app.session
        .vault()
        .is_some_and(|vault| vault.secret_opens_this_slot(&secret))
}

fn create_recovery_shares(app: &mut App) {
    let strings = app.strings();
    let typed = app.settings.recovery_password.to_string();
    let threshold = app.settings.recovery_threshold;
    let count = app.settings.recovery_count;

    let outcome = (|| -> crate::errors::Result<Vec<String>> {
        // Verify before splitting: pieces of the wrong password would look
        // perfectly valid and fail only when they were the last hope.
        let vault = app
            .session
            .vault()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;
        let typed_secret = Secret::from_str(&typed);
        let secret =
            crate::crypto::combine_secret(&typed_secret, &app.session.config.keyfiles)?;
        // Checked against the slot already open, not by opening the file a
        // second time: a second open would write the rollback record and
        // could save, all to answer a yes-or-no question.
        if !vault.secret_opens_this_slot(&secret) {
            return Err(crate::errors::Error::Authentication);
        }

        let shares = crate::shamir::split(typed.as_bytes(), threshold, count)?;
        Ok(shares.iter().map(|s| s.to_text()).collect())
    })();

    app.settings.recovery_password = Zeroizing::new(String::new());
    match outcome {
        Ok(shares) => {
            app.settings.recovery_shares = shares;
            app.show_recovery_shares = true;
            // Recorded so a later password change can say, precisely, that
            // these pieces have stopped working.
            if let Some(vault) = app.session.vault_mut() {
                vault.data.recovery_made_at = Some(crate::model::timestamp());
                vault.data.record(crate::model::AuditAction::RecoveryCreated, "");
                if let Err(e) = vault.save() {
                    app.status = Some(Status::error(strings, &e));
                }
            }
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

/// The pieces, shown once and kept nowhere.
pub fn show_recovery_window(app: &mut App, ui: &mut egui::Ui) {
    if !app.show_recovery_shares {
        return;
    }
    let strings = app.strings();
    let palette = app.session.config.appearance.palette();
    let threshold = app.settings.recovery_threshold;
    let total = app.settings.recovery_shares.len();
    let mut open = true;
    let mut save = false;
    // `open` is already borrowed by the window's own close button, so the
    // "Done" button inside sets its own flag rather than reaching for it.
    let mut finished = false;

    egui::Window::new(strings.recovery.card_heading)
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .show(ui.ctx(), |ui| {
            widgets::notice(
                ui,
                palette,
                palette.danger,
                Icon::Warning,
                strings.recovery.warning_title,
                strings.recovery.warning_body,
            );
            ui.add_space(theme::space::MD);
            ui.label(theme::muted(
                palette,
                fill1(strings.recovery.card_note, threshold),
            ));
            ui.add_space(theme::space::MD);

            egui::ScrollArea::vertical()
                .max_height(320.0)
                .show(ui, |ui| {
                    for (index, share) in app.settings.recovery_shares.iter().enumerate() {
                        widgets::card(ui, palette, |ui| {
                            ui.label(theme::label_caps(
                                palette,
                                fill2(strings.recovery.card_share, index + 1, total),
                            ));
                            ui.add_space(theme::space::XS);
                            // Selectable and monospaced: this is meant to be
                            // copied out by hand or by mouse, character for
                            // character.
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(share)
                                        .monospace()
                                        .size(13.0)
                                        .color(palette.text_strong),
                                )
                                .selectable(true)
                                .wrap(),
                            );
                        });
                        ui.add_space(theme::space::SM);
                    }
                });

            ui.add_space(theme::space::MD);
            ui.horizontal(|ui| {
                if ui.button(strings.recovery.save).clicked() {
                    save = true;
                }
                if widgets::primary_button(ui, palette, strings.recovery.done, true).clicked() {
                    finished = true;
                }
            });
        });

    if save {
        save_recovery_shares(app);
    }
    if !open || finished {
        // Kept nowhere: the moment this window closes, the only copies are
        // the ones the user made.
        app.settings.recovery_shares.clear();
        app.show_recovery_shares = false;
    }
}

fn save_recovery_shares(app: &mut App) {
    let strings = app.strings();
    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.recovery.save)
        .add_filter("text", &["txt"])
        .set_file_name("deep-defense-recovery.txt")
        .save_file()
    else {
        return;
    };

    let threshold = app.settings.recovery_threshold;
    let total = app.settings.recovery_shares.len();
    let mut text = String::new();
    for (index, share) in app.settings.recovery_shares.iter().enumerate() {
        text.push_str(strings.recovery.card_heading);
        text.push('\n');
        text.push_str(&fill2(strings.recovery.card_share, index + 1, total));
        text.push('\n');
        text.push_str(&fill1(strings.recovery.card_note, threshold));
        text.push_str("\n\n");
        text.push_str(share);
        text.push_str("\n\n\n");
    }

    match std::fs::write(&path, text.as_bytes()) {
        Ok(()) => {
            app.status = Some(Status::warn(
                strings.recovery.warning_title,
                fill1(strings.recovery.saved, path.display()),
            ))
        }
        Err(e) => {
            let error = crate::errors::Error::io(path, e);
            app.status = Some(Status::error(strings, &error));
        }
    }
}

// ------------------------------------------------------- published passwords

fn breach_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.breach.section);

        let bundled = app.breach.bundled().map(|f| f.count()).unwrap_or(0);
        widgets::info_row(
            ui,
            palette,
            strings.breach.section,
            &fill1(strings.breach.bundled_body, bundled),
        );
        if let Some(user) = app.breach.user() {
            widgets::info_row(
                ui,
                palette,
                strings.breach.import,
                &fill1(strings.breach.imported_body, user.count()),
            );
            if user.saturation() > 0.7 {
                ui.add_space(theme::space::XS);
                widgets::error_text(ui, palette, strings.breach.crowded);
            }
        }

        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            if ui.button(strings.breach.import).clicked() {
                import_wordlist(app);
            }
            if app.breach.user().is_some() && ui.button(strings.breach.forget).clicked() {
                let outcome = app.breach.forget_user();
                if let Err(e) = outcome {
                    let strings = app.strings();
                    app.status = Some(Status::error(strings, &e));
                }
            }
        });
        widgets::hint(ui, palette, strings.breach.hint);
    });
}

fn import_wordlist(app: &mut App) {
    let strings = app.strings();
    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.breach.dialog_title)
        .add_filter(strings.breach.filter, &["txt", "lst", "dic"])
        .pick_file()
    else {
        return;
    };

    let outcome = (|| -> crate::errors::Result<crate::breach::ImportSummary> {
        let text = crate::portable::read_text_file(&path)?;
        let summary = app.breach.import(&text)?;
        app.breach.save_user()?;
        Ok(summary)
    })();

    match outcome {
        Ok(summary) => {
            app.status = Some(Status::success(fill2(
                strings.breach.import_done,
                summary.added,
                summary.as_digests,
            )))
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

fn veracrypt_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.settings.section_veracrypt);
        let mut changed = false;

        changed |= widgets::text_field(
            ui,
            &mut app.settings.veracrypt_binary,
            r"C:\Program Files\VeraCrypt\VeraCrypt.exe",
            strings.settings.veracrypt_binary,
        )
        .changed();
        ui.add_space(theme::space::XS);
        changed |= widgets::text_field(
            ui,
            &mut app.settings.veracrypt_format_binary,
            r"C:\Program Files\VeraCrypt\VeraCrypt Format.exe",
            strings.settings.veracrypt_format_binary,
        )
        .changed();

        if changed {
            app.session.config.veracrypt_binary =
                std::path::PathBuf::from(app.settings.veracrypt_binary.trim());
            app.session.config.veracrypt_format_binary =
                std::path::PathBuf::from(app.settings.veracrypt_format_binary.trim());
            app.session.refresh_veracrypt();
            let _ = app.session.config.save();
        }

        ui.add_space(theme::space::SM);
        let available = app.session.veracrypt().is_available();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
            super::icons::paint(
                ui.painter(),
                if available { Icon::Check } else { Icon::Warning },
                rect,
                if available {
                    palette.success
                } else {
                    palette.danger
                },
            );
            ui.label(
                egui::RichText::new(if available {
                    strings.settings.veracrypt_found
                } else {
                    strings.settings.veracrypt_not_found
                })
                .color(if available {
                    palette.success
                } else {
                    palette.danger
                })
                .size(12.0),
            );
        });
    });
}

fn vault_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.settings.section_vault);
        let Some(vault) = app.session.vault() else {
            return;
        };
        let kdf = vault.kdf().clone();
        let suite = vault.suite();
        let location = vault.path.display().to_string();
        let mounted = app
            .session
            .mount_path()
            .map(|p| p.display().to_string());

        egui::Grid::new("vault_info")
            .num_columns(2)
            .spacing([18.0, 5.0])
            .show(ui, |ui| {
                widgets::info_row(
                    ui,
                    palette,
                    strings.settings.vault_entries,
                    &vault.data.entries.len().to_string(),
                );
                widgets::info_row(
                    ui,
                    palette,
                    strings.settings.vault_revision,
                    &vault.data.revision.to_string(),
                );
                widgets::info_row(
                    ui,
                    palette,
                    strings.settings.vault_layers,
                    if mounted.is_some() {
                        strings.settings.vault_layers_container
                    } else {
                        strings.settings.vault_layers_standalone
                    },
                );
                widgets::info_row(ui, palette, strings.settings.vault_cipher, suite.display());
                widgets::info_row(
                    ui,
                    palette,
                    strings.settings.vault_kdf,
                    &fill2(
                        strings.settings.vault_kdf_value,
                        kdf.memory_mib(),
                        kdf.t_cost,
                    ),
                );
                widgets::info_row(ui, palette, strings.settings.vault_location, &location);
                if let Some(mounted) = mounted.as_deref() {
                    widgets::info_row(ui, palette, strings.settings.vault_mounted_at, mounted);
                }
                widgets::info_row(
                    ui,
                    palette,
                    strings.settings.vault_backups,
                    &vault.available_backups().len().to_string(),
                );
                widgets::info_row(
                    ui,
                    palette,
                    strings.attachments.section,
                    &super::entries::human_size(vault.free_capacity()),
                );
            });
    });
}

// -------------------------------------------------------------------- audit

struct Finding {
    name: String,
    problem: String,
    detail: String,
    tone: FindingTone,
}

#[derive(Clone, Copy)]
enum FindingTone {
    Danger,
    Warning,
    Neutral,
}

impl FindingTone {
    fn color(self, palette: &Palette) -> egui::Color32 {
        match self {
            FindingTone::Danger => palette.danger,
            FindingTone::Warning => palette.warning,
            FindingTone::Neutral => palette.text_muted,
        }
    }
}

pub fn show_audit_window(app: &mut App, ui: &mut egui::Ui) {
    if !app.show_audit {
        return;
    }
    let palette = app.palette();
    let strings = app.strings();
    let mut open = true;
    let ctx = ui.ctx().clone();

    let findings = audit(app);
    let total = app
        .session
        .vault()
        .map(|v| v.data.entries.len())
        .unwrap_or(0);

    egui::Window::new(strings.audit.title)
        .open(&mut open)
        .resizable(true)
        .collapsible(false)
        .default_width(540.0)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(&ctx, |ui| {
            ui.label(theme::muted(palette, strings.audit.offline_note));
            ui.add_space(theme::space::MD);

            if findings.is_empty() {
                widgets::notice(
                    ui,
                    palette,
                    palette.success,
                    Icon::Shield,
                    strings.audit.all_good_title,
                    &fill1(strings.audit.all_good_body, total),
                );
                return;
            }

            widgets::notice(
                ui,
                palette,
                palette.warning,
                Icon::Warning,
                &fill2(strings.audit.needs_attention, findings.len(), total),
                "",
            );
            ui.add_space(theme::space::MD);

            egui::ScrollArea::vertical()
                .max_height(420.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for finding in &findings {
                        let tone = finding.tone.color(palette);
                        widgets::card(ui, palette, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(&finding.name)
                                        .size(13.5)
                                        .family(egui::FontFamily::Name(theme::SEMIBOLD.into())),
                                );
                                ui.label(
                                    egui::RichText::new(&finding.problem)
                                        .color(tone)
                                        .size(11.5),
                                );
                            });
                            ui.add_space(2.0);
                            ui.label(theme::muted(palette, finding.detail.clone()));
                        });
                        ui.add_space(theme::space::SM);
                    }
                });
        });

    if !open {
        app.show_audit = false;
    }
}

/// Weak, reused, published and stale passwords, found without leaving the machine.
fn audit(app: &App) -> Vec<Finding> {
    let Some(vault) = app.session.vault() else {
        return Vec::new();
    };
    let strings = app.strings();
    let warn_days = app.session.config.warn_password_age_days;

    // Count by password so reuse shows up. The map borrows the real passwords,
    // but it lives only for this function and never leaves it.
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for entry in &vault.data.entries {
        if !entry.password.is_empty() {
            *counts.entry(entry.password.as_str()).or_insert(0) += 1;
        }
    }

    let mut findings = Vec::new();
    for entry in &vault.data.entries {
        if entry.password.is_empty() {
            findings.push(Finding {
                name: entry.name.clone(),
                problem: strings.audit.problem_no_password.to_owned(),
                detail: strings.audit.detail_no_password.to_owned(),
                tone: FindingTone::Neutral,
            });
            continue;
        }

        // Checked before strength: a password already in a public dump is
        // the first thing tried whatever its entropy says, and reporting only
        // "weak" for it would understate the problem. Until now this was
        // reported in the entry editor and nowhere else, so the one screen
        // people open to ask "is anything wrong?" stayed silent about it.
        if app.breach.contains(&entry.password) {
            findings.push(Finding {
                name: entry.name.clone(),
                problem: strings.audit.problem_breached.to_owned(),
                detail: strings.audit.detail_breached.to_owned(),
                tone: FindingTone::Danger,
            });
        }

        let bits = estimate_entropy_bits(&entry.password);
        let strength = Strength::from_bits(bits);
        if matches!(strength, Strength::Critical | Strength::Weak) {
            findings.push(Finding {
                name: entry.name.clone(),
                problem: fill1(
                    strings.audit.problem_weak,
                    theme::strength_label(strings, strength),
                ),
                detail: fill1(strings.audit.detail_weak, format!("{bits:.0}")),
                tone: FindingTone::Danger,
            });
        }

        if counts.get(entry.password.as_str()).copied().unwrap_or(0) > 1 {
            findings.push(Finding {
                name: entry.name.clone(),
                problem: strings.audit.problem_reused.to_owned(),
                detail: strings.audit.detail_reused.to_owned(),
                tone: FindingTone::Danger,
            });
        }

        if let Some(days) = entry.age_days() {
            if days > warn_days {
                findings.push(Finding {
                    name: entry.name.clone(),
                    problem: strings.audit.problem_old.to_owned(),
                    detail: fill1(strings.audit.detail_old, days),
                    tone: FindingTone::Warning,
                });
            }
        }
    }
    findings
}
