//! The lock screen.

use eframe::egui;
use zeroize::Zeroizing;

use crate::i18n::{fill1, fill2, Strings};

use super::app::{App, Screen, Status};
use super::icons::Icon;
use super::theme::{self, Palette};
use super::widgets;

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let palette = app.palette();
    let strings = app.strings();
    let available = ui.available_height();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            widgets::centered_column(ui, 430.0, |ui| {
                ui.add_space((available * 0.10).clamp(24.0, 80.0));

                ui.vertical_centered(|ui| {
                    // A large padlock: on a screen with a single field, the
                    // icon is what states the situation at a glance.
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(52.0, 52.0), egui::Sense::hover());
                    super::icons::paint(ui.painter(), Icon::LockClosed, rect, palette.accent);

                    ui.add_space(theme::space::MD);
                    ui.label(theme::heading("Deep Defense", 26.0));
                    ui.add_space(theme::space::XS);
                    let subheading = if app.session.config.use_container {
                        strings.unlock.subheading
                    } else {
                        strings.unlock.subheading_standalone
                    };
                    ui.label(theme::muted(palette, subheading));
                });
                ui.add_space(theme::space::LG);

                widgets::card(ui, palette, |ui| {
                    widgets::field_label_first(ui, palette, strings.entry.password);

                    let width = ui.available_width();
                    let response = widgets::secret_field(
                        ui,
                        &mut app.password_input,
                        strings.unlock.master_placeholder,
                        false,
                        width,
                        strings.entry.password,
                    );

                    // Put the caret here on arrival, but only when nothing
                    // else holds focus - grabbing it every frame would make
                    // the rest of the screen unclickable.
                    if !app.busy() && ui.ctx().memory(|m| m.focused().is_none()) {
                        response.request_focus();
                    }

                    let submitted = response.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter));

                    ui.add_space(theme::space::MD);
                    let can_unlock = !app.password_input.is_empty() && !app.busy();
                    let clicked =
                        widgets::primary_button(ui, palette, strings.common.unlock, can_unlock)
                            .clicked();

                    if (clicked || submitted) && can_unlock {
                        let ctx = ui.ctx().clone();
                        app.start_unlock(&ctx, crate::session::IfOlder::Refuse);
                    }

                    if !app.session.config.keyfiles.is_empty() {
                        ui.add_space(theme::space::SM);
                        ui.label(theme::muted(
                            palette,
                            fill1(
                                strings.unlock.keyfiles_used,
                                app.session.config.keyfiles.len(),
                            ),
                        ));
                        for keyfile in &app.session.config.keyfiles {
                            if !keyfile.is_file() {
                                widgets::error_text(
                                    ui,
                                    palette,
                                    &fill1(
                                        strings.unlock.keyfile_missing,
                                        keyfile.display(),
                                    ),
                                );
                            }
                        }
                    }
                });

                ui.add_space(theme::space::MD);
                recovery_panel(app, ui, palette, strings);
                ui.add_space(theme::space::SM);
                backups_panel(app, ui, palette, strings);

                ui.add_space(theme::space::MD);
                let uses_container = app.session.config.use_container;
                ui.label(theme::muted(
                    palette,
                    if uses_container {
                        fill1(
                            strings.unlock.container_label,
                            app.session.config.container_path.display(),
                        )
                    } else {
                        fill1(
                            strings.unlock.vault_label,
                            app.session.config.vault_path.display(),
                        )
                    },
                ));

                // Only a container needs VeraCrypt; a standalone vault opens
                // with nothing installed, so do not raise an alarm about it.
                if uses_container && !app.session.veracrypt().is_available() {
                    ui.add_space(theme::space::MD);
                    widgets::notice(
                        ui,
                        palette,
                        palette.danger,
                        Icon::Warning,
                        strings.unlock.veracrypt_missing_title,
                        strings.unlock.veracrypt_missing_body,
                    );
                    ui.add_space(theme::space::SM);
                    widgets::card(ui, palette, |ui| {
                        widgets::field_label_first(
                            ui,
                            palette,
                            strings.unlock.veracrypt_path_label,
                        );
                        let mut path =
                            app.session.config.veracrypt_binary.display().to_string();
                        if widgets::text_field(
                            ui,
                            &mut path,
                            r"C:\Program Files\VeraCrypt\VeraCrypt.exe",
                            strings.unlock.veracrypt_path_label,
                        )
                        .changed()
                        {
                            app.session.config.veracrypt_binary =
                                std::path::PathBuf::from(path);
                            app.session.refresh_veracrypt();
                            let _ = app.session.config.save();
                        }
                    });
                }

                ui.add_space(theme::space::LG);
                // Named for what is actually in use: the default is a plain
                // vault file, and offering "a different container" to someone
                // who never had one only makes them wonder what they missed.
                let (different, notice) = if app.session.config.use_container {
                    (strings.unlock.different_container, strings.unlock.pick_container_notice)
                } else {
                    (strings.unlock.different_vault, strings.unlock.pick_vault_notice)
                };
                if ui
                    .small_button(different)
                    .on_hover_text(strings.unlock.different_container_hint)
                    .clicked()
                {
                    app.screen = Screen::Setup;
                    app.setup = super::setup::SetupState::new(&app.session.config);
                    app.status = Some(Status::info(notice));
                }
                ui.add_space(theme::space::PAGE);
            });
        });
}

/// Rebuild the master password from recovery pieces.
///
/// Put on the unlock screen rather than in the settings, because settings
/// require an open vault — which is exactly what the person needing this does
/// not have.
fn recovery_panel(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    if !app.show_recovery_unlock {
        ui.vertical_centered(|ui| {
            if ui
                .link(strings.recovery.unlock_open)
                .on_hover_text(strings.recovery.unlock_hint)
                .clicked()
            {
                app.show_recovery_unlock = true;
            }
        });
        return;
    }

    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.recovery.unlock_paste);
        widgets::hint(ui, palette, strings.recovery.unlock_hint);
        ui.add_space(theme::space::SM);

        let field = ui.add(
            egui::TextEdit::multiline(&mut *app.recovery_input)
                .desired_width(f32::INFINITY)
                .desired_rows(6)
                .font(egui::TextStyle::Monospace)
                .hint_text(strings.recovery.unlock_paste),
        );
        widgets::describe(ui, &field, strings.recovery.unlock_paste);

        // Counting as they paste turns "it did not work" into "you have two of
        // the three you need", which is the difference between giving up and
        // going to fetch another piece.
        let found = crate::shamir::parse_shares(&app.recovery_input);
        ui.add_space(theme::space::SM);
        if found.is_empty() {
            if !app.recovery_input.trim().is_empty() {
                widgets::error_text(ui, palette, strings.recovery.unlock_none);
            }
        } else {
            let needed = found[0].threshold();
            let enough = found.len() >= needed as usize;
            widgets::status_chip(
                ui,
                if enough { Icon::Check } else { Icon::Info },
                &fill2(strings.recovery.unlock_found, found.len(), needed),
                if enough { palette.success } else { palette.accent },
            );
        }

        ui.add_space(theme::space::MD);
        ui.horizontal(|ui| {
            let ready = !found.is_empty() && found.len() >= found[0].threshold() as usize;
            if widgets::primary_button(ui, palette, strings.recovery.unlock_rebuild, ready)
                .clicked()
            {
                rebuild_password(app, &found);
            }
            if ui.button(strings.common.cancel).clicked() {
                app.recovery_input = Zeroizing::new(String::new());
                app.show_recovery_unlock = false;
            }
        });
    });
}

fn rebuild_password(app: &mut App, shares: &[crate::shamir::Share]) {
    let strings = app.strings();
    match crate::shamir::combine(shares) {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            Ok(password) => {
                app.password_input = Zeroizing::new(password.to_owned());
                // Not "unlocked": whether the pieces were the right ones is
                // answered by the vault opening, and claiming success before
                // that would be guessing.
                app.status = Some(Status::warn(
                    strings.recovery.unlock_rebuild,
                    strings.recovery.unlock_done,
                ));
                app.recovery_input = Zeroizing::new(String::new());
                app.show_recovery_unlock = false;
            }
            Err(_) => {
                let error = crate::errors::Error::format(
                    "the pieces combined, but not into a password — one of them is \
                     probably from another set",
                );
                app.status = Some(Status::error(strings, &error));
            }
        },
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

/// Restore from a backup before unlocking.
///
/// The lock screen is where a missing vault is noticed: the password that
/// used to open it no longer does. So that is where putting the file back has
/// to be possible, without first opening something else. Only for a vault
/// kept as a plain file — inside a container, the backups are on a volume
/// that is not mounted yet.
fn backups_panel(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    if app.session.config.use_container {
        return;
    }
    let path = app.session.config.vault_path.clone();
    let backups = crate::vault::list_backups(&path);
    if backups.is_empty() {
        return;
    }

    if !app.show_backups_unlock {
        ui.vertical_centered(|ui| {
            if ui.link(strings.backups.open_on_unlock).clicked() {
                app.show_backups_unlock = true;
            }
        });
        return;
    }

    let mut chosen = None;
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.backups.section);
        widgets::hint(ui, palette, strings.backups.hint);
        ui.add_space(theme::space::SM);
        chosen = super::settings::backups_list(
            ui,
            palette,
            strings,
            &backups,
            &mut app.settings.restoring_backup,
        );
        ui.add_space(theme::space::SM);
        if ui.button(strings.common.close).clicked() {
            app.show_backups_unlock = false;
            app.settings.restoring_backup = None;
        }
    });

    if let Some(index) = chosen {
        app.settings.restoring_backup = None;
        app.show_backups_unlock = false;
        app.status = Some(match crate::vault::restore_backup(&path, index) {
            Ok(()) => Status::warn(strings.backups.restored_title, strings.backups.restored_body),
            Err(e) => Status::error(strings, &e),
        });
    }
}
