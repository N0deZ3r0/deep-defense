//! First run: create the vault, optionally inside a VeraCrypt container.

use eframe::egui;

use crate::generator::{check_master_password, MasterPasswordProblem};
use crate::i18n::{fill1, Strings};

use super::app::{App, Screen, Status};
use super::icons::Icon;
use super::theme::{self, Palette};
use super::widgets;

pub struct SetupState {
    /// Where a standalone vault file goes.
    pub vault_path: String,
    /// Where a VeraCrypt container goes.
    pub container_path: String,
    pub size_mb: u64,
    pub keyfile_path: String,
    pub use_keyfile: bool,
    pub acknowledged: bool,
}

impl SetupState {
    pub fn new(config: &crate::config::Config) -> Self {
        let default_container = dirs::document_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("DeepDefense")
            .join("vault.hc");
        Self {
            vault_path: if config.vault_path.as_os_str().is_empty() {
                crate::config::default_vault_path().display().to_string()
            } else {
                config.vault_path.display().to_string()
            },
            container_path: if config.container_path.as_os_str().is_empty() {
                default_container.display().to_string()
            } else {
                config.container_path.display().to_string()
            },
            size_mb: 64,
            keyfile_path: String::new(),
            use_keyfile: false,
            acknowledged: false,
        }
    }

    /// The path the chosen mode will actually create.
    fn target_path(&self, use_container: bool) -> std::path::PathBuf {
        std::path::PathBuf::from(if use_container {
            self.container_path.trim()
        } else {
            self.vault_path.trim()
        })
    }
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let palette = app.palette();
    let strings = app.strings();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // A centred column with left-aligned contents: form labels and
            // hint paragraphs read badly when centred, headings read well.
            widgets::centered_column(ui, 640.0, |ui| {
                ui.add_space(theme::space::PAGE);

                ui.vertical_centered(|ui| {
                    ui.label(theme::heading(strings.setup.heading, 23.0));
                    ui.add_space(theme::space::XS);
                    ui.label(theme::muted(palette, strings.setup.subheading));
                });
                ui.add_space(theme::space::LG);

                mode_card(app, ui, palette, strings);
                ui.add_space(theme::space::MD);
                location_card(app, ui, palette, strings);
                ui.add_space(theme::space::MD);
                password_card(app, ui, palette, strings);
                ui.add_space(theme::space::MD);
                keyfile_card(app, ui, palette, strings);
                ui.add_space(theme::space::LG);

                let container = app.session.config.use_container;
                widgets::notice(
                    ui,
                    palette,
                    palette.warning,
                    Icon::Info,
                    strings.setup.backup_title,
                    if container {
                        strings.setup.backup_body
                    } else {
                        strings.setup.backup_body_standalone
                    },
                );
                ui.add_space(theme::space::MD);
                ui.checkbox(&mut app.setup.acknowledged, strings.setup.acknowledge);
                ui.add_space(theme::space::LG);

                action_area(app, ui, palette, strings);
                ui.add_space(theme::space::PAGE);
            });
        });
}

fn mode_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let available = app.session.veracrypt().is_available();

    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.setup.section_mode);

        let mut chosen = app.session.config.use_container;
        ui.radio_value(&mut chosen, false, strings.setup.mode_standalone);

        // Offered but disabled when VeraCrypt is absent: hiding it would leave
        // the user wondering whether the program supports containers at all.
        ui.add_enabled_ui(available, |ui| {
            ui.radio_value(&mut chosen, true, strings.setup.mode_container);
        });

        if chosen != app.session.config.use_container {
            app.session.config.use_container = chosen;
            let _ = app.session.config.save();
        }

        widgets::hint(
            ui,
            palette,
            if chosen {
                strings.setup.mode_hint_container
            } else {
                strings.setup.mode_hint_standalone
            },
        );
        if !available {
            widgets::hint(ui, palette, strings.setup.mode_container_unavailable);
        }
    });
}

fn location_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let use_container = app.session.config.use_container;

    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.setup.section_location);

        if use_container {
            widgets::path_field(
                ui,
                palette,
                &mut app.setup.container_path,
                r"C:\Users\you\Documents\DeepDefense\vault.hc",
                strings.common.browse,
                widgets::PathDialog {
                    title: strings.setup.pick_container_title,
                    filter_name: strings.setup.filter_container,
                    extensions: &["hc"],
                    save: true,
                },
            );
            widgets::hint(ui, palette, strings.setup.location_hint);

            // Only a container has a fixed size to choose; a vault file grows
            // with its contents.
            widgets::field_label(ui, palette, strings.setup.section_size);
            ui.add(
                egui::Slider::new(&mut app.setup.size_mb, 16..=2048)
                    .suffix(strings.setup.size_suffix)
                    .logarithmic(true),
            );
            widgets::hint(ui, palette, strings.setup.size_hint);
        } else {
            widgets::path_field(
                ui,
                palette,
                &mut app.setup.vault_path,
                r"C:\Users\you\Documents\DeepDefense\vault.ddv",
                strings.common.browse,
                widgets::PathDialog {
                    title: strings.setup.pick_vault_title,
                    filter_name: strings.setup.filter_vault,
                    extensions: &["ddv"],
                    save: true,
                },
            );
            widgets::hint(ui, palette, strings.setup.location_hint_standalone);
        }
    });
}

fn password_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.setup.section_master);

        let reveal = app.reveal_password;
        let width = ui.available_width();
        widgets::secret_field(
            ui,
            &mut app.password_input,
            strings.setup.master_placeholder,
            reveal,
            width,
            strings.setup.section_master,
        );
        ui.add_space(theme::space::XS);
        widgets::secret_field(
            ui,
            &mut app.password_confirm,
            strings.setup.confirm_placeholder,
            reveal,
            width,
            strings.setup.confirm_placeholder,
        );
        ui.add_space(theme::space::SM);
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.reveal_password, strings.setup.show_typing);
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
                            // Revealed on purpose: a phrase you cannot see is
                            // a phrase you cannot write down or memorise.
                            app.password_input = phrase.clone();
                            app.password_confirm = phrase;
                            app.reveal_password = true;
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

        widgets::strength_meter(ui, palette, strings, &app.password_input);

        // The floor is checked here, next to the field, rather than only when
        // the button is pressed: a refusal is far less annoying if it arrives
        // before the user has filled in everything else.
        match check_master_password(&app.password_input) {
            Some(MasterPasswordProblem::TooWeak) if !app.password_input.is_empty() => {
                widgets::error_text(ui, palette, strings.setup.master_too_weak);
            }
            Some(MasterPasswordProblem::TooShort) if !app.password_input.is_empty() => {
                widgets::error_text(ui, palette, strings.setup.master_too_short);
            }
            _ => {}
        }
        // Length and unpredictability say nothing about whether a password has
        // already been published, and a published one is the first thing tried.
        if app.breach.contains(&app.password_input) {
            widgets::error_text(ui, palette, strings.breach.warning_master);
        }
        if !app.password_confirm.is_empty() && *app.password_input != *app.password_confirm {
            widgets::error_text(ui, palette, strings.setup.mismatch);
        }
        widgets::hint(ui, palette, strings.setup.master_hint);
    });
}

fn keyfile_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    widgets::card(ui, palette, |ui| {
        ui.horizontal(|ui| {
            ui.label(theme::label_caps(palette, strings.setup.section_keyfile));
            ui.label(theme::muted(palette, strings.common.optional));
        });
        ui.add_space(theme::space::XS);
        ui.checkbox(&mut app.setup.use_keyfile, strings.setup.keyfile_enable);

        if !app.setup.use_keyfile {
            return;
        }
        ui.add_space(theme::space::SM);
        widgets::path_field(
            ui,
            palette,
            &mut app.setup.keyfile_path,
            r"E:\usb\deep-defense.key",
            strings.common.browse,
            widgets::PathDialog {
                title: strings.setup.pick_keyfile_title,
                filter_name: strings.setup.filter_keyfile,
                extensions: &["key"],
                save: true,
            },
        );
        ui.add_space(theme::space::SM);

        if ui.button(strings.setup.keyfile_generate).clicked() {
            let path = std::path::PathBuf::from(app.setup.keyfile_path.trim());
            if path.as_os_str().is_empty() {
                app.status = Some(Status::warn(
                    strings.setup.keyfile_need_path_title,
                    strings.setup.keyfile_need_path_body,
                ));
            } else {
                match crate::generator::generate_keyfile(&path, 1024) {
                    Ok(()) => app.status = Some(Status::success(strings.setup.keyfile_written)),
                    Err(e) => app.status = Some(Status::error(strings, &e)),
                }
            }
        }
        widgets::hint(ui, palette, strings.setup.keyfile_hint);
    });
}

fn action_area(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let use_container = app.session.config.use_container;
    let target = app.setup.target_path(use_container);

    // If the path already holds a vault, offer to open it. Returning to this
    // screen to re-open an existing vault is at least as common as creating a
    // new one, and refusing to overwrite is not a helpful answer.
    if target.is_file() {
        widgets::notice(
            ui,
            palette,
            palette.accent,
            Icon::Info,
            strings.setup.existing_title,
            strings.setup.existing_body,
        );
        ui.add_space(theme::space::MD);
        if widgets::primary_button(ui, palette, strings.setup.open_existing, true).clicked() {
            commit_paths(app, use_container);
            app.clear_inputs();
            app.status = None;
            app.screen = Screen::Locked;
        }
        return;
    }

    let password_ok = check_master_password(&app.password_input).is_none()
        && !app.breach.contains(&app.password_input)
        && *app.password_input == *app.password_confirm;
    let keyfile_ok = !app.setup.use_keyfile
        || std::path::Path::new(app.setup.keyfile_path.trim()).is_file();
    let ready = password_ok
        && !target.as_os_str().is_empty()
        && keyfile_ok
        && app.setup.acknowledged
        // VeraCrypt is only a prerequisite when the container layer is chosen.
        && (!use_container || app.session.veracrypt().is_available())
        && !app.busy();

    if app.setup.use_keyfile && !keyfile_ok {
        widgets::error_text(ui, palette, strings.setup.keyfile_missing);
    }
    ui.add_space(theme::space::SM);

    if widgets::primary_button(ui, palette, strings.setup.create_button, ready).clicked() {
        commit_paths(app, use_container);
        let size_bytes = app.setup.size_mb * 1024 * 1024;
        let ctx = ui.ctx().clone();
        app.start_create(&ctx, size_bytes);
    }
}

fn commit_paths(app: &mut App, use_container: bool) {
    if use_container {
        app.session.config.container_path =
            std::path::PathBuf::from(app.setup.container_path.trim());
    } else {
        app.session.config.vault_path = std::path::PathBuf::from(app.setup.vault_path.trim());
    }
    app.session.config.keyfiles = if app.setup.use_keyfile {
        vec![std::path::PathBuf::from(app.setup.keyfile_path.trim())]
    } else {
        Vec::new()
    };
    let _ = app.session.config.save();
}
