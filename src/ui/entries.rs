//! The main screen: the entry list on the left, one entry's detail on the
//! right, and the password generator.

use eframe::egui;
use zeroize::Zeroizing;

use crate::generator::{estimate_entropy_bits, generate_password, Strength};
use crate::i18n::{fill1, fill2, Strings};
use crate::model::Entry;
use crate::totp::TotpConfig;

use super::app::{App, Draft, Status};
use super::icons::Icon;
use super::theme::{self, Palette};
use super::widgets;

/// What a list row needs, lifted out of the vault before we start mutating
/// `app` in response to clicks — the borrow has to end first.
struct Row {
    key: String,
    name: String,
    username: String,
    weak: bool,
    stale: bool,
    has_totp: bool,
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let palette = app.palette();
    let rows = collect_rows(app);
    let tags = app
        .session
        .vault()
        .map(|v| v.data.all_tags())
        .unwrap_or_default();

    egui::Panel::left("entry_list")
        .resizable(true)
        .default_size(300.0)
        .size_range(230.0..=460.0)
        .frame(
            egui::Frame::new()
                .fill(palette.surface)
                .inner_margin(egui::Margin::same(12))
                .stroke(egui::Stroke::new(1.0, palette.border)),
        )
        .show(ui, |ui| list_panel(app, ui, &rows, &tags));

    egui::CentralPanel::default()
        .frame(
            egui::Frame::new()
                .fill(palette.bg)
                .inner_margin(egui::Margin::same(theme::space::PAGE as i8)),
        )
        .show(ui, |ui| detail_panel(app, ui));

    delete_modal(app, ui);
}

fn collect_rows(app: &App) -> Vec<Row> {
    let Some(vault) = app.session.vault() else {
        return Vec::new();
    };
    let warn_days = app.session.config.warn_password_age_days;
    // Folded once here rather than once per entry inside the filter.
    let needle = app.search.trim().to_lowercase();
    let tag_filter = app.tag_filter.clone();

    let mut rows: Vec<Row> = vault
        .data
        .entries
        .iter()
        .filter(|entry| entry.matches_folded(&needle))
        .filter(|entry| match &tag_filter {
            Some(tag) => entry.tags.iter().any(|t| t == tag),
            None => true,
        })
        .map(|entry| Row {
            key: entry.key(),
            name: entry.name.clone(),
            username: entry.username.clone(),
            weak: !entry.password.is_empty()
                && matches!(
                    Strength::from_bits(estimate_entropy_bits(&entry.password)),
                    Strength::Critical | Strength::Weak
                ),
            stale: entry.age_days().is_some_and(|days| days > warn_days),
            has_totp: entry.has_totp(),
        })
        .collect();
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    rows
}

fn list_panel(app: &mut App, ui: &mut egui::Ui, rows: &[Row], tags: &[String]) {
    let palette = app.palette();
    let strings = app.strings();

    ui.horizontal(|ui| {
        let search_width = (ui.available_width() - 38.0).max(60.0);
        let response = ui.add(
            egui::TextEdit::singleline(&mut app.search)
                .desired_width(search_width)
                .hint_text(strings.common.search)
                .margin(egui::Margin::symmetric(9, 7)),
        );
        if std::mem::take(&mut app.focus_search) {
            response.request_focus();
        }
        if widgets::icon_button(ui, palette, Icon::Plus, strings.entry.new_button, false)
            .on_hover_text("Ctrl+N")
            .clicked()
        {
            app.draft = Some(Draft::blank());
            app.selected = None;
            app.reveal_password = false;
        }
    });

    ui.add_space(theme::space::SM);
    let total = app
        .session
        .vault()
        .map(|v| v.data.entries.len())
        .unwrap_or(0);
    ui.label(theme::muted(
        palette,
        if app.search.is_empty() && app.tag_filter.is_none() {
            fill1(strings.entry.entries_count, total)
        } else {
            fill2(strings.entry.matches_count, rows.len(), total)
        },
    ));

    if !tags.is_empty() {
        ui.add_space(theme::space::SM);
        tag_filter_row(app, ui, palette, strings, tags);
    }

    ui.add_space(theme::space::SM);
    ui.separator();
    ui.add_space(theme::space::XS);

    let mut clicked: Option<String> = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if rows.is_empty() {
                ui.add_space(theme::space::PAGE);
                ui.label(theme::muted(
                    palette,
                    if total == 0 {
                        strings.entry.empty_list
                    } else {
                        strings.entry.no_matches
                    },
                ));
                return;
            }
            for row in rows {
                let selected = app.selected.as_deref() == Some(row.key.as_str());
                if entry_row(ui, palette, strings, row, selected).clicked() {
                    clicked = Some(row.key.clone());
                }
            }
        });

    if let Some(key) = clicked {
        select_entry(app, &key);
    }

    // Arrow keys move the selection, as in any list. Suppressed while a text
    // field has focus, where the same keys move the caret.
    let typing = ui.ctx().memory(|m| m.focused().is_some());
    if !typing && !rows.is_empty() {
        let (up, down) = ui.ctx().input(|i| {
            (
                i.key_pressed(egui::Key::ArrowUp),
                i.key_pressed(egui::Key::ArrowDown),
            )
        });
        if up || down {
            let current = app
                .selected
                .as_deref()
                .and_then(|key| rows.iter().position(|r| r.key == key));
            let next = match (current, down) {
                (None, _) => 0,
                (Some(index), true) => (index + 1).min(rows.len() - 1),
                (Some(index), false) => index.saturating_sub(1),
            };
            let key = rows[next].key.clone();
            select_entry(app, &key);
        }
    }
}

fn tag_filter_row(
    app: &mut App,
    ui: &mut egui::Ui,
    palette: &Palette,
    strings: &Strings,
    tags: &[String],
) {
    let mut chosen: Option<Option<String>> = None;
    // A fixed-height strip: left to itself, a horizontal ScrollArea expands to
    // fill the panel and squeezes the entry list out of existence.
    egui::ScrollArea::horizontal()
        .id_salt("tag_filter")
        .auto_shrink([false, true])
        .max_height(26.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                if tag_chip(ui, palette, strings.entry.filter_all, app.tag_filter.is_none())
                    .clicked()
                {
                    chosen = Some(None);
                }
                for tag in tags {
                    let active = app.tag_filter.as_deref() == Some(tag.as_str());
                    if tag_chip(ui, palette, tag, active).clicked() {
                        chosen = Some(if active { None } else { Some(tag.clone()) });
                    }
                }
            });
        });
    if let Some(filter) = chosen {
        app.tag_filter = filter;
    }
}

fn tag_chip(
    ui: &mut egui::Ui,
    palette: &Palette,
    label: &str,
    active: bool,
) -> egui::Response {
    let fill = if active {
        palette.accent.gamma_multiply(0.30)
    } else {
        palette.raised
    };
    let text_color = if active {
        palette.accent
    } else {
        palette.text_muted
    };
    ui.add(
        egui::Button::new(egui::RichText::new(label).size(11.5).color(text_color))
            .fill(fill)
            .stroke(egui::Stroke::new(
                1.0,
                if active {
                    palette.accent.gamma_multiply(0.7)
                } else {
                    palette.border
                },
            ))
            .corner_radius(egui::CornerRadius::same(11))
            .min_size(egui::vec2(0.0, 22.0)),
    )
}

/// One row: name, badges, and the username underneath.
///
/// Badges are words as well as colours — a red dot alone would tell a
/// colour-blind reader nothing, and tells nobody *what* is wrong.
fn entry_row(
    ui: &mut egui::Ui,
    palette: &Palette,
    strings: &Strings,
    row: &Row,
    selected: bool,
) -> egui::Response {
    let height = if row.username.is_empty() { 34.0 } else { 46.0 };
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    // Drawn by hand, so it has to be named by hand. Without this a screen
    // reader met every entry in the list as a button called nothing — found
    // only when the screen tests went looking for an entry by its name.
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            true,
            selected,
            spoken_name(strings, row),
        )
    });

    if selected {
        ui.painter().rect_filled(
            rect,
            egui::CornerRadius::same(theme::radius::CONTROL),
            palette.accent.gamma_multiply(0.22),
        );
    } else if response.hovered() {
        ui.painter().rect_filled(
            rect,
            egui::CornerRadius::same(theme::radius::CONTROL),
            palette.raised,
        );
    }

    let text_x = rect.min.x + 10.0;
    let name_y = if row.username.is_empty() {
        rect.center().y - 8.0
    } else {
        rect.min.y + 7.0
    };
    let painter = ui.painter();

    let name_galley = painter.layout_no_wrap(
        row.name.clone(),
        egui::FontId::new(13.5, egui::FontFamily::Name(theme::SEMIBOLD.into())),
        if selected {
            palette.text_strong
        } else {
            palette.text
        },
    );
    painter.galley(
        egui::pos2(text_x, name_y),
        name_galley.clone(),
        palette.text,
    );

    // Badges flow after the name, and are dropped rather than clipped if the
    // pane is too narrow to hold them.
    let mut badge_x = text_x + name_galley.size().x + 7.0;
    for (label, color) in [
        (row.weak.then_some(strings.entry.marker_weak), palette.danger),
        (row.stale.then_some(strings.entry.marker_old), palette.warning),
        (
            row.has_totp.then_some(strings.entry.marker_totp),
            palette.text_muted,
        ),
    ] {
        let Some(label) = label else { continue };
        let galley = painter.layout_no_wrap(
            label.to_owned(),
            egui::FontId::proportional(10.5),
            color,
        );
        let width = galley.size().x + 10.0;
        if badge_x + width > rect.max.x - 6.0 {
            break;
        }
        let badge = egui::Rect::from_min_size(
            egui::pos2(badge_x, name_y + 1.0),
            egui::vec2(width, galley.size().y + 2.0),
        );
        painter.rect_filled(
            badge,
            egui::CornerRadius::same(4),
            color.gamma_multiply(0.20),
        );
        painter.galley(egui::pos2(badge_x + 5.0, name_y + 2.0), galley, color);
        badge_x += width + 4.0;
    }

    if !row.username.is_empty() {
        let galley = painter.layout(
            row.username.clone(),
            egui::FontId::proportional(11.5),
            palette.text_muted,
            rect.width() - 16.0,
        );
        painter.galley(
            egui::pos2(text_x, rect.min.y + 25.0),
            galley,
            palette.text_muted,
        );
    }

    response
}

/// What a screen reader says for a row: the name, then the badges as the
/// words they show, then the username.
fn spoken_name(strings: &Strings, row: &Row) -> String {
    let mut spoken = row.name.clone();
    for (shown, word) in [
        (row.weak, strings.entry.marker_weak),
        (row.stale, strings.entry.marker_old),
        (row.has_totp, strings.entry.marker_totp),
    ] {
        if shown {
            spoken.push_str(", ");
            spoken.push_str(word);
        }
    }
    if !row.username.is_empty() {
        spoken.push_str(", ");
        spoken.push_str(&row.username);
    }
    spoken
}

fn select_entry(app: &mut App, key: &str) {
    let draft = app
        .session
        .vault()
        .and_then(|vault| vault.data.find(key))
        .map(Draft::from_entry);
    if let Some(draft) = draft {
        app.selected = Some(key.to_string());
        app.draft = Some(draft);
        // Honour the setting rather than always hiding: someone working alone
        // at a desk may reasonably prefer to see what they are editing.
        app.reveal_password = !app.session.config.mask_passwords;
    }
}

// ------------------------------------------------------------------- detail

fn detail_panel(app: &mut App, ui: &mut egui::Ui) {
    let palette = app.palette();
    let strings = app.strings();

    if app.draft.is_none() {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.30);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), egui::Sense::hover());
            super::icons::paint(ui.painter(), Icon::Key, rect, palette.border_strong);
            ui.add_space(theme::space::MD);
            ui.label(theme::muted(palette, strings.entry.no_selection));
        });
        return;
    }

    let is_new = app
        .draft
        .as_ref()
        .is_some_and(|d| d.original_key.is_none());

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.label(theme::heading(
                if is_new {
                    strings.entry.new_title
                } else {
                    strings.entry.edit_title
                },
                19.0,
            ));
            ui.add_space(theme::space::MD);

            identity_card(app, ui, palette, strings);
            ui.add_space(theme::space::MD);
            password_card(app, ui, palette, strings);
            ui.add_space(theme::space::MD);
            totp_card(app, ui, palette, strings);
            ui.add_space(theme::space::MD);
            fields_card(app, ui, palette, strings);
            ui.add_space(theme::space::MD);
            attachments_card(app, ui, palette, strings);
            ui.add_space(theme::space::MD);
            history_section(app, ui, palette, strings);
            ui.add_space(theme::space::LG);
            action_buttons(app, ui, palette, strings, is_new);
            ui.add_space(theme::space::PAGE);
        });
}

fn identity_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let mut copy_username = false;

    widgets::card(ui, palette, |ui| {
        if let Some(draft) = app.draft.as_mut() {
            widgets::field_label_first(ui, palette, strings.entry.name);
            widgets::text_field(
                ui,
                &mut draft.name,
                strings.entry.name_placeholder,
                strings.entry.name,
            );

            widgets::field_label(ui, palette, strings.entry.username);
            ui.horizontal(|ui| {
                let width = (ui.available_width() - 38.0).max(80.0);
                let field = ui.add(
                    egui::TextEdit::singleline(&mut draft.username)
                        .desired_width(width)
                        .hint_text(strings.entry.username_placeholder)
                        .margin(egui::Margin::symmetric(9, 7)),
                );
                widgets::describe(ui, &field, strings.entry.username);
                if widgets::icon_button(ui, palette, Icon::Copy, strings.common.copy, false)
                    .clicked()
                {
                    copy_username = true;
                }
            });

            widgets::field_label(ui, palette, strings.entry.url);
            widgets::text_field(
                ui,
                &mut draft.url,
                strings.entry.url_placeholder,
                strings.entry.url,
            );

            widgets::field_label(ui, palette, strings.entry.tags);
            widgets::text_field(
                ui,
                &mut draft.tags,
                strings.entry.tags_placeholder,
                strings.entry.tags,
            );

            widgets::field_label(ui, palette, strings.entry.notes);
            ui.add(
                egui::TextEdit::multiline(&mut draft.notes)
                    .desired_width(f32::INFINITY)
                    .desired_rows(3)
                    .margin(egui::Margin::symmetric(9, 7)),
            );
        }
    });

    if copy_username {
        let value = app
            .draft
            .as_ref()
            .map(|d| d.username.clone())
            .unwrap_or_default();
        copy_to_clipboard(app, &value, strings.entry.copied_username);
    }
}

fn password_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let mut copy = false;
    let mut generate = false;
    let mut toggle_reveal = false;
    let mut autotype = false;

    widgets::card(ui, palette, |ui| {
        widgets::field_label_first(ui, palette, strings.entry.password);

        let reveal = app.reveal_password;
        if let Some(draft) = app.draft.as_mut() {
            ui.horizontal(|ui| {
                let width = (ui.available_width() - 108.0).max(90.0);
                widgets::secret_field(
                    ui,
                    &mut draft.password,
                    strings.entry.password_placeholder,
                    reveal,
                    width,
                    strings.entry.password,
                );
                if widgets::icon_button(
                    ui,
                    palette,
                    if reveal { Icon::EyeOff } else { Icon::Eye },
                    if reveal {
                        strings.common.hide
                    } else {
                        strings.common.show
                    },
                    reveal,
                )
                .clicked()
                {
                    toggle_reveal = true;
                }
                if widgets::icon_button(ui, palette, Icon::Copy, strings.common.copy, false)
                    .clicked()
                {
                    copy = true;
                }
                if widgets::icon_button(
                    ui,
                    palette,
                    Icon::Keyboard,
                    strings.entry.autotype,
                    false,
                )
                .on_hover_text(strings.entry.autotype_hint)
                .clicked()
                {
                    autotype = true;
                }
                if widgets::icon_button(
                    ui,
                    palette,
                    Icon::Refresh,
                    strings.common.generate,
                    false,
                )
                .on_hover_text("Ctrl+G")
                .clicked()
                {
                    generate = true;
                }
            });
        }

        let password = app
            .draft
            .as_ref()
            .map(|d| d.password.to_string())
            .unwrap_or_default();
        widgets::strength_meter(ui, palette, strings, &password);

        // A warning, not a refusal: the user may not be able to change that
        // site's password this minute, and blocking the save would only throw
        // away the rest of what they typed.
        if app.breach.contains(&password) {
            widgets::error_text(ui, palette, strings.breach.warning_entry);
        }
    });

    if toggle_reveal {
        app.reveal_password = !app.reveal_password;
    }
    if copy {
        let value = app
            .draft
            .as_ref()
            .map(|d| d.password.to_string())
            .unwrap_or_default();
        let seconds = app.session.config.clipboard_seconds;
        let message = fill1(strings.entry.copied_password, seconds);
        copy_to_clipboard(app, &value, &message);
    }
    if autotype {
        // The password never touches the clipboard on this path; it goes
        // straight into the window the user is about to switch to.
        let value = app
            .draft
            .as_ref()
            .map(|d| d.password.to_string())
            .unwrap_or_default();
        if !value.is_empty() {
            app.begin_autotype(&value);
        }
    }
    if generate {
        app.show_generator = true;
        regenerate(app);
    }
}

fn totp_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let mut copy_code: Option<String> = None;

    widgets::card(ui, palette, |ui| {
        ui.horizontal(|ui| {
            ui.label(theme::label_caps(palette, strings.entry.totp_section));
            ui.label(theme::muted(palette, strings.common.optional));
        });
        ui.add_space(theme::space::XS);

        if let Some(draft) = app.draft.as_mut() {
            ui.add(
                egui::TextEdit::singleline(&mut draft.totp)
                    .password(true)
                    .desired_width(f32::INFINITY)
                    .hint_text(strings.entry.totp_placeholder)
                    .margin(egui::Margin::symmetric(9, 7)),
            );
        }

        let parsed = app
            .draft
            .as_ref()
            .filter(|d| !d.totp.trim().is_empty())
            .map(|d| TotpConfig::parse(&d.totp));

        match parsed {
            None => widgets::hint(ui, palette, strings.entry.totp_hint),
            Some(Err(e)) => widgets::error_text(ui, palette, &e.to_string()),
            Some(Ok(config)) => match config.current() {
                Ok((code, remaining)) => {
                    ui.add_space(theme::space::MD);
                    ui.horizontal(|ui| {
                        // Grouped in threes: a six-digit code is read aloud
                        // and typed in pairs of three, never as one number.
                        let spaced = if code.len() == 6 {
                            format!("{} {}", &code[..3], &code[3..])
                        } else {
                            code.clone()
                        };
                        ui.label(
                            egui::RichText::new(spaced)
                                .size(25.0)
                                .color(palette.accent)
                                .monospace(),
                        );
                        ui.label(theme::muted(palette, format!("{remaining}s")));
                        if widgets::icon_button(
                            ui,
                            palette,
                            Icon::Copy,
                            strings.entry.totp_copy,
                            false,
                        )
                        .clicked()
                        {
                            copy_code = Some(code.clone());
                        }
                    });
                    ui.add_space(theme::space::XS);
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 4.0),
                        egui::Sense::hover(),
                    );
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(2), palette.sunken);
                    let fraction = remaining as f32 / config.period as f32;
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(
                            rect.min,
                            egui::vec2(rect.width() * fraction, rect.height()),
                        ),
                        egui::CornerRadius::same(2),
                        palette.accent,
                    );
                }
                Err(e) => widgets::error_text(ui, palette, &e.to_string()),
            },
        }
    });

    if let Some(code) = copy_code {
        copy_to_clipboard(app, &code, strings.entry.copied_code);
    }
}

/// Named values beside the password.
fn fields_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let mut copy: Option<String> = None;
    let mut remove: Option<usize> = None;
    let mut add = false;

    widgets::card(ui, palette, |ui| {
        ui.horizontal(|ui| {
            ui.label(theme::label_caps(palette, strings.entry.fields_section));
            ui.label(theme::muted(palette, strings.common.optional));
        });
        ui.add_space(theme::space::XS);

        let Some(draft) = app.draft.as_mut() else {
            return;
        };
        if draft.fields.is_empty() {
            ui.label(theme::muted(palette, strings.entry.fields_none));
        }

        for (index, field) in draft.fields.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut field.name)
                        .desired_width(110.0)
                        .hint_text(strings.entry.field_name)
                        .margin(egui::Margin::symmetric(8, 6)),
                );
                let value_width = (ui.available_width() - 140.0).max(70.0);
                ui.add(
                    egui::TextEdit::singleline(&mut field.value)
                        .password(field.secret)
                        .desired_width(value_width)
                        .hint_text(strings.entry.field_value)
                        .margin(egui::Margin::symmetric(8, 6)),
                );
                if widgets::icon_button(
                    ui,
                    palette,
                    if field.secret { Icon::EyeOff } else { Icon::Eye },
                    strings.entry.field_secret,
                    field.secret,
                )
                .clicked()
                {
                    field.secret = !field.secret;
                }
                if widgets::icon_button(ui, palette, Icon::Copy, strings.common.copy, false)
                    .clicked()
                {
                    copy = Some(field.value.clone());
                }
                if widgets::icon_button(ui, palette, Icon::Trash, strings.common.delete, false)
                    .clicked()
                {
                    remove = Some(index);
                }
            });
        }

        ui.add_space(theme::space::SM);
        if ui.button(strings.entry.field_add).clicked() {
            add = true;
        }
    });

    if let Some(index) = remove {
        if let Some(draft) = app.draft.as_mut() {
            draft.fields.remove(index);
        }
    }
    if add {
        if let Some(draft) = app.draft.as_mut() {
            draft.fields.push(crate::model::CustomField {
                name: String::new(),
                value: String::new(),
                // Secret by default: it is easier to reveal a field than to
                // notice that a PIN has been sitting in plain view.
                secret: true,
            });
        }
    }
    if let Some(value) = copy {
        let seconds = app.session.config.clipboard_seconds;
        let message = fill1(strings.entry.copied_password, seconds);
        copy_to_clipboard(app, &value, &message);
    }
}

/// Files kept inside the entry.
///
/// Works on the saved entry rather than the draft: an attachment is a file on
/// disk, not a text field, so there is nothing to "cancel" — adding one writes
/// straight through, and the button is simply unavailable until the entry has
/// been saved once.
fn attachments_card(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let Some(key) = app.selected.clone() else {
        return;
    };

    let listed: Vec<(String, usize)> = app
        .session
        .vault()
        .and_then(|vault| vault.data.find(&key))
        .map(|entry| {
            entry
                .attachments
                .iter()
                .map(|a| (a.name.clone(), a.size))
                .collect()
        })
        .unwrap_or_default();
    let free = app.session.vault().map(|v| v.free_capacity()).unwrap_or(0);

    let mut add = false;
    let mut save: Option<String> = None;
    let mut remove: Option<String> = None;

    widgets::card(ui, palette, |ui| {
        ui.horizontal(|ui| {
            ui.label(theme::label_caps(palette, strings.attachments.section));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(theme::muted(
                    palette,
                    fill1(strings.attachments.space_left, human_size(free)),
                ));
            });
        });
        ui.add_space(theme::space::XS);

        if listed.is_empty() {
            ui.label(theme::muted(palette, strings.attachments.none));
        }
        for (name, size) in &listed {
            ui.horizontal(|ui| {
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(15.0, 15.0), egui::Sense::hover());
                super::icons::paint(ui.painter(), Icon::Copy, rect, palette.text_muted);
                ui.label(egui::RichText::new(name).size(13.0));
                ui.label(theme::muted(palette, human_size(*size)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if widgets::icon_button(
                        ui,
                        palette,
                        Icon::Trash,
                        strings.attachments.remove,
                        false,
                    )
                    .clicked()
                    {
                        remove = Some(name.clone());
                    }
                    if ui.small_button(strings.attachments.save_as).clicked() {
                        save = Some(name.clone());
                    }
                });
            });
        }

        ui.add_space(theme::space::SM);
        if ui.button(strings.attachments.add).clicked() {
            add = true;
        }
        widgets::hint(ui, palette, strings.attachments.hint);
    });

    if add {
        add_attachment(app, &key, free);
    }
    if let Some(name) = save {
        save_attachment(app, &key, &name);
    }
    if let Some(name) = remove {
        remove_attachment(app, &key, &name);
    }
}

fn add_attachment(app: &mut App, key: &str, free: usize) {
    let strings = app.strings();
    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.attachments.pick_title)
        .pick_file()
    else {
        return;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        app.status = Some(Status::warn(
            strings.attachments.read_failed,
            path.display().to_string(),
        ));
        return;
    };
    // Base64 costs a third on top, and the check has to be against what will
    // actually be stored rather than the file's size on disk.
    let stored = bytes.len().div_ceil(3) * 4;
    if stored >= free {
        app.status = Some(Status::warn(
            fill1(strings.attachments.too_large, human_size(free)),
            path.display().to_string(),
        ));
        return;
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "attachment".into());
    let attachment = crate::model::Attachment::new(name.clone(), &bytes);

    let outcome = (|| -> crate::errors::Result<()> {
        let vault = app
            .session
            .vault_mut()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;
        let entry = vault
            .data
            .find_mut(key)
            .ok_or_else(|| crate::errors::Error::EntryNotFound(key.to_string()))?;
        entry.attachments.push(attachment);
        entry.touch();
        vault
            .data
            .record(crate::model::AuditAction::AttachmentAdded, &name);
        vault.save()
    })();

    match outcome {
        Ok(()) => app.status = Some(Status::success(strings.attachments.added)),
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

fn save_attachment(app: &mut App, key: &str, name: &str) {
    let strings = app.strings();
    let bytes = app
        .session
        .vault()
        .and_then(|vault| vault.data.find(key))
        .and_then(|entry| entry.attachments.iter().find(|a| a.name == name))
        .and_then(|a| a.decode());
    let Some(bytes) = bytes else {
        return;
    };

    let Some(path) = rfd::FileDialog::new()
        .set_title(strings.attachments.save_title)
        .set_file_name(name)
        .save_file()
    else {
        return;
    };
    // Writing it out puts a plaintext copy on disk, which is the user's call
    // to make - but it is worth being clear that it happened.
    match std::fs::write(&path, &*bytes) {
        Ok(()) => app.status = Some(Status::warn(
            strings.attachments.saved,
            path.display().to_string(),
        )),
        Err(e) => {
            let error = crate::errors::Error::io(path, e);
            app.status = Some(Status::error(strings, &error));
        }
    }
}

fn remove_attachment(app: &mut App, key: &str, name: &str) {
    let strings = app.strings();
    let outcome = (|| -> crate::errors::Result<()> {
        let vault = app
            .session
            .vault_mut()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;
        let entry = vault
            .data
            .find_mut(key)
            .ok_or_else(|| crate::errors::Error::EntryNotFound(key.to_string()))?;
        entry.attachments.retain(|a| a.name != name);
        entry.touch();
        vault
            .data
            .record(crate::model::AuditAction::AttachmentRemoved, name);
        vault.save()
    })();

    match outcome {
        Ok(()) => app.status = Some(Status::success(strings.attachments.removed)),
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

/// Bytes as something a person reads without counting digits.
pub fn human_size(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn history_section(app: &mut App, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
    let Some(key) = app.selected.clone() else {
        return;
    };
    let history: Vec<(String, String)> = app
        .session
        .vault()
        .and_then(|vault| vault.data.find(&key))
        .map(|entry| {
            entry
                .history
                .iter()
                .map(|h| (h.password.clone(), h.replaced_at.clone()))
                .collect()
        })
        .unwrap_or_default();

    if history.is_empty() {
        return;
    }

    let mut copy: Option<String> = None;
    egui::CollapsingHeader::new(fill1(strings.entry.history_title, history.len()))
        .default_open(false)
        .show(ui, |ui| {
            widgets::hint(ui, palette, strings.entry.history_hint);
            ui.add_space(theme::space::SM);
            for (password, replaced_at) in &history {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(mask(password))
                            .monospace()
                            .color(palette.text_muted),
                    );
                    ui.label(theme::muted(palette, replaced_at.clone()));
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            if widgets::icon_button(
                                ui,
                                palette,
                                Icon::Copy,
                                strings.common.copy,
                                false,
                            )
                            .clicked()
                            {
                                copy = Some(password.clone());
                            }
                        },
                    );
                });
            }
        });

    if let Some(password) = copy {
        copy_to_clipboard(app, &password, strings.entry.copied_old);
    }
}

/// Show the first two characters and hide the rest.
///
/// Enough to recognise which old password a row is, not enough for a
/// shoulder-surfer to take anything away.
fn mask(password: &str) -> String {
    let total = password.chars().count();
    let visible = total.min(2);
    let head: String = password.chars().take(visible).collect();
    format!("{head}{}", "•".repeat(total - visible))
}

fn action_buttons(
    app: &mut App,
    ui: &mut egui::Ui,
    palette: &Palette,
    strings: &Strings,
    is_new: bool,
) {
    let can_save = app
        .draft
        .as_ref()
        .is_some_and(|d| !d.name.trim().is_empty());

    ui.horizontal(|ui| {
        if widgets::primary_button(ui, palette, strings.common.save, can_save)
            .on_hover_text("Ctrl+S")
            .clicked()
        {
            commit_draft(app);
        }
        if ui.button(strings.common.cancel).clicked() {
            app.draft = None;
            app.selected = None;
            app.reveal_password = false;
        }
        if !is_new {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::danger_button(ui, palette, strings.common.delete).clicked() {
                    app.confirm_delete = app.selected.clone();
                }
            });
        }
    });

    if !can_save {
        widgets::error_text(ui, palette, strings.entry.needs_name);
    }
}

fn commit_draft(app: &mut App) {
    let strings = app.strings();
    let Some(draft) = app.draft.take() else {
        return;
    };
    let tags = draft.parsed_tags();
    let name = draft.name.trim().to_string();

    let result = (|| -> crate::errors::Result<String> {
        let vault = app
            .session
            .vault_mut()
            .ok_or_else(|| crate::errors::Error::vault("the vault is not open"))?;

        match draft.original_key.clone() {
            Some(original) => {
                if original != name.to_lowercase() {
                    vault.rename(&original, &name)?;
                }
                let entry = vault
                    .data
                    .find_mut(&name)
                    .ok_or_else(|| crate::errors::Error::EntryNotFound(name.clone()))?;
                let username = draft.username.trim().to_string();
                let url = draft.url.trim().to_string();
                let totp = draft.totp.trim().to_string();
                // Blank rows are the ones the user added and then thought
                // better of; saving them would clutter every future edit.
                let fields: Vec<crate::model::CustomField> = draft
                    .fields
                    .iter()
                    .filter(|f| !f.name.trim().is_empty() || !f.value.is_empty())
                    .cloned()
                    .collect();

                // Compared before assigning, because the log is only useful if
                // "edited" means something changed. Opening a record and
                // closing it again must not push the real events off the end.
                let edited = entry.username != username
                    || entry.url != url
                    || entry.notes != *draft.notes
                    || entry.totp_secret != totp
                    || entry.tags != tags
                    || entry.fields.len() != fields.len()
                    || entry.fields.iter().zip(&fields).any(|(before, after)| {
                        before.name != after.name
                            || before.value != after.value
                            || before.secret != after.secret
                    });

                entry.username = username;
                entry.url = url;
                entry.notes = draft.notes.clone();
                entry.totp_secret = totp;
                entry.tags = tags;
                entry.fields = fields;
                // Pushes the old value onto the history only if it changed.
                let password_changed = entry.set_password(draft.password.to_string());

                // A password change is its own line: it is the one edit worth
                // spotting at a glance in a list of five hundred.
                if password_changed {
                    vault
                        .data
                        .record(crate::model::AuditAction::PasswordChanged, &name);
                }
                if edited {
                    vault.data.record(crate::model::AuditAction::EntryEdited, &name);
                }
                vault.mark_dirty();
            }
            None => {
                let mut entry = Entry::new(&name);
                entry.username = draft.username.trim().to_string();
                entry.url = draft.url.trim().to_string();
                entry.notes = draft.notes.clone();
                entry.totp_secret = draft.totp.trim().to_string();
                entry.tags = tags;
                entry.fields = draft
                    .fields
                    .iter()
                    .filter(|f| !f.name.trim().is_empty() || !f.value.is_empty())
                    .cloned()
                    .collect();
                entry.set_password(draft.password.to_string());
                vault.add(entry)?;
            }
        }
        vault.save()?;
        Ok(name.to_lowercase())
    })();

    match result {
        Ok(key) => {
            app.status = Some(Status::success(strings.shell.saved));
            select_entry(app, &key);
        }
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

fn delete_modal(app: &mut App, ui: &mut egui::Ui) {
    let Some(key) = app.confirm_delete.clone() else {
        return;
    };
    let palette = app.palette();
    let strings = app.strings();
    let name = app
        .session
        .vault()
        .and_then(|v| v.data.find(&key))
        .map(|e| e.name.clone())
        .unwrap_or_else(|| key.clone());

    egui::Modal::new(egui::Id::new("delete")).show(ui.ctx(), |ui| {
        ui.set_width(400.0);
        widgets::notice(
            ui,
            palette,
            palette.danger,
            Icon::Trash,
            &fill1(strings.entry.delete_title, name),
            strings.entry.delete_body,
        );
        ui.add_space(theme::space::MD);
        ui.horizontal(|ui| {
            if widgets::danger_button(ui, palette, strings.common.delete).clicked() {
                let outcome = app
                    .session
                    .vault_mut()
                    .map(|vault| vault.remove(&key).and_then(|_| vault.save()));
                match outcome {
                    Some(Ok(())) => {
                        app.status = Some(Status::success(strings.entry.deleted));
                        app.draft = None;
                        app.selected = None;
                    }
                    Some(Err(e)) => app.status = Some(Status::error(strings, &e)),
                    None => {}
                }
                app.confirm_delete = None;
            }
            if ui.button(strings.common.cancel).clicked() {
                app.confirm_delete = None;
            }
        });

        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            app.confirm_delete = None;
        }
    });
}

fn copy_to_clipboard(app: &mut App, value: &str, message: &str) {
    let strings = app.strings();
    let seconds = app.session.config.clipboard_seconds;
    match app.session.clipboard.copy_secret(value, seconds) {
        Ok(()) => app.status = Some(Status::success(message)),
        Err(e) => app.status = Some(Status::error(strings, &e)),
    }
}

// ---------------------------------------------------------------- generator

fn regenerate(app: &mut App) {
    let strings = app.strings();
    match generate_password(&app.generator_policy) {
        Ok(password) => app.generator_preview = password,
        Err(e) => {
            app.generator_preview = Zeroizing::new(String::new());
            app.status = Some(Status::error(strings, &e));
        }
    }
}

pub fn show_generator_window(app: &mut App, ui: &mut egui::Ui) {
    if !app.show_generator {
        return;
    }
    let palette = app.palette();
    let strings = app.strings();
    let mut open = true;
    let mut changed = false;
    let mut use_it = false;
    let mut copy = false;
    let ctx = ui.ctx().clone();

    egui::Window::new(strings.generator.title)
        .open(&mut open)
        .resizable(false)
        .collapsible(false)
        .default_width(430.0)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(&ctx, |ui| {
            if app.generator_preview.is_empty() {
                regenerate(app);
            }

            // Read-only display: the password is edited by regenerating, not
            // by typing, so an editable field would only invite confusion.
            egui::Frame::new()
                .fill(palette.sunken)
                .stroke(egui::Stroke::new(1.0, palette.border))
                .corner_radius(egui::CornerRadius::same(theme::radius::CONTROL))
                .inner_margin(egui::Margin::symmetric(10, 12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        egui::RichText::new(app.generator_preview.as_str())
                            .monospace()
                            .size(15.0),
                    );
                });

            ui.add_space(theme::space::SM);
            ui.label(
                egui::RichText::new(fill1(
                    strings.generator.entropy,
                    format!("{:.0}", app.generator_policy.entropy_bits()),
                ))
                .color(palette.success)
                .size(12.0),
            );

            ui.add_space(theme::space::MD);
            changed |= ui
                .add(
                    egui::Slider::new(&mut app.generator_policy.length, 8..=128)
                        .text(strings.generator.length),
                )
                .changed();
            ui.add_space(theme::space::XS);
            changed |= ui
                .checkbox(&mut app.generator_policy.use_lower, strings.generator.lowercase)
                .changed();
            changed |= ui
                .checkbox(&mut app.generator_policy.use_upper, strings.generator.uppercase)
                .changed();
            changed |= ui
                .checkbox(&mut app.generator_policy.use_digits, strings.generator.digits)
                .changed();
            changed |= ui
                .checkbox(&mut app.generator_policy.use_symbols, strings.generator.symbols)
                .changed();
            changed |= ui
                .checkbox(
                    &mut app.generator_policy.avoid_ambiguous,
                    strings.generator.avoid_ambiguous,
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut app.generator_policy.require_each_class,
                    strings.generator.require_each,
                )
                .changed();

            ui.add_space(theme::space::MD);
            ui.horizontal(|ui| {
                if widgets::primary_button(
                    ui,
                    palette,
                    strings.generator.use_this,
                    app.draft.is_some(),
                )
                .clicked()
                {
                    use_it = true;
                }
                if ui.button(strings.generator.another).clicked() {
                    changed = true;
                }
                if ui.button(strings.common.copy).clicked() {
                    copy = true;
                }
            });
        });

    if changed {
        regenerate(app);
    }
    if copy {
        let value = app.generator_preview.to_string();
        let seconds = app.session.config.clipboard_seconds;
        let message = fill1(strings.entry.copied_password, seconds);
        copy_to_clipboard(app, &value, &message);
    }
    if use_it {
        let generated = app.generator_preview.clone();
        if let Some(draft) = app.draft.as_mut() {
            draft.password = generated;
        }
        app.show_generator = false;
        app.reveal_password = true;
    }
    if !open {
        app.show_generator = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking_shows_two_characters_and_hides_the_length_change() {
        assert_eq!(mask("password"), "pa••••••");
        assert_eq!(mask("ab"), "ab");
        assert_eq!(mask("a"), "a");
        assert_eq!(mask(""), "");
    }

    fn row(name: &str, username: &str, weak: bool, stale: bool, has_totp: bool) -> Row {
        Row {
            key: name.to_lowercase(),
            name: name.into(),
            username: username.into(),
            weak,
            stale,
            has_totp,
        }
    }

    #[test]
    fn a_row_is_spoken_with_its_badges_as_words() {
        use crate::i18n::{EN, RU};
        for strings in [&EN, &RU] {
            let spoken = spoken_name(strings, &row("GitHub", "octo@example.com", true, false, true));
            assert!(spoken.starts_with("GitHub"), "{spoken}");
            assert!(spoken.contains(strings.entry.marker_weak), "{spoken}");
            assert!(spoken.contains(strings.entry.marker_totp), "{spoken}");
            assert!(!spoken.contains(strings.entry.marker_old), "{spoken}");
            assert!(spoken.ends_with("octo@example.com"), "{spoken}");
        }
        assert_eq!(spoken_name(&EN, &row("Router", "", false, false, false)), "Router");
    }

    #[test]
    fn every_entry_in_the_list_is_named_for_a_screen_reader() {
        // The rows are painted by hand, which is how they came to be the one
        // clickable thing in the program announced as nothing.
        use crate::i18n::EN;
        let rows = [
            row("GitHub", "octo@example.com", false, true, false),
            row("Router", "", true, false, false),
        ];
        let ctx = egui::Context::default();
        theme::apply(&ctx, theme::Appearance::Dark);
        ctx.enable_accesskit();
        let mut draw = |ui: &mut egui::Ui| {
            for (index, row) in rows.iter().enumerate() {
                entry_row(ui, &theme::DARK, &EN, row, index == 0);
            }
        };
        // Two passes: the first lays out, the second reports on it.
        let mut output = ctx.run_ui(Default::default(), &mut draw);
        output.textures_delta.clear();
        let mut output = ctx.run_ui(Default::default(), &mut draw);
        output.textures_delta.clear();

        let nodes = output
            .platform_output
            .accesskit_update
            .expect("accesskit was enabled, so a tree must come back")
            .nodes;
        for row in &rows {
            let named = nodes.iter().any(|(_, node)| {
                node.role() == egui::accesskit::Role::Button
                    && node.label().is_some_and(|label| label.starts_with(row.name.as_str()))
            });
            assert!(named, "{} is not announced by name", row.name);
        }
    }

    #[test]
    fn masking_counts_characters_not_bytes() {
        // A byte-based implementation would panic or mis-count here.
        assert_eq!(mask("пароль"), "па••••");
        assert_eq!(mask("日本語パス"), "日本•••");
    }
}
