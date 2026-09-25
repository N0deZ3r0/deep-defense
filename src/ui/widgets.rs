//! Reusable pieces of the interface.
//!
//! Every screen draws its controls through here, so a spacing or radius
//! decision is made once. The alternative — tuning padding at each call site —
//! is how an interface ends up with six slightly different buttons.

use eframe::egui::{self, Color32, CornerRadius, Margin, Rect, Response, Sense, Stroke, StrokeKind,
                   Ui, Vec2, WidgetInfo, WidgetType};

use super::icons::{self, Icon};
use super::theme::{self, Palette};

/// A fixed-width column centred in the available space, whose contents are
/// laid out left-aligned.
///
/// `ui.vertical_centered` would centre the children too, which centres form
/// labels and hint paragraphs — readable for a heading, wrong for a form.
pub fn centered_column<R>(
    ui: &mut Ui,
    width: f32,
    contents: impl FnOnce(&mut Ui) -> R,
) -> Option<R> {
    let mut out = None;
    ui.horizontal(|ui| {
        let pad = ((ui.available_width() - width) / 2.0).max(0.0);
        ui.add_space(pad);
        ui.allocate_ui_with_layout(
            Vec2::new(width.min(ui.available_width()), ui.available_height()),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_max_width(width);
                out = Some(contents(ui));
            },
        );
    });
    out
}

/// A bordered block grouping one decision.
pub fn card<R>(ui: &mut Ui, palette: &Palette, contents: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(palette.surface)
        .stroke(Stroke::new(1.0, palette.border))
        .corner_radius(CornerRadius::same(theme::radius::CARD))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contents(ui)
        })
        .inner
}

/// A small uppercase caption above a field.
pub fn field_label(ui: &mut Ui, palette: &Palette, text: &str) {
    ui.add_space(theme::space::MD);
    ui.label(theme::label_caps(palette, text));
    ui.add_space(theme::space::XS);
}

/// The same, without the leading gap — for the first label in a card.
pub fn field_label_first(ui: &mut Ui, palette: &Palette, text: &str) {
    ui.label(theme::label_caps(palette, text));
    ui.add_space(theme::space::XS);
}

/// Explanatory text under a control.
pub fn hint(ui: &mut Ui, palette: &Palette, text: &str) {
    ui.add_space(theme::space::XS);
    ui.label(theme::muted(palette, text));
}

pub fn error_text(ui: &mut Ui, palette: &Palette, text: &str) {
    ui.add_space(theme::space::XS);
    ui.label(egui::RichText::new(text).color(palette.danger).size(12.5));
}

/// Give a widget a name for anyone who cannot see it.
///
/// A field's caption is drawn as a separate label above the box, which leaves
/// a screen reader announcing "edit, blank" with no idea what goes in it. This
/// writes the name onto the field's own node instead of relying on a relation
/// a call site has to remember to declare.
///
/// Free when nobody is listening: egui builds these nodes only once a screen
/// reader has asked it to.
pub fn describe(ui: &Ui, response: &Response, name: &str) {
    ui.ctx().accesskit_node_builder(response.id, |node| {
        node.set_label(name.to_owned());
    });
}

/// A single-line text field that fills the available width.
///
/// `name` is what the field is called out loud. It is a required argument
/// rather than an option because an unnamed field is a defect, and one that
/// nobody who can see the screen will ever notice.
pub fn text_field(
    ui: &mut Ui,
    value: &mut String,
    placeholder: &str,
    name: &str,
) -> Response {
    let response = ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(f32::INFINITY)
            .hint_text(placeholder)
            .margin(Margin::symmetric(9, 7)),
    );
    describe(ui, &response, name);
    response
}

/// A password field, masked unless `reveal`.
pub fn secret_field(
    ui: &mut Ui,
    value: &mut String,
    placeholder: &str,
    reveal: bool,
    width: f32,
    name: &str,
) -> Response {
    let response = ui.add(
        egui::TextEdit::singleline(value)
            .password(!reveal)
            .desired_width(width)
            .hint_text(placeholder)
            .margin(Margin::symmetric(9, 7))
            // Monospace so a revealed password can actually be read character
            // by character - the whole reason for revealing it.
            .font(if reveal {
                egui::TextStyle::Monospace
            } else {
                egui::TextStyle::Body
            }),
    );
    describe(ui, &response, name);
    response
}

/// The one emphasised action on a screen.
pub fn primary_button(ui: &mut Ui, palette: &Palette, text: &str, enabled: bool) -> Response {
    let fill = if enabled {
        palette.accent
    } else {
        palette.raised
    };
    let text_color = if enabled {
        palette.on_accent
    } else {
        palette.text_muted
    };
    ui.add_enabled(
        enabled,
        egui::Button::new(
            egui::RichText::new(text)
                .color(text_color)
                .size(14.0)
                .family(egui::FontFamily::Name(theme::SEMIBOLD.into())),
        )
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(theme::radius::CONTROL))
        .min_size(Vec2::new(0.0, 34.0)),
    )
}

/// A destructive action: red text, never a red fill.
///
/// A big red block invites the misclick it is warning about; red lettering on
/// a neutral button reads as "careful" without drawing the eye to it.
pub fn danger_button(ui: &mut Ui, palette: &Palette, text: &str) -> Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(palette.danger))
            .fill(palette.raised)
            .stroke(Stroke::new(1.0, palette.danger.gamma_multiply(0.5)))
            .corner_radius(CornerRadius::same(theme::radius::CONTROL)),
    )
}

/// An icon-only square button. `tooltip` is mandatory: an unlabelled icon
/// that does not say what it does is a guessing game.
pub fn icon_button(
    ui: &mut Ui,
    palette: &Palette,
    icon: Icon,
    tooltip: &str,
    active: bool,
) -> Response {
    let size = Vec2::splat(30.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    let hovered = response.hovered();
    let fill = if active {
        palette.accent.gamma_multiply(0.28)
    } else if hovered {
        palette.raised
    } else {
        Color32::TRANSPARENT
    };
    if fill != Color32::TRANSPARENT {
        ui.painter().rect_filled(
            rect,
            CornerRadius::same(theme::radius::CONTROL),
            fill,
        );
    }
    if active {
        ui.painter().rect_stroke(
            rect,
            CornerRadius::same(theme::radius::CONTROL),
            Stroke::new(1.0, palette.accent),
            StrokeKind::Inside,
        );
    }

    let color = if active {
        palette.accent
    } else if hovered {
        palette.text_strong
    } else {
        palette.text_muted
    };
    let inner = Rect::from_center_size(rect.center(), Vec2::splat(16.0));
    icons::paint(ui.painter(), icon, inner, color);

    // Without this the control is a nameless rectangle to a screen reader.
    // The tooltip is the right name: it already says what the button does,
    // and it is already translated.
    let enabled = ui.is_enabled();
    response.widget_info(|| {
        WidgetInfo::selected(WidgetType::Button, enabled, active, tooltip)
    });

    response.on_hover_text(tooltip)
}

/// A toolbar button with an icon and a label.
pub fn tool_button(
    ui: &mut Ui,
    palette: &Palette,
    icon: Icon,
    label: &str,
    active: bool,
) -> Response {
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::TextStyle::Button.resolve(ui.style()),
        palette.text,
    );
    let width = 16.0 + 6.0 + galley.size().x + 20.0;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 30.0), Sense::click());

    let hovered = response.hovered();
    let fill = if active {
        palette.accent.gamma_multiply(0.28)
    } else if hovered {
        palette.raised
    } else {
        Color32::TRANSPARENT
    };
    if fill != Color32::TRANSPARENT {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(theme::radius::CONTROL), fill);
    }

    let color = if active {
        palette.accent
    } else if hovered {
        palette.text_strong
    } else {
        palette.text
    };
    let icon_rect = Rect::from_min_size(
        egui::pos2(rect.min.x + 10.0, rect.center().y - 8.0),
        Vec2::splat(16.0),
    );
    icons::paint(ui.painter(), icon, icon_rect, color);
    ui.painter().galley(
        egui::pos2(icon_rect.max.x + 6.0, rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );

    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::selected(WidgetType::Button, enabled, active, label));

    response
}

/// A left-right choice strip, as used for language and theme.
///
/// Returns the newly chosen index if the user picked a different one.
///
/// Drawn by hand rather than with a `Frame` and `horizontal`: this control
/// sits inside a right-to-left toolbar layout, where a laid-out container
/// either mirrors its children or expands to fill the whole bar. Measuring
/// the text and allocating exactly that much space avoids both.
pub fn segmented(
    ui: &mut Ui,
    palette: &Palette,
    id: &str,
    options: &[(Icon, &str)],
    selected: usize,
) -> Option<usize> {
    if options.is_empty() {
        return None;
    }
    const PAD: f32 = 2.0;
    const GAP: f32 = 2.0;
    const ICON: f32 = 15.0;
    const ICON_TEXT_GAP: f32 = 5.0;
    const SIDE: f32 = 8.0;
    const HEIGHT: f32 = 28.0;

    let font = egui::TextStyle::Small.resolve(ui.style());
    let galleys: Vec<_> = options
        .iter()
        .map(|(_, label)| {
            ui.painter()
                .layout_no_wrap((*label).to_owned(), font.clone(), palette.text_muted)
        })
        .collect();
    let widths: Vec<f32> = galleys
        .iter()
        .map(|g| SIDE + ICON + ICON_TEXT_GAP + g.size().x + SIDE)
        .collect();

    let total_width = PAD * 2.0
        + widths.iter().sum::<f32>()
        + GAP * (options.len() - 1) as f32;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(total_width, HEIGHT), Sense::hover());

    let radius = CornerRadius::same(theme::radius::CONTROL);
    ui.painter().rect_filled(rect, radius, palette.sunken);
    ui.painter()
        .rect_stroke(rect, radius, Stroke::new(1.0, palette.border), StrokeKind::Inside);

    let inner_radius = CornerRadius::same(theme::radius::CONTROL.saturating_sub(2));
    let mut chosen = None;
    let mut x = rect.min.x + PAD;

    for (index, ((icon, _), width)) in options.iter().zip(&widths).enumerate() {
        let seg = Rect::from_min_size(
            egui::pos2(x, rect.min.y + PAD),
            Vec2::new(*width, HEIGHT - PAD * 2.0),
        );
        let response = ui.interact(seg, ui.id().with((id, index)), Sense::click());
        let is_selected = index == selected;

        // A segmented control is a row of radio buttons wearing a costume,
        // and announcing it as one is what lets it be operated without sight.
        let enabled = ui.is_enabled();
        let name = options[index].1;
        response.widget_info(|| {
            WidgetInfo::selected(WidgetType::RadioButton, enabled, is_selected, name)
        });

        if is_selected {
            ui.painter().rect_filled(seg, inner_radius, palette.surface);
            ui.painter().rect_stroke(
                seg,
                inner_radius,
                Stroke::new(1.0, palette.border_strong),
                StrokeKind::Inside,
            );
        } else if response.hovered() {
            ui.painter().rect_filled(seg, inner_radius, palette.raised);
        }

        let color = if is_selected {
            palette.text_strong
        } else {
            palette.text_muted
        };
        let icon_rect = Rect::from_min_size(
            egui::pos2(seg.min.x + SIDE, seg.center().y - ICON / 2.0),
            Vec2::splat(ICON),
        );
        icons::paint(ui.painter(), *icon, icon_rect, color);
        let galley = galleys[index].clone();
        ui.painter().galley(
            egui::pos2(
                icon_rect.max.x + ICON_TEXT_GAP,
                seg.center().y - galley.size().y / 2.0,
            ),
            galley,
            color,
        );

        // Report only a real change, or the setting would be written to disk
        // on every frame the pointer is held down on the active segment.
        if response.clicked() && !is_selected {
            chosen = Some(index);
        }
        x += width + GAP;
    }
    chosen
}

/// A small non-interactive icon-and-text chip, for the toolbar countdowns.
///
/// Measured and allocated explicitly for the same reason as `segmented`: it
/// sits inside a right-to-left toolbar layout, where a laid-out container
/// either mirrors its children or is handed no width at all.
pub fn status_chip(ui: &mut Ui, icon: Icon, text: &str, color: Color32) {
    const ICON: f32 = 13.0;
    const GAP: f32 = 4.0;

    let galley = ui.painter().layout_no_wrap(
        text.to_owned(),
        egui::FontId::proportional(12.0),
        color,
    );
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(ICON + GAP + galley.size().x, 20.0),
        Sense::hover(),
    );
    // Painted, so it has to be named by hand like everything else painted:
    // these are the countdowns to the lock and to auto-type, and whether the
    // rollback record checked out — exactly what someone listening needs.
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, text));
    let icon_rect = Rect::from_min_size(
        egui::pos2(rect.min.x, rect.center().y - ICON / 2.0),
        Vec2::splat(ICON),
    );
    icons::paint(ui.painter(), icon, icon_rect, color);
    ui.painter().galley(
        egui::pos2(icon_rect.max.x + GAP, rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
}

/// A coloured advisory box. The words carry the meaning; the colour only
/// reinforces it.
pub fn notice(ui: &mut Ui, palette: &Palette, tone: Color32, icon: Icon, title: &str, body: &str) {
    egui::Frame::new()
        .fill(tone.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, tone.gamma_multiply(0.55)))
        .corner_radius(CornerRadius::same(theme::radius::CARD - 2))
        .inner_margin(Margin::symmetric(12, 11))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(17.0), Sense::hover());
                icons::paint(ui.painter(), icon, rect, tone);
                ui.add_space(3.0);
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new(title)
                            .color(tone)
                            .size(13.0)
                            .family(egui::FontFamily::Name(theme::SEMIBOLD.into())),
                    );
                    if !body.is_empty() {
                        ui.add_space(2.0);
                        ui.label(egui::RichText::new(body).color(palette.text).size(12.5));
                    }
                });
            });
        });
}

/// A path field with a Browse button beside it.
///
/// Typing a path by hand is error-prone and, on Windows, unusual enough that
/// its absence reads as an unfinished program. `save` picks the dialog: saving
/// lets the user name a file that does not exist yet, opening does not.
pub fn path_field(
    ui: &mut Ui,
    palette: &Palette,
    value: &mut String,
    placeholder: &str,
    browse_label: &str,
    dialog: PathDialog<'_>,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let galley = ui.painter().layout_no_wrap(
            browse_label.to_owned(),
            egui::TextStyle::Button.resolve(ui.style()),
            palette.text,
        );
        let button_width = galley.size().x + 26.0;
        ui.add(
            egui::TextEdit::singleline(value)
                .desired_width((ui.available_width() - button_width - 8.0).max(80.0))
                .hint_text(placeholder)
                .margin(Margin::symmetric(9, 7)),
        );
        if ui.button(browse_label).clicked() {
            if let Some(picked) = dialog.run(value.as_str()) {
                *value = picked.display().to_string();
                changed = true;
            }
        }
    });
    changed
}

/// What the Browse button should open.
pub struct PathDialog<'a> {
    pub title: &'a str,
    pub filter_name: &'a str,
    pub extensions: &'a [&'a str],
    /// Save dialog (name a new file) rather than open (pick an existing one).
    pub save: bool,
}

impl PathDialog<'_> {
    fn run(&self, current: &str) -> Option<std::path::PathBuf> {
        let current = std::path::Path::new(current.trim());
        let mut dialog = rfd::FileDialog::new().set_title(self.title);
        if !self.extensions.is_empty() {
            dialog = dialog.add_filter(self.filter_name, self.extensions);
        }
        // Start where the user last pointed, so Browse is a correction rather
        // than a fresh hunt through the filesystem.
        if let Some(parent) = current.parent() {
            if parent.is_dir() {
                dialog = dialog.set_directory(parent);
            }
        }
        if let Some(name) = current.file_name() {
            dialog = dialog.set_file_name(name.to_string_lossy());
        }
        if self.save {
            dialog.save_file()
        } else {
            dialog.pick_file()
        }
    }
}

/// A password-strength bar with its verdict spelled out beside it.
///
/// Takes the password rather than a bit count so the caller cannot
/// accidentally hide the meter for the worst passwords: anything non-empty
/// gets a verdict, even when the estimate bottoms out at zero.
pub fn strength_meter(
    ui: &mut Ui,
    palette: &Palette,
    strings: &crate::i18n::Strings,
    password: &str,
) {
    use crate::generator::{estimate_entropy_bits, Strength};

    if password.is_empty() {
        return;
    }
    let bits = estimate_entropy_bits(password);
    let strength = Strength::from_bits(bits);
    let color = theme::strength_color(palette, strength);

    ui.add_space(theme::space::SM);
    let (rect, meter) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 5.0),
        Sense::hover(),
    );

    // A coloured bar carries its whole meaning in colour and length, which is
    // exactly the meaning that does not survive being read aloud. Reuse the
    // caption below rather than inventing a second wording: one of the two
    // would drift, and it would be the one nobody can see.
    let summary = crate::i18n::fill2(
        strings.strength.summary,
        theme::strength_label(strings, strength),
        format!("{bits:.0}"),
    );
    let spoken = summary.clone();
    meter.widget_info(|| WidgetInfo::labeled(WidgetType::ProgressIndicator, true, &spoken));
    ui.painter()
        .rect_filled(rect, CornerRadius::same(3), palette.sunken);
    let filled = Rect::from_min_size(
        rect.min,
        // A visible stub at zero bits: an empty track would be
        // indistinguishable from a field nobody has typed in yet.
        Vec2::new(
            (rect.width() * Strength::fraction(bits)).max(6.0),
            rect.height(),
        ),
    );
    ui.painter()
        .rect_filled(filled, CornerRadius::same(3), color);

    ui.add_space(theme::space::XS);
    ui.label(egui::RichText::new(summary).color(color).size(12.0));
}

/// A row in a read-only key/value table.
pub fn info_row(ui: &mut Ui, palette: &Palette, label: &str, value: &str) {
    ui.label(theme::muted(palette, label));
    ui.label(egui::RichText::new(value).size(12.5));
    ui.end_row();
}

#[cfg(test)]
mod tests {
    /// Run one frame and discard its output properly.
    ///
    /// `FullOutput::textures_delta` panics if dropped with unapplied deltas -
    /// a real renderer would upload them - so a test has to clear it by hand.
    fn run_frame(ctx: &egui::Context, add_contents: impl FnMut(&mut egui::Ui)) {
        let mut output = ctx.run_ui(Default::default(), add_contents);
        output.textures_delta.clear();
    }

    use super::*;
    use crate::i18n::EN;

    /// Lay every widget out once, in both palettes.
    ///
    /// This is a smoke test, not a look test: it catches the failure this code
    /// actually has - size arithmetic that goes negative, or a `CornerRadius`
    /// cast that underflows - which panics rather than looking wrong.
    fn exercise(appearance: theme::Appearance, width: f32) {
        let ctx = egui::Context::default();
        // Go through the real entry point: it is what binds the "semibold"
        // font family, and anything drawing with that family before it runs
        // would panic. Exercising it here keeps that wiring under test.
        theme::apply(&ctx, appearance);
        let palette = appearance.palette();
        run_frame(&ctx, |ui| {
            ui.set_max_width(width);
            card(ui, palette, |ui| {
                field_label_first(ui, palette, "Name");
                field_label(ui, palette, "Password");
                let mut text = String::from("value");
                text_field(ui, &mut text, "hint", "Name");
                secret_field(ui, &mut text, "hint", false, 200.0, "Password");
                secret_field(ui, &mut text, "hint", true, 200.0, "Password");
                hint(ui, palette, "explanatory text");
                error_text(ui, palette, "something is wrong");
                primary_button(ui, palette, "Save", true);
                primary_button(ui, palette, "Save", false);
                danger_button(ui, palette, "Delete");
                icon_button(ui, palette, Icon::Copy, "Copy", false);
                icon_button(ui, palette, Icon::Gear, "Settings", true);
                tool_button(ui, palette, Icon::LockClosed, "Lock", false);
                tool_button(ui, palette, Icon::Shield, "Health", true);
                segmented(
                    ui,
                    palette,
                    "seg",
                    &[(Icon::Sun, "Light"), (Icon::Moon, "Dark")],
                    1,
                );
                notice(ui, palette, palette.warning, Icon::Warning, "Title", "Body");
                notice(ui, palette, palette.success, Icon::Check, "Title", "");
                for password in ["", "111", "hunter2", "Xq7Bm4Kp9T", "correct horse battery"] {
                    strength_meter(ui, palette, &EN, password);
                }
                egui::Grid::new("g").num_columns(2).show(ui, |ui| {
                    info_row(ui, palette, "Entries", "42");
                });
            });
        });
    }

    #[test]
    fn every_widget_lays_out_in_the_dark_palette() {
        exercise(theme::Appearance::Dark, 400.0);
    }

    #[test]
    fn every_widget_lays_out_in_the_light_palette() {
        exercise(theme::Appearance::Light, 400.0);
    }

    #[test]
    fn a_narrow_pane_does_not_panic() {
        // The side panel can be dragged very narrow, and the window has a
        // minimum size but the panes inside it do not.
        exercise(theme::Appearance::Dark, 40.0);
        exercise(theme::Appearance::Light, 1.0);
    }

    #[test]
    fn segmented_reports_only_a_real_change() {
        // Clicking the already-selected segment must not report a change, or
        // the setting would be written to disk on every frame of the click.
        let ctx = egui::Context::default();
        theme::apply(&ctx, theme::Appearance::Dark);
        run_frame(&ctx, |ui| {
            let picked = segmented(
                ui,
                &theme::DARK,
                "seg",
                &[(Icon::Sun, "Light"), (Icon::Moon, "Dark")],
                0,
            );
            assert_eq!(picked, None, "no click happened, so nothing changed");
        });
    }

    // ------------------------------------------------------- accessibility

    /// Collect the accessibility tree of one frame.
    ///
    /// This is what a screen reader is handed. egui only builds it when asked,
    /// so the test has to ask — which is also why the gap it checks for went
    /// unnoticed: nothing in normal use produces this tree.
    fn accessibility_nodes(
        appearance: theme::Appearance,
        add_contents: impl FnMut(&mut egui::Ui),
    ) -> Vec<egui::accesskit::Node> {
        let ctx = egui::Context::default();
        theme::apply(&ctx, appearance);
        ctx.enable_accesskit();
        // Two passes: the first builds the layout, the second reports on it.
        // A one-pass read finds a tree that has not settled.
        let mut add_contents = add_contents;
        let mut output = ctx.run_ui(Default::default(), &mut add_contents);
        output.textures_delta.clear();
        let mut output = ctx.run_ui(Default::default(), &mut add_contents);
        output.textures_delta.clear();

        output
            .platform_output
            .accesskit_update
            .expect("accesskit was enabled, so a tree must come back")
            .nodes
            .into_iter()
            .map(|(_, node)| node)
            .collect()
    }

    fn is_interactive(role: egui::accesskit::Role) -> bool {
        use egui::accesskit::Role;
        matches!(
            role,
            Role::Button
                | Role::CheckBox
                | Role::RadioButton
                | Role::ComboBox
                | Role::Link
                | Role::Slider
                | Role::TextInput
                | Role::MultilineTextInput
        )
    }

    #[test]
    fn every_control_tells_a_screen_reader_what_it_is() {
        // The hand-drawn controls — the toolbar icons, the segmented control,
        // the strength bar — were rectangles of nothing here until they were
        // given a name. Somebody who cannot see the icon has no other way to
        // find out what the button does.
        let nodes = accessibility_nodes(theme::Appearance::Dark, |ui| {
            ui.set_max_width(400.0);
            let palette = &theme::DARK;
            icon_button(ui, palette, Icon::Copy, "Copy the password", false);
            icon_button(ui, palette, Icon::Eye, "Show the password", true);
            tool_button(ui, palette, Icon::Gear, "Settings", false);
            segmented(
                ui,
                palette,
                "seg",
                &[(Icon::Sun, "Light"), (Icon::Moon, "Dark")],
                0,
            );
            strength_meter(ui, palette, &EN, "a-password-to-measure");
            primary_button(ui, palette, "Unlock", true);
            danger_button(ui, palette, "Delete");
            let mut text = String::from("value");
            text_field(ui, &mut text, "hint", "Name");
        });

        let nameless: Vec<String> = nodes
            .iter()
            .filter(|node| is_interactive(node.role()))
            .filter(|node| node.label().is_none_or(|label| label.trim().is_empty()))
            .map(|node| format!("{:?}", node.role()))
            .collect();

        assert!(
            nameless.is_empty(),
            "these controls would be announced as nothing: {nameless:?}"
        );
        assert!(
            nodes.iter().filter(|n| is_interactive(n.role())).count() >= 7,
            "the tree looks too small to have covered the gallery"
        );
    }

    #[test]
    fn a_status_chip_is_read_out_as_well_as_shown() {
        // Not a control, so the test above does not look at it — which is how
        // the auto-type countdown came to be silent for anyone not looking.
        let nodes = accessibility_nodes(theme::Appearance::Dark, |ui| {
            status_chip(ui, Icon::Keyboard, "Typing in 4 s", theme::DARK.warning);
            status_chip(ui, Icon::Check, "Checked against this computer's record", theme::DARK.success);
        });
        // egui puts a label's text in `value`, the AccessKit convention for
        // static text; a control's name goes in `label`. A reader uses either.
        for text in ["Typing in 4 s", "Checked against this computer's record"] {
            assert!(
                nodes.iter().any(|node| {
                    [node.label(), node.value()]
                        .into_iter()
                        .flatten()
                        .any(|said| said == text)
                }),
                "{text:?} is drawn but never said"
            );
        }
    }

    #[test]
    fn a_toggled_control_reports_whether_it_is_on() {
        // Name alone is not enough for a toggle: "Show the password" has to
        // come with whether it currently is.
        use egui::accesskit::{Role, Toggled};
        let nodes = accessibility_nodes(theme::Appearance::Dark, |ui| {
            let palette = &theme::DARK;
            icon_button(ui, palette, Icon::Eye, "Show the password", true);
            icon_button(ui, palette, Icon::EyeOff, "Hide the password", false);
        });

        let toggles: Vec<Option<Toggled>> = nodes
            .iter()
            .filter(|node| node.role() == Role::Button)
            .map(|node| node.toggled())
            .collect();
        assert!(
            toggles.contains(&Some(Toggled::True)),
            "the active icon button must report that it is on: {toggles:?}"
        );
        assert!(
            toggles.contains(&Some(Toggled::False)),
            "and the inactive one that it is off: {toggles:?}"
        );
    }

    #[test]
    fn the_segmented_control_is_announced_as_a_choice() {
        use egui::accesskit::{Role, Toggled};
        let nodes = accessibility_nodes(theme::Appearance::Dark, |ui| {
            segmented(
                ui,
                &theme::DARK,
                "seg",
                &[(Icon::Sun, "Light"), (Icon::Moon, "Dark")],
                1,
            );
        });

        let radios: Vec<(String, Option<Toggled>)> = nodes
            .iter()
            .filter(|node| node.role() == Role::RadioButton)
            .map(|node| {
                (
                    node.label().unwrap_or_default().to_string(),
                    node.toggled(),
                )
            })
            .collect();

        assert_eq!(radios.len(), 2, "one node per segment: {radios:?}");
        assert!(radios.iter().any(|(name, on)| name == "Dark"
            && *on == Some(Toggled::True)));
        assert!(radios.iter().any(|(name, on)| name == "Light"
            && *on == Some(Toggled::False)));
    }

    #[test]
    fn the_strength_bar_says_out_loud_what_it_shows_in_colour() {
        use egui::accesskit::Role;
        let nodes = accessibility_nodes(theme::Appearance::Dark, |ui| {
            strength_meter(ui, &theme::DARK, &EN, "correct horse battery staple");
        });

        let spoken: Vec<String> = nodes
            .iter()
            .filter(|node| node.role() == Role::ProgressIndicator)
            .filter_map(|node| node.label().map(str::to_string))
            .collect();
        assert_eq!(spoken.len(), 1, "one bar, one announcement: {spoken:?}");
        assert!(
            spoken[0].contains("bits"),
            "the announcement should carry the number, not just a colour: {:?}",
            spoken[0]
        );
    }
}
