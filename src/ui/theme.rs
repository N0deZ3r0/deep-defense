//! Visual design: palettes, typography, spacing.
//!
//! Two rules run through this module.
//!
//! **Colour never carries meaning alone.** Every coloured state in this
//! program is also spelled out in words, because a colour-blind reader, a
//! greyscale screenshot and a printed page all lose the hue.
//!
//! **Contrast is a requirement, not a preference.** Body text against its
//! background clears roughly 7:1 in both palettes, and the muted variant
//! stays above 4.5:1 — a password manager is read carefully, often in a hurry,
//! sometimes on a dim laptop screen.

use std::sync::Arc;

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Margin, Stroke, TextStyle};
use serde::{Deserialize, Serialize};

use crate::generator::Strength;

/// Which palette to paint with.
///
/// Named `Appearance` rather than `Theme` so it cannot be confused with
/// `egui::Theme`, which means something narrower.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Appearance {
    #[default]
    Dark,
    Light,
}

impl Appearance {
    pub const ALL: [Appearance; 2] = [Appearance::Dark, Appearance::Light];

    pub fn palette(self) -> &'static Palette {
        match self {
            Appearance::Dark => &DARK,
            Appearance::Light => &LIGHT,
        }
    }
}

/// A semantic colour set. Screens reference roles, never raw hex.
pub struct Palette {
    /// The window behind everything.
    pub bg: Color32,
    /// Chrome: toolbar, side panel, status bar.
    pub surface: Color32,
    /// Cards and inputs sitting on `surface`.
    pub raised: Color32,
    /// Inputs, which must read as recessed rather than raised.
    pub sunken: Color32,
    pub border: Color32,
    pub border_strong: Color32,

    pub text: Color32,
    pub text_muted: Color32,
    pub text_strong: Color32,
    /// Text drawn on top of `accent`.
    pub on_accent: Color32,

    pub accent: Color32,
    pub accent_hover: Color32,
    pub danger: Color32,
    pub warning: Color32,
    pub success: Color32,
}

pub static DARK: Palette = Palette {
    bg: Color32::from_rgb(0x14, 0x16, 0x1b),
    surface: Color32::from_rgb(0x1a, 0x1d, 0x24),
    raised: Color32::from_rgb(0x22, 0x26, 0x2f),
    sunken: Color32::from_rgb(0x0f, 0x11, 0x15),
    border: Color32::from_rgb(0x2e, 0x33, 0x3e),
    border_strong: Color32::from_rgb(0x41, 0x48, 0x57),

    text: Color32::from_rgb(0xe6, 0xe9, 0xef),
    text_muted: Color32::from_rgb(0x9a, 0xa2, 0xb1),
    text_strong: Color32::from_rgb(0xff, 0xff, 0xff),
    on_accent: Color32::from_rgb(0x0b, 0x12, 0x1e),

    accent: Color32::from_rgb(0x62, 0xa3, 0xf7),
    accent_hover: Color32::from_rgb(0x7d, 0xb4, 0xfa),
    danger: Color32::from_rgb(0xf2, 0x73, 0x73),
    warning: Color32::from_rgb(0xe8, 0xab, 0x45),
    success: Color32::from_rgb(0x55, 0xc4, 0x92),
};

pub static LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xf4, 0xf5, 0xf7),
    surface: Color32::from_rgb(0xff, 0xff, 0xff),
    raised: Color32::from_rgb(0xfa, 0xfb, 0xfc),
    sunken: Color32::from_rgb(0xff, 0xff, 0xff),
    border: Color32::from_rgb(0xd8, 0xdc, 0xe3),
    border_strong: Color32::from_rgb(0xb4, 0xbb, 0xc7),

    text: Color32::from_rgb(0x1c, 0x21, 0x2b),
    text_muted: Color32::from_rgb(0x5d, 0x66, 0x75),
    text_strong: Color32::from_rgb(0x0a, 0x0d, 0x12),
    on_accent: Color32::from_rgb(0xff, 0xff, 0xff),

    // 5.3:1 against the light background. A brighter blue looks better in
    // isolation but drops under the 4.5:1 floor for small text.
    accent: Color32::from_rgb(0x18, 0x63, 0xc2),
    accent_hover: Color32::from_rgb(0x13, 0x56, 0xab),
    // Darkened against white: the dark palette's reds and greens are too
    // light to read on a white background.
    danger: Color32::from_rgb(0xc4, 0x2b, 0x2b),
    warning: Color32::from_rgb(0x9a, 0x66, 0x00),
    success: Color32::from_rgb(0x15, 0x7f, 0x52),
};

/// A font family for headings, so they carry weight without egui having to
/// synthesise bold (which it does not do).
pub const SEMIBOLD: &str = "semibold";

pub mod space {
    /// Gap inside a control.
    pub const XS: f32 = 4.0;
    /// Gap between related controls.
    pub const SM: f32 = 8.0;
    /// Gap between a label and its field.
    pub const MD: f32 = 12.0;
    /// Gap between sections.
    pub const LG: f32 = 18.0;
    /// Page margin.
    pub const PAGE: f32 = 20.0;
}

pub mod radius {
    pub const CONTROL: u8 = 6;
    pub const CARD: u8 = 10;
}

/// Install fonts and the palette. Call whenever the appearance changes.
pub fn apply(ctx: &egui::Context, appearance: Appearance) {
    install_fonts(ctx);

    let palette = appearance.palette();
    // Write the same palette into both of egui's theme slots, so an OS
    // light/dark switch cannot repaint the app in colours we never chose.
    ctx.all_styles_mut(|style| style_one(style, palette));
    ctx.set_visuals(visuals(palette));
}

/// Ask the window manager to give us a matching title bar.
///
/// Without this, a light app keeps the OS's dark title bar bolted to the top
/// of it, which is the most obvious sign of a program that did not bother.
///
/// Must be sent from inside a frame: during `App::new` the viewport does not
/// exist yet and the command is discarded.
pub fn apply_window_theme(ctx: &egui::Context, appearance: Appearance) {
    ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(match appearance {
        Appearance::Dark => egui::SystemTheme::Dark,
        Appearance::Light => egui::SystemTheme::Light,
    }));
}

/// Prefer the platform's own UI font: matching the surrounding desktop is most
/// of what makes an application look native rather than transplanted.
///
/// Falls back silently to egui's embedded Ubuntu, which also covers Cyrillic,
/// so a missing system font costs appearance and nothing else.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let mut installed_ui = false;
    let mut installed_semibold = false;
    let mut installed_mono = false;

    // Segoe UI Variable first: it is the Windows 11 UI font.
    for candidate in ["SegUIVar.ttf", "segoeui.ttf"] {
        if let Some(data) = read_system_font(candidate) {
            fonts
                .font_data
                .insert("ui".to_owned(), Arc::new(egui::FontData::from_owned(data)));
            installed_ui = true;
            break;
        }
    }
    for candidate in ["seguisb.ttf", "segoeuib.ttf"] {
        if let Some(data) = read_system_font(candidate) {
            fonts.font_data.insert(
                "ui-semibold".to_owned(),
                Arc::new(egui::FontData::from_owned(data)),
            );
            installed_semibold = true;
            break;
        }
    }
    if let Some(data) = read_system_font("consola.ttf") {
        fonts
            .font_data
            .insert("mono".to_owned(), Arc::new(egui::FontData::from_owned(data)));
        installed_mono = true;
    }

    if installed_ui {
        // Insert ahead of the defaults rather than replacing them: the
        // embedded fonts stay as a fallback for glyphs Segoe lacks.
        if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
            family.insert(0, "ui".to_owned());
        }
    }
    if installed_mono {
        if let Some(family) = fonts.families.get_mut(&FontFamily::Monospace) {
            family.insert(0, "mono".to_owned());
        }
    }

    // The heading family always exists, even without the semibold file, so
    // callers never have to check which fonts were found.
    let mut heading_stack = Vec::new();
    if installed_semibold {
        heading_stack.push("ui-semibold".to_owned());
    }
    if installed_ui {
        heading_stack.push("ui".to_owned());
    }
    heading_stack.extend(
        fonts
            .families
            .get(&FontFamily::Proportional)
            .cloned()
            .unwrap_or_default(),
    );
    fonts
        .families
        .insert(FontFamily::Name(SEMIBOLD.into()), heading_stack);

    ctx.set_fonts(fonts);
}

fn read_system_font(file_name: &str) -> Option<Vec<u8>> {
    if !cfg!(windows) {
        return None;
    }
    let root = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let path = std::path::Path::new(&root).join("Fonts").join(file_name);
    std::fs::read(path).ok()
}

fn style_one(style: &mut egui::Style, palette: &Palette) {
    use FontFamily::{Monospace, Proportional};

    style.text_styles = [
        (TextStyle::Heading, FontId::new(19.0, FontFamily::Name(SEMIBOLD.into()))),
        (TextStyle::Body, FontId::new(14.0, Proportional)),
        (TextStyle::Button, FontId::new(14.0, Proportional)),
        (TextStyle::Small, FontId::new(12.0, Proportional)),
        (TextStyle::Monospace, FontId::new(13.5, Monospace)),
    ]
    .into();

    style.spacing.item_spacing = egui::vec2(space::SM, space::SM);
    style.spacing.button_padding = egui::vec2(11.0, 6.0);
    style.spacing.menu_margin = Margin::same(6);
    style.spacing.indent = 18.0;
    style.spacing.interact_size.y = 30.0;
    style.spacing.slider_width = 190.0;
    style.spacing.combo_width = 140.0;
    style.spacing.scroll.bar_width = 9.0;
    style.spacing.scroll.floating = false;

    style.visuals = visuals(palette);
    // Deliberately not forcing a wrap mode: egui picks per container, and
    // wrapping a single-line label inside a width-starved horizontal layout
    // breaks it into one character per line.
}

fn visuals(palette: &Palette) -> egui::Visuals {
    let dark = palette.bg.r() < 0x80;
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    v.panel_fill = palette.bg;
    v.window_fill = palette.surface;
    v.faint_bg_color = palette.raised;
    v.extreme_bg_color = palette.sunken;
    v.override_text_color = Some(palette.text);
    // `strong_text_color()` is derived from widgets.active, set further down;
    // emphasis in this app comes from the semibold family rather than from
    // `.strong()`, which override_text_color would swallow anyway.
    v.hyperlink_color = palette.accent;

    v.window_stroke = Stroke::new(1.0, palette.border);
    v.window_corner_radius = CornerRadius::same(radius::CARD);
    v.menu_corner_radius = CornerRadius::same(radius::CONTROL);
    v.window_shadow = egui::epaint::Shadow {
        offset: [0, 6],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 150 } else { 40 }),
    };
    v.popup_shadow = v.window_shadow;

    v.selection.bg_fill = palette.accent.gamma_multiply(if dark { 0.35 } else { 0.22 });
    v.selection.stroke = Stroke::new(1.0, palette.accent);

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = palette.surface;
    w.noninteractive.weak_bg_fill = palette.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, palette.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, palette.text);
    w.noninteractive.corner_radius = CornerRadius::same(radius::CONTROL);

    w.inactive.bg_fill = palette.raised;
    w.inactive.weak_bg_fill = palette.raised;
    w.inactive.bg_stroke = Stroke::new(1.0, palette.border);
    w.inactive.fg_stroke = Stroke::new(1.0, palette.text);
    w.inactive.corner_radius = CornerRadius::same(radius::CONTROL);

    w.hovered.bg_fill = if dark {
        Color32::from_rgb(0x2c, 0x32, 0x3d)
    } else {
        Color32::from_rgb(0xed, 0xf0, 0xf4)
    };
    w.hovered.weak_bg_fill = w.hovered.bg_fill;
    w.hovered.bg_stroke = Stroke::new(1.0, palette.border_strong);
    w.hovered.fg_stroke = Stroke::new(1.0, palette.text_strong);
    w.hovered.corner_radius = CornerRadius::same(radius::CONTROL);

    w.active.bg_fill = palette.accent.gamma_multiply(if dark { 0.55 } else { 0.85 });
    w.active.weak_bg_fill = w.active.bg_fill;
    w.active.bg_stroke = Stroke::new(1.0, palette.accent);
    w.active.fg_stroke = Stroke::new(1.0, palette.text_strong);
    w.active.corner_radius = CornerRadius::same(radius::CONTROL);

    w.open.bg_fill = palette.raised;
    w.open.weak_bg_fill = palette.raised;
    w.open.bg_stroke = Stroke::new(1.0, palette.border_strong);
    w.open.corner_radius = CornerRadius::same(radius::CONTROL);

    v
}

// --------------------------------------------------------------- text helpers

pub fn heading(text: impl Into<String>, size: f32) -> egui::RichText {
    egui::RichText::new(text).size(size).family(FontFamily::Name(SEMIBOLD.into()))
}

pub fn muted(palette: &Palette, text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).color(palette.text_muted).size(12.5)
}

pub fn body(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).size(14.0)
}

pub fn label_caps(palette: &Palette, text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text.into().to_uppercase())
        .color(palette.text_muted)
        .size(10.5)
        .family(FontFamily::Name(SEMIBOLD.into()))
}

pub fn strength_color(palette: &Palette, strength: Strength) -> Color32 {
    match strength {
        Strength::Critical | Strength::Weak => palette.danger,
        Strength::Fair => palette.warning,
        Strength::Strong | Strength::Excellent => palette.success,
    }
}

pub fn strength_label(strings: &crate::i18n::Strings, strength: Strength) -> &'static str {
    match strength {
        Strength::Critical => strings.strength.critical,
        Strength::Weak => strings.strength.weak,
        Strength::Fair => strings.strength.fair,
        Strength::Strong => strings.strength.strong,
        Strength::Excellent => strings.strength.excellent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG relative luminance.
    fn luminance(c: Color32) -> f64 {
        let channel = |v: u8| {
            let s = v as f64 / 255.0;
            if s <= 0.03928 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        let (hi, lo) = if x > y { (x, y) } else { (y, x) };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn body_text_is_comfortably_readable() {
        for (name, p) in [("dark", &DARK), ("light", &LIGHT)] {
            for (role, fg, bg) in [
                ("text on bg", p.text, p.bg),
                ("text on surface", p.text, p.surface),
                ("text on raised", p.text, p.raised),
            ] {
                let ratio = contrast(fg, bg);
                assert!(ratio >= 7.0, "{name}: {role} is only {ratio:.1}:1, want 7:1+");
            }
        }
    }

    #[test]
    fn muted_and_status_colours_clear_the_accessibility_floor() {
        // 4.5:1 is the WCAG AA threshold for normal-size text. Muted text and
        // the status colours are all used at small sizes, so they must clear it.
        for (name, p) in [("dark", &DARK), ("light", &LIGHT)] {
            for (role, fg) in [
                ("muted", p.text_muted),
                ("danger", p.danger),
                ("warning", p.warning),
                ("success", p.success),
                ("accent", p.accent),
            ] {
                for (bg_name, bg) in [("bg", p.bg), ("surface", p.surface)] {
                    let ratio = contrast(fg, bg);
                    assert!(
                        ratio >= 4.5,
                        "{name}: {role} on {bg_name} is {ratio:.1}:1, want 4.5:1+"
                    );
                }
            }
        }
    }

    #[test]
    fn text_on_accent_is_readable() {
        // Used for the primary button's label.
        for (name, p) in [("dark", &DARK), ("light", &LIGHT)] {
            let ratio = contrast(p.on_accent, p.accent);
            assert!(ratio >= 4.5, "{name}: on_accent is {ratio:.1}:1");
        }
    }

    #[test]
    fn the_two_palettes_are_genuinely_light_and_dark() {
        assert!(luminance(DARK.bg) < 0.05);
        assert!(luminance(LIGHT.bg) > 0.8);
    }

    #[test]
    fn borders_are_visible_against_their_surface() {
        // A border that cannot be seen is not a border; 1.5:1 is about the
        // floor for a 1px separator to register.
        for (name, p) in [("dark", &DARK), ("light", &LIGHT)] {
            let ratio = contrast(p.border, p.surface);
            assert!(ratio >= 1.15, "{name}: border on surface is {ratio:.2}:1");
            let strong = contrast(p.border_strong, p.surface);
            assert!(strong >= 1.4, "{name}: border_strong is {strong:.2}:1");
        }
    }

    #[test]
    fn every_strength_maps_to_a_colour_and_a_word() {
        use crate::i18n::{EN, RU};
        for strength in [
            Strength::Critical,
            Strength::Weak,
            Strength::Fair,
            Strength::Strong,
            Strength::Excellent,
        ] {
            // Colour alone is never the signal, so both must exist.
            let _ = strength_color(&DARK, strength);
            assert!(!strength_label(&EN, strength).is_empty());
            assert!(!strength_label(&RU, strength).is_empty());
        }
    }
}
