// A GUI program: no console window in release builds. Debug builds keep the
// console so panics and logs remain visible while developing.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use deep_defense::secret;
use deep_defense::ui::App;
use eframe::egui;

/// The window and taskbar icon, as raw RGBA pixels.
///
/// eframe wants pixels rather than a container format, so the icon is stored
/// pre-decoded and no PNG decoder has to be linked in just for this.
const WINDOW_ICON: &[u8] = include_bytes!("../assets/icon-64.rgba");
const WINDOW_ICON_SIZE: u32 = 64;

fn window_icon() -> Option<egui::IconData> {
    let expected = (WINDOW_ICON_SIZE * WINDOW_ICON_SIZE * 4) as usize;
    if WINDOW_ICON.len() != expected {
        // Regenerate with `python tools/make_icon.py`. A wrong-sized buffer
        // would be read out of bounds by the compositor, so refuse it.
        return None;
    }
    Some(egui::IconData {
        rgba: WINDOW_ICON.to_vec(),
        width: WINDOW_ICON_SIZE,
        height: WINDOW_ICON_SIZE,
    })
}

fn main() -> eframe::Result {
    // Suppress crash dumps: one written while the vault is open would contain
    // the master key. Best-effort - see `secret::harden_process`.
    secret::harden_process();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Deep Defense")
        .with_inner_size([1040.0, 700.0])
        .with_min_inner_size([760.0, 520.0]);
    if let Some(icon) = window_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        // Deliberately no persistence: eframe would otherwise write window
        // and widget state - including text buffers - to a file on disk.
        persist_window: false,
        ..Default::default()
    };

    eframe::run_native(
        "Deep Defense",
        options,
        Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))),
    )
}
