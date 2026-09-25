//! The real screens, drawn without a window, checked and kept as pictures.
//!
//! Built only with `--features ui-snapshots`. What draws the pictures is a
//! whole GPU renderer, run on a software adapter, and the program itself never
//! needs it. CI runs these and keeps the images, so a change to a screen can
//! be looked at by someone who cannot start the program — which, on a machine
//! where Smart App Control refuses freshly built executables, includes the
//! person who wrote the change.
//!
//! Each test also asserts on what is on screen, through the same
//! accessibility tree a screen reader sees. A picture has to be looked at to
//! be useful; the assertions fail on their own.

use std::path::PathBuf;

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;

use crate::config::test_home::TestHome;
use crate::crypto::KdfParams;
use crate::errors::{CopyAt, Evidence};
use crate::i18n::{Lang, Strings};
use crate::model::Entry;
use crate::secret::Secret;
use crate::session::OpenVault;
use crate::vault::{AnchorState, Vault};

use super::app::{unlock_notice, App, Screen};
use super::theme::{self, Appearance};

/// The size the program opens at.
const WINDOW: egui::Vec2 = egui::vec2(1040.0, 700.0);

struct Shot {
    app: App,
    appearance: Appearance,
    themed: bool,
}

/// Where the pictures go: `DEEP_DEFENSE_SNAPSHOTS` if set, otherwise beside
/// the build output.
fn snapshot_dir() -> PathBuf {
    std::env::var_os("DEEP_DEFENSE_SNAPSHOTS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("ui-snapshots")
        })
}

fn params() -> KdfParams {
    KdfParams {
        m_cost: KdfParams::MIN_M_COST,
        t_cost: 2,
        p_cost: 1,
        algorithm: "argon2id".into(),
    }
}

/// An app on a scratch home, holding a standalone vault saved `saves` times.
///
/// The vault is left locked; `open` opens it the way an unlock would.
fn app_with_vault(home: &TestHome, lang: Lang, appearance: Appearance, saves: usize) -> App {
    let vault_path = home.join("vault.ddv");
    let secret = Secret::from_str("snapshot password");
    let mut vault = Vault::create_in_slot(
        &vault_path,
        &secret,
        params(),
        crate::slots::PRIMARY_SLOT,
        Some(crate::slots::MIN_SLOT_CAPACITY),
    )
    .unwrap();
    for (index, (name, user, url)) in [
        ("GitHub", "octo@example.com", "https://github.com"),
        ("Bank", "a.smith", "https://bank.example"),
        ("Mail", "a.smith@example.com", "https://mail.example"),
        ("Router", "admin", "http://192.168.0.1"),
    ]
    .into_iter()
    .enumerate()
    .take(saves.max(1))
    {
        let mut entry = Entry::new(name);
        entry.username = user.into();
        entry.url = url.into();
        entry.set_password(format!("correct-horse-{index}"));
        vault.add(entry).unwrap();
        vault.save().unwrap();
    }
    drop(vault);

    let mut app = App::new(&egui::Context::default());
    let config = &mut app.session.config;
    config.use_container = false;
    config.vault_path = vault_path;
    config.kdf = params();
    config.language = lang;
    config.appearance = appearance;
    // The runner's desktop may well count as locked. A screenshot of the
    // lock screen taken because of that would be a picture of nothing.
    config.lock_on_screen_lock = false;
    app.screen = Screen::Locked;
    app
}

/// Open the configured vault, as a successful unlock would leave things.
fn open(app: &mut App) {
    let vault = Vault::open(
        &app.session.config.vault_path,
        &Secret::from_str("snapshot password"),
        false,
    )
    .unwrap();
    app.session.adopt(OpenVault {
        vault,
        container: None,
    });
    app.screen = Screen::Main;
}

fn harness(app: App) -> Harness<'static, Shot> {
    let appearance = app.session.config.appearance;
    Harness::builder()
        .with_size(WINDOW)
        .with_max_steps(64)
        .wgpu()
        .build_ui_state(
            |ui, shot: &mut Shot| {
                if !shot.themed {
                    theme::apply(ui.ctx(), shot.appearance);
                    shot.themed = true;
                }
                shot.app.draw(ui);
            },
            Shot {
                app,
                appearance,
                themed: false,
            },
        )
}

/// Settle, draw, and keep the picture.
fn keep(harness: &mut Harness<'static, Shot>, name: &str) {
    harness.run_ok();
    let image = harness
        .render()
        .unwrap_or_else(|e| panic!("{name}: the software renderer failed: {e}"));
    let dir = snapshot_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.png"));
    image.save(&path).unwrap();
    // Not blank: a renderer that silently draws nothing would otherwise
    // produce a folder of convincing empty rectangles.
    let first = image.get_pixel(0, 0);
    assert!(
        image.pixels().any(|pixel| pixel != first),
        "{name}: the picture is a single colour"
    );
}

fn strings(harness: &Harness<'static, Shot>) -> &'static Strings {
    harness.state().app.strings()
}

fn count(harness: &Harness<'static, Shot>, label: &str) -> usize {
    harness.query_all_by_label(label).count()
}

/// Whether any text on screen contains `text`. Several may: a title can be
/// repeated in the status bar, and a word in more than one sentence.
fn shown(harness: &Harness<'static, Shot>, text: &str) -> bool {
    harness.query_all_by_label_contains(text).next().is_some()
}

/// Bring the first thing labelled `label` into view, in whichever scroll
/// area holds it.
fn scroll_to(harness: &mut Harness<'static, Shot>, label: &str) {
    harness
        .query_all_by_label(label)
        .next()
        .unwrap_or_else(|| panic!("nothing on screen is labelled {label:?}"))
        .scroll_to_me();
    harness.run_ok();
}

// ----------------------------------------------------------- the lock screen

#[test]
fn the_lock_screen_lists_the_backups_to_restore() {
    for (lang, appearance, name) in [
        (Lang::En, Appearance::Light, "unlock_backups_en_light"),
        (Lang::Ru, Appearance::Dark, "unlock_backups_ru_dark"),
    ] {
        let home = TestHome::new(name);
        let mut app = app_with_vault(&home, lang, appearance, 3);
        app.show_backups_unlock = true;
        let mut harness = harness(app);
        harness.run_ok();

        let s = strings(&harness);
        assert!(shown(&harness, s.backups.section));
        // Created, then saved three times: three files before the current one.
        assert_eq!(count(&harness, s.backups.restore), 3);
        keep(&mut harness, name);
    }
}

#[test]
fn restoring_from_the_lock_screen_asks_first() {
    let home = TestHome::new("unlock_backups_confirm");
    let mut app = app_with_vault(&home, Lang::En, Appearance::Light, 3);
    app.show_backups_unlock = true;
    let mut harness = harness(app);
    harness.run_ok();

    let s = strings(&harness);
    let before = std::fs::read(home.join("vault.ddv")).unwrap();
    harness
        .query_all_by_label(s.backups.restore)
        .next()
        .expect("a restore button per backup")
        .click();
    harness.run_ok();

    assert!(shown(&harness, s.backups.confirm_title), "asks before replacing");
    assert_eq!(
        std::fs::read(home.join("vault.ddv")).unwrap(),
        before,
        "the first click changes nothing on disk"
    );
    keep(&mut harness, "unlock_backups_confirm_en_light");
}

// ------------------------------------------------ an older file, three ways

fn prompt(evidence: Evidence, lang: Lang, appearance: Appearance) -> (TestHome, Harness<'static, Shot>) {
    let home = TestHome::new("prompt");
    let mut app = app_with_vault(&home, lang, appearance, 2);
    app.rollback_prompt = Some((2, evidence));
    let mut harness = harness(app);
    harness.run_ok();
    (home, harness)
}

#[test]
fn a_newer_copy_is_offered_back() {
    for (lang, appearance, name) in [
        (Lang::En, Appearance::Light, "prompt_newer_copy_en_light"),
        (Lang::Ru, Appearance::Dark, "prompt_newer_copy_ru_dark"),
    ] {
        let (_home, mut harness) = prompt(
            Evidence::Copy {
                revision: 4,
                at: CopyAt::Backup(1),
            },
            lang,
            appearance,
        );
        let s = strings(&harness);
        assert!(shown(&harness, s.shell.newer_title));
        assert_eq!(count(&harness, s.shell.restore_newer), 1);
        assert_eq!(count(&harness, s.shell.rollback_accept), 1);
        assert_eq!(count(&harness, s.common.cancel), 1);
        keep(&mut harness, name);
    }
}

#[test]
fn a_newer_copy_in_the_mirror_says_where() {
    let mirror = PathBuf::from(r"E:\Backups\Deep Defense\vault.ddv");
    let (_home, mut harness) = prompt(
        Evidence::Copy {
            revision: 9,
            at: CopyAt::Mirror(mirror.clone()),
        },
        Lang::En,
        Appearance::Light,
    );
    assert!(shown(&harness, &mirror.display().to_string()));
    keep(&mut harness, "prompt_newer_copy_mirror_en_light");
}

#[test]
fn a_copy_from_before_a_key_change_is_not_offered_as_current() {
    {
        let (_home, mut harness) = prompt(Evidence::Superseded, Lang::En, Appearance::Light);
        let s = strings(&harness);
        assert!(shown(&harness, s.shell.superseded_title));
        assert_eq!(count(&harness, s.shell.restore_newer), 0, "nothing newer to offer");
        assert_eq!(count(&harness, s.shell.rollback_accept), 1);
        keep(&mut harness, "prompt_superseded_en_light");
    }
    // One scratch home at a time: they share a lock.
    let (_home, mut harness) = prompt(Evidence::Superseded, Lang::Ru, Appearance::Dark);
    keep(&mut harness, "prompt_superseded_ru_dark");
}

#[test]
fn a_record_that_is_ahead_is_shown_with_both_numbers() {
    let (_home, mut harness) =
        prompt(Evidence::Record { revision: 7 }, Lang::En, Appearance::Light);
    let s = strings(&harness);
    assert!(shown(&harness, s.shell.rollback_title));
    assert_eq!(count(&harness, s.shell.restore_newer), 0);
    keep(&mut harness, "prompt_record_en_light");
}

// ------------------------------------------------------------- once inside

#[test]
fn a_first_visit_is_said_on_the_way_in() {
    for (lang, appearance, name) in [
        (Lang::En, Appearance::Light, "main_first_visit_en_light"),
        (Lang::Ru, Appearance::Dark, "main_first_visit_ru_dark"),
    ] {
        let home = TestHome::new(name);
        let mut app = app_with_vault(&home, lang, appearance, 4);
        open(&mut app);
        app.status = unlock_notice(app.strings(), AnchorState::FirstSeenHere);
        let mut harness = harness(app);
        harness.run_ok();

        let s = strings(&harness);
        assert!(shown(&harness, s.anchor.first_seen));
        assert!(shown(&harness, "GitHub"), "the entries are there behind it");
        keep(&mut harness, name);
    }
}

#[test]
fn the_backups_section_in_settings() {
    for (lang, appearance, name) in [
        (Lang::En, Appearance::Light, "settings_backups_en_light"),
        (Lang::Ru, Appearance::Dark, "settings_backups_ru_dark"),
    ] {
        let home = TestHome::new(name);
        let mut app = app_with_vault(&home, lang, appearance, 3);
        open(&mut app);
        app.show_settings = true;
        let mut harness = harness(app);
        harness.run_ok();

        let s = strings(&harness);
        scroll_to(&mut harness, s.backups.section);
        assert_eq!(count(&harness, s.backups.restore), 3);
        keep(&mut harness, name);
    }
}

#[test]
fn the_rollback_record_section_in_settings() {
    let home = TestHome::new("settings_record");
    let mut app = app_with_vault(&home, Lang::En, Appearance::Light, 2);
    open(&mut app);
    app.show_settings = true;
    let mut harness = harness(app);
    harness.run_ok();

    let s = strings(&harness);
    scroll_to(&mut harness, s.anchor.section);
    assert!(shown(&harness, s.anchor.verified), "opened here, checked here");
    keep(&mut harness, "settings_record_en_light");
}
