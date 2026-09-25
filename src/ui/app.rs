//! The application shell: toolbar, state machine, background work, auto-lock.

use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::errors::Error;
use crate::generator::Policy;
use crate::i18n::{fill1, fill2, Lang, Strings};
use crate::model::Entry;
use crate::platform::LockWatcher;
use crate::secret::Secret;
use crate::session::{self, OpenVault, Session};

use super::icons::Icon;
use super::theme::{self, Appearance, Palette};
use super::widgets;
use super::{entries, settings, setup, unlock};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// No container configured yet.
    Setup,
    /// A container exists and is closed.
    Locked,
    /// Mounted and open.
    Main,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Info,
    Success,
    Warning,
    Danger,
}

impl Tone {
    fn color(self, palette: &Palette) -> egui::Color32 {
        match self {
            Tone::Info => palette.accent,
            Tone::Success => palette.success,
            Tone::Warning => palette.warning,
            Tone::Danger => palette.danger,
        }
    }

    fn icon(self) -> Icon {
        match self {
            Tone::Info => Icon::Info,
            Tone::Success => Icon::Check,
            Tone::Warning => Icon::Warning,
            Tone::Danger => Icon::Warning,
        }
    }
}

/// A message in the status bar.
///
/// Plain confirmations fade on their own; anything the user may need to act on
/// stays until dismissed, because a warning that vanishes unread is no warning.
pub struct Status {
    pub tone: Tone,
    pub title: String,
    pub body: String,
    raised_at: Instant,
    auto_dismiss: bool,
}

impl Status {
    fn new(tone: Tone, title: String, body: String, auto_dismiss: bool) -> Self {
        Self {
            tone,
            title,
            body,
            raised_at: Instant::now(),
            auto_dismiss,
        }
    }

    pub fn info(title: impl Into<String>) -> Self {
        Self::new(Tone::Info, title.into(), String::new(), true)
    }

    pub fn success(title: impl Into<String>) -> Self {
        Self::new(Tone::Success, title.into(), String::new(), true)
    }

    pub fn warn(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self::new(Tone::Warning, title.into(), body.into(), false)
    }

    pub fn error(strings: &Strings, err: &Error) -> Self {
        Self::new(
            Tone::Danger,
            strings.shell.error_title.to_owned(),
            err.localized(strings),
            false,
        )
    }

    fn expired(&self) -> bool {
        self.auto_dismiss && self.raised_at.elapsed() > Duration::from_secs(6)
    }
}

/// The outcome of a slow operation running off the UI thread.
pub enum TaskOutcome {
    Unlocked(Box<OpenVault>),
    Created(Box<OpenVault>),
    Failed(Error),
    /// The vault opened but is older than the revision we recorded.
    RollbackDetected { on_disk: u64, expected: u64 },
}

pub struct Task {
    pub label: String,
    pub receiver: Receiver<TaskOutcome>,
}

/// A password waiting to be typed into whatever window is in front.
///
/// The delay is the whole safety mechanism: it is the window in which the user
/// switches to the application that needs the password, and the window in
/// which they can change their mind. Typing immediately would put the password
/// into this program's own search box.
pub struct PendingType {
    pub text: Zeroizing<String>,
    pub fires_at: Instant,
}

/// How long to wait before typing. Long enough to alt-tab without hurrying,
/// short enough not to be abandoned halfway through.
pub const AUTOTYPE_DELAY: Duration = Duration::from_secs(5);

/// An entry being edited. Separate from [`Entry`] so an abandoned edit never
/// touches the vault, and so the password lives in a buffer we can wipe.
pub struct Draft {
    /// `None` for a new entry, otherwise the key of the entry being edited.
    pub original_key: Option<String>,
    pub name: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub totp: String,
    pub fields: Vec<crate::model::CustomField>,
}

impl Draft {
    pub fn blank() -> Self {
        Self {
            original_key: None,
            name: String::new(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
            url: String::new(),
            notes: String::new(),
            tags: String::new(),
            totp: String::new(),
            fields: Vec::new(),
        }
    }

    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            original_key: Some(entry.key()),
            name: entry.name.clone(),
            username: entry.username.clone(),
            password: Zeroizing::new(entry.password.clone()),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            tags: entry.tags.join(", "),
            totp: entry.totp_secret.clone(),
            fields: entry.fields.clone(),
        }
    }

    pub fn parsed_tags(&self) -> Vec<String> {
        self.tags
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    }
}

pub struct App {
    pub session: Session,
    pub screen: Screen,
    pub status: Option<Status>,
    pub task: Option<Task>,

    pub password_input: Zeroizing<String>,
    pub password_confirm: Zeroizing<String>,

    pub setup: setup::SetupState,
    pub settings: settings::SettingsState,

    pub search: String,
    pub tag_filter: Option<String>,
    pub selected: Option<String>,
    pub draft: Option<Draft>,
    pub reveal_password: bool,
    pub confirm_delete: Option<String>,

    pub show_settings: bool,
    pub show_audit: bool,
    pub show_history: bool,
    pub show_generator: bool,
    /// The one-time window listing freshly made recovery pieces.
    pub show_recovery_shares: bool,
    /// The recovery panel on the unlock screen.
    pub show_recovery_unlock: bool,
    /// The backups panel on the unlock screen.
    pub show_backups_unlock: bool,
    /// Pieces pasted in to rebuild a forgotten master password.
    pub recovery_input: Zeroizing<String>,

    /// A password counting down to being typed into another window.
    pub autotype: Option<PendingType>,

    /// Passwords already known to be public.
    ///
    /// Loaded once: the bundled block is a megabyte, and re-reading it per
    /// keystroke would be felt while typing.
    pub breach: crate::breach::Catalogue,
    pub generator_policy: Policy,
    pub generator_preview: Zeroizing<String>,
    pub rollback_prompt: Option<(u64, u64)>,

    /// Set when a screen wants the search box focused on the next frame.
    pub focus_search: bool,
    /// The appearance we last told the window manager about, so the title bar
    /// is reconciled once per change rather than on every frame.
    window_theme: Option<Appearance>,
    /// Debounced watch on the desktop being locked.
    lock_watcher: LockWatcher,
    last_lock_check: Instant,
}

impl App {
    pub fn new(ctx: &egui::Context) -> Self {
        // A broken settings file must not vanish silently: falling back to
        // defaults changes the language, the theme and the container path all
        // at once, and the user is owed an explanation for that.
        let (config, load_error) = match Config::load() {
            Ok(config) => (config, None),
            Err(e) => (Config::default(), Some(e)),
        };
        theme::apply(ctx, config.appearance);

        let configured = config.is_configured();
        let session = Session::new(config);
        let status = load_error
            .as_ref()
            .map(|e| Status::error(session.config.language.strings(), e));

        Self {
            screen: if configured {
                Screen::Locked
            } else {
                Screen::Setup
            },
            setup: setup::SetupState::new(&session.config),
            settings: settings::SettingsState::new(&session.config),
            session,
            status,
            task: None,
            password_input: Zeroizing::new(String::new()),
            password_confirm: Zeroizing::new(String::new()),
            search: String::new(),
            tag_filter: None,
            selected: None,
            draft: None,
            reveal_password: false,
            confirm_delete: None,
            show_settings: false,
            show_audit: false,
            show_history: false,
            show_generator: false,
            show_recovery_shares: false,
            show_recovery_unlock: false,
            show_backups_unlock: false,
            recovery_input: Zeroizing::new(String::new()),
            breach: crate::breach::Catalogue::load(),
            autotype: None,
            generator_policy: Policy::default(),
            generator_preview: Zeroizing::new(String::new()),
            rollback_prompt: None,
            focus_search: false,
            window_theme: None,
            lock_watcher: LockWatcher::default(),
            last_lock_check: Instant::now(),
        }
    }

    pub fn strings(&self) -> &'static Strings {
        self.session.config.language.strings()
    }

    pub fn palette(&self) -> &'static Palette {
        self.session.config.appearance.palette()
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// True while a modal is up, so background shortcuts stay inert.
    fn modal_open(&self) -> bool {
        self.busy() || self.rollback_prompt.is_some() || self.confirm_delete.is_some()
    }

    /// Forget every password buffer the UI is holding.
    pub fn clear_inputs(&mut self) {
        self.password_input = Zeroizing::new(String::new());
        self.password_confirm = Zeroizing::new(String::new());
        self.generator_preview = Zeroizing::new(String::new());
        self.draft = None;
    }

    pub fn set_language(&mut self, lang: Lang) {
        self.session.config.language = lang;
        let _ = self.session.config.save();
    }

    pub fn set_appearance(&mut self, ctx: &egui::Context, appearance: Appearance) {
        self.session.config.appearance = appearance;
        theme::apply(ctx, appearance);
        let _ = self.session.config.save();
    }

    // ----------------------------------------------------------- background

    /// Run the unlock on a worker thread: two Argon2id passes plus a mount
    /// take seconds, and a frozen window looks like a crash.
    pub fn start_unlock(&mut self, ctx: &egui::Context, allow_rollback: bool) {
        if self.busy() {
            return;
        }
        let password = Secret::from_str(&self.password_input);
        let config = self.session.config.clone();
        let veracrypt = self.session.veracrypt().clone();
        let (sender, receiver) = channel();
        let ctx = ctx.clone();

        std::thread::spawn(move || {
            let outcome = match session::unlock(&veracrypt, &config, &password, allow_rollback) {
                Ok(open) => TaskOutcome::Unlocked(Box::new(open)),
                Err(Error::Rollback { on_disk, expected }) => {
                    TaskOutcome::RollbackDetected { on_disk, expected }
                }
                Err(e) => TaskOutcome::Failed(e),
            };
            let _ = sender.send(outcome);
            ctx.request_repaint();
        });

        self.task = Some(Task {
            label: self.strings().shell.busy_unlocking.to_owned(),
            receiver,
        });
        self.status = None;
    }

    pub fn start_create(&mut self, ctx: &egui::Context, size_bytes: u64) {
        if self.busy() {
            return;
        }
        let password = Secret::from_str(&self.password_input);
        let config = self.session.config.clone();
        let veracrypt = self.session.veracrypt().clone();
        let (sender, receiver) = channel();
        let ctx = ctx.clone();

        std::thread::spawn(move || {
            let outcome = match session::create_vault(
                &veracrypt, &config, &password, size_bytes,
            ) {
                Ok(open) => TaskOutcome::Created(Box::new(open)),
                Err(e) => TaskOutcome::Failed(e),
            };
            let _ = sender.send(outcome);
            ctx.request_repaint();
        });

        self.task = Some(Task {
            label: self.strings().shell.busy_creating.to_owned(),
            receiver,
        });
        self.status = None;
    }

    fn poll_task(&mut self) {
        let Some(task) = self.task.as_ref() else {
            return;
        };
        let Ok(outcome) = task.receiver.try_recv() else {
            return;
        };
        self.task = None;
        let strings = self.strings();

        match outcome {
            TaskOutcome::Unlocked(open) => {
                // Read before the vault is handed over. A missing or damaged
                // record is what a swapped-in older file leaves behind, and a
                // warning buried in a settings pane is one nobody opens.
                let state = open.vault.anchor_state();
                self.session.adopt(*open);
                self.screen = Screen::Main;
                self.clear_inputs();
                self.rollback_prompt = None;
                self.status = match state {
                    crate::vault::AnchorState::Removed => Some(Status::warn(
                        strings.anchor.removed_title,
                        strings.anchor.removed_body,
                    )),
                    crate::vault::AnchorState::Unverifiable => Some(Status::warn(
                        strings.anchor.unverifiable,
                        strings.anchor.unverifiable_body,
                    )),
                    // A first visit is announced in the settings pane; on the
                    // way in it would greet every new computer with an alarm.
                    crate::vault::AnchorState::Verified
                    | crate::vault::AnchorState::FirstSeenHere => None,
                };
            }
            TaskOutcome::Created(open) => {
                // With a container, mirror its sidecar into settings so losing
                // one copy of the key material is survivable.
                let used_container = open.container.is_some();
                if let Some(container) = open.container.as_ref() {
                    self.session.config.container_meta = Some(container.meta.clone());
                    let _ = self.session.config.save();
                }
                self.session.adopt(*open);
                self.screen = Screen::Main;
                self.clear_inputs();
                self.status = Some(if used_container {
                    Status::warn(strings.setup.backup_title, strings.setup.created_success)
                } else {
                    Status::warn(
                        strings.setup.backup_title,
                        strings.setup.created_success_standalone,
                    )
                });
            }
            TaskOutcome::RollbackDetected { on_disk, expected } => {
                self.rollback_prompt = Some((on_disk, expected));
            }
            TaskOutcome::Failed(e) => {
                self.status = Some(Status::error(strings, &e));
                if !e.is_retryable() {
                    self.password_input = Zeroizing::new(String::new());
                }
            }
        }
    }

    // ----------------------------------------------------------------- lock

    pub fn lock_now(&mut self) {
        let strings = self.strings();
        match self.session.lock() {
            Ok(()) => self.status = Some(Status::info(strings.shell.locked_notice)),
            Err(e) => self.status = Some(Status::error(strings, &e)),
        }
        self.screen = Screen::Locked;
        self.selected = None;
        self.search.clear();
        self.tag_filter = None;
        self.show_settings = false;
        self.show_audit = false;
        self.show_history = false;
        self.show_generator = false;
        self.reveal_password = false;
        self.clear_inputs();
    }

    /// Lock when the desktop does, if the user asked for that.
    ///
    /// Walking away and hitting Win+L is the common case the idle timer
    /// handles too slowly: it would leave the vault open, and the volume
    /// mounted, for however many minutes remain on the clock.
    fn check_screen_lock(&mut self) {
        if !self.session.is_unlocked() {
            self.lock_watcher.reset();
            return;
        }
        // A mount raises a UAC prompt, which lives on the secure desktop and
        // would otherwise read as "the workstation is locked".
        if self.busy() {
            self.lock_watcher.reset();
            return;
        }
        if self.last_lock_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_lock_check = Instant::now();

        if self
            .lock_watcher
            .should_lock(self.session.config.lock_on_screen_lock)
        {
            let strings = self.strings();
            let (title, body) = (
                strings.shell.screen_locked_title,
                strings.shell.screen_locked_body,
            );
            self.lock_now();
            self.status = Some(Status::warn(title, body));
        }
    }

    fn check_autolock(&mut self) {
        if self.session.should_autolock() {
            let strings = self.strings();
            let (title, body) = (
                strings.shell.autolocked_title,
                strings.shell.autolocked_body,
            );
            self.lock_now();
            self.status = Some(Status::warn(title, body));
        }
    }

    pub fn save_vault(&mut self) {
        let strings = self.strings();
        let Some(vault) = self.session.vault_mut() else {
            return;
        };
        if !vault.is_dirty() {
            return;
        }
        match vault.save() {
            Ok(()) => self.status = Some(Status::success(strings.shell.saved)),
            Err(e) => self.status = Some(Status::error(strings, &e)),
        }
    }

    // ------------------------------------------------------------ shortcuts

    /// Keyboard accelerators. Professional tools are driven from the keyboard,
    /// and a password manager especially so: the fewer trips to the mouse, the
    /// shorter the vault stays open.
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if self.modal_open() {
            // Esc still has to close a modal, which each modal handles itself.
            return;
        }
        let (ctrl, esc, keys) = ctx.input(|i| {
            (
                i.modifiers.command,
                i.key_pressed(egui::Key::Escape),
                (
                    i.key_pressed(egui::Key::N),
                    i.key_pressed(egui::Key::F),
                    i.key_pressed(egui::Key::L),
                    i.key_pressed(egui::Key::S),
                    i.key_pressed(egui::Key::G),
                ),
            )
        });
        let (n, f, l, s, g) = keys;

        if self.screen == Screen::Main && ctrl {
            if n {
                self.draft = Some(Draft::blank());
                self.selected = None;
                self.reveal_password = false;
            }
            if f {
                self.focus_search = true;
            }
            if l {
                self.lock_now();
                return;
            }
            if s {
                self.save_vault();
            }
            if g {
                self.show_generator = true;
            }
        }

        if esc {
            if self.show_generator {
                self.show_generator = false;
            } else if self.show_settings {
                self.show_settings = false;
            } else if self.show_audit {
                self.show_audit = false;
            } else if self.show_history {
                self.show_history = false;
            } else if self.draft.is_some() {
                self.draft = None;
                self.selected = None;
            } else if self.status.is_some() {
                self.status = None;
            }
        }
    }

    // ------------------------------------------------------------------ ui

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        let strings = self.strings();

        egui::Panel::top("toolbar")
            .frame(
                egui::Frame::new()
                    .fill(palette.surface)
                    .inner_margin(egui::Margin::symmetric(12, 7))
                    .stroke(egui::Stroke::new(1.0, palette.border)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Brand: a lock whose state mirrors the vault's.
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
                    let unlocked = self.screen == Screen::Main;
                    super::icons::paint(
                        ui.painter(),
                        if unlocked {
                            Icon::LockOpen
                        } else {
                            Icon::LockClosed
                        },
                        rect,
                        if unlocked {
                            palette.success
                        } else {
                            palette.accent
                        },
                    );
                    ui.add_space(2.0);
                    // `extend` keeps the brand on one line: in a toolbar the
                    // buttons should be what gives way, not the wordmark.
                    ui.add(egui::Label::new(theme::heading("Deep Defense", 15.0)).extend());
                    // The tagline is for the screens that have room for it.
                    if self.screen != Screen::Main {
                        ui.add(
                            egui::Label::new(theme::muted(palette, strings.shell.subtitle))
                                .extend(),
                        );
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        self.toolbar_right(ui, palette, strings);
                    });
                });
            });
    }

    fn toolbar_right(&mut self, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
        // Before the vault is open there is no Settings window, so the
        // language and theme pickers have to live here - and someone who
        // cannot read the current language must be able to change it before
        // logging in. On the main screen they would only crowd the actions.
        if self.screen == Screen::Main {
            self.toolbar_actions(ui, palette, strings);
            return;
        }

        let lang_index = Lang::ALL
            .iter()
            .position(|l| *l == self.session.config.language)
            .unwrap_or(0);
        let lang_options: Vec<(Icon, &str)> = Lang::ALL
            .iter()
            .map(|l| (Icon::Globe, l.native_name()))
            .collect();
        if let Some(picked) = widgets::segmented(ui, palette, "lang", &lang_options, lang_index) {
            self.set_language(Lang::ALL[picked]);
        }

        let appearance_index = if self.session.config.appearance == Appearance::Dark {
            1
        } else {
            0
        };
        let appearance_options = [
            (Icon::Sun, strings.common.theme_light),
            (Icon::Moon, strings.common.theme_dark),
        ];
        if let Some(picked) =
            widgets::segmented(ui, palette, "theme", &appearance_options, appearance_index)
        {
            let ctx = ui.ctx().clone();
            self.set_appearance(
                &ctx,
                if picked == 1 {
                    Appearance::Dark
                } else {
                    Appearance::Light
                },
            );
        }

    }

    /// The action buttons, shown only while a vault is open.
    fn toolbar_actions(&mut self, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
        if widgets::tool_button(ui, palette, Icon::LockClosed, strings.common.lock, false)
            .on_hover_text("Ctrl+L")
            .clicked()
        {
            self.lock_now();
            return;
        }
        if widgets::tool_button(
            ui,
            palette,
            Icon::Gear,
            strings.common.settings,
            self.show_settings,
        )
        .clicked()
        {
            self.show_settings = !self.show_settings;
            self.settings = settings::SettingsState::new(&self.session.config);
        }
        if widgets::tool_button(
            ui,
            palette,
            Icon::Shield,
            strings.common.health,
            self.show_audit,
        )
        .clicked()
        {
            self.show_audit = !self.show_audit;
        }
        if widgets::tool_button(
            ui,
            palette,
            Icon::Clock,
            strings.common.history,
            self.show_history,
        )
        .clicked()
        {
            self.show_history = !self.show_history;
        }
    }

    /// How long until the clipboard clears and until the vault locks itself.
    fn countdowns(&self, ui: &mut egui::Ui, palette: &Palette, strings: &Strings) {
        if let Some(seconds) = self.session.seconds_until_autolock() {
            // Amber under half a minute: long enough to finish a thought,
            // short enough that the warning still means something.
            let urgent = seconds <= 30;
            widgets::status_chip(
                ui,
                Icon::Clock,
                &fill1(strings.shell.locks_in, format_seconds(strings, seconds)),
                if urgent {
                    palette.warning
                } else {
                    palette.text_muted
                },
            );
        }
        if let Some(seconds) = self.session.clipboard.seconds_remaining() {
            ui.add_space(theme::space::MD);
            widgets::status_chip(
                ui,
                Icon::Copy,
                &fill1(strings.shell.clipboard_clears_in, seconds),
                palette.warning,
            );
        }
    }

    /// Type the pending password once its countdown runs out.
    fn tick_autotype(&mut self, ctx: &egui::Context) {
        let Some(pending) = self.autotype.as_ref() else {
            return;
        };
        if Instant::now() < pending.fires_at {
            // Without this the countdown would only advance when something
            // else asked for a repaint, and the delay would be unpredictable.
            ctx.request_repaint_after(Duration::from_millis(100));
            return;
        }

        let Some(pending) = self.autotype.take() else {
            return;
        };
        let strings = self.strings();
        let target = crate::platform::foreground_window()
            .map(|(title, _)| title)
            .unwrap_or_default();

        match crate::platform::type_text(&pending.text) {
            Ok(()) => {
                self.status = Some(Status::success(fill1(
                    strings.entry.autotype_done,
                    if target.is_empty() {
                        strings.common.unknown.to_owned()
                    } else {
                        target
                    },
                )))
            }
            Err(e) => self.status = Some(Status::error(strings, &e)),
        }
    }

    /// Start the countdown for one password.
    pub fn begin_autotype(&mut self, password: &str) {
        self.autotype = Some(PendingType {
            text: Zeroizing::new(password.to_owned()),
            fires_at: Instant::now() + AUTOTYPE_DELAY,
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let palette = self.palette();
        let strings = self.strings();

        if self.status.as_ref().is_some_and(|s| s.expired()) {
            self.status = None;
        }

        let Some(status) = self.status.as_ref() else {
            // With no message, the bar carries the shortcut legend and the
            // live countdowns: state belongs here, actions belong in the
            // toolbar, and neither has to fight the other for width.
            if self.screen == Screen::Main {
                egui::Panel::bottom("status_bar")
                    .frame(
                        egui::Frame::new()
                            .fill(palette.surface)
                            .inner_margin(egui::Margin::symmetric(12, 6))
                            .stroke(egui::Stroke::new(1.0, palette.border)),
                    )
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(theme::muted(
                                    palette,
                                    strings.shell.shortcut_hint,
                                ))
                                .truncate(),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    self.countdowns(ui, palette, strings);
                                    // Shown beside the others, and first,
                                    // because it is the one that is about to
                                    // do something to another window.
                                    if let Some(pending) = self.autotype.as_ref() {
                                        let left = pending
                                            .fires_at
                                            .saturating_duration_since(Instant::now())
                                            .as_secs()
                                            + 1;
                                        widgets::status_chip(
                                            ui,
                                            Icon::Keyboard,
                                            &fill1(strings.entry.autotype_waiting, left),
                                            palette.warning,
                                        );
                                    }
                                },
                            );
                        });
                    });
            }
            return;
        };

        let tone = status.tone;
        let title = status.title.clone();
        let body = status.body.clone();
        let mut dismiss = false;

        egui::Panel::bottom("status_bar")
            .frame(
                egui::Frame::new()
                    .fill(palette.surface)
                    .inner_margin(egui::Margin::symmetric(12, 9))
                    .stroke(egui::Stroke::new(1.0, palette.border)),
            )
            .show(ui, |ui| {
                ui.horizontal_top(|ui| {
                    let color = tone.color(palette);
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
                    super::icons::paint(ui.painter(), tone.icon(), rect, color);
                    ui.add_space(3.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(&title)
                                .color(color)
                                .size(13.0)
                                .family(egui::FontFamily::Name(theme::SEMIBOLD.into())),
                        );
                        if !body.is_empty() {
                            ui.label(egui::RichText::new(&body).size(12.5));
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        if widgets::icon_button(
                            ui,
                            palette,
                            Icon::Close,
                            strings.common.dismiss,
                            false,
                        )
                        .clicked()
                        {
                            dismiss = true;
                        }
                    });
                });
            });

        if dismiss {
            self.status = None;
        }
    }

    fn busy_overlay(&mut self, ui: &mut egui::Ui) {
        let Some(task) = self.task.as_ref() else {
            return;
        };
        let label = task.label.clone();
        let palette = self.palette();
        let strings = self.strings();

        egui::Modal::new(egui::Id::new("busy")).show(ui.ctx(), |ui| {
            ui.set_width(400.0);
            ui.vertical_centered(|ui| {
                ui.add_space(theme::space::MD);
                ui.add(egui::Spinner::new().size(30.0).color(palette.accent));
                ui.add_space(theme::space::MD);
                ui.label(egui::RichText::new(&label).size(13.5));
                ui.add_space(theme::space::XS);
                ui.label(theme::muted(palette, strings.shell.busy_note));
                ui.add_space(theme::space::MD);
            });
        });
    }

    fn rollback_modal(&mut self, ui: &mut egui::Ui) {
        let Some((on_disk, expected)) = self.rollback_prompt else {
            return;
        };
        let palette = self.palette();
        let strings = self.strings();
        let ctx = ui.ctx().clone();

        egui::Modal::new(egui::Id::new("rollback")).show(&ctx, |ui| {
            ui.set_width(470.0);
            widgets::notice(
                ui,
                palette,
                palette.warning,
                Icon::Warning,
                strings.shell.rollback_title,
                &fill2(strings.shell.rollback_body, on_disk, expected),
            );
            ui.add_space(theme::space::MD);
            ui.horizontal(|ui| {
                if widgets::primary_button(ui, palette, strings.shell.rollback_accept, true)
                    .clicked()
                {
                    self.rollback_prompt = None;
                    self.start_unlock(&ctx, true);
                }
                if ui.button(strings.common.cancel).clicked() {
                    self.rollback_prompt = None;
                    self.password_input = Zeroizing::new(String::new());
                }
            });
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_task();
        self.check_autolock();
        self.check_screen_lock();
        self.handle_shortcuts(ui.ctx());

        // The title bar has to be set from inside a frame, and only when it
        // changes - the command is a round trip to the window manager.
        let appearance = self.session.config.appearance;
        if self.window_theme != Some(appearance) {
            theme::apply_window_theme(ui.ctx(), appearance);
            self.window_theme = Some(appearance);
        }

        // Keep the countdowns honest even when nothing else is happening.
        ui.ctx().request_repaint_after(Duration::from_millis(500));

        // Any real interaction counts as the user still being there. Pointer
        // *movement* deliberately does not: a nudged desk should not keep an
        // unattended vault open indefinitely.
        if self.screen == Screen::Main
            && ui.ctx().input(|i| {
                i.pointer.any_click()
                    || i.pointer.any_down()
                    || i.smooth_scroll_delta != egui::Vec2::ZERO
                    || i.events.iter().any(|e| {
                        matches!(
                            e,
                            egui::Event::Key { .. }
                                | egui::Event::Text(_)
                                | egui::Event::Paste(_)
                                | egui::Event::PointerButton { .. }
                        )
                    })
            })
        {
            self.session.touch();
        }

        self.tick_autotype(ui.ctx());

        let palette = self.palette();
        self.toolbar(ui);
        self.status_bar(ui);

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(palette.bg))
            .show(ui, |ui| match self.screen {
                Screen::Setup => setup::show(self, ui),
                Screen::Locked => unlock::show(self, ui),
                Screen::Main => entries::show(self, ui),
            });

        if self.screen == Screen::Main {
            settings::show_window(self, ui);
            settings::show_audit_window(self, ui);
            settings::show_history_window(self, ui);
            settings::show_recovery_window(self, ui);
            entries::show_generator_window(self, ui);
        }
        self.rollback_modal(ui);
        self.busy_overlay(ui);
    }

    /// The `glow` backend hands back its context here so a program that
    /// allocated GPU resources can release them. We allocate none — the
    /// parameter exists because the renderer's trait says so.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Never leave a decrypted volume mounted behind us.
        self.session.emergency_lock();
    }
}

/// A countdown such as "5m 04s", in the reader's own abbreviations.
pub fn format_seconds(strings: &Strings, seconds: u64) -> String {
    let (minute, second) = (strings.common.minutes_short, strings.common.seconds_short);
    if seconds >= 60 {
        format!("{}{minute} {:02}{second}", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}{second}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        use crate::i18n::EN;
        assert_eq!(format_seconds(&EN, 0), "0s");
        assert_eq!(format_seconds(&EN, 45), "45s");
        assert_eq!(format_seconds(&EN, 60), "1m 00s");
        assert_eq!(format_seconds(&EN, 305), "5m 05s");
        assert_eq!(format_seconds(&EN, 3600), "60m 00s");
    }

    #[test]
    fn durations_use_the_readers_own_abbreviations() {
        use crate::i18n::RU;
        // A Russian interface showing "5m 04s" is the kind of seam that makes
        // a translation feel like a veneer.
        assert_eq!(format_seconds(&RU, 45), "45с");
        assert_eq!(format_seconds(&RU, 304), "5м 04с");
        assert!(!format_seconds(&RU, 304).contains('m'));
    }

    #[test]
    fn confirmations_fade_but_warnings_do_not() {
        // A warning that disappears before it is read is not a warning.
        assert!(Status::success("Saved").auto_dismiss);
        assert!(Status::info("Locked").auto_dismiss);
        assert!(!Status::warn("Careful", "details").auto_dismiss);
        assert!(!Status::error(&crate::i18n::EN, &Error::Authentication).auto_dismiss);
    }

    #[test]
    fn a_fresh_status_has_not_expired() {
        assert!(!Status::success("Saved").expired());
    }

    #[test]
    fn every_tone_has_a_colour_and_an_icon_in_both_palettes() {
        for tone in [Tone::Info, Tone::Success, Tone::Warning, Tone::Danger] {
            let _ = tone.icon();
            for palette in [&theme::DARK, &theme::LIGHT] {
                let _ = tone.color(palette);
            }
        }
    }

    #[test]
    fn a_draft_from_an_entry_copies_every_field() {
        let mut entry = Entry::new("GitHub");
        entry.username = "me@example.com".into();
        entry.url = "https://github.com".into();
        entry.tags = vec!["work".into(), "dev".into()];
        entry.totp_secret = "JBSWY3DPEHPK3PXP".into();
        entry.set_password("secret".into());

        let draft = Draft::from_entry(&entry);
        assert_eq!(draft.original_key.as_deref(), Some("github"));
        assert_eq!(draft.name, "GitHub");
        assert_eq!(draft.username, "me@example.com");
        assert_eq!(*draft.password, "secret");
        assert_eq!(draft.tags, "work, dev");
        assert_eq!(draft.parsed_tags(), vec!["work", "dev"]);
    }

    #[test]
    fn tag_parsing_drops_blanks_and_trims() {
        let mut draft = Draft::blank();
        draft.tags = "  work ,, email,  ,critical ".into();
        assert_eq!(draft.parsed_tags(), vec!["work", "email", "critical"]);
    }

    #[test]
    fn a_blank_draft_is_marked_as_new() {
        assert!(Draft::blank().original_key.is_none());
    }
}
