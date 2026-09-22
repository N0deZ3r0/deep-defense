//! Copying a password to the clipboard without leaving it there.
//!
//! The clipboard is the weakest link in any password manager: it is global,
//! every process on the desktop can read it, and on Windows 11 it is synced
//! to the cloud and kept in a searchable history by default. So we do three
//! things — exclude the value from history and cloud sync, clear it on a
//! timer, and clear it again when the program exits.
//!
//! We only clear if the clipboard still holds *our* value. Blindly wiping it
//! would destroy whatever the user copied in the meantime.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::errors::{Error, Result};

/// What we remember about a copy that is still waiting to be cleared.
///
/// The digest, not the text: keeping a second copy of the password alive for
/// the length of the timer would undo the point of the exercise.
#[derive(Clone)]
struct Pending {
    generation: u64,
    expires_at: Instant,
    digest: [u8; 32],
}

#[derive(Clone, Default)]
pub struct ClipboardManager {
    pending: Arc<Mutex<Option<Pending>>>,
    generation: Arc<AtomicU64>,
}

impl ClipboardManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy `text`, then clear it after `seconds`.
    pub fn copy_secret(&self, text: &str, seconds: u64) -> Result<()> {
        let mut clipboard = open()?;

        #[cfg(windows)]
        {
            use arboard::SetExtWindows;
            clipboard
                .set()
                .exclude_from_cloud()
                .exclude_from_history()
                .text(text.to_owned())
                .map_err(|e| Error::vault(format!("cannot write to the clipboard: {e}")))?;
        }
        #[cfg(not(windows))]
        {
            clipboard
                .set_text(text.to_owned())
                .map_err(|e| Error::vault(format!("cannot write to the clipboard: {e}")))?;
        }

        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let pending = Pending {
            generation,
            expires_at: Instant::now() + Duration::from_secs(seconds),
            digest: Sha256::digest(text.as_bytes()).into(),
        };
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(pending.clone());

        let manager = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds));
            // A newer copy supersedes this timer: without the generation
            // check, an old thread would wipe a freshly copied password.
            if manager.generation.load(Ordering::SeqCst) == pending.generation {
                manager.clear_if_ours(&pending.digest);
            }
        });
        Ok(())
    }

    /// Seconds left before the pending clear fires, for the UI countdown.
    pub fn seconds_remaining(&self) -> Option<u64> {
        let guard = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let pending = guard.as_ref()?;
        let now = Instant::now();
        if now >= pending.expires_at {
            return None;
        }
        Some((pending.expires_at - now).as_secs() + 1)
    }

    /// Clear immediately, whatever is pending.
    pub fn clear_now(&self) {
        let digest = {
            let guard = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|p| p.digest)
        };
        match digest {
            Some(digest) => self.clear_if_ours(&digest),
            None => {
                self.generation.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn clear_if_ours(&self, digest: &[u8; 32]) {
        let Ok(mut clipboard) = open() else {
            return;
        };
        // `get_text` fails when the clipboard holds a non-text format, which
        // means the user has copied something else - nothing for us to clear.
        if let Ok(current) = clipboard.get_text() {
            let current_digest: [u8; 32] = Sha256::digest(current.as_bytes()).into();
            if &current_digest == digest {
                let _ = clipboard.clear();
            }
        }
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// True while a copied secret is still sitting on the clipboard.
    pub fn has_pending(&self) -> bool {
        self.seconds_remaining().is_some()
    }
}

fn open() -> Result<arboard::Clipboard> {
    arboard::Clipboard::new().map_err(|e| {
        Error::vault(format!(
            "cannot reach the system clipboard: {e}. \
             Another application may be holding it open."
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // These touch the real system clipboard, so they are serialised and are
    // tolerant of a headless or busy environment where it is unavailable.
    static CLIPBOARD_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn copying_then_clearing_leaves_nothing_behind() {
        let _guard = CLIPBOARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let manager = ClipboardManager::new();
        if manager.copy_secret("deep-defense-test-value", 60).is_err() {
            return; // no clipboard in this environment
        }
        assert!(manager.has_pending());

        manager.clear_now();
        assert!(!manager.has_pending());

        if let Ok(mut clipboard) = open() {
            let text = clipboard.get_text().unwrap_or_default();
            assert_ne!(text, "deep-defense-test-value");
        }
    }

    #[test]
    fn a_newer_copy_supersedes_the_previous_timer() {
        let _guard = CLIPBOARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let manager = ClipboardManager::new();
        if manager.copy_secret("first", 60).is_err() {
            return;
        }
        let first = manager.generation.load(Ordering::SeqCst);
        manager.copy_secret("second", 60).unwrap();
        assert!(manager.generation.load(Ordering::SeqCst) > first);
        manager.clear_now();
    }

    #[test]
    fn we_do_not_wipe_something_the_user_copied_afterwards() {
        let _guard = CLIPBOARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let manager = ClipboardManager::new();
        if manager.copy_secret("our-secret", 60).is_err() {
            return;
        }
        // The user copies something else from another application.
        let Ok(mut clipboard) = open() else { return };
        if clipboard.set_text("the user's own text".to_owned()).is_err() {
            return;
        }

        manager.clear_now();

        let text = clipboard.get_text().unwrap_or_default();
        assert_eq!(text, "the user's own text");
    }
}
