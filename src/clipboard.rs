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
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// How often a busy clipboard is tried before giving up, and how long apart.
const ATTEMPTS: u32 = 10;
const BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);

/// What we remember about a copy that is still waiting to be cleared.
///
/// The digest, not the text: keeping a second copy of the password alive for
/// the length of the timer would undo the point of the exercise.
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
                // Borrowed, not copied: a copy here would be one more heap
                // buffer holding the password, freed without a wipe.
                .text(text)
                .map_err(|e| Error::vault(format!("cannot write to the clipboard: {e}")))?;
        }
        #[cfg(not(windows))]
        {
            clipboard
                .set_text(text)
                .map_err(|e| Error::vault(format!("cannot write to the clipboard: {e}")))?;
        }

        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(Pending {
            generation,
            expires_at: Instant::now() + Duration::from_secs(seconds),
            digest,
        });

        let manager = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds));
            manager.expire(generation, &digest);
        });
        Ok(())
    }

    /// The timer for copy number `generation` has run out.
    fn expire(&self, generation: u64, digest: &[u8; 32]) {
        // A newer copy supersedes this timer: without the check, an old
        // thread would wipe a freshly copied password.
        if self.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        clear_if_holds(digest);
        // Only this copy's own record. One made while the clipboard was being
        // cleared has a timer of its own and a countdown to show; forgetting
        // it here left that password with nothing that would ever clear it.
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.as_ref().is_some_and(|p| p.generation == generation) {
            *pending = None;
        }
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
        // Whatever timer is still asleep has nothing left to do.
        self.generation.fetch_add(1, Ordering::SeqCst);
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(pending) = pending {
            clear_if_holds(&pending.digest);
        }
    }

    /// True while a copied secret is still sitting on the clipboard.
    pub fn has_pending(&self) -> bool {
        self.seconds_remaining().is_some()
    }
}

/// Clear the clipboard if what it holds hashes to `digest`.
///
/// Only then: blindly wiping it would destroy whatever the user copied in
/// the meantime. And more than once if need be. Another program holding the
/// clipboard open for a moment is ordinary on Windows — a clipboard manager,
/// a remote-desktop session — and one failed attempt used to be the end of
/// it: the timer had fired, nothing tried again, and the password stayed.
fn clear_if_holds(digest: &[u8; 32]) {
    for _ in 0..ATTEMPTS {
        if try_clear(digest) {
            return;
        }
        std::thread::sleep(BETWEEN_ATTEMPTS);
    }
}

/// One attempt. `false` means the clipboard was busy, and worth another.
fn try_clear(digest: &[u8; 32]) -> bool {
    let Ok(mut clipboard) = arboard::Clipboard::new() else {
        return false;
    };
    match clipboard.get_text() {
        Ok(current) => {
            // Read back, this is the password again; it is wiped like one.
            let current = Zeroizing::new(current);
            let held: [u8; 32] = Sha256::digest(current.as_bytes()).into();
            held != *digest || clipboard.clear().is_ok()
        }
        Err(arboard::Error::ClipboardOccupied) => false,
        // Anything else means it holds something that is not text: the user
        // has copied something else, and that is not ours to clear.
        Err(_) => true,
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
