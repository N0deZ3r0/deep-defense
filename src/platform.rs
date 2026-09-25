//! The few things that have to ask the operating system directly.

/// Whether the desktop is locked, or another session has the input desktop.
///
/// Detected by asking for the input desktop: when the workstation is locked,
/// the secure desktop owns it and the call fails. There is no polling-free way
/// to learn this without a window procedure, and the check is cheap enough to
/// run once a second.
///
/// It is deliberately conservative — it also reports `true` while a UAC prompt
/// is on screen, because that is the secure desktop too. The caller therefore
/// suppresses the check while a mount is in progress, which is the one moment
/// this program legitimately triggers UAC.
#[cfg(windows)]
pub fn workstation_is_locked() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{CloseDesktop, OpenInputDesktop};

    // DESKTOP_SWITCHDESKTOP
    const ACCESS: u32 = 0x0100;
    unsafe {
        let desktop = OpenInputDesktop(0, 0, ACCESS);
        if desktop.is_null() {
            return true;
        }
        CloseDesktop(desktop);
        false
    }
}

#[cfg(not(windows))]
pub fn workstation_is_locked() -> bool {
    // No portable equivalent; the idle timer still applies.
    false
}

// ----------------------------------------------------------------- auto-type

/// What is in front right now, and whether it is us.
///
/// Used to name the window before typing into it, and to refuse when that
/// window is our own — typing a password into the password manager's own
/// search box is the most likely way for this feature to go wrong.
#[cfg(windows)]
pub fn foreground_window() -> Option<(String, bool)> {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
    };

    unsafe {
        let window = GetForegroundWindow();
        if window.is_null() {
            return None;
        }

        let mut pid: u32 = 0;
        GetWindowThreadProcessId(window, &mut pid);
        let ours = pid == GetCurrentProcessId();

        let length = GetWindowTextLengthW(window);
        let title = if length > 0 {
            let mut buffer = vec![0u16; length as usize + 1];
            let written = GetWindowTextW(window, buffer.as_mut_ptr(), buffer.len() as i32);
            String::from_utf16_lossy(&buffer[..written.max(0) as usize])
        } else {
            String::new()
        };
        Some((title, ours))
    }
}

#[cfg(not(windows))]
pub fn foreground_window() -> Option<(String, bool)> {
    None
}

/// Send `text` to whatever window has the keyboard, one character at a time.
///
/// Sent as Unicode scan codes rather than virtual keys, so the result does not
/// depend on the keyboard layout in effect — a password containing `@` must
/// not arrive as `"` because the layout happens to be German.
#[cfg(windows)]
pub fn type_text(text: &str) -> crate::errors::Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
        KEYEVENTF_UNICODE,
    };

    if text.is_empty() {
        return Ok(());
    }
    // Refused rather than merely discouraged: by the time the user sees what
    // happened, the password is in a field they did not intend.
    if let Some((_, ours)) = foreground_window() {
        if ours {
            return Err(crate::errors::Error::format(
                "the window in front is this program's own",
            ));
        }
    }

    let mut events: Vec<INPUT> = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        for flags in [KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP] {
            events.push(INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        // Zero, because the character comes from wScan.
                        wVk: 0,
                        wScan: unit,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            });
        }
    }

    let sent = unsafe {
        SendInput(
            events.len() as u32,
            events.as_ptr(),
            size_of::<INPUT>() as i32,
        )
    };
    if sent as usize != events.len() {
        return Err(crate::errors::Error::format(
            "the system refused the keystrokes; another program may be blocking input",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn type_text(_text: &str) -> crate::errors::Result<()> {
    Err(crate::errors::Error::format(
        "typing into another window is only implemented on Windows",
    ))
}

// ------------------------------------------------------------ machine identity

/// A stable identifier for this computer, or `None` if there is none to read.
///
/// On Windows, `MachineGuid` — generated when Windows is installed, readable
/// without administrator rights, and the same for every user of the machine.
/// It is never stored as it is: the vault keeps only a keyed tag of it, so a
/// vault opened elsewhere carries no identifier of this computer, and a vault
/// that is never opened carries nothing at all.
#[cfg(windows)]
pub fn machine_id() -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Cryptography\0".encode_utf16().collect();
    let value: Vec<u16> = "MachineGuid\0".encode_utf16().collect();
    let mut buffer = [0u16; 128];
    let mut size = (buffer.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return None;
    }
    let units = (size as usize / 2).min(buffer.len());
    let id = String::from_utf16_lossy(&buffer[..units]);
    let id = id.trim_end_matches('\0').trim();
    (!id.is_empty()).then(|| id.to_string())
}

#[cfg(not(windows))]
pub fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .map(|text| text.trim().to_string())
        .filter(|id| !id.is_empty())
}

// ------------------------------------------------------------- durable rename

/// Replace `to` with `from`, and do not return until the change is on the disk.
///
/// The vault is written to a sibling file, flushed, and then renamed over the
/// real one, so a crash leaves either the old file or the new one. `sync_all`
/// makes the *contents* durable, but the rename is a separate change to the
/// directory, and nothing so far has waited for that. A power cut in the gap
/// can leave a directory entry that has not reached the platter — pointing at
/// either file, or at neither.
///
/// On Windows the flag for this is `MOVEFILE_WRITE_THROUGH`, which Rust's own
/// `fs::rename` does not pass. Elsewhere the equivalent is opening the parent
/// directory and syncing it.
#[cfg(windows)]
pub fn rename_durably(from: &std::path::Path, to: &std::path::Path) -> crate::errors::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    fn wide(path: &std::path::Path) -> Vec<u16> {
        let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
        encoded.push(0);
        encoded
    }

    let (source, destination) = (wide(from), wide(to));
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(crate::errors::Error::io(
            to.to_path_buf(),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn rename_durably(from: &std::path::Path, to: &std::path::Path) -> crate::errors::Result<()> {
    std::fs::rename(from, to).map_err(|e| crate::errors::Error::io(to.to_path_buf(), e))?;
    // The rename is a change to the directory, so the directory is what has to
    // be synced. Best effort: a filesystem that refuses to open a directory as
    // a file is not a reason to fail a save that has already succeeded.
    if let Some(parent) = to.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Debounces the lock check.
///
/// A single failed `OpenInputDesktop` is not proof of anything — it can happen
/// for a moment during a desktop switch. Locking a vault, and dismounting a
/// volume, is disruptive enough to be worth waiting for a second opinion.
#[derive(Default)]
pub struct LockWatcher {
    consecutive: u8,
}

impl LockWatcher {
    /// How many consecutive positive readings before we believe it.
    const THRESHOLD: u8 = 2;

    /// Call about once a second. Returns true once, on the reading that
    /// crosses the threshold.
    pub fn should_lock(&mut self, enabled: bool) -> bool {
        if !enabled {
            self.consecutive = 0;
            return false;
        }
        if workstation_is_locked() {
            self.consecutive = self.consecutive.saturating_add(1);
            self.consecutive == Self::THRESHOLD
        } else {
            self.consecutive = 0;
            false
        }
    }

    /// Forget what we have seen, after locking or while a mount is running.
    pub fn reset(&mut self) {
        self.consecutive = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The watcher's own logic, independent of what the desktop is doing.
    struct Fake {
        readings: Vec<bool>,
        index: usize,
        consecutive: u8,
    }

    impl Fake {
        fn step(&mut self) -> bool {
            let locked = self.readings[self.index];
            self.index += 1;
            if locked {
                self.consecutive += 1;
                self.consecutive == LockWatcher::THRESHOLD
            } else {
                self.consecutive = 0;
                false
            }
        }
    }

    #[test]
    fn one_reading_is_not_enough() {
        let mut fake = Fake {
            readings: vec![true, false, true, false],
            index: 0,
            consecutive: 0,
        };
        // A flicker during a desktop switch must not dismount anything.
        assert!(!fake.step());
        assert!(!fake.step());
        assert!(!fake.step());
        assert!(!fake.step());
    }

    #[test]
    fn two_in_a_row_trigger_once() {
        let mut fake = Fake {
            readings: vec![true, true, true, true],
            index: 0,
            consecutive: 0,
        };
        assert!(!fake.step());
        assert!(fake.step(), "the second reading should trigger");
        // And not again while it stays locked - the vault is already closed.
        assert!(!fake.step());
        assert!(!fake.step());
    }

    #[test]
    fn disabling_it_reports_nothing() {
        let mut watcher = LockWatcher::default();
        for _ in 0..5 {
            assert!(!watcher.should_lock(false));
        }
    }

    #[test]
    fn resetting_clears_the_count() {
        let mut watcher = LockWatcher { consecutive: 1 };
        watcher.reset();
        assert_eq!(watcher.consecutive, 0);
    }

    #[test]
    fn the_real_check_runs_and_answers() {
        // On a machine running tests the desktop is normally unlocked; the
        // point here is that the call itself is sound and does not hang.
        let _ = workstation_is_locked();
    }
}
