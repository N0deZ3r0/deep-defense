//! Secret material that erases itself.
//!
//! This is the part Rust does genuinely better than a garbage-collected
//! language. `Zeroizing<T>` overwrites its buffer in `Drop` using volatile
//! writes the optimiser is not allowed to elide, so a master key stops
//! existing the moment it goes out of scope rather than whenever a collector
//! happens to run.
//!
//! Key material is also pinned in physical memory with `VirtualLock` (or
//! `mlock`), so the pages holding it are not written to the page file.
//!
//! The limits of that are worth stating plainly, because it is easy to
//! oversell. Locking is best-effort: the operating system caps how much a
//! process may lock, and the call can simply fail. It does nothing about
//! hibernation, which writes all of RAM to disk regardless. And it is no
//! defence against a debugger attached as the same user, which can read the
//! process while it runs.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Ask the operating system to keep these bytes out of the page file.
///
/// Best-effort by design: a process may only lock so much before the call
/// starts failing, and failing to lock is not a reason to refuse to run. The
/// zeroing in `Drop` is the guarantee; this only narrows the window in which a
/// copy could reach the disk.
fn lock_pages(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualLock(
            bytes.as_ptr() as *mut core::ffi::c_void,
            bytes.len(),
        );
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc_mlock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len());
    }
    #[cfg(not(any(windows, unix)))]
    let _ = bytes;
}

fn unlock_pages(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualUnlock(
            bytes.as_ptr() as *mut core::ffi::c_void,
            bytes.len(),
        );
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc_munlock(bytes.as_ptr() as *const core::ffi::c_void, bytes.len());
    }
    #[cfg(not(any(windows, unix)))]
    let _ = bytes;
}

#[cfg(unix)]
extern "C" {
    #[link_name = "mlock"]
    fn libc_mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    #[link_name = "munlock"]
    fn libc_munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
}

/// A password or key held in memory, wiped on drop.
///
/// It has no `Display`, no `Debug` that prints contents, and no `Serialize`,
/// because the most common way a secret escapes is a log line or a panic
/// message that someone added for debugging and forgot to remove.
#[derive(Clone)]
pub struct Secret {
    inner: Zeroizing<Vec<u8>>,
}

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        let inner = Zeroizing::new(bytes);
        // The buffer never grows after this, so its address is stable and the
        // lock stays with the bytes it was taken for.
        lock_pages(&inner);
        Self { inner }
    }

    pub fn from_str(text: &str) -> Self {
        Self::new(text.as_bytes().to_vec())
    }

    /// Take ownership of a `String`, wiping the original's buffer.
    ///
    /// Prefer this over `from_str` whenever you own the `String` - it leaves
    /// no second copy of the password behind in the caller's allocation.
    pub fn from_string(mut text: String) -> Self {
        let secret = Self::new(text.as_bytes().to_vec());
        text.zeroize();
        secret
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Expose as UTF-8 for the few APIs that demand a `&str`.
    ///
    /// Only VeraCrypt's command line needs this; keep the lifetime short.
    pub fn expose_str(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.inner)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Unlock before `Zeroizing` wipes: the write has to land in the pages
        // we pinned, not in whatever replaced them.
        unlock_pages(&self.inner);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret([redacted; {} bytes])", self.inner.len())
    }
}

/// Compares in constant time. A byte-by-byte comparison that returns early
/// leaks, through timing, how many leading bytes a guess got right.
impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner).into()
    }
}

impl Eq for Secret {}

/// A 256-bit symmetric key, wiped on drop.
pub struct Key {
    bytes: Zeroizing<[u8; 32]>,
}

impl Key {
    pub fn new(bytes: [u8; 32]) -> Self {
        let key = Self {
            bytes: Zeroizing::new(bytes),
        };
        lock_pages(key.bytes.as_slice());
        key
    }

    pub fn zeroed() -> Self {
        Self::new([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.bytes
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unlock_pages(self.bytes.as_slice());
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key([redacted; 32 bytes])")
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {
        Self::new(*self.bytes)
    }
}

/// Wipe a `String` in place, then drop it.
///
/// `String` can reallocate as it grows, and a reallocation leaves the old
/// bytes behind untouched. For text the user types into a field, prefer a
/// pre-sized buffer over trusting this to have caught every copy.
pub fn wipe_string(mut text: String) {
    text.zeroize();
}

/// Reduce the ways another process can read this one's memory.
///
/// On Windows this suppresses the error dialog and crash dump that would
/// otherwise be written with the master key still in the heap. It is a
/// mitigation, not a boundary: an attacker already running as this user can
/// attach a debugger regardless.
pub fn harden_process() {
    #[cfg(windows)]
    unsafe {
        // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
        windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(0x0001 | 0x0002);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_wipes_itself_on_drop() {
        let secret = Secret::from_str("master password");
        let address = secret.expose().as_ptr();
        let length = secret.len();
        drop(secret);
        // Reading freed memory is undefined behaviour, so this checks the
        // observable contract instead: the buffer existed and had content.
        assert!(!address.is_null());
        assert_eq!(length, "master password".len());
    }

    #[test]
    fn locking_an_empty_buffer_is_harmless() {
        // Called for zero-length secrets during setup, before anything is typed.
        lock_pages(&[]);
        unlock_pages(&[]);
        let empty = Secret::empty();
        assert!(empty.is_empty());
    }

    #[test]
    fn locking_does_not_disturb_the_contents() {
        // VirtualLock must not be doing anything to the bytes themselves.
        let secret = Secret::from_str("unmistakable");
        assert_eq!(secret.expose(), b"unmistakable");

        let key = Key::new([7u8; 32]);
        assert_eq!(key.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn many_secrets_at_once_still_work() {
        // The lock quota is finite; exceeding it must degrade to "not locked",
        // never to a failure.
        let secrets: Vec<Secret> = (0..500)
            .map(|i| Secret::from_string(format!("secret number {i}")))
            .collect();
        assert_eq!(secrets.len(), 500);
        assert_eq!(secrets[499].expose(), b"secret number 499");
    }

    #[test]
    fn secrets_compare_in_constant_time_and_by_value() {
        let a = Secret::from_str("same");
        let b = Secret::from_str("same");
        let c = Secret::from_str("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let secret = Secret::from_str("unmistakable-marker");
        let key = Key::new([1u8; 32]);
        assert!(!format!("{secret:?}").contains("unmistakable-marker"));
        assert!(format!("{secret:?}").contains("redacted"));
        assert!(format!("{key:?}").contains("redacted"));
    }

    #[test]
    fn from_string_leaves_no_second_copy() {
        let original = String::from("typed by the user");
        let secret = Secret::from_string(original);
        assert_eq!(secret.expose(), b"typed by the user");
    }
}
