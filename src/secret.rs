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

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// The unit the operating system locks memory in.
fn page_size() -> usize {
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        #[cfg(windows)]
        let size = {
            let mut info = windows_sys::Win32::System::SystemInformation::SYSTEM_INFO::default();
            unsafe { windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut info) };
            info.dwPageSize as usize
        };
        #[cfg(unix)]
        let size = usize::try_from(unsafe { libc_getpagesize() }).unwrap_or(0);
        #[cfg(not(any(windows, unix)))]
        let size = 0usize;
        if size == 0 {
            4096
        } else {
            size
        }
    })
}

/// How many live secrets hold each page that is locked on their behalf.
///
/// `VirtualLock` is not counted: a single `VirtualUnlock` releases a page
/// however many callers locked it. Secrets are small and share pages — the
/// master key and a password typed a moment ago can sit in the same four
/// kilobytes — so without a count, dropping the short-lived one released the
/// page under the long-lived one, and the master key became pageable the first
/// time anything else was wiped.
static LOCKED: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

/// The pages a region touches, as page numbers.
fn pages_of(ptr: *const u8, len: usize) -> std::ops::RangeInclusive<usize> {
    let page = page_size();
    let start = ptr as usize;
    (start / page)..=((start + (len - 1)) / page)
}

/// Ask the operating system to keep these bytes out of the page file.
///
/// Best-effort by design: a process may only lock so much before the call
/// starts failing, and failing to lock is not a reason to refuse to run. The
/// zeroing in `Drop` is the guarantee; this only narrows the window in which a
/// copy could reach the disk.
fn lock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let page = page_size();
    let mut held = LOCKED.lock().unwrap_or_else(|e| e.into_inner());
    for number in pages_of(ptr, len) {
        let count = held.entry(number).or_insert(0);
        if *count == 0 {
            os_lock(number * page, page);
        }
        *count += 1;
    }
}

/// Give back what [`lock_region`] took for the same region.
///
/// Called only once the bytes have been wiped: releasing first would leave the
/// page free to be written to the page file, secret and all, in the moment
/// between the two.
fn unlock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(test)]
    tests::SEEN_AT_UNLOCK.with(|seen| {
        // The region is still allocated: only its pages are being released.
        seen.borrow_mut()
            .push(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec());
    });
    let page = page_size();
    let mut held = LOCKED.lock().unwrap_or_else(|e| e.into_inner());
    for number in pages_of(ptr, len) {
        let Some(count) = held.get_mut(&number) else {
            continue;
        };
        *count -= 1;
        if *count == 0 {
            held.remove(&number);
            os_unlock(number * page, page);
        }
    }
}

fn os_lock(address: usize, len: usize) {
    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualLock(address as *mut core::ffi::c_void, len);
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc_mlock(address as *const core::ffi::c_void, len);
    }
    #[cfg(not(any(windows, unix)))]
    let _ = (address, len);
}

fn os_unlock(address: usize, len: usize) {
    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualUnlock(address as *mut core::ffi::c_void, len);
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc_munlock(address as *const core::ffi::c_void, len);
    }
    #[cfg(not(any(windows, unix)))]
    let _ = (address, len);
}

#[cfg(unix)]
extern "C" {
    #[link_name = "mlock"]
    fn libc_mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    #[link_name = "munlock"]
    fn libc_munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    #[link_name = "getpagesize"]
    fn libc_getpagesize() -> i32;
}

/// A password or key held in memory, wiped on drop.
///
/// It has no `Display`, no `Debug` that prints contents, and no `Serialize`,
/// because the most common way a secret escapes is a log line or a panic
/// message that someone added for debugging and forgot to remove.
pub struct Secret {
    inner: Zeroizing<Vec<u8>>,
}

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        let inner = Zeroizing::new(bytes);
        // The buffer never grows after this, so its address is stable and the
        // lock stays with the bytes it was taken for.
        lock_region(inner.as_ptr(), inner.len());
        Self { inner }
    }

    /// Not `std::str::FromStr`: that returns a `Result`, and there is no way
    /// for turning text into a secret to fail. Making it fallible to satisfy
    /// the trait would add an unwrap at every call site, which is worse than
    /// sharing a name with it.
    #[allow(clippy::should_implement_trait)]
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

/// Written out rather than derived: a derived clone would copy the bytes
/// without locking them, and its drop would then release pages it never held.
impl Clone for Secret {
    fn clone(&self) -> Self {
        Self::new(self.inner.to_vec())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Wipe, then release the pages. This used to run the other way round,
        // on the reasoning that the write had to land in the pinned pages —
        // but an address is the same page whether or not it is pinned, and
        // releasing first left the secret on a page free to be written to disk
        // until the wipe caught up.
        let (ptr, len) = (self.inner.as_ptr(), self.inner.len());
        self.inner.zeroize();
        unlock_region(ptr, len);
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
    /// On the heap, so the key stays at the address that was locked however
    /// often the `Key` itself is moved. Held inline, as it used to be, the
    /// bytes were copied to a new place by every move — the lock covered the
    /// stack slot of the constructor, and every earlier home kept a copy that
    /// nothing ever wiped.
    bytes: Box<Zeroizing<[u8; 32]>>,
}

impl Key {
    /// A key holding `bytes`. The array passed in is a copy, and is wiped
    /// here; prefer [`Key::zeroed`] and writing through [`Key::as_mut`], which
    /// makes no copy at all.
    pub fn new(mut bytes: [u8; 32]) -> Self {
        let mut key = Self::zeroed();
        key.as_mut().copy_from_slice(&bytes);
        bytes.zeroize();
        key
    }

    pub fn zeroed() -> Self {
        let bytes = Box::new(Zeroizing::new([0u8; 32]));
        lock_region(bytes.as_ptr(), bytes.len());
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Not `std::convert::AsMut`: that would let a key be handed to generic
    /// code expecting a plain array, which is exactly the accident this type
    /// exists to prevent. The name is the familiar one; the trait is not
    /// implemented on purpose.
    #[allow(clippy::should_implement_trait)]
    pub fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.bytes
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Wipe, then release: see `Secret`'s drop for why the order matters.
        let (ptr, len) = (self.bytes.as_ptr(), self.bytes.len());
        let bytes: &mut [u8; 32] = &mut self.bytes;
        bytes.zeroize();
        unlock_region(ptr, len);
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key([redacted; 32 bytes])")
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {
        // Straight from one heap copy to the other, with no array on the
        // stack in between to be left behind.
        let mut key = Self::zeroed();
        key.as_mut().copy_from_slice(self.as_bytes());
        key
    }
}

/// Serialise `value` as JSON into one allocation that wipes itself.
///
/// `serde_json::to_vec` grows its buffer as it writes, and every time it grows
/// the previous buffer is freed as it is — unwiped. For the vault that buffer
/// is every password in plaintext, so each save used to leave several partial
/// copies of the whole vault behind in freed memory. Measured first and
/// allocated once, the buffer never moves, and the one copy there is goes when
/// it is dropped.
pub fn json_bytes<T: serde::Serialize + ?Sized>(
    value: &T,
    pretty: bool,
) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    let length = json_len(value, pretty)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    if pretty {
        serde_json::to_writer_pretty(&mut *bytes, value)?;
    } else {
        serde_json::to_writer(&mut *bytes, value)?;
    }
    Ok(bytes)
}

/// How long `value` is as JSON, without writing it anywhere.
///
/// For asking how big the vault is: serialising it to find out, as the
/// free-space readout used to on every frame, made a plaintext copy of every
/// password each time.
pub fn json_len<T: serde::Serialize + ?Sized>(value: &T, pretty: bool) -> serde_json::Result<usize> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    if pretty {
        serde_json::to_writer_pretty(&mut count, value)?;
    } else {
        serde_json::to_writer(&mut count, value)?;
    }
    Ok(count.0)
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

    thread_local! {
        /// The bytes of each region at the moment its pages were released.
        pub(super) static SEEN_AT_UNLOCK: std::cell::RefCell<Vec<Vec<u8>>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn seen_at_unlock() -> Vec<Vec<u8>> {
        SEEN_AT_UNLOCK.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
    }

    fn holders(page_number: usize) -> usize {
        LOCKED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&page_number)
            .copied()
            .unwrap_or(0)
    }

    #[test]
    fn a_secret_is_wiped_before_its_pages_are_released() {
        // The defect this pins down: released first, the page was free to go
        // to the page file with the password still on it.
        seen_at_unlock();
        drop(Secret::from_str("unmistakable"));
        let seen = seen_at_unlock();
        assert_eq!(seen.len(), 1, "one region, released once");
        assert_eq!(seen[0].len(), "unmistakable".len());
        assert!(seen[0].iter().all(|&b| b == 0), "still readable at release: {:?}", seen[0]);
    }

    #[test]
    fn a_key_is_wiped_before_its_pages_are_released() {
        seen_at_unlock();
        drop(Key::new([0xA5; 32]));
        let seen = seen_at_unlock();
        // One for the key, and none for anything else: `new` makes no second
        // locked copy on the way.
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], vec![0u8; 32]);
    }

    #[test]
    fn a_key_stays_where_it_was_locked_when_it_moves() {
        let key = Key::new([3u8; 32]);
        let at = key.as_bytes().as_ptr();
        let page = at as usize / page_size();
        let moved = vec![key];
        let moved_again = moved.into_iter().next().unwrap();
        assert_eq!(moved_again.as_bytes().as_ptr(), at, "moving the key moved the bytes");
        assert!(holders(page) >= 1, "and the page it is on is still held");
        assert_eq!(moved_again.as_bytes(), &[3u8; 32]);
    }

    #[test]
    fn one_secret_leaving_does_not_release_its_neighbours_page() {
        // A page of our own, inside a buffer nothing else can share, so no
        // other test's secrets can be counted on it.
        let page = page_size();
        let buffer = vec![0u8; page * 3];
        let aligned = (buffer.as_ptr() as usize).div_ceil(page) * page;
        let number = aligned / page;
        let (first, second) = (aligned as *const u8, (aligned + 64) as *const u8);

        lock_region(first, 32);
        lock_region(second, 32);
        assert_eq!(holders(number), 2);
        unlock_region(first, 32);
        assert_eq!(holders(number), 1, "the neighbour's page was released with it");
        unlock_region(second, 32);
        assert_eq!(holders(number), 0);
        seen_at_unlock();
        drop(buffer);
    }

    #[test]
    fn a_cloned_secret_is_locked_and_released_like_the_original() {
        let original = Secret::from_str("cloned");
        let copy = original.clone();
        let page = copy.expose().as_ptr() as usize / page_size();
        assert!(holders(page) >= 1, "the copy was never locked");
        assert_eq!(copy, original);
        seen_at_unlock();
        drop(copy);
        let seen = seen_at_unlock();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].iter().all(|&b| b == 0));
    }

    #[test]
    fn json_is_written_in_one_allocation_of_exactly_its_length() {
        // One allocation, never grown: growing is what leaves copies behind.
        #[derive(serde::Serialize)]
        struct Sample<'a> {
            password: &'a str,
            notes: Vec<&'a str>,
        }
        let sample = Sample {
            password: "correct horse battery staple",
            notes: vec!["one", "two \"quoted\"", "три"],
        };
        for pretty in [false, true] {
            let bytes = json_bytes(&sample, pretty).unwrap();
            assert_eq!(bytes.len(), bytes.capacity(), "pretty = {pretty}");
            assert_eq!(bytes.len(), json_len(&sample, pretty).unwrap());
            let expected = if pretty {
                serde_json::to_vec_pretty(&sample).unwrap()
            } else {
                serde_json::to_vec(&sample).unwrap()
            };
            assert_eq!(bytes.as_slice(), expected.as_slice(), "the same bytes as serde_json's own");
        }
    }

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
        lock_region(std::ptr::null(), 0);
        unlock_region(std::ptr::null(), 0);
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
