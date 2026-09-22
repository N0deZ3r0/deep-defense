//! Driving the real VeraCrypt binary.
//!
//! This is a wrapper, not a reimplementation. Writing our own container
//! format would mean writing our own disk cryptography, and VeraCrypt's has
//! been audited and attacked for a decade; ours has not.
//!
//! One leak you should know about, because it cannot be fixed from here: on
//! Windows, VeraCrypt takes the volume password as a command-line argument,
//! and a process command line is readable by any other process running as the
//! same user. That is why the vault is *also* sealed with its own key — an
//! attacker who scrapes the container password still holds only ciphertext.
//! See the threat model in README.md.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use crate::errors::{Error, Result};
use crate::secret::Secret;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Drive letters we never hand out, even if Windows reports them free.
const RESERVED_LETTERS: [char; 3] = ['A', 'B', 'C'];

const WINDOWS_MAIN: [&str; 2] = [
    r"C:\Program Files\VeraCrypt\VeraCrypt.exe",
    r"C:\Program Files (x86)\VeraCrypt\VeraCrypt.exe",
];
const WINDOWS_FORMAT: [&str; 2] = [
    r"C:\Program Files\VeraCrypt\VeraCrypt Format.exe",
    r"C:\Program Files (x86)\VeraCrypt\VeraCrypt Format.exe",
];
const POSIX_MAIN: [&str; 3] = [
    "/usr/bin/veracrypt",
    "/usr/local/bin/veracrypt",
    "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt",
];

/// Where a mounted volume can be reached, and how to name it to VeraCrypt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountPoint {
    /// `Z:\` on Windows, a temporary directory elsewhere.
    pub path: PathBuf,
    /// `Z` on Windows, the same directory elsewhere.
    pub identifier: String,
    /// POSIX: did we create the directory, and so must remove it?
    pub created_dir: bool,
}

impl MountPoint {
    pub fn is_present(&self) -> bool {
        self.path.is_dir()
    }

    /// A mount point that exists but cannot be listed is not usable yet.
    /// Windows creates the drive node slightly before it is readable.
    pub fn is_ready(&self) -> bool {
        std::fs::read_dir(&self.path).is_ok()
    }
}

#[derive(Clone, Debug)]
pub struct VeraCrypt {
    pub binary: Option<PathBuf>,
    pub format_binary: Option<PathBuf>,
}

impl Default for VeraCrypt {
    fn default() -> Self {
        Self::discover()
    }
}

impl VeraCrypt {
    pub fn discover() -> Self {
        Self {
            binary: first_existing(if cfg!(windows) {
                &WINDOWS_MAIN
            } else {
                &POSIX_MAIN
            })
            .or_else(|| which("veracrypt")),
            format_binary: if cfg!(windows) {
                first_existing(&WINDOWS_FORMAT)
            } else {
                first_existing(&POSIX_MAIN).or_else(|| which("veracrypt"))
            },
        }
    }

    /// Use explicitly configured paths when present, else search.
    pub fn from_config(main: &Path, format: &Path) -> Self {
        let mut found = Self::discover();
        if main.is_file() {
            found.binary = Some(main.to_path_buf());
        }
        if format.is_file() {
            found.format_binary = Some(format.to_path_buf());
        }
        found
    }

    pub fn is_available(&self) -> bool {
        self.binary.as_ref().is_some_and(|p| p.is_file())
    }

    fn require(&self) -> Result<&PathBuf> {
        self.binary.as_ref().filter(|p| p.is_file()).ok_or_else(|| {
            Error::veracrypt(
                "VeraCrypt was not found on this system.\n\n\
                 Install it from https://www.veracrypt.fr and restart Deep Defense. \
                 If it is installed in an unusual location, set the path in Settings.",
            )
        })
    }

    fn run(&self, command: &mut Command, password: Option<&Secret>, stdin: bool) -> Result<Output> {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // We are a GUI app; never flash a console window at the user.
            command.creation_flags(CREATE_NO_WINDOW);
        }

        if stdin {
            use std::io::Write;
            command.stdin(std::process::Stdio::piped());
            command.stdout(std::process::Stdio::piped());
            command.stderr(std::process::Stdio::piped());
            let mut child = command
                .spawn()
                .map_err(|e| Error::veracrypt(format!("cannot start VeraCrypt: {e}")))?;
            if let Some(secret) = password {
                let mut pipe = child
                    .stdin
                    .take()
                    .ok_or_else(|| Error::veracrypt("cannot open a pipe to VeraCrypt"))?;
                pipe.write_all(secret.expose())
                    .and_then(|_| pipe.write_all(b"\n"))
                    .map_err(|e| Error::veracrypt(format!("cannot send the password: {e}")))?;
                // Dropping the pipe closes stdin, which VeraCrypt waits for.
            }
            child
                .wait_with_output()
                .map_err(|e| Error::veracrypt(format!("VeraCrypt did not run: {e}")))
        } else {
            command
                .output()
                .map_err(|e| Error::veracrypt(format!("cannot start VeraCrypt: {e}")))
        }
    }

    // --------------------------------------------------------------- create

    /// Create a new file-hosted VeraCrypt container.
    ///
    /// Refuses to touch an existing file: silently reformatting a container
    /// would destroy whatever was inside it.
    pub fn create_volume(
        &self,
        container: &Path,
        size_bytes: u64,
        password: &Secret,
        keyfiles: &[PathBuf],
        encryption: &str,
        hash_algo: &str,
        quick: bool,
    ) -> Result<()> {
        self.require()?;
        let format_binary = self
            .format_binary
            .as_ref()
            .filter(|p| p.is_file())
            .ok_or_else(|| {
                Error::veracrypt("\"VeraCrypt Format\" was not found next to VeraCrypt")
            })?;

        if container.exists() {
            return Err(Error::veracrypt(format!(
                "refusing to overwrite an existing file: {}",
                container.display()
            )));
        }
        if let Some(parent) = container.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent.to_path_buf(), e))?;
        }

        let mut command = Command::new(format_binary);
        #[cfg(windows)]
        {
            let password_text = password
                .expose_str()
                .map_err(|_| Error::veracrypt("the password is not valid UTF-8"))?;
            command.args(windows_create_args(
                container,
                size_bytes,
                password_text,
                keyfiles,
                encryption,
                hash_algo,
                quick,
            ));
            let output = self.run(&mut command, Some(password), false)?;
            self.check_created(container, &output)
        }
        #[cfg(not(windows))]
        {
            command.args(posix_create_args(
                container, size_bytes, keyfiles, encryption, hash_algo, quick,
            ));
            let output = self.run(&mut command, Some(password), true)?;
            self.check_created(container, &output)
        }
    }

    /// VeraCrypt Format can exit 0 having done nothing, so verify the
    /// artefact rather than trusting the exit code.
    fn check_created(&self, container: &Path, output: &Output) -> Result<()> {
        if container.is_file() {
            return Ok(());
        }
        Err(Error::veracrypt(format!(
            "the container was not created (exit code {}).\n{}",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".into()),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    // ---------------------------------------------------------------- mount

    pub fn mount(
        &self,
        container: &Path,
        password: &Secret,
        keyfiles: &[PathBuf],
        pim: u32,
        read_only: bool,
    ) -> Result<MountPoint> {
        let binary = self.require()?.clone();
        if !container.is_file() {
            return Err(Error::veracrypt(format!(
                "container not found: {}",
                container.display()
            )));
        }

        let mount_point;
        let mut command = Command::new(&binary);

        #[cfg(windows)]
        {
            let letter = free_drive_letter()?;
            mount_point = MountPoint {
                path: PathBuf::from(format!("{letter}:\\")),
                identifier: letter.to_string(),
                created_dir: false,
            };
            let password_text = password
                .expose_str()
                .map_err(|_| Error::veracrypt("the password is not valid UTF-8"))?;
            command.args(windows_mount_args(
                container,
                letter,
                password_text,
                keyfiles,
                pim,
                read_only,
            ));
            self.run(&mut command, Some(password), false)?;
        }
        #[cfg(not(windows))]
        {
            let dir = std::env::temp_dir().join(format!("deep-defense-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(|e| Error::io(dir.clone(), e))?;
            mount_point = MountPoint {
                path: dir.clone(),
                identifier: dir.display().to_string(),
                created_dir: true,
            };
            command.args(posix_mount_args(container, &dir, keyfiles, pim, read_only));
            self.run(&mut command, Some(password), true)?;
        }

        // The Windows binary returns before the volume is actually attached,
        // so poll for a readable mount point instead of trusting the exit
        // code. A mount point that never becomes readable means failure.
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            if mount_point.is_present() && mount_point.is_ready() {
                return Ok(mount_point);
            }
            std::thread::sleep(Duration::from_millis(150));
        }

        self.cleanup_dir(&mount_point);
        Err(Error::veracrypt(
            "could not mount the container.\n\n\
             The usual causes are a wrong password, wrong or missing keyfiles, \
             a wrong PIM, or the container already being mounted elsewhere.",
        ))
    }

    // ------------------------------------------------------------- dismount

    /// Detach the volume. Returns `true` once it is really gone.
    pub fn dismount(&self, mount_point: &MountPoint, force: bool) -> bool {
        let Some(binary) = self.binary.as_ref() else {
            return false;
        };
        let mut command = Command::new(binary);
        #[cfg(windows)]
        {
            command
                .arg("/dismount")
                .arg(&mount_point.identifier)
                .arg("/quit")
                .arg("/silent");
            if force {
                command.arg("/force");
            }
        }
        #[cfg(not(windows))]
        {
            command
                .args(["--text", "--dismount"])
                .arg(&mount_point.path)
                .arg("--non-interactive");
            if force {
                command.arg("--force");
            }
        }
        let _ = self.run(&mut command, None, false);

        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if !mount_point.is_present() {
                self.cleanup_dir(mount_point);
                return true;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        false
    }

    /// Panic button: detach every VeraCrypt volume on the system.
    ///
    /// Used when the process is going down unexpectedly and we would rather
    /// over-dismount than leave a decrypted volume attached.
    pub fn dismount_all(&self, force: bool) {
        let Some(binary) = self.binary.as_ref() else {
            return;
        };
        let mut command = Command::new(binary);
        #[cfg(windows)]
        {
            command.args(["/dismount", "/quit", "/silent"]);
            if force {
                command.arg("/force");
            }
        }
        #[cfg(not(windows))]
        {
            command.args(["--text", "--dismount", "--non-interactive"]);
            if force {
                command.arg("--force");
            }
        }
        let _ = self.run(&mut command, None, false);
    }

    fn cleanup_dir(&self, mount_point: &MountPoint) {
        if mount_point.created_dir && mount_point.path.is_dir() {
            let _ = std::fs::remove_dir(&mount_point.path);
        }
    }
}

// ------------------------------------------------------------ command lines
//
// Kept as pure functions so they can be tested without VeraCrypt installed.
// A wrong flag here fails at the worst possible moment - while creating or
// opening someone's vault - and the mistakes are quiet ones: a missing
// `/silent` hangs on a dialog, a missing `/tryemptypass n` pops a password
// box, a wrong `/size` makes a container of the wrong size.

#[cfg(windows)]
fn windows_create_args(
    container: &Path,
    size_bytes: u64,
    password: &str,
    keyfiles: &[PathBuf],
    encryption: &str,
    hash_algo: &str,
    quick: bool,
) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut args: Vec<OsString> = vec![
        "/create".into(),
        container.into(),
        "/size".into(),
        size_bytes.to_string().into(),
        "/password".into(),
        password.into(),
        "/encryption".into(),
        encryption.into(),
        "/hash".into(),
        hash_algo.into(),
        "/filesystem".into(),
        "NTFS".into(),
        "/pim".into(),
        "0".into(),
        "/force".into(),
        "/silent".into(),
    ];
    if quick {
        args.push("/quick".into());
    }
    for keyfile in keyfiles {
        args.push("/keyfile".into());
        args.push(keyfile.into());
    }
    args
}

#[cfg(windows)]
fn windows_mount_args(
    container: &Path,
    letter: char,
    password: &str,
    keyfiles: &[PathBuf],
    pim: u32,
    read_only: bool,
) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut args: Vec<OsString> = vec![
        "/volume".into(),
        container.into(),
        "/letter".into(),
        letter.to_string().into(),
        "/password".into(),
        password.into(),
        "/pim".into(),
        pim.to_string().into(),
        "/quit".into(),
        "/silent".into(),
        // Never let VeraCrypt raise its own password box: a silent failure
        // must fail, not sit waiting for a human who is not watching.
        "/tryemptypass".into(),
        "n".into(),
    ];
    if read_only {
        args.push("/mountoption".into());
        args.push("ro".into());
    }
    for keyfile in keyfiles {
        args.push("/keyfile".into());
        args.push(keyfile.into());
    }
    args
}

#[cfg(not(windows))]
fn posix_create_args(
    container: &Path,
    size_bytes: u64,
    keyfiles: &[PathBuf],
    encryption: &str,
    hash_algo: &str,
    quick: bool,
) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut args: Vec<OsString> = vec![
        "--text".into(),
        "--create".into(),
        container.into(),
        "--size".into(),
        size_bytes.to_string().into(),
        "--encryption".into(),
        encryption.into(),
        "--hash".into(),
        hash_algo.into(),
        "--filesystem".into(),
        "FAT".into(),
        "--volume-type".into(),
        "normal".into(),
        "--pim".into(),
        "0".into(),
        "--random-source".into(),
        "/dev/urandom".into(),
        "--keyfiles".into(),
        join_keyfiles(keyfiles).into(),
        // The password arrives on stdin, never on the command line.
        "--stdin".into(),
        "--non-interactive".into(),
    ];
    if quick {
        args.push("--quick".into());
    }
    args
}

#[cfg(not(windows))]
fn posix_mount_args(
    container: &Path,
    mount_dir: &Path,
    keyfiles: &[PathBuf],
    pim: u32,
    read_only: bool,
) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut args: Vec<OsString> = vec![
        "--text".into(),
        "--mount".into(),
        container.into(),
        mount_dir.into(),
        "--pim".into(),
        pim.to_string().into(),
        "--keyfiles".into(),
        join_keyfiles(keyfiles).into(),
        "--protect-hidden".into(),
        "no".into(),
        "--stdin".into(),
        "--non-interactive".into(),
    ];
    if read_only {
        args.push("--mount-options".into());
        args.push("ro".into());
    }
    args
}

#[cfg(not(windows))]
fn join_keyfiles(keyfiles: &[PathBuf]) -> String {
    keyfiles
        .iter()
        .map(|k| k.display().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        for candidate in [dir.join(program), dir.join(format!("{program}.exe"))] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    })
}

/// Return a drive letter Windows is not currently using.
///
/// Walks backwards from Z: high letters are far less likely to collide with a
/// drive the user plugs in while the vault is open.
#[cfg(windows)]
fn free_drive_letter() -> Result<char> {
    let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    if mask == 0 {
        return Err(Error::veracrypt("cannot enumerate drive letters"));
    }
    for index in (0..26u32).rev() {
        let letter = (b'A' + index as u8) as char;
        if RESERVED_LETTERS.contains(&letter) {
            continue;
        }
        if mask & (1 << index) == 0 {
            return Ok(letter);
        }
    }
    Err(Error::veracrypt(
        "every drive letter is in use — free one and try again",
    ))
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn free_drive_letter() -> Result<char> {
    Err(Error::veracrypt("drive letters are a Windows concept"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[std::ffi::OsString]) -> Vec<String> {
        args.iter().map(|a| a.to_string_lossy().into_owned()).collect()
    }

    fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn a_missing_binary_gives_advice_not_a_bare_failure() {
        let absent = VeraCrypt {
            binary: None,
            format_binary: None,
        };
        assert!(!absent.is_available());
        let message = absent.require().unwrap_err().to_string();
        assert!(message.contains("veracrypt.fr"), "{message}");
    }

    #[test]
    fn creating_over_an_existing_file_is_refused() {
        // Reformatting a container would destroy whatever was inside it.
        let dir = std::env::temp_dir().join(format!("dd-vc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("already-here.hc");
        std::fs::write(&existing, b"precious data").unwrap();

        let veracrypt = VeraCrypt {
            binary: Some(existing.clone()),
            format_binary: Some(existing.clone()),
        };
        let err = veracrypt
            .create_volume(
                &existing,
                1024 * 1024,
                &Secret::from_str("pw"),
                &[],
                "AES",
                "sha512",
                false,
            )
            .unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));
        // ...and the file is untouched.
        assert_eq!(std::fs::read(&existing).unwrap(), b"precious data");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mounting_a_missing_container_fails_before_launching_anything() {
        let veracrypt = VeraCrypt {
            binary: Some(PathBuf::from(file!())), // any real file
            format_binary: None,
        };
        let err = veracrypt
            .mount(
                Path::new("definitely-not-here.hc"),
                &Secret::from_str("pw"),
                &[],
                0,
                false,
            )
            .unwrap_err();
        assert!(err.to_string().contains("container not found"));
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_mount_line_is_fully_non_interactive() {
        let args = strings(&windows_mount_args(
            Path::new(r"C:\vaults\v.hc"),
            'Z',
            "volume-password",
            &[],
            0,
            false,
        ));
        // Any of these missing turns a silent failure into a dialog box that
        // waits forever on a machine nobody is looking at.
        assert!(args.contains(&"/silent".to_string()));
        assert!(args.contains(&"/quit".to_string()));
        assert!(has_pair(&args, "/tryemptypass", "n"));
        assert!(has_pair(&args, "/letter", "Z"));
        assert!(has_pair(&args, "/password", "volume-password"));
        assert!(!args.contains(&"/mountoption".to_string()));
    }

    #[cfg(windows)]
    #[test]
    fn read_only_and_keyfiles_reach_the_windows_mount_line() {
        let keyfiles = vec![PathBuf::from(r"E:\a.key"), PathBuf::from(r"E:\b.key")];
        let args = strings(&windows_mount_args(
            Path::new(r"C:\v.hc"),
            'Y',
            "pw",
            &keyfiles,
            485,
            true,
        ));
        assert!(has_pair(&args, "/mountoption", "ro"));
        assert!(has_pair(&args, "/pim", "485"));
        assert_eq!(args.iter().filter(|a| *a == "/keyfile").count(), 2);
        assert!(args.contains(&r"E:\b.key".to_string()));
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_create_line_carries_size_and_cipher() {
        let args = strings(&windows_create_args(
            Path::new(r"C:\v.hc"),
            64 * 1024 * 1024,
            "pw",
            &[],
            "AES(Twofish(Serpent))",
            "sha512",
            false,
        ));
        assert!(has_pair(&args, "/size", "67108864"));
        assert!(has_pair(&args, "/encryption", "AES(Twofish(Serpent))"));
        assert!(has_pair(&args, "/hash", "sha512"));
        assert!(args.contains(&"/silent".to_string()));
        // Without /quick, VeraCrypt fills the container with random data -
        // which is what we want, so it must be absent by default.
        assert!(!args.contains(&"/quick".to_string()));
    }

    #[cfg(not(windows))]
    #[test]
    fn the_posix_lines_take_the_password_on_stdin() {
        // On POSIX there is no excuse for putting a password in argv.
        let mount = strings(&posix_mount_args(
            Path::new("/vaults/v.hc"),
            Path::new("/tmp/mnt"),
            &[],
            0,
            false,
        ));
        assert!(mount.contains(&"--stdin".to_string()));
        assert!(mount.contains(&"--non-interactive".to_string()));
        assert!(!mount.iter().any(|a| a.contains("password")));

        let create = strings(&posix_create_args(
            Path::new("/vaults/v.hc"),
            1024,
            &[],
            "AES",
            "sha512",
            false,
        ));
        assert!(create.contains(&"--stdin".to_string()));
        assert!(!create.iter().any(|a| a.contains("password")));
    }

    #[cfg(windows)]
    #[test]
    fn the_chosen_drive_letter_is_free_and_not_reserved() {
        let letter = free_drive_letter().unwrap();
        assert!(!RESERVED_LETTERS.contains(&letter));
        // If Windows says it is free, the directory must not be there.
        assert!(!Path::new(&format!("{letter}:\\")).is_dir());
    }

    #[test]
    fn a_mount_point_that_is_not_there_is_not_ready() {
        let absent = MountPoint {
            path: PathBuf::from("definitely-not-a-mount-point"),
            identifier: "X".into(),
            created_dir: false,
        };
        assert!(!absent.is_present());
        assert!(!absent.is_ready());
    }
}
