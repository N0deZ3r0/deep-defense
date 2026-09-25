<div align="center">

# Deep Defense

**Two unrelated ciphers over one password, and a file that will not say whether it holds one vault or two.**

[![CI](https://github.com/N0deZ3r0/deep-defense/actions/workflows/ci.yml/badge.svg)](https://github.com/N0deZ3r0/deep-defense/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-1.1.0-3b5bdb)
![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-4c6ef5)
![tests](https://img.shields.io/badge/tests-378-2f9e44)
![Rust](https://img.shields.io/badge/Rust-1.98-dea584)
![install](https://img.shields.io/badge/install-none-2f9e44)

**English** · [Русский](README.ru.md)

</div>

A password manager for Windows: one `.exe`, nothing to install, no administrator
rights, no account, no network. The interface is in English and Russian and follows
the language you pick.

## First, honestly, about "impossible to break"

Nothing is. What can be said precisely is what an attacker holding your file has to
do, and what this program cannot help with.

**Against the file, they must guess the master password.** Each guess costs an
Argon2id pass — by default 256 MiB and four iterations, which a graphics card cannot
parallelise its way out of. A passphrase of five random words costs more than any
budget worth spending on one person.

**They cannot do less.** The vault is sealed under AES-256-GCM *and*
XChaCha20-Poly1305, in cascade, with independent subkeys. A break in one of them
leaves the other, and the two share no structure to break together.

**None of that helps** if malware is already running as you, if someone films your
keyboard, or if you forget the password and never made the recovery pieces. Those are
the realistic ways to lose a vault, and two of the three are outside a program's
reach.

This is a self-built construction that has not been audited. It is written to be read —
every non-obvious decision carries the reasoning next to it — but read is not audited.
Keeping a copy of your passwords in something mainstream is sensible insurance, and
the export exists so that staying is a choice rather than a trap.

## Install

Download `deep-defense.exe` from
[Releases](https://github.com/N0deZ3r0/deep-defense/releases/latest) and run it. That
is the whole procedure.

Before running a copy you did not build yourself, check its fingerprint against
`SHA256SUMS.txt` in the same release:

```powershell
(Get-FileHash -Algorithm SHA256 .\deep-defense.exe).Hash
```

A swapped executable is the end of everything this program protects — it would simply
read the password as you type it. There is no signing certificate here, so a
fingerprint recorded at build time is the next best thing.

VeraCrypt is **optional**. Without it the vault file is still sealed under the full
cascade; with it the whole thing additionally sits inside a mounted volume. That
layer needs a kernel driver and therefore administrator rights, which is why it is off
by default.

## How it is protected

- **Argon2id** turns the master password into one key, then **HKDF** splits that into
  independent subkeys — one per cipher. Argon2id runs once per unlock, not once per
  cipher: the cost belongs to guessing the password, and running it twice would double
  the wait for the user and change nothing for the attacker.
- **A cipher cascade.** XChaCha20-Poly1305 inside AES-256-GCM, each with its own key.
  Both are authenticated, so a modified file is refused rather than misread.
- **A key derived per message.** A fresh 32-byte seed makes each message key unique,
  so a fixed nonce is safe and the birthday bound that limits random 96-bit IVs does
  not apply. This is the XAES-256-GCM idea.
- **Keys wiped and pinned.** Keys and passwords live in buffers that overwrite
  themselves on the way out and are pinned with `VirtualLock` so they do not reach the
  page file. `panic = "abort"` is deliberately **not** set: aborting would skip the
  destructors, which is to say the wiping.
- **Atomic writes and five rotating backups**, plus an optional second directory so
  the copies are not all on one disk. The rename that commits a save is made durable
  too — flushing the file's contents is not the same as flushing the directory entry
  that points at it, and a power cut in that gap is the one moment a vault could be
  lost to a crash.
- **A ceiling on what the file may ask for.** The Argon2 parameters live in the vault
  header, which means they are chosen by whoever supplies the file, and they are read
  before anything in it has been authenticated — deriving the key is what authenticates
  it. Without a bound, `m_cost` is a `u32`: a crafted header could ask for four
  terabytes, and a failed allocation in Rust ends the process rather than returning an
  error. The bound is the largest thing this program's own settings can produce, so no
  vault anyone legitimately made is refused by it.

## What it does beyond storing passwords

**A hidden vault.** One file holds two slots of identical fixed size. The unused one
is filled with random bytes, and everything on disk — salt, seed, ciphertext, padding —
is indistinguishable from random, so the file cannot answer whether a second vault
exists. Your password opens whichever slot belongs to it. A file with a hidden vault
is byte-for-byte the same size as one without.

**Recovery by Shamir's scheme.** The master password splits into pieces of which any
*k* rebuild it and any *k−1* say nothing at all — not "almost nothing": the remaining
possibilities are exactly as numerous as before. Nothing is stored; the pieces exist
only where you put them. Deliberately, a piece carries **no hash of the secret** —
that would turn one photographed piece into an offline cracking target, which is the
attack the whole program exists to prevent.

**An offline check against published passwords.** A Bloom filter compiled into the
binary answers "this password is already public" without a network call and cannot be
read back into a wordlist. A weak-because-published master password is refused; for an
entry it is a warning, because you may not be free to change that site's password this
minute.

**A tamper-evident change log**, hash-chained so a removed line is visible, and a
**rollback record** kept outside the vault so restoring an older file is noticed. The
record has a second witness: every open also compares the file with the backups beside
it and with the mirror, using the key already derived, so deleting the record — or
putting it back from the same old snapshot as the file — is not enough, and the newer
copy can be put back from the prompt itself. Changing the master password retires the
old key's record, so the file from just before the change cannot pass for current.
When there really was nothing to compare against, the program says so on the way in.

**The work factor can be raised later.** Argon2 parameters live in the file header and
used to be fixed at creation, so a vault built for today's hardware would still be
guarded by today's costs in ten years. The file can now be rebuilt under new
parameters, and the slot size raised with it.

**Typing into another window**, skipping the clipboard entirely — the last place a
password sits in the clear where everything on the machine can read it. Characters go
out as Unicode rather than virtual keys, so the result does not depend on the keyboard
layout. The program refuses to type into its own window.

**Import and export** for KeePass, Bitwarden, 1Password, Chrome and Firefox, matched by
column name rather than position. An entry whose name already exists is never
overwritten.

Also: TOTP codes, attachments, custom fields, a password health report, a generator,
auto-lock on idle and on screen lock, and a clipboard that clears itself.

## How it is verified

```bash
cargo test            # 369 tests, about four minutes
cargo build --release # or build.ps1, which also records the fingerprint
```

The interesting ones are not the round trips.

`src/robustness.rs` takes every parser — the vault file, the Bloom filter, CSV, JSON,
recovery pieces, authenticator secrets — and breaks it at random tens of thousands of
times, biased towards the first hundred bytes where headers and length fields live.
Exactly one thing counts as failure: a panic. A parser may reject whatever it likes;
what it may not do is bring the process down on a length the file supplied. Around
150,000 mutated inputs, no panics.

`shamir.rs` proves the information-theoretic claim rather than asserting it: for a
two-of-two split of one byte, one piece plus every possible partner yields every
possible secret exactly once.

Nine tests beyond those 369, in `ui/snapshots.rs`, draw the real screens — the lock
screen and its backups, the older-file prompt in each of its three forms, settings
sections — with egui's own test harness, through wgpu on WARP, the software Direct3D 12
adapter every Windows runner has. CI keeps the pictures for a person to look at, and
every test also asserts on what is on screen, so the job fails on its own. They sit
behind the `ui-snapshots` feature because the renderer is a large dependency the program
never needs.

`ui/widgets.rs` renders the interface with AccessKit enabled, walks the accessibility
tree and fails if any interactive control has no name. The field helpers take that name
as a **required argument**, so forgetting it is a compile error rather than a defect
nobody sighted will ever notice.

**The format is written down, and a second implementation checks it.**
[`docs/FORMAT.md`](docs/FORMAT.md) specifies every byte this program writes — the
vault file, the sealed volume password, the rollback record, the recovery pieces,
the password filter — so the construction can be reviewed without reading Rust.
[`tools/reference_vault.py`](tools/reference_vault.py) implements the vault format
from that text on top of different libraries: OpenSSL through `cryptography`, and
the Argon2 authors' own C code through `argon2-cffi`. It checks itself against the
published RFC 5869 and XChaCha20 vectors first. `src/vectors.rs` then requires the
Rust code to produce the same bytes as the reference, and to open
`tests/vectors/reference-v2.ddv`, a vault file the Rust code did not write. Agreement
between two implementations on different libraries is not an audit, but it is
evidence that the specification describes what the program does — which is what an
audit would need first.

The vault tests include the case that matters most for re-keying: a wrong master
password must be refused **before a single byte is written**, because sealing a vault
under a password nobody knows would be silent and permanent.

## Limits

What this program knowingly does not do. The rule for being on this list: we know it,
we decided it, and the reason is written down.

1. **It has not been audited.** One author, no external review. The construction uses
   only well-studied primitives, but assembling proven parts is not the same as having
   the assembly checked. What can be done short of that has been: the format is
   specified byte for byte in `docs/FORMAT.md`, an independent implementation
   produces the same bytes, and [`docs/REVIEW.md`](docs/REVIEW.md) sets out the threat
   model and the questions for whoever looks next. The remaining step is a person.
2. **Wiping memory is not absolute.** The OS can page a buffer out before it is
   overwritten, hibernation writes all of memory to disk regardless, and a debugger
   running as the same user reads the process through. Pinning pages is best-effort and
   the process quota is finite.
3. **The container's volume password goes on the command line** — only if you turn the
   container on. The Windows build of VeraCrypt accepts it no other way, which is
   exactly why a random string goes there and never the master password. On Linux and
   macOS `--stdin` is used and nothing leaks.
4. **While a container is open the volume is an ordinary drive.** Any program can read
   `vault.ddv` on it — but that is ciphertext, and the keys live only in this process.
5. **Changing the master password blocks the window for several seconds.** It runs two
   Argon2id passes synchronously. Deliberate: doing it on a thread would hand over
   ownership of the mounted volume, and emergency dismount on close would stop working.
6. **Recovery pieces go stale when the master password changes.** The vault records
   that working pieces exist and warns at the moment of the change, but making a new
   set is up to you.
7. **The bundled list of public passwords is generated, not a real corpus.** It covers
   the shapes that dominate every published leak — keyboard walks, dates, a word with a
   year, a Russian word typed without switching layout. For completeness, import Have I
   Been Pwned's list; the import understands both plaintext and SHA-1 digests.
8. **The Bloom filter errs in one direction.** It can call a password public that it
   has never seen — at the bundled size, rarer than one in a million — but it never
   misses one it holds.
9. **Rebuilding the file with a new work factor needs the master password.** New
   parameters make a different key from the same password and the old one cannot be
   reproduced. The password is verified before anything is written.
10. **Rebuilding changes the file irreversibly.** A slot whose password is not supplied
    is refilled with fresh noise. If a hidden vault was in it, only a backup will bring
    it back.
11. **Auto-type does not check which window it is typing into.** It checks exactly one
    thing: that the window is not this program's own. The rest is the five-second
    countdown, which is there to be used.
12. **Rollback protection is only as good as what is left to compare with.** Its
    witnesses are the record on this computer, the backups beside the file and the
    mirror. Someone who can delete all three and put back a file from before this
    computer first saw the vault leaves nothing but a first visit to report — so a
    first visit is reported on the way in, and only you know whether it really is
    one. A mirror on a drive that is not always plugged in is what makes this hard.
    On a new computer the record can be carried across by hand.
13. **Accessibility has not been tested with a live screen reader.** The AccessKit tree
    is under test; nobody has sat down with NVDA or Narrator.
14. **TOTP next to the password is one and a half factors.** It defeats phishing,
    credential stuffing and password reuse; it does not help if the vault itself is
    opened. The interface says so where the seed is entered.
15. **A from-scratch build fails if the path contains a space.** `dlltool` does not
    quote the temporary file it passes to the assembler. `build.ps1` works around it by
    building elsewhere; a bare `cargo` command in such a path does not. The Build
    section says what to set.
16. **A second hidden vault destroys the first.** Making one under a different
    password overwrites whatever was in that slot, without asking. Nothing could warn
    you by checking: finding a hidden vault without its password is exactly what the
    format prevents, so the program genuinely cannot tell the slot is taken. It can be
    undone, though: the save that overwrote it copied the file aside first, and backup 1
    can be put back from the lock screen or from Settings → Backups until five more saves
    push it out. The program says both things before and after the button.
17. **The VeraCrypt container path has not been exercised live.** Its driver needs
    administrator rights, and installing VeraCrypt on someone's behalf is wrong — it is
    a tool for protecting your data and worth fetching from the project's own page
    yourself. The command-line construction is covered by tests; the first real
    container will be yours.

## Build

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Rust 1.98, target `x86_64-pc-windows-gnu`. MSVC is avoided on purpose: it wants
administrator rights and several gigabytes of Visual Studio Build Tools. The GNU target
needs `as.exe` from a MinGW-w64 toolchain, which rustup does not ship; `build.ps1`
explains where to put it and puts it on `PATH` for the build only.

`tools/make_breach_filter.py` regenerates the bundled password filter and
`tools/make_icon.py` the icon — both standard library only, so they run wherever Python
does.

**A space in the path breaks a from-scratch build.** `dlltool`, which rustc calls to
build the import libraries the `windows-*` crates need, does not quote the temporary
file name it hands to the assembler, so `C:\Users\me\My Projects\deep-defense`
becomes a request for a file called `Projects\...`. It is a defect in binutils and
nothing here can close it. `build.ps1` notices and builds into `%LOCALAPPDATA%`
instead; a bare `cargo build` in such a path fails with a message about a missing `.o`
file, and `CARGO_TARGET_DIR` set to somewhere without a space fixes it.

## Contributing

Bug reports and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Found a security problem?
[Report it privately](https://github.com/N0deZ3r0/deep-defense/security/advisories/new)
rather than in a public issue.

## License

[MIT](LICENSE).
