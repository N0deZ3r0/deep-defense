# Reviewing Deep Defense

Everything someone reviewing the construction needs, in the order they will need
it. The program has not been audited: one author, no external review. This page
exists to make a review cheap enough to happen.

It is not a request for a line-by-line read of the Rust. The construction is
small, it is specified byte for byte in [`FORMAT.md`](FORMAT.md), and a second
implementation already agrees with the code. What is missing is a person who
knows where such constructions usually go wrong, looking at this one.

---

## 1. What an attacker is assumed to have

- **Every copy of the vault file**, as many as they like, taken at different
  times. Backups, a synced folder, a stolen laptop.
- **Write access to the disk** while the program is closed: they can put an
  older copy back, delete files, and edit the settings folder, including the
  rollback record.
- **Other processes' command lines**, when the optional VeraCrypt container is
  in use (Windows exposes them to the same user).
- **The ability to ask for a password**, and to be given one. That is what the
  second slot is for.

Not assumed, and named in the README as out of reach rather than defended
against: code already running as the user, a keylogger, a camera on the
keyboard.

## 2. What to look at, most important first

Each item names the section of [`FORMAT.md`](FORMAT.md), the code, and the
questions the author cannot answer alone.

### 2.1 Key schedule and the cipher cascade — §1.3–1.5, `src/crypto.rs`

One Argon2id pass gives a 32-byte master key. Every save draws a fresh 32-byte
seed; HKDF-SHA256 over (master key, seed) gives two independent subkeys; the
payload is sealed with XChaCha20-Poly1305 under one, and the result with
AES-256-GCM under the other. Both nonces are **fixed at zero**, justified by the
key being new for every message.

- Is "a fresh HKDF subkey per message, fixed nonce" sound as used here —
  including the seed being stored in the clear beside the ciphertext?
- Does the cascade add anything an attacker could use against either layer: a
  shared structure, an oracle, a length?
- The associated data binds the file header and the slot's index (§1.5). Is
  there any way to move a slot, or lower the Argon2 cost in the header, and have
  a slot still authenticate?

### 2.2 Two slots that do not admit to being two — §1.1, §1.6, `src/slots.rs`

Every file has two slots of the same fixed size. An unused slot is random bytes
and is never rewritten; a used one is `salt ‖ seed ‖ ciphertext` of padded data.

- Can a slot holding a vault be told from one holding noise, from one file? From
  several copies of the file taken over time, given that only the slot being
  saved changes?
- Padding is a 4-byte length, the payload, then random bytes, all inside the
  ciphertext. Anything visible from outside?

### 2.3 What the header can make the reader do — §1.2, `KdfParams::validate`

The Argon2 parameters are read from the header before anything in the file is
authenticated. They are bounded on both sides (§1.2 lists the bounds).

- Are the bounds tight enough that a crafted file cannot exhaust memory or time,
  and loose enough that a file made on a stronger machine still opens?

### 2.4 The rollback record — §3, `src/vault.rs`

Outside the vault, a store of revisions sealed under keys derived from each
slot's master key, with placeholders so that the store has the same shape
whether or not a hidden vault exists. A key that goes out of use leaves a
marker no revision can pass. On opening, the file is also compared with its
backups and the mirror (§3.4).

- Can someone without the master key make an older file pass?
- Does the store, or its changes over time, reveal whether a second slot is in
  use, or how many times a password was changed?
- §3.4 ends with what remains open. Is it stated correctly, and is there a
  cheaper way around than the one given?

### 2.5 Everything else that holds a secret

- **Keyfiles**, §2: SHA-512 of each file, the digests sorted and hashed again,
  and that used as the HMAC-SHA512 key over the password. Order independence is
  intended.
- **The container's volume password**, §1.9 and the module comment in
  `src/session.rs`: 64 random characters, wrapped under a key from the master
  password, because VeraCrypt on Windows only takes it on the command line.
- **Recovery pieces**, §4, `src/shamir.rs`: Shamir over GF(256). A piece
  deliberately carries **no hash of the secret**, only a checksum of its own
  body — a hash would turn one photographed piece into an offline cracking
  target.
- **The published-password filter**, §5: a Bloom filter that must not be
  readable back into a wordlist.

## 3. Checking without reading Rust

Python 3 with `cryptography` and `argon2-cffi`:

```bash
python tools/reference_vault.py self-test   # the primitives against RFC 5869 and the XChaCha20 draft
python tools/reference_vault.py kat         # the known-answer values src/vectors.rs also checks
python tools/reference_vault.py open tests/vectors/reference-v2.ddv
```

The last one asks for the password: `correct horse battery staple`. The file was
written by the Python, not by the Rust, and `src/vectors.rs` requires the Rust to
open it.

To see a vault file under a password of your own, build the program
(`build.ps1`) or take the one from the latest release, create a vault with a
throwaway password, and open the file with the reference implementation.

With Rust: `cargo test --lib` runs everything, `src/robustness.rs` included — the
parsers damaged at random around 150,000 times.

## 4. What is already known

The README's **Limits** section lists what the program knowingly does not do,
each with its reason. Those are out of scope unless something is materially
worse than described there.

## 5. Sending findings

Privately, through a
[security advisory](https://github.com/N0deZ3r0/deep-defense/security/advisories/new),
as [`SECURITY.md`](../SECURITY.md) describes. A short note that something looks
wrong is as welcome as a finished write-up. Please never send a real vault or a
real password; a vault made with a throwaway one shows everything a real one
would.
