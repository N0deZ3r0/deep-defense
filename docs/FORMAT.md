# Deep Defense — file formats

Everything this program writes, to disk or to paper, byte for byte.

This document exists so the construction can be reviewed without reading Rust.
It is written to be implementable: [`tools/reference_vault.py`](../tools/reference_vault.py)
is a second implementation of the vault format written from this text on top of
different libraries (OpenSSL through `cryptography`, and the Argon2 authors' own
C code through `argon2-cffi`), and [`src/vectors.rs`](../src/vectors.rs) checks
that the Rust code produces the same bytes. If this document and the code ever
disagree, one of those tests fails.

Nothing here is secret. The security of every format below rests on the keys,
never on the layout being unknown.

Notation: `‖` is concatenation. `u16be`, `u32be` and `u64be` are big-endian
unsigned integers. `hex(x)` is lower-case hexadecimal. Lengths are in bytes
unless stated.

---

## 1. The vault file

A vault file holds exactly two slots, always. Each slot is either a vault or
random bytes, and the two cannot be told apart without the slot's password.
There is no count, flag or length anywhere in the file that says which.

### 1.1 Layout

```
file   = MAGIC ‖ VERSION ‖ u16be(len(header)) ‖ header ‖ slot_0 ‖ slot_1

MAGIC   = "DDVAULT2"            8 bytes, ASCII
VERSION = 0x02                  1 byte
header  = UTF-8 JSON, see 1.2
slot_i  = salt ‖ seed ‖ ciphertext
          salt       32 bytes
          seed       32 bytes
          ciphertext capacity + 32 bytes
```

A reader must refuse a file whose length is not exactly
`11 + len(header) + 2 × (64 + capacity + 32)`.

### 1.2 The header

Public, and authenticated by every slot (see 1.5). As written by this program:

```json
{"kdf":{"m_cost":262144,"t_cost":4,"p_cost":4,"algorithm":"argon2id"},"slot_capacity":4194304,"cipher":"AES-256-GCM+XChaCha20-Poly1305"}
```

Compact JSON, fields in that order. A reader uses the header bytes **as stored**,
never a re-serialisation, because those exact bytes are part of the associated
data.

| Field | Meaning | Bounds a reader enforces |
|---|---|---|
| `kdf.m_cost` | Argon2id memory, KiB | 65 536 (64 MiB) … 2 097 152 (2 GiB) |
| `kdf.t_cost` | Argon2id passes | 2 … 16 |
| `kdf.p_cost` | Argon2id lanes | 1 … 16 |
| `kdf.algorithm` | must be `"argon2id"` | — |
| `slot_capacity` | padded plaintext size per slot | 65 536 … 67 108 864 |
| `cipher` | informational | — |

The upper bounds matter as much as the lower ones. These parameters are read
before anything in the file has been authenticated — deriving the key *is* the
authentication — so without a ceiling a crafted header chooses how much memory
the reader allocates. The ceilings are the largest values this program's own
settings can produce, so no legitimately created file is refused.

### 1.3 Key schedule

```
secret     = the password, or its combination with keyfiles (section 2)
master_key = Argon2id(password = secret, salt = slot.salt,
                      m = kdf.m_cost, t = kdf.t_cost, p = kdf.p_cost,
                      version = 0x13, output = 32 bytes,
                      no secret value, no associated data)

inner_key  = HKDF-SHA256(ikm = master_key, salt = slot.seed,
                         info = "deep-defense/vault-inner-key/xchacha20poly1305/v1", L = 32)
outer_key  = HKDF-SHA256(ikm = master_key, salt = slot.seed,
                         info = "deep-defense/vault-data-key/v1", L = 32)
```

Argon2id runs **once** per slot. The two cipher keys are independent HKDF
outputs of its result. Running Argon2id once per cipher would double the honest
user's cost and leave an attacker's unchanged: testing a guess only needs the
outer key.

`salt` is fixed for the life of a slot's password. `seed` is fresh random bytes
on every save.

### 1.4 Encryption

```
inner      = XChaCha20-Poly1305(key = inner_key, nonce = 0^24, aad = AAD_i, plaintext = padded)
ciphertext = AES-256-GCM(key = outer_key, nonce = 0^12, aad = AAD_i, plaintext = inner)
```

Both nonces are all zeros. That is safe **only** because every save derives new
keys from a new 32-byte seed, so no key ever encrypts a second message. This is
the derive-a-key-per-message construction (the idea behind XAES-256-GCM); it
removes the birthday bound that limits random 96-bit GCM nonces, and it means no
nonce counter has to survive between saves.

Each cipher adds a 16-byte tag, so `len(ciphertext) = capacity + 32`.

### 1.5 Associated data

```
AAD_i = MAGIC ‖ VERSION ‖ header ‖ u8(i)
```

The header is included, so changing any cost parameter or the slot size
invalidates every slot. The index is included, so a slot moved to the other
position does not open.

### 1.6 Padding

```
padded = u32be(len(payload)) ‖ payload ‖ random bytes to fill capacity
```

Every slot is exactly `capacity` bytes of plaintext regardless of what it holds,
so the file never says how much a slot contains — or whether it contains
anything. An unused slot is `64 + capacity + 32` bytes of random data.

### 1.7 The payload

UTF-8 JSON of the vault's contents: entries, password history, attachments,
custom fields, the audit log, and the fields described in section 3.2. It is
not further specified here because nothing outside the vault depends on its
shape; an implementation that only needs to verify the cryptography can treat it
as opaque bytes.

### 1.8 Opening

A reader does not know which slot a password belongs to and must not reveal
which it tried. It derives a key for each slot and returns the first that
authenticates. When `2 × m_cost` is at most 1 GiB both slots are tried in
parallel; otherwise one after the other.

### 1.9 Sealed blobs: the container's volume password

The optional VeraCrypt container is opened with a random volume password that
the user never sees. It is kept sealed under the master password, in the
`.ddmeta` file beside the container and in a second copy in the settings file.
That seal is a single-slot format older than the vault file above:

```
blob   = "DDVAULT1" ‖ 0x01 ‖ u16be(len(header)) ‖ header ‖ seed ‖ ciphertext
header = JSON {"cipher":"AES-256-GCM+XChaCha20-Poly1305","kdf":{…},"salt":"<base64 of 32 bytes>","created_at":"…"}
seed   = 32 random bytes

master_key = Argon2id(secret, base64-decoded header.salt, header.kdf)   as in 1.3
AAD        = every byte before the ciphertext: magic ‖ version ‖ length ‖ header ‖ seed
ciphertext = the cascade of 1.4 under keys derived as in 1.3, with this AAD
```

A `cipher` of `"AES-256-GCM"` means only the outer layer, as written by builds
before the cascade existed; it is still read. The same KDF bounds apply. The
sidecar may hold more than one blob while a change of master password is under
way, so that a crash in the middle leaves the container openable with either
password rather than neither.

---

## 2. Combining the password with keyfiles

```
if no keyfiles:
    secret = password (UTF-8)
else:
    d_k      = SHA-512(contents of keyfile k)      for each keyfile
    combined = SHA-512(d_1 ‖ d_2 ‖ …)               digests sorted bytewise, ascending
    secret   = HMAC-SHA512(key = combined, message = password)
```

Sorting the digests makes the result independent of the order the keyfiles were
listed in.

---

## 3. The rollback record

Kept outside the vault, in the settings directory (`%APPDATA%\DeepDefense\revision.anchor`
on Windows), so an attacker who swaps in an older vault file also has to reach a
second place.

### 3.1 The store

```json
{"version":2,"entries":[{"id":"…","sealed":"…"}, …]}
```

One entry per slot of every vault file seen on this computer, most recently
written last, at most 64; past that the oldest are dropped.

```
id     = hex(SHA-256("deep-defense/vault-id/v2" ‖ slot.salt ‖ u8(slot_index))[0..16])
k      = HKDF-SHA256(ikm = master_key, salt = none, info = "deep-defense/rollback-anchor/seal/v2", L = 32)
sealed = base64(nonce ‖ XChaCha20-Poly1305(key = k, nonce, aad = id as ASCII, plaintext = u64be(revision)))
         nonce = 24 random bytes; sealed is always 48 bytes before encoding
```

`revision` counts saves. A vault whose revision is lower than its sealed record
is reported as rolled back.

Whenever a vault writes its record it also makes sure every *other* slot of the
same file has an entry, adding 48 random bytes under that slot's `id` if there is
none. The `id` of a slot is computable from the file alone — its first 32 bytes
are a salt if it holds a vault and noise if not — so the store has the same shape
whether or not a hidden vault exists, and a hidden vault opened on this computer
later finds a placeholder waiting under its own `id`. Revisions are sealed rather
than written out because a plain number would show which entries are real.

A record written by another vault is never modified.

### 3.2 Which computers a vault has been on

Inside the vault payload, not in the store:

```
machine_key = 32 random bytes, hex, made once per vault
anchored_on = [ hex(HMAC-SHA256(machine_key, "deep-defense/machine/v1" ‖ machine_id)[0..16]), … ]
machine_id  = on Windows, HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
```

When a vault is opened and the store holds no entry for it, `anchored_on` decides
what that means: this computer listed means the record was **removed**; not
listed means this is the first visit. The identity itself is never stored, only
a tag keyed with a secret inside the vault. Both fields are left out of JSON
exports.

The residual gap: an older copy of the file from before this computer was first
listed looks like a first visit, and is reported as one.

### 3.3 The carried record and the earlier store

The record exported for carrying to another computer, and the whole store before
version 2, is a single record:

```json
{"vault_id":"…","revision":17,"mac":"…"}
```

```
mac = base64(HMAC-SHA256(key = master_key,
                         message = "deep-defense/rollback-anchor/v1" ‖ vault_id as ASCII ‖ u64be(revision)))
```

A store in this form is read once and rewritten as version 2.

---

## 4. Recovery pieces

The master password split by Shamir's scheme over GF(2⁸) with the AES polynomial
`x⁸ + x⁴ + x³ + x + 1`. Nothing is stored anywhere; the pieces exist only where
their owner puts them.

### 4.1 Splitting

For each byte `s` of the password, a random polynomial of degree `threshold − 1`
with constant term `s` is evaluated at `x = 1 … count`. `threshold` is at least 2,
`count` at most 16. The secret is recovered by Lagrange interpolation at `x = 0`.

### 4.2 One piece

```
body     = u8(1)            version
         ‖ u8(threshold)
         ‖ u8(index)        x, never 0
         ‖ set_id           8 random bytes, the same for every piece of one split
         ‖ data             one byte per byte of the password
piece    = body ‖ SHA-256(body)[0..4]
```

Written as RFC 4648 base32 without padding, in groups of four separated by `-`.
A reader drops everything outside the alphabet, reads `0`, `1` and `8` as `O`,
`I` and `B`, and scans pasted text line by line.

A piece deliberately carries **no hash of the secret**. That would be the obvious
way to detect a wrong set, and it would turn one photographed piece into an
offline cracking target. Pieces from different splits are told apart by `set_id`;
whether a reconstruction is right is answered by the vault opening.

---

## 5. The list of published passwords

A Bloom filter compiled into the program, plus one the user may import.

```
filter = "DDBLOOM1" ‖ u8(1) ‖ u32be(k) ‖ u64be(m) ‖ u64be(count) ‖ bits
         m     number of bits, a multiple of 8, between 2^10 and 2^28
         bits  m / 8 bytes

digest = SHA-1(password as UTF-8)
h1     = u64be(digest[0..8])
h2     = u64be(digest[8..16]) | 1
probe_j = (h1 + j × h2) mod m, for j = 0 … k−1, with wrapping 64-bit arithmetic
bit p   = bits[p / 8] & (1 << (p mod 8))
```

A password is reported as published when every probed bit is set. `h2` is forced
odd because `m` is a power of two, and an even step would walk a short cycle.
SHA-1 is used only as the key into the filter, so that the published Have I Been
Pwned list, which is distributed as SHA-1 digests, can be imported directly.

---

## 6. Checking an implementation against this document

```bash
python tools/reference_vault.py self-test   # the primitives against RFC 5869 and the XChaCha20 draft
python tools/reference_vault.py kat         # the values pinned in src/vectors.rs
cargo test vectors                          # the Rust code against those values and the reference file
```

`tests/vectors/reference-v2.ddv` is a complete vault file written by the
reference implementation. Its password is `correct horse battery staple`, slot 0
holds the JSON `{"note":"written by tools/reference_vault.py, not by the Rust code"}`,
and slot 1 is noise.
