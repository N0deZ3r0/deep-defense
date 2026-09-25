"""An independent implementation of the Deep Defense vault format.

Why this exists
---------------
The Rust code has never been audited. The most useful thing short of an audit
is to make one cheap: a second implementation, written from the specification
in docs/FORMAT.md rather than from the Rust, on top of *different* libraries —
OpenSSL through `cryptography`, and the Argon2 authors' own C implementation
through `argon2-cffi`. If both produce the same bytes, the specification says
what the program does; if they disagree, one of them is wrong, and the test
suite finds out on the next push.

It is deliberately small and deliberately plain. A reviewer should be able to
read the whole format in one sitting, here, without learning Rust.

Its own correctness is not assumed either: `self-test` checks every primitive
it builds on against the published vectors — RFC 5869 for HKDF, and the IETF
XChaCha20 draft for HChaCha20 and XChaCha20-Poly1305 — before it checks the
vault construction against itself.

Usage
-----
    python tools/reference_vault.py self-test
    python tools/reference_vault.py kat                  # values pinned in src/vectors.rs
    python tools/reference_vault.py write-vector FILE    # the file in tests/vectors/
    python tools/reference_vault.py open FILE [KEYFILE...]  # asks for the password

`open` prints which slot a password opens and a digest of what is inside, not
the contents: pointed at a real vault, printing the payload would print every
password in it to the terminal.

Needs `cryptography` and `argon2-cffi` (pip install cryptography argon2-cffi).
"""

import getpass
import hashlib
import hmac
import json
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# --------------------------------------------------------------- constants

MAGIC = b"DDVAULT2"
FORMAT_VERSION = 2
SLOT_COUNT = 2
SALT_LEN = 32
SEED_LEN = 32
KEY_LEN = 32
LENGTH_PREFIX = 4
CASCADE_OVERHEAD = 32  # one 16-byte tag per cipher

INFO_OUTER = b"deep-defense/vault-data-key/v1"
INFO_INNER = b"deep-defense/vault-inner-key/xchacha20poly1305/v1"
CIPHER_NAME = "AES-256-GCM+XChaCha20-Poly1305"

# Both nonces are all zeros. That is safe only because every save derives
# fresh keys from a fresh 32-byte seed, so no key ever sees a second message.
GCM_NONCE = bytes(12)
XCHACHA_NONCE = bytes(24)


# ---------------------------------------------------------------- HKDF

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869, written out rather than imported, so it can be read."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


# ----------------------------------------------------------- XChaCha20

def _rotl(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl(state[b] ^ state[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """draft-irtf-cfrg-xchacha, section 2.2."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _quarter(state, 0, 4, 8, 12)
        _quarter(state, 1, 5, 9, 13)
        _quarter(state, 2, 6, 10, 14)
        _quarter(state, 3, 7, 11, 15)
        _quarter(state, 0, 5, 10, 15)
        _quarter(state, 1, 6, 11, 12)
        _quarter(state, 2, 7, 8, 13)
        _quarter(state, 3, 4, 9, 14)
    return struct.pack("<8I", *(state[0:4] + state[12:16]))


def xchacha20poly1305(key: bytes, nonce24: bytes):
    """XChaCha20-Poly1305 as HChaCha20 plus the IETF ChaCha20-Poly1305."""
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey), bytes(4) + nonce24[16:]


# ------------------------------------------------------------- the vault

def combine_secret(password: bytes, keyfiles=()) -> bytes:
    """The password alone, or HMAC-SHA512 of it keyed by the keyfiles.

    Each keyfile is hashed with SHA-512, the digests are sorted — so the order
    they were listed in does not matter — and hashed together into the key.
    """
    if not keyfiles:
        return password
    digests = sorted(hashlib.sha512(open(path, "rb").read()).digest() for path in keyfiles)
    combined = hashlib.sha512(b"".join(digests)).digest()
    return hmac.new(combined, password, hashlib.sha512).digest()


def derive_master_key(secret: bytes, salt: bytes, kdf: dict) -> bytes:
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=kdf["t_cost"],
        memory_cost=kdf["m_cost"],
        parallelism=kdf["p_cost"],
        hash_len=KEY_LEN,
        type=Type.ID,
        version=19,
    )


def seal_cascade(plaintext: bytes, master_key: bytes, seed: bytes, aad: bytes) -> bytes:
    inner_key = hkdf_sha256(master_key, seed, INFO_INNER, KEY_LEN)
    outer_key = hkdf_sha256(master_key, seed, INFO_OUTER, KEY_LEN)
    cipher, nonce = xchacha20poly1305(inner_key, XCHACHA_NONCE)
    inner = cipher.encrypt(nonce, plaintext, aad)
    return AESGCM(outer_key).encrypt(GCM_NONCE, inner, aad)


def open_cascade(ciphertext: bytes, master_key: bytes, seed: bytes, aad: bytes) -> bytes:
    inner_key = hkdf_sha256(master_key, seed, INFO_INNER, KEY_LEN)
    outer_key = hkdf_sha256(master_key, seed, INFO_OUTER, KEY_LEN)
    inner = AESGCM(outer_key).decrypt(GCM_NONCE, ciphertext, aad)
    cipher, nonce = xchacha20poly1305(inner_key, XCHACHA_NONCE)
    return cipher.decrypt(nonce, inner, aad)


def slot_size(capacity: int) -> int:
    return SALT_LEN + SEED_LEN + capacity + CASCADE_OVERHEAD


def slot_aad(header_json: bytes, index: int) -> bytes:
    """What every slot authenticates besides its own contents.

    The header is included, so changing the cost parameters or the slot size
    invalidates every slot; the index is included, so a slot cannot be moved to
    the other position and still open.
    """
    return MAGIC + bytes([FORMAT_VERSION]) + header_json + bytes([index])


def pad(payload: bytes, capacity: int, filler: bytes) -> bytes:
    if len(payload) > capacity - LENGTH_PREFIX:
        raise ValueError("payload does not fit in the slot")
    padding = filler[: capacity - LENGTH_PREFIX - len(payload)]
    return struct.pack(">I", len(payload)) + payload + padding


def unpad(padded: bytes) -> bytes:
    (length,) = struct.unpack(">I", padded[:LENGTH_PREFIX])
    if length > len(padded) - LENGTH_PREFIX:
        raise ValueError("slot claims a length that does not fit")
    return padded[LENGTH_PREFIX : LENGTH_PREFIX + length]


def parse_file(data: bytes):
    if data[:8] != MAGIC:
        raise ValueError("not a version 2 vault file")
    if data[8] != FORMAT_VERSION:
        raise ValueError(f"format version {data[8]}")
    (header_len,) = struct.unpack(">H", data[9:11])
    header_json = data[11 : 11 + header_len]
    header = json.loads(header_json)
    size = slot_size(header["slot_capacity"])
    start = 11 + header_len
    if len(data) != start + size * SLOT_COUNT:
        raise ValueError("file length does not match its header")
    slots = [data[start + size * i : start + size * (i + 1)] for i in range(SLOT_COUNT)]
    return header, header_json, slots


def open_slot(header, header_json: bytes, slot: bytes, index: int, secret: bytes) -> bytes:
    salt = slot[:SALT_LEN]
    seed = slot[SALT_LEN : SALT_LEN + SEED_LEN]
    ciphertext = slot[SALT_LEN + SEED_LEN :]
    master_key = derive_master_key(secret, salt, header["kdf"])
    return unpad(open_cascade(ciphertext, master_key, seed, slot_aad(header_json, index)))


def build_slot(header, header_json, index, secret, salt, seed, payload, filler) -> bytes:
    master_key = derive_master_key(secret, salt, header["kdf"])
    padded = pad(payload, header["slot_capacity"], filler)
    return salt + seed + seal_cascade(padded, master_key, seed, slot_aad(header_json, index))


def serialise(header_json: bytes, slots) -> bytes:
    return MAGIC + bytes([FORMAT_VERSION]) + struct.pack(">H", len(header_json)) + header_json + b"".join(slots)


# ----------------------------------------------------------- the vectors

def stream(label: bytes, length: int) -> bytes:
    """Deterministic bytes, so the vector file is reproducible exactly."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


VECTOR_PASSWORD = b"correct horse battery staple"
VECTOR_KDF = {"m_cost": 65536, "t_cost": 2, "p_cost": 1, "algorithm": "argon2id"}
VECTOR_CAPACITY = 65536
VECTOR_PAYLOAD = b'{"note":"written by tools/reference_vault.py, not by the Rust code"}'

KAT_KEY = bytes(range(0x40, 0x60))
KAT_SEED = bytes(range(0x80, 0xA0))
KAT_AAD = b"deep-defense known-answer test"
KAT_PLAINTEXT = b"Two ciphers, one password."
KAT_SALT = stream(b"deep-defense/vector/kat-salt", SALT_LEN)


def vector_header_json() -> bytes:
    header = {"kdf": VECTOR_KDF, "slot_capacity": VECTOR_CAPACITY, "cipher": CIPHER_NAME}
    return json.dumps(header, separators=(",", ":")).encode()


def vector_file() -> bytes:
    header_json = vector_header_json()
    header = json.loads(header_json)
    size = slot_size(VECTOR_CAPACITY)
    slot0 = build_slot(
        header,
        header_json,
        0,
        VECTOR_PASSWORD,
        salt=stream(b"deep-defense/vector/salt/0", SALT_LEN),
        seed=stream(b"deep-defense/vector/seed/0", SEED_LEN),
        payload=VECTOR_PAYLOAD,
        filler=stream(b"deep-defense/vector/padding/0", VECTOR_CAPACITY),
    )
    # The second slot is noise, as it is in every file with no hidden vault.
    slot1 = stream(b"deep-defense/vector/noise/1", size)
    return serialise(header_json, [slot0, slot1])


def kat() -> dict:
    return {
        "master_key": derive_master_key(VECTOR_PASSWORD, KAT_SALT, VECTOR_KDF).hex(),
        "inner_key": hkdf_sha256(KAT_KEY, KAT_SEED, INFO_INNER, KEY_LEN).hex(),
        "outer_key": hkdf_sha256(KAT_KEY, KAT_SEED, INFO_OUTER, KEY_LEN).hex(),
        "cascade": seal_cascade(KAT_PLAINTEXT, KAT_KEY, KAT_SEED, KAT_AAD).hex(),
        "vector_file_sha256": hashlib.sha256(vector_file()).hexdigest(),
    }


# ------------------------------------------------------------- self-test

def self_test() -> None:
    # RFC 5869, appendix A.1.
    okm = hkdf_sha256(
        bytes([0x0B] * 22),
        bytes(range(0x00, 0x0D)),
        bytes(range(0xF0, 0xFA)),
        42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), "HKDF does not match RFC 5869 A.1"

    # draft-irtf-cfrg-xchacha-03, section 2.2.1.
    subkey = hchacha20(
        bytes(range(0x00, 0x20)),
        bytes.fromhex("000000090000004a0000000031415927"),
    )
    assert subkey.hex() == (
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    ), "HChaCha20 does not match the draft"

    # draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"
    )
    cipher, nonce = xchacha20poly1305(
        bytes(range(0x80, 0xA0)),
        bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
    )
    sealed = cipher.encrypt(nonce, plaintext, bytes.fromhex("50515253c0c1c2c3c4c5c6c7"))
    assert sealed.hex() == (
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"
        "c0875924c1c7987947deafd8780acf49"
    ), "XChaCha20-Poly1305 does not match the draft"

    # The construction against itself: a round trip, and the two refusals the
    # format depends on — the header and the slot index are authenticated.
    data = vector_file()
    header, header_json, slots = parse_file(data)
    assert open_slot(header, header_json, slots[0], 0, VECTOR_PASSWORD) == VECTOR_PAYLOAD
    for bad_index in (1,):
        try:
            open_slot(header, header_json, slots[0], bad_index, VECTOR_PASSWORD)
        except Exception:
            pass
        else:
            raise AssertionError("a slot opened at the wrong index")
    try:
        tampered = bytearray(header_json)
        tampered[-2] ^= 0x01
        open_slot(header, bytes(tampered), slots[0], 0, VECTOR_PASSWORD)
    except Exception:
        pass
    else:
        raise AssertionError("a slot opened under a modified header")
    print("self-test passed: HKDF, HChaCha20, XChaCha20-Poly1305, vault round trip")


# ------------------------------------------------------------------ main

def main(argv) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    command = argv[1]
    if command == "self-test":
        self_test()
    elif command == "kat":
        for name, value in kat().items():
            print(f"{name} = {value}")
    elif command == "write-vector" and len(argv) == 3:
        data = vector_file()
        with open(argv[2], "wb") as out:
            out.write(data)
        print(f"wrote {argv[2]}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")
    elif command == "open" and len(argv) >= 3:
        data = open(argv[2], "rb").read()
        header, header_json, slots = parse_file(data)
        secret = combine_secret(getpass.getpass("Password: ").encode(), argv[3:])
        for index, slot in enumerate(slots):
            try:
                payload = open_slot(header, header_json, slot, index, secret)
            except Exception:
                continue
            print(f"slot {index} opened: {len(payload)} bytes, sha256 {hashlib.sha256(payload).hexdigest()}")
            return 0
        print("no slot opened with that password")
        return 1
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
