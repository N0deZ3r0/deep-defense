"""Build the bundled Bloom filter of passwords that leak constantly.

Honesty first: this is *not* a copy of a breach corpus. It is generated from
the shapes that dominate every published leak -- keyboard walks, dates, a word
with a year stuck on the end, a Russian word typed without switching layout.
That catches the overwhelming majority of what people actually choose, and it
catches nothing that a real corpus would miss for a different reason.

Anyone who wants the real thing can feed Have I Been Pwned's list into the
program at runtime; the import understands both plaintext lines and SHA-1
digests, and writes a second filter beside the bundled one.

Only the standard library, so it runs wherever Python does.

    python tools/make_breach_filter.py
"""

import hashlib
import math
import pathlib
import struct

MAGIC = b"DDBLOOM1"
VERSION = 1
# 2^23 bits = 1 MiB in the executable. At the corpus size below that leaves the
# filter about half full, where a false positive is rarer than one in a million.
# The trade is deliberate: wrongly saying "this password is public" costs a few
# seconds of annoyance, and missing a real one costs the vault.
M_BITS = 1 << 23
MASK64 = (1 << 64) - 1


def indices(digest: bytes, k: int):
    """Must match `breach.rs` byte for byte."""
    h1 = int.from_bytes(digest[0:8], "big")
    # Forced odd: with a power-of-two modulus an even step walks a short cycle
    # and the filter would use a fraction of its bits.
    h2 = int.from_bytes(digest[8:16], "big") | 1
    index = h1
    for _ in range(k):
        yield index % M_BITS
        index = (index + h2) & MASK64


class Bloom:
    """The number of hashes is chosen from the corpus, then written into the
    header, so the reader never has to agree with us about the corpus size."""

    def __init__(self, k: int):
        self.k = k
        self.bits = bytearray(M_BITS // 8)
        self.count = 0

    def add(self, password: str):
        digest = hashlib.sha1(password.encode("utf-8")).digest()
        for index in indices(digest, self.k):
            self.bits[index >> 3] |= 1 << (index & 7)
        self.count += 1

    def to_bytes(self) -> bytes:
        header = MAGIC + struct.pack(">BIQQ", VERSION, self.k, M_BITS, self.count)
        return header + bytes(self.bits)


# --------------------------------------------------------------- the corpus

# English bases: the words that top every published leak, plus the nouns people
# reach for when told "pick something memorable".
ENGLISH = """
password passwd pass admin administrator root user guest test demo login welcome
letmein secret master shadow monkey dragon sunshine princess football baseball
soccer hockey basketball superman batman spiderman pokemon starwars trustno1
iloveyou lovely angel flower summer winter spring autumn orange purple silver
golden diamond phoenix falcon eagle tiger lion panther cobra viper ninja samurai
hunter killer sniper gamer player winner champion legend master chief captain
freedom liberty justice america canada london paris berlin moscow tokyo
computer internet network system server database access control security
private secure protect defend guard safety backup archive storage cloud
money cash bank credit finance market trade profit dollar euro
happy lucky smile laugh dream hope peace love heart kiss forever
mother father sister brother family friend buddy honey baby sweetie
coffee beer whisky vodka wine pizza burger chocolate cookie candy
music guitar piano drums rock metal blues jazz techno rapper
apple banana orange cherry lemon melon grape peach
january february march april may june july august september october november
december monday tuesday wednesday thursday friday saturday sunday
red blue green black white yellow pink grey brown
one two three four five six seven eight nine ten
cat dog bird fish horse mouse bear wolf fox rabbit
house home door window garden forest river ocean mountain island
school teacher student college university science math history
doctor nurse police fireman driver pilot soldier farmer
china japan korea india brazil france italy spain germany england
qwerty asdfgh zxcvbn qazwsx wasd
abc abcd abcde abcdef xyz
""".split()

# Russian words as they are actually typed: transliterated, and typed on a
# Latin keyboard without switching layout (parol / gfhjkm are the same word).
RUSSIAN = """
parol privet poka spasibo pozhaluysta zdravstvuy lyubov lyublyu schastye
druzhba semya mama papa babushka dedushka sestra brat doch syn
rossiya moskva piter sochi kazan samara omsk perm ufa
zima vesna leto osen solnce luna zvezda nebo more reka
kotik sobaka koshka medved volk zayac lisa tigr
krasota krasivaya milaya solnyshko zaychik kisa lapochka
rabota dengi kvartira mashina dacha otpusk
futbol hokkey sport chempion pobeda
vodka pivo chay kofe
ugaday sekret zashita bezopasnost
gfhjkm ghbdtn cgfcb,j k.,jdm vfvf gfgf hjccbz vjcrdf
pbvf ktnj cjkywt pdtplf yt,j vjht
rjitxrf cj,frf vtldtlm
hf,jnf ltymub rdfhnbhf vfibyf
ajn,jk [jrrtq xtvgbjy gj,tlf
""".split()

NAMES = """
alex alexander alexey andrey anna anton artem boris daniel david dmitry egor
elena evgeny ivan igor irina julia katya kirill ksenia lena leonid lera
maria marina maxim michael mikhail natasha nikita nikolay oleg olga oksana
pavel peter polina roman sasha sergey sofia stepan svetlana tanya tatiana
vadim valentina vera victor victoria vladimir vlad yana yuri zhenya
john james robert mary patricia jennifer linda william richard joseph thomas
charles christopher daniel matthew anthony donald mark paul steven andrew
kenneth george joshua kevin brian edward ronald timothy jason jeffrey ryan
jacob gary nicholas eric jonathan stephen larry justin scott brandon frank
elizabeth barbara susan jessica sarah karen nancy lisa betty margaret sandra
ashley kimberly emily donna michelle carol amanda dorothy melissa deborah
""".split()

BASES = sorted(set(ENGLISH + RUSSIAN + NAMES))

# Kept deliberately short. A filter is a fixed number of bits, so every
# improbable string crowds out a probable one: "@P4$$w0rd1987" costs exactly as
# much room as "password1" and nobody has ever chosen it.
SUFFIXES = [
    "", "1", "2", "3", "7", "11", "12", "21", "22", "23", "69", "77", "88", "99",
    "007", "111", "123", "321", "666", "777", "999",
    "1111", "1234", "4321", "12345", "123456", "1234567",
    "!", "!!", "1!", "123!", "@", "#", "$", "*", ".", "_", "-",
    "01", "02", "03", "1q", "qq", "aa",
]
SUFFIXES += [str(year) for year in range(1960, 2027)]

# A short tail for the mangled forms, which are far rarer than the plain ones.
SHORT_SUFFIXES = ["", "1", "12", "123", "1234", "!", "2023", "2024", "2025", "2026"]

# Substituting every eligible character is the wrong model of what people do.
# "Passw0rd" replaces exactly one letter and is far more common than the
# thorough "p@$$w0rd", so the single-character tables come first and the
# all-or-nothing ones are treated as the rarity they are.
LEET = [
    {"o": "0"},
    {"a": "@"},
    {"a": "4"},
    {"e": "3"},
    {"i": "1"},
    {"s": "$"},
    {"a": "@", "o": "0"},
    {"e": "3", "o": "0"},
    {"a": "@", "o": "0", "e": "3", "i": "1", "s": "$"},
    {"a": "4", "o": "0", "e": "3", "i": "1", "s": "5", "t": "7"},
]


def cases(word: str):
    yield word
    yield word.capitalize()
    yield word.upper()


def leeted(word: str):
    seen = {word}
    for table in LEET:
        out = "".join(table.get(ch, ch) for ch in word)
        if out not in seen:
            seen.add(out)
            yield out


def keyboard_walks():
    rows = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "0987654321", "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
        "qazwsxedcrfvtgbyhnujmikolp", "1qaz2wsx3edc4rfv5tgb",
        "qweasdzxc", "qazxsw", "zaq12wsx", "1q2w3e4r5t6y", "q1w2e3r4t5",
        "!@#$%^&*()", "qwerty123", "qwerty1234", "asdf1234",
    ]
    for row in rows:
        for length in range(4, len(row) + 1):
            piece = row[:length]
            yield piece
            yield piece.upper()
            yield piece + "123"
            yield piece.capitalize()


def numeric():
    # Every four-digit PIN: the space is small enough that all of it is weak.
    for pin in range(10000):
        yield f"{pin:04d}"
    # Six- and eight-digit dates, which is what most long "numbers" really are.
    for day in range(1, 32):
        for month in range(1, 13):
            for year in range(1940, 2027):
                yield f"{day:02d}{month:02d}{year % 100:02d}"
                yield f"{month:02d}{day:02d}{year % 100:02d}"
                yield f"{day:02d}{month:02d}{year:04d}"
    # Runs and repeats of every length.
    digits = "1234567890"
    for length in range(4, 21):
        yield (digits * 3)[:length]
        yield (digits[::-1] * 3)[:length]
    for digit in "0123456789":
        for length in range(4, 21):
            yield digit * length


def corpus():
    seen = set()

    def emit(candidate):
        if 3 <= len(candidate) <= 32 and candidate not in seen:
            seen.add(candidate)
            return True
        return False

    for group in (numeric(), keyboard_walks()):
        for candidate in group:
            if emit(candidate):
                yield candidate

    # Plain word, every capitalisation, every suffix: by far the largest real
    # class of chosen passwords.
    for base in BASES:
        for shaped in cases(base):
            for suffix in SUFFIXES:
                candidate = shaped + suffix
                if emit(candidate):
                    yield candidate

    # Character substitutions, which are much rarer, get a much shorter tail.
    for base in BASES:
        for mangled in leeted(base):
            for suffix in SHORT_SUFFIXES:
                for candidate in (mangled + suffix, mangled.capitalize() + suffix):
                    if emit(candidate):
                        yield candidate


def main():
    out = pathlib.Path("assets/breached.bloom")
    out.parent.mkdir(parents=True, exist_ok=True)

    # Build the corpus first so the hash count can be derived from its real
    # size rather than from a guess that goes stale the moment a word is added.
    passwords = list(corpus())
    k = max(1, min(30, round(M_BITS / len(passwords) * math.log(2))))

    bloom = Bloom(k)
    for password in passwords:
        bloom.add(password)

    blob = bloom.to_bytes()
    out.write_bytes(blob)

    set_bits = sum(bin(byte).count("1") for byte in bloom.bits)
    fill = set_bits / M_BITS
    # The textbook estimate: a lookup hits k set bits by chance at fill^k.
    false_positive = fill**k
    print(f"entries        : {bloom.count:,}")
    print(f"hashes (k)     : {k}")
    print(f"bits set       : {set_bits:,} of {M_BITS:,} ({fill:.1%})")
    print(f"false positives: {false_positive:.2%}")
    print(f"written        : {out} ({len(blob):,} bytes)")


if __name__ == "__main__":
    main()
