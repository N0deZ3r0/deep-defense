"""Generate the application icon: assets/deep-defense.ico and a raw RGBA
window icon.

Uses only the Python standard library — `zlib` writes the PNG streams and the
shapes are rasterised here from signed distance functions, so there is no
image library to install and the icon is reproducible from source.

Run from the project root:

    python tools/make_icon.py
"""

from __future__ import annotations

import math
import pathlib
import struct
import zlib

ICO_SIZES = (256, 128, 64, 48, 32, 24, 16)
WINDOW_ICON_SIZE = 64
SUPERSAMPLE = 4  # 4x4 samples per pixel

# Matches the accent and surface colours of the dark theme.
BG_TOP = (0x4C, 0x8E, 0xF0)
BG_BOTTOM = (0x1B, 0x54, 0xB0)
LOCK = (0xFF, 0xFF, 0xFF)


def smoothstep(edge: float, value: float, softness: float) -> float:
    """1 inside the shape, 0 outside, with a soft edge of width `softness`."""
    if softness <= 0.0:
        return 1.0 if value <= edge else 0.0
    t = (edge - value) / softness + 0.5
    return min(1.0, max(0.0, t))


def rounded_box(px: float, py: float, cx: float, cy: float,
                half_w: float, half_h: float, radius: float) -> float:
    """Signed distance to a rounded rectangle; negative inside."""
    dx = abs(px - cx) - (half_w - radius)
    dy = abs(py - cy) - (half_h - radius)
    outside = math.hypot(max(dx, 0.0), max(dy, 0.0))
    inside = min(max(dx, dy), 0.0)
    return outside + inside - radius


def ring(px: float, py: float, cx: float, cy: float,
         radius: float, thickness: float) -> float:
    """Signed distance to a circular ring."""
    return abs(math.hypot(px - cx, py - cy) - radius) - thickness / 2.0


def lock_alpha(x: float, y: float, softness: float) -> float:
    """Coverage of the padlock at unit coordinates (0..1, y down)."""
    # Shackle: the upper half of a ring, squared off where it meets the body.
    shackle = ring(x, y, 0.5, 0.435, 0.150, 0.072)
    if y > 0.435:
        # Extend the two legs straight down to the body.
        left = rounded_box(x, y, 0.350, 0.475, 0.036, 0.075, 0.012)
        right = rounded_box(x, y, 0.650, 0.475, 0.036, 0.075, 0.012)
        shackle = min(left, right)

    body = rounded_box(x, y, 0.5, 0.665, 0.270, 0.195, 0.070)
    shape = min(shackle, body)
    alpha = smoothstep(0.0, shape, softness)

    # Keyhole, punched out of the body.
    hole = min(
        math.hypot(x - 0.5, y - 0.625) - 0.052,
        rounded_box(x, y, 0.5, 0.710, 0.026, 0.060, 0.020),
    )
    alpha *= 1.0 - smoothstep(0.0, hole, softness)
    return min(1.0, max(0.0, alpha))


def render(size: int) -> bytes:
    """Render one RGBA image of `size` x `size` pixels."""
    step = 1.0 / (size * SUPERSAMPLE)
    softness = 1.6 / size  # edge softness in unit coordinates
    corner = 0.215 if size >= 32 else 0.18

    pixels = bytearray(size * size * 4)
    for py in range(size):
        for px in range(size):
            bg_cov = 0.0
            lock_cov = 0.0
            for sy in range(SUPERSAMPLE):
                for sx in range(SUPERSAMPLE):
                    x = (px * SUPERSAMPLE + sx + 0.5) * step
                    y = (py * SUPERSAMPLE + sy + 0.5) * step
                    plate = rounded_box(x, y, 0.5, 0.5, 0.5, 0.5, corner)
                    bg_cov += smoothstep(0.0, plate, softness)
                    lock_cov += lock_alpha(x, y, softness)
            samples = SUPERSAMPLE * SUPERSAMPLE
            bg_cov /= samples
            lock_cov = min(lock_cov / samples, bg_cov)

            # Vertical gradient across the plate.
            t = py / max(size - 1, 1)
            base = tuple(
                BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t for i in range(3)
            )
            # Composite the white lock over the plate.
            mix = lock_cov / bg_cov if bg_cov > 0.0 else 0.0
            colour = tuple(base[i] + (LOCK[i] - base[i]) * mix for i in range(3))

            offset = (py * size + px) * 4
            pixels[offset + 0] = int(colour[0] + 0.5)
            pixels[offset + 1] = int(colour[1] + 0.5)
            pixels[offset + 2] = int(colour[2] + 0.5)
            pixels[offset + 3] = int(bg_cov * 255 + 0.5)
    return bytes(pixels)


def png_chunk(tag: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + tag
        + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


def to_png(size: int, rgba: bytes) -> bytes:
    """Encode RGBA bytes as a PNG (colour type 6, no filtering)."""
    stride = size * 4
    raw = b"".join(b"\x00" + rgba[y * stride : (y + 1) * stride] for y in range(size))
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(raw, 9))
        + png_chunk(b"IEND", b"")
    )


def to_ico(images: list[tuple[int, bytes]]) -> bytes:
    """Pack PNG-compressed images into an .ico. Windows has accepted PNG
    entries at every size since Vista, which keeps the file small."""
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    entries = b""
    payload = b""
    offset = 6 + 16 * count
    for size, png in images:
        # 0 means 256 in the directory entry.
        dimension = 0 if size >= 256 else size
        entries += struct.pack(
            "<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(png), offset
        )
        payload += png
        offset += len(png)
    return header + entries + payload


def main() -> None:
    assets = pathlib.Path(__file__).resolve().parent.parent / "assets"
    assets.mkdir(exist_ok=True)

    images = []
    for size in ICO_SIZES:
        rgba = render(size)
        images.append((size, to_png(size, rgba)))
        print(f"  rendered {size}x{size}")
        if size == WINDOW_ICON_SIZE:
            # Raw RGBA for the window/taskbar icon: eframe wants pixels, not a
            # container format, and this saves shipping a PNG decoder.
            (assets / f"icon-{size}.rgba").write_bytes(rgba)

    ico = to_ico(images)
    (assets / "deep-defense.ico").write_bytes(ico)
    print(f"wrote assets/deep-defense.ico ({len(ico):,} bytes)")


if __name__ == "__main__":
    main()
