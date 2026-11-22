#!/usr/bin/env python3
"""Generate favicon.svg and 1200x630 OG PNG cards from code. No counts on
cards, so they cannot go stale. Pure stdlib PNG writer, no AI imagery."""
import struct, zlib
from pathlib import Path

ASSETS = Path(__file__).resolve().parents[1] / "docs" / "assets"
FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="8" fill="#080d14"/><path d="M10 44 L26 18 L34 36 L42 18 L54 44" fill="none" stroke="#5cc8d8" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/><circle cx="52" cy="14" r="4" fill="#e8b45a"/></svg>
"""

def png(width, height, pixel):
    rows = b""
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            row += bytes(pixel(x, y))
        rows += bytes(row)
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b"")

def card(accent):
    bg, ink = (8, 13, 20), (236, 231, 218)
    def pixel(x, y):
        # Border frame, accent bar, and a W course line. Text-free by design.
        if x < 24 or y < 24 or x >= 1176 or y >= 606: return accent
        if 80 <= x < 560 and 470 <= y < 486: return accent
        for (x0, y0, x1, y1) in [(120, 420, 260, 180), (260, 180, 340, 340), (340, 340, 420, 180), (420, 180, 560, 420)]:
            t = 0 if x1 == x0 else (x - x0) / (x1 - x0)
            if 0 <= t <= 1 and abs(y - (y0 + t * (y1 - y0))) < 9: return ink
        if (x - 620) ** 2 + (y - 150) ** 2 < 22 ** 2: return (232, 180, 90)
        return bg
    return png(1200, 630, pixel)

ASSETS.mkdir(parents=True, exist_ok=True)
(ASSETS / "favicon.svg").write_text(FAVICON)
for name, accent in [("og.png", (92, 200, 216)), ("og-architecture.png", (127, 211, 154)),
                     ("og-verifier.png", (92, 200, 216)), ("og-expeditions.png", (232, 180, 90)),
                     ("og-blueprints.png", (154, 164, 181))]:
    data = card(accent)
    (ASSETS / name).write_bytes(data)
    print(name, len(data), "bytes")
print("favicon.svg", len(FAVICON), "bytes")
