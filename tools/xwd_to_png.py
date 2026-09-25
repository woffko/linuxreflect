#!/usr/bin/env python3
"""Convert bounded 24-bit TrueColor Xvfb XWD captures using only the stdlib."""

import argparse
from pathlib import Path
import struct
import zlib


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def convert(source, destination):
    with source.open("rb") as stream:
        header = stream.read(100)
        if len(header) != 100:
            raise ValueError("Truncated XWD header")
        fields = struct.unpack(">25I", header)
        size, version, format_, depth, width, height, xoffset, byte_order = fields[:8]
        bpp, stride, visual, red, green, blue = fields[11:17]
        colors = fields[19]
        if (version, format_, depth, xoffset, byte_order, red, green, blue) != (
            7, 2, 24, 0, 0, 0xFF0000, 0xFF00, 0xFF
        ) or bpp not in (24, 32) or visual not in (4, 5):
            raise ValueError(f"Unsupported XWD pixel format: {fields}")
        if not (100 <= size <= 65536 and colors <= 65536
                and 1 <= width <= 3840 and 1 <= height <= 2160
                and width * (bpp // 8) <= stride <= width * 4 + 64):
            raise ValueError("XWD dimensions or header exceed capture limits")
        stream.seek(size)
        palette = stream.read(colors * 12)
        if len(palette) != colors * 12:
            raise ValueError("Truncated XWD color table")
        if visual == 5:
            covered = [set(), set(), set()]
            for pixel, r, g, b, _flags, _ in struct.iter_unpack(">IHHHBB", palette):
                for channel, (shift, value) in enumerate(((16, r), (8, g), (0, b))):
                    index = (pixel >> shift) & 255
                    if value != index * 257:
                        raise ValueError("Nonlinear DirectColor map is unsupported")
                    covered[channel].add(index)
            if any(len(values) != 256 for values in covered):
                raise ValueError("Incomplete DirectColor map")
        pixels = stream.read(stride * height)
        if len(pixels) != stride * height or stream.read(1):
            raise ValueError("Truncated or oversized XWD pixel data")
    rows = bytearray()
    step = bpp // 8
    for y in range(height):
        row = pixels[y * stride:y * stride + width * step]
        rows.append(0)  # PNG filter: none.
        rgb = bytearray(width * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = row[2::step], row[1::step], row[0::step]
        rows.extend(rgb)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">2I5B", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(rows))
    png += chunk(b"IEND", b"")
    with destination.open("xb") as stream:
        stream.write(png)
    print(f"Converted {width}x{height} XWD capture to {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    convert(args.source, args.destination)
