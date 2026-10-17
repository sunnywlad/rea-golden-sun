#!/usr/bin/env python3
"""Reconstruct private analytical RGBA PNGs; publish only hashes/counts.

No PPU execution. Reuses unchanged step-28/29 native isolated harnesses.
Run with cached unicorn==2.1.4, output JSON then optional private PNG directory.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import zlib

from audit_sprite_decode import Harness, ROOT, ROM_BASE, sha, u32
from audit_sprite_upload import UploadHarness

AFFINE_SOURCE = 'https://raw.githubusercontent.com/mgba-emu/mgba/master/src/gba/renderers/software-obj.c'


def untile(tiles, width, height):
    assert width % 8 == height % 8 == 0 and len(tiles) == width * height
    return bytes(tiles[((y // 8) * (width // 8) + x // 8) * 64
                       + (y % 8) * 8 + x % 8]
                 for y in range(height) for x in range(width))


def affine_sample(pixels, width, height, matrix):
    """Inverse OBJ sampling, integer centre, Q8; outside texture is index 0.

    mGBA software-obj.c:221-222 plus pre-sample increment at :30-34.
    No double-size, mosaic, blending, background or display simulation.
    """
    a, b, c, d = matrix
    result = bytearray(width * height)
    outside = 0
    for y in range(height):
        for x in range(width):
            sx = (a * (x - width // 2) + b * (y - height // 2) + width * 128) >> 8
            sy = (c * (x - width // 2) + d * (y - height // 2) + height * 128) >> 8
            if 0 <= sx < width and 0 <= sy < height:
                result[y * width + x] = pixels[sy * width + sx]
            else:
                outside += 1
    return bytes(result), outside


def mirror_reference(pixels, width, height):
    """Independent forward scatter for Q8 (-256,0,0,256), centre width/2."""
    result = bytearray(width * height)
    for source_y in range(height):
        for source_x in range(width):
            target_x = width - source_x
            if target_x < width:
                result[source_y * width + target_x] = pixels[source_y * width + source_x]
    return bytes(result)


def rgba_from_indices(indices, palette):
    assert len(palette) == 224 and all(index < len(palette) for index in indices)
    return bytes(channel for index in indices for channel in (
        (palette[index] & 31) * 255 // 31,
        ((palette[index] >> 5) & 31) * 255 // 31,
        ((palette[index] >> 10) & 31) * 255 // 31,
        255 if index else 0))


def png_rgba(rgba, width, height):
    assert len(rgba) == width * height * 4
    def chunk(kind, payload):
        return (struct.pack('>I', len(payload)) + kind + payload
                + struct.pack('>I', zlib.crc32(kind + payload) & 0xffffffff))
    rows = b''.join(b'\0' + rgba[y * width * 4:(y + 1) * width * 4] for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(rows, 9)) + chunk(b'IEND', b''))


def main():
    output = Path(sys.argv[1])
    private_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / 'work/step30_private'
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_dir.chmod(0o700)
    rom = (ROOT / 'work/rom/Golden Sun (USA, Europe).gba').read_bytes()
    assert hashlib.sha1(rom).hexdigest() == '5c4695205413df7db52b9a184815a07783999971'
    previous28 = json.loads((ROOT / 'work/step28_decode_verification.json').read_text())
    previous29 = json.loads((ROOT / 'work/step29_upload_verification.json').read_text())
    metadata = rom[0x185024:0x185038]
    width, height = metadata[:2]
    assert (width, height) == (32, 32)
    script = u32(rom, u32(metadata, 16) - ROM_BASE)
    cases = []
    for heading in (0, 0x8000):
        baseline, state = Harness(rom).compose(metadata, script, heading, 0)
        assert state[0x16] == 1
        saved28 = next(case for case in previous28['native_compositor_cases']
                       if int(case['heading'], 16) == heading and case['mode'] == 0)
        assert sha(baseline) == saved28['pixels_sha256']
        native = UploadHarness(rom)
        initialization = native.configure()
        native.vram_writes.clear()
        native.prepare(metadata, script, heading)
        placement = native.placement(heading)
        assert placement == previous29['native_placement_and_oam'][int(heading != 0)]
        attr2 = int(placement['oam_attributes'][2], 16)
        address = 0x06010000 + (attr2 & 1023) * 32
        tiles = bytes(native.uc.mem_read(address, width * height))
        saved29 = previous29['native_compositions'][int(heading != 0)]
        assert sha(tiles) == saved29['tiles_sha256']
        decoded = untile(tiles, width, height)
        assert decoded == baseline
        assert sha(decoded) == saved29['pixels_sha256']
        palette_bytes = bytes(native.uc.mem_read(0x05000200, 448))
        assert sha(palette_bytes) == previous29['initialization']['palette_sha256']
        assert initialization['palette_entries'] == 224
        palette = struct.unpack('<224H', palette_bytes)
        assert all(color & 0x8000 == 0 for color in palette)
        base_rgba = rgba_from_indices(baseline, palette)
        assert sha(base_rgba) == previous29['frame1_palette_lookup']['analytical_rgba_sha256']
        matrix = placement['matrix_q8'] or [256, 0, 0, 256]
        displayed, outside = affine_sample(decoded, width, height, matrix)
        expected = mirror_reference(baseline, width, height) if heading else baseline
        assert displayed == expected
        rgba = rgba_from_indices(displayed, palette)
        reference_rgba = rgba_from_indices(expected, palette)
        assert rgba == reference_rgba
        used = set(displayed) - {0}
        opaque = sum(index != 0 for index in displayed)
        assert opaque == 258 and len(used) == len({palette[index] for index in used}) == 42
        assert sum(rgba[i] == 0 for i in range(3, len(rgba), 4)) == 766
        flip = b''.join(baseline[y * width:(y + 1) * width][::-1] for y in range(height))
        if heading:
            assert all(baseline[y * width] == 0 for y in range(height))
            assert displayed == b''.join(b'\0' + flip[y * width:(y + 1) * width - 1]
                                         for y in range(height))
        image = png_rgba(rgba, width, height)
        name = f'spr000_frame1_mode0_dir{heading:04x}.png'
        path = private_dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(image)
        path.chmod(0o600)
        assert path.read_bytes() == image
        cases.append({'heading': hex(heading), 'frame': 1, 'mode': 0,
                      'width': width, 'height': height, 'tile_count': 16,
                      'vram_address_synthetic': hex(address), 'tile_sha256': sha(tiles),
                      'step28_indices_sha256': sha(baseline), 'untiled_equals_step28': True,
                      'palette_entries': 224, 'palette_sha256': sha(palette_bytes),
                      'matrix_q8': matrix, 'affine_enabled': bool(heading),
                      'sampling_outside_texture_pixels': outside,
                      'indices_sha256_after_transform': sha(displayed),
                      'rgba_sha256': sha(rgba), 'rgba_reference_sha256': sha(reference_rgba),
                      'index_mismatches': sum(a != b for a, b in zip(displayed, expected)),
                      'rgba_pixel_mismatches': sum(rgba[i:i+4] != reference_rgba[i:i+4]
                                                   for i in range(0, len(rgba), 4)),
                      'nonzero_pixels': opaque, 'opaque_colors': len(used),
                      'transparent_pixels': 1024 - opaque,
                      'ordinary_flip_mismatches': (sum(a != b for a, b in zip(displayed, flip))
                                                   if heading else None),
                      'affine_equals_flip_shifted_right_one': True if heading else None,
                      'private_png_name': name, 'png_sha256': sha(image), 'png_bytes': len(image)})
    sources = ['scripts/audit_sprite_rgb.py', 'scripts/audit_sprite_upload.py',
               'scripts/audit_sprite_decode.py', 'work/step28_decode_verification.json',
               'work/step29_upload_verification.json']
    report = {'step': 30, 'rom_sha1': hashlib.sha1(rom).hexdigest(),
              'sources_sha256': {p: sha((ROOT / p).read_bytes()) for p in sources},
              'color_format': 'BGR555 word: R bits0..4, G bits5..9, B bits10..14',
              'channel_expansion': 'floor(channel5 * 255 / 31), analytical choice',
              'alpha': 'index0 transparent, others opaque; hidden RGB preserved',
              'affine_convention_source': AFFINE_SOURCE,
              'affine_convention_lines': '221-222 and 30-34, consulted 2026-10-17',
              'affine_centre': [16, 16], 'cases': cases,
              'ghidra_started': False, 'ghidra_mutated': False,
              'limits': ['Analytical object RGBA reconstruction, no PPU or game execution',
                         'Synthetic objects, layer, heap, cache, slots and VBlank flags',
                         'Immediate DMA simulated, inherited unaligned LDM shims',
                         'Assumed 1D OBJ tile mapping, no DISPCNT execution',
                         'No blending, fading, mosaic, scene composition or LCD color model',
                         'Local private PNGs only; no image/ROM/payload published']}
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'step': 30, 'cases': len(cases), 'pixel_mismatches': 0,
                      'private_pngs_written': len(cases)}))


if __name__ == '__main__':
    main()
