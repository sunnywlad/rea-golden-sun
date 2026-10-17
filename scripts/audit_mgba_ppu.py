#!/usr/bin/env python3
"""Execute the commercial ROM in installed mGBA; private dumps, public hashes.

The ONLY externally forced machine-state change is a PC redirection after
System_Initialize and before the title loop, into native Func_12518. This
does not establish natural accessibility of the debug viewer.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from probe_mgba31 import Core, ROOT, PRIVATE, private_write
from audit_sprite_decode import Harness, ROM_BASE, sha, u32
from audit_sprite_upload import UploadHarness
from audit_sprite_rgb import affine_sample, png_rgba, rgba_from_indices, untile

def rgb555(word):
    return bytes(((word >> shift & 31) << 3) | ((word >> shift & 31) >> 2)
                 for shift in (0, 5, 10))

def normalize_oam(attrs):
    a, b, d = attrs
    return [a & 0xff00, b & 0xc000, d & 0xfc00]

def rgb_crop(image, left, top):
    return b''.join(image[((top+y)*240+left+x)*4:((top+y)*240+left+x)*4+3]
                    for y in range(32) for x in range(32))

def main():
    output = Path(sys.argv[1])
    rompath = ROOT / 'work/rom/Golden Sun (USA, Europe).gba'
    rom = rompath.read_bytes()
    assert hashlib.sha1(rom).hexdigest() == '5c4695205413df7db52b9a184815a07783999971'
    previous = json.loads((ROOT / 'work/step30_rgb_verification.json').read_text())
    meta = rom[0x185024:0x185038]
    script = u32(rom, u32(meta, 16) - ROM_BASE)
    core = Core()
    try:
        # gprs[15] / readRegister('pc') includes the Thumb pipeline offset of 2.
        # Before executing the BL at address 0x08002ed8 to _Func_8a8e4,
        # initialization (including ten WaitFrames) has run; title has not.
        steps = core.lib.until(2_000_000, 0x08002eda, 0x08002edc)
        assert steps < 2_000_000
        entry = {name: hex(core.reg(name)) for name in ('pc', 'cpsr', 'sp')}
        assert entry == {'pc': '0x8002eda', 'cpsr': '0x6000003f', 'sp': '0x3007ef4'}
        # No register/memory/ROM patch other than this one PC redirection.
        core.reg('pc', 0x08012519)
        core.frames(120)
        # Edit animation 1 -> 0, turn shadows off, then A applies animation.
        inputs = [32, 0, 512, 0, 8, 0, 1, 0]
        for keys in inputs:
            core.frames(3, keys)
        before = {name: core.dump(a, n) for name, a, n in (
            ('vram', 0x06000000, 0x18000), ('palette', 0x05000000, 1024),
            ('oam', 0x07000000, 1024))}
        core.frames(1)
        dumps = {name: core.dump(a, n) for name, a, n in (
            ('vram', 0x06000000, 0x18000), ('palette', 0x05000000, 1024),
            ('oam', 0x07000000, 1024), ('io_bus', 0x04000000, 0x60))}
        assert all(before[name] == dumps[name] for name in before)
        image = core.image()
        # rawRead16, unlike busRead16, can inspect write-only MMIO backing.
        regs = {name: hex(core.lib.raw16(a)) for name, a in (
            ('DISPCNT', 0x04000000), ('BG0CNT', 0x04000008),
            ('MOSAIC', 0x0400004c), ('BLDCNT', 0x04000050),
            ('BLDALPHA', 0x04000052), ('BLDY', 0x04000054))}
        assert regs['DISPCNT'] == '0x1140'  # BG0+OBJ, OBJ 1D, mode0, no window
        assert regs['MOSAIC'] == '0x0'
        palette_bytes = dumps['palette'][512:960]
        assert palette_bytes == rom[0x779c:0x795c]
        palette = struct.unpack('<224H', palette_bytes)
        backdrop = struct.unpack_from('<H', dumps['palette'])[0]
        cases = []
        for heading, oam_index in ((0, 4), (0x8000, 3)):
            # Independently rerun the old native isolated harness, unmodified.
            baseline, state = Harness(rom).compose(meta, script, heading, 0)
            assert state[0x16] == 1
            harness = UploadHarness(rom)
            harness.configure()
            harness.prepare(meta, script, heading)
            placement = harness.placement(heading)
            harness_attrs = [int(a, 16) for a in placement['oam_attributes']]
            harness_address = 0x06010000 + (harness_attrs[2] & 1023) * 32
            harness_tiles = bytes(harness.uc.mem_read(harness_address, 1024))
            attrs = struct.unpack_from('<3H', dumps['oam'], oam_index*8)
            assert normalize_oam(attrs) == normalize_oam(harness_attrs)
            assert not attrs[0] & 0xdc00  # no effects, mosaic, alternative shape
            assert bool(attrs[0] & 0x100) == bool(heading)
            address = 0x06010000 + (attrs[2] & 1023)*32
            start = address-0x06000000
            tiles = dumps['vram'][start:start+1024]
            assert tiles == harness_tiles and untile(tiles, 32, 32) == baseline
            saved30 = next(c for c in previous['cases'] if int(c['heading'], 16) == heading)
            assert sha(tiles) == saved30['tile_sha256']
            assert sha(palette_bytes) == saved30['palette_sha256']
            affine_index = ((attrs[1] >> 9) & 31) if heading else None
            matrix = ([struct.unpack_from('<h', dumps['oam'], affine_index*32+n)[0]
                       for n in (6, 14, 22, 30)] if heading else [256, 0, 0, 256])
            assert matrix == ([-256, 0, 0, 256] if heading else [256, 0, 0, 256])
            indices, outside = affine_sample(baseline, 32, 32, matrix)
            assert sha(indices) == saved30['indices_sha256_after_transform']
            assert sha(rgba_from_indices(indices, palette)) == saved30['rgba_sha256']
            left, top = attrs[1] & 511, attrs[0] & 255
            assert [left, top] == ([72, 66] if heading else [184, 66])
            crop = rgb_crop(image, left, top)
            expected = b''.join(rgb555(palette[index] if index else backdrop) for index in indices)
            opaque_mismatches = sum(crop[i*3:i*3+3] != expected[i*3:i*3+3]
                                    for i, index in enumerate(indices) if index)
            total_mismatches = sum(crop[i:i+3] != expected[i:i+3] for i in range(0, 3072, 3))
            assert opaque_mismatches == total_mismatches == 0
            # Wrong centre must demonstrably fail against the actual PPU output.
            flip = b''.join(baseline[y*32:(y+1)*32][::-1] for y in range(32))
            wrong = b''.join(rgb555(palette[index] if index else backdrop) for index in flip)
            wrong_differences = sum(crop[i:i+3] != wrong[i:i+3] for i in range(0,3072,3)) if heading else None
            if heading:
                assert wrong_differences == 246
            rgba = b''.join(crop[i:i+3]+b'\xff' for i in range(0,3072,3))
            private_write(f'dir{heading:04x}_ppu.png', png_rgba(rgba,32,32))
            cases.append({'heading': hex(heading), 'oam_index': oam_index,
                'oam_attributes': [hex(a) for a in attrs],
                'oam_normalized': normalize_oam(attrs),
                'reference_oam_normalized': normalize_oam(harness_attrs),
                'top_left': [left, top], 'vram_address': hex(address),
                'tile_sha256': sha(tiles), 'palette_sha256': sha(palette_bytes),
                'matrix_index': affine_index, 'matrix_q8': matrix,
                'index_sha256': sha(indices), 'step30_analytical_rgba_sha256': saved30['rgba_sha256'],
                'ppu_rgb_sha256': sha(crop), 'expected_rgb_sha256': sha(expected),
                'nonzero_pixels': sum(bool(i) for i in indices),
                'opaque_pixel_mismatches': opaque_mismatches,
                'all_1024_pixel_mismatches': total_mismatches,
                'ordinary_flip_pixel_mismatches': wrong_differences,
                'sampling_outside_pixels': outside})
        for name, data in dumps.items():
            private_write(name+'.bin', data)
        private_write('frame.native32', image)
        # Serialized state is private, uncompressed and not a distributable ROM.
        private_write('viewer.state', core.state())
        report = {'step':31, 'rom_sha1':hashlib.sha1(rom).hexdigest(),
            'engine': subprocess.check_output(['/usr/games/mgba','--version'],text=True).strip(),
            'library_sha256':sha(Path('/usr/lib/x86_64-linux-gnu/libmgba.so.0.10').read_bytes()),
            'headers_deb_sha256':sha((ROOT/'work/step31_tools/libmgba-dev_0.10.5+dfsg-3build1_amd64.deb').read_bytes()),
            'entry': {'method':'Forced PC redirection after native system initialization; before title',
                      'steps_from_reset':steps, 'before':entry,'target_thumb':'0x08012519',
                      'natural_menu_access_established':False,
                      'external_memory_writes':0,'external_register_writes':['pc']},
            'inputs': {'initial_viewer_frames':120, 'key_masks':inputs, 'frames_per_mask':3,
                       'capture_after_extra_frames':1},
            'registers_raw_backing':regs,
            'complete_vram_palette_oam_stable_across_rendered_frame':True,
            'framebuffer_format':'little-endian uint32: RGB low24, metadata high8 discarded; not RGBA',
            'rgb_expansion':'(channel5 << 3) | (channel5 >> 2); step30 floor expansion normalized',
            'private_dumps':{name:{'bytes':len(data),'sha256':sha(data)} for name,data in dumps.items()},
            'framebuffer_sha256':sha(image),'cases':cases,
            'sources_sha256': {p:sha((ROOT/p).read_bytes()) for p in (
                'scripts/mgba31.c','scripts/probe_mgba31.py','scripts/audit_mgba_ppu.py',
                'scripts/audit_sprite_decode.py','scripts/audit_sprite_upload.py',
                'scripts/audit_sprite_rgb.py','work/step30_rgb_verification.json')},
            'limits':['Viewer access forced by one PC write; no natural menu/input path established',
                      'mGBA software PPU and HLE BIOS, not physical GBA or original BIOS',
                      'Engine constructs heap, objects, tiles, palettes, OAM and DMA natively after forced entry',
                      'Two SPR_000 animation0 frame1 mode0 headings only; shadows switched off via input',
                      'No Ghidra; no package installed; headers downloaded and extracted locally only',
                      'All extracted data and PNGs private; no ROM/image/payload publication']}
        output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
        assert rompath.read_bytes() == rom
        print(json.dumps({'step':31,'cases':len(cases),'all_pixel_mismatches':0,
                          'natural_menu_access':False}))
    finally:
        core.lib.stop()

if __name__ == '__main__':
    main()
