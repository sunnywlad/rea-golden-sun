#!/usr/bin/env python3
"""Isolated native verification of sprite upload, shared palette and mirror.

Reuses the step-28 harness without changing it. Outputs facts and hashes only.
DMA3 immediate transfers and heap allocation are explicitly simulated.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_PC

from audit_sprite_decode import Harness, ROOT, ROM_BASE, CODE, SOURCE, STOP, OBJ, LAYER, SYSTEM, sha, u32, unpack_lz, draw_model

VRAM = 0x06010000
POSITION = 0x02012000
SCALE = 0x02012100
OAM_SHADOW = 0x02013000


def tile_model(pixels, width, height):
    """Independent coordinate-based 8x8 tile order, one byte per pixel."""
    assert width % 8 == height % 8 == 0
    return bytes(pixels[y * width + x]
                 for ty in range(0, height, 8)
                 for tx in range(0, width, 8)
                 for y in range(ty, ty + 8)
                 for x in range(tx, tx + 8))


class UploadHarness(Harness):
    def __init__(self, rom):
        self.dmas = []
        self.heap_slots = {}
        self.upload_calls = []
        self.vram_writes = []
        self.affine_calls = []
        self.native_calls = []
        self.oam_builder_calls = 0
        self.slice_stop = False
        super().__init__(rom)
        for address, size in ((0x04000000, 0x1000), (0x05000000, 0x1000),
                              (0x06000000, 0x20000), (0x07000000, 0x1000)):
            self.uc.mem_map(address, size)
        # Synthetic empty VRAM cache, with the first 64 bytes reserved to make
        # tile zero unavailable, as required by ResourceObject_Create.
        self.uc.mem_write(0x03001810, bytes([0xff]) * 512)
        self.uc.mem_write(0x03001810, bytes([94]))
        self.uc.mem_write(0x03001b10 + 94 * 4, struct.pack('<HH', 64, 0))
        self.uc.mem_write(0x05000000, bytes([0xa5]) * 1024)
        self.uc.mem_write(0x06000000, bytes([0xa5]) * 0x20000)

    def on_write(self, uc, access, address, size, value, data):
        super().on_write(uc, access, address, size, value, data)
        if VRAM <= address < VRAM + 0x8000:
            self.vram_writes.append((address, size))
        if address == 0x040000dc and size == 4 and value & 0x80000000:
            # All observed transfers are immediate DMA3, increasing destination;
            # source is either increasing or fixed. No bus/timing model.
            control = value
            assert control & 0x30000000 == 0
            assert (control >> 21) & 3 == 0
            source_mode = (control >> 23) & 3
            assert source_mode in (0, 2)
            source = u32(bytes(uc.mem_read(0x040000d4, 4)), 0)
            destination = u32(bytes(uc.mem_read(0x040000d8, 4)), 0)
            unit = 4 if control & 0x04000000 else 2
            count = control & 0xffff
            assert count > 0
            payload = (bytes(uc.mem_read(source, unit)) * count if source_mode == 2
                       else bytes(uc.mem_read(source, count * unit)))
            uc.mem_write(destination, payload)
            self.dmas.append({'source': hex(source), 'destination': hex(destination),
                              'control': hex(control), 'bytes': len(payload),
                              'sha256': sha(payload)})

    def on_code(self, uc, address, size, data):
        if self.slice_stop and address in (0x080036a8, 0x080036bc):
            uc.reg_write(UC_ARM_REG_PC, STOP)
            uc.emu_stop()
            return
        if address == 0x0800af12:
            return  # Continue beyond the step-28 stop into the upload.
        if address == 0x080048b0:
            slot, length = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            assert slot not in self.heap_slots and length <= 0x2000
            pointer = 0x02020000 + len(self.heap_slots) * 0x2000
            self.heap_slots[slot] = (pointer, length)
            uc.mem_write(0x03001e50 + slot * 4, struct.pack('<I', pointer))
            uc.reg_write(UC_ARM_REG_R0, pointer)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if 53 in self.heap_slots and address == self.heap_slots[53][0]:
            self.upload_calls.append([uc.reg_read(reg) for reg in
                                      (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)])
        if address == 0x08003d28:
            pointer = uc.reg_read(UC_ARM_REG_R0)
            self.affine_calls.append(list(struct.unpack('<hhh', bytes(uc.mem_read(pointer, 6)))))
        if self.allocations and self.allocations[-1] == (address, 0xe0):
            self.oam_builder_calls += 1
        if address in (0x08003fa4, 0x08003dec, 0x08004838):
            self.native_calls.append(hex(address))
        super().on_code(uc, address, size, data)

    def configure(self):
        self.run(0x0800bb21, (2,))
        assert sorted(self.heap_slots) == [3, 4, 53]
        uploader, length = self.heap_slots[53]
        assert length == 0x7c
        assert bytes(self.uc.mem_read(uploader, length)) == self.rom[0xa418:0xa494]
        colors = bytes(self.uc.mem_read(0x05000200, 448))
        assert colors == self.rom[0x779c:0x795c]
        assert bytes(self.uc.mem_read(0x050003c0, 64)) == bytes([0xa5]) * 64
        return {'uploader_slot': 53, 'uploader_ram': hex(uploader),
                'uploader_rom': '0x0800a418', 'uploader_bytes': length,
                'uploader_sha256': sha(self.rom[0xa418:0xa494]),
                'palette_source': '0x0800779c', 'palette_destination': '0x05000200',
                'palette_entries': 224, 'palette_sha256': sha(colors),
                'palette_224_to_255_preserved': True, 'dma': list(self.dmas)}

    def uploader_witness(self, width, height):
        pixels = bytes(((x * 37 + y * 61 + (x ^ y) * 13) & 255)
                       for y in range(height) for x in range(width))
        self.uc.mem_write(SOURCE, pixels)
        self.uc.mem_write(VRAM, bytes([0xa5]) * (len(pixels) + 32))
        self.vram_writes.clear()
        self.uc.reg_write(UC_ARM_REG_R3, VRAM)
        self.run(self.heap_slots[53][0], (SOURCE, width, height))
        native = bytes(self.uc.mem_read(VRAM, len(pixels)))
        assert native == tile_model(pixels, width, height)
        assert bytes(self.uc.mem_read(VRAM + len(pixels), 32)) == bytes([0xa5]) * 32
        touched = {a + i for a, n in self.vram_writes for i in range(n)}
        assert touched == set(range(VRAM, VRAM + len(pixels)))
        return {'width': width, 'height': height, 'bytes': len(pixels),
                'input_sha256': sha(pixels), 'tiles_sha256': sha(native)}

    def placement(self, heading):
        self.uc.mem_write(POSITION, struct.pack('<iiii', 144 << 16, 0, 96 << 16, 0))
        self.uc.mem_write(SCALE, struct.pack('<ii', 1 << 16, 1 << 16))
        self.uc.reg_write(UC_ARM_REG_R3, heading)
        self.run(0x0800b169, (OBJ, POSITION, SCALE))
        count = self.uc.mem_read(0x03001d00, 1)[0]
        assert count == int(heading == 0x8000)
        if count:
            assert self.affine_calls == [[-256, 256, 0]]
            matrix = list(struct.unpack('<4h', bytes(self.uc.mem_read(0x03001d40, 8))))
            assert matrix == [-256, 0, 0, 256]
        else:
            assert not self.affine_calls
            matrix = None
        # Use the real wrapper: copies OAM builder into allocated RAM via DMA,
        # executes it and frees that code. The hardware palette/VRAM/OAM buses
        # themselves remain plain Unicorn memory.
        self.run(0x08003e11, (OAM_SHADOW,))
        assert self.oam_builder_calls == 1
        assert bytes(self.uc.mem_read(self.allocations[-1][0], 0xe0)) == self.rom[0x1dc8:0x1ea8]
        self.uc.mem_write(0x03001f20, struct.pack('<I', OAM_SHADOW))
        self.uc.mem_write(0x03001e44, b'\x01')
        self.uc.mem_write(0x03001d18, b'\x01')
        self.slice_stop = True
        # Execute only the OAM gate and DMA instructions of Func_3650, stopping
        # before BG transfers and the rest of the VBlank handler.
        dma_count = len(self.dmas)
        self.run(0x08003687, ())
        self.slice_stop = False
        assert len(self.dmas) == dma_count + 1
        oam_dma = self.dmas[-1]
        assert oam_dma['source'] == hex(OAM_SHADOW)
        assert oam_dma['destination'] == '0x7000000'
        assert oam_dma['control'] == '0x84000100' and oam_dma['bytes'] == 1024
        assert bytes(self.uc.mem_read(0x07000000, 1024)) == bytes(self.uc.mem_read(OAM_SHADOW, 1024))
        disabled_gates = []
        for frame_ready, oam_ready in ((0, 0), (0, 1), (1, 0)):
            self.uc.mem_write(0x03001e44, bytes([frame_ready]))
            self.uc.mem_write(0x03001d18, bytes([oam_ready]))
            self.slice_stop = True
            before = len(self.dmas)
            self.run(0x08003687, ())
            self.slice_stop = False
            assert len(self.dmas) == before
            disabled_gates.append([frame_ready, oam_ready])
        attr0, attr1, attr2 = struct.unpack('<3H', bytes(self.uc.mem_read(0x07000000, 6)))
        assert attr0 == (0x2142 if count else 0x2042)
        assert attr1 == 0x8080
        assert attr2 == 0x806
        if count:
            oam_matrix = [struct.unpack('<h', bytes(self.uc.mem_read(0x07000000 + n, 2)))[0]
                          for n in (6, 14, 22, 30)]
            assert oam_matrix == matrix
        return {'heading': hex(heading), 'position_pixels': [144, 0, 96, 0],
                'scale_q16': [65536, 65536], 'sprite_top_left': [128, 66],
                'oam_attributes': [hex(attr0), hex(attr1), hex(attr2)],
                'affine_matrix_count': count, 'matrix_q8': matrix,
                'matrix_copied_to_oam': bool(count), 'oam_destination': '0x07000000',
                'oam_shadow': hex(OAM_SHADOW), 'oam_dma': oam_dma,
                'no_oam_dma_for_flags': disabled_gates,
                'oam_builder_executed_from_ram': True,
                'oam_builder_sha256': sha(self.rom[0x1dc8:0x1ea8]),
                'native_entries_observed': self.native_calls,
                'vblank_slice': ['0x08003686', '0x080036a8'],
                'complete_vblank_executed': False}

    def prepare(self, metadata, script, heading, mode=0):
        self.composing = True
        self.uc.mem_write(0x03001e68, struct.pack('<I', SYSTEM))
        self.uc.mem_write(0x03001f20, struct.pack('<I', CODE))
        obj = bytearray(0x38)
        # Native constructor's square 32x32, 8bpp template and priority 2.
        struct.pack_into('<II', obj, 4, 0x80002000, 0x800)
        obj[0x20:0x22] = metadata[:2]
        obj[0x22:0x24] = metadata[6:8]
        obj[0x1c] = 0
        obj[0x27] = 1
        struct.pack_into('<I', obj, 0x28, LAYER)
        layer = bytearray(0x18)
        layer[4:8] = bytes([metadata[4], mode, 0, metadata[10]])
        layer[8:16] = metadata[12:20]
        struct.pack_into('<I', layer, 0x10, script)
        layer[0x15:0x18] = bytes([16, 255, 0])
        self.uc.mem_write(OBJ, bytes(obj))
        self.uc.mem_write(LAYER, bytes(layer))

    def result(self, metadata, heading, mode):
        width, height = metadata[:2]
        size = width * height
        pixels = bytes(self.uc.mem_read(self.allocations[0][0], size))
        frame = (self.rom[0x130ac + (heading >> 12)] & 7)
        pointer = u32(self.rom, u32(metadata, 12) - ROM_BASE + frame * 4)
        stream, _ = unpack_lz(self.rom, pointer - ROM_BASE)
        expected, _, _, _ = draw_model(self.rom, stream, mode, 3, bytes(size))
        assert pixels == expected
        attr2 = struct.unpack('<H', bytes(self.uc.mem_read(OBJ + 8, 2)))[0]
        tile = attr2 & 1023
        destination = VRAM + tile * 32
        uploaded = bytes(self.uc.mem_read(destination, size))
        assert uploaded == tile_model(expected, width, height)
        assert self.upload_calls == [[self.allocations[0][0], width, height, destination]]
        assert self.frees == [self.allocations[0][0]]
        assert self.uc.mem_read(OBJ + 0x25, 1) == b'\0'
        assert attr2 & 0xfc00 == 0x800
        touched = {address + i for address, count in self.vram_writes for i in range(count)}
        assert touched == set(range(destination, destination + size))
        assert all(count == 4 for _, count in self.vram_writes)
        return {'heading': hex(heading), 'mode': mode, 'frame': frame,
                'tile': tile, 'destination': hex(destination), 'bytes': size,
                'pixels_sha256': sha(pixels), 'tiles_sha256': sha(uploaded),
                'native_vram_store_count': len(self.vram_writes),
                'upload_args': [hex(v) for v in self.upload_calls[0]],
                'dirty_after': 0, 'freed_pixel_buffer': True,
                'attr2': hex(attr2), 'ldm_shims': self.ldm_shims}


def main():
    output = Path(sys.argv[1])
    rom = (ROOT / 'work/rom/Golden Sun (USA, Europe).gba').read_bytes()
    assert hashlib.sha1(rom).hexdigest() == '5c4695205413df7db52b9a184815a07783999971'
    repo = ROOT / 'external/alchemy'
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    assert commit == '1517ff0750d988f570b6efcd06bf30d0f64c9d2a'
    assert not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip()
    metadata = rom[0x185024:0x185038]
    assert metadata[:2] == bytes([32, 32]) and metadata[6:8] == bytes([0, 2])
    assert struct.unpack_from('<ii', rom, 0x13584) == (65536, 65536)
    script = u32(rom, u32(metadata, 16) - ROM_BASE)
    first = UploadHarness(rom)
    initialization = first.configure()
    witnesses = [first.uploader_witness(w, h) for w, h in
                 ((8, 8), (16, 8), (8, 16), (16, 16), (32, 32), (64, 32), (32, 64), (64, 64))]
    cases = []
    for heading in (0, 0x8000):
        h = UploadHarness(rom)
        h.configure()
        h.vram_writes.clear()
        h.prepare(metadata, script, heading)
        h.run(0x0800aa0d, (OBJ, heading))
        result = h.result(metadata, heading, 0)
        result['mirror_return'] = h.uc.reg_read(UC_ARM_REG_R0)
        assert result['mirror_return'] == int(heading == 0x8000)
        cases.append(result)
    assert cases[0]['tiles_sha256'] == cases[1]['tiles_sha256']
    frame_pointer = u32(rom, u32(metadata, 12) - ROM_BASE + 4)
    stream, _ = unpack_lz(rom, frame_pointer - ROM_BASE)
    pixels, _, written, _ = draw_model(rom, stream, 0, 3, bytes(1024))
    palette = struct.unpack_from('<224H', rom, 0x779c)
    used = set(pixels) - {0}
    assert min(used) == 10 and max(used) == 222
    assert len(used) == len({palette[index] for index in used}) == 42
    assert len(written) == 258 and all(palette[index] & 0x8000 == 0 for index in used)
    # An analytical color mapping, not a PPU render: zero gets alpha zero.
    rgba = bytes(component for index in pixels for component in
                 (((palette[index] & 31) * 255 // 31),
                  (((palette[index] >> 5) & 31) * 255 // 31),
                  (((palette[index] >> 10) & 31) * 255 // 31),
                  255 if index else 0))
    color_summary = {'frame': 1, 'mode': 0, 'nonzero_pixels': len(written),
                     'distinct_nonzero_indices': len(used), 'distinct_colors': 42,
                     'min_nonzero_index': min(used), 'max_nonzero_index': max(used),
                     'all_nonzero_indices_in_loaded_palette': True,
                     'analytical_rgba_sha256': sha(rgba),
                     'rgb_expansion': 'floor(channel5 * 255 / 31)',
                     'alpha_rule': 'index zero transparent, other indices opaque',
                     'ppu_color_blending_emulated': False}
    # A direction change that selects the same frame must change the mirror
    # result without a second upload or allocation.
    before_counts = (len(h.allocations), len(h.frees), len(h.upload_calls), len(h.vram_writes))
    h.run(0x0800aa0d, (OBJ, 0))
    assert h.uc.reg_read(UC_ARM_REG_R0) == 0
    assert before_counts == (len(h.allocations), len(h.frees), len(h.upload_calls), len(h.vram_writes))
    placements = []
    for heading in (0, 0x8000):
        h = UploadHarness(rom)
        h.configure()
        h.vram_writes.clear()
        h.prepare(metadata, script, heading)
        placement = h.placement(heading)
        # The wrapper added a code allocation/free after the pixel upload.
        assert len(h.allocations) == len(h.frees) == 2
        assert h.allocations[1][1] == 0xe0
        assert h.frees == [p for p, length in h.allocations]
        placements.append(placement)
    sources = ['scripts/audit_sprite_decode.py', 'scripts/audit_sprite_upload.py',
               'external/alchemy/games/tbs/src/field/field.c',
               'external/alchemy/games/tbs/src/graphics/tile/convert_map.s',
               'work/repo/rom_9000/src/rom_a97c.s', 'work/repo/rom_9000/src/rom_92b8.s',
               'work/repo/rom_9000/src/rom_b798.s', 'work/repo/rom_9000/src/rom_b074.s',
               'work/repo/rom_c0/src/rom_45e8.s', 'work/repo/rom_c0/src/rom_3e58.s',
               'work/repo/rom_c0/src/rom_3d04.s', 'work/repo/rom_c0/src/rom_1b70.s',
               'work/repo/rom_c0/src/rom_3650.s']
    report = {'step': 29, 'rom_sha1': hashlib.sha1(rom).hexdigest(),
              'alchemy_commit': commit, 'ghidra_started': False, 'ghidra_mutated': False,
              'sources_sha256': {p: sha((ROOT / p).read_bytes()) for p in sources},
              'initialization': initialization, 'uploader_synthetic_witnesses': witnesses,
              'native_compositions': cases, 'native_placement_and_oam': placements,
              'frame1_palette_lookup': color_summary,
              'same_frame_direction_change_avoids_reupload': True,
              'limits': ['Isolated ROM execution, no complete game or display emulation',
                         'Synthetic object, layer, heap, cache state and decoder slot',
                         'Immediate DMA3 simulated by explicit memory transfers',
                         'Three inherited unaligned decoder LDM corrections',
                         'Only an OAM gate/DMA slice of VBlank is executed',
                         'DISPCNT, PPU mapping, blending and scanout are not executed',
                         'No framebuffer, screenshot or extracted payload output']}
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'output': str(output), 'native_compositions': len(cases)}))


if __name__ == '__main__':
    main()
