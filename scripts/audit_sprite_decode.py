#!/usr/bin/env python3
"""Verify SPR_000 animation 0 with isolated ROM ARM/Thumb execution.

Run: uv run --offline --no-project --with unicorn==2.1.4 python
     scripts/audit_sprite_decode.py work/step28_decode_verification.json
No game, BIOS, Ghidra, external build, image, or ROM payload is output.
Allocation/free and three unaligned LDM sites are harness hooks; the compositor
stops before outline/upload. The LDM shim matches mGBA GBALoadMultiple's address
alignment and low-bit-preserving writeback, not Unicorn's default behavior.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR,
    UC_ARM_REG_PC, UC_ARM_REG_CPSR,
)

ROOT = Path(__file__).resolve().parents[1]
ROM_BASE = 0x08000000
CODE = 0x02001000
SOURCE = 0x02003000
DEST = 0x02006000
STOP = 0x0200f000
OBJ = 0x02011000
LAYER = 0x02011100
SYSTEM = 0x02011200
HEAP = 0x02018000
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def unpack_lz(rom, start):
    """Independent byte model of Func_a97c, using ROM-backed references."""
    token = struct.unpack_from('<H', rom, start)[0]
    if token == 0:
        end = rom.index(0, start + 2) + 1
        return rom[start + 2:end], set(range(start, end))
    literal = start + 2
    base = literal
    command = start + token
    output = bytearray()
    reads = set()

    def read(at):
        assert 0 <= at < len(rom)
        reads.add(at)
        return rom[at]

    for _ in range(0x10000):
        control = read(command) | 0x100
        command += 1
        while control != 1:
            if control & 1:
                output.append(read(literal))
                literal += 1
            else:
                token = read(command) << 8 | read(command + 1)
                command += 2
                if token == 0:
                    return bytes(output), reads
                length = token >> 12
                if length == 0:
                    length = read(command) + 16
                    command += 1
                length += 2
                copy = base - (token & 0xfff)
                output.extend(read(copy + i) for i in range(length))
            assert len(output) <= 0x400
            control >>= 1
    raise AssertionError('LZ model did not terminate')


def draw_model(rom, stream, mode, fill, background):
    result = bytearray(background)
    pos = 0
    writes = []
    key = mode if 1 <= mode <= 6 else mode - 2
    table = u32(rom, 0x9d98) - ROM_BASE + (key << 8)
    for index, value in enumerate(stream):
        if value == 0:
            return bytes(result), pos, writes, index + 1
        if value > 223:
            pos += value - 223
        else:
            if mode == 0:
                pixel = value
            elif mode in (7, 8, 13, 14, 15):
                pixel = {7: 15, 8: 15, 13: fill, 14: 1, 15: 0}[mode]
            else:
                pixel = rom[table + value]
            assert 0 <= pos < len(result)
            result[pos] = pixel
            writes.append(pos)
            pos += 1
    raise AssertionError('Missing draw stream terminator')


class Harness:
    def __init__(self, rom):
        self.rom = rom
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for addr, size in ((ROM_BASE, len(rom)), (0x02000000, 0x40000),
                           (0x03000000, 0x8000)):
            self.uc.mem_map(addr, size)
        self.uc.mem_write(ROM_BASE, rom)
        # Match the already established startup relocation of rom_770.
        self.uc.mem_write(0x03000000, rom[0x770:0x1b70])
        self.uc.mem_write(CODE, rom[0x9bb8:0x9d9c])
        self.uc.mem_write(0x03001c90, b'\x03')
        self.allocations = []
        self.frees = []
        self.decoder_calls = []
        self.table_writes = []
        self.trace = []
        self.composing = False
        self.ldm_shims = 0
        self.uc.hook_add(UC_HOOK_CODE, self.on_code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write)

    def on_write(self, uc, access, address, size, value, _):
        if CODE + 0x1e4 <= address < CODE + 0x2c4:
            self.table_writes.append((address - CODE - 0x1e4, size))

    def on_code(self, uc, address, size, _):
        if address == STOP:
            uc.emu_stop()
            return
        if address in (CODE + 0x10, CODE + 0x70, CODE + 0xc0):
            source = uc.reg_read(UC_ARM_REG_R0)
            if source & 3:
                assert bytes(uc.mem_read(address, 4)) == struct.pack('<I', 0xe8b00008)
                word = u32(bytes(uc.mem_read(source & ~3, 4)), 0)
                uc.reg_write(UC_ARM_REG_R3, word)
                uc.reg_write(UC_ARM_REG_R0, source + 4)
                uc.reg_write(UC_ARM_REG_PC, address + 4)
                self.ldm_shims += 1
                return
        if not self.composing:
            return
        if address == 0x08004938:
            length = uc.reg_read(UC_ARM_REG_R0)
            allocated = HEAP + len(self.allocations) * 0x1000
            assert length <= 0x1000 and allocated + length < 0x02040000
            self.allocations.append((allocated, length))
            uc.reg_write(UC_ARM_REG_R0, allocated)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == 0x08002df0:
            self.frees.append(uc.reg_read(UC_ARM_REG_R0))
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == CODE:
            self.decoder_calls.append([uc.reg_read(reg) for reg in REGS])
        elif address in (0x0800a97c, 0x030005c0, 0x08005340):
            self.trace.append(hex(address))
        elif address == 0x0800af12:
            uc.emu_stop()

    def run(self, address, args):
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x10)
        self.uc.reg_write(UC_ARM_REG_SP, 0x03007f00)
        self.uc.reg_write(UC_ARM_REG_LR, STOP)
        for reg, value in zip(REGS, args):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(address, STOP + 4, count=250000)
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        assert pc in (STOP, 0x0800af12), hex(pc)

    def decode(self, stream, mode, alignment=0, fill=3, background=None):
        background = bytes([0xa5]) * 0x1000 if background is None else background
        self.uc.mem_write(SOURCE, bytes(4) + stream + bytes(8))
        self.uc.mem_write(SOURCE + alignment, stream + bytes(8))
        self.uc.mem_write(DEST, background)
        self.uc.mem_write(0x03001c90, bytes([fill]))
        self.table_writes = []
        self.run(CODE, (SOURCE + alignment, DEST, mode))
        result = bytes(self.uc.mem_read(DEST, len(background)))
        expected, extent, writes, consumed = draw_model(
            self.rom, stream, mode, fill, background)
        assert result == expected, ('decoder mismatch', mode, alignment)
        assert self.uc.reg_read(UC_ARM_REG_R1) == DEST + extent
        return result, extent, writes, consumed

    def compose(self, metadata, script, heading, mode):
        self.composing = True
        self.uc.mem_write(0x03001e68, struct.pack('<I', SYSTEM))
        self.uc.mem_write(0x03001f20, struct.pack('<I', CODE))
        obj = bytearray(0x38)
        obj[0x20:0x22] = metadata[:2]
        obj[0x27] = 1
        struct.pack_into('<I', obj, 0x28, LAYER)
        layer = bytearray(0x18)
        layer[4:8] = bytes([metadata[4], mode, 0, metadata[10]])
        layer[8:16] = metadata[12:20]
        struct.pack_into('<I', layer, 0x10, script)
        layer[0x15:0x18] = bytes([16, 255, 0])
        self.uc.mem_write(OBJ, bytes(obj))
        self.uc.mem_write(LAYER, bytes(layer))
        self.run(0x0800aa0d, (OBJ, heading))
        size = metadata[0] * metadata[1]
        pixels = bytes(self.uc.mem_read(self.allocations[0][0], size))
        state = bytes(self.uc.mem_read(LAYER, 0x18))
        return pixels, state


def main():
    output = Path(sys.argv[1])
    rom = (ROOT / 'work/rom/Golden Sun (USA, Europe).gba').read_bytes()
    assert hashlib.sha1(rom).hexdigest() == '5c4695205413df7db52b9a184815a07783999971'
    repo = ROOT / 'external/alchemy'
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    assert commit == '1517ff0750d988f570b6efcd06bf30d0f64c9d2a'
    assert not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip()
    sources = [
        'external/alchemy/games/tbs/src/field/field.c',
        'external/alchemy/games/tbs/src/field/facing.c',
        'external/alchemy/games/tbs/src/field/remap.s',
        'external/alchemy/games/tbs/src/graphics/render/decode.s',
        'external/alchemy/games/tbs/src/graphics/sprite/sprites.tsv',
        'external/alchemy/games/tbs/src/graphics/sprite/spr_000.tsv',
        'external/alchemy/games/tbs/src/system/resource/colconv.s',
        'external/alchemy/tools/ags-graphics/resource.c',
        'work/repo/rom_9000/src/rom_92b8.s',
        'work/repo/rom_9000/src/rom_a97c.s',
        'work/repo/rom_9000/src/rom_1219c.s',
        'work/repo/rom_c0/src/rom_770.s',
    ]
    for i in range(9):
        relative = (f'external/alchemy/games/tbs/src/system/resource/colconv{i}.tsv'
                    if i < 5 else f'external/alchemy/games/tbs/src/field/remap{i - 5}.tsv')
        sources.append(relative)
        rows = (ROOT / relative).read_text().splitlines()
        values = bytes(int(value) for row in rows[1:] for value in row.split('\t'))
        assert len(values) == 256
        assert values == rom[0x92b8 + i * 256:0x93b8 + i * 256]

    metadata = rom[0x185024:0x185038]
    scripts = u32(metadata, 16)
    script = u32(rom, scripts - ROM_BASE)
    assert rom[script - ROM_BASE:script - ROM_BASE + 4] == bytes.fromhex('00 04 f1 00')
    assert metadata[:2] == bytes([32, 32]) and metadata[4] == 5 and metadata[10] == 3
    assert metadata[5] == 38
    facing = rom[0x130ac:0x130bc]
    frames = u32(metadata, 12)
    table_base = u32(rom, 0x9d98)
    assert table_base == 0x080091b8
    offsets = struct.unpack_from('<16h', rom, 0x9cdc)
    modes = []
    for mode in range(16):
        row = {'mode': mode, 'dispatch_target': hex(0x08009ce0 + offsets[mode])}
        if mode in (*range(1, 7), *range(9, 13)):
            key = mode if mode <= 6 else mode - 2
            start = table_base - ROM_BASE + key * 256
            table = rom[start:start + 224]
            row.update(key=key, table_address=hex(ROM_BASE + start),
                       copied_bytes=224, table_sha256=sha(table),
                       distinct_outputs_for_pixels=len(set(table[1:])),
                       zero_outputs_for_pixels=table[1:].count(0),
                       outputs_above_223=sum(v > 223 for v in table[1:]),
                       alchemy_tsv=(f'colconv{mode - 1}.tsv' if mode <= 5 else
                                    f'remap{key - 6}.tsv' if key <= 9 else None))
        else:
            row['effect'] = {0: 'identity', 7: 'constant 15', 8: 'constant 15',
                             13: 'byte at 0x03001c90', 14: 'constant 1',
                             15: 'constant 0'}[mode]
        modes.append(row)

    # Exhaustive pixel/skip alphabets at all alignments, with explicit LDM shim.
    # Each stream stops at zero. Additional cases place zero at each word lane.
    probe_streams = [bytes(range(1, 224)) + bytes(range(224, 256)) + b'\0']
    probe_streams += [bytes([1, 2, 3][:lane]) + b'\0\x04\x05\x06' for lane in range(4)]
    probe_streams += [bytes([0xff, 223, 0xe0, 1, 0])]
    harness = Harness(rom)
    probe_count = 0
    for stream in probe_streams:
        for mode in range(16):
            for alignment in range(4):
                harness.decode(stream, mode, alignment)
                probe_count += 1
    # Mode 13 is runtime data, not a constant three in the decoder.
    for fill in (0, 1, 3, 15, 223, 255):
        harness.decode(bytes([1, 223, 224, 2, 0]), 13, fill=fill)
        probe_count += 1

    # Reuse one RAM instance: same key skips table writes; mode 9 and 1 differ.
    cache_checks = []
    for mode in (1, 1, 9, 9, 1, 7, 1, 12, 12):
        harness.decode(bytes([1, 223, 0]), mode)
        cache_checks.append({'mode': mode, 'cache_key': u32(bytes(harness.uc.mem_read(CODE + 0x1d8, 4)), 0),
                             'table_bytes_written': sum(size for _, size in harness.table_writes)})
    assert [r['table_bytes_written'] for r in cache_checks] == [224, 0, 224, 0, 224, 0, 0, 224, 0]

    frame_results = []
    for index in range(5):
        pointer = u32(rom, frames - ROM_BASE + index * 4)
        decoded, reads = unpack_lz(rom, pointer - ROM_BASE)
        native = Harness(rom)
        native.run(0x0800a97d, (pointer, SOURCE))
        returned = native.uc.reg_read(UC_ARM_REG_R0)
        header = struct.unpack_from('<H', rom, pointer - ROM_BASE)[0]
        assert returned == (SOURCE if header else pointer + 2)
        assert bytes(native.uc.mem_read(returned, len(decoded))) == decoded
        buffers = []
        for mode in range(16):
            pixels, extent, writes, consumed = native.decode(decoded, mode, background=bytes(1024))
            assert extent <= 1024
            buffers.append({'mode': mode, 'pixels_sha256': sha(pixels),
                            'nonzero_pixels': sum(p != 0 for p in pixels),
                            'distinct_nonzero_indices': len(set(pixels) - {0})})
        frame_results.append({'frame': index, 'pointer': hex(pointer),
                              'lz_header': struct.unpack_from('<H', rom, pointer - ROM_BASE)[0],
                              'lz_unique_rom_bytes_read': len(reads),
                              'intermediate_bytes': len(decoded), 'intermediate_sha256': sha(decoded),
                              'stream_consumed_bytes': consumed, 'destination_extent': extent,
                              'pixel_writes': len(writes), 'skipped_pixels': extent - len(writes),
                              'trailing_untouched_pixels': 1024 - extent,
                              'model_equals_native_unpack': True, 'draw_modes': buffers})

    composition = []
    for heading in range(0, 0x10000, 0x2000):
        value = facing[heading >> 12]
        frame = value & 7
        for mode in range(16):
            native = Harness(rom)
            pixels, state = native.compose(metadata, script, heading, mode)
            expected = frame_results[frame]['draw_modes'][mode]
            assert sha(pixels) == expected['pixels_sha256'], (heading, mode, native.trace)
            assert state[0x16] == frame and state[0x17] == 0 and state[0x14] == 2
            assert struct.unpack_from('<h', state, 2)[0] == 64
            stack = native.uc.reg_read(UC_ARM_REG_SP)
            assert u32(bytes(native.uc.mem_read(stack + 0x28, 4)), 0) == bool(value & 0x80)
            if mode == 0:
                assert '0x30005c0' in native.trace
                assert len(native.decoder_calls) == 1 and native.decoder_calls[0][2] == 0
            else:
                assert '0x800a97c' in native.trace and len(native.decoder_calls) == 1
                assert native.decoder_calls[0][2] == mode
            composition.append({'heading': hex(heading), 'frame': frame,
                                'mirrored': bool(value & 0x80), 'mode': mode,
                                'decoder_calls': len(native.decoder_calls),
                                'unaligned_ldm_shims': native.ldm_shims,
                                'pixels_sha256': sha(pixels), 'native_paths': native.trace})

    # Continue the same script after the initial draw. Model the dirty reset
    # normally performed after upload, beyond this harness's stopping point.
    native = Harness(rom)
    native.compose(metadata, script, 0, 1)
    timeline = []
    for call in range(7):
        if call:
            native.uc.mem_write(OBJ + 0x25, b'\0')
            native.decoder_calls = []
            native.run(0x0800aa0d, (OBJ, 0))
        state = bytes(native.uc.mem_read(LAYER, 0x18))
        timeline.append({'call': call + 1, 'timer': struct.unpack_from('<h', state, 2)[0],
                         'script_position': state[0x14], 'frame': state[0x16],
                         'decoder_calls': len(native.decoder_calls)})
    assert [row['timer'] for row in timeline] == [64, 48, 32, 16, 0, 0, 0]
    assert [row['decoder_calls'] for row in timeline] == [1, 0, 0, 0, 0, 0, 0]
    assert all(row['script_position'] == 2 and row['frame'] == 1 for row in timeline)

    # Frame 5 is outside animation 0; it is a control for the compressed branch
    # that frames 0..4 do not take. Observe, rather than hide, the fused writer's
    # treatment of the expanded zero byte at the end of the draw stream.
    pointer = u32(rom, frames - ROM_BASE + 5 * 4)
    decoded, _ = unpack_lz(rom, pointer - ROM_BASE)
    native = Harness(rom)
    native.run(0x0800a97d, (pointer, SOURCE))
    assert native.uc.reg_read(UC_ARM_REG_R0) == SOURCE
    assert bytes(native.uc.mem_read(SOURCE, len(decoded))) == decoded
    expected, extent, writes, consumed = draw_model(rom, decoded, 0, 3, bytes([0xa5]) * 0x1000)
    native.uc.mem_write(DEST, bytes([0xa5]) * 0x1000)
    native.run(0x030005c0, (pointer, DEST))
    fused = bytes(native.uc.mem_read(DEST, 0x1000))
    differences = [i for i, (a, b) in enumerate(zip(fused, expected)) if a != b]
    assert native.uc.reg_read(UC_ARM_REG_R0) == 0
    assert differences == [1024] and fused[1024] == 0
    assert native.uc.reg_read(UC_ARM_REG_R1) == DEST + 1025
    compressed_control = {'frame': 5, 'outside_animation_0': True, 'pointer': hex(pointer),
                          'lz_header': struct.unpack_from('<H', rom, pointer - ROM_BASE)[0],
                          'intermediate_bytes': len(decoded), 'intermediate_sha256': sha(decoded),
                          'native_unpack_equals_model': True, 'fused_return': 0,
                          'fused_equals_draw_model_first_1024_bytes': fused[:1024] == expected[:1024],
                          'extra_zero_write_at_destination_offset': 1024,
                          'final_destination_offset': 1025}

    result = {
        'verified': True, 'rom_sha1': hashlib.sha1(rom).hexdigest(),
        'alchemy_commit': commit, 'unicorn_version': unicorn.__version__,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'source_sha256': {name: sha((ROOT / name).read_bytes()) for name in sources},
        'protocol': {'decoder_copy_address': hex(CODE), 'decoder_dma_bytes': 0x1e4,
                     'reserved_decoder_bytes': 0x2c4, 'startup_iwram_copy_rom': ['0x770', '0x1b70'],
                     'startup_iwram_destination': '0x03000000',
                     'heap_hooks': ['Func_4938', 'Func_2df0'],
                     'unaligned_ldm_hooks': ['decoder+0x10', 'decoder+0x70', 'decoder+0xc0'],
                     'ldm_rule_source': 'https://github.com/mgba-emu/mgba/blob/master/src/gba/memory.c#L1424-L1502',
                     'compositor_stop_before_outline_and_upload': '0x0800af12',
                     'instruction_limit_per_call': 250000, 'fill_byte': 3,
                     'layer_count': 1, 'initial_timer': 0, 'initial_frame': 255,
                     'flags': 0, 'priority': 0},
        'sprite': {'id': 0, 'width': 32, 'height': 32, 'direction_kind': 5,
                   'codec': 3, 'animation_count': 38, 'animation_index': 0,
                   'metadata': '0x08185024', 'frames_table': hex(frames),
                   'scripts_table': hex(scripts), 'script_pointer': hex(script)},
        'modes': modes, 'synthetic_native_model_comparisons': probe_count,
        'cache_sequence': cache_checks, 'frames': frame_results,
        'animation_timeline': timeline, 'compressed_codec3_control': compressed_control,
        'native_compositor_cases': composition,
        'limits': ['Isolated Unicorn execution, no full game, BIOS or GBA bus timing',
                   'Unaligned LDM at three decoder sites uses explicit mGBA-compatible shim',
                   'Synthetic object and one layer, supplied heap and preloaded decoder slot',
                   'Compositor stops before outline, upload, OAM and screen display',
                   'Animation 0 frames 0..4 and hold; frame 5 only as separate compressed-codec control',
                   'No full Alchemy build or binary matching',
                   'No Ghidra opened or mutated; runtime addresses are harness choices'],
    }
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'verified': True, 'synthetic_cases': probe_count,
                      'frame_count': len(frame_results), 'compositor_cases': len(composition),
                      'output': str(output)}))


if __name__ == '__main__':
    main()
