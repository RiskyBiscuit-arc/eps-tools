# place stock user.bin in /rwd-xray/tools and run 'python3 eps_tool.py'

import os
import sys
import subprocess
import struct
import hashlib
import binascii
import argparse

default_decrypt_lookup_table = {144: 72, 218: 55, 255: 255, 164: 1, 195: 26, 99: 2, 28: 178, 205: 158, 125: 138, 45: 118, 222: 98, 142: 78, 62: 58, 243: 38, 163: 18, 83: 254, 3: 234, 172: 214, 92: 194, 12: 174, 189: 154, 109: 134, 29: 114, 206: 94, 126: 74, 46: 54, 227: 34, 147: 14, 113: 0, 67: 250, 236: 230, 156: 210, 76: 190, 252: 170, 173: 150, 93: 130, 13: 110, 148: 253, 120: 159, 199: 148, 198: 137, 77: 126, 23: 104, 73: 83, 203: 73, 78: 62, 123: 53, 254: 42, 43: 33, 90: 23, 161: 12, 10: 3, 132: 249, 191: 239, 226: 220, 197: 201, 248: 191, 117: 181, 34: 172, 37: 161, 88: 151, 141: 142, 8: 131, 134: 121, 185: 111, 54: 101, 190: 90, 57: 79, 128: 68, 139: 57, 14: 46, 138: 35, 131: 10, 100: 241, 1: 228, 146: 200, 133: 185, 168: 171, 104: 155, 40: 139, 251: 85, 94: 66, 91: 45, 103: 124, 55: 112, 231: 156, 80: 56, 224: 92, 102: 113, 96: 60, 98: 188, 97: 252, 140: 206, 122: 31, 232: 187, 16: 40, 202: 51, 26: 7, 239: 251, 5: 153, 219: 77, 119: 128, 21: 157, 238: 102, 180: 5, 217: 119, 30: 50, 7: 100, 32: 44, 183: 144, 50: 176, 110: 70, 157: 146, 2: 164, 44: 182, 145: 8, 58: 15, 27: 29, 64: 52, 9: 67, 31: 199, 179: 22, 42: 11, 193: 20, 211: 30, 129: 4, 241: 32, 74: 19, 178: 208, 247: 160, 112: 64, 242: 224, 114: 192, 165: 193, 0: 36, 59: 37, 196: 9, 154: 39, 75: 41, 72: 147, 249: 127, 162: 204, 130: 196, 229: 209, 182: 133, 48: 48, 86: 109, 240: 96, 137: 99, 151: 136, 209: 24, 108: 198, 181: 197, 212: 13, 244: 21, 11: 25, 118: 117, 228: 17, 214: 141, 52: 229, 160: 76, 115: 6, 106: 27, 56: 143, 25: 71, 36: 225, 194: 212, 208: 88, 187: 69, 171: 65, 153: 103, 38: 97, 207: 243, 82: 184, 184: 175, 188: 218, 213: 205, 121: 95, 15: 195, 81: 248, 24: 135, 70: 105, 150: 125, 174: 86, 158: 82, 220: 226, 201: 115, 71: 116, 51: 246, 177: 16, 176: 80, 22: 93, 39: 108, 159: 231, 223: 247, 186: 47, 169: 107, 245: 213, 235: 81, 192: 84, 124: 202, 175: 235, 84: 237, 79: 211, 234: 59, 143: 227, 237: 166, 33: 236, 253: 106, 65: 244, 111: 219, 200: 179, 101: 177, 17: 232, 20: 221, 166: 129, 60: 186, 61: 122, 167: 140, 204: 222, 87: 120, 41: 75, 135: 132, 136: 163, 49: 240, 250: 63, 107: 49, 170: 43, 18: 168, 221: 162, 35: 242, 225: 28, 149: 189, 85: 173, 152: 167, 95: 215, 53: 165, 89: 87, 66: 180, 6: 89, 47: 203, 210: 216, 215: 152, 233: 123, 116: 245, 127: 223, 19: 238, 69: 169, 105: 91, 4: 217, 216: 183, 68: 233, 63: 207, 155: 61, 246: 149, 230: 145}

parser = argparse.ArgumentParser()
parser.add_argument("-stock", action="store_true")
args = parser.parse_args()

def param_to_data_string(param):
    # strip leading '0x'
    param = param.replace('0x','')
    param = param.replace(', ','')
    # pad to even number of characters (required by binascii)
    if len(param) % 2 == 1:
        param = '0' + param
    return binascii.a2b_hex(param)

def u16be(data, address):
    return struct.unpack('>H', data[address:address + 2])[0]

def words_string(data, address, count=1):
    """Return one or more big-endian firmware words in patch-list syntax."""
    return ', '.join(
        '0x{:04x}'.format(u16be(data, address + index * 2))
        for index in range(count)
    )


# --- controller-field guardrails -------------------------------------------
#
# Neither of these checks is theoretical. A single wrong MOVI20 immediate
# nibble (0x90 instead of 0x10 at Clarity 0x2A437) sent JSR @R1 into unmapped
# flash and bricked an EPS; recovery needed a reflash of 0x4000-0x4FFFF.
#
# The feedback normalization constant is the low half of a 32-bit
#
#     MOVI20 #imm20, Rn  =  0000 nnnn iiii 0000 / imm[15:0]
#
# instruction, where nnnn is the destination register and iiii is imm[19:16].
# The instruction is followed immediately by MULR R0,R6, which hardcodes R0.
#
# We therefore only ever patch imm[15:0] -- word1, two bytes. Word0 is never
# written, so nnnn and iiii cannot be corrupted by a typo, and a patch applied
# at the wrong width cannot run off the end of the instruction into MULR.
# Under the "lower the normalization only, never raise it" rule every legal
# value is below 65536, so word0 never needs to change.
MOVI20_LO = 'movi20_lo'  # low word of a 32-bit MOVI20; word0 must stay intact
SIGNED_WORD = 's16'      # 16-bit signed constant loaded with MOV.W


def check_controller_guards(fw, guards, phase):
    """Validate controller fields before and after patching.

    `phase` is only used to make an assertion message say whether the problem
    was already present in the input or was introduced by this run.
    """
    for guard in guards:
        offset = guard['offset']
        label = guard['label']
        value = u16be(fw, offset)
        low, high = guard['bounds']
        assert low <= value <= high, \
            '{}: {} at {} is {}, outside the allowed range {}..{}'.format(
                phase, label, hex(offset), value, low, high)

        if guard['kind'] == MOVI20_LO:
            word0_offset = offset - 2
            word0 = u16be(fw, word0_offset)
            assert (word0 >> 12) == 0 and (word0 & 0xF) == 0, \
                '{}: {} at {} is not preceded by a MOVI20 word0 ' \
                '(found {:#06x} at {})'.format(
                    phase, label, hex(offset), word0, hex(word0_offset))
            assert ((word0 >> 8) & 0xF) == guard['rn'], \
                '{}: {} MOVI20 destination register changed to R{} ' \
                '(expected R{}) at {}'.format(
                    phase, label, (word0 >> 8) & 0xF, guard['rn'],
                    hex(word0_offset))
            assert ((word0 >> 4) & 0xF) == 0, \
                '{}: {} MOVI20 imm[19:16] is {:#x}, expected 0 at {}'.format(
                    phase, label, (word0 >> 4) & 0xF, hex(word0_offset))

        # Instructions that must be untouched on either side of the field.
        # These catch an offset that is right by value but wrong by position.
        for delta, expected in guard.get('neighbors', ()):
            neighbor_offset = offset + delta
            actual = u16be(fw, neighbor_offset)
            assert actual == expected, \
                '{}: {} neighbour check failed at {}: expected {:#06x} ' \
                'but found {:#06x}'.format(
                    phase, label, hex(neighbor_offset), expected, actual)


def check_curve_slopes(fw, checks, phase):
    """Validate interpolated curves whose slopes the ECU precomputes in Q26.

    Each check is (x_offset, y_offset, points, label). Breakpoints must rise
    strictly, and every segment must satisfy |dY| <= 31*dX so that
    (dY << 26) / dX stays inside a signed 32-bit slope word.
    """
    for x_offset, y_offset, points, label in checks:
        xs = [struct.unpack('>h', fw[x_offset + 2 * i:x_offset + 2 * i + 2])[0]
              for i in range(points)]
        ys = [struct.unpack('>h', fw[y_offset + 2 * i:y_offset + 2 * i + 2])[0]
              for i in range(points)]
        for i in range(points - 1):
            dx = xs[i + 1] - xs[i]
            dy = ys[i + 1] - ys[i]
            assert dx > 0, \
                '{}: {} breakpoints not increasing at point {} ({} -> {})'.format(
                    phase, label, i, xs[i], xs[i + 1])
            assert abs(dy) <= 31 * dx, \
                '{}: {} segment {} slope too steep: dY {} over dX {} ' \
                '(limit {})'.format(phase, label, i, dy, dx, 31 * dx)

def apply_shadow_mirrors(fw, input_fw, mirrors):
    """Copy primary tables onto shadow copies that stock keeps identical.

    Each mirror is (primary_offset, shadow_offset, size, label). The shadow
    must equal the primary in the input bin, so a wrong offset is caught
    instead of overwriting unrelated bytes.
    """
    for primary, shadow, size, label in mirrors:
        assert input_fw[primary:primary + size] == input_fw[shadow:shadow + size], \
            'input bin: {} shadow at {} does not match primary at {}'.format(
                label, hex(shadow), hex(primary))
        if fw[shadow:shadow + size] != fw[primary:primary + size]:
            fw[shadow:shadow + size] = fw[primary:primary + size]
            print('Mirror {} from {} to shadow {}'.format(
                label, hex(primary), hex(shadow)))


def _crc32_bzip2_table():
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        table.append(c)
    return table


_CRC32_BZIP2_TABLE = _crc32_bzip2_table()


def crc32_bzip2(data):
    """CRC-32/BZIP2: MSB-first poly 0x04C11DB7, init and final xor 0xFFFFFFFF."""
    c = 0xFFFFFFFF
    for b in data:
        c = ((c << 8) & 0xFFFFFFFF) ^ _CRC32_BZIP2_TABLE[((c >> 24) ^ b) & 0xFF]
    return c ^ 0xFFFFFFFF


# Runtime ROM CRC regions of the THR-A020 family (THR FUN_0000E226, RUNNING_LOG
# 2026-10-04; TJB-A220 region table 0xF578/0xF580, CRC table 0xF070). The EPS
# sweeps each region 32 bytes per pass while running and compares the CRC with
# the big-endian word at the slot. A mismatch latches an EPS fault a second or
# two after start, which is what the first RDX PTM did (2026-10-15). These are
# separate from, and must be computed before, the 0x7FF80/0x7FFFE words.
THR_FAMILY_ROM_CRC_REGIONS = [
    (0x40000, 0x4ff60, 0x4ff7c),
    (0x60000, 0x6ff60, 0x6ff7c),
]


def apply_rom_crcs(fw, input_fw, regions):
    """Recompute runtime ROM CRC words in full-image offsets.

    Each region is (start, end, slot). The stock input must reproduce its
    stored word first, so a wrong region or slot is caught instead of written.
    """
    for start, end, slot in regions:
        stored = struct.unpack('>I', bytes(input_fw[slot:slot + 4]))[0]
        assert crc32_bzip2(input_fw[start:end]) == stored, \
            'input bin: ROM CRC [{},{}) does not reproduce stored {:08x} at {}'.format(
                hex(start), hex(end), stored, hex(slot))
        new = crc32_bzip2(bytes(fw[start:end]))
        if new != stored:
            struct.pack_into('>I', fw, slot, new)
            print('Update ROM CRC [{},{}) at offset {} from {:08x} to {:08x}'.format(
                hex(start), hex(end), hex(slot), stored, new))


FEEDFORWARD_HOOK_OLD = bytes.fromhex('061a 4611 8d03')
FEEDFORWARD_AFTER_HOOK = bytes.fromhex(
    '6203 e4ff 644c 364c e5f8 465c 01f0 8001'
)
FEEDFORWARD_SITES = {
    '39990-TBA-A030': {
        'hook': 0x297d6, 'resume': 0x297e4,
        'cave': 0x4f1cc, 'erased_end': 0x4ff80, 'image_size': 0x60000,
    },
    '39990-TEG-A010': {
        'hook': 0x29676, 'resume': 0x29684,
        'cave': 0x4f1cc, 'erased_end': 0x4ff80, 'image_size': 0x60000,
    },
    # Ghidra TXM-A040 trace: at 0x418CC, R0 is the returned P+D term,
    # R8 is the callee-preserved steering reference, and MACL is the existing
    # scale product. 0x6F900 begins an unreferenced erased run ending before
    # the large-flash checksum word at 0x6FF80.
    '39990-TXM-A040': {
        'hook': 0x418cc, 'resume': 0x418da,
        'cave': 0x6f900, 'erased_end': 0x6ff80, 'image_size': 0x70000,
    },
    # TGG-A120 stock trace: the final P+D wrapper has the same displaced
    # sequence and R0/R8/MACL contract as the verified A030/TEG sites.
    # 0x4F1CC..0x4FF7F is an unreferenced erased run in the 0x50000 image;
    # 0x4FF80 is the first Honda checksum word.
    '39990-TGG-A120': {
        'hook': 0x29886, 'resume': 0x29894,
        'cave': 0x4f1cc, 'erased_end': 0x4ff80, 'image_size': 0x50000,
    },
    # C120 controller code and the FF insertion window are byte-identical to
    # the verified C020 path. The erased run ends at 0x4D000; the later image
    # region is populated and must not be treated as cave space.
    '39990-TBA-C120': {
        'hook': 0x29006, 'resume': 0x29014,
        'cave': 0x4c3c4, 'erased_end': 0x4d000, 'image_size': 0x50000,
    },
    # TLA-A220: the caller 0x415FA is the A040 function (0x41A42) shifted
    # -0x448, literal pools only; same R0/R8/MACL contract. After resume,
    # R1/R7/R0 are rewritten before use, MACL and PR are restored from the
    # stack in the epilogue. 0x6EB78..0x6FF7F is erased; the last code is a
    # literal pool ending at 0x6EB77. Cave starts 8 bytes later; its 70-byte
    # window is clear of every (unaligned, coincidental) 32-bit match the
    # checker scans for, the nearest being 0x6ED36. Both accepted inputs.
    '39990-TLA-A220': {
        'hook': 0x41650, 'resume': 0x4165e,
        'cave': 0x6eb80, 'erased_end': 0x6ff80, 'image_size': (0x80000, 0x70000),
    },
}


def _sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _movi20(register, value):
    assert 0 <= register <= 15
    assert 0 <= value <= 0xfffff
    word0 = (register << 8) | (((value >> 16) & 0xf) << 4)
    return struct.pack('>HH', word0, value & 0xffff)


def _feedforward_cave_code(kff, resume):
    assert 1 <= kff <= 127, 'KFF must fit positive signed MOV #imm8'
    code = bytes([
        0x06, 0x1a,              # STS MACL,R6
        0x46, 0x11,              # CMP/PZ R6
        0x8d, 0x03,              # BT/S +3
        0x00, 0x09,              # delay NOP
        0xe1, 0xff,              # MOV #-1,R1
        0x61, 0x1c,              # EXTU.B R1,R1
        0x36, 0x1c,              # ADD R1,R6
        0xe1, kff,               # MOV #KFF,R1
        0x28, 0x1f,              # MULS.W R1,R8
        0x01, 0x1a,              # STS MACL,R1
        0xe2, 0xf6,              # MOV #-10,R2
        0x41, 0x2c,              # SHAD R2,R1
        0x30, 0x1c,              # ADD R1,R0
        0x01, 0xf0, 0x80, 0x01,  # MOVI20 #-32767,R1
        0x30, 0x13,              # CMP/GE R1,R0
        0x8d, 0x03,              # BT/S low-side okay
        0x62, 0x03,              # delay MOV R0,R2
        0x60, 0x13,              # MOV R1,R0
        0xa0, 0x07,              # BRA clamp-done
        0x62, 0x13,              # delay MOV R1,R2
        0x01, 0x00, 0x7f, 0xff,  # MOVI20 #32767,R1
        0x30, 0x17,              # CMP/GT R1,R0
        0x8f, 0x02,              # BF/S high-side okay
        0x00, 0x09,              # delay NOP
        0x60, 0x13,              # MOV R1,R0
        0x62, 0x13,              # MOV R1,R2
    ]) + _movi20(1, resume) + bytes.fromhex(
        '412a 0009 0009 000b 0009'  # LDS R1,PR; bubbles; RTS; delay NOP
    )
    assert len(code) == 70
    return code


def _verify_feedforward_cave_unreferenced(fw, cave_start, cave_end):

    for offset in range(len(fw) - 3):
        value = struct.unpack_from('>I', fw, offset)[0]
        assert not cave_start <= value < cave_end, \
            '32-bit pointer into FF cave at {}'.format(hex(offset))

    for pc in range(0, len(fw) - 1, 2):
        word = u16be(fw, pc)
        opcode = word >> 12
        target = None
        kind = None
        if opcode in (0xa, 0xb):
            target = pc + 4 + 2 * _sign_extend(word & 0xfff, 12)
            kind = 'BRA/BSR'
        elif (word >> 8) in (0x89, 0x8b, 0x8d, 0x8f):
            target = pc + 4 + 2 * _sign_extend(word & 0xff, 8)
            kind = 'conditional branch'
        elif opcode == 0x9:
            target = pc + 4 + 2 * (word & 0xff)
            kind = 'PC-relative MOV.W'
        elif opcode == 0xd or (word >> 8) == 0xc7:
            target = ((pc + 4) & ~3) + 4 * (word & 0xff)
            kind = 'PC-relative MOV.L/MOVA'
        if target is not None:
            assert not cave_start <= target < cave_end, \
                '{} target into FF cave at {}'.format(kind, hex(pc))

        if pc + 3 < len(fw):
            word1 = u16be(fw, pc + 2)
            if (word & 0xf00f) == 0:
                immediate = (((word >> 4) & 0xf) << 16) | word1
                assert not cave_start <= immediate < cave_end, \
                    'MOVI20 immediate into FF cave at {}'.format(hex(pc))


def apply_feedforward_patch(fw, stock_fw, car_model, kff):
    assert car_model in FEEDFORWARD_SITES, \
        'feedforward is not verified for {}'.format(car_model)
    site = FEEDFORWARD_SITES[car_model]
    hook = site['hook']
    resume = site['resume']
    cave = site['cave']
    cave_end = cave + 70
    erased_end = site['erased_end']
    image_sizes = site['image_size'] if isinstance(site['image_size'], tuple) \
        else (site['image_size'],)
    assert len(fw) == len(stock_fw) and len(fw) in image_sizes, \
        '{} FF hook is verified only for a {}-byte image'.format(
            car_model, site['image_size'])
    assert 0x4000 <= cave < cave_end <= erased_end <= len(fw)
    cave_code = _feedforward_cave_code(kff, resume)
    hook_new = _movi20(7, cave) + bytes.fromhex('470b')
    assert len(hook_new) == 6
    assert cave_code[14:16] == bytes([0xe1, kff])

    assert stock_fw[hook:hook + 6] == FEEDFORWARD_HOOK_OLD
    assert stock_fw[hook + 6:hook + 6 + len(FEEDFORWARD_AFTER_HOOK)] == \
        FEEDFORWARD_AFTER_HOOK
    assert stock_fw[cave:erased_end] == \
        bytes([0xff]) * (erased_end - cave)
    _verify_feedforward_cave_unreferenced(stock_fw, cave, cave_end)

    assert fw[hook:hook + 6] == FEEDFORWARD_HOOK_OLD
    assert fw[cave:cave_end] == bytes([0xff]) * 70
    fw[hook:hook + 6] = hook_new
    fw[cave:cave_end] = cave_code

    assert fw[hook:hook + 6] == hook_new
    assert fw[hook + 6:hook + 6 + len(FEEDFORWARD_AFTER_HOOK)] == \
        FEEDFORWARD_AFTER_HOOK
    assert fw[cave:cave_end] == cave_code
    assert cave_code[-14:-10] == _movi20(1, resume)
    return cave_code


def generate_file_header(indicator, headers):
    header_bytes = indicator
    for header in headers:
        header_bytes += chr(len(header))
        for item in header:
            header_bytes += chr(len(item.encode())) + str(item)
    return header_bytes

def checksum_by_sum(fw, start, end):
  s = 0
  for i in range(start, end - start, 2):
    s += struct.unpack('!H', fw[i:i + 2])[0]
  return s

# sum of -x, x is unsigned shorts
def checksum_by_negative_sum(fw, start, end):
  s = 0
  for i in range(start, end - start, 2):
    s += -struct.unpack('!H', fw[i:i + 2])[0]
  return s

checksum_funcs = [checksum_by_sum, checksum_by_negative_sum]

def main():
    hash_md5 = hashlib.md5()
    with open(os.path.join(sys.path[0], "user.bin"), "rb+") as f:
        input_bin = f.read()
        fw_bytes = f
        start_address = 0x4000
        if len(input_bin) == 0x50000:
            data_size = 0x4c000
            checksum_offsets = [(0, 0x4bf80), (1, 0x4bffe)]  # 0x4FF80/0x4FFFE minus 0x4000
        elif len(input_bin) == 393216:  # 0x60000
            data_size = 0x4c000
            checksum_offsets = [(0, 0x4bf80), (1, 0x4bffe)]
        elif len(input_bin) == 458752:  # 0x70000 RWD image
            data_size = 0x6c000
            checksum_offsets = [(0, 0x6bf80), (1, 0x6bffe)]
        elif len(input_bin) == 524288:  # 0x80000 hardware dump
            # Two different layouts share this size, so disambiguate on the
            # 48 37 FF FF payload magic rather than on length alone:
            #   TLA-A040 / TJB-A030 : magic at 0x4000, payload 0x4000..0x70000
            #   THR-A020 (Odyssey)  : magic at 0xC000, payload 0xC000..0x80000
            #   TJB-A220 (RDX)      : THR geometry; stock DA88/9364 reproduce
            magic = input_bin.find(b'\x48\x37\xff\xff')
            if magic == 0xc000:
                # 39990-THR-A020 (2018 Odyssey). Boot area is 0xC000, NOT 0x4000.
                # Both stored checksums were solved for empirically; 0xC000 is
                # the unique valid flash-aligned start satisfying either one
                # (an arbitrary word-aligned scan also has an accidental
                # second mathematical match at 0x1F12A):
                #   sum  over [0xC000,0x7FF80) == 0xD0CA (stored at 0x7FF80)
                #   -sum over [0xC000,0x7FFFE) == 0xA6E0 (stored at 0x7FFFE)
                #
                # CONFIRMED 2026-09-20 against Honda's own rwds, not inferred.
                # ~/Downloads/cal/ holds 68 stock 39990-* EPS rwds. Three of them
                # -- 39990-T5R-A030-M1, 39990-T7T-M020-M1, 39990-T7W-A020-M1 --
                # declare exactly this geometry in their own headers:
                #     key = 01 02 03, start = 0xC000, data_size = 0x74000
                # so these are not our numbers, they are Honda's, for this flash
                # class. Decrypting those payloads with default_decrypt_lookup_table
                # yields the 48 37 FF FF app magic, 14 readable "39990-XXX-YYYY"
                # part strings, and 0x2000 bytes BYTE-FOR-BYTE IDENTICAL to this
                # Odyssey full-flash dump at 0xC000 (first divergence 0xE000).
                # An 8192-byte exact match cannot arise from a wrong substitution.
                #
                # Negative control, same geometry, different cipher: 39990-THX-A130
                # also declares start 0xC000 / size 0x74000 but carries key BF 10 9E.
                # Under this table it decodes to garbage -- 0 part strings, 0 erased
                # bytes (impossible for real flash), and 0.00% identity at 0xC000.
                # So geometry alone does NOT imply the cipher; the header key does,
                # and 01 02 03 is the SH2A-family key this table belongs to.
                start_address = 0xc000
                data_size = 0x74000
                checksum_offsets = [(0, 0x73f80), (1, 0x73ffe)]  # 0x7FF80/0x7FFFE minus 0xC000
            else:
                data_size = 0x6c000
                checksum_offsets = [(0, 0x6bf80), (1, 0x6bffe)]
        else:
            print(f"unsupported fw length: {len(input_bin)} bytes (0x{len(input_bin):x})")
            sys.exit()
        input_bin_hash = hashlib.md5(input_bin).hexdigest()
        # Populated by the branches that expose closed-loop controller fields.
        controller_guards = []
        # Optional per-model curve and shadow-table checks (THR-A020 only so far).
        curve_checks = []
        shadow_mirrors = []
        # Runtime ROM CRCs (full-image offsets), recomputed before the checksums.
        rom_crc_regions = []
        feedforward_kff = None
        if input_bin_hash == '79b695a73fd5ff22cbfeb4b83908ab29': #CR-V thanks to joe1
            print('Detected bin: 39990-TLA-A040 Honda CR-V')
            supported_versions = ['39990-TLA-A030\x00\x00', '39990-TLA-A040\x00\x00', '39990-TLA,A040\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0xf8db, 0xf936, 0xf991, 0xf9ec, 0xfa47, 0xfaa2, 0xfafd, 0xfb58, 0xfbb3, 0xfc0e, 0xfc69, 0xfcc4]
            version_old = b'39990-TLA-A040'
            version_new = b'39990-TLA,A040'
            data_offsets = [
                0x11908, #speed_clamp_lo

                0x11b5e, #torque_table row 1
                0x11b70, #torque_table row 2
                0x11b82, #torque_table row 3
                0x11b94, #torque_table row 4
                0x11ba6, #torque_table row 5
                0x11bb8, #torque_table row 6
                0x11bca, #torque_table row 7

                0x11db0, #filter_table row 1

                0x11eac, #new_table row 1

                0x119ae, #speed_table row 1
                ]
            data_old = [
                '0x0028', #speed_clamp_lo

                '0x0000, 0x0500, 0x0a15, 0x0e6d, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', # original torque_table row 1
                '0x0000, 0x0500, 0x0a15, 0x0e6d, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', # original torque_table row 2
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 3
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 4
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 5
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 6
                '0x0000, 0x06e1, 0x0c9a, 0x1000, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', # original torque_table row 7

                '0x009f, 0x0100, 0x0180, 0x01e6, 0x01e6, 0x01e6, 0x01e6, 0x01e6, 0x01e6', #filter_table row 1

                '0x0021, 0x004d, 0x0096, 0x00c0, 0x00cb, 0x00cd, 0x00cd, 0x00cd, 0x00cd', #new_table row 1

                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 1
                ]
            data_new = [
                '0x0000', #speed_clamp_lo

                '0x0000, 0x0500, 0x0A15, 0x0E6D, 0x1100, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 1
                '0x0000, 0x0500, 0x0A15, 0x0E6D, 0x1100, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 2
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 3
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 4
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 5
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 6
                '0x0000, 0x06E1, 0x0C9A, 0x1000, 0x1100, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 7

                '0x009f, 0x0100, 0x0180, 0x01e6, 0x01e6, 0x01e6, 0x0200, 0x0200, 0x0200', # filter_table row 1

                '0x0021, 0x004d, 0x0096, 0x00c0, 0x00cb, 0x00cd, 0x00cd, 0x00cd, 0x00cd', #new_table row 1

                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 1
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',

                'new_table row 1',

                'speed_table row 1'
                ]
            
        elif input_bin_hash == '0c21cdf567d6a5a5faaf4512af1029f0': #CR-V thanks to martin146, cfranhonda
            print('Detected bin: 39990-TPA-G030 Honda CR-V')
            supported_versions = ['39990-TPA-G010\x00\x00', '39990-TPA-G030\x00\x00', '39990-TPA,G030\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0xecdf, 0xed3a, 0xed95, 0xedf0, 0xee4b]
            version_old = b'39990-TPA-G030'
            version_new = b'39990-TPA,G030'
            data_offsets = [
                0x11908, #speed_clamp_lo

                0x11b5e, #torque_table row 1
                0x11b70, #torque_table row 2
                0x11b82, #torque_table row 3
                0x11b94, #torque_table row 4
                0x11ba6, #torque_table row 5
                0x11bb8, #torque_table row 6
                0x11bca, #torque_table row 7

                0x11dd4, #filter_table row 1

                0x11eac, #new_table row 1

                0x119ae, #speed_table row 1
                ]
            data_old = [
                '0x000a', #speed_clamp_lo

                '0x0000, 0x00B5, 0x0161, 0x02d6, 0x04C0, 0x0B83, 0x1169, 0x1500, 0x1600', # original torque_table row 1
                '0x0000, 0x00D4, 0x015A, 0x0233, 0x04C0, 0x0A85, 0x1100, 0x1500, 0x1600', # original torque_table row 2
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 3
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 4
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 5
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 6
                '0x0000, 0x06E1, 0x0C9A, 0x1000, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', # original torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', #filter_table row 1

                '0x002c, 0x009a, 0x00c0, 0x00c0, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd', #new_table row 1

                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x0532, 0x0532, 0x0532', #speed_table row 1
                ]
            data_new = [
                '0x0001', #speed_clamp_lo

                '0x0000, 0x00B5, 0x0161, 0x02D6, 0x04C0, 0x0B83, 0x0FA3, 0x161B, 0x2C00', # new torque_table row 1
                '0x0000, 0x00D4, 0x015A, 0x0233, 0x04C0, 0x0A85, 0x0E4A, 0x1596, 0x2C00', # new torque_table row 2
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1873, 0x183D, 0x29E8', # new torque_table row 3
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1873, 0x183D, 0x29E8', # new torque_table row 4
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1873, 0x183D, 0x29E8', # new torque_table row 5
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1873, 0x183D, 0x29E8', # new torque_table row 6
                '0x0000, 0x06E1, 0x0C9A, 0x1000, 0x1100, 0x1200, 0x129A, 0x134D, 0x2871', # new torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0200, 0x0200, 0x0200', # filter_table row 1

                '0x002c, 0x009a, 0x00c0, 0x00c0, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd', #new_table row 1

                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x0532, 0x0532, 0x0532', #speed_table row 1
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',

                'new_table row 1',

                'speed_table row 1'
                ]
            
        elif input_bin_hash == '9ccedbdd7d4d8d0eb356fadcc763353d':
            print('Detected bin: 39990-TBA-A030 Honda Civic Sedan')
            car_model = '39990-TBA-A030'  #civic sedan thanks to mystery leaker
            supported_versions = ['39990-TBA-A010\x00\x00', '39990-TBA-A030\x00\x00', '39990-TBA,A030\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b42d, 0x4b486, 0x4b4df, 0x4b538, 0x4b591, 0x4b5ea, 0x4b643, 0x4b69c, 0x4b6f5, 0x4b74e, 0x4b7a7]
            version_old = b'39990-TBA-A030'
            version_new = b'39990-TBA,A030'
            data_offsets = [
                0x13544, #speed_clamp_lo

                0x1379a, #torque_table row 1
                0x137ac, #torque_table row 2
                0x137be, #torque_table row 3
                0x137d0, #torque_table row 4
                0x137e2, #torque_table row 5
                0x137f4, #torque_table row 6
                0x13806, #torque_table row 7

                0x139ec, #filter_table row 1
                0x139fe, #filter_table row 2
                0x13a10, #filter_table row 3
                0x13a22, #filter_table row 4
                0x13a34, #filter_table row 5
                0x13a46, #filter_table row 6
                0x13a58, #filter_table row 7
                ]
            data_old = [
                '0x0028', #speed_clamp_lo

                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 1
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 2
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 3
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 4
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 5
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 6
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', # torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_new = [
                '0x0000',

                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 1
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 2
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 3
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 4
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 5
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x16C4, 0x1D3C, 0x2A2C', # new torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 7
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                'filter_table row 2',
                'filter_table row 3',
                'filter_table row 4',
                'filter_table row 5',
                'filter_table row 6',
                'filter_table row 7',
                ]
        elif input_bin_hash == 'a062d1b894ef57efc2f54c392f47d9f0':
            print('Detected bin: 39990-TBA-C120 Honda Civic Sedan 2019')
            car_model = '39990-TBA-C120'  #civic sedan thanks doktor h0e tony81 cfranhonda
            supported_versions = ['39990-TBA-C110\x00\x00', '39990-TBA-C120\x00\x00', '39990-TBA,C120\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b14d, 0x4b1a6, 0x4b1ff, 0x4b258, 0x4b2b1, 0x4b30a, 0x4b363, 0x4b3bc, 0x4b415, 0x4b46e, 0x4b4c7, 0x4b520]
            version_old = b'39990-TBA-C120'
            version_new = b'39990-TBA,C120'
            data_offsets = [
                0x1361c, #speed_clamp_lo

                0x13872, #torque_table row 1
                0x13884, #torque_table row 2
                0x13896, #torque_table row 3
                0x138a8, #torque_table row 4
                0x138ba, #torque_table row 5
                0x138cc, #torque_table row 6
                0x138de, #torque_table row 7

                0x13ac4, #filter_table row 1
                0x13ad6, #filter_table row 2
                0x13ae8, #filter_table row 3
                0x13afa, #filter_table row 4
                0x13b0c, #filter_table row 5
                0x13b1e, #filter_table row 6
                0x13b30, #filter_table row 7
                ]
            data_old = [
                '0x000a', #speed_clamp_lo

                '0x0000, 0x0500, 0x0980, 0x0D80, 0x0FCD, 0x1180, 0x1200, 0x1200, 0x1200', # torque_table row 1
                '0x0000, 0x034D, 0x07CD, 0x0C00, 0x0F00, 0x1080, 0x1200, 0x1200, 0x1200', # torque_table row 2
                '0x0000, 0x034D, 0x07CD, 0x0C00, 0x0ECC, 0x1066, 0x1200, 0x1200, 0x1200', # torque_table row 3
                '0x0000, 0x0400, 0x0680, 0x0980, 0x0CD5, 0x1000, 0x1200, 0x1200, 0x1200', # torque_table row 4
                '0x0000, 0x039A, 0x0726, 0x0AEF, 0x0E9A, 0x10E6, 0x1200, 0x1200, 0x1200', # torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x119A, 0x11DA, 0x11DA', # torque_table row 7

                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 1
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 2
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 3
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 4
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 5
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_new = [
                '0x0001',

                '0x0000, 0x0500, 0x0980, 0x0D80, 0x0FCD, 0x1180, 0x1200, 0x1F80, 0x2D00', # new torque_table row 1
                '0x0000, 0x034D, 0x07CD, 0x0C00, 0x0F00, 0x1080, 0x1200, 0x1F80, 0x2D00', # new torque_table row 2
                '0x0000, 0x034D, 0x07CD, 0x0C00, 0x0ECC, 0x1066, 0x1200, 0x1F80, 0x2D00', # new torque_table row 3
                '0x0000, 0x0400, 0x0680, 0x0980, 0x0CD5, 0x1000, 0x1200, 0x1F80, 0x2D00', # new torque_table row 4
                '0x0000, 0x039A, 0x0726, 0x0AEF, 0x0E9A, 0x10E6, 0x1200, 0x1F80, 0x2D00', # new torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x19BE, 0x232F, 0x2CA1', # new torque_table row 7

                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 1
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 2
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 3
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 4
                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 5
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                'filter_table row 2',
                'filter_table row 3',
                'filter_table row 4',
                'filter_table row 5',
                'filter_table row 6',
                'filter_table row 7',
                ]
        elif input_bin_hash == '23d29fe18a086299a7ca7168e2f32bb6':
            print('Detected bin: 39990-TBA-C020 Honda Civic Sedan Sport 2019')
            car_model = '39990-TBA-C020'  #civic sedan sport thanks to whiskytango_gaming cfranhonda tony81
            supported_versions = ['39990-TBA-C010\x00\x00', '39990-TBA-C020\x00\x00', '39990-TBA,C020\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b14d, 0x4b1a6, 0x4b1ff, 0x4b258, 0x4b2b1, 0x4b30a, 0x4b363, 0x4b3bc, 0x4b415]
            version_old = b'39990-TBA-C020'
            version_new = b'39990-TBA,C020'
            data_offsets = [
                0x1361c, #speed_clamp_lo

                0x13872, #torque_table row 1
                0x13884, #torque_table row 2
                0x13896, #torque_table row 3
                0x138a8, #torque_table row 4
                0x138ba, #torque_table row 5
                0x138cc, #torque_table row 6
                0x138de, #torque_table row 7

                0x13ac4, #filter_table row 1
                0x13ad6, #filter_table row 2
                0x13ae8, #filter_table row 3
                0x13afa, #filter_table row 4
                0x13b0c, #filter_table row 5
                0x13b1e, #filter_table row 6
                0x13b30, #filter_table row 7
                ]
            data_old = [
                '0x000a', #speed_clamp_lo

                '0x0000, 0x02BA, 0x06BA, 0x0B00, 0x0EB3, 0x10BE, 0x1200, 0x1200, 0x1200', # torque_table row 1
                '0x0000, 0x02CA, 0x065D, 0x0ABA, 0x0DC2, 0x0F80, 0x1033, 0x1033, 0x1033', # torque_table row 2
                '0x0000, 0x0300, 0x0680, 0x0980, 0x0C4D, 0x0E80, 0x0F00, 0x0F80, 0x1033', # torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x119A, 0x11DA, 0x11DA', # torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_new = [
                '0x0001',

                '0x0000, 0x02BA, 0x06BA, 0x0B00, 0x0EB3, 0x10BE, 0x1200, 0x1F80, 0x2D00', # new torque_table row 1
                '0x0000, 0x02CA, 0x065D, 0x0ABA, 0x0DC2, 0x0F80, 0x1033, 0x1F80, 0x2D00', # new torque_table row 2
                '0x0000, 0x0300, 0x0680, 0x0980, 0x0C4D, 0x0E80, 0x0F00, 0x1F80, 0x2D00', # new torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x19BE, 0x232F, 0x2CA1', # new torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 7
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                'filter_table row 2',
                'filter_table row 3',
                'filter_table row 4',
                'filter_table row 5',
                'filter_table row 6',
                'filter_table row 7',
                ]
        elif input_bin_hash == 'ac19028aa235d672cd393a2c5afd93cc':
            print('Detected bin: 39990-TEG-A010 Honda Civic Sedan (Japan)')
            car_model = '39990-TEG-A010'  #civic sedan (Japan) thanks to mystery person DE
            supported_versions = ['39990-TEG-A010\x00\x00', '39990-TEG,A010\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4adc6, 0x4add5, 0x4ae1f, 0x4ae2e, 0x4ae78, 0x4ae87, 0x4aed1, 0x4aee0, 0x4af2a, 0x4af39, 0x4af83, 0x4af92, 0x4afdc, 0x4afeb]
            version_old = b'39990-TEG-A010'
            version_new = b'39990-TEG,A010'
            data_offsets = [
                0x13544, #speed_clamp_lo

                0x1379a, #torque_table row 1
                0x137ac, #torque_table row 2
                0x137be, #torque_table row 3 <--- Touring uses config index 3
                0x137d0, #torque_table row 4
                0x137e2, #torque_table row 5
                0x137f4, #torque_table row 6
                0x13806, #torque_table row 7

                0x139ec, #filter_table row 1
                0x139fe, #filter_table row 2
                0x13a10, #filter_table row 3
                0x13a22, #filter_table row 4
                0x13a34, #filter_table row 5
                0x13a46, #filter_table row 6
                0x13a58, #filter_table row 7
                ]
            data_old = [
                '0x0028', #speed_clamp_lo

                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 1
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 2
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 3
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 4
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 5
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119f, 0x140b, 0x1680, 0x1680, 0x1680', # torque_table row 6
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', # torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_new = [
                '0x0000',

                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 1
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 2
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 3
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 4
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 5
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140B, 0x1680, 0x21C0, 0x3840', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x16C4, 0x1D3C, 0x2A2C', # new torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 7
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                'filter_table row 2',
                'filter_table row 3',
                'filter_table row 4',
                'filter_table row 5',
                'filter_table row 6',
                'filter_table row 7',
                ]
        elif input_bin_hash == 'aafcf594418ba625fa439a0e52ee7d36': #civic hatch au thanks to ming
            print('Detected bin: 39990-TEA-T330 Honda Civic Hatch (Australia)')
            supported_versions = ['39990-TEA-T310\x00\x00', '39990-TEA-T330\x00\x00', '39990-TEA,T330\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b4e1, 0x4b53a, 0x4b593, 0x4b5ec, 0x4b645, 0x4b69e, 0x4b6f7]
            version_old = b'39990-TEA-T330'
            version_new = b'39990-TEA,T330'
            data_offsets = [
                0x135bc, #speed_clamp_lo

                0x13812, #torque_table row 1
                0x13824, #torque_table row 2
                0x13836, #torque_table row 3
                0x13848, #torque_table row 4
                0x1385a, #torque_table row 5
                0x1386c, #torque_table row 6
                0x1387e, #torque_table row 7

                0x13a76, #filter_table row 1
                ]
            data_old = [
                '0x0028', #speed_clamp_lo

                '0x0000, 0x0380, 0x0800, 0x0C00, 0x0EB6, 0x10AE, 0x1200, 0x1200, 0x1200', # original torque_table row 1
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 2
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 6
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', # original torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', #filter_table row 1
                ]
            data_new = [
                '0x0000', #speed_clamp_lo

                '0x0000, 0x0380, 0x0800, 0x0C00, 0x0EB6, 0x10AE, 0x1200, 0x1B00, 0x2D00', # new torque_table row 1
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 2
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x16C4, 0x1D3C, 0x2A2C', # new torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', #filter_table row 1
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                ]
        elif input_bin_hash == '11ba08b27a643c3e3b23bbd08463a40e': #civic hatch thanks to R3DLOBST3R
            print('Detected bin: 39990-TGG-A120 Honda Civic Hatch')
            supported_versions = ['39990-TGG-A110\x00\x00', '39990-TGG-A120\x00\x00', '39990-TGG,A120\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b541, 0x4b59a, 0x4b5f3, 0x4b64c, 0x4b6a5]
            version_old = b'39990-TGG-A120'
            version_new = b'39990-TGG,A120'
            data_offsets = [
                0x135c0, #speed_clamp_lo

                0x13816, #torque_table row 1
                0x13828, #torque_table row 2
                0x1383a, #torque_table row 3
                0x1384c, #torque_table row 4
                0x1385e, #torque_table row 5
                0x13870, #torque_table row 6
                0x13882, #torque_table row 7

                0x13a68, #filter_table row 1
                0x13a7a, #filter_table row 2
                0x13a8c, #filter_table row 3
                0x13a9e, #filter_table row 4
                0x13ab0, #filter_table row 5
                0x13ac2, #filter_table row 6
                0x13ad4, #filter_table row 7
                ]
            data_old = [
                '0x0028', #speed_clamp_lo

                '0x0000, 0x0380, 0x0800, 0x0C00, 0x0EB6, 0x10AE, 0x1200, 0x1200, 0x1200', # original torque_table row 1
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 2
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x119A, 0x11DA, 0x11DA', # original torque_table row 7

                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A', # filter_table row 1
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 2
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 3
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 4
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 5
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_new = [
                '0x0001', #speed_clamp_lo

                '0x0000, 0x0380, 0x0800, 0x0C00, 0x0EB6, 0x10AE, 0x1200, 0x1F80, 0x2D00', # new torque_table row 1
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 2
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x19BE, 0x232F, 0x2CA1', # new torque_table row 7

                '0x00C0, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x011A, 0x0400, 0x0480', # filter_table row 1
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 2
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 3
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 4
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 5
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 6
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 7
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                'filter_table row 2',
                'filter_table row 3',
                'filter_table row 4',
                'filter_table row 5',
                'filter_table row 6',
                'filter_table row 7',
                ]
        elif input_bin_hash == '98f133c5e3b72653e71fee5ea3ef52e8': #civic hatch thanks to CFranHonda , cyptonome
            print('Detected bin: 39990-TGN-E120 Honda Civic Hatch EU')
            supported_versions = ['39990-TGN-E110\x00\x00', '39990-TGN-E120\x00\x00', '39990-TGN,E120\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b4e1, 0x4b53a, 0x4b593, 0x4b5ec, 0x4b645, 0x4b69e, 0x4b6f7, 0x4b750, 0x4b7a9, 0x4b802, 0x4b85b, 0x4b8b4, 0x4b90d, 0x4b966, 0x4b9bf, 0x4ba18, 0x4ba71, 0x4baca, 0x4bb23, 0x4bb7c, 0x4bbd5, 0x4bc2e, 0x4bc87, 0x4bce0, 0x4bd39, 0x4bd92, 0x4bdeb, 0x4be44, 0x4be9d, 0x4bef6, 0x4bf4f, 0x4bfa8, 0x4c001, 0x4c05a, 0x4c0b3, 0x4c10c, 0x4c165, 0x4c1be, 0x4c217]
            version_old = b'39990-TGN-E120'
            version_new = b'39990-TGN,E120'
            data_offsets = [
                0x135bc, #speed_clamp_lo

                0x13812, #torque_table row 1
                0x13824, #torque_table row 2
                0x13836, #torque_table row 3
                0x13848, #torque_table row 4
                0x1385a, #torque_table row 5
                0x1386c, #torque_table row 6
                0x1387e, #torque_table row 7
                
                0x13a64, #filter_table row 1
                0x13a76, #filter_table row 2
                0x13a88, #filter_table row 3
                0x13a9a, #filter_table row 4
                0x13aac, #filter_table row 5
                0x13abe, #filter_table row 6
                0x13ad0, #filter_table row 7
                ]
            data_old = [
                '0x0028', #speed_clamp_lo

                '0x0000, 0x02A1, 0x0692, 0x0AEE, 0x0EB6, 0x10AE, 0x1200, 0x1200, 0x1200', # original torque_table row 1
                '0x0000, 0x02A1, 0x0692, 0x0AEE, 0x0EB6, 0x10AE, 0x1200, 0x1200, 0x1200', # original torque_table row 2
                '0x0000, 0x02A1, 0x0692, 0x0AEE, 0x0EB6, 0x10AE, 0x1200, 0x1200, 0x1200', # original torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x119A, 0x11DA, 0x11DA', # original torque_table row 7

                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 1
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 2
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 3
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 4
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 5
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_new = [
                '0x0001', #speed_clamp_lo

                '0x0000, 0x02A1, 0x0692, 0x0AEE, 0x0EB6, 0x10AE, 0x1200, 0x1F80, 0x2D00', # new torque_table row 1
                '0x0000, 0x02A1, 0x0692, 0x0AEE, 0x0EB6, 0x10AE, 0x1200, 0x1F80, 0x2D00', # new torque_table row 2
                '0x0000, 0x02A1, 0x0692, 0x0AEE, 0x0EB6, 0x10AE, 0x1200, 0x1F80, 0x2D00', # new torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x19BE, 0x232F, 0x2CA1', # new torque_table row 7

                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 1
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 2
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 3
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 4
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 5
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 6
                '0x009F, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 7
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                'filter_table row 2',
                'filter_table row 3',
                'filter_table row 4',
                'filter_table row 5',
                'filter_table row 6',
                'filter_table row 7',
                ]
        elif input_bin_hash == '39710b41653f6b73b3b8c678d82790c0': #civic hatch sport thanks to bitchemist tony81 cfranhonda
            print('Detected bin: 39990-TGG-A020 Honda Civic Hatch Sport')
            supported_versions = ['39990-TGG-A010\x00\x00', '39990-TGG-A020\x00\x00', '39990-TGG,A020\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4b4e1, 0x4b53a, 0x4b593, 0x4b5ec, 0x4b645]
            version_old = b'39990-TGG-A020'
            version_new = b'39990-TGG,A020'
            data_offsets = [
                0x135bc, #speed_clamp_lo

                0x13812, #torque_table row 1
                0x13824, #torque_table row 2
                0x13836, #torque_table row 3
                0x13848, #torque_table row 4
                0x1385a, #torque_table row 5
                0x1386c, #torque_table row 6
                0x1387e, #torque_table row 7

                0x13a64, #filter_table row 1
                0x13a76, #filter_table row 2
                0x13a88, #filter_table row 3
                0x13a9a, #filter_table row 4
                0x13aac, #filter_table row 5
                0x13abe, #filter_table row 6
                0x13ad0, #filter_table row 7
                ]
            data_old = [
                '0x0028', #speed_clamp_lo

                '0x0000, 0x02A1, 0x0693, 0x0AEE, 0x0EB6, 0x10AF, 0x1200, 0x1200, 0x1200', # original torque_table row 1
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 2
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x119A, 0x11DA, 0x11DA', # original torque_table row 7
            
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108', # filter_table row 7
                ]
            data_new = [
                '0x0001', #speed_clamp_lo

                '0x0000, 0x02A1, 0x0693, 0x0AEE, 0x0EB6, 0x10AF, 0x1200, 0x1F80, 0x2D00', # new torque_table row 1
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 2
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1F80, 0x2D00', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x19BE, 0x232F, 0x2CA1', # new torque_table row 7

                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 1
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 2
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 3
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 4
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 5
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 6
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0400, 0x0480', # filter_table row 7
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',
                'filter_table row 2',
                'filter_table row 3',
                'filter_table row 4',
                'filter_table row 5',
                'filter_table row 6',
                'filter_table row 7',
                ]
        elif input_bin_hash == '3f0c3b65ed8f105673b2bc6d9933fa10': #clarity thanks to wirelessnet2
            print('Detected bin: 39990-TRW-A020 Honda Clarity')
            supported_versions = ['39990-TRW-A010\x00\x00', '39990-TRW-A020\x00\x00', '39990-TRW,A020\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0x4ba1d, 0x4ba76, 0x4bacf, 0x4bb28, 0x4bb81, 0x4bbda]
            version_old = b'39990-TRW-A020'
            version_new = b'39990-TRW,A020'
            data_offsets = [
                0x13638, #speed_clamp_lo

                0x1388e, #torque_table row 1
                0x138a0, #torque_table row 2
                0x138b2, #torque_table row 3
                0x138c4, #torque_table row 4
                0x138d6, #torque_table row 5
                0x138e8, #torque_table row 6
                0x138fa, #torque_table row 7

                0x13ae0, #filter_table row 0

                0x13bdc, #new_table row 0
                ]
            data_old = [
                '0x000a', #speed_clamp_lo

                '0x0000, 0x0580, 0x0a00, 0x0d00, 0x0f00, 0x10c0, 0x11ff, 0x1300, 0x1400', # original torque_table row 1
                '0x0000, 0x0500, 0x0800, 0x0a00, 0x0c00, 0x0e00, 0x1000, 0x1180, 0x1400', # original torque_table row 2
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 3
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 4
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 5
                '0x0000, 0x0746, 0x0b04, 0x0cdf, 0x0e19, 0x1008, 0x1200, 0x1200, 0x1200', # original torque_table row 6
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', # original torque_table row 7

                '0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200', #filter_table row 1

                '0x004d, 0x0066, 0x0080, 0x009a, 0x00b3, 0x00c0, 0x00c0, 0x00c0, 0x00c0', #new_table row 1
                ]
            data_new = [
                '0x0000', #speed_clamp_lo

                '0x0000, 0x0580, 0x0A00, 0x0D00, 0x0F00, 0x10C0, 0x11FF, 0x1300, 0x2800', # new torque_table row 1
                '0x0000, 0x0500, 0x0800, 0x0A00, 0x0C00, 0x0E00, 0x1000, 0x1180, 0x2800', # new torque_table row 2
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 3
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 4
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 5
                '0x0000, 0x0746, 0x0B04, 0x0CDF, 0x0E19, 0x1008, 0x1200, 0x1B00, 0x2D00', # new torque_table row 6
                '0x0000, 0x06B3, 0x0B1A, 0x0CCD, 0x0E9A, 0x104D, 0x16C4, 0x1852, 0x2F16', # new torque_table row 7

                '0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0280', #filter_table row 1

                '0x004d, 0x0066, 0x0080, 0x009a, 0x00b3, 0x00c0, 0x00c0, 0x00c0, 0x00ff', #new_table row 1
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',

                'new_table row 1',
                ]
        elif input_bin_hash == '87114e2d4ec30c336dde9820f8a09620': #insight thanks to fkndean
            print('Detected bin: 39990-TXM-A040 Honda Insight')
            supported_versions = ['39990-TXM-A010\x00\x00', '39990-TXM-A040\x00\x00', '39990-TXM,A040\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            version_offsets = [0xecdf, 0xed3a, 0xed95, 0xedf0, 0xf7e4, 0xf83f]
            version_old = b'39990-TXM-A040'
            version_new = b'39990-TXM,A040'
            data_offsets = [
                0x11964, #speed_clamp_lo

                0x11bba, #torque_table row 1
                0x11bcc, #torque_table row 2
                0x11bde, #torque_table row 3
                0x11bf0, #torque_table row 4
                0x11c02, #torque_table row 5
                0x11c14, #torque_table row 6
                0x11c26, #torque_table row 7

                0x11e0c, #filter_table row 1

                0x11f08, #new_table row 1

                0x11a0a, #speed_table row 1
                ]
            data_old = [
                '0x000a', #speed_clamp_lo

                '0x0000, 0x0500, 0x0800, 0x0a80, 0x0ce6, 0x1000, 0x1180, 0x1200, 0x1300', # original torque_table row 1
                '0x0000, 0x0500, 0x0800, 0x0a80, 0x0ce6, 0x1100, 0x141a, 0x1600, 0x1600', # original torque_table row 2
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 3
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 4
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 5
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 6
                '0x0000, 0x0917, 0x0dc5, 0x1017, 0x119f, 0x140a, 0x1680, 0x1680, 0x1680', # original torque_table row 7

                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #filter_table row 1

                '0x0033, 0x0080, 0x009a, 0x00b3, 0x00b8, 0x00b8, 0x00b8, 0x00b8, 0x00b8', #new_table row 1

                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 1
                ]
            data_new = [
                '0x0000', #speed_clamp_lo

                '0x0000, 0x0500, 0x0800, 0x0A80, 0x0CE6, 0x1000, 0x1180, 0x1200, 0x2600', # new torque_table row 1
                '0x0000, 0x0500, 0x0800, 0x0A80, 0x0CE6, 0x1100, 0x141A, 0x1600, 0x2C00', # new torque_table row 2
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2F56', # new torque_table row 3
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1317, 0x1E74, 0x318C', # new torque_table row 4
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1317, 0x1E74, 0x318C', # new torque_table row 5
                '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1317, 0x1E74, 0x318C', # new torque_table row 6
                '0x0000, 0x0917, 0x0DC5, 0x1017, 0x119F, 0x140A, 0x1680, 0x21C0, 0x3840', # new torque_table row 7

                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #filter_table row 1

                '0x0033, 0x0080, 0x009a, 0x00b3, 0x00b8, 0x00b8, 0x00b8, 0x00b8, 0x00b8', #new_table row 1

                '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 1
            #    0   	 15.5    31.1    46.6    62.1    77.7    93.2    108.7   124.3    #mph breakpoints for torque limit
                ]
            data_label = [
                'speed_clamp_lo',

                'torque_table row 1',
                'torque_table row 2',
                'torque_table row 3',
                'torque_table row 4',
                'torque_table row 5',
                'torque_table row 6',
                'torque_table row 7',

                'filter_table row 1',

                'new_table row 1',

                'speed_table row 1'
                ]
        elif input_bin_hash in (
            '81a1415207caff22dedbcb04d79b8cb8',  # sequential-UPLOAD CCP dump 39990-TLA-A220-raw.bin, 0x80000 (sha256 df85f988...)
            '2137c5aafaec7f03aeedf5ddb2384f2b',  # decoded reconstructed stock x5a RWD, 0x70000
        ): # CR-V 2020+
            print('Detected bin: 39990-TLA-A220 Honda CR-V')
            car_model = '39990-TLA-A220'
            # Only A220 part strings exist in this image (28, all 39990-TLA-A220),
            # so no predecessor version is listed. Security constants 0111/0112/1120
            # are the A220's own: key routine 0x559A0 reads them from 0xE150, and the
            # update config record at 0x10874 is byte-identical to A040's.
            supported_versions = ['39990-TLA-A220\x00\x00', '39990-TLA,A220\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            # Same record layout as TXM-A040: 0x5B-byte records, version string at
            # +0x43. Main table 0xEC9C (12 records, record search 0x5A10C) plus the
            # two-record table at 0xF7A1 (literal 0x5A3B4).
            version_offsets = [0xecdf, 0xed3a, 0xed95, 0xedf0, 0xee4b, 0xeea6, 0xef01, 0xef5c, 0xefb7, 0xf012, 0xf06d, 0xf0c8, 0xf7e4, 0xf83f]
            version_old = b'39990-TLA-A220'
            version_new = b'39990-TLA,A220'
            # Controller block 0x40000-0x43000 is the A040 code shifted -0x448
            # (literal pools only differ; RAM +0x24), and every calibration
            # literal it loads resolves to the SAME table address as A040. The
            # stock VALUES differ from A040 (newer tune), so data_old below is
            # A220's own. Normalizer: 0x42556 MOVI20 #3429,R0 (A040 0x4299E).
            controller_guards = [
                {'kind': MOVI20_LO, 'offset': 0x42558, 'rn': 0,
                 'label': 'feedback_normalization', 'bounds': (1, 3429),
                 'neighbors': ((-4, 0x6662), (2, 0x4680))},
                {'kind': SIGNED_WORD, 'offset': 0x11ada,
                 'label': 'feedback_tracker_1_coeff', 'bounds': (1, 32767)},
                {'kind': SIGNED_WORD, 'offset': 0x11bdc,
                 'label': 'p_term_clamp', 'bounds': (1, 32767)},
                {'kind': SIGNED_WORD, 'offset': 0x11bde,
                 'label': 'd_term_clamp', 'bounds': (1, 32767)},
                {'kind': SIGNED_WORD, 'offset': 0x11be0,
                 'label': 'final_output_clamp', 'bounds': (1, 32767)},
                ]
            # All 7 rows are exposed: rows 0-3 are A220-specific and the A220
            # variant-row selection has not been traced yet.
            data_offsets = [
                0x11908, #speed_clamp_lo

                0x42558, #feedback_normalization: imm[15:0] of MOVI20 #3429,R0 at 0x42556
                0x11ada, #tracker_alpha (Q15)

                0x11bdc, #p_term_clamp
                0x11bde, #d_term_clamp
                0x11be0, #final_output_clamp

                0x11b5e, 0x11b70, 0x11b82, 0x11b94, 0x11ba6, 0x11bb8, 0x11bca, #target_map_y rows 0-6

                0x11db0, 0x11dc2, 0x11dd4, 0x11de6, 0x11df8, 0x11e0a, 0x11e1c, #d_gain_y rows 0-6

                0x11eac, 0x11ebe, 0x11ed0, 0x11ee2, 0x11ef4, 0x11f06, 0x11f18, #p_gain_y rows 0-6

                # A280 torque-rate attenuation Y tables (6 points, 12-byte rows).
                # A280 homolog 0x4183C: row = byte @(0xC, 0xFFF89C4C) = 0xFFF89C58,
                # Y1 0x11C36 / Y2 0x11CDE (literals 0x41A24/0x41A2C). Row byte is
                # written only by setter 0x422EA, fed record copy[0x0F] from the
                # 12-record search 0x5A10C (table 0xEC9C): rows {0,1,2,3}.
                0x11c36, 0x11c42, 0x11c4e, 0x11c5a, #a280_y1 rows 0-3
                0x11cde, 0x11cea, 0x11cf6, 0x11d02, #a280_y2 rows 0-3
                ]
            data_old = [
                '0x000a', #speed_clamp_lo

                '0x0d65', #feedback_normalization (stock 3429)
                '0x07cf', #tracker_alpha (stock 1999)

                '0x08a9', #p_term_clamp (stock 2217)
                '0x0455', #d_term_clamp (stock 1109)
                '0x08a9', #final_output_clamp (stock 2217)

                '0x0000, 0x03ae, 0x0540, 0x075a, 0x0973, 0x0c1a, 0x0f9a, 0x1580, 0x1600',
                '0x0000, 0x03ae, 0x0540, 0x075a, 0x0973, 0x0c1a, 0x0f9a, 0x1580, 0x1600',
                '0x0000, 0x0400, 0x05b3, 0x0800, 0x0a00, 0x0d00, 0x1000, 0x1600, 0x1800',
                '0x0000, 0x0400, 0x05b3, 0x0800, 0x0a00, 0x0d00, 0x1000, 0x1600, 0x1800',
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400',
                '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400',
                '0x0000, 0x06e1, 0x0c9a, 0x1000, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400',

                '0x0080, 0x0180, 0x0280, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300',
                '0x0080, 0x011a, 0x0280, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300',
                '0x0080, 0x0200, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300',
                '0x0080, 0x0200, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300, 0x0300',
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108',
                '0x009f, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108, 0x0108',
                '0x009f, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200, 0x0200',

                '0x002c, 0x009a, 0x00c0, 0x00ca, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd',
                '0x002c, 0x009a, 0x00c0, 0x00ca, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd',
                '0x0066, 0x009a, 0x00c0, 0x00ca, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd',
                '0x0066, 0x009a, 0x00c0, 0x00ca, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd',
                '0x001f, 0x003d, 0x006e, 0x008a, 0x0094, 0x009f, 0x00a6, 0x00b3, 0x00b3',
                '0x001f, 0x003d, 0x006e, 0x008a, 0x0094, 0x009f, 0x00a6, 0x00b3, 0x00b3',
                '0x0040, 0x0080, 0x00c0, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd, 0x00cd',
                ] + ['0x0100, 0x0100, 0x00e6, 0x00c8, 0x00a9, 0x0094'] * 8  # a280_y1/y2 rows 0-3
            # PTM calibration: the released CR-V PTM values (TLA-A040
            # Clarity_FF_tune, payload sha256 8cf8e537...), written to the same
            # consumer-verified addresses. All rows set, as the A040 PTM does.
            # Note the A220 stock baseline differs from A040 stock (data_old).
            _ptm_target_map = '0x0000, 0x0786, 0x134a, 0x2107, 0x2f04, 0x3e36, 0x4eaa, 0x694b, 0x7530'
            _ptm_d_gain = '0x02e1, 0x02e1, 0x02e1, 0x02e1, 0x02e1, 0x02e1, 0x02e1, 0x02e1, 0x02e1'  # D737
            _ptm_p_gain = '0x0075, 0x0094, 0x00b8, 0x00dc, 0x00f5, 0x0101, 0x0107, 0x0109, 0x0109'  # P117..265
            data_new = [
                '0x0000', #speed_clamp_lo 0

                '0x0672', #feedback_normalization 1650
                '0x0c80', #tracker_alpha 3200

                '0x1ccd', #p_term_clamp 7373
                '0x06ee', #d_term_clamp 1774
                '0x2328', #final_output_clamp 9000
                ] + [_ptm_target_map] * 7 + [_ptm_d_gain] * 7 + [_ptm_p_gain] * 7 \
                  + ['0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100'] * 8  # A280 flat
            # PTM FF45 hook (verified site in FEEDFORWARD_SITES); None disables.
            feedforward_kff = 45
            data_label = [
                'speed_clamp_lo',

                'feedback_normalization',
                'feedback_tracker_1_coeff',

                'p_term_clamp',
                'd_term_clamp',
                'final_output_clamp',
                ] + ['target_map_y row %d' % r for r in range(7)] \
                  + ['d_gain_y row %d' % r for r in range(7)] \
                  + ['p_gain_y row %d' % r for r in range(7)] \
                  + ['a280_y1 row %d' % r for r in range(4)] \
                  + ['a280_y2 row %d' % r for r in range(4)]

        elif input_bin_hash == 'ad8198fbfb419669dc3e9a9132a378d4':
            print('Detected bin: 39990-THR-A020 Honda Odyssey 2018')
            car_model = '39990-THR-A020'  #odyssey
            rom_crc_regions = THR_FAMILY_ROM_CRC_REGIONS
            # Payload geometry (0xC000/0x74000), checksums and cipher are set by
            # the length branch at the top of main(); the cipher/geometry/key are
            # Honda's own for this flash class (genuine T5R/T7T/T7W rwds).
            #
            # Sources: THR_A020_INDEPENDENT_TRACE_20260920/RUNNING_LOG.md and
            # THR_A020_FINDINGS_20260925.md. Every address below was mapped to
            # the code that reads it (literal pool -> reader), and the PD /
            # curve / mixer path was checked bit-exact in an SH-2A emulator.
            supported_versions = ['39990-THR-A020\x00\x00', '39990-THR,A020\x00\x00']
            # Same key in all three genuine 0xC000/0x74000 rwds, and the THR
            # security constant (0x51E4/0x4F6A).
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            # 14 identity records at 0x5EB00, stride 0x46; version at record +0x37.
            # The profile-key compare (FUN_0002F8FC) reads +0x00 and the bank
            # selector +0x10, so the comma marker does not change bank selection.
            version_offsets = [0x5eb37, 0x5eb7d, 0x5ebc3, 0x5ec09, 0x5ec4f, 0x5ec95, 0x5ecdb, 0x5ed21, 0x5ed67, 0x5edad, 0x5edf3, 0x5ee39, 0x5ee7f, 0x5eec5]
            version_old = b'39990-THR-A020'
            version_new = b'39990-THR,A020'
            #
            # Calibration rows. THR keeps one copy of every controller table per
            # selector, at bank-1 address + 0x300*row (FFF82F04 = (sel-1)*0x180,
            # tables read at base + 2*FFF82F04). row = selector - 1:
            #   row 0      keys THRA0, THRC0 and unkeyed records
            #   row 1      keys THRA1/A2/A3
            #   row 2      keys THRA4/X0/Y0
            #   rows 3..5  not selected by any stock key
            #   row 6      forced when either byte of FFF85420 == 1 (mode 7)
            # Rows 0-2 are byte-identical (the normal-driving calibration); rows
            # 3-6 are identical to each other, and row 6's target map is the
            # Clarity TRW target row 6 exactly. So THR row N lines up with the
            # Clarity/Civic "row N" convention. The car's key is not known, so
            # edit rows 0-2 together. 0x59000 (row 7) is a different structure,
            # not a bank, and is never written.
            #
            # Loop (bank-1 stock): a = E4/4 -> speed_limit clamp -> target_map
            # s -> err = s - tracker1(FFF8029C) -> P,D (x Kp,Kd >>6, clamped)
            # -> u = K*(P+D)>>8 clamped -> mixer total clamp +/-8868 (0x57C94).
            # The steady ceiling is target_map x Kp (row 0: u = 836); raising
            # the clamps alone gives no steady-state gain.
            #
            # Curves are interpolated with Q26 slopes, so every segment must
            # satisfy |dY| <= 31*dX with dX > 0 (checked below, input and output).
            #
            # Deliberately not exposed:
            #   0x57B52 = 768   driver-override fade cut |T| (FUN_00073D20), with
            #                   its fade curves 0x57B54..0x57BAB
            #   0x57B06 = 8868  assist-limit floor (FUN_00072DDC, FUN_000754B0)
            #   0x57C94 = 8868  mixer total clamp (FUN_00074C9C)
            #   0x57BDC..0x57C4B K scheduling on |T| and |E0 rate| (E/F/G/H)
            #   0x57CD6..0x57CEB E4 command monitors (FUN_00073A28/750E8/751EA)
            # The 0x54340/0x54400 grids (and 0x64340/0x64400) are read only by
            # code outside the verified E4 -> mixer chain; their role is open.
            controller_guards = [
                {'kind': SIGNED_WORD, 'offset': base + 0x300 * row,
                 'label': '{} row {}'.format(label, row), 'bounds': bounds}
                for label, base, bounds in (
                    ('feedback_tracker_1_coeff', 0x57bd2, (1, 32767)),
                    ('feedback_tracker_2_coeff', 0x57b4e, (1, 32767)),
                    ('feedback_tracker_2_clamp', 0x57b50, (1, 32767)),
                    ('command_input_clamp', 0x57bac, (1, 1774)),
                    ('d_term_clamp', 0x57bd6, (1, 32767)),
                    ('p_term_clamp', 0x57bd8, (1, 32767)),
                    # u above the 8868 mixer clamp can never reach the motor
                    ('final_output_clamp', 0x57bda, (1, 8868)),
                )
                for row in range(7)
            ]
            curve_checks = [
                (x + 0x300 * row, y + 0x300 * row, 9, '{} row {}'.format(label, row))
                for label, x, y in (
                    ('speed_limit', 0x57b2a, 0x57b3c),
                    ('target_map', 0x57bae, 0x57bc0),
                    ('d_gain', 0x57c4c, 0x57c5e),
                    ('p_gain', 0x57c70, 0x57c82),
                )
                for row in range(7)
            ]
            # Monitor copies. FUN_000727E4 runs a set of monitors that redo each
            # controller stage from its own copy of the calibration at 0x67xxx and
            # compare with the live result (e.g. FUN_0006ACC4 re-evaluates the
            # target map and flags a mismatch; FUN_0006B010 flags P/D/u beyond its
            # own clamp copies). Flags debounce into FFF8A5CC.. and the diagnostic
            # entry at 0x6FC00. Every exposed field has a copy, banked the same way
            # and identical to the primary in stock rows 0-6, so edits are mirrored.
            shadow_mirrors = [
                (primary + 0x300 * row, shadow + 0x300 * row, size, '{} row {}'.format(label, row))
                for label, primary, shadow, size in (
                    ('speed_clamp_lo', 0x57b00, 0x67b00, 2),             # FUN_00069000
                    ('speed_limit_x', 0x57b2a, 0x67b2e, 18),             # FUN_0006A210
                    ('speed_limit_y', 0x57b3c, 0x67b40, 18),
                    ('feedback_tracker_2_coeff', 0x57b4e, 0x67b56, 2),   # FUN_0006A420
                    ('feedback_tracker_2_clamp', 0x57b50, 0x67b58, 2),
                    ('command_input_clamp', 0x57bac, 0x67bc2, 2),        # FUN_0006ACC4
                    ('target_map_x', 0x57bae, 0x67bc4, 18),
                    ('target_map_y', 0x57bc0, 0x67bd6, 18),
                    ('feedback_tracker_1_coeff', 0x57bd2, 0x67be8, 2),   # FUN_0006AF30
                    ('feedback_tracker_1_clamp', 0x57bd4, 0x67bea, 2),
                    ('d_term_clamp', 0x57bd6, 0x67bec, 2),               # FUN_0006B010
                    ('p_term_clamp', 0x57bd8, 0x67bee, 2),
                    ('final_output_clamp', 0x57bda, 0x67bf0, 2),
                    ('d_gain_x', 0x57c4c, 0x67c72, 18),
                    ('d_gain_y', 0x57c5e, 0x67c84, 18),
                    ('p_gain_x', 0x57c70, 0x67c9a, 18),
                    ('p_gain_y', 0x57c82, 0x67cac, 18),
                )
                for row in range(7)
            ]
            # All values below are STOCK (data_new == data_old): a default build
            # changes only the version marker.
            data_offsets = [
                # speed_clamp_lo: engage speed-window minimum, 0.5 kph/count (FUN_00072DDC); 10 = 5 kph
                0x57b00, #speed_clamp_lo row 0
                0x57e00, #speed_clamp_lo row 1
                0x58100, #speed_clamp_lo row 2
                0x58400, #speed_clamp_lo row 3
                0x58700, #speed_clamp_lo row 4
                0x58a00, #speed_clamp_lo row 5
                0x58d00, #speed_clamp_lo row 6

                # speed_limit_x: command-limit speed axis, 0.5 kph/count (FUN_00073AE0; informational)
                0x57b2a, #speed_limit_x row 0
                0x57e2a, #speed_limit_x row 1
                0x5812a, #speed_limit_x row 2
                0x5842a, #speed_limit_x row 3
                0x5872a, #speed_limit_x row 4
                0x58a2a, #speed_limit_x row 5
                0x58d2a, #speed_limit_x row 6

                # speed_limit_y: command limit L vs speed; E4 cmd/4 clamped to +/-L (FUN_00073AE0)
                0x57b3c, #speed_limit_y row 0
                0x57e3c, #speed_limit_y row 1
                0x5813c, #speed_limit_y row 2
                0x5843c, #speed_limit_y row 3
                0x5873c, #speed_limit_y row 4
                0x58a3c, #speed_limit_y row 5
                0x58d3c, #speed_limit_y row 6

                # feedback_tracker_2_coeff: tracker-2 one-pole k/32768 on E0 rate (FUN_00073BCC)
                0x57b4e, #feedback_tracker_2_coeff row 0
                0x57e4e, #feedback_tracker_2_coeff row 1
                0x5814e, #feedback_tracker_2_coeff row 2
                0x5844e, #feedback_tracker_2_coeff row 3
                0x5874e, #feedback_tracker_2_coeff row 4
                0x58a4e, #feedback_tracker_2_coeff row 5
                0x58d4e, #feedback_tracker_2_coeff row 6

                # feedback_tracker_2_clamp: tracker-2 output clamp (FUN_00073BCC)
                0x57b50, #feedback_tracker_2_clamp row 0
                0x57e50, #feedback_tracker_2_clamp row 1
                0x58150, #feedback_tracker_2_clamp row 2
                0x58450, #feedback_tracker_2_clamp row 3
                0x58750, #feedback_tracker_2_clamp row 4
                0x58a50, #feedback_tracker_2_clamp row 5
                0x58d50, #feedback_tracker_2_clamp row 6

                # command_input_clamp: |a| input limit before target map (FUN_0007415C); hard +/-1774 after
                0x57bac, #command_input_clamp row 0
                0x57eac, #command_input_clamp row 1
                0x581ac, #command_input_clamp row 2
                0x584ac, #command_input_clamp row 3
                0x587ac, #command_input_clamp row 4
                0x58aac, #command_input_clamp row 5
                0x58dac, #command_input_clamp row 6

                # target_map_x: target map breakpoints on |a| (FUN_0007415C; informational)
                0x57bae, #target_map_x row 0
                0x57eae, #target_map_x row 1
                0x581ae, #target_map_x row 2
                0x584ae, #target_map_x row 3
                0x587ae, #target_map_x row 4
                0x58aae, #target_map_x row 5
                0x58dae, #target_map_x row 6

                # target_map_y: target map s (FUN_0007415C)
                0x57bc0, #target_map_y row 0
                0x57ec0, #target_map_y row 1
                0x581c0, #target_map_y row 2
                0x584c0, #target_map_y row 3
                0x587c0, #target_map_y row 4
                0x58ac0, #target_map_y row 5
                0x58dc0, #target_map_y row 6

                # feedback_tracker_1_coeff: tracker-1 one-pole k/32768 on FFF8029C (FUN_000742C0)
                0x57bd2, #feedback_tracker_1_coeff row 0
                0x57ed2, #feedback_tracker_1_coeff row 1
                0x581d2, #feedback_tracker_1_coeff row 2
                0x584d2, #feedback_tracker_1_coeff row 3
                0x587d2, #feedback_tracker_1_coeff row 4
                0x58ad2, #feedback_tracker_1_coeff row 5
                0x58dd2, #feedback_tracker_1_coeff row 6

                # feedback_tracker_1_clamp: tracker-1 reference clamp (FUN_000742C0)
                0x57bd4, #feedback_tracker_1_clamp row 0
                0x57ed4, #feedback_tracker_1_clamp row 1
                0x581d4, #feedback_tracker_1_clamp row 2
                0x584d4, #feedback_tracker_1_clamp row 3
                0x587d4, #feedback_tracker_1_clamp row 4
                0x58ad4, #feedback_tracker_1_clamp row 5
                0x58dd4, #feedback_tracker_1_clamp row 6

                # d_term_clamp: D = clamp(Kd*derr>>6) (FUN_0007435C)
                0x57bd6, #d_term_clamp row 0
                0x57ed6, #d_term_clamp row 1
                0x581d6, #d_term_clamp row 2
                0x584d6, #d_term_clamp row 3
                0x587d6, #d_term_clamp row 4
                0x58ad6, #d_term_clamp row 5
                0x58dd6, #d_term_clamp row 6

                # p_term_clamp: P = clamp(Kp*err>>6) (FUN_0007435C)
                0x57bd8, #p_term_clamp row 0
                0x57ed8, #p_term_clamp row 1
                0x581d8, #p_term_clamp row 2
                0x584d8, #p_term_clamp row 3
                0x587d8, #p_term_clamp row 4
                0x58ad8, #p_term_clamp row 5
                0x58dd8, #p_term_clamp row 6

                # final_output_clamp: u = clamp(K*(P+D)>>8) -> FFF83074 (FUN_0007435C)
                0x57bda, #final_output_clamp row 0
                0x57eda, #final_output_clamp row 1
                0x581da, #final_output_clamp row 2
                0x584da, #final_output_clamp row 3
                0x587da, #final_output_clamp row 4
                0x58ada, #final_output_clamp row 5
                0x58dda, #final_output_clamp row 6

                # d_gain_x: Kd breakpoints (FUN_0007435C; informational)
                0x57c4c, #d_gain_x row 0
                0x57f4c, #d_gain_x row 1
                0x5824c, #d_gain_x row 2
                0x5854c, #d_gain_x row 3
                0x5884c, #d_gain_x row 4
                0x58b4c, #d_gain_x row 5
                0x58e4c, #d_gain_x row 6

                # d_gain_y: Kd, applied >>6 (FUN_0007435C)
                0x57c5e, #d_gain_y row 0
                0x57f5e, #d_gain_y row 1
                0x5825e, #d_gain_y row 2
                0x5855e, #d_gain_y row 3
                0x5885e, #d_gain_y row 4
                0x58b5e, #d_gain_y row 5
                0x58e5e, #d_gain_y row 6

                # p_gain_x: Kp breakpoints on |a| (FUN_0007435C; informational)
                0x57c70, #p_gain_x row 0
                0x57f70, #p_gain_x row 1
                0x58270, #p_gain_x row 2
                0x58570, #p_gain_x row 3
                0x58870, #p_gain_x row 4
                0x58b70, #p_gain_x row 5
                0x58e70, #p_gain_x row 6

                # p_gain_y: Kp, applied >>6 (FUN_0007435C)
                0x57c82, #p_gain_y row 0
                0x57f82, #p_gain_y row 1
                0x58282, #p_gain_y row 2
                0x58582, #p_gain_y row 3
                0x58882, #p_gain_y row 4
                0x58b82, #p_gain_y row 5
                0x58e82, #p_gain_y row 6
                ]
            data_old = [
                # speed_clamp_lo
                '0x000a', #speed_clamp_lo row 0
                '0x000a', #speed_clamp_lo row 1
                '0x000a', #speed_clamp_lo row 2
                '0x0046', #speed_clamp_lo row 3
                '0x0046', #speed_clamp_lo row 4
                '0x0046', #speed_clamp_lo row 5
                '0x0046', #speed_clamp_lo row 6

                # speed_limit_x
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 0
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 1
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 2
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 3
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 4
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 5
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 6

                # speed_limit_y
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 0
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 1
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 2
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 3
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 4
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 5
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 6

                # feedback_tracker_2_coeff
                '0x0222', #feedback_tracker_2_coeff row 0
                '0x0222', #feedback_tracker_2_coeff row 1
                '0x0222', #feedback_tracker_2_coeff row 2
                '0x655f', #feedback_tracker_2_coeff row 3
                '0x655f', #feedback_tracker_2_coeff row 4
                '0x655f', #feedback_tracker_2_coeff row 5
                '0x655f', #feedback_tracker_2_coeff row 6

                # feedback_tracker_2_clamp
                '0x0140', #feedback_tracker_2_clamp row 0
                '0x0140', #feedback_tracker_2_clamp row 1
                '0x0140', #feedback_tracker_2_clamp row 2
                '0x0140', #feedback_tracker_2_clamp row 3
                '0x0140', #feedback_tracker_2_clamp row 4
                '0x0140', #feedback_tracker_2_clamp row 5
                '0x0140', #feedback_tracker_2_clamp row 6

                # command_input_clamp
                '0x0400', #command_input_clamp row 0
                '0x0400', #command_input_clamp row 1
                '0x0400', #command_input_clamp row 2
                '0x0400', #command_input_clamp row 3
                '0x0400', #command_input_clamp row 4
                '0x0400', #command_input_clamp row 5
                '0x0400', #command_input_clamp row 6

                # target_map_x
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 0
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 1
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 2
                '0x0000, 0x00de, 0x01bb, 0x0299, 0x0377, 0x0455, 0x0532, 0x0610, 0x06ee', #target_map_x row 3
                '0x0000, 0x00de, 0x01bb, 0x0299, 0x0377, 0x0455, 0x0532, 0x0610, 0x06ee', #target_map_x row 4
                '0x0000, 0x00de, 0x01bb, 0x0299, 0x0377, 0x0455, 0x0532, 0x0610, 0x06ee', #target_map_x row 5
                '0x0000, 0x00de, 0x01bb, 0x0299, 0x0377, 0x0455, 0x0532, 0x0610, 0x06ee', #target_map_x row 6

                # target_map_y
                '0x0000, 0x07e3, 0x0c9e, 0x0f8c, 0x10f9, 0x11e1, 0x1271, 0x1300, 0x1300', #target_map_y row 0
                '0x0000, 0x07e3, 0x0c9e, 0x0f8c, 0x10f9, 0x11e1, 0x1271, 0x1300, 0x1300', #target_map_y row 1
                '0x0000, 0x07e3, 0x0c9e, 0x0f8c, 0x10f9, 0x11e1, 0x1271, 0x1300, 0x1300', #target_map_y row 2
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', #target_map_y row 3
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', #target_map_y row 4
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', #target_map_y row 5
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', #target_map_y row 6

                # feedback_tracker_1_coeff
                '0x019a', #feedback_tracker_1_coeff row 0
                '0x019a', #feedback_tracker_1_coeff row 1
                '0x019a', #feedback_tracker_1_coeff row 2
                '0x759e', #feedback_tracker_1_coeff row 3
                '0x759e', #feedback_tracker_1_coeff row 4
                '0x759e', #feedback_tracker_1_coeff row 5
                '0x759e', #feedback_tracker_1_coeff row 6

                # feedback_tracker_1_clamp
                '0x7ffd', #feedback_tracker_1_clamp row 0
                '0x7ffd', #feedback_tracker_1_clamp row 1
                '0x7ffd', #feedback_tracker_1_clamp row 2
                '0x7ffd', #feedback_tracker_1_clamp row 3
                '0x7ffd', #feedback_tracker_1_clamp row 4
                '0x7ffd', #feedback_tracker_1_clamp row 5
                '0x7ffd', #feedback_tracker_1_clamp row 6

                # d_term_clamp
                '0x0280', #d_term_clamp row 0
                '0x0280', #d_term_clamp row 1
                '0x0280', #d_term_clamp row 2
                '0x0280', #d_term_clamp row 3
                '0x0280', #d_term_clamp row 4
                '0x0280', #d_term_clamp row 5
                '0x0280', #d_term_clamp row 6

                # p_term_clamp
                '0x0400', #p_term_clamp row 0
                '0x0400', #p_term_clamp row 1
                '0x0400', #p_term_clamp row 2
                '0x0400', #p_term_clamp row 3
                '0x0400', #p_term_clamp row 4
                '0x0400', #p_term_clamp row 5
                '0x0400', #p_term_clamp row 6

                # final_output_clamp
                '0x0400', #final_output_clamp row 0
                '0x0400', #final_output_clamp row 1
                '0x0400', #final_output_clamp row 2
                '0x0400', #final_output_clamp row 3
                '0x0400', #final_output_clamp row 4
                '0x0400', #final_output_clamp row 5
                '0x0400', #final_output_clamp row 6

                # d_gain_x
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 0
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 1
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 2
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 3
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 4
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 5
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 6

                # d_gain_y
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 0
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 1
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 2
                '0x000a, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010', #d_gain_y row 3
                '0x000a, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010', #d_gain_y row 4
                '0x000a, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010', #d_gain_y row 5
                '0x000a, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010', #d_gain_y row 6

                # p_gain_x
                '0x0000, 0x0037, 0x00a6, 0x013f, 0x0214, 0x0308, 0x0377, 0x03ae, 0x03e6', #p_gain_x row 0
                '0x0000, 0x0037, 0x00a6, 0x013f, 0x0214, 0x0308, 0x0377, 0x03ae, 0x03e6', #p_gain_x row 1
                '0x0000, 0x0037, 0x00a6, 0x013f, 0x0214, 0x0308, 0x0377, 0x03ae, 0x03e6', #p_gain_x row 2
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #p_gain_x row 3
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #p_gain_x row 4
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #p_gain_x row 5
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #p_gain_x row 6

                # p_gain_y
                '0x0001, 0x0004, 0x0006, 0x0008, 0x000a, 0x000b, 0x000b, 0x000b, 0x000b', #p_gain_y row 0
                '0x0001, 0x0004, 0x0006, 0x0008, 0x000a, 0x000b, 0x000b, 0x000b, 0x000b', #p_gain_y row 1
                '0x0001, 0x0004, 0x0006, 0x0008, 0x000a, 0x000b, 0x000b, 0x000b, 0x000b', #p_gain_y row 2
                '0x0002, 0x0006, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 3
                '0x0002, 0x0006, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 4
                '0x0002, 0x0006, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 5
                '0x0002, 0x0006, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 6
                ]
            data_new = list(data_old)
            data_label = [
                # speed_clamp_lo
                'speed_clamp_lo row 0',
                'speed_clamp_lo row 1',
                'speed_clamp_lo row 2',
                'speed_clamp_lo row 3',
                'speed_clamp_lo row 4',
                'speed_clamp_lo row 5',
                'speed_clamp_lo row 6',

                # speed_limit_x
                'speed_limit_x row 0',
                'speed_limit_x row 1',
                'speed_limit_x row 2',
                'speed_limit_x row 3',
                'speed_limit_x row 4',
                'speed_limit_x row 5',
                'speed_limit_x row 6',

                # speed_limit_y
                'speed_limit_y row 0',
                'speed_limit_y row 1',
                'speed_limit_y row 2',
                'speed_limit_y row 3',
                'speed_limit_y row 4',
                'speed_limit_y row 5',
                'speed_limit_y row 6',

                # feedback_tracker_2_coeff
                'feedback_tracker_2_coeff row 0',
                'feedback_tracker_2_coeff row 1',
                'feedback_tracker_2_coeff row 2',
                'feedback_tracker_2_coeff row 3',
                'feedback_tracker_2_coeff row 4',
                'feedback_tracker_2_coeff row 5',
                'feedback_tracker_2_coeff row 6',

                # feedback_tracker_2_clamp
                'feedback_tracker_2_clamp row 0',
                'feedback_tracker_2_clamp row 1',
                'feedback_tracker_2_clamp row 2',
                'feedback_tracker_2_clamp row 3',
                'feedback_tracker_2_clamp row 4',
                'feedback_tracker_2_clamp row 5',
                'feedback_tracker_2_clamp row 6',

                # command_input_clamp
                'command_input_clamp row 0',
                'command_input_clamp row 1',
                'command_input_clamp row 2',
                'command_input_clamp row 3',
                'command_input_clamp row 4',
                'command_input_clamp row 5',
                'command_input_clamp row 6',

                # target_map_x
                'target_map_x row 0',
                'target_map_x row 1',
                'target_map_x row 2',
                'target_map_x row 3',
                'target_map_x row 4',
                'target_map_x row 5',
                'target_map_x row 6',

                # target_map_y
                'target_map_y row 0',
                'target_map_y row 1',
                'target_map_y row 2',
                'target_map_y row 3',
                'target_map_y row 4',
                'target_map_y row 5',
                'target_map_y row 6',

                # feedback_tracker_1_coeff
                'feedback_tracker_1_coeff row 0',
                'feedback_tracker_1_coeff row 1',
                'feedback_tracker_1_coeff row 2',
                'feedback_tracker_1_coeff row 3',
                'feedback_tracker_1_coeff row 4',
                'feedback_tracker_1_coeff row 5',
                'feedback_tracker_1_coeff row 6',

                # feedback_tracker_1_clamp
                'feedback_tracker_1_clamp row 0',
                'feedback_tracker_1_clamp row 1',
                'feedback_tracker_1_clamp row 2',
                'feedback_tracker_1_clamp row 3',
                'feedback_tracker_1_clamp row 4',
                'feedback_tracker_1_clamp row 5',
                'feedback_tracker_1_clamp row 6',

                # d_term_clamp
                'd_term_clamp row 0',
                'd_term_clamp row 1',
                'd_term_clamp row 2',
                'd_term_clamp row 3',
                'd_term_clamp row 4',
                'd_term_clamp row 5',
                'd_term_clamp row 6',

                # p_term_clamp
                'p_term_clamp row 0',
                'p_term_clamp row 1',
                'p_term_clamp row 2',
                'p_term_clamp row 3',
                'p_term_clamp row 4',
                'p_term_clamp row 5',
                'p_term_clamp row 6',

                # final_output_clamp
                'final_output_clamp row 0',
                'final_output_clamp row 1',
                'final_output_clamp row 2',
                'final_output_clamp row 3',
                'final_output_clamp row 4',
                'final_output_clamp row 5',
                'final_output_clamp row 6',

                # d_gain_x
                'd_gain_x row 0',
                'd_gain_x row 1',
                'd_gain_x row 2',
                'd_gain_x row 3',
                'd_gain_x row 4',
                'd_gain_x row 5',
                'd_gain_x row 6',

                # d_gain_y
                'd_gain_y row 0',
                'd_gain_y row 1',
                'd_gain_y row 2',
                'd_gain_y row 3',
                'd_gain_y row 4',
                'd_gain_y row 5',
                'd_gain_y row 6',

                # p_gain_x
                'p_gain_x row 0',
                'p_gain_x row 1',
                'p_gain_x row 2',
                'p_gain_x row 3',
                'p_gain_x row 4',
                'p_gain_x row 5',
                'p_gain_x row 6',

                # p_gain_y
                'p_gain_y row 0',
                'p_gain_y row 1',
                'p_gain_y row 2',
                'p_gain_y row 3',
                'p_gain_y row 4',
                'p_gain_y row 5',
                'p_gain_y row 6',
                ]
        elif input_bin_hash == '91254318f2c6d28b80a23fa8fadcb5ff':
            # Decoded stock 39990-TJB-A220.rwd (sha256 d951de3c...), payload
            # 0xC000..0x7FFFF, 0x0000..0xBFFF FF padding (sha256 5b25409e...).
            print('Detected bin: 39990-TJB-A220 Acura RDX')
            car_model = '39990-TJB-A220'
            rom_crc_regions = THR_FAMILY_ROM_CRC_REGIONS
            # THR-A020 twin (TJB_A220_THR_FAMILY_OFFSETS_20261014.md): the LKAS
            # controller loads every calibration literal at the THR address
            # (pools shifted ~+0x90; PD/governor stage = THR 0x7435C at 0x743F8,
            # 99% identical). Stock checksums reproduce with the THR geometry.
            supported_versions = ['39990-TJB-A220\x00\x00', '39990-TJB,A220\x00\x00']
            security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
            # 14 identity records at 0x5EB00, stride 0x46, version at +0x37,
            # selector at +0x10 (TJBA0 1, TJBA6 2, TJBA7 3, TJBA8 4, unkeyed 2).
            version_offsets = [0x5eb37 + 0x46 * i for i in range(14)]
            version_old = b'39990-TJB-A220'
            version_new = b'39990-TJB,A220'
            # Rows: bank index FFF86904 = (mode-1)*0x180, written at 0x1AB94;
            # tables read at base + 0x300*row. mode = record selector, or 5 when
            # either byte of FFF8D450 == 1 (0x1AB5E MOV #5; THR uses 7). Rows 0-3
            # are byte-identical (normal); row 4 is the override row (= THR bank
            # 7). Rows 5/6 are erased, 0x59000 (row 7) is not a bank.
            # Shadow (monitor) copies sit at THR shadow - 0x4D00 (0x62E00..),
            # loaded next to FFF86904 by the 0x68xxx-0x6Bxxx monitors.
            controller_guards = [
                {'kind': SIGNED_WORD, 'offset': base + 0x300 * row,
                 'label': '{} row {}'.format(label, row), 'bounds': bounds}
                for label, base, bounds in (
                    ('feedback_tracker_1_coeff', 0x57bd2, (1, 32767)),
                    ('feedback_tracker_2_coeff', 0x57b4e, (1, 32767)),
                    ('feedback_tracker_2_clamp', 0x57b50, (1, 32767)),
                    ('command_input_clamp', 0x57bac, (1, 1774)),
                    ('d_term_clamp', 0x57bd6, (1, 32767)),
                    ('p_term_clamp', 0x57bd8, (1, 32767)),
                    ('final_output_clamp', 0x57bda, (1, 8868)),
                )
                for row in range(5)
            ]
            curve_checks = [
                (x + 0x300 * row, y + 0x300 * row, n, '{} row {}'.format(label, row))
                for label, x, y, n in (
                    ('speed_limit', 0x57b2a, 0x57b3c, 9),
                    ('override_authority_fade', 0x57b54, 0x57b64, 8),
                    ('target_map', 0x57bae, 0x57bc0, 9),
                    ('governor_e', 0x57bdc, 0x57bec, 8),
                    ('governor_f', 0x57bfc, 0x57c0c, 8),
                    ('governor_g', 0x57c1c, 0x57c28, 6),
                    ('governor_h', 0x57c34, 0x57c40, 6),
                    ('d_gain', 0x57c4c, 0x57c5e, 9),
                    ('p_gain', 0x57c70, 0x57c82, 9),
                )
                for row in range(5)
            ]
            shadow_mirrors = [
                (primary + 0x300 * row, shadow + 0x300 * row, size, '{} row {}'.format(label, row))
                for label, primary, shadow, size in (
                    ('speed_clamp_lo', 0x57b00, 0x62e00, 2),
                    ('speed_limit_x', 0x57b2a, 0x62e2e, 18),
                    ('speed_limit_y', 0x57b3c, 0x62e40, 18),
                    ('feedback_tracker_2_coeff', 0x57b4e, 0x62e56, 2),
                    ('feedback_tracker_2_clamp', 0x57b50, 0x62e58, 2),
                    ('override_authority_fade_x', 0x57b54, 0x62e5e, 16),
                    ('override_authority_fade_y', 0x57b64, 0x62e6e, 16),
                    ('command_input_clamp', 0x57bac, 0x62ec2, 2),
                    ('target_map_x', 0x57bae, 0x62ec4, 18),
                    ('target_map_y', 0x57bc0, 0x62ed6, 18),
                    ('feedback_tracker_1_coeff', 0x57bd2, 0x62ee8, 2),
                    ('feedback_tracker_1_clamp', 0x57bd4, 0x62eea, 2),
                    ('d_term_clamp', 0x57bd6, 0x62eec, 2),
                    ('p_term_clamp', 0x57bd8, 0x62eee, 2),
                    ('final_output_clamp', 0x57bda, 0x62ef0, 2),
                    ('governor_e_x', 0x57bdc, 0x62ef2, 16),
                    ('governor_e_y', 0x57bec, 0x62f02, 16),
                    ('governor_f_x', 0x57bfc, 0x62f16, 16),
                    ('governor_f_y', 0x57c0c, 0x62f26, 16),
                    ('governor_g_x', 0x57c1c, 0x62f3a, 12),
                    ('governor_g_y', 0x57c28, 0x62f46, 12),
                    ('governor_h_x', 0x57c34, 0x62f56, 12),
                    ('governor_h_y', 0x57c40, 0x62f62, 12),
                    ('d_gain_x', 0x57c4c, 0x62f72, 18),
                    ('d_gain_y', 0x57c5e, 0x62f84, 18),
                    ('p_gain_x', 0x57c70, 0x62f9a, 18),
                    ('p_gain_y', 0x57c82, 0x62fac, 18),
                )
                for row in range(5)
            ]
            # Payload geometry/checksums. The length branch already selects
            # these from the 48 37 FF FF magic at 0xC000; restated here so the
            # TJB values are on record and a change to that branch is caught.
            # Honda's own TJB-A220 rwd declares start 0xC000 / size 0x74000,
            # key 01 02 03, and the tool's -stock payload is byte-identical to it.
            #   sum  over [0xC000,0x7FF80) == 0xDA88 (stored at 0x7FF80)
            #   -sum over [0xC000,0x7FFFE) == 0x9364 (stored at 0x7FFFE)
            # Default A280-flat build: 0xF560 / 0x5DB4.
            assert (start_address, data_size) == (0xc000, 0x74000)
            start_address = 0xc000
            data_size = 0x74000
            checksum_offsets = [(0, 0x73f80), (1, 0x73ffe)]  # 0x7FF80/0x7FFFE minus 0xC000
            #
            # Calibration rows 0-4 (rows 5/6 erased, 0x59000 not a bank). Rows
            # 0-3 run in normal driving and are identical; row 4 is the mode-5
            # override. Shadows follow through shadow_mirrors.
            # A280 flat: K = [W*E+(1-W)*F]>>14 * [W*G+(1-W)*H]>>14 >> 8 (stage
            # 0x743F8); G/H are keyed on |tracker-2 rate|, the A280 role, so
            # Y = 256 removes that factor (Clarity PTM A280 Y 256). Rows 0-3
            # only; every other field is exposed at stock.
            data_offsets = [
                # speed_clamp_lo: engage speed-window minimum, 0.5 kph/count (THR FUN_00072DDC); 10 = 5 kph
                0x57b00, #speed_clamp_lo row 0
                0x57e00, #speed_clamp_lo row 1
                0x58100, #speed_clamp_lo row 2
                0x58400, #speed_clamp_lo row 3
                0x58700, #speed_clamp_lo row 4

                # speed_limit_x: command-limit speed axis, 0.5 kph/count (informational)
                0x57b2a, #speed_limit_x row 0
                0x57e2a, #speed_limit_x row 1
                0x5812a, #speed_limit_x row 2
                0x5842a, #speed_limit_x row 3
                0x5872a, #speed_limit_x row 4

                # speed_limit_y: command limit L vs speed; E4 cmd/4 clamped to +/-L
                0x57b3c, #speed_limit_y row 0
                0x57e3c, #speed_limit_y row 1
                0x5813c, #speed_limit_y row 2
                0x5843c, #speed_limit_y row 3
                0x5873c, #speed_limit_y row 4

                # feedback_tracker_2_coeff: tracker-2 one-pole k/32768 on E0 rate
                0x57b4e, #feedback_tracker_2_coeff row 0
                0x57e4e, #feedback_tracker_2_coeff row 1
                0x5814e, #feedback_tracker_2_coeff row 2
                0x5844e, #feedback_tracker_2_coeff row 3
                0x5874e, #feedback_tracker_2_coeff row 4

                # feedback_tracker_2_clamp: tracker-2 output clamp; also hard-clamps the G/H key
                0x57b50, #feedback_tracker_2_clamp row 0
                0x57e50, #feedback_tracker_2_clamp row 1
                0x58150, #feedback_tracker_2_clamp row 2
                0x58450, #feedback_tracker_2_clamp row 3
                0x58750, #feedback_tracker_2_clamp row 4

                # override_authority_fade: driver-torque authority fade applied by FUN_000741F8
                #   (THR 0x74168). As |column torque| rises the EPS fades its own assist by
                #   Y/256 (interp over X), with the engage cut at 0x57b52 (=768). This is the
                #   primary "torque dropping" on TJB: the fade collapses to 0 far earlier than
                #   the Clarity's TRW (helper governor_e below is the second half).
                #   Rows 0-3 stock Y = [256,256,166,117,62,20,0,0] over X = [0,341,518,623,
                #   735,826,889,1280]; -> <=10% authority by |T|~889. Row 4 (mode-5 override)
                #   X=[0,256,512,768,1024,1280,1536,1792] Y=[256,256,169,44,0,0,0,0] (harsher).
                #   Clarity override fade @0x13328 Y=[256,256,218,141,64,0,0,0] over
                #   X=[0,512,1024,1536,2048,2560,3072,3584] (T_tjb = T_clarity/2).
                #   Clarity-matched replacement Y (at the TJB X breakpoints, rows 0-3):
                #     [256, 243, 216, 185, 151, 124, 105, 0]
                #   Monitor shadow (mapped 2026-10-20, byte-identical all 5 rows): X primary
                #   0x57b54 -> shadow 0x62e5e, Y primary 0x57b64 -> shadow 0x62e6e, size 16,
                #   stride 0x300 (between the feedback_tracker_2_clamp 0x62e58 and
                #   command_input_clamp 0x62ec2 shadows). Both are in shadow_mirrors, so the tool
                #   copies primary->shadow on any edit and the 0x68xxx-0x6Bxxx monitors stay consistent.
                # override_authority_fade_x: fade breakpoints on |column torque| (informational)
                0x57b54, #override_authority_fade_x row 0
                0x57e54, #override_authority_fade_x row 1
                0x58154, #override_authority_fade_x row 2
                0x58454, #override_authority_fade_x row 3
                0x58754, #override_authority_fade_x row 4

                # override_authority_fade_y: authority gain, Q8 (256 = full assist, 0 = no assist)
                0x57b64, #override_authority_fade_y row 0
                0x57e64, #override_authority_fade_y row 1
                0x58164, #override_authority_fade_y row 2
                0x58464, #override_authority_fade_y row 3
                0x58764, #override_authority_fade_y row 4

                # command_input_clamp: |a| input limit before target map; hard +/-1774 after
                0x57bac, #command_input_clamp row 0
                0x57eac, #command_input_clamp row 1
                0x581ac, #command_input_clamp row 2
                0x584ac, #command_input_clamp row 3
                0x587ac, #command_input_clamp row 4

                # target_map_x: target map breakpoints on |a| (informational)
                0x57bae, #target_map_x row 0
                0x57eae, #target_map_x row 1
                0x581ae, #target_map_x row 2
                0x584ae, #target_map_x row 3
                0x587ae, #target_map_x row 4

                # target_map_y: target map s
                0x57bc0, #target_map_y row 0
                0x57ec0, #target_map_y row 1
                0x581c0, #target_map_y row 2
                0x584c0, #target_map_y row 3
                0x587c0, #target_map_y row 4

                # feedback_tracker_1_coeff: tracker-1 one-pole k/32768
                0x57bd2, #feedback_tracker_1_coeff row 0
                0x57ed2, #feedback_tracker_1_coeff row 1
                0x581d2, #feedback_tracker_1_coeff row 2
                0x584d2, #feedback_tracker_1_coeff row 3
                0x587d2, #feedback_tracker_1_coeff row 4

                # feedback_tracker_1_clamp: tracker-1 reference clamp
                0x57bd4, #feedback_tracker_1_clamp row 0
                0x57ed4, #feedback_tracker_1_clamp row 1
                0x581d4, #feedback_tracker_1_clamp row 2
                0x584d4, #feedback_tracker_1_clamp row 3
                0x587d4, #feedback_tracker_1_clamp row 4

                # d_term_clamp: D = clamp(Kd*derr>>6) (stage 0x743F8)
                0x57bd6, #d_term_clamp row 0
                0x57ed6, #d_term_clamp row 1
                0x581d6, #d_term_clamp row 2
                0x584d6, #d_term_clamp row 3
                0x587d6, #d_term_clamp row 4

                # p_term_clamp: P = clamp(Kp*err>>6) (stage 0x743F8)
                0x57bd8, #p_term_clamp row 0
                0x57ed8, #p_term_clamp row 1
                0x581d8, #p_term_clamp row 2
                0x584d8, #p_term_clamp row 3
                0x587d8, #p_term_clamp row 4

                # final_output_clamp: u = clamp(K*(P+D)>>8)
                0x57bda, #final_output_clamp row 0
                0x57eda, #final_output_clamp row 1
                0x581da, #final_output_clamp row 2
                0x584da, #final_output_clamp row 3
                0x587da, #final_output_clamp row 4

                # governor_e_x: K helper-A breakpoints on |T| (informational)
                0x57bdc, #governor_e_x row 0
                0x57edc, #governor_e_x row 1
                0x581dc, #governor_e_x row 2
                0x584dc, #governor_e_x row 3
                0x587dc, #governor_e_x row 4

                # governor_e_y: K helper-A gain, Q8 (W weight)
                0x57bec, #governor_e_y row 0
                0x57eec, #governor_e_y row 1
                0x581ec, #governor_e_y row 2
                0x584ec, #governor_e_y row 3
                0x587ec, #governor_e_y row 4

                # governor_f_x: K helper-A breakpoints on |T| (informational)
                0x57bfc, #governor_f_x row 0
                0x57efc, #governor_f_x row 1
                0x581fc, #governor_f_x row 2
                0x584fc, #governor_f_x row 3
                0x587fc, #governor_f_x row 4

                # governor_f_y: K helper-A gain, Q8 (1-W weight)
                0x57c0c, #governor_f_y row 0
                0x57f0c, #governor_f_y row 1
                0x5820c, #governor_f_y row 2
                0x5850c, #governor_f_y row 3
                0x5880c, #governor_f_y row 4

                # governor_g_x: A280 breakpoints on |tracker-2 rate|, key clamped to 320 (informational)
                0x57c1c, #governor_g_x row 0
                0x57f1c, #governor_g_x row 1
                0x5821c, #governor_g_x row 2
                0x5851c, #governor_g_x row 3
                0x5881c, #governor_g_x row 4

                # governor_g_y: A280 gain, Q8 (W weight); PTM: flat 256 rows 0-3
                0x57c28, #governor_g_y row 0
                0x57f28, #governor_g_y row 1
                0x58228, #governor_g_y row 2
                0x58528, #governor_g_y row 3
                0x58828, #governor_g_y row 4

                # governor_h_x: A280 breakpoints on |tracker-2 rate| (informational)
                0x57c34, #governor_h_x row 0
                0x57f34, #governor_h_x row 1
                0x58234, #governor_h_x row 2
                0x58534, #governor_h_x row 3
                0x58834, #governor_h_x row 4

                # governor_h_y: A280 gain, Q8 (1-W weight); PTM: flat 256 rows 0-3
                0x57c40, #governor_h_y row 0
                0x57f40, #governor_h_y row 1
                0x58240, #governor_h_y row 2
                0x58540, #governor_h_y row 3
                0x58840, #governor_h_y row 4

                # d_gain_x: Kd breakpoints (informational)
                0x57c4c, #d_gain_x row 0
                0x57f4c, #d_gain_x row 1
                0x5824c, #d_gain_x row 2
                0x5854c, #d_gain_x row 3
                0x5884c, #d_gain_x row 4

                # d_gain_y: Kd, applied >>6
                0x57c5e, #d_gain_y row 0
                0x57f5e, #d_gain_y row 1
                0x5825e, #d_gain_y row 2
                0x5855e, #d_gain_y row 3
                0x5885e, #d_gain_y row 4

                # p_gain_x: Kp breakpoints on |a| (informational)
                0x57c70, #p_gain_x row 0
                0x57f70, #p_gain_x row 1
                0x58270, #p_gain_x row 2
                0x58570, #p_gain_x row 3
                0x58870, #p_gain_x row 4

                # p_gain_y: Kp, applied >>6
                0x57c82, #p_gain_y row 0
                0x57f82, #p_gain_y row 1
                0x58282, #p_gain_y row 2
                0x58582, #p_gain_y row 3
                0x58882, #p_gain_y row 4
                ]
            data_old = [
                # speed_clamp_lo
                '0x000a', #speed_clamp_lo row 0
                '0x000a', #speed_clamp_lo row 1
                '0x000a', #speed_clamp_lo row 2
                '0x000a', #speed_clamp_lo row 3
                '0x0046', #speed_clamp_lo row 4

                # speed_limit_x
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 0
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 1
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 2
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 3
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 4

                # speed_limit_y
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 0
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 1
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 2
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 3
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 4

                # feedback_tracker_2_coeff
                '0x0222', #feedback_tracker_2_coeff row 0
                '0x0222', #feedback_tracker_2_coeff row 1
                '0x0222', #feedback_tracker_2_coeff row 2
                '0x0222', #feedback_tracker_2_coeff row 3
                '0x655f', #feedback_tracker_2_coeff row 4

                # feedback_tracker_2_clamp
                '0x0140', #feedback_tracker_2_clamp row 0
                '0x0140', #feedback_tracker_2_clamp row 1
                '0x0140', #feedback_tracker_2_clamp row 2
                '0x0140', #feedback_tracker_2_clamp row 3
                '0x0140', #feedback_tracker_2_clamp row 4

                # override_authority_fade_x
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 0
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 1
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 2
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 3
                '0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700', #override_authority_fade_x row 4

                # override_authority_fade_y
                '0x0100, 0x0100, 0x00a6, 0x0075, 0x003e, 0x0014, 0x0000, 0x0000', #override_authority_fade_y row 0
                '0x0100, 0x0100, 0x00a6, 0x0075, 0x003e, 0x0014, 0x0000, 0x0000', #override_authority_fade_y row 1
                '0x0100, 0x0100, 0x00a6, 0x0075, 0x003e, 0x0014, 0x0000, 0x0000', #override_authority_fade_y row 2
                '0x0100, 0x0100, 0x00a6, 0x0075, 0x003e, 0x0014, 0x0000, 0x0000', #override_authority_fade_y row 3
                '0x0100, 0x0100, 0x00a9, 0x002c, 0x0000, 0x0000, 0x0000, 0x0000', #override_authority_fade_y row 4

                # command_input_clamp
                '0x0400', #command_input_clamp row 0
                '0x0400', #command_input_clamp row 1
                '0x0400', #command_input_clamp row 2
                '0x0400', #command_input_clamp row 3
                '0x0400', #command_input_clamp row 4

                # target_map_x
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 0
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 1
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 2
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 3
                '0x0000, 0x00de, 0x01bb, 0x0299, 0x0377, 0x0455, 0x0532, 0x0610, 0x06ee', #target_map_x row 4

                # target_map_y
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 0
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 1
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 2
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 3
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', #target_map_y row 4

                # feedback_tracker_1_coeff
                '0x019a', #feedback_tracker_1_coeff row 0
                '0x019a', #feedback_tracker_1_coeff row 1
                '0x019a', #feedback_tracker_1_coeff row 2
                '0x019a', #feedback_tracker_1_coeff row 3
                '0x759e', #feedback_tracker_1_coeff row 4

                # feedback_tracker_1_clamp
                '0x7ffd', #feedback_tracker_1_clamp row 0
                '0x7ffd', #feedback_tracker_1_clamp row 1
                '0x7ffd', #feedback_tracker_1_clamp row 2
                '0x7ffd', #feedback_tracker_1_clamp row 3
                '0x7ffd', #feedback_tracker_1_clamp row 4

                # d_term_clamp
                '0x0280', #d_term_clamp row 0
                '0x0280', #d_term_clamp row 1
                '0x0280', #d_term_clamp row 2
                '0x0280', #d_term_clamp row 3
                '0x0280', #d_term_clamp row 4

                # p_term_clamp
                '0x0400', #p_term_clamp row 0
                '0x0400', #p_term_clamp row 1
                '0x0400', #p_term_clamp row 2
                '0x0400', #p_term_clamp row 3
                '0x0400', #p_term_clamp row 4

                # final_output_clamp
                '0x0400', #final_output_clamp row 0
                '0x0400', #final_output_clamp row 1
                '0x0400', #final_output_clamp row 2
                '0x0400', #final_output_clamp row 3
                '0x0400', #final_output_clamp row 4

                # governor_e_x
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 0
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 1
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 2
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 3
                '0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700', #governor_e_x row 4

                # governor_e_y
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 0
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 1
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 2
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 3
                '0x0100, 0x0100, 0x00a9, 0x005a, 0x0031, 0x0031, 0x0031, 0x0031', #governor_e_y row 4

                # governor_f_x
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 0
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 1
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 2
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 3
                '0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700', #governor_f_x row 4

                # governor_f_y
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 0
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 1
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 2
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 3
                '0x0100, 0x0100, 0x00a9, 0x005a, 0x0031, 0x0031, 0x0031, 0x0031', #governor_f_y row 4

                # governor_g_x
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 0
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 1
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 2
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 3
                '0x0000, 0x0040, 0x0080, 0x00c0, 0x0100, 0x0140', #governor_g_x row 4

                # governor_g_y
                '0x0100, 0x0100, 0x0066, 0x0066, 0x0066, 0x0066', #governor_g_y row 0
                '0x0100, 0x0100, 0x0066, 0x0066, 0x0066, 0x0066', #governor_g_y row 1
                '0x0100, 0x0100, 0x0066, 0x0066, 0x0066, 0x0066', #governor_g_y row 2
                '0x0100, 0x0100, 0x0066, 0x0066, 0x0066, 0x0066', #governor_g_y row 3
                '0x0100, 0x0100, 0x00e6, 0x00c8, 0x00a9, 0x0094', #governor_g_y row 4

                # governor_h_x
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 0
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 1
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 2
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 3
                '0x0000, 0x0040, 0x0080, 0x00c0, 0x0100, 0x0140', #governor_h_x row 4

                # governor_h_y
                '0x0100, 0x0100, 0x0066, 0x004d, 0x004d, 0x004d', #governor_h_y row 0
                '0x0100, 0x0100, 0x0066, 0x004d, 0x004d, 0x004d', #governor_h_y row 1
                '0x0100, 0x0100, 0x0066, 0x004d, 0x004d, 0x004d', #governor_h_y row 2
                '0x0100, 0x0100, 0x0066, 0x004d, 0x004d, 0x004d', #governor_h_y row 3
                '0x0100, 0x0100, 0x00e6, 0x00c8, 0x00a9, 0x0094', #governor_h_y row 4

                # d_gain_x
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 0
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 1
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 2
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 3
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 4

                # d_gain_y
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 0
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 1
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 2
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 3
                '0x000a, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010', #d_gain_y row 4

                # p_gain_x
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 0
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 1
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 2
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 3
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #p_gain_x row 4

                # p_gain_y
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 0
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 1
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 2
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 3
                '0x0002, 0x0006, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 4
                ]
            data_new = [
                # speed_clamp_lo
                '0x000a', #speed_clamp_lo row 0
                '0x000a', #speed_clamp_lo row 1
                '0x000a', #speed_clamp_lo row 2
                '0x000a', #speed_clamp_lo row 3
                '0x0046', #speed_clamp_lo row 4

                # speed_limit_x
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 0
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 1
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 2
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 3
                '0x0000, 0x0032, 0x0064, 0x0096, 0x00c8, 0x00fa, 0x012c, 0x015e, 0x0190', #speed_limit_x row 4

                # speed_limit_y
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 0
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 1
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 2
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 3
                '0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400', #speed_limit_y row 4

                # feedback_tracker_2_coeff
                '0x0222', #feedback_tracker_2_coeff row 0
                '0x0222', #feedback_tracker_2_coeff row 1
                '0x0222', #feedback_tracker_2_coeff row 2
                '0x0222', #feedback_tracker_2_coeff row 3
                '0x655f', #feedback_tracker_2_coeff row 4

                # feedback_tracker_2_clamp
                '0x0140', #feedback_tracker_2_clamp row 0
                '0x0140', #feedback_tracker_2_clamp row 1
                '0x0140', #feedback_tracker_2_clamp row 2
                '0x0140', #feedback_tracker_2_clamp row 3
                '0x0140', #feedback_tracker_2_clamp row 4

                # override_authority_fade_x
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 0
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 1
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 2
                '0x0000, 0x0155, 0x0206, 0x026f, 0x02df, 0x033a, 0x0379, 0x0500', #override_authority_fade_x row 3
                '0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700', #override_authority_fade_x row 4

                # override_authority_fade_y
                '0x0100, 0x00f3, 0x00d8, 0x00b9, 0x0097, 0x007c, 0x0069, 0x0000', #override_authority_fade_y row 0
                '0x0100, 0x00f3, 0x00d8, 0x00b9, 0x0097, 0x007c, 0x0069, 0x0000', #override_authority_fade_y row 1
                '0x0100, 0x00f3, 0x00d8, 0x00b9, 0x0097, 0x007c, 0x0069, 0x0000', #override_authority_fade_y row 2
                '0x0100, 0x00f3, 0x00d8, 0x00b9, 0x0097, 0x007c, 0x0069, 0x0000', #override_authority_fade_y row 3
                '0x0100, 0x0100, 0x00da, 0x008d, 0x0040, 0x0000, 0x0000, 0x0000', #override_authority_fade_y row 4

                # command_input_clamp
                '0x0400', #command_input_clamp row 0
                '0x0400', #command_input_clamp row 1
                '0x0400', #command_input_clamp row 2
                '0x0400', #command_input_clamp row 3
                '0x0400', #command_input_clamp row 4

                # target_map_x
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 0
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 1
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 2
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #target_map_x row 3
                '0x0000, 0x00de, 0x01bb, 0x0299, 0x0377, 0x0455, 0x0532, 0x0610, 0x06ee', #target_map_x row 4

                # target_map_y
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 0
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 1
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 2
                '0x0000, 0x07cd, 0x0c80, 0x0f00, 0x1000, 0x1100, 0x1100, 0x1100, 0x1100', #target_map_y row 3
                '0x0000, 0x06b3, 0x0b1a, 0x0ccd, 0x0e9a, 0x104d, 0x119a, 0x11da, 0x11da', #target_map_y row 4

                # feedback_tracker_1_coeff
                '0x019a', #feedback_tracker_1_coeff row 0
                '0x019a', #feedback_tracker_1_coeff row 1
                '0x019a', #feedback_tracker_1_coeff row 2
                '0x019a', #feedback_tracker_1_coeff row 3
                '0x759e', #feedback_tracker_1_coeff row 4

                # feedback_tracker_1_clamp
                '0x7ffd', #feedback_tracker_1_clamp row 0
                '0x7ffd', #feedback_tracker_1_clamp row 1
                '0x7ffd', #feedback_tracker_1_clamp row 2
                '0x7ffd', #feedback_tracker_1_clamp row 3
                '0x7ffd', #feedback_tracker_1_clamp row 4

                # d_term_clamp
                '0x0280', #d_term_clamp row 0
                '0x0280', #d_term_clamp row 1
                '0x0280', #d_term_clamp row 2
                '0x0280', #d_term_clamp row 3
                '0x0280', #d_term_clamp row 4

                # p_term_clamp
                '0x0400', #p_term_clamp row 0
                '0x0400', #p_term_clamp row 1
                '0x0400', #p_term_clamp row 2
                '0x0400', #p_term_clamp row 3
                '0x0400', #p_term_clamp row 4

                # final_output_clamp
                '0x0400', #final_output_clamp row 0
                '0x0400', #final_output_clamp row 1
                '0x0400', #final_output_clamp row 2
                '0x0400', #final_output_clamp row 3
                '0x0400', #final_output_clamp row 4

                # governor_e_x
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 0
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 1
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 2
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_e_x row 3
                '0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700', #governor_e_x row 4

                # governor_e_y
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 0
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 1
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 2
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_e_y row 3
                '0x0100, 0x0100, 0x00a9, 0x005a, 0x0031, 0x0031, 0x0031, 0x0031', #governor_e_y row 4

                # governor_f_x
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 0
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 1
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 2
                '0x0000, 0x00b6, 0x0103, 0x012d, 0x0181, 0x0237, 0x02ca, 0x032c', #governor_f_x row 3
                '0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700', #governor_f_x row 4

                # governor_f_y
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 0
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 1
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 2
                '0x0100, 0x0100, 0x0100, 0x00f7, 0x00d6, 0x007e, 0x0033, 0x0000', #governor_f_y row 3
                '0x0100, 0x0100, 0x00a9, 0x005a, 0x0031, 0x0031, 0x0031, 0x0031', #governor_f_y row 4

                # governor_g_x
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 0
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 1
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 2
                '0x0000, 0x0018, 0x0110, 0x0120, 0x0130, 0x0140', #governor_g_x row 3
                '0x0000, 0x0040, 0x0080, 0x00c0, 0x0100, 0x0140', #governor_g_x row 4

                # governor_g_y
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_g_y row 0
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_g_y row 1
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_g_y row 2
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_g_y row 3
                '0x0100, 0x0100, 0x00e6, 0x00c8, 0x00a9, 0x0094', #governor_g_y row 4

                # governor_h_x
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 0
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 1
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 2
                '0x0000, 0x0010, 0x00a0, 0x00c0, 0x0100, 0x0140', #governor_h_x row 3
                '0x0000, 0x0040, 0x0080, 0x00c0, 0x0100, 0x0140', #governor_h_x row 4

                # governor_h_y
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_h_y row 0
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_h_y row 1
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_h_y row 2
                '0x0100, 0x0100, 0x0100, 0x0100, 0x0100, 0x0100', #governor_h_y row 3
                '0x0100, 0x0100, 0x00e6, 0x00c8, 0x00a9, 0x0094', #governor_h_y row 4

                # d_gain_x
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 0
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 1
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 2
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 3
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #d_gain_x row 4

                # d_gain_y
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 0
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 1
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 2
                '0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0010, 0x0010, 0x0010', #d_gain_y row 3
                '0x000a, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010', #d_gain_y row 4

                # p_gain_x
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 0
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 1
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 2
                '0x0000, 0x003a, 0x006d, 0x00f3, 0x0140, 0x01c0, 0x0280, 0x0380, 0x0400', #p_gain_x row 3
                '0x0000, 0x0080, 0x0100, 0x0180, 0x0200, 0x0280, 0x0300, 0x0380, 0x0400', #p_gain_x row 4

                # p_gain_y
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 0
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 1
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 2
                '0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 3
                '0x0002, 0x0006, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009', #p_gain_y row 4
                ]
            data_label = [
                # speed_clamp_lo
                'speed_clamp_lo row 0',
                'speed_clamp_lo row 1',
                'speed_clamp_lo row 2',
                'speed_clamp_lo row 3',
                'speed_clamp_lo row 4',

                # speed_limit_x
                'speed_limit_x row 0',
                'speed_limit_x row 1',
                'speed_limit_x row 2',
                'speed_limit_x row 3',
                'speed_limit_x row 4',

                # speed_limit_y
                'speed_limit_y row 0',
                'speed_limit_y row 1',
                'speed_limit_y row 2',
                'speed_limit_y row 3',
                'speed_limit_y row 4',

                # feedback_tracker_2_coeff
                'feedback_tracker_2_coeff row 0',
                'feedback_tracker_2_coeff row 1',
                'feedback_tracker_2_coeff row 2',
                'feedback_tracker_2_coeff row 3',
                'feedback_tracker_2_coeff row 4',

                # feedback_tracker_2_clamp
                'feedback_tracker_2_clamp row 0',
                'feedback_tracker_2_clamp row 1',
                'feedback_tracker_2_clamp row 2',
                'feedback_tracker_2_clamp row 3',
                'feedback_tracker_2_clamp row 4',

                # override_authority_fade_x
                'override_authority_fade_x row 0',
                'override_authority_fade_x row 1',
                'override_authority_fade_x row 2',
                'override_authority_fade_x row 3',
                'override_authority_fade_x row 4',

                # override_authority_fade_y
                'override_authority_fade_y row 0',
                'override_authority_fade_y row 1',
                'override_authority_fade_y row 2',
                'override_authority_fade_y row 3',
                'override_authority_fade_y row 4',

                # command_input_clamp
                'command_input_clamp row 0',
                'command_input_clamp row 1',
                'command_input_clamp row 2',
                'command_input_clamp row 3',
                'command_input_clamp row 4',

                # target_map_x
                'target_map_x row 0',
                'target_map_x row 1',
                'target_map_x row 2',
                'target_map_x row 3',
                'target_map_x row 4',

                # target_map_y
                'target_map_y row 0',
                'target_map_y row 1',
                'target_map_y row 2',
                'target_map_y row 3',
                'target_map_y row 4',

                # feedback_tracker_1_coeff
                'feedback_tracker_1_coeff row 0',
                'feedback_tracker_1_coeff row 1',
                'feedback_tracker_1_coeff row 2',
                'feedback_tracker_1_coeff row 3',
                'feedback_tracker_1_coeff row 4',

                # feedback_tracker_1_clamp
                'feedback_tracker_1_clamp row 0',
                'feedback_tracker_1_clamp row 1',
                'feedback_tracker_1_clamp row 2',
                'feedback_tracker_1_clamp row 3',
                'feedback_tracker_1_clamp row 4',

                # d_term_clamp
                'd_term_clamp row 0',
                'd_term_clamp row 1',
                'd_term_clamp row 2',
                'd_term_clamp row 3',
                'd_term_clamp row 4',

                # p_term_clamp
                'p_term_clamp row 0',
                'p_term_clamp row 1',
                'p_term_clamp row 2',
                'p_term_clamp row 3',
                'p_term_clamp row 4',

                # final_output_clamp
                'final_output_clamp row 0',
                'final_output_clamp row 1',
                'final_output_clamp row 2',
                'final_output_clamp row 3',
                'final_output_clamp row 4',

                # governor_e_x
                'governor_e_x row 0',
                'governor_e_x row 1',
                'governor_e_x row 2',
                'governor_e_x row 3',
                'governor_e_x row 4',

                # governor_e_y
                'governor_e_y row 0',
                'governor_e_y row 1',
                'governor_e_y row 2',
                'governor_e_y row 3',
                'governor_e_y row 4',

                # governor_f_x
                'governor_f_x row 0',
                'governor_f_x row 1',
                'governor_f_x row 2',
                'governor_f_x row 3',
                'governor_f_x row 4',

                # governor_f_y
                'governor_f_y row 0',
                'governor_f_y row 1',
                'governor_f_y row 2',
                'governor_f_y row 3',
                'governor_f_y row 4',

                # governor_g_x
                'governor_g_x row 0',
                'governor_g_x row 1',
                'governor_g_x row 2',
                'governor_g_x row 3',
                'governor_g_x row 4',

                # governor_g_y
                'governor_g_y row 0',
                'governor_g_y row 1',
                'governor_g_y row 2',
                'governor_g_y row 3',
                'governor_g_y row 4',

                # governor_h_x
                'governor_h_x row 0',
                'governor_h_x row 1',
                'governor_h_x row 2',
                'governor_h_x row 3',
                'governor_h_x row 4',

                # governor_h_y
                'governor_h_y row 0',
                'governor_h_y row 1',
                'governor_h_y row 2',
                'governor_h_y row 3',
                'governor_h_y row 4',

                # d_gain_x
                'd_gain_x row 0',
                'd_gain_x row 1',
                'd_gain_x row 2',
                'd_gain_x row 3',
                'd_gain_x row 4',

                # d_gain_y
                'd_gain_y row 0',
                'd_gain_y row 1',
                'd_gain_y row 2',
                'd_gain_y row 3',
                'd_gain_y row 4',

                # p_gain_x
                'p_gain_x row 0',
                'p_gain_x row 1',
                'p_gain_x row 2',
                'p_gain_x row 3',
                'p_gain_x row 4',

                # p_gain_y
                'p_gain_y row 0',
                'p_gain_y row 1',
                'p_gain_y row 2',
                'p_gain_y row 3',
                'p_gain_y row 4',
                ]
            # Clarity-match (Option B; mirrors tools/build.py and verified against the Clarity's own
            # interp over pointer sets 0x45BDC/0x45BEC): set the override fade (Y1 and its 1-W twin Y2)
            # and the helper (governor_e/f, W and 1-W) X and Y to the Clarity grid at the /2 torque
            # scale, on rows 0-3 (normal driving). Row 4 (the mode-5 override row) stays stock.
            _ov_x = '0x0000, 0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700'
            _ov_y = '0x0100, 0x0100, 0x00da, 0x008d, 0x0040, 0x0000, 0x0000, 0x0000'
            _he_x = '0x0000, 0x0080, 0x0130, 0x019a, 0x0200, 0x029a, 0x0380, 0x0700'
            _he_y = '0x0100, 0x00fb, 0x00f3, 0x00e6, 0x00da, 0x00a6, 0x0031, 0x0031'
            for _lbl, _val in (
                    ('override_authority_fade_x', _ov_x), ('override_authority_fade_y', _ov_y),
                    ('governor_e_x', _he_x), ('governor_e_y', _he_y),
                    ('governor_f_x', _he_x), ('governor_f_y', _he_y)):
                for _r in range(4):
                    data_new[data_label.index('{} row {}'.format(_lbl, _r))] = _val
            data_new[data_label.index('override_authority_fade_y row 4')] = \
                words_string(input_bin, 0x58764, 8)
            # Catalog + match the override 1-W companion X2 (0x57b74) / Y2 (0x57b84), which were not
            # previously exposed. Appended to all lists in lockstep so alignment holds by construction;
            # data_old reads the stock bytes from the input so the write-time verify passes.
            for _nm, _po, _sho, _mx in (
                    ('override_fade_x2', 0x57b74, 0x62e82, _ov_x),
                    ('override_fade_y2', 0x57b84, 0x62e92, _ov_y)):
                for _r in range(5):
                    _off = _po + 0x300 * _r
                    data_offsets.append(_off)
                    data_old.append(words_string(input_bin, _off, 8))
                    data_new.append(_mx if _r < 4 else words_string(input_bin, _off, 8))
                    data_label.append('{} row {}'.format(_nm, _r))
                    shadow_mirrors.append((_off, _sho + 0x300 * _r, 16, '{} row {}'.format(_nm, _r)))
        else:
             print('unsupported fw')
             sys.exit()


## do patch
    if args.stock:
        print('Patch bypassed, making stock RWD')
        with open(os.path.join(sys.path[0], "user.bin"), 'rb+') as f:
            full_fw = f.read()
            patch_fw = full_fw[start_address:(start_address + data_size)]
    else:
        with open(os.path.join(sys.path[0], "user_patched.bin"), 'wb+') as output_bin:
            output_bin.write(input_bin)
            for version_offset in version_offsets:
                output_bin.seek(version_offset)
                #validate original version
                version_old_actual = output_bin.read(int(len(version_old)))
                assert version_old_actual == version_old, 'Check fw version at offset {}: expected {} but found {}'.format(hex(version_offset), version_old, version_old_actual.decode())
                #validate new version length
                assert len(version_old) == len(version_new), 'New fw version length error. {} is {} bytes, {} is {} bytes.'.format(version_old, len(version_old), version_new, len(version_new))
                output_bin.seek(version_offset)
                output_bin.write(version_new)
            print("Update fw version at offsets {}:".format(', '.join(hex(x) for x in version_offsets)))
            print("  Old Data: {}".format(version_old.decode()))
            print("  New Data: {}".format(version_new.decode()))
            assert len(data_offsets) == len(data_old) == len(data_new) == len(data_label), 'Number of data items mismatch!'
            #reject a repeated offset. Two entries for one address silently fight:
            #the first is skipped when old == new, then the second writes, so the
            #field ends up at a value neither entry appears to request.
            _dupes = sorted({hex(o) for o in data_offsets if data_offsets.count(o) > 1})
            assert not _dupes, 'Duplicate data_offsets entries: {}'.format(', '.join(_dupes))
            #validate controller fields as they arrived in the input bin
            check_controller_guards(input_bin, controller_guards, 'input bin')
            check_curve_slopes(input_bin, curve_checks, 'input bin')
            for data_offsets, data_old, data_new, data_label in zip(data_offsets, data_old, data_new, data_label):
                if data_new != data_old:
                    data_old_bytes = param_to_data_string(data_old)
                    data_new_bytes = param_to_data_string(data_new)
                    #validate patch width in bytes, not in source-string characters
                    assert len(data_old_bytes) == len(data_new_bytes), '{} data length error. {} is {} bytes, {} is {} bytes'.format(data_label, data_old, len(data_old_bytes), data_new, len(data_new_bytes))
                    output_bin.seek(data_offsets)
                    #validate original data
                    data_old_actual = output_bin.read(len(data_old_bytes))
                    assert data_old_actual == data_old_bytes, 'Check {} at offset {}: expected {} but found {}'.format(data_label, hex(data_offsets), str(data_old_bytes), str(data_old_actual))
                    output_bin.seek(data_offsets)
                    output_bin.write(data_new_bytes)
                    print("Update {} at offset {}:".format(data_label, hex(data_offsets)))
                    print("  Old Data: {}".format(str(data_old)))
                    print("  New Data: {}".format(str(data_new)))
                else:
                    #exposed but deliberately left at stock; say so rather than
                    #silently skipping, so an unapplied field is not mistaken
                    #for an applied one
                    print("Keep {} at offset {} unchanged (stock): {}".format(data_label, hex(data_offsets), str(data_old)))
            # Re-read what was actually written, add any hash-gated code hook,
            # and re-validate the complete image before checksums.
            output_bin.seek(0)
            patched_full = bytearray(output_bin.read())
            if feedforward_kff is not None:
                apply_feedforward_patch(
                    patched_full, input_bin, car_model, feedforward_kff)
                output_bin.seek(0)
                output_bin.write(patched_full)
                print(
                    'Install verified {} FF{} hook at {} with cave {}'.format(
                        car_model, feedforward_kff,
                        hex(FEEDFORWARD_SITES[car_model]['hook']),
                        hex(FEEDFORWARD_SITES[car_model]['cave'])))
            if shadow_mirrors:
                apply_shadow_mirrors(patched_full, input_bin, shadow_mirrors)
                output_bin.seek(0)
                output_bin.write(patched_full)
            check_controller_guards(
                bytes(patched_full), controller_guards, 'patched bin')
            check_curve_slopes(bytes(patched_full), curve_checks, 'patched bin')
            if rom_crc_regions:
                apply_rom_crcs(patched_full, input_bin, rom_crc_regions)
                output_bin.seek(0)
                output_bin.write(patched_full)
            output_bin.seek(start_address)
            patch_fw = output_bin.read(data_size)
            for func_idx, off in checksum_offsets:
                old_checksum = struct.unpack('!H', patch_fw[off:off+2])[0]
                new_checksum = checksum_funcs[func_idx](patch_fw, 0, off) & 0xFFFF
                if new_checksum != old_checksum:
                    print('Update checksum at offset {} from {} to {}'.format(hex(off),  hex(old_checksum), hex(new_checksum)))
                    patch_fw = patch_fw[:off] + struct.pack('!H', new_checksum & 0xFFFF) + patch_fw[off+2:]
            output_bin.seek(start_address)
            output_bin.write(patch_fw)
            #validate patched fw length
            output_bin.seek(0)
            new_fw = output_bin.read()
            output_bin_hash = hashlib.md5(new_fw).hexdigest()
            with open(os.path.join(sys.path[0], "user.bin"), 'rb') as input_bin:
                old_fw = input_bin.read()
                assert len(new_fw) == len(old_fw), 'New fw length error. Old:{}, New:{}'.format(len(old_fw), len(new_fw))
        print('Patch done, hash = {}. Saved to rwd-xray/tools/user_patched.bin Encrypting...'.format(output_bin_hash))


## do encryption
    encrypt_lookup_table = {}
    for k, v in default_decrypt_lookup_table.items():
        encrypt_lookup_table[v] = k
    encrypted = bytearray()
    for b in patch_fw:
        encrypted.append(encrypt_lookup_table[b])
    with open(os.path.join(sys.path[0], "user_patched.enc"), 'wb') as encrypted_bin_out:
        encrypted_bin_out.write(encrypted)
        encrypted_bin_hash = hashlib.md5(encrypted).hexdigest()
        print('Encryption done, hash = {}. Saved to rwd-xray/tools/user_patched.enc Building RWD...'.format(encrypted_bin_hash))


## build rwd
    start_addr = param_to_data_string(hex(start_address))
    data_siz = param_to_data_string(hex(data_size))

    indicator = '\x5A\x0D\x0A' # CAN format
    headers = [
        ['\x00'], # always zero
        [], # always empty
        ['\x30'], # significant byte in 29 bit addr (0x18da__f1)
        supported_versions, # previous firmware version(s)
        security_key, # security access key (one per prev firmware version)
        ['\x01\x02\x03'], # firmware encryption key
    ]

    for i in range(len(headers)):
        print('[Header {}]: {}'.format(i, headers[i]))

    rwd_header_bytes = generate_file_header(indicator, headers)

    rwd_start_len = start_addr.rjust(4, b'\x00') + data_siz.rjust(4, b'\x00')
    file_checksum = sum(rwd_header_bytes.encode()+rwd_start_len+encrypted) & 0xFFFFFFFF

    print('File checksum: {}'.format(hex(file_checksum)))
    rwd_checksum_bytes = struct.pack('<L', file_checksum)

    if args.stock:
        out_rwd_path = os.path.join(sys.path[0], "user.rwd")
    else:
        out_rwd_path = os.path.join(sys.path[0], "user_patched.rwd")
    with open(out_rwd_path, 'wb+') as f:
        f.write(rwd_header_bytes.encode())
        f.write(rwd_start_len)
        f.write(encrypted)
        f.write(rwd_checksum_bytes)
        rwd_hash = hashlib.md5(rwd_header_bytes.encode()+rwd_start_len+encrypted+rwd_checksum_bytes).hexdigest()
        print('RWD built, hash = {}. Saved to {}'.format(rwd_hash, out_rwd_path))
    print("Done!")


main()
