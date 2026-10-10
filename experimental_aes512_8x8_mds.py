#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Required Notice: Copyright © 2026. Commercial use requires a separate license from the repository owner.
"""Educational 512-bit Rijndael-inspired cipher using an 8x8 byte state.
EXPERIMENTAL: not standard AES and not for real secrets.
"""
import argparse, hashlib, secrets

SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]


ROWS = 8
COLS = 8
BLOCK_BYTES = KEY_BYTES = 64
ROUNDS = 30
VERSION = "0.2.0"

def _bytes64(value, name):
    """Snapshot mutable buffers and enforce the public primitive contract."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes, bytearray, or memoryview")
    value = bytes(value)
    if len(value) != 64:
        raise ValueError(f"{name} must contain exactly 64 bytes")
    return value
# Distinct cyclic row rotations for the 8x8 state.
SHIFT_OFFSETS = [0, 1, 3, 4, 5, 7, 2, 6]

def show(label, s):
    print("\n" + label)
    for row in range(ROWS):
        print("  " + " ".join(f"{s[ROWS*c + row]:02x}" for c in range(COLS)))

def mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11b if a & 0x80 else 0)) & 0xff
        b >>= 1
    return result

def gf_pow(a, n):
    if not isinstance(n, int) or n < 0:
        raise ValueError("exponent must be a nonnegative integer")
    out = 1
    while n:
        if n & 1:
            out = mul(out, a)
        a = mul(a, a)
        n >>= 1
    return out

def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    return gf_pow(a, 254)

# 8x8 Cauchy matrix over GF(2^8).
# x_i and y_j are pairwise distinct and disjoint.
# Every square minor is nonsingular, so this is MDS.
# Optimal byte-level branch number = 8 + 1 = 9.
_X = list(range(0x00, 0x08))
_Y = list(range(0x08, 0x10))
MIX_MATRIX = [[gf_inv(x ^ y) for y in _Y] for x in _X]

def _inverse_matrix(matrix):
    a = [row[:] + [int(i == j) for j in range(8)]
         for i, row in enumerate(matrix)]
    for col in range(8):
        pivot = next(i for i in range(col, 8) if a[i][col])
        a[col], a[pivot] = a[pivot], a[col]
        scale = gf_inv(a[col][col])
        a[col] = [mul(x, scale) for x in a[col]]
        for row in range(8):
            if row != col:
                factor = a[row][col]
                a[row] = [x ^ mul(factor, y) for x, y in zip(a[row], a[col])]
    return [row[8:] for row in a]

INV_MIX_MATRIX = _inverse_matrix(MIX_MATRIX)
INV_SBOX = [0] * 256
for _i, _value in enumerate(SBOX):
    INV_SBOX[_value] = _i

def inverse_shift(s):
    t = s[:]
    for row, offset in enumerate(SHIFT_OFFSETS):
        for col in range(COLS):
            t[ROWS*col + row] = s[ROWS*((col - offset) % COLS) + row]
    return t

def inverse_mix(s):
    t = [0] * 64
    for col in range(COLS):
        for row in range(ROWS):
            for k in range(ROWS):
                t[ROWS*col + row] ^= mul(INV_MIX_MATRIX[row][k], s[ROWS*col + k])
    return t

def shift(s):
    t = s[:]
    for row, offset in enumerate(SHIFT_OFFSETS):
        for c in range(COLS):
            t[ROWS*c + row] = s[ROWS*((c + offset) % COLS) + row]
    return t

def mix(s):
    t = [0] * 64
    for c in range(COLS):
        col = s[c*ROWS:(c+1)*ROWS]
        mixed = []
        for r in range(ROWS):
            v = 0
            for k in range(ROWS):
                v ^= mul(MIX_MATRIX[r][k], col[k])
            mixed.append(v)
        t[c*ROWS:(c+1)*ROWS] = mixed
    return t

def round_key(key, r):
    key = _bytes64(key, "key")
    if type(r) is not int:
        raise TypeError("round must be an integer")
    if not 0 <= r <= ROUNDS:
        raise ValueError("round must be between 0 and 30")
    return list(hashlib.shake_256(
        b"EXPERIMENTAL-AES512-ROUNDKEY-8x8-v1" + key + r.to_bytes(2, "big")
    ).digest(64))

def encrypt_block(block, key, trace=False, steps=False):
    block = _bytes64(block, "block")
    key = _bytes64(key, "key")
    state = list(block)
    rk = round_key(key, 0)
    state = [x ^ y for x, y in zip(state, rk)]
    if trace:
        show("ROUND 0: AddRoundKey", state)

    for r in range(1, 31):
        if trace:
            print(f"\n========== ROUND {r}/30 ==========")

        before = state[:]
        state = [SBOX[b] for b in state]
        if trace and steps:
            print("SubBytes:", " ".join(
                f"S[{x:02x}]={y:02x}" for x, y in zip(before, state)
            ))
        if trace:
            show("SubBytes", state)

        state = shift(state)
        if trace:
            show(f"ShiftRows {SHIFT_OFFSETS}", state)

        if r != 30:
            if trace and steps:
                col = state[:8]
                terms = [f"{MIX_MATRIX[0][k]:02x}*{col[k]:02x}" for k in range(8)]
                first = 0
                for k in range(8):
                    first ^= mul(MIX_MATRIX[0][k], col[k])
                print("Mix8 first byte:", " XOR ".join(terms), f"= {first:02x} in GF(2^8)")
            state = mix(state)
            if trace:
                show("MixColumns8", state)

        rk = round_key(key, r)
        if trace and steps:
            print("AddRoundKey:", " ".join(
                f"{x:02x}^{y:02x}={x^y:02x}" for x, y in zip(state, rk)
            ))
        state = [x ^ y for x, y in zip(state, rk)]
        if trace:
            show("AddRoundKey", state)

    return bytes(state)

def decrypt_block(block, key):
    """Invert one exact 64-byte block; no mode, padding, or authentication."""
    block = _bytes64(block, "block")
    key = _bytes64(key, "key")
    state = list(block)
    for r in range(ROUNDS, 0, -1):
        state = [x ^ y for x, y in zip(state, round_key(key, r))]
        if r != ROUNDS:
            state = inverse_mix(state)
        state = inverse_shift(state)
        state = [INV_SBOX[x] for x in state]
    return bytes(x ^ y for x, y in zip(state, round_key(key, 0)))

def main():
    p = argparse.ArgumentParser(description="Educational Experimental Candidate 512-bit 8x8 matrix visualizer")
    p.add_argument("message", nargs="?", default="Hello test!")
    p.add_argument("--steps", action="store_true", help="Print byte-by-byte operations")
    p.add_argument("--trace", action="store_true", help="Print internal states (reveals secret material)")
    p.add_argument("--show-key", action="store_true", help="Explicitly reveal demo key and permit debug output")
    p.add_argument("--avalanche", action="store_true",
                   help="Flip one input bit and report final avalanche distance")
    p.add_argument("--bit", type=int, default=0,
                   help="Input bit 0..511 used by --avalanche")
    a = p.parse_args()
    if (a.trace or a.steps) and not a.show_key:
        p.error("--trace/--steps require --show-key: debug output reveals secret material")
    if a.avalanche and not 0 <= a.bit < 512:
        p.error("--bit must be between 0 and 511")

    data = a.message.encode("utf-8")
    if len(data) > 63:
        p.error("Message must be at most 63 UTF-8 bytes for this one-block demonstration")

    block = bytearray(data + b"\x80" + bytes(63 - len(data)))
    key = secrets.token_bytes(64)

    print("Experimental AES-512 Candidate EXPERIMENT — 8x8 STATE + 8x8 MDS (NOT STANDARD AES; NOT FOR REAL SECRETS)")
    print("Message:", repr(a.message), "UTF-8:", data.hex())
    if a.show_key:
        print("Random 512-bit demo key:", key.hex())
    print("State: 8 rows x 8 columns = 64 bytes = 512 bits")
    print("ShiftRows offsets:", SHIFT_OFFSETS)
    print("MixColumns8: Cauchy 8x8 MDS over GF(2^8), byte branch number = 9")
    show("8x8 INPUT STATE:", list(block))

    out = encrypt_block(bytes(block), key, trace=a.trace or a.steps, steps=a.steps)
    print("\nFINAL 512-BIT BLOCK:", out.hex())

    if a.avalanche:
        if not 0 <= a.bit < 512:
            p.error("--bit must be between 0 and 511")
        altered = bytearray(block)
        altered[a.bit // 8] ^= 1 << (7 - (a.bit % 8))
        out2 = encrypt_block(bytes(altered), key, trace=False, steps=False)
        distance = sum((x ^ y).bit_count() for x, y in zip(out, out2))
        print(f"AVALANCHE: {distance} / 512 bits = {distance/512*100:.2f}%")

    print("WARNING: Experimental construction; no security claim, authentication, or safe multi-block mode.")

if __name__ == "__main__":
    main()
