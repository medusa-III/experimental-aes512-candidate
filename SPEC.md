# Experimental AES-512 Candidate 8×8 MDS — Specification v0.2.0

## Status

This document freezes the current experimental design for public cryptanalysis and comparison against AES-256.

## Parameters

```text
Block size:       512 bits
Master key size:  512 bits
State:            8 × 8 bytes
Rounds:           30
S-box:            AES S-box
ShiftRows:        [0, 1, 3, 4, 5, 7, 2, 6]
Linear layer:     8 × 8 Cauchy MDS matrix over GF(2^8)
Round-key source: SHAKE-256
```

## State layout

The 64-byte block is stored column-major.

For byte index:

```text
index = 8 * column + row
```

with rows and columns in `0..7`.

## Encryption structure

The implementation first applies a 64-byte round key for round 0.

For rounds 1 through 29:

```text
SubBytes
ShiftRows
MixColumns8
AddRoundKey
```

Round 30:

```text
SubBytes
ShiftRows
AddRoundKey
```

The final round intentionally omits the linear MixColumns8 layer, mirroring the broad structure used by AES.

## SubBytes

Each byte is independently transformed using the standard AES S-box.

## ShiftRows

Rows are cyclically shifted left by:

```text
row 0: 0
row 1: 1
row 2: 3
row 3: 4
row 4: 5
row 5: 7
row 6: 2
row 7: 6
```

## MixColumns8

Each 8-byte column is multiplied by the Cauchy MDS matrix constructed in the reference code from:

```text
X = 00 01 02 03 04 05 06 07
Y = 08 09 0A 0B 0C 0D 0E 0F
```

with matrix elements:

```text
M[i][j] = inverse_GF256(X[i] XOR Y[j])
```

Arithmetic is in GF(2^8) using the AES irreducible polynomial:

```text
x^8 + x^4 + x^3 + x + 1
```

equivalent to reduction constant `0x11B`.

`audit.py` exhaustively checks all 12,869 square minors for nonsingularity. The matrix is symmetric and has M squared = 0x26 times the identity over GF(2^8); this structure requires further cryptanalysis.

## Round keys

For round `r`, the reference implementation derives 64 bytes using SHAKE-256 over:

```text
"EXPERIMENTAL-AES512-ROUNDKEY-8x8-v1" || master_key || r_be16
```

where `r_be16` is the round number encoded as two big-endian bytes.

## Padding in the demo program

The command-line demo accepts at most 63 UTF-8 bytes and pads the one-block demonstration as:

```text
message || 0x80 || zero bytes
```

This padding is part of the demo program, not a general-purpose encryption mode.

## Authentication / modes

None are specified yet.

This construction is currently only a block-cipher primitive. It does not define:

- nonce handling
- authenticated encryption
- multi-block operation
- replay protection
- key management

## Security status

No production security claim is made.

This version exists for public cryptanalysis.

## API contract (v0.2.0)

`encrypt_block(block, key)` and `decrypt_block(block, key)` accept bytes, bytearray or memoryview. Both arguments are snapshotted to bytes and must contain exactly 64 bytes. Wrong types raise TypeError; wrong lengths raise ValueError. No truncation, padding, unpadding or authentication occurs in the primitive.

Decryption executes rounds 30 down to 1: AddRoundKey; InvMixColumns except in round 30; InvShiftRows; InvSubBytes. Finally it applies round key 0.

`round_key` requires a 64-byte key and an integer round index 0 through 30 (booleans are rejected).

The CLI hides the demo key by default. `--show-key` explicitly displays it. `--trace` and `--steps` require `--show-key` because internal states can disclose secret material. Library callers choosing `trace=True` are likewise opting into secret-bearing debug output.

The cipher parameters and SHAKE domain string remain unchanged from v0.1. Valid 64-byte inputs therefore have exactly compatible ciphertexts.
