# Experimental AES-512 Candidate 8×8 MDS — v0.2.0

Experimental 512-bit block cipher for public cryptanalysis. No production-security claim. Not standard AES.

## What changed

- Exact 64-byte block and key validation, with clear TypeError/ValueError exceptions.
- Decryption API and inverse transformations.
- Immutable snapshots of supported mutable input buffers.
- Quiet demo by default; secret-bearing debug output requires explicit CLI permission.
- Four checked machine-readable test vectors and a complete reproducible engineering audit.

The 30-round cipher, AES S-box, 8×8 Cauchy MDS matrix, ShiftRows offsets and SHAKE256 key derivation are unchanged. Valid v0.1 ciphertexts remain compatible.

## Run

```bash
python3 experimental_aes512_8x8_mds.py 'Hello test!'
python3 experimental_aes512_8x8_mds.py 'Hello test!' --avalanche --bit 0
python3 prepublication_tests.py
# Larger audit requires NumPy:
python3 audit.py
```

For deliberately visible demo keys and internal states:

```bash
python3 experimental_aes512_8x8_mds.py 'Hello test!' --show-key --steps
```

## API

```python
from experimental_aes512_8x8_mds import encrypt_block, decrypt_block
import secrets
key = secrets.token_bytes(64)
block = bytes(range(64))
ciphertext = encrypt_block(block, key)
assert decrypt_block(ciphertext, key) == block
```

This is a single-block primitive: no authentication, general message padding or multi-block mode. The implementation is not constant-time. Do not use it for real secrets.

## Evidence

`PREPUBLICATION_REPORT.md` describes the current run. `results.json` contains measurements; `regression-output.txt` contains the API regression run. `test_vectors.json` freezes vectors and the exact source SHA-256. `SPEC.md` defines the algorithm and API. `CHANGELOG.md` records this upgrade. Statistical tests and MDS do not prove security.

## License

Existing licensing is retained: PolyForm Noncommercial 1.0.0; commercial use requires the separate license described in COMMERCIAL_LICENSE.md. LICENSE, NOTICE and LEGAL_NOTICE.md are unchanged.
