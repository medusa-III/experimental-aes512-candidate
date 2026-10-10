# Validation report — v0.2.0

Run date: 2026-10-10. Source SHA-256: `c474509de291e05243dc97e10adf6fffd53f8b9fa6f6f05139a4afaf7a3c3714`.
Source hash and vectors are checked by `prepublication_tests.py`.

## Confirmed results

| Check | Result |
|---|---|
| Field multiplication | 65536/65536 correct |
| Nonzero field inverses | 255/255 correct |
| Matrix square minors | 12869 checked; 0 singular; branch number 9 |
| Independent reference vs candidate | 256 encryptions match; candidate and reference decrypt correctly |
| Additional reference-only roundtrips | 4096 passed |
| S-box differential uniformity / maximum nontrivial Walsh coefficient | 4 / 32 |
| Plaintext bit-flip sample | 4096 trials; 256.24023/512 mean changed bits |
| Key bit-flip sample | 4096 trials; 255.97266/512 mean changed bits |
| Round-key distances | 126976 samples; mean 255.94935/512 |
| Fixed-key random blocks | 4096 unique outputs; output-one fraction 0.50009346 |
| Full-round differential samples | Four differences, 4096 trials each; no repeated full output difference |
| Reduced-round integral samples | Four byte-variation sets per round count; XOR balanced at 1–3 rounds, not in sampled 4–6 rounds |

The extended audit uses deterministic seed 20261010 and NumPy. The independently written reference derives its AES S-box via the field inverse and affine transform, uses polynomial multiplication and independent state operations. It is still a Python implementation, not a second-language implementation. The 4096 additional batch roundtrips exercise this reference, not 4096 additional direct candidate comparisons.

## Null vector

64 zero bytes for both block and key:

```text
bf073ec1c325616543acc765669c100cf98bd32c2e25e5e20d9b144e8186f68f655efe54969e952b3a16f95e7e29efdd73a6221b14b5fdd67f988a45b73a373a
```

This agrees with TEST_VECTORS.md and test_vectors.json.

## API regression coverage

The deterministic unittest suite checks both API directions against wrong lengths and types; bytearray/memoryview acceptance, snapshot behavior and nonmutation; structured block/key combinations; decryption of arbitrary ciphertext; valid and invalid round indices; negative exponent rejection; frozen vectors and exact source hash; and CLI secrecy/debug behavior. See regression-output.txt for the exact completed test count.

All supplied invalid block/key lengths are rejected with ValueError. Wrong types are rejected with TypeError. There is no silent truncation or accepted empty key.

## Compatibility

64/64 direct comparisons against the archived, hash-checked v0.1 implementation passed. Reproduce with `python3 compatibility_check.py`. The old implementation is included only as test evidence in compatibility/v01.py; use the upgraded root implementation.

## Scope and remaining limitations

No full 30-round break was found. Passing these tests does not establish cryptographic security. Differential tests count whole-output differences and Hamming weights; they do not exhaustively search trails or hulls. Bit-flip metrics pool all positions across eight baselines; they do not establish every input/output bit pair's SAC or BIC. Collision-free samples are not an independent proof of security for an invertible primitive.

The symmetric Cauchy matrix retains M squared = 0x26 times identity; this structure merits dedicated analysis. Reduced-round integral distinguishers remain present. The cipher is not constant-time, and library callers opting into trace can reveal secret material. SHAKE256 key derivation remains unchanged; 512-bit input/output lengths are not proof of 512-bit security. No authentication or multi-block mode is supplied.

Formal active-S-box bounds, differential/linear hulls, higher-order integrals/division property, boomerang, impossible differential, rebound, meet-in-the-middle, biclique, slide, invariant-subspace, algebraic, and dedicated related-key analyses remain open. No measured side-channel attack, hardware analysis, or legal-license review was performed.

## Reproduce

```bash
python3 prepublication_tests.py
python3 audit.py
```

The first command uses only Python's standard library; the second needs NumPy. results.json records the extended measurements.
