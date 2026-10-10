# v0.2.0

Implementation upgrade; cipher design and valid-input ciphertexts unchanged.

Fixed silent truncation, acceptance of empty/wrong-length keys, accidental CLI key display, negative-exponent nontermination in gf_pow, and inconsistent published vectors. Added decryption, inverse layers, buffer snapshots, round-number validation, deterministic regressions and an executable extended audit.

Historical statistical claims without corresponding test code were removed from the current report; current results are reproducible from the included tests.

No authentication or multi-block mode is added. No new claim of cryptographic security, constant-time operation or 512-bit security strength is made.
