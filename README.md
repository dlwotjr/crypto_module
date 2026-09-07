# Software Cryptographic Module

Course project that wraps the existing ARIA, SHA3, and HMAC-SHA3 code in a
controlled software cryptographic module. The module adds a private finite-state
machine, startup tests, integrity and entropy checks, SHA3-based Hash_DRBG,
P-256 ECDH, and ML-KEM-768.

This is an educational implementation. It has not been submitted for or granted
KCMVP, FIPS 140, or other formal validation.

## Requirement Coverage

| Project requirement | Implementation | Status |
|---|---|---|
| Symmetric cipher | ARIA-128/192/256; public ECB, CBC, and CTR encryption/decryption | Implemented |
| Hash | SHA3-224/256/384/512 | Implemented |
| MAC | HMAC-SHA3-224/256/384/512 | Implemented |
| RNG/DRBG | SHA3-256 Hash_DRBG with instantiate, generate, reseed, uninstantiate, request limit, and reseed counter | Implemented |
| Entropy source | Linux `getrandom()` only; no insecure fallback | Implemented |
| Entropy health tests | Startup Repetition Count Test and Adaptive Proportion Test | Implemented |
| ECC key agreement | P-256/secp256r1 ECDH using micro-ecc | Implemented |
| Known-answer tests | ARIA, SHA3-256, HMAC-SHA3, Hash_DRBG, P-256 ECDH, and ML-KEM-768 startup KATs | Implemented |
| Software integrity | Generated SHA3-256 manifest over selected module source files | Implemented |
| Conditional self-test | P-256 and ML-KEM-768 generated-key pairwise consistency tests | Implemented |
| FSM/state enforcement | Private state and legal transition table; all public services are gated | Implemented |
| Error-state lockout | Startup, entropy, reseed, KAT, integrity, ECC, and ML-KEM pairwise failures block services | Implemented |
| ML-KEM | ML-KEM-768 clean reference implementation from PQClean | Implemented |

## Supported Services

### ARIA

- Key sizes: 128, 192, and 256 bits.
- Public modes: ECB, CBC, and CTR.
- ECB and CBC require a positive input length that is a multiple of 16 bytes;
  padding is intentionally outside the module API.
- CTR accepts any positive byte length and processes a trailing partial block.
- ECB, CBC, and CTR encryption and decryption are validated by the supplied
  course vectors.

### SHA3 and HMAC-SHA3

- SHA3-224, SHA3-256, SHA3-384, and SHA3-512 one-shot hashing.
- SHA3 streaming state is caller-owned internally; independent operations do
  not share mutable Keccak state.
- HMAC with all four SHA3 digest sizes.
- Existing byte-oriented SHA3/HMAC vector suite: 1,266 passing cases.

### Hash_DRBG

- SHA3-256 construction with 440-bit `V` and `C` state.
- Entropy-backed instantiate and reseed.
- Maximum request: 65,536 bytes.
- Reseed interval: `2^48` generate requests.
- Internal state is zeroized on uninstantiate, shutdown, zeroize, and fatal
  reseed failure.

### P-256 ECDH

- Private keys are generated through the module Hash_DRBG.
- Public keys are 64-byte `X || Y` values without a SEC1 `0x04` prefix.
- Peer public keys are checked for valid curve coordinates before ECDH.
- Shared-secret output is the 32-byte P-256 x-coordinate.
- Uses micro-ecc commit `24c60e243580c7868f4334a1ba3123481fe1aa48`,
  BSD 2-Clause; see `third_party/micro-ecc/`.

### ML-KEM-768

- Public key: 1,184 bytes; secret key: 2,400 bytes.
- Ciphertext: 1,088 bytes; shared secret: 32 bytes.
- Key generation and encapsulation randomness comes from the module Hash_DRBG.
- Decapsulation uses ML-KEM implicit rejection as implemented by PQClean.
- Uses the portable clean implementation from PQClean commit
  `202a8f96315f9ed219387a50f7e40d04af037ea8`, CC0/public domain; see
  `third_party/PQClean/README.kcmvp` and the vendored `LICENSE`.

## Module State Machine

The current state is private to `module_state.c`. Callers can query it but cannot
write it.

```text
LOAD
  -> PRE_SELFTEST
       -> NORMAL                    all startup checks pass
       -> CRITICAL_ERROR            any startup check fails

NORMAL
  -> EXECUTION -> NORMAL            ordinary crypto service
  -> COND_SELFTEST -> NORMAL        ECC/ML-KEM generated-key test passes
  -> CRITICAL_ERROR                 fatal runtime failure or zeroize
  -> EXIT                           shutdown

EXECUTION / COND_SELFTEST
  -> CRITICAL_ERROR                 fatal service or conditional-test failure

CRITICAL_ERROR
  -> EXIT                           shutdown only
```

`DEGRADED` and `NORMAL_ERROR` are reserved states in the public state enum but
are not entered by the current implementation.

Before initialization, crypto services return
`KCMVP_ERROR_NOT_INITIALIZED`. Outside `NORMAL`, they return
`KCMVP_ERROR_INVALID_STATE`. A critical error permits status queries,
zeroization, and shutdown, but no cryptographic service.

## Initialization Sequence

`KCMVP_Initialize()` performs the following before entering `NORMAL`:

1. Transition from `LOAD` to `PRE_SELFTEST`.
2. Verify the generated SHA3-256 integrity manifest.
3. Collect 512 bytes from Linux `getrandom()`.
4. Run the Repetition Count Test and Adaptive Proportion Test.
5. Run the ARIA-128 encrypt/decrypt KAT.
6. Run the SHA3-256 KAT.
7. Run the HMAC-SHA3 KAT.
8. Run the deterministic Hash_DRBG KAT.
9. Run the deterministic P-256 public-key/ECDH KAT.
10. Run the deterministic ML-KEM-768 keypair/encapsulation KAT.
11. Instantiate the live Hash_DRBG from fresh entropy.
12. Transition to `NORMAL`.

Each algorithm flag is set only after its KAT succeeds. Any failure clears
module test/DRBG state, enters `CRITICAL_ERROR`, and prevents service output.

## Conditional Self-Test

Every successful `KCMVP_ECC_GenerateKeyPair()` candidate is tested before its
private or public key is released:

1. Generate the private key through `KCMVP_RNG_Generate()`.
2. Compute its P-256 public key.
3. Enter `COND_SELFTEST`.
4. Compute ECDH with a fixed valid P-256 peer.
5. Independently compute the reciprocal peer shared secret.
6. Compare both 32-byte secrets.
7. Return to `NORMAL` only on success.

ML-KEM key generation similarly enters `COND_SELFTEST`, performs deterministic
encapsulation and decapsulation with the candidate keypair, and compares the
32-byte secrets. Failure zeroizes the candidate keypair and enters
`CRITICAL_ERROR`.

## Public API Boundary

Consumers include `include/kcmvp.h` and link with
`build/libkcmvp_crypto.so`. Public services are:

- Lifecycle: `KCMVP_Initialize`, `KCMVP_GetState`, `KCMVP_GetStatus`,
  `KCMVP_Zeroize`, `KCMVP_Shutdown`.
- Compatibility self-test entry points: `KCMVP_PreSelfTest`,
  `KCMVP_AlgKATSelfTest`.
- ARIA: `KCMVP_ARIA_*`.
- SHA3 and HMAC-SHA3: `KCMVP_SHA3_Hash`, `KCMVP_HMAC_SHA3`.
- RNG: `KCMVP_RNG_Generate`, `KCMVP_RNG_Reseed`,
  `KCMVP_RNG_Uninstantiate`.
- P-256: `KCMVP_ECC_GenerateKeyPair`,
  `KCMVP_ECC_ComputeSharedSecret`.
- ML-KEM-768: `KCMVP_MLKEM_Keypair`, `KCMVP_MLKEM_Encaps`,
  `KCMVP_MLKEM_Decaps`.

The shared library is built with hidden visibility and a linker version script.
Raw primitive, entropy, DRBG, integrity, self-test, micro-ecc, and PQClean
functions are not exported.

## Build and Test

Requirements: Linux, GCC, GNU Make, and binutils (`nm`). Run commands from the
project root because integrity-manifest paths and test-vector paths are relative
to it.

```bash
make clean
make
make test
make audit-exports

# Complete rebuild, test, and ABI export audit
make clean && make audit
```

Generated output is placed in `build/`. The integrity manifest is regenerated
when a protected source changes.

Test coverage includes:

- Startup integrity, entropy, ARIA/SHA3/HMAC/DRBG/ECC/ML-KEM KAT success.
- Forced integrity, entropy-provider, RCT, APT, KAT, reseed, ECC pairwise, and
  ML-KEM pairwise failures.
- Pre-initialization and critical-error service rejection.
- DRBG generation, request limit, reseed, and uninstantiate.
- P-256 keypair generation, reciprocal shared-secret agreement, and invalid
  public-key rejection.
- ML-KEM-768 keypair, encapsulation, decapsulation, parameter validation, and
  shared-secret agreement.
- 3,342 supplied ARIA vectors, each checked for encryption and decryption.
- 1,266 supplied SHA3 and HMAC-SHA3 vectors.

Run the service/lifecycle demonstration with:

```bash
./build/main
```

The same demo can additionally run the complete supplied ARIA vector
set with `./build/main --vectors`; `make test` uses this mode.

## File Layout

```text
include/kcmvp.h                 public module API
lib/KCMVP_Crypto.c              module boundary and service dispatch
lib/module_state.c              private FSM and authorization
lib/selftest.c                  startup algorithm KATs
lib/integrity.c                 manifest verification
lib/entropy.c                   getrandom provider and health tests
lib/hash_drbg.c                 SHA3-based Hash_DRBG
lib/ecc.c                       P-256 module adapter and pairwise test
lib/mlkem.c                     ML-KEM module adapter, KAT, and pairwise test
lib/aria*.c                     existing course ARIA implementation
lib/sha3.c                      existing course SHA3 implementation
lib/KISA_HMAC_SHA3.c            existing course HMAC-SHA3 implementation
third_party/micro-ecc/          external P-256 reference implementation/license
third_party/PQClean/            vendored ML-KEM-768 clean implementation/license
test/module_state_test.c        lifecycle and fault-injection tests
test/sha3_vs.c                  SHA3/HMAC vector validation
app/kat.c                       offline ARIA vector parser
app/main.c                      public API demonstration
```

## Design Documentation

- [Basic design](docs/basic_design.pdf): requirements, architecture, state
  machine, supported algorithms, and test strategy.
- [Detailed design](docs/detailed_design.pdf): API boundary, state transitions,
  startup checks, DRBG, P-256, ML-KEM, zeroization, and fault-injection tests.
- Editable LaTeX sources and build instructions are available in
  [`docs/`](docs/README.md).

## Remaining Gaps and Warnings

- This project is not formally validated or certified.
- CFB64/OFB remain internal course code and are not public module services.
- ECB/CBC do not provide padding; callers must supply complete blocks. CTR is
  byte-oriented and supports a trailing partial block.
- The integrity scheme detects accidental or simple source-file modification;
  it is not a signed code-loading mechanism. It also requires execution from the
  project root and checks source files rather than loaded executable pages.
- Entropy health-test thresholds are basic project settings, not parameters
  justified by a measured source min-entropy assessment.
- Hash_DRBG is SHA3-based project code and has not undergone independent
  standards-validation testing.
- ECDH returns a raw shared secret. Applications should apply an approved KDF
  before using it as a symmetric key.
- Successful caller-owned private keys and shared secrets remain the caller's
  responsibility to zeroize.
- The vendored PQClean repository announced deprecation and planned archival
  after July 2026; this project pins and audits the recorded source revision.
