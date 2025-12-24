# Red Team Notes: Stutter CSPRNG (2025-12-24)

This document tracks the process and findings of a white-box red team assessment of the Stutter C library.

## Initial Analysis & Plan

- **Target**: `stutter`, a Fortuna-based CSPRNG in C89.
- **Source Files**: Available.
- **Documentation**: `README.md` and `docs/ARCHITECTURE.md` reviewed.
- **Initial Threat Model**:
    - Cryptographic implementation flaws (especially in custom AES/SHA256).
    - Memory safety vulnerabilities (buffer overflows, use-after-free).
    - Failure of security guarantees (backtrack resistance, prediction resistance).
    - Side-channel attacks (timing attacks on crypto primitives).
    - Incorrect thread safety implementation (race conditions, deadlocks).
    - Weak or insecure entropy sourcing.
    - Failure to securely wipe sensitive state from memory.

## Audit Checklist & Findings

- [ ] **Phase 1: Foundational Primitives**
    - [X] `platform_secure_zero()`: Verify it's not optimized away by the compiler.
    - **Finding (Medium Severity):** The function at `src/platform/posix.c` uses a `volatile` pointer in a byte-by-byte loop to zero memory. This is a common but non-portable and unreliable method. Aggressive compiler optimization may still remove this loop, as the C standard does not guarantee that `volatile` will prevent this specific optimization. This could lead to sensitive data (keys, internal state) not being properly cleared from memory. The proper solution is to use a library function designed for this (e.g., `memset_s`, `explicit_bzero`) or a memory barrier.
    - [X] `aes256.c`: Audit for constant-time execution. (High Priority Target)
    - **Finding (Critical Severity):** The implementation in `src/aes256.c` is NOT constant-time, contrary to the claim in the architecture document. The `SubBytes` step is implemented as a simple table lookup: `sbox[state[i]]`. This creates a textbook cache-timing side-channel vulnerability. An attacker on the same machine can monitor cache usage to determine which S-box entries are being accessed, which leaks information about the internal state of the cipher. This class of vulnerability is practical and can lead to full key recovery, completely compromising the generator.
    - [X] `sha256.c`: Quick review for obvious deviations from FIPS 180-4.
      - **Finding (Low Severity):** The `sha256_final` function uses `memset` to clear the context struct. This call can be optimized away by a compiler, potentially leaving intermediate hash state in memory after the operation is complete. This is a minor information leak vulnerability.
- [ ] **Phase 2: Core Components**
    - [ ] `platform_get_entropy()`: Verify sources and failure modes.
    - [X] `generator.c`:
        - [X] Verify backtrack resistance key rotation.
        - [X] Verify quota enforcement.
        - [X] Check for integer overflows on request size.
        - **Finding (High Severity):** The reseeding mechanism in `generator_reseed` is critically flawed. The comments explicitly state the intention is `new_key = SHA256(old_key || seed)`, but the code ignores the old key entirely, calculating `new_key = SHA256(seed)`. A `TODO` comment confirms the developer knew this was incorrect. This breaks the forward-secrecy guarantee of the Fortuna design. An attacker who compromises the entropy source can predict all future output after the next reseed.
        - **Finding (Medium Severity):** The generator's state management is brittle. Both the post-read re-keying in `generator_read` and the `generator_reseed` function reset the CTR-mode counter to zero. The security of CTR mode relies on a `(key, counter)` pair never being reused. This design's security now dangerously depends on every key generated being unique, which is not guaranteed by the flawed reseed logic. If the same seed is ever provided twice, the same keystream will be produced.
        - **Finding (Low Severity):** The byte quota enforcement in `generator_read` is buggy. The logic will cause the generator to exhaust its quota prematurely, leading to more frequent reseeds than necessary and potential unexpected `STUTTER_ERR_NO_ENTROPY` errors (an availability issue).
    - [X] `accumulator.c`:
        - [X] Verify Fortuna pool scheduling algorithm.
        - [X] Analyze entropy estimation logic.
        - **Finding (Correct):** The core logic of the accumulator, including the Fortuna pool scheduling algorithm, the fine-grained threading model (per-pool spinlocks + global reseed mutex), and the entropy estimation logic, appears to be a sound and correct implementation of the Fortuna specification.
        - **Finding (Inherited Medium Severity):** The `accumulator_shutdown` function relies on `platform_secure_zero` to wipe pool state. This inherits the "Medium Severity" finding from the platform audit, as the memory zeroing is not guaranteed to be effective against compiler optimizations.
- [X] **Phase 3: System-Level Logic**
    - [X] `stutter.c` / `stutter_internal.h`:
        - [X] Analyze threading model and TLS for race conditions.
        - [X] Verify `stutter_shutdown()` securely zeroes all state.
        - [X] Check `stutter_init()` for correct initial seeding.
        - **Finding (Medium Severity):** The `stutter_shutdown` function is incomplete. It never calls `pthread_key_delete`, so the `generator_destructor` for thread-local storage is never invoked during shutdown. This means the generator state (including AES keys) for any thread other than the one calling `shutdown` is not cleaned up and remains in memory until that thread exits. This is both a memory leak and a security flaw, as sensitive data is not deterministically zeroed on shutdown.
        - **Finding (Low Severity / Design Flaw):** The reseeding logic in `stutter_rand` and `stutter_reseed` undermines the Fortuna design. It bypasses the normal entropy gathering process and injects fresh system entropy directly into Pool 0 just before a reseed. This makes the other 31 pools mostly irrelevant and reduces the resilience the accumulator was designed to provide.
- [X] **Phase 4: Testing & Build**
    - [X] Review `tests/`: Assess coverage of security properties.
      - **Finding (Inadequate):** The test suite consists only of basic functional "happy path" tests. It completely fails to validate any of the library's critical security properties (e.g., backtrack resistance, forward secrecy). The flaws in `generator.c` could have been caught by a simple, security-focused unit test, but none was present.
    - [X] Review `Makefile`: Check compiler flags for security hardening.
      - **Finding (High Severity):** The build process fails to enable standard compiler and linker security features. The `CFLAGS` are missing `-fstack-protector-strong` (stack canaries), `-D_FORTIFY_SOURCE=2` (safer libc functions), and the linker flags are missing full RELRO (`-Wl,-z,relro,-z,now`). This lack of basic hardening makes the compiled code significantly more vulnerable to memory corruption exploits.

---
## Detailed Log

### 2025-12-24

- **10:01**: Created directory structure `redteam_reports/2025-12-24`.
- **10:05**: Reviewed `README.md`. Identified custom crypto and complex threading as primary areas of interest.
- **10:10**: Reviewed `docs/ARCHITECTURE.md`. A detailed blueprint. Key claims like "constant-time AES" and "secure zeroing" are now top-priority targets for verification.
- **10:15**: Created this notes file.
- **10:16**: Proceeding to audit `platform_secure_zero`. Starting by locating the function in the codebase.
