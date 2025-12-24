# Stutter CSPRNG - White-Box Security Assessment Report

- **Date**: 2025-12-24
- **Auditor**: Gemini Advanced
- **Scope**: Full white-box source code review, build process, and test suite analysis of the `stutter` C library.

---

## 1. Executive Summary

This report details the findings of a comprehensive white-box security assessment of the Stutter CSPRNG library. The audit revealed several significant vulnerabilities that undermine the library's core security guarantees.

While the library is based on the sound architectural principles of the Fortuna CSPRNG, critical flaws were discovered in the implementation of its cryptographic primitives and state management logic. These flaws, if exploited, could lead to a complete compromise of the generator's confidentiality, allowing an attacker to predict its output.

**Key Findings:**

- **One (1) Critical Finding:** A cache-timing side-channel vulnerability in the custom AES-256 implementation allows for full key recovery by a local attacker.
- **Two (2) High Severity Findings:** The forward-secrecy guarantee is broken due to a flawed reseeding mechanism, and the build process fails to enable standard compiler hardening, leaving the binary vulnerable to memory corruption exploits.
- **Three (3) Medium Severity Findings:** Unreliable memory wiping, brittle state management, and an incomplete shutdown process that leaks cryptographic state were identified.
- **Several Low Severity Findings and Design Flaws** were also noted.

The library's test suite was found to be inadequate, as it only covers basic functionality and fails to validate any of the claimed security properties.

It is our assessment that the Stutter library, in its current state, is **not secure for use in any production environment**. Remediation of the identified vulnerabilities, particularly the critical side-channel flaw, is required to establish a baseline of security.

---

## 2. Findings

Findings are listed in order of severity from Critical to Low.

### STUT-001: Cache-Timing Side-Channel in AES Implementation
- **Severity**: **Critical**
- **Component**: `src/aes256.c`
- **Description**: The AES-256 implementation uses a standard S-box lookup table (`sbox[state[i]]`) in its `SubBytes` routine. This creates a classic data-dependent memory access pattern.
- **Impact**: This implementation is vulnerable to cache-timing attacks. A local attacker can monitor CPU cache usage to determine which S-box entries are accessed during encryption. This information leaks bits of the internal cipher state, which can be aggregated to fully recover the AES key, compromising all output from the generator. The claim of a "constant-time" implementation is false.
- **Remediation**: Replace the table-based `SubBytes` implementation with a "bitsliced" or other constant-time equivalent that computes the substitution using only bitwise operations, with no data-dependent branches or memory lookups.

### STUT-002: Broken Forward Secrecy in Generator Reseeding
- **Severity**: **High**
- **Component**: `src/generator.c`
- **Description**: The `generator_reseed` function is intended to mix a new seed with the existing key (`new_key = SHA256(old_key || seed)`). The actual implementation ignores the old key and calculates `new_key = SHA256(seed)`. A `TODO` comment in the code confirms the developer was aware of this discrepancy.
- **Impact**: This flaw breaks the forward-secrecy guarantee of the Fortuna design. If an attacker ever compromises the entropy accumulator, they can predict all future outputs of the generator following the next reseed, as the generator's prior state contributes nothing to the new state.
- **Remediation**: Modify `generator_reseed` to correctly implement the mixing of the old key and the new seed. The generator will need to store its key separately from the AES context to make this possible.

### STUT-003: Lack of Compiler Hardening in Build Process
- **Severity**: **High**
- **Component**: `Makefile`
- **Description**: The build process does not enable standard compiler and linker security flags. The `CFLAGS` are missing `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, and the linker flags lack full RELRO (`-Wl,-z,relro,-z,now`).
- **Impact**: The compiled binary is left without common defenses against memory corruption vulnerabilities. If a buffer overflow or similar flaw exists, it is significantly easier for an attacker to exploit it to achieve arbitrary code execution.
- **Remediation**: Add `-fstack-protector-strong -D_FORTIFY_SOURCE=2` to `CFLAGS` and `-Wl,-z,relro,-z,now` to the linker flags (`LDFLAGS` is not the right place, it should be during the final link step).

### STUT-004: Unreliable Secure Memory Wiping
- **Severity**: **Medium**
- **Component**: `src/platform/posix.c`
- **Description**: The `platform_secure_zero` function uses a `volatile` pointer loop to zero memory. This technique is not guaranteed by the C standard to prevent a compiler from optimizing the operation away.
- **Impact**: Sensitive data, such as AES keys and intermediate state, may not be cleared from memory when requested. This could allow an attacker with memory-reading capabilities to recover cryptographic secrets.
- **Remediation**: Replace the `volatile` loop with a call to a platform-specific function like `explicit_bzero` (BSD) or `memset_s` (C11 Annex K), or use a memory barrier with a standard `memset`.

### STUT-005: Incomplete Shutdown Leaks Cryptographic State
- **Severity**: **Medium**
- **Component**: `src/stutter.c`
- **Description**: `stutter_shutdown` does not call `pthread_key_delete`. This means the destructor for thread-local generator instances is never called during shutdown.
- **Impact**: The `stutter_generator_t` struct, including the AES key, for any thread other than the one calling `shutdown` is leaked until that thread exits. This is a memory leak and a security flaw, as sensitive data is not deterministically cleared.
- **Remediation**: `stutter_shutdown` should call `pthread_key_delete(g_generator_key)` after shutting down the global accumulator. The `g_tls_init_once` variable should also be reset to allow for re-initialization.

### STUT-006: Brittle State Management in CTR Mode
- **Severity**: **Medium**
- **Component**: `src/generator.c`
- **Description**: The 128-bit counter for AES-CTR mode is reset to zero in two separate places: after a post-read key rotation (`generator_read`) and after a reseed (`generator_reseed`).
- **Impact**: The security of CTR mode depends on a `(key, counter)` pair never being reused. This design's safety now relies entirely on every new key being unique. The flawed reseeding logic (STUT-002) weakens this guarantee. If the same seed is ever fed to the generator twice, it will produce the exact same keystream, resulting in a total loss of confidentiality.
- **Remediation**: The counter should not be reset. It should be a persistent part of the generator state that is only ever incremented.

### STUT-007: Inadequate Test Suite
- **Severity**: **Low**
- **Component**: `tests/`
- **Description**: The test suite consists of basic "happy path" functional tests. It completely fails to validate any of the library's security properties.
- **Impact**: Critical flaws like the broken forward secrecy (STUT-002) went undetected, despite being simple to write a unit test for. This demonstrates a gap in the development process.
- **Remediation**: Implement a dedicated security test suite that validates properties like forward secrecy, backtrack resistance, and resistance to reseeding with non-random data.

### STUT-008: Insecure Wiping in SHA-256
- **Severity**: **Low**
- **Component**: `src/sha256.c`
- **Description**: The `sha256_final` function uses `memset` to clear its context, which can be optimized away by the compiler.
- **Impact**: This could leak intermediate hash state, which is less sensitive than an AES key but still represents an unnecessary information leak. This is a lesser instance of STUT-004.
- **Remediation**: Use the corrected `platform_secure_zero` function to wipe the context.

### STUT-009: Design Flaw in Reseeding Strategy
- **Severity**: **Low (Design Flaw)**
- **Component**: `src/stutter.c`
- **Description**: The logic in `stutter_rand` and `stutter_reseed` bypasses the intended Fortuna pooling architecture by always injecting fresh entropy directly into Pool 0 before a reseed.
- **Impact**: This undermines the resilience of the Fortuna design, making the other 31 entropy pools largely irrelevant. While not a direct vulnerability, it negates a primary reason for choosing Fortuna.
- **Remediation**: Refactor the reseeding logic to rely on the `entropy_gather` subsystem and the accumulator's existing state, rather than short-circuiting it with direct entropy injection.

---

## 3. Conclusion

The Stutter library exhibits a solid high-level architectural design but is critically undermined by implementation-level vulnerabilities. The combination of a side-channel-vulnerable AES primitive, broken state management logic, and a lack of basic build hardening renders the library unfit for any purpose where cryptographic security is required. The findings suggest a disconnect between the documented architecture and the final implementation, as well as a lack of security-focused testing.

We advise against using this library until, at a minimum, findings STUT-001, STUT-002, and STUT-003 are addressed.
