# Stutter Code Review Report

**Date:** 2025-12-24
**Reviewer:** Aida (Automated Security Review)
**Project:** Stutter CSPRNG Library (Fortuna-based)
**Scope:** Full source code security review

---

## Executive Summary

Stutter is a cryptographically secure pseudorandom number generator (CSPRNG) implementing the Fortuna algorithm. The library uses OpenSSL for cryptographic primitives (SHA-256, AES-256) and integrates with RAMpart for secure memory management. The implementation follows established Fortuna design patterns with proper forward secrecy and backtrack resistance.

**Overall Assessment:** Well-designed PRNG architecture with appropriate cryptographic practices. A few areas warrant attention regarding thread safety during shutdown and OpenSSL error handling.

---

## Architecture Overview

### Cryptographic Design
- **Algorithm:** Fortuna PRNG (Ferguson & Schneier)
- **Generator:** AES-256-CTR mode
- **Hash:** SHA-256 (via OpenSSL EVP API)
- **Entropy Pools:** 32 pools with scheduled inclusion
- **Key Material:** Protected via RAMpart secure memory with parking

### Security Properties
1. **Forward Secrecy:** New seed mixed with existing key via SHA-256
2. **Backtrack Resistance:** Key rotated after every read operation
3. **Prediction Resistance:** Multi-pool accumulator prevents single-pool compromise
4. **Thread Safety:** Per-thread generators with thread-local storage

### Module Analysis

| Module | LOC | Risk Level | Notes |
|--------|-----|------------|-------|
| stutter.c | 620 | Medium | Public API, TLS management |
| generator.c | 225 | High | Key material handling |
| accumulator.c | 228 | Medium | Entropy pool management |
| entropy.c | 394 | Medium | Entropy source plugins |
| secure_mem.c | 214 | Medium | RAMpart integration |
| sha256.c | 95 | Low | OpenSSL wrapper |
| aes256.c | 75 | Low | OpenSSL wrapper |

---

## Findings

### SEC-001: Shutdown Race Condition (Medium)
**File:** `stutter.c:255-327`
**Description:** During shutdown, there is a window between setting `g_initialized = 0` and `g_shutdown_complete = 1` where concurrent threads could have their TLS destructors called but RAMpart pools may still be accessible. The code handles this with the `g_shutdown_complete` flag check in `tls_destructor`, but the ordering is fragile.

**Code Path:**
```c
g_initialized = 0;           // Line 312 - New requests rejected
entropy_shutdown();          // Line 314
accumulator_shutdown(&g_accumulator);  // Line 315
secure_mem_shutdown();       // Line 316 - RAMpart pools destroyed
g_shutdown_complete = 1;     // Line 322 - TLS destructors now know pools are gone
```

**Impact:** If a thread exits between lines 316 and 322, the TLS destructor might attempt to access destroyed pools.

**Recommendation:** Set `g_shutdown_complete = 1` BEFORE destroying RAMpart pools, or use a more robust synchronization mechanism.

### SEC-002: Counter Overflow Handling (Low)
**File:** `generator.c:24-33`
**Description:** The 128-bit counter increment function has correct implementation, but there is no handling for the astronomically unlikely case of counter exhaustion.

```c
static void increment_counter(unsigned char counter[16])
{
    int i;
    for (i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) {
            break;
        }
    }
}
```

**Impact:** After 2^128 blocks (functionally impossible), counter wraps to zero.
**Recommendation:** Acknowledged as acceptable. Document the theoretical limit.

### SEC-003: OpenSSL Error State Leakage (Low)
**File:** `sha256.c`, `aes256.c`
**Description:** OpenSSL operations may leave error state in the thread-local error queue. Functions should call `ERR_clear_error()` on entry or exit to prevent confusion in callers.

**Impact:** Stale OpenSSL errors could confuse error diagnosis.
**Recommendation:** Add `ERR_clear_error()` at function entry in wrapper functions.

### SEC-004: Entropy Source Mutex Held During I/O (Medium)
**File:** `entropy.c:290-357`
**Description:** The `entropy_gather` function holds `g_entropy_mutex` for the entire duration of entropy collection, including blocking I/O operations from entropy sources.

```c
pthread_mutex_lock(&g_entropy_mutex);
// ... entire gather loop including source->read() calls ...
pthread_mutex_unlock(&g_entropy_mutex);
```

**Impact:** Slow entropy sources block all entropy operations, including source registration/unregistration.
**Recommendation:** Release mutex during I/O operations or use a snapshot of source pointers.

### SEC-005: Jitter Entropy Quality (Informational)
**File:** `entropy.c:76-119`
**Description:** The timing jitter entropy source estimates 2 bits per byte. This is a conservative estimate, but actual entropy depends heavily on system load and CPU architecture.

**Impact:** On systems with highly deterministic timing, actual entropy may be lower.
**Recommendation:** Consider using CPU-specific jitter entropy implementations (e.g., jitterentropy library) for higher confidence.

### SEC-006: Reseed Count Saturation (Low)
**File:** `accumulator.c:141-144`
**Description:** Reseed count saturates at ULONG_MAX to prevent schedule repeat. This is correct, but after saturation, pool scheduling becomes static (all pools used every time).

```c
if (acc->reseed_count < ULONG_MAX) {
    acc->reseed_count++;
}
```

**Impact:** After ~18 quintillion reseeds, pool scheduling becomes less optimal. Functionally irrelevant.
**Recommendation:** Document this theoretical limit.

---

## Positive Security Practices Observed

1. **Proper key rotation** after every generator read (`generator.c:166-191`)
2. **Counter preservation across reseeds** - prevents (key, counter) reuse
3. **Secure memory zeroing** of intermediate cryptographic values
4. **Conservative entropy estimates** for timing jitter
5. **Thread-local generators** eliminate contention and key sharing
6. **RAMpart integration** for guard bands and secure wiping
7. **Key parking** encrypts generator state when idle
8. **Pool scheduling** per Fortuna specification

---

## Code Quality Observations

### Positive
- Clear separation of concerns (accumulator, generator, entropy)
- Comprehensive logging via STUTTER_LOG macro
- Consistent error handling patterns
- Well-documented security rationale in comments

### Areas for Improvement
- Some functions exceed 50 lines (e.g., `stutter_init`)
- Mixed use of `int` and `size_t` for lengths could cause truncation on large values
- TLS destructor logic is complex due to shutdown edge cases

---

## Recommendations Summary

| Priority | ID | Action |
|----------|----|--------|
| Medium | SEC-001 | Fix shutdown race by setting completion flag before pool destruction |
| Medium | SEC-004 | Reduce mutex hold time in entropy_gather |
| Low | SEC-003 | Clear OpenSSL error state in wrapper functions |
| Low | SEC-002, SEC-006 | Document theoretical limits in documentation |
| Info | SEC-005 | Consider more robust jitter entropy implementation |

---

## Conclusion

Stutter demonstrates solid cryptographic engineering following the established Fortuna design. The integration with RAMpart for secure memory management is well-implemented. The primary concerns are shutdown timing edge cases and mutex contention during entropy gathering.

The library is appropriate for applications requiring a self-contained CSPRNG with strong security properties. The OpenSSL dependency provides confidence in cryptographic primitive correctness.

**Risk Rating:** Low-Medium (primarily due to shutdown race condition)
