# Red Team Regression Test Notes: Stutter CSPRNG (2025-12-24)

This document tracks the verification of fixes and regression analysis for the Stutter C library, following the initial assessment.

## Verification Plan

The primary goal is to verify the remediation status of findings STUT-001 through STUT-009 from the initial report. Each finding will be re-assessed against the current codebase.

- **STUT-001 (Critical - AES Side-Channel)**: Re-audit `src/aes256.c`.
- **STUT-002 (High - Broken Forward Secrecy)**: Re-audit `src/generator.c`.
- **STUT-003 (High - Build Hardening)**: Re-audit `Makefile`.
- **STUT-004 (Medium - Unreliable Secure Zeroing)**: Re-audit `src/platform/posix.c`.
- **STUT-005 (Medium - Incomplete Shutdown)**: Re-audit `src/stutter.c`.
- **STUT-006 (Medium - Brittle CTR State)**: Re-audit `src/generator.c`.
- **STUT-007 (Low - Inadequate Tests)**: Re-audit `tests/`.
- **STUT-008 (Low - Insecure Wiping in SHA-256)**: Re-audit `src/sha256.c`.
- **STUT-009 (Low - Design Flaw in Reseeding)**: Re-audit `src/stutter.c`.

A section for any new regressions will be included in the final report.

---
## Detailed Log

### 2025-12-24 (Regression)

- **11:01**: Created directory `redteam_reports/2025-12-24_regression`.
- **11:02**: Created this regression notes file.
- **11:03**: Commencing verification. Starting with the most critical finding from the previous report, STUT-001. I will re-read `src/aes256.c` to check for the side-channel vulnerability.
- **11:05**: **[VERIFIED]** STUT-001 is **FIXED**. The `src/aes256.c` file has been completely rewritten. The table-based `sbox` lookup has been removed and replaced with a `sbox_compute` function that calculates the value on the fly using constant-time finite field arithmetic (bitslicing). This mitigates the cache-timing side-channel vulnerability.
- **11:06**: Proceeding to verify STUT-003 (Build Hardening). I will re-read the `Makefile`.
- **11:08**: **[VERIFIED]** STUT-003 is **FIXED**. The `Makefile` has been updated to include the recommended security hardening flags. `CFLAGS` now contains `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2`. `LDFLAGS` now conditionally includes `-Wl,-z,relro,-z,now` for full RELRO on non-macOS platforms.
- **11:09**: Proceeding to verify STUT-002 (Broken Forward Secrecy) and STUT-006 (Brittle CTR State). I will re-read `src/generator.c`.
- **11:11**: **[VERIFIED]** STUT-002 is **FIXED**. The `generator_reseed` function now correctly implements forward secrecy by computing the new key as `SHA256(old_key || seed)`. A `key` field was added to the generator struct to support this.
- **11:11**: **[VERIFIED]** STUT-006 is **FIXED**. The generator no longer resets the CTR counter to zero on key rotations or subsequent reseeds, making the `(key, counter)` uniqueness guarantee robust.
- **11:12**: Proceeding to verify STUT-004 (Unreliable Secure Zeroing). I will re-read `src/platform/posix.c`.
- **11:14**: **[VERIFIED]** STUT-004 is **FIXED**. The `platform_secure_zero` function no longer uses a simple volatile pointer loop. It now uses a volatile function pointer to call `memset`, a robust and portable technique to prevent the compiler from optimizing away the memory-wiping operation.
- **11:15**: Proceeding to verify STUT-005 (Incomplete Shutdown). I will re-read `src/stutter.c`.
- **11:17**: **[VERIFIED]** STUT-005 is **NOT FIXED**. The developer added `pthread_key_delete`, likely based on the incorrect assumption that it triggers destructors on other threads. Per POSIX, it does not. This change introduces a **REGRESSION**: by deleting the key, any thread that exits *after* `stutter_shutdown` is called will no longer have its destructor run at all, making the key/memory leak permanent for those threads.
- **11:18**: Proceeding to verify STUT-007 (Inadequate Tests). The `Makefile` listed a new file, `test_security.c`. I will read its contents.
- **11:20**: **[VERIFIED]** STUT-007 is **FIXED**. The new file `tests/test_security.c` adds explicit, well-designed tests for critical security properties, including forward secrecy and counter non-reuse. This directly addresses the original finding.
- **11:21**: Proceeding to verify STUT-008 (Insecure Wiping in SHA-256). I will re-read `src/sha256.c`.
- **11:22**: **[VERIFIED]** STUT-008 is **FIXED**. The `sha256_final` function now calls `platform_secure_zero` instead of `memset` to securely wipe the context struct.
- **11:23**: Proceeding to verify STUT-009 (Design Flaw in Reseeding). I will re-read `src/stutter.c`.
- **11:25**: **[VERIFIED]** STUT-009 is **NOT FIXED**. The logic in `stutter_rand` and `stutter_reseed` still bypasses the pooling architecture by injecting entropy directly into Pool 0 immediately before reseeding. This design flaw remains.

- **11:26**: All findings from the initial report have been verified. I will now compile the final regression report.
