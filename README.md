# Stutter

*Because a smooth PRNG is a predictable PRNG.*

Stutter is a Fortuna-based cryptographically secure pseudorandom number generator (CSPRNG) library written in strict ANSI C (C89). It provides backtrack resistance, prediction resistance, and a pluggable entropy source architecture.

## Features

- **Fortuna Architecture**: 32-pool entropy accumulator with scheduled reseeding
- **AES-256-CTR Generator**: NIST CTR-DRBG compatible output generation
- **Backtrack Resistant**: Compromised state cannot recover previous states
- **Prediction Resistant**: Fresh entropy injection prevents forward prediction
- **Thread Safe**: Hierarchical locking with thread-local generators
- **Pluggable Entropy**: Register custom entropy sources
- **Zero Dependencies**: Self-contained SHA-256 and AES-256 implementations
- **POSIX Compliant**: Linux, BSD, and POSIX-compatible Unix systems

## Quick Start

```c
#include <stutter.h>

int main(void)
{
    unsigned char buf[32];

    if (stutter_init() != STUTTER_OK) {
        return 1;
    }

    if (stutter_rand(buf, sizeof(buf)) != STUTTER_OK) {
        stutter_shutdown();
        return 1;
    }

    /* Use buf... */

    stutter_shutdown();
    return 0;
}
```

## Building

```bash
make            # Build library
make test       # Run tests
make clean      # Clean build artifacts
```

## API Reference

### Lifecycle

```c
int  stutter_init(void);      /* Initialize library (blocks until seeded) */
void stutter_shutdown(void);  /* Clean shutdown, zero all state */
```

### Random Generation

```c
int stutter_rand(void *buf, size_t len);  /* Generate random bytes */
int stutter_reseed(void);                  /* Force reseed from entropy */
```

### Entropy Management

```c
int stutter_entropy_register(const stutter_entropy_source_t *source);
int stutter_entropy_unregister(const char *name);
int stutter_add_entropy(unsigned int pool, const void *data, size_t len);
```

### Status

```c
int stutter_is_seeded(void);       /* Returns 1 if properly seeded */
int stutter_get_reseed_count(void); /* Number of reseeds performed */
```

## Architecture

Stutter implements the Fortuna PRNG as described by Ferguson and Schneier:

```
ENTROPY SOURCES --> 32 POOLS --> ACCUMULATOR --> AES-256-CTR GENERATOR --> OUTPUT
                    (SHA-256)    (scheduled)     (thread-local)
```

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Backtrack Resistance | State wiped after generation, one-way hash accumulation |
| Prediction Resistance | Multi-pool accumulator, scheduled reseeding |
| State Independence | AES-CTR output reveals nothing about key |

### Thread Safety Model

- Global accumulator with per-pool spinlocks for entropy addition
- Thread-local AES-256-CTR generators
- Single mutex for reseed operations
- Each thread gets 64KB quota before forced reseed

## License

GNU Lesser General Public License v3.0 (LGPLv3)

See [LICENSE](LICENSE) for details.

## Contributing

This is an LLM-ARCH project. Contributions should follow the labeling conventions:

- `[CLASSIC]` - Traditional hand-coded implementation
- `[LLM-ASSISTED]` - Code written with LLM assistance
- `[LLM-ARCH]` - LLM-generated code with human review
- `[LLM-REVIEW]` - LLM-powered code review

## References

- Ferguson, N., Schneier, B. (2003). *Practical Cryptography*. Wiley.
- NIST SP 800-90A Rev. 1: *Recommendation for Random Number Generation Using Deterministic Random Bit Generators*
