# Stutter Architecture Documentation

This document captures the complete architectural design for Stutter, serving as the authoritative reference for implementation and future development.

## Design Decision: Fortuna (Option A)

After evaluating three approaches (Fortuna, HMAC-DRBG, Hybrid), Fortuna was selected for:

1. **Proven design**: Published 2003, extensively analyzed, used in FreeBSD/Windows
2. **Graceful degradation**: 32 pools ensure recovery even with partial entropy
3. **Pool scheduling**: Guarantees attacker cannot predict reseed timing
4. **NIST compatibility**: Generator layer aligns with CTR-DRBG for test vector validation

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ENTROPY LAYER                               │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Pluggable Sources: /dev/urandom, getentropy(), jitter    │    │
│  └────────────────────────────────────────────────────────────┘    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      ACCUMULATOR (32 Pools)                         │
│  ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐         ┌────┐                │
│  │ P0 │ │ P1 │ │ P2 │ │ P3 │ │ P4 │   ...   │P31 │                │
│  └────┘ └────┘ └────┘ └────┘ └────┘         └────┘                │
│                                                                     │
│  Pool i included in reseed when: reseed_count % 2^i == 0           │
│  Each pool: SHA-256 running hash + entropy estimate                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ (reseed trigger: P0 >= 128 bits)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    GENERATOR (AES-256-CTR)                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Key: 256 bits (from accumulator reseed)                    │   │
│  │  Counter: 128 bits (incremented per block)                  │   │
│  │  Quota: 65536 bytes before forced reseed                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  After each request: generate 2 extra blocks, use as new key       │
│  (provides backtrack resistance)                                    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           OUTPUT                                    │
│  Random bytes delivered to caller                                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Specifications

### 1. SHA-256 (`src/sha256.c`)

Standard FIPS 180-4 implementation. Used for:
- Pool accumulation (running hash of entropy)
- Key derivation during reseed

```c
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, unsigned char digest[32]);
void sha256(const void *data, size_t len, unsigned char digest[32]);
```

### 2. AES-256 (`src/aes256.c`)

FIPS 197 implementation. Counter mode for generation.

```c
void aes256_init(aes256_ctx_t *ctx, const unsigned char key[32]);
void aes256_encrypt(const aes256_ctx_t *ctx,
                    const unsigned char in[16],
                    unsigned char out[16]);
void aes256_done(aes256_ctx_t *ctx);  /* Zero key schedule */
```

### 3. Accumulator (`src/accumulator.c`)

32 entropy pools with Fortuna scheduling.

```c
/* State per pool */
typedef struct {
    sha256_ctx_t hash_ctx;      /* Running SHA-256 */
    size_t entropy_bits;        /* Estimated entropy */
    pthread_spinlock_t lock;    /* Per-pool lock */
} stutter_pool_t;

/* Global accumulator */
typedef struct {
    stutter_pool_t pools[32];
    unsigned long reseed_count;
    pthread_mutex_t reseed_mutex;
} stutter_accumulator_t;

void accumulator_init(stutter_accumulator_t *acc);
void accumulator_add(stutter_accumulator_t *acc, unsigned int pool,
                     const void *data, size_t len, unsigned int quality);
int  accumulator_reseed(stutter_accumulator_t *acc, unsigned char seed[32]);
void accumulator_shutdown(stutter_accumulator_t *acc);
```

**Pool Scheduling Algorithm**:
```
On reseed request:
    if pool[0].entropy_bits < 128:
        return STUTTER_ERR_NO_ENTROPY

    reseed_count++
    seed_material = empty

    for i = 0 to 31:
        if reseed_count % (1 << i) == 0:
            seed_material += sha256_final(pool[i])
            sha256_init(pool[i])  /* Reset pool */
            pool[i].entropy_bits = 0

    return sha256(seed_material)
```

### 4. Generator (`src/generator.c`)

Thread-local AES-256-CTR generator.

```c
typedef struct {
    aes256_ctx_t aes;           /* Expanded key */
    unsigned char counter[16];  /* 128-bit counter */
    size_t bytes_remaining;     /* Quota until reseed */
    int seeded;                 /* Has been seeded */
} stutter_generator_t;

void generator_init(stutter_generator_t *gen);
void generator_reseed(stutter_generator_t *gen, const unsigned char seed[32]);
int  generator_read(stutter_generator_t *gen, void *buf, size_t len);
void generator_shutdown(stutter_generator_t *gen);
```

**Backtrack Resistance**:
After each `generator_read()`:
1. Generate 2 additional AES blocks (32 bytes)
2. Use these 32 bytes as new key
3. Re-initialize AES with new key
4. Zero old key material

### 5. Platform Shim (`src/platform/posix.c`)

POSIX-specific implementations.

```c
/* Entropy gathering */
int platform_get_entropy(void *buf, size_t len);

/* Secure memory operations */
void platform_secure_zero(void *buf, size_t len);

/* Threading */
int platform_mutex_init(pthread_mutex_t *m);
int platform_mutex_lock(pthread_mutex_t *m);
int platform_mutex_unlock(pthread_mutex_t *m);
void platform_mutex_destroy(pthread_mutex_t *m);

int platform_spin_init(pthread_spinlock_t *s);
int platform_spin_lock(pthread_spinlock_t *s);
int platform_spin_unlock(pthread_spinlock_t *s);
void platform_spin_destroy(pthread_spinlock_t *s);

/* Thread-local storage */
int platform_tls_create(pthread_key_t *key, void (*destructor)(void *));
void *platform_tls_get(pthread_key_t key);
int platform_tls_set(pthread_key_t key, void *value);
```

### 6. Entropy Sources (`src/entropy.c`)

Pluggable entropy source management.

```c
typedef struct stutter_entropy_source {
    const char *name;
    int (*init)(void *ctx);
    int (*read)(void *ctx, void *buf, size_t len, size_t *actual);
    void (*shutdown)(void *ctx);
    void *ctx;
    unsigned int quality;       /* Bits per byte: 0-8 */
    unsigned int pool_mask;     /* Which pools to feed */
} stutter_entropy_source_t;

/* Built-in sources */
static stutter_entropy_source_t builtin_sources[] = {
    { "urandom",    ... },  /* /dev/urandom */
    { "getentropy", ... },  /* getentropy() syscall */
    { "jitter",     ... },  /* Timing jitter */
};
```

**Entropy Distribution**:
- Sources rotate through pools using round-robin
- Pool selection: `pool = (source_index + call_count) % 32`
- Quality field scales entropy estimate

### 7. Main Library (`src/stutter.c`)

Glue code coordinating all components.

```c
/* Global state */
static stutter_accumulator_t g_accumulator;
static pthread_key_t g_generator_key;
static stutter_entropy_source_t *g_sources[16];
static int g_source_count;
static int g_initialized;
static pthread_mutex_t g_init_mutex;

/* Public API implementation */
int stutter_init(void) {
    /* 1. Initialize accumulator */
    /* 2. Register built-in entropy sources */
    /* 3. Gather initial entropy (block until 256 bits in P0) */
    /* 4. Create TLS key for generators */
    /* 5. Mark initialized */
}

int stutter_rand(void *buf, size_t len) {
    /* 1. Get thread-local generator (create if needed) */
    /* 2. Check if reseed needed (quota exhausted) */
    /* 3. Generate bytes */
    /* 4. Perform backtrack resistance key rotation */
}
```

## Thread Safety Model

### Hierarchy

```
Level 0: Per-pool spinlocks (entropy addition)
    └── Minimal contention, very fast
    └── Only held during SHA-256 update

Level 1: Reseed mutex (generator reseeding)
    └── Held during pool harvesting
    └── One thread reseeds at a time

Level 2: Init mutex (library initialization)
    └── Held only during stutter_init()
    └── Ensures single initialization
```

### Thread-Local Generators

Each thread gets its own generator via `pthread_key_t`:

```c
static stutter_generator_t *get_thread_generator(void) {
    stutter_generator_t *gen = pthread_getspecific(g_generator_key);
    if (gen == NULL) {
        gen = malloc(sizeof(*gen));
        generator_init(gen);
        /* Perform initial reseed */
        pthread_setspecific(g_generator_key, gen);
    }
    return gen;
}
```

Destructor function zeros and frees generator on thread exit.

## Security Considerations

### Backtrack Resistance

1. **Pool one-way**: SHA-256 accumulation is not invertible
2. **Generator key rotation**: New key after every read
3. **Secure zeroing**: All sensitive state zeroed on destruction

### Prediction Resistance

1. **Multi-pool accumulator**: Attacker cannot predict which pools reseed
2. **Entropy thresholds**: Reseed only when sufficient entropy available
3. **Pool scheduling**: Geometric distribution of pool inclusion

### Side Channels

1. **Constant-time AES**: Table lookups use full table (no early exit)
2. **No branching on secrets**: Control flow independent of key material
3. **Memory barriers**: Prevent compiler reordering of secure zeroing

## File Structure

```
stutter/
├── LICENSE                     # LGPLv3
├── README.md                   # Project overview
├── Makefile                    # Build system
├── docs/
│   └── ARCHITECTURE.md         # This document
├── include/
│   └── stutter.h               # Public API
├── src/
│   ├── stutter.c               # Main library
│   ├── stutter_internal.h      # Internal declarations
│   ├── accumulator.c           # 32-pool accumulator
│   ├── generator.c             # AES-256-CTR generator
│   ├── entropy.c               # Entropy source management
│   ├── aes256.c                # AES-256 implementation
│   ├── sha256.c                # SHA-256 implementation
│   └── platform/
│       └── posix.c             # POSIX platform shim
├── tests/
│   ├── test_main.c             # Test harness
│   ├── test_sha256.c           # SHA-256 tests
│   ├── test_aes256.c           # AES-256 tests
│   ├── test_generator.c        # Generator + NIST vectors
│   ├── test_accumulator.c      # Accumulator tests
│   └── test_thread.c           # Threading tests
└── examples/
    └── basic_usage.c           # Usage example
```

## Build Configuration

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c89 -pedantic -O2 -fPIC
LDFLAGS = -lpthread

# Debug build
CFLAGS_DEBUG = -Wall -Wextra -std=c89 -pedantic -g -O0 -DSTUTTER_DEBUG
```

## NIST Test Vector Compatibility

The generator layer can be validated against NIST SP 800-90A CTR-DRBG test vectors by:

1. Bypassing the accumulator
2. Directly seeding the generator with known values
3. Comparing output against published vectors

Test mode enabled via `STUTTER_TEST_MODE` compile flag.

## Constants

```c
#define STUTTER_NUM_POOLS       32
#define STUTTER_POOL_THRESHOLD  128     /* Bits before reseed allowed */
#define STUTTER_INIT_THRESHOLD  256     /* Bits before init completes */
#define STUTTER_GENERATOR_QUOTA 65536   /* Bytes before forced reseed */
#define STUTTER_MAX_REQUEST     1048576 /* Max bytes per request (1MB) */
#define STUTTER_MAX_SOURCES     16      /* Max registered entropy sources */
```

## Error Codes

```c
#define STUTTER_OK              0   /* Success */
#define STUTTER_ERR_NOT_INIT   -1   /* Library not initialized */
#define STUTTER_ERR_NO_ENTROPY -2   /* Insufficient entropy */
#define STUTTER_ERR_INVALID    -3   /* Invalid parameter */
#define STUTTER_ERR_LOCKED     -4   /* Resource locked (internal) */
#define STUTTER_ERR_MEMORY     -5   /* Memory allocation failed */
#define STUTTER_ERR_PLATFORM   -6   /* Platform-specific error */
```

## Implementation Notes

### C89 Compliance

- No `//` comments (use `/* */`)
- No mixed declarations and code
- No `inline` keyword (use macros or static functions)
- No `restrict` keyword
- No variable-length arrays
- No designated initializers
- Declare all variables at block start

### Portability

- Use `unsigned char` for byte buffers (not `uint8_t`)
- Use `unsigned long` for 32-bit values (not `uint32_t`)
- Use `size_t` for sizes
- Avoid assuming pointer sizes
