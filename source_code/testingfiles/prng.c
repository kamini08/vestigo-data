#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __SDCC
int putchar(int c) { (void)c; return c; }
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/*
 * Alternate PRNG Suite
 * Includes:
 *   - LCG (Park–Miller)
 *   - XORSHIFT64*
 *   - PCG32
 *   - SplitMix64
 *
 * Unified interface with random bytes, range, and double output.
 */

/* ============================================================
 *  Linear Congruential Generator (Minimal Standard)
 * ============================================================ */

typedef struct {
    uint64_t state;
} LCG_PM;

void lcg_pm_init(LCG_PM *lcg, uint64_t seed) {
    lcg->state = seed % 2147483647ULL;
    if (lcg->state == 0) lcg->state = 1;
}

uint64_t lcg_pm_next(LCG_PM *lcg) {
    lcg->state = (lcg->state * 48271ULL) % 2147483647ULL;
    return lcg->state;
}

/* ============================================================
 * XORSHIFT64*
 * ============================================================ */

typedef struct {
    uint64_t s;
} XS64;

void xs64_init(XS64 *xs, uint64_t seed) {
    xs->s = seed ? seed : 0xBADF00D1234ULL;
}

uint64_t xs64_next(XS64 *xs) {
    uint64_t x = xs->s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    xs->s = x;
    return x * 2685821657736338717ULL;
}

/* ============================================================
 * PCG32 RNG (simple, high quality)
 * ============================================================ */

typedef struct {
    uint64_t state;
    uint64_t inc;
} PCG32;

void pcg32_init(PCG32 *pcg, uint64_t seed) {
    pcg->state = 0;
    pcg->inc   = (seed << 1u) | 1u;
    pcg32_init(pcg, seed + 0x9E3779B97F4A7C15ULL);
    pcg->state += seed;
}

uint32_t pcg32_next_u32(PCG32 *pcg) {
    uint64_t old = pcg->state;
    pcg->state = old * 6364136223846793005ULL + pcg->inc;
    uint32_t xorshifted = ((old >> 18u) ^ old) >> 27u;
    uint32_t rot = old >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

/* ============================================================
 * SplitMix64 (fast & simple)
 * ============================================================ */

typedef struct {
    uint64_t state;
} SM64;

void sm64_init(SM64 *sm, uint64_t seed) {
    sm->state = seed + 0x9E3779B97F4A7C15ULL;
}

uint64_t sm64_next(SM64 *sm) {
    uint64_t z = (sm->state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ============================================================
 * Unified PRNG Interface
 * ============================================================ */

typedef enum {
    RNG_LCG_PM,
    RNG_XORSHIFT64,
    RNG_PCG32,
    RNG_SPLITMIX64
} RNGType;

typedef struct {
    RNGType type;
    union {
        LCG_PM    lcg;
        XS64      xs;
        PCG32     pcg;
        SM64      sm;
    } u;
} RNG;

void rng_init(RNG *rng, RNGType type, uint64_t seed) {
    rng->type = type;
    switch(type) {
        case RNG_LCG_PM:     lcg_pm_init(&rng->u.lcg, seed); break;
        case RNG_XORSHIFT64: xs64_init(&rng->u.xs, seed); break;
        case RNG_PCG32:      pcg32_init(&rng->u.pcg, seed); break;
        case RNG_SPLITMIX64: sm64_init(&rng->u.sm, seed); break;
    }
}

uint64_t rng_next(RNG *rng) {
    switch(rng->type) {
        case RNG_LCG_PM:     return lcg_pm_next(&rng->u.lcg);
        case RNG_XORSHIFT64: return xs64_next(&rng->u.xs);
        case RNG_PCG32:      return ((uint64_t)pcg32_next_u32(&rng->u.pcg) << 32) |
                                          pcg32_next_u32(&rng->u.pcg);
        case RNG_SPLITMIX64: return sm64_next(&rng->u.sm);
    }
    return 0;
}

/* random bytes */
void rng_bytes(RNG *rng, uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t v = rng_next(rng);
        size_t chunk = (i + 8 > len) ? (len - i) : 8;
        memcpy(buf + i, &v, chunk);
    }
}

/* random range [0, max) */
uint64_t rng_range(RNG *rng, uint64_t max) {
    return rng_next(rng) % max;
}

/* random float in [0,1) */
double rng_double(RNG *rng) {
    return (double)rng_next(rng) / (double)UINT64_MAX;
}

/* ============================================================
 * Main test
 * ============================================================ */

int main() {
    uint64_t seed = (uint64_t)time(NULL);

    printf("Alternate PRNG Suite\n");
    printf("Seed = %llu\n\n", seed);

    const char *names[] = {
        "Park–Miller LCG",
        "XORSHIFT64*",
        "PCG32",
        "SplitMix64"
    };

    for (int t = 0; t < 4; t++) {
        RNG rng;
        rng_init(&rng, (RNGType)t, seed);

        printf("=== %s ===\n", names[t]);

        printf("Numbers: ");
        for (int i = 0; i < 10; i++) {
            printf("%llu ", rng_next(&rng));
        }
        printf("\n");

        uint8_t b[16];
        rng_bytes(&rng, b, 16);

        printf("Bytes:   ");
        for (int i = 0; i < 16; i++) printf("%02x ", b[i]);
        printf("\n");

        printf("Doubles: ");
        for (int i = 0; i < 5; i++) printf("%.6f ", rng_double(&rng));
        printf("\n\n");
    }

    /* small distribution test */
    printf("=== SplitMix64 distribution ===\n");
    RNG r;
    rng_init(&r, RNG_SPLITMIX64, seed);

    int freq[10] = {0};
    int SAMPLES = 5000;

    for (int i = 0; i < SAMPLES; i++) {
        freq[rng_range(&r, 10)]++;
    }

    for (int i = 0; i < 10; i++) {
        printf("Bucket %d: %d (%.2f%%)\n",
               i, freq[i], 100.0 * freq[i] / SAMPLES);
    }

    return 0;
}
