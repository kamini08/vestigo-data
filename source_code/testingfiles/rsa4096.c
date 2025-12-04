#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __SDCC
int putchar(int c) { (void)c; return c; }
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>



typedef uint64_t u64;
typedef __uint128_t u128;

/* ---------- modular helpers ---------- */

static u64 mul_mod(u64 a, u64 b, u64 m) {
    return (u64)((u128)a * b % m);
}

static u64 pow_mod(u64 a, u64 e, u64 m) {
    u64 res = 1;
    a %= m;
    while (e) {
        if (e & 1) res = mul_mod(res, a, m);
        a = mul_mod(a, a, m);
        e >>= 1;
    }
    return res;
}

/* Extended GCD, returns gcd and computes x,y so that ax+by=gcd */
static int64_t egcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (a == 0) {
        *x = 0; *y = 1;
        return b;
    }
    int64_t x1, y1;
    int64_t g = egcd(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return g;
}

static u64 inv_mod(u64 a, u64 m) {
    int64_t x, y;
    int64_t g = egcd((int64_t)a, (int64_t)m, &x, &y);
    if (g != 1) return 0;
    int64_t r = x % (int64_t)m;
    if (r < 0) r += m;
    return (u64)r;
}

/* ---------- Miller–Rabin primality (deterministic for 64-bit) ---------- */

static int is_prime_mr(u64 n) {
    if (n < 2) return 0;
    static const u64 small_primes[] = {2,3,5,7,11,13,17,19,23,29,31};
    for (size_t i=0; i < sizeof(small_primes)/sizeof(small_primes[0]); ++i) {
        if (n == small_primes[i]) return 1;
        if (n % small_primes[i] == 0) return 0;
    }

    // Write n-1 as d * 2^s
    u64 d = n - 1;
    int s = 0;
    while ((d & 1) == 0) { d >>= 1; s++; }

    // Deterministic witness set for 64-bit integers
    const u64 witnesses[] = {2ULL, 325ULL, 9375ULL, 28178ULL, 450775ULL, 9780504ULL, 1795265022ULL};
    for (size_t i = 0; i < sizeof(witnesses)/sizeof(witnesses[0]); ++i) {
        u64 a = witnesses[i] % n;
        if (a <= 1) continue;
        u64 x = pow_mod(a, d, n);
        if (x == 1 || x == n-1) continue;
        int composite = 1;
        for (int r = 1; r < s; ++r) {
            x = mul_mod(x, x, n);
            if (x == n - 1) { composite = 0; break; }
        }
        if (composite) return 0;
    }
    return 1;
}

/* ---------- random prime generation in [low, high) ---------- */

static u64 rand_in_range(u64 low, u64 high) {
    if (low >= high) return low;
    u64 range = high - low;
    // combine two rand() calls to get 31+31 bits -> 62 bits (ok for our toy ranges)
    u64 r = ((u64)rand() << 31) ^ (u64)rand();
    return low + (r % range);
}

static u64 gen_prime(u64 low, u64 high) {
    for (int attempts = 0; attempts < 100000; ++attempts) {
        u64 cand = rand_in_range(low, high);
        cand |= 1ULL; // make odd
        if (is_prime_mr(cand)) return cand;
    }
    // fallback (shouldn't normally happen)
    return 3;
}

/* ---------- RSA structures & operations ---------- */

typedef struct {
    u64 n;
    u64 e;
} RSA_Pub;

typedef struct {
    u64 n;
    u64 d;
} RSA_Priv;

typedef struct {
    RSA_Pub pub;
    RSA_Priv priv;
} RSAKeys;

static RSAKeys rsa_generate(u64 p_low, u64 p_high, u64 q_low, u64 q_high) {
    RSAKeys K;
    u64 p = gen_prime(p_low, p_high);
    u64 q = gen_prime(q_low, q_high);
    while (q == p) q = gen_prime(q_low, q_high);

    u64 n = p * q;
    u64 phi = (p - 1) * (q - 1);

    u64 e = 65537ULL;
    // ensure e and phi are coprime
    int64_t x,y;
    while (egcd((int64_t)e, (int64_t)phi, &x, &y) != 1) {
        e += 2;
    }
    u64 d = inv_mod(e, phi);

    K.pub.n = n; K.pub.e = e;
    K.priv.n = n; K.priv.d = d;

    printf("rsa_generate() info:\n");
    printf("  p = %llu\n", (unsigned long long)p);
    printf("  q = %llu\n", (unsigned long long)q);
    printf("  n = %llu\n", (unsigned long long)n);
    printf("  phi = %llu\n", (unsigned long long)phi);
    printf("  e = %llu\n", (unsigned long long)e);
    printf("  d = %llu\n", (unsigned long long)d);

    return K;
}

static u64 rsa_encrypt(u64 m, RSA_Pub pub) {
    return pow_mod(m, pub.e, pub.n);
}

static u64 rsa_decrypt(u64 c, RSA_Priv priv) {
    return pow_mod(c, priv.d, priv.n);
}

/* ---------- Demo main ---------- */

int main(void) {
    srand((unsigned)time(NULL) ^ 0xABCD1234);

    /* Simulated "4096-bit" ranges are represented by large 64-bit ranges here.
     * For demonstration choose non-overlapping ranges for p and q.
     */
    u64 p_lo = 100000000ULL;
    u64 p_hi = 500000000ULL;
    u64 q_lo = 500000000ULL;
    u64 q_hi = 1000000000ULL;

    RSAKeys keys = rsa_generate(p_lo, p_hi, q_lo, q_hi);

    u64 message = 987654321ULL;
    printf("\nOriginal message: %llu\n", (unsigned long long)message);

    u64 ct = rsa_encrypt(message, keys.pub);
    printf("Encrypted: %llu\n", (unsigned long long)ct);

    u64 pt = rsa_decrypt(ct, keys.priv);
    printf("Decrypted: %llu\n", (unsigned long long)pt);

    printf("Decryption %s\n", (pt == message) ? "succeeded (MATCH)" : "FAILED");

    return 0;
}
