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

/*
 * Alternate RSA (toy 64-bit)
 * Uses:
 *   - Miller–Rabin primality test
 *   - Different function names
 *   - Different code organization
 */

typedef uint64_t u64;

/* -------------------------------------------------------------
 * Modular arithmetic helpers
 * ------------------------------------------------------------- */
static u64 modmul(u64 a, u64 b, u64 m) {
    __uint128_t r = ( __uint128_t)a * b;
    return (u64)(r % m);
}

static u64 modpow(u64 base, u64 exp, u64 mod) {
    u64 r = 1;
    while (exp) {
        if (exp & 1) r = modmul(r, base, mod);
        base = modmul(base, base, mod);
        exp >>= 1;
    }
    return r;
}

/* -------------------------------------------------------------
 * Extended Euclidean Algorithm
 * ------------------------------------------------------------- */
static int64_t egcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (!a) {
        *x = 0; *y = 1;
        return b;
    }
    int64_t x1, y1;
    int64_t g = egcd(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return g;
}

static u64 modinv(u64 a, u64 m) {
    int64_t x, y;
    int64_t g = egcd(a, m, &x, &y);
    if (g != 1) return 0;                  /* no inverse */
    int64_t r = x % m;
    return (r < 0) ? r + m : r;
}

/* -------------------------------------------------------------
 * Miller–Rabin primality test
 * ------------------------------------------------------------- */
static int is_probable_prime(u64 n) {
    if (n < 2) return 0;
    for (u64 p : (u64[]){2,3,5,7,11,13,17,19,23}) {
        if (n == p) return 1;
        if (n % p == 0) return 0;
    }

    u64 d = n - 1, s = 0;
    while ((d & 1) == 0) { d >>= 1; s++; }

    /* witnesses (deterministic for 64-bit) */
    u64 testPrimes[] = {2, 325, 9375, 28178, 450775, 9780504, 1795265022};

    for (u64 a : testPrimes) {
        if (a % n == 0) continue;
        u64 x = modpow(a, d, n);
        if (x == 1 || x == n - 1) continue;

        int composite = 1;
        for (u64 r = 1; r < s; r++) {
            x = modmul(x, x, n);
            if (x == n - 1) {
                composite = 0;
                break;
            }
        }
        if (composite) return 0;
    }
    return 1;
}

/* Generate random odd prime in [low, high] */
static u64 random_prime(u64 low, u64 high) {
    u64 p;
    do {
        p = (rand() % (high - low)) + low;
        p |= 1;  /* make odd */
    } while (!is_probable_prime(p));
    return p;
}

/* -------------------------------------------------------------
 * RSA key structures
 * ------------------------------------------------------------- */
typedef struct {
    u64 n, e;
} RSA_PublicKey;

typedef struct {
    u64 n, d;
} RSA_PrivateKey;

typedef struct {
    RSA_PublicKey pub;
    RSA_PrivateKey prv;
} RSA_KeyPair;

/* -------------------------------------------------------------
 * RSA key generation
 * ------------------------------------------------------------- */
static RSA_KeyPair rsa_make_keys(void) {
    RSA_KeyPair K;

    /* Generate two distinct primes */
    u64 p = random_prime(1e6, 5e6);
    u64 q = random_prime(5e6, 9e6);
    while (p == q)
        q = random_prime(5e6, 9e6);

    u64 n   = p * q;
    u64 phi = (p - 1) * (q - 1);

    /* Choose e */
    u64 e = 65537;
    while (egcd(e, phi, (int64_t*)&p, (int64_t*)&q) != 1)
        e += 2;

    /* Compute d */
    u64 d = modinv(e, phi);

    K.pub.n = n;
    K.pub.e = e;
    K.prv.n = n;
    K.prv.d = d;

    printf("Generated RSA keys (toy 64-bit)\n");
    printf(" p   = %llu\n", p);
    printf(" q   = %llu\n", q);
    printf(" n   = %llu\n", n);
    printf(" phi = %llu\n", phi);
    printf(" e   = %llu\n", e);
    printf(" d   = %llu\n\n", d);

    return K;
}

/* -------------------------------------------------------------
 * RSA encrypt / decrypt
 * ------------------------------------------------------------- */
static u64 rsa_encrypt(u64 m, RSA_PublicKey pub) {
    return modpow(m, pub.e, pub.n);
}

static u64 rsa_decrypt(u64 c, RSA_PrivateKey prv) {
    return modpow(c, prv.d, prv.n);
}

/* -------------------------------------------------------------
 * Demo
 * ------------------------------------------------------------- */
int main(void) {
    srand((unsigned)time(NULL));

    RSA_KeyPair keys = rsa_make_keys();

    u64 msg = 12345678;
    printf("Message: %llu\n", msg);

    u64 enc = rsa_encrypt(msg, keys.pub);
    printf("Encrypted: %llu\n", enc);

    u64 dec = rsa_decrypt(enc, keys.prv);
    printf("Decrypted: %llu\n", dec);

    printf("Match: %s\n", (msg == dec) ? "YES" : "NO");

    return 0;
}
