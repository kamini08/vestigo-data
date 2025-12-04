#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __SDCC
int putchar(int c) { (void)c; return c; }
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/*
 * Toy ECC demo (different style from your original)
 * Curve: y^2 = x^3 + A*x + B (mod P)
 * Uses small prime P for demonstration only (NOT secure)
 */

typedef struct {
    uint64_t x;
    uint64_t y;
    int infinity;
} Point;

typedef struct {
    uint64_t P;
    uint64_t A;
    uint64_t B;
    Point  base;
    uint64_t order; /* not a real order for demo, just used as mod for scalar ops here */
} Curve;

/* --- modular helpers --- */

static uint64_t modnorm(int64_t v, uint64_t m) {
    int64_t r = v % (int64_t)m;
    if (r < 0) r += m;
    return (uint64_t)r;
}

static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m) {
    uint64_t r = a + b;
    if (r >= m) r -= m;
    return r % m;
}

static uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m) {
    return (a >= b) ? (a - b) % m : (m - (b - a) % m) % m;
}

static uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m) {
    /* simple multiply then mod; numbers small for demo */
    return (uint64_t)(((__uint128_t)a * b) % m);
}

/* Extended Euclidean for modular inverse */
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

static uint64_t mod_inv(uint64_t a, uint64_t m) {
    int64_t x, y;
    int64_t g = egcd((int64_t)a, (int64_t)m, &x, &y);
    if (g != 1) {
        /* inverse does not exist; for demo return 0 */
        return 0;
    }
    int64_t inv = x % (int64_t)m;
    if (inv < 0) inv += m;
    return (uint64_t)inv;
}

/* modular exponentiation (unused but handy) */
static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t m) {
    __uint128_t res = 1;
    __uint128_t b = base % m;
    while (exp) {
        if (exp & 1) res = (res * b) % m;
        b = (b * b) % m;
        exp >>= 1;
    }
    return (uint64_t)res;
}

/* --- curve initialization (different values) --- */
Curve init_demo_curve(void) {
    Curve C;
    /* Small demo curve over prime P = 257 (a cute small prime) */
    C.P = 257;
    /* choose A,B such that curve has some points: y^2 = x^3 + 2x + 2 */
    C.A = 2;
    C.B = 2;
    /* pick a base point (found by simple search or chosen) */
    C.base.x = 5;
    C.base.y = 1;
    C.base.infinity = 0;
    C.order = 257; /* toy modulus for scalar operations */
    return C;
}

/* --- point helpers --- */

static Point point_infinity(void) {
    Point p = {0,0,1};
    return p;
}

static int point_is_equal(const Point *P, const Point *Q) {
    if (P->infinity && Q->infinity) return 1;
    if (P->infinity || Q->infinity) return 0;
    return (P->x == Q->x && P->y == Q->y);
}

/* point doubling */
Point point_double(const Point *P, const Curve *C) {
    Point R = point_infinity();
    if (P->infinity) return R;
    if (P->y == 0) return R; /* tangent vertical => infinity */

    uint64_t Pmod = C->P;
    /* lambda = (3*x^2 + A) / (2*y) mod P */
    uint64_t num = mod_add(mod_mul(3, mod_mul(P->x, P->x, Pmod), Pmod), C->A % Pmod, Pmod);
    uint64_t den = mod_mul(2, P->y, Pmod);
    uint64_t den_inv = mod_inv(den, Pmod);
    if (den_inv == 0) return R; /* won't happen in demo usually */

    uint64_t lambda = mod_mul(num, den_inv, Pmod);

    /* xr = lambda^2 - 2*x */
    uint64_t xr = mod_sub(mod_mul(lambda, lambda, Pmod), mod_mul(2, P->x, Pmod), Pmod);
    /* yr = lambda*(x - xr) - y */
    uint64_t yr = mod_sub(mod_mul(lambda, mod_sub(P->x, xr, Pmod), Pmod), P->y, Pmod);

    R.x = xr; R.y = yr; R.infinity = 0;
    return R;
}

/* point addition P + Q */
Point point_add(const Point *P, const Point *Q, const Curve *C) {
    if (P->infinity) return *Q;
    if (Q->infinity) return *P;

    /* if x1 == x2 and y1 == (-y2) mod p => infinity */
    uint64_t Pmod = C->P;
    if (P->x == Q->x) {
        if (mod_add(P->y, Q->y, Pmod) % Pmod == 0) return point_infinity();
        /* else they are equal point => doubling */
        return point_double(P, C);
    }

    /* lambda = (y2 - y1) / (x2 - x1) */
    uint64_t num = mod_sub(Q->y, P->y, Pmod);
    uint64_t den = mod_sub(Q->x, P->x, Pmod);
    uint64_t den_inv = mod_inv(den, Pmod);
    if (den_inv == 0) return point_infinity(); /* degenerate */

    uint64_t lambda = mod_mul(num, den_inv, Pmod);
    uint64_t xr = mod_sub(mod_sub(mod_mul(lambda, lambda, Pmod), P->x, Pmod), Q->x, Pmod);
    uint64_t yr = mod_sub(mod_mul(lambda, mod_sub(P->x, xr, Pmod), Pmod), P->y, Pmod);

    Point R = {xr, yr, 0};
    return R;
}

/* scalar multiplication: left-to-right double-and-add (different loop style) */
Point scalar_mul(uint64_t k, const Point *P, const Curve *C) {
    Point R = point_infinity();
    Point Q = *P;

    if (k == 0) return R;

    /* find highest bit */
    int highest = 63 - __builtin_clzll(k);
    for (int i = highest; i >= 0; --i) {
        /* double */
        R = point_double(&R, C);
        if ((k >> i) & 1) {
            R = point_add(&R, &Q, C);
        }
    }
    return R;
}

/* --- ECDH Key generation & shared secret --- */
typedef struct {
    uint64_t priv;
    Point pub;
} KeyPair;

KeyPair gen_keypair(const Curve *C) {
    KeyPair kp;
    do {
        kp.priv = 1 + (uint64_t)(rand() % (C->order - 1));
    } while (kp.priv == 0);
    kp.pub = scalar_mul(kp.priv, &C->base, C);
    return kp;
}

Point compute_shared(uint64_t my_priv, const Point *their_pub, const Curve *C) {
    return scalar_mul(my_priv, their_pub, C);
}

/* --- simple ECDSA-like (toy) sign & verify --- */
typedef struct { uint64_t r, s; } Sig;

Sig ecdsa_sign_toy(uint64_t msg, uint64_t priv, const Curve *C) {
    Sig sg = {0,0};
    uint64_t n = C->order;
    while (1) {
        uint64_t k = 1 + (uint64_t)(rand() % (n - 1));
        Point R = scalar_mul(k, &C->base, C);
        if (R.infinity) continue;
        sg.r = R.x % n;
        if (sg.r == 0) continue;

        uint64_t k_inv = mod_inv(k % n, n);
        if (k_inv == 0) continue;

        uint64_t tmp = ( (msg % n) + mod_mul(sg.r, priv % n, n) ) % n;
        sg.s = mod_mul(k_inv, tmp, n);
        if (sg.s == 0) continue;
        break;
    }
    return sg;
}

int ecdsa_verify_toy(uint64_t msg, const Sig *sg, const Point *pub, const Curve *C) {
    uint64_t n = C->order;
    if (sg->r == 0 || sg->r >= n || sg->s == 0 || sg->s >= n) return 0;
    uint64_t w = mod_inv(sg->s % n, n);
    if (w == 0) return 0;
    uint64_t u1 = mod_mul(msg % n, w, n);
    uint64_t u2 = mod_mul(sg->r % n, w, n);
    Point p1 = scalar_mul(u1, &C->base, C);
    Point p2 = scalar_mul(u2, pub, C);
    Point X = point_add(&p1, &p2, C);
    if (X.infinity) return 0;
    return ( (X.x % n) == (sg->r % n) );
}

/* --- utility: print a point --- */
void print_point(const char *label, const Point *P) {
    if (P->infinity) {
        printf("%s: POINT_AT_INFINITY\n", label);
    } else {
        printf("%s: (x=%llu, y=%llu)\n", label, (unsigned long long)P->x, (unsigned long long)P->y);
    }
}

int main(void) {
    srand((unsigned)time(NULL));

    Curve C = init_demo_curve();
    printf("Demo ECC curve: y^2 = x^3 + %llux + %llu (mod %llu)\n",
           (unsigned long long)C.A, (unsigned long long)C.B, (unsigned long long)C.P);
    print_point("Base point G", &C.base);
    printf("Order (toy) = %llu\n\n", (unsigned long long)C.order);

    /* ECDH demo */
    printf("---- ECDH demo ----\n");
    KeyPair A = gen_keypair(&C);
    KeyPair B = gen_keypair(&C);
    printf("Alice priv=%llu\n", (unsigned long long)A.priv);
    print_point("Alice pub", &A.pub);
    printf("Bob priv=%llu\n", (unsigned long long)B.priv);
    print_point("Bob pub", &B.pub);

    Point S1 = compute_shared(A.priv, &B.pub, &C);
    Point S2 = compute_shared(B.priv, &A.pub, &C);
    print_point("Alice shared", &S1);
    print_point("Bob shared  ", &S2);
    printf("Shared match: %s\n\n", point_is_equal(&S1, &S2) ? "YES" : "NO");

    /* ECDSA demo */
    printf("---- ECDSA (toy) demo ----\n");
    uint64_t message = 0xdeadbeef;
    Sig signature = ecdsa_sign_toy(message, A.priv, &C);
    printf("Message: 0x%llx\n", (unsigned long long)message);
    printf("Signature: r=%llu, s=%llu\n", (unsigned long long)signature.r, (unsigned long long)signature.s);

    int ok = ecdsa_verify_toy(message, &signature, &A.pub, &C);
    printf("Signature valid: %s\n", ok ? "YES" : "NO");

    /* small sanity checks: scalar mul by 0 and 1 */
    Point zero = scalar_mul(0, &C.base, &C);
    print_point("0 * G", &zero);
    Point one = scalar_mul(1, &C.base, &C);
    print_point("1 * G", &one);

    return 0;
}
