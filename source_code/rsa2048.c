#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>

void rsa_generate_2048(mpz_t n, mpz_t e, mpz_t d, gmp_randstate_t state) {
    mpz_t p, q, phi, p1, q1, g;
    mpz_inits(p, q, phi, p1, q1, g, NULL);

    // Generate two random 1024-bit primes p and q
    mpz_urandomb(p, state, 1024);
    mpz_nextprime(p, p);

    do {
        mpz_urandomb(q, state, 1024);
        mpz_nextprime(q, q);
    } while (mpz_cmp(p, q) == 0); // ensure p != q

    // n = p * q
    mpz_mul(n, p, q);

    // phi = (p-1)*(q-1)
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);

    // Choose public exponent e (start with 65537)
    mpz_set_ui(e, 65537);

    // Ensure gcd(e, phi) == 1
    mpz_gcd(g, e, phi);
    while (mpz_cmp_ui(g, 1) != 0) {
        mpz_add_ui(e, e, 2);   // just bump e by 2 until it’s coprime
        mpz_gcd(g, e, phi);
    }

    // Compute d = e^{-1} mod phi
    if (mpz_invert(d, e, phi) == 0) {
        fprintf(stderr, "Error: modular inverse for d does not exist\n");
        exit(1);
    }

    mpz_clears(p, q, phi, p1, q1, g, NULL);
}

int main(void) {
    // Random state for GMP
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    printf("Generating 2048-bit RSA keypair...\n");
    rsa_generate_2048(n, e, d, state);

    // Show bit length of n
    printf("Modulus n size: %zu bits\n", mpz_sizeinbase(n, 2));

    // Test: encrypt and decrypt a small message
    mpz_t m, c, m2;
    mpz_inits(m, c, m2, NULL);

    // message m (must be < n)
    mpz_set_ui(m, 123456789); // small test integer

    // c = m^e mod n
    mpz_powm(c, m, e, n);

    // m2 = c^d mod n
    mpz_powm(m2, c, d, n);

    printf("\nPublic key (e, n):\n");
    gmp_printf("e = %Zd\n", e);
    gmp_printf("n = %Zd\n", n);

    printf("\nPrivate key (d, n):\n");
    gmp_printf("d = %Zd\n", d);

    printf("\nTest message:\n");
    gmp_printf("m  = %Zd\n", m);
    gmp_printf("c  = %Zd\n", c);
    gmp_printf("m' = %Zd\n", m2);

    if (mpz_cmp(m, m2) == 0) {
        printf("\nDecryption OK (m == m')\n");
    } else {
        printf("\nDecryption FAILED (m != m')\n");
    }

    mpz_clears(n, e, d, m, c, m2, NULL);
    gmp_randclear(state);
    return 0;
}
