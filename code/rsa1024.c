#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// RSA-1024 (Simulated with 64-bit, for real use GMP library)

typedef unsigned long long uint64;

uint64 mod_exp(uint64 base, uint64 exp, uint64 mod) {
    uint64 result = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    
    return result;
}

int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    
    int64_t x1, y1;
    int64_t gcd = extended_gcd(b % a, a, &x1, &y1);
    
    *x = y1 - (b / a) * x1;
    *y = x1;
    
    return gcd;
}

uint64 mod_inverse(uint64 a, uint64 m) {
    int64_t x, y;
    extended_gcd(a, m, &x, &y);
    return (x % m + m) % m;
}

int is_prime(uint64 n, int k) {
    if (n <= 1 || n == 4) return 0;
    if (n <= 3) return 1;
    
    for (int i = 0; i < k; i++) {
        uint64 a = 2 + rand() % (n - 3);
        if (mod_exp(a, n - 1, n) != 1) {
            return 0;
        }
    }
    
    return 1;
}

uint64 generate_prime(uint64 min, uint64 max) {
    uint64 candidate;
    do {
        candidate = min + rand() % (max - min);
        if (candidate % 2 == 0) candidate++;
    } while (!is_prime(candidate, 5));
    
    return candidate;
}

typedef struct {
    uint64 e;
    uint64 n;
} RSA1024_PublicKey;

typedef struct {
    uint64 d;
    uint64 n;
} RSA1024_PrivateKey;

typedef struct {
    RSA1024_PublicKey public_key;
    RSA1024_PrivateKey private_key;
} RSA1024_KeyPair;

RSA1024_KeyPair rsa1024_generate_keypair() {
    RSA1024_KeyPair keypair;
    
    // Simulating 1024-bit with larger 64-bit primes
    uint64 p = generate_prime(1000000, 5000000);
    uint64 q = generate_prime(5000000, 10000000);
    
    while (p == q) {
        q = generate_prime(5000000, 10000000);
    }
    
    uint64 n = p * q;
    uint64 phi = (p - 1) * (q - 1);
    
    uint64 e = 65537;
    while (e < phi) {
        int64_t x, y;
        if (extended_gcd(e, phi, &x, &y) == 1) {
            break;
        }
        e += 2;
    }
    
    uint64 d = mod_inverse(e, phi);
    
    keypair.public_key.e = e;
    keypair.public_key.n = n;
    keypair.private_key.d = d;
    keypair.private_key.n = n;
    
    printf("RSA-1024 Key Generation (simulated)\n");
    printf("  p = %llu\n", p);
    printf("  q = %llu\n", q);
    printf("  n = %llu\n", n);
    printf("  e = %llu\n", e);
    printf("  d = %llu\n", d);
    
    return keypair;
}

uint64 rsa1024_encrypt(uint64 plaintext, RSA1024_PublicKey public_key) {
    return mod_exp(plaintext, public_key.e, public_key.n);
}

uint64 rsa1024_decrypt(uint64 ciphertext, RSA1024_PrivateKey private_key) {
    return mod_exp(ciphertext, private_key.d, private_key.n);
}

int main() {
    srand(1024);
    
    RSA1024_KeyPair keypair = rsa1024_generate_keypair();
    
    uint64 message = 42424242;
    printf("\nOriginal message: %llu\n", message);
    
    uint64 encrypted = rsa1024_encrypt(message, keypair.public_key);
    printf("Encrypted: %llu\n", encrypted);
    
    uint64 decrypted = rsa1024_decrypt(encrypted, keypair.private_key);
    printf("Decrypted: %llu\n", decrypted);
    
    printf("Match: %s\n", (message == decrypted) ? "YES" : "NO");
    
    return 0;
}