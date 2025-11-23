#include <stdio.h>
#include <stdint.h>
#include <string.h>

// SHA-1 Implementation

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))

typedef struct {
    uint8_t data[SHA1_BLOCK_SIZE];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[5];
} SHA1_CTX;

void sha1_transform(SHA1_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, k, temp, w[80];
    int i, j;
    
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
    
    for (; i < 80; ++i) {
        w[i] = ROTLEFT((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
    }
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    
    for (i = 0; i < 80; ++i) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        
        temp = ROTLEFT(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = temp;
    }
    
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(SHA1_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
}

void sha1_update(SHA1_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == SHA1_BLOCK_SIZE) {
            sha1_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha1_final(SHA1_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < SHA1_BLOCK_SIZE) {
            ctx->data[i++] = 0x00;
        }
        sha1_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha1_transform(ctx, ctx->data);
    
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    }
}

int main() {
    const char *message = "The quick brown fox jumps over the lazy dog";
    uint8_t hash[SHA1_DIGEST_SIZE];
    SHA1_CTX ctx;
    
    printf("SHA-1 Hash Function\n");
    printf("Message: %s\n", message);
    
    sha1_init(&ctx);
    sha1_update(&ctx, (uint8_t*)message, strlen(message));
    sha1_final(&ctx, hash);
    
    printf("SHA-1: ");
    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}