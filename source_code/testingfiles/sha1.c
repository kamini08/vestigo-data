#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __SDCC
int putchar(int c) { (void)c; return c; }
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Alternate SHA-1 implementation */

#define SHA1_BLOCK 64
#define SHA1_HASH 20

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef struct {
    uint32_t h[5];
    uint64_t bitcount;
    uint8_t buffer[SHA1_BLOCK];
    size_t buffer_len;
} SHA1_ALT;

/* ------------------- Core SHA-1 Compression ------------------- */

static void sha1_compress(SHA1_ALT *ctx, const uint8_t block[64]) {
    uint32_t w[80];
    uint32_t a, b, c, d, e, temp;

    /* load block in big endian */
    for (int i = 0; i < 16; i++) {
        w[i] = (block[4*i] << 24)
             | (block[4*i+1] << 16)
             | (block[4*i+2] << 8)
             | (block[4*i+3]);
    }

    /* expand */
    for (int i = 16; i < 80; i++)
        w[i] = ROL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    /* working vars */
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        temp = ROL32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROL32(b, 30);
        b = a;
        a = temp;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}

/* ------------------- Initialization ------------------- */

static void sha1_init_alt(SHA1_ALT *ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;

    ctx->bitcount = 0;
    ctx->buffer_len = 0;
}

/* ------------------- Update ------------------- */

static void sha1_update_alt(SHA1_ALT *ctx, const uint8_t *data, size_t len) {
    ctx->bitcount += (uint64_t)len * 8;

    while (len > 0) {
        size_t space = SHA1_BLOCK - ctx->buffer_len;
        size_t copy_len = (len < space) ? len : space;

        memcpy(ctx->buffer + ctx->buffer_len, data, copy_len);
        ctx->buffer_len += copy_len;
        data += copy_len;
        len -= copy_len;

        if (ctx->buffer_len == 64) {
            sha1_compress(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

/* ------------------- Final ------------------- */

static void sha1_final_alt(SHA1_ALT *ctx, uint8_t out[20]) {
    /* append 0x80 */
    ctx->buffer[ctx->buffer_len++] = 0x80;

    /* if not enough room for message length */
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < 64)
            ctx->buffer[ctx->buffer_len++] = 0x00;
        sha1_compress(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }

    /* pad until 56 bytes */
    while (ctx->buffer_len < 56)
        ctx->buffer[ctx->buffer_len++] = 0x00;

    /* append bit count (big endian) */
    uint64_t bc = ctx->bitcount;
    for (int i = 7; i >= 0; i--) {
        ctx->buffer[ctx->buffer_len++] = (uint8_t)(bc >> (i * 8));
    }

    sha1_compress(ctx, ctx->buffer);

    /* output digest */
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (ctx->h[i] >> 24) & 0xFF;
        out[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
        out[i*4+2] = (ctx->h[i] >> 8) & 0xFF;
        out[i*4+3] = ctx->h[i] & 0xFF;
    }
}

/* ------------------- Test Program ------------------- */

int main() {
    const char *msg = "The quick brown fox jumps over the lazy dog";
    uint8_t digest[20];

    SHA1_ALT ctx;
    sha1_init_alt(&ctx);
    sha1_update_alt(&ctx, (const uint8_t *)msg, strlen(msg));
    sha1_final_alt(&ctx, digest);

    printf("Alternate SHA-1 Implementation\n");
    printf("Message: %s\nSHA-1: ", msg);

    for (int i = 0; i < 20; i++)
        printf("%02x", digest[i]);

    printf("\n");
    return 0;
}
