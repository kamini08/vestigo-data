#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __SDCC
int putchar(int c) { (void)c; return c; }
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Completely different SHA-224 implementation */

#define BLK 64
#define OUT224 28

/* rotation */
#define RR(x,n) (((x) >> (n)) | ((x) << (32-(n))))

/* SHA-256 style functions */
#define B0(x) (RR(x,2) ^ RR(x,13) ^ RR(x,22))
#define B1(x) (RR(x,6) ^ RR(x,11) ^ RR(x,25))
#define G0(x) (RR(x,7) ^ RR(x,18) ^ ((x)>>3))
#define G1(x) (RR(x,17)^ RR(x,19)^ ((x)>>10))
#define CH(x,y,z) (((x)&(y)) ^ (~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))

/* constants */
static const uint32_t C224[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* alternate context structure */
typedef struct {
    uint32_t H[8];
    uint8_t buf[BLK];
    uint64_t bits;
    uint32_t used;
} SHA224_ALT;

/* transform block */
static void do_block(SHA224_ALT *s, const uint8_t b[64]) {
    uint32_t W[64];
    for (int i=0;i<16;i++) {
        W[i] = ((uint32_t)b[i*4]<<24) |
               ((uint32_t)b[i*4+1]<<16) |
               ((uint32_t)b[i*4+2]<<8) |
               ((uint32_t)b[i*4+3]);
    }
    for (int i=16;i<64;i++) {
        W[i] = G1(W[i-2]) + W[i-7] + G0(W[i-15]) + W[i-16];
    }

    uint32_t a=s->H[0],b2=s->H[1],c=s->H[2],d=s->H[3];
    uint32_t e=s->H[4],f=s->H[5],g=s->H[6],h=s->H[7];

    for (int i=0;i<64;i++) {
        uint32_t t1 = h + B1(e) + CH(e,f,g) + C224[i] + W[i];
        uint32_t t2 = B0(a) + MAJ(a,b2,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b2;
        b2 = a;
        a = t1 + t2;
    }

    s->H[0]+=a; s->H[1]+=b2; s->H[2]+=c; s->H[3]+=d;
    s->H[4]+=e; s->H[5]+=f;  s->H[6]+=g; s->H[7]+=h;
}

/* init with SHA-224 IV */
void sha224_alt_init(SHA224_ALT *s) {
    s->H[0]=0xc1059ed8;
    s->H[1]=0x367cd507;
    s->H[2]=0x3070dd17;
    s->H[3]=0xf70e5939;
    s->H[4]=0xffc00b31;
    s->H[5]=0x68581511;
    s->H[6]=0x64f98fa7;
    s->H[7]=0xbefa4fa4;

    s->used = 0;
    s->bits = 0;
}

/* update */
void sha224_alt_update(SHA224_ALT *s, const uint8_t *in, size_t len) {
    s->bits += (uint64_t)len * 8;

    while (len--) {
        s->buf[s->used++] = *in++;
        if (s->used == 64) {
            do_block(s, s->buf);
            s->used = 0;
        }
    }
}

/* finalize */
void sha224_alt_final(SHA224_ALT *s, uint8_t out[28]) {
    s->buf[s->used++] = 0x80;

    /* pad to 56 bytes */
    if (s->used > 56) {
        while (s->used < 64) s->buf[s->used++] = 0;
        do_block(s, s->buf);
        s->used = 0;
    }
    while (s->used < 56) s->buf[s->used++] = 0;

    /* append bit count big-endian */
    uint64_t x = s->bits;
    for (int i=7;i>=0;i--) {
        s->buf[s->used++] = (uint8_t)(x>>(i*8));
    }

    do_block(s, s->buf);

    /* SHA-224 = first 7 words of SHA-256 */
    for (int i=0;i<7;i++) {
        out[i*4+0]=(s->H[i]>>24)&0xff;
        out[i*4+1]=(s->H[i]>>16)&0xff;
        out[i*4+2]=(s->H[i]>>8)&0xff;
        out[i*4+3]=(s->H[i])&0xff;
    }
}

/* test */
int main() {
    const char *msg = "The quick brown fox jumps over the lazy dog";
    uint8_t d[OUT224];

    SHA224_ALT ctx;
    sha224_alt_init(&ctx);
    sha224_alt_update(&ctx,(const uint8_t*)msg,strlen(msg));
    sha224_alt_final(&ctx,d);

    printf("Alternate SHA-224\nMessage: %s\nSHA-224: ", msg);
    for (int i=0;i<OUT224;i++) printf("%02x", d[i]);
    printf("\n");
}
