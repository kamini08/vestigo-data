#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __SDCC
int putchar(int c) { (void)c; return c; }
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define XRKEY 32
#define XRBLOCK 16
#define XRROUND 6

/* Context */
typedef struct {
    uint8_t master[XRKEY];
    uint8_t rkey[XRROUND][XRKEY];
} XORCTX;

/* Simple S-box */
static const uint8_t SBOX[256] = {
    0x6A,0x12,0xF3,0x88,0x0F,0x34,0xC5,0x7E,0x91,0x55,0xA2,0xCE,0x1D,0xB8,0xE0,0x43,
    0x9C,0x01,0x6F,0xDD,0x84,0x23,0x5A,0xBC,0x4E,0x67,0x11,0x02,0x98,0x76,0xAF,0xF9,
    0xC2,0x5D,0x7A,0x49,0xB1,0xEA,0x0C,0x3E,0x82,0x14,0xF5,0x67,0x33,0xAC,0x9F,0xD0,
    0x2A,0x51,0x70,0xC9,0x0D,0xBE,0xE8,0x47,0x95,0x13,0x64,0x1F,0xC4,0x7B,0x22,0xDA,
    0xE3,0xF0,0x28,0x8D,0x36,0x42,0xA9,0xCD,0x58,0x6C,0x0A,0x35,0xB7,0xF6,0x89,0x9E,
    0x65,0xC8,0x27,0xE4,0x0B,0x92,0xAF,0x4C,0x1A,0x7D,0x52,0xFC,0x33,0xE1,0xD4,0x0E,
    0xB3,0xA4,0x19,0x6B,0x87,0x54,0xFE,0x20,0xDC,0x3A,0x66,0x90,0xAB,0x17,0x7C,0x48,
    0x11,0x62,0xC3,0x39,0xE9,0x05,0xB0,0x97,0x4F,0x81,0xF8,0x2F,0x0C,0xD1,0x25,0x76,
    0x59,0x1C,0xA3,0x88,0x5F,0x6E,0x92,0x47,0xCB,0x3C,0xBD,0x04,0xE6,0x7A,0x55,0x9B,
    0x10,0xD9,0x2E,0xF1,0x68,0x4D,0xB5,0xAC,0x32,0x03,0x91,0x7F,0xC7,0x58,0xE2,0x0A,
    0x40,0x29,0xDF,0x63,0x8C,0x12,0xFA,0xB6,0x35,0xEE,0x57,0x03,0x94,0x7D,0xA1,0xC0,
    0xDA,0x18,0x4B,0x6C,0xB2,0x0F,0x79,0x53,0xEC,0x36,0xA7,0x91,0x08,0x62,0xDF,0xCB,
    0x14,0xC6,0x7E,0xF3,0x9A,0x55,0x81,0x24,0x39,0xD5,0xAE,0x02,0xF7,0x60,0x48,0x8E,
    0x2C,0xD0,0x93,0x11,0xF4,0x3F,0x52,0xED,0x86,0xC1,0x79,0xBE,0x25,0x4A,0x07,0x94,
    0x64,0x27,0xD8,0x35,0xAC,0xF2,0x8B,0x13,0x50,0xE7,0x9D,0x04,0x7A,0xCA,0xB1,0x56,
    0x8F,0x05,0xD6,0xFE,0x21,0x90,0x34,0xC2,0x6A,0x49,0xBE,0x0D,0x78,0xE3,0x57,0x00
};

/* Rotate left 8-bit */
static inline uint8_t rol(uint8_t v, int s) {
    return (v << s) | (v >> (8 - s));
}

/* Generate round keys */
void xor_init(XORCTX *c, const uint8_t *key) {
    memcpy(c->master, key, XRKEY);

    for (int r=0; r<XRROUND; r++) {
        for (int i=0; i<XRKEY; i++) {
            uint8_t v = key[(i + r) % XRKEY];
            v ^= SBOX[(i * 7 + r * 13) & 0xFF];
            v ^= rol(r + i, r % 5);
            c->rkey[r][i] = v;
        }
    }
}

/* substitute */
static void sub(uint8_t *b) {
    for (int i=0;i<XRBLOCK;i++) b[i] = SBOX[b[i]];
}

/* permute */
static void perm(uint8_t *b) {
    uint8_t t[XRBLOCK];
    for(int i=0;i<XRBLOCK;i++)
        t[i] = b[(i*3 + 5) % XRBLOCK];
    memcpy(b,t,XRBLOCK);
}

/* diffusion */
static void diff(uint8_t *b) {
    for(int i=0;i<XRBLOCK;i++){
        int p=(i+XRBLOCK-1)%XRBLOCK;
        int n=(i+1)%XRBLOCK;
        b[i] ^= rol(b[p],2) ^ (b[n]>>3);
    }
}

/* encrypt a block */
void xor_encrypt_block(const uint8_t *in, uint8_t *out, XORCTX *c) {
    uint8_t s[XRBLOCK];
    memcpy(s,in,XRBLOCK);

    for(int r=0;r<XRROUND;r++){
        for(int i=0;i<XRBLOCK;i++)
            s[i] ^= c->rkey[r][i];

        sub(s);
        perm(s);
        if(r < XRROUND-1) diff(s);
    }
    memcpy(out,s,XRBLOCK);
}

/* decrypt a block */
void xor_decrypt_block(const uint8_t *in, uint8_t *out, XORCTX *c) {
    uint8_t s[XRBLOCK];
    memcpy(s,in,XRBLOCK);

    for(int r=XRROUND-1;r>=0;r--){
        for(int x=0;x<2;x++) diff(s); // approximate inverse

        uint8_t t[XRBLOCK];
        for(int i=0;i<XRBLOCK;i++)
            t[(i*3+5)%XRBLOCK] = s[i];
        memcpy(s,t,XRBLOCK);

        for(int i=0;i<XRBLOCK;i++)
            for(int k=0;k<256;k++)
                if(SBOX[k] == s[i]) { s[i]=k; break; }

        for(int i=0;i<XRBLOCK;i++)
            s[i] ^= c->rkey[r][i];
    }
    memcpy(out,s,XRBLOCK);
}

/* CTR stream mode */
void xor_stream(const uint8_t *in, uint8_t *out, size_t len, XORCTX *c, uint64_t nonce) {
    uint8_t ks[XRBLOCK], ctr[XRBLOCK];

    for(size_t i=0;i<len;i+=XRBLOCK) {
        uint64_t blk = i / XRBLOCK;
        memcpy(ctr,&nonce,8);
        memcpy(ctr+8,&blk,8);

        xor_encrypt_block(ctr,ks,c);

        size_t n = (i+XRBLOCK>len)? len-i : XRBLOCK;
        for(size_t j=0;j<n;j++)
            out[i+j] = in[i+j] ^ ks[j];
    }
}

/* --------------------------------------------------------- */
int main(){
    uint8_t key[XRKEY];
    for(int i=0;i<XRKEY;i++) key[i]=i*4;

    XORCTX ctx;
    xor_init(&ctx,key);

    uint8_t pt[XRBLOCK] = "XorCipher Test!";
    uint8_t ct[XRBLOCK], dt[XRBLOCK];

    printf("Alternate XOR Cipher (Simple)\n\n");

    xor_encrypt_block(pt,ct,&ctx);
    xor_decrypt_block(ct,dt,&ctx);

    printf("Block:\n");
    printf("Plain : ");
    for(int i=0;i<XRBLOCK;i++) printf("%02x ",pt[i]); printf("\n");
    printf("Cipher: ");
    for(int i=0;i<XRBLOCK;i++) printf("%02x ",ct[i]); printf("\n");
    printf("Dec   : ");
    for(int i=0;i<XRBLOCK;i++) printf("%02x ",dt[i]); printf("\n\n");

    const char *msg="Alternate XOR CTR stream mode works!";
    size_t L=strlen(msg);
    uint8_t *sc=malloc(L), *sd=malloc(L);

    xor_stream((uint8_t*)msg,sc,L,&ctx,0xAABBCCDDEEFF0011ULL);
    xor_stream(sc,sd,L,&ctx,0xAABBCCDDEEFF0011ULL);

    printf("Stream Encrypted: ");
    for(size_t i=0;i<L;i++) printf("%02x",sc[i]);
    printf("\n");

    printf("Stream Decrypted: %s\n", sd);

    free(sc); free(sd);
}
