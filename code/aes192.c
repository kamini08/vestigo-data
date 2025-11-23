#include <stdio.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define AES192_NUM_ROUNDS 12

// S-Box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Enough Rcon values for AES-192
static const uint8_t rcon[10] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b
};

typedef struct {
    uint8_t round_keys[13][4][4]; // 13 round keys for AES-192
} AES192_CTX;

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

static void shift_rows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 1: left shift by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2: left shift by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: left shift by 3 (or right shift by 1)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

static void mix_columns(uint8_t state[4][4]) {
    uint8_t tmp[4];

    for (int i = 0; i < 4; i++) {
        tmp[0] = state[0][i];
        tmp[1] = state[1][i];
        tmp[2] = state[2][i];
        tmp[3] = state[3][i];

        state[0][i] = (uint8_t)(xtime(tmp[0]) ^ xtime(tmp[1]) ^ tmp[1] ^ tmp[2] ^ tmp[3]);
        state[1][i] = (uint8_t)(tmp[0] ^ xtime(tmp[1]) ^ xtime(tmp[2]) ^ tmp[2] ^ tmp[3]);
        state[2][i] = (uint8_t)(tmp[0] ^ tmp[1] ^ xtime(tmp[2]) ^ xtime(tmp[3]) ^ tmp[3]);
        state[3][i] = (uint8_t)(xtime(tmp[0]) ^ tmp[0] ^ tmp[1] ^ tmp[2] ^ xtime(tmp[3]));
    }
}

static void add_round_key(uint8_t state[4][4], uint8_t round_key[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= round_key[i][j];
        }
    }
}

static void key_expansion_192(const uint8_t *key, AES192_CTX *ctx) {
    int key_words = 6; // 192-bit key = 6 words
    int num_rounds = AES192_NUM_ROUNDS;
    int i, j;
    uint8_t temp[4];

    // Copy initial key (6 words -> 24 bytes)
    for (i = 0; i < key_words; i++) {
        ctx->round_keys[i / 4][0][i % 4] = key[4 * i];
        ctx->round_keys[i / 4][1][i % 4] = key[4 * i + 1];
        ctx->round_keys[i / 4][2][i % 4] = key[4 * i + 2];
        ctx->round_keys[i / 4][3][i % 4] = key[4 * i + 3];
    }

    // Generate remaining words up to 4*(num_rounds+1) = 52 words
    for (i = key_words; i < 4 * (num_rounds + 1); i++) {
        int prev_word = i - 1;
        int prev_key_word = i - key_words;

        for (j = 0; j < 4; j++) {
            temp[j] = ctx->round_keys[prev_word / 4][j][prev_word % 4];
        }

        if (i % key_words == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord
            for (j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }

            temp[0] ^= rcon[i / key_words];
        }

        for (j = 0; j < 4; j++) {
            ctx->round_keys[i / 4][j][i % 4] =
                (uint8_t)(ctx->round_keys[prev_key_word / 4][j][prev_key_word % 4] ^ temp[j]);
        }
    }
}

void aes192_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *key) {
    AES192_CTX ctx;
    uint8_t state[4][4];

    key_expansion_192(key, &ctx);

    // Copy plaintext (column-major as in your code)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = plaintext[i + 4 * j];
        }
    }

    // Initial AddRoundKey
    add_round_key(state, ctx.round_keys[0]);

    // 11 full rounds
    for (int round = 1; round < AES192_NUM_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx.round_keys[round]);
    }

    // Final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx.round_keys[AES192_NUM_ROUNDS]);

    // Copy state to ciphertext
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ciphertext[i + 4 * j] = state[i][j];
        }
    }
}

int main(void) {
    // Same plaintext you used
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    // AES-192 key (your test vector)
    uint8_t key192[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t ciphertext[16];

    aes192_encrypt(plaintext, ciphertext, key192);

    printf("=== AES-192 ===\n");
    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
