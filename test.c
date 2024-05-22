#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Constants for SHA-1
#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

#define BLOCK_SIZE 64
#define OUTPUT_SIZE 20

void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e, f, k, temp;
    uint32_t w[80];
    
    for (int i = 0; i < 16; ++i) {
        w[i]  = buffer[i * 4] << 24;
        w[i] |= buffer[i * 4 + 1] << 16;
        w[i] |= buffer[i * 4 + 2] << 8;
        w[i] |= buffer[i * 4 + 3];
    }
    
    for (int i = 16; i < 80; ++i) {
        w[i] = LEFTROTATE(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    
    for (int i = 0; i < 80; ++i) {
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
        
        temp = LEFTROTATE(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = LEFTROTATE(b, 30);
        b = a;
        a = temp;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_update(uint32_t state[5], uint64_t bitlen[2], uint8_t buffer[64], const uint8_t data[], size_t len) {
    size_t i, j;
    
    j = (bitlen[0] >> 3) & 63;
    if ((bitlen[0] += len << 3) < (len << 3)) bitlen[1]++;
    bitlen[1] += (len >> 29);
    
    if ((j + len) > 63) {
        memcpy(&buffer[j], data, (i = 64 - j));
        sha1_transform(state, buffer);
        for (; i + 63 < len; i += 64) {
            sha1_transform(state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&buffer[j], &data[i], len - i);
}

void sha1_final(uint32_t state[5], uint64_t bitlen[2], uint8_t buffer[64], uint8_t hash[20]) {
    uint8_t finalcount[8];
    
    for (int i = 0; i < 8; ++i) {
        finalcount[i] = (uint8_t)((bitlen[(i >= 4 ? 0 : 1)]
                        >> ((3 - (i & 3)) * 8) ) & 255);
    }
    sha1_update(state, bitlen, buffer, (const uint8_t *)"\x80", 1);
    
    while ((bitlen[0] & 504) != 448) {
        sha1_update(state, bitlen, buffer, (const uint8_t *)"\0", 1);
    }
    
    sha1_update(state, bitlen, buffer, finalcount, 8);
    
    for (int i = 0; i < 20; ++i) {
        hash[i] = (uint8_t)((state[i>>2] >> ((3-(i & 3)) * 8)) & 255);
    }
}

void sha1(const uint8_t *data, size_t len, uint8_t hash[20]) {
    printf("%d ",len);
    uint32_t state[5] = {H0, H1, H2, H3, H4};
    uint64_t bitlen[2] = {0, 0};
    uint8_t buffer[64];
    
    sha1_update(state, bitlen, buffer, data, len);
    sha1_final(state, bitlen, buffer, hash);
}

void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t hmac[20]) {
    uint8_t k_ipad[BLOCK_SIZE] = {0};
    uint8_t k_opad[BLOCK_SIZE] = {0};
    uint8_t tk[20];
    uint8_t temp_key[BLOCK_SIZE];
    int i;
    
    if (key_len > BLOCK_SIZE) {
        sha1(key, key_len, tk);
        key = tk;
        key_len = OUTPUT_SIZE;
    }
    
    memcpy(temp_key, key, key_len);
    memset(temp_key + key_len, 0, BLOCK_SIZE - key_len);
    
    for (i = 0; i < BLOCK_SIZE; i++) {
        k_ipad[i] = temp_key[i] ^ 0x36;
        k_opad[i] = temp_key[i] ^ 0x5c;
    }
    
    uint8_t inner_hash[20];
    uint8_t inner_data[BLOCK_SIZE + data_len];
    
    memcpy(inner_data, k_ipad, BLOCK_SIZE);
    memcpy(inner_data + BLOCK_SIZE, data, data_len);
    
    sha1(inner_data, BLOCK_SIZE + data_len, inner_hash);
    
    uint8_t outer_data[BLOCK_SIZE + OUTPUT_SIZE];
    
    memcpy(outer_data, k_opad, BLOCK_SIZE);
    memcpy(outer_data + BLOCK_SIZE, inner_hash, OUTPUT_SIZE);
    
    sha1(outer_data, BLOCK_SIZE + OUTPUT_SIZE, hmac);
}

void print_hash(const uint8_t hash[20]) {
    for (int i = 0; i < 20; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    const char *msg = "g";
    const char *key = "a";
    uint8_t hmac[20];
    
    hmac_sha1((const uint8_t *)key, strlen(key), (const uint8_t *)msg, strlen(msg), hmac);
    printf("HMAC-SHA1(\"%s\", \"%s\") = ", msg, key);
    print_hash(hmac);
    
    return 0;
}
