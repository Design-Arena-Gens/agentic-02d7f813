#include "hmac.h"

#include <string.h>

void hmac_sha512(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len,
                 unsigned char out[SHA512_DIGEST_LENGTH]) {
    unsigned char ipad[SHA512_BLOCK_SIZE];
    unsigned char opad[SHA512_BLOCK_SIZE];
    unsigned char key_block[SHA512_BLOCK_SIZE];
    unsigned char inner_hash[SHA512_DIGEST_LENGTH];

    memset(key_block, 0, sizeof(key_block));

    if (key_len > SHA512_BLOCK_SIZE) {
        sha512_compute(key, key_len, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (int i = 0; i < SHA512_BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, ipad, sizeof(ipad));
    sha512_update(&ctx, data, data_len);
    sha512_final(&ctx, inner_hash);

    sha512_init(&ctx);
    sha512_update(&ctx, opad, sizeof(opad));
    sha512_update(&ctx, inner_hash, sizeof(inner_hash));
    sha512_final(&ctx, out);

    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(key_block, 0, sizeof(key_block));
    memset(inner_hash, 0, sizeof(inner_hash));
}
