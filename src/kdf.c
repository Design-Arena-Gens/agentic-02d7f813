#include "kdf.h"

#include <string.h>

#include "hmac.h"

int pbkdf2_sha512(const unsigned char *password, size_t password_len,
                  const unsigned char *salt, size_t salt_len,
                  unsigned int iterations,
                  unsigned char *output, size_t output_len) {
    if (!password || !salt || !output || iterations == 0 || output_len == 0) {
        return -1;
    }

    size_t block_count = (output_len + SHA512_DIGEST_LENGTH - 1) / SHA512_DIGEST_LENGTH;
    unsigned char u[SHA512_DIGEST_LENGTH];
    unsigned char t[SHA512_DIGEST_LENGTH];
    unsigned char block_salt[1024];

    if (salt_len + 4 > sizeof(block_salt)) {
        return -1;
    }

    for (size_t block = 1; block <= block_count; block++) {
        memcpy(block_salt, salt, salt_len);
        block_salt[salt_len] = (unsigned char)(block >> 24);
        block_salt[salt_len + 1] = (unsigned char)(block >> 16);
        block_salt[salt_len + 2] = (unsigned char)(block >> 8);
        block_salt[salt_len + 3] = (unsigned char)(block);

        hmac_sha512(password, password_len, block_salt, salt_len + 4, u);
        memcpy(t, u, sizeof(t));

        for (unsigned int i = 1; i < iterations; i++) {
            hmac_sha512(password, password_len, u, sizeof(u), u);
            for (size_t j = 0; j < sizeof(t); j++) {
                t[j] ^= u[j];
            }
        }

        size_t offset = (block - 1) * SHA512_DIGEST_LENGTH;
        size_t copy_len = SHA512_DIGEST_LENGTH;
        if (offset + copy_len > output_len) {
            copy_len = output_len - offset;
        }
        memcpy(output + offset, t, copy_len);
    }

    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
    memset(block_salt, 0, sizeof(block_salt));

    return 0;
}
