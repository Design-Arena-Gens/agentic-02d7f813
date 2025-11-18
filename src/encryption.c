#include "encryption.h"

#include <stdint.h>
#include <string.h>

#include "hmac.h"
#include "kdf.h"
#include "utils.h"

#define DERIVED_KEY_LEN 256
#define PBKDF2_ITERATIONS 150000

int derive_key_and_encrypt(const char *message,
                           const char *password,
                           const unsigned char *salt,
                           size_t salt_len,
                           char *out_hex,
                           size_t out_hex_len) {
    if (!message || !password || !salt || !out_hex) {
        return -1;
    }

    if (out_hex_len < (DERIVED_KEY_LEN * 2 + 1)) {
        return -1;
    }

    size_t password_len = strlen(password);
    size_t message_len = strlen(message);
    if (password_len == 0 || message_len == 0) {
        return -1;
    }

    unsigned char derived_key[DERIVED_KEY_LEN];
    if (pbkdf2_sha512((const unsigned char *)password, password_len,
                      salt, salt_len, PBKDF2_ITERATIONS,
                      derived_key, sizeof(derived_key)) != 0) {
        secure_zero(derived_key, sizeof(derived_key));
        return -1;
    }

    unsigned char previous_block[SHA512_DIGEST_LENGTH];
    unsigned char block[SHA512_DIGEST_LENGTH];
    unsigned char final_bytes[DERIVED_KEY_LEN];
    unsigned char data_buf[SHA512_DIGEST_LENGTH + MESSAGE_MAX_LEN + 1];
    size_t produced = 0;

    memset(previous_block, 0, sizeof(previous_block));

    for (unsigned int counter = 1; produced < sizeof(final_bytes); counter++) {
        size_t data_len = 0;
        if (produced > 0) {
            memcpy(data_buf, previous_block, sizeof(previous_block));
            data_len += sizeof(previous_block);
        }

        if (data_len + message_len + 1 > sizeof(data_buf)) {
            secure_zero(derived_key, sizeof(derived_key));
            secure_zero(previous_block, sizeof(previous_block));
            secure_zero(block, sizeof(block));
            secure_zero(final_bytes, sizeof(final_bytes));
            secure_zero(data_buf, sizeof(data_buf));
            return -1;
        }

        memcpy(data_buf + data_len, message, message_len);
        data_len += message_len;
        data_buf[data_len++] = (unsigned char)counter;

        hmac_sha512(derived_key, sizeof(derived_key), data_buf, data_len, block);

        size_t to_copy = sizeof(block);
        if (produced + to_copy > sizeof(final_bytes)) {
            to_copy = sizeof(final_bytes) - produced;
        }
        memcpy(final_bytes + produced, block, to_copy);
        memcpy(previous_block, block, sizeof(block));
        produced += to_copy;
    }

    bytes_to_hex(final_bytes, sizeof(final_bytes), out_hex);

    secure_zero(derived_key, sizeof(derived_key));
    secure_zero(previous_block, sizeof(previous_block));
    secure_zero(block, sizeof(block));
    secure_zero(final_bytes, sizeof(final_bytes));
    secure_zero(data_buf, sizeof(data_buf));

    return 0;
}
